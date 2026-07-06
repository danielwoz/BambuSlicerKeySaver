/*
 * rdtsc_fake.so — Agent PLACATE Phase 1
 *
 * LD_PRELOAD shim that makes RDTSC / RDTSCP deterministic-monotonic.
 *
 * Mechanism:
 *   prctl(PR_SET_TSC, PR_TSC_SIGSEGV) → every RDTSC/RDTSCP traps SIGSEGV.
 *   Our SIGSEGV handler decodes the instruction, writes a monotonic
 *   counter into RAX/RDX (and RCX for RDTSCP), advances RIP, and returns.
 *
 * Critical: we INTERPOSE sigaction(SIGSEGV, ...) so that any subsequent
 * application install of a SIGSEGV handler stacks under us — we always
 * see RDTSC traps first, and chain non-RDTSC SIGSEGVs to the app's
 * handler.
 *
 * Non-RDTSC SIGSEGVs are forwarded to the application's most recent
 * handler (if any) or to SIG_DFL.
 *
 * Build:  gcc -shared -fPIC -O2 -Wl,-z,now -ldl -o rdtsc_fake.so rdtsc_fake.c
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/prctl.h>
#include <ucontext.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>
#include <errno.h>

/* Configurable via env */
static uint64_t fake_tsc_init   = 0x100000000ULL;   /* ~4 G initial */
static uint64_t fake_tsc_step   = 1000ULL;          /* low-frequency monotonic */

static volatile uint64_t fake_tsc = 0;
static volatile uint64_t intercepted_count = 0;
static volatile uint64_t passthrough_count = 0;

/* The application's current SIGSEGV disposition (what they think they
 * registered). We update this on each sigaction(SIGSEGV, ...) interpose. */
static struct sigaction app_segv = { .sa_handler = SIG_DFL };
static pthread_mutex_t app_segv_lock = PTHREAD_MUTEX_INITIALIZER;

static int verbose = 0;  /* 1 = log every RDTSC, 2 = log all signals */

static int (*real_sigaction)(int, const struct sigaction *, struct sigaction *) = NULL;

static int should_trap_on_this_process(void);

static void
write_log(const char *msg, size_t n)
{
    (void)write(2, msg, n);
}

static void
sigsegv_handler(int sig, siginfo_t *si, void *ctx)
{
    ucontext_t *uc = (ucontext_t *)ctx;
    uint8_t *rip = (uint8_t *)uc->uc_mcontext.gregs[REG_RIP];

    /* Detect RDTSC = 0F 31 / RDTSCP = 0F 01 F9.
     * If RIP is unmapped, this dereference will recurse. Linux delivers
     * SIGSEGV from PR_TSC with si_code SI_KERNEL and si_addr==0; a real
     * SIGSEGV usually has si_code SEGV_MAPERR/SEGV_ACCERR and si_addr
     * non-NULL. We sanity-check si_code first.
     */
    int looks_like_tsc_trap = (si->si_code == SI_KERNEL) || (si->si_addr == NULL);

    if (looks_like_tsc_trap) {
        /* Safe to read rip: this is from kernel, RIP must be valid */
        if (rip[0] == 0x0f && rip[1] == 0x31) {
            fake_tsc += fake_tsc_step;
            uc->uc_mcontext.gregs[REG_RAX] = (greg_t)(fake_tsc & 0xffffffffULL);
            uc->uc_mcontext.gregs[REG_RDX] = (greg_t)((fake_tsc >> 32) & 0xffffffffULL);
            uc->uc_mcontext.gregs[REG_RIP] += 2;
            intercepted_count++;
            if (verbose && intercepted_count <= 30) {
                char buf[256];
                int n = snprintf(buf, sizeof(buf),
                                 "[rdtsc_fake] RDTSC #%lu rip=%p tsc=0x%lx\n",
                                 (unsigned long)intercepted_count,
                                 (void*)rip, (unsigned long)fake_tsc);
                if (n > 0) write_log(buf, (size_t)n);
            }
            return;
        }
        if (rip[0] == 0x0f && rip[1] == 0x01 && rip[2] == 0xf9) {
            fake_tsc += fake_tsc_step;
            uc->uc_mcontext.gregs[REG_RAX] = (greg_t)(fake_tsc & 0xffffffffULL);
            uc->uc_mcontext.gregs[REG_RDX] = (greg_t)((fake_tsc >> 32) & 0xffffffffULL);
            uc->uc_mcontext.gregs[REG_RCX] = 0;
            uc->uc_mcontext.gregs[REG_RIP] += 3;
            intercepted_count++;
            return;
        }
    }

    /* Non-TSC SIGSEGV — forward to application's handler. Log first call. */
    passthrough_count++;
    if (verbose && passthrough_count <= 5) {
        uint8_t op0 = 0, op1 = 0, op2 = 0, op3 = 0;
        /* Don't dereference unsafely if si_addr suggests bad RIP */
        if (rip) {
            op0 = rip[0]; op1 = rip[1]; op2 = rip[2]; op3 = rip[3];
        }
        char buf[256];
        int n = snprintf(buf, sizeof(buf),
                         "[rdtsc_fake] passthrough SIGSEGV si_code=%d si_addr=%p rip=%p bytes=%02x%02x%02x%02x\n",
                         si->si_code, si->si_addr, (void*)rip,
                         op0, op1, op2, op3);
        if (n > 0) write_log(buf, (size_t)n);
    }

    /* Snapshot app handler (cheap copy under lock) */
    struct sigaction snap;
    pthread_mutex_lock(&app_segv_lock);
    snap = app_segv;
    pthread_mutex_unlock(&app_segv_lock);

    if (snap.sa_flags & SA_SIGINFO) {
        if (snap.sa_sigaction && snap.sa_sigaction != (void *)SIG_DFL && snap.sa_sigaction != (void *)SIG_IGN) {
            snap.sa_sigaction(sig, si, ctx);
            return;
        }
    } else if (snap.sa_handler == SIG_IGN) {
        return;
    } else if (snap.sa_handler && snap.sa_handler != SIG_DFL) {
        snap.sa_handler(sig);
        return;
    }

    /* Default disposition: clear handler and re-deliver to die. */
    struct sigaction dfl;
    memset(&dfl, 0, sizeof(dfl));
    dfl.sa_handler = SIG_DFL;
    if (real_sigaction)
        real_sigaction(SIGSEGV, &dfl, NULL);
    else
        sigaction(SIGSEGV, &dfl, NULL);
    raise(SIGSEGV);
}

/* Interposed sigaction: keep our SIGSEGV handler installed; record the
 * app's intent so we can forward non-TSC traps to it.
 */
int
sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
    if (!real_sigaction) {
        real_sigaction = dlsym(RTLD_NEXT, "sigaction");
        if (!real_sigaction) {
            errno = ENOSYS;
            return -1;
        }
    }

    if (signum != SIGSEGV) {
        return real_sigaction(signum, act, oldact);
    }

    /* SIGSEGV: maintain ourselves as the kernel handler; record app intent */
    if (oldact) {
        pthread_mutex_lock(&app_segv_lock);
        *oldact = app_segv;
        pthread_mutex_unlock(&app_segv_lock);
    }

    if (act) {
        pthread_mutex_lock(&app_segv_lock);
        app_segv = *act;
        pthread_mutex_unlock(&app_segv_lock);
        if (verbose >= 2) {
            char buf[128];
            int n = snprintf(buf, sizeof(buf),
                             "[rdtsc_fake] sigaction(SIGSEGV) interposed; app handler=%p flags=0x%x\n",
                             (void*)(act->sa_flags & SA_SIGINFO ? (void*)act->sa_sigaction : (void*)act->sa_handler),
                             act->sa_flags);
            if (n > 0) write_log(buf, (size_t)n);
        }
    }

    /* Always install OUR handler in the kernel slot */
    struct sigaction self;
    memset(&self, 0, sizeof(self));
    self.sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER;
    self.sa_sigaction = sigsegv_handler;
    sigemptyset(&self.sa_mask);
    return real_sigaction(SIGSEGV, &self, NULL);
}

/* Hook execve* so when bambu-studio forks+execs a helper (sh -c "uname -s",
 * WebKitWebProcess, etc.), we re-enable TSC in the CALLING process BEFORE
 * exec (PR_TSC state inherits). The child will start with TSC enabled.
 *
 * After exec returns failure (or in the unreachable success-path), restore
 * TSC trap state for the parent.
 */
static int (*real_execve)(const char *, char *const[], char *const[]) = NULL;
static int (*real_execvp)(const char *, char *const[]) = NULL;
static int (*real_execvpe)(const char *, char *const[], char *const[]) = NULL;
static int (*real_execv)(const char *, char *const[]) = NULL;

static void
pre_exec_disable_tsc(void)
{
    /* Disable trap in CURRENT process (a forked child). After exec, the
     * loaded program will start with TSC enabled. Our constructor runs
     * in the new image and will EITHER re-enable trap (if exe matches)
     * or leave it alone (sh, WebKit, ...).
     */
    prctl(PR_SET_TSC, PR_TSC_ENABLE);
}

static void
post_exec_restore_tsc(void)
{
    /* exec failed; restore trap mode in parent (if we should trap) */
    if (should_trap_on_this_process())
        prctl(PR_SET_TSC, PR_TSC_SIGSEGV);
}

int execve(const char *path, char *const argv[], char *const envp[])
{
    if (!real_execve) real_execve = dlsym(RTLD_NEXT, "execve");
    pre_exec_disable_tsc();
    int rc = real_execve(path, argv, envp);
    post_exec_restore_tsc();
    return rc;
}

int execv(const char *path, char *const argv[])
{
    if (!real_execv) real_execv = dlsym(RTLD_NEXT, "execv");
    pre_exec_disable_tsc();
    int rc = real_execv(path, argv);
    post_exec_restore_tsc();
    return rc;
}

int execvp(const char *file, char *const argv[])
{
    if (!real_execvp) real_execvp = dlsym(RTLD_NEXT, "execvp");
    pre_exec_disable_tsc();
    int rc = real_execvp(file, argv);
    post_exec_restore_tsc();
    return rc;
}

int execvpe(const char *file, char *const argv[], char *const envp[])
{
    if (!real_execvpe) real_execvpe = dlsym(RTLD_NEXT, "execvpe");
    pre_exec_disable_tsc();
    int rc = real_execvpe(file, argv, envp);
    post_exec_restore_tsc();
    return rc;
}

/* Some apps use signal() instead — intercept too. */
typedef void (*sighandler_t)(int);

sighandler_t
signal(int signum, sighandler_t handler)
{
    if (signum != SIGSEGV) {
        static sighandler_t (*real_signal)(int, sighandler_t) = NULL;
        if (!real_signal) real_signal = dlsym(RTLD_NEXT, "signal");
        return real_signal ? real_signal(signum, handler) : SIG_ERR;
    }

    struct sigaction act, oldact;
    memset(&act, 0, sizeof(act));
    act.sa_handler = handler;
    sigemptyset(&act.sa_mask);
    if (sigaction(SIGSEGV, &act, &oldact) != 0) return SIG_ERR;
    return (oldact.sa_flags & SA_SIGINFO) ? SIG_DFL : oldact.sa_handler;
}

/* Is the running executable's basename one we want to trap RDTSC on?
 * We default to "bambu-studio" or "bambustu_main". Override via env. */
static int
should_trap_on_this_process(void)
{
    char buf[256];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return 0;
    buf[n] = '\0';

    const char *base = strrchr(buf, '/');
    base = base ? base + 1 : buf;

    const char *want = getenv("RDTSC_FAKE_EXES");
    if (!want) want = "bambu-studio,bambustu_main";

    /* split want on comma */
    const char *p = want;
    while (*p) {
        const char *q = strchr(p, ',');
        size_t len = q ? (size_t)(q - p) : strlen(p);
        if (len > 0 && strncmp(base, p, len) == 0 && base[len] == '\0') return 1;
        if (!q) break;
        p = q + 1;
    }
    return 0;
}

__attribute__((constructor))
static void init(void)
{
    /* Read env tunables */
    const char *s = getenv("RDTSC_FAKE_INIT");
    if (s) fake_tsc_init = strtoull(s, NULL, 0);
    s = getenv("RDTSC_FAKE_STEP");
    if (s) fake_tsc_step = strtoull(s, NULL, 0);
    s = getenv("RDTSC_FAKE_VERBOSE");
    if (s) verbose = atoi(s);

    fake_tsc = fake_tsc_init;

    /* If we're inside a subprocess (e.g., WebKitWebProcess, /bin/sh
     * launched via system()) — RE-ENABLE TSC so they don't crash, and
     * do NOT install any handler. PR_SET_TSC persists across exec but
     * our handler does not.
     */
    if (!should_trap_on_this_process()) {
        /* Re-enable TSC for this child */
        prctl(PR_SET_TSC, PR_TSC_ENABLE);
        if (verbose) {
            char buf[256];
            char exe[256] = "?";
            ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
            if (n > 0) exe[n] = '\0';
            int m = snprintf(buf, sizeof(buf),
                             "[rdtsc_fake] subprocess %s — re-enabled TSC, no trap\n",
                             exe);
            if (m > 0) write_log(buf, (size_t)m);
        }
        return;
    }

    /* Resolve real_sigaction early so dlsym doesn't recurse */
    real_sigaction = dlsym(RTLD_NEXT, "sigaction");

    /* Install our SIGSEGV handler */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER;
    sa.sa_sigaction = sigsegv_handler;
    sigemptyset(&sa.sa_mask);

    int rc;
    if (real_sigaction)
        rc = real_sigaction(SIGSEGV, &sa, &app_segv);
    else
        rc = sigaction(SIGSEGV, &sa, &app_segv);

    if (rc != 0) {
        const char *m = "[rdtsc_fake] sigaction failed\n";
        write_log(m, strlen(m));
        return;
    }

    /* Enable TSC trap */
    if (prctl(PR_SET_TSC, PR_TSC_SIGSEGV) != 0) {
        const char *m = "[rdtsc_fake] prctl(PR_SET_TSC, PR_TSC_SIGSEGV) failed\n";
        write_log(m, strlen(m));
        return;
    }

    const char *m = "[rdtsc_fake] active (interposing sigaction/signal)\n";
    write_log(m, strlen(m));
}

__attribute__((destructor))
static void fini(void)
{
    char buf[160];
    int n = snprintf(buf, sizeof(buf),
                     "[rdtsc_fake] intercepted=%lu passthrough=%lu final_tsc=0x%lx\n",
                     (unsigned long)intercepted_count,
                     (unsigned long)passthrough_count,
                     (unsigned long)fake_tsc);
    if (n > 0) write_log(buf, (size_t)n);
}
