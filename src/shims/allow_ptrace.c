/* Lifted from BambuBridge-vmp-devirt/agent_alpha_phase22 on 2026-06-20. AGPL-3.0 -- see LICENSE. */
// Minimal LD_PRELOAD shim. Runs prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)
// at load time so any user-owned process can ptrace the host process
// under Yama ptrace_scope=1. Used to permit Frida attach from sibling
// agent shells without sudo.
#include <sys/prctl.h>
#include <stdio.h>

#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif
#ifndef PR_SET_PTRACER_ANY
#define PR_SET_PTRACER_ANY ((unsigned long)-1)
#endif

__attribute__((constructor))
static void allow_ptrace_init(void) {
    int rc = prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
    fprintf(stderr, "[allow_ptrace] prctl(PR_SET_PTRACER_ANY) rc=%d\n", rc);
}
