// instr_cb -- ProcessInstrumentationCallback DR-scrub. See instr_cb.hpp.
//
// Mechanism (x64 process instrumentation callback):
//   NtSetInformationProcess(ProcessInstrumentationCallback=0x28) registers a
//   callback the kernel invokes on EVERY user-mode return from a kernel
//   transition -- crucially INCLUDING returns from a direct `syscall` the plugin
//   issues from its own inline stub, which the ntdll export hooks never see.
//
//   Callback ABI on entry: R10 = original return RIP, RAX = syscall return value,
//   RSP = user stack (volatile GPRs clobbered by the kernel service exit; the
//   non-volatiles hold the interrupted thread's values). We resume by restoring
//   the exact register state and `jmp r10`.
//
//   A trampoline (hand-assembled into an RX page) snapshots the volatile GPRs and
//   calls dispatch(). dispatch() is scoped to plugin/anonymous returns (so host
//   threads and our own DR re-armer are never touched) and, when it finds the
//   CONTEXT buffer a context-query just filled, zeroes Dr0-3/Dr6/Dr7 in it. The
//   buffer is positively identified by Dr7 == the value we programmed, so we can
//   never corrupt unrelated memory.
//
//   Re-entrancy: the trampoline sets TEB->InstrumentationCallbackDisabled=1 for
//   the duration of dispatch() and clears it before `jmp r10`, so any transition
//   dispatch() itself makes does not recurse. (dispatch() is written to avoid
//   syscalls anyway; the flag is belt-and-suspenders and version-robust.)

#include "host/instr_cb.hpp"

#include <winsock2.h>
#include <windows.h>
#include <psapi.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace bbl {
namespace {

// --- NtSetInformationProcess + the callback info struct ---------------------
using NtSetInformationProcess_t =
    LONG(NTAPI*)(HANDLE, ULONG /*ProcessInformationClass*/, PVOID, ULONG);
NtSetInformationProcess_t p_NtSetInformationProcess = nullptr;

constexpr ULONG ProcessInstrumentationCallback = 0x28;
struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
    ULONG Version;    // 0 on x64
    ULONG Reserved;
    PVOID Callback;   // -> our trampoline
};

// TEB->InstrumentationCallbackDisabled offset. Resolved at runtime from the loaded
// ntdll's KiUserExceptionDispatcher-adjacent path is overkill; the value has been
// stable on x64 for many builds. 24H2/26100+ (this host is 26200) = 0x2EC.
// A wrong offset would only make re-entrancy suppression touch the wrong TEB byte;
// dispatch() makes no syscalls, so correctness does not actually depend on it, but
// we keep it right so the disable/enable is a true no-op-safe toggle.
constexpr uint32_t kTebInstrDisabledOff = 0x2EC;

// --- state ------------------------------------------------------------------
std::atomic<uint64_t> g_dr7_armed{0};
std::atomic<uint64_t> g_slot0{0}, g_slot1{0}, g_slot2{0}, g_slot3{0};
std::atomic<long long> g_fires{0};
std::atomic<long long> g_fires_raw{0};   // EVERY dispatch entry (unscoped) -- proves the callback fires at all
std::atomic<long long> g_scrubs{0};
// Where the leaked CONTEXT buffer was recovered from, for diagnostics:
//   [0]=rdx [1]=r8 [2]=r9 [3]=rcx [4]=stack-scan.
std::atomic<long long> g_path_hits[5] = {};
std::atomic<int>       g_last_path{-1};
bool g_scope_self = false;
bool g_installed  = false;

// Scope decision (must be cheap + syscall/loader-lock-free per fire).
//
//   EXCLUDE ranges: the hot ntdll / kernel* / win32u modules. The overwhelming
//     majority of kernel->user returns land here and are NOT the plugin's inline
//     syscall, so an exclude-hit is an immediate cheap bail. Precomputed once.
//   INCLUDE ranges: the plugin module + any registered extra ranges (the plugin's
//     unpacked anonymous exec regions, and -- for the self-test -- our direct
//     syscall stub page). A return is "interesting" if it is NOT excluded.
//
// Because the actual scrub is Dr7-match gated, running the cheap register fast-path
// on any non-excluded return is safe (it can only ever touch a real leaked CONTEXT).
// The expensive stack scan is additionally gated on an INCLUDE hit.
uintptr_t g_exe_lo = 0, g_exe_hi = 0;
std::atomic<uintptr_t> g_plugin_lo{0}, g_plugin_hi{0};

struct Range { uintptr_t lo, hi; };
constexpr int kMaxRanges = 16;
Range              g_exclude[kMaxRanges]; std::atomic<int> g_nexclude{0};
Range              g_include[kMaxRanges]; std::atomic<int> g_ninclude{0};

void add_range(Range* arr, std::atomic<int>& n, uintptr_t lo, uintptr_t hi) {
    if (!lo || hi <= lo) return;
    int i = n.load(std::memory_order_relaxed);
    for (int k = 0; k < i; ++k) if (arr[k].lo == lo) return;   // dedupe
    if (i >= kMaxRanges) return;
    arr[i].lo = lo; arr[i].hi = hi;
    n.store(i + 1, std::memory_order_release);
}
bool module_range(const wchar_t* name, uintptr_t& lo, uintptr_t& hi) {
    HMODULE h = GetModuleHandleW(name);
    if (!h) return false;
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof mi)) return false;
    lo = (uintptr_t)mi.lpBaseOfDll; hi = lo + mi.SizeOfImage; return true;
}
void register_exclude_module(const wchar_t* name) {
    uintptr_t lo, hi; if (module_range(name, lo, hi)) add_range(g_exclude, g_nexclude, lo, hi);
}
void register_include_range(uintptr_t lo, uintptr_t hi) { add_range(g_include, g_ninclude, lo, hi); }

void resolve_exe_range() {
    HMODULE h = GetModuleHandleW(nullptr);
    MODULEINFO mi{};
    if (h && GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof mi)) {
        g_exe_lo = (uintptr_t)mi.lpBaseOfDll;
        g_exe_hi = g_exe_lo + mi.SizeOfImage;
    }
}
// Lazily resolve the plugin range (it loads after install) and register it as an
// INCLUDE range. Cheap: a single GetModuleHandle when not yet known.
void resolve_plugin_range_if_needed() {
    if (g_plugin_lo.load(std::memory_order_relaxed)) return;
    uintptr_t lo, hi;
    if (!module_range(L"bambu_networking.dll", lo, hi)) return;
    g_plugin_hi.store(hi, std::memory_order_relaxed);
    g_plugin_lo.store(lo, std::memory_order_relaxed);
    register_include_range(lo, hi);
}

inline bool in_ranges(const Range* arr, int n, uintptr_t rip) {
    for (int k = 0; k < n; ++k) if (rip >= arr[k].lo && rip < arr[k].hi) return true;
    return false;
}

// The register snapshot the trampoline hands to dispatch() (ascending memory order
// = push order r11..rax, see the trampoline). rdx/r8/r9 are candidate CONTEXT
// pointers (whichever register the plugin's inline stub left the 2nd arg in that
// survived the syscall); r10 = return RIP; rax = return value.
struct Frame { uint64_t r11, r10, r9, r8, rdx, rcx, rax; };

// --- CONTEXT layout offsets (x64) -------------------------------------------
// We avoid depending on winnt's CONTEXT for the raw scan; use fixed offsets.
//   ContextFlags @ +0x30 (DWORD)
//   Dr0 @ +0x48, Dr1 @ +0x50, Dr2 @ +0x58, Dr3 @ +0x60, Dr6 @ +0x68, Dr7 @ +0x70
constexpr size_t CTX_ContextFlags = 0x30;
constexpr size_t CTX_Dr0 = 0x48, CTX_Dr1 = 0x50, CTX_Dr2 = 0x58,
                 CTX_Dr3 = 0x60, CTX_Dr6 = 0x68, CTX_Dr7 = 0x70;
constexpr size_t CTX_MIN = 0x78;                 // must be able to read through Dr7
constexpr uint32_t CTXF_DEBUG = 0x00100010u;     // CONTEXT_AMD64 | CONTEXT_DEBUG_REGISTERS

// A canonical, plausibly-mapped user pointer? (cheap sanity gate before deref)
inline bool plausible_ptr(uint64_t p) {
    if (p < 0x10000) return false;                   // null page
    if (p & 0x7) return false;                        // CONTEXT is 16-aligned; ptr at least 8-aligned
    if (p >= 0x7FFFFFFFFFFFull) return false;          // above user VA space (x64 user max)
    return true;
}

// SEH-guarded probe of a candidate CONTEXT buffer. Returns true and scrubs iff the
// buffer looks like a CONTEXT with DEBUG_REGISTERS set AND it leaks a breakpoint
// (Dr7 == our armed Dr7, or any Dr0-3 == an armed slot, or -- as a looser gate --
// Dr7 has any enable bit set while we hold armed breakpoints). Reads/writes are raw
// (no syscall). A fault just returns false.
bool try_scrub_context(uint64_t base) {
    if (!plausible_ptr(base)) return false;
    volatile uint8_t* p = (volatile uint8_t*)base;
    __try {
        uint32_t flags = *(volatile uint32_t*)(p + CTX_ContextFlags);
        // Require the AMD64 CONTEXT id in the high word and the DEBUG bit.
        if ((flags & 0xFFFF0000u) != 0x00100000u) return false;   // not an AMD64 CONTEXT
        if ((flags & 0x00000010u) == 0) return false;              // DEBUG_REGISTERS not requested
        uint64_t dr7 = *(volatile uint64_t*)(p + CTX_Dr7);
        uint64_t dr0 = *(volatile uint64_t*)(p + CTX_Dr0);
        uint64_t dr1 = *(volatile uint64_t*)(p + CTX_Dr1);
        uint64_t dr2 = *(volatile uint64_t*)(p + CTX_Dr2);
        uint64_t dr3 = *(volatile uint64_t*)(p + CTX_Dr3);
        uint64_t dr6 = *(volatile uint64_t*)(p + CTX_Dr6);

        uint64_t armed7 = g_dr7_armed.load(std::memory_order_relaxed);
        uint64_t s0 = g_slot0.load(std::memory_order_relaxed);
        uint64_t s1 = g_slot1.load(std::memory_order_relaxed);
        uint64_t s2 = g_slot2.load(std::memory_order_relaxed);
        uint64_t s3 = g_slot3.load(std::memory_order_relaxed);

        bool leaks = false;
        if (armed7 && dr7 == armed7) leaks = true;
        if (!leaks && ((s0 && dr0 == s0) || (s1 && dr1 == s1) ||
                       (s2 && dr2 == s2) || (s3 && dr3 == s3))) leaks = true;
        // Looser gate: any Dr7 local/global enable bit set while we hold armed BPs.
        // Safe because we only reach here on a plugin/self-scoped context query that
        // already parsed as a DEBUG-flagged AMD64 CONTEXT.
        if (!leaks && (armed7 || s0 || s1 || s2 || s3) && (dr7 & 0xFFULL)) leaks = true;

        if (!leaks) {
            // Nothing to hide (e.g. the query wasn't leaking a BP). Leave it be.
            (void)dr6;
            return false;
        }
        // Scrub: present a clean, un-breakpointed context.
        *(volatile uint64_t*)(p + CTX_Dr0) = 0;
        *(volatile uint64_t*)(p + CTX_Dr1) = 0;
        *(volatile uint64_t*)(p + CTX_Dr2) = 0;
        *(volatile uint64_t*)(p + CTX_Dr3) = 0;
        *(volatile uint64_t*)(p + CTX_Dr6) = 0;
        *(volatile uint64_t*)(p + CTX_Dr7) = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Scan a bounded window of the returning thread's stack for a leaking CONTEXT. Two
// interpretations at each slot, because the buffer may be reached either way:
//   (a) INLINE: the CONTEXT is itself a stack local (the common case -- the compiler
//       materialises `&ctx` with an inline `lea` and never stores the pointer). We
//       test the stack address ITSELF as a CONTEXT base.
//   (b) POINTER: a pointer to a CONTEXT elsewhere sits on the stack. We test *slot.
// Only ever WRITEs to a buffer positively confirmed by try_scrub_context (Dr7 match),
// so scanning cannot corrupt unrelated memory. Returns the count scrubbed.
int scan_stack_for_context(uint64_t rsp) {
    if (rsp < 0x10000) return 0;
    int scrubbed = 0;
    uint64_t base = rsp & ~0xFULL;                 // CONTEXT is 16-aligned
    constexpr int kSlots = 0x1000;                 // 64 KB window (16-byte stride)
    __try {
        for (int i = 0; i < kSlots; ++i) {
            uint64_t addr = base + (uint64_t)i * 16;
            // (a) inline CONTEXT at this 16-aligned stack address.
            if (try_scrub_context(addr)) { ++scrubbed; if (scrubbed >= 2) break; continue; }
            // (b) a pointer to a CONTEXT stored here (check both 8-aligned halves).
            uint64_t p0 = *(volatile uint64_t*)addr;
            if (plausible_ptr(p0) && try_scrub_context(p0)) { ++scrubbed; if (scrubbed >= 2) break; continue; }
            uint64_t p1 = *(volatile uint64_t*)(addr + 8);
            if (plausible_ptr(p1) && try_scrub_context(p1)) { ++scrubbed; if (scrubbed >= 2) break; }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // ran off the mapped stack; whatever we scrubbed stands.
    }
    return scrubbed;
}

// "Interesting" = a return that could be the plugin's inline syscall: NOT in a hot
// host module (ntdll/kernel*/win32u) and NOT in our own exe/trampoline (unless the
// self-test opted our exe in). Anonymous/plugin/registered-stub returns pass.
inline bool rip_interesting(uintptr_t rip) {
    if (in_ranges(g_exclude, g_nexclude.load(std::memory_order_acquire), rip)) return false;
    if (!g_scope_self && g_exe_lo && rip >= g_exe_lo && rip < g_exe_hi) return false;  // our own exe
    return true;
}
// Tighter gate for the expensive stack scan: only plugin range or a registered
// include range (self-test stub / plugin anon regions).
inline bool rip_included(uintptr_t rip) {
    return in_ranges(g_include, g_ninclude.load(std::memory_order_acquire), rip);
}

// The C dispatcher, called by the trampoline with a pointer to the saved GPRs.
// MUST NOT make a syscall on the hot path (kept branch-cheap) and must be tolerant
// of bad memory (all derefs are SEH-guarded inside try_scrub_context/scan).
extern "C" void __cdecl instr_dispatch(Frame* f) {
    g_fires_raw.fetch_add(1, std::memory_order_relaxed);
    uintptr_t rip = (uintptr_t)f->r10;

    // Cheap scope gate: skip the hot ntdll/kernel returns (the vast majority) and
    // our own exe. Everything else (plugin, anonymous unpacked code, the self-test
    // stub page) proceeds to the Dr7-gated scrub.
    if (!rip_interesting(rip)) return;

    // Lazily register the plugin's include range the first time we see a non-excluded
    // return (bounded to while-unknown so it stays cheap).
    if (!g_plugin_lo.load(std::memory_order_relaxed)) resolve_plugin_range_if_needed();

    g_fires.fetch_add(1, std::memory_order_relaxed);

    // Fast path: the 2nd arg (CONTEXT ptr) may still be live in rdx (SYSCALL does
    // not clobber rdx; the kernel service-exit sometimes preserves it). Try the
    // candidates that survive most often first. Dr7-match gated => safe on any value.
    const uint64_t cands[4] = { f->rdx, f->r8, f->r9, f->rcx };
    for (int k = 0; k < 4; ++k) {
        if (try_scrub_context(cands[k])) {
            g_scrubs.fetch_add(1, std::memory_order_relaxed);
            g_path_hits[k].fetch_add(1, std::memory_order_relaxed);
            g_last_path.store(k, std::memory_order_relaxed);
            return;
        }
    }

    // Fallback stack scan (the path proven to work in the self-test: the plugin
    // passes an INLINE CONTEXT stack local and the pointer never survives in a
    // register). Run it when this is a registered include range (plugin/self-test
    // stub) OR whenever breakpoints are currently armed -- the plugin's inline
    // syscall may return into an anonymous unpacked region outside the module range,
    // and the scan is Dr7-gated so it can only ever touch a genuine leaked CONTEXT.
    bool armed = g_dr7_armed.load(std::memory_order_relaxed) ||
                 g_slot0.load(std::memory_order_relaxed) || g_slot1.load(std::memory_order_relaxed) ||
                 g_slot2.load(std::memory_order_relaxed) || g_slot3.load(std::memory_order_relaxed);
    if (!rip_included(rip) && !armed) return;
    uint64_t approx_rsp = (uint64_t)(f + 1);
    int n = scan_stack_for_context(approx_rsp);
    if (n) {
        g_scrubs.fetch_add(n, std::memory_order_relaxed);
        g_path_hits[4].fetch_add(n, std::memory_order_relaxed);
        g_last_path.store(4, std::memory_order_relaxed);
    }
}

// --- the hand-assembled trampoline ------------------------------------------
// See the module header for the ABI. CRITICAL: RFLAGS must be preserved -- the
// callback fires on EVERY syscall return in the process (incl. all ntdll returns
// during LoadLibrary), and the instruction after a syscall frequently branches on
// the NTSTATUS sign flag; clobbering RFLAGS corrupts those and (observed) makes the
// plugin's LoadLibrary fail. Encodes:
//   push rbp; mov rbp,rsp; pushfq
//   push rax; push rcx; push rdx; push r8; push r9; push r10; push r11
//   mov byte gs:[disabled],1
//   lea rcx,[rbp-64]                 ; arg1 = &Frame{r11,r10,r9,r8,rdx,rcx,rax}
//   sub rsp,32 ; and rsp,-16          ; shadow space + align
//   mov rax, imm64(instr_dispatch) ; call rax
//   lea rsp,[rbp-64]
//   mov byte gs:[disabled],0
//   pop r11; pop r10; pop r9; pop r8; pop rdx; pop rcx; pop rax; popfq; pop rbp
//   jmp r10
uint8_t* g_tramp = nullptr;

bool build_trampoline() {
    uint8_t code[] = {
        0x55,                               // push rbp
        0x48,0x89,0xE5,                     // mov rbp,rsp
        0x9C,                               // pushfq                     -> [rbp-8]
        0x50,                               // push rax                   -> [rbp-16]
        0x51,                               // push rcx                   -> [rbp-24]
        0x52,                               // push rdx                   -> [rbp-32]
        0x41,0x50,                          // push r8                    -> [rbp-40]
        0x41,0x51,                          // push r9                    -> [rbp-48]
        0x41,0x52,                          // push r10                   -> [rbp-56]
        0x41,0x53,                          // push r11                   -> [rbp-64]
        0x65,0xC6,0x04,0x25, 0,0,0,0, 0x01, // mov byte gs:[disabled],1   (imm @ +20)
        0x48,0x8D,0x4D,0xC0,               // lea rcx,[rbp-64]
        0x48,0x83,0xEC,0x20,               // sub rsp,32
        0x48,0x83,0xE4,0xF0,               // and rsp,-16
        0x48,0xB8, 0,0,0,0,0,0,0,0,         // mov rax, imm64(dispatch)   (imm @ +39)
        0xFF,0xD0,                          // call rax
        0x48,0x8D,0x65,0xC0,               // lea rsp,[rbp-64]
        0x65,0xC6,0x04,0x25, 0,0,0,0, 0x00, // mov byte gs:[disabled],0   (imm @ +57)
        0x41,0x5B,                          // pop r11
        0x41,0x5A,                          // pop r10
        0x41,0x59,                          // pop r9
        0x41,0x58,                          // pop r8
        0x5A,                               // pop rdx
        0x59,                               // pop rcx
        0x58,                               // pop rax
        0x9D,                               // popfq                      (rsp @ rbp-8)
        0x5D,                               // pop rbp
        0x41,0xFF,0xE2,                     // jmp r10
    };
    // Patch offsets computed from the layout above.
    const size_t OFF_DIS1  = 20;   // disabled-store #1 imm32 (65 C6 04 25 @16, imm @20, 01 @24)
    const size_t OFF_DISP  = 39;   // dispatch imm64 (48 B8 @37, imm64 @39)
    const size_t OFF_DIS2  = 57;   // disabled-store #2 imm32 (65 C6 04 25 @53, imm @57, 00 @61)
    // sanity: verify the bytes at the patch sites are the placeholders we expect.
    if (!(code[OFF_DIS1-4]==0x65 && code[OFF_DIS1+4]==0x01 &&
          code[OFF_DISP-2]==0x48 && code[OFF_DISP-1]==0xB8 &&
          code[OFF_DIS2-4]==0x65 && code[OFF_DIS2+4]==0x00)) {
        std::fprintf(stderr, "[instr-cb] trampoline layout mismatch (patch offsets wrong)\n");
        return false;
    }
    uint32_t dis = kTebInstrDisabledOff;
    std::memcpy(code + OFF_DIS1, &dis, 4);
    std::memcpy(code + OFF_DIS2, &dis, 4);
    void* disp = (void*)&instr_dispatch;
    std::memcpy(code + OFF_DISP, &disp, 8);

    g_tramp = (uint8_t*)VirtualAlloc(nullptr, sizeof code, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_tramp) { std::fprintf(stderr, "[instr-cb] VirtualAlloc failed\n"); return false; }
    std::memcpy(g_tramp, code, sizeof code);
    DWORD old = 0;
    if (!VirtualProtect(g_tramp, sizeof code, PAGE_EXECUTE_READ, &old)) {
        std::fprintf(stderr, "[instr-cb] VirtualProtect RX failed\n");
        return false;
    }
    FlushInstructionCache(GetCurrentProcess(), g_tramp, sizeof code);
    return true;
}

}  // namespace

void instr_cb_set_armed_dr7(uint64_t dr7) { g_dr7_armed.store(dr7, std::memory_order_relaxed); }
void instr_cb_set_armed_slots(uint64_t d0, uint64_t d1, uint64_t d2, uint64_t d3) {
    g_slot0.store(d0, std::memory_order_relaxed); g_slot1.store(d1, std::memory_order_relaxed);
    g_slot2.store(d2, std::memory_order_relaxed); g_slot3.store(d3, std::memory_order_relaxed);
}
long long instr_cb_fires()  { return g_fires.load(); }
long long instr_cb_scrubs() { return g_scrubs.load(); }
long long instr_cb_fires_raw() { return g_fires_raw.load(); }

// Human-readable name of the path that last recovered a leaking CONTEXT buffer.
const char* instr_cb_last_path_name() {
    switch (g_last_path.load()) {
        case 0: return "rdx"; case 1: return "r8"; case 2: return "r9";
        case 3: return "rcx"; case 4: return "stack-scan"; default: return "(none)";
    }
}
void instr_cb_log_paths(FILE* out) {
    std::fprintf(out, "[instr-cb] buffer-recovery paths: rdx=%lld r8=%lld r9=%lld rcx=%lld stack=%lld\n",
                 g_path_hits[0].load(), g_path_hits[1].load(), g_path_hits[2].load(),
                 g_path_hits[3].load(), g_path_hits[4].load());
}

bool install_instrumentation_callback(bool scope_self) {
    if (g_installed) { g_scope_self = g_scope_self || scope_self; return true; }
    g_scope_self = scope_self;
    resolve_exe_range();
    resolve_plugin_range_if_needed();   // may still be null; dispatch resolves later

    // Exclude the hot host modules so the callback fast-bails on the overwhelming
    // majority of returns. (The plugin's inline syscall returns into the plugin /
    // an anonymous unpacked region, never into these.)
    register_exclude_module(L"ntdll.dll");
    register_exclude_module(L"kernelbase.dll");
    register_exclude_module(L"kernel32.dll");
    register_exclude_module(L"win32u.dll");
    register_exclude_module(L"KernelBase.dll");

    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    p_NtSetInformationProcess = nt ? (NtSetInformationProcess_t)GetProcAddress(nt, "NtSetInformationProcess") : nullptr;
    if (!p_NtSetInformationProcess) {
        std::fprintf(stderr, "[instr-cb] NtSetInformationProcess not found\n");
        return false;
    }
    if (!g_tramp && !build_trampoline()) return false;

    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info{};
    info.Version  = 0;      // x64
    info.Reserved = 0;
    info.Callback = g_tramp;
    LONG st = p_NtSetInformationProcess(GetCurrentProcess(), ProcessInstrumentationCallback,
                                        &info, sizeof info);
    if (st != 0) {
        std::fprintf(stderr, "[instr-cb] NtSetInformationProcess(0x28) failed: 0x%08lX\n",
                     (unsigned long)st);
        return false;
    }
    g_installed = true;
    std::fprintf(stderr, "[instr-cb] installed (scope_self=%d, tramp=%p, plugin=%p-%p)\n",
                 (int)scope_self, (void*)g_tramp, (void*)g_plugin_lo.load(), (void*)g_plugin_hi.load());
    std::fflush(stderr);
    return true;
}

void remove_instrumentation_callback() {
    if (!g_installed || !p_NtSetInformationProcess) return;
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info{};
    info.Version = 0; info.Reserved = 0; info.Callback = nullptr;
    p_NtSetInformationProcess(GetCurrentProcess(), ProcessInstrumentationCallback, &info, sizeof info);
    g_installed = false;
}

// ---------------------------------------------------------------------------
// Self-test: verify the scrub works against a DIRECT-syscall context read, with no
// plugin dependency. Sets a real DR7 execute BP on a dummy fn on THIS thread, reads
// our own context via a hand-written NtGetContextThread syscall stub, and checks
// the callback zeroed Dr7 in the result while the BP still fires.
// ---------------------------------------------------------------------------
namespace {

// A dummy target we set a hardware execute-BP on. Marked noinline + volatile side
// effect so the compiler can't fold/duplicate it.
volatile int g_dummy_sink = 0;
#if defined(_MSC_VER)
__declspec(noinline)
#endif
void dummy_bp_target() { g_dummy_sink += 1; _ReadWriteBarrier(); }

// A #DB (single-step) VEH that just counts the BP firing and re-arms via RF so the
// trapped instruction runs once. Proves the DR breakpoint is LIVE despite the scrub
// hiding it from a context read.
std::atomic<long long> g_selftest_bp_hits{0};
uint64_t g_selftest_bp_va = 0;
LONG CALLBACK selftest_veh(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT* c = ep->ContextRecord;
    if (g_selftest_bp_va && c->Rip == g_selftest_bp_va) {
        g_selftest_bp_hits.fetch_add(1, std::memory_order_relaxed);
        c->Dr6 = 0;
        c->EFlags |= 0x10000;   // RF
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Hand-written direct NtGetContextThread syscall stub. We locate the SSN by reading
// it out of ntdll's own NtGetContextThread export (the `mov eax, imm32` at byte 4),
// then invoke `mov r10,rcx; mov eax,ssn; syscall; ret` from our OWN RX page so the
// return address is in the exe/our-page -- NOT ntdll -- exactly like the plugin's
// inline stub. This is what the export hooks miss and the instrumentation callback
// must catch.
using DirectNtGct_t = LONG(NTAPI*)(HANDLE, PCONTEXT);
DirectNtGct_t g_direct_gct = nullptr;

bool build_direct_syscall_stub() {
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) return false;
    uint8_t* exp = (uint8_t*)GetProcAddress(nt, "NtGetContextThread");
    if (!exp) return false;
    // Standard ntdll stub prologue: 4C 8B D1 (mov r10,rcx) B8 <ssn:32> ...
    if (!(exp[0] == 0x4C && exp[1] == 0x8B && exp[2] == 0xD1 && exp[3] == 0xB8)) {
        std::fprintf(stderr, "[instr-selftest] unexpected ntdll stub prologue "
                     "(%02x %02x %02x %02x); cannot derive SSN\n", exp[0],exp[1],exp[2],exp[3]);
        return false;
    }
    uint32_t ssn = *(uint32_t*)(exp + 4);
    uint8_t stub[] = {
        0x4C,0x8B,0xD1,                 // mov r10, rcx
        0xB8, 0,0,0,0,                  // mov eax, ssn   (off @ +4)
        0x0F,0x05,                      // syscall
        0xC3,                           // ret
    };
    std::memcpy(stub + 4, &ssn, 4);
    uint8_t* page = (uint8_t*)VirtualAlloc(nullptr, sizeof stub, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!page) return false;
    std::memcpy(page, stub, sizeof stub);
    DWORD old = 0;
    if (!VirtualProtect(page, sizeof stub, PAGE_EXECUTE_READ, &old)) return false;
    FlushInstructionCache(GetCurrentProcess(), page, sizeof stub);
    g_direct_gct = (DirectNtGct_t)page;
    // The stub's `ret` after `syscall` returns into THIS page (anonymous, non-module)
    // -- exactly like the plugin's inline stub. Register it so the callback treats
    // the return as interesting (include range enables the stack-scan fallback too).
    register_include_range((uintptr_t)page, (uintptr_t)page + sizeof stub);
    std::fprintf(stderr, "[instr-selftest] direct NtGetContextThread stub built (ssn=0x%x, page=%p)\n",
                 ssn, (void*)page);
    return true;
}

// Program DR0 on the current thread with an execute BP at va, via the ntdll export
// SetThreadContext path (the host's legitimate arming path -- the very path the
// production re-armer uses). Publishes the programmed Dr7 so the callback can Dr7-
// match. Returns the Dr7 value programmed.
uint64_t arm_dr0_here(uint64_t va) {
    CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE th = GetCurrentThread();
    GetThreadContext(th, &c);
    c.Dr0 = va;
    c.Dr7 = (c.Dr7 & ~0xFFULL & ~0xFFFF0000ULL) | 0x1ULL;   // L0=1, exec(00)/len(00) for Dr0
    c.Dr6 = 0;
    c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext(th, &c);
    // Re-read what the kernel actually stored (it normalises Dr7, e.g. sets the
    // reserved bit 10 -> 0x401) so the Dr7-match uses the true value.
    CONTEXT r{}; r.ContextFlags = CONTEXT_DEBUG_REGISTERS; GetThreadContext(th, &r);
    instr_cb_set_armed_dr7(r.Dr7);
    instr_cb_set_armed_slots(va, 0, 0, 0);
    return r.Dr7;
}

}  // namespace

int instrumentation_selftest() {
    std::fprintf(stderr, "[instr-selftest] begin\n");
    if (!install_instrumentation_callback(/*scope_self=*/true)) {
        std::fprintf(stderr, "[instr-selftest] FAIL: could not install callback\n");
        return 1;
    }
    if (!build_direct_syscall_stub()) {
        std::fprintf(stderr, "[instr-selftest] FAIL: could not build direct syscall stub\n");
        return 2;
    }
    PVOID veh = AddVectoredExceptionHandler(1, selftest_veh);

    g_selftest_bp_va = (uint64_t)(void*)&dummy_bp_target;
    uint64_t dr7 = arm_dr0_here(g_selftest_bp_va);
    std::fprintf(stderr, "[instr-selftest] armed DR0=%p Dr7=0x%llx on this thread\n",
                 (void*)g_selftest_bp_va, (unsigned long long)dr7);

    int rc = 0;

    // (A) The breakpoint must be LIVE: calling the dummy fires the #DB.
    long long before = g_selftest_bp_hits.load();
    dummy_bp_target();
    long long after = g_selftest_bp_hits.load();
    bool bp_live = (after > before);
    std::fprintf(stderr, "[instr-selftest] BP live check: hits %lld -> %lld (%s)\n",
                 before, after, bp_live ? "FIRED" : "did NOT fire");

    // (B) Read our own context via the DIRECT syscall stub. Without the callback
    // this returns the real Dr0/Dr7. With the callback, they must be scrubbed to 0.
    // Use a STACK-local CONTEXT (16-aligned) -- exactly what the plugin uses -- so
    // this exercises the stack-scan fallback (the register may not survive the
    // kernel service exit). alignas(16) keeps the CONTEXT layout kernel-valid.
    alignas(16) CONTEXT ctx_storage;
    CONTEXT* ctx = &ctx_storage;
    std::memset(ctx, 0, sizeof(CONTEXT));
    ctx->ContextFlags = CONTEXT_DEBUG_REGISTERS;
    long long scrubs_before = instr_cb_scrubs();
    long long fires_before  = instr_cb_fires();
    long long raw_before    = instr_cb_fires_raw();
    LONG st = g_direct_gct(GetCurrentThread(), ctx);
    long long scrubs_after = instr_cb_scrubs();
    long long fires_after  = instr_cb_fires();
    long long raw_after    = instr_cb_fires_raw();

    std::fprintf(stderr, "[instr-selftest] direct NtGetContextThread -> st=0x%08lX  "
                 "raw_fires %lld->%lld scoped_fires %lld->%lld scrubs %lld->%lld  path=%s\n",
                 (unsigned long)st, raw_before, raw_after, fires_before, fires_after,
                 scrubs_before, scrubs_after, instr_cb_last_path_name());
    instr_cb_log_paths(stderr);
    std::fprintf(stderr, "[instr-selftest] context after read: Dr0=0x%llx Dr1=0x%llx Dr2=0x%llx "
                 "Dr3=0x%llx Dr6=0x%llx Dr7=0x%llx (flags=0x%lx)\n",
                 (unsigned long long)ctx->Dr0, (unsigned long long)ctx->Dr1,
                 (unsigned long long)ctx->Dr2, (unsigned long long)ctx->Dr3,
                 (unsigned long long)ctx->Dr6, (unsigned long long)ctx->Dr7,
                 (unsigned long)ctx->ContextFlags);

    bool scrubbed = (ctx->Dr0 == 0 && ctx->Dr1 == 0 && ctx->Dr2 == 0 &&
                     ctx->Dr3 == 0 && ctx->Dr7 == 0);

    // (C) The breakpoint must STILL be live after the read (we only hid it, not
    // cleared it): fire it once more.
    before = g_selftest_bp_hits.load();
    dummy_bp_target();
    after = g_selftest_bp_hits.load();
    bool bp_live_after = (after > before);
    std::fprintf(stderr, "[instr-selftest] BP live AFTER scrub: hits %lld -> %lld (%s)\n",
                 before, after, bp_live_after ? "FIRED" : "did NOT fire");

    if (st != 0) { std::fprintf(stderr, "[instr-selftest] NOTE: syscall returned nonzero\n"); }
    if (!bp_live)       { std::fprintf(stderr, "[instr-selftest] FAIL: BP was not live to begin with\n"); rc = 10; }
    else if (raw_after == raw_before) {
        std::fprintf(stderr, "[instr-selftest] FAIL: the instrumentation callback never fired AT ALL "
                     "on the direct syscall (NtSetInformationProcess(0x28) not effective on this OS/session)\n"); rc = 11;
    }
    else if (fires_after == fires_before) {
        std::fprintf(stderr, "[instr-selftest] FAIL: callback fired but the return was not in scope "
                     "(scope gate mis-tuned; raw=%lld)\n", raw_after - raw_before); rc = 14;
    }
    else if (!scrubbed) {
        std::fprintf(stderr, "[instr-selftest] FAIL: debug registers were NOT scrubbed in the "
                     "direct-syscall context read\n"); rc = 12;
    }
    else if (!bp_live_after) {
        std::fprintf(stderr, "[instr-selftest] FAIL: BP stopped firing after scrub (we cleared it, "
                     "not just hid it)\n"); rc = 13;
    }
    else {
        std::fprintf(stderr, "[instr-selftest] PASS: direct-syscall context read returned Dr=0 while "
                     "the hardware breakpoint stayed live (fired before & after)\n");
    }

    // Tear down the BP on this thread so we don't leave DR set.
    arm_dr0_here(0);
    { CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS; GetThreadContext(GetCurrentThread(), &c);
      c.Dr0=c.Dr1=c.Dr2=c.Dr3=c.Dr6=c.Dr7=0; c.ContextFlags=CONTEXT_DEBUG_REGISTERS;
      SetThreadContext(GetCurrentThread(), &c); }
    instr_cb_set_armed_dr7(0); instr_cb_set_armed_slots(0,0,0,0);
    if (veh) RemoveVectoredExceptionHandler(veh);
    return rc;
}

}  // namespace bbl
