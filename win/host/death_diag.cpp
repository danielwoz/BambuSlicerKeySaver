// Diagnostic for when the plugin process exits mid-capture.
//
// A worker may exit without an unhandled exception -- it calls a process-exit
// routine mid-operation rather than faulting. This also hooks the process-exit
// path to log WHO calls it and from WHICH module: a caller with no owning module
// (a private arena) or the plugin DLL indicates the exit originated in the
// plugin rather than in the host's own `main` return.
//
// Everything here is passive: the VEH/UEF only log (UEF also suppresses a WER
// dialog that could hang a background run); the exit hooks log then call the
// original, so control flow is unchanged.
//
// Exit-cause discrimination:
//   - fatal UNHANDLED exception logged   -> CRASH (+ where/what)
//   - TerminateProcess/exit hook fires   -> DELIBERATE EXIT (+ caller module)
//   - none of the above, runs until kill -> HANG / inlined-syscall exit
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <intrin.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

#include "MinHook.h"

#pragma intrinsic(_ReturnAddress)

namespace bbl {
namespace {

constexpr DWORD kSingleStep = EXCEPTION_SINGLE_STEP;
constexpr DWORD kCppEh      = 0xE06D7363;
constexpr DWORD kDbgPrint   = 0x40010006;
constexpr DWORD kDbgPrintW  = 0x4001000A;
constexpr DWORD kMsgWait    = 0x406D1388;

LONG g_logged = 0;
bool g_block   = false;   // BBL_BLOCK_WATCHDOG=1: park a plugin-originated early exit
void* g_studio_seed = nullptr;   // an address inside bambu-studio.exe, seeded from an exit backtrace

bool frame_in_mod(void* addr, HMODULE mod) {
    if (!mod) return false;
    HMODULE h = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)addr, &h))
        return h == mod;
    return false;
}
// Detect a plugin-originated exit: it carries plugin/studio frames on its stack,
// whereas the host's own exit (main returns) does not. Robust to our death_diag
// hook frames (in bambu_host.exe) also being present.
bool g_park_all = false;   // BBL_PARK_ALL=1: park EVERY self-exit (capture mode)

// True if any return-address frame lives in the plugin or in bambu-studio.exe.
// Resolve per-frame by ADDRESS (GetModuleHandleEx FROM_ADDRESS) rather than by
// name: bambu-studio.exe is mapped in a way GetModuleHandleA("bambu-studio.exe")
// misses, so the name check silently failed and the exit was never parked.
bool exit_is_watchdog() {
    void* frames[40];
    USHORT n = CaptureStackBackTrace(0, 40, frames, nullptr);
    for (USHORT i = 0; i < n; ++i) {
        HMODULE h = nullptr;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)frames[i], &h) && h) {
            char nm[MAX_PATH] = {0};
            GetModuleBaseNameA(GetCurrentProcess(), h, nm, sizeof nm);
            if (_stricmp(nm, "bambu_networking.dll") == 0 ||
                _strnicmp(nm, "bambu-studio", 12) == 0) return true;
        }
    }
    return false;
}

void module_for(void* addr, char* out, size_t n) {
    HMODULE h = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)addr, &h) && h) {
        char path[MAX_PATH];
        if (GetModuleFileNameA(h, path, MAX_PATH)) {
            const char* base = std::strrchr(path, '\\');
            uintptr_t off = (uintptr_t)addr - (uintptr_t)h;
            std::snprintf(out, n, "%s+0x%llx", base ? base + 1 : path,
                          (unsigned long long)off);
            return;
        }
    }
    MEMORY_BASIC_INFORMATION mbi{};
    const char* kind = "unknown";
    if (VirtualQuery(addr, &mbi, sizeof mbi)) {
        kind = (mbi.Type == MEM_PRIVATE) ? "private-arena"
             : (mbi.Type == MEM_IMAGE)   ? "image-noname"
             : (mbi.Type == MEM_MAPPED)  ? "mapped" : "reserved";
    }
    std::snprintf(out, n, "<%s:%p>", kind, addr);
}

const char* code_name(DWORD c) {
    switch (c) {
        case EXCEPTION_ACCESS_VIOLATION:    return "ACCESS_VIOLATION";
        case EXCEPTION_ILLEGAL_INSTRUCTION: return "ILLEGAL_INSTRUCTION(ud2?)";
        case EXCEPTION_PRIV_INSTRUCTION:    return "PRIV_INSTRUCTION(rdtsc/priv?)";
        case EXCEPTION_STACK_OVERFLOW:      return "STACK_OVERFLOW";
        case EXCEPTION_INT_DIVIDE_BY_ZERO:  return "INT_DIVIDE_BY_ZERO";
        case 0xC0000006:                    return "IN_PAGE_ERROR";
        case 0xC0000025:                    return "NONCONTINUABLE";
        case 0xC0000026:                    return "INVALID_DISPOSITION";
        case 0xC0000409:                    return "STACK_BUFFER_OVERRUN(__fastfail)";
        default:                            return "?";
    }
}

bool fatal_code(DWORD c) {
    switch (c) {
        case EXCEPTION_ACCESS_VIOLATION: case EXCEPTION_ILLEGAL_INSTRUCTION:
        case EXCEPTION_PRIV_INSTRUCTION: case EXCEPTION_STACK_OVERFLOW:
        case EXCEPTION_INT_DIVIDE_BY_ZERO: case 0xC0000006:
        case 0xC0000025: case 0xC0000026: case 0xC0000409: return true;
        default: return false;
    }
}

void log_exc(const char* tag, EXCEPTION_POINTERS* ep) {
    DWORD c = ep->ExceptionRecord->ExceptionCode;
    void* rip = ep->ExceptionRecord->ExceptionAddress;
    char mod[544]; module_for(rip, mod, sizeof mod);
    if (c == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2) {
        std::fprintf(stderr, "[death-diag] %s %s code=0x%08lX rip=%p (%s) %s addr=%p\n",
                     tag, code_name(c), (unsigned long)c, rip, mod,
                     ep->ExceptionRecord->ExceptionInformation[0] ? "WRITE" : "READ",
                     (void*)ep->ExceptionRecord->ExceptionInformation[1]);
    } else {
        std::fprintf(stderr, "[death-diag] %s %s code=0x%08lX rip=%p (%s)\n",
                     tag, code_name(c), (unsigned long)c, rip, mod);
    }
    std::fflush(stderr);
}

LONG CALLBACK diag_veh(EXCEPTION_POINTERS* ep) {
    DWORD c = ep->ExceptionRecord->ExceptionCode;
    if (c == kSingleStep || c == EXCEPTION_BREAKPOINT || c == kCppEh ||
        c == kDbgPrint || c == kDbgPrintW || c == kMsgWait)
        return EXCEPTION_CONTINUE_SEARCH;
    if (!fatal_code(c)) return EXCEPTION_CONTINUE_SEARCH;
    if (InterlockedIncrement(&g_logged) <= 200) log_exc("FIRST-CHANCE", ep);
    return EXCEPTION_CONTINUE_SEARCH;
}

LONG WINAPI diag_uef(EXCEPTION_POINTERS* ep) {
    log_exc("*** UNHANDLED (terminating, WER suppressed)", ep);
    return EXCEPTION_EXECUTE_HANDLER;
}

// Thread-start query — used by the exit hooks (to capture the exiting thread's
// own start address) and by the suppressor.
using NtQIT_t = LONG (NTAPI*)(HANDLE, int, PVOID, ULONG, PULONG);
NtQIT_t p_NtQueryInformationThread = nullptr;
volatile uintptr_t g_wd_start = 0;
uintptr_t thread_start_addr(HANDLE th) {
    if (!p_NtQueryInformationThread) return 0;
    uintptr_t start = 0;   // ThreadQuerySetWin32StartAddress == 9
    if (p_NtQueryInformationThread(th, 9, &start, sizeof start, nullptr) == 0) return start;
    return 0;
}

// ---- exit-path hooks: catch a deliberate self-terminate + WHO calls it -------
using TerminateProcess_t   = BOOL (WINAPI*)(HANDLE, UINT);
using NtTerminateProcess_t = LONG (NTAPI*)(HANDLE, LONG);
using RtlExitUserProcess_t = VOID (NTAPI*)(ULONG);
TerminateProcess_t   o_TerminateProcess   = nullptr;
NtTerminateProcess_t o_NtTerminateProcess = nullptr;
RtlExitUserProcess_t o_RtlExitUserProcess = nullptr;

void log_exit(const char* fn, void* caller, unsigned long status) {
    char mod[544]; module_for(caller, mod, sizeof mod);
    std::fprintf(stderr,
        "[death-diag] *** PROCESS-EXIT: %s(status=0x%lX) called from %p (%s)\n",
        fn, status, caller, mod);
    // Full backtrace: reveals the original ExitProcess caller (and whether it
    // sits in a private arena).
    void* frames[24];
    USHORT n = CaptureStackBackTrace(0, 24, frames, nullptr);
    for (USHORT i = 0; i < n; ++i) {
        char m[544]; module_for(frames[i], m, sizeof m);
        std::fprintf(stderr, "[death-diag]     frame[%2u] %p  %s\n", i, frames[i], m);
        if (!g_studio_seed && std::strncmp(m, "bambu-studio", 12) == 0) g_studio_seed = frames[i];
    }
    std::fflush(stderr);
}

void park_watchdog(const char* fn) {
    std::fprintf(stderr,
        "[death-diag] intercepted %s self-exit from plugin thread; parking thread, process continues\n", fn);
    std::fflush(stderr);
    for (;;) Sleep(1000000);   // park the exiting thread forever
}

BOOL WINAPI hk_TerminateProcess(HANDLE h, UINT code) {
    bool self = (h == GetCurrentProcess() || h == (HANDLE)-1);
    if (self) {
        log_exit("TerminateProcess", _ReturnAddress(), code);
        if (g_park_all || (g_block && exit_is_watchdog())) park_watchdog("TerminateProcess");
    }
    return o_TerminateProcess(h, code);
}
LONG NTAPI hk_NtTerminateProcess(HANDLE h, LONG status) {
    bool self = (h == GetCurrentProcess() || h == (HANDLE)-1);
    if (self) {
        log_exit("NtTerminateProcess", _ReturnAddress(), (unsigned long)status);
        if (g_park_all || (g_block && exit_is_watchdog())) park_watchdog("NtTerminateProcess");
    }
    return o_NtTerminateProcess(h, status);
}
VOID NTAPI hk_RtlExitUserProcess(ULONG status) {
    log_exit("RtlExitUserProcess", _ReturnAddress(), status);
    if (g_park_all || exit_is_watchdog()) {
        g_wd_start = thread_start_addr(GetCurrentThread());
        std::fprintf(stderr, "[death-diag] exiting thread Win32-start = %p\n", (void*)g_wd_start);
        std::fflush(stderr);
        if (g_block || g_park_all) park_watchdog("RtlExitUserProcess");
    }
    o_RtlExitUserProcess(status);
}

// ---- report a cleared debug-register context to callers --------------------
// User mode can read DR0-7 only through NtGetContextThread. Hook it and zero the
// debug-register fields in the returned CONTEXT, so any caller that inspects
// DR0-7 sees them cleared. The hardware execute breakpoints stay LIVE (they were
// programmed via SetThreadContext, which this hook does not touch), so captures
// keep working. Gated BBL_HIDE_DR=1.
using NtGetContextThread_t = LONG (NTAPI*)(HANDLE, PCONTEXT);
NtGetContextThread_t o_NtGetContextThread = nullptr;
bool g_hide_dr = false;
LONG NTAPI hk_NtGetContextThread(HANDLE th, PCONTEXT c) {
    LONG r = o_NtGetContextThread(th, c);
    if (g_hide_dr && r == 0 && c) { c->Dr0 = c->Dr1 = c->Dr2 = c->Dr3 = c->Dr6 = c->Dr7 = 0; }
    return r;
}

// ---- proactive thread suppression -----------------------------------------
// The early exit comes from threads whose START address is in the in-process
// bambu-studio.exe mapping; the signing work runs in bambu_networking.dll/openssl.
// Suspend studio-start threads so the exit routine is never reached, while
// signing continues. This catches the exit routes the export hooks can't.
uintptr_t g_studio_lo = 0, g_studio_hi = 0;
uintptr_t g_ntdll_lo = 0, g_ntdll_hi = 0;
bool addr_in_studio(uintptr_t a) { return g_studio_lo && a >= g_studio_lo && a < g_studio_hi; }
bool addr_in_ntdll (uintptr_t a) { return g_ntdll_lo  && a >= g_ntdll_lo  && a < g_ntdll_hi; }

// Freeze the studio-start thread(s) so the exit routine is never reached, while
// signing threads keep running.
//
// Discriminator: a candidate thread is SLEEPING (RIP in ntdll wait) with the
// studio mapping on its stack; signing threads run in OpenSSL/plugin and never
// touch studio. We only KEEP-suspend sleeping threads (they hold no user-mode
// lock), and the suspend window is strictly lock-free (GetThreadContext +
// ReadProcessMemory only), so briefly freezing a running signing thread to
// inspect it can't deadlock. Studio range is resolved by name, else from the
// seed address captured in an exit backtrace (name lookup fails for it).
DWORD WINAPI suppressor_thread(LPVOID) {
    HMODULE mainm = GetModuleHandleA(nullptr);
    DWORD frozen[256]; int nfrozen = 0;   // already frozen -> skip re-inspecting (no re-perturbation)
    int caught = 0;
    for (;;) {
        if (!g_studio_lo) {
            HMODULE h = GetModuleHandleA("bambu-studio.exe");
            if (!h && g_studio_seed)
                GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                   GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCSTR)g_studio_seed, &h);
            if (h) {
                MODULEINFO mi{};
                if (GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof mi)) {
                    g_studio_lo = (uintptr_t)mi.lpBaseOfDll; g_studio_hi = g_studio_lo + mi.SizeOfImage;
                    std::fprintf(stderr, "[death-diag] suppressor armed: bambu-studio.exe %p-%p\n",
                                 (void*)g_studio_lo, (void*)g_studio_hi); std::fflush(stderr);
                }
            }
        }
        if (g_studio_lo) {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                THREADENTRY32 te{}; te.dwSize = sizeof te;
                DWORD me = GetCurrentThreadId(), pid = GetCurrentProcessId();
                DWORD newly[64]; int nnew = 0;
                if (Thread32First(snap, &te)) do {
                    if (te.th32OwnerProcessID != pid || te.th32ThreadID == me) continue;
                    bool skip = false;   // already frozen? don't re-touch it
                    for (int i = 0; i < nfrozen; ++i) if (frozen[i] == te.th32ThreadID) { skip = true; break; }
                    if (skip) continue;
                    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                                           FALSE, te.th32ThreadID);
                    if (!th) continue;
                    if (frame_in_mod((void*)thread_start_addr(th), mainm)) { CloseHandle(th); continue; }
                    DWORD prev = SuspendThread(th);
                    if (prev == (DWORD)-1) { CloseHandle(th); continue; }
                    bool keep = false;   // --- lock-free suspend window ---
                    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_CONTROL;
                    if (prev == 0 && GetThreadContext(th, &ctx)) {
                        if (addr_in_studio(ctx.Rip)) keep = true;
                        else if (ctx.Rsp) {
                            uintptr_t buf[4096]; SIZE_T got = 0;   // 32KB of stack
                            if (ReadProcessMemory(GetCurrentProcess(), (void*)ctx.Rsp, buf, sizeof buf, &got))
                                for (size_t i = 0, nn = got / sizeof(uintptr_t); i < nn; ++i)
                                    if (addr_in_studio(buf[i])) { keep = true; break; }
                        }
                    }
                    if (keep && nfrozen < 256) { frozen[nfrozen++] = te.th32ThreadID; if (nnew < 64) newly[nnew++] = te.th32ThreadID; /* stays suspended */ }
                    else ResumeThread(th);
                    CloseHandle(th);
                } while (Thread32Next(snap, &te));
                CloseHandle(snap);
                for (int i = 0; i < nnew; ++i)
                    std::fprintf(stderr, "[death-diag] suppressor: suspended thread tid=%lu (total=%d)\n", newly[i], ++caught);
                if (nnew) std::fflush(stderr);
            }
        }
        Sleep(700);
    }
    return 0;
}

void start_watchdog_suppressor() {
    if (HMODULE nt = GetModuleHandleA("ntdll.dll"))
        p_NtQueryInformationThread = (NtQIT_t)GetProcAddress(nt, "NtQueryInformationThread");
    std::fprintf(stderr, "[death-diag] suppressor(diag) thread starting (ntqit=%p)\n",
                 (void*)p_NtQueryInformationThread);
    std::fflush(stderr);
    CreateThread(nullptr, 0, suppressor_thread, nullptr, 0, nullptr);
}

void install_exit_hooks() {
    char e[8]{}; g_block = (GetEnvironmentVariableA("BBL_BLOCK_WATCHDOG", e, sizeof e) && e[0] == '1');
    char e2[8]{}; g_hide_dr = (GetEnvironmentVariableA("BBL_HIDE_DR", e2, sizeof e2) && e2[0] == '1');
    char e3[8]{}; g_park_all = (GetEnvironmentVariableA("BBL_PARK_ALL", e3, sizeof e3) && e3[0] == '1');
    MH_Initialize();  // harmless if verify_fake already initialised it
    struct { const wchar_t* mod; const char* fn; void* det; void** orig; } hooks[] = {
        { L"kernel32.dll", "TerminateProcess",   (void*)hk_TerminateProcess,   (void**)&o_TerminateProcess },
        { L"ntdll.dll",    "NtTerminateProcess", (void*)hk_NtTerminateProcess, (void**)&o_NtTerminateProcess },
        { L"ntdll.dll",    "RtlExitUserProcess", (void*)hk_RtlExitUserProcess, (void**)&o_RtlExitUserProcess },
        { L"ntdll.dll",    "NtGetContextThread", (void*)hk_NtGetContextThread, (void**)&o_NtGetContextThread },
    };
    int ok = 0;
    for (auto& h : hooks)
        if (MH_CreateHookApi(h.mod, h.fn, h.det, h.orig) == MH_OK) ++ok;
    MH_EnableHook(MH_ALL_HOOKS);
    std::fprintf(stderr, "[death-diag] exit hooks: %d/4 armed (hide_dr=%d)\n", ok, (int)g_hide_dr);
}

}  // namespace

void install_death_diag() {
    AddVectoredExceptionHandler(1, diag_veh);
    SetUnhandledExceptionFilter(diag_uef);
    install_exit_hooks();
    if (g_block) start_watchdog_suppressor();
    std::fprintf(stderr, "[death-diag] installed (VEH + WER-suppressing UEF + exit hooks%s)\n",
                 g_block ? " + exit suppressor" : "");
    std::fflush(stderr);
}

}  // namespace bbl
