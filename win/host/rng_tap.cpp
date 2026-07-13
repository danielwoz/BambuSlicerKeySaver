// rng_tap — hook bcrypt!BCryptGenRandom to log the plugin's random draws.
// See rng_tap.hpp for the rationale (BCryptGenRandom is the plugin's sole RNG).

#include "host/rng_tap.hpp"

#include <windows.h>
#include <psapi.h>
#include <intrin.h>

#include "MinHook.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>

#pragma intrinsic(_ReturnAddress)

namespace bbl {
namespace {

using BCGR_t = LONG(WINAPI*)(void* /*hAlg*/, unsigned char* /*pb*/, unsigned long /*cb*/, unsigned long /*flags*/);
BCGR_t     o_BCryptGenRandom = nullptr;
FILE*      g_log             = nullptr;
std::mutex g_mu;
uintptr_t  g_base            = 0;
uintptr_t  g_end             = 0;
long long  g_hits            = 0;

// Map an address to "plugin+0xRVA" when it falls inside bambu_networking.dll, so
// call sites are stable across runs (ASLR-independent).
bool in_plugin(uintptr_t a) { return g_base && a >= g_base && a < g_end; }

LONG WINAPI hk_BCryptGenRandom(void* hAlg, unsigned char* pb, unsigned long cb, unsigned long flags)
{
    LONG st = o_BCryptGenRandom(hAlg, pb, cb, flags);

    void* frames[12] = {};
    USHORT n = RtlCaptureStackBackTrace(1, 12, frames, nullptr);
    uintptr_t caller = (uintptr_t)_ReturnAddress();

    std::lock_guard<std::mutex> lk(g_mu);
    if (!g_base) {   // plugin may not have been loaded when start_rng_tap ran
        if (HMODULE m = GetModuleHandleA("bambu_networking.dll")) {
            g_base = (uintptr_t)m;
            MODULEINFO mi{};
            if (GetModuleInformation(GetCurrentProcess(), m, &mi, sizeof mi))
                g_end = g_base + mi.SizeOfImage;
        }
    }
    ++g_hits;
    if (g_log && pb && cb && st == 0) {
        std::fprintf(g_log, "[rng] #%lld cb=%lu ", g_hits, cb);
        if (in_plugin(caller)) std::fprintf(g_log, "caller=plugin+0x%llx", (unsigned long long)(caller - g_base));
        else                   std::fprintf(g_log, "caller=%p", (void*)caller);
        // First few plugin frames give the call context (RNG often sits under an
        // OpenSSL wrapper, so the immediate caller alone can be ambiguous).
        std::fprintf(g_log, " bt=[");
        int printed = 0;
        for (USHORT i = 0; i < n && printed < 6; ++i) {
            uintptr_t f = (uintptr_t)frames[i];
            if (in_plugin(f)) { std::fprintf(g_log, "%s0x%llx", printed ? "," : "", (unsigned long long)(f - g_base)); ++printed; }
        }
        std::fprintf(g_log, "] bytes=");
        unsigned long lim = cb < 512 ? cb : 512;
        for (unsigned long i = 0; i < lim; ++i) std::fprintf(g_log, "%02x", pb[i]);
        if (cb > lim) std::fprintf(g_log, "..+%lu", cb - lim);
        std::fprintf(g_log, "\n");
        std::fflush(g_log);
    }
    return st;
}

} // namespace

void start_rng_tap()
{
    static bool started = false;
    if (started) return;
    started = true;

    const char* path = std::getenv("BBL_RNG_LOG");
    if (!path || !path[0]) path = "rng_tap.log";
    g_log = std::fopen(path, "a");

    if (HMODULE m = GetModuleHandleA("bambu_networking.dll")) {
        g_base = (uintptr_t)m;
        MODULEINFO mi{};
        if (GetModuleInformation(GetCurrentProcess(), m, &mi, sizeof mi))
            g_end = g_base + mi.SizeOfImage;
    }

    MH_Initialize(); // harmless if verify_fake/death_diag already initialised it

    void* target = (void*)GetProcAddress(GetModuleHandleW(L"bcrypt.dll"), "BCryptGenRandom");
    MH_STATUS s = MH_CreateHookApi(L"bcrypt.dll", "BCryptGenRandom",
                                   (void*)hk_BCryptGenRandom, (void**)&o_BCryptGenRandom);
    bool armed = (s == MH_OK) && target && (MH_EnableHook(target) == MH_OK);

    std::fprintf(stderr, "[rng-tap] BCryptGenRandom hook %s (plugin base=%p size=0x%llx) -> %s\n",
                 armed ? "ARMED" : "FAILED", (void*)g_base,
                 (unsigned long long)(g_end - g_base), path);
    std::fflush(stderr);
}

void stop_rng_tap()
{
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_log) { std::fprintf(g_log, "[rng] total draws = %lld\n", g_hits); std::fclose(g_log); g_log = nullptr; }
}

long long rng_tap_hits() { return g_hits; }

// ---- file-trace: hook CreateFile/GetFileAttributes so we can see exactly which
// paths the plugin opens (to diagnose start_print's stage-3 "3mf is not exists").
namespace {
using CreateFileW_t = HANDLE (WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using CreateFileA_t = HANDLE (WINAPI*)(LPCSTR,  DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using GetAttrW_t    = DWORD  (WINAPI*)(LPCWSTR);
using GetAttrExW_t  = BOOL   (WINAPI*)(LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID);
CreateFileW_t o_CreateFileW = nullptr;
CreateFileA_t o_CreateFileA = nullptr;
GetAttrW_t    o_GetAttrW    = nullptr;
GetAttrExW_t  o_GetAttrExW  = nullptr;
FILE*         g_flog        = nullptr;
void flog_path(const char* fn, const char* p, bool ok, DWORD err) {
    if (!g_flog) return;
    const char* s = p ? p : "(null)";
    bool empty = !s[0] || !std::strcmp(s, "(null)");
    bool interesting = strstr(s,".3mf")||strstr(s,".gcode")||strstr(s,"cube")||strstr(s,"bambu")||
                       strstr(s,"plate_")||strstr(s,"Temp")||strstr(s,"cloud")||strstr(s,".3MF")||strstr(s,"3D");
    if (interesting || !ok || empty) {
        void* fr[40]; USHORT n = RtlCaptureStackBackTrace(1, 40, fr, nullptr);
        std::fprintf(g_flog, "%-14s '%s' -> %s err=%lu  plugin_stack=[", fn, s, ok?"OK":"FAIL", err);
        int c = 0;
        for (USHORT i = 0; i < n && c < 8; ++i)
            if (in_plugin((uintptr_t)fr[i])) { std::fprintf(g_flog, "%s0x%llx", c?",":"", (unsigned long long)((uintptr_t)fr[i]-g_base)); ++c; }
        std::fprintf(g_flog, "]\n"); std::fflush(g_flog);
    }
}
void flog_w(const char* fn, LPCWSTR w, bool ok, DWORD err) {
    if (!g_flog) return;
    if (!w) { flog_path(fn, "(null)", ok, err); return; }
    char b[1024]; int n = WideCharToMultiByte(CP_UTF8,0,w,-1,b,(int)sizeof b,nullptr,nullptr);
    flog_path(fn, n>0 ? b : "", ok, err);
}
HANDLE WINAPI hk_CreateFileW(LPCWSTR n, DWORD a, DWORD s, LPSECURITY_ATTRIBUTES sa, DWORD d, DWORD f, HANDLE t) {
    HANDLE h=o_CreateFileW(n,a,s,sa,d,f,t); flog_w("CreateFileW",n,h!=INVALID_HANDLE_VALUE,h==INVALID_HANDLE_VALUE?GetLastError():0); return h; }
HANDLE WINAPI hk_CreateFileA(LPCSTR n, DWORD a, DWORD s, LPSECURITY_ATTRIBUTES sa, DWORD d, DWORD f, HANDLE t) {
    HANDLE h=o_CreateFileA(n,a,s,sa,d,f,t); flog_path("CreateFileA",n,h!=INVALID_HANDLE_VALUE,h==INVALID_HANDLE_VALUE?GetLastError():0); return h; }
DWORD WINAPI hk_GetAttrW(LPCWSTR n) { DWORD r=o_GetAttrW(n); flog_w("GetFileAttrW",n,r!=INVALID_FILE_ATTRIBUTES,r==INVALID_FILE_ATTRIBUTES?GetLastError():0); return r; }
BOOL  WINAPI hk_GetAttrExW(LPCWSTR n, GET_FILEEX_INFO_LEVELS lv, LPVOID o) { BOOL r=o_GetAttrExW(n,lv,o); flog_w("GetFileAttrExW",n,r!=0,r?0:GetLastError()); return r; }
} // namespace

void start_file_trace() {
    static bool started=false; if (started) return; started=true;
    const char* path=std::getenv("BBL_FILE_TRACE"); if(!path||!path[0]) path="file_trace.log";
    g_flog=std::fopen(path,"a");
    if (!g_base) if (HMODULE m=GetModuleHandleA("bambu_networking.dll")) {
        g_base=(uintptr_t)m; MODULEINFO mi{};
        if (GetModuleInformation(GetCurrentProcess(),m,&mi,sizeof mi)) g_end=g_base+mi.SizeOfImage;
    }
    MH_Initialize();
    MH_CreateHookApi(L"kernelbase.dll","CreateFileW",(void*)hk_CreateFileW,(void**)&o_CreateFileW);
    MH_CreateHookApi(L"kernelbase.dll","CreateFileA",(void*)hk_CreateFileA,(void**)&o_CreateFileA);
    MH_CreateHookApi(L"kernelbase.dll","GetFileAttributesW",(void*)hk_GetAttrW,(void**)&o_GetAttrW);
    MH_CreateHookApi(L"kernelbase.dll","GetFileAttributesExW",(void*)hk_GetAttrExW,(void**)&o_GetAttrExW);
    MH_EnableHook(MH_ALL_HOOKS);
    std::fprintf(stderr,"[file-trace] armed -> %s\n",path);
}

} // namespace bbl
