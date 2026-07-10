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

} // namespace bbl
