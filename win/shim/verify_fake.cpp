#include "verify_fake.hpp"

#ifdef _WIN32

#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <intrin.h>
#include <vector>

#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <mutex>
#include <string>

#include "MinHook.h"

namespace {

// --------------------------------------------------------------------------
// Logging: every intercepted call is recorded so a run shows which checks the
// plugin performs.
// --------------------------------------------------------------------------
std::mutex g_log_mu;
FILE*      g_log = nullptr;

void logf(const char* fmt, ...) {
    std::lock_guard<std::mutex> lk(g_log_mu);
    va_list ap;
    char buf[1024];
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    std::fprintf(stderr, "[verify_fake] %s\n", buf);
    std::fflush(stderr);
    if (g_log) { std::fprintf(g_log, "%s\n", buf); std::fflush(g_log); }
}

// --------------------------------------------------------------------------
// Identity state (resolved at install()).
//   g_self     : our own module (the host exe / studio dll)
//   g_our_exe  : path of our process exe
//   g_genuine_*: optional signed files to redirect cert queries to (env), used
//                only as a fallback when the trust-query hooks are insufficient.
// --------------------------------------------------------------------------
HMODULE g_self = nullptr;
wchar_t g_our_exe[MAX_PATH]      = {0};
wchar_t g_our_self[MAX_PATH]     = {0};
wchar_t g_genuine_dll_w[MAX_PATH]= {0};
wchar_t g_genuine_exe_w[MAX_PATH]= {0};
bool    g_have_genuine_dll = false;
bool    g_have_genuine_exe = false;

// --------------------------------------------------------------------------
// Original (trampoline) pointers.
// --------------------------------------------------------------------------
typedef DWORD   (WINAPI *fn_gmfw)(HMODULE, LPWSTR, DWORD);
typedef DWORD   (WINAPI *fn_gmfa)(HMODULE, LPSTR, DWORD);
typedef HMODULE (WINAPI *fn_gmhw)(LPCWSTR);
typedef HMODULE (WINAPI *fn_gmha)(LPCSTR);
typedef BOOL    (WINAPI *fn_cqo)(DWORD, const void*, DWORD, DWORD, DWORD,
                                 DWORD*, DWORD*, DWORD*, HCERTSTORE*, HCRYPTMSG*, const void**);
typedef LONG    (WINAPI *fn_wvt)(HWND, GUID*, LPVOID);
typedef BOOL    (WINAPI *fn_cgcc)(HCERTCHAINENGINE, PCCERT_CONTEXT, LPFILETIME, HCERTSTORE,
                                  PCERT_CHAIN_PARA, DWORD, LPVOID, PCCERT_CHAIN_CONTEXT*);
typedef BOOL    (WINAPI *fn_cvccp)(LPCSTR, PCCERT_CHAIN_CONTEXT, PCERT_CHAIN_POLICY_PARA,
                                   PCERT_CHAIN_POLICY_STATUS);
typedef BOOL    (WINAPI *fn_gtc)(HANDLE, LPCONTEXT);
typedef BOOL    (WINAPI *fn_stc)(HANDLE, const CONTEXT*);
typedef LONG    (WINAPI *fn_ncte)(PHANDLE, ACCESS_MASK, void*, HANDLE, PVOID, PVOID,
                                  ULONG, SIZE_T, SIZE_T, SIZE_T, void*);
typedef LONG    (NTAPI  *fn_ntgct)(HANDLE, PCONTEXT);
typedef LONG    (NTAPI  *fn_ntsct)(HANDLE, PCONTEXT);
typedef BOOL    (WINAPI *fn_idp)(void);
typedef BOOL    (WINAPI *fn_crdp)(HANDLE, PBOOL);
typedef LONG    (NTAPI  *fn_ntqip)(HANDLE, ULONG, PVOID, ULONG, PULONG);

fn_gmfw o_gmfw = nullptr;
fn_gmfa o_gmfa = nullptr;
fn_gmhw o_gmhw = nullptr;
fn_gmha o_gmha = nullptr;
fn_cqo  o_cqo  = nullptr;
fn_wvt  o_wvt  = nullptr;
fn_wvt  o_wvtex = nullptr;   // WinVerifyTrustEx (same 3-arg shape as WinVerifyTrust)
typedef HANDLE (WINAPI *fn_cfw)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
fn_cfw  o_cfw  = nullptr;    // CreateFileW (redirect studio-image reads to genuine)
// Process/module image-path APIs the plugin may use to locate the host exe
// before hashing it. Hooked to hand back the genuine signed path.
typedef BOOL  (WINAPI *fn_qfpin)(HANDLE, DWORD, LPWSTR, PDWORD);
typedef DWORD (WINAPI *fn_gpifw)(HANDLE, LPWSTR, DWORD);
typedef DWORD (WINAPI *fn_gmfex)(HANDLE, HMODULE, LPWSTR, DWORD);
typedef DWORD (WINAPI *fn_gmapw)(HANDLE, LPVOID, LPWSTR, DWORD);
fn_qfpin o_qfpin = nullptr;
fn_gpifw o_gpifw = nullptr;
fn_gmfex o_gmfex = nullptr;
fn_gmapw o_gmapw = nullptr;
fn_cgcc o_cgcc = nullptr;
fn_cvccp o_cvccp = nullptr;
fn_gtc  o_gtc  = nullptr;
fn_stc  o_stc  = nullptr;
fn_ncte o_ncte = nullptr;
fn_ntgct o_ntgct = nullptr;
fn_ntsct o_ntsct = nullptr;
fn_idp   o_idp   = nullptr;
fn_crdp  o_crdp  = nullptr;
fn_ntqip o_ntqip = nullptr;
std::atomic<int> g_threads_created{0};

// Is the return address inside the network plugin? Resolved lazily
// (the plugin loads after we install). Uses the trampoline to avoid recursion.
bool caller_is_plugin(void* ra) {
    HMODULE h = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)ra, &h) || !h || !o_gmfw)
        return false;
    wchar_t p[MAX_PATH] = {0};
    o_gmfw(h, p, MAX_PATH);
    return wcsstr(p, L"bambu_networking") != nullptr ||
           wcsstr(p, L"BambuSource")      != nullptr;
}

// The plugin runs its sign-path image verification from ANONYMOUS executable
// regions, so the return address of that WinVerifyTrust[Ex] call has NO owning
// module and the module-name predicate above misses it. Treat "no owning
// module" (anonymous) as the plugin too. Other verify callers live in real
// modules (wintrust/CRT) and fall through unchanged, so this stays scoped to a
// headless host.
bool caller_is_plugin_or_anon(void* ra) {
    if (caller_is_plugin(ra)) return true;
    HMODULE h = nullptr;
    bool has_mod = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                      GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                      (LPCWSTR)ra, &h) && h != nullptr;
    return !has_mod;
}

const wchar_t* leaf_w(const wchar_t* p);  // fwd
// If `path` refers to OUR host image (by full path or leaf) or to the leaf name we
// substitute for GetModuleFileName, return the corresponding genuine signed file to
// open instead -- so the plugin's Authenticode hash (via
// CryptCATAdminCalcHashFromFileHandle / ImageGetDigestStream over the opened file)
// is computed over a signed image regardless of which path API it used.
const wchar_t* redirect_studio_read_w(const wchar_t* path) {
    if (!path || !*path) return nullptr;
    const wchar_t* lf = leaf_w(path);
    if (g_have_genuine_exe &&
        (( g_our_exe[0] && _wcsicmp(path, g_our_exe) == 0) ||
         _wcsicmp(lf, L"bambu-studio.exe") == 0 ||
         (g_our_exe[0] && _wcsicmp(lf, leaf_w(g_our_exe)) == 0)))
        return g_genuine_exe_w;
    if (g_have_genuine_dll &&
        (( g_our_self[0] && _wcsicmp(path, g_our_self) == 0) ||
         _wcsicmp(lf, L"BambuStudio.dll") == 0))
        return g_genuine_dll_w;
    return nullptr;
}

const wchar_t* leaf_w(const wchar_t* p) {
    if (!p) return L"";
    const wchar_t* b = wcsrchr(p, L'\\');
    return b ? b + 1 : p;
}

bool wants_studio_w(const wchar_t* n) {
    const wchar_t* b = leaf_w(n);
    return _wcsicmp(b, L"BambuStudio.dll") == 0 || _wcsicmp(b, L"BambuStudio") == 0;
}
bool wants_studio_a(const char* n) {
    if (!n) return false;
    const char* b = strrchr(n, '\\'); b = b ? b + 1 : n;
    return _stricmp(b, "BambuStudio.dll") == 0 || _stricmp(b, "BambuStudio") == 0;
}

// Replace the leaf filename of `full` with `newleaf`, writing into out (sz wide chars).
void spoof_leaf(const wchar_t* full, const wchar_t* newleaf, wchar_t* out, DWORD sz) {
    wchar_t tmp[MAX_PATH] = {0};
    wcsncpy_s(tmp, MAX_PATH, full, _TRUNCATE);
    wchar_t* b = wcsrchr(tmp, L'\\');
    if (b) b[1] = 0; else tmp[0] = 0;
    wcsncat_s(tmp, MAX_PATH, newleaf, _TRUNCATE);
    wcsncpy_s(out, sz, tmp, _TRUNCATE);
}

// --------------------------------------------------------------------------
// Hooks.
// --------------------------------------------------------------------------

// WinVerifyTrust: for the plugin's own calls, report the subject as trusted
// (ERROR_SUCCESS) so the plugin proceeds.
LONG WINAPI hk_wvt(HWND hwnd, GUID* action, LPVOID data) {
    void* ra = _ReturnAddress();
    if (caller_is_plugin_or_anon(ra)) {
        logf("WinVerifyTrust(plugin/anon) -> ERROR_SUCCESS");
        return ERROR_SUCCESS;  // 0 == trusted
    }
    return o_wvt(hwnd, action, data);
}

// WinVerifyTrustEx: the plugin's image verification references it and the
// WinVerifyTrust hook alone does not cover it. Same 3-arg shape; handle
// identically (plugin- or anonymous-origin calls report trusted).
LONG WINAPI hk_wvtex(HWND hwnd, GUID* action, LPVOID data) {
    void* ra = _ReturnAddress();
    if (caller_is_plugin_or_anon(ra)) {
        logf("WinVerifyTrustEx(plugin/anon) -> ERROR_SUCCESS");
        return ERROR_SUCCESS;
    }
    return o_wvtex ? o_wvtex(hwnd, action, data) : ERROR_SUCCESS;
}

// CreateFileW: the choke point for the image check. Whatever path API the plugin
// used to locate the host image, it must OPEN that file to hash it -- redirect an
// open of OUR host exe/dll to the user's genuine signed Bambu Studio binary so the
// Authenticode verification passes.
HANDLE WINAPI hk_cfw(LPCWSTR path, DWORD acc, DWORD share, LPSECURITY_ATTRIBUTES sa,
                     DWORD disp, DWORD flags, HANDLE tmpl) {
    if (path && caller_is_plugin_or_anon(_ReturnAddress())) {
        const wchar_t* red = redirect_studio_read_w(path);
        if (red) {
            logf("CreateFileW(plugin/anon) '%ls' -> genuine '%ls'", path, red);
            return o_cfw(red, acc, share, sa, disp, flags, tmpl);
        }
    }
    return o_cfw(path, acc, share, sa, disp, flags, tmpl);
}

// If `buf` holds a path to OUR host image, overwrite it with the genuine signed
// path and return the new length; else return `orig`. Shared by the image-path
// API hooks below so any subsequent open+hash lands on a genuinely-signed file.
DWORD subst_genuine_w(void* ra, LPWSTR buf, DWORD orig, DWORD cap) {
    if (!buf || !orig || cap == 0 || !caller_is_plugin_or_anon(ra)) return orig;
    const wchar_t* red = redirect_studio_read_w(buf);
    if (!red) return orig;
    logf("image-path(plugin/anon) '%ls' -> genuine '%ls'", buf, red);
    wcsncpy_s(buf, cap, red, _TRUNCATE);
    return (DWORD)wcslen(buf);
}
BOOL WINAPI hk_qfpin(HANDLE proc, DWORD flags, LPWSTR buf, PDWORD sz) {
    DWORD cap = (sz ? *sz : 0);
    BOOL r = o_qfpin(proc, flags, buf, sz);
    if (r && buf && sz) { *sz = subst_genuine_w(_ReturnAddress(), buf, *sz, cap); }
    return r;
}
DWORD WINAPI hk_gpifw(HANDLE proc, LPWSTR buf, DWORD sz) {
    DWORD r = o_gpifw(proc, buf, sz);
    return subst_genuine_w(_ReturnAddress(), buf, r, sz);
}
DWORD WINAPI hk_gmfex(HANDLE proc, HMODULE mod, LPWSTR buf, DWORD sz) {
    DWORD r = o_gmfex(proc, mod, buf, sz);
    return subst_genuine_w(_ReturnAddress(), buf, r, sz);
}
DWORD WINAPI hk_gmapw(HANDLE proc, LPVOID addr, LPWSTR buf, DWORD sz) {
    DWORD r = o_gmapw(proc, addr, buf, sz);
    return subst_genuine_w(_ReturnAddress(), buf, r, sz);
}

// CryptQueryObject: log what file the plugin inspects. If a genuine signed file
// is configured, redirect to it so the query succeeds; otherwise pass through
// (and the log tells us whether the plugin relied on this succeeding).
BOOL WINAPI hk_cqo(DWORD ot, const void* obj, DWORD a, DWORD b, DWORD c,
                   DWORD* d, DWORD* e, DWORD* f, HCERTSTORE* st, HCRYPTMSG* msg,
                   const void** ctx) {
    const void* use = obj;
    if (ot == CERT_QUERY_OBJECT_FILE && obj && caller_is_plugin(_ReturnAddress())) {
        const wchar_t* p = (const wchar_t*)obj;
        const wchar_t* lf = leaf_w(p);
        if (g_have_genuine_dll && wants_studio_w(p)) {
            logf("CryptQueryObject(plugin) file='%ls' -> redirect to genuine dll", lf);
            use = g_genuine_dll_w;
        } else if (g_have_genuine_exe && _wcsicmp(lf, L"bambu-studio.exe") == 0) {
            logf("CryptQueryObject(plugin) file='%ls' -> redirect to genuine exe", lf);
            use = g_genuine_exe_w;
        } else {
            logf("CryptQueryObject(plugin) file='%ls' -> pass-through", lf);
        }
    }
    return o_cqo(ot, use, a, b, c, d, e, f, st, msg, ctx);
}

DWORD WINAPI hk_gmfw(HMODULE hMod, LPWSTR fn, DWORD sz) {
    void* ra = _ReturnAddress();
    DWORD r = o_gmfw(hMod, fn, sz);
    if (fn && r && caller_is_plugin_or_anon(ra)) {
        // The plugin Authenticode-verifies the studio module FILE. Return the
        // user's genuine signed bambu-studio.exe / BambuStudio.dll full path so
        // the plugin's own verify passes; fall back to a leaf-rename (identity
        // only) if no genuine file was located.
        if (hMod == nullptr) {
            if (g_have_genuine_exe) {
                wcsncpy_s(fn, sz, g_genuine_exe_w, _TRUNCATE);
                logf("GetModuleFileNameW(plugin,exe) -> genuine '%ls'", fn);
            } else {
                logf("GetModuleFileNameW(plugin, exe) '%ls' -> spoof bambu-studio.exe", fn);
                spoof_leaf(fn, L"bambu-studio.exe", fn, sz);
            }
            return (DWORD)wcslen(fn);
        }
        if (g_have_genuine_dll) {
            wcsncpy_s(fn, sz, g_genuine_dll_w, _TRUNCATE);
            logf("GetModuleFileNameW(plugin,dll) -> genuine '%ls'", fn);
        } else {
            logf("GetModuleFileNameW(plugin) '%ls' -> spoof BambuStudio.dll", fn);
            spoof_leaf(fn, L"BambuStudio.dll", fn, sz);
        }
        return (DWORD)wcslen(fn);
    }
    return r;
}

DWORD WINAPI hk_gmfa(HMODULE hMod, LPSTR fn, DWORD sz) {
    void* ra = _ReturnAddress();
    DWORD r = o_gmfa(hMod, fn, sz);
    if (fn && r && caller_is_plugin_or_anon(ra)) {
        const wchar_t* genw = (hMod == nullptr)
            ? (g_have_genuine_exe ? g_genuine_exe_w : nullptr)
            : (g_have_genuine_dll ? g_genuine_dll_w : nullptr);
        if (genw) {
            char gen[MAX_PATH] = {0};
            WideCharToMultiByte(CP_ACP, 0, genw, -1, gen, MAX_PATH, nullptr, nullptr);
            strncpy_s(fn, sz, gen, _TRUNCATE);
            logf("GetModuleFileNameA(plugin) -> genuine '%s'", fn);
            return (DWORD)strlen(fn);
        }
        const char* leaf = (hMod == nullptr) ? "bambu-studio.exe" : "BambuStudio.dll";
        logf("GetModuleFileNameA(plugin) '%s' -> spoof %s", fn, leaf);
        char tmp[MAX_PATH] = {0};
        strncpy_s(tmp, MAX_PATH, fn, _TRUNCATE);
        char* b = strrchr(tmp, '\\');
        if (b) b[1] = 0; else tmp[0] = 0;
        strncat_s(tmp, MAX_PATH, leaf, _TRUNCATE);
        strncpy_s(fn, sz, tmp, _TRUNCATE);
        return (DWORD)strlen(fn);
    }
    return r;
}

// CertGetCertificateChain: if the plugin validates the printer's TLS cert via
// the Windows cert APIs, clear the chain's error status so it looks fully trusted.
BOOL WINAPI hk_cgcc(HCERTCHAINENGINE eng, PCCERT_CONTEXT cert, LPFILETIME t, HCERTSTORE store,
                    PCERT_CHAIN_PARA para, DWORD flags, LPVOID res, PCCERT_CHAIN_CONTEXT* out) {
    BOOL r = o_cgcc(eng, cert, t, store, para, flags, res, out);
    if (r && out && *out && caller_is_plugin(_ReturnAddress())) {
        CERT_CHAIN_CONTEXT* c = const_cast<CERT_CHAIN_CONTEXT*>(*out);
        c->TrustStatus.dwErrorStatus = CERT_TRUST_NO_ERROR;
        for (DWORD i = 0; i < c->cChain; ++i) {
            c->rgpChain[i]->TrustStatus.dwErrorStatus = CERT_TRUST_NO_ERROR;
            for (DWORD j = 0; j < c->rgpChain[i]->cElement; ++j)
                c->rgpChain[i]->rgpElement[j]->TrustStatus.dwErrorStatus = CERT_TRUST_NO_ERROR;
        }
        logf("CertGetCertificateChain(plugin) -> cleared error status (cChain=%lu)", c->cChain);
    }
    return r;
}

// CertVerifyCertificateChainPolicy: report the policy check as passed.
BOOL WINAPI hk_cvccp(LPCSTR policy, PCCERT_CHAIN_CONTEXT chain, PCERT_CHAIN_POLICY_PARA para,
                     PCERT_CHAIN_POLICY_STATUS status) {
    BOOL r = o_cvccp(policy, chain, para, status);
    if (status && caller_is_plugin(_ReturnAddress())) {
        logf("CertVerifyCertificateChainPolicy(plugin) policy=%p prev_err=0x%lx -> 0",
             (void*)policy, status->dwError);
        status->dwError = 0;
        return TRUE;
    }
    return r;
}

// Debug-register masking: the plugin reads its own thread context and inspects
// the debug registers. Present zeroed debug registers to the plugin and ignore
// its attempts to clear them. Scoped to the plugin via a caller check so the
// host exe's own code can still use them freely.
BOOL WINAPI hk_gtc(HANDLE th, LPCONTEXT c) {
    BOOL r = o_gtc(th, c);
    if (r && c && (c->ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS &&
        caller_is_plugin(_ReturnAddress())) {
        c->Dr0 = c->Dr1 = c->Dr2 = c->Dr3 = 0; c->Dr6 = 0; c->Dr7 = 0;
    }
    return r;
}
BOOL WINAPI hk_stc(HANDLE th, const CONTEXT* c) {
    if (c && (c->ContextFlags & CONTEXT_DEBUG_REGISTERS) && caller_is_plugin(_ReturnAddress())) {
        CONTEXT tmp = *c;
        tmp.ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;  // ignore the plugin's Dr writes
        return o_stc(th, &tmp);
    }
    return o_stc(th, c);
}

// ntdll-level debug-register masking (catches the plugin calling
// NtGetContextThread / NtSetContextThread directly, bypassing the kernelbase
// wrappers).
LONG NTAPI hk_ntgct(HANDLE th, PCONTEXT c) {
    LONG r = o_ntgct(th, c);
    if (c && (c->ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS &&
        caller_is_plugin(_ReturnAddress())) {
        c->Dr0 = c->Dr1 = c->Dr2 = c->Dr3 = 0; c->Dr6 = 0; c->Dr7 = 0;
    }
    return r;
}
LONG NTAPI hk_ntsct(HANDLE th, PCONTEXT c) {
    if (c && (c->ContextFlags & CONTEXT_DEBUG_REGISTERS) && caller_is_plugin(_ReturnAddress())) {
        CONTEXT tmp = *c; tmp.ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
        return o_ntsct(th, &tmp);
    }
    return o_ntsct(th, c);
}

// ---------------------------------------------------------------------------
// Debugger-presence queries. The plugin checks whether a debugger is attached
// before entering its sign path; if it detects one it takes a different path
// that does not run the signing work. Report "no debugger" for the plugin's own
// callers so it proceeds; the host's normal behaviour is untouched.
// ---------------------------------------------------------------------------

// IsDebuggerPresent -> FALSE for the plugin. (Reads PEB->BeingDebugged.)
BOOL WINAPI hk_idp(void) {
    if (caller_is_plugin(_ReturnAddress())) return FALSE;
    return o_idp();
}

// CheckRemoteDebuggerPresent -> *present = FALSE for the plugin.
BOOL WINAPI hk_crdp(HANDLE proc, PBOOL present) {
    BOOL r = o_crdp(proc, present);
    if (present && caller_is_plugin(_ReturnAddress())) *present = FALSE;
    return r;
}

// NtQueryInformationProcess: launder the three debug-related info classes so the
// plugin sees a clean, un-debugged process.
//   ProcessDebugPort         = 7   -> port handle 0
//   ProcessDebugObjectHandle = 0x1e -> handle 0, return STATUS_PORT_NOT_SET
//   ProcessDebugFlags        = 0x1f -> flags 1 (NoDebugInherit clear == not debugged)
LONG NTAPI hk_ntqip(HANDLE proc, ULONG cls, PVOID info, ULONG len, PULONG retlen) {
    LONG r = o_ntqip(proc, cls, info, len, retlen);
    if (!info || !caller_is_plugin(_ReturnAddress())) return r;
    const ULONG ProcessDebugPort = 7, ProcessDebugObjectHandle = 0x1e, ProcessDebugFlags = 0x1f;
    if (cls == ProcessDebugPort && len >= sizeof(ULONG_PTR)) {
        *(ULONG_PTR*)info = 0;
    } else if (cls == ProcessDebugObjectHandle && len >= sizeof(HANDLE)) {
        *(HANDLE*)info = nullptr;
        return (LONG)0xC0000353;  // STATUS_PORT_NOT_SET (no debug object => not debugged)
    } else if (cls == ProcessDebugFlags && len >= sizeof(ULONG)) {
        *(ULONG*)info = 1;        // 1 == inherit-flag set == NOT being debugged
    }
    return r;
}

// Diagnostic: does the plugin spawn a thread per signature? Log creations whose
// caller is the plugin, with the start routine.
LONG WINAPI hk_ncte(PHANDLE hOut, ACCESS_MASK am, void* oa, HANDLE proc, PVOID start,
                    PVOID arg, ULONG flags, SIZE_T zb, SIZE_T ss, SIZE_T ms, void* al) {
    bool plug = caller_is_plugin(_ReturnAddress());
    LONG r = o_ncte(hOut, am, oa, proc, start, arg, flags, zb, ss, ms, al);
    if (plug) {
        int n = g_threads_created.fetch_add(1) + 1;
        logf("NtCreateThreadEx(plugin) #%d start=%p", n, start);
    }
    return r;
}

HMODULE WINAPI hk_gmhw(LPCWSTR name) {
    if (g_self && wants_studio_w(name) && caller_is_plugin(_ReturnAddress())) {
        logf("GetModuleHandleW(plugin, '%ls') -> our module", name ? name : L"(null)");
        return g_self;
    }
    return o_gmhw(name);
}
HMODULE WINAPI hk_gmha(LPCSTR name) {
    if (g_self && wants_studio_a(name) && caller_is_plugin(_ReturnAddress())) {
        logf("GetModuleHandleA(plugin, '%s') -> our module", name ? name : "(null)");
        return g_self;
    }
    return o_gmha(name);
}

bool set_genuine_from_env(const char* env, wchar_t* out_w) {
    const char* v = std::getenv(env);
    if (!v || !*v) return false;
    wchar_t w[MAX_PATH] = {0};
    MultiByteToWideChar(CP_UTF8, 0, v, -1, w, MAX_PATH);
    if (GetFileAttributesW(w) == INVALID_FILE_ATTRIBUTES) {
        logf("warning: %s='%s' does not exist; ignoring", env, v);
        return false;
    }
    wcscpy_s(out_w, MAX_PATH, w);
    return true;
}

// --- Runtime crypto-provider capture (CNG / NCrypt) ------------------------
// The plugin's import table is rebuilt at runtime, so the static IAT does not
// show which RSA provider it uses. Hook the CNG/NCrypt key-import and sign entry
// points: log every call (revealing the provider) and, whenever a PRIVATE RSA
// key blob passes through -- or a signing key can be exported -- read it. If the
// plugin signs via a system provider, this yields the slicer private key
// directly (no heap scan, fully reproducible).
void dump_captured_key(const char* how, const unsigned char* blob, unsigned long len) {
    if (!blob || len < 8) return;
    unsigned magic = *(const unsigned*)blob;
    bool priv = (magic == 0x32415352u /*RSA2*/ || magic == 0x33415352u /*RSA3*/);
    logf("CNG blob via %s: len=%lu magic=0x%08x (%s)", how, len, magic,
         priv ? "RSA PRIVATE" : (magic == 0x31415352u ? "RSA public" : "other"));
    if (!priv) return;
    const char* out = std::getenv("BBL_CNG_CAPTURE");
    char path[512];
    std::snprintf(path, sizeof(path), "%s", (out && out[0]) ? out : "cng_key_blob.bin");
    FILE* f = std::fopen(path, "wb");
    if (f) { std::fwrite(blob, 1, len, f); std::fclose(f);
             logf("*** CAPTURED CNG RSA PRIVATE KEY BLOB (%lu bytes) -> %s ***", len, path); }
}

NTSTATUS (WINAPI *o_BImportKeyPair)(BCRYPT_ALG_HANDLE,BCRYPT_KEY_HANDLE,LPCWSTR,BCRYPT_KEY_HANDLE*,PUCHAR,ULONG,ULONG) = nullptr;
NTSTATUS WINAPI hk_BImportKeyPair(BCRYPT_ALG_HANDLE a,BCRYPT_KEY_HANDLE b,LPCWSTR t,BCRYPT_KEY_HANDLE* k,PUCHAR in,ULONG cin,ULONG fl){
    logf("BCryptImportKeyPair type=%ls cb=%lu plugin=%d", t?t:L"(null)", cin, (int)caller_is_plugin(_ReturnAddress()));
    dump_captured_key("BCryptImportKeyPair", in, cin);
    return o_BImportKeyPair(a,b,t,k,in,cin,fl);
}
NTSTATUS (WINAPI *o_BImportKey)(BCRYPT_ALG_HANDLE,BCRYPT_KEY_HANDLE,LPCWSTR,BCRYPT_KEY_HANDLE*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG) = nullptr;
NTSTATUS WINAPI hk_BImportKey(BCRYPT_ALG_HANDLE a,BCRYPT_KEY_HANDLE b,LPCWSTR t,BCRYPT_KEY_HANDLE* k,PUCHAR ko,ULONG cko,PUCHAR in,ULONG cin,ULONG fl){
    logf("BCryptImportKey type=%ls cb=%lu plugin=%d", t?t:L"(null)", cin, (int)caller_is_plugin(_ReturnAddress()));
    dump_captured_key("BCryptImportKey", in, cin);
    return o_BImportKey(a,b,t,k,ko,cko,in,cin,fl);
}
NTSTATUS (WINAPI *o_BSignHash)(BCRYPT_KEY_HANDLE,VOID*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG*,ULONG) = nullptr;
NTSTATUS WINAPI hk_BSignHash(BCRYPT_KEY_HANDLE hKey,VOID* pad,PUCHAR in,ULONG cin,PUCHAR out,ULONG cout,ULONG* res,ULONG fl){
    logf("*** BCryptSignHash cin=%lu plugin=%d *** (plugin signs via CNG!)", cin, (int)caller_is_plugin(_ReturnAddress()));
    ULONG need=0;
    NTSTATUS s = BCryptExportKey(hKey, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, nullptr, 0, &need, 0);
    if (s==0 && need) {
        std::vector<unsigned char> buf(need);
        if (BCryptExportKey(hKey, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, buf.data(), need, &need, 0)==0)
            dump_captured_key("BCryptSignHash/export", buf.data(), need);
        else logf("BCryptSignHash: export step2 failed");
    } else logf("BCryptSignHash: key not exportable (s=0x%lx need=%lu)", (unsigned long)s, need);
    return o_BSignHash(hKey,pad,in,cin,out,cout,res,fl);
}
SECURITY_STATUS (WINAPI *o_NSignHash)(NCRYPT_KEY_HANDLE,VOID*,PBYTE,DWORD,PBYTE,DWORD,DWORD*,DWORD) = nullptr;
SECURITY_STATUS WINAPI hk_NSignHash(NCRYPT_KEY_HANDLE hKey,VOID* pad,PBYTE h,DWORD ch,PBYTE sig,DWORD csig,DWORD* res,DWORD fl){
    logf("*** NCryptSignHash ch=%lu plugin=%d *** (plugin signs via NCrypt!)", ch, (int)caller_is_plugin(_ReturnAddress()));
    DWORD need=0;
    SECURITY_STATUS s = NCryptExportKey(hKey, 0, BCRYPT_RSAFULLPRIVATE_BLOB, nullptr, nullptr, 0, &need, 0);
    if (s==0 && need) {
        std::vector<unsigned char> buf(need);
        if (NCryptExportKey(hKey, 0, BCRYPT_RSAFULLPRIVATE_BLOB, nullptr, buf.data(), need, &need, 0)==0)
            dump_captured_key("NCryptSignHash/export", buf.data(), need);
        else logf("NCryptSignHash: export step2 failed");
    } else logf("NCryptSignHash: key not exportable (s=0x%lx need=%lu)", (unsigned long)s, need);
    return o_NSignHash(hKey,pad,h,ch,sig,csig,res,fl);
}
SECURITY_STATUS (WINAPI *o_NImportKey)(NCRYPT_PROV_HANDLE,NCRYPT_KEY_HANDLE,LPCWSTR,NCryptBufferDesc*,NCRYPT_KEY_HANDLE*,PBYTE,DWORD,DWORD) = nullptr;
SECURITY_STATUS WINAPI hk_NImportKey(NCRYPT_PROV_HANDLE p,NCRYPT_KEY_HANDLE ik,LPCWSTR t,NCryptBufferDesc* pl,NCRYPT_KEY_HANDLE* k,PBYTE in,DWORD cin,DWORD fl){
    logf("NCryptImportKey type=%ls cb=%lu plugin=%d", t?t:L"(null)", cin, (int)caller_is_plugin(_ReturnAddress()));
    dump_captured_key("NCryptImportKey", in, cin);
    return o_NImportKey(p,ik,t,pl,k,in,cin,fl);
}

bool create(void* target, void* detour, void** orig, const char* label) {
    if (!target) { logf("hook %s: target not found", label); return false; }
    if (MH_CreateHook(target, detour, orig) != MH_OK) {
        logf("hook %s: MH_CreateHook failed", label);
        return false;
    }
    return true;
}

}  // namespace

namespace bbl {

void install_verify_fake() {
    static bool done = false;
    if (done) return;
    done = true;

    if (const char* lp = std::getenv("BBL_SHIM_LOG")) {
        g_log = std::fopen(lp, "w");
    }

    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)&install_verify_fake, &g_self);
    GetModuleFileNameW(g_self,  g_our_self, MAX_PATH);
    GetModuleFileNameW(nullptr, g_our_exe,  MAX_PATH);

    g_have_genuine_dll = set_genuine_from_env("BBL_GENUINE_DLL", g_genuine_dll_w);
    g_have_genuine_exe = set_genuine_from_env("BBL_GENUINE_EXE", g_genuine_exe_w);

    // Auto-default to the installed genuine Bambu Studio binaries (signed by the
    // same publisher as the plugin) if not overridden by env. The plugin
    // Authenticode-verifies these files.
    if (!g_have_genuine_exe) {
        const wchar_t* d = L"C:\\Program Files\\Bambu Studio\\bambu-studio.exe";
        if (GetFileAttributesW(d) != INVALID_FILE_ATTRIBUTES) {
            wcsncpy_s(g_genuine_exe_w, MAX_PATH, d, _TRUNCATE); g_have_genuine_exe = true;
        }
    }
    if (!g_have_genuine_dll) {
        const wchar_t* d = L"C:\\Program Files\\Bambu Studio\\BambuStudio.dll";
        if (GetFileAttributesW(d) != INVALID_FILE_ATTRIBUTES) {
            wcsncpy_s(g_genuine_dll_w, MAX_PATH, d, _TRUNCATE); g_have_genuine_dll = true;
        }
    }

    logf("install: self='%ls' exe='%ls' genuine_dll=%d genuine_exe=%d",
         g_our_self, g_our_exe, (int)g_have_genuine_dll, (int)g_have_genuine_exe);

#if defined(_M_X64)
    // The plugin reads the process image path from the PEB
    // (ProcessParameters->ImagePathName) directly -- bypassing the Win32 path APIs
    // we hook -- then NtCreateFile-opens+hashes that file. Point ImagePathName (and
    // CommandLine) at the user's genuine signed bambu-studio.exe so the Authenticode
    // hash is computed over a signed image. Writing our own PEB is safe (it is data,
    // not code) and independent of which syscall path the plugin uses.
    if (g_have_genuine_exe) {
        struct UNISTR64 { USHORT Length; USHORT MaximumLength; PWSTR Buffer; };
        BYTE* peb = (BYTE*)__readgsqword(0x60);
        BYTE* upp = peb ? *(BYTE**)(peb + 0x20) : nullptr;   // ProcessParameters
        if (upp) {
            static wchar_t genpath[MAX_PATH];
            wcsncpy_s(genpath, MAX_PATH, g_genuine_exe_w, _TRUNCATE);
            USHORT blen = (USHORT)(wcslen(genpath) * sizeof(wchar_t));
            for (size_t off : { (size_t)0x38, (size_t)0x70 }) {   // ImagePathName, CommandLine
                UNISTR64* us = (UNISTR64*)(upp + off);
                us->Buffer = genpath; us->Length = blen;
                us->MaximumLength = (USHORT)(blen + sizeof(wchar_t));
            }
            logf("PEB ImagePathName/CommandLine -> genuine '%ls'", genpath);
        }
        // Also rewrite the PEB->Ldr loaded-module entry for the main exe
        // (InLoadOrderModuleList head -> first LDR_DATA_TABLE_ENTRY): the plugin
        // may read FullDllName straight from the loader data.
        BYTE* ldr = *(BYTE**)(peb + 0x18);              // PEB_LDR_DATA
        if (ldr) {
            BYTE* first = *(BYTE**)(ldr + 0x10);        // InLoadOrderModuleList.Flink (== &entry[0])
            if (first) {
                static wchar_t genpath2[MAX_PATH];
                wcsncpy_s(genpath2, MAX_PATH, g_genuine_exe_w, _TRUNCATE);
                static wchar_t genbase[64]; wcsncpy_s(genbase, 64, L"bambu-studio.exe", _TRUNCATE);
                USHORT flen = (USHORT)(wcslen(genpath2) * sizeof(wchar_t));
                USHORT blen2 = (USHORT)(wcslen(genbase) * sizeof(wchar_t));
                UNISTR64* full = (UNISTR64*)(first + 0x48);   // FullDllName (x64)
                full->Buffer = genpath2; full->Length = flen; full->MaximumLength = (USHORT)(flen + 2);
                UNISTR64* base = (UNISTR64*)(first + 0x58);   // BaseDllName (x64)
                base->Buffer = genbase; base->Length = blen2; base->MaximumLength = (USHORT)(blen2 + 2);
                logf("PEB Ldr[0] FullDllName -> genuine '%ls'", genpath2);
            }
        }
    }
#endif

    // MinHook may already be initialised by another component (death_diag installs
    // its exit hooks first). ALREADY_INITIALIZED is fine -- our hooks still create.
    // Bailing here silently disabled ALL the anti-debug/DR-scrubbing hooks below.
    { MH_STATUS s_ = MH_Initialize();
      if (s_ != MH_OK && s_ != MH_ERROR_ALREADY_INITIALIZED) { logf("MH_Initialize failed (%d)", (int)s_); return; } }

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE c32 = GetModuleHandleW(L"crypt32.dll");
    if (!c32) c32 = LoadLibraryW(L"crypt32.dll");
    HMODULE wt  = GetModuleHandleW(L"wintrust.dll");
    if (!wt)  wt = LoadLibraryW(L"wintrust.dll");

    if (k32) {
        create((void*)GetProcAddress(k32, "GetModuleFileNameW"), (void*)hk_gmfw, (void**)&o_gmfw, "GetModuleFileNameW");
        create((void*)GetProcAddress(k32, "GetModuleFileNameA"), (void*)hk_gmfa, (void**)&o_gmfa, "GetModuleFileNameA");
        create((void*)GetProcAddress(k32, "GetModuleHandleW"),   (void*)hk_gmhw, (void**)&o_gmhw, "GetModuleHandleW");
        create((void*)GetProcAddress(k32, "GetModuleHandleA"),   (void*)hk_gmha, (void**)&o_gmha, "GetModuleHandleA");
        create((void*)GetProcAddress(k32, "CreateFileW"),        (void*)hk_cfw,  (void**)&o_cfw,  "CreateFileW");
        // Image-path acquisition APIs (used to locate the host exe before the
        // Authenticode hash) -> return the genuine signed path.
        if (void* p = (void*)GetProcAddress(k32, "QueryFullProcessImageNameW"))
            create(p, (void*)hk_qfpin, (void**)&o_qfpin, "QueryFullProcessImageNameW");
        if (void* p = (void*)GetProcAddress(k32, "K32GetProcessImageFileNameW"))
            create(p, (void*)hk_gpifw, (void**)&o_gpifw, "K32GetProcessImageFileNameW");
        if (void* p = (void*)GetProcAddress(k32, "K32GetModuleFileNameExW"))
            create(p, (void*)hk_gmfex, (void**)&o_gmfex, "K32GetModuleFileNameExW");
        if (void* p = (void*)GetProcAddress(k32, "K32GetMappedFileNameW"))
            create(p, (void*)hk_gmapw, (void**)&o_gmapw, "K32GetMappedFileNameW");
    }
    if (c32) {
        create((void*)GetProcAddress(c32, "CryptQueryObject"), (void*)hk_cqo, (void**)&o_cqo, "CryptQueryObject");
        create((void*)GetProcAddress(c32, "CertGetCertificateChain"), (void*)hk_cgcc, (void**)&o_cgcc, "CertGetCertificateChain");
        create((void*)GetProcAddress(c32, "CertVerifyCertificateChainPolicy"), (void*)hk_cvccp, (void**)&o_cvccp, "CertVerifyCertificateChainPolicy");
    }
    if (wt) {
        create((void*)GetProcAddress(wt, "WinVerifyTrust"), (void*)hk_wvt, (void**)&o_wvt, "WinVerifyTrust");
        // WinVerifyTrustEx: the plugin's image verification uses it too; without
        // this hook the sign-time verification is not covered even though
        // WinVerifyTrust is.
        void* pex = (void*)GetProcAddress(wt, "WinVerifyTrustEx");
        if (pex) create(pex, (void*)hk_wvtex, (void**)&o_wvtex, "WinVerifyTrustEx");
    }

    // BBL_MINIMAL_HOOKS: install ONLY the load-essential hooks above (module
    // path + crypt32 + WinVerifyTrust). Skip the debugger-presence /
    // debug-register / CNG hooks -- the plugin may detect those inline hooks on
    // the ntdll/kernelbase functions it also uses, and stop building param_enc.
    // Minimal mode is for the heap/freeze capture (no hardware breakpoint, so
    // debug-register masking is not needed).
    bool minimal = std::getenv("BBL_MINIMAL_HOOKS") != nullptr;
    if (minimal) logf("install: MINIMAL hook set (anti-debug/DR/CNG hooks skipped)");

    // Debug-register masking hooks on the real GetThreadContext/SetThreadContext.
    HMODULE kb = minimal ? nullptr : GetModuleHandleW(L"kernelbase.dll");
    if (kb) {
        create((void*)GetProcAddress(kb, "GetThreadContext"), (void*)hk_gtc, (void**)&o_gtc, "GetThreadContext");
        create((void*)GetProcAddress(kb, "SetThreadContext"), (void*)hk_stc, (void**)&o_stc, "SetThreadContext");
    }
    HMODULE nt = minimal ? nullptr : GetModuleHandleW(L"ntdll.dll");
    if (nt) {
        create((void*)GetProcAddress(nt, "NtCreateThreadEx"), (void*)hk_ncte, (void**)&o_ncte, "NtCreateThreadEx");
        create((void*)GetProcAddress(nt, "NtGetContextThread"), (void*)hk_ntgct, (void**)&o_ntgct, "NtGetContextThread");
        create((void*)GetProcAddress(nt, "NtSetContextThread"), (void*)hk_ntsct, (void**)&o_ntsct, "NtSetContextThread");
        create((void*)GetProcAddress(nt, "NtQueryInformationProcess"), (void*)hk_ntqip, (void**)&o_ntqip, "NtQueryInformationProcess");
    }

    // Debugger-presence queries: IsDebuggerPresent / CheckRemoteDebuggerPresent
    // (kernel32).
    if (k32 && !minimal) {
        create((void*)GetProcAddress(k32, "IsDebuggerPresent"), (void*)hk_idp, (void**)&o_idp, "IsDebuggerPresent");
        create((void*)GetProcAddress(k32, "CheckRemoteDebuggerPresent"), (void*)hk_crdp, (void**)&o_crdp, "CheckRemoteDebuggerPresent");
    }

    // Also clear PEB->BeingDebugged directly (some code paths read it inline
    // without an API call). Process-wide, safe -- no external debugger is
    // attached.
#if defined(_M_X64)
    if (!minimal) {
        // TEB at gs:[0x30]; PEB at TEB+0x60; BeingDebugged at PEB+0x02.
        BYTE* peb = (BYTE*)__readgsqword(0x60);
        if (peb) {
            peb[0x02] = 0;                      // BeingDebugged
            // NtGlobalFlag at PEB+0xBC: clear the heap-debug bits.
            DWORD* ngf = (DWORD*)(peb + 0xBC);
            *ngf &= ~0x70;                       // FLG_HEAP_* debug flags
        }
    }
#endif

    // Runtime crypto-provider capture: hook CNG (bcrypt) + NCrypt key-import and
    // sign entry points to detect the plugin's RSA provider and read the key.
    HMODULE bc = minimal ? nullptr : GetModuleHandleW(L"bcrypt.dll"); if (!minimal && !bc) bc = LoadLibraryW(L"bcrypt.dll");
    if (bc) {
        create((void*)GetProcAddress(bc,"BCryptImportKeyPair"),(void*)hk_BImportKeyPair,(void**)&o_BImportKeyPair,"BCryptImportKeyPair");
        create((void*)GetProcAddress(bc,"BCryptImportKey"),    (void*)hk_BImportKey,    (void**)&o_BImportKey,    "BCryptImportKey");
        create((void*)GetProcAddress(bc,"BCryptSignHash"),     (void*)hk_BSignHash,     (void**)&o_BSignHash,     "BCryptSignHash");
    }
    HMODULE nc = minimal ? nullptr : GetModuleHandleW(L"ncrypt.dll"); if (!minimal && !nc) nc = LoadLibraryW(L"ncrypt.dll");
    if (nc) {
        create((void*)GetProcAddress(nc,"NCryptSignHash"),  (void*)hk_NSignHash,  (void**)&o_NSignHash,  "NCryptSignHash");
        create((void*)GetProcAddress(nc,"NCryptImportKey"), (void*)hk_NImportKey, (void**)&o_NImportKey, "NCryptImportKey");
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) { logf("MH_EnableHook failed"); return; }
    logf("install: hooks enabled");
}

}  // namespace bbl

#else  // !_WIN32
namespace bbl { void install_verify_fake() {} }
#endif
