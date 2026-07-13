// One-click Windows extractor for the Bambu slicer RSA-2048 key.
//
// Mirrors the Linux tool's flow but uses the Windows-native method: the plugin
// is loaded in-process (host verification satisfied by the shim), driven to
// materialise its decrypted RSA key into the heap by signing against a LOCAL fake
// printer, then the key is recovered by a blind heap sweep + primality test and
// validated against embedded public signing envelopes. No real printer required.
//
//   bambu_host [--plugin <dll>] [--out <file>] [--dev-id <id>]
//              [--cert-dir <dir>] [--broker <exe>] [--attempts N]
//
// With no --plugin, the DLL is downloaded from the Bambu CDN (same endpoint and
// version as the Linux daemon; see src/plugin_source.h) and cached.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "shim/verify_fake.hpp"
#include "bambu/BambuNetworkingPluginHandle.hpp"
#include "host/known_scan.hpp"
#include "host/plugin_fetch.hpp"
#include "host/test_envelopes.h"
#include "host/verdict_flip.hpp"
#include "host/cloud_tap.hpp"
#include "host/rng_tap.hpp"
#include "host/aes_tap.hpp"
#include "host/instr_cb.hpp"
#include "host/app_key_sweep.hpp"
#include "host/death_diag.hpp"
#include "host/dump_regions.hpp"
#include "host/lan_discover.hpp"
#include "reconstruct.h"
#include "bigint.h"

using Slic3r::bambu::BambuNetworkingPluginHandle;
using Slic3r::bambu::PluginHandleConfig;

namespace bbl { int find_log_key(const char* logpath, const char* keyout = nullptr); int find_config_key(const char* confpath, const char* outpath); }
namespace bbl { int run_get_app_cert(const char* conf_path, const char* config_key,
                                     const char* app_identity, const char* out_dir, const char* api_host); }
namespace bbl { std::string scan_app_identity(); }

// Verification push-site frames captured by the plugin-message callback on the
// first 'unsigned_studio' push (defined in BambuNetworkingPluginHandle.cpp).
namespace Slic3r { namespace bambu {
extern std::vector<unsigned long long> g_unsigned_studio_plugin_frames;
extern bool g_unsigned_studio_captured;
}}

namespace {

const char* arg_value(int argc, char** argv, const char* key, const char* dflt) {
    for (int i = 1; i + 1 < argc; ++i)
        if (std::strcmp(argv[i], key) == 0) return argv[i + 1];
    return dflt;
}
bool has_flag(int argc, char** argv, const char* key) {
    for (int i = 1; i < argc; ++i) if (!std::strcmp(argv[i], key)) return true;
    return false;
}

// Invoke the plugin's get_device_security_sign directly (a nullary member
// returning std::string: rcx=secctx, rdx=&ret). out32 is 32 zeroed bytes shaped
// as an MSVC std::string; on return it holds the value. SEH-guarded so a wrong
// secctx faults cleanly instead of crashing the probe. No C++ objects here so
// __try is legal. Returns false on fault.
static bool sign_probe_call(void* fn, void* secctx, unsigned char* out32) {
    __try {
        reinterpret_cast<void(*)(void*, void*)>(fn)(secctx, out32);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// SEH-guarded byte scan of one committed region for a literal needle. Writes the
// addresses of matches into out[]. A faulting read (guard page mid-region) just
// ends this region's scan. Raw pointers only, so __try is legal. Returns count.
static int scan_region_needle(unsigned char* b, size_t n, const char* needle, size_t nl, void** out, int maxout) {
    int cnt = 0;
    __try {
        for (size_t i = 0; i + nl <= n && cnt < maxout; ++i) {
            if (b[i] == (unsigned char)needle[0] && std::memcmp(b + i, needle, nl) == 0)
                out[cnt++] = (void*)(b + i);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return cnt;
}

// SEH-read the MSVC std::string size/capacity words that would sit at h+0x10 / h+0x18.
static void read_str_envelope(void* h, size_t* sz, size_t* cp) {
    *sz = 0; *cp = 0;
    __try { *sz = *(size_t*)((char*)h + 0x10); *cp = *(size_t*)((char*)h + 0x18); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// SEH-guarded scan of one region for an 8-byte pointer value (finds objects that
// point at a known heap buffer). Writes match addresses into out[]. Returns count.
static int scan_region_qword(unsigned char* b, size_t n, uint64_t target, void** out, int maxout) {
    int cnt = 0;
    __try {
        for (size_t i = 0; i + 8 <= n && cnt < maxout; i += 8)
            if (*(uint64_t*)(b + i) == target) out[cnt++] = (void*)(b + i);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return cnt;
}

// Invoke a nullary member returning std::string (rcx=this, rdx=&ret). Copies up to
// cap-1 bytes of the result into out (NUL-terminated); returns length (0 if empty
// or faulted). No C++ objects here, so __try is legal.
static size_t call_str_member(void* fn, void* thisp, char* out, size_t cap) {
    unsigned char s32[32];
    __try {
        std::memset(s32, 0, sizeof s32);
        reinterpret_cast<void(*)(void*, void*)>(fn)(thisp, s32);
        size_t len = *(size_t*)(s32 + 16), c = *(size_t*)(s32 + 24);
        const char* data = (c <= 15) ? (const char*)s32 : *(const char**)s32;
        if (len == 0 || len > 8192) return 0;
        size_t k = len < cap - 1 ? len : cap - 1;
        std::memcpy(out, data, k); out[k] = 0;
        return len;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// ---- verification-check probe / override (DR execute-BPs, no code write) ------
// The LAN sign path calls the check at 0x22f160 (rcx=secctx) then branches on
// `test al,al`. get_device_security_sign (0x22acd0) is virtualized; this measures
// whether that sign ALSO routes through the same check (0x22f160 / wrapper
// 0x18d080), and can make the check report success by emulating `*out=1;return 1`
// from a VEH. A vectored handler is used because the plugin .text is read-only.
static uint64_t     g_gbp[4]   = {0, 0, 0, 0};  // 0=control 1=verify 2=wrapper 3=key data-BP
static bool         g_bp_data[4] = {false, false, false, false};  // true => read/write data BP
static volatile long g_ghits[4] = {0, 0, 0, 0};
static uint64_t     g_gra[4]   = {0, 0, 0, 0};   // exec: caller RA; data: RIP that accessed
static volatile long g_force_idx = -1;           // index of BP to force return-1, else -1
static uint64_t     g_key_addr = 0;              // resident app-key limb address (data BP)
static volatile bool g_in_sign = false;          // true only while the sign call runs
static volatile bool g_kcap    = false;          // captured the first key-read context yet?
static uint64_t      g_pl_base = 0, g_pl_end = 0; // plugin image span (skip VM-internal reads)
static uint64_t      g_kreg[18];                 // regs at first key-read (rax..r15,rip,rsp,[rsp])
static unsigned char g_kbuf[18][256];            // 256 bytes each register points at
static LONG CALLBACK gate_veh(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT* c = ep->ContextRecord;
    for (int i = 0; i < 4; ++i) {
        bool match = g_gbp[i] && (g_bp_data[i] ? ((c->Dr6 & (1u << i)) != 0) : (c->Rip == g_gbp[i]));
        if (match) {
            InterlockedIncrement(&g_ghits[i]);
            g_gra[i] = g_bp_data[i] ? c->Rip : *(uint64_t*)c->Rsp;
            if (g_bp_data[i]) {
                bool real_code = g_pl_end && (c->Rip < g_pl_base || c->Rip >= g_pl_end);  // outside plugin
                if (g_in_sign && real_code) InterlockedIncrement(&g_ghits[2]);  // reuse [2] as ext-read counter
                if (g_in_sign && !g_kcap && real_code) {   // snapshot standard modexp operands
                    uint64_t r[18] = { c->Rax,c->Rbx,c->Rcx,c->Rdx,c->Rsi,c->Rdi,c->Rbp,c->R8,c->R9,
                                       c->R10,c->R11,c->R12,c->R13,c->R14,c->R15,c->Rip,c->Rsp,*(uint64_t*)c->Rsp };
                    for (int j = 0; j < 18; ++j) {
                        g_kreg[j] = r[j];
                        __try { std::memcpy(g_kbuf[j], (void*)r[j], 256); }
                        __except (EXCEPTION_EXECUTE_HANDLER) { std::memset(g_kbuf[j], 0, 256); }
                    }
                    g_kcap = true;
                }
                c->Dr6 = 0; c->EFlags |= 0x10000; return EXCEPTION_CONTINUE_EXECUTION;
            }
            if (g_force_idx == i) {
                uint64_t out = *(uint64_t*)(c->Rsp + 0x28);   // 5th arg = out byte ptr
                __try { if (out) *(unsigned char*)out = 1; } __except (EXCEPTION_EXECUTE_HANDLER) {}
                c->Rax = (c->Rax & ~0xFFull) | 1;             // return 1 (verified)
                c->Rip = *(uint64_t*)c->Rsp; c->Rsp += 8;     // emulate ret
            } else {
                c->EFlags |= 0x10000;                         // RF: run the insn, don't re-trap
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
static void gate_arm_current_thread() {
    CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &c);
    c.Dr0 = g_gbp[0]; c.Dr1 = g_gbp[1]; c.Dr2 = g_gbp[2]; c.Dr3 = g_gbp[3];
    uint64_t dr7 = 0;
    for (int i = 0; i < 4; ++i) if (g_gbp[i]) {
        dr7 |= (1ull << (i * 2));                              // Li local enable
        if (g_bp_data[i]) dr7 |= (0b1111ull << (16 + i * 4));  // rw=11 (r/w), len=11 (8 bytes)
        // else exec: rw=00, len=00
    }
    c.Dr7 = dr7; c.Dr6 = 0; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext(GetCurrentThread(), &c);
}

// SEH-guarded scan of one region for a 12-14 digit ASCII run parsing to a ms-timestamp
// in [lo,hi]. Prints each hit with +/-32 bytes of context so the message structure shows.
static int scan_region_timestamp(unsigned char* b, size_t n, uint64_t lo, uint64_t hi, int maxhit) {
    int hits = 0;
    __try {
        for (size_t i = 0; i + 12 <= n && hits < maxhit; ) {
            if (b[i] < '0' || b[i] > '9') { ++i; continue; }
            size_t j = i; while (j < n && b[j] >= '0' && b[j] <= '9') ++j;
            size_t len = j - i;
            if (len >= 12 && len <= 14) {
                uint64_t v = 0; for (size_t k = i; k < j; ++k) v = v * 10 + (b[k] - '0');
                if (v >= lo && v <= hi) {
                    // Is this a bare std::string(str(ms))? SSO: data inline, size@+0x10, cap@+0x18.
                    long long ssz = -1, scap = -1;
                    if (i + 0x20 <= n) { ssz = *(long long*)(b + i + 0x10); scap = *(long long*)(b + i + 0x18); }
                    char hex[160]; int p = 0; size_t s = i > 24 ? i - 24 : 0;
                    for (size_t k = s; k < j + 16 && k < n && p < 156; k += 1) p += std::snprintf(hex + p, 4, "%02x", b[k]);
                    std::fprintf(stderr, "[sign] TS-hit %llu @%p len=%zu sso[size=%lld cap=%lld]%s hex=%s\n",
                                 (unsigned long long)v, (void*)(b + i), len, ssz, scap,
                                 (ssz == (long long)len && scap == 15) ? " <= BARE std::string(str(ms))!" : "", hex);
                    ++hits;
                }
            }
            i = j;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return hits;
}
static void scan_heap_for_timestamp(uint64_t now_ms) {
    uint64_t lo = now_ms - 120000, hi = now_ms + 5000; int found = 0;
    MEMORY_BASIC_INFORMATION mbi{};
    for (unsigned char* a = nullptr; VirtualQuery(a, &mbi, sizeof mbi) && found < 60; a = (unsigned char*)mbi.BaseAddress + mbi.RegionSize) {
        if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE) continue;
        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) continue;
        DWORD pr = mbi.Protect & 0xFF;
        if (pr != PAGE_READWRITE && pr != PAGE_WRITECOPY && pr != PAGE_EXECUTE_READWRITE) continue;
        if (mbi.RegionSize > (256u << 20)) continue;
        found += scan_region_timestamp((unsigned char*)mbi.BaseAddress, mbi.RegionSize, lo, hi, 60 - found);
    }
    std::fprintf(stderr, "[sign] timestamp scan: %d hit(s) in [%llu,%llu]\n", found,
                 (unsigned long long)lo, (unsigned long long)hi);
}

// Load hex "label window" lines and scan committed private heap for each window.
static void scan_known_primes(const char* path) {
    std::FILE* f = std::fopen(path, "r");
    if (!f) { std::fprintf(stderr, "[sign] (no prime file %s)\n", path); return; }
    char label[32]; char hex[128];
    while (std::fscanf(f, "%31s %127s", label, hex) == 2) {
        unsigned char needle[64]; size_t nl = 0;
        for (size_t i = 0; hex[i] && hex[i+1] && nl < sizeof needle; i += 2) {
            auto nib = [](char ch){ return (ch>='0'&&ch<='9')?ch-'0':(ch|0x20)-'a'+10; };
            needle[nl++] = (unsigned char)((nib(hex[i]) << 4) | nib(hex[i+1]));
        }
        long hits = 0;
        MEMORY_BASIC_INFORMATION mbi{};
        for (unsigned char* a = nullptr; VirtualQuery(a, &mbi, sizeof mbi); a = (unsigned char*)mbi.BaseAddress + mbi.RegionSize) {
            if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE) continue;
            if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) continue;
            DWORD pr = mbi.Protect & 0xFF;
            if (pr != PAGE_READWRITE && pr != PAGE_WRITECOPY && pr != PAGE_EXECUTE_READWRITE) continue;
            if (mbi.RegionSize > (256u << 20)) continue;
            void* hit[8];
            int k = scan_region_needle((unsigned char*)mbi.BaseAddress, mbi.RegionSize, (const char*)needle, nl, hit, 8);
            hits += k;
            // Record a key limb address for a data BP. The window is at offset 40 into the
            // 128-byte LE prime; back it up to the prime start (8-aligned) to BP a live limb.
            if (k > 0 && !g_key_addr && std::strcmp(label, "p_le") == 0)
                g_key_addr = ((uint64_t)hit[0] - 40) & ~7ull;
        }
        std::fprintf(stderr, "[sign] residency %-5s hits=%ld%s\n", label, hits,
                     (g_key_addr && std::strcmp(label, "p_le") == 0) ? "  (key BP anchor set)" : "");
    }
    std::fclose(f);
}

// SEH-guarded write of the studio-verified flag (a .data byte). Returns prior value.
static uint8_t write_verified_flag(volatile uint8_t* flag) {
    uint8_t before = 0;
    __try { before = *flag; *flag = 1; } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return before;
}

// The signing trigger driven continuously by blind_extract's background thread.
// install_device_cert makes the plugin decrypt + use the slicer RSA key, which
// materialises p/q/dp/dq/d/N in the heap.
struct SignCtx { BambuNetworkingPluginHandle* h; std::string dev; };
void trigger_fn(void* p) {
    auto* s = static_cast<SignCtx*>(p);
    s->h->set_user_selected_machine(s->dev);
    // install_device_cert arms the enc_msg gate and drives the slicer-key path;
    // the gcode_file print command is the privileged signed command. NOTE: on
    // this build the plugin rejects print.* with rc=-2 headless.
    s->h->install_device_cert(s->dev, false);
    // The slicer key is exercised only by a PRIVILEGED print.* command whose
    // param is encrypted (param->param_enc) and then RSA-signed. `gcode_line`
    // (M105) is NOT signed. The Linux LanUplink uses a
    // print.command=gcode_file referencing a NON-EXISTENT file (no real print
    // starts, but the plugin still builds the encrypted+signed envelope, which
    // decrypts+uses the RSA private key). Mirror it exactly.
    static unsigned long seq = 100000;
    unsigned long long r = ((unsigned long long)std::rand() << 32) ^
                           ((unsigned long long)std::rand() << 16) ^ (unsigned long long)seq;
    char fname[80];
    std::snprintf(fname, sizeof(fname), "net_nonexistent_%016llx.gcode.3mf", r);
    // The signing trigger: print.command=ams_filament_setting. This exercises the
    // slicer RSA key. No file, no FTPS. gcode_file does not sign; this command
    // does.
    (void)fname;
    char buf[512];
    std::snprintf(buf, sizeof(buf),
        "{\"print\":{\"command\":\"ams_filament_setting\",\"sequence_id\":\"%lu\","
        "\"ams_id\":0,\"slot_id\":0,\"tray_id\":0,\"tray_info_idx\":\"GFL96\","
        "\"setting_id\":\"PFB67E5CD6E2C7C7B5\",\"tray_color\":\"%s\","
        "\"nozzle_temp_min\":190,\"nozzle_temp_max\":240,\"tray_type\":\"PLA\"}}",
        seq++, (seq & 1) ? "FF00FFAA" : "0000FFAA");
    int rc = s->h->send_message_to_printer(s->dev, buf, 1);
    if ((seq % 30) == 0)
        std::fprintf(stderr, "[host] trigger ams_filament_setting seq=%lu send rc=%d\n", seq, rc);
}

// Case-insensitive substring search.
bool contains_ci(const std::string& hay, const std::string& needle) {
    if (needle.empty()) return true;
    auto it = std::search(hay.begin(), hay.end(), needle.begin(), needle.end(),
        [](char a, char b){ return std::tolower((unsigned char)a) == std::tolower((unsigned char)b); });
    return it != hay.end();
}

// Extract a short window around the first case-insensitive occurrence of `needle`.
std::string window_around(const std::string& hay, const std::string& needle, size_t pad) {
    auto it = std::search(hay.begin(), hay.end(), needle.begin(), needle.end(),
        [](char a, char b){ return std::tolower((unsigned char)a) == std::tolower((unsigned char)b); });
    if (it == hay.end()) return {};
    size_t pos = (size_t)(it - hay.begin());
    size_t s = pos > pad ? pos - pad : 0;
    size_t e = std::min(hay.size(), pos + needle.size() + pad);
    return hay.substr(s, e - s);
}

// Fetch the account's cloud device list via the plugin's HTTPS bindpath and
// report whether the target serial appears + its online/bind status. This is
// the authoritative check for "is the H2S cloud-online and bound to this
// account", which the plugin requires before it will route+sign a command via
// the cloud relay.
struct PrintInfoResult {
    bool  called      = false;
    bool  ok          = false;   // plugin returned success (http 2xx)
    unsigned http_code = 0;
    bool  serial_seen = false;
    bool  online      = false;   // "online":true near the serial (best-effort)
    std::string body;
};

PrintInfoResult probe_print_info(BambuNetworkingPluginHandle& handle,
                                 const std::string& serial) {
    PrintInfoResult r;
    r.called = true;
    unsigned http = 0;
    std::string body;
    // The plugin performs a blocking HTTPS GET to the Bambu cloud
    // (api.bambulab.com /v1/iot-service/api/user/bind). Retry a few times to
    // ride out transient failures (the cloud is shared with another agent).
    for (int attempt = 0; attempt < 4; ++attempt) {
        http = 0; body.clear();
        r.ok = handle.get_user_print_info(&http, &body);
        r.http_code = http;
        r.body = body;
        std::fprintf(stderr, "[print-info] attempt %d: ok=%d http_code=%u body_len=%zu\n",
                     attempt, (int)r.ok, http, body.size());
        if (r.ok && !body.empty()) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    }
    // Dump the (possibly large) body so the device list is visible.
    if (!r.body.empty()) {
        std::fprintf(stderr, "[print-info] --- body begin ---\n%.*s\n[print-info] --- body end ---\n",
                     (int)std::min<size_t>(r.body.size(), 8000), r.body.c_str());
    }
    if (!serial.empty() && contains_ci(r.body, serial)) {
        r.serial_seen = true;
        std::string win = window_around(r.body, serial, 200);
        std::fprintf(stderr, "[print-info] serial %s FOUND in device list; context:\n  %s\n",
                     serial.c_str(), win.c_str());
        // Best-effort online detection: the cloud device-list uses "dev_online".
        if (contains_ci(win, "\"dev_online\":true") || contains_ci(win, "\"dev_online\": true") ||
            contains_ci(win, "\"online\":true")     || contains_ci(win, "\"online\": true"))
            r.online = true;
        std::fprintf(stderr, "[print-info] serial online (best-effort) = %d\n", (int)r.online);
    } else if (!serial.empty()) {
        std::fprintf(stderr, "[print-info] serial %s NOT found in device list "
                     "(device not bound to this account, or list not returned)\n",
                     serial.c_str());
    }
    return r;
}

bool spawn_broker(const std::string& exe, const char* dev_id, const std::string& cert_out,
                  PROCESS_INFORMATION& pi) {
    std::string cmd = "\"" + exe + "\" --dev-id " + dev_id +
                      " --port 8883 --cert-out \"" + cert_out + "\"";
    STARTUPINFOA si{}; si.cb = sizeof(si);
    std::string mut = cmd;
    if (!CreateProcessA(nullptr, mut.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
        std::fprintf(stderr, "[host] failed to spawn broker (err=%lu)\n", GetLastError());
        return false;
    }
    std::fprintf(stderr, "[host] fake printer (broker) pid=%lu\n", pi.dwProcessId);
    return true;
}

std::string exe_dir() {
    char buf[MAX_PATH];
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string s(buf);
    size_t p = s.find_last_of("\\/");
    return p == std::string::npos ? std::string(".") : s.substr(0, p);
}

bool exists(const std::string& p) {
    return GetFileAttributesA(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}

// Walk up from `start`, returning the first existing `start/.../rel`.
std::string find_up(std::string start, const char* rel, int levels) {
    for (int i = 0; i <= levels; ++i) {
        std::string cand = start + "\\" + rel;
        if (exists(cand)) return cand;
        size_t p = start.find_last_of("\\/");
        if (p == std::string::npos) break;
        start = start.substr(0, p);
    }
    return {};
}

// Terminate every process with image name `image` except our own PID. --auto uses
// this to clear stragglers (previous worker + broker) so each attempt starts clean
// (each attempt wants a fresh plugin map).
void kill_by_name(const char* image) {
    DWORD self = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID != self && _stricmp(pe.szExeFile, image) == 0) {
                HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (h) { TerminateProcess(h, 1); CloseHandle(h); }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}
bool proc_running(const char* image) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32First(snap, &pe)) {
        do { if (_stricmp(pe.szExeFile, image) == 0) { found = true; break; } }
        while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}
std::string abspath(const std::string& p) {
    char full[MAX_PATH];
    DWORD n = GetFullPathNameA(p.c_str(), MAX_PATH, full, nullptr);
    return (n > 0 && n < MAX_PATH) ? std::string(full) : p;
}

// --auto: one-shot supervisor. Resolves (or downloads) the plugin, locates the
// broker + report, then spawns FRESH `bambu_host --flip-gate` worker children in a
// retry loop until one writes a validated key. A single self-contained command:
//   bambu_host --auto  [--plugin <dll>] [--out <file>] [--attempts N] [--kill-studio]
int run_auto(int argc, char** argv, const std::string& ed) {
    char self[MAX_PATH]; GetModuleFileNameA(nullptr, self, MAX_PATH);
    const char* dev = arg_value(argc, argv, "--dev-id", "01S00A2B3C4D5E6");

    // Plugin: --plugin arg -> (--plugin-version CDN download) -> %APPDATA% install -> CDN default.
    std::string plugin = arg_value(argc, argv, "--plugin", "");
    if (plugin.empty()) {
        const char* ad = std::getenv("APPDATA");
        if (ad) {
            std::string cand = std::string(ad) + "\\BambuStudio\\plugins\\bambu_networking.dll";
            if (exists(cand)) plugin = cand;
        }
    }
    if (plugin.empty()) {
        // Use a previously-fetched cache, but do NOT download here: keep the
        // network fetch a separate, explicit, visible step (--fetch-plugin) so a
        // run does not download in the same process.
        std::string cached = bbl::cached_plugin_path(arg_value(argc, argv, "--plugin-version", ""));
        if (!cached.empty() && exists(cached)) plugin = cached;
    }
    if (plugin.empty() || !exists(plugin)) {
        std::fprintf(stderr,
            "[auto] no plugin DLL found. Fetch it once (separately) with:\n"
            "         bambu_host --fetch-plugin [--plugin-version X]\n"
            "       then re-run --auto, or pass --plugin <path>.\n");
        return 2;
    }

    // Broker (prefer the working fake_broker2.exe).
    std::string broker = arg_value(argc, argv, "--broker", "");
    if (broker.empty()) {
        const char* names[] = {"fake_broker2.exe", "broker\\fake_broker2.exe",
                                "win\\broker\\fake_broker2.exe", "fake_broker.exe",
                                "broker\\fake_broker.exe", "win\\broker\\fake_broker.exe"};
        for (const char* n : names) { std::string c = find_up(ed, n, 6); if (!c.empty()) { broker = c; break; } }
    }
    if (broker.empty() || !exists(broker)) { std::fprintf(stderr, "[auto] cannot find fake_broker2.exe (give --broker)\n"); return 2; }

    // cert-dir (dir holding slicer_base64.cer) -- optional; worker re-resolves too.
    std::string cert = arg_value(argc, argv, "--cert-dir", "");
    if (cert.empty()) {
        std::string cf = find_up(ed, "resources\\cert\\slicer_base64.cer", 6);
        if (cf.empty()) cf = find_up(ed, "win\\resources\\cert\\slicer_base64.cer", 6);
        if (!cf.empty()) cert = cf.substr(0, cf.find_last_of("\\/"));
    }

    // Report carrying the enc-enable `fun` token (required for the sign to route).
    std::string report;
    if (const char* e = std::getenv("BAMBU_FAKE_REPORT")) report = e;
    if (report.empty() || !exists(report)) {
        std::string r = find_up(ed, "real_report.json", 2);
        if (r.empty()) r = find_up(ed, "build\\real_report.json", 6);
        if (r.empty()) r = find_up(ed, "win\\build\\real_report.json", 6);
        report = r;
    }
    if (report.empty() || !exists(report)) {
        std::fprintf(stderr, "[auto] cannot find real_report.json (the 23KB report with the `fun` token)\n"); return 2;
    }

    // Capture env inherited by every worker child.
    SetEnvironmentVariableA("BAMBU_FAKE_REPORT", report.c_str());
    SetEnvironmentVariableA("BBL_NO_FREEZE", "1");
    SetEnvironmentVariableA("BBL_REARM_MS", "50");
    if (!std::getenv("BBL_GATE_REGION_MB")) SetEnvironmentVariableA("BBL_GATE_REGION_MB", "4");
    // Keep each worker alive past an unexpected early exit so the sweep gets many
    // passes per attempt.
    if (!std::getenv("BBL_BLOCK_WATCHDOG")) SetEnvironmentVariableA("BBL_BLOCK_WATCHDOG", "1");

    std::string base = arg_value(argc, argv, "--work-dir", ".");
    if (base == ".") base = ed + "\\auto_runs";
    base = abspath(base);
    CreateDirectoryA(base.c_str(), nullptr);
    std::string canonical_out = abspath(arg_value(argc, argv, "--out", "slicer_key_windows.txt"));
    const int max_runs = std::atoi(arg_value(argc, argv, "--attempts", "15"));
    const bool kill_studio = has_flag(argc, argv, "--kill-studio");

    std::fprintf(stderr, "[auto] plugin=%s\n[auto] broker=%s\n[auto] report=%s\n[auto] out=%s\n[auto] up to %d attempts\n",
                 plugin.c_str(), broker.c_str(), report.c_str(), canonical_out.c_str(), max_runs);
    if (proc_running("bambu-studio.exe")) {
        if (kill_studio) { std::fprintf(stderr, "[auto] closing running bambu-studio.exe for a clean slate\n"); kill_by_name("bambu-studio.exe"); }
        else std::fprintf(stderr, "[auto] WARNING: bambu-studio.exe is running -- close it (or pass --kill-studio) for best reliability\n");
    }

    // --- (0) Config/AES key (network_engine.key): deterministic, ONE-shot. ---
    // It's a persistent global constant resident in the plugin from init, so a
    // single worker recovers it byte-exact (no retry loop, unlike the RSA p/q).
    std::string config_key_out;
    {
        kill_by_name("fake_broker2.exe"); kill_by_name("fake_broker.exe"); Sleep(300);
        std::string cwork = base + "\\config_key_run";
        CreateDirectoryA(cwork.c_str(), nullptr);
        std::string cout = cwork + "\\config_key.txt";
        std::string clog = cwork + "\\config.err";
        std::string ccmd = "\"" + std::string(self) + "\""
            + " --plugin \"" + plugin + "\""
            + " --dev-id " + dev
            + " --broker \"" + broker + "\""
            + (cert.empty() ? std::string() : (" --cert-dir \"" + cert + "\""))
            + " --work-dir \"" + cwork + "\""
            + " --out \"" + cout + "\""
            + " --cloud-settle 3 --find-config-key";
        std::fprintf(stderr, "[auto] (0) recovering config key (network_engine.key)...\n");
        SECURITY_ATTRIBUTES sa{}; sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE;
        HANDLE hlog = CreateFileA(clog.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        STARTUPINFOA si{}; si.cb = sizeof(si);
        if (hlog != INVALID_HANDLE_VALUE) { si.dwFlags |= STARTF_USESTDHANDLES; si.hStdError = hlog; si.hStdOutput = hlog; si.hStdInput = GetStdHandle(STD_INPUT_HANDLE); }
        PROCESS_INFORMATION pi{}; std::string mut = ccmd;
        if (CreateProcessA(nullptr, mut.data(), nullptr, nullptr, TRUE, 0, nullptr, cwork.c_str(), &si, &pi)) {
            if (WaitForSingleObject(pi.hProcess, 120000) == WAIT_TIMEOUT) { TerminateProcess(pi.hProcess, 1); WaitForSingleObject(pi.hProcess, 5000); }
            CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        } else {
            std::fprintf(stderr, "[auto] failed to spawn config-key worker (err=%lu)\n", GetLastError());
        }
        if (hlog != INVALID_HANDLE_VALUE) CloseHandle(hlog);
        if (exists(cout)) {
            std::string cdir = canonical_out.substr(0, canonical_out.find_last_of("\\/"));
            config_key_out = (cdir.empty() ? std::string(".") : cdir) + "\\network_engine_key.txt";
            CopyFileA(cout.c_str(), config_key_out.c_str(), FALSE);
            std::fprintf(stderr, "[auto] *** CONFIG KEY recovered -> %s ***\n", config_key_out.c_str());
            if (FILE* kf = std::fopen(cout.c_str(), "rb")) { char b[512]; size_t n = std::fread(b, 1, sizeof(b) - 1, kf); b[n] = 0; std::fclose(kf); std::fprintf(stderr, "%s\n", b); }
        } else {
            std::fprintf(stderr, "[auto] WARNING: config key not recovered (continuing to RSA capture)\n");
        }
    }

    for (int i = 1; i <= max_runs; ++i) {
        kill_by_name("fake_broker2.exe");
        kill_by_name("fake_broker.exe");
        if (kill_studio) kill_by_name("bambu-studio.exe");
        Sleep(300);

        char wbuf[64]; std::snprintf(wbuf, sizeof(wbuf), "\\run_auto%d", i);
        std::string work = base + wbuf;
        CreateDirectoryA(work.c_str(), nullptr);
        std::string outf = work + "\\live_key.txt";
        std::string logf = work + "\\auto.err";

        std::string cmd = "\"" + std::string(self) + "\""
            + " --plugin \"" + plugin + "\""
            + " --dev-id " + dev
            + " --broker \"" + broker + "\""
            + (cert.empty() ? std::string() : (" --cert-dir \"" + cert + "\""))
            + " --work-dir \"" + work + "\""
            + " --out \"" + outf + "\""
            + " --cloud-settle 3 --scan-budget-ms 3000 --scan-passes 8 --sign-sleep-ms 1 --flip-gate";

        std::fprintf(stderr, "[auto] attempt %d/%d -> %s\n", i, max_runs, work.c_str());
        SECURITY_ATTRIBUTES sa{}; sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE;
        HANDLE hlog = CreateFileA(logf.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        STARTUPINFOA si{}; si.cb = sizeof(si);
        if (hlog != INVALID_HANDLE_VALUE) { si.dwFlags |= STARTF_USESTDHANDLES; si.hStdError = hlog; si.hStdOutput = hlog; si.hStdInput = GetStdHandle(STD_INPUT_HANDLE); }
        PROCESS_INFORMATION pi{}; std::string mut = cmd;
        if (!CreateProcessA(nullptr, mut.data(), nullptr, nullptr, TRUE, 0, nullptr, work.c_str(), &si, &pi)) {
            std::fprintf(stderr, "[auto] failed to spawn worker (err=%lu)\n", GetLastError());
            if (hlog != INVALID_HANDLE_VALUE) CloseHandle(hlog);
            continue;
        }
        DWORD w = WaitForSingleObject(pi.hProcess, 180000);
        if (w == WAIT_TIMEOUT) { TerminateProcess(pi.hProcess, 1); WaitForSingleObject(pi.hProcess, 5000); }
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        if (hlog != INVALID_HANDLE_VALUE) CloseHandle(hlog);

        if (exists(outf)) {
            CopyFileA(outf.c_str(), canonical_out.c_str(), FALSE);
            std::fprintf(stderr, "[auto] *** KEY CAPTURED on attempt %d ***\n", i);
            if (FILE* kf = std::fopen(outf.c_str(), "rb")) {
                char buf[4096]; size_t n = std::fread(buf, 1, sizeof(buf) - 1, kf); buf[n] = 0; std::fclose(kf);
                std::fprintf(stderr, "%s\n", buf);
            }
            std::fprintf(stderr, "[auto] SUCCESS: slicer key -> %s\n", canonical_out.c_str());
            if (!config_key_out.empty()) std::fprintf(stderr, "[auto] SUCCESS: config key -> %s\n", config_key_out.c_str());
            kill_by_name("fake_broker2.exe"); kill_by_name("fake_broker.exe");
            return 0;
        }
        std::fprintf(stderr, "[auto] attempt %d: no key (worker ended); retrying fresh\n", i);
    }
    kill_by_name("fake_broker2.exe"); kill_by_name("fake_broker.exe");
    std::fprintf(stderr, "[auto] FAILED after %d attempts: no validated key recovered. "
                 "Retry with a freshly started plugin/host, or use --from-disk.\n", max_runs);
    return 2;
}

// Spawn `cmd` in `work` with stdout+stderr redirected to `logpath`. A capture
// worker parks its own exiting thread (the early process-exit block) so it does not
// terminate cleanly on success; therefore we poll for `success_file` and, once it
// appears, kill the (now idle) worker rather than waiting out timeout_ms. Returns
// 0 if the file was produced, 1 on timeout, -1 on spawn failure.
static int run_worker(const std::string& cmd, const std::string& work,
                      const std::string& logpath, DWORD timeout_ms,
                      const std::string& success_file) {
    SECURITY_ATTRIBUTES sa{}; sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE;
    HANDLE hlog = CreateFileA(logpath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    STARTUPINFOA si{}; si.cb = sizeof(si);
    if (hlog != INVALID_HANDLE_VALUE) {
        si.dwFlags |= STARTF_USESTDHANDLES;
        si.hStdError = hlog; si.hStdOutput = hlog; si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    }
    PROCESS_INFORMATION pi{}; std::string mut = cmd; int rc = -1;
    if (CreateProcessA(nullptr, mut.data(), nullptr, nullptr, TRUE, 0, nullptr, work.c_str(), &si, &pi)) {
        const DWORD step = 500; DWORD waited = 0; rc = 1;
        for (;;) {
            if (WaitForSingleObject(pi.hProcess, step) == WAIT_OBJECT_0) {   // exited on its own
                rc = exists(success_file) ? 0 : 1; break;
            }
            waited += step;
            if (exists(success_file)) {                                     // done; worker is parked
                Sleep(400);                                                 // let the file flush
                TerminateProcess(pi.hProcess, 0); WaitForSingleObject(pi.hProcess, 3000);
                rc = 0; break;
            }
            if (waited >= timeout_ms) {
                TerminateProcess(pi.hProcess, 1); WaitForSingleObject(pi.hProcess, 3000);
                rc = 1; break;
            }
        }
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    } else {
        std::fprintf(stderr, "[auto-capture] failed to spawn worker (err=%lu)\n", GetLastError());
    }
    if (hlog != INVALID_HANDLE_VALUE) CloseHandle(hlog);
    return rc;
}

// Newest %APPDATA%\BambuStudio\log\debug_network_*.log.enc -- the oracle the
// log-key recovery decrypts against. Returns "" if none. Skips *.dec sidecars.
static std::string newest_debug_log() {
    const char* ad = std::getenv("APPDATA");
    if (!ad) return "";
    std::string dir = std::string(ad) + "\\BambuStudio\\log";
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA((dir + "\\debug_network_*.log.enc").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return "";
    std::string best; FILETIME bt{};
    do {
        std::string nm = fd.cFileName;
        if (nm.size() < 8 || nm.compare(nm.size() - 8, 8, ".log.enc") != 0) continue;  // guard 8.3 matches
        if (CompareFileTime(&fd.ftLastWriteTime, &bt) > 0) { bt = fd.ftLastWriteTime; best = dir + "\\" + nm; }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return best;
}

// Parse the ascii key out of a find_config_key / find_log_key key file
// ("...\nascii: <16 chars>\n..."). Returns "" if not present.
static std::string parse_ascii_key(const std::string& path) {
    std::string s;
    if (FILE* f = std::fopen(path.c_str(), "rb")) {
        char b[512]; size_t n = std::fread(b, 1, sizeof b - 1, f); b[n] = 0; std::fclose(f); s = b;
    }
    size_t p = s.find("ascii:");
    if (p == std::string::npos) return "";
    p = s.find_first_not_of(" \t", p + 6);
    if (p == std::string::npos) return "";
    size_t e = s.find_first_of("\r\n", p);
    return s.substr(p, (e == std::string::npos ? s.size() : e) - p);
}

// --auto-capture: fully auto-configuring supervisor. Uses the login + access
// codes BambuStudio already stores, discovers the LAN printers via SSDP, and
// produces all four artifacts with zero manual configuration: the config +
// debug-log AES keys (blind, from the running plugin), the cloud app cert (via
// get_app_cert), and the slicer RSA key (live --flip-known capture against the
// first reachable printer -- the key is per-installation, so one printer suffices).
int run_auto_capture(int argc, char** argv, const std::string& ed) {
    std::string plugin = arg_value(argc, argv, "--plugin", "");
    if (plugin.empty()) {
        if (const char* ad = std::getenv("APPDATA"))
            plugin = std::string(ad) + "\\BambuStudio\\plugins\\bambu_networking.dll";
    }
    if (!exists(plugin)) {
        std::fprintf(stderr, "[auto-capture] plugin not found (%s) -- is BambuStudio installed?\n", plugin.c_str());
        return 2;
    }
    char self[MAX_PATH] = {0};
    GetModuleFileNameA(nullptr, self, sizeof self);
    std::string repo = ed + "\\..\\..";                          // win/build_main -> repo root
    const char* cert_arg = arg_value(argc, argv, "--cert-dir", nullptr);
    std::string cert = cert_arg ? std::string(cert_arg) : (repo + "\\resources\\cert");
    const char* work_arg = arg_value(argc, argv, "--work-dir", nullptr);
    std::string base = work_arg ? std::string(work_arg) : (ed + "\\autocap");
    const char* out_arg = arg_value(argc, argv, "--out", nullptr);
    std::string out_final = out_arg ? std::string(out_arg) : (ed + "\\slicer_key.txt");
    std::string diag = repo + "\\win\\build\\d_extracted.json";  // optional diagnostic reference
    const bool have_diag = exists(diag);
    const int max_runs = std::atoi(arg_value(argc, argv, "--attempts", "6"));

    // Access codes + LAN printers -- both from what BambuStudio already has.
    auto codes = bbl::read_studio_access_codes();
    std::fprintf(stderr, "[auto-capture] %zu access code(s) from BambuStudio.conf\n", codes.size());
    std::fprintf(stderr, "[auto-capture] discovering LAN printers (SSDP, up to 15s)...\n");
    auto printers = bbl::discover_lan_printers(15);
    std::fprintf(stderr, "[auto-capture] discovered %zu printer(s):\n", printers.size());
    for (const auto& p : printers)
        std::fprintf(stderr, "   %-15s %s '%s' access-code=%s\n", p.ip.c_str(), p.serial.c_str(),
                     p.name.c_str(), codes.count(p.serial) ? "found" : "MISSING");

    // Survival env inherited by every spawned worker.
    SetEnvironmentVariableA("BBL_BLOCK_WATCHDOG", "1");
    SetEnvironmentVariableA("BBL_PARK_ALL", "1");
    SetEnvironmentVariableA("BBL_NO_FREEZE", "1");
    SetEnvironmentVariableA("BBL_REARM_MS", "50");
    SetEnvironmentVariableA("BBL_GATE_REGION_MB", "4");
    CreateDirectoryA(base.c_str(), nullptr);
    std::string res = base + "\\out";
    CreateDirectoryA(res.c_str(), nullptr);

    const std::string self_q = "\"" + std::string(self) + "\"";
    const std::string plug_q = " --plugin \"" + plugin + "\"";
    std::string conf_path;
    if (const char* ad = std::getenv("APPDATA"))
        conf_path = std::string(ad) + "\\BambuStudio\\BambuNetworkEngine.conf";

    bool ok_cfg = false, ok_log = false, ok_cert = false, ok_slicer = false;
    const std::string cfg_key_path = res + "\\config_key.txt";
    const std::string log_key_path = res + "\\log_key.txt";
    const std::string aid_path     = res + "\\app_identity.txt";
    const std::string appcert_dir  = res + "\\appcert_out";

    // (1) config AES key (network_engine.key): recovered blind from the running
    // plugin, printer-free (fake broker). The conf itself is the decrypt oracle.
    {
        kill_by_name("fake_broker2.exe"); Sleep(300);
        std::string work = base + "\\cfgkey"; CreateDirectoryA(work.c_str(), nullptr);
        std::string cmd = self_q + plug_q + " --work-dir \"" + work + "\""
            + " --cloud-settle 4 --find-config-key --out \"" + cfg_key_path + "\"";
        std::fprintf(stderr, "[auto-capture] (1/4) recovering config AES key (network_engine.key)...\n");
        run_worker(cmd, work, work + "\\w.err", 120000, cfg_key_path);
        ok_cfg = exists(cfg_key_path);
    }

    // (2) debug-log AES key: recovered blind, printer-free, using the newest
    // encrypted debug_network log as the oracle.
    {
        std::string oracle = newest_debug_log();
        if (oracle.empty()) {
            std::fprintf(stderr, "[auto-capture] (2/4) no debug_network_*.log.enc oracle found; skipping log key\n");
        } else {
            kill_by_name("fake_broker2.exe"); Sleep(300);
            std::string work = base + "\\logkey"; CreateDirectoryA(work.c_str(), nullptr);
            std::string cmd = self_q + plug_q + " --work-dir \"" + work + "\""
                + " --cloud-settle 4 --find-log-key \"" + oracle + "\" --key-out \"" + log_key_path + "\"";
            std::fprintf(stderr, "[auto-capture] (2/4) recovering debug-log AES key (oracle %s)...\n", oracle.c_str());
            run_worker(cmd, work, work + "\\w.err", 120000, log_key_path);
            ok_log = exists(log_key_path);
        }
    }

    // (3) cloud app cert via get_app_cert: recover this account's app_identity
    // from the plugin heap (printer-free), then fetch the cert with the token
    // decrypted from the conf. BBL_APP_IDENTITY overrides the heap scan.
    {
        std::string aid;
        if (const char* e = std::getenv("BBL_APP_IDENTITY")) if (e[0]) aid = e;
        if (aid.empty()) {
            kill_by_name("fake_broker2.exe"); Sleep(300);
            std::string work = base + "\\appid"; CreateDirectoryA(work.c_str(), nullptr);
            std::string cmd = self_q + plug_q + " --work-dir \"" + work + "\""
                + " --cloud-settle 6 --find-app-identity --out \"" + aid_path + "\"";
            std::fprintf(stderr, "[auto-capture] (3/4) recovering app_identity from plugin...\n");
            run_worker(cmd, work, work + "\\w.err", 120000, aid_path);
            if (FILE* f = std::fopen(aid_path.c_str(), "rb")) {
                char b[128]; size_t n = std::fread(b, 1, sizeof b - 1, f); b[n] = 0; std::fclose(f); aid = b;
            }
            while (!aid.empty() && (aid.back() == '\n' || aid.back() == '\r' || aid.back() == ' ')) aid.pop_back();
        }
        if (aid.empty()) {
            std::fprintf(stderr, "[auto-capture] (3/4) app_identity not found; skipping app cert "
                         "(set BBL_APP_IDENTITY to force)\n");
        } else {
            std::string cfgk = parse_ascii_key(cfg_key_path);
            if (cfgk.size() != 16) cfgk = "i4crL3LESLnWapLS";
            std::fprintf(stderr, "[auto-capture] (3/4) fetching app cert (get_app_cert) for %s...\n", aid.c_str());
            ok_cert = (bbl::run_get_app_cert(conf_path.c_str(), cfgk.c_str(), aid.c_str(),
                                             appcert_dir.c_str(), "https://api.bambulab.com") == 0);
        }
    }

    // (4) slicer RSA key: live --flip-known capture against a LAN printer (each
    // attempt is a fresh process, so one landing suffices; the key is
    // per-installation, so any one reachable printer works).
    if (printers.empty()) {
        std::fprintf(stderr, "[auto-capture] (4/4) no LAN printer found; skipping slicer-key capture "
                     "(is this PC on the printer's subnet?)\n");
    } else {
        for (const auto& p : printers) {
            if (ok_slicer) break;
            auto it = codes.find(p.serial);
            if (it == codes.end()) {
                std::fprintf(stderr, "[auto-capture] skip %s: no access code in BambuStudio.conf\n", p.name.c_str());
                continue;
            }
            for (int i = 1; i <= max_runs && !ok_slicer; ++i) {
                kill_by_name("fake_broker2.exe"); Sleep(300);
                std::string work = base + "\\" + p.serial + "_" + std::to_string(i);
                CreateDirectoryA(work.c_str(), nullptr);
                std::string out = work + "\\live_key.txt";
                std::string cmd = self_q + plug_q
                    + " --printer-ip " + p.ip + " --dev-id " + p.serial + " --dev-serial " + p.serial
                    + " --access-code " + it->second
                    + " --cert-dir \"" + cert + "\" --work-dir \"" + work + "\" --out \"" + out + "\""
                    + (have_diag ? (" --diag-known \"" + diag + "\"") : std::string())
                    + " --cloud-settle 6 --scan-passes 50 --scan-budget-ms 2000 --sign-sleep-ms 1 --flip-known";
                std::fprintf(stderr, "[auto-capture] (4/4) capture %s (%s) attempt %d/%d\n",
                             p.name.c_str(), p.ip.c_str(), i, max_runs);
                run_worker(cmd, work, work + "\\cap.err", 180000, out);
                if (exists(out)) {
                    CopyFileA(out.c_str(), out_final.c_str(), FALSE);
                    CopyFileA(out.c_str(), (res + "\\slicer_key.txt").c_str(), FALSE);
                    ok_slicer = true;
                    std::fprintf(stderr, "[auto-capture] *** SLICER KEY CAPTURED from %s -> %s ***\n",
                                 p.name.c_str(), out_final.c_str());
                } else {
                    std::fprintf(stderr, "[auto-capture] attempt %d: no key; retrying\n", i);
                }
            }
        }
    }

    kill_by_name("fake_broker2.exe");
    std::fprintf(stderr,
        "\n[auto-capture] ===== SUMMARY (outputs in %s) =====\n"
        "  slicer RSA key    : %s\n"
        "  config AES key    : %s\n"
        "  debug-log AES key : %s\n"
        "  cloud app cert    : %s\n",
        res.c_str(),
        ok_slicer ? "OK (slicer_key.txt)"           : "MISSING",
        ok_cfg    ? "OK (config_key.txt)"           : "MISSING",
        ok_log    ? "OK (log_key.txt)"              : "MISSING",
        ok_cert   ? "OK (appcert_out\\app_cert.pem)" : "MISSING");
    int have = (int)ok_slicer + (int)ok_cfg + (int)ok_log + (int)ok_cert;
    std::fprintf(stderr, "[auto-capture] %d/4 artifacts produced\n", have);
    return (have == 4) ? 0 : 1;
}

}  // namespace

// ---------------------------------------------------------------------------
// Path A: hardware-breakpoint capture of the RSA-CRT exponent bytes (faithful
// port of the Linux src/capture.cpp). Discover the accumulator PC in the
// decrypted plugin code, arm Dr0/Dr7 on all plugin threads via VEH, drive
// continuous signing, collect 256 bytes (two 128-byte CRT halves), then
// reconstruct + validate against the public envelopes / N.
// ---------------------------------------------------------------------------
bool try_reconstruct_and_validate(const std::vector<uint8_t>& stream,
                                  const std::vector<Envelope>& envs,
                                  const char* n_hex, const char* out_path) {
    if (stream.size() < 256) {
        std::fprintf(stderr, "[capA] only %zu captured bytes (<256) -- cannot reconstruct\n",
                     stream.size());
        return false;
    }
    const bn::BigInt N = bn::from_hex(n_hex);
    // Try the 256-byte window in both endiannesses and both half orderings.
    // reconstruct_no_N internally tries both half orderings; we additionally
    // try a fully byte-reversed stream (LE limb order).
    std::vector<std::vector<uint8_t>> variants;
    variants.push_back(stream);                                   // as captured
    { std::vector<uint8_t> r(stream.rbegin(), stream.rend()); variants.push_back(r); }
    // per-half reversal (each 128-byte limb reversed independently)
    { std::vector<uint8_t> h = stream;
      std::reverse(h.begin(), h.begin() + 128);
      std::reverse(h.begin() + 128, h.end());
      variants.push_back(h); }
    for (size_t vi = 0; vi < variants.size(); ++vi) {
        DRecon rec = reconstruct_no_N(variants[vi], 65537, 65537);
        if (!rec.ok) continue;
        bn::BigInt Ncalc = bn::mul(rec.p, rec.q);
        bool n_ok = (bn::BigInt::cmp(Ncalc, N) == 0);
        int ff = -1;
        int passed = validate_envelopes(rec.d, Ncalc, envs, &ff);
        std::fprintf(stderr,
            "[capA] variant %zu: reconstruct ok mode=%s k=%d  N-consistent=%d  "
            "envelopes %d/%zu\n",
            vi, rec.mode.c_str(), rec.k_found, (int)n_ok, passed, envs.size());
        if (n_ok && passed == (int)envs.size()) {
            FILE* kf = std::fopen(out_path, "w");
            if (kf) {
                std::fprintf(kf,
                    "# Slicer RSA-2048 private key - HW-breakpoint capture (Windows, Path A)\n"
                    "N=%s\nE=65537\nd=%s\np=%s\nq=%s\ndp=%s\ndq=%s\n",
                    bn::to_hex_str(Ncalc, false).c_str(), bn::to_hex_str(rec.d, false).c_str(),
                    bn::to_hex_str(rec.p, false).c_str(), bn::to_hex_str(rec.q, false).c_str(),
                    bn::to_hex_str(rec.dp, false).c_str(), bn::to_hex_str(rec.dq, false).c_str());
                std::fclose(kf);
            }
            std::fprintf(stderr, "[capA] *** KEY RECONSTRUCTED + VALIDATED "
                         "(%d/%zu envelopes, N consistent) -> %s ***\n",
                         passed, envs.size(), out_path);
            return true;
        }
    }
    std::fprintf(stderr, "[capA] captured bytes did not reconstruct to a valid key "
                 "(not the CRT exponent, or partial capture)\n");
    return false;
}

// Prove the capture->reconstruct->validate chain WITHOUT live signing: feed the
// CRT exponent halves (dp||dq, big-endian, 128 bytes each) through the same
// reconstruct+envelope-validate a real capture uses. This isolates "downstream is
// correct" from "the breakpoint has not fired yet". The halves are read at
// runtime from a hex file (dp then dq, 512 hex chars; whitespace ignored) so no
// key material is stored in the source tree. Point BBL_SELFTEST_DPDQ at the file;
// it defaults to "capture_selftest_dpdq.txt" in the working directory. Absent
// input skips the check rather than failing.
bool capture_downstream_selftest(const std::vector<Envelope>& envs, const char* n_hex) {
    const char* envp = std::getenv("BBL_SELFTEST_DPDQ");
    std::string path = (envp && *envp) ? envp : "capture_selftest_dpdq.txt";
    std::string raw;
    if (FILE* f = std::fopen(path.c_str(), "rb")) {
        char buf[4096]; size_t n;
        while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) raw.append(buf, n);
        std::fclose(f);
    }
    std::string hex;
    for (char c : raw)
        if ((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F')) hex.push_back(c);
    if (hex.size() < 512) {
        std::fprintf(stderr, "[capA-selftest] no CRT input at %s "
                     "(set BBL_SELFTEST_DPDQ to a file of dp||dq hex, 512 chars); skipping\n",
                     path.c_str());
        return true;   // input not provided -> skip, not a failure
    }
    auto hx = [](const std::string& h) {
        std::vector<uint8_t> v; for (size_t i = 0; i + 1 < h.size(); i += 2) {
            auto nib = [](char c){ return c<='9'?c-'0':(c|32)-'a'+10; };
            v.push_back((uint8_t)((nib(h[i])<<4)|nib(h[i+1]))); } return v; };
    std::vector<uint8_t> stream = hx(hex.substr(0, 512));   // dp||dq = 256 bytes
    std::fprintf(stderr, "[capA-selftest] feeding %zu CRT bytes through "
                 "reconstruct+validate\n", stream.size());
    return try_reconstruct_and_validate(stream, envs, n_hex, "capture_selftest_key.txt");
}

// ---------------------------------------------------------------------------
// On-disk cache (NOT provisioned by BambuStudio): %APPDATA%/BambuStudio/
// slicer_key.pem is written by a prior successful extraction (this tool or the
// Linux tool), so an already-recovered key can be reused without re-capturing.
// --from-disk re-reads that cached PKCS#1 PEM and re-validates it against the
// embedded public envelopes. It is a convenience for subsequent runs, NOT a
// fresh extraction: if the file is absent, run a live heap capture against the
// running plugin to produce it.
// ---------------------------------------------------------------------------
namespace {

bool read_file_bytes(const std::string& path, std::string& out) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    char buf[8192]; size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) out.append(buf, n);
    std::fclose(f);
    return true;
}

// Read one DER INTEGER (p must point at 0x02); advance p; strip sign byte.
bool der_read_int(const uint8_t*& p, const uint8_t* end, std::vector<uint8_t>& val) {
    if (p >= end || *p != 0x02) return false; ++p;
    if (p >= end) return false;
    size_t len = 0;
    if (*p < 0x80) { len = *p; ++p; }
    else { int nb = *p & 0x7f; ++p; if (nb < 1 || nb > 4 || p + nb > end) return false;
           for (int i = 0; i < nb; i++) len = (len << 8) | *p++; }
    if (p + len > end) return false;
    const uint8_t* v = p; size_t vl = len;
    while (vl > 1 && v[0] == 0x00) { ++v; --vl; }
    val.assign(v, v + vl);
    p += len;
    return true;
}

// Parse PKCS#1 RSAPrivateKey: SEQ { version, n, e, d, p, q, dp, dq, qinv }.
bool parse_rsa_pkcs1_der(const std::vector<uint8_t>& der,
                         bn::BigInt& N, bn::BigInt& D, bn::BigInt& P, bn::BigInt& Q) {
    const uint8_t* p = der.data(); const uint8_t* end = p + der.size();
    if (p >= end || *p != 0x30) return false; ++p;                 // SEQUENCE
    if (p >= end) return false;
    if (*p < 0x80) ++p; else { int nb = *p & 0x7f; ++p; p += nb; } // seq length
    std::vector<std::vector<uint8_t>> ints;
    for (int i = 0; i < 9 && p < end; i++) {
        std::vector<uint8_t> v; if (!der_read_int(p, end, v)) break; ints.push_back(std::move(v));
    }
    if (ints.size() < 6) return false;
    N = bn::from_bytes_be(ints[1].data(), ints[1].size());
    D = bn::from_bytes_be(ints[3].data(), ints[3].size());
    P = bn::from_bytes_be(ints[4].data(), ints[4].size());
    Q = bn::from_bytes_be(ints[5].data(), ints[5].size());
    return true;
}

int run_from_disk(const char* pem_path, const std::vector<Envelope>& envs, const char* out_path) {
    std::fprintf(stderr, "[disk] === on-disk extraction: %s ===\n", pem_path);
    std::string pem;
    if (!read_file_bytes(pem_path, pem)) {
        std::fprintf(stderr, "[disk] cannot read %s (no cached key yet -- run a capture to produce it, or pass --slicer-key)\n", pem_path);
        return 1;
    }
    size_t b = pem.find("-----BEGIN");
    size_t nl = (b == std::string::npos) ? std::string::npos : pem.find('\n', b);
    size_t e = pem.find("-----END");
    if (b == std::string::npos || e == std::string::npos || nl == std::string::npos) {
        std::fprintf(stderr, "[disk] not a PEM file\n"); return 1;
    }
    std::string b64 = pem.substr(nl + 1, e - nl - 1), clean;
    for (char c : b64) if (c != '\n' && c != '\r' && c != ' ' && c != '\t') clean += c;
    std::vector<uint8_t> der;
    if (!base64_decode(clean, der)) { std::fprintf(stderr, "[disk] base64 decode failed\n"); return 1; }
    bn::BigInt N, D, P, Q;
    if (!parse_rsa_pkcs1_der(der, N, D, P, Q)) {
        std::fprintf(stderr, "[disk] DER parse failed (expected PKCS#1 RSA PRIVATE KEY)\n"); return 1;
    }
    std::fprintf(stderr, "[disk] parsed key: N=%d-bit p=%d-bit q=%d-bit\n",
                 N.bit_length(), P.bit_length(), Q.bit_length());
    int ff = -1;
    int passed = validate_envelopes(D, N, envs, &ff);
    if (passed != (int)envs.size()) {
        std::fprintf(stderr, "[disk] key does NOT validate (%d/%zu envelopes, first fail #%d)\n",
                     passed, envs.size(), ff);
        return 1;
    }
    bn::BigInt dp = bn::mod(D, bn::sub(P, bn::BigInt(1)));
    bn::BigInt dq = bn::mod(D, bn::sub(Q, bn::BigInt(1)));
    FILE* kf = std::fopen(out_path, "w");
    if (kf) {
        std::fprintf(kf,
            "# Slicer RSA-2048 private key - re-read from cached slicer_key.pem (Windows)\n"
            "N=%s\nE=65537\nd=%s\np=%s\nq=%s\ndp=%s\ndq=%s\n",
            bn::to_hex_str(N, false).c_str(), bn::to_hex_str(D, false).c_str(),
            bn::to_hex_str(P, false).c_str(), bn::to_hex_str(Q, false).c_str(),
            bn::to_hex_str(dp, false).c_str(), bn::to_hex_str(dq, false).c_str());
        std::fclose(kf);
    }
    std::fprintf(stderr, "[disk] *** KEY EXTRACTED + VALIDATED (%d/%zu envelopes) -> %s ***\n",
                 passed, envs.size(), out_path);
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    const char* out      = arg_value(argc, argv, "--out", "slicer_key_windows.txt");
    const char* dev_id   = arg_value(argc, argv, "--dev-id", "00M00A000000000");
    const char* user     = arg_value(argc, argv, "--username", "bblp");
    const char* access   = arg_value(argc, argv, "--access-code", "offline");
    const char* work_arg = arg_value(argc, argv, "--work-dir", ".");
    // The broker writes its self-signed leaf to
    // <work-dir>\printer_trust\printer.cer, which the plugin validates the
    // broker's TLS leaf against. If --work-dir is RELATIVE, the broker (spawned
    // via CreateProcessA, inheriting cwd) resolves a different relative path,
    // never writes printer.cer, TLS fails, and the sign never runs. Force an
    // ABSOLUTE work dir here so this is consistent regardless of the caller.
    std::string work_abs;
    {
        char full[MAX_PATH];
        DWORD wl = GetFullPathNameA(work_arg, MAX_PATH, full, nullptr);
        work_abs = (wl > 0 && wl < MAX_PATH) ? std::string(full) : std::string(work_arg);
    }
    const char* work = work_abs.c_str();
    const int   attempts = std::atoi(arg_value(argc, argv, "--attempts", "8"));
    const std::string ed = exe_dir();

    // --instr-selftest: verify the ProcessInstrumentationCallback DR-register scrub
    // works against a direct-syscall context read, with NO plugin loaded. Runs
    // before death_diag so its exit hooks don't interfere. Confirms the scrub in
    // isolation before arming hardware breakpoints on the real plugin.
    if (has_flag(argc, argv, "--instr-selftest")) {
        int rc = bbl::instrumentation_selftest();
        std::fprintf(stderr, "[instr-selftest] result rc=%d (%s)\n", rc, rc == 0 ? "PASS" : "FAIL");
        return rc;
    }

    // --auto is a long-running supervisor; install death_diag with the same
    // exit-block its worker children use so this process is not ended early.
    // Must run BEFORE install_death_diag() reads BBL_BLOCK_WATCHDOG (run_auto
    // also sets it, but that path runs after death_diag has already installed).
    if (has_flag(argc, argv, "--auto")) {
        if (!std::getenv("BBL_BLOCK_WATCHDOG")) SetEnvironmentVariableA("BBL_BLOCK_WATCHDOG", "1");
        if (!std::getenv("BBL_GATE_REGION_MB")) SetEnvironmentVariableA("BBL_GATE_REGION_MB", "4");
    }

    bbl::install_death_diag();   // log WHY the plugin dies: crash / self-terminate / hang

    // --auto: fully self-contained one-shot. Resolves/downloads the plugin, finds
    // the broker + report, and loops FRESH --flip-gate worker children until one
    // writes a validated key (fresh processes handle the per-session instability).
    if (has_flag(argc, argv, "--fetch-plugin")) {
        // Standalone, VISIBLE plugin download, deliberately decoupled from any
        // execution so a download and a run never happen in one process. Prints
        // the cached path on success.
        const char* pv = arg_value(argc, argv, "--plugin-version", "");
        std::fprintf(stderr, "[fetch] downloading plugin%s%s from Bambu CDN...\n",
                     (pv && pv[0]) ? " version " : "", (pv ? pv : ""));
        std::string p = bbl::download_plugin_win(pv ? std::string(pv) : std::string());
        if (p.empty()) { std::fprintf(stderr, "[fetch] FAILED\n"); return 1; }
        std::fprintf(stderr, "[fetch] plugin ready: %s\n", p.c_str());
        std::printf("%s\n", p.c_str());
        return 0;
    }
    if (has_flag(argc, argv, "--auto")) return run_auto(argc, argv, ed);
    if (has_flag(argc, argv, "--auto-capture")) return run_auto_capture(argc, argv, ed);
    if (has_flag(argc, argv, "--get-app-cert")) {
        // Retrieve the Studio app cert from Bambu's cloud (no plugin needed): decrypt
        // the token from BambuNetworkEngine.conf and call obn::appcert::fetch.
        const char* ck = arg_value(argc, argv, "--config-key", "i4crL3LESLnWapLS");
        const char* aid = arg_value(argc, argv, "--app-identity", nullptr);
        if (!aid || !aid[0]) aid = std::getenv("BBL_APP_IDENTITY");
        std::string conf = arg_value(argc, argv, "--conf", "");
        if (conf.empty()) { if (const char* ad = std::getenv("APPDATA")) conf = std::string(ad) + "\\BambuStudio\\BambuNetworkEngine.conf"; }
        const char* od = arg_value(argc, argv, "--out", "appcert_out");
        const char* api = arg_value(argc, argv, "--api", "https://api.bambulab.com");
        return bbl::run_get_app_cert(conf.c_str(), ck, aid ? aid : "", od, api);
    }

    // Downstream-only proof (no plugin): a correct 256-byte accumulator capture
    // reconstructs + validates the slicer key.
    if (has_flag(argc, argv, "--capture-selftest")) {
        bool ok = capture_downstream_selftest(embedded_test_envelopes(), SLICER_PUBLIC_N_HEX);
        std::fprintf(stderr, "[capA-selftest] %s\n", ok ? "PASS" : "FAIL");
        return ok ? 0 : 1;
    }

    // Reuse a previously-extracted key (no plugin, no printer): re-read the cached
    // slicer_key.pem and self-validate it against the public envelopes. The file
    // is written by a prior capture, NOT by BambuStudio. Default path is
    // %APPDATA%/BambuStudio/slicer_key.pem; override with --slicer-key.
    if (has_flag(argc, argv, "--from-disk") || arg_value(argc, argv, "--slicer-key", nullptr)) {
        std::string keypath = arg_value(argc, argv, "--slicer-key", "");
        if (keypath.empty()) {
            const char* appdata = std::getenv("APPDATA");
            if (appdata) keypath = std::string(appdata) + "\\BambuStudio\\slicer_key.pem";
        }
        return run_from_disk(keypath.c_str(), embedded_test_envelopes(), out);
    }

    // 1. Resolve the plugin DLL (download if not supplied; --plugin-version picks a build).
    std::string plugin = arg_value(argc, argv, "--plugin", "");
    if (plugin.empty()) {
        const char* ad = std::getenv("APPDATA");
        if (ad) { std::string cand = std::string(ad) + "\\BambuStudio\\plugins\\bambu_networking.dll"; if (exists(cand)) plugin = cand; }
    }
    if (plugin.empty()) {
        // No auto-download here (see --fetch-plugin): keep fetch separate from run.
        std::string cached = bbl::cached_plugin_path(arg_value(argc, argv, "--plugin-version", ""));
        if (!cached.empty() && exists(cached)) plugin = cached;
    }
    if (plugin.empty() || !exists(plugin)) {
        std::fprintf(stderr, "[host] no plugin DLL. Fetch once with: bambu_host --fetch-plugin, or pass --plugin <path>.\n");
        return 2;
    }
    std::fprintf(stderr, "[host] plugin: %s\n", plugin.c_str());

    // 2. Resolve the (public) Bambu cloud cert slicer_base64.cer. Bundled in the
    //    repo at resources/cert/ (same file the Linux tool uses).
    std::string cert_arg = arg_value(argc, argv, "--cert-dir", "");
    std::string cert_src;
    if (!cert_arg.empty() && exists(cert_arg + "\\slicer_base64.cer"))
        cert_src = cert_arg + "\\slicer_base64.cer";
    if (cert_src.empty()) cert_src = find_up(ed, "resources\\cert\\slicer_base64.cer", 6);
    if (cert_src.empty()) cert_src = find_up(ed, "win\\resources\\cert\\slicer_base64.cer", 6);
    if (cert_src.empty()) {
        std::string bs = "C:\\Program Files\\Bambu Studio\\resources\\cert\\slicer_base64.cer";
        if (exists(bs)) cert_src = bs;
    }
    if (cert_src.empty()) {
        std::fprintf(stderr, "[host] cannot find slicer_base64.cer (bundle it in resources/cert)\n");
        return 2;
    }

    // 3. Resolve the bundled fake-printer broker.
    std::string broker = arg_value(argc, argv, "--broker", "");
    if (broker.empty()) broker = find_up(ed, "fake_broker2.exe", 0);
    if (broker.empty()) broker = find_up(ed, "broker\\fake_broker2.exe", 1);
    if (broker.empty()) broker = find_up(ed, "win\\broker\\fake_broker2.exe", 6);
    if (broker.empty() || !exists(broker)) {
        std::fprintf(stderr, "[host] cannot find fake_broker2.exe (give --broker)\n");
        return 2;
    }
    std::fprintf(stderr, "[host] broker: %s\n", broker.c_str());

    // 4. Satisfy the plugin's host verification so this host may load it.
    std::fprintf(stderr, "[host] installing host-verification shim...\n");
    bbl::install_verify_fake();

    // 4a. Syscall-level DR scrub: some plugin threads read their own DR7 via a DIRECT
    //     `syscall` NtGetContextThread (not through the ntdll export hooks in
    //     verify_fake). A ProcessInstrumentationCallback runs on every kernel->user
    //     return including that direct syscall, and zeroes the debug-register fields
    //     in the returned CONTEXT so an armed hardware breakpoint is not visible to it.
    //     Only needed when a DR breakpoint is armed (aes_tap); install it BEFORE the
    //     plugin loads. Scoped to plugin/anon returns so host threads + the re-armer
    //     are untouched.
    if (has_flag(argc, argv, "--aes-tap") || std::getenv("BBL_AES_LOG") ||
        has_flag(argc, argv, "--instr-cb")) {
        bbl::install_instrumentation_callback(/*scope_self=*/false);
        std::atexit(bbl::remove_instrumentation_callback);
    }

    // 4b. Cloud plaintext tap: capture the genuine plugin's HTTP request/response
    //     plaintext (endpoint, X-BBL-* headers, Bearer, PEM cert/key) straight from
    //     its private heap during the live cloud session -- read from the plugin's
    //     own buffers rather than the TLS socket (static OpenSSL + pinned cloud
    //     CA). Gate on --tap/BBL_TAP_LOG.
    if (has_flag(argc, argv, "--tap") || std::getenv("BBL_TAP_LOG")) {
        bbl::start_cloud_tap();
        std::atexit(bbl::stop_cloud_tap);
    }
    //     rng_tap: hook bcrypt!BCryptGenRandom (the plugin's sole RNG import) to
    //     capture the client AES key + nonces used to build get_app_cert's
    //     encAppKey/aes256 and the create_task signature. Gate on --rng-tap/BBL_RNG_LOG.
    if (has_flag(argc, argv, "--rng-tap") || std::getenv("BBL_RNG_LOG")) {
        bbl::start_rng_tap();
        std::atexit(bbl::stop_rng_tap);
    }
    //     aes_tap: DR-breakpoint OpenSSL AES-NI key expansion to capture the raw AES
    //     key K (DRBG-generated, so invisible to rng_tap). Gate on --aes-tap/BBL_AES_LOG.
    if (has_flag(argc, argv, "--aes-tap") || std::getenv("BBL_AES_LOG")) {
        bbl::start_aes_tap();
        std::atexit(bbl::stop_aes_tap);
    }

    // Note: the cloud APP key (create_task signer) is captured in the --flip-gate
    // loop via blind_scan_gated against the app modulus (--app-key-sweep <hex>), at
    // the same tight sign->snapshot moment as the slicer key -- see that branch.

    // 5. printer-trust cert dir: keep the REAL (pinned) slicer_base64.cer, and let
    //    the broker drop its self-signed leaf as printer.cer (the LAN device CA the
    //    plugin checks the printer against).
    std::string trust_dir = std::string(work) + "\\printer_trust";
    CreateDirectoryA(trust_dir.c_str(), nullptr);
    CopyFileA(cert_src.c_str(), (trust_dir + "\\slicer_base64.cer").c_str(), FALSE);
    std::string printer_cer = trust_dir + "\\printer.cer";
    DeleteFileA(printer_cer.c_str());

    // --offline: skip the fake printer entirely (local RSA op still materialises
    // the key). --printer-ip <ip>: connect to a REAL printer instead of the fake
    // broker (the most reliable capture path -- the printer drives real signing).
    const bool offline = has_flag(argc, argv, "--offline");
    const char* printer_ip = arg_value(argc, argv, "--printer-ip", nullptr);
    const bool use_broker = !offline && !printer_ip;
    PROCESS_INFORMATION broker_pi{};
    bool broker_up = false;
    if (use_broker) {
        if (!spawn_broker(broker, dev_id, printer_cer, broker_pi)) return 1;
        broker_up = true;
        for (int i = 0; i < 80 && !exists(printer_cer); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    } else if (printer_ip) {
        // Real printer: the plugin verifies the printer's TLS leaf against
        // printer.cer (a device-CA bundle). Supply a CA that validates it:
        //   --printer-cert <file>  -> use that file directly as printer.cer
        //                             (e.g. the printer's own leaf, or a CA bundle)
        //   else --cert-dir/<Bambu install>/printer.cer -> genuine device CA
        //         (6.6 KB bundle that chains the real H2S leaf; verified with
        //          openssl verify -CAfile printer.cer <leaf> == OK).
        const char* pcert = arg_value(argc, argv, "--printer-cert", nullptr);
        std::string ca_src;
        if (pcert && exists(pcert)) {
            ca_src = pcert;
        } else if (!cert_arg.empty() && exists(cert_arg + "\\printer.cer")) {
            ca_src = cert_arg + "\\printer.cer";
        } else {
            std::string bs = "C:\\Program Files\\Bambu Studio\\resources\\cert\\printer.cer";
            if (exists(bs)) ca_src = bs;
        }
        if (!ca_src.empty() && CopyFileA(ca_src.c_str(), printer_cer.c_str(), FALSE))
            std::fprintf(stderr, "[host] printer device-CA: %s -> printer.cer\n", ca_src.c_str());
        else
            std::fprintf(stderr, "[host] WARNING: no device CA for real printer "
                                 "(TLS verify of printer will fail; give --printer-cert)\n");
    }

    // 6. Env vars the plugin reads (mirror the Linux daemon).
    SetEnvironmentVariableA("BAMBU_NET_RESIGN_MS", "3000");
    SetEnvironmentVariableA("BAMBU_NET_GCODE_CMD_MS", "2000");
    SetEnvironmentVariableA("BAMBU_NET_TARGET_DEV", dev_id);
    SetEnvironmentVariableA("BAMBU_NET_CLOUD_CERT_DIR", trust_dir.c_str());
    SetEnvironmentVariableA("BAMBU_NET_CLOUD_CERT_FILE", "slicer_base64.cer");

    // 6b. Stage the real BambuStudio config into our scratch config dir so the
    //     plugin can LOAD its signing key (slicer_key.pem), OAuth token
    //     (BambuNetworkEngine.conf) + cert id. Without these in config_dir the
    //     plugin has no key to sign with and no login state -> it never enters
    //     the RSA-CRT signing path (so the capture breakpoint never fires).
    //     We copy FROM the real dir so we never write to it. --no-stage disables.
    if (!has_flag(argc, argv, "--no-stage")) {
        const char* appdata = std::getenv("APPDATA");
        std::string real = appdata ? std::string(appdata) + "\\BambuStudio" : "";
        std::string cfgd = arg_value(argc, argv, "--config-dir", real.c_str());
        const char* files[] = { "slicer_key.pem", "slicer_cert_id.txt",
                                "BambuNetworkEngine.conf", "slicer_base64.cer" };
        for (const char* f : files) {
            std::string src = cfgd + "\\" + f, dst = std::string(work) + "\\" + f;
            if (exists(src) && CopyFileA(src.c_str(), dst.c_str(), FALSE))
                std::fprintf(stderr, "[host] staged %s -> config_dir\n", f);
        }
    }

    // 7. Load + initialise the plugin (full host contract).
    PluginHandleConfig cfg;
    cfg.plugin_path  = plugin;
    cfg.log_dir      = work;
    cfg.config_dir   = work;
    cfg.country_code = "US";
    cfg.cert_dir     = trust_dir;
    cfg.cert_file    = "slicer_base64.cer";

    // 7a. Studio fingerprint: inject the exact host-side X-BBL-* header block that
    //     genuine BambuStudio sets via bambu_network_set_extra_http_header
    //     (BBLCloudServiceAgent::get_extra_header). Makes this host a faithful,
    //     Cloudflare-JA4H-identical Studio for the genuine plugin's cloud REST.
    //     The ABI is a std::map (sorted keys) -> emitted in this order, which is
    //     exactly the genuine Linux-captured order. X-BBL-Executable-Env is NOT
    //     here: on the wire it lands AFTER the plugin's own headers, so it is
    //     plugin/separate, not part of this host map. Values overridable via env;
    //     --no-studio-headers disables (A/B).
    if (!has_flag(argc, argv, "--no-studio-headers")) {
        auto env_or = [](const char* k, const char* d) {
            const char* v = std::getenv(k); return std::string(v && v[0] ? v : d); };
        cfg.extra_http_headers = {
            {"X-BBL-Client-Name",    "BambuStudio"},
            {"X-BBL-Client-Type",    "slicer"},
            {"X-BBL-Client-Version", env_or("BBL_CLIENT_VERSION", "02.07.01.57")},
            {"X-BBL-Device-ID",      env_or("BBL_DEVICE_ID", "887b3544-9221-4b48-9838-cc01c35e6e8d")},
            {"X-BBL-Language",       env_or("BBL_LANGUAGE", "en-US")},
            {"X-BBL-OS-Type",        env_or("BBL_OS_TYPE", "windows")},
            {"X-BBL-OS-Version",     env_or("BBL_OS_VERSION", "10.0.26200")},
        };
        std::fprintf(stderr, "[host] Studio fingerprint: injecting %zu extra headers\n",
                     cfg.extra_http_headers.size());
        for (const auto& kv : cfg.extra_http_headers)
            std::fprintf(stderr, "[host]   %s: %s\n", kv.first.c_str(), kv.second.c_str());
    }

    std::fprintf(stderr, "[host] init plugin handle...\n");
    BambuNetworkingPluginHandle handle(cfg);
    if (!handle.init()) {
        std::fprintf(stderr, "[host] FAIL: handle.init()\n");
        if (broker_up) TerminateProcess(broker_pi.hProcess, 0);
        return 1;
    }

    // --extract-appkey --modulus: PRE-ARM the app-key p/q sweep NOW, before the
    // cloud session runs get_app_cert. The app key's p/q are PLAIN but transient --
    // they materialise only during the get_app_cert decrypt (and each sign) -- so
    // the looping heap sweep must already be running when that brief window opens.
    if (has_flag(argc, argv, "--extract-appkey")) {
        if (const char* mod = arg_value(argc, argv, "--modulus", nullptr); mod && mod[0] && mod[0] != '-') {
            static std::vector<uint8_t> s_N;
            for (const char* h = mod; h[0] && h[1]; h += 2) {
                auto nib = [](char c){ return (c>='0'&&c<='9')?c-'0':(c|0x20)-'a'+10; };
                s_N.push_back((uint8_t)((nib(h[0])<<4)|nib(h[1])));
            }
            const char* od = arg_value(argc, argv, "--out", "appkey_out");
            CreateDirectoryA(od, nullptr);
            static std::string s_pq = std::string(od) + "\\app_key_pq.txt";
            std::fprintf(stderr, "[extract] pre-arming app-key p/q sweep (%zu-byte N) before get_app_cert...\n", s_N.size());
            bbl::start_app_key_sweep(s_N, s_pq.c_str());
        }
    }

    // --dump-regions: snapshot the plugin's in-memory image (image sections +
    // anonymous arenas) for offline disassembly of the OpenSSL / get_app_cert
    // crypto, then exit. The relevant .rdata + .text are decoded in memory by load
    // time, so init() is enough. Pure VirtualQuery copy -> no DR/hardware BP, no
    // debug-register state set.
    if (has_flag(argc, argv, "--dump-regions")) {
        const char* dd = arg_value(argc, argv, "--dump-dir", "regions_dump");
        std::fprintf(stderr, "[host] --dump-regions -> %s\n", dd);
        int rc = bbl::dump_plugin_regions(dd);
        if (broker_up) TerminateProcess(broker_pi.hProcess, 0);
        return rc;
    }

    // Wait for the cloud session (login was staged from BambuNetworkEngine.conf).
    // The plugin may gate print.* signing on a live server session.
    for (int i = 0; i < 40 && !handle.is_server_connected(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    std::fprintf(stderr, "[host] after init: login=%d server_connected=%d\n",
                 (int)handle.is_user_login(), (int)handle.is_server_connected());

    // 7b. Fetch the account's cloud device list and report H2S online/bind
    //     status. This is the gate for cloud routing+signing: the plugin will
    //     only sign a command if it routes it via the cloud relay to a
    //     cloud-ONLINE device bound to this account. --dev-serial supplies the
    //     printer's MQTT serial to search for; falls back to
    //     --dev-id. Always run so the extraction log records the status; with
    //     --print-info as the sole action, print + exit.
    {
        const char* serial = arg_value(argc, argv, "--dev-serial", dev_id);
        PrintInfoResult pi = probe_print_info(handle, serial ? serial : "");
        std::fprintf(stderr,
            "[host] === get_user_print_info summary: http_code=%u ok=%d "
            "serial_seen=%d online=%d ===\n",
            pi.http_code, (int)pi.ok, (int)pi.serial_seen, (int)pi.online);
        if (has_flag(argc, argv, "--print-info")) {
            // Let the tap catch the response plaintext while it's still warm, then
            // flush with a final scan.
            if (bbl::cloud_tap_hits() >= 0 &&
                (has_flag(argc, argv, "--tap") || std::getenv("BBL_TAP_LOG"))) {
                std::this_thread::sleep_for(std::chrono::milliseconds(600));
                bbl::stop_cloud_tap();
                std::fprintf(stderr, "[host] cloud_tap captured %lld blocks\n",
                             bbl::cloud_tap_hits());
            }
            std::fprintf(stderr, "[host] --print-info: done (exiting before extract)\n");
            if (broker_up) {
                TerminateProcess(broker_pi.hProcess, 0);
                CloseHandle(broker_pi.hProcess); CloseHandle(broker_pi.hThread);
            }
            return pi.serial_seen ? 0 : 3;
        }
    }

    // 8. Connect to the printer (fake broker or real --printer-ip); wait for the
    //    local channel. Skipped entirely in --offline mode.
    if (!offline) {
        const char* ip = printer_ip ? printer_ip : "127.0.0.1";
        // Connect FIRST; the plugin's on_printer_connected callback performs the
        // set_user_selected_machine + install_device_cert once the tunnel is up.
        // (Calling set_user_selected_machine before connect makes the plugin
        //  fail-fast on the local connect.)
        std::fprintf(stderr, "[host] connect_printer(%s)...\n", ip);
        handle.connect_printer(dev_id, ip, user, access, true);
        handle.register_local_message_receiver(dev_id, [](std::string, std::vector<uint8_t>, uint8_t){});
        handle.register_receiver(dev_id, [](std::string, std::vector<uint8_t>, uint8_t){});
        for (int i = 0; i < 120 && !handle.is_local_connected(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            if (i == 39 || i == 79)
                std::fprintf(stderr, "[host] waiting for local connect... (%ds)\n", (i + 1) / 2);
        }
        std::fprintf(stderr, "[host] is_local_connected=%d\n", (int)handle.is_local_connected());
    }
    handle.set_user_selected_machine(dev_id);
    // Bring up the cloud MQTT session exactly as BambuStudio does when its
    // window becomes active: connect_server (done in init) -> start_subscribe
    // ("app") -> add_subscribe(dev_list). WITHOUT start_subscribe("app") the
    // plugin's cloud MQTT is not connected, so cloud send_message returns
    // CONNECT_FAILED (-2) and never reaches the RSA-CRT signing path. Then wait
    // for the REAL (plugin) server-connected before publishing.
    int ss_rc = handle.start_subscribe("app");
    std::fprintf(stderr, "[host] start_subscribe(app) rc=%d\n", ss_rc);
    for (int i = 0; i < 60 && !handle.raw_is_server_connected(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        if (i == 19 || i == 39)
            std::fprintf(stderr, "[host] waiting for REAL cloud MQTT connect... (%ds) raw=%d\n",
                         (i + 1) / 2, (int)handle.raw_is_server_connected());
    }
    std::fprintf(stderr, "[host] raw_is_server_connected=%d (wrapped=%d)\n",
                 (int)handle.raw_is_server_connected(), (int)handle.is_server_connected());
    // Subscribe to the device via the CLOUD channel. The slicer signs commands
    // routed through the cloud relay (LAN commands go plaintext with just the
    // access code); a cloud-subscribed device is what puts send_message on the
    // signing path. Requires login=1 + server_connected=1 (staged config).
    int sub_rc = handle.subscribe_device(dev_id);
    std::fprintf(stderr, "[host] subscribe_device(%s) rc=%d\n", dev_id, sub_rc);
    // Diagnostic receiver: log ANY cloud message from the device. A real cloud
    // report proves the device<->plugin cloud channel is live (a precondition
    // for the plugin to accept a publish, i.e. rc != CONNECT_FAILED).
    static std::atomic<int> g_msg_count{0};
    handle.register_receiver(dev_id, [](std::string topic, std::vector<uint8_t> payload, uint8_t) {
        int n = ++g_msg_count;
        if (n <= 12)
            std::fprintf(stderr, "[cloud-rx #%d] topic=%s bytes=%zu head=%.120s\n",
                         n, topic.c_str(), payload.size(),
                         std::string(payload.begin(), payload.end()).c_str());
    });
    handle.install_device_cert(dev_id, false);
    // Wait for the device's cloud MQTT report to arrive AND probe a publish each
    // second so we can see WHEN (if ever) send_message stops returning
    // CONNECT_FAILED. A cloud report means the device topic is live; a probe
    // command_pushall (unprivileged) that returns 0 means the publish path is
    // open, at which point privileged signed commands will materialise the key.
    int settle_s = std::atoi(arg_value(argc, argv, "--cloud-settle", "20"));
    for (int i = 0; i < settle_s; ++i) {
        char probe[160];
        std::snprintf(probe, sizeof(probe),
            "{\"pushing\":{\"command\":\"pushall\",\"sequence_id\":\"%d\"}}", 900000 + i);
        int prc = handle.send_message_to_printer(dev_id, probe, 0);
        std::fprintf(stderr, "[host] cloud settle %ds: pushall probe rc=%d rx_msgs=%d raw_srv=%d\n",
                     i, prc, g_msg_count.load(), (int)handle.raw_is_server_connected());
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    // 9. Blind extraction: drives signing on a background thread, sweeps the heap
    //    for the factors, and self-validates against the embedded public envelopes.
    SignCtx sctx{ &handle, dev_id };
    const char* diag = arg_value(argc, argv, "--diag-known", nullptr);
    if (diag) {
        for (int i = 0; i < 150; ++i) trigger_fn(&sctx);
        bbl::scan_known_memory(diag, "diag");
    }
    // --cloud-print: drive the genuine plugin's cloud print (bambu_network_start_print)
    // with a pre-sliced 3mf so create_task fires; cloud_tap captures the request (incl.
    // x-bbl-device-security-sign) in-process. Stage-based cancel (BAMBU_NET_PRINT_CANCEL_AFTER_STAGE)
    // aborts before/after create_task. RSA-recover the captured sign offline vs the slicer key.
    if (has_flag(argc, argv, "--cloud-print")) {
        if (has_flag(argc, argv, "--file-trace") || std::getenv("BBL_FILE_TRACE")) bbl::start_file_trace();
        std::fprintf(stderr, "[cloud] settling cloud session...\n");
        for (int i = 0; i < 12 && !handle.is_server_connected(); ++i) { trigger_fn(&sctx); std::this_thread::sleep_for(std::chrono::milliseconds(400)); }
        // start_print's create_task sign check is at plugin 0x228f10, whose fall-through path
        // returns the verification global byte at rva 0x7C861C (0 headless -> -26
        // SIGNED_ERROR). That byte is in a WRITABLE .data region, so setting it to 1 lets
        // the check pass and the create_task sign proceeds. No breakpoint needed.
        if (!has_flag(argc, argv, "--no-verflag")) {
            if (HMODULE m = GetModuleHandleA("bambu_networking.dll")) {
                volatile uint8_t* flag = (uint8_t*)((uintptr_t)m + 0x7C861C);
                uint8_t before = write_verified_flag(flag);
                std::fprintf(stderr, "[cloud] verification flag @%p: %u -> %u\n", (void*)flag, before, *flag);
            }
        }
        BambuNetworkingPluginHandle::CloudUploadParams cp{};
        cp.dev_id          = arg_value(argc, argv, "--print-dev", "00M00A000000000");
        cp.local_file_path = arg_value(argc, argv, "--print-file", "");
        cp.project_name    = arg_value(argc, argv, "--print-name", "cube");
        cp.task_name       = cp.project_name;
        cp.connection_type = "cloud";
        cp.plate_index     = std::atoi(arg_value(argc, argv, "--plate", "1"));
        cp.task_bed_type   = arg_value(argc, argv, "--bed-type", "textured_plate");
        cp.ams_mapping     = "-1";
        cp.ams_mapping2    = "-1";
        cp.origin_model_id = "";
        cp.use_ssl_for_ftp = true; cp.use_ssl_for_mqtt = true;
        std::fprintf(stderr, "[cloud] start_cloud_print dev=%s file=%s plate=%d bed=%s (server_connected=%d)\n",
                     cp.dev_id.c_str(), cp.local_file_path.c_str(), cp.plate_index, cp.task_bed_type.c_str(),
                     (int)handle.is_server_connected());
        int rc = handle.start_cloud_print(cp);
        std::fprintf(stderr, "[cloud] start_cloud_print rc=%d\n", rc);
        if (has_flag(argc, argv, "--tap") || std::getenv("BBL_TAP_LOG")) {
            std::this_thread::sleep_for(std::chrono::milliseconds(800));
            bbl::stop_cloud_tap();
            std::fprintf(stderr, "[cloud] cloud_tap captured %lld blocks\n", bbl::cloud_tap_hits());
        }
        if (broker_up) { TerminateProcess(broker_pi.hProcess, 0); CloseHandle(broker_pi.hProcess); CloseHandle(broker_pi.hThread); }
        return rc == 0 ? 0 : 1;
    }

    // --sign-probe: capture a device-security-sign by invoking the plugin's own
    // signing routine (get_device_security_sign) locally; it sends nothing. The
    // account's app cert-id (supply via --app-cert-id / BBL_APP_CERT_ID) is the
    // string held at secctx+0x230 and is used to locate and validate the security
    // context. Two calls ~1.5s apart yield two timestamps for a liveness check.
    if (has_flag(argc, argv, "--sign-probe")) {
        const uintptr_t SIGN_RVA = 0x22ACD0, CERTID_RVA = 0x22AB20, CERTID_OFF = 0x230;
        const char* certid = arg_value(argc, argv, "--app-cert-id", nullptr);
        if (!certid || !certid[0]) certid = std::getenv("BBL_APP_CERT_ID");
        if (!certid || !certid[0]) {
            std::fprintf(stderr, "[sign] set --app-cert-id or BBL_APP_CERT_ID (this account's app cert serial) to locate the security context\n");
            if (broker_up) { TerminateProcess(broker_pi.hProcess, 0); CloseHandle(broker_pi.hProcess); CloseHandle(broker_pi.hThread); }
            return 2;
        }
        const int certid_len = (int)std::strlen(certid);
        std::fprintf(stderr, "[sign] settling cloud session so get_app_cert loads the app key...\n");
        // Warm the sign path so the verification sites resolve, then arm the override so
        // the enc_msg signs during settle -- this sets whatever global verification
        // state get_device_security_sign may consult before returning its result.
        for (int i = 0; i < 8; ++i) { trigger_fn(&sctx); std::this_thread::sleep_for(std::chrono::milliseconds(400)); }
        bool did_flip = false;
        if (!has_flag(argc, argv, "--no-flip")) {
            std::vector<bbl::VerdictSite> vsites = bbl::find_verdict_sites();
            did_flip = bbl::arm_verdict_flip(vsites);
            std::fprintf(stderr, "[sign] verification override: %zu site(s), armed=%d\n", vsites.size(), (int)did_flip);
        }
        for (int i = 0; i < 10; ++i) { trigger_fn(&sctx); std::this_thread::sleep_for(std::chrono::milliseconds(400)); }

        HMODULE m = GetModuleHandleA("bambu_networking.dll");
        std::fprintf(stderr, "[sign] plugin_base=%p agent=%p\n", (void*)m, handle.raw_agent());

        // The sign check (create_task path) reads the verification byte at rva
        // 0x7C861C; get_device_security_sign (0x22acd0) may gate on the same flag. Set it
        // to 1 so a direct call returns the genuine signature instead of empty.
        if (m && !has_flag(argc, argv, "--no-verflag")) {
            volatile uint8_t* vf = (uint8_t*)((uintptr_t)m + 0x7C861C);
            uint8_t b0 = write_verified_flag(vf);
            std::fprintf(stderr, "[sign] verification flag @%p: %u -> %u\n", (void*)vf, b0, *vf);
        }

        // Locate the security context. The cert-id getter (rva 0x22ab20) returns a
        // std::string held at secctx+0x230; that string is the full app cert serial
        // (lowercase, >15 chars) so it is NOT inline -- the object at secctx+0x230
        // holds a POINTER to the serial text. So: (1) find the serial text in the
        // heap, (2) find std::string objects pointing at it, (3) secctx = object-0x230.
        std::vector<void*> serials, cands;
        int cn_hits = 0;
        auto walk = [&](auto fn_region) {
            MEMORY_BASIC_INFORMATION mbi{};
            for (unsigned char* a = nullptr; VirtualQuery(a, &mbi, sizeof mbi); a = (unsigned char*)mbi.BaseAddress + mbi.RegionSize) {
                if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE) continue;
                if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) continue;
                DWORD pr = mbi.Protect & 0xFF;
                if (pr != PAGE_READWRITE && pr != PAGE_WRITECOPY && pr != PAGE_EXECUTE_READWRITE) continue;
                if (mbi.RegionSize > (256u << 20)) continue;
                fn_region((unsigned char*)mbi.BaseAddress, mbi.RegionSize);
            }
        };
        walk([&](unsigned char* base, size_t rn) {
            void* hit[32];
            cn_hits += scan_region_needle(base, rn, "GLOF", 4, hit, 32);   // generic app-cert CN prefix
            int k = scan_region_needle(base, rn, certid, certid_len, hit, 32);
            for (int j = 0; j < k; ++j) if (serials.size() < 16) serials.push_back(hit[j]);
        });
        for (void* T : serials) {
            walk([&](unsigned char* base, size_t rn) {
                void* hit[32];
                int k = scan_region_qword(base, rn, (uint64_t)T, hit, 32);
                for (int j = 0; j < k; ++j) {
                    void* secctx = (void*)((char*)hit[j] - CERTID_OFF);
                    bool dup = false; for (void* c : cands) if (c == secctx) { dup = true; break; }
                    if (!dup && cands.size() < 32) cands.push_back(secctx);
                }
            });
        }
        std::fprintf(stderr, "[sign] app-cert CN resident: %d; serial-text hits: %zu; secctx candidates: %zu\n",
                     cn_hits, serials.size(), cands.size());

        const char* od = arg_value(argc, argv, "--out", "sign_probe");
        CreateDirectoryA(od, nullptr);
        std::string outpath = std::string(od) + "\\signs.txt";
        std::FILE* sf = std::fopen(outpath.c_str(), "w");
        int got = 0;
        void* signfn   = (void*)((uintptr_t)m + SIGN_RVA);
        void* certidfn = (void*)((uintptr_t)m + CERTID_RVA);
        // Find the validated secctx: the directly-callable cert-id getter (0x22ab20)
        // must return the serial on it (proves the pointer is a real security ctx).
        void* good = nullptr;
        for (size_t ci = 0; ci < cands.size() && m; ++ci) {
            char cid[128];
            size_t idlen = call_str_member(certidfn, cands[ci], cid, sizeof cid);
            bool ok2 = (idlen > 0 && std::strstr(cid, certid) != nullptr);
            std::fprintf(stderr, "[sign] cand[%zu] secctx=%p cert-id(len=%zu)=\"%.40s\" valid=%d\n",
                         ci, cands[ci], idlen, idlen ? cid : "", (int)ok2);
            if (ok2) { good = cands[ci]; break; }
        }
        if (good && m) {
            uint64_t base = (uintptr_t)m;
            { MODULEINFO mi{}; if (GetModuleInformation(GetCurrentProcess(), m, &mi, sizeof mi)) { g_pl_base = base; g_pl_end = base + mi.SizeOfImage; } }
            g_gbp[0] = base + 0x22AB20;   // control: cert-id getter (we call it -> BP must fire)
            g_gbp[1] = base + 0x22F160;   // studio verify
            g_gbp[2] = base + 0x18D080;   // verify wrapper
            if (const char* fv = arg_value(argc, argv, "--force-verify", nullptr); fv && fv[0] && fv[0] != '-') g_force_idx = std::atol(fv);
            // Is the app private key resident in the heap right now (post-settle)? This also
            // sets g_key_addr (a live key limb) so we can arm a DATA read-BP on the key.
            if (const char* pf = arg_value(argc, argv, "--prime-file", nullptr); pf && pf[0]) {
                std::fprintf(stderr, "[sign] --- app-key residency BEFORE sign ---\n");
                scan_known_primes(pf);
            }
            if (g_key_addr) {   // slot 3 = hardware READ breakpoint on the resident key
                g_gbp[3] = g_key_addr; g_bp_data[3] = true;
                std::fprintf(stderr, "[sign] key data-BP armed @%p (fires if the signer reads the app key)\n", (void*)g_key_addr);
            }
            PVOID veh = AddVectoredExceptionHandler(1, gate_veh);
            gate_arm_current_thread();
            char cctl[128]; call_str_member(certidfn, good, cctl, sizeof cctl);   // control call
            std::fprintf(stderr, "[sign] gate control: cert-id(0x22ab20) BP hits=%ld -> DR arming %s (force_idx=%ld)\n",
                         g_ghits[0], g_ghits[0] ? "WORKS" : "FAILED", g_force_idx);
            g_in_sign = true;
            uint64_t sign_ms = 0;
            for (int t = 0; t < 2; ++t) {
                uint64_t t_ms = (uint64_t)time(nullptr) * 1000; sign_ms = t_ms;
                char sig[1024];
                size_t len = call_str_member(signfn, good, sig, sizeof sig);
                if (len >= 16) {
                    std::fprintf(stderr, "[sign] >>> SIGN captured: len=%zu %.48s...\n", len, sig);
                    if (sf) { std::fprintf(sf, "%llu\t%.*s\n", (unsigned long long)t_ms, (int)len, sig); std::fflush(sf); }
                    ++got;
                } else {
                    std::fprintf(stderr, "[sign] sign call %d EMPTY\n", t);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1200));
            }
            g_in_sign = false;
            // The signer builds a ms-timestamp string on the heap; scan for it (and its
            // surrounding context) to read exactly what message the plugin signs.
            std::fprintf(stderr, "[sign] --- heap timestamp scan (message the signer built) ---\n");
            scan_heap_for_timestamp(sign_ms);
            // Dump the modexp-operand snapshot from the first key read: each register +
            // 256 bytes it points at. Offline we test each buffer as an RSA operand (the
            // padded message I -> its tail is the signed message).
            if (g_kcap) {
                std::string kp = std::string(od) + "\\keyctx.hex";
                if (std::FILE* kf = std::fopen(kp.c_str(), "w")) {
                    const char* rn[18] = {"rax","rbx","rcx","rdx","rsi","rdi","rbp","r8","r9",
                                          "r10","r11","r12","r13","r14","r15","rip","rsp","[rsp]"};
                    for (int j = 0; j < 18; ++j) {
                        std::fprintf(kf, "%s %016llx ", rn[j], (unsigned long long)g_kreg[j]);
                        for (int b = 0; b < 256; ++b) std::fprintf(kf, "%02x", g_kbuf[j][b]);
                        std::fprintf(kf, "\n");
                    }
                    std::fclose(kf);
                    std::fprintf(stderr, "[sign] captured modexp operand snapshot -> %s\n", kp.c_str());
                }
            }
            std::fprintf(stderr, "[sign] plugin span %p..%p; verify 0x22f160=%ld  KEY-READ total=%ld  ext(real-code)=%ld  captured_rip=%p\n",
                         (void*)g_pl_base, (void*)g_pl_end, g_ghits[1], g_ghits[3], g_ghits[2],
                         (void*)(g_kcap ? g_kreg[15] : 0));
            if (const char* pf = arg_value(argc, argv, "--prime-file", nullptr); pf && pf[0]) {
                std::fprintf(stderr, "[sign] --- app-key residency AFTER sign ---\n");
                scan_known_primes(pf);
            }
            // Identify the crypto module (the one the key-read rip lives in) and resolve
            // OpenSSL sign exports -- if EVP_PKEY_sign et al. are exported, we can BP them
            // directly next run and read the exact message/tbs the plugin signs.
            {
                HMODULE mods[512]; DWORD cb = 0;
                if (EnumProcessModules(GetCurrentProcess(), mods, sizeof mods, &cb)) {
                    int nm = (int)(cb / sizeof(HMODULE));
                    const char* fns[] = { "EVP_PKEY_sign", "EVP_DigestSign", "EVP_DigestSignInit",
                                          "RSA_sign", "RSA_private_encrypt", "EVP_PKEY_sign_init",
                                          "EVP_PKEY_CTX_new", "OSSL_PARAM_construct_end" };
                    for (int i = 0; i < nm; ++i) {
                        MODULEINFO mi{}; char nmz[MAX_PATH] = {0};
                        GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof mi);
                        GetModuleBaseNameA(GetCurrentProcess(), mods[i], nmz, sizeof nmz);
                        uint64_t b = (uint64_t)mi.lpBaseOfDll, e = b + mi.SizeOfImage;
                        if (g_gra[3] && g_gra[3] >= b && g_gra[3] < e)
                            std::fprintf(stderr, "[sign] *** key-read rip in module %s (base %p, +%#llx)\n",
                                         nmz, (void*)b, (unsigned long long)(g_gra[3] - b));
                        for (const char* fn : fns)
                            if (FARPROC pr = GetProcAddress(mods[i], fn))
                                std::fprintf(stderr, "[sign] export %-22s = %s+%#llx\n", fn, nmz,
                                             (unsigned long long)((uint64_t)pr - b));
                    }
                }
            }
            g_force_idx = -1;
            CONTEXT dc{}; dc.ContextFlags = CONTEXT_DEBUG_REGISTERS; GetThreadContext(GetCurrentThread(), &dc);
            dc.Dr7 = 0; dc.ContextFlags = CONTEXT_DEBUG_REGISTERS; SetThreadContext(GetCurrentThread(), &dc);
            if (veh) RemoveVectoredExceptionHandler(veh);
            if (did_flip) bbl::disarm_verdict_flip();
        }
        if (sf) std::fclose(sf);
        std::fprintf(stderr, "[sign] captured %d sign(s) -> %s\n", got, outpath.c_str());
        if (broker_up) { TerminateProcess(broker_pi.hProcess, 0); CloseHandle(broker_pi.hProcess); CloseHandle(broker_pi.hThread); }
        return got > 0 ? 0 : 1;
    }

    bool ok = false;   // must default false: a mode that doesn't set it must NOT print a false SUCCESS
    if (has_flag(argc, argv, "--find-verdict")) {
        // DR-breakpoint diagnostic: drive the sign path so the verification code +
        // strings decode, then locate the unsigned_studio decision (string VAs ->
        // LEA xrefs -> guarding Jcc). Report only; no capture.
        std::fprintf(stderr, "[flip] warming sign path (verdict strings must be resident)...\n");
        for (int i = 0; i < 200 && !Slic3r::bambu::g_unsigned_studio_captured; ++i)
            trigger_fn(&sctx);
        // Disassemble the verification push-site + its callers so the guarding
        // branch (studio_verified ? verify_ok : unsigned_studio) is readable.
        auto& fr = Slic3r::bambu::g_unsigned_studio_plugin_frames;
        std::fprintf(stderr, "[flip] captured %zu plugin frame(s) from unsigned_studio push\n", fr.size());
        for (size_t i = 0; i < fr.size() && i < 4; ++i) {
            std::fprintf(stderr, "[flip] --- disasm around plugin frame #%zu 0x%llx (rva 0x%llx) ---\n",
                         i, fr[i], (unsigned long long)(fr[i] - bbl::plugin_base()));
            bbl::disasm_va(fr[i], 96, 24);
        }
        ok = !fr.empty();
    } else if (has_flag(argc, argv, "--trace-verdict")) {
        // Runtime trace: arm an execute BP on the unsigned_studio message LEA;
        // drive the sign trigger until it fires, dumping regs + stack return chain
        // + backward disasm so the decision instruction is identified.
        std::fprintf(stderr, "[trace] warming sign path...\n");
        for (int i = 0; i < 120; ++i) trigger_fn(&sctx);
        std::vector<bbl::VerdictSite> sites = bbl::find_verdict_sites();
        uint64_t armed = bbl::trace_unsigned_studio(sites);
        if (armed) {
            for (int i = 0; i < 400 && !bbl::trace_captured(); ++i) {
                trigger_fn(&sctx);
                if ((i % 32) == 0)
                    std::fprintf(stderr, "[trace] driving... captured=%d\n", (int)bbl::trace_captured());
            }
        }
        std::fprintf(stderr, "[trace] captured=%d\n", (int)bbl::trace_captured());
        ok = bbl::trace_captured();
    } else if (has_flag(argc, argv, "--flip-capture")) {
        // DR-breakpoint live: warm the sign path, locate + arm the DR breakpoint
        // at the unsigned_studio branch, then run blind_extract while the
        // breakpoint steers the branch to the verified edge every attempt so the
        // plugin proceeds to sign_string_internal and p/q materialise in the heap.
        std::fprintf(stderr, "[flip] warming sign path (capturing unsigned_studio frames)...\n");
        // Drive until the unsigned_studio push back-trace is captured.
        for (int i = 0; i < 300 && !Slic3r::bambu::g_unsigned_studio_captured; ++i)
            trigger_fn(&sctx);
        auto& fr = Slic3r::bambu::g_unsigned_studio_plugin_frames;
        std::fprintf(stderr, "[flip] captured %zu plugin frame(s)\n", fr.size());
        // Arm DR breakpoints at the test-al;jnz in the captured frames (steer the
        // jnz to the verified path, skipping the unsigned_studio branch).
        int armed = bbl::arm_flip_from_frames(fr);
        std::fprintf(stderr, "[flip] arm_flip_from_frames: %d armed\n", armed);
        if (armed) {
            // Drive a burst so the flips fire and unsigned_studio stops.
            for (int i = 0; i < 120; ++i) trigger_fn(&sctx);
            std::fprintf(stderr, "[flip] flip fired %lld time(s) after burst\n",
                         bbl::verdict_flip_hits());
        }
        // Keep the background re-armer RUNNING (it keeps signing stable); it is
        // PAUSED around blind_extract's freeze via flip_pause_rearm() so there is
        // only ONE suspender at a time (no double-suspend crash).
        ok = bbl::blind_extract(out, trigger_fn, &sctx, embedded_test_envelopes(),
                                SLICER_PUBLIC_N_HEX, attempts);
        std::fprintf(stderr, "[flip] total flip hits=%lld  extract ok=%d\n",
                     bbl::verdict_flip_hits(), (int)ok);
        bbl::disarm_verdict_flip();
    } else if (has_flag(argc, argv, "--flip-scan")) {
        // STABLE capture: arm the DR breakpoint, run ONE gentle background signer,
        // and loop a NON-SUSPENDING heap sweep (blind_scan_once). No freeze, no
        // aggressive threading -> no collision with the DR re-armer.
        std::fprintf(stderr, "[flip] warming + capturing unsigned_studio frames...\n");
        for (int i = 0; i < 300 && !Slic3r::bambu::g_unsigned_studio_captured; ++i)
            trigger_fn(&sctx);
        auto& fr = Slic3r::bambu::g_unsigned_studio_plugin_frames;
        int armed = bbl::arm_flip_from_frames(fr);
        std::fprintf(stderr, "[flip] armed=%d; single-thread interleave sign+scan...\n", armed);
        // SINGLE-THREADED, interleaved: the plugin process may exit after a few
        // signs, so scan the heap after EACH sign from the very first one.
        // The RSA private key object (p,q) is resident on the heap once the sign
        // path loads it; a non-suspending sweep catches it inside the stable window.
        int passes = std::atoi(arg_value(argc, argv, "--scan-passes", "40"));
        ok = false;
        for (int p = 0; p < passes && !ok; ++p) {
            for (int s = 0; s < 3; ++s) trigger_fn(&sctx);      // fresh signature(s)
            ok = bbl::blind_scan_once(out, embedded_test_envelopes(), SLICER_PUBLIC_N_HEX);
            std::fprintf(stderr, "[flip] pass %d/%d ok=%d flip_hits=%lld\n",
                         p + 1, passes, (int)ok, bbl::verdict_flip_hits());
        }
        std::fprintf(stderr, "[flip] flip-scan done: ok=%d total flip hits=%lld\n",
                     (int)ok, bbl::verdict_flip_hits());
        bbl::disarm_verdict_flip();
    } else if (has_flag(argc, argv, "--flip-gate")) {
        // DETERMINISTIC TARGETED-REGION capture.
        //
        // A full-memory sweep (blind_scan_montgomery/-once looping over ALL
        // memory) is timing-racy: p/q are a TRANSIENT per-sign heap struct and a
        // slow sweep (~3 min/pass, 5.5M windows) only overlaps a live sign by
        // luck. Two facts let this target instead:
        //   * p and q are stored PLAIN (big- AND little-endian) in a SMALL heap
        //     arena (the [flip-known] repr diagnostic finds p:plainBE / p:plainLE
        //     / q:plainBE / q:plainLE resident during the sign). No Montgomery
        //     de-transform is needed.
        //   * That arena is one of only a handful of small MEM_PRIVATE regions
        //     (a few MB total) -- re-sweeping just those is SUB-MILLISECOND.
        // So: arm the DR breakpoint (so the sign runs), drive a CONTINUOUS signer
        // to keep re-materialising p/q, and TIGHT-LOOP a fast plain division sweep
        // over ONLY the small MEM_PRIVATE regions (blind_scan_gated). Thousands of
        // sweeps/sec back-to-back cover every live-sign instant -> the primes are
        // caught in the first burst, deterministically. Recover + validate
        // (p*q==N + all public envelopes) + write the key.
        std::fprintf(stderr, "[flip-gate] warming + capturing unsigned_studio frames...\n");
        for (int i = 0; i < 300 && !Slic3r::bambu::g_unsigned_studio_captured; ++i)
            trigger_fn(&sctx);
        auto& fr = Slic3r::bambu::g_unsigned_studio_plugin_frames;
        int armed = bbl::arm_flip_from_frames(fr);
        std::fprintf(stderr, "[flip-gate] armed=%d flip breakpoint(s)\n", armed);
        if (armed <= 0) {
            std::fprintf(stderr, "[flip-gate] no flip armed -- cannot proceed\n");
            ok = false;
        } else {
            // blind_scan_gated drives the sign ITSELF (via trigger_fn) immediately
            // before each snapshot, so p/q are captured microseconds after they
            // materialise -- the tightest sign->read coupling, which removes the
            // timing race. No separate signer thread is needed.
            int passes  = std::atoi(arg_value(argc, argv, "--scan-passes", "40"));
            int budget  = std::atoi(arg_value(argc, argv, "--scan-budget-ms", "2000"));
            ok = false;
            // Also capture the cloud APP key (the create_task signer, modulus given
            // via --app-key-sweep) at the SAME gated sign moment. The enc_msg cloud
            // command sign uses the app key, so its p/q are the
            // ones resident during the sign; validating against the app modulus with
            // EMPTY envelopes accepts on p*q==N alone (validate_envelopes 0==0).
            const char* akm = arg_value(argc, argv, "--app-key-sweep", nullptr);
            const bool  want_app = akm && akm[0] && akm[0] != '-';
            bool        app_done = false;
            std::string akout = arg_value(argc, argv, "--app-key-out", "app_key.txt");
            for (int p = 0; p < passes && (!ok || (want_app && !app_done)); ++p) {
                // The plugin exits after 1-2 sweeps, so spend the FIRST pass on
                // the goal -- the app key -- and only fall back to the slicer key
                // when not in app-key mode.
                if (want_app && !app_done &&
                    bbl::blind_scan_gated(akout.c_str(), std::vector<Envelope>{},
                                          akm, budget, trigger_fn, &sctx)) {
                    app_done = true;
                    std::fprintf(stderr, "[flip-gate] *** APP KEY captured -> %s ***\n",
                                 akout.c_str());
                }
                if (!ok && !want_app)
                    ok = bbl::blind_scan_gated(out, embedded_test_envelopes(),
                                               SLICER_PUBLIC_N_HEX, budget,
                                               trigger_fn, &sctx);
                std::fprintf(stderr, "[flip-gate] pass %d/%d ok=%d app_key=%d flip_hits=%lld\n",
                             p + 1, passes, (int)ok, (int)app_done, bbl::verdict_flip_hits());
            }
            std::fprintf(stderr, "[flip-gate] done: ok=%d flip_hits=%lld\n",
                         (int)ok, bbl::verdict_flip_hits());
        }
        bbl::disarm_verdict_flip();
    } else if (has_flag(argc, argv, "--flip-known")) {
        // REPRESENTATION DIAGNOSTIC + MONTGOMERY-AWARE CAPTURE with the DR
        // breakpoint armed.
        // 1. Arm the DR breakpoint so the sign runs (p/q materialise).
        // 2. Run scan_known_representations (a reference key used ONLY as a search
        //    key) to pin the exact storage form of p/q in the LIVE plugin.
        // 3. Run blind_scan_montgomery (no foreknowledge) to capture+validate.
        std::fprintf(stderr, "[flip-known] warming + capturing unsigned_studio frames...\n");
        for (int i = 0; i < 300 && !Slic3r::bambu::g_unsigned_studio_captured; ++i)
            trigger_fn(&sctx);
        auto& fr = Slic3r::bambu::g_unsigned_studio_plugin_frames;
        int armed = bbl::arm_flip_from_frames(fr);
        std::fprintf(stderr, "[flip-known] armed=%d\n", armed);
        const char* gt = arg_value(argc, argv, "--diag-known", "d_extracted.json");
        int passes = std::atoi(arg_value(argc, argv, "--scan-passes", "30"));
        ok = false;
        for (int p = 0; p < passes && !ok; ++p) {
            for (int s = 0; s < 3; ++s) trigger_fn(&sctx);      // fresh signature(s)
            // (a) representation diagnostic every few passes (it is heavier).
            if (p == 0 || (p % 5) == 4) {
                char lbl[32]; std::snprintf(lbl, sizeof lbl, "flip-p%d", p);
                bbl::scan_known_representations(gt, SLICER_PUBLIC_N_HEX, lbl);
            }
            // (b) blind Montgomery-aware capture.
            ok = bbl::blind_scan_montgomery(out, embedded_test_envelopes(), SLICER_PUBLIC_N_HEX);
            std::fprintf(stderr, "[flip-known] pass %d/%d ok=%d flip_hits=%lld\n",
                         p + 1, passes, (int)ok, bbl::verdict_flip_hits());
        }
        std::fprintf(stderr, "[flip-known] done: ok=%d total flip hits=%lld\n",
                     (int)ok, bbl::verdict_flip_hits());
        bbl::disarm_verdict_flip();
    } else if (const char* lk = arg_value(argc, argv, "--find-log-key", nullptr)) {
        // Recover the plugin's AES-128-ECB debug-log key from its LIVE memory
        // (it's resident now that the plugin is loaded + connected), and decrypt
        // the log. Drive a bit first so the log has fresh content and the key is
        // materialised.
        for (int i = 0; i < 60; ++i) trigger_fn(&sctx);
        const char* ko = arg_value(argc, argv, "--key-out", nullptr);
        ok = (bbl::find_log_key(lk, ko) == 0);
    } else if (has_flag(argc, argv, "--find-config-key")) {
        // Recover the plugin's AES-128-ECB CONFIG key (network_engine.key,
        // i4crL3LESLnWapLS) BLIND from live memory, using BambuNetworkEngine.conf
        // as the decryption oracle. The config decrypt runs at plugin init, so no
        // sign/flip/printer is required; drive a few triggers so init has settled.
        for (int i = 0; i < 5; ++i) trigger_fn(&sctx);
        const char* cf = arg_value(argc, argv, "--find-config-key", nullptr);
        if (cf && cf[0] == '-') cf = nullptr;   // bare flag -> default path inside
        ok = (bbl::find_config_key(cf, out) == 0);
    } else if (has_flag(argc, argv, "--find-app-identity")) {
        // Recover THIS account's app_identity ("GLOF<digits>-<hex...>") from the
        // plugin's live memory. It materialises when the plugin builds a get_app_cert
        // request, so drive the cloud session until it appears (get_app_cert runs
        // upstream of the verification check, so no printer sign is needed). Write it
        // to --out for the app-cert fetch step. No cloud secret is reproduced.
        std::string aid;
        for (int i = 0; i < 60 && aid.empty(); ++i) {
            trigger_fn(&sctx);
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            aid = bbl::scan_app_identity();
        }
        if (!aid.empty()) {
            std::fprintf(stderr, "[app-identity] recovered %s\n", aid.c_str());
            FILE* f = std::fopen(out, "wb");
            if (f) { std::fwrite(aid.data(), 1, aid.size(), f); std::fclose(f); }
            ok = true;
        } else {
            std::fprintf(stderr, "[app-identity] not found in plugin memory\n");
            ok = false;
        }
    } else if (has_flag(argc, argv, "--extract-appkey")) {
        // Per-user app-key extractor. get_app_cert runs on the cloud session and
        // decrypts THIS account's app RSA private key into the plugin heap (the
        // decrypt routine is obfuscated, but the plaintext key + app cert +
        // app_identity all land in the heap). Settle so they are resident, then
        // snapshot heap+image. assemble_appkey.py turns the snapshot into
        // app_key.pem + app_cert_id.txt + app_identity.txt for the OSS plugin --
        // no cloud secret is reproduced; it just reads this account's own key.
        const char* od = arg_value(argc, argv, "--out", "appkey_out");
        CreateDirectoryA(od, nullptr);
        // Always snapshot the heap first -- the app cert (modulus + cert_id) and
        // app_identity are resident after get_app_cert (used to derive N + metadata).
        std::fprintf(stderr, "[extract] settling cloud session so get_app_cert runs...\n");
        for (int i = 0; i < 12; ++i) { trigger_fn(&sctx); std::this_thread::sleep_for(std::chrono::milliseconds(400)); }
        int rc = bbl::dump_plugin_regions(od);
        std::fprintf(stderr, "[extract] cert/app_identity snapshot -> %s (rc=%d)\n", od, rc);
        // If the modulus is supplied, ALSO loop-sweep the heap for the app key's
        // p/q (they materialise while the key is in use). N comes from the cert in
        // the snapshot (assemble_appkey.py derives it, then re-invokes with --modulus).
        ok = (rc == 0);
        const char* mod = arg_value(argc, argv, "--modulus", nullptr);
        if (mod && mod[0] && mod[0] != '-') {
            // The sweep was PRE-ARMED before get_app_cert (see after handle.init()),
            // so it was already looping through the decrypt window. Keep driving so
            // get_app_cert re-fires (more decrypt windows) and wait for a hit.
            std::string pqout = std::string(od) + "\\app_key_pq.txt";
            std::fprintf(stderr, "[extract] waiting for app-key p/q (sweep pre-armed)...\n");
            for (int i = 0; i < 120 && !bbl::app_key_sweep_found(); ++i) {
                trigger_fn(&sctx);
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            bbl::stop_app_key_sweep();
            ok = bbl::app_key_sweep_found();
            std::fprintf(stderr, "[extract] app-key p/q %s -> %s\n", ok ? "FOUND" : "NOT FOUND", pqout.c_str());
        }
    } else {
        ok = bbl::blind_extract(out, trigger_fn, &sctx, embedded_test_envelopes(),
                                SLICER_PUBLIC_N_HEX, attempts);
    }

    if (broker_up) {
        TerminateProcess(broker_pi.hProcess, 0);
        CloseHandle(broker_pi.hProcess); CloseHandle(broker_pi.hThread);
    }

    const char* what = has_flag(argc, argv, "--find-config-key")  ? "recovered config key (network_engine.key)"
                     : has_flag(argc, argv, "--find-log-key")     ? "recovered debug-log key"
                     : has_flag(argc, argv, "--find-app-identity") ? "recovered app_identity"
                     : "validated slicer key";
    if (ok) std::fprintf(stderr, "[host] *** SUCCESS: %s -> %s ***\n", what, out);
    else    std::fprintf(stderr, "[host] extraction failed\n");
    return ok ? 0 : 1;
}
