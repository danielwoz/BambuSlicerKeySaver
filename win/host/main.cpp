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
#include "host/app_key_sweep.hpp"
#include "host/death_diag.hpp"
#include "reconstruct.h"
#include "bigint.h"

using Slic3r::bambu::BambuNetworkingPluginHandle;
using Slic3r::bambu::PluginHandleConfig;

namespace bbl { int find_log_key(const char* logpath); int find_config_key(const char* confpath, const char* outpath); }

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
// On-disk extraction: BambuStudio stores the slicer signing key in PLAINTEXT at
// %APPDATA%/BambuStudio/slicer_key.pem (PKCS#1 RSA private key). It is the SAME
// key the plugin loads to sign -- byte-identical to the heap-extracted key, and
// it reproduces the captured signatures exactly. So the reliable Windows
// "extraction" is simply to read + self-validate this file. No plugin, no
// printer, no capture.
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
        std::fprintf(stderr, "[disk] cannot read %s (is BambuStudio installed + logged in?)\n", pem_path);
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
            "# Slicer RSA-2048 private key - read from on-disk slicer_key.pem (Windows)\n"
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

    // Downstream-only proof (no plugin): a correct 256-byte accumulator capture
    // reconstructs + validates the slicer key.
    if (has_flag(argc, argv, "--capture-selftest")) {
        bool ok = capture_downstream_selftest(embedded_test_envelopes(), SLICER_PUBLIC_N_HEX);
        std::fprintf(stderr, "[capA-selftest] %s\n", ok ? "PASS" : "FAIL");
        return ok ? 0 : 1;
    }

    // Reliable extraction (no plugin, no printer): read BambuStudio's on-disk
    // slicer_key.pem and self-validate. This IS the slicer signing key. Default
    // path is %APPDATA%/BambuStudio/slicer_key.pem; override with --slicer-key.
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
    std::fprintf(stderr, "[host] installing verification-faking shim...\n");
    bbl::install_verify_fake();

    // 4b. Cloud plaintext tap: capture the genuine plugin's HTTP request/response
    //     plaintext (endpoint, X-BBL-* headers, Bearer, PEM cert/key) straight from
    //     its private heap during the live cloud session -- read from the plugin's
    //     own buffers rather than the TLS socket (static OpenSSL + pinned cloud
    //     CA). Gate on --tap/BBL_TAP_LOG.
    if (has_flag(argc, argv, "--tap") || std::getenv("BBL_TAP_LOG")) {
        bbl::start_cloud_tap();
        std::atexit(bbl::stop_cloud_tap);
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
    //     real MQTT serial (00M00A000000000) to search for; falls back to
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
            // command sign uses the app key (cert_id 00000000), so its p/q are the
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
        ok = (bbl::find_log_key(lk) == 0);
    } else if (has_flag(argc, argv, "--find-config-key")) {
        // Recover the plugin's AES-128-ECB CONFIG key (network_engine.key,
        // i4crL3LESLnWapLS) BLIND from live memory, using BambuNetworkEngine.conf
        // as the decryption oracle. The config decrypt runs at plugin init, so no
        // sign/flip/printer is required; drive a few triggers so init has settled.
        for (int i = 0; i < 5; ++i) trigger_fn(&sctx);
        const char* cf = arg_value(argc, argv, "--find-config-key", nullptr);
        if (cf && cf[0] == '-') cf = nullptr;   // bare flag -> default path inside
        ok = (bbl::find_config_key(cf, out) == 0);
    } else {
        ok = bbl::blind_extract(out, trigger_fn, &sctx, embedded_test_envelopes(),
                                SLICER_PUBLIC_N_HEX, attempts);
    }

    if (broker_up) {
        TerminateProcess(broker_pi.hProcess, 0);
        CloseHandle(broker_pi.hProcess); CloseHandle(broker_pi.hThread);
    }

    const char* what = has_flag(argc, argv, "--find-config-key") ? "recovered config key (network_engine.key)"
                     : has_flag(argc, argv, "--find-log-key")    ? "recovered debug-log key"
                     : "validated slicer key";
    if (ok) std::fprintf(stderr, "[host] *** SUCCESS: %s -> %s ***\n", what, out);
    else    std::fprintf(stderr, "[host] extraction failed\n");
    return ok ? 0 : 1;
}
