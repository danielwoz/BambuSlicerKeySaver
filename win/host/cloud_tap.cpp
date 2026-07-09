#include "cloud_tap.hpp"

#if defined(_WIN32)

#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <atomic>
#include <thread>
#include <unordered_set>
#include <vector>

namespace {

FILE*                    g_log = nullptr;
std::atomic<bool>        g_run{false};
std::thread              g_thr;
std::atomic<long long>   g_hits{0};
std::unordered_set<uint64_t> g_seen;      // dedup by FNV-1a of window head

// Markers that indicate a plaintext HTTP request or response block. Kept in the
// plugin's PRIVATE heap; we deliberately scan only MEM_PRIVATE so our own copy
// of these literals (in bambu_host's MEM_IMAGE .rdata) never self-matches.
const char* const kMarkers[] = {
    "Authorization: Bearer",
    "X-BBL-Client",
    "X-BBL-Executable",
    "X-BBL-Agent",
    "GET /v1/",
    "POST /v1/",
    "PUT /v1/",
    "Host: api.bambulab",
    "iot-service/api",
    "/applications/",
    "\"aes256\"",
    "app_key",
    "-----BEGIN CERTIFICATE-----",
    "-----BEGIN RSA PRIVATE",
    "-----BEGIN PRIVATE KEY-----",
    "get_app_cert",
    "device-security-sign",
    "GLOF0000000000.bambulab.com",   // DER cert subject/issuer CN -> triggers DER dump
};
constexpr int NM = (int)(sizeof(kMarkers) / sizeof(kMarkers[0]));

size_t   g_mlen[NM];
bool     g_first[256];
bool     g_tables_ready = false;

// ---- DER X.509 app-cert capture ------------------------------------------
// The decrypted cloud app cert (and slicer/device certs) briefly appear in the
// plugin's PRIVATE heap as raw DER X.509. Their subject/issuer DN embeds the
// ASCII string below (CN=GLOF0000000000.bambulab.com). When we see it we walk
// BACKWARD to the enclosing outer Certificate SEQUENCE (30 82 LL LL), read its
// declared length, and dump those exact DER bytes to a per-cert file so the
// full cert (and its RSA modulus) can be decoded offline -- unlike the 8KB
// HTTP window which fragments the cert. Distinct certs are deduped by content
// hash, so the slicer cert, app cert and device cert each land once.
const char kDerCn[] = "GLOF0000000000.bambulab.com";
constexpr size_t kDerCnLen = sizeof(kDerCn) - 1;

std::unordered_set<uint64_t>  g_der_seen;      // dedup dumped certs by full-DER hash
std::atomic<long long>        g_der_hits{0};
char                          g_der_dir[MAX_PATH] = {0};
bool                          g_der_dir_ready = false;

void build_tables() {
    if (g_tables_ready) return;
    memset(g_first, 0, sizeof(g_first));
    for (int i = 0; i < NM; ++i) {
        g_mlen[i] = strlen(kMarkers[i]);
        g_first[(unsigned char)kMarkers[i][0]] = true;
    }
    g_tables_ready = true;
}

uint64_t fnv1a(const uint8_t* p, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

struct RawHit { const char* marker; const uint8_t* at; };

// Single linear pass over one region, first-byte gated. All raw pointer work is
// inside SEH so a region freed mid-scan (a race with the plugin) just aborts this
// region instead of crashing the host. POD-only -> __try is legal here.
int scan_region_raw(const uint8_t* base, size_t rsz, RawHit* hits, int cap) {
    int n = 0;
    __try {
        for (size_t i = 0; i < rsz && n < cap; ++i) {
            unsigned char c = base[i];
            if (!g_first[c]) continue;
            for (int mi = 0; mi < NM; ++mi) {
                size_t ml = g_mlen[mi];
                if (c == (unsigned char)kMarkers[mi][0] &&
                    i + ml <= rsz &&
                    memcmp(base + i, kMarkers[mi], ml) == 0) {
                    hits[n].marker = kMarkers[mi];
                    hits[n].at     = base + i;
                    if (++n >= cap) break;
                    i += ml - 1;                 // don't re-hit the same match
                    break;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return n;
    }
    return n;
}

// Back up to the start of the HTTP block (request line / status line, within 3KB)
// and copy up to dstcap bytes into dst. Returns bytes copied (0 on fault). POD-only.
size_t grab_window_raw(const uint8_t* base, size_t rsz, const uint8_t* at,
                       uint8_t* dst, size_t dstcap) {
    size_t got = 0;
    __try {
        const uint8_t* start = at;
        size_t back = (size_t)(at - base);
        size_t lim  = back < 3072 ? back : 3072;
        for (size_t k = 1; k <= lim; ++k) {
            const uint8_t* p = at - k;
            if (p + 8 <= base + rsz &&
                (memcmp(p, "GET /",   5) == 0 ||
                 memcmp(p, "POST /",  6) == 0 ||
                 memcmp(p, "PUT /",   5) == 0 ||
                 memcmp(p, "DELETE ", 7) == 0 ||
                 memcmp(p, "HTTP/1.", 7) == 0)) {
                start = p;                        // keep backing up to the earliest
            }
        }
        size_t avail = (size_t)(base + rsz - start);
        size_t wn    = avail < dstcap ? avail : dstcap;
        memcpy(dst, start, wn);
        got = wn;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        got = 0;
    }
    return got;
}

void emit(const char* marker, const uint8_t* va, const uint8_t* buf, size_t wn) {
    // Trim the tail to the plausible end of the block (double CRLF after headers is
    // kept; we just cap trailing NULs for readability).
    while (wn > 0 && buf[wn - 1] == 0) --wn;
    if (wn < 8) return;
    uint64_t h = fnv1a(buf, wn < 256 ? wn : 256);
    if (g_seen.count(h)) return;
    g_seen.insert(h);
    ++g_hits;
    FILE* f = g_log ? g_log : stderr;
    fprintf(f, "\n==== [cloud_tap] hit #%lld marker='%s' va=%p len=%zu ====\n",
            (long long)g_hits.load(), marker, (const void*)va, wn);
    fwrite(buf, 1, wn, f);
    fprintf(f, "\n==== [cloud_tap] end ====\n");
    fflush(f);
}

// Resolve the per-cert dump directory once. Defaults to <BBL_TAP_LOG dir or
// cwd>\appcert_dump, overridable via BBL_APPCERT_DIR. Created if absent.
void der_dir_init() {
    if (g_der_dir_ready) return;
    g_der_dir_ready = true;
    const char* d = std::getenv("BBL_APPCERT_DIR");
    if (d && d[0]) {
        strncpy(g_der_dir, d, sizeof(g_der_dir) - 1);
    } else {
        // Derive from BBL_TAP_LOG's directory if set, else cwd.
        const char* lp = std::getenv("BBL_TAP_LOG");
        char base[MAX_PATH] = {0};
        if (lp && lp[0]) {
            strncpy(base, lp, sizeof(base) - 1);
            char* slash = strrchr(base, '\\');
            char* fwd   = strrchr(base, '/');
            if (fwd > slash) slash = fwd;
            if (slash) *slash = 0; else base[0] = 0;
        }
        if (base[0])
            _snprintf(g_der_dir, sizeof(g_der_dir) - 1, "%s\\appcert_dump", base);
        else
            strncpy(g_der_dir, "appcert_dump", sizeof(g_der_dir) - 1);
    }
    CreateDirectoryA(g_der_dir, nullptr);   // ok if it already exists
}

// Copy the DER cert enclosing `at` (a pointer to the CN string) into dst.
// Walks BACKWARD from `at` for an outer Certificate SEQUENCE header 30 82 HH LL
// whose declared length (HH LL big-endian) + 4 encloses `at` and stays inside
// the region. Returns total DER length copied (0 on miss/fault). POD-only, so
// the raw reads are SEH-guarded exactly like the other scanners (the region may
// be freed mid-walk). A real X.509 cert is 30 82 .. so we only accept the
// 2-byte-length long form, which every RSA-2048 cert here uses (~0x3xx bytes).
size_t grab_der_cert_raw(const uint8_t* base, size_t rsz, const uint8_t* at,
                         uint8_t* dst, size_t dstcap) {
    size_t got = 0;
    __try {
        size_t back = (size_t)(at - base);
        // A 2048-bit self-signed cert is ~0x3c0 bytes; the CN sits a few hundred
        // bytes in. Search a generous 8KB window back for the SEQUENCE header.
        size_t lim = back < 8192 ? back : 8192;
        for (size_t k = 4; k <= lim; ++k) {
            const uint8_t* p = at - k;
            if (p[0] != 0x30 || p[1] != 0x82) continue;
            size_t len   = ((size_t)p[2] << 8) | (size_t)p[3];
            size_t total = len + 4;                       // header (4) + content
            if (total < 256 || total > dstcap) continue;  // reject implausible
            const uint8_t* end = p + total;
            // Must enclose the CN marker and stay within the committed region.
            if ((const uint8_t*)at + kDerCnLen > end) continue;
            if (end > base + rsz) continue;
            // Sanity: the byte right after the outer SEQ length must be the tbs
            // SEQUENCE (30 82 ..) -- an X.509 Certificate is SEQ{ SEQ tbs, .. }.
            if (p[4] != 0x30 || p[5] != 0x82) continue;
            memcpy(dst, p, total);
            got = total;
            break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        got = 0;
    }
    return got;
}

// Persist a captured DER cert (deduped by content hash) to its own file and log
// a one-line hex record. Files: <der_dir>\cert_<hash16>.der.
void emit_der(const uint8_t* va, const uint8_t* der, size_t n) {
    if (n < 256) return;
    uint64_t h = fnv1a(der, n);
    if (g_der_seen.count(h)) return;
    g_der_seen.insert(h);
    ++g_der_hits;
    der_dir_init();

    char path[MAX_PATH];
    _snprintf(path, sizeof(path) - 1, "%s\\cert_%016llx.der",
              g_der_dir, (unsigned long long)h);
    if (FILE* cf = std::fopen(path, "wb")) {
        std::fwrite(der, 1, n, cf);
        std::fclose(cf);
    }

    FILE* f = g_log ? g_log : stderr;
    fprintf(f, "\n==== [cloud_tap] DER cert #%lld va=%p len=%zu -> %s ====\n",
            (long long)g_der_hits.load(), (const void*)va, n, path);
    // Full hex on one line so the cert can also be reconstructed from the log.
    for (size_t i = 0; i < n; ++i) fprintf(f, "%02x", der[i]);
    fprintf(f, "\n==== [cloud_tap] DER end ====\n");
    fflush(f);
}

void scan_once() {
    build_tables();
    SYSTEM_INFO si; GetSystemInfo(&si);
    uint8_t* addr = (uint8_t*)si.lpMinimumApplicationAddress;
    uint8_t* maxa = (uint8_t*)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    std::vector<uint8_t> win(8192);
    std::vector<uint8_t> der(16384);          // holds one outer DER cert (~1KB)
    RawHit hits[64];

    while (addr < maxa && VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        uint8_t* rbase = (uint8_t*)mbi.BaseAddress;
        size_t   rsz   = mbi.RegionSize;

        bool prot_ok = (mbi.Protect == PAGE_READWRITE ||
                        mbi.Protect == PAGE_READONLY  ||
                        mbi.Protect == PAGE_WRITECOPY ||
                        mbi.Protect == PAGE_EXECUTE_READWRITE);
        if (mbi.Protect & PAGE_GUARD) prot_ok = false;

        // Only the plugin's private heap holds the transient plaintext; skip
        // images/mapped (our own marker literals live in an image) and cap size.
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && prot_ok &&
            rsz > 0 && rsz < (size_t)(512ull << 20)) {
            int n = scan_region_raw(rbase, rsz, hits, 64);
            for (int i = 0; i < n; ++i) {
                // DER-cert capture: the CN marker lives inside a raw X.509 cert.
                // Walk back to the outer SEQUENCE and dump the whole cert. This
                // is independent of (and in addition to) the HTTP-window dump.
                if (hits[i].marker == kDerCn ||
                    memcmp(hits[i].marker, kDerCn, kDerCnLen) == 0) {
                    size_t dn = grab_der_cert_raw(rbase, rsz, hits[i].at,
                                                  der.data(), der.size());
                    if (dn) emit_der(hits[i].at, der.data(), dn);
                }
                size_t wn = grab_window_raw(rbase, rsz, hits[i].at, win.data(), win.size());
                if (wn) emit(hits[i].marker, hits[i].at, win.data(), wn);
            }
        }

        uint8_t* next = rbase + rsz;
        if (next <= addr) break;                 // overflow / no progress guard
        addr = next;
    }
}

void loop() {
    // Poll while the session runs. Cloud request/response buffers persist tens of
    // ms to seconds; a ~150ms cadence reliably catches them without much cost
    // (MEM_PRIVATE only, first-byte gated single pass).
    while (g_run.load()) {
        scan_once();
        Sleep(150);
    }
    scan_once();                                 // final pass on shutdown
}

}  // namespace

namespace bbl {

void start_cloud_tap() {
    if (g_run.load()) return;
    if (const char* lp = std::getenv("BBL_TAP_LOG")) {
        if (lp[0]) g_log = std::fopen(lp, "a");
    }
    build_tables();
    g_run = true;
    g_thr = std::thread(loop);
    fprintf(stderr, "[cloud_tap] started (log=%s)\n",
            g_log ? "BBL_TAP_LOG" : "stderr");
}

void stop_cloud_tap() {
    if (!g_run.load()) return;
    g_run = false;
    if (g_thr.joinable()) g_thr.join();
    fprintf(stderr, "[cloud_tap] stopped; %lld distinct blocks, %lld DER certs captured\n",
            (long long)g_hits.load(), (long long)g_der_hits.load());
    if (g_log) { std::fflush(g_log); std::fclose(g_log); g_log = nullptr; }
}

long long cloud_tap_hits() { return g_hits.load(); }

}  // namespace bbl

#else   // !_WIN32
namespace bbl {
void start_cloud_tap() {}
void stop_cloud_tap() {}
long long cloud_tap_hits() { return 0; }
}
#endif
