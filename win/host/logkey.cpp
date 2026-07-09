// Recover the plugin's AES-128-ECB debug-log key from the LIVE plugin process
// memory, then decrypt a .log.enc. The debug log records how the plugin handles
// RSA signing (plaintext vs encrypted, rc=-2). The key is not stored on disk but
// is resident in the running plugin's memory while it logs. We scan committed
// private memory: for each 16-byte window, AES-128-ECB-decrypt the log's first
// blocks and keep keys whose output is high-printable (the log plaintext is
// text/JSON).
#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

namespace bbl {

static bool read_file(const char* p, std::vector<uint8_t>& out) {
    FILE* f = std::fopen(p, "rb");
    if (!f) return false;
    uint8_t buf[4096]; size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) out.insert(out.end(), buf, buf + n);
    std::fclose(f);
    return true;
}

static bool readable_prot(DWORD p) {
    if (p & PAGE_GUARD) return false;
    if (p & PAGE_NOACCESS) return false;
    return (p & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                 PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
}

static int printable_score(const uint8_t* p, int n) {
    int ok = 0;
    for (int i = 0; i < n; ++i) {
        uint8_t c = p[i];
        if (c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f)) ++ok;
    }
    return ok * 100 / n;
}

// AES-128-ECB decrypt `nblocks` 16-byte blocks of `ct` with `key` into `pt`.
static bool aes_ecb_dec(BCRYPT_ALG_HANDLE hAlg, const uint8_t key[16],
                        const uint8_t* ct, uint8_t* pt, int nbytes) {
    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key, 16, 0) != 0)
        return false;
    ULONG res = 0;
    NTSTATUS s = BCryptDecrypt(hKey, (PUCHAR)ct, nbytes, nullptr, nullptr, 0,
                               pt, nbytes, &res, 0);
    BCryptDestroyKey(hKey);
    return s == 0;
}

// Returns 0 on success (prints the key + decrypted preview), 1 otherwise.
int find_log_key(const char* logpath) {
    std::vector<uint8_t> log;
    if (!read_file(logpath, log) || log.size() < 64) {
        std::fprintf(stderr, "[logkey] cannot read log %s\n", logpath);
        return 1;
    }
    const int TEST = 48;  // 3 blocks
    // Try ciphertext starting at offset 0 and at 16 (in case of a 1-block header).
    const int ct_off = 0;
    uint8_t ct[TEST];
    std::memcpy(ct, log.data() + ct_off, TEST);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) {
        std::fprintf(stderr, "[logkey] BCryptOpenAlgorithmProvider failed\n");
        return 1;
    }
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                      sizeof(BCRYPT_CHAIN_MODE_ECB), 0);

    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uintptr_t maxA = (uintptr_t)si.lpMaximumApplicationAddress, a = 0;
    MEMORY_BASIC_INFORMATION m{};
    long long windows = 0, hits = 0;
    int best = 0; uint8_t best_key[16]; uint8_t best_pt[TEST];
    std::vector<uint8_t> buf;

    while (a < maxA && VirtualQuery((void*)a, &m, sizeof m)) {
        uintptr_t rb = (uintptr_t)m.BaseAddress; size_t rs = m.RegionSize;
        // Committed readable data (heap/data AND the DLL's decrypted image data,
        // where the key/cert resides). Skip only huge mapped files.
        if (m.State == MEM_COMMIT && readable_prot(m.Protect) &&
            rs >= 16 && rs < (size_t)256 * 1024 * 1024) {
            buf.resize(rs);
            SIZE_T got = 0;
            if (ReadProcessMemory(GetCurrentProcess(), (void*)rb, buf.data(), rs, &got) && got >= 16) {
                const uint8_t* bp = buf.data();
                uint8_t pt[TEST];
                for (size_t off = 0; off + 16 <= got; off += 4) {
                    ++windows;
                    if (!aes_ecb_dec(hAlg, bp + off, ct, pt, TEST)) continue;
                    int sc = printable_score(pt, TEST);
                    if (sc > best) {
                        best = sc; std::memcpy(best_key, bp + off, 16); std::memcpy(best_pt, pt, TEST);
                    }
                    if (sc >= 95) {
                        ++hits;
                        std::fprintf(stderr, "[logkey] candidate @%p score=%d key=", (void*)(rb + off), sc);
                        for (int i = 0; i < 16; ++i) std::fprintf(stderr, "%02x", bp[off + i]);
                        std::fprintf(stderr, " pt='%.*s'\n", TEST, (const char*)pt);
                    }
                }
            }
        }
        a = rb + rs; if (rs == 0) break;
    }
    std::fprintf(stderr, "[logkey] scanned %lld windows, %lld high-printable hits; best score=%d\n",
                 windows, hits, best);
    if (best >= 90) {
        std::fprintf(stderr, "[logkey] BEST key=");
        for (int i = 0; i < 16; ++i) std::fprintf(stderr, "%02x", best_key[i]);
        std::fprintf(stderr, "\n[logkey] BEST preview='%.*s'\n", TEST, (const char*)best_pt);
        // Full-log decrypt to a sidecar file for inspection.
        size_t full = log.size() & ~size_t(15);
        std::vector<uint8_t> out(full);
        if (aes_ecb_dec(hAlg, best_key, log.data(), out.data(), (int)full)) {
            std::string op = std::string(logpath) + ".dec";
            FILE* of = std::fopen(op.c_str(), "wb");
            if (of) { std::fwrite(out.data(), 1, full, of); std::fclose(of);
                      std::fprintf(stderr, "[logkey] wrote decrypted log -> %s\n", op.c_str()); }
        }
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return best >= 90 ? 0 : 1;
}

// True iff the 16-byte window is entirely printable ASCII. Both of the plugin's
// baked AES keys are 16-char ASCII strings (log key yyuBcftO2jkZeucy, config key
// i4crL3LESLnWapLS), so this cheap prefilter lets us scan byte-granular fast:
// only ASCII-string windows reach the (expensive) AES-decrypt oracle test.
static bool ascii_key16(const uint8_t* p) {
    for (int i = 0; i < 16; ++i)
        if (p[i] < 0x20 || p[i] > 0x7e) return false;
    return true;
}

// Recover the plugin's AES-128-ECB CONFIG key (a.k.a. network_engine.key) BLIND
// from live process memory, using the encrypted BambuNetworkEngine.conf as the
// oracle: the correct 16-byte key decrypts it to JSON (leading '{', high
// printable). No foreknowledge of the key value is used in the search; the
// known-value comparison at the end is only a self-verification of the result.
// confpath NULL/empty -> %APPDATA%\BambuStudio\BambuNetworkEngine.conf.
// Returns 0 on success (prints the recovered key + a non-sensitive preview).
int find_config_key(const char* confpath, const char* outpath) {
    std::string cp;
    if (confpath && confpath[0]) {
        cp = confpath;
    } else {
        const char* ad = std::getenv("APPDATA");
        if (!ad) { std::fprintf(stderr, "[cfgkey] no APPDATA and no --find-config-key path\n"); return 1; }
        cp = std::string(ad) + "\\BambuStudio\\BambuNetworkEngine.conf";
    }
    std::vector<uint8_t> conf;
    if (!read_file(cp.c_str(), conf) || conf.size() < 48) {
        std::fprintf(stderr, "[cfgkey] cannot read conf oracle %s (need >=48 bytes)\n", cp.c_str());
        return 1;
    }
    std::fprintf(stderr, "[cfgkey] oracle: %s (%zu bytes)\n", cp.c_str(), conf.size());
    const int TEST = 48;  // 3 AES blocks of the encrypted config
    uint8_t ct[TEST];
    std::memcpy(ct, conf.data(), TEST);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) {
        std::fprintf(stderr, "[cfgkey] BCryptOpenAlgorithmProvider failed\n"); return 1;
    }
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                      sizeof(BCRYPT_CHAIN_MODE_ECB), 0);

    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uintptr_t maxA = (uintptr_t)si.lpMaximumApplicationAddress, a = 0;
    MEMORY_BASIC_INFORMATION m{};
    long long windows = 0, ascii_win = 0, hits = 0;
    int best = 0; uint8_t best_key[16]{}; uint8_t best_pt[TEST]{};
    std::vector<uint8_t> buf;

    while (a < maxA && VirtualQuery((void*)a, &m, sizeof m)) {
        uintptr_t rb = (uintptr_t)m.BaseAddress; size_t rs = m.RegionSize;
        if (m.State == MEM_COMMIT && readable_prot(m.Protect) &&
            rs >= 16 && rs < (size_t)256 * 1024 * 1024) {
            buf.resize(rs);
            SIZE_T got = 0;
            if (ReadProcessMemory(GetCurrentProcess(), (void*)rb, buf.data(), rs, &got) && got >= 16) {
                const uint8_t* bp = buf.data();
                uint8_t pt[TEST];
                for (size_t off = 0; off + 16 <= got; off += 1) {
                    ++windows;
                    if (!ascii_key16(bp + off)) continue;     // cheap prefilter
                    ++ascii_win;
                    if (!aes_ecb_dec(hAlg, bp + off, ct, pt, TEST)) continue;
                    if (pt[0] != '{') continue;               // config plaintext is JSON
                    int sc = printable_score(pt, TEST);
                    if (sc > best) { best = sc; std::memcpy(best_key, bp + off, 16); std::memcpy(best_pt, pt, TEST); }
                    if (sc >= 95) {
                        ++hits;
                        std::fprintf(stderr, "[cfgkey] candidate @%p key(ascii)='%.16s' pt='%.*s'\n",
                                     (void*)(rb + off), (const char*)(bp + off), 32, (const char*)pt);
                    }
                }
            }
        }
        a = rb + rs; if (rs == 0) break;
    }
    std::fprintf(stderr, "[cfgkey] scanned %lld windows (%lld ascii), %lld JSON hits; best score=%d\n",
                 windows, ascii_win, hits, best);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (best >= 90 && best_pt[0] == '{') {
        std::fprintf(stderr, "[cfgkey] RECOVERED config key (ascii)='%.16s' hex=", (const char*)best_key);
        for (int i = 0; i < 16; ++i) std::fprintf(stderr, "%02x", best_key[i]);
        std::fprintf(stderr, "\n[cfgkey] conf preview='%.*s'\n", 40, (const char*)best_pt);
        static const uint8_t KNOWN[16] = { 'i','4','c','r','L','3','L','E','S','L','n','W','a','p','L','S' };
        std::fprintf(stderr, "[cfgkey] matches known network_engine.key (i4crL3LESLnWapLS): %s\n",
                     std::memcmp(best_key, KNOWN, 16) == 0 ? "YES" : "no");
        if (outpath && outpath[0]) {
            if (FILE* of = std::fopen(outpath, "wb")) {
                std::fprintf(of, "network_engine.key (AES-128-ECB)\nascii: %.16s\nhex:   ", (const char*)best_key);
                for (int i = 0; i < 16; ++i) std::fprintf(of, "%02x", best_key[i]);
                std::fprintf(of, "\n");
                std::fclose(of);
                std::fprintf(stderr, "[cfgkey] wrote key -> %s\n", outpath);
            }
        }
        return 0;
    }
    std::fprintf(stderr, "[cfgkey] no JSON-decrypting key found resident in plugin memory\n");
    return 1;
}

}  // namespace bbl
