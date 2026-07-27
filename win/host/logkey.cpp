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
#include "key_oracle.h"   // bbl_oracle:: printable_score / conf_key_matches / log_key_score (shared with Linux)

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

// AES-ECB decrypt `nbytes` (multiple of 16) of `ct` with a `klen`-byte `key`.
static bool aes_ecb_dec(BCRYPT_ALG_HANDLE hAlg, const uint8_t* key, int klen,
                        const uint8_t* ct, uint8_t* pt, int nbytes) {
    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key, (ULONG)klen, 0) != 0)
        return false;
    ULONG res = 0;
    NTSTATUS s = BCryptDecrypt(hKey, (PUCHAR)ct, nbytes, nullptr, nullptr, 0,
                               pt, nbytes, &res, 0);
    BCryptDestroyKey(hKey);
    return s == 0;
}

// Returns 0 on success (prints the key + decrypted preview), 1 otherwise. When
// keyout is non-null the recovered 16-byte key is written there (ascii + hex).
int find_log_key(const char* logpath, const char* keyout) {
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
                    if (!aes_ecb_dec(hAlg, bp + off, 16, ct, pt, TEST)) continue;
                    int sc = bbl_oracle::printable_score(pt, TEST);
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
        if (keyout && keyout[0]) {
            if (FILE* kf = std::fopen(keyout, "wb")) {
                std::fprintf(kf, "debug-log key (AES-128-ECB)\nascii: %.16s\nhex:   ", (const char*)best_key);
                for (int i = 0; i < 16; ++i) std::fprintf(kf, "%02x", best_key[i]);
                std::fprintf(kf, "\n");
                std::fclose(kf);
            }
        }
        // Full-log decrypt to a sidecar file for inspection.
        size_t full = log.size() & ~size_t(15);
        std::vector<uint8_t> out(full);
        if (aes_ecb_dec(hAlg, best_key, 16, log.data(), out.data(), (int)full)) {
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
// baked AES keys are 16-char ASCII strings (loaded at runtime), so this cheap
// prefilter lets us scan byte-granular fast: only ASCII-string windows reach
// the (expensive) AES-decrypt oracle test.
static bool ascii_key16(const uint8_t* p) {
    for (int i = 0; i < 16; ++i)
        if (p[i] < 0x20 || p[i] > 0x7e) return false;
    return true;
}

// Recover the plugin's AES-128-ECB CONFIG key (a.k.a. network_engine.key) BLIND
// from live process memory using the embedded known-plaintext oracle
// (conf_oracle.h, shared with the Linux tool): the key is the 16-byte memory
// window K for which AES-128-ECB-decrypt(kOracleCipher) == kOraclePlain. A known
// plaintext/ciphertext pair cannot reveal K, so the oracle ships safely and no
// real BambuNetworkEngine.conf file is needed. confpath is accepted but unused.
// Returns 0 on success (prints the recovered key + a non-sensitive preview).
int find_config_key(const char* /*confpath (unused: oracle is embedded)*/, const char* outpath) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) {
        std::fprintf(stderr, "[cfgkey] BCryptOpenAlgorithmProvider failed\n"); return 1;
    }
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                      sizeof(BCRYPT_CHAIN_MODE_ECB), 0);

    // Shared decrypt callback (BCrypt) for the oracle test in key_oracle.h.
    auto decfn = [&](const uint8_t* key, int klen, const uint8_t* c, uint8_t* p, int n) {
        return aes_ecb_dec(hAlg, key, klen, c, p, n);
    };

    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uintptr_t maxA = (uintptr_t)si.lpMaximumApplicationAddress, a = 0;
    MEMORY_BASIC_INFORMATION m{};
    long long windows = 0, ascii_win = 0;
    uint8_t found_key[16]{}; bool found = false;
    std::vector<uint8_t> buf;

    while (!found && a < maxA && VirtualQuery((void*)a, &m, sizeof m)) {
        uintptr_t rb = (uintptr_t)m.BaseAddress; size_t rs = m.RegionSize;
        if (m.State == MEM_COMMIT && readable_prot(m.Protect) &&
            rs >= 16 && rs < (size_t)256 * 1024 * 1024) {
            buf.resize(rs);
            SIZE_T got = 0;
            if (ReadProcessMemory(GetCurrentProcess(), (void*)rb, buf.data(), rs, &got) && got >= 16) {
                const uint8_t* bp = buf.data();
                for (size_t off = 0; off + 16 <= got; off += 1) {
                    ++windows;
                    if (!ascii_key16(bp + off)) continue;     // the baked key is 16-char ASCII
                    ++ascii_win;
                    if (!bbl_oracle::conf_key_matches(bp + off, 16, decfn)) continue;
                    std::memcpy(found_key, bp + off, 16);
                    found = true;
                    std::fprintf(stderr, "[cfgkey] oracle match @%p\n", (void*)(rb + off));
                    break;
                }
            }
        }
        a = rb + rs; if (rs == 0) break;
    }
    std::fprintf(stderr, "[cfgkey] scanned %lld windows (%lld ascii)\n", windows, ascii_win);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (found) {
        std::fprintf(stderr, "[cfgkey] RECOVERED config key (ascii)='%.16s' hex=", (const char*)found_key);
        for (int i = 0; i < 16; ++i) std::fprintf(stderr, "%02x", found_key[i]);
        std::fprintf(stderr, "\n");
        if (outpath && outpath[0]) {
            if (FILE* of = std::fopen(outpath, "wb")) {
                std::fprintf(of, "network_engine.key (AES-128-ECB)\nascii: %.16s\nhex:   ", (const char*)found_key);
                for (int i = 0; i < 16; ++i) std::fprintf(of, "%02x", found_key[i]);
                std::fprintf(of, "\n");
                std::fclose(of);
                std::fprintf(stderr, "[cfgkey] wrote key -> %s\n", outpath);
            }
        }
        return 0;
    }
    std::fprintf(stderr, "[cfgkey] no oracle-matching key found resident in plugin memory\n");
    return 1;
}

}  // namespace bbl
