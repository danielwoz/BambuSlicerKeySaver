// Recover the plugin's two AES-128-ECB keys (debug-log key + network_engine
// config key) BLIND from the LIVE plugin process memory. Neither key is stored
// on disk, but both are resident in the running plugin's memory. Each key is a
// 16-char ASCII string, so we cheaply prefilter memory to ASCII-only windows and
// test each against an embedded known-plaintext oracle (conf_oracle.h /
// log_oracle.h, shared with the Linux tool): the key is the window K for which
// AES-128-ECB-decrypt(kOracleCipher) == kOraclePlain. Self-contained -- no
// pre-existing config or encrypted-log file is needed, so a clean environment
// recovers both keys in a single run.
#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include "key_oracle.h"   // bbl_oracle:: conf_key_matches / log_key_matches (shared with Linux)

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

// True iff the 16-byte window is entirely printable ASCII. Both of the plugin's
// baked AES keys are 16-char ASCII strings (loaded at runtime), so this cheap
// prefilter lets us scan byte-granular fast: only ASCII-string windows reach
// the (expensive) AES-decrypt oracle test.
static bool ascii_key16(const uint8_t* p) {
    for (int i = 0; i < 16; ++i)
        if (p[i] < 0x20 || p[i] > 0x7e) return false;
    return true;
}

// Recover the plugin's AES-128-ECB debug-log key BLIND from live process memory
// using the embedded known-plaintext oracle (log_oracle.h, shared with the Linux
// tool): the key is the 16-byte window K for which AES-128-ECB-decrypt(
// kLogOracleCipher) == kLogOraclePlain. Self-contained -- no pre-existing
// encrypted debug_network_*.log.enc file is needed, so a clean environment
// recovers the log key in a single run. A known plaintext/ciphertext pair cannot
// reveal K, so the oracle ships safely. If `logpath` names a readable encrypted
// log, it is additionally decrypted to a "<logpath>.dec" sidecar for inspection.
// Returns 0 on success (prints the recovered key). When keyout is non-null the
// recovered 16-byte key is written there (ascii + hex).
int find_log_key(const char* logpath, const char* keyout) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) {
        std::fprintf(stderr, "[logkey] BCryptOpenAlgorithmProvider failed\n");
        return 1;
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
        // Committed readable data (heap/data AND the DLL's decrypted image data,
        // where the key resides). Skip only huge mapped files.
        if (m.State == MEM_COMMIT && readable_prot(m.Protect) &&
            rs >= 16 && rs < (size_t)256 * 1024 * 1024) {
            buf.resize(rs);
            SIZE_T got = 0;
            if (ReadProcessMemory(GetCurrentProcess(), (void*)rb, buf.data(), rs, &got) && got >= 16) {
                const uint8_t* bp = buf.data();
                for (size_t off = 0; off + 16 <= got; off += 1) {
                    ++windows;
                    if (!ascii_key16(bp + off)) continue;   // the baked key is 16-char ASCII
                    ++ascii_win;
                    if (!bbl_oracle::log_key_matches(bp + off, decfn)) continue;
                    std::memcpy(found_key, bp + off, 16);
                    found = true;
                    std::fprintf(stderr, "[logkey] oracle match @%p\n", (void*)(rb + off));
                    break;
                }
            }
        }
        a = rb + rs; if (rs == 0) break;
    }
    std::fprintf(stderr, "[logkey] scanned %lld windows (%lld ascii)\n", windows, ascii_win);

    if (found) {
        std::fprintf(stderr, "[logkey] RECOVERED debug-log key (ascii)='%.16s' hex=", (const char*)found_key);
        for (int i = 0; i < 16; ++i) std::fprintf(stderr, "%02x", found_key[i]);
        std::fprintf(stderr, "\n");
        if (keyout && keyout[0]) {
            if (FILE* kf = std::fopen(keyout, "wb")) {
                std::fprintf(kf, "debug-log key (AES-128-ECB)\nascii: %.16s\nhex:   ", (const char*)found_key);
                for (int i = 0; i < 16; ++i) std::fprintf(kf, "%02x", found_key[i]);
                std::fprintf(kf, "\n");
                std::fclose(kf);
            }
        }
        // If a real encrypted log was supplied, decrypt it to a sidecar for inspection.
        std::vector<uint8_t> log;
        if (logpath && logpath[0] && read_file(logpath, log) && log.size() >= 16) {
            size_t full = log.size() & ~size_t(15);
            std::vector<uint8_t> outbuf(full);
            if (aes_ecb_dec(hAlg, found_key, 16, log.data(), outbuf.data(), (int)full)) {
                std::string op = std::string(logpath) + ".dec";
                if (FILE* of = std::fopen(op.c_str(), "wb")) {
                    std::fwrite(outbuf.data(), 1, full, of); std::fclose(of);
                    std::fprintf(stderr, "[logkey] wrote decrypted log -> %s\n", op.c_str());
                }
            }
        }
    } else {
        std::fprintf(stderr, "[logkey] no oracle-matching debug-log key found resident in plugin memory\n");
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return found ? 0 : 1;
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
