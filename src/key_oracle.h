#pragma once
// Shared AES-key recovery oracles + scoring, used by both the Linux capture
// engine (src/capture.cpp) and the Windows host (win/host/logkey.cpp). The AES
// primitive itself is platform-specific (OpenSSL AES on Linux, BCrypt on
// Windows), so the caller passes a decrypt callback; only the oracle DECISION
// logic and the printability scoring live here, once.
#include <cstdint>
#include <cstring>
#include "conf_oracle.h"   // kOraclePlain[] + kOracleCipher[] (no key)

namespace bbl_oracle {

// Printable-ASCII ratio (0..100) of n bytes. The conf/log plaintext is text/JSON,
// so the real key decrypts an oracle block to a near-100 score.
inline int printable_score(const uint8_t* p, int n) {
    if (n <= 0) return 0;
    int ok = 0;
    for (int i = 0; i < n; ++i) {
        uint8_t c = p[i];
        if (c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f)) ++ok;
    }
    return ok * 100 / n;
}

// DecFn contract: bool dec(const uint8_t* key, int key_len_bytes,
//                          const uint8_t* ct, uint8_t* pt, int nbytes)
// -- AES-ECB-decrypt nbytes (a multiple of 16) of ct into pt under `key`.
// Returns true on success.

// True iff `key` (key_len 16 or 32) is the network_engine config AES key, tested
// against the embedded known-plaintext oracle (conf_oracle.h): the key is the one
// for which AES-ECB-decrypt(kOracleCipher) == kOraclePlain. A known plaintext/
// ciphertext pair cannot reveal the key, so the oracle ships safely.
template <class DecFn>
inline bool conf_key_matches(const uint8_t* key, int key_len, DecFn&& dec) {
    uint8_t pt[16];
    if (!dec(key, key_len, kOracleCipher, pt, 16)) return false;
    return std::memcmp(pt, kOraclePlain, 16) == 0;
}

// Printability score (0..100) of decrypting the debug-log's first 48 bytes with a
// 16-byte `key`; the real log key scores ~100. -1 on decrypt failure. Used to pick
// the highest-scoring window (early-out at >= 95).
template <class DecFn>
inline int log_key_score(const uint8_t* key, const uint8_t* log_first48, DecFn&& dec) {
    uint8_t pt[48];
    if (!dec(key, 16, log_first48, pt, 48)) return -1;
    return printable_score(pt, 48);
}

}  // namespace bbl_oracle
