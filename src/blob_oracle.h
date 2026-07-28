#pragma once
// Shared get_app_cert response-blob oracle (decision logic only; the AES-GCM
// primitive is supplied by the caller so the same logic serves OpenSSL on either
// platform).
//
// The get_app_cert reply is plaintext JSON { cert, key, crl }: `cert`/`crl` are
// PEM, and `key` is the app's RSA private key sealed as base64( nonce(12) ‖
// ciphertext ‖ tag(16) ), AES-256-GCM, no AAD -- the same primitive the client
// uses to build encAppKey, run in reverse. The 32-byte GCM key is resident in the
// plugin during the decrypt, so the AES key-expansion tap (aes_tap) captures it as
// one of the userKeys it logs. This oracle picks, out of all captured candidate
// keys, the one whose GCM tag verifies against the blob -- a 16-byte tag makes that
// a definitive match (~2^-128 false-positive) -- and returns the decrypted key.
#include <cstdint>
#include <cstring>
#include <cstddef>

namespace bbl_oracle {

// GcmFn contract:
//   bool gcm(const uint8_t key[32],
//            const uint8_t* nonce, int nlen,
//            const uint8_t* ct,    int ctlen,
//            const uint8_t* tag,   int tlen,
//            uint8_t* pt_out)
// AES-256-GCM authenticated-decrypt `ct` into `pt_out` (ctlen bytes), no AAD.
// MUST return true ONLY when the authentication tag verifies.

// Byte-substring search (plaintext plausibility labelling only; the tag is the
// real oracle).
inline bool blob_contains(const uint8_t* p, int n, const char* needle) {
    int m = (int)std::strlen(needle);
    if (m > n) return false;
    for (int i = 0; i + m <= n; ++i)
        if (std::memcmp(p + i, needle, (size_t)m) == 0) return true;
    return false;
}

// A decrypted get_app_cert "key" blob is a PEM RSA private key.
inline bool looks_like_app_key(const uint8_t* pt, int n) {
    return blob_contains(pt, n, "-----BEGIN") || blob_contains(pt, n, "PRIVATE KEY");
}

// Split a base64-decoded blob (nonce(12) ‖ ct ‖ tag(16)) and GCM-verify+decrypt it
// under `key`. On tag-verify, writes the plaintext into `out` (caller sizes it to
// at least bloblen-28) and returns the plaintext length; returns -1 otherwise.
template <class GcmFn>
inline int try_blob_key(const uint8_t key[32],
                        const uint8_t* blob, int bloblen,
                        uint8_t* out, GcmFn&& gcm) {
    const int NONCE = 12, TAG = 16;
    if (bloblen < NONCE + TAG + 1) return -1;
    const uint8_t* nonce = blob;
    const uint8_t* ct    = blob + NONCE;
    const int      ctlen = bloblen - NONCE - TAG;
    const uint8_t* tag   = blob + NONCE + ctlen;
    if (!gcm(key, nonce, NONCE, ct, ctlen, tag, TAG, out)) return -1;
    return ctlen;
}

// Scan a candidate-key pool for the one that unseals `blob`. On success returns the
// winning candidate index and its plaintext length (via out params); -1 if none.
template <class GcmFn>
inline int find_blob_key(const uint8_t* candidates, int cand_count,
                         const uint8_t* blob, int bloblen,
                         uint8_t* out, int* out_len, GcmFn&& gcm) {
    for (int i = 0; i < cand_count; ++i) {
        int n = try_blob_key(candidates + (size_t)i * 32, blob, bloblen, out, gcm);
        if (n >= 0) { if (out_len) *out_len = n; return i; }
    }
    return -1;
}

}  // namespace bbl_oracle
