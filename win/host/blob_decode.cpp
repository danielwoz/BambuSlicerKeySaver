// blob_decode -- offline decoder for the get_app_cert response "key" blob.
//
// The reply's `key` field is an AES-256-GCM sealing of the app private material.
// Two container framings are known/possible, so both are tried per candidate key:
//   A (standard):  nonce(12) ‖ ciphertext ‖ tag(16)
//   B (observed):  nonce(12) ‖ tag(16) ‖ len(4 LE) ‖ ciphertext(len)   [704 B live]
// The 32-byte GCM key is a session-derived R, NOT the transported session key K
// (decrypt with K fails), and the derivation appears to run inside the plugin's
// VMProtect-virtualized code -- so R may never pass through OpenSSL's AES nor sit
// contiguously in memory. This tool does not assume where R comes from: it GCM-
// trial-decrypts the blob with every candidate key it is given (an aes_tap log,
// an explicit --key, and/or every aligned window of a --dump-regions snapshot).
// A 16-byte tag makes a verify a definitive match (~2^-128 false-positive), so the
// winning candidate is R and its plaintext is the decoded key material -- whatever
// its form (PEM or raw CRT secrets). With --enc-app-key it also finds K and names
// the transform R = f(K).
//
// Usage:
//   bambu_host --decode-appcert-blob --blob <b64|@file|raw response JSON>
//              [--enc-app-key <b64|@file>] [--keys aes_tap.log] [--key <hex32>]
//              [--dump <snapshot-file>] [--step <bytes>] [--out app_key.pem]
//   bambu_host --decode-appcert-blob --selftest

#include <winsock2.h>
#include <windows.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "blob_oracle.h"   // bbl_oracle:: looks_like_app_key

namespace bbl {
namespace {

using Key32 = std::array<uint8_t, 32>;

// ---- AES-256-GCM authenticated decrypt (the oracle primitive) ---------------
// Returns true ONLY if the tag verifies. No AAD (get_app_cert uses none).
bool gcm_decrypt(const uint8_t key[32], const uint8_t* nonce, int nlen,
                 const uint8_t* ct, int ctlen, const uint8_t* tag, int tlen,
                 uint8_t* out) {
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return false;
    bool ok = false;
    do {
        if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, nlen, nullptr) != 1) break;
        if (EVP_DecryptInit_ex(c, nullptr, nullptr, key, nonce) != 1) break;
        int outl = 0;
        if (ctlen && EVP_DecryptUpdate(c, out, &outl, ct, ctlen) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, tlen, (void*)tag) != 1) break;
        int fin = 0;
        ok = (EVP_DecryptFinal_ex(c, out + outl, &fin) > 0);  // >0 only when tag authenticates
    } while (0);
    EVP_CIPHER_CTX_free(c);
    return ok;
}

bool gcm_seal(const uint8_t key[32], const uint8_t nonce[12],
              const uint8_t* pt, int ptlen, std::vector<uint8_t>& ct_out, uint8_t tag_out[16]) {
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return false;
    bool ok = false;
    ct_out.assign(ptlen, 0);
    do {
        if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) break;
        if (EVP_EncryptInit_ex(c, nullptr, nullptr, key, nonce) != 1) break;
        int outl = 0;
        if (ptlen && EVP_EncryptUpdate(c, ct_out.data(), &outl, pt, ptlen) != 1) break;
        int fin = 0;
        if (EVP_EncryptFinal_ex(c, ct_out.data() + outl, &fin) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, tag_out) != 1) break;
        ok = true;
    } while (0);
    EVP_CIPHER_CTX_free(c);
    return ok;
}

// Try both container framings for one candidate key. On tag-verify writes plaintext
// to `out`, sets *framing (0=std, 1=len-prefixed), returns plaintext length; else -1.
int try_candidate(const uint8_t key[32], const uint8_t* blob, int bloblen,
                  uint8_t* out, int* framing) {
    // A: nonce(12) ‖ ct ‖ tag(16)
    if (bloblen >= 12 + 16 + 1) {
        int ctlen = bloblen - 12 - 16;
        if (gcm_decrypt(key, blob, 12, blob + 12, ctlen, blob + 12 + ctlen, 16, out)) {
            if (framing) *framing = 0; return ctlen;
        }
    }
    // B: nonce(12) ‖ tag(16) ‖ len(4 LE) ‖ ct(len)
    if (bloblen >= 12 + 16 + 4) {
        uint32_t len = 0; std::memcpy(&len, blob + 28, 4);
        if (len > 0 && (int)(32 + len) <= bloblen &&
            gcm_decrypt(key, blob, 12, blob + 32, (int)len, blob + 12, 16, out)) {
            if (framing) *framing = 1; return (int)len;
        }
    }
    return -1;
}

// ---- small codecs -----------------------------------------------------------
int b64val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}
bool b64_decode(const std::string& in, std::vector<uint8_t>& out) {
    out.clear();
    int acc = 0, nbits = 0;
    for (char ch : in) {
        int v = b64val((unsigned char)ch);
        if (v < 0) continue;
        acc = (acc << 6) | v; nbits += 6;
        if (nbits >= 8) { nbits -= 8; out.push_back((uint8_t)((acc >> nbits) & 0xff)); }
    }
    return !out.empty();
}
bool hex_decode(const std::string& in, std::vector<uint8_t>& out) {
    out.clear();
    int hi = -1;
    for (char ch : in) {
        int v;
        if (ch >= '0' && ch <= '9') v = ch - '0';
        else if (ch >= 'a' && ch <= 'f') v = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F') v = ch - 'A' + 10;
        else continue;
        if (hi < 0) hi = v; else { out.push_back((uint8_t)((hi << 4) | v)); hi = -1; }
    }
    return !out.empty();
}
std::string load_arg(const char* v) {
    if (!v || !v[0]) return {};
    if (v[0] == '@') {
        FILE* f = std::fopen(v + 1, "rb");
        if (!f) return {};
        std::string s; char buf[4096]; size_t n;
        while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) s.append(buf, n);
        std::fclose(f);
        return s;
    }
    return v;
}
// Pull the "<field>" string value out of a get_app_cert response JSON, else return
// `s` unchanged (already the bare base64 token).
std::string json_field_or_self(const std::string& s, const char* field) {
    std::string needle = std::string("\"") + field + "\"";
    size_t k = s.find(needle);
    if (k == std::string::npos) return s;
    size_t c = s.find(':', k + needle.size()); if (c == std::string::npos) return s;
    size_t q1 = s.find('"', c + 1);            if (q1 == std::string::npos) return s;
    size_t q2 = s.find('"', q1 + 1);           if (q2 == std::string::npos) return s;
    return s.substr(q1 + 1, q2 - q1 - 1);
}

// Every 32-byte key candidate in an aes_tap.log: any >= 64-hex run after an '='.
void collect_from_log(const char* path, std::vector<Key32>& out) {
    FILE* f = std::fopen(path, "rb");
    if (!f) return;
    char line[8192];
    while (std::fgets(line, sizeof line, f)) {
        const char* eq = std::strchr(line, '=');
        if (!eq) continue;
        const char* p = eq + 1;
        while (*p == ' ' || *p == '\t') ++p;
        int hexlen = 0;
        for (const char* q = p; ; ++q) {
            char ch = *q;
            bool ishex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
            if (!ishex) break; ++hexlen;
        }
        if (hexlen < 64) continue;
        std::vector<uint8_t> b; hex_decode(std::string(p, p + 64), b);
        if (b.size() >= 32) { Key32 k; std::memcpy(k.data(), b.data(), 32); out.push_back(k); }
    }
    std::fclose(f);
}
void dedup(std::vector<Key32>& v) {
    std::vector<Key32> u;
    for (auto& k : v) {
        bool seen = false;
        for (auto& e : u) if (std::memcmp(k.data(), e.data(), 32) == 0) { seen = true; break; }
        if (!seen) u.push_back(k);
    }
    v.swap(u);
}
std::string hex(const uint8_t* p, int n) {
    static const char* H = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (int i = 0; i < n; ++i) { s.push_back(H[p[i] >> 4]); s.push_back(H[p[i] & 15]); }
    return s;
}

// Brute-force every `step`-aligned 32-byte window of a raw memory-snapshot file
// against the blob. Returns the plaintext length + fills R/framing/offset on the
// first tag-verify; -1 if the blob is not unsealed by any window (R not resident
// contiguously, or wrong framing). This is the angle that does not depend on the
// decrypt surfacing at OpenSSL: if R is anywhere in the dump, the tag finds it.
long long scan_dump(const char* path, int step, const uint8_t* blob, int bloblen,
                    uint8_t* R_out, uint8_t* pt_out, int* ptlen, int* framing, uint64_t* off) {
    FILE* f = std::fopen(path, "rb");
    if (!f) { std::fprintf(stderr, "[blob] cannot open dump %s\n", path); return -1; }
    std::fseek(f, 0, SEEK_END); long long sz = std::ftell(f); std::fseek(f, 0, SEEK_SET);
    if (sz < 32) { std::fclose(f); return -1; }
    std::vector<uint8_t> buf((size_t)sz);
    if (std::fread(buf.data(), 1, (size_t)sz, f) != (size_t)sz) { std::fclose(f); return -1; }
    std::fclose(f);
    if (step < 1) step = 1;
    long long tried = 0;
    for (long long o = 0; o + 32 <= sz; o += step) {
        ++tried;
        int fr = 0;
        int n = try_candidate(buf.data() + o, blob, bloblen, pt_out, &fr);
        if (n >= 0) {
            std::memcpy(R_out, buf.data() + o, 32);
            if (ptlen) *ptlen = n; if (framing) *framing = fr; if (off) *off = (uint64_t)o;
            std::fprintf(stderr, "[blob] dump %s: R found at offset 0x%llx after %lld windows\n",
                         path, (unsigned long long)o, tried);
            return n;
        }
        if ((tried % 4000000) == 0)
            std::fprintf(stderr, "[blob]   ...%lld windows scanned (%.0f%%)\n", tried, 100.0 * o / sz);
    }
    std::fprintf(stderr, "[blob] dump %s: no window unseals the blob (%lld windows, step %d)\n", path, tried, step);
    return -1;
}

// ---- f-derivation battery: given K and R, name the transform R = f(K) ----------
void sha256(const uint8_t* m, int n, uint8_t out[32]) { SHA256(m, n, out); }
void hmac256(const uint8_t* key, int klen, const uint8_t* m, int mlen, uint8_t out[32]) {
    unsigned l = 32; HMAC(EVP_sha256(), key, klen, m, mlen, out, &l);
}
void hkdf256(const uint8_t* ikm, int ikmlen, const uint8_t* salt, int saltlen, uint8_t out[32]) {
    uint8_t zero[32] = {0}, prk[32], t[32], one = 0x01;
    hmac256(salt && saltlen ? salt : zero, salt && saltlen ? saltlen : 32, ikm, ikmlen, prk);
    hmac256(prk, 32, &one, 1, t);
    std::memcpy(out, t, 32);
}
const char* name_derivation(const uint8_t K[32], const uint8_t R[32]) {
    uint8_t t[32];
    if (std::memcmp(K, R, 32) == 0) return "identity (R == K)";
    sha256(K, 32, t);                      if (!std::memcmp(t, R, 32)) return "SHA-256(K)";
    hmac256(K, 32, K, 32, t);              if (!std::memcmp(t, R, 32)) return "HMAC-SHA256(key=K, msg=K)";
    { uint8_t z[1]; hmac256(K, 32, z, 0, t); } if (!std::memcmp(t, R, 32)) return "HMAC-SHA256(key=K, msg=\"\")";
    { uint8_t z[1]; hmac256(z, 0, K, 32, t); } if (!std::memcmp(t, R, 32)) return "HMAC-SHA256(key=\"\", msg=K)";
    hkdf256(K, 32, nullptr, 0, t);         if (!std::memcmp(t, R, 32)) return "HKDF-SHA256(ikm=K, salt=\"\")";
    { uint8_t kk[64]; std::memcpy(kk, K, 32); std::memcpy(kk + 32, K, 32); sha256(kk, 64, t); }
                                           if (!std::memcmp(t, R, 32)) return "SHA-256(K ‖ K)";
    return nullptr;
}

int fail(const char* msg) { std::fprintf(stderr, "[blob] %s\n", msg); return 1; }

// ---- self-test: both framings, synthetic K/blob, decoys (no plugin) ----------
int one_selftest(int framing) {
    uint8_t K[32], nonce[12];
    if (RAND_bytes(K, 32) != 1 || RAND_bytes(nonce, 12) != 1) return fail("RAND_bytes failed");
    const char* pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow<synthetic>\n-----END RSA PRIVATE KEY-----\n";
    int ptlen = (int)std::strlen(pem);
    std::vector<uint8_t> ct; uint8_t tag[16];
    if (!gcm_seal(K, nonce, (const uint8_t*)pem, ptlen, ct, tag)) return fail("gcm_seal failed");

    std::vector<uint8_t> blob(nonce, nonce + 12);
    if (framing == 0) {                       // nonce ‖ ct ‖ tag
        blob.insert(blob.end(), ct.begin(), ct.end());
        blob.insert(blob.end(), tag, tag + 16);
    } else {                                  // nonce ‖ tag ‖ len ‖ ct
        blob.insert(blob.end(), tag, tag + 16);
        uint32_t len = (uint32_t)ct.size();
        blob.insert(blob.end(), (uint8_t*)&len, (uint8_t*)&len + 4);
        blob.insert(blob.end(), ct.begin(), ct.end());
    }
    uint8_t out[512]; int fr = -1;
    // decoy key must fail
    uint8_t decoy[32]; RAND_bytes(decoy, 32);
    if (try_candidate(decoy, blob.data(), (int)blob.size(), out, &fr) >= 0) return fail("decoy key verified (should not)");
    int n = try_candidate(K, blob.data(), (int)blob.size(), out, &fr);
    if (n != ptlen || std::memcmp(out, pem, n) != 0) return fail("plaintext mismatch");
    if (fr != framing) return fail("framing misdetected");
    std::fprintf(stderr, "[blob]   framing %d (%s): recovered %d B OK\n",
                 framing, framing ? "nonce|tag|len|ct" : "nonce|ct|tag", n);
    return 0;
}
int selftest() {
    std::fprintf(stderr, "[blob] self-test: seal + recover under both container framings, reject decoys\n");
    if (one_selftest(0)) return 1;
    if (one_selftest(1)) return 1;
    uint8_t K[32]; RAND_bytes(K, 32); uint8_t R[32]; sha256(K, 32, R);
    const char* nm = name_derivation(K, R);
    if (!nm || std::strcmp(nm, "SHA-256(K)") != 0) return fail("derivation battery misnamed SHA-256(K)");
    std::fprintf(stderr, "[blob] self-test PASSED (both framings + derivation battery)\n");
    return 0;
}

}  // namespace

int decode_appcert_blob(const char* blob_arg, const char* encappkey_arg,
                        const char* keys_log, const char* key_hex, const char* dump_path,
                        int step, const char* out_pem, bool want_selftest) {
    if (want_selftest) return selftest();

    std::string blob_s = json_field_or_self(load_arg(blob_arg), "key");
    if (blob_s.empty()) return fail("no --blob (base64 of the response 'key' field, @file, or raw response JSON)");
    std::vector<uint8_t> blob;
    if (!b64_decode(blob_s, blob) || blob.size() < 12 + 16 + 1)
        return fail("--blob did not base64-decode to a sealed container");
    std::fprintf(stderr, "[blob] response key blob: %zu B (trying framings A: nonce|ct|tag  B: nonce|tag|len|ct)\n",
                 blob.size());

    const char* op = (out_pem && out_pem[0]) ? out_pem : "app_key_from_blob.bin";
    std::vector<uint8_t> pt(blob.size() + 16);
    int ptlen = 0, framing = 0;
    uint8_t R[32]; bool have_R = false;

    // 1) Named candidates: explicit --key + every 32-byte key in the aes_tap log.
    std::vector<Key32> cand;
    if (key_hex && key_hex[0]) {
        std::vector<uint8_t> b;
        if (hex_decode(key_hex, b) && b.size() >= 32) { Key32 k; std::memcpy(k.data(), b.data(), 32); cand.push_back(k); }
    }
    const char* logp = (keys_log && keys_log[0]) ? keys_log : "aes_tap.log";
    collect_from_log(logp, cand);
    dedup(cand);
    if (!cand.empty()) {
        std::fprintf(stderr, "[blob] %zu candidate key(s) from --key/%s\n", cand.size(), logp);
        for (auto& k : cand) {
            int fr = 0; int n = try_candidate(k.data(), blob.data(), (int)blob.size(), pt.data(), &fr);
            if (n >= 0) { std::memcpy(R, k.data(), 32); ptlen = n; framing = fr; have_R = true; break; }
        }
    }

    // 2) If no named key worked, brute-force a memory snapshot (R need not have
    //    passed through OpenSSL; it only needs to be resident contiguously).
    if (!have_R && dump_path && dump_path[0]) {
        uint64_t off = 0;
        long long n = scan_dump(dump_path, step > 0 ? step : 4, blob.data(), (int)blob.size(),
                                R, pt.data(), &ptlen, &framing, &off);
        have_R = (n >= 0);
    }

    if (!have_R)
        return fail("no candidate key unseals the blob. Provide R's source: --keys <aes_tap.log>, "
                    "--key <hex32>, or --dump <--dump-regions snapshot taken during get_app_cert.");

    std::fprintf(stderr, "[blob] DECRYPTED (framing %s): R = %s\n",
                 framing ? "nonce|tag|len|ct" : "nonce|ct|tag", hex(R, 32).c_str());
    std::fprintf(stderr, "[blob] plaintext %d B, %s; head=%s\n", ptlen,
                 bbl_oracle::looks_like_app_key(pt.data(), ptlen) ? "PEM key" : "raw (e.g. CRT secrets)",
                 hex(pt.data(), ptlen < 16 ? ptlen : 16).c_str());
    if (FILE* of = std::fopen(op, "wb")) { std::fwrite(pt.data(), 1, ptlen, of); std::fclose(of);
        std::fprintf(stderr, "[blob] wrote decoded material -> %s\n", op); }

    // 3) With encAppKey, find K and name R = f(K).
    std::string enc_s = load_arg(encappkey_arg);
    if (!enc_s.empty()) {
        std::vector<uint8_t> enc;
        if (b64_decode(enc_s, enc) && enc.size() >= 28) {
            std::vector<uint8_t> id(enc.size() + 16); int idl = 0, fr = 0; bool have_K = false; uint8_t K[32];
            for (auto& k : cand) {
                int n = try_candidate(k.data(), enc.data(), (int)enc.size(), id.data(), &fr);
                if (n >= 0) { std::memcpy(K, k.data(), 32); idl = n; have_K = true; break; }
            }
            if (have_K) {
                std::fprintf(stderr, "[blob] K = %s; app-identity = '%.*s'\n", hex(K, 32).c_str(), idl, (const char*)id.data());
                const char* nm = name_derivation(K, R);
                if (nm) std::fprintf(stderr, "[blob] *** derivation recovered: R = %s ***\n", nm);
                else    std::fprintf(stderr, "[blob] R not a simple transform of K (battery exhausted) -> analyse (K,R) offline\n");
            } else {
                std::fprintf(stderr, "[blob] K not among the named candidates (encAppKey from a different run?)\n");
            }
        }
    }
    return 0;
}

}  // namespace bbl
