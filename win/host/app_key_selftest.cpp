// Offline self-test for app_key_sweep: recover an RSA-2048 key's primes p,q
// from a raw memory buffer, GIVEN the public modulus N.
//
// No plugin required. It:
//   1. Generates a synthetic RSA-2048 key (two real 1024-bit primes, e=65537)
//      with the project's own bigint -- the same generator core_selftest uses.
//   2. Serialises p as 128 bytes into a decoy buffer at a known offset,
//      surrounded by deterministic pseudo-random noise (so the factor sits in a
//      realistic haystack, not at buffer start).
//   3. Calls recover_pq_for_modulus(N, {buffer}) and asserts the recovered
//      p*q == N and that {p,q} equals the synthetic {p,q}, and that
//      e*d == 1 (mod (p-1)(q-1)).
//   4. Runs the above for BOTH byte orders of the planted prime (big-endian and
//      little-endian) in separate cases, plus a negative case (no factor).
//
// Prints PASS/FAIL. Exit code 0 = pass, nonzero = failure.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "app_key_sweep.hpp"
#include "bigint.h"
#include "reconstruct.h"

namespace {

constexpr int E_PUB = 65537;

// --- synthetic RSA-2048 key generation (mirrors core_selftest.cpp) ----------

std::string seed_hex(uint64_t s) {
    static const char* H = "0123456789abcdef";
    std::string out;
    out.reserve(256);
    out.push_back(H[0xc | (s & 1u)]);          // 'c' or 'd' -> top bit set
    uint64_t x = s * 6364136223846793005ULL + 1442695040888963407ULL;
    for (int i = 1; i < 255; ++i) {
        x = x * 6364136223846793005ULL + 1442695040888963407ULL;
        out.push_back(H[(x >> 33) & 0xf]);
    }
    out.push_back('1');                        // odd
    return out;
}

bn::BigInt next_prime(bn::BigInt n) {
    if ((n.v.empty() ? 0u : n.v[0]) % 2u == 0u) n = bn::add(n, bn::BigInt(1));
    while (!bn::is_probable_prime(n)) n = bn::add(n, bn::BigInt(2));
    return n;
}

bn::BigInt gen_prime(uint64_t seed) {
    bn::BigInt p = next_prime(bn::from_hex(seed_hex(seed)));
    for (;;) {
        bn::BigInt pm1 = bn::sub(p, bn::BigInt(1));
        if (!bn::mod_inverse(bn::BigInt(uint32_t(E_PUB)), pm1).is_zero()) return p;
        p = next_prime(bn::add(p, bn::BigInt(2)));
    }
}

bool same(const bn::BigInt& a, const bn::BigInt& b) {
    return bn::BigInt::cmp(a, b) == 0;
}

// Deterministic pseudo-random byte (splitmix64) so the haystack is reproducible.
uint8_t noise_byte(uint64_t i) {
    uint64_t z = (i + 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    z = z ^ (z >> 31);
    return (uint8_t)(z & 0xff);
}

// One recovery case: plant `factor` (128 bytes) at `offset` in a noise buffer,
// in the requested byte order, then recover against N and check everything.
// `label` and the two expected primes are for reporting/verification.
bool run_case(const char* label,
              const bn::BigInt& N, const bn::BigInt& p, const bn::BigInt& q,
              const bn::BigInt& d, const bn::BigInt& factor_to_plant,
              bool little_endian, size_t bufsize, size_t offset) {
    std::printf("[app-key-selftest] case '%s' (%s placement, buf=%zuB off=%zu)...\n",
                label, little_endian ? "little-endian" : "big-endian",
                bufsize, offset);

    // 128-byte big-endian serialisation of the prime to plant.
    uint8_t be[128];
    bn::to_bytes_be_fixed(factor_to_plant, be, 128);

    // Fill the buffer with reproducible noise, then overwrite [offset,offset+128)
    // with the prime in the chosen byte order.
    std::vector<uint8_t> buf(bufsize);
    for (size_t i = 0; i < bufsize; ++i) buf[i] = noise_byte(i);
    for (size_t i = 0; i < 128; ++i)
        buf[offset + i] = little_endian ? be[127 - i] : be[i];

    // Modulus as big-endian (minimal length is fine -- the API left-pads).
    uint8_t n_be[256];
    bn::to_bytes_be_fixed(N, n_be, 256);
    std::vector<uint8_t> n_vec(n_be, n_be + 256);

    std::vector<std::pair<const uint8_t*, size_t>> buffers{
        {buf.data(), buf.size()}};
    bbl::RsaKeyParts r = bbl::recover_pq_for_modulus(n_vec, buffers);

    if (!r.ok) { std::printf("  FAIL: recover_pq_for_modulus found no factor\n"); return false; }

    bn::BigInt rp = bn::from_bytes_be(r.p.data(), r.p.size());
    bn::BigInt rq = bn::from_bytes_be(r.q.data(), r.q.size());
    bn::BigInt rd = bn::from_bytes_be(r.d.data(), r.d.size());
    bn::BigInt rn = bn::from_bytes_be(r.n.data(), r.n.size());

    // p*q == N.
    if (!same(bn::mul(rp, rq), N)) { std::printf("  FAIL: recovered p*q != N\n"); return false; }
    // Echoed modulus matches.
    if (!same(rn, N)) { std::printf("  FAIL: echoed N != input N\n"); return false; }
    // Factors match the synthetic pair (order may swap).
    bool factors_ok = (same(rp, p) && same(rq, q)) || (same(rp, q) && same(rq, p));
    if (!factors_ok) { std::printf("  FAIL: recovered factors != synthetic p/q\n"); return false; }
    // Private exponent matches.
    if (!same(rd, d)) { std::printf("  FAIL: recovered d != synthetic d\n"); return false; }
    // e*d == 1 (mod (p-1)(q-1)).
    bn::BigInt phi = bn::mul(bn::sub(rp, bn::BigInt(1)), bn::sub(rq, bn::BigInt(1)));
    if (!same(bn::mod(bn::mul_small(rd, (uint32_t)E_PUB), phi), bn::BigInt(1))) {
        std::printf("  FAIL: e*d != 1 mod phi\n"); return false;
    }
    // CRT exponents consistent.
    bn::BigInt rdp = bn::from_bytes_be(r.dp.data(), r.dp.size());
    bn::BigInt rdq = bn::from_bytes_be(r.dq.data(), r.dq.size());
    if (!same(rdp, bn::mod(rd, bn::sub(rp, bn::BigInt(1)))) ||
        !same(rdq, bn::mod(rd, bn::sub(rq, bn::BigInt(1))))) {
        std::printf("  FAIL: CRT exponents inconsistent\n"); return false;
    }

    std::printf("  OK: p*q==N, factors + d + CRT exponents all match\n");
    return true;
}

}  // namespace

int main() {
    std::printf("[app-key-selftest] generating synthetic RSA-2048 key "
                "(1024-bit primes)...\n");
    bn::BigInt p = gen_prime(0x51);
    bn::BigInt q = gen_prime(0x72);
    if (same(p, q)) { std::printf("FAIL: p == q\n"); return 1; }
    if (p.bit_length() < 1000 || p.bit_length() > 1025 ||
        q.bit_length() < 1000 || q.bit_length() > 1025) {
        std::printf("FAIL: prime widths out of range (p=%d q=%d)\n",
                    p.bit_length(), q.bit_length());
        return 1;
    }
    bn::BigInt N = bn::mul(p, q);
    bn::BigInt d;
    if (!compute_d(p, q, E_PUB, d)) { std::printf("FAIL: compute_d\n"); return 1; }
    std::printf("[app-key-selftest] N bits=%d  p bits=%d  q bits=%d\n",
                N.bit_length(), p.bit_length(), q.bit_length());

    bool ok = true;
    // Case 1: p planted big-endian.
    ok &= run_case("p/BE", N, p, q, d, p, /*le=*/false, 64 * 1024, 4096 + 8);
    // Case 2: q planted little-endian (OpenSSL limb order).
    ok &= run_case("q/LE", N, p, q, d, q, /*le=*/true, 64 * 1024, 12288 + 24);
    // Case 3: p planted little-endian, different offset/buffer size.
    ok &= run_case("p/LE", N, p, q, d, p, /*le=*/true, 200 * 1024, 100000 + 16);
    // Case 4: q planted big-endian.
    ok &= run_case("q/BE", N, p, q, d, q, /*le=*/false, 32 * 1024, 8192 + 40);

    // Negative case: a buffer with NO factor must return ok=false.
    {
        std::printf("[app-key-selftest] negative case (no factor present)...\n");
        std::vector<uint8_t> buf(64 * 1024);
        for (size_t i = 0; i < buf.size(); ++i) buf[i] = noise_byte(i ^ 0xABCDEF);
        uint8_t n_be[256]; bn::to_bytes_be_fixed(N, n_be, 256);
        std::vector<uint8_t> n_vec(n_be, n_be + 256);
        std::vector<std::pair<const uint8_t*, size_t>> buffers{{buf.data(), buf.size()}};
        bbl::RsaKeyParts r = bbl::recover_pq_for_modulus(n_vec, buffers);
        if (r.ok) { std::printf("  FAIL: reported a factor in noise-only buffer\n"); ok = false; }
        else       std::printf("  OK: correctly found no factor\n");
    }

    if (!ok) { std::printf("[app-key-selftest] FAIL\n"); return 1; }
    std::printf("[app-key-selftest] PASS\n");
    return 0;
}
