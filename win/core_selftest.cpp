// Phase 0 self-test for the Windows port of BambuSlicerKeySaver.
//
// Proves the OS-independent key-recovery core compiles and works under MSVC,
// with no plugin required. It:
//   1. Generates a synthetic RSA-2048 key with the project's own bigint
//      (two real 1024-bit primes, e = 65537) -- mirroring the real plugin's
//      key layout (1024-bit factors, 128-byte CRT exponents).
//   2. Serializes dp = d mod (p-1) and dq = d mod (q-1) into a 256-byte
//      big-endian stream, exactly the shape capture.cpp produces.
//   3. Feeds that stream to reconstruct_no_N() and asserts the recovered
//      (p, q, d, N) match the originals -- the same path the real tool runs
//      after hardware-breakpoint capture.
//   4. If OpenSSL is available, also writes a PEM and reports it.
//
// Exit code 0 = pass.

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "bigint.h"
#include "reconstruct.h"
#include "version.h"
#ifdef HAVE_OPENSSL
#  include "output.h"
#endif

namespace {

constexpr int E_PUB = 65537;

// Deterministic 1024-bit odd seed (256 hex chars). Top nibble 0xC/0xD keeps
// the high bit set (full 1024-bit width) with headroom so the prime search
// never carries into a 1025th bit. Distinct `s` -> distinct primes.
std::string seed_hex(uint64_t s) {
    static const char* H = "0123456789abcdef";
    std::string out;
    out.reserve(256);
    out.push_back(H[0xc | (s & 1u)]);             // 'c' or 'd'
    uint64_t x = s * 6364136223846793005ULL + 1442695040888963407ULL;
    for (int i = 1; i < 255; ++i) {
        x = x * 6364136223846793005ULL + 1442695040888963407ULL;
        out.push_back(H[(x >> 33) & 0xf]);
    }
    out.push_back('1');                           // odd
    return out;
}

bn::BigInt next_prime(bn::BigInt n) {
    if ((n.v.empty() ? 0u : n.v[0]) % 2u == 0u) n = bn::add(n, bn::BigInt(1));
    while (!bn::is_probable_prime(n)) n = bn::add(n, bn::BigInt(2));
    return n;
}

// Generate a prime p such that gcd(E, p-1) == 1 (so d exists).
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

}  // namespace

int main() {
    using clk = std::chrono::steady_clock;
    auto secs = [](clk::time_point a, clk::time_point b) {
        return std::chrono::duration<double>(b - a).count();
    };

    std::printf("[selftest] generating synthetic RSA-2048 key (1024-bit primes)...\n");
    auto t0 = clk::now();
    bn::BigInt p = gen_prime(0x11);
    bn::BigInt q = gen_prime(0x22);
    auto t1 = clk::now();
    std::printf("[selftest] key generation: %.2fs (test-only; not in the real flow)\n",
                secs(t0, t1));
    if (same(p, q)) { std::printf("FAIL: p == q\n"); return 1; }

    std::printf("[selftest] p bits=%d  q bits=%d\n", p.bit_length(), q.bit_length());
    if (p.bit_length() < 900 || p.bit_length() > 1100 ||
        q.bit_length() < 900 || q.bit_length() > 1100) {
        std::printf("FAIL: prime size outside the [900,1100]-bit recovery window\n");
        return 1;
    }

    bn::BigInt d;
    if (!compute_d(p, q, E_PUB, d)) { std::printf("FAIL: compute_d\n"); return 1; }

    bn::BigInt dp = bn::mod(d, bn::sub(p, bn::BigInt(1)));
    bn::BigInt dq = bn::mod(d, bn::sub(q, bn::BigInt(1)));

    // 256-byte big-endian capture stream: [dp:128][dq:128].
    std::vector<uint8_t> stream(256, 0);
    bn::to_bytes_be_fixed(dp, stream.data(), 128);
    bn::to_bytes_be_fixed(dq, stream.data() + 128, 128);

    std::printf("[selftest] reconstructing from CRT pair (no N)...\n");
    auto t2 = clk::now();
    DRecon R = reconstruct_no_N(stream, E_PUB, E_PUB);
    auto t3 = clk::now();
    std::printf("[selftest] reconstruction: %.2fs (this IS the real-flow cost)\n",
                secs(t2, t3));
    if (!R.ok) { std::printf("FAIL: reconstruct_no_N did not recover the key\n"); return 1; }

    // Factor order may be swapped by the recovery; accept either pairing.
    bool factors_ok = (same(R.p, p) && same(R.q, q)) ||
                      (same(R.p, q) && same(R.q, p));
    if (!factors_ok) { std::printf("FAIL: recovered factors != originals\n"); return 1; }
    if (!same(R.d, d)) { std::printf("FAIL: recovered d != original d\n"); return 1; }

    bn::BigInt N_orig = bn::mul(p, q);
    bn::BigInt N_rec  = bn::mul(R.p, R.q);
    if (!same(N_orig, N_rec)) { std::printf("FAIL: recovered N != original N\n"); return 1; }

    std::printf("[selftest] OK: recovered p, q, d, N all match (mode=%s)\n", R.mode.c_str());

#ifdef HAVE_OPENSSL
    const char* out_path = "selftest_key.pem";
    if (write_pem_output(out_path, R, N_rec)) {
        std::printf("[selftest] OK: PEM written to %s\n", out_path);
    } else {
        std::printf("FAIL: write_pem_output\n");
        return 1;
    }
#else
    std::printf("[selftest] (PEM output skipped: built without OpenSSL)\n");
#endif

    std::printf("[selftest] PASS\n");
    return 0;
}
