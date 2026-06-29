#include "reconstruct.h"
#include <cstring>
#include "vendored/Sha256Portable.hpp"
#include "vendored/BigIntModExp.hpp"

bool compute_d(const bn::BigInt& p, const bn::BigInt& q, int E, bn::BigInt& d) {
    bn::BigInt p_minus_1 = bn::sub(p, bn::BigInt(1));
    bn::BigInt q_minus_1 = bn::sub(q, bn::BigInt(1));
    bn::BigInt phi = bn::mul(p_minus_1, q_minus_1);
    d = bn::mod_inverse(bn::BigInt(uint32_t(E)), phi);
    return !d.is_zero();
}

// Collect prime factor candidates from one captured CRT exponent half.
// For h = d mod (f-1):  E*h - 1 = k*(f-1)  =>  f = (E*h-1)/k + 1, 1 <= k < E.
static std::vector<bn::BigInt> crt_prime_candidates(const bn::BigInt& h,
                                                    int E, int max_k) {
    std::vector<bn::BigInt> out;
    if (h.is_zero()) return out;
    bn::BigInt num = bn::mul_small(h, uint32_t(E));
    if (num.is_zero()) return out;
    num = bn::sub(num, bn::BigInt(1));
    for (int k = 1; k < max_k; ++k) {
        uint32_t rem = 0;
        bn::BigInt quot = bn::div_small(num, uint32_t(k), &rem);
        if (rem != 0) continue;
        // f = quot + 1 must be an odd prime, so quot must be even — cheap reject.
        if (!quot.is_zero() && (quot.v[0] & 1u)) continue;
        bn::BigInt f = bn::add(quot, bn::BigInt(1));     // candidate prime factor
        // RSA-2048 factors are ~1024 bits; ignore degenerate small candidates.
        if (f.bit_length() < 900 || f.bit_length() > 1100) continue;
        if (bn::is_probable_prime(f)) out.push_back(f);
    }
    return out;
}

DRecon factor_from_crt_pair(const bn::BigInt& dp_half, const bn::BigInt& dq_half,
                            int E, int max_k) {
    DRecon R;
    std::vector<bn::BigInt> ps = crt_prime_candidates(dp_half, E, max_k);
    std::vector<bn::BigInt> qs = crt_prime_candidates(dq_half, E, max_k);

    for (const auto& p : ps) {
        for (const auto& q : qs) {
            if (bn::BigInt::cmp(p, q) == 0) continue;
            bn::BigInt d;
            if (!compute_d(p, q, E, d)) continue;
            // CRT-consistency: d mod (p-1) must equal the captured dp half, and
            // d mod (q-1) the dq half. Only the true (p,q) pair satisfies both.
            bn::BigInt p1 = bn::sub(p, bn::BigInt(1));
            bn::BigInt q1 = bn::sub(q, bn::BigInt(1));
            if (bn::BigInt::cmp(bn::mod(d, p1), dp_half) != 0) continue;
            if (bn::BigInt::cmp(bn::mod(d, q1), dq_half) != 0) continue;
            R.ok = true;
            R.mode = "crt_pair_noN";
            R.p = p; R.q = q; R.dp = dp_half; R.dq = dq_half; R.d = d;
            R.k_found = 0;
            return R;
        }
    }
    return R;
}

DRecon reconstruct_no_N(const std::vector<uint8_t>& stream, int E, int max_k) {
    DRecon R;
    if (stream.size() != 256) return R;
    const int H = 128;
    bn::BigInt a = bn::from_bytes_be(stream.data(),     H);
    bn::BigInt b = bn::from_bytes_be(stream.data() + H, H);
    R = factor_from_crt_pair(a, b, E, max_k);
    if (R.ok) return R;
    // Half ordering is symmetric for this recovery, but try the swap defensively.
    return factor_from_crt_pair(b, a, E, max_k);
}

int validate_envelopes(const bn::BigInt& d, const bn::BigInt& N,
                       const std::vector<Envelope>& envs,
                       int* first_fail_ix) {
    uint8_t N_be[256], d_be[256];
    bn::to_bytes_be_fixed(N, N_be, 256);
    bn::to_bytes_be_fixed(d, d_be, 256);
    size_t d_first = 0;
    while (d_first < 256 && d_be[d_first] == 0) ++d_first;
    size_t exp_len = 256 - d_first;
    const uint8_t* exp_ptr = d_be + d_first;

    int passed = 0;
    for (size_t ix = 0; ix < envs.size(); ++ix) {
        const auto& env = envs[ix];
        auto h = bambu_signing::Sha256Portable::hash(env.to_sign);
        uint8_t EM[256];
        pkcs1_v15_pad_sha256(h.data(), EM);
        uint8_t sig[256];
        bambu_signing::big_modexp_rsa2048(EM, exp_ptr, exp_len, N_be, sig);
        std::vector<uint8_t> exp_bytes;
        if (!base64_decode(env.sig_b64, exp_bytes)) {
            if (first_fail_ix && *first_fail_ix < 0) *first_fail_ix = int(ix);
            continue;
        }
        if (exp_bytes.size() != 256) {
            if (first_fail_ix && *first_fail_ix < 0) *first_fail_ix = int(ix);
            continue;
        }
        if (std::memcmp(sig, exp_bytes.data(), 256) == 0) {
            ++passed;
        } else if (first_fail_ix && *first_fail_ix < 0) {
            *first_fail_ix = int(ix);
        }
    }
    return passed;
}

