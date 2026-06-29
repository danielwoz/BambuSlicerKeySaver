#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "bigint.h"
#include "envelope.h"

// ===========================================================================
// Factor recovery + d reconstruction
// ===========================================================================

struct DRecon {
    bool ok = false;
    bn::BigInt p, q, dp, dq, d;
    int k_found = 0;
    std::string mode;  // recovery mode label, e.g. "crt_pair_noN"
};

bool compute_d(const bn::BigInt& p, const bn::BigInt& q, int E, bn::BigInt& d);

// Recover the RSA factors from the two captured CRT private exponents alone,
// WITHOUT a pre-known modulus N. For each half h (== d mod (f-1)) the prime
// factor f is a candidate (E*h - 1)/k + 1 for some 1 <= k < E; the real factor
// is prime, and the correct (p,q) pair is pinned by the CRT-consistency check
// d mod (p-1) == dp and d mod (q-1) == dq. On success R.p/R.q/R.dp/R.dq/R.d are
// set; the caller computes N = p*q.
DRecon factor_from_crt_pair(const bn::BigInt& dp_half, const bn::BigInt& dq_half,
                            int E, int max_k);

// Convenience wrapper: split the 256-byte capture into the two 128-byte halves
// and run factor_from_crt_pair (tries both half orderings).
DRecon reconstruct_no_N(const std::vector<uint8_t>& stream, int E, int max_k);

int validate_envelopes(const bn::BigInt& d, const bn::BigInt& N,
                       const std::vector<Envelope>& envs,
                       int* first_fail_ix = nullptr);
