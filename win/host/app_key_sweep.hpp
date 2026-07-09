#pragma once

// ===========================================================================
// app_key_sweep -- recover an RSA-2048 private key's primes p,q from raw memory
// buffers, GIVEN the key's public modulus N.
//
// This is the same capability the slicer-key pipeline uses (known_scan.cpp's
// blind sweep), generalised to an ARBITRARY caller-supplied 256-byte modulus so
// it can target the cloud "app key" that signs create_task (moduli such as
// AE1DB130.../96CC5B72.../9A4B382E...) instead of the hard-coded slicer N.
//
// The recovery is pure division against the public modulus: a 1024-bit prime
// factor p of N is located by scanning committed memory for 128-byte integers
// (tried in BOTH byte orders -- big-endian and little-endian/OpenSSL-limb
// order), testing N mod p == 0. On a hit, q = N/p and d = E^-1 mod (p-1)(q-1)
// are reconstructed with keysaver_core (reconstruct.cpp / bigint.cpp); the
// result is verified (p*q == N, e*d == 1 mod lcm) before being returned.
//
// No primality test is needed: dividing the KNOWN modulus pins the true factor
// directly, so a factor stored in either byte order is caught regardless of the
// heap's surrounding noise.
// ===========================================================================

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace bbl {

// Recovered RSA key components (big-endian, minimal length -- no leading zero
// padding). `ok` is true only after p*q == N has been re-verified.
struct RsaKeyParts {
    std::vector<uint8_t> n;   // the supplied modulus (echoed back, big-endian)
    std::vector<uint8_t> p;   // recovered prime factor
    std::vector<uint8_t> q;   // N / p
    std::vector<uint8_t> d;   // private exponent, E = 65537
    std::vector<uint8_t> dp;  // d mod (p-1)   (CRT exponent)
    std::vector<uint8_t> dq;  // d mod (q-1)   (CRT exponent)
    bool ok = false;
};

// Scan `buffers` (each a {pointer, byte-length} span) for a 128-byte factor of
// N. Every 8-byte-aligned 128-byte window is interpreted BOTH as big-endian and
// as little-endian (full byte reverse); the first that divides N wins. On a hit
// q = N/p and d are reconstructed and p*q == N is re-verified.
//
// `n_be256` is the modulus in big-endian. It may be shorter than 256 bytes (it
// is left-zero-padded internally); the meaningful width must be ~2048 bits.
//
// Returns ok=false (empty parts) if no factor is found in the supplied buffers.
RsaKeyParts recover_pq_for_modulus(
    const std::vector<uint8_t>& n_be256,
    const std::vector<std::pair<const uint8_t*, size_t>>& buffers);

// Convenience: walk THIS process's committed MEM_PRIVATE heap regions
// (VirtualQuery sweep, SEH-guarded reads -- mirrors cloud_tap.cpp) and run
// recover_pq_for_modulus over each region. For later in-process extraction:
// call this after the target key's RSA object has been materialised in the
// heap (e.g. while the plugin is signing). Returns ok=false if not found.
//
// Windows only. On other platforms returns ok=false.
RsaKeyParts recover_pq_for_modulus_self(const std::vector<uint8_t>& n_be256);

// ---------------------------------------------------------------------------
// Background sweeper: spawn a thread that loops recover_pq_for_modulus_self(N)
// back-to-back (each full heap pass ~10-15s) until it recovers the key or is
// stopped. The target RSA key (the cloud "app key") is CACHED resident in the
// plugin heap after get_app_cert, so once it is loaded a pass will find it.
// On success it writes n/p/q/d/dp/dq (hex) to `out_path` and to stderr, and
// sets the found flag. Idempotent. Gate the whole thing on a --app-key-sweep
// modulus so ordinary runs are unaffected.
void start_app_key_sweep(const std::vector<uint8_t>& n_be, const char* out_path);
void stop_app_key_sweep();
bool app_key_sweep_found();

}  // namespace bbl
