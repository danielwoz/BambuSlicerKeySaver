#pragma once

// Known-plaintext locator for the slicer RSA key.
//
// Unlike the blind capture pipeline, this module is GIVEN a reference key
// (d_extracted.json) and searches the live plugin's memory for it. This serves
// two purposes:
//   1. If the bytes appear anywhere, it pins the exact location where the key
//      is resident, so a targeted read there yields the key.
//   2. If they never appear, it indicates the signing routine is not being
//      exercised in a headless setup (the trigger never fires).
//
// Searches both big- and little-endian forms of p, q, dp, dq, d and N.

#include <vector>
#include "envelope.h"

namespace bbl {

// One-shot sweep of all committed, readable memory. Logs every hit with its
// address, region protection and owning module/stack. Returns the hit count.
// `json_path` -> d_extracted.json. `label` tags the log line (e.g. "after-connect").
int scan_known_memory(const char* json_path, const char* label);

// Spawn a background watcher that tight-loops over every thread's stack looking
// for the (transient) key buffer while the caller drives signing on the main
// thread. Catches the wrapper's stack copy that exists only during a signature.
void start_known_stack_watch(const char* json_path);

// Stop the watcher and return the number of distinct hits it observed.
int stop_known_stack_watch();

// BLIND extraction (no foreknowledge of the key): sweep the heap for
// high-entropy 1024-bit windows, primality-test them to find the RSA factors,
// and recover the full key. `trigger(ctx)` drives one signing op
// (install_device_cert) and is called continuously on a background thread so the
// transient key stays materialised in the heap during the scan. The correct
// (p,q) is pinned by validating against `envs` (public signed messages). Retries
// up to `attempts` times. Writes recovered components (hex) to out_path on
// success. Returns true only after the recovered key validates all envelopes.
bool blind_extract(const char* out_path, void (*trigger)(void*), void* ctx,
                   const std::vector<Envelope>& envs, const char* n_hex,
                   int attempts = 6);

// Single NON-SUSPENDING committed-heap sweep for the RSA factor (p or q), the
// private exponent d, or a CRT half. Returns true (and writes the validated key
// to out_path) if found. No thread suspend, no freeze -> safe to run repeatedly
// while an external signer keeps p/q materialised (e.g. while the DR breakpoint
// steers signing). Persistent dedup across calls is kept internally so repeated
// calls are cheap. Call trigger yourself between calls to drive fresh signatures.
bool blind_scan_once(const char* out_path,
                     const std::vector<Envelope>& envs, const char* n_hex);

// DIAGNOSTIC (uses a reference key as a SEARCH KEY only, never as the output):
// sweep all committed memory for the reference p/q under MANY candidate
// representations -- plain BE, plain LE (full byte reverse), 32-bit-limb LE with
// byte-swapped limbs, 64-bit-limb orderings, and Montgomery forms w = (p*R) mod N
// for R in {2^1024, 2^1088, 2^2048} and mod p. On a hit it reports the exact
// representation + address, which pins how the live plugin stores the primes so
// the blind sweep can target that representation. Returns the number of hits.
int scan_known_representations(const char* json_path, const char* n_hex,
                               const char* label);

// DETERMINISTIC read-at-breakpoint capture. Blocks up to wait_ms for the DR
// breakpoint's VEH to HOLD a signing thread at the branch (p/q resident), COPIES
// the small MEM_PRIVATE heap regions while held (so the captured bytes are the
// resident-primes instant), releases the thread, then analyses the frozen copy
// (plain BE+LE division vs N). Recovers + validates (p*q==N + all envelopes) +
// writes the key on success. Requires the capture gate to be armed
// (flip_enable_capture_gate). Returns true on a validated key.
bool blind_scan_gated(const char* out_path, const std::vector<Envelope>& envs,
                      const char* n_hex, int wait_ms,
                      void (*trigger)(void*) = nullptr, void* ctx = nullptr);

// BLIND Montgomery-aware NON-SUSPENDING sweep: like blind_scan_once, but for each
// high-entropy 128-byte window w it ALSO tests candidate transforms (32-bit/64-bit
// limb re-orderings and Montgomery de-conversion w*R^-1 mod N) and checks whether
// the de-transformed value divides N. Recovers + validates + writes the key on a
// hit. Safe to call repeatedly while the DR breakpoint is armed. Returns true on
// validated key.
bool blind_scan_montgomery(const char* out_path,
                           const std::vector<Envelope>& envs, const char* n_hex);

}  // namespace bbl
