#include "app_key_sweep.hpp"

#include "bigint.h"
#include "reconstruct.h"

#include <cstdio>
#include <cstring>

namespace bbl {

namespace {

constexpr int    E_PUB    = 65537;
constexpr size_t PRIME_BYTES = 128;   // RSA-2048 -> 1024-bit factors

// Left-zero-pad (or copy) the supplied modulus to exactly 256 big-endian bytes.
std::vector<uint8_t> pad_be256(const std::vector<uint8_t>& n) {
    std::vector<uint8_t> out(256, 0);
    // Drop any leading zeros from the input, then right-align the rest.
    size_t first = 0;
    while (first < n.size() && n[first] == 0) ++first;
    size_t len = n.size() - first;
    if (len > 256) {  // oversized -- keep the low 256 bytes (shouldn't happen)
        first = n.size() - 256;
        len = 256;
    }
    std::memcpy(out.data() + (256 - len), n.data() + first, len);
    return out;
}

// Emit a BigInt as minimal-length (no leading zero) big-endian bytes.
std::vector<uint8_t> to_min_be(const bn::BigInt& x) {
    uint8_t tmp[512];
    // 256 bytes is enough for any value here (N, d <= 2048 bits); use 512 for
    // safety against an unexpected carry.
    bn::to_bytes_be_fixed(x, tmp, sizeof tmp);
    size_t first = 0;
    while (first < sizeof(tmp) - 1 && tmp[first] == 0) ++first;
    return std::vector<uint8_t>(tmp + first, tmp + sizeof(tmp));
}

// Given a candidate factor `cand`, test cand | N. On success fill `out` with the
// fully reconstructed + re-verified key and return true.
bool try_factor(const bn::BigInt& N, const bn::BigInt& cand, RsaKeyParts& out) {
    // A real 1024-bit factor: reject degenerate widths cheaply before the
    // (relatively costly) big-integer division.
    int bl = cand.bit_length();
    if (bl < 1000 || bl > 1025) return false;
    if (bn::BigInt::cmp(cand, N) >= 0) return false;
    if (!bn::mod(N, cand).is_zero()) return false;      // the arbiter: cand | N

    bn::BigInt q = bn::div(N, cand, nullptr);
    if (q.is_zero()) return false;

    // Re-verify p*q == N (guards against any div/mod edge case).
    if (bn::BigInt::cmp(bn::mul(cand, q), N) != 0) return false;

    bn::BigInt d;
    if (!compute_d(cand, q, E_PUB, d)) return false;    // d = E^-1 mod (p-1)(q-1)

    bn::BigInt dp = bn::mod(d, bn::sub(cand, bn::BigInt(1)));
    bn::BigInt dq = bn::mod(d, bn::sub(q,    bn::BigInt(1)));

    out.n  = to_min_be(N);
    out.p  = to_min_be(cand);
    out.q  = to_min_be(q);
    out.d  = to_min_be(d);
    out.dp = to_min_be(dp);
    out.dq = to_min_be(dq);
    out.ok = true;
    return true;
}

// Light pre-filter: an RSA prime is odd and has its top bit set (full 1024-bit
// width). This is applied to whichever byte order is being tested, so BOTH the
// "already big-endian" reading and the "reverse to big-endian" reading get a
// cheap gate before trial division. Returns true if the 128 big-endian bytes
// COULD be a 1024-bit prime.
inline bool be_prime_shape(const uint8_t* be128) {
    return (be128[0] & 0x80) != 0 &&        // top bit set  -> ~1024 bits
           (be128[127] & 0x01) != 0;        // odd
}

// Scan a single flat buffer for a 128-byte factor of N (both byte orders).
bool scan_buffer(const bn::BigInt& N, const uint8_t* base, size_t len,
                 RsaKeyParts& out) {
    if (len < PRIME_BYTES) return false;
    uint8_t be[PRIME_BYTES];
    const size_t last = len - PRIME_BYTES;
    for (size_t off = 0; off <= last; off += 8) {
        const uint8_t* w = base + off;

        // (a) window is ALREADY big-endian: w[0] is the most significant byte.
        if (be_prime_shape(w)) {
            bn::BigInt v = bn::from_bytes_be(w, PRIME_BYTES);
            if (try_factor(N, v, out)) return true;
        }

        // (b) window is little-endian (OpenSSL limb order): reverse to BE first.
        for (size_t i = 0; i < PRIME_BYTES; ++i) be[i] = w[PRIME_BYTES - 1 - i];
        if (be_prime_shape(be)) {
            bn::BigInt v = bn::from_bytes_be(be, PRIME_BYTES);
            if (try_factor(N, v, out)) return true;
        }
    }
    return false;
}

}  // namespace

RsaKeyParts recover_pq_for_modulus(
    const std::vector<uint8_t>& n_be256,
    const std::vector<std::pair<const uint8_t*, size_t>>& buffers) {
    RsaKeyParts out;
    std::vector<uint8_t> nbe = pad_be256(n_be256);
    bn::BigInt N = bn::from_bytes_be(nbe.data(), nbe.size());
    if (N.bit_length() < 2000) {          // expect a ~2048-bit modulus
        std::fprintf(stderr,
                     "[app-key] modulus is only %d bits -- expected ~2048\n",
                     N.bit_length());
        return out;
    }
    for (const auto& b : buffers) {
        if (!b.first || b.second < PRIME_BYTES) continue;
        if (scan_buffer(N, b.first, b.second, out)) return out;
    }
    return out;
}

}  // namespace bbl

// ---------------------------------------------------------------------------
// In-process committed-heap variant. Mirrors cloud_tap.cpp: a VirtualQuery walk
// of MEM_PRIVATE committed regions with SEH-guarded reads, feeding each region
// to recover_pq_for_modulus. Windows only.
// ---------------------------------------------------------------------------
#if defined(_WIN32)

#include <windows.h>
#include <vector>
#include <atomic>
#include <thread>
#include <string>

namespace bbl {
namespace {

// SEH-guarded copy (POD-only, no C++ objects in scope -> legal __try). Returns
// false if the source page faults mid-read (a race with the owning process).
static bool safe_copy_region(void* dst, const void* src, size_t n) {
    __try {
        std::memcpy(dst, src, n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

}  // namespace

RsaKeyParts recover_pq_for_modulus_self(const std::vector<uint8_t>& n_be256) {
    RsaKeyParts out;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uint8_t* addr = (uint8_t*)si.lpMinimumApplicationAddress;
    uint8_t* maxa = (uint8_t*)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    std::vector<uint8_t> rbuf;
    long long regions = 0;
    size_t scanned = 0;

    while (addr < maxa && VirtualQuery(addr, &mbi, sizeof mbi) == sizeof mbi) {
        uint8_t* rbase = (uint8_t*)mbi.BaseAddress;
        size_t   rsz   = mbi.RegionSize;

        bool prot_ok = (mbi.Protect == PAGE_READWRITE ||
                        mbi.Protect == PAGE_READONLY  ||
                        mbi.Protect == PAGE_WRITECOPY ||
                        mbi.Protect == PAGE_EXECUTE_READWRITE ||
                        mbi.Protect == PAGE_EXECUTE_READ);
        if (mbi.Protect & PAGE_GUARD)   prot_ok = false;
        if (mbi.Protect & PAGE_NOACCESS) prot_ok = false;

        // Only the owning process's private heap holds the transient RSA object;
        // skip images/mapped and cap the per-region size so one giant region
        // cannot stall the sweep.
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && prot_ok &&
            rsz >= 128 && rsz < (size_t)(512ull << 20)) {
            rbuf.resize(rsz);
            if (safe_copy_region(rbuf.data(), rbase, rsz)) {
                ++regions;
                scanned += rsz;
                std::vector<std::pair<const uint8_t*, size_t>> one{
                    {rbuf.data(), rsz}};
                out = recover_pq_for_modulus(n_be256, one);
                if (out.ok) {
                    std::fprintf(stderr,
                        "[app-key] *** factor found in MEM_PRIVATE region %p "
                        "(%.2f MB) ***\n", (void*)rbase, rsz / 1048576.0);
                    return out;
                }
            }
        }

        uint8_t* next = rbase + rsz;
        if (next <= addr) break;      // overflow / no-progress guard
        addr = next;
    }
    std::fprintf(stderr,
                 "[app-key] self-scan: %lld MEM_PRIVATE regions, %.1f MB, "
                 "no factor\n", regions, scanned / 1048576.0);
    return out;   // ok == false
}

// ---- background sweeper --------------------------------------------------
namespace {

std::atomic<bool>    g_ak_run{false};
std::atomic<bool>    g_ak_found{false};
std::thread          g_ak_thr;
std::vector<uint8_t> g_ak_n;
std::string          g_ak_out;

void write_hex(FILE* f, const char* name, const std::vector<uint8_t>& v) {
    if (f) { std::fprintf(f, "%s=", name);
             for (uint8_t b : v) std::fprintf(f, "%02X", b);
             std::fprintf(f, "\n"); }
    std::fprintf(stderr, "[app-key] %-3s = ", name);
    for (uint8_t b : v) std::fprintf(stderr, "%02X", b);
    std::fprintf(stderr, "\n");
}

// Locate the app RSA private key as a DER RSAPrivateKey in the heap. The cached
// app_key_blob (from get_app_cert) is a DER key whose version+modulus prefix is
// "02 01 00  02 82 01 01 00  <256-byte modulus>"; the enclosing Certificate/key
// SEQUENCE header (30 82 HH LL) sits 4 bytes before that match. Works for a bare
// PKCS#1 key and for the inner key of a PKCS#8 wrapper (both carry that prefix).
// Writes the exact DER SEQUENCE to `out_der` and returns true on the first hit.
// pad_be256 / safe_copy_region live in this TU's bbl anonymous namespace.
bool find_app_key_der(const std::vector<uint8_t>& mod_be, const std::string& out_der) {
    std::vector<uint8_t> nd;
    const uint8_t hdr[] = {0x02,0x01,0x00, 0x02,0x82,0x01,0x01,0x00};
    nd.insert(nd.end(), hdr, hdr + sizeof hdr);
    std::vector<uint8_t> m = pad_be256(mod_be);           // exactly 256 bytes BE
    nd.insert(nd.end(), m.begin(), m.end());
    const size_t nn = nd.size();                           // 8 + 256 = 264

    SYSTEM_INFO si; GetSystemInfo(&si);
    uint8_t* addr = (uint8_t*)si.lpMinimumApplicationAddress;
    uint8_t* maxa = (uint8_t*)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    std::vector<uint8_t> rbuf;

    while (addr < maxa && VirtualQuery(addr, &mbi, sizeof mbi) == sizeof mbi) {
        uint8_t* rbase = (uint8_t*)mbi.BaseAddress;
        size_t   rsz   = mbi.RegionSize;
        bool prot_ok = (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY ||
                        mbi.Protect == PAGE_WRITECOPY || mbi.Protect == PAGE_EXECUTE_READWRITE ||
                        mbi.Protect == PAGE_EXECUTE_READ);
        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) prot_ok = false;

        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && prot_ok &&
            rsz >= nn + 4 && rsz < (size_t)(512ull << 20)) {
            rbuf.resize(rsz);
            if (safe_copy_region(rbuf.data(), rbase, rsz)) {
                const uint8_t* b = rbuf.data();
                for (size_t i = 4; i + nn <= rsz; ++i) {
                    if (b[i] != 0x02) continue;                        // first-byte gate
                    if (std::memcmp(b + i, nd.data(), nn) != 0) continue;
                    if (b[i-4] != 0x30 || b[i-3] != 0x82) continue;    // enclosing SEQUENCE
                    size_t total = ((size_t)b[i-2] << 8 | b[i-1]) + 4;
                    if (i - 4 + total > rsz || total < nn) continue;
                    FILE* f = std::fopen(out_der.c_str(), "wb");
                    if (f) { std::fwrite(b + (i - 4), 1, total, f); std::fclose(f); }
                    std::fprintf(stderr,
                        "[app-key] *** found app private key DER (%zu bytes) at %p ***\n",
                        total, (void*)(rbase + i - 4));
                    return true;
                }
            }
        }
        uint8_t* next = rbase + rsz;
        if (next <= addr) break;
        addr = next;
    }
    return false;
}

void ak_loop() {
    int pass = 0;
    std::string der_out = g_ak_out + ".der";
    while (g_ak_run.load() && !g_ak_found.load()) {
        ++pass;
        // (1) cached DER private-key blob -- stable after get_app_cert, the likely form.
        if (find_app_key_der(g_ak_n, der_out)) {
            g_ak_found = true;
            std::fprintf(stderr,
                "[app-key] *** app private key DER dumped to %s (pass %d) ***\n",
                der_out.c_str(), pass);
            return;
        }
        // (2) fallback: a live OpenSSL RSA struct with plain 8-aligned p/q.
        RsaKeyParts k = recover_pq_for_modulus_self(g_ak_n);
        if (k.ok) {
            g_ak_found = true;
            std::fprintf(stderr,
                "[app-key] *** RECOVERED app private key (plain p/q) on pass %d ***\n", pass);
            FILE* f = std::fopen(g_ak_out.c_str(), "w");
            write_hex(f, "n",  k.n);
            write_hex(f, "p",  k.p);
            write_hex(f, "q",  k.q);
            write_hex(f, "d",  k.d);
            write_hex(f, "dp", k.dp);
            write_hex(f, "dq", k.dq);
            if (f) std::fclose(f);
            return;
        }
        std::fprintf(stderr, "[app-key] pass %d: app key not resident (no DER blob, no plain p/q)\n", pass);
        Sleep(150);
    }
}

}  // namespace

void start_app_key_sweep(const std::vector<uint8_t>& n_be, const char* out_path) {
    if (g_ak_run.load()) return;
    g_ak_n   = n_be;
    g_ak_out = out_path && out_path[0] ? out_path : "app_key.txt";
    g_ak_run = true;
    g_ak_thr = std::thread(ak_loop);
    std::fprintf(stderr, "[app-key] background sweep started (N=%zuB, out=%s)\n",
                 n_be.size(), g_ak_out.c_str());
}

void stop_app_key_sweep() {
    if (!g_ak_run.load()) return;
    g_ak_run = false;
    if (g_ak_thr.joinable()) g_ak_thr.join();
    std::fprintf(stderr, "[app-key] sweep stopped (found=%d)\n",
                 (int)g_ak_found.load());
}

bool app_key_sweep_found() { return g_ak_found.load(); }

}  // namespace bbl

#else   // !_WIN32

namespace bbl {
RsaKeyParts recover_pq_for_modulus_self(const std::vector<uint8_t>&) {
    return RsaKeyParts{};
}
void start_app_key_sweep(const std::vector<uint8_t>&, const char*) {}
void stop_app_key_sweep() {}
bool app_key_sweep_found() { return false; }
}  // namespace bbl

#endif
