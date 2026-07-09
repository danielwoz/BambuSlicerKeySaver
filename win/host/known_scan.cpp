#include "known_scan.hpp"
#include "reconstruct.h"
#include "bigint.h"

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace bbl {

// Coordination with the DR breakpoint re-armer (verdict_flip.cpp): while we
// freeze-suspend all threads for a stack snapshot, the re-armer must not also
// SuspendThread (double-suspend deadlock). No-op if the breakpoint isn't armed.
void flip_pause_rearm();
void flip_resume_rearm();
void flip_rearm_now();               // re-program flip DR BPs once (single suspender)
void flip_stop_background_rearm();   // stop the standalone re-armer thread

namespace {

struct Needle {
    std::string          name;   // e.g. "dp(BE)"
    std::vector<uint8_t> bytes;
};

// --- tiny hex/json helpers ------------------------------------------------

std::vector<uint8_t> hex_to_bytes(const std::string& hx) {
    std::string h = hx;
    if (h.size() >= 2 && h[0] == '0' && (h[1] == 'x' || h[1] == 'X')) h = h.substr(2);
    if (h.size() & 1) h = "0" + h;
    std::vector<uint8_t> out;
    out.reserve(h.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        int hi = nib(h[i]), lo = nib(h[i + 1]);
        if (hi < 0 || lo < 0) break;
        out.push_back((uint8_t)((hi << 4) | lo));
    }
    return out;
}

// Extract the hex string value of "key": "...." from a json blob (crude).
std::string json_str(const std::string& blob, const char* key) {
    std::string pat = std::string("\"") + key + "\"";
    size_t k = blob.find(pat);
    if (k == std::string::npos) return "";
    size_t c = blob.find(':', k + pat.size());
    if (c == std::string::npos) return "";
    size_t q1 = blob.find('"', c + 1);
    if (q1 == std::string::npos) return "";
    size_t q2 = blob.find('"', q1 + 1);
    if (q2 == std::string::npos) return "";
    return blob.substr(q1 + 1, q2 - q1 - 1);
}

std::vector<Needle> load_needles(const char* json_path) {
    std::vector<Needle> ns;
    FILE* f = std::fopen(json_path, "rb");
    if (!f) {
        std::fprintf(stderr, "[known] cannot open %s\n", json_path);
        return ns;
    }
    std::string blob;
    char buf[4096];
    size_t r;
    while ((r = std::fread(buf, 1, sizeof buf, f)) > 0) blob.append(buf, r);
    std::fclose(f);

    const char* keys[] = {"p_hex", "q_hex", "dp_hex", "dq_hex", "d_hex", "N_hex"};
    for (const char* key : keys) {
        std::string hx = json_str(blob, key);
        if (hx.empty()) continue;
        std::vector<uint8_t> be = hex_to_bytes(hx);
        if (be.size() < 32) continue;
        std::vector<uint8_t> le(be.rbegin(), be.rend());
        std::string base(key);
        base = base.substr(0, base.find("_hex"));
        ns.push_back({base + "(BE)", be});
        ns.push_back({base + "(LE)", le});
    }
    std::fprintf(stderr, "[known] loaded %zu needles from %s\n", ns.size(), json_path);
    return ns;
}

// --- search ---------------------------------------------------------------

const uint8_t* find_bytes(const uint8_t* hay, size_t hl, const uint8_t* ndl, size_t nl) {
    if (nl == 0 || hl < nl) return nullptr;
    const uint8_t* p = hay;
    const uint8_t* end = hay + (hl - nl) + 1;
    while (p < end) {
        const void* q = std::memchr(p, ndl[0], (size_t)(end - p));
        if (!q) return nullptr;
        if (std::memcmp(q, ndl, nl) == 0) return (const uint8_t*)q;
        p = (const uint8_t*)q + 1;
    }
    return nullptr;
}

std::string region_desc(const void* addr) {
    char namebuf[MAX_PATH];
    HMODULE mod = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)addr, &mod) &&
        mod && GetModuleBaseNameA(GetCurrentProcess(), mod, namebuf, sizeof namebuf)) {
        return std::string("module:") + namebuf;
    }
    return "private/heap/stack";
}

// Scan one region; report hits. Returns number of needle hits in this region.
int scan_block(const uint8_t* base, size_t size,
               const std::vector<Needle>& ns, const char* label) {
    int hits = 0;
    for (const auto& n : ns) {
        const uint8_t* at = find_bytes(base, size, n.bytes.data(), n.bytes.size());
        while (at) {
            std::fprintf(stderr,
                         "[known] *** HIT [%s] %s at %p  (%s) ***\n",
                         label, n.name.c_str(), (const void*)at, region_desc(at).c_str());
            ++hits;
            size_t consumed = (size_t)(at - base) + 1;
            if (consumed + n.bytes.size() > size) break;
            at = find_bytes(at + 1, size - consumed, n.bytes.data(), n.bytes.size());
        }
    }
    return hits;
}

bool readable(DWORD prot) {
    if (prot & PAGE_GUARD) return false;
    if (prot & PAGE_NOACCESS) return false;
    DWORD m = prot & 0xff;
    return m == PAGE_READONLY || m == PAGE_READWRITE || m == PAGE_WRITECOPY ||
           m == PAGE_EXECUTE_READ || m == PAGE_EXECUTE_READWRITE ||
           m == PAGE_EXECUTE_WRITECOPY;
}

// --- thread stack enumeration (for the transient watcher) -----------------

typedef LONG(NTAPI* NtQIT)(HANDLE, ULONG, PVOID, ULONG, PULONG);
struct THREAD_BASIC_INFO {
    LONG     ExitStatus;
    PVOID    TebBaseAddress;
    PVOID    UniqueProcessId;
    PVOID    UniqueThreadId;
    ULONG_PTR AffinityMask;
    LONG     Priority;
    LONG     BasePriority;
};

// Suspend every other thread in this process so the heap cannot churn while we
// snapshot it. IDs are enumerated and handles opened BEFORE any suspend, and the
// suspend itself is a tight no-allocation loop -- otherwise we could deadlock by
// suspending a worker that holds the heap lock and then allocating. The caller
// must keep the frozen window allocation-free.
void freeze_others(std::vector<HANDLE>& out) {
    DWORD me = GetCurrentThreadId(), pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    std::vector<DWORD> ids;
    THREADENTRY32 te{}; te.dwSize = sizeof te;
    if (Thread32First(snap, &te)) do {
        if (te.th32OwnerProcessID == pid && te.th32ThreadID != me) ids.push_back(te.th32ThreadID);
    } while (Thread32Next(snap, &te));
    CloseHandle(snap);
    out.reserve(ids.size());
    for (DWORD id : ids) { HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, id); if (h) out.push_back(h); }
    for (HANDLE h : out) SuspendThread(h);     // tight loop, no heap allocation
}
void thaw(std::vector<HANDLE>& hs) { for (HANDLE h : hs) { ResumeThread(h); CloseHandle(h); } hs.clear(); }

struct StackRange { uintptr_t lo, hi; };

std::vector<StackRange> enum_thread_stacks() {
    std::vector<StackRange> out;
    static NtQIT ntqit = (NtQIT)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                               "NtQueryInformationThread");
    if (!ntqit) return out;
    DWORD me = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    THREADENTRY32 te{}; te.dwSize = sizeof te;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != me) continue;
            HANDLE th = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!th) continue;
            THREAD_BASIC_INFO tbi{};
            if (ntqit(th, 0 /*ThreadBasicInformation*/, &tbi, sizeof tbi, nullptr) == 0 &&
                tbi.TebBaseAddress) {
                uintptr_t teb = (uintptr_t)tbi.TebBaseAddress;
                uintptr_t stackBase  = *(uintptr_t*)(teb + 0x08);
                uintptr_t stackLimit = *(uintptr_t*)(teb + 0x10);
                if (stackLimit && stackBase > stackLimit)
                    out.push_back({stackLimit, stackBase});
            }
            CloseHandle(th);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return out;
}

// --- watcher state --------------------------------------------------------

std::atomic<bool>  g_run{false};
std::atomic<int>   g_hits{0};
std::thread        g_watch;
std::vector<Needle> g_needles;

void watch_loop() {
    long long iters = 0;
    while (g_run.load()) {
        auto stacks = enum_thread_stacks();
        for (auto& s : stacks) {
            // Validate + clamp the stack range against actual committed pages.
            uintptr_t a = s.lo;
            while (a < s.hi && g_run.load()) {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery((void*)a, &mbi, sizeof mbi)) break;
                uintptr_t rb = (uintptr_t)mbi.BaseAddress;
                uintptr_t re = rb + mbi.RegionSize;
                if (mbi.State == MEM_COMMIT && readable(mbi.Protect)) {
                    uintptr_t lo = a > rb ? a : rb;
                    uintptr_t hi = re < s.hi ? re : s.hi;
                    if (hi > lo)
                        g_hits += scan_block((const uint8_t*)lo, (size_t)(hi - lo),
                                             g_needles, "stack-watch");
                }
                a = re;
            }
        }
        ++iters;
    }
    std::fprintf(stderr, "[known] stack watcher ran %lld sweeps, %d hits\n",
                 iters, g_hits.load());
}

}  // namespace

int scan_known_memory(const char* json_path, const char* label) {
    std::vector<Needle> ns = load_needles(json_path);
    if (ns.empty()) return 0;
    int hits = 0;
    uintptr_t a = 0;
    MEMORY_BASIC_INFORMATION mbi{};
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uintptr_t maxA = (uintptr_t)si.lpMaximumApplicationAddress;
    size_t scanned = 0;
    while (a < maxA && VirtualQuery((void*)a, &mbi, sizeof mbi)) {
        uintptr_t rb = (uintptr_t)mbi.BaseAddress;
        size_t rs = mbi.RegionSize;
        if (mbi.State == MEM_COMMIT && readable(mbi.Protect)) {
            hits += scan_block((const uint8_t*)rb, rs, ns, label);
            scanned += rs;
        }
        a = rb + rs;
        if (rs == 0) break;
    }
    std::fprintf(stderr, "[known] sweep[%s]: scanned %.1f MB, %d hit(s)\n",
                 label, scanned / 1048576.0, hits);
    return hits;
}

void start_known_stack_watch(const char* json_path) {
    g_needles = load_needles(json_path);
    if (g_needles.empty()) return;
    g_hits = 0;
    g_run = true;
    g_watch = std::thread(watch_loop);
}

int stop_known_stack_watch() {
    g_run = false;
    if (g_watch.joinable()) g_watch.join();
    return g_hits.load();
}

// ---------------------------------------------------------------------------
// Blind extraction
// ---------------------------------------------------------------------------
namespace {

// SEH-guarded copy: returns false if the source page faults mid-read (guard
// pages, races between VirtualQuery and access). No C++ objects -> legal __try.
static bool safe_copy(void* dst, const void* src, size_t n) {
    __try {
        memcpy(dst, src, n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

std::vector<uint32_t> small_primes(uint32_t limit) {
    std::vector<bool> sieve(limit + 1, true);
    std::vector<uint32_t> ps;
    for (uint32_t i = 2; i <= limit; ++i)
        if (sieve[i]) {
            ps.push_back(i);
            for (uint32_t j = i * 2; j <= limit; j += i) sieve[j] = false;
        }
    return ps;
}

// Cheap necessary-prime check: not divisible by any small prime.
bool passes_trial_division(const bn::BigInt& n, const std::vector<uint32_t>& ps) {
    for (uint32_t p : ps) {
        uint32_t rem = 0;
        bn::div_small(n, p, &rem);
        if (rem == 0) return false;
    }
    return true;
}

// Allocation-free trial division of a 128-byte big-endian value by the first
// `np` small primes (Horner's method, mod by each). Returns true if it survives
// (no small factor) -- used as a cheap inline filter so the hot scan collects
// only plausible primes without any heap allocation. Rejects ~90% of composites.
bool survives_small_primes(const uint8_t* be, const std::vector<uint32_t>& sp, int np) {
    int n = (int)sp.size() < np ? (int)sp.size() : np;
    for (int k = 0; k < n; ++k) {
        uint32_t m = sp[k], r = 0;
        for (int i = 0; i < 128; ++i)
            r = (uint32_t)((((uint64_t)r << 8) + be[i]) % m);
        if (r == 0) return false;
    }
    return true;
}

// 128-byte window entropy heuristic: looks like a 1024-bit RSA prime in LE.
// Read one cache line from every committed page (including MEM_IMAGE). This
// faults in / cycles the working set the same way the full key-search pass does;
// empirically it makes the transient key reliably present for the subsequent
// window scan. No key material involved.
void touch_all_committed() {
    volatile uint64_t sink = 0;
    uintptr_t a = 0;
    MEMORY_BASIC_INFORMATION mbi{};
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uintptr_t maxA = (uintptr_t)si.lpMaximumApplicationAddress;
    uint8_t tmp[64];
    while (a < maxA && VirtualQuery((void*)a, &mbi, sizeof mbi)) {
        uintptr_t rb = (uintptr_t)mbi.BaseAddress;
        size_t rs = mbi.RegionSize;
        if (mbi.State == MEM_COMMIT && readable(mbi.Protect)) {
            const uint8_t* base = (const uint8_t*)rb;
            for (size_t off = 0; off + 64 <= rs; off += 4096)
                if (safe_copy(tmp, base + off, 64)) sink += tmp[0];
        }
        a = rb + rs;
        if (rs == 0) break;
    }
    (void)sink;
}

bool looks_like_prime_window(const uint8_t* w) {
    if (!(w[0] & 1)) return false;        // odd
    if (w[127] < 0x80) return false;      // top bit set => ~1024 bits
    int distinct[256] = {0};
    int nd = 0, run = 1, maxrun = 1;
    for (int i = 0; i < 128; ++i) {
        if (!distinct[w[i]]) { distinct[w[i]] = 1; ++nd; }
        if (i && w[i] == w[i - 1]) { if (++run > maxrun) maxrun = run; }
        else run = 1;
    }
    // 128 uniform-random bytes average ~101 distinct values, so the threshold
    // must sit well below that to keep real key material (>=80 still rejects
    // pointers/strings/structured data, which have far fewer distinct bytes).
    return nd >= 80 && maxrun < 6;
}

// Write the recovered key components to out_path.
void write_key(const char* out_path, const bn::BigInt& N, const bn::BigInt& d,
               const bn::BigInt& p, const bn::BigInt& q,
               const bn::BigInt& dp, const bn::BigInt& dq) {
    FILE* kf = std::fopen(out_path, "w");
    if (!kf) return;
    std::fprintf(kf,
        "# Slicer RSA-2048 private key - heap extraction (Windows)\n"
        "N=%s\nE=65537\nd=%s\np=%s\nq=%s\ndp=%s\ndq=%s\n",
        bn::to_hex_str(N, false).c_str(), bn::to_hex_str(d, false).c_str(),
        bn::to_hex_str(p, false).c_str(), bn::to_hex_str(q, false).c_str(),
        bn::to_hex_str(dp, false).c_str(), bn::to_hex_str(dq, false).c_str());
    std::fclose(kf);
}

static bn::BigInt gcd_bi(bn::BigInt a, bn::BigInt b) {
    while (!b.is_zero()) { bn::BigInt r = bn::mod(a, b); a = b; b = r; }
    return a;
}

// Recover the factors from a validated (N, e, d): e*d-1 = 2^t * r; a random base
// raised to r and repeatedly squared hits a non-trivial sqrt of 1, whose gcd with
// N is a factor. Standard RSA "factor with private exponent" procedure.
static bool factor_from_d(const bn::BigInt& N, uint32_t e, const bn::BigInt& d,
                          bn::BigInt& p, bn::BigInt& q) {
    bn::BigInt kk = bn::sub(bn::mul_small(d, e), bn::BigInt(1));  // e*d - 1
    if (kk.is_zero()) return false;
    bn::BigInt r = kk; int t = 0;
    while (!r.v.empty() && !(r.v[0] & 1)) { r = bn::div_small(r, 2); ++t; }
    bn::BigInt one(1), Nm1 = bn::sub(N, one);
    const uint32_t bases[] = {2,3,5,7,11,13,17,19,23,29,31,37};
    for (uint32_t a : bases) {
        bn::BigInt x = bn::modexp(bn::BigInt(a), r, N);
        if (bn::BigInt::cmp(x, one) == 0 || bn::BigInt::cmp(x, Nm1) == 0) continue;
        for (int i = 0; i < t; ++i) {
            bn::BigInt y = bn::modexp(x, bn::BigInt(2), N);
            if (bn::BigInt::cmp(y, one) == 0) {
                bn::BigInt f = gcd_bi(bn::sub(x, one), N);
                if (!f.is_zero() && bn::BigInt::cmp(f, one) != 0 && bn::BigInt::cmp(f, N) != 0) {
                    p = f; q = bn::div(N, f, nullptr); return true;
                }
                break;
            }
            if (bn::BigInt::cmp(y, Nm1) == 0) break;
            x = y;
        }
    }
    return false;
}

}  // namespace

// The decrypted slicer key is a PERIODIC transient in the heap (the plugin
// re-signs every few seconds, then frees the RSA object, whose blocks the
// encrypted-logging threads quickly reuse). So a single snapshot usually misses
// it. We take several freeze-snapshots across materialisation cycles, ACCUMULATE
// the distinct high-entropy 1024-bit values into a persistent set, and after
// each snapshot test them against the PUBLIC modulus N (N mod p == 0 -> the
// private factor). No primality test -- hopeless against the heap's encrypted-
// log noise; just a fast division. On a hit, recover d and validate the public
// envelopes before writing.
// True if the 128-byte window looks like a high-entropy 1024-bit value (a key
// half); byte-order agnostic (no odd/MSB requirement -- dp/dq can be anything).
static bool high_entropy128(const uint8_t* w) {
    // Distinct-byte count via a 32-byte bitset (cheap to zero) + max run length.
    uint64_t bs[4] = {0, 0, 0, 0};
    int nd = 0, run = 1, mx = 1;
    for (int i = 0; i < 128; ++i) {
        uint8_t b = w[i];
        uint64_t m = 1ull << (b & 63);
        if (!(bs[b >> 6] & m)) { bs[b >> 6] |= m; ++nd; }
        if (i && b == w[i - 1]) { if (++run > mx) mx = run; } else run = 1;
    }
    // ~93-102 distinct for the real key halves; keep the bar high enough to reject
    // structured stack data (pointers/saved regs) which repeats bytes.
    return nd >= 85 && mx < 6;
}

bool blind_extract(const char* out_path, void (*trigger)(void*), void* ctx,
                   const std::vector<Envelope>& envs, const char* n_hex, int attempts) {
    std::fprintf(stderr, "[blind] === heap sweep for RSA prime factors (whitepaper method) ===\n");
    const bn::BigInt N = bn::from_hex(n_hex);
    auto sp = small_primes(2000);

    // Contamination-free presence check: the PUBLIC modulus N is embedded, not
    // secret. If the plugin has the RSA object loaded, N's 256 bytes (BE or LE
    // limb order) must be resident. This tells apart "signing never materialises
    // the key" from "the key is present but the prime filter misses it".
    if (trigger) for (int i = 0; i < 150; ++i) trigger(ctx);   // warm up the RSA object
    {
        std::vector<uint8_t> nbe = hex_to_bytes(n_hex);
        while (nbe.size() < 256) nbe.insert(nbe.begin(), 0);
        std::vector<uint8_t> nle(nbe.rbegin(), nbe.rend());
        SYSTEM_INFO s2{}; GetSystemInfo(&s2);
        uintptr_t mx = (uintptr_t)s2.lpMaximumApplicationAddress, a = 0;
        MEMORY_BASIC_INFORMATION m{}; long long hbe = 0, hle = 0;
        std::vector<uint8_t> buf;
        while (a < mx && VirtualQuery((void*)a, &m, sizeof m)) {
            uintptr_t rb = (uintptr_t)m.BaseAddress; size_t rs = m.RegionSize;
            if (m.State == MEM_COMMIT && m.Type != MEM_IMAGE && readable(m.Protect) && rs >= 256) {
                buf.resize(rs);
                if (safe_copy(buf.data(), (const void*)rb, rs)) {
                    const uint8_t* bp = buf.data();
                    if (find_bytes(bp, rs, nbe.data(), 256)) ++hbe;
                    if (find_bytes(bp, rs, nle.data(), 256)) ++hle;
                }
            }
            a = rb + rs; if (rs == 0) break;
        }
        std::fprintf(stderr, "[blind] public-N presence: BE-regions=%lld LE-regions=%lld\n", hbe, hle);
    }

    // Persistent dedup across sweeps (skip already-tested 128-byte values).
    const size_t TB = 1u << 22; std::vector<uint64_t> table(TB, 0);
    auto seen_or_add = [&](const uint8_t* b) -> bool {
        uint64_t h = 1469598103934665603ULL;
        for (int i = 0; i < 128; ++i) { h ^= b[i]; h *= 1099511628211ULL; }
        if (h == 0) h = 1;
        size_t i = h & (TB - 1);
        for (;;) { uint64_t v = table[i]; if (v == 0) { table[i] = h; return false; }
                   if (v == h) return true; i = (i + 1) & (TB - 1); }
    };
    // A recovered 1024-bit prime that divides N is p (or q): recover d and validate
    // against the public envelopes.
    auto try_factor = [&](const bn::BigInt& v) -> bool {
        if (!bn::mod(N, v).is_zero()) return false;
        bn::BigInt q = bn::div(N, v, nullptr);
        bn::BigInt d;
        if (!compute_d(v, q, 65537, d)) return false;
        int ff = -1;
        if (validate_envelopes(d, N, envs, &ff) != (int)envs.size()) return false;
        bn::BigInt dp = bn::mod(d, bn::sub(v, bn::BigInt(1)));
        bn::BigInt dq = bn::mod(d, bn::sub(q, bn::BigInt(1)));
        std::fprintf(stderr, "[blind] *** KEY RECOVERED + VALIDATED (%zu/%zu envelopes) ***\n",
                     envs.size(), envs.size());
        write_key(out_path, N, d, v, q, dp, dq);
        return true;
    };

    // Candidate = the private exponent d itself (a 256-byte window). Validate
    // directly against one envelope (fast), then all. This catches a resident/
    // transient full d that the prime/division sweep cannot (N % d != 0).
    std::vector<Envelope> env1; if (!envs.empty()) env1.push_back(envs[0]);
    auto try_d = [&](const bn::BigInt& d) -> bool {
        if (env1.empty()) return false;
        if (d.bit_length() < 2000) return false;                 // d is ~2048-bit
        if (validate_envelopes(d, N, env1) != 1) return false;   // one-modexp reject
        int ff = -1;
        if (validate_envelopes(d, N, envs, &ff) != (int)envs.size()) return false;
        bn::BigInt p, q;
        factor_from_d(N, 65537, d, p, q);                        // best-effort p,q
        bn::BigInt dp = p.is_zero() ? bn::BigInt() : bn::mod(d, bn::sub(p, bn::BigInt(1)));
        bn::BigInt dq = q.is_zero() ? bn::BigInt() : bn::mod(d, bn::sub(q, bn::BigInt(1)));
        std::fprintf(stderr, "[blind] *** KEY RECOVERED via private-exponent d (%zu/%zu envelopes) ***\n",
                     envs.size(), envs.size());
        write_key(out_path, N, d, p, q, dp, dq);
        return true;
    };

    // Candidate = a CRT private exponent half dp = d mod (p-1) (a 128-byte
    // window). The prime factor is (E*dp - 1)/k + 1 for some 1 <= k < E; the one
    // that divides N is p. This is the Linux single-half recovery, applied to any
    // high-entropy window that might be a transient exponent half.
    auto try_dp = [&](const bn::BigInt& dp) -> bool {
        int bl = dp.bit_length();
        if (bl < 1000 || bl > 1024) return false;                // dp ~1024-bit
        bn::BigInt x = bn::sub(bn::mul_small(dp, 65537), bn::BigInt(1));   // E*dp - 1
        if (x.is_zero()) return false;
        for (uint32_t k = 1; k < 65537; ++k) {
            uint32_t rem = 0; bn::BigInt qd = bn::div_small(x, k, &rem);
            if (rem != 0) continue;
            bn::BigInt p = bn::add(qd, bn::BigInt(1));
            int pb = p.bit_length();
            if (pb < 1000 || pb > 1025) continue;
            if (!bn::mod(N, p).is_zero()) continue;
            bn::BigInt q = bn::div(N, p, nullptr);
            bn::BigInt d;
            if (!compute_d(p, q, 65537, d)) continue;
            int ff = -1;
            if (validate_envelopes(d, N, envs, &ff) != (int)envs.size()) continue;
            bn::BigInt ddp = bn::mod(d, bn::sub(p, bn::BigInt(1)));
            bn::BigInt ddq = bn::mod(d, bn::sub(q, bn::BigInt(1)));
            std::fprintf(stderr, "[blind] *** KEY RECOVERED via CRT half (k=%u, %zu/%zu envelopes) ***\n",
                         k, envs.size(), envs.size());
            write_key(out_path, N, d, p, q, ddp, ddq);
            return true;
        }
        return false;
    };

    // Separate dedup for 256-byte d-candidates.
    const size_t TB2 = 1u << 22; std::vector<uint64_t> table2(TB2, 0);
    auto seen_or_add256 = [&](const uint8_t* b) -> bool {
        uint64_t h = 1469598103934665603ULL;
        for (int i = 0; i < 256; ++i) { h ^= b[i]; h *= 1099511628211ULL; }
        if (h == 0) h = 1;
        size_t i = h & (TB2 - 1);
        for (;;) { uint64_t v = table2[i]; if (v == 0) { table2[i] = h; return false; }
                   if (v == h) return true; i = (i + 1) & (TB2 - 1); }
    };

    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uintptr_t maxA = (uintptr_t)si.lpMaximumApplicationAddress;

    // Drive signing CONTINUOUSLY on a background thread so the (transient) key
    // stays materialised in the heap *while* the sweep reads it. A small sleep
    // avoids hammering the plugin into an abort. The sweep runs on this thread.
    std::atomic<bool> stop{false};
    std::atomic<long long> signs{0};
    std::thread signer;
    if (trigger) {
        signer = std::thread([&]() {
            while (!stop.load(std::memory_order_relaxed)) {
                trigger(ctx);
                signs.fetch_add(1, std::memory_order_relaxed);
                Sleep(3);
            }
        });
    }

    // Sweep an already-copied byte buffer for the key (used by the freeze-
    // snapshot pass, where the buffer is a frozen-instant copy of thread stacks).
    auto test_bytes = [&](const uint8_t* base, size_t rs) -> bool {
        uint8_t w[256], be[128], be2[256];
        for (size_t off = 0; off + 128 <= rs; off += 8) {
            size_t got = (off + 256 <= rs) ? 256 : 128;
            std::memcpy(w, base + off, got);
            if (!high_entropy128(w)) continue;
            for (int i = 0; i < 128; ++i) be[i] = w[127 - i];
            if (!seen_or_add(w))  { bn::BigInt v = bn::from_bytes_be(w, 128);  if (try_factor(v) || try_dp(v)) return true; }
            if (!seen_or_add(be)) { bn::BigInt v = bn::from_bytes_be(be, 128); if (try_factor(v) || try_dp(v)) return true; }
            if (got == 256 && high_entropy128(w + 128)) {
                if (!seen_or_add256(w)) { bn::BigInt d = bn::from_bytes_be(w, 256); if (try_d(d)) return true; }
                for (int i = 0; i < 256; ++i) be2[i] = w[255 - i];
                if (!seen_or_add256(be2)) { bn::BigInt d = bn::from_bytes_be(be2, 256); if (try_d(d)) return true; }
            }
        }
        return false;
    };
    // Preallocated snapshot buffer + segment table (allocation-free during freeze).
    std::vector<uint8_t> snap(96u << 20);
    std::vector<std::pair<size_t, size_t>> segs; segs.reserve(512);

    for (int attempt = 1; attempt <= attempts; ++attempt) {
        // FREEZE-SNAPSHOT pass: the private exponent (dp/dq) lives only on the
        // signing thread's stack DURING the modexp. Suspend all threads at a
        // random instant, copy every thread stack into the preallocated buffer,
        // resume, then test the frozen copy. Rapid cycles raise the odds of
        // catching a mid-signature instant.
        bool okf = false;
        // BBL_NO_FREEZE: skip the thread-suspend freeze-snapshot pass entirely.
        // Required when a DR breakpoint re-armer is running (it also suspends
        // threads, and two concurrent SuspendThread sweeps destabilise the
        // plugin). With the breakpoint armed, signing runs continuously so p/q
        // stay in the committed heap; the non-suspending sweep below catches them.
        static const bool no_freeze = std::getenv("BBL_NO_FREEZE") != nullptr;
        // Pause the DR re-armer for the whole freeze phase so it does not
        // SuspendThread concurrently with our freeze (double-suspend deadlock).
        if (!no_freeze) flip_pause_rearm();
        for (int cyc = 0; cyc < 12 && !okf && !no_freeze; ++cyc) {
            auto stacks = enum_thread_stacks();          // allocate BEFORE freeze
            segs.clear(); if (segs.capacity() < stacks.size()) segs.reserve(stacks.size() + 8);
            std::vector<HANDLE> frozen; frozen.reserve(128);
            freeze_others(frozen);
            size_t soff = 0;
            for (auto& sr : stacks) {                    // allocation-free window
                size_t len = sr.hi - sr.lo;
                if (soff + len > snap.size()) len = snap.size() - soff;
                if (len < 128) continue;
                if (safe_copy(snap.data() + soff, (const void*)sr.lo, len)) {
                    segs.push_back({soff, len}); soff += len;
                }
                if (soff + 128 >= snap.size()) break;
            }
            thaw(frozen);
            // Re-arm the DR breakpoint now that all threads are resumed (this is
            // the single suspender, so no collision). Keeps signing proceeding so
            // the NEXT freeze cycle catches a fresh p/q.
            flip_rearm_now();
            for (auto& sg : segs) if (test_bytes(snap.data() + sg.first, sg.second)) { okf = true; break; }
            if (!okf) Sleep(15);
        }
        if (!no_freeze) flip_resume_rearm();
        if (okf) {
            stop.store(true); if (signer.joinable()) signer.join();
            std::fprintf(stderr, "[blind] *** captured key from a frozen thread stack ***\n");
            std::fprintf(stderr, "[blind] wrote validated key -> %s\n", out_path);
            return true;
        }

        // Sweep committed memory for the private factor. Gate each 128-byte,
        // 8-aligned window on high entropy (byte-order agnostic), then test BOTH
        // orientations (little-endian OpenSSL limbs AND raw big-endian) by pure
        // division: N mod v == 0 pins p or q directly -- no primality test and no
        // reliance on odd/MSB byte positions, so a factor in either byte order is
        // caught. `mr` counts high-entropy windows; `primes` counts factor hits.
        long long windows = 0, mr = 0, primes = 0; bool ok = false;
        uintptr_t a = 0; MEMORY_BASIC_INFORMATION m{};
        while (a < maxA && !ok && VirtualQuery((void*)a, &m, sizeof m)) {
            uintptr_t rb = (uintptr_t)m.BaseAddress; size_t rs = m.RegionSize;
            if (m.State == MEM_COMMIT && m.Type != MEM_IMAGE && readable(m.Protect) && rs >= 128) {
                const uint8_t* base = (const uint8_t*)rb;
                uint8_t w[256], be[128], be2[256];
                for (size_t off = 0; off + 128 <= rs && !ok; off += 8) {
                    ++windows;
                    size_t got = (off + 256 <= rs) ? 256 : 128;
                    if (!safe_copy(w, base + off, got)) { off = (((off >> 12) + 1) << 12) - 8; continue; }
                    if (!high_entropy128(w)) continue;
                    ++mr;
                    for (int i = 0; i < 128; ++i) be[i] = w[127 - i];   // LE(128) -> BE
                    // p/q factor test + CRT-half test, both byte orders.
                    if (!seen_or_add(w)) {
                        bn::BigInt v = bn::from_bytes_be(w, 128);
                        if (try_factor(v) || try_dp(v)) { ++primes; ok = true; break; }
                    }
                    if (!seen_or_add(be)) {
                        bn::BigInt v = bn::from_bytes_be(be, 128);
                        if (try_factor(v) || try_dp(v)) { ++primes; ok = true; break; }
                    }
                    // private-exponent d test (256-byte window, both byte orders).
                    if (got == 256 && high_entropy128(w + 128)) {
                        if (!seen_or_add256(w)) {
                            bn::BigInt d = bn::from_bytes_be(w, 256);
                            if (try_d(d)) { ++primes; ok = true; break; }
                        }
                        for (int i = 0; i < 256; ++i) be2[i] = w[255 - i];
                        if (!seen_or_add256(be2)) {
                            bn::BigInt d = bn::from_bytes_be(be2, 256);
                            if (try_d(d)) { ++primes; ok = true; break; }
                        }
                    }
                }
            }
            a = rb + rs; if (rs == 0) break;
        }
        if (ok) {
            stop.store(true); if (signer.joinable()) signer.join();
            std::fprintf(stderr, "[blind] wrote validated key -> %s\n", out_path);
            return true;
        }
        std::fprintf(stderr, "[blind] attempt %d/%d: windows=%lld miller-rabin=%lld primes=%lld signs=%lld (no factor yet)\n",
                     attempt, attempts, windows, mr, primes, signs.load());
    }
    stop.store(true); if (signer.joinable()) signer.join();
    std::fprintf(stderr, "[blind] exhausted %d attempts\n", attempts);
    return false;
}

// ---------------------------------------------------------------------------
// blind_scan_once: one non-suspending committed-heap sweep for p/q, d, or a CRT
// half. Safe to call repeatedly while an external signer drives fresh sigs (the
// DR breakpoint path). NO thread suspension, so it never collides with the
// re-armer.
// ---------------------------------------------------------------------------
bool blind_scan_once(const char* out_path,
                     const std::vector<Envelope>& envs, const char* n_hex) {
    const bn::BigInt N = bn::from_hex(n_hex);
    // Persistent dedup across calls.
    static const size_t TB = 1u << 22;
    static std::vector<uint64_t> table(TB, 0), table2(TB, 0);
    auto seen = [&](std::vector<uint64_t>& t, const uint8_t* b, int n) -> bool {
        uint64_t h = 1469598103934665603ULL;
        for (int i = 0; i < n; ++i) { h ^= b[i]; h *= 1099511628211ULL; }
        if (h == 0) h = 1;
        size_t i = h & (TB - 1);
        for (;;) { uint64_t v = t[i]; if (v == 0) { t[i] = h; return false; }
                   if (v == h) return true; i = (i + 1) & (TB - 1); }
    };
    std::vector<Envelope> env1; if (!envs.empty()) env1.push_back(envs[0]);
    auto try_factor = [&](const bn::BigInt& v) -> bool {
        if (v.bit_length() < 1000 || v.bit_length() > 1025) return false;
        if (!bn::mod(N, v).is_zero()) return false;
        bn::BigInt q = bn::div(N, v, nullptr), d;
        if (!compute_d(v, q, 65537, d)) return false;
        int ff = -1; if (validate_envelopes(d, N, envs, &ff) != (int)envs.size()) return false;
        bn::BigInt dp = bn::mod(d, bn::sub(v, bn::BigInt(1)));
        bn::BigInt dq = bn::mod(d, bn::sub(q, bn::BigInt(1)));
        std::fprintf(stderr, "[flip-scan] *** KEY RECOVERED via factor (%zu/%zu envelopes) ***\n",
                     envs.size(), envs.size());
        write_key(out_path, N, d, v, q, dp, dq); return true;
    };
    auto try_dp = [&](const bn::BigInt& dp) -> bool {
        int bl = dp.bit_length(); if (bl < 1000 || bl > 1024) return false;
        bn::BigInt x = bn::sub(bn::mul_small(dp, 65537), bn::BigInt(1)); if (x.is_zero()) return false;
        for (uint32_t k = 1; k < 65537; ++k) {
            uint32_t rem = 0; bn::BigInt qd = bn::div_small(x, k, &rem); if (rem) continue;
            bn::BigInt p = bn::add(qd, bn::BigInt(1)); int pb = p.bit_length();
            if (pb < 1000 || pb > 1025) continue;
            if (!bn::mod(N, p).is_zero()) continue;
            bn::BigInt q = bn::div(N, p, nullptr), d;
            if (!compute_d(p, q, 65537, d)) continue;
            int ff = -1; if (validate_envelopes(d, N, envs, &ff) != (int)envs.size()) continue;
            bn::BigInt ddp = bn::mod(d, bn::sub(p, bn::BigInt(1)));
            bn::BigInt ddq = bn::mod(d, bn::sub(q, bn::BigInt(1)));
            std::fprintf(stderr, "[flip-scan] *** KEY RECOVERED via CRT half k=%u (%zu/%zu) ***\n",
                         k, envs.size(), envs.size());
            write_key(out_path, N, d, p, q, ddp, ddq); return true;
        }
        return false;
    };
    auto try_d = [&](const bn::BigInt& d) -> bool {
        if (d.bit_length() < 2000) return false;
        if (env1.empty() || validate_envelopes(d, N, env1) != 1) return false;
        int ff = -1; if (validate_envelopes(d, N, envs, &ff) != (int)envs.size()) return false;
        bn::BigInt p, q; factor_from_d(N, 65537, d, p, q);
        bn::BigInt dp = p.is_zero()?bn::BigInt():bn::mod(d, bn::sub(p, bn::BigInt(1)));
        bn::BigInt dq = q.is_zero()?bn::BigInt():bn::mod(d, bn::sub(q, bn::BigInt(1)));
        std::fprintf(stderr, "[flip-scan] *** KEY RECOVERED via private-exponent d (%zu/%zu) ***\n",
                     envs.size(), envs.size());
        write_key(out_path, N, d, p, q, dp, dq); return true;
    };

    // FAST mode (BBL_SCAN_FAST): only the cheap p/q factor test (one N-mod per
    // window) -- skip try_dp (65k divisions/window) and try_d. p and q ARE the
    // RSA-object primes resident on the heap once signing loads the key, so the
    // pure division sweep finds them quickly. Essential when the capture window is
    // short (the plugin process may exit after a few signs).
    static const bool fast = std::getenv("BBL_SCAN_FAST") != nullptr;
    // PLUGIN-ONLY (BBL_SCAN_PLUGIN_ONLY): restrict to MEM_PRIVATE (heap) regions
    // and skip huge (>256 MB) regions so each sweep completes inside the window.
    static const bool plug_only = std::getenv("BBL_SCAN_PLUGIN_ONLY") != nullptr;
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uintptr_t maxA = (uintptr_t)si.lpMaximumApplicationAddress, a = 0;
    MEMORY_BASIC_INFORMATION m{};
    std::vector<uint8_t> rbuf;
    long long windows = 0, hi_e = 0;
    while (a < maxA && VirtualQuery((void*)a, &m, sizeof m)) {
        uintptr_t rb = (uintptr_t)m.BaseAddress; size_t rs = m.RegionSize;
        bool type_ok = plug_only ? (m.Type == MEM_PRIVATE) : (m.Type != MEM_IMAGE);
        if (m.State == MEM_COMMIT && type_ok && readable(m.Protect) && rs >= 128 &&
            rs <= (size_t)256 * 1024 * 1024) {
            rbuf.resize(rs);
            if (safe_copy(rbuf.data(), (const void*)rb, rs)) {
                const uint8_t* base = rbuf.data();
                uint8_t be[128], be2[256];
                for (size_t off = 0; off + 128 <= rs; off += 8) {
                    ++windows;
                    const uint8_t* w = base + off;
                    size_t got = (off + 256 <= rs) ? 256 : 128;
                    if (!high_entropy128(w)) continue;
                    ++hi_e;
                    for (int i = 0; i < 128; ++i) be[i] = w[127 - i];
                    if (!seen(table, w, 128))  { bn::BigInt v = bn::from_bytes_be(w, 128);  if (try_factor(v) || (!fast && try_dp(v))) return true; }
                    if (!seen(table, be, 128)) { bn::BigInt v = bn::from_bytes_be(be, 128); if (try_factor(v) || (!fast && try_dp(v))) return true; }
                    if (!fast && got == 256 && high_entropy128(w + 128)) {
                        if (!seen(table2, w, 256)) { bn::BigInt d = bn::from_bytes_be(w, 256); if (try_d(d)) return true; }
                        for (int i = 0; i < 256; ++i) be2[i] = w[255 - i];
                        if (!seen(table2, be2, 256)) { bn::BigInt d = bn::from_bytes_be(be2, 256); if (try_d(d)) return true; }
                    }
                }
            }
        }
        a = rb + rs; if (rs == 0) break;
    }
    std::fprintf(stderr, "[flip-scan] sweep: windows=%lld high-entropy=%lld (no factor this pass)\n",
                 windows, hi_e);
    return false;
}

// ---------------------------------------------------------------------------
// blind_scan_gated: DETERMINISTIC targeted-region capture.
//
// The DR breakpoint fires BEFORE the RSA modexp, so p/q are not yet in the heap
// AT the breakpoint -- a snapshot there finds nothing. But the primes live
// (plain BE+LE) in ONE small heap arena that is CO-LOCATED with the public
// modulus N. N is persistently resident (the RSA object is loaded), so it is a
// stable ANCHOR that pins the key cluster's region.
//
// This routine removes the timing race not by freezing but by TARGETING + REPEAT:
//   1. Locate the committed MEM_PRIVATE region(s) that contain N (256B, BE/LE).
//      That region (plus its immediate neighbours) is the key cluster.
//   2. TIGHT-LOOP for a time budget: re-copy ONLY those small target regions and
//      sweep them for a factor of N (plain BE+LE division). The target area is a
//      few hundred KB -> each sweep is sub-millisecond -> THOUSANDS of sweeps per
//      second, while an external continuous signer keeps re-materialising p/q in
//      that same arena. With the whole per-sign lifetime of the primes covered by
//      back-to-back sweeps of the exact region they land in, the overlap is
//      effectively certain within the budget (lands in the first burst).
// Recover + validate (p*q==N + all envelopes) + write. Returns true on success.
//
// `wait_ms` is the per-call time budget for the tight loop. If N's region cannot
// be located yet (RSA object not loaded), it falls back to scanning ALL small
// MEM_PRIVATE regions for that call.
bool blind_scan_gated(const char* out_path, const std::vector<Envelope>& envs,
                      const char* n_hex, int wait_ms,
                      void (*trigger)(void*), void* ctx) {
    const bn::BigInt N = bn::from_hex(n_hex);
    static const size_t TB = 1u << 22;
    static std::vector<uint64_t> table(TB, 0);
    auto seen = [&](const uint8_t* b, int n) -> bool {
        uint64_t h = 1469598103934665603ULL;
        for (int i = 0; i < n; ++i) { h ^= b[i]; h *= 1099511628211ULL; }
        if (h == 0) h = 1;
        size_t i = h & (TB - 1);
        for (;;) { uint64_t v = table[i]; if (v == 0) { table[i] = h; return false; }
                   if (v == h) return true; i = (i + 1) & (TB - 1); }
    };
    auto try_factor = [&](const bn::BigInt& v) -> bool {
        if (v.bit_length() < 1000 || v.bit_length() > 1025) return false;
        if (!bn::mod(N, v).is_zero()) return false;
        bn::BigInt q = bn::div(N, v, nullptr), d;
        if (!compute_d(v, q, 65537, d)) return false;
        int ff = -1; if (validate_envelopes(d, N, envs, &ff) != (int)envs.size()) return false;
        bn::BigInt dp = bn::mod(d, bn::sub(v, bn::BigInt(1)));
        bn::BigInt dq = bn::mod(d, bn::sub(q, bn::BigInt(1)));
        std::fprintf(stderr, "[flip-gate] *** KEY RECOVERED via factor (%zu/%zu envelopes) ***\n",
                     envs.size(), envs.size());
        write_key(out_path, N, d, v, q, dp, dq); return true;
    };

    // N as 256-byte BE + LE, for anchoring the key cluster's region.
    std::vector<uint8_t> nbe = hex_to_bytes(n_hex);
    while (nbe.size() < 256) nbe.insert(nbe.begin(), 0);
    std::vector<uint8_t> nle(nbe.rbegin(), nbe.rend());

    // Target-region size cap. The live primes were observed in a CHURNING heap
    // arena whose CONTAINING VirtualQuery region varies in size (0.02MB .. 34MB in
    // different samples), so we must NOT cap small -- a snapshot restricted to tiny
    // regions misses the primes whenever their block has coalesced into a larger
    // one. Default 256MB; overridable via BBL_GATE_REGION_MB.
    static size_t region_cap = [] {
        size_t mb = 4;
        if (const char* e = std::getenv("BBL_GATE_REGION_MB")) { int v = std::atoi(e); if (v > 0) mb = (size_t)v; }
        return mb * 1024 * 1024;
    }();

    struct Reg { uintptr_t base; size_t size; };
    // Target every committed non-image region (MEM_PRIVATE heap AND MEM_MAPPED) up
    // to the cap -- the RSA key object can land in either, and the region size
    // fluctuates as the heap coalesces.
    auto enum_private = [&](std::vector<Reg>& out) {
        out.clear();
        SYSTEM_INFO si{}; GetSystemInfo(&si);
        uintptr_t maxA = (uintptr_t)si.lpMaximumApplicationAddress, a = 0;
        MEMORY_BASIC_INFORMATION m{};
        while (a < maxA && VirtualQuery((void*)a, &m, sizeof m)) {
            uintptr_t rb = (uintptr_t)m.BaseAddress; size_t rs = m.RegionSize;
            if (m.State == MEM_COMMIT && m.Type != MEM_IMAGE && readable(m.Protect) &&
                rs >= 128 && rs <= region_cap)
                out.push_back({rb, rs});
            a = rb + rs; if (rs == 0) break;
        }
    };

    static std::vector<uint8_t> db;
    ULONGLONG t0 = GetTickCount64();
    long long sweeps = 0, hi_e = 0; size_t total_bytes = 0;
    uint8_t be[128];

    // Optional needle diagnostic (BBL_GATE_DIAG=<d_extracted.json>): report where
    // the live p sits. Needle-free capture below does not use it.
    std::vector<Needle> diag_needles;
    if (const char* gtp = std::getenv("BBL_GATE_DIAG")) diag_needles = load_needles(gtp);
    auto report_diag = [&](const uint8_t* base, size_t rs) {
        for (auto& n : diag_needles) {
            if (n.name != "p(BE)" && n.name != "p(LE)") continue;
            if (find_bytes(base, rs, n.bytes.data(), n.bytes.size()))
                std::fprintf(stderr, "[gate-diag] %s present (region %.2fMB)\n",
                             n.name.c_str(), rs/1048576.0);
        }
    };
    (void)enum_private; (void)nle; (void)region_cap;   // (kept for diag/back-compat)

    // ENTRY CAPTURE -- SNAPSHOT (fast) then ANALYSE (slow). The transient primes
    // are resident for only a brief async window. A per-region "read+divide"
    // sweep is too SLOW: the division work on earlier regions lets p churn away
    // before the prime region is reached (verified: a divide-as-you-go read finds
    // p 0x where a pure read finds it). So FIRST snapshot every committed non-image
    // region into one big buffer with pure memcpy (reaching the prime region in a
    // few ms while p is still resident), THEN analyse the frozen snapshot with the
    // plain factor test. Repeated a few times, re-signing between, to get several
    // shots at the residency window. Needle-free.
    static std::vector<uint8_t> snap(320u << 20);   // 320 MB scratch (allocated once)
    std::vector<std::pair<size_t,size_t>> segs; segs.reserve(4096);
    for (int esweep = 0; esweep < 3; ++esweep) {
        // The FIRST snapshot runs IMMEDIATELY on the caller's fresh warm-up key;
        // later ones drive a few signs so the async worker re-materialises p.
        if (esweep > 0) { for (int s = 0; s < 3 && trigger; ++s) trigger(ctx); Sleep(40); }
        // Phase 1: FAST snapshot (pure memcpy, no division). Enumerate regions,
        // SMALL MEM_PRIVATE (<=4MB -- where the primes land) FIRST so they are
        // always captured even if the 320MB buffer fills; skip (not break on) a
        // region that would overflow so later small regions still get in.
        segs.clear(); size_t soff = 0;
        std::vector<std::pair<size_t,size_t>> rprivate, rother;
        SYSTEM_INFO se{}; GetSystemInfo(&se);
        uintptr_t mxe = (uintptr_t)se.lpMaximumApplicationAddress, ae = 0;
        MEMORY_BASIC_INFORMATION me{};
        while (ae < mxe && VirtualQuery((void*)ae, &me, sizeof me)) {
            uintptr_t rbe = (uintptr_t)me.BaseAddress; size_t rse = me.RegionSize;
            if (me.State == MEM_COMMIT && me.Type != MEM_IMAGE && readable(me.Protect) &&
                rse >= 128 && rse <= (size_t)512 * 1024 * 1024) {
                if (me.Type == MEM_PRIVATE && rse <= (size_t)4 * 1024 * 1024)
                    rprivate.push_back({(size_t)rbe, rse});
                else rother.push_back({(size_t)rbe, rse});
            }
            ae = rbe + rse; if (rse == 0) break;
        }
        auto grab = [&](std::vector<std::pair<size_t,size_t>>& v) {
            for (auto& r : v) {
                if (soff + r.second > snap.size()) continue;   // skip, keep going
                if (safe_copy(snap.data() + soff, (const void*)(uintptr_t)r.first, r.second)) {
                    segs.push_back({soff, r.second}); soff += r.second; total_bytes += r.second;
                }
            }
        };
        grab(rprivate); grab(rother);
        // Phase 2: analyse the frozen snapshot (plain BE + LE factor test).
        static const uint8_t nf_sentinel[16] =
            {0x9e,0x37,0x79,0xb9,0x7f,0x4a,0x7c,0x15,0xf3,0x9c,0xc0,0x60,0x5c,0xed,0xc8,0x34};
        for (auto& sg : segs) {
            const uint8_t* base = snap.data() + sg.first; size_t rse = sg.second;
            report_diag(base, rse);
            // Needle-free equivalent of the diagnostic's per-region find_bytes scan
            // (a full memchr walk). In testing, runs WITH this full per-region scan
            // captured the key where runs without it did not -- the sequential walk
            // cycles the working set / paces the loop so the async signer worker
            // re-materialises p between snapshots. Sentinel never matches.
            { const uint8_t* h = find_bytes(base, rse, nf_sentinel, 16); total_bytes += (h ? 1 : 0); }
            for (size_t off = 0; off + 128 <= rse; off += 8) {
                const uint8_t* w = base + off;
                if (!high_entropy128(w)) continue;
                ++hi_e;
                { bn::BigInt v = bn::from_bytes_be(w, 128);  if (try_factor(v)) return true; }
                for (int i = 0; i < 128; ++i) be[i] = w[127 - i];
                { bn::BigInt v = bn::from_bytes_be(be, 128); if (try_factor(v)) return true; }
            }
        }
    }
    std::fprintf(stderr, "[flip-gate] entry capture done (scanned %.1fMB, hi-e=%lld)\n",
                 total_bytes / 1048576.0, hi_e);
    (void)nbe;
    // LEAN HIGH-FREQUENCY HAMMER. p/q are resident (plain BE+LE) in a SMALL
    // MEM_PRIVATE region for only a brief, ASYNC window per sign (the plugin signs
    // on a worker thread). The winning strategy is to READ THAT SMALL REGION AS
    // OFTEN AS POSSIBLE so a read instant overlaps the residency. So: enumerate the
    // small (<=4MB) MEM_PRIVATE regions once, then tight-loop re-reading+testing
    // ONLY them (each read is sub-ms), driving a fresh sign every few reads to keep
    // p/q re-materialising. Both byte orders (plain BE + LE). Needle-free -- only
    // public N + envelopes gate acceptance. This maximises read frequency of the
    // prime-bearing region, which is what determines the per-run catch probability.
    std::vector<std::pair<size_t,size_t>> smallreg;
    int rep = 0;
    do {
        if (trigger && (rep % 2) == 0) { trigger(ctx); trigger(ctx); }
        ++rep;
        // Re-enumerate periodically (the heap layout churns); cheap between.
        if ((rep & 7) == 1 || smallreg.empty()) {
            smallreg.clear();
            SYSTEM_INFO s2{}; GetSystemInfo(&s2);
            uintptr_t mx = (uintptr_t)s2.lpMaximumApplicationAddress, aa = 0;
            MEMORY_BASIC_INFORMATION mm{};
            while (aa < mx && VirtualQuery((void*)aa, &mm, sizeof mm)) {
                uintptr_t rb2 = (uintptr_t)mm.BaseAddress; size_t rs2 = mm.RegionSize;
                if (mm.State == MEM_COMMIT && mm.Type == MEM_PRIVATE && readable(mm.Protect) &&
                    rs2 >= 128 && rs2 <= (size_t)4 * 1024 * 1024)
                    smallreg.push_back({(size_t)rb2, rs2});
                aa = rb2 + rs2; if (rs2 == 0) break;
            }
        }
        for (auto& r : smallreg) {
            uintptr_t rbA = (uintptr_t)r.first; size_t rsA = r.second;
            db.resize(rsA);
            if (!safe_copy(db.data(), (const void*)rbA, rsA)) continue;
            total_bytes += rsA;
            const uint8_t* base = db.data();
            for (size_t off = 0; off + 128 <= rsA; off += 8) {
                const uint8_t* w = base + off;
                if (!high_entropy128(w)) continue;
                ++hi_e;
                // No persistent dedup here -- the same offset cycles noise->p across
                // reads, and we WANT to re-test whenever the bytes changed to p.
                { bn::BigInt v = bn::from_bytes_be(w, 128);  if (try_factor(v)) return true; }
                for (int i = 0; i < 128; ++i) be[i] = w[127 - i];
                { bn::BigInt v = bn::from_bytes_be(be, 128); if (try_factor(v)) return true; }
            }
        }
        ++sweeps;
    } while ((long long)(GetTickCount64() - t0) < wait_ms);

    std::fprintf(stderr, "[flip-gate] sweep: passes=%lld scanned=%.1fMB "
                 "high-entropy=%lld (no factor this budget)\n",
                 sweeps, total_bytes / 1048576.0, hi_e);
    return false;
}

// ===========================================================================
// Representation diagnostic + Montgomery-aware blind sweep.
//
// This path covers the case where the plain LE/BE division sweeps surface only
// the public modulus N during a sign and p/q never appear as a contiguous
// 128-byte LE or BE integer -- e.g. if the bignum stores the CRT
// primes/exponents in a limb-reordered and/or Montgomery form. Here we
// (a) DIAGNOSE by materialising a reference p/q under every candidate
// representation and searching memory for the exact bytes (the reference is used
// ONLY as a search key), and (b) BLINDLY de-transform each resident high-entropy
// window and test divisibility of N.
// ===========================================================================
namespace {

// --- representation transforms of a big-endian 128-byte value ---------------
// Each returns a 128-byte candidate byte pattern that the plugin MIGHT store.

// Reverse whole buffer (BE <-> full LE).
static std::vector<uint8_t> rep_full_reverse(const uint8_t* be, int n) {
    std::vector<uint8_t> o(n);
    for (int i = 0; i < n; ++i) o[i] = be[n - 1 - i];
    return o;
}
// 32-bit limbs in little-endian ORDER, bytes within each limb little-endian too
// (== full reverse for a pure LE integer -- but we also do the byte-BE-in-limb
// variant below). This is the canonical OpenSSL BN_ULONG=32-bit layout.
static std::vector<uint8_t> rep_limb32_le(const uint8_t* be, int n) {
    // Interpret `be` as a big-endian integer, output limbs low->high, each limb
    // stored little-endian (native x86). Equivalent to full byte reverse.
    return rep_full_reverse(be, n);
}
// 32-bit limbs in little-endian ORDER but each 4-byte limb kept BIG-endian
// (limb sequence reversed, bytes inside limb NOT reversed). Some ports do this.
static std::vector<uint8_t> rep_limb32_le_beword(const uint8_t* be, int n) {
    std::vector<uint8_t> o(n);
    int limbs = n / 4;
    for (int L = 0; L < limbs; ++L) {
        const uint8_t* src = be + (limbs - 1 - L) * 4;   // low limb comes from high BE bytes
        uint8_t* dst = o.data() + L * 4;
        dst[0] = src[0]; dst[1] = src[1]; dst[2] = src[2]; dst[3] = src[3];
    }
    return o;
}
// 64-bit limbs in little-endian ORDER, bytes within limb little-endian (BN_ULONG
// = 64-bit, native). Also equals full reverse for a pure LE integer, but limb
// grouping differs when the value is padded -- keep as an explicit candidate.
static std::vector<uint8_t> rep_limb64_le(const uint8_t* be, int n) {
    std::vector<uint8_t> o(n);
    int limbs = n / 8;
    for (int L = 0; L < limbs; ++L) {
        const uint8_t* src = be + (limbs - 1 - L) * 8;   // low 64-bit limb <- high BE bytes
        uint8_t* dst = o.data() + L * 8;
        for (int b = 0; b < 8; ++b) dst[b] = src[7 - b]; // little-endian bytes in limb
    }
    return o;
}
// 64-bit limbs in little-endian ORDER but bytes within each limb BIG-endian.
static std::vector<uint8_t> rep_limb64_le_beword(const uint8_t* be, int n) {
    std::vector<uint8_t> o(n);
    int limbs = n / 8;
    for (int L = 0; L < limbs; ++L) {
        const uint8_t* src = be + (limbs - 1 - L) * 8;
        uint8_t* dst = o.data() + L * 8;
        for (int b = 0; b < 8; ++b) dst[b] = src[b];
    }
    return o;
}

// Montgomery: given value X (BigInt) and modulus M, produce X*R mod M with
// R = 2^rbits, output as a 128-byte big-endian buffer (the "mont form" the
// plugin's bignum would hold). Returns empty if it doesn't fit 128 bytes.
static std::vector<uint8_t> rep_mont(const bn::BigInt& X, const bn::BigInt& M, int rbits) {
    // R = 2^rbits
    bn::BigInt R(1);
    for (int i = 0; i < rbits; ++i) R = bn::add(R, R);
    bn::BigInt xr = bn::mod(bn::mul(X, R), M);
    std::vector<uint8_t> be(128, 0);
    bn::to_bytes_be_fixed(xr, be.data(), 128);
    return be;
}

}  // namespace

int scan_known_representations(const char* json_path, const char* n_hex,
                               const char* label) {
    std::vector<Needle> base = load_needles(json_path);  // gives p(BE),p(LE),q(BE),q(LE),...
    if (base.empty()) return 0;
    const bn::BigInt N = bn::from_hex(n_hex);

    // Build the extended needle set for p and q ONLY (the primes we care about),
    // covering every candidate storage representation.
    std::vector<Needle> ns;
    for (const auto& b : base) {
        // keep only the *(BE) needles for p and q; derive the rest from them.
        if (b.name != "p(BE)" && b.name != "q(BE)") { ns.push_back(b); continue; }
        const std::string who = b.name.substr(0, 1);           // "p" or "q"
        const uint8_t* be = b.bytes.data();
        int n = (int)b.bytes.size();
        if (n != 128) { ns.push_back(b); continue; }
        bn::BigInt X = bn::from_bytes_be(be, 128);

        ns.push_back({who + ":plainBE",         std::vector<uint8_t>(be, be + 128)});
        ns.push_back({who + ":plainLE",         rep_full_reverse(be, 128)});
        ns.push_back({who + ":limb32LE_beword", rep_limb32_le_beword(be, 128)});
        ns.push_back({who + ":limb64LE",        rep_limb64_le(be, 128)});
        ns.push_back({who + ":limb64LE_beword", rep_limb64_le_beword(be, 128)});
        // Montgomery forms mod p itself is 0 -> meaningless. The transiently
        // Montgomery-domain values are the BASE/accumulator, not the prime. But
        // the prime MAY be stored pre-multiplied by a small constant or with R
        // relative to N. Cover mont(p) mod N with several R word-boundaries.
        for (int rbits : {1024, 1088, 2048}) {
            std::vector<uint8_t> m = rep_mont(X, N, rbits);
            ns.push_back({who + ":montN_R2^" + std::to_string(rbits), m});
            ns.push_back({who + ":montN_R2^" + std::to_string(rbits) + "_LE",
                          rep_full_reverse(m.data(), 128)});
        }
    }
    std::fprintf(stderr, "[repr] scanning %zu representation-needles for p,q...\n", ns.size());

    // Sweep every committed readable region for any needle.
    int hits = 0;
    uintptr_t a = 0; MEMORY_BASIC_INFORMATION mbi{};
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uintptr_t maxA = (uintptr_t)si.lpMaximumApplicationAddress;
    std::vector<uint8_t> buf; size_t scanned = 0;
    while (a < maxA && VirtualQuery((void*)a, &mbi, sizeof mbi)) {
        uintptr_t rb = (uintptr_t)mbi.BaseAddress; size_t rs = mbi.RegionSize;
        if (mbi.State == MEM_COMMIT && readable(mbi.Protect) && rs >= 128) {
            buf.resize(rs);
            if (safe_copy(buf.data(), (const void*)rb, rs)) {
                hits += scan_block(buf.data(), rs, ns, label);
                scanned += rs;
            }
        }
        a = rb + rs; if (rs == 0) break;
    }
    std::fprintf(stderr, "[repr] sweep[%s]: scanned %.1f MB, %d representation hit(s)\n",
                 label, scanned / 1048576.0, hits);
    if (hits == 0)
        std::fprintf(stderr, "[repr] NONE of the tested representations of p/q are "
                     "resident -- primes are stored in a form not yet covered "
                     "(or only transiently in registers during the modexp).\n");
    return hits;
}

// ---------------------------------------------------------------------------
// blind_scan_montgomery: for each resident high-entropy 128-byte window, test
// the plain factor divisibility PLUS de-transformed variants (limb re-orderings
// and Montgomery de-conversion w*R^-1 mod N), any of which dividing N pins p/q.
// ---------------------------------------------------------------------------
bool blind_scan_montgomery(const char* out_path,
                           const std::vector<Envelope>& envs, const char* n_hex) {
    const bn::BigInt N = bn::from_hex(n_hex);
    // Precompute R^-1 mod N for the candidate Montgomery radii.
    struct MontR { int rbits; bn::BigInt rinv; };
    std::vector<MontR> radii;
    for (int rbits : {1024, 1088, 2048}) {
        bn::BigInt R(1);
        for (int i = 0; i < rbits; ++i) R = bn::add(R, R);
        bn::BigInt rinv = bn::mod_inverse(bn::mod(R, N), N);
        if (!rinv.is_zero()) radii.push_back({rbits, rinv});
    }
    static const size_t TB = 1u << 22;
    static std::vector<uint64_t> table(TB, 0);
    auto seen = [&](const uint8_t* b, int n) -> bool {
        uint64_t h = 1469598103934665603ULL;
        for (int i = 0; i < n; ++i) { h ^= b[i]; h *= 1099511628211ULL; }
        if (h == 0) h = 1;
        size_t i = h & (TB - 1);
        for (;;) { uint64_t v = table[i]; if (v == 0) { table[i] = h; return false; }
                   if (v == h) return true; i = (i + 1) & (TB - 1); }
    };
    // Given a candidate factor value, validate + write on success.
    auto accept = [&](const bn::BigInt& p, const char* how) -> bool {
        int bl = p.bit_length();
        if (bl < 1000 || bl > 1025) return false;
        if (!bn::mod(N, p).is_zero()) return false;
        bn::BigInt q = bn::div(N, p, nullptr), d;
        if (!compute_d(p, q, 65537, d)) return false;
        int ff = -1; if (validate_envelopes(d, N, envs, &ff) != (int)envs.size()) return false;
        bn::BigInt dp = bn::mod(d, bn::sub(p, bn::BigInt(1)));
        bn::BigInt dq = bn::mod(d, bn::sub(q, bn::BigInt(1)));
        std::fprintf(stderr, "[mont-scan] *** KEY RECOVERED via %s (%zu/%zu envelopes) ***\n",
                     how, envs.size(), envs.size());
        write_key(out_path, N, d, p, q, dp, dq);
        return true;
    };
    // Test one 128-byte big-endian candidate under all de-transforms.
    auto test_be = [&](const uint8_t* be) -> bool {
        // plain
        { bn::BigInt v = bn::from_bytes_be(be, 128); if (accept(v, "plain")) return true; }
        // 32-bit limb LE with BE bytes-in-limb
        { auto r = rep_limb32_le_beword(be, 128); bn::BigInt v = bn::from_bytes_be(r.data(), 128);
          if (accept(v, "limb32LE_beword")) return true; }
        // 64-bit limb LE
        { auto r = rep_limb64_le(be, 128); bn::BigInt v = bn::from_bytes_be(r.data(), 128);
          if (accept(v, "limb64LE")) return true; }
        { auto r = rep_limb64_le_beword(be, 128); bn::BigInt v = bn::from_bytes_be(r.data(), 128);
          if (accept(v, "limb64LE_beword")) return true; }
        // Montgomery de-conversion: treat the window as X*R mod N, recover X.
        bn::BigInt W = bn::from_bytes_be(be, 128);
        for (const auto& mr : radii) {
            bn::BigInt x = bn::mod(bn::mul(W, mr.rinv), N);
            char lbl[32]; std::snprintf(lbl, sizeof lbl, "montN^-1 R2^%d", mr.rbits);
            if (accept(x, lbl)) return true;
        }
        return false;
    };

    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uintptr_t maxA = (uintptr_t)si.lpMaximumApplicationAddress, a = 0;
    MEMORY_BASIC_INFORMATION m{};
    std::vector<uint8_t> rbuf;
    long long windows = 0, hi_e = 0;
    while (a < maxA && VirtualQuery((void*)a, &m, sizeof m)) {
        uintptr_t rb = (uintptr_t)m.BaseAddress; size_t rs = m.RegionSize;
        if (m.State == MEM_COMMIT && m.Type != MEM_IMAGE && readable(m.Protect) &&
            rs >= 128 && rs <= (size_t)256 * 1024 * 1024) {
            rbuf.resize(rs);
            if (safe_copy(rbuf.data(), (const void*)rb, rs)) {
                const uint8_t* base = rbuf.data();
                uint8_t bebuf[128];
                for (size_t off = 0; off + 128 <= rs; off += 8) {
                    ++windows;
                    const uint8_t* w = base + off;
                    if (!high_entropy128(w)) continue;
                    ++hi_e;
                    if (seen(w, 128)) continue;
                    // Interpret the window as BOTH BE and LE big-endian source, so
                    // the de-transforms cover a native-LE-stored window too.
                    if (test_be(w)) return true;
                    for (int i = 0; i < 128; ++i) bebuf[i] = w[127 - i];
                    if (test_be(bebuf)) return true;
                }
            }
        }
        a = rb + rs; if (rs == 0) break;
    }
    std::fprintf(stderr, "[mont-scan] sweep: windows=%lld high-entropy=%lld (no factor this pass)\n",
                 windows, hi_e);
    return false;
}

}  // namespace bbl
