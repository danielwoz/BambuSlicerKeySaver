#include "verdict_flip.hpp"

#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

namespace bbl {
namespace {

// ---------------------------------------------------------------------------
// Plugin memory model.
// ---------------------------------------------------------------------------
struct Region { uintptr_t lo, hi; DWORD type, prot; };

static bool exec_prot(DWORD p) {
    if (p & PAGE_GUARD || p & PAGE_NOACCESS) return false;
    DWORD m = p & 0xff;
    return m == PAGE_EXECUTE || m == PAGE_EXECUTE_READ ||
           m == PAGE_EXECUTE_READWRITE || m == PAGE_EXECUTE_WRITECOPY;
}
static bool read_prot(DWORD p) {
    if (p & PAGE_GUARD || p & PAGE_NOACCESS) return false;
    DWORD m = p & 0xff;
    return m == PAGE_READONLY || m == PAGE_READWRITE || m == PAGE_WRITECOPY ||
           m == PAGE_EXECUTE_READ || m == PAGE_EXECUTE_READWRITE ||
           m == PAGE_EXECUTE_WRITECOPY;
}

static bool safe_copy(void* dst, const void* src, size_t n) {
    __try { memcpy(dst, src, n); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Enumerate committed regions matching a predicate.
static std::vector<Region> enum_regions(bool want_exec) {
    std::vector<Region> out;
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uintptr_t a = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t maxA = (uintptr_t)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION m{};
    while (a < maxA && VirtualQuery((void*)a, &m, sizeof m)) {
        uintptr_t rb = (uintptr_t)m.BaseAddress; size_t rs = m.RegionSize;
        bool ok = (m.State == MEM_COMMIT) &&
                  (want_exec ? exec_prot(m.Protect) : read_prot(m.Protect));
        if (ok) out.push_back({rb, rb + rs, m.Type, m.Protect});
        a = rb + rs; if (rs == 0) break;
    }
    return out;
}

// Keep only regions with NO owning module (anonymous arena) OR owned by
// bambu_networking.dll. Rejects ntdll/kernel32/host-exe OpenSSL noise.
static bool is_plugin_or_anon(uintptr_t va) {
    HMODULE h = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)va, &h) && h) {
        char nm[MAX_PATH] = {0};
        GetModuleBaseNameA(GetCurrentProcess(), h, nm, sizeof nm);
        return _stricmp(nm, "bambu_networking.dll") == 0;
    }
    return true;  // no owning module -> anonymous arena
}

// ---------------------------------------------------------------------------
// Minimal x86-64 instruction length decoder.
// ---------------------------------------------------------------------------
struct Insn {
    int len = 0;
    bool is_jcc = false;
    bool jcc_near = false;
    uint8_t jcc_cc = 0;
    uint64_t jcc_target = 0;
    bool is_lea_riprel = false;
    uint64_t lea_target = 0;
    bool is_jmp = false;
    bool is_call = false;
    bool is_ret = false;
    uint8_t primary = 0;
    bool two_byte = false;
};

static int modrm_len(const uint8_t* p, size_t avail, bool* riprel, int32_t* disp32) {
    if (avail < 1) return -1;
    uint8_t modrm = p[0];
    int mod = modrm >> 6;
    int rm  = modrm & 7;
    int len = 1;
    bool has_sib = (mod != 3 && rm == 4);
    if (riprel) *riprel = false;
    if (mod == 0 && rm == 5) {
        if (avail < 5) return -1;
        if (riprel) *riprel = true;
        if (disp32) std::memcpy(disp32, p + 1, 4);
        return 5;
    }
    if (has_sib) {
        if (avail < 2) return -1;
        uint8_t sib = p[1];
        len += 1;
        int base = sib & 7;
        if (mod == 0 && base == 5) {
            if (avail < (size_t)(len + 4)) return -1;
            len += 4; return len;
        }
    }
    if (mod == 1) { if (avail < (size_t)(len + 1)) return -1; len += 1; }
    else if (mod == 2) { if (avail < (size_t)(len + 4)) return -1; len += 4; }
    return len;
}

static Insn decode(const uint8_t* p, size_t avail, uint64_t va) {
    Insn in;
    size_t i = 0;
    bool op66 = false; bool rex_w = false;
    while (i < avail) {
        uint8_t b = p[i];
        if (b == 0x66) { op66 = true; ++i; continue; }
        if (b == 0x67 || b == 0xf0 || b == 0xf2 || b == 0xf3 ||
            b == 0x2e || b == 0x36 || b == 0x3e || b == 0x26 ||
            b == 0x64 || b == 0x65) { ++i; continue; }
        break;
    }
    if (i < avail && (p[i] & 0xf0) == 0x40) { rex_w = (p[i] & 0x08) != 0; ++i; }
    if (i >= avail) return in;
    uint8_t op = p[i];
    if (op == 0x0f) {
        in.two_byte = true;
        if (i + 1 >= avail) return in;
        uint8_t op2 = p[i + 1];
        in.primary = op2;
        if (op2 >= 0x80 && op2 <= 0x8f) {
            if (i + 6 > avail) return in;
            int32_t rel; std::memcpy(&rel, p + i + 2, 4);
            in.is_jcc = true; in.jcc_near = true; in.jcc_cc = op2 & 0x0f;
            in.len = (int)(i + 6);
            in.jcc_target = va + in.len + rel;
            return in;
        }
        {
            bool rr; int32_t d32;
            int ml = modrm_len(p + i + 2, avail - (i + 2), &rr, &d32);
            if (ml < 0) return in;
            int imm = 0;
            if (op2 == 0xba || op2 == 0x70 || op2 == 0xc2 || op2 == 0xc6) imm = 1;
            in.len = (int)(i + 2 + ml + imm);
            return in;
        }
    }
    in.primary = op;
    if (op >= 0x70 && op <= 0x7f) {
        if (i + 2 > avail) return in;
        int8_t rel = (int8_t)p[i + 1];
        in.is_jcc = true; in.jcc_near = false; in.jcc_cc = op & 0x0f;
        in.len = (int)(i + 2);
        in.jcc_target = va + in.len + rel;
        return in;
    }
    if (op == 0xe9) { if (i + 5 > avail) return in; in.is_jmp = true; in.len = (int)(i + 5); return in; }
    if (op == 0xeb) { if (i + 2 > avail) return in; in.is_jmp = true; in.len = (int)(i + 2); return in; }
    if (op == 0xe8) { if (i + 5 > avail) return in; in.is_call = true; in.len = (int)(i + 5); return in; }
    if (op == 0xc3 || op == 0xc2) { in.is_ret = true; in.len = (int)(i + (op == 0xc2 ? 3 : 1)); return in; }
    if (op == 0x8d) {
        bool rr; int32_t d32;
        int ml = modrm_len(p + i + 1, avail - (i + 1), &rr, &d32);
        if (ml < 0) return in;
        in.len = (int)(i + 1 + ml);
        if (rr) { in.is_lea_riprel = true; in.lea_target = va + in.len + (int64_t)d32; }
        return in;
    }
    {
        auto is_modrm_noimm = [](uint8_t o) {
            if (o == 0x63) return true;
            if (o == 0x84 || o == 0x85 || o == 0x86 || o == 0x87) return true;
            if (o >= 0x88 && o <= 0x8b) return true;
            uint8_t hi = o & 0xf8, lo = o & 0x07;
            if ((o & 0xc0) == 0x00 && lo <= 0x03 &&
                (hi==0x00||hi==0x08||hi==0x10||hi==0x18||hi==0x20||hi==0x28||hi==0x30||hi==0x38))
                return true;
            return false;
        };
        if (is_modrm_noimm(op)) {
            bool rr; int32_t d32;
            int ml = modrm_len(p + i + 1, avail - (i + 1), &rr, &d32);
            if (ml < 0) return in;
            in.len = (int)(i + 1 + ml);
            return in;
        }
    }
    if (op == 0x80 || op == 0x83) {
        bool rr; int32_t d32;
        int ml = modrm_len(p + i + 1, avail - (i + 1), &rr, &d32);
        if (ml < 0) return in;
        in.len = (int)(i + 1 + ml + 1);
        return in;
    }
    if (op == 0x81) {
        bool rr; int32_t d32;
        int ml = modrm_len(p + i + 1, avail - (i + 1), &rr, &d32);
        if (ml < 0) return in;
        int immsz = op66 ? 2 : 4;
        in.len = (int)(i + 1 + ml + immsz);
        return in;
    }
    if (op == 0xf6 || op == 0xf7) {
        if (i + 1 >= avail) return in;
        int reg = (p[i + 1] >> 3) & 7;
        bool rr; int32_t d32;
        int ml = modrm_len(p + i + 1, avail - (i + 1), &rr, &d32);
        if (ml < 0) return in;
        int imm = 0;
        if (reg <= 1) imm = (op == 0xf6) ? 1 : (op66 ? 2 : 4);
        in.len = (int)(i + 1 + ml + imm);
        return in;
    }
    if (op == 0xc6) { bool rr; int32_t d; int ml = modrm_len(p+i+1, avail-(i+1), &rr, &d); if (ml<0) return in; in.len=(int)(i+1+ml+1); return in; }
    if (op == 0xc7) { bool rr; int32_t d; int ml = modrm_len(p+i+1, avail-(i+1), &rr, &d); if (ml<0) return in; in.len=(int)(i+1+ml+(op66?2:4)); return in; }
    if (op >= 0xb8 && op <= 0xbf) { in.len = (int)(i + 1 + (rex_w ? 8 : (op66 ? 2 : 4))); return in; }
    if (op >= 0xb0 && op <= 0xb7) { in.len = (int)(i + 2); return in; }
    {
        uint8_t lo = op & 0x07;
        if ((op & 0xc0) == 0x00 && (lo == 0x04 || lo == 0x05)) {
            if (lo == 0x04) { in.len = (int)(i + 2); return in; }
            else { in.len = (int)(i + 1 + (op66 ? 2 : 4)); return in; }
        }
    }
    if (op == 0xa8) { in.len = (int)(i + 2); return in; }
    if (op == 0xa9) { in.len = (int)(i + 1 + (op66 ? 2 : 4)); return in; }
    if ((op >= 0x50 && op <= 0x5f) || op == 0x90 || op == 0x98 || op == 0x99 ||
        op == 0xc9 || op == 0xf4 || op == 0xcc || op == 0x9c || op == 0x9d) {
        in.len = (int)(i + 1); return in;
    }
    if (op == 0xff) {
        bool rr; int32_t d; int ml = modrm_len(p+i+1, avail-(i+1), &rr, &d);
        if (ml < 0) return in;
        in.len = (int)(i + 1 + ml); return in;
    }
    if (op == 0x6a) { in.len = (int)(i + 2); return in; }
    if (op == 0x68) { in.len = (int)(i + 1 + (op66 ? 2 : 4)); return in; }
    return in;
}

struct LeaHit { uint64_t lea_va, lea_end, target; };

static std::vector<LeaHit> scan_lea_xrefs(const std::vector<Region>& exec,
                                          const std::vector<uint64_t>& targets) {
    std::vector<LeaHit> hits;
    for (const auto& r : exec) {
        if (!is_plugin_or_anon(r.lo)) continue;
        size_t sz = (size_t)(r.hi - r.lo);
        if (sz == 0 || sz > (size_t)512 * 1024 * 1024) continue;
        std::vector<uint8_t> buf(sz);
        if (!safe_copy(buf.data(), (const void*)r.lo, sz)) continue;
        const uint8_t* b = buf.data();
        for (size_t i = 0; i + 7 <= sz; ++i) {
            if ((b[i] & 0xf0) != 0x40) continue;      // REX
            // LEA r64,[rip+disp32] (8d) OR MOV r64,[rip+disp32] (8b) -- both load a
            // pointer TO the string / a pointer-to-string cell.
            if (b[i + 1] != 0x8d && b[i + 1] != 0x8b) continue;
            uint8_t modrm = b[i + 2];
            if ((modrm & 0xc7) != 0x05) continue;     // mod=00, rm=101 -> rip+disp32
            int32_t disp; std::memcpy(&disp, b + i + 3, 4);
            uint64_t end = r.lo + i + 7;
            uint64_t tgt = end + (int64_t)disp;
            for (uint64_t t : targets) {
                if (tgt == t) { hits.push_back({r.lo + i, end, tgt}); break; }
            }
        }
    }
    return hits;
}

// Some strings are referenced INDIRECTLY: a data cell holds an 8-byte pointer to
// the .rdata string, and code does `mov reg,[rip+X]` to load that pointer. Find
// every 8-byte aligned data cell (in readable regions) whose value == a target
// string VA. The returned VAs are pointer-cells; a second LEA/MOV xref pass over
// these cells finds the executing reference.
static std::vector<uint64_t> find_ptr_cells(const std::vector<Region>& read,
                                            const std::vector<uint64_t>& targets) {
    std::vector<uint64_t> cells;
    for (const auto& r : read) {
        if (!is_plugin_or_anon(r.lo)) continue;
        size_t sz = (size_t)(r.hi - r.lo);
        if (sz < 8 || sz > (size_t)512 * 1024 * 1024) continue;
        std::vector<uint8_t> buf(sz);
        if (!safe_copy(buf.data(), (const void*)r.lo, sz)) continue;
        const uint8_t* b = buf.data();
        for (size_t i = 0; i + 8 <= sz; i += 8) {
            uint64_t v; std::memcpy(&v, b + i, 8);
            for (uint64_t t : targets) if (v == t) { cells.push_back(r.lo + i); break; }
        }
    }
    return cells;
}

struct GuardResult {
    uint64_t jcc_va = 0; uint8_t jcc_op = 0; bool jcc_near = false;
    uint64_t jcc_end = 0; uint64_t jcc_target = 0;
    uint64_t cmp_va = 0; uint8_t cmp_op = 0;
};

static bool read_exec_window(uint64_t va, size_t before, size_t after,
                             std::vector<uint8_t>& out, uint64_t& base) {
    base = va - before;
    out.resize(before + after);
    return safe_copy(out.data(), (const void*)base, before + after);
}

static bool align_to(const uint8_t* buf, size_t sz, uint64_t base, uint64_t start,
                     uint64_t target, std::vector<uint64_t>& bounds) {
    bounds.clear();
    uint64_t va = start;
    int guard = 0;
    while (va < target && guard++ < 4096) {
        size_t off = (size_t)(va - base);
        if (off >= sz) return false;
        Insn in = decode(buf + off, sz - off, va);
        if (in.len <= 0) return false;
        bounds.push_back(va);
        va += in.len;
    }
    return va == target;
}

static void hexdump_window(uint64_t lea_va, size_t before, size_t after) {
    std::vector<uint8_t> buf; uint64_t base;
    if (!read_exec_window(lea_va, before, after, buf, base)) return;
    std::fprintf(stderr, "        raw bytes 0x%llx .. 0x%llx (LEA at +0x%zx):\n",
                 (unsigned long long)base, (unsigned long long)(base + buf.size()), before);
    for (size_t i = 0; i < buf.size(); i += 16) {
        std::fprintf(stderr, "        0x%llx: ", (unsigned long long)(base + i));
        for (size_t j = 0; j < 16 && i + j < buf.size(); ++j)
            std::fprintf(stderr, "%02x ", buf[i + j]);
        std::fprintf(stderr, "\n");
    }
}

// Find the guarding conditional branch closest-before the LEA. Strategy:
// pick the alignment whose decoded instruction chain reaches lea_va exactly AND
// contains the MOST instructions (true stream), then take the LAST Jcc before the
// LEA (the immediate guard) plus the compare/test feeding it.
static GuardResult find_guard(uint64_t lea_va, bool dump) {
    GuardResult g;
    const size_t BEFORE = 320, AFTER = 16;
    std::vector<uint8_t> buf; uint64_t base;
    if (!read_exec_window(lea_va, BEFORE, AFTER, buf, base)) return g;
    if (dump) hexdump_window(lea_va, 64, 8);
    std::vector<uint64_t> best;
    for (size_t s = 0; s < BEFORE; ++s) {
        std::vector<uint64_t> bounds;
        if (align_to(buf.data(), buf.size(), base, base + s, lea_va, bounds)) {
            if (bounds.size() > best.size()) best = bounds;
        }
    }
    if (best.empty()) return g;
    // Walk boundaries; remember the LAST Jcc before lea_va (closest guard) and the
    // last compare/test seen before that Jcc.
    uint64_t last_cmp = 0; uint8_t last_cmp_op = 0;
    for (uint64_t va : best) {
        size_t off = (size_t)(va - base);
        Insn in = decode(buf.data() + off, buf.size() - off, va);
        if (in.len <= 0) break;
        bool is_cmp = (in.primary == 0x85 || in.primary == 0x84 ||
                       in.primary == 0x3b || in.primary == 0x39 ||
                       in.primary == 0x38 || in.primary == 0x3a ||
                       in.primary == 0x83 || in.primary == 0x81 ||
                       in.primary == 0xf6 || in.primary == 0xf7) && !in.two_byte;
        if (in.is_jcc) {
            g.jcc_va = va; g.jcc_op = in.primary; g.jcc_near = in.jcc_near;
            g.jcc_end = va + in.len; g.jcc_target = in.jcc_target;
            g.cmp_va = last_cmp; g.cmp_op = last_cmp_op;   // pair the feeding compare
        } else if (is_cmp) {
            last_cmp = va; last_cmp_op = in.primary;
        }
    }
    return g;
}

static std::vector<uint64_t> find_string_va(const std::vector<Region>& read,
                                            const char* needle) {
    std::vector<uint64_t> vas;
    size_t nlen = std::strlen(needle);
    for (const auto& r : read) {
        if (!is_plugin_or_anon(r.lo)) continue;
        size_t sz = (size_t)(r.hi - r.lo);
        if (sz < nlen || sz > (size_t)512 * 1024 * 1024) continue;
        std::vector<uint8_t> buf(sz);
        if (!safe_copy(buf.data(), (const void*)r.lo, sz)) continue;
        const uint8_t* b = buf.data();
        for (size_t i = 0; i + nlen <= sz; ++i) {
            if (b[i] != (uint8_t)needle[0]) continue;
            if (std::memcmp(b + i, needle, nlen) == 0)
                vas.push_back(r.lo + i);
        }
    }
    return vas;
}

}  // namespace

std::vector<VerdictSite> find_verdict_sites() {
    std::vector<VerdictSite> out;
    std::vector<Region> read = enum_regions(false);
    std::vector<Region> exec = enum_regions(true);
    std::fprintf(stderr, "[flip] %zu readable, %zu exec regions (whole process)\n",
                 read.size(), exec.size());

    struct Target { const char* text; };
    const Target targets[] = {
        // The control-message status token (underscore) is the one pushed to the
        // app callback on every sign attempt -- its xref is the executing decision
        // site (distinct from the "enc_msg: unsigned studio" log line).
        {"unsigned_studio"},
        {"enc_msg: unsigned studio"},
        {"enc_msg: not studio sequence_int = {}"},
        {"enc_msg: verify ok"},
        {"enc_msg: verify failed, result={}, err_code={}, err_msg={}"},
    };

    std::vector<uint64_t> all_str;
    std::vector<std::pair<uint64_t,const char*>> str_meta;
    for (const auto& t : targets) {
        std::vector<uint64_t> vas = find_string_va(read, t.text);
        std::fprintf(stderr, "[flip] string \"%s\": %zu VA(s)\n", t.text, vas.size());
        for (uint64_t v : vas) {
            std::fprintf(stderr, "[flip]     @0x%llx\n", (unsigned long long)v);
            all_str.push_back(v);
            str_meta.push_back({v, t.text});
        }
    }
    if (all_str.empty()) {
        std::fprintf(stderr, "[flip] no verdict strings resident -- sign/verify path "
                     "not decoded yet (drive the trigger first)\n");
        return out;
    }

    std::vector<LeaHit> leas = scan_lea_xrefs(exec, all_str);
    std::fprintf(stderr, "[flip] %zu LEA xref(s) to verdict strings\n", leas.size());

    int dumped = 0;
    for (const auto& l : leas) {
        VerdictSite s;
        s.str_va = l.target; s.lea_va = l.lea_va; s.lea_end = l.lea_end;
        for (auto& m : str_meta) if (m.first == l.target) { s.str_text = m.second; break; }
        bool is_unsigned = (s.str_text.find("unsigned studio") != std::string::npos) ||
                           (s.str_text.find("not studio") != std::string::npos);
        bool dump = is_unsigned && (dumped++ < 4);
        GuardResult g = find_guard(l.lea_va, dump);
        s.jcc_va = g.jcc_va; s.jcc_opcode = g.jcc_op; s.jcc_near = g.jcc_near;
        s.jcc_end = g.jcc_end; s.jcc_target = g.jcc_target;
        s.cmp_va = g.cmp_va; s.cmp_kind = g.cmp_op;
        std::fprintf(stderr,
            "[flip] SITE \"%s\"\n"
            "        str=0x%llx  lea=0x%llx..0x%llx\n"
            "        guarding Jcc: va=0x%llx op=%s%02x near=%d  end(fallthru)=0x%llx target=0x%llx\n"
            "        cmp/test: va=0x%llx op=%02x\n",
            s.str_text.c_str(),
            (unsigned long long)s.str_va, (unsigned long long)s.lea_va, (unsigned long long)s.lea_end,
            (unsigned long long)s.jcc_va, s.jcc_near ? "0f " : "", s.jcc_opcode, (int)s.jcc_near,
            (unsigned long long)s.jcc_end, (unsigned long long)s.jcc_target,
            (unsigned long long)s.cmp_va, s.cmp_kind);
        out.push_back(s);
    }

    // INDIRECT resolution for the control-msg token "unsigned_studio": it has no
    // direct code xref (referenced via a pointer cell). Find data cells holding
    // its .rdata VA, then code that loads those cells.
    {
        std::vector<uint64_t> us_vas;
        for (auto& m : str_meta)
            if (std::string(m.second) == "unsigned_studio" && m.first >= 0x10000000000ull)
                us_vas.push_back(m.first);   // .rdata copy (skip stack/heap transient)
        if (!us_vas.empty()) {
            std::vector<uint64_t> cells = find_ptr_cells(read, us_vas);
            std::fprintf(stderr, "[flip] unsigned_studio(token): %zu pointer-cell(s)\n", cells.size());
            for (uint64_t c : cells)
                std::fprintf(stderr, "[flip]     ptr-cell @0x%llx\n", (unsigned long long)c);
            if (!cells.empty()) {
                std::vector<LeaHit> ind = scan_lea_xrefs(exec, cells);
                std::fprintf(stderr, "[flip] %zu code xref(s) to unsigned_studio pointer-cells\n",
                             ind.size());
                for (const auto& l : ind) {
                    VerdictSite s;
                    s.str_va = l.target; s.lea_va = l.lea_va; s.lea_end = l.lea_end;
                    s.str_text = "unsigned_studio";   // token (indirect)
                    GuardResult g = find_guard(l.lea_va, true);
                    s.jcc_va = g.jcc_va; s.jcc_opcode = g.jcc_op; s.jcc_near = g.jcc_near;
                    s.jcc_end = g.jcc_end; s.jcc_target = g.jcc_target;
                    s.cmp_va = g.cmp_va; s.cmp_kind = g.cmp_op;
                    std::fprintf(stderr,
                        "[flip] TOKEN-SITE \"unsigned_studio\" (indirect)\n"
                        "        ptrcell=0x%llx  ref=0x%llx..0x%llx\n"
                        "        guarding Jcc: va=0x%llx op=%s%02x  fallthru=0x%llx target=0x%llx\n"
                        "        cmp/test: va=0x%llx op=%02x\n",
                        (unsigned long long)s.str_va, (unsigned long long)s.lea_va,
                        (unsigned long long)s.lea_end, (unsigned long long)s.jcc_va,
                        s.jcc_near ? "0f " : "", s.jcc_opcode,
                        (unsigned long long)s.jcc_end, (unsigned long long)s.jcc_target,
                        (unsigned long long)s.cmp_va, s.cmp_kind);
                    out.push_back(s);
                }
            }
        }
    }
    return out;
}

// ===========================================================================
// DR flip machinery -- up to 4 simultaneous execute breakpoints (Dr0-Dr3), each
// with its own "verified" redirect target. On a hit at slot k's VA, steer RIP to
// that slot's verified VA (control-flow redirect; no code byte written).
// ===========================================================================
namespace {

struct FlipSlot { std::atomic<uint64_t> va{0}; std::atomic<uint64_t> verified{0}; };
FlipSlot               g_slots[4];
std::atomic<long long> g_flip_hits{0};
PVOID                  g_flip_veh = nullptr;
std::atomic<bool>      g_rearm_run{false};
std::thread            g_rearm_thr;
std::atomic<int>       g_rearm_pause{0};   // >0 -> re-armer must not suspend threads
std::atomic<bool>      g_rearm_idle{true}; // re-armer currently not inside arm_all_slots

// ---- read-at-breakpoint capture gate -------------------------------------
// When enabled, the VEH -- fired ON the signing thread at the verdict jnz, with
// p/q live+resident -- HOLDS that thread (bounded busy-wait, still inside the
// VEH so RIP/regs are untouched) and announces the window to an external
// capturer, which reads the heap while p/q cannot be freed. All lock/alloc-free
// so it is safe inside a VEH on a thread that may hold the CRT/heap lock.
std::atomic<bool>      g_gate_on{false};       // capture gate armed
std::atomic<int>       g_gate_hold_ms{8};      // max ms the VEH holds the sign thread
std::atomic<int>       g_gate_state{0};        // 0=idle 1=window-open(held) 2=capturer-done
std::atomic<long long> g_gate_windows{0};      // windows opened (diagnostic)

static uint64_t now_ms() {
    LARGE_INTEGER f, c;
    if (QueryPerformanceFrequency(&f) && QueryPerformanceCounter(&c) && f.QuadPart)
        return (uint64_t)(c.QuadPart * 1000 / f.QuadPart);
    return (uint64_t)GetTickCount64();
}

// Program Dr0-Dr3 from the current slot table into a CONTEXT.
static void ctx_program(CONTEXT* c) {
    uint64_t dr7 = c->Dr7;
    // clear all local-enable + rw/len fields for Dr0-3
    dr7 &= ~0xFFULL;                 // L0..L3,G0..G3 (bits 0-7)
    dr7 &= ~0xFFFF0000ULL;           // rw/len for Dr0-3 (bits 16-31)
    uint64_t vas[4] = { g_slots[0].va.load(), g_slots[1].va.load(),
                        g_slots[2].va.load(), g_slots[3].va.load() };
    c->Dr0 = vas[0]; c->Dr1 = vas[1]; c->Dr2 = vas[2]; c->Dr3 = vas[3];
    for (int k = 0; k < 4; ++k)
        if (vas[k]) dr7 |= (1ULL << (k * 2));   // Lk=1, rw=00(exec), len=00(1B)
    c->Dr7 = dr7;
    c->Dr6 = 0;
}

static void arm_thread(DWORD tid) {
    if (tid == GetCurrentThreadId()) return;
    HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                          FALSE, tid);
    if (!h) return;
    SuspendThread(h);
    CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(h, &c)) {
        ctx_program(&c);
        c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        SetThreadContext(h, &c);
    }
    ResumeThread(h);
    CloseHandle(h);
}

static void arm_all_slots() {
    DWORD me = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te{}; te.dwSize = sizeof te;
    if (Thread32First(snap, &te)) do {
        if (te.th32OwnerProcessID == me) arm_thread(te.th32ThreadID);
    } while (Thread32Next(snap, &te));
    CloseHandle(snap);
}

// legacy single-BP compat used by trace mode: it programs Dr0 via slot 0.
static void arm_all(uint64_t va) {
    g_slots[0].va.store(va);
    g_slots[0].verified.store(0);
    arm_all_slots();
}

// Persistent re-armer: the plugin's message/sign worker threads are created after
// the initial arm AND the DR registers are periodically cleared. Continuously
// re-program every thread so the BP stays live on whichever thread runs the
// decision. Cheap (Suspend/Set/Resume) at ~50ms cadence.
static void start_rearm() {
    if (g_rearm_run.exchange(true)) return;
    int ms = 30;
    if (const char* e = std::getenv("BBL_REARM_MS")) { int v = std::atoi(e); if (v > 0) ms = v; }
    g_rearm_thr = std::thread([ms]{
        while (g_rearm_run.load(std::memory_order_relaxed)) {
            if (g_rearm_pause.load(std::memory_order_acquire) == 0) {
                g_rearm_idle.store(false, std::memory_order_release);
                arm_all_slots();
                g_rearm_idle.store(true, std::memory_order_release);
            }
            Sleep(ms);
        }
    });
}
static void stop_rearm() {
    if (!g_rearm_run.exchange(false)) return;
    if (g_rearm_thr.joinable()) g_rearm_thr.join();
}

// The armed BP sits on a `jnz <verified>` (75/0f85) that follows `test al,al`.
// Least-invasive approach: clear ZF so the jnz naturally takes the verified edge,
// then let the trapped instruction execute (RF set). We do NOT move RIP or touch
// registers -> minimal disturbance of the plugin's hot signing path (moving RIP
// mid-flow was less stable). Set BBL_FLIP_RIP=1 to fall back to RIP redirect.
static bool g_flip_use_rip = false;
static LONG CALLBACK flip_veh(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT* c = ep->ContextRecord;
    for (int k = 0; k < 4; ++k) {
        uint64_t va = g_slots[k].va.load(std::memory_order_relaxed);
        if (va && c->Rip == va) {
            uint64_t v = g_slots[k].verified.load(std::memory_order_relaxed);
            g_flip_hits.fetch_add(1, std::memory_order_relaxed);
            c->Dr6 = 0;
            if (g_flip_use_rip && v) {
                c->Rip = v;                 // hard redirect (fallback)
            } else {
                c->EFlags &= ~0x40ULL;      // clear ZF -> `jnz verified` taken
                c->EFlags |= 0x10000;       // RF: re-execute the jnz once, no re-trap
            }
            // READ-AT-BREAKPOINT: hold this (signing) thread here while an external
            // capturer sweeps the heap; p/q are live+resident RIGHT NOW. Only claim
            // a window if the gate is armed and none is currently open. Bounded busy
            // wait -> a slow/blocked capturer can never wedge the plugin.
            if (g_gate_on.load(std::memory_order_acquire)) {
                int expected = 0;
                if (g_gate_state.compare_exchange_strong(expected, 1,
                        std::memory_order_acq_rel)) {
                    g_gate_windows.fetch_add(1, std::memory_order_relaxed);
                    uint64_t deadline = now_ms() + (uint64_t)g_gate_hold_ms.load();
                    // Wait for the capturer to finish (state->2) or the hold to lapse.
                    while (g_gate_state.load(std::memory_order_acquire) == 1 &&
                           now_ms() < deadline) {
                        YieldProcessor();
                    }
                    g_gate_state.store(0, std::memory_order_release);
                }
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    // Not one of our BPs (or a trace-only BP): step over it.
    c->Dr6 = 0; c->EFlags |= 0x10000;
    return EXCEPTION_CONTINUE_EXECUTION;
}

}  // namespace

bool arm_verdict_flip(const std::vector<VerdictSite>& sites_in) {
    // Legacy string-xref path is superseded by the stack-frame path. Keep the
    // symbol for compatibility: if any site has a guarding Jcc, arm slot 0.
    std::vector<VerdictSite> sites = sites_in;
    if (sites.empty()) sites = find_verdict_sites();
    for (const auto& s : sites) {
        bool is_unsigned = (s.str_text.find("unsigned studio") != std::string::npos);
        if (is_unsigned && s.jcc_va) {
            return arm_flip_at(s.jcc_va, s.jcc_target);
        }
    }
    std::fprintf(stderr, "[flip] (legacy) no string-xref guarding Jcc; use frame flip\n");
    return false;
}

void disarm_verdict_flip() {
    stop_rearm();
    for (int k = 0; k < 4; ++k) { g_slots[k].va.store(0); g_slots[k].verified.store(0); }
    arm_all_slots();
    if (g_flip_veh) { RemoveVectoredExceptionHandler(g_flip_veh); g_flip_veh = nullptr; }
}

long long verdict_flip_hits() { return g_flip_hits.load(); }

void flip_pause_rearm() {
    g_rearm_pause.fetch_add(1, std::memory_order_acq_rel);
    // Wait until the re-armer is not mid-suspend, so we don't overlap.
    for (int i = 0; i < 1000 && !g_rearm_idle.load(std::memory_order_acquire); ++i)
        Sleep(1);
}
void flip_resume_rearm() {
    int prev = g_rearm_pause.fetch_sub(1, std::memory_order_acq_rel);
    if (prev <= 0) g_rearm_pause.store(0);   // guard against underflow
}

void flip_rearm_now() { arm_all_slots(); }

void flip_stop_background_rearm() { stop_rearm(); }

// ---- read-at-breakpoint capture gate API ---------------------------------
void flip_enable_capture_gate(int hold_ms) {
    if (hold_ms < 1) hold_ms = 1;
    if (hold_ms > 200) hold_ms = 200;      // never wedge the plugin for long
    g_gate_hold_ms.store(hold_ms);
    g_gate_state.store(0);
    g_gate_on.store(true, std::memory_order_release);
}
void flip_disable_capture_gate() {
    g_gate_on.store(false, std::memory_order_release);
    g_gate_state.store(0);
}
bool flip_wait_capture_window(int timeout_ms) {
    uint64_t deadline = now_ms() + (uint64_t)(timeout_ms < 0 ? 0 : timeout_ms);
    for (;;) {
        if (g_gate_state.load(std::memory_order_acquire) == 1) return true;
        if (now_ms() >= deadline) return false;
        Sleep(0);
    }
}
void flip_release_capture_window() {
    // Move 1 (window-open/held) -> 2 (capturer-done); the VEH then resets to 0.
    int expected = 1;
    g_gate_state.compare_exchange_strong(expected, 2, std::memory_order_acq_rel);
}
long long flip_capture_windows() { return g_gate_windows.load(); }

// ===========================================================================
// Runtime trace of the unsigned_studio decision.
// ===========================================================================
namespace {

std::atomic<uint64_t> g_trace_bp{0};
std::atomic<bool>     g_trace_done{false};
PVOID                 g_trace_veh = nullptr;

// range of the plugin image + arena, for classifying code pointers on the stack.
static uint64_t g_plug_lo = 0, g_plug_hi = 0, g_arena_lo = 0, g_arena_hi = 0;
static bool code_ptr(uint64_t va) {
    return (va >= g_plug_lo && va < g_plug_hi) || (va >= g_arena_lo && va < g_arena_hi);
}

static LONG CALLBACK trace_veh(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT* c = ep->ContextRecord;
    uint64_t bp = g_trace_bp.load(std::memory_order_relaxed);
    if (bp == 0) return EXCEPTION_CONTINUE_SEARCH;
    bool ours = (c->Rip == bp) || (c->Dr6 & 0x1);
    if (!ours) return EXCEPTION_CONTINUE_SEARCH;
    if (!g_trace_done.exchange(true)) {
        std::fprintf(stderr, "\n[trace] *** unsigned_studio message-LEA reached @0x%llx ***\n",
                     (unsigned long long)c->Rip);
        std::fprintf(stderr, "[trace] regs: rax=%llx rbx=%llx rcx=%llx rdx=%llx rsi=%llx rdi=%llx\n"
                             "[trace]       r8=%llx r9=%llx r10=%llx r11=%llx r12=%llx r13=%llx r14=%llx r15=%llx\n"
                             "[trace]       rbp=%llx rsp=%llx eflags=%llx\n",
            (unsigned long long)c->Rax,(unsigned long long)c->Rbx,(unsigned long long)c->Rcx,
            (unsigned long long)c->Rdx,(unsigned long long)c->Rsi,(unsigned long long)c->Rdi,
            (unsigned long long)c->R8,(unsigned long long)c->R9,(unsigned long long)c->R10,
            (unsigned long long)c->R11,(unsigned long long)c->R12,(unsigned long long)c->R13,
            (unsigned long long)c->R14,(unsigned long long)c->R15,
            (unsigned long long)c->Rbp,(unsigned long long)c->Rsp,(unsigned long long)c->EFlags);
        // stack return chain: scan up to 512 qwords from rsp for plugin/arena code ptrs.
        std::fprintf(stderr, "[trace] stack code-ptr chain (rsp+off -> retaddr):\n");
        uint64_t* sp = (uint64_t*)c->Rsp;
        int found = 0;
        for (int i = 0; i < 512 && found < 20; ++i) {
            uint64_t v = 0;
            if (!safe_copy(&v, sp + i, 8)) break;
            if (code_ptr(v)) {
                std::fprintf(stderr, "[trace]   rsp+0x%x = 0x%llx\n", i * 8, (unsigned long long)v);
                ++found;
            }
        }
        // Backward-aligned disasm from RIP: find the alignment whose chain reaches
        // RIP and print the last ~24 instructions with Jcc/cmp annotations.
        const size_t BEFORE = 400;
        std::vector<uint8_t> buf; uint64_t base;
        if (read_exec_window(c->Rip, BEFORE, 0, buf, base)) {
            std::vector<uint64_t> best;
            for (size_t s = 0; s < BEFORE; ++s) {
                std::vector<uint64_t> b2;
                if (align_to(buf.data(), buf.size(), base, base + s, c->Rip, b2))
                    if (b2.size() > best.size()) best = b2;
            }
            std::fprintf(stderr, "[trace] backward disasm (%zu insns) leading to the LEA:\n",
                         best.size());
            size_t start = best.size() > 24 ? best.size() - 24 : 0;
            for (size_t k = start; k < best.size(); ++k) {
                uint64_t va = best[k];
                size_t off = (size_t)(va - base);
                Insn in = decode(buf.data() + off, buf.size() - off, va);
                char note[80] = "";
                if (in.is_jcc) std::snprintf(note, sizeof note,
                    "  <== Jcc cc=0x%x -> 0x%llx (fallthru 0x%llx)", in.jcc_cc,
                    (unsigned long long)in.jcc_target, (unsigned long long)(va + in.len));
                else if (in.primary == 0x85 || in.primary == 0x84 || in.primary == 0x3b ||
                         in.primary == 0x39 || in.primary == 0x38 || in.primary == 0x83)
                    std::snprintf(note, sizeof note, "  <== cmp/test op=%02x", in.primary);
                std::fprintf(stderr, "[trace]   0x%llx: ", (unsigned long long)va);
                for (int bi = 0; bi < in.len && bi < 12; ++bi)
                    std::fprintf(stderr, "%02x ", buf[off + bi]);
                std::fprintf(stderr, "%s\n", note);
            }
        }
        std::fprintf(stderr, "[trace] *** end trace ***\n\n");
    }
    c->Dr6 = 0; c->EFlags |= 0x10000;
    return EXCEPTION_CONTINUE_EXECUTION;
}

}  // namespace

uint64_t trace_unsigned_studio(const std::vector<VerdictSite>& sites) {
    // Prefer the control-message token "unsigned_studio" (underscore) -- that is the
    // status string pushed on every sign attempt. Fall back to the
    // "enc_msg: unsigned studio" log line only if the token has no xref.
    uint64_t lea = 0;
    for (const auto& s : sites)
        if (s.str_text == std::string("unsigned_studio")) { lea = s.lea_va; break; }
    if (!lea)
        for (const auto& s : sites)
            if (s.str_text.find("unsigned studio") != std::string::npos) { lea = s.lea_va; break; }
    if (!lea) { std::fprintf(stderr, "[trace] no unsigned_studio LEA to arm\n"); return 0; }
    // Populate plugin/arena ranges for stack classification.
    HMODULE h = GetModuleHandleA("bambu_networking.dll");
    if (h) {
        MODULEINFO mi{};
        if (GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof mi)) {
            g_plug_lo = (uint64_t)mi.lpBaseOfDll; g_plug_hi = g_plug_lo + mi.SizeOfImage;
        }
    }
    // arena = the largest MEM_PRIVATE exec run after the image (approx).
    { std::vector<Region> ex = enum_regions(true);
      uint64_t blo=0,bhi=0;
      for (auto& r : ex) if (!is_plugin_or_anon(r.lo)) continue; else
          if (r.hi - r.lo > bhi - blo) { blo = r.lo; bhi = r.hi; }
      // widen arena bounds to whole anon exec span
      for (auto& r : ex) if (is_plugin_or_anon(r.lo) && (r.lo < g_plug_lo || r.lo >= g_plug_hi)) {
          if (g_arena_lo == 0 || r.lo < g_arena_lo) g_arena_lo = r.lo;
          if (r.hi > g_arena_hi) g_arena_hi = r.hi;
      }
    }
    std::fprintf(stderr, "[trace] plugin 0x%llx-0x%llx arena 0x%llx-0x%llx; arming BP @unsigned LEA 0x%llx\n",
                 (unsigned long long)g_plug_lo, (unsigned long long)g_plug_hi,
                 (unsigned long long)g_arena_lo, (unsigned long long)g_arena_hi,
                 (unsigned long long)lea);
    g_trace_done.store(false);
    g_trace_bp.store(lea);
    if (!g_trace_veh) g_trace_veh = AddVectoredExceptionHandler(1, trace_veh);
    arm_all(lea);
    return lea;
}

bool trace_captured() { return g_trace_done.load(); }

uint64_t plugin_base() {
    HMODULE h = GetModuleHandleA("bambu_networking.dll");
    return (uint64_t)h;
}

void disasm_va(uint64_t va, int back, int fwd) {
    std::vector<uint8_t> buf; uint64_t base;
    if (!read_exec_window(va, (size_t)back, (size_t)fwd, buf, base)) {
        std::fprintf(stderr, "[disasm] cannot read window around 0x%llx\n",
                     (unsigned long long)va);
        return;
    }
    // Find the alignment whose chain reaches `va` exactly (longest).
    std::vector<uint64_t> best;
    for (int s = 0; s < back; ++s) {
        std::vector<uint64_t> b2;
        if (align_to(buf.data(), buf.size(), base, base + s, va, b2))
            if (b2.size() > best.size()) best = b2;
    }
    // Continue decoding forward from va through the fwd window.
    std::vector<uint64_t> chain = best;
    { uint64_t p = va;
      while (p < base + buf.size()) {
          size_t off = (size_t)(p - base);
          Insn in = decode(buf.data() + off, buf.size() - off, p);
          if (in.len <= 0) break;
          chain.push_back(p); p += in.len;
      } }
    std::fprintf(stderr, "[disasm] window around 0x%llx (%zu insns):\n",
                 (unsigned long long)va, chain.size());
    for (uint64_t iva : chain) {
        size_t off = (size_t)(iva - base);
        if (off >= buf.size()) break;
        Insn in = decode(buf.data() + off, buf.size() - off, iva);
        if (in.len <= 0) break;
        char note[96] = "";
        if (in.is_jcc)
            std::snprintf(note, sizeof note, "  Jcc cc=0x%x -> 0x%llx (fallthru 0x%llx)",
                          in.jcc_cc, (unsigned long long)in.jcc_target,
                          (unsigned long long)(iva + in.len));
        else if (in.is_call) std::snprintf(note, sizeof note, "  CALL");
        else if (in.is_jmp)  std::snprintf(note, sizeof note, "  JMP");
        else if (in.is_lea_riprel)
            std::snprintf(note, sizeof note, "  LEA rip-> 0x%llx", (unsigned long long)in.lea_target);
        else if (in.primary == 0x85 || in.primary == 0x84 || in.primary == 0x3b ||
                 in.primary == 0x39 || in.primary == 0x38 || in.primary == 0x83)
            std::snprintf(note, sizeof note, "  cmp/test op=%02x", in.primary);
        std::fprintf(stderr, "  %s0x%llx: ", (iva == va ? "=>" : "  "),
                     (unsigned long long)iva);
        for (int bi = 0; bi < in.len && bi < 14; ++bi)
            std::fprintf(stderr, "%02x ", buf[off + bi]);
        std::fprintf(stderr, "%s\n", note);
    }
}

bool arm_flip_at(uint64_t branch_va, uint64_t verified_va) {
    // Find a free slot (or reuse one already at branch_va).
    int slot = -1;
    for (int k = 0; k < 4; ++k) {
        uint64_t v = g_slots[k].va.load();
        if (v == 0 || v == branch_va) { slot = k; break; }
    }
    if (slot < 0) { std::fprintf(stderr, "[flip] no free DR slot for 0x%llx\n",
                                 (unsigned long long)branch_va); return false; }
    std::fprintf(stderr, "[flip] arm_flip_at slot%d Jcc=0x%llx verified=0x%llx\n",
                 slot, (unsigned long long)branch_va, (unsigned long long)verified_va);
    g_slots[slot].va.store(branch_va);
    g_slots[slot].verified.store(verified_va);
    g_flip_use_rip = (std::getenv("BBL_FLIP_RIP") != nullptr);
    if (!g_flip_veh) g_flip_veh = AddVectoredExceptionHandler(1, flip_veh);
    if (!g_flip_veh) { std::fprintf(stderr, "[flip] AddVectoredExceptionHandler failed\n"); return false; }
    arm_all_slots();
    start_rearm();   // keep the BP live across new / DR-cleared plugin threads
    return true;
}

// Decode the verification pattern at a frame return-address:
//   <call>  (the frame VA points HERE, right after the verification call)
//   test al,al        ; 84 c0
//   jnz/jz  <target>  ; 75 xx (near/short) or 74 xx
// The 'verified' edge is the one that skips the unsigned_studio handling. For
// `jnz` (75) after `test al,al`, verified = AL!=0 = branch taken => jnz target.
// For `jz` (74) verified would be fallthrough; we detect the opcode and choose.
bool find_al_test_jnz(uint64_t frame_va, uint64_t* jnz_va, uint64_t* jnz_target) {
    uint8_t buf[16];
    if (!safe_copy(buf, (const void*)frame_va, sizeof buf)) return false;
    // Expect test al,al (84 c0) at frame_va (possibly preceded by nothing; the
    // return address points exactly at it in the observed layouts).
    size_t i = 0;
    // tolerate a leading 'nop' (0x90) some builds insert after the call.
    if (buf[i] == 0x90) ++i;
    if (!(buf[i] == 0x84 && buf[i + 1] == 0xc0) &&           // test al,al
        !(buf[i] == 0x85 && buf[i + 1] == 0xc0)) {           // test eax,eax
        return false;
    }
    size_t j = i + 2;
    uint64_t jva = frame_va + j;
    uint8_t op = buf[j];
    if (op == 0x75 || op == 0x74) {          // short jnz/jz rel8
        int8_t rel = (int8_t)buf[j + 1];
        uint64_t end = jva + 2;
        uint64_t tgt = end + rel;
        // verified edge: jnz(75) taken=AL!=0=verified -> target ; jz(74) verified=fallthru(end)
        *jnz_va = jva;
        *jnz_target = (op == 0x75) ? tgt : end;
        return true;
    }
    if (op == 0x0f && (buf[j + 1] == 0x85 || buf[j + 1] == 0x84)) {  // near jnz/jz rel32
        int32_t rel; std::memcpy(&rel, buf + j + 2, 4);
        uint64_t end = jva + 6;
        uint64_t tgt = end + (int64_t)rel;
        *jnz_va = jva;
        *jnz_target = (buf[j + 1] == 0x85) ? tgt : end;
        return true;
    }
    return false;
}

int arm_flip_from_frames(const std::vector<unsigned long long>& frames) {
    int armed = 0;
    for (size_t fi = 0; fi < frames.size() && armed < 4; ++fi) {
        uint64_t jnz_va = 0, jnz_tgt = 0;
        if (find_al_test_jnz((uint64_t)frames[fi], &jnz_va, &jnz_tgt)) {
            std::fprintf(stderr, "[flip] frame#%zu 0x%llx -> test-al;jnz @0x%llx verified->0x%llx\n",
                         fi, frames[fi], (unsigned long long)jnz_va, (unsigned long long)jnz_tgt);
            if (arm_flip_at(jnz_va, jnz_tgt)) ++armed;
        } else {
            std::fprintf(stderr, "[flip] frame#%zu 0x%llx: no test-al;jnz pattern\n",
                         fi, frames[fi]);
        }
    }
    std::fprintf(stderr, "[flip] armed %d verdict flip breakpoint(s)\n", armed);
    return armed;
}

}  // namespace bbl
