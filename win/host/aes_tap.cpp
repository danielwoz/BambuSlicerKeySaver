// aes_tap — set a hardware execute breakpoint on OpenSSL's AES-NI key expansion
// to capture the raw AES key(s), so the DRBG-generated get_app_cert session key K
// can be recovered. See aes_tap.hpp. A DR execute-BP modifies no code, so it works
// on read-only/execute-only code pages; capture is done into a lock-free ring
// drained off-thread so the VEH never touches a CRT/heap lock.

#include "host/aes_tap.hpp"
#include "host/instr_cb.hpp"

#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

namespace bbl {
namespace {

FILE*                  g_log = nullptr;
std::atomic<long long> g_hits{0};
uintptr_t              g_base = 0, g_end = 0;

// ---- DR execute-breakpoint machinery (pattern from verdict_flip) -----------
std::atomic<uint64_t> g_slot[4];
std::atomic<bool>     g_run{false};
std::thread           g_rearm_thr, g_drain_thr;
PVOID                 g_veh = nullptr;
// If a hit's rip == g_ct_bp (or g_ct_all), also grab the callee's stack-arg
// ciphertext (arg5 `in` @ [rsp+0x28], arg6 `inl` @ [rsp+0x30]) — for cipher
// data fns this is the input blob; captured at the crypto layer (no scan race).
std::atomic<uint64_t> g_ct_bp{0};
std::atomic<bool>     g_ct_all{false};   // BBL_AES_CT_ALL=1 -> try ct-grab on every hit

// ---- data-watch: capture R at the response-blob decrypt -------------------
// When BBL_AES_DWATCH_SCAN=1, the rearm thread scans for the base64-decoded 704-byte
// get_app_cert key blob (nonce12|tag16|len4=672|ct672) and arms Dr3 as a read/write
// data breakpoint on its ciphertext. When the (virtualized) AES-256-GCM decrypt reads
// it, we snapshot the faulting thread's stack + every GP-register target -- R's live
// AES key schedule is in there -- so the plaintext key is never needed offline.
std::atomic<uint64_t> g_dwatch{0};       // ct address to watch (0 = none)
std::atomic<bool>     g_dwatch_scan{false};
std::atomic<bool>     g_b64watch{false};   // watch the base64 key STRING (localizes the decode reader) instead of the blob
std::atomic<int>      g_dwatch_hits{0};
// Decoder-hook arming: an execute BP at the base64-decoder's exit (BBL_AES_DECODE_BP,
// plugin-rva) whose output buffer (BBL_AES_DECODE_OUT = a GP-reg name, its value = the
// buffer pointer) is the fresh 704-byte blob. When it holds a valid blob we arm the
// Dr3 data watch on ct IN THE SAME THREAD's context, so the immediately-following
// decrypt trips it (no transient-buffer race).
std::atomic<uint64_t> g_decode_bp{0};    // VA of the decoder-exit exec BP (0 = off)
uint64_t              g_decode_rva = 0;  // plugin-relative rva (resolved to VA once loaded)
int                   g_decode_outreg = 0; // index into the gpr[] order below
std::atomic<long long> g_decode_hits{0}, g_decode_704{0}, g_decode_armed{0};
std::atomic<uint64_t>  g_decode_arm_addr{0};
int                    g_decode_inlen = 0;   // if >0, filter the decode BP by R9d (input len) instead of output content
int                    g_decode_off = 32;    // byte offset from the output ptr to watch (32 = ct start; 0 = the key itself)
bool                   g_decode_any = false;  // arm on the first valid hit regardless of content (mechanism test)
std::atomic<bool>     g_decode_done{false};
// gpr order used for DCap + decode-out selection: rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8..r15
uint64_t ctx_gpr(const CONTEXT* c, int i) {
    switch (i) { case 0:return c->Rax; case 1:return c->Rcx; case 2:return c->Rdx; case 3:return c->Rbx;
        case 4:return c->Rsp; case 5:return c->Rbp; case 6:return c->Rsi; case 7:return c->Rdi;
        case 8:return c->R8; case 9:return c->R9; case 10:return c->R10; case 11:return c->R11;
        case 12:return c->R12; case 13:return c->R13; case 14:return c->R14; default:return c->R15; }
}

void ctx_program(CONTEXT* c) {
    uint64_t dr7 = c->Dr7;
    dr7 &= ~0xFFULL;            // L0..G3
    dr7 &= ~0xFFFF0000ULL;      // rw/len for Dr0-3
    uint64_t dw = g_dwatch.load();
    uint64_t v[4] = { g_slot[0].load(), g_slot[1].load(), g_slot[2].load(),
                      dw ? 0 : g_slot[3].load() };
    c->Dr0=v[0]; c->Dr1=v[1]; c->Dr2=v[2];
    c->Dr3 = dw ? dw : v[3];
    for (int k=0;k<3;++k) if (v[k]) dr7 |= (1ULL << (k*2));   // Dr0-2: exec, 1 byte
    if (dw) {
        dr7 |= (1ULL << 6);        // L3
        dr7 |= (3ULL << 28);       // RW3 = 11 (read/write)
        dr7 |= (2ULL << 30);       // LEN3 = 10 (8 bytes)
    } else if (v[3]) {
        dr7 |= (1ULL << 6);        // Dr3: exec, 1 byte
    }
    c->Dr7 = dr7; c->Dr6 = 0;
    // Publish exactly what we program so the ProcessInstrumentationCallback can
    // positively identify (Dr7-match) the CONTEXT returned by a direct-syscall
    // NtGetContextThread and zero the debug-register fields before it is read.
    instr_cb_set_armed_dr7(dr7);
    instr_cb_set_armed_slots(v[0], v[1], v[2], c->Dr3);
}
void arm_thread(DWORD tid) {
    if (tid == GetCurrentThreadId()) return;
    HANDLE h = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!h) return;
    SuspendThread(h);
    CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(h,&c)) { ctx_program(&c); c.ContextFlags=CONTEXT_DEBUG_REGISTERS; SetThreadContext(h,&c); }
    ResumeThread(h); CloseHandle(h);
}
void arm_all() {
    DWORD me = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap==INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te{}; te.dwSize=sizeof te;
    if (Thread32First(snap,&te)) do {
        if (te.th32OwnerProcessID==me) arm_thread(te.th32ThreadID);
    } while (Thread32Next(snap,&te));
    CloseHandle(snap);
}

// ---- lock-free capture ring (VEH writes, drain thread formats) -------------
struct Cap {
    volatile LONG ready;        // 0 empty, 1 filled
    uint64_t rip, rcx, r8, rdx, r9, rax;
    uint8_t  m[4][48]; uint8_t ok[4];     // safe-read bytes at rcx,r8,rdx,r9
    uint8_t  xmm[3][16];
    uint64_t stk[4];
    uint8_t  ct[2048]; uint32_t ctlen; uint8_t ct_ok;  // update-input ciphertext (the response blob)
};
Cap                   g_ring[1024];
std::atomic<uint32_t> g_w{0};
uint32_t              g_r = 0;

// data-watch capture: at a data-BP hit, snapshot RIP + all GP regs + a stack window
// + memory at each register pointer. R's live AES schedule lands somewhere in here;
// the drain thread writes it out for an offline GCM scan.
struct DCap {
    volatile LONG ready;
    uint64_t rip, gpr[16];                 // rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8..r15
    uint8_t  stack[4096]; uint8_t stk_ok;
    uint8_t  pm[16][256];  uint8_t pm_ok[16];
};
DCap                  g_dring[16];
std::atomic<uint32_t> g_dw_w{0};
uint32_t              g_dw_r = 0;

// SEH-guarded copy (bad pointers just fail). POD-only so __try is legal.
bool safe_read(void* dst, const void* src, size_t n) {
    __try { memcpy(dst, src, n); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

LONG CALLBACK aes_veh(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT* c = ep->ContextRecord;
    // Data-watch hit: Dr6 bit 3 set and Dr3 is our data BP (not an exec slot).
    uint64_t dw = g_dwatch.load(std::memory_order_relaxed);
    if (dw && (c->Dr6 & (1ULL << 3))) {
        uint32_t i = g_dw_w.fetch_add(1, std::memory_order_relaxed) % 16;
        DCap& d = g_dring[i];
        d.rip = c->Rip;
        uint64_t g[16] = { c->Rax,c->Rcx,c->Rdx,c->Rbx,c->Rsp,c->Rbp,c->Rsi,c->Rdi,
                           c->R8,c->R9,c->R10,c->R11,c->R12,c->R13,c->R14,c->R15 };
        for (int j=0;j<16;++j) d.gpr[j]=g[j];
        d.stk_ok = safe_read(d.stack, (void*)(c->Rsp>0x100?c->Rsp-0x100:c->Rsp), sizeof d.stack) ? 1 : 0;
        for (int j=0;j<16;++j)
            d.pm_ok[j] = (g[j] && safe_read(d.pm[j], (void*)g[j], 256)) ? 1 : 0;
        _WriteBarrier(); d.ready = 1;
        g_dwatch_hits.fetch_add(1);
        c->Dr6 = 0;
        c->EFlags |= 0x10000;   // RF: re-run the trapped access once without re-trapping
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    // Decoder-exit BP: when the base64 decode output holds the 704-byte key blob, arm the
    // Dr3 data watch on its ciphertext in THIS thread so the next (same-thread) decrypt
    // read trips it.
    uint64_t dbp = g_decode_bp.load(std::memory_order_relaxed);
    if (dbp && c->Rip==dbp) {
        g_decode_hits.fetch_add(1);
        if (!g_decode_done.load()) {
            uint64_t outp = ctx_gpr(c, g_decode_outreg);
            bool match;
            if (g_decode_any) {
                match = outp != 0;                     // mechanism test: arm on first valid hit
            } else if (g_decode_inlen > 0) {
                // Filter by input length (R9d) -- at a decoder ENTRY the output buffer is
                // not written yet, so content can't be checked. R9 low32 = input char count.
                int inl = (int)(c->R9 & 0xffffffff);
                match = outp && (inl >= g_decode_inlen - 6 && inl <= g_decode_inlen + 6);
            } else {
                uint8_t hdr[32];
                match = outp && safe_read(hdr,(void*)outp,32) &&
                        hdr[28]==0xA0 && hdr[29]==0x02 && hdr[30]==0x00 && hdr[31]==0x00;
            }
            if (match) {
                g_decode_704.fetch_add(1);
                uint64_t ct = outp + g_decode_off;
                c->Dr3 = ct;
                uint64_t dr7 = c->Dr7;
                dr7 &= ~(0xFULL<<28); dr7 |= (1ULL<<6)|(3ULL<<28)|(2ULL<<30);  // L3+RW=rw+LEN=8
                c->Dr7 = dr7;
                g_dwatch.store(ct); g_decode_arm_addr.store(ct);
                g_decode_armed.fetch_add(1); g_decode_done.store(true);
                instr_cb_set_armed_dr7(dr7);
            }
        }
        c->Dr6 = 0; c->EFlags |= 0x10000;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    for (int k=0;k<4;++k) {
        uint64_t va = g_slot[k].load(std::memory_order_relaxed);
        if (va && c->Rip==va) {
            uint32_t i = g_w.fetch_add(1, std::memory_order_relaxed) % 1024;
            Cap& r = g_ring[i];
            r.rip=c->Rip; r.rcx=c->Rcx; r.r8=c->R8; r.rdx=c->Rdx; r.r9=c->R9; r.rax=c->Rax;
            const uint64_t ptrs[4] = { c->Rcx, c->R8, c->Rdx, c->R9 };
            for (int j=0;j<4;++j) r.ok[j] = ptrs[j] ? (safe_read(r.m[j], (void*)ptrs[j], 48)?1:0) : 0;
            safe_read(r.xmm[0], &c->Xmm0, 16);
            safe_read(r.xmm[1], &c->Xmm1, 16);
            safe_read(r.xmm[2], &c->Xmm2, 16);
            safe_read(r.stk, (void*)c->Rsp, sizeof r.stk);
            r.ct_ok = 0; r.ctlen = 0;
            if (g_ct_all.load(std::memory_order_relaxed) || va == g_ct_bp.load(std::memory_order_relaxed)) {
                uint64_t inp = 0, inl = 0;
                if (safe_read(&inp, (void*)(c->Rsp + 0x28), 8) &&
                    safe_read(&inl, (void*)(c->Rsp + 0x30), 8) &&
                    inp && inl >= 64 && inl <= sizeof r.ct) {
                    if (safe_read(r.ct, (void*)inp, (size_t)inl)) { r.ctlen = (uint32_t)inl; r.ct_ok = 1; }
                }
            }
            _WriteBarrier(); r.ready = 1;
            ++g_hits;
            c->Dr6 = 0;
            c->EFlags |= 0x10000;   // RF: run the trapped insn once without re-trapping
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

const char* rva(uint64_t a, char* b, size_t n) {
    if (g_base && a>=g_base && a<g_end) std::snprintf(b,n,"plugin+0x%llx",(unsigned long long)(a-g_base));
    else std::snprintf(b,n,"0x%llx",(unsigned long long)a);
    return b;
}
void hexcat(char* out, const uint8_t* p, int n) { for(int i=0;i<n;++i) std::sprintf(out+2*i,"%02x",p[i]); }

void drain_one(const Cap& r) {
    char site[48], b1[48], b2[48];
    char h[100];
    std::fprintf(g_log, "[aes] hit %s  rcx=%s r8=%s rdx=0x%llx\n",
                 rva(r.rip,site,sizeof site), rva(r.rcx,b1,sizeof b1), rva(r.r8,b2,sizeof b2),
                 (unsigned long long)r.rdx);
    const char* names[4] = {"[rcx]","[r8] ","[rdx]","[r9] "};
    for (int j=0;j<4;++j) if (r.ok[j]) { hexcat(h, r.m[j], 32); std::fprintf(g_log, "   %s = %s\n", names[j], h); }
    hexcat(h, r.xmm[0],16); std::fprintf(g_log, "   xmm0 = %s\n", h);
    hexcat(h, r.xmm[2],16); std::fprintf(g_log, "   xmm2 = %s\n", h);
    // Delayed re-read: for a DRBG-generate BP the output buffer is filled AFTER the
    // entry BP, so re-read the arg pointers now (drain runs ms later) to catch the
    // generated bytes that weren't present at the immediate capture.
    uint8_t d[48]; const uint64_t p[4]={r.rcx,r.r8,r.rdx,r.r9}; const char* pn[4]={"rcx","r8 ","rdx","r9 "};
    for (int j=0;j<4;++j) if (p[j] && safe_read(d,(void*)p[j],48)) { hexcat(h,d,32); std::fprintf(g_log,"   delayed[%s]=%s\n",pn[j],h); }
    if (r.ct_ok) {
        std::fprintf(g_log, "   CT rcx=0x%llx len=%u = ", (unsigned long long)r.rcx, r.ctlen);
        for (uint32_t i=0;i<r.ctlen;++i) std::fprintf(g_log, "%02x", r.ct[i]);
        std::fprintf(g_log, "\n");
    }
    std::fflush(g_log);
}

int scan_and_arm() {
    // Resolve plugin bounds.
    if (HMODULE m = GetModuleHandleA("bambu_networking.dll")) {
        g_base=(uintptr_t)m; MODULEINFO mi{};
        if (GetModuleInformation(GetCurrentProcess(),m,&mi,sizeof mi)) g_end=g_base+mi.SizeOfImage;
    }
    // Manual mode: BBL_AES_BP=<rva,rva,..> (hex, plugin-relative). Bypasses the
    // instruction scan -> DR-BP arbitrary functions (e.g. the OpenSSL DRBG generate,
    // whose RVAs came from the rng_tap backtraces) and capture their args + the
    // delayed output buffer.
    if (const char* bp = std::getenv("BBL_AES_BP")) {
        if (!g_base) return 0;                      // wait until the plugin is loaded
        static bool logged_bp = false;
        std::vector<uint64_t> ms; const char* s = bp;
        while (*s && ms.size()<4) {
            char* e; unsigned long long v = std::strtoull(s, &e, 16);
            if (e==s) break; ms.push_back(g_base+v);
            s = (*e==',') ? e+1 : e; if (*e && *e!=',') break;
        }
        int n=(int)ms.size();
        for (int k=0;k<4;++k) g_slot[k].store(k<n?ms[k]:0);
        if (const char* cb = std::getenv("BBL_AES_CT_BP")) {
            unsigned long long v = std::strtoull(cb, nullptr, 16);
            if (v) g_ct_bp.store(g_base + v);   // rva of update() to grab the ciphertext at
        }
        if (const char* ca = std::getenv("BBL_AES_CT_ALL")) if (ca[0]=='1') g_ct_all.store(true);
        if (!logged_bp) { for(int k=0;k<n;++k){char c[48]; std::fprintf(g_log,"[aes] MANUAL bp %s\n", rva(ms[k],c,sizeof c));}
                          std::fprintf(g_log,"[aes] armed %d manual DR bp(s)\n", n); std::fflush(g_log); logged_bp=true; }
        arm_all();
        return n;
    }
    // Scan committed executable regions (plugin image + anonymous unpacked) for the
    // FIRST-round aeskeygenassist: 66 0F 3A DF <modrm> 01.
    std::vector<uint64_t> sites;
    long long tot_kga=0, tot_enc=0, tot_last=0, exec_regions=0;
    long long tot_cc=0, tot_bytes=0, tot_vex=0; int rok=0, rfail=0;
    static bool logged=false;      // per-region detail only on the first scan
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uintptr_t a=(uintptr_t)si.lpMinimumApplicationAddress, maxA=(uintptr_t)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi{};
    std::vector<uint8_t> buf;
    while (a<maxA && VirtualQuery((void*)a,&mbi,sizeof mbi)==sizeof mbi) {
        uintptr_t rb=(uintptr_t)mbi.BaseAddress; size_t rs=mbi.RegionSize;
        DWORD pr = mbi.Protect & 0xff;
        bool execp = !(mbi.Protect&(PAGE_GUARD|PAGE_NOACCESS)) &&
                     (pr==PAGE_EXECUTE||pr==PAGE_EXECUTE_READ||pr==PAGE_EXECUTE_READWRITE||pr==PAGE_EXECUTE_WRITECOPY);
        if (mbi.State==MEM_COMMIT && execp && rs>0 && rs<(size_t)(256ull<<20)) {
            ++exec_regions;
            buf.resize(rs);
            if (safe_read(buf.data(),(void*)rb,rs)) {
                ++rok; tot_bytes += rs;
                long long kga=0,enc=0,last=0,vex=0,cc=0;
                bool plug = (g_base && rb>=g_base && rb<g_end);
                for (size_t i=0;i+6<=rs;++i) {
                    uint8_t b=buf[i];
                    if (b==0xCC) { ++cc; continue; }
                    if (b==0xC4 || b==0xC5) {
                        ++vex;
                        // VEX VAESKEYGENASSIST (C4 E3 ?? DF) marks OpenSSL's AES key
                        // expansion. Resolve the enclosing function ENTRY (nearest
                        // preceding ENDBR64 = F3 0F 1E FA) so RCX=userKey at the BP.
                        if (b==0xC4 && buf[i+1]==0xE3 && buf[i+3]==0xDF && (plug||mbi.Type==MEM_PRIVATE)) {
                            ++kga;
                            size_t lim = i>4096 ? i-4096 : 0;
                            for (size_t j=i; j>lim; --j)
                                if (buf[j]==0xF3 && buf[j+1]==0x0F && buf[j+2]==0x1E && buf[j+3]==0xFA) { sites.push_back(rb+j); break; }
                        }
                        continue;
                    }
                    if (b!=0x0F) continue;
                    if (buf[i+1]==0x3A && buf[i+2]==0xDF) ++kga;        // legacy aeskeygenassist (census)
                    else if (buf[i+1]==0x38 && buf[i+2]==0xDC) ++enc;
                    else if (buf[i+1]==0x38 && buf[i+2]==0xDD) ++last;
                }
                tot_kga+=kga; tot_enc+=enc; tot_last+=last; tot_vex+=vex; tot_cc+=cc;
                if (!logged && g_base && (plug || kga||enc||last)) {
                    char nm[64]; HMODULE h=nullptr;
                    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,(LPCSTR)rb,&h)&&h)
                        GetModuleBaseNameA(GetCurrentProcess(),h,nm,sizeof nm);
                    else std::strcpy(nm, mbi.Type==MEM_PRIVATE?"<anon>":mbi.Type==MEM_MAPPED?"<mapped>":"<img>");
                    std::fprintf(g_log,"[aes]   rgn %p sz=0x%zx prot=0x%lx ty=%lu mod=%s%s  cc=%lld vex=%lld kga=%lld enc=%lld last=%lld\n",
                                 (void*)rb, rs, mbi.Protect, mbi.Type, nm, plug?"*PLUGIN*":"", cc, vex, kga, enc, last);
                }
            } else ++rfail;
        }
        a=rb+rs; if(rs==0) break;
    }
    if (!logged && g_base) std::fprintf(g_log,"[aes] CENSUS regions=%lld read_ok=%d read_fail=%d bytes=%lld cc=%lld vex=%lld | keygenassist=%lld aesenc=%lld aesenclast=%lld sites=%zu (plugin %p-%p)\n",
                              exec_regions, rok, rfail, tot_bytes, tot_cc, tot_vex, tot_kga, tot_enc, tot_last, sites.size(), (void*)g_base, (void*)g_end);
    if (g_base) logged=true;
    std::sort(sites.begin(), sites.end());
    sites.erase(std::unique(sites.begin(), sites.end()), sites.end());
    std::fprintf(g_log, "[aes] scan found %zu AES key-setup entr(y/ies)\n", sites.size());
    for (size_t k=0;k<sites.size() && k<24;++k) { char s[48]; std::fprintf(g_log,"[aes]   entry %s\n", rva(sites[k],s,sizeof s)); }
    // Arm up to 4 (DR0-3). If more than 4 exist we take the first 4 (all are AES key
    // expansions; the get_app_cert 256-bit setup is identified offline via GCM).
    int n = (int)(sites.size()<4?sites.size():4);
    for (int k=0;k<4;++k) g_slot[k].store(k<n?sites[k]:0);
    std::fprintf(g_log, "[aes] armed %d DR breakpoint(s)\n", n);
    std::fflush(g_log);
    arm_all();
    return n;
}

// Scan committed private RW memory for the base64-decoded 704-byte get_app_cert key
// blob: a window whose [28:32] little-endian length == 672 and whose 12-byte nonce
// head is high-entropy (rules out counter/pointer arrays). Returns the ciphertext
// address (blob+32, the decrypt's first read) or 0.
uint64_t scan_for_blob() {
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uintptr_t a=(uintptr_t)si.lpMinimumApplicationAddress, maxA=(uintptr_t)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION m{};
    std::vector<uint8_t> buf;
    while (a<maxA && VirtualQuery((void*)a,&m,sizeof m)) {
        uintptr_t rb=(uintptr_t)m.BaseAddress; size_t rs=m.RegionSize;
        DWORD pr=m.Protect&0xff;
        bool rw = !(m.Protect&(PAGE_GUARD|PAGE_NOACCESS)) && (pr==PAGE_READWRITE||pr==PAGE_READWRITE);
        if (m.State==MEM_COMMIT && m.Type==MEM_PRIVATE && rw && rs>=704 && rs<(size_t)(256ull<<20)) {
            buf.resize(rs);
            if (safe_read(buf.data(),(void*)rb,rs)) {
                const uint8_t* p=buf.data();
                for (size_t o=0;o+704<=rs;o+=8) {
                    if (p[o+28]==0xA0 && p[o+29]==0x02 && p[o+30]==0x00 && p[o+31]==0x00) {
                        // The real blob is an AES-GCM ciphertext: the full 704 bytes are
                        // high-entropy. Reject struct/counter arrays by requiring the ct
                        // (bytes 32..704) to have many distinct values and few zeros.
                        uint8_t seen[256]={0}; int distinct=0, zeros=0;
                        for (int j=32;j<704;++j){ uint8_t b=p[o+j]; if(!seen[b]){seen[b]=1;++distinct;} if(b==0)++zeros; }
                        if (distinct<180 || zeros>24) continue;
                        // Precise fingerprint: the plugin's stored (decrypt-input) copy sits
                        // right after the cert in the parsed response struct. Prefer a blob
                        // preceded by "CERTIFICATE" within 256 bytes (the real target); a plain
                        // high-entropy match elsewhere is a decoy.
                        bool cert_adj = false;
                        size_t lo = o>256 ? o-256 : 0;
                        for (size_t j=lo; j+11<=o; ++j)
                            if (std::memcmp(p+j,"CERTIFICATE",11)==0) { cert_adj=true; break; }
                        if (cert_adj) return (uint64_t)(rb+o+32);
                        // remember a fallback but keep scanning for a cert-adjacent one
                    }
                }
            }
        }
        a=rb+rs; if(rs==0) break;
    }
    return 0;
}

// Scan for the get_app_cert "key" base64 string: a >=900-char contiguous run of
// base64 chars (the cert PEM is line-wrapped, so a long UNwrapped run is the key/
// aes256 value; >=900 uniquely picks the 940-char key). Returns an address mid-run
// (so the decode's read trips a data watch, dodging whole-buffer memcpy at the head).
uint64_t scan_for_b64() {
    auto isb64 = [](uint8_t c){ return (c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='+'||c=='/'||c=='-'||c=='_'||c=='='; };
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uintptr_t a=(uintptr_t)si.lpMinimumApplicationAddress, maxA=(uintptr_t)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION m{};
    std::vector<uint8_t> buf;
    while (a<maxA && VirtualQuery((void*)a,&m,sizeof m)) {
        uintptr_t rb=(uintptr_t)m.BaseAddress; size_t rs=m.RegionSize;
        DWORD pr=m.Protect&0xff;
        if (m.State==MEM_COMMIT && m.Type==MEM_PRIVATE && (pr==PAGE_READWRITE) && rs>=1000 && rs<(size_t)(256ull<<20)) {
            buf.resize(rs);
            if (safe_read(buf.data(),(void*)rb,rs)) {
                const uint8_t* p=buf.data();
                size_t run=0, start=0;
                for (size_t i=0;i<rs;++i) {
                    if (isb64(p[i])) { if(run==0) start=i; ++run;
                        if (run>=940) return (uint64_t)(rb+start+468);  // mid-run byte
                    } else run=0;
                }
            }
        }
        a=rb+rs; if(rs==0) break;
    }
    return 0;
}

void drain_dcap() {
    static FILE* df=nullptr;
    if (!df) {
        const char* p=std::getenv("BBL_AES_DWATCH_LOG"); if(!p||!p[0]) p="dwatch.log";
        df=std::fopen(p,"a"); if(!df) df=stderr;
    }
    uint32_t w=g_dw_w.load(std::memory_order_acquire);
    while (g_dw_r!=w) {
        DCap& d=g_dring[g_dw_r%16];
        if (d.ready!=1) break;
        char site[48];
        std::fprintf(df,"=== DWATCH hit rip=%s ===\n", rva(d.rip,site,sizeof site));
        static const char* gn[16]={"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
        for (int j=0;j<16;++j) std::fprintf(df,"%s=0x%llx ",gn[j],(unsigned long long)d.gpr[j]);
        std::fprintf(df,"\n");
        char h[9000];
        if (d.stk_ok){ hexcat(h,d.stack,sizeof d.stack); std::fprintf(df,"stack=%s\n",h); }
        for (int j=0;j<16;++j) if(d.pm_ok[j]){ hexcat(h,d.pm[j],256); std::fprintf(df,"[%s]=%s\n",gn[j],h); }
        std::fflush(df);
        d.ready=0; ++g_dw_r;
    }
}

} // namespace

void start_aes_tap() {
    static bool started=false; if (started) return; started=true;
    const char* p = std::getenv("BBL_AES_LOG"); if (!p||!p[0]) p="aes_tap.log";
    g_log = std::fopen(p,"a");
    if (!g_log) g_log = stderr;
    g_veh = AddVectoredExceptionHandler(1, aes_veh);
    g_run = true;
    int ms = 30; if (const char* e=std::getenv("BBL_REARM_MS")){int v=std::atoi(e); if(v>0) ms=v;}
    // Hold off arming the DR breakpoints until the plugin has finished loading (its
    // DllMain has run) and the initial local-connect has settled. Arming DR on the
    // main thread WHILE it is inside the plugin's DllMain races the loader and makes
    // LoadLibrary fail (observed with manual BBL_AES_BP). get_app_cert fires during
    // the later cloud session, so a delay costs nothing. Default 6s; override with
    // BBL_AES_ARM_DELAY_MS.
    int arm_delay = 6000; if (const char* e=std::getenv("BBL_AES_ARM_DELAY_MS")){int v=std::atoi(e); if(v>=0) arm_delay=v;}
    if (const char* e=std::getenv("BBL_AES_DWATCH_SCAN")) if (e[0]=='1') g_dwatch_scan.store(true);
    if (const char* e=std::getenv("BBL_AES_B64WATCH")) if (e[0]=='1') { g_dwatch_scan.store(true); g_b64watch.store(true); }
    if (const char* e=std::getenv("BBL_AES_DECODE_BP")) g_decode_rva = std::strtoull(e,nullptr,16);
    if (const char* e=std::getenv("BBL_AES_DECODE_OUT")) {
        const char* rn[16]={"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
        for (int i=0;i<16;++i) if(!_stricmp(e,rn[i])){ g_decode_outreg=i; break; }
    }
    if (const char* e=std::getenv("BBL_AES_DECODE_INLEN")) g_decode_inlen = std::atoi(e);
    if (const char* e=std::getenv("BBL_AES_DECODE_OFF")) g_decode_off = std::atoi(e);
    if (const char* e=std::getenv("BBL_AES_DECODE_ANY")) if (e[0]=='1') g_decode_any = true;
    g_rearm_thr = std::thread([ms, arm_delay]{
        int armed = 0, readd = 0;
        DWORD t0 = GetTickCount();
        bool announced_wait = false;
        while (g_run.load()) {
            // Keep our #DB handler at the FRONT of the VEH chain: the plugin installs
            // its own vectored handler during init that terminates the process on a
            // hardware-breakpoint exception. Re-registering ours (First=1) puts it
            // ahead so it consumes the #DB (CONTINUE_EXECUTION) before the plugin's
            // handler runs. Capped; handles intentionally leaked for the capture's
            // lifetime.
            if (readd < 200) { AddVectoredExceptionHandler(1, aes_veh); ++readd; }
            // Arm-delay gate: do not touch any thread's DR until the plugin is loaded
            // AND the settle window has elapsed. Until then, just keep our VEH fronted.
            bool plugin_loaded = (GetModuleHandleA("bambu_networking.dll") != nullptr);
            if (!plugin_loaded || (int)(GetTickCount() - t0) < arm_delay) {
                if (!announced_wait) { std::fprintf(g_log, "[aes] arm gate: waiting for plugin-load + %dms settle before DR arm\n", arm_delay); std::fflush(g_log); announced_wait = true; }
                Sleep(100);
                continue;
            }
            // Decode-hook: resolve the decoder-exit BP rva -> VA once the plugin is loaded.
            if (g_decode_rva && g_decode_bp.load()==0) {
                if (HMODULE m=GetModuleHandleA("bambu_networking.dll")) {
                    uint64_t va=(uint64_t)m + g_decode_rva;
                    g_decode_bp.store(va);
                    std::fprintf(g_log,"[aes] decode-hook exec BP @%p (rva 0x%llx) outreg=%d inlen=%d\n",
                                 (void*)va,(unsigned long long)g_decode_rva,g_decode_outreg,g_decode_inlen);
                    std::fflush(g_log);
                }
            }
            // Data-watch: once past the arm gate, keep scanning for the response blob;
            // when found, arm the Dr3 read/write watch on its ciphertext.
            if (g_dwatch_scan.load() && g_dwatch.load()==0) {
                uint64_t ct = g_b64watch.load() ? scan_for_b64() : scan_for_blob();
                if (ct) { g_dwatch.store(ct);
                          std::fprintf(g_log,"[aes] DWATCH armed on %s @%p\n", g_b64watch.load()?"b64-key-string":"blob ct", (void*)ct);
                          std::fflush(g_log); arm_all(); }
            }
            if (g_decode_bp.load()) {
                // Decode-hook mode: don't run the AES-site scan (it clobbers g_slot[0]);
                // just keep Dr0 = decode BP armed on all threads.
                g_slot[0].store(g_decode_bp.load());
                arm_all(); Sleep(ms);
            }
            else if (armed == 0) { armed = scan_and_arm(); Sleep(400); }  // AES code may unpack lazily -> keep scanning
            else { arm_all(); Sleep(ms); }
            static DWORD last_log=0;
            if ((g_decode_bp.load()||g_dwatch.load()) && GetTickCount()-last_log>2000) {
                last_log=GetTickCount();
                std::fprintf(g_log,"[aes] decode hits=%lld 704=%lld armed=%lld watch@%p dhits=%d\n",
                    g_decode_hits.load(),g_decode_704.load(),g_decode_armed.load(),
                    (void*)g_decode_arm_addr.load(),g_dwatch_hits.load());
                std::fflush(g_log);
            }
        }
    });
    g_drain_thr = std::thread([]{
        while (g_run.load() || g_r != g_w.load() || g_dw_r != g_dw_w.load()) {
            uint32_t w = g_w.load(std::memory_order_acquire);
            while (g_r != w) {
                Cap& r = g_ring[g_r % 1024];
                if (r.ready != 1) break;      // not yet fully written
                drain_one(r); r.ready = 0; ++g_r;
            }
            drain_dcap();
            Sleep(20);
        }
    });
    std::fprintf(stderr, "[aes-tap] started (plugin base=%p)\n", (void*)g_base);
}

void stop_aes_tap() {
    if (!g_run.exchange(false)) return;
    if (g_rearm_thr.joinable()) g_rearm_thr.join();
    if (g_drain_thr.joinable()) g_drain_thr.join();
    if (g_veh) { RemoveVectoredExceptionHandler(g_veh); g_veh=nullptr; }
    if (g_log && g_log!=stderr) { std::fprintf(g_log,"[aes] total key-expansions captured = %lld\n", g_hits.load()); std::fclose(g_log); }
    std::fprintf(stderr, "[aes-tap] stopped; %lld key expansions captured\n", g_hits.load());
}

long long aes_tap_hits() { return g_hits.load(); }

} // namespace bbl
