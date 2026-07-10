// aes_tap — DR-breakpoint OpenSSL's AES-NI key expansion to capture the raw AES
// key(s), so the DRBG-generated get_app_cert session key K can be recovered.
// See aes_tap.hpp. DR execute-BP writes no code -> works despite the plugin's
// SEC_NO_CHANGE .text; capture is done into a lock-free ring drained off-thread
// so the VEH never touches a CRT/heap lock.

#include "host/aes_tap.hpp"

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

void ctx_program(CONTEXT* c) {
    uint64_t dr7 = c->Dr7;
    dr7 &= ~0xFFULL;            // L0..G3
    dr7 &= ~0xFFFF0000ULL;      // rw/len for Dr0-3
    uint64_t v[4] = { g_slot[0].load(), g_slot[1].load(), g_slot[2].load(), g_slot[3].load() };
    c->Dr0=v[0]; c->Dr1=v[1]; c->Dr2=v[2]; c->Dr3=v[3];
    for (int k=0;k<4;++k) if (v[k]) dr7 |= (1ULL << (k*2));   // Lk=1, exec, 1 byte
    c->Dr7 = dr7; c->Dr6 = 0;
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
};
Cap                   g_ring[1024];
std::atomic<uint32_t> g_w{0};
uint32_t              g_r = 0;

// SEH-guarded copy (bad pointers just fail). POD-only so __try is legal.
bool safe_read(void* dst, const void* src, size_t n) {
    __try { memcpy(dst, src, n); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

LONG CALLBACK aes_veh(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT* c = ep->ContextRecord;
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

} // namespace

void start_aes_tap() {
    static bool started=false; if (started) return; started=true;
    const char* p = std::getenv("BBL_AES_LOG"); if (!p||!p[0]) p="aes_tap.log";
    g_log = std::fopen(p,"a");
    if (!g_log) g_log = stderr;
    g_veh = AddVectoredExceptionHandler(1, aes_veh);
    g_run = true;
    int ms = 30; if (const char* e=std::getenv("BBL_REARM_MS")){int v=std::atoi(e); if(v>0) ms=v;}
    g_rearm_thr = std::thread([ms]{
        int armed = 0, readd = 0;
        while (g_run.load()) {
            // Keep our #DB handler at the FRONT of the VEH chain: the plugin installs
            // its own vectored handler during init that treats a hardware-breakpoint
            // exception as "debugger present" and poison-crashes. Re-registering ours
            // (First=1) puts it ahead so it consumes the #DB (CONTINUE_EXECUTION)
            // before the plugin's handler runs. Capped; handles intentionally leaked
            // for the capture's lifetime.
            if (readd < 200) { AddVectoredExceptionHandler(1, aes_veh); ++readd; }
            if (armed == 0) { armed = scan_and_arm(); Sleep(400); }  // AES code may unpack lazily -> keep scanning
            else { arm_all(); Sleep(ms); }
        }
    });
    g_drain_thr = std::thread([]{
        while (g_run.load() || g_r != g_w.load()) {
            uint32_t w = g_w.load(std::memory_order_acquire);
            while (g_r != w) {
                Cap& r = g_ring[g_r % 1024];
                if (r.ready != 1) break;      // not yet fully written
                drain_one(r); r.ready = 0; ++g_r;
            }
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
