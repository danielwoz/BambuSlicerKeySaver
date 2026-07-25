// dump_regions — snapshot the loaded plugin's committed memory so the
// get_app_cert crypto (OpenSSL AES/RSA/base64) and the baked server RSA public
// key / URL-template constants can be disassembled OFFLINE.
//
// This runs IN-PROCESS after the plugin has been loaded, connected and driven
// through get_app_cert by the normal harness. It uses no debugger and no
// hardware breakpoint: it walks the address space with VirtualQuery and copies
// every committed, readable region to a file, with a manifest describing each.
//
// It dumps:
//   * the whole bambu_networking.dll image span (headers/.text/.rdata/.data) --
//     this contains the OpenSSL crypto region at plugin_base+0x16BE000 as well
//     as the remaining sections;
//   * every anonymous MEM_PRIVATE region that is executable OR reasonably sized
//     readable data (the plugin may place code/const in anonymous regions too).
//
// Files: <dir>\img_<rva>_<size>_<prot>.bin        (inside the plugin image)
//        <dir>\anon_<va>_<size>_<prot>.bin        (anonymous arenas)
//        <dir>\MANIFEST.txt                        (one line per region)
// The RVA/VA and size are in the filename so the disassembler can rebase.

#include "host/dump_regions.hpp"

#if defined(_WIN32)

#include <windows.h>
#include <psapi.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace bbl {
namespace {

bool safe_copy(void* dst, const void* src, size_t n) {
    __try { memcpy(dst, src, n); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

const char* prot_str(DWORD p) {
    switch (p & 0xff) {
        case PAGE_NOACCESS:          return "NA";
        case PAGE_READONLY:          return "R";
        case PAGE_READWRITE:         return "RW";
        case PAGE_WRITECOPY:         return "WC";
        case PAGE_EXECUTE:           return "X";
        case PAGE_EXECUTE_READ:      return "RX";
        case PAGE_EXECUTE_READWRITE: return "RWX";
        case PAGE_EXECUTE_WRITECOPY: return "XWC";
        default:                     return "??";
    }
}

// Write one region to disk (SEH-guarded copy through a bounce buffer so a page
// that faults mid-copy is skipped rather than crashing). Returns bytes written.
size_t dump_one(const char* dir, const char* tag, uint64_t va, uint64_t rva,
                size_t sz, DWORD prot, FILE* manifest) {
    // Cap any single dump so a runaway region can't fill the disk; the crypto
    // region is ~22MB, data sections a few MB, so 64MB is ample headroom.
    size_t cap = (size_t)(64ull << 20);
    size_t n   = sz < cap ? sz : cap;

    char path[MAX_PATH];
    if (rva != (uint64_t)-1)
        std::snprintf(path, sizeof path, "%s\\%s_%08llx_%zx_%s.bin",
                      dir, tag, (unsigned long long)rva, n, prot_str(prot));
    else
        std::snprintf(path, sizeof path, "%s\\%s_%012llx_%zx_%s.bin",
                      dir, tag, (unsigned long long)va, n, prot_str(prot));

    std::vector<uint8_t> buf(n);
    // Copy page-by-page so one bad page doesn't lose the whole region.
    const size_t PG = 4096;
    size_t good = 0;
    for (size_t off = 0; off < n; off += PG) {
        size_t chunk = (n - off) < PG ? (n - off) : PG;
        if (safe_copy(buf.data() + off, (const uint8_t*)va + off, chunk)) good += chunk;
        else std::memset(buf.data() + off, 0, chunk);   // zero-fill unreadable page
    }
    FILE* f = std::fopen(path, "wb");
    if (!f) { std::fprintf(stderr, "[dump] cannot open %s\n", path); return 0; }
    std::fwrite(buf.data(), 1, n, f);
    std::fclose(f);

    if (manifest) {
        if (rva != (uint64_t)-1)
            std::fprintf(manifest, "%-5s va=%016llx rva=%08llx size=%zx prot=%-3s readable=%zx file=%s\n",
                         tag, (unsigned long long)va, (unsigned long long)rva, n, prot_str(prot), good,
                         std::strrchr(path, '\\') ? std::strrchr(path, '\\') + 1 : path);
        else
            std::fprintf(manifest, "%-5s va=%016llx rva=-------- size=%zx prot=%-3s readable=%zx file=%s\n",
                         tag, (unsigned long long)va, n, prot_str(prot), good,
                         std::strrchr(path, '\\') ? std::strrchr(path, '\\') + 1 : path);
    }
    return good;
}

}  // namespace

int dump_plugin_regions(const char* out_dir) {
    std::string dir = (out_dir && out_dir[0]) ? out_dir : "region_dump";
    CreateDirectoryA(dir.c_str(), nullptr);

    uint64_t base = 0, end = 0;
    if (HMODULE m = GetModuleHandleA("bambu_networking.dll")) {
        base = (uint64_t)m;
        MODULEINFO mi{};
        if (GetModuleInformation(GetCurrentProcess(), m, &mi, sizeof mi))
            end = base + mi.SizeOfImage;
    }
    if (!base) {
        std::fprintf(stderr, "[dump] bambu_networking.dll not loaded -- nothing to dump\n");
        return 1;
    }

    std::string mpath = dir + "\\MANIFEST.txt";
    FILE* manifest = std::fopen(mpath.c_str(), "w");
    std::fprintf(stderr, "[dump] plugin image %016llx..%016llx (%.1f MB) -> %s\n",
                 (unsigned long long)base, (unsigned long long)end,
                 (double)(end - base) / (1024.0 * 1024.0), dir.c_str());
    if (manifest)
        std::fprintf(manifest, "# bambu_networking.dll base=%016llx end=%016llx size=%llx\n",
                     (unsigned long long)base, (unsigned long long)end,
                     (unsigned long long)(end - base));

    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uint8_t* a    = (uint8_t*)si.lpMinimumApplicationAddress;
    uint8_t* maxa = (uint8_t*)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi{};

    long long img_regions = 0, anon_regions = 0;
    uint64_t img_bytes = 0, anon_bytes = 0;

    while (a < maxa && VirtualQuery(a, &mbi, sizeof mbi) == sizeof mbi) {
        uint64_t rb = (uint64_t)mbi.BaseAddress;
        size_t   rs = mbi.RegionSize;
        DWORD    pr = mbi.Protect & 0xff;
        bool committed = (mbi.State == MEM_COMMIT);
        bool guarded   = (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0;
        bool readable  = committed && !guarded &&
                         (pr == PAGE_READONLY || pr == PAGE_READWRITE || pr == PAGE_WRITECOPY ||
                          pr == PAGE_EXECUTE_READ || pr == PAGE_EXECUTE_READWRITE ||
                          pr == PAGE_EXECUTE_WRITECOPY || pr == PAGE_EXECUTE);
        bool exec = (pr == PAGE_EXECUTE || pr == PAGE_EXECUTE_READ ||
                     pr == PAGE_EXECUTE_READWRITE || pr == PAGE_EXECUTE_WRITECOPY);

        bool in_image = (rb >= base && rb < end);

        if (readable && in_image) {
            // Whole plugin image: dump every committed sub-region (each section /
            // protection run lands as its own file, keyed by RVA).
            uint64_t rva = rb - base;
            size_t got = dump_one(dir.c_str(), "img", rb, rva, rs, mbi.Protect, manifest);
            ++img_regions; img_bytes += got;
        } else if (readable && mbi.Type == MEM_PRIVATE && !in_image &&
                   rs >= 4096 && rs < (size_t)(128ull << 20)) {
            // Anonymous regions. Executable ones may hold code; large readable
            // ones may hold const data (server pubkey, URL template). Dump exec
            // always, and non-exec data up to 32MB.
            if (exec || rs <= (size_t)(32ull << 20)) {
                size_t got = dump_one(dir.c_str(), "anon", rb, (uint64_t)-1, rs, mbi.Protect, manifest);
                ++anon_regions; anon_bytes += got;
            }
        }

        uint8_t* next = (uint8_t*)(rb + rs);
        if (next <= a) break;
        a = next;
    }

    std::fprintf(stderr,
                 "[dump] done: %lld image region(s) (%.1f MB), %lld anon region(s) (%.1f MB) -> %s\n",
                 img_regions, (double)img_bytes / (1024.0 * 1024.0),
                 anon_regions, (double)anon_bytes / (1024.0 * 1024.0), dir.c_str());
    if (manifest) {
        std::fprintf(manifest, "# totals: img_regions=%lld img_bytes=%llu anon_regions=%lld anon_bytes=%llu\n",
                     img_regions, (unsigned long long)img_bytes, anon_regions, (unsigned long long)anon_bytes);
        std::fclose(manifest);
    }
    return 0;
}

}  // namespace bbl

#else   // !_WIN32
namespace bbl { int dump_plugin_regions(const char*) { return 0; } }
#endif
