#include "plugin_fetch.hpp"
#include "plugin_source.h"      // shared version + manifest URL + parser (with Linux)

#include <windows.h>
#include <cstdio>
#include <string>

namespace bbl {
namespace {

std::string env(const char* k) {
    char buf[1024];
    DWORD n = GetEnvironmentVariableA(k, buf, sizeof buf);
    return (n > 0 && n < sizeof buf) ? std::string(buf, n) : std::string();
}

bool file_ok(const std::string& p) {
    DWORD a = GetFileAttributesA(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

void mkdirs(const std::string& path) {
    std::string acc;
    for (size_t i = 0; i < path.size(); ++i) {
        acc.push_back(path[i]);
        if (path[i] == '\\' || path[i] == '/') CreateDirectoryA(acc.c_str(), nullptr);
    }
    CreateDirectoryA(path.c_str(), nullptr);
}

// Run a command line synchronously; return true iff exit code 0.
bool run(const std::string& cmd) {
    STARTUPINFOA si{}; si.cb = sizeof si;
    PROCESS_INFORMATION pi{};
    std::string mut = cmd;
    // Run VISIBLE (no CREATE_NO_WINDOW): show the curl/tar subprocess window so
    // the download step is transparent to the user.
    if (!CreateProcessA(nullptr, mut.data(), nullptr, nullptr, TRUE,
                        0, nullptr, nullptr, &si, &pi))
        return false;
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return code == 0;
}

std::string slurp(const std::string& p) {
    FILE* f = std::fopen(p.c_str(), "rb");
    if (!f) return {};
    std::string s; char b[4096]; size_t n;
    while ((n = std::fread(b, 1, sizeof b, f)) > 0) s.append(b, n);
    std::fclose(f);
    return s;
}

// Find the extracted bambu_networking.dll anywhere under dir (one level deep).
std::string find_dll(const std::string& dir) {
    std::string direct = dir + "\\bambu_networking.dll";
    if (file_ok(direct)) return direct;
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA((dir + "\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return {};
    std::string found;
    do {
        std::string name = fd.cFileName;
        if (name == "." || name == "..") continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            std::string sub = dir + "\\" + name + "\\bambu_networking.dll";
            if (file_ok(sub)) { found = sub; break; }
        } else if (name == "bambu_networking.dll") {
            found = dir + "\\" + name; break;
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return found;
}

}  // namespace

std::string download_plugin_win(const std::string& version) {
    std::string ver = version.empty() ? std::string(plugin_source::kVersion) : version;
    std::string base = env("LOCALAPPDATA");
    if (base.empty()) base = env("TEMP");
    if (base.empty()) { std::fprintf(stderr, "[plugin-dl] no LOCALAPPDATA/TEMP\n"); return {}; }

    std::string cache_dir = base + "\\bambu_slicer_key_saver\\plugins\\" + ver;
    std::string cache_dll = cache_dir + "\\bambu_networking.dll";
    if (file_ok(cache_dll)) {
        std::fprintf(stderr, "[plugin-dl] using cached plugin: %s\n", cache_dll.c_str());
        return cache_dll;
    }

    std::fprintf(stderr, "[plugin-dl] no local plugin - fetching manifest from Bambu CDN...\n");
    std::string tmp = env("TEMP"); if (tmp.empty()) tmp = ".";
    std::string manifest = tmp + "\\bambu_manifest.json";
    std::string zip      = tmp + "\\bambu_plugin.zip";

    // 1. manifest (windows build). curl ships in Windows 10+ (System32\curl.exe).
    std::string c1 = "curl --silent --location --max-time 60 -H \"X-BBL-OS-Type: windows\" -o \"" +
                     manifest + "\" \"" + plugin_source::manifest_url_for(ver) + "\"";
    if (!run(c1)) { std::fprintf(stderr, "[plugin-dl] manifest fetch failed\n"); return {}; }

    std::string url = plugin_source::parse_manifest_url(slurp(manifest));
    DeleteFileA(manifest.c_str());
    if (url.empty()) { std::fprintf(stderr, "[plugin-dl] no url in manifest\n"); return {}; }
    std::fprintf(stderr, "[plugin-dl] downloading plugin ZIP: %s\n", url.c_str());

    // 2. ZIP
    std::string c2 = "curl --silent --location --max-time 120 -o \"" + zip + "\" \"" + url + "\"";
    if (!run(c2)) { std::fprintf(stderr, "[plugin-dl] ZIP download failed\n"); return {}; }

    // 3. extract (tar ships in Windows 10+ and reads .zip).
    mkdirs(cache_dir);
    std::string c3 = "tar -xf \"" + zip + "\" -C \"" + cache_dir + "\"";
    bool ex = run(c3);
    DeleteFileA(zip.c_str());
    if (!ex) { std::fprintf(stderr, "[plugin-dl] extract failed\n"); return {}; }

    std::string dll = find_dll(cache_dir);
    if (dll.empty()) { std::fprintf(stderr, "[plugin-dl] bambu_networking.dll not found in ZIP\n"); return {}; }
    if (dll != cache_dll) { CopyFileA(dll.c_str(), cache_dll.c_str(), FALSE); }
    std::fprintf(stderr, "[plugin-dl] plugin cached: %s\n", cache_dll.c_str());
    return cache_dll;
}

// Return the cached plugin path for `version` if already fetched, else "".
// Does NOT touch the network -- keeps the download a separate, explicit step
// (--fetch-plugin) so a run never triggers a download in the same process.
std::string cached_plugin_path(const std::string& version) {
    std::string ver = version.empty() ? std::string(plugin_source::kVersion) : version;
    std::string base = env("LOCALAPPDATA");
    if (base.empty()) base = env("TEMP");
    if (base.empty()) return {};
    std::string cache_dll = base + "\\bambu_slicer_key_saver\\plugins\\" + ver + "\\bambu_networking.dll";
    return file_ok(cache_dll) ? cache_dll : std::string();
}

}  // namespace bbl
