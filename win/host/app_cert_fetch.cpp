// Retrieve the Studio "application" certificate from Bambu's cloud using
// open-bamboo-networking's obn::appcert::fetch (the real get_app_cert REST call),
// so no memory scanning of the app key is needed. The cloud token is decrypted
// from BambuStudio's BambuNetworkEngine.conf (AES-128-ECB with the global config
// key). Writes app_cert.pem + app_cert_id.txt (+ crl + the K-wrapped key blob).
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include "obn/app_cert.hpp"
#include "obn/http_client.hpp"

#include <cstdio>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace bbl {

namespace {

bool read_file(const std::string& path, std::string& out) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    char b[8192]; size_t n;
    while ((n = std::fread(b, 1, sizeof b, f)) > 0) out.append(b, n);
    std::fclose(f);
    return true;
}

bool write_file(const std::string& path, const std::string& data) {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    if (!data.empty()) std::fwrite(data.data(), 1, data.size(), f);
    std::fclose(f);
    return true;
}

// AES-128-ECB decrypt (no IV, no padding — the plugin space-pads the config) with a
// 16-byte ASCII key, via Windows CNG.
std::string aes128_ecb_decrypt(const std::string& ct, const std::string& key) {
    std::string out;
    if (key.size() != 16 || ct.empty() || (ct.size() % 16) != 0) return out;
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) return out;
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                      sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    BCRYPT_KEY_HANDLE k = nullptr;
    if (BCryptGenerateSymmetricKey(alg, &k, nullptr, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0) == 0) {
        out.resize(ct.size());
        ULONG done = 0;
        if (BCryptDecrypt(k, (PUCHAR)ct.data(), (ULONG)ct.size(), nullptr, nullptr, 0,
                          (PUCHAR)out.data(), (ULONG)out.size(), &done, 0) == 0)
            out.resize(done);
        else
            out.clear();
        BCryptDestroyKey(k);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return out;
}

// First `"key": "value"` string value in a JSON-ish blob (whole-key match, so
// "token" does not match inside "refresh_token"/"autotest_token").
std::string json_str(const std::string& s, const std::string& key) {
    const std::string pat = "\"" + key + "\"";
    size_t p = 0;
    while ((p = s.find(pat, p)) != std::string::npos) {
        size_t c = s.find(':', p + pat.size());
        if (c == std::string::npos) return "";
        size_t q = s.find_first_not_of(" \t\r\n", c + 1);
        if (q != std::string::npos && s[q] == '"') {
            size_t e = s.find('"', q + 1);
            if (e != std::string::npos) return s.substr(q + 1, e - q - 1);
        }
        p += pat.size();
    }
    return "";
}

// First `"key": <number>` integer value, as a string.
std::string json_num(const std::string& s, const std::string& key) {
    const std::string pat = "\"" + key + "\"";
    size_t p = s.find(pat);
    if (p == std::string::npos) return "";
    size_t c = s.find(':', p + pat.size());
    if (c == std::string::npos) return "";
    size_t q = s.find_first_not_of(" \t\r\n\"", c + 1);
    if (q == std::string::npos) return "";
    size_t e = q;
    while (e < s.size() && (s[e] >= '0' && s[e] <= '9')) ++e;
    return s.substr(q, e - q);
}

bool is_hex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }

// Scan one region for the longest "GLOF<digits>-<hex...>" match beating cur_best;
// copies it into outbuf[64] and returns the new best length. SEH-guarded and
// POD-only (no C++ objects, so it does not require /EHsc object unwinding).
int scan_region_appid(const char* base, size_t n, char* outbuf, int cur_best) {
    int bestlen = cur_best;
    __try {
        for (size_t i = 0; i + 8 < n; ++i) {
            if (base[i] != 'G' || base[i+1] != 'L' || base[i+2] != 'O' || base[i+3] != 'F') continue;
            size_t j = i + 4;
            while (j < n && base[j] >= '0' && base[j] <= '9') ++j;
            if (j == i + 4 || j >= n || base[j] != '-') continue;      // GLOF<digits>-
            size_t k = j + 1;
            while (k < n && is_hex(base[k])) ++k;
            int total = (int)(k - i);
            if ((int)(k - (j + 1)) >= 24 && total < 64 && total > bestlen) {   // >=24 hex after '-'
                for (int t = 0; t < total; ++t) outbuf[t] = base[i + t];
                bestlen = total;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return bestlen;
}

}  // namespace

// Scan this process's committed memory for the account's app_identity, resident
// after the plugin builds a get_app_cert request: "GLOF<digits>-<hex...>" where the
// hex tail is the app-cert CN hex (~12) followed by the app-key token (16). Returns
// the longest such string (the full identity, longer than the bare cert CN).
std::string scan_app_identity() {
    char buf[64] = {0};
    int bestlen = 0;
    MEMORY_BASIC_INFORMATION mbi{};
    for (unsigned char* a = nullptr; VirtualQuery(a, &mbi, sizeof mbi);
         a = (unsigned char*)mbi.BaseAddress + mbi.RegionSize) {
        if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD)) continue;
        DWORD pr = mbi.Protect & 0xFF;
        if (pr == PAGE_NOACCESS) continue;
        if (mbi.RegionSize > (256ull << 20)) continue;
        bestlen = scan_region_appid((const char*)mbi.BaseAddress, mbi.RegionSize, buf, bestlen);
    }
    return bestlen > 0 ? std::string(buf, bestlen) : std::string();
}

// Fetch the app cert. Returns 0 on success. app_identity is account-specific and
// must be supplied (BBL_APP_IDENTITY or --app-identity or read from the plugin).
int run_get_app_cert(const char* conf_path, const char* config_key,
                     const char* app_identity, const char* out_dir, const char* api_host) {
    if (!app_identity || !app_identity[0]) {
        std::fprintf(stderr, "[app-cert] no app_identity (pass --app-identity or set BBL_APP_IDENTITY)\n");
        return 2;
    }
    std::string conf;
    if (!read_file(conf_path, conf)) {
        std::fprintf(stderr, "[app-cert] cannot read %s (is BambuStudio installed + logged in?)\n", conf_path);
        return 2;
    }
    std::string pt = aes128_ecb_decrypt(conf, config_key);
    if (pt.find("\"token\"") == std::string::npos) {
        std::fprintf(stderr, "[app-cert] config decrypt failed or no token (wrong --config-key?)\n");
        return 2;
    }
    std::string token = json_str(pt, "token");
    std::string uid = json_num(pt, "user_id");
    if (token.empty()) {
        std::fprintf(stderr, "[app-cert] no cloud token in config\n");
        return 2;
    }
    std::fprintf(stderr, "[app-cert] token %zu chars, uid=%s; fetching get_app_cert...\n", token.size(), uid.c_str());

    obn::http::global_init();
    auto r = obn::appcert::fetch(api_host, token, uid, app_identity);
    if (!r.ok) {
        std::fprintf(stderr, "[app-cert] get_app_cert FAILED: http=%ld %s\n", r.http_status, r.error.c_str());
        return 1;
    }

    CreateDirectoryA(out_dir, nullptr);
    std::string od(out_dir);
    write_file(od + "\\app_cert.pem", r.cert_pem);
    write_file(od + "\\app_cert_id.txt", r.cert_id);
    if (!r.crl.empty())          write_file(od + "\\app_crl.pem", r.crl);
    if (!r.key_blob_b64.empty()) write_file(od + "\\app_key_blob.b64", r.key_blob_b64);
    std::fprintf(stderr,
        "[app-cert] *** SUCCESS: app cert cert_id=%s (%zu B cert, %zu B key blob) -> %s ***\n",
        r.cert_id.c_str(), r.cert_pem.size(), r.key_blob_b64.size(), out_dir);
    return 0;
}

}  // namespace bbl
