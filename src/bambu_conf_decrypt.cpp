// bambu_conf_decrypt — decode BambuStudio's encrypted BambuNetworkEngine.conf.
//
// The stock libbambu_networking plugin persists its cloud session state (user
// token, refresh token, user_id, account, region, device serial) to
// <config>/BambuNetworkEngine.conf, encrypted with AES-ECB and a fixed global
// key baked (obfuscated) into the plugin. Plaintext is JSON, zero-padded to the
// 16-byte block boundary.
//
// The key is NOT hardcoded here — it is recovered from the plugin at runtime by
// bambu_slicer_key_saver and written to `network_engine.key`. This tool reads
// that key file, so distributing this binary does not distribute the key.
//
// Usage:
//   bambu_conf_decrypt [--key KEYFILE] [CONF]      # decrypt (default: config dir)
//   bambu_conf_decrypt --encrypt [--key KEYFILE] IN
//
// If --key is omitted, network_engine.key is looked for next to CONF, then in
// the OS BambuStudio config dir, then in the current directory.
//
// Build: g++ -std=c++17 -O2 bambu_conf_decrypt.cpp -lcrypto -o bambu_conf_decrypt

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <openssl/evp.h>

static bool slurp(const std::string& path, std::vector<unsigned char>& out) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END); long n = std::ftell(f); std::fseek(f, 0, SEEK_SET);
    if (n < 0) { std::fclose(f); return false; }
    out.resize((size_t)n);
    size_t got = std::fread(out.data(), 1, out.size(), f);
    std::fclose(f);
    return got == out.size();
}

static bool aes_ecb(bool enc, const std::vector<unsigned char>& key,
                    const std::vector<unsigned char>& in, std::vector<unsigned char>& out) {
    if (in.size() % 16) { std::fprintf(stderr, "input not a multiple of 16 bytes\n"); return false; }
    const EVP_CIPHER* c = key.size() == 16 ? EVP_aes_128_ecb()
                        : key.size() == 24 ? EVP_aes_192_ecb()
                        : key.size() == 32 ? EVP_aes_256_ecb() : nullptr;
    if (!c) { std::fprintf(stderr, "unexpected key length %zu\n", key.size()); return false; }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = EVP_CipherInit_ex(ctx, c, nullptr, key.data(), nullptr, enc ? 1 : 0) == 1;
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    out.resize(in.size() + 16);
    int l1 = 0, l2 = 0;
    ok = ok && EVP_CipherUpdate(ctx, out.data(), &l1, in.data(), (int)in.size()) == 1;
    ok = ok && EVP_CipherFinal_ex(ctx, out.data() + l1, &l2) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (ok) out.resize((size_t)(l1 + l2));
    return ok;
}

static std::string bambustudio_config_dir() {
#if defined(_WIN32)
    if (const char* a = std::getenv("APPDATA")) return std::string(a) + "\\BambuStudio";
#elif defined(__APPLE__)
    if (const char* h = std::getenv("HOME")) return std::string(h) + "/Library/Application Support/BambuStudio";
#else
    if (const char* x = std::getenv("XDG_CONFIG_HOME")) return std::string(x) + "/BambuStudio";
    if (const char* h = std::getenv("HOME")) return std::string(h) + "/.config/BambuStudio";
#endif
    return ".";
}

static bool find_key(const std::string& conf, std::vector<unsigned char>& key) {
    std::vector<std::string> cands;
    auto sl = conf.rfind('/');
    if (sl != std::string::npos) cands.push_back(conf.substr(0, sl) + "/network_engine.key");
    cands.push_back(bambustudio_config_dir() + "/network_engine.key");
    cands.push_back("network_engine.key");
    for (auto& c : cands)
        if (slurp(c, key) && (key.size() == 16 || key.size() == 24 || key.size() == 32)) {
            std::fprintf(stderr, "using key: %s (%zu-bit)\n", c.c_str(), key.size() * 8);
            return true;
        }
    return false;
}

int main(int argc, char** argv) {
    bool encrypt = false;
    std::string path, keyfile;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--encrypt") encrypt = true;
        else if (a == "--key" && i + 1 < argc) keyfile = argv[++i];
        else path = a;
    }
    if (path.empty()) path = bambustudio_config_dir() + "/BambuNetworkEngine.conf";

    std::vector<unsigned char> key;
    if (!keyfile.empty()) {
        if (!slurp(keyfile, key)) { std::fprintf(stderr, "cannot read key %s\n", keyfile.c_str()); return 1; }
    } else if (!find_key(path, key)) {
        std::fprintf(stderr,
            "no key found. Run bambu_slicer_key_saver first (writes network_engine.key)\n"
            "or pass --key <network_engine.key>.\n");
        return 1;
    }

    std::vector<unsigned char> in, out;
    if (!slurp(path, in)) { std::fprintf(stderr, "cannot read %s\n", path.c_str()); return 1; }

    if (encrypt) {
        while (in.size() % 16) in.push_back(0);
        if (!aes_ecb(true, key, in, out)) return 2;
        std::fwrite(out.data(), 1, out.size(), stdout);
        return 0;
    }
    if (!aes_ecb(false, key, in, out)) return 2;
    while (!out.empty() && out.back() == 0) out.pop_back();
    std::fwrite(out.data(), 1, out.size(), stdout);
    std::fputc('\n', stdout);
    return 0;
}
