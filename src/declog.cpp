// declog — decode the plugin's debug_network_*.log.enc numeric log (Linux/OpenSSL
// port of win/host/declog.cpp). The log is AES-128-ECB encrypted with the plugin's
// fixed global log key "yyuBcftO2jkZeucy" (the second baked AES key, alongside the
// conf key "i4crL3LESLnWapLS"). Records are \x1f<msg_id>\x1f<param>...\r\n where
// msg_id indexes the plugin's format-string table and the params are logged verbatim.
//
// Usage: declog <in.enc>            # raw decrypted bytes to stdout
//        declog --pretty <in.enc>   # \x1f rendered as '|' for readability
//
// Build: g++ -std=c++17 -O2 declog.cpp -lcrypto -o declog

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <openssl/evp.h>

// The log encryption key is loaded from a file rather than hardcoded.
// Search order: BAMBU_LOG_ENC_KEY env var, then ~/.config/BambuStudio/log_enc.key.
static const unsigned char* load_log_key() {
    static unsigned char key[16];
    static bool loaded = false;
    if (loaded) return key;
    loaded = true;

    // Check environment variable first.
    const char* env_path = std::getenv("BAMBU_LOG_ENC_KEY");
    if (env_path && env_path[0]) {
        FILE* f = std::fopen(env_path, "rb");
        if (f) {
            size_t n = std::fread(key, 1, 16, f);
            std::fclose(f);
            if (n == 16) {
                std::fprintf(stderr, "loaded log key from env: %s\n", env_path);
                return key;
            }
        }
        std::fprintf(stderr, "warning: BAMBU_LOG_ENC_KEY=%s failed to load\n", env_path);
    }

    // Try platform-specific config directory.
    const char* home = std::getenv("HOME");
    if (home && home[0]) {
        char path[512];
        snprintf(path, sizeof(path), "%s/.config/BambuStudio/log_enc.key", home);
        FILE* f = std::fopen(path, "rb");
        if (f) {
            size_t n = std::fread(key, 1, 16, f);
            std::fclose(f);
            if (n == 16) {
                std::fprintf(stderr, "loaded log key from: %s\n", path);
                return key;
            }
        }
    }

    std::fprintf(stderr, "error: no log encryption key found. Set BAMBU_LOG_ENC_KEY or place key at ~/.config/BambuStudio/log_enc.key\n");
    return nullptr;
}

int main(int argc, char** argv) {
    bool pretty = false;
    const char* path = nullptr;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--pretty")) pretty = true;
        else path = argv[i];
    }
    if (!path) { std::fprintf(stderr, "usage: declog [--pretty] <in.enc>\n"); return 2; }

    FILE* f = std::fopen(path, "rb");
    if (!f) { std::fprintf(stderr, "open fail: %s\n", path); return 1; }
    std::fseek(f, 0, SEEK_END); long n = std::ftell(f); std::fseek(f, 0, SEEK_SET);
    if (n < 16) { std::fclose(f); std::fprintf(stderr, "too short\n"); return 1; }
    std::vector<unsigned char> in((size_t)n);
    if (std::fread(in.data(), 1, in.size(), f) != in.size()) { std::fclose(f); return 1; }
    std::fclose(f);
    n -= (n % 16);  // ECB: whole 16-byte blocks only

    const unsigned char* log_key = load_log_key();
    if (!log_key) return 1;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 1;
    std::vector<unsigned char> out((size_t)n + 16);
    int l1 = 0, l2 = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, log_key, nullptr) == 1;
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    ok = ok && EVP_DecryptUpdate(ctx, out.data(), &l1, in.data(), (int)n) == 1;
    ok = ok && EVP_DecryptFinal_ex(ctx, out.data() + l1, &l2) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) { std::fprintf(stderr, "decrypt fail\n"); return 1; }

    size_t total = (size_t)(l1 + l2);
    if (pretty)
        for (size_t i = 0; i < total; ++i) out[i] = (out[i] == 0x1f) ? '|' : out[i];
    std::fwrite(out.data(), 1, total, stdout);
    return 0;
}
