// Minimal AES-128-ECB decoder for the plugin's debug_network_*.log.enc numeric
// log. The key is loaded at runtime (BAMBU_LOG_ENC_KEY or <config>/log_enc.key),
// not hardcoded -- recover it with `bambu_host --find-log-key`. Prints the
// decrypted bytes to stdout; the log stores \x1f<id>\x1f<param>... \r\n records.
// Usage: declog <in.enc>
#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include "bambu_config.h"
#pragma comment(lib, "bcrypt.lib")

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: declog <in.enc>\n"); return 2; }
    unsigned char k[16];
    if (!bbl_config::load_log_key(k)) {
        std::fprintf(stderr, "error: no log key. Set BAMBU_LOG_ENC_KEY to a 16-byte key file "
                             "or place it at <APPDATA>\\BambuStudio\\log_enc.key "
                             "(recover it with: bambu_host --find-log-key <log.enc> --key-out ...).\n");
        return 2;
    }
    FILE* f = std::fopen(argv[1], "rb");
    if (!f) { std::fprintf(stderr, "open fail\n"); return 1; }
    std::fseek(f, 0, SEEK_END); long n = std::ftell(f); std::fseek(f, 0, SEEK_SET);
    std::vector<unsigned char> in(n);
    std::fread(in.data(), 1, n, f); std::fclose(f);
    n -= (n % 16);

    BCRYPT_ALG_HANDLE alg = nullptr; BCRYPT_KEY_HANDLE key = nullptr;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                      sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    BCryptGenerateSymmetricKey(alg, &key, nullptr, 0, k, 16, 0);

    std::vector<unsigned char> out(n);
    ULONG done = 0;
    NTSTATUS s = BCryptDecrypt(key, in.data(), (ULONG)n, nullptr, nullptr, 0,
                               out.data(), (ULONG)n, &done, 0);
    if (s != 0) { std::fprintf(stderr, "decrypt fail 0x%lx\n", (unsigned long)s); return 1; }
    fwrite(out.data(), 1, done, stdout);
    return 0;
}
