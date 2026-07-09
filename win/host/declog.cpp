// Minimal AES-128-ECB decoder for the plugin's debug_network_*.log.enc numeric
// log. Key = "yyuBcftO2jkZeucy". Prints the decrypted bytes to stdout; the log
// stores \x1f<id>\x1f<param>... \r\n records. Usage: declog <in.enc>
#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstdlib>
#include <vector>
#pragma comment(lib, "bcrypt.lib")

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: declog <in.enc>\n"); return 2; }
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
    unsigned char k[16]; memcpy(k, "yyuBcftO2jkZeucy", 16);
    BCryptGenerateSymmetricKey(alg, &key, nullptr, 0, k, 16, 0);

    std::vector<unsigned char> out(n);
    ULONG done = 0;
    NTSTATUS s = BCryptDecrypt(key, in.data(), (ULONG)n, nullptr, nullptr, 0,
                               out.data(), (ULONG)n, &done, 0);
    if (s != 0) { std::fprintf(stderr, "decrypt fail 0x%lx\n", (unsigned long)s); return 1; }
    fwrite(out.data(), 1, done, stdout);
    return 0;
}
