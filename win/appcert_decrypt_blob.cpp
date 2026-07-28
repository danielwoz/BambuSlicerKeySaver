// appcert_decrypt_blob.cpp
//
// Recovers the Bambu application RSA private key from a get_app_cert response
// "key" blob, with no proprietary plugin and no secret input. See
// appcert_cipher.h for the cipher; this file adds the blob framing + SKEY parse.
//
// Blob framing (704 bytes for a 2048-bit key):
//   nonce(12) | tag(16, unused by CTR) | ct_len(4, little-endian) | ciphertext
// Plaintext "SKEY" struct:
//   magic 0x534b4559 ("SKEY", little-endian) | version | six size words
//   | p(128) | q(128) | dp(128) | dq(128) | qinv(128)   (all big-endian)
//
// Build:  g++ -O2 -o decrypt_appcert_blob appcert_decrypt_blob.cpp
// Usage:  decrypt_appcert_blob <blob-file>
#include "appcert_cipher.h"
#include <cstdio>
#include <vector>

static void print_hex(const char *label, const uint8_t *b, int n){
    printf("%s = ", label);
    for (int i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(int argc, char **argv){
    if (argc < 2){ fprintf(stderr, "usage: %s <blob-file> (recovers the app RSA private key)", argv[0]); return 2; }
    const char *path = argv[1];
    FILE *f = fopen(path, "rb");
    if (!f){ fprintf(stderr, "cannot open %s\n", path); return 1; }
    std::vector<uint8_t> blob;
    { uint8_t buf[4096]; size_t r; while ((r = fread(buf,1,sizeof buf,f)) > 0) blob.insert(blob.end(), buf, buf+r); }
    fclose(f);
    if (blob.size() < 32){ fprintf(stderr, "blob too short\n"); return 1; }

    const uint8_t *nonce = blob.data();
    uint32_t ctlen = blob[28] | (blob[29]<<8) | (blob[30]<<16) | ((uint32_t)blob[31]<<24);
    if (32 + ctlen > blob.size()) ctlen = (uint32_t)blob.size() - 32;

    std::vector<uint8_t> pt(ctlen);
    appcert::ctr_xor(appcert::APPCERT_KEY, nonce, blob.data() + 32, ctlen, pt.data());

    print_hex("nonce", nonce, 12);
    uint32_t magic = pt[0] | (pt[1]<<8) | (pt[2]<<16) | ((uint32_t)pt[3]<<24);
    printf("magic = 0x%08x  (%s)\n", magic, magic == 0x534b4559 ? "SKEY - OK" : "MISMATCH");
    if (magic != 0x534b4559){ fprintf(stderr, "not a SKEY struct - wrong key/framing\n"); return 2; }

    const int H = 32, L = 128;
    print_hex("p   ", pt.data() + H + 0*L, L);
    print_hex("q   ", pt.data() + H + 1*L, L);
    print_hex("dp  ", pt.data() + H + 2*L, L);
    print_hex("dq  ", pt.data() + H + 3*L, L);
    print_hex("qinv", pt.data() + H + 4*L, L);
    printf("\nRecovered the RSA CRT private key (p, q, dp, dq, qinv).\n");
    return 0;
}
