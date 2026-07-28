// appcert_decrypt_blob_test.cpp
//
// Tests for the get_app_cert blob cipher (appcert_cipher.h).
//
// The vectors marked "real" are taken from an actual captured get_app_cert
// session (response nonce 303c8f52...). They are all functions of public
// inputs only -- the fixed key, the nonce, and the SKEY struct *header* -- so
// they contain no private key material: p/q live at offset 32+ and are never
// embedded here. A synthetic round-trip covers the full framing without any
// real secret.
//
// Build:  g++ -O2 -o appcert_test appcert_decrypt_blob_test.cpp && ./appcert_test
#include "appcert_cipher.h"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>

using namespace appcert;

static int g_total = 0, g_fail = 0;

static void hexparse(const char *h, uint8_t *out, int n){
    for (int i = 0; i < n; i++){ unsigned v; sscanf(h + 2*i, "%2x", &v); out[i] = (uint8_t)v; }
}
static void expect_bytes(const char *name, const uint8_t *got, const char *exphex, int n){
    g_total++;
    uint8_t exp[256]; hexparse(exphex, exp, n);
    if (memcmp(got, exp, n) == 0){ printf("  PASS  %s\n", name); return; }
    g_fail++;
    printf("  FAIL  %s\n        got ", name);
    for (int i = 0; i < n; i++) printf("%02x", got[i]);
    printf("\n        exp %s\n", exphex);
}
static void expect_true(const char *name, bool cond){
    g_total++;
    if (cond) printf("  PASS  %s\n", name);
    else { g_fail++; printf("  FAIL  %s\n", name); }
}

// keystream block for the real capture nonce (public: E(KEY, nonce||BE32(ctr)))
static void ks_block(const uint8_t nonce[12], uint32_t ctr, uint8_t out[16]){
    uint8_t rk[15][16]; key_expand(APPCERT_KEY, rk);
    uint8_t b[16]; memcpy(b, nonce, 12);
    b[12] = (uint8_t)(ctr >> 24); b[13] = (uint8_t)(ctr >> 16);
    b[14] = (uint8_t)(ctr >> 8);  b[15] = (uint8_t)ctr;
    aes_encrypt(b, rk, out);
}

// Optional: decrypt a real blob file end-to-end and sanity-check the recovered
// key. No secret is printed; we only assert structural validity (SKEY magic and
// that p, q look like 1024-bit odd RSA primes). Run: appcert_test <blob-file>.
static void run_blob_file(const char *path){
    printf("== Real end-to-end: decrypt %s ==\n", path);
    FILE *f = fopen(path, "rb");
    if (!f){ printf("  FAIL  cannot open %s\n", path); g_fail++; g_total++; return; }
    std::vector<uint8_t> blob;
    { uint8_t buf[4096]; size_t r; while ((r = fread(buf,1,sizeof buf,f)) > 0) blob.insert(blob.end(), buf, buf+r); }
    fclose(f);
    if (blob.size() < 32 + 288){ printf("  FAIL  blob too short\n"); g_fail++; g_total++; return; }
    uint32_t ctlen = blob[28] | (blob[29]<<8) | (blob[30]<<16) | ((uint32_t)blob[31]<<24);
    if (32 + ctlen > blob.size()) ctlen = (uint32_t)blob.size() - 32;
    std::vector<uint8_t> pt(ctlen);
    ctr_xor(APPCERT_KEY, blob.data(), blob.data() + 32, ctlen, pt.data());
    expect_true("SKEY magic present",
                pt[0]==0x59 && pt[1]==0x45 && pt[2]==0x4b && pt[3]==0x53);
    const int H = 32, L = 128;             // p at [H, H+L), q at [H+L, H+2L)
    const uint8_t *p = pt.data() + H, *q = pt.data() + H + L;
    expect_true("p is 1024-bit and odd (RSA prime shape)", (p[0] & 0x80) && (p[L-1] & 1));
    expect_true("q is 1024-bit and odd (RSA prime shape)", (q[0] & 0x80) && (q[L-1] & 1));
    expect_true("p != q", memcmp(p, q, L) != 0);
}

int main(int argc, char **argv){
    uint8_t nonce[12]; hexparse("303c8f522a171b9a40dc8901", nonce, 12);
    uint8_t blk[16];

    printf("== S-box properties ==\n");
    { bool seen[256] = {false}, bij = true;
      for (int i = 0; i < 256; i++){ if (seen[SBOX[i]]) bij = false; seen[SBOX[i]] = true; }
      expect_true("S-box is a bijection (0..255 permutation)", bij);
      expect_true("S-box is NOT the standard AES S-box (SBOX[0] != 0x63)", SBOX[0] != 0x63); }

    printf("== Real keystream blocks: E(KEY, nonce||BE32(ctr)), nonce=303c8f52... ==\n");
    ks_block(nonce, 2, blk); expect_bytes("keystream block 0 (ctr=2)", blk, "c6bf1cc1b40dcc16443034d6dabe7b81", 16);
    ks_block(nonce, 3, blk); expect_bytes("keystream block 1 (ctr=3)", blk, "a5dee6b960b56cf67aa24081f505a4b8", 16);
    ks_block(nonce, 4, blk); expect_bytes("known-answer oracle (ctr=4)", blk, "a155d92625a1eb00d8901fef52a8f105", 16);

    printf("== Real blob transform: first 32 ciphertext bytes -> SKEY header ==\n");
    // The real blob's ciphertext[0:32] and the SKEY struct header it decrypts to.
    // Header = magic|version|size words only; the private p/q begin at offset 32.
    uint8_t ct32[32], pt32[32];
    hexparse("9ffa5792b50dcc16443834d65abe7b8125dee6b9e0b56cf6faa240817505a4b8", ct32, 32);
    ctr_xor(APPCERT_KEY, nonce, ct32, 32, pt32);
    expect_bytes("decrypt(real ct[0:32]) == SKEY header",
                 pt32, "59454b5301000000000800008000000080000000800000008000000080000000", 32);
    expect_true("magic == 'SKEY' (0x534b4559)",
                pt32[0]==0x59 && pt32[1]==0x45 && pt32[2]==0x4b && pt32[3]==0x53);

    printf("== Round-trip on a synthetic SKEY (no real key material) ==\n");
    uint8_t nonce2[12]; hexparse("000102030405060708090a0b", nonce2, 12);
    uint8_t pt[704], ct[704], back[704];
    memset(pt, 0, sizeof pt);
    pt[0]=0x59; pt[1]=0x45; pt[2]=0x4b; pt[3]=0x53; pt[4]=1;   // "SKEY" magic + version
    for (int i = 32; i < 704; i++) pt[i] = (uint8_t)(i*7 + 3); // deterministic filler for p/q/...
    ctr_xor(APPCERT_KEY, nonce2, pt, 704, ct);                 // encrypt
    ctr_xor(APPCERT_KEY, nonce2, ct, 704, back);               // decrypt
    expect_true("CTR round-trip is identity (704 bytes)", memcmp(pt, back, 704) == 0);
    expect_true("ciphertext differs from plaintext", memcmp(pt, ct, 704) != 0);
    // CTR is a stream: decrypting with the wrong nonce must NOT recover the header.
    uint8_t wrong[704]; ctr_xor(APPCERT_KEY, nonce, ct, 704, wrong);
    expect_true("wrong nonce does not recover the SKEY magic",
                !(wrong[0]==0x59 && wrong[1]==0x45 && wrong[2]==0x4b && wrong[3]==0x53));

    for (int i = 1; i < argc; i++) run_blob_file(argv[i]);

    printf("\n%d/%d tests passed\n", g_total - g_fail, g_total);
    return g_fail ? 1 : 0;
}
