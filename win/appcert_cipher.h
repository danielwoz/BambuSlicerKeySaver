// appcert_cipher.h
//
// The symmetric cipher used to obfuscate the Bambu get_app_cert response
// "key" blob. It is AES-256 in CTR mode with one modification: the AES S-box
// is replaced by a fixed non-standard permutation (below). Key schedule,
// ShiftRows, and MixColumns are textbook AES-256; the swapped S-box is used in
// both SubBytes and the key schedule's SubWord. The blob key is a fixed
// constant (00 01 .. 1f), so no per-session or secret input is needed.
//
// CTR counter: keystream block i = E(KEY, nonce(12) || BE32(2+i)); the first
// data block uses counter 2 (counter 1 is reserved). Decrypt and encrypt are
// the same XOR-with-keystream operation (ctr_xor).
#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>

namespace appcert {

// Non-standard S-box (extracted from the plugin; a bijection, not the AES S-box).
static const uint8_t SBOX[256] = {
    0xc5, 0x57, 0x4d, 0x6c, 0x3a, 0x95, 0x05, 0xe0, 0xa3, 0xba, 0x36, 0x1f, 0xea, 0x51, 0x53, 0x3b,
    0x0e, 0x07, 0x4e, 0x64, 0x50, 0x04, 0x40, 0xe8, 0x62, 0x6e, 0x9f, 0x2d, 0x70, 0x8b, 0x28, 0x49,
    0xd5, 0xf9, 0x65, 0x8d, 0x74, 0x68, 0x7c, 0x6f, 0x0a, 0x6a, 0xb3, 0xaf, 0x38, 0xfe, 0x7e, 0x8a,
    0x47, 0x7f, 0xb0, 0x16, 0x00, 0xd4, 0x0f, 0x13, 0xc9, 0x80, 0x4a, 0xac, 0x8c, 0x4f, 0xa7, 0x98,
    0x83, 0x94, 0x5d, 0x48, 0xb4, 0xe9, 0x30, 0x19, 0x03, 0x99, 0x25, 0xbf, 0x8e, 0x41, 0xa0, 0xe4,
    0xc3, 0xcf, 0x2c, 0xab, 0xd2, 0x32, 0x1a, 0x0c, 0x11, 0xb5, 0x56, 0x63, 0x15, 0xa6, 0x69, 0x0b,
    0x88, 0xbb, 0x4c, 0x10, 0xcb, 0x75, 0xfa, 0x81, 0xf8, 0xcd, 0xa1, 0xd6, 0x97, 0xb7, 0x26, 0xc6,
    0x9e, 0xf1, 0x5f, 0xe5, 0xa9, 0x87, 0xc7, 0xdc, 0x8f, 0x7a, 0x86, 0x20, 0x9a, 0xd1, 0x08, 0xc2,
    0x84, 0x09, 0x33, 0x1b, 0xdd, 0x1e, 0xfd, 0x01, 0x71, 0xda, 0x77, 0x0d, 0xd7, 0xde, 0x93, 0xca,
    0xa5, 0xd0, 0xe6, 0x60, 0x89, 0x37, 0xc8, 0x21, 0x59, 0x79, 0x96, 0xad, 0x24, 0x34, 0xb9, 0x44,
    0xfc, 0xc1, 0xae, 0xf3, 0x82, 0x46, 0x43, 0x31, 0xe3, 0x2e, 0x4b, 0xfb, 0x92, 0x55, 0xed, 0x45,
    0x76, 0x6d, 0xaa, 0x3f, 0xf5, 0x5a, 0x91, 0x78, 0x22, 0x06, 0xff, 0xd9, 0x35, 0x7d, 0x7b, 0xdb,
    0x54, 0x12, 0x9c, 0xd8, 0xd3, 0xee, 0x17, 0x42, 0x52, 0x3e, 0xa4, 0xe7, 0xdf, 0x9d, 0xf2, 0xf4,
    0xef, 0x73, 0xf6, 0x5e, 0xb1, 0x5b, 0x18, 0xe2, 0x9b, 0x58, 0xa8, 0x2a, 0xe1, 0x3d, 0x90, 0xb6,
    0x1c, 0xbd, 0x61, 0xeb, 0x23, 0xa2, 0x67, 0x39, 0xf0, 0xbc, 0xb2, 0xf7, 0x85, 0x27, 0x72, 0xcc,
    0x29, 0xb8, 0x1d, 0xbe, 0x66, 0xc4, 0x2f, 0xce, 0x14, 0x3c, 0x6b, 0xec, 0x5c, 0x2b, 0xc0, 0x02,
};

// Fixed blob key: the 32 bytes 00 01 02 ... 1f.
static const uint8_t APPCERT_KEY[32] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
};

static const uint8_t RCON[14] =
    {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d};

// GF(2^8) multiply for MixColumns (AES reduction polynomial 0x11b).
inline uint8_t xtime(uint8_t a){ return (uint8_t)((a << 1) ^ ((a >> 7) * 0x1b)); }
inline uint8_t gmul(uint8_t a, uint8_t b){
    uint8_t r = 0;
    while (b){ if (b & 1) r ^= a; a = xtime(a); b >>= 1; }
    return r;
}

// AES-256 key expansion (Nk=8, Nr=14): 15 round keys of 16 bytes. SubWord uses SBOX.
inline void key_expand(const uint8_t key[32], uint8_t rk[15][16]){
    uint8_t w[60][4];
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 4; j++) w[i][j] = key[4*i + j];
    for (int i = 8; i < 60; i++){
        uint8_t t[4] = { w[i-1][0], w[i-1][1], w[i-1][2], w[i-1][3] };
        if (i % 8 == 0){
            uint8_t tmp = t[0];
            t[0] = SBOX[t[1]] ^ RCON[i/8 - 1];
            t[1] = SBOX[t[2]];
            t[2] = SBOX[t[3]];
            t[3] = SBOX[tmp];
        } else if (i % 8 == 4){
            for (int j = 0; j < 4; j++) t[j] = SBOX[t[j]];
        }
        for (int j = 0; j < 4; j++) w[i][j] = w[i-8][j] ^ t[j];
    }
    for (int r = 0; r < 15; r++)
        for (int c = 0; c < 4; c++)
            for (int j = 0; j < 4; j++) rk[r][4*c + j] = w[4*r + c][j];
}

// One AES-256 block encryption; column-major state (state[4*col + row]).
inline void aes_encrypt(const uint8_t in[16], const uint8_t rk[15][16], uint8_t out[16]){
    uint8_t s[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ rk[0][i];
    for (int round = 1; round <= 14; round++){
        for (int i = 0; i < 16; i++) s[i] = SBOX[s[i]];             // SubBytes
        uint8_t t[16];                                              // ShiftRows
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++) t[4*c + r] = s[4*((c + r) % 4) + r];
        memcpy(s, t, 16);
        if (round < 14){                                            // MixColumns
            for (int c = 0; c < 4; c++){
                uint8_t *col = &s[4*c];
                uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
                col[0] = gmul(a0,2) ^ gmul(a1,3) ^ a2 ^ a3;
                col[1] = a0 ^ gmul(a1,2) ^ gmul(a2,3) ^ a3;
                col[2] = a0 ^ a1 ^ gmul(a2,2) ^ gmul(a3,3);
                col[3] = gmul(a0,3) ^ a1 ^ a2 ^ gmul(a3,2);
            }
        }
        for (int i = 0; i < 16; i++) s[i] ^= rk[round][i];          // AddRoundKey
    }
    memcpy(out, s, 16);
}

// CTR keystream XOR (decrypt == encrypt). out[k] = in[k] ^ E(key, nonce||BE32(2 + k/16))[k%16].
inline void ctr_xor(const uint8_t key[32], const uint8_t nonce[12],
                    const uint8_t *in, size_t n, uint8_t *out){
    uint8_t rk[15][16];
    key_expand(key, rk);
    for (size_t i = 0; i * 16 < n; i++){
        uint8_t ctr[16]; memcpy(ctr, nonce, 12);
        uint32_t c = (uint32_t)(2 + i);
        ctr[12] = (uint8_t)(c >> 24); ctr[13] = (uint8_t)(c >> 16);
        ctr[14] = (uint8_t)(c >> 8);  ctr[15] = (uint8_t)c;
        uint8_t ks[16]; aes_encrypt(ctr, rk, ks);
        size_t blk = (n - i*16 < 16) ? (n - i*16) : 16;
        for (size_t j = 0; j < blk; j++) out[i*16 + j] = in[i*16 + j] ^ ks[j];
    }
}

} // namespace appcert
