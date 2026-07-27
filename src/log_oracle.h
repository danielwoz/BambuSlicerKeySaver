// Fake debug-log oracle for runtime AES-key recovery.
// FAKE plaintext + its ciphertext under the (undisclosed) debug-log key.
// A known plaintext/ciphertext pair does NOT reveal the AES-128 key.
// Mirrors conf_oracle.h so the log key recovers self-contained, without
// needing a pre-existing encrypted debug_network_*.log.enc file.
#pragma once
static const unsigned char kLogOraclePlain[16] = {
    0x42,0x53,0x4c,0x4b,0x53,0x2e,0x6c,0x6f,0x67,0x2e,0x6f,0x72,
    0x61,0x63,0x6c,0x65,
};
static const unsigned char kLogOracleCipher[16] = {
    0x93,0x50,0x83,0x01,0x74,0x64,0xaa,0xc2,0x90,0x82,0xaa,0x31,
    0xac,0xe1,0xe3,0xae,
};
