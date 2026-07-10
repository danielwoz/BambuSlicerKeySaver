#pragma once
// aes_tap — capture the AES key(s) the plugin expands, to recover the get_app_cert
// session key K (which is OpenSSL-DRBG-generated, so NOT visible via BCryptGenRandom).
//
// Mechanism: OpenSSL's AES-NI key expansion (aesni_set_encrypt_key) contains the
// rare `aeskeygenassist` instruction (66 0F 3A DF). We scan the plugin's runtime
// executable pages for its FIRST round (imm8=0x01), set a DR execute-breakpoint
// there (writes no code -> works despite the plugin's SEC_NO_CHANGE .text and
// VMProtect), and at the hit read the candidate key pointers (RCX=userKey on the
// Win64 ABI, R8=key schedule) + XMM regs. Every expanded key is logged; the
// get_app_cert K is identified offline by GCM-verifying against encAppKey.
//
// Output: appended to $BBL_AES_LOG (default "aes_tap.log").

namespace bbl {
void start_aes_tap();   // scan + arm DR breakpoints on aeskeygenassist sites
void stop_aes_tap();
long long aes_tap_hits();
}
