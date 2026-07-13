#pragma once
// rng_tap — capture every random draw the genuine plugin makes.
//
// The plugin's ONLY bcrypt import is BCryptGenRandom (verified via objdump), i.e.
// it is the plugin's single source of fresh randomness. Hooking it captures the
// client AES key + nonces the plugin generates while building the get_app_cert
// request (encAppKey + aes256) and the create_task signature. BCryptGenRandom is
// an ordinary dynamic import, so it can be hooked without modifying the plugin.
//
// Output: appended to $BBL_RNG_LOG (default "rng_tap.log") -- one line per draw:
//   [rng] cb=<n> caller=plugin+0x.. bt=[plugin+0x..,..] bytes=<hex>

namespace bbl {
void start_rng_tap();   // idempotent; hooks bcrypt!BCryptGenRandom
void stop_rng_tap();
long long rng_tap_hits();
void start_file_trace(); // idempotent; hooks CreateFile*/GetFileAttributes* -> $BBL_FILE_TRACE
}
