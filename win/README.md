# BambuSlicerKeySaver — Windows port (`win/`)

Windows (MSVC) build of the key-recovery tooling. It recovers the RSA-2048
private key the Bambu networking plugin (`bambu_networking.dll`) uses to sign
device commands, validates the recovered key, and provides helpers for the
plugin's AES configuration- and log-file keys.

## Components

- **`keysaver_core`** — the OS-independent key-reconstruction core, built from
  `../src` (`reconstruct.cpp`, `bigint.cpp`, `envelope.cpp`, `version.cpp`,
  `vendored/BigIntModExp.cpp`). No third-party dependencies.
- **`core_selftest.exe`** — round-trips a synthetic RSA-2048 key through the
  reconstruction path and asserts the recovered `p, q, d, N` match.
- **`bambu_host.exe`** — loads the plugin, drives it through a signing operation
  against a local stand-in broker, recovers the private key from the signing
  arithmetic, and validates it (`p·q == N`, `e·d ≡ 1`, and against known public
  signatures). Also hosts the AES config/log-key helpers.
- **`declog.exe`** — standalone AES-128-ECB decoder for the plugin's numeric
  `debug_network_*.log.enc` files.
- **`app_key_selftest.exe`** — offline round-trip for the raw-buffer factor
  recovery, using a synthetic modulus (no plugin required).

## Build

Requires Visual Studio 2022+ (MSVC), CMake, and Ninja. OpenSSL is optional and
not needed for reconstruction.

From a Developer prompt (or after sourcing `vcvars64.bat`):

```sh
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -S win -B win/build
cmake --build win/build
```

Always build `Release` — a Debug build runs the big-integer factor recovery
roughly 10× slower.

## Run

Verify the core first:

```sh
win/build/core_selftest.exe        # prints "[selftest] PASS", exit 0
```

Recover and validate the plugin's signing key end to end (downloads the target
plugin build, runs the capture, and self-validates):

```sh
win/build/bambu_host.exe --auto
```

Other modes:

| Command | Purpose |
|---|---|
| `bambu_host --from-disk` | Re-read and re-validate a **previously extracted** key cached at `%APPDATA%\BambuStudio\slicer_key.pem`. This reuses a prior capture's result — it is not a fresh extraction, and the file is not provisioned by BambuStudio. |
| `bambu_host --capture-selftest` | Offline reconstruction self-test (no plugin). |
| `bambu_host --fetch-plugin --plugin-version <v>` | Download a plugin build into the local cache. |
| `bambu_host --find-config-key` | Recover the AES-128 key that decrypts `BambuNetworkEngine.conf`. |
| `bambu_host --find-log-key` | Recover the AES-128 key that decrypts the plugin's `debug_network_*.log.enc`. |
| `declog <in.log.enc> <out.txt>` | Decode a plugin debug log with a known key. |

Recovered key material and decrypted configuration are never written to the
repository; see the ignore rules in the top-level `.gitignore`.
