# BambuSlicerKeySaver

A fork of [BambuStudio](https://github.com/bambulab/BambuStudio) (pinned at
`v02.07.01.57`) whose sole purpose is to **save the slicer signing key one
time** to disk.

## Why

BambuStudio derives its per-request signing material on the fly through a very
expensive code path that runs on every cloud/print operation. Doing that work
once and caching the resulting key:

- **Saves CPU.** The normal derivation path is costly; a one-shot key save
  replaces it with a cheap read of a saved `.pem`.
- **Enables AGPL compliance and interoperability.** With the key available as a
  plain file, open-source tooling can interoperate with Bambu services without
  re-implementing or hiding the proprietary derivation, keeping the stack
  inspectable and AGPL-friendly.

## What this is

This repository is not the full slicer. It is the minimal **`bambu_slicer_key_saver`**
application: a self-contained key saver that loads the stock networking plugin,
drives it once, captures the RSA-CRT components, and reconstructs the slicer's
full private key. The only file retained from upstream BambuStudio is the
bundled slicer certificate at `resources/cert/slicer_base64.cer`, which the key
saver reads at its original location.

The key is **fully self-recovered**: the public modulus is reconstructed as
`N = p·q` from the captured factors, so nothing is hardcoded and the tool is not
tied to any version-specific modulus constant. (Pass `--modulus` to supply a
known modulus as an optional cross-check.)

By default the key is written to the operating system's BambuStudio user config
directory as `slicer_key.pem` — a PKCS#1 RSA private key — alongside
`slicer_pubkey.pem` (on Linux, `$XDG_CONFIG_HOME/BambuStudio` or
`~/.config/BambuStudio`). Override the destination with `--out PATH`.

## Layout

```
run.sh                     one-shot build + key-save helper
resources/cert/            slicer_base64.cer (kept from BambuStudio, unchanged)
src/                       the key saver application
  Makefile                 builds src/bambu_slicer_key_saver
  main.cpp, daemon.cpp …   key saver core
  vendored/                vendored BigInt / MQTT helpers
  shims/                   runtime shims (watchdog defeat)
  daemon/CMakeLists.txt    builds the embedded headless bambu-daemon
  bambu/                   Slic3r::bambu net sources (BambuStudio src/bambu)
```

## Platform support

⚠️ **Only Linux has been tested so far.** The build, the runtime shims, and the
key-extraction path have only been exercised on Linux. The Windows and macOS
config-directory locations are wired up but unverified — getting the key saver
running on those platforms is expected to need further work.

## Build & run (Linux)

```bash
./run.sh                 # installs deps, builds, saves the key to the config dir
```

or manually:

```bash
make -C src -j"$(nproc)"
./src/bambu_slicer_key_saver               # writes <config dir>/slicer_key.pem
./src/bambu_slicer_key_saver --out other.pem   # or choose an explicit path
```

The key saver locates `slicer_base64.cer` automatically (it looks under
`resources/cert/` relative to the binary, then in standard BambuStudio install
locations); pass `--cert /path/to/slicer_base64.cer` to override.

## License

Derived from BambuStudio, which is licensed under the GNU AGPL-3.0.
