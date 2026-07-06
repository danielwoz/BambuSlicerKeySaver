#!/bin/bash
set -e
cd "$(dirname "$0")"

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "error: this tool only runs on Linux" >&2
    exit 1
fi

# Install build and runtime dependencies — best-effort only. This is skipped
# when the toolchain is already present, and a failure (e.g. sudo needs a
# password) is non-fatal so the build/extract still proceeds.
missing=0
for t in g++ gcc make xxd curl unzip; do command -v "$t" >/dev/null 2>&1 || missing=1; done
if [[ $missing -eq 1 ]]; then
    if command -v apt-get >/dev/null 2>&1; then
        SUDO=""; [[ $EUID -ne 0 ]] && SUDO="sudo"
        $SUDO apt-get install -y \
            build-essential cmake ninja-build xxd curl unzip \
            libssl-dev libcurl4-openssl-dev zlib1g-dev \
          || echo "warning: dependency install failed — continuing (assuming they are present)" >&2
    else
        echo "warning: apt-get not found — ensure these are installed:" >&2
        echo "  build-essential cmake ninja-build xxd curl unzip libssl-dev libcurl4-openssl-dev zlib1g-dev" >&2
    fi
fi

make -C src -j"$(nproc)"

echo ""
./src/bambu_slicer_key_saver "$@"
