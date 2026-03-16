#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# build_linux.sh — Cross-kompiliert Stone-Binaries für Linux (x86_64 + aarch64)
#
# Nutzung:
#   ./build_linux.sh          # baut beide Architekturen
#   ./build_linux.sh x86_64   # nur x86_64
#   ./build_linux.sh aarch64  # nur aarch64 (z.B. Raspberry Pi)
# ─────────────────────────────────────────────────────────────────────────────
set -e
export PATH="/opt/homebrew/opt/zig@0.14/bin:$PATH"
echo "Zig version: $(zig version)"
cd /Users/leon/stone-1

ARCH="${1:-all}"
BINS="--bin stone-master --bin stone-setup"

if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "all" ]; then
    echo "⚙️  Cross-compiling for x86_64-unknown-linux-gnu..."
    cargo zigbuild --release --target x86_64-unknown-linux-gnu $BINS 2>&1
    echo "✅ x86_64 done"
    ls -lh target/x86_64-unknown-linux-gnu/release/stone-master target/x86_64-unknown-linux-gnu/release/stone-setup
fi

if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "all" ]; then
    echo "⚙️  Cross-compiling for aarch64-unknown-linux-gnu..."
    cargo zigbuild --release --target aarch64-unknown-linux-gnu $BINS 2>&1
    echo "✅ aarch64 done"
    ls -lh target/aarch64-unknown-linux-gnu/release/stone-master target/aarch64-unknown-linux-gnu/release/stone-setup
fi

echo "BUILD DONE"
