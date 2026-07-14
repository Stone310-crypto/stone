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
cd /Users/leon/stone

ARCH="${1:-all}"
BINS="--bin stone-master --bin stone-setup"
VPN_DIR="/Users/leon/stone/stone_vpn"

if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "all" ]; then
    echo "⚙️  Cross-compiling for x86_64-unknown-linux-gnu..."
    cargo zigbuild --release --target x86_64-unknown-linux-gnu $BINS 2>&1
    echo "✅ x86_64 stone done"
    ls -lh target/x86_64-unknown-linux-gnu/release/stone-master target/x86_64-unknown-linux-gnu/release/stone-setup
    echo ""
    echo "⚙️  Building stonevpn for x86_64..."
    cd "$VPN_DIR" && cargo zigbuild --release --target x86_64-unknown-linux-gnu 2>&1 && cd /Users/leon/stone
    echo "✅ x86_64 stonevpn done"
    ls -lh "$VPN_DIR/target/x86_64-unknown-linux-gnu/release/stonevpn"
fi

if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "all" ]; then
    echo "⚙️  Cross-compiling for aarch64-unknown-linux-gnu..."
    cargo zigbuild --release --target aarch64-unknown-linux-gnu $BINS 2>&1
    echo "✅ aarch64 stone done"
    ls -lh target/aarch64-unknown-linux-gnu/release/stone-master target/aarch64-unknown-linux-gnu/release/stone-setup
    echo ""
    echo "⚙️  Building stonevpn for aarch64..."
    cd "$VPN_DIR" && cargo zigbuild --release --target aarch64-unknown-linux-gnu 2>&1 && cd /Users/leon/stone
    echo "✅ aarch64 stonevpn done"
    ls -lh "$VPN_DIR/target/aarch64-unknown-linux-gnu/release/stonevpn"
fi

echo "BUILD DONE"
