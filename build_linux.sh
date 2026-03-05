#!/bin/bash
set -e
export PATH="/opt/homebrew/opt/zig@0.14/bin:$PATH"
echo "Zig version: $(zig version)"
cd /Users/leon/Desktop/stone
echo "Starting cross-compile (stone-master + stone-setup)..."
cargo zigbuild --release --target x86_64-unknown-linux-gnu --bin stone-master --bin stone-setup 2>&1
echo "BUILD DONE"
ls -lh target/x86_64-unknown-linux-gnu/release/stone-master target/x86_64-unknown-linux-gnu/release/stone-setup
