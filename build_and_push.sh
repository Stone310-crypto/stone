#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# build-and-push.sh — Baut beide Docker-Images und pusht sie zu GHCR
#
# Voraussetzung (einmalig):
#   echo $GITHUB_TOKEN | docker login ghcr.io -u Unrooted-dev --password-stdin
#
# Nutzung:
#   ./build-and-push.sh              # baut + pusht beide Images
#   ./build-and-push.sh stone        # nur Stone-Node
#   ./build-and-push.sh web          # nur Unrooted-Web
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REGISTRY="ghcr.io/unrooted-dev"
STONE_SRC="/Users/leon/stone-1"
WEB_SRC="$(cd "$(dirname "$0")" && pwd)"

TARGET="${1:-all}"

# ── Stone-Node Image (Multi-Arch: amd64 + arm64) ────────────────────────────
build_stone() {
    echo ""
    echo "  ┌───────────────────────────────────────────┐"
    echo "  │  🔨 Building stone-node image...          │"
    echo "  │     (amd64 + arm64 / Raspberry Pi)        │"
    echo "  └───────────────────────────────────────────┘"
    echo ""

    if [ ! -f "$STONE_SRC/Cargo.toml" ]; then
        echo "❌ Stone-Source nicht gefunden: $STONE_SRC"
        echo "   Setze STONE_SRC_PATH=/pfad/zu/stone"
        exit 1
    fi

    # 1) Linux-Binaries auf dem Mac cross-kompilieren (beide Architekturen)
    echo "  ⚙️  Cross-compiling Linux binaries (x86_64 + aarch64)..."
    bash "$STONE_SRC/build_linux.sh"

    # 2) Binaries in staging-Verzeichnisse kopieren (Docker TARGETARCH-kompatibel)
    echo "  📁 Staging binaries..."
    mkdir -p "$STONE_SRC/target/binaries-amd64" "$STONE_SRC/target/binaries-arm64"
    cp "$STONE_SRC/target/x86_64-unknown-linux-gnu/release/stone-setup"  "$STONE_SRC/target/binaries-amd64/stone-setup"
    cp "$STONE_SRC/target/x86_64-unknown-linux-gnu/release/stone-master" "$STONE_SRC/target/binaries-amd64/stone-master"
    cp "$STONE_SRC/target/aarch64-unknown-linux-gnu/release/stone-setup"  "$STONE_SRC/target/binaries-arm64/stone-setup"
    cp "$STONE_SRC/target/aarch64-unknown-linux-gnu/release/stone-master" "$STONE_SRC/target/binaries-arm64/stone-master"

    # Prüfen ob alle Binaries existieren
    for arch in amd64 arm64; do
        for bin in stone-setup stone-master; do
            if [ ! -f "$STONE_SRC/target/binaries-$arch/$bin" ]; then
                echo "❌ Binary nicht gefunden: target/binaries-$arch/$bin"
                exit 1
            fi
        done
    done

    # 3) Docker-Images pro Architektur bauen
    echo "  📦 Building Docker image (amd64)..."
    docker build \
        --platform linux/amd64 \
        -f "$STONE_SRC/docker/Dockerfile" \
        -t "$REGISTRY/stone-node:amd64" \
        "$STONE_SRC"

    echo "  📦 Building Docker image (arm64)..."
    docker build \
        --platform linux/arm64 \
        -f "$STONE_SRC/docker/Dockerfile" \
        -t "$REGISTRY/stone-node:arm64" \
        "$STONE_SRC"

    # 4) Beide Images pushen + Multi-Arch Manifest erstellen
    echo "📤 Pushing stone-node (amd64)..."
    docker push "$REGISTRY/stone-node:amd64"
    echo "📤 Pushing stone-node (arm64)..."
    docker push "$REGISTRY/stone-node:arm64"

    echo "📦 Creating multi-arch manifest..."
    docker manifest create --amend "$REGISTRY/stone-node:latest" \
        "$REGISTRY/stone-node:amd64" \
        "$REGISTRY/stone-node:arm64"
    docker manifest annotate "$REGISTRY/stone-node:latest" \
        "$REGISTRY/stone-node:amd64" --arch amd64 --os linux
    docker manifest annotate "$REGISTRY/stone-node:latest" \
        "$REGISTRY/stone-node:arm64" --arch arm64 --os linux
    docker manifest push "$REGISTRY/stone-node:latest"

    echo "✅ stone-node gepusht (amd64 + arm64)"
}

# ── Unrooted-Web Image ───────────────────────────────────────────────────────
build_web() {
    echo ""
    echo "  ┌───────────────────────────────────────────┐"
    echo "  │  🔨 Building unrooted-web image...        │"
    echo "  └───────────────────────────────────────────┘"
    echo ""

    docker build \
        -t "$REGISTRY/unrooted-web:latest" \
        "$WEB_SRC"

    echo "📤 Pushing unrooted-web..."
    docker push "$REGISTRY/unrooted-web:latest"
    echo "✅ unrooted-web gepusht"
}

# ── Ausführen ─────────────────────────────────────────────────────────────────
case "$TARGET" in
    stone)  build_stone ;;
    web)    build_web ;;
    all)    build_stone; build_web ;;
    *)
        echo "Nutzung: $0 [stone|web|all]"
        exit 1
        ;;
esac

echo ""
echo "  ┌───────────────────────────────────────────────────────┐"
echo "  │  ✅ Fertig! Images auf $REGISTRY gepusht.            │"
echo "  │                                                       │"
echo "  │  Auf dem Server:                                      │"
echo "  │    docker-compose pull && docker-compose up -d        │"
echo "  └───────────────────────────────────────────────────────┘"
echo ""
