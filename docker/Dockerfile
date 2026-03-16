# ─────────────────────────────────────────────────────────────────────────────
# Stone Node – Docker Image (Multi-Arch: amd64 + arm64)
#
# Verwendet lokal cross-kompilierte Linux-Binaries (build_linux.sh).
# Kein Rust-Build im Container nötig → schnell & ressourcenschonend.
#
# Build:
#   ./build_linux.sh   # erst Linux-Binaries bauen (beide Architekturen)
#   docker build --platform linux/amd64  -f docker/Dockerfile -t stone-node:amd64  .
#   docker build --platform linux/arm64  -f docker/Dockerfile -t stone-node:arm64  .
#
# Run:
#   docker run -d -p 8080:8080 -p 4001:4001 -p 4001:4001/udp \
#     -e STONE_NODE_NAME=mein-node \
#     -e STONE_PASSWORD=MeinPasswort1! \
#     stone-node
# ─────────────────────────────────────────────────────────────────────────────

FROM debian:bookworm-slim

ARG TARGETARCH

# Minimal Runtime-Deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libsnappy1v5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Nicht-Root User
RUN useradd -m -s /bin/bash stone

# Verzeichnisse
RUN mkdir -p /opt/stone-node/stone_data /opt/stone-node/target/release && \
    chown -R stone:stone /opt/stone-node

WORKDIR /opt/stone-node

# Lokal cross-kompilierte Linux-Binaries reinkopieren (architektur-abhängig)
COPY target/binaries-${TARGETARCH}/stone-setup  target/release/stone-setup
COPY target/binaries-${TARGETARCH}/stone-master target/release/stone-master
RUN chmod +x target/release/stone-setup target/release/stone-master

# Entrypoint-Script
COPY docker/entrypoint.sh /opt/stone-node/entrypoint.sh
RUN chmod +x /opt/stone-node/entrypoint.sh

# Ports:
#   8080 = HTTP API + Dashboard
#   4001 = P2P TCP (libp2p) + QUIC (UDP)
EXPOSE 8080 4001 4001/udp

# Volumes für persistente Daten
VOLUME ["/opt/stone-node/stone_data"]

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8080/api/v1/health || exit 1

USER stone

ENTRYPOINT ["/opt/stone-node/entrypoint.sh"]
