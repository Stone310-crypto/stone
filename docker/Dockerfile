# ─────────────────────────────────────────────────────────────────────────────
# Stone Node – Docker Image
#
# Multi-Stage Build:
#   1. Builder: Rust Toolchain kompiliert stone-setup + stone-master
#   2. Runtime: Minimales Debian mit nur den nötigen Libs
#
# Build:
#   docker build -f docker/Dockerfile -t stone-node .
#
# Run:
#   docker run -d -p 8080:8080 -p 4001:4001 -p 4001:4001/udp \
#     -e STONE_NODE_NAME=mein-node \
#     -e STONE_PASSWORD=MeinPasswort1! \
#     stone-node
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Builder ─────────────────────────────────────────────────────────
FROM rust:1.85-bookworm AS builder

# System-Deps für RocksDB, libp2p, OpenSSL
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    clang \
    libclang-dev \
    librocksdb-dev \
    libsnappy-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cargo.toml + Cargo.lock zuerst kopieren → Dependency-Layer cachen
COPY Cargo.toml Cargo.lock* ./
# Leere src erstellen damit cargo fetch funktioniert
RUN mkdir -p src/bin && \
    echo 'fn main() {}' > src/bin/setup.rs && \
    echo 'fn main() {}' > src/bin/master_server.rs && \
    echo 'fn main() {}' > src/bin/auth_server.rs && \
    echo 'fn main() {}' > src/bin/db_dump.rs && \
    echo 'fn main() {}' > src/bin/stone_keygen.rs && \
    echo 'fn main() {}' > src/bin/stone_publish_update.rs && \
    echo '' > src/lib.rs && \
    cargo fetch 2>/dev/null || true

# Echten Source kopieren
COPY src/ src/

# Release Build (nur die Binaries die wir brauchen)
RUN cargo build --release --bin stone-setup --bin stone-master 2>&1 && \
    strip target/release/stone-setup target/release/stone-master

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

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

# Binaries aus Builder kopieren
COPY --from=builder /build/target/release/stone-setup  target/release/stone-setup
COPY --from=builder /build/target/release/stone-master target/release/stone-master

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
