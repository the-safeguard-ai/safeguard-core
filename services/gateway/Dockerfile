# SafeGuard AI — gateway image. Build from the repo root:
#   docker build -f services/gateway/Dockerfile -t safeguard/gateway .
# (the build context must be the workspace root so shared crates resolve.)

FROM rust:1.85-slim AS builder
WORKDIR /app

# OpenSSL for reqwest's default TLS; pkg-config to find it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the whole workspace (runtime SQLx queries need no DB at build time).
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY services ./services

RUN cargo build --release -p gateway

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 safeguard
COPY --from=builder /app/target/release/gateway /usr/local/bin/gateway

USER safeguard
ENV GATEWAY_BIND=0.0.0.0:8080
EXPOSE 8080
CMD ["gateway"]
