# SafeGuard AI — control-plane image. Build from the repo root:
#   docker build -f services/control-plane/Dockerfile -t safeguard/control-plane .
# (the build context must be the workspace root so shared crates resolve.)

FROM rust:1.85-slim AS builder
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY services ./services

RUN cargo build --release -p control-plane

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 safeguard
COPY --from=builder /app/target/release/control-plane /usr/local/bin/control-plane

USER safeguard
ENV CONTROL_PLANE_BIND=0.0.0.0:8081
EXPOSE 8081
CMD ["control-plane"]
