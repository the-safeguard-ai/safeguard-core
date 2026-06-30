# SafeGuard AI — Core

The open-source core of **SafeGuard AI**, a privacy-first Shadow AI governance
platform. Contains the **Secure AI Gateway** (OpenAI-compatible proxy with inline
DLP redaction, on-the-fly streaming redaction, and quota) and the
**control-plane** (auth, policies, configurable regional rule packs, RAG,
telemetry/discovery, teams, integrations), plus the shared Rust crates
(`dlp`, `proto`, `embed`, `notify`).

**License:** AGPL-3.0-only. (The TypeScript SDK & shared types are MIT — see
[`safeguard-shared`](https://github.com/the-safeguard/safeguard-shared).)

## Self-host (no build required)
Use **[safeguard-deploy](https://github.com/the-safeguard/safeguard-deploy)** —
a single `docker compose up` that pulls pre-built images.

## Build from source
```bash
cp .env.example .env        # set JWT_SECRET + a provider key
cargo run -p control-plane  # :8081
cargo run -p gateway        # :8080
```
Requires Postgres (pgvector), Redis, and the Presidio sidecars — all wired in
`safeguard-deploy`.

## Layout
- `crates/dlp` — DLP engine (detectors, regional packs, Presidio NER)
- `services/gateway` — the secure AI gateway
- `services/control-plane` — governance API
- `infra/migrations` — Postgres schema

## Container images
`ghcr.io/the-safeguard/gateway` · `ghcr.io/the-safeguard/control-plane`
(multi-arch, published on each `v*` tag).

Part of the [SafeGuard AI](https://github.com/the-safeguard) suite.
