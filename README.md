# SafeGuard AI — Core

The open-source core of **SafeGuard AI**, a privacy-first Shadow AI governance
platform. Contains the **Secure AI Gateway** (OpenAI-compatible proxy with inline
DLP redaction, on-the-fly streaming redaction, and quota) and the
**control-plane** (auth, policies, configurable regional rule packs, RAG,
telemetry/discovery, teams, integrations), plus the shared Rust crates
(`dlp`, `proto`, `embed`, `notify`).

**License:** AGPL-3.0-only. (The TypeScript SDK & shared types are MIT — see
[`safeguard-shared`](https://github.com/the-safeguard-ai/safeguard-shared).)

## Quick start (pre-built images, no build required)

```bash
cp .env.example .env                 # edit JWT_SECRET + your AI provider key
docker compose up -d                 # pulls pre-built images — nothing builds locally
```

Opens at **http://localhost:5174** (chat) and **http://localhost:5173** (admin dashboard).

## Build from source

```bash
cp .env.example .env        # set JWT_SECRET + a provider key
cargo run -p control-plane  # :8081
cargo run -p gateway        # :8080
```
Requires Postgres (pgvector) and Redis — start them with `docker compose up -d postgres redis`.

## Standalone deploy repo

For production or cloud VMs, use **[safeguard-deploy](https://github.com/the-safeguard-ai/safeguard-deploy)** — same stack, pinned images, `.env.example` tailored for self-host.

## Layout
- `crates/dlp` — DLP engine (detectors, regional packs, Presidio NER)
- `services/gateway` — the secure AI gateway
- `services/control-plane` — governance API
- `infra/migrations` — Postgres schema

## Container images
`ghcr.io/the-safeguard-ai/gateway` · `ghcr.io/the-safeguard-ai/control-plane`
(multi-arch, published on each `v*` tag).

Part of the [SafeGuard AI](https://github.com/the-safeguard-ai) suite.
