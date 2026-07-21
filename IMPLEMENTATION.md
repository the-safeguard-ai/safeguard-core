# SafeGuard AI — Implementation Tracker

> Living checklist. `[ ]` = not started · `[~]` = in progress · `[x]` = done & verified.
> Status legend per item updated as we go. See `SafeGuard_AI_PRD.docx` for product requirements.

**Last updated:** 2026-06-30 — Phase 0 + Gateway (§1A) + Control-Plane (§1C) + Admin dashboard (§1D) + **Browser extension (§1E)** complete. Latest pass: comprehensive AI-site coverage (incl. Grok), extension **account login** (no key needed), **real-time dashboard** (extension events → alerts/graph, 8s polling), **Shadow AI drill-down** (outcome + data-type breakdown + recent events), full **Policies editing** (all fields) and **Usage Logs** (provider filter + pagination + refresh), token **refresh** endpoint, and a **network egress backstop** (MAIN-world fetch/XHR guard that aborts leaking requests at the wire, detect-and-block only — see §1E-QA for the manual click-test). Extension does token-free in-browser DLP on free AI sites (the core Shadow AI protection) + reports to a new dashboard "Shadow AI" discovery view. **End-user chat app (`apps/chat`) now built** — a Grok-style secure AI chat (replicated from current Grok screenshots) that streams through the gateway with inbound DLP surfaced inline; gateway gained JWT dual-auth + CORS so it works. **Marketing website (`apps/landing`) now built** — a full ~25-page, x.ai-caliber site with dark/light toggle, mega-menu nav, and 13 custom animated SVG visuals (honest content, no fabricated proof). All three frontends build/typecheck/serve. **MCP server (`services/mcp`) now built** — a Bun/TS stdio Model Context Protocol server exposing six tools: `dlp_scan`/`dlp_redact`/`dlp_detectors` (local, zero-token, mirror `crates/dlp`), `secure_chat` (asks a model through the gateway → inbound redaction + policy + audit), and `shadow_ai_report`/`list_policies` (read-only governance). Typechecks; smoke-tested over stdio (initialize + tools/list + tool calls). Landing `/developers/mcp` flipped from "Coming soon" to live. **VS Code extension (`extensions/vscode`) now built** — a local OpenAI-compatible proxy (`127.0.0.1:7575/v1`, Bun-bundled to CommonJS) that forwards AI coding-assistant traffic through the gateway (token injected, SSE piped back, `x-safeguard-redactions` surfaced), with a local DLP pre-scan (off/warn/block), SecretStorage sign-in + token refresh, status-bar item, and commands. Headless proxy tests pass (5/5); typecheck + bundle clean. Landing `/developers/ide-extension` flipped to live. **Presidio deep-scan now fully wired into the gateway** — `crates/dlp` gained an async `scan_deep` that merges Presidio ML/NER entities with the regex hot path (entities redact-only so NER false positives never hard-block; overlap-deduped; 4s timeout; fails open to the regex result when the sidecar is down), and the gateway calls it for inbound prompts + non-streaming responses whenever an active policy sets `deep_scan` (the resolved `deep_scan` flag was previously dead). `dlp` tests 5→8, full `cargo build --workspace` green. **Teams / org management + member invites now built** — control-plane gained a `teams` CRUD module (member counts; deleting a team detaches its members) and a link-based **invite flow** (admin creates an `invited` member → one-time SHA-256-hashed token, 7-day expiry → public `/accept-invite` sets a password, activates, and signs in; no SMTP). Admin `Users & Teams` page rebuilt with invite-link surfacing/copy, per-member edit/remove/resend, and a Teams panel. New migration `0005_invites.sql`; admin typecheck/build green. **Quota tiers now real + observable** — plan limits, the Redis key format, and reset math are centralized in `proto::plan` (free=200, team=20k, enterprise=unlimited); the gateway emits `x-safeguard-quota-*` headers + a structured 429 (over-limit attempts rolled back), and a new control-plane `GET /api/metrics/quota` reads the same counter to drive a live quota meter on the admin dashboard. **RAG now built** — new shared `crates/embed` (OpenAI-compatible embeddings + chunker), control-plane `/api/rag/documents` ingest (chunk→embed→pgvector) + `/api/rag/search`, an admin **Knowledge** page (ingest + retrieval tester), and the gateway injects retrieved context for `rag_enabled` policies (embeds the redacted prompt, cosine-retrieves top-5 org chunks, prepends a system message; fails open). **Webhooks + Slack/Teams now built** — new shared `crates/notify` fans risk alerts out to installed integrations (Slack/Teams `{text}`, generic JSON webhooks), fired best-effort from both the gateway (block/redaction) and control-plane (extension telemetry); admin Extensions page gained per-integration URL config + a live "send test" (and dropped fabricated star ratings). **OSS packaging now done** — Apache-2.0 `LICENSE` + `NOTICE`, `CONTRIBUTING`/`CODE_OF_CONDUCT`/`SECURITY`, `.github` CI (cargo + bun + Docker builds) and issue/PR templates, multi-stage Dockerfiles for both Rust services with the app containers now enabled in `infra/docker-compose.yml`. **All Phase-2 build items are complete.** **Category-B follow-ups now built too:** (1) **outbound DLP on live-streamed tokens** — `gateway/stream_dlp.rs` redacts SSE response chunks on the fly with a 64-char cross-chunk holdback; (2) **configurable regional rule packs** — `crates/dlp/packs.rs` + `GET /api/rule-packs` + admin Policies pills (UK/India/Canada/Australia/Brazil/Spain/France/South Africa/Singapore, all off by default); (3) **org DLP policy fetch into the browser extension** — dual-auth `GET /api/extension/policy` + extension `policy.ts` sync (sign-in/startup/page-load), driving in-page + egress enforcement from the org's configured detectors/mode; (4) **server-side conversation persistence** — control-plane conversation/message write endpoints (redacted at rest; zero-retention stores no bodies) + chat-app `lib/sync.ts` best-effort sync & sign-in hydration. Workspace `cargo fmt`/`clippy -D warnings`/`test` all green (dlp 8→12); admin/chat/extension typecheck+build green. **Manual-test caveats for all not-yet-live work are tracked in `QA_CHECKLIST.md`** (A Presidio, B Teams/invites, C quota tiers, D RAG, E egress backstop, F webhooks, G Docker self-host, H streaming/regional-packs/extension-policy/chat-persistence) for the §1F end-to-end QA stage — the only remaining Phase-1 work. All Phase-1 surfaces (gateway, control-plane, dashboard, browser extension, chat, landing, MCP, VS Code) now built.

**Strategy note (from product discussion):** the browser extension — not the hosted chat — is the primary protection for free web-app AI usage (ChatGPT/Gemini free tiers) because it needs **no company LLM tokens**. The sanctioned chat app is the safe alternative employees are nudged toward; its model backend is **per-org configurable (cloud OR self-hosted)** via `policies.route`.

---

## 0. Decisions (locked)

| Concern | Decision |
|---|---|
| Backend language/framework | Rust + **Axum** (Tokio/Hyper/Tower) |
| LLM backends | **Cloud (BYO OpenAI/Anthropic) + Self-hosted (Ollama/vLLM)** from day one |
| Frontend | **Vite + React on Bun** (migrated off Next.js) |
| DLP engine | **Hybrid:** Rust regex rules (hot path) + Presidio sidecar (deep NER) |
| Database | PostgreSQL 16 + **pgvector** |
| Cache / rate limit | Redis |
| Auth | JWT + refresh, OIDC-ready, Argon2 |
| Deploy | **Docker Compose** self-host |

---

## Phase 0 — Foundations  ✅

- [x] Monorepo scaffold: Bun workspaces (`package.json`) + Cargo workspace (`Cargo.toml`)
- [x] Directory layout: `apps/`, `services/`, `extensions/`, `packages/`, `crates/`, `infra/`
- [x] `infra/docker-compose.yml` — Postgres+pgvector, Redis, Presidio (+ `initdb/` extensions)
- [x] `packages/types` — shared TS types mirroring Rust API contracts
- [x] `packages/sdk-ts` — typed client (control-plane + gateway SSE streaming)
- [x] `crates/proto` — shared Rust types + OpenAI-compatible schema
- [x] `crates/dlp` — DLP engine: regex detectors + Presidio client + **5 passing tests**
- [x] SQLx migration setup (`infra/migrations/0001_init.sql`) — full schema from mockData contracts
- [x] Gateway skeleton (`services/gateway`) — health + `/v1/chat/completions` w/ in/out DLP + cloud/self-host routing
- [x] Control-plane skeleton (`services/control-plane`) — health + lazy DB pool
- [x] Root README + dev quickstart; `.env.example`; `rust-toolchain.toml`; `.gitignore`
- [x] Full `cargo build --workspace` green; TS typecheck green
- [x] CI: `cargo fmt`/`clippy`/`test`/`build` + `bun` typecheck/test/build + Docker image builds (`.github/workflows/ci.yml`)

---

## Phase 1 — MVP: Personal tier + Gateway + Extension

### 1A. Secure AI Gateway (`services/gateway`) — CORE  ✅ (verified end-to-end)
- [x] Axum app skeleton + config (env, provider keys, base URLs)
- [x] OpenAI-compatible route: `POST /v1/chat/completions`  · [ ] `/v1/embeddings`
- [x] **Auth middleware** — API key (SHA-256 hashed) → resolve org + user + plan  · [ ] JWT
- [x] **Rate-limit / quota middleware** — Redis daily window per org (per-plan limits)
- [x] **Policy resolution** — load org policies from DB, pick routing target
- [x] **Inbound DLP scan** (calls `crates/dlp`) — redact / block / flag
- [x] **Upstream forward — cloud** (`reqwest` → OpenAI, configurable base URL)
- [x] **Upstream forward — self-hosted** (Ollama/vLLM, OpenAI-compatible)
- [x] **SSE streaming pass-through** to client (`text/event-stream`)
- [x] **Outbound DLP scan** of model response (non-streaming; streaming deferred)
- [x] **Audit logging** to Postgres — stores **redacted** bodies, never raw PII
- [x] **Zero-retention mode** — bodies NULL, counts still tracked
- [x] Risk-alert emission (block → high; redactions → medium)
- [ ] Anthropic native adapter + per-policy (not per-org) routing  *(follow-up)*
- [x] **Presidio deep-scan call on `deep_scan` policies** — gateway calls `dlp::scan_deep` (regex hot path + Presidio NER) for inbound prompts and non-streaming responses whenever any active policy has `deep_scan = true`; regex stays authoritative for block/flag, ML entities redact-only, overlap-deduped, fails open (4s timeout) to the regex result when the sidecar is down
- [x] **Outbound DLP on live-streamed tokens (cross-chunk)** — gateway `stream_dlp.rs` transforms the upstream SSE stream on the fly: accumulates `delta.content`, redacts settled text, re-emits OpenAI-compatible chunks, holding back a 64-char tail so a PII match straddling chunk boundaries is caught before emission. Engaged only when a redact policy applies (else passthrough); non-content frames + `[DONE]` preserved. 2 tests (email split across frames; clean passthrough)

### 1B. DLP Engine (`crates/dlp`)
- [x] Rule engine (regex/rules) — email, API key, secret/token, phone, credit card, SSN
- [x] **International detectors** — IBAN, IP address, passport, E.164 phone (country-agnostic)
- [x] **Configurable regional rule packs** — per-org, off by default (no country hardcoded). New `crates/dlp/packs.rs` adds region-specific detectors (UK NINO, India Aadhaar/PAN, Canada SIN, Australia TFN/ABN, Brazil CPF/CNPJ, Spain DNI, France INSEE, South Africa ID, Singapore NRIC) grouped into named packs, appended to `rules::detectors()` so they only match when a policy enables their pattern keys. Control-plane `GET /api/rule-packs` exposes the catalog; admin Policies editor surfaces them as opt-in pills (toggle a whole pack on/off). 4 new dlp tests (incl. "off until selected")
- [x] Actions: `redact` (`[REDACTED:type]`), `block`, `flag`
- [x] Presidio client (deep-scan path) — `presidio.rs`
- [ ] Export rules as JSON (for browser/IDE extension reuse)
- [x] Unit tests (table-driven PII samples → expected redactions)

### 1C. Control Plane API (`services/control-plane`)  ✅ (verified end-to-end)
- [x] Axum + SQLx skeleton + Postgres connection + CORS
- [x] **Auth**: register/login, JWT issue/refresh, Argon2, RBAC (`require_manage`). **Register seeds 3 default DLP policies** (Personal Data, Secrets & API Keys, Financial & ID Numbers — international detectors, redact, enabled) so every org is protected from day one; admins layer industry/regional policies on top
- [x] **DLP source-of-truth = configured policies**: redaction (gateway audit + chat persistence at-rest) is policy-driven, so day-one default policies ensure no raw PII is ever stored for a normally-registered org
- [x] `GET /api/metrics/kpis` — replaces `dashboardKPIs` (computed live)
- [x] `GET /api/metrics/usage` — replaces `usageChartData` (10-day series)
- [x] `GET /api/alerts` — replaces `riskAlerts`
- [x] `GET /api/activity` — replaces `recentActivity`
- [x] `GET/POST/PATCH/DELETE /api/policies` — replaces `policyRules`
- [x] `GET/POST/PATCH/DELETE /api/users` + `GET /api/teams` (team upsert) — replaces `users`
- [x] `GET /api/logs` — usage logs (filter by provider, paginate)
- [x] `GET /api/integrations` + install/uninstall — replaces `extensions`
- [x] `GET/PATCH /api/org/settings` — name, zero-retention, settings JSON
- [x] `GET /api/conversations` + `/conversations/:id/messages` — chat history
- [x] **API/enrollment keys**: `GET/POST /api/keys`, `DELETE /api/keys/:id` (plaintext shown once; SHA-256 stored) + Settings UI to generate/copy/revoke — links the browser extension to the org
- [x] **User-invite flow** — `POST /api/users` now creates an `invited` member (no password) and returns a one-time invite token; public `GET /api/auth/invite?token` (preview) + `POST /api/auth/accept-invite` (set password → activate → log in); `POST /api/users/:id/invite` re-issues the link. SHA-256-hashed tokens, 7-day expiry, one pending invite per user. Link-based (no SMTP), self-host friendly. New `invites` table (migration 0005)
- [ ] Token refresh endpoint + activity-feed writes on mutations  *(follow-up)*

### 1D. Frontends (Vite + React + Bun)
- [x] Tailwind 4 + `globals.css` design tokens ported (`apps/admin/src/index.css`)
- [x] `packages/sdk-ts` — typed client for control-plane + gateway (SSE)
- [x] **`apps/admin`** — ported off Next.js (React Router + TanStack Query), live data, builds + typechecks + serves
  - [x] login/register + protected routes + auth context (JWT in localStorage)
  - [x] dashboard · [x] policies (CRUD) · [x] users · [x] logs · [x] extensions · [x] settings (zero-retention toggle)
- [x] No `mockData.ts` imports (admin uses live API only)
- [ ] Browser-based click-through verification (served + CORS verified; full E2E pending)
- [ ] Extract shared components into `packages/ui` (currently colocated in `apps/admin`)  *(refactor)*
- [x] **`apps/chat`** (end-user) — **Grok-style** secure AI chat (replicated from current Grok UI screenshots, SafeGuard-branded), builds + typechecks + serves on :5174
  - [x] Light theme + Inter, collapsible sidebar (rail ↔ full), grouped history (Today/Last 7 Days/Earlier), profile footer
  - [x] Centered welcome state + pill **Composer** (auto-grow textarea, `+`, Fast/Expert model dropdown, mic, black send/voice button, Enter-to-send/Shift+Enter newline, Stop while streaming)
  - [x] Conversation view: right-aligned user bubbles, full-width assistant, **SafeGuard meta line** ("redacted N sensitive items before sending" + "Thought for Xs"), action row (copy/vote/regenerate), code-block rendering
  - [x] **SSE streaming through the gateway** (`/v1/chat/completions`, stream); 401→refresh-once retry; 422→**blocked** notice; 502→friendly "no model backend"
  - [x] **DLP surfaced inline** via gateway `x-safeguard-redactions` header (the product differentiator)
  - [x] Search/history modal (filter, "Current" badge, relative times, preview pane)
  - [x] Login/register reusing control-plane `/api/auth`; **same account as the dashboard** (auto-linked to org)
  - [x] Per-user conversation history in `localStorage` (full multi-chat UX without new persistence endpoints)
  - [x] **Server-side conversation persistence** — control-plane gained write endpoints (`PUT /api/conversations/:id` create/rename, `DELETE`, `POST /api/conversations/:id/messages` append; idempotent on client-supplied UUIDs); chat app `lib/sync.ts` mirrors localStorage history to them best-effort (create on first send, user turn on send, assistant turn on stream-complete, delete) and hydrates prior history on sign-in (`loadServerHistory`, local copies win). **Privacy:** content is redacted with the org's policies before storage (raw PII never persisted); zero-retention orgs store no message bodies. localStorage stays primary (fail-open)
  - [ ] Markdown rendering beyond code blocks; attachments/voice (placeholder buttons)  *(follow-up)*
  - [ ] Browser click-through QA (built + serves; not yet exercised against a live upstream)
- [x] **Gateway dual-auth** — `gate` middleware now accepts a **user JWT** (chat app/IDE) in addition to org API keys (extension/SDK); resolves org plan/zero-retention from claims. Added **CORS** (browser clients) + exposes `x-safeguard-redactions`.
- [x] **`apps/landing`** — full **multi-page marketing website** (Vite + React + Bun + Tailwind 4, `:5175`), x.ai-caliber. Builds + typechecks + serves; all routes return 200.
  - [x] **Dark default + light toggle** (`ThemeProvider`, no-flash inline script, persisted), Geist/Geist Mono, marketing palette tokens
  - [x] **Mega-menu Navbar** (Platform/Solutions/Developers/Resources/Company) + mobile slide-in nav + rich Footer
  - [x] **13 custom animated SVG visuals** (`components/visuals/`): RedactionFlow (hero), ShadowRadar, DLPPipeline, EgressShield, ArchitectureDiagram, GlobeRulePacks (international, not country-hardcoded), GatewayProxyViz, StreamTokens, PolicyStates, AuroraMesh, Counter, ProviderLogos — all `prefers-reduced-motion` aware. Static `favicon.svg` + `og.svg`.
  - [x] **~25 pages, all fully built**: Home; Platform ×6; Solutions ×4; Developers ×5 (MCP + IDE **now live**); Pricing; Security; Company (about/careers/news/contact); Resources (guides/changelog); Legal ×3; designed 404
  - [x] **Honest content** — no fabricated customers/logos/testimonials/metrics; capability-based stats; "works with" provider marquee
  - [x] UI kit (Button/Badge/Card/SectionHeading/Reveal/Marquee/Accordion/Tabs/CodeBlock/Pricing) + per-page SEO meta (`useDocumentMeta`)
  - [ ] Route-level code-splitting (React.lazy) to trim the 151 kB-gzip bundle  *(perf follow-up)*
  - [ ] Wire the contact form to a real endpoint (front-end only today)  *(follow-up)*

### 1E. Browser Extension (`extensions/browser`, Manifest V3)  ✅ (built + DLP-tested)
- [x] Scaffold (TS + Bun bundler → `dist/`, loadable unpacked)
- [x] Content scripts: ChatGPT, Claude, Gemini, Copilot, Perplexity
- [x] Intercept submit (Enter + send-click) and paste on prompt fields
- [x] Local DLP (`src/dlp.ts` mirrors `crates/dlp`) + **6 passing bun tests**
- [x] Enforcement modes: **redact / block / educate(flag)** — token-free, in-browser
- [x] Service worker → telemetry to control-plane; options page + popup stats
- [x] Control-plane ingest (`POST /api/telemetry/events`, API-key auth) + `shadow_events` table
- [x] `GET /api/discovery` + **dashboard "Shadow AI" page** (admin app)
- [x] **Comprehensive site coverage** — ChatGPT, Grok (standalone + in X), Gemini, Claude, Copilot, Perplexity, DeepSeek, Mistral, Meta AI, Qwen, Kimi, HuggingChat, Poe, Pi, Character.AI, You.com, Phind, Genspark (+ generic fallback)
- [x] **Account login in extension** — sign in with email/password → auto-linked to org (JWT + auto-refresh); org key now optional (IT path)
- [x] Per-event **outcome** (redact/block/flag) captured; events raise dashboard alerts
- [x] **Admin drill-down** — discovery shows redacted/blocked per tool, data-type breakdown, recent-events table
- [x] **Resilient enforcement** — enforce BEFORE reporting; all `chrome.*` calls guarded so an extension reload ("context invalidated") or telemetry failure can't let a prompt through. Generic `phone` detector added (local numbers without `+`).
- [x] **Full-field replacement** — paste lands, then the whole field is replaced with the scanned-clean version (fixes "redacted + original both present" duplication on ProseMirror). React-controlled inputs handled via native value setter; contenteditable via select-all + `execCommand insertText`. Submit-blocking (Enter + send-click) is the hard guarantee.
- [x] **Network egress backstop (MAIN-world fetch/XHR scan)** — `src/egress.ts` injected `world: "MAIN"` at `document_start`, wraps `fetch` + `XMLHttpRequest` and **aborts at the wire** any request whose body still contains sensitive data. **Detect-and-block only — never mutates bodies.** Educate mode observes/warns without blocking. Config bridged from the isolated content script via `postMessage` (MAIN world has no `chrome.*`); block/flag events relayed back to telemetry + banner. Toggle in Options (*Network egress backstop*, on by default). Fails open on its own errors. ⚠️ *Needs real-browser click-test — see §1E-QA.*
- [ ] Live-site selector tuning + file-upload interception (needs real-browser QA; `block` mode is the guaranteed-safe fallback)
- [x] **Fetch org DLP policies into extension** — new dual-auth control-plane `GET /api/extension/policy` returns the union of the org's enabled-policy detector patterns + a single recommended enforcement mode (block > redact > flag). Extension `policy.ts` fetches + caches it (JWT with refresh, else org key), synced on sign-in (popup), on install/startup (background), and on each AI-site page load (content script); `resolvePolicies()` uses the org's detectors + mode (driving the egress backstop too), falling back to the built-in default. Forward-compatible: the in-browser engine ignores pattern keys it doesn't mirror (e.g. regional packs). Fails open — a fetch failure keeps the cached/default policy
- [ ] Auto-generate `dlp.ts` from exported Rust rules (avoid drift)  *(follow-up)*

#### §1E-QA. Egress backstop — manual click-test (I can't run a browser)
Build first: `cd extensions/browser && bun run build`, then reload the unpacked
extension at `chrome://extensions` (the new MAIN-world script + manifest change
require a full reload, not just a refresh).

1. **Block-mode hard stop (the key test).** Options → mode = **block**, *Network
   egress backstop* = on. On chatgpt.com type a prompt with a fake email +
   credit-card number and hit send. Expect: request aborted, red banner
   *"SafeGuard blocked a network request…"*, nothing in the conversation, and a
   `block`/`egress` event in the dashboard Shadow AI view. In DevTools → Network
   the `…/conversation` request should show as **(failed)/cancelled**.
2. **Grok specifically** (the site the DOM layer missed). Repeat on grok.com and
   x.com/i/grok — confirm the send is stopped at the network layer.
3. **Redact mode still fails safe.** Mode = redact. Normal paste should redact
   on-page as before; the egress layer should only fire (and block) if PII
   somehow slips past — confirm clean prompts send normally with **no** false
   blocks.
4. **Educate mode = observe only.** Mode = educate. Sending PII should show the
   amber *"network request carried N sensitive item(s)"* warning but the request
   must still go through.
5. **Toggle off.** Uncheck *Network egress backstop*, save. Confirm requests are
   no longer intercepted at the network layer (DOM layer still active).
6. **No page breakage.** Browse a normal (clean) chat session on 2–3 sites and
   confirm streaming responses, file pickers, and login flows all work — the
   wrapper must be invisible when nothing sensitive is present.

> If any site breaks, flip the toggle off and report the failing host + the
> Network-tab request; the wrapper fails open on its own errors but a site that
> reads `window.fetch` in an unusual way may need an allowlist exception.

### 1F. Phase-1 End-to-End Verification
- [ ] `docker compose up` brings full stack live
- [ ] Scenario: login → set PII policy → chat with PII → redaction + dashboard alert
- [ ] Gateway integration test: email+API key prompt → redaction + audit row + (zero-retention) no body
- [ ] SSE tokens stream end-to-end through gateway
- [ ] Browser ext: paste fake card on chatgpt.com → block/redact + telemetry shows in dashboard

---

## Phase 2 — OSS + Team

- [x] **Presidio deep-scan fully integrated into gateway DLP** — `dlp::scan_deep` merges Presidio NER entities with the regex hot path (entities redact-only so NER false positives never hard-block; overlap-deduped; 4s timeout; fails open). Gateway invokes it only when a `deep_scan` policy is active. `localhost:5001` for host-run dev; `presidio-analyzer:3000` documented for in-stack. 3 new dlp tests (8 total pass)
- [x] **Teams / org management UI + API** — control-plane `teams.rs` (list w/ member counts, create, rename, delete; detach-not-delete members on team removal) + the link-based member **invite flow** (see §1C). Admin `Users & Teams` page rebuilt: invite members (one-time link surfaced + copy), edit role/team/status, remove, resend invite, and a Teams panel (add/rename/delete with live counts). New public `/accept-invite` page (preview + set password → auto sign-in). `cargo build --workspace` + admin typecheck/build green
- [x] **Quota plans / tiered limits (free vs team)** — limits + Redis key format + reset math centralized in `proto::plan` (single source of truth: free=200, team=20k, enterprise=unlimited). Gateway enforces the daily window and now emits `x-safeguard-quota-{limit,remaining,used,reset}` headers on every proxied response + a structured 429 (rejected attempts rolled back so the counter can't drift). New control-plane `GET /api/metrics/quota` reads the **same** Redis counter (best-effort; degrades to `used:0` if Redis is down). Admin dashboard shows a live quota meter (plan chip, used/limit bar, remaining + reset). QA caveats in `QA_CHECKLIST.md §C`
- [x] **RAG**: `POST /api/rag/documents` (chunk → embed → pgvector), `GET /api/rag/documents` (list w/ chunk counts), `DELETE /api/rag/documents/:id`, `GET /api/rag/search` (cosine top-k). New shared `crates/embed` (OpenAI-compatible `/v1/embeddings`, char-based chunker, pgvector text-literal helper; 4 tests). Admin **Knowledge** page (ingest + retrieval tester). Embeddings configurable (OpenAI key or self-hosted `EMBEDDING_BASE_URL`); routes return a clear error when unconfigured
- [x] **Gateway injects retrieved context for RAG-enabled policies** — for `rag_enabled` policies it embeds the **redacted** latest user message, cosine-retrieves the org's top-5 chunks (`db::retrieve_chunks`, hnsw), and prepends them as a system message. Best-effort/fails open (20s timeout; injects nothing on error or empty KB). QA caveats in `QA_CHECKLIST.md §D`
- [x] **`services/mcp`** — Model Context Protocol server (Bun/TS, stdio). Six tools:
  - [x] Local, zero-token (mirror `crates/dlp`): `dlp_scan`, `dlp_redact`, `dlp_detectors`
  - [x] `secure_chat` — asks a model through the gateway (streaming; reads `x-safeguard-redactions`); maps blocked/quota/no-backend to clear messages
  - [x] `shadow_ai_report` (`/api/discovery` + `/labels`) and `list_policies` (`/api/policies`) — read-only governance, token-gated
  - [x] Configurable via `SAFEGUARD_TOKEN` / `SAFEGUARD_GATEWAY_URL` / `SAFEGUARD_CONTROL_PLANE_URL`; `bun run mcp`; client config docs in `services/mcp/README.md`
- [x] **`extensions/vscode`** — local OpenAI-compatible proxy (`127.0.0.1:7575/v1`) → gateway:
  - [x] `proxy.ts` — `/v1/chat/completions`, `/v1/completions`, `/v1/models`; injects the real token, pipes SSE back, mirrors `x-safeguard-redactions`, retries once on 401 via refresh. Decoupled from `vscode` for headless tests (5/5 pass)
  - [x] Local DLP pre-scan (off/warn/block, mirrors `crates/dlp`) — `block` refuses to send secrets before they leave the machine
  - [x] `auth.ts` — SecretStorage sign-in (control-plane) + token refresh; or `safeguard.apiKey` for IT rollout
  - [x] Status-bar item + commands (sign in/out, start/stop, copy base URL, status, logs); `contributes.configuration` settings; Bun bundle → `dist/extension.js` (CJS, `vscode` external)
- [x] **Webhooks + Slack integration (Extensions page)** — new shared `crates/notify` delivers risk alerts to installed integrations with a `config.url` (Slack/Teams → `{text}` incoming-webhook; Webhooks → structured JSON), best-effort (spawned, 8s timeout). Fired from **both** the gateway (block/redaction alerts) and the control-plane (extension telemetry alerts). Control-plane gained `PATCH /api/integrations/:slug/config` (set URL) + `POST /api/integrations/:slug/test` (live test). Admin Extensions page reworked: per-integration URL field + Save + Send-test; **removed fabricated star ratings** (honesty). 2 notify tests. QA caveats in `QA_CHECKLIST.md §F`
- [x] **OSS packaging, licensing, contributor docs** — `LICENSE` (Apache-2.0, matching the Cargo workspace) + `NOTICE`; `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), `SECURITY.md` (private disclosure); `.github/` CI workflow (cargo fmt/clippy/test/build + TS typecheck/build + Docker image builds) and issue/PR templates; multi-stage **Dockerfiles** for gateway + control-plane (+ `.dockerignore`) with the app services now **enabled** in `infra/docker-compose.yml`; README self-host + contributing/security/license sections. Docker build/run is a QA-stage caveat (`QA_CHECKLIST.md §G`)

---

## Phase 3 — Enterprise

- [ ] OIDC / SSO + SCIM provisioning
- [ ] Compliance reports (DPA / ODPC), audit export
- [ ] Self-hosted model management UI
- [ ] Kubernetes / Helm charts
- [ ] JetBrains IDE plugin
- [ ] Hardened zero-retention guarantees

---

## Phase 4 — Role System & Deployment Modes

**Target:** Separate normal users from admins. Three deployment modes: Dev (current), Self-hosted (admin bootstrap + gated registration), Cloud (shared org + open sign-up as User). Users see the chat app; admins see the full dashboard.

**Last updated:** 2026-07-21 — Planning complete. Starting Phase 4.

### Phase 4.1 — Backend Role Guards (all 3 modes)
- [x] Add `require_admin()` to Claims (remove `#[allow(dead_code)]` on `is_admin()`, add `require_admin()`)
- [x] Guard **Policies** create/update/delete — `require_admin()`
- [x] Guard **Integrations** install/uninstall/configure/test — `require_admin()`
- [x] Guard **RAG** ingest/delete — `require_admin()`
- [x] Guard **Settings** update (org name, zero-retention) — `require_admin()`
- [x] Verify **all Manage routes** (users/teams/keys CRUD) already have `require_manage()`

### Phase 4.2 — Admin Bootstrap (self-hosted + cloud)
- [x] Read env vars: `ADMIN_EMAIL`, `ADMIN_PASSWORD` (optional), `CONTROL_PLANE_MODE` (`cloud` / unset)
- [x] Bootstrap logic: on startup with `ADMIN_EMAIL` set, create org + admin user idempotently. Log generated password.
- [x] Self-hosted mode: gate `POST /api/auth/register` — return 403 "Registration is disabled" when `ADMIN_EMAIL` is set
- [x] Cloud mode: registration creates user with role=User in the shared bootstrap org (no new org)
- [x] Dev mode (`ADMIN_EMAIL` unset): current behavior — registration creates org + Admin

### Phase 4.3 — Personal API Keys & User Endpoints
- [x] Migration `0006_api_key_scope.sql`: add `scope` column (`org` / `personal`)
- [x] `GET /api/me/keys` — list personal API keys (scope=personal, user_id=claims.sub)
- [x] `POST /api/me/keys` — create personal key with scope=personal
- [x] `DELETE /api/me/keys/:id` — revoke personal key
- [x] `GET /api/me/stats` — personal usage counts (prompts, redactions, blocks, quota)
- [x] `GET /api/me/activity` — personal activity feed (own actions only)
- [x] `POST /api/auth/change-password` — change own password
- [x] Mount `/api/me/*` routes in main router

### Phase 4.4 — Admin Dashboard Role Gating (frontend)
- [ ] Filter sidebar nav items by role — add `roles` field to each nav item
- [ ] Add "API Keys" nav item for User role
- [ ] Update `Protected` wrapper: accept `minRole`, hierarchy check, redirect to chat
- [ ] Assign `minRole` to each route in App.tsx
- [ ] Create restricted pages for User role: Overview (personal stats), Settings (password only), API Keys (personal keys CRUD)
- [ ] Gate page content by role — hide admin-only UI elements inside pages
- [ ] Handle HTTP 403 in API client — show readable permission-denied message

### Phase 4.5 — Chat App Mini-Dashboard (for normal users)
- [ ] Add `/settings` route with profile info, change password, usage stats, personal API keys, activity
- [ ] Add navigation link ("Settings" gear icon) in chat sidebar
- [ ] Wire personal stats/keys endpoints into chat API client

### Phase 4.6 — User Promotion
- [ ] Admins can promote Users to Manager/Admin from Users page (UI already exists, validate backend)

### Phase 4.7 — Docker Compose & Config
- [x] Add `ADMIN_EMAIL`, `CONTROL_PLANE_MODE` to docker-compose files
- [x] Update `.env.example` with new variables and documentation
- [ ] Update deploy README with bootstrap flow (post-push)
- [ ] Push changes to standalone repos (safeguard-core, safeguard-admin, safeguard-chat, safeguard-deploy)

---

## Notes / Open Items
- **International by default** — no country-specific localization. Regional PII packs (e.g. national ID / tax-number formats) are opt-in, per-org config layered on top of the built-in international detectors.
- Compliance framing: GDPR / CCPA and general data-protection regimes.
- Cloud provider priority: **OpenAI + Anthropic** first; others via OpenAI-compatible adapter.
- Self-hosted: **Ollama** (dev) → vLLM (prod scale).
- ⚠️ Gateway built natively in Rust — deliberately NOT based on LiteLLM (supply-chain compromise, Mar 2026).
