-- SafeGuard AI — initial schema
-- Contracts derived from Admin-dash/lib/mockData.ts

-- ── Organizations ──────────────────────────────────────────────
CREATE TABLE orgs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            TEXT NOT NULL,
    plan            TEXT NOT NULL DEFAULT 'free'
                    CHECK (plan IN ('free', 'team', 'enterprise')),
    zero_retention  BOOLEAN NOT NULL DEFAULT FALSE,
    settings        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Teams ──────────────────────────────────────────────────────
CREATE TABLE teams (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id     UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

-- ── Users ──────────────────────────────────────────────────────
-- role mirrors mockData.ts: Admin | Manager | User
CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    team_id       UUID REFERENCES teams(id) ON DELETE SET NULL,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'User'
                  CHECK (role IN ('Admin', 'Manager', 'User')),
    status        TEXT NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'inactive')),
    password_hash TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, email)
);

-- ── API keys (gateway auth) ────────────────────────────────────
CREATE TABLE api_keys (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    key_hash    TEXT NOT NULL UNIQUE,   -- store hash, never the raw key
    prefix      TEXT NOT NULL,          -- first chars, for display
    last_used   TIMESTAMPTZ,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Policies (DLP rules) ───────────────────────────────────────
-- mirrors mockData.ts policyRules + routing/action extensions
CREATE TABLE policies (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    patterns    TEXT[] NOT NULL DEFAULT '{}',     -- e.g. {email, ssn, api_key, iban}; regional packs optional
    action      TEXT NOT NULL DEFAULT 'redact'
                CHECK (action IN ('redact', 'block', 'flag')),
    deep_scan   BOOLEAN NOT NULL DEFAULT FALSE,    -- route through Presidio
    route       TEXT NOT NULL DEFAULT 'cloud'
                CHECK (route IN ('cloud', 'selfhosted')),
    rag_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Usage / audit logs ─────────────────────────────────────────
CREATE TABLE usage_logs (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    team_id       UUID REFERENCES teams(id) ON DELETE SET NULL,
    model         TEXT NOT NULL,
    provider      TEXT NOT NULL,        -- openai | anthropic | ollama | vllm
    route         TEXT NOT NULL,        -- cloud | selfhosted
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    latency_ms    INTEGER NOT NULL DEFAULT 0,
    redactions    INTEGER NOT NULL DEFAULT 0,
    blocked       BOOLEAN NOT NULL DEFAULT FALSE,
    -- bodies are NULL when org.zero_retention is true
    prompt_body   TEXT,
    response_body TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_usage_logs_org_time ON usage_logs (org_id, created_at DESC);

-- ── Risk alerts ────────────────────────────────────────────────
-- mirrors mockData.ts riskAlerts
CREATE TABLE risk_alerts (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id     UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    team_id    UUID REFERENCES teams(id) ON DELETE SET NULL,
    log_id     UUID REFERENCES usage_logs(id) ON DELETE SET NULL,
    severity   TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    message    TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'open'
               CHECK (status IN ('open','investigating','resolved')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_risk_alerts_org_time ON risk_alerts (org_id, created_at DESC);

-- ── Activity feed ──────────────────────────────────────────────
-- mirrors mockData.ts recentActivity
CREATE TABLE activity (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id     UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    actor      TEXT NOT NULL,         -- user name or 'System'
    action     TEXT NOT NULL,
    target     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_activity_org_time ON activity (org_id, created_at DESC);

-- ── Conversations + messages (chat) ────────────────────────────
CREATE TABLE conversations (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id     UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title      TEXT NOT NULL DEFAULT 'New Chat',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE messages (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    role            TEXT NOT NULL CHECK (role IN ('user','assistant','system')),
    content         TEXT NOT NULL,
    safe_mode       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_messages_conversation ON messages (conversation_id, created_at);

-- ── Integrations (Extensions page) ─────────────────────────────
-- mirrors mockData.ts extensions
CREATE TABLE integrations (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    slug        TEXT NOT NULL,         -- slack | google-sheets | teams | webhooks
    installed   BOOLEAN NOT NULL DEFAULT FALSE,
    config      JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, slug)
);

-- ── RAG: documents + chunks (pgvector) ─────────────────────────
CREATE TABLE rag_documents (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id     UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    title      TEXT NOT NULL,
    source     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 1536 dims = text-embedding-3-small default; adjust per embedding model.
CREATE TABLE rag_chunks (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_id UUID NOT NULL REFERENCES rag_documents(id) ON DELETE CASCADE,
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    content     TEXT NOT NULL,
    embedding   vector(1536),
    chunk_index INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_rag_chunks_embedding ON rag_chunks
    USING hnsw (embedding vector_cosine_ops);
CREATE INDEX idx_rag_chunks_org ON rag_chunks (org_id);
