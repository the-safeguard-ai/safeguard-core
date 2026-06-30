-- Shadow AI discovery events reported by the browser extension.
-- Stores only metadata (site, detector labels, counts) — never prompt text.
CREATE TABLE shadow_events (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id     UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    site       TEXT NOT NULL,          -- chatgpt | gemini | claude | ...
    host       TEXT NOT NULL,          -- e.g. chatgpt.com
    action     TEXT NOT NULL,          -- paste | submit
    labels     TEXT[] NOT NULL DEFAULT '{}',
    count      INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_shadow_events_org_time ON shadow_events (org_id, created_at DESC);
CREATE INDEX idx_shadow_events_org_site ON shadow_events (org_id, site);
