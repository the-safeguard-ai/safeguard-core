-- Add scope to API keys: org-wide (used by extensions/gateway, managed by org admins)
-- or personal (owned by a single user, visible only to them).
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'org'
    CHECK (scope IN ('org', 'personal'));
