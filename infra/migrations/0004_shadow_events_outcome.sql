-- Records the enforcement outcome (redact | block | flag) per shadow event,
-- so admins can see what was redacted vs blocked (for policy tuning / training).
ALTER TABLE shadow_events
    ADD COLUMN outcome TEXT NOT NULL DEFAULT 'flag'
    CHECK (outcome IN ('redact', 'block', 'flag'));
