-- Development seed: one demo org with an admin user, an API key, and a default
-- DLP policy. Idempotent (safe to re-run). DO NOT load in production.
--
-- Demo API key (plaintext): sg_dev_key_demo_0001
--   SHA-256: e8082954c51580524c8d1ad62aee5cd1cdc10bfb54242aff7c94afc2fa4dc33f

INSERT INTO orgs (id, name, plan, zero_retention)
VALUES ('00000000-0000-0000-0000-000000000001', 'Demo Org', 'free', FALSE)
ON CONFLICT (id) DO NOTHING;

INSERT INTO users (id, org_id, name, email, role, status)
VALUES (
    '00000000-0000-0000-0000-000000000010',
    '00000000-0000-0000-0000-000000000001',
    'Demo Admin', 'admin@demo.local', 'Admin', 'active'
)
ON CONFLICT (org_id, email) DO NOTHING;

INSERT INTO api_keys (org_id, user_id, name, key_hash, prefix)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000010',
    'Demo Key',
    'e8082954c51580524c8d1ad62aee5cd1cdc10bfb54242aff7c94afc2fa4dc33f',
    'sg_dev_key_'
)
ON CONFLICT (key_hash) DO NOTHING;

INSERT INTO policies (org_id, name, description, enabled, patterns, action, route)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Default PII Protection',
    'Redact common PII and secrets in prompts and responses',
    TRUE,
    ARRAY['email','api_key','credit_card','ssn','iban','ip_address','intl_phone'],
    'redact',
    'cloud'
)
ON CONFLICT DO NOTHING;
