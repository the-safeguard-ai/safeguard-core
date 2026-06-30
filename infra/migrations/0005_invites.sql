-- Team-member invites. Admins/managers add a member (created without a
-- password, status 'invited'); the raw invite token is shown once so the admin
-- can share an accept link. The invitee sets a password to activate the account.
-- No SMTP dependency — link-based, self-host friendly.

-- Allow the 'invited' lifecycle state on users.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_status_check;
ALTER TABLE users
    ADD CONSTRAINT users_status_check
    CHECK (status IN ('active', 'inactive', 'invited'));

CREATE TABLE invites (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,        -- SHA-256 of the raw invite token
    expires_at  TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,                 -- set once the invitee sets a password
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One active invite per user (re-inviting replaces the prior token).
CREATE UNIQUE INDEX invites_one_pending_per_user
    ON invites (user_id) WHERE accepted_at IS NULL;
