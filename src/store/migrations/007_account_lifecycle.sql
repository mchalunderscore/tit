CREATE TABLE signup_invitation (
    id INTEGER PRIMARY KEY,
    code_hash BLOB NOT NULL UNIQUE CHECK (length(code_hash) = 32),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    consumed_at INTEGER CHECK (consumed_at IS NULL OR consumed_at >= created_at)
) STRICT;

CREATE INDEX signup_invitation_active
ON signup_invitation (expires_at, consumed_at);

ALTER TABLE ssh_public_key
ADD COLUMN label TEXT NOT NULL DEFAULT 'initial'
    CHECK (length(label) BETWEEN 1 AND 80);

ALTER TABLE ssh_public_key
ADD COLUMN last_used_at INTEGER
    CHECK (last_used_at IS NULL OR last_used_at >= created_at);

ALTER TABLE ssh_public_key
ADD COLUMN revoked_at INTEGER
    CHECK (revoked_at IS NULL OR revoked_at >= created_at);
