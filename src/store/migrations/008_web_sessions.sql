CREATE TABLE login_nonce (
    id INTEGER PRIMARY KEY,
    nonce_hash BLOB NOT NULL UNIQUE CHECK (length(nonce_hash) = 32),
    csrf_hash BLOB NOT NULL CHECK (length(csrf_hash) = 32),
    account_id INTEGER NOT NULL REFERENCES account (id) ON DELETE RESTRICT,
    ssh_public_key_id INTEGER NOT NULL REFERENCES ssh_public_key (id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    consumed_at INTEGER CHECK (consumed_at IS NULL OR consumed_at >= created_at)
) STRICT;

CREATE INDEX login_nonce_active
ON login_nonce (expires_at, consumed_at);

CREATE TABLE web_session (
    id INTEGER PRIMARY KEY,
    session_hash BLOB NOT NULL UNIQUE CHECK (length(session_hash) = 32),
    csrf_hash BLOB NOT NULL CHECK (length(csrf_hash) = 32),
    account_id INTEGER NOT NULL REFERENCES account (id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    ended_at INTEGER CHECK (ended_at IS NULL OR ended_at >= created_at)
) STRICT;

CREATE INDEX web_session_account_active
ON web_session (account_id, expires_at, ended_at);
