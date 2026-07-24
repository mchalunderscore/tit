ALTER TABLE login_nonce RENAME TO login_nonce_v17;

CREATE TABLE login_nonce (
    id INTEGER PRIMARY KEY,
    nonce_hash BLOB NOT NULL UNIQUE CHECK (length(nonce_hash) = 32),
    csrf_hash BLOB NOT NULL CHECK (length(csrf_hash) = 32),
    account_id INTEGER NOT NULL REFERENCES account (id) ON DELETE RESTRICT,
    ssh_public_key_id INTEGER REFERENCES ssh_public_key (id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    consumed_at INTEGER CHECK (consumed_at IS NULL OR consumed_at >= created_at)
) STRICT;

INSERT INTO login_nonce
    (id, nonce_hash, csrf_hash, account_id, ssh_public_key_id,
     created_at, expires_at, consumed_at)
SELECT id, nonce_hash, csrf_hash, account_id, ssh_public_key_id,
       created_at, expires_at, consumed_at
FROM login_nonce_v17;

DROP TABLE login_nonce_v17;

CREATE INDEX login_nonce_active
ON login_nonce (expires_at, consumed_at);

CREATE TABLE ssh_login_approval (
    id INTEGER PRIMARY KEY,
    secret_hash BLOB NOT NULL UNIQUE CHECK (length(secret_hash) = 32),
    csrf_hash BLOB NOT NULL CHECK (length(csrf_hash) = 32),
    account_id INTEGER REFERENCES account (id) ON DELETE RESTRICT,
    ssh_public_key_id INTEGER REFERENCES ssh_public_key (id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    approved_at INTEGER CHECK (approved_at IS NULL OR approved_at >= created_at),
    consumed_at INTEGER CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    CHECK (
        (account_id IS NULL AND ssh_public_key_id IS NULL AND approved_at IS NULL)
        OR
        (account_id IS NOT NULL AND ssh_public_key_id IS NOT NULL AND approved_at IS NOT NULL)
    )
) STRICT;

CREATE INDEX ssh_login_approval_active
ON ssh_login_approval (expires_at, consumed_at);
