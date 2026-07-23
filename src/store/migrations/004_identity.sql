CREATE TABLE account (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE
        CHECK (
            length(username) BETWEEN 1 AND 40
            AND username NOT GLOB '*[^a-z0-9-]*'
            AND substr(username, 1, 1) != '-'
            AND substr(username, -1, 1) != '-'
        ),
    is_administrator INTEGER NOT NULL
        CHECK (is_administrator IN (0, 1)),
    state TEXT NOT NULL
        CHECK (state IN ('active', 'suspended')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;

CREATE TABLE ssh_public_key (
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL
        REFERENCES account (id) ON DELETE RESTRICT,
    canonical_key TEXT NOT NULL
        CHECK (length(canonical_key) BETWEEN 1 AND 16384),
    fingerprint TEXT NOT NULL UNIQUE
        CHECK (length(fingerprint) BETWEEN 1 AND 256),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    UNIQUE (account_id, canonical_key)
) STRICT;

CREATE INDEX ssh_public_key_account
ON ssh_public_key (account_id, id);

CREATE TABLE recovery_credential (
    account_id INTEGER PRIMARY KEY
        REFERENCES account (id) ON DELETE RESTRICT,
    credential_hash BLOB NOT NULL UNIQUE
        CHECK (length(credential_hash) = 32),
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;
