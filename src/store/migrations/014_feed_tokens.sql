CREATE TABLE feed_token (
    id TEXT PRIMARY KEY
        CHECK (
            length(id) = 32
            AND id = lower(id)
            AND id NOT GLOB '*[^0-9a-f]*'
        ),
    token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    account_id INTEGER NOT NULL
        REFERENCES account (id) ON DELETE RESTRICT,
    scope TEXT NOT NULL
        CHECK (scope IN ('repository', 'watched', 'assignments', 'mentions')),
    repository_id TEXT
        REFERENCES repository (id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    revoked_at INTEGER CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    CHECK (
        (scope = 'repository' AND repository_id IS NOT NULL)
        OR (scope != 'repository' AND repository_id IS NULL)
    )
) STRICT;

CREATE INDEX feed_token_account_active
ON feed_token (account_id, revoked_at, created_at DESC);

CREATE INDEX feed_token_repository_active
ON feed_token (repository_id, revoked_at)
WHERE repository_id IS NOT NULL;
