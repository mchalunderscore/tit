CREATE TABLE watch (
    id TEXT PRIMARY KEY
        CHECK (
            length(id) = 32
            AND id = lower(id)
            AND id NOT GLOB '*[^0-9a-f]*'
        ),
    repository_id TEXT NOT NULL
        REFERENCES repository (id) ON DELETE RESTRICT,
    account_id INTEGER NOT NULL
        REFERENCES account (id) ON DELETE RESTRICT,
    pushes INTEGER NOT NULL CHECK (pushes IN (0, 1)),
    issues INTEGER NOT NULL CHECK (issues IN (0, 1)),
    pull_requests INTEGER NOT NULL CHECK (pull_requests IN (0, 1)),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    UNIQUE (repository_id, account_id),
    CHECK (pushes = 1 OR issues = 1 OR pull_requests = 1)
) STRICT;

CREATE INDEX watch_account_activity
ON watch (account_id, repository_id);
