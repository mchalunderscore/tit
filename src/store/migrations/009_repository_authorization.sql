CREATE TABLE repository_collaborator (
    repository_id TEXT NOT NULL
        REFERENCES repository (id) ON DELETE RESTRICT,
    account_id INTEGER NOT NULL
        REFERENCES account (id) ON DELETE RESTRICT,
    role TEXT NOT NULL
        CHECK (role IN ('maintainer', 'writer', 'reader')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (repository_id, account_id)
) STRICT;

CREATE INDEX repository_collaborator_account
ON repository_collaborator (account_id, repository_id);
