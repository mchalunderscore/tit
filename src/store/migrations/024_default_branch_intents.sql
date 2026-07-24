CREATE TABLE repository_default_branch_intent (
    id TEXT PRIMARY KEY
        CHECK (
            length(id) = 32
            AND id NOT GLOB '*[^0-9a-f]*'
        ),
    repository_id TEXT NOT NULL UNIQUE
        REFERENCES repository(id) ON DELETE CASCADE,
    actor TEXT NOT NULL,
    previous_ref_name TEXT NOT NULL
        CHECK (
            length(previous_ref_name) BETWEEN 12 AND 1024
            AND substr(previous_ref_name, 1, 11) = 'refs/heads/'
        ),
    proposed_ref_name TEXT NOT NULL
        CHECK (
            length(proposed_ref_name) BETWEEN 12 AND 1024
            AND substr(proposed_ref_name, 1, 11) = 'refs/heads/'
        ),
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;
