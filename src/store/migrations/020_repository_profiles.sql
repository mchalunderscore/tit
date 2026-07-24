CREATE TABLE repository_profile (
    repository_id TEXT PRIMARY KEY
        REFERENCES repository (id) ON DELETE RESTRICT,
    description TEXT NOT NULL DEFAULT ''
        CHECK (length(CAST(description AS BLOB)) <= 512)
) STRICT;
