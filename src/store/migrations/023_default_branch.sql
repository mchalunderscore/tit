CREATE TABLE repository_default_branch (
    repository_id TEXT PRIMARY KEY
        REFERENCES repository(id) ON DELETE CASCADE,
    ref_name TEXT NOT NULL
        CHECK (
            length(ref_name) BETWEEN 12 AND 1024
            AND substr(ref_name, 1, 11) = 'refs/heads/'
        )
) STRICT;

INSERT INTO repository_default_branch (repository_id, ref_name)
SELECT id, 'refs/heads/main' FROM repository;
