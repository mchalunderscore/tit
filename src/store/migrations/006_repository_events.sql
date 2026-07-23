CREATE TABLE repository_event (
    id INTEGER PRIMARY KEY,
    repository_id TEXT NOT NULL
        REFERENCES repository (id) ON DELETE RESTRICT,
    source_intent_id TEXT
        REFERENCES git_operation_intent (id) ON DELETE RESTRICT,
    source_ordinal INTEGER CHECK (source_ordinal IS NULL OR source_ordinal >= 0),
    kind TEXT NOT NULL
        CHECK (kind IN (
            'repository-created', 'repository-imported', 'push',
            'ref-created', 'ref-updated', 'ref-deleted',
            'tag-created', 'tag-updated', 'tag-deleted'
        )),
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 256),
    ref_name BLOB,
    old_target TEXT,
    new_target TEXT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    UNIQUE (source_intent_id, source_ordinal),
    CHECK (
        (source_intent_id IS NULL AND source_ordinal IS NULL)
        OR (source_intent_id IS NOT NULL AND source_ordinal IS NOT NULL)
    ),
    CHECK (
        (kind IN ('repository-created', 'repository-imported', 'push')
            AND ref_name IS NULL AND old_target IS NULL AND new_target IS NULL)
        OR
        (kind LIKE 'ref-%' OR kind LIKE 'tag-%')
            AND ref_name IS NOT NULL
            AND (old_target IS NOT NULL OR new_target IS NOT NULL)
    )
) STRICT;

INSERT INTO repository_event (repository_id, kind, actor, created_at)
SELECT repository.id, 'repository-created', account.username, repository.created_at
FROM repository
JOIN account ON account.id = repository.owner_account_id
ORDER BY repository.created_at, repository.id;

CREATE INDEX repository_event_feed
ON repository_event (repository_id, id DESC);
