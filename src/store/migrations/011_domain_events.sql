DROP INDEX repository_event_feed;
ALTER TABLE repository_event RENAME TO repository_event_v10;

CREATE TABLE repository_event (
    id INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE
        CHECK (
            length(event_id) = 32
            AND event_id = lower(event_id)
            AND event_id NOT GLOB '*[^0-9a-f]*'
        ),
    repository_id TEXT NOT NULL
        REFERENCES repository (id) ON DELETE RESTRICT,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
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
    payload_version INTEGER NOT NULL CHECK (payload_version = 1),
    payload TEXT NOT NULL
        CHECK (
            length(payload) BETWEEN 1 AND 1048576
            AND CASE WHEN json_valid(payload) THEN
                json_type(payload) = 'object'
                AND coalesce(json_extract(payload, '$.version') = payload_version, 0)
            ELSE 0 END
        ),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    UNIQUE (repository_id, sequence),
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

INSERT INTO repository_event
    (id, event_id, repository_id, sequence, source_intent_id, source_ordinal,
     kind, actor, ref_name, old_target, new_target, payload_version, payload,
     created_at)
SELECT
    legacy.id,
    lower(hex(randomblob(16))),
    legacy.repository_id,
    row_number() OVER (PARTITION BY legacy.repository_id ORDER BY legacy.id),
    legacy.source_intent_id,
    legacy.source_ordinal,
    legacy.kind,
    legacy.actor,
    legacy.ref_name,
    legacy.old_target,
    legacy.new_target,
    1,
    CASE
        WHEN legacy.kind IN ('repository-created', 'repository-imported') THEN
            json_object(
                'version', 1,
                'owner', account.username,
                'repository', repository.slug,
                'object_format', repository.object_format
            )
        WHEN legacy.kind = 'push' THEN
            json_object('version', 1, 'operation_id', legacy.source_intent_id)
        ELSE
            json_object(
                'version', 1,
                'name_hex', lower(hex(legacy.ref_name)),
                'old_target', legacy.old_target,
                'new_target', legacy.new_target
            )
    END,
    legacy.created_at
FROM repository_event_v10 AS legacy
JOIN repository ON repository.id = legacy.repository_id
JOIN account ON account.id = repository.owner_account_id
ORDER BY legacy.id;

DROP TABLE repository_event_v10;

CREATE INDEX repository_event_feed
ON repository_event (repository_id, sequence DESC);
