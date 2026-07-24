DROP INDEX repository_event_feed;
DROP INDEX repository_event_issue_timeline;
DROP INDEX repository_event_pull_request_timeline;
ALTER TABLE repository_event RENAME TO repository_event_v20;

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
    issue_id TEXT REFERENCES issue (id) ON DELETE RESTRICT,
    pull_request_id TEXT REFERENCES pull_request (id) ON DELETE RESTRICT,
    kind TEXT NOT NULL
        CHECK (kind IN (
            'repository-created', 'repository-imported', 'push',
            'ref-created', 'ref-updated', 'ref-deleted',
            'tag-created', 'tag-updated', 'tag-deleted',
            'issue-created', 'issue-edited', 'issue-commented',
            'issue-closed', 'issue-reopened',
            'issue-labeled', 'issue-unlabeled',
            'issue-assigned', 'issue-unassigned',
            'pull-request-created', 'pull-request-revised',
            'pull-request-edited', 'pull-request-closed',
            'pull-request-reopened',
            'pull-request-commented', 'pull-request-line-commented',
            'pull-request-approved', 'pull-request-changes-requested',
            'pull-request-merged'
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
            AND issue_id IS NULL AND pull_request_id IS NULL
            AND ref_name IS NULL AND old_target IS NULL AND new_target IS NULL)
        OR
        ((kind LIKE 'ref-%' OR kind LIKE 'tag-%')
            AND issue_id IS NULL AND pull_request_id IS NULL
            AND ref_name IS NOT NULL
            AND (old_target IS NOT NULL OR new_target IS NOT NULL))
        OR
        (kind LIKE 'issue-%'
            AND issue_id IS NOT NULL AND pull_request_id IS NULL
            AND source_intent_id IS NULL AND source_ordinal IS NULL
            AND ref_name IS NULL AND old_target IS NULL AND new_target IS NULL)
        OR
        (kind LIKE 'pull-request-%'
            AND issue_id IS NULL AND pull_request_id IS NOT NULL
            AND (source_intent_id IS NULL OR kind = 'pull-request-merged')
            AND ref_name IS NULL AND old_target IS NULL AND new_target IS NULL)
    )
) STRICT;

INSERT INTO repository_event
    (id, event_id, repository_id, sequence, source_intent_id, source_ordinal,
     issue_id, pull_request_id, kind, actor, ref_name, old_target, new_target,
     payload_version, payload, created_at)
SELECT
    id, event_id, repository_id, sequence, source_intent_id, source_ordinal,
    issue_id, pull_request_id, kind, actor, ref_name, old_target, new_target,
    payload_version, payload, created_at
FROM repository_event_v20
ORDER BY id;

DROP TABLE repository_event_v20;

CREATE INDEX repository_event_feed
ON repository_event (repository_id, sequence DESC);

CREATE INDEX repository_event_issue_timeline
ON repository_event (issue_id, sequence)
WHERE issue_id IS NOT NULL;

CREATE INDEX repository_event_pull_request_timeline
ON repository_event (pull_request_id, sequence)
WHERE pull_request_id IS NOT NULL;
