CREATE TABLE pull_request_review (
    id TEXT PRIMARY KEY
        CHECK (
            length(id) = 32
            AND id = lower(id)
            AND id NOT GLOB '*[^0-9a-f]*'
        ),
    pull_request_id TEXT NOT NULL
        REFERENCES pull_request (id) ON DELETE RESTRICT,
    revision_id TEXT NOT NULL
        REFERENCES pull_request_revision (id) ON DELETE RESTRICT,
    author_account_id INTEGER NOT NULL
        REFERENCES account (id) ON DELETE RESTRICT,
    kind TEXT NOT NULL
        CHECK (kind IN ('comment', 'line-comment', 'approved', 'changes-requested')),
    body TEXT NOT NULL CHECK (length(CAST(body AS BLOB)) <= 262144),
    commit_object_id TEXT
        CHECK (
            commit_object_id IS NULL
            OR (length(commit_object_id) IN (40, 64)
                AND commit_object_id = lower(commit_object_id)
                AND commit_object_id NOT GLOB '*[^0-9a-f]*')
        ),
    path BLOB CHECK (path IS NULL OR (length(path) BETWEEN 1 AND 4096 AND instr(path, X'00') = 0)),
    side TEXT CHECK (side IS NULL OR side IN ('base', 'head')),
    line INTEGER CHECK (line IS NULL OR line >= 1),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    CHECK (
        (kind = 'line-comment'
            AND length(CAST(body AS BLOB)) >= 1
            AND commit_object_id IS NOT NULL
            AND path IS NOT NULL
            AND side IS NOT NULL
            AND line IS NOT NULL)
        OR
        (kind != 'line-comment'
            AND commit_object_id IS NULL
            AND path IS NULL
            AND side IS NULL
            AND line IS NULL)
    ),
    CHECK (kind NOT IN ('comment', 'changes-requested') OR length(CAST(body AS BLOB)) >= 1)
) STRICT;

CREATE INDEX pull_request_review_timeline
ON pull_request_review (pull_request_id, created_at, id);

CREATE INDEX pull_request_review_status
ON pull_request_review (pull_request_id, author_account_id, created_at DESC, id DESC)
WHERE kind IN ('approved', 'changes-requested');

DROP INDEX repository_event_feed;
DROP INDEX repository_event_issue_timeline;
DROP INDEX repository_event_pull_request_timeline;
ALTER TABLE repository_event RENAME TO repository_event_v15;

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
            'pull-request-commented', 'pull-request-line-commented',
            'pull-request-approved', 'pull-request-changes-requested'
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
            AND source_intent_id IS NULL AND source_ordinal IS NULL
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
FROM repository_event_v15
ORDER BY id;

DROP TABLE repository_event_v15;

CREATE INDEX repository_event_feed
ON repository_event (repository_id, sequence DESC);

CREATE INDEX repository_event_issue_timeline
ON repository_event (issue_id, sequence)
WHERE issue_id IS NOT NULL;

CREATE INDEX repository_event_pull_request_timeline
ON repository_event (pull_request_id, sequence)
WHERE pull_request_id IS NOT NULL;
