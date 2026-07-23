CREATE TABLE repository_counter (
    repository_id TEXT PRIMARY KEY
        REFERENCES repository (id) ON DELETE RESTRICT,
    next_issue_number INTEGER NOT NULL DEFAULT 1
        CHECK (next_issue_number >= 1),
    next_pull_request_number INTEGER NOT NULL DEFAULT 1
        CHECK (next_pull_request_number >= 1)
) STRICT;

CREATE TABLE issue (
    id TEXT PRIMARY KEY
        CHECK (
            length(id) = 32
            AND id = lower(id)
            AND id NOT GLOB '*[^0-9a-f]*'
        ),
    repository_id TEXT NOT NULL
        REFERENCES repository (id) ON DELETE RESTRICT,
    number INTEGER NOT NULL CHECK (number >= 1),
    title TEXT NOT NULL
        CHECK (length(CAST(title AS BLOB)) BETWEEN 1 AND 200),
    body TEXT NOT NULL CHECK (length(CAST(body AS BLOB)) <= 262144),
    state TEXT NOT NULL CHECK (state IN ('open', 'closed')),
    author_account_id INTEGER NOT NULL
        REFERENCES account (id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    closed_at INTEGER CHECK (closed_at IS NULL OR closed_at >= created_at),
    UNIQUE (repository_id, number),
    CHECK (
        (state = 'open' AND closed_at IS NULL)
        OR (state = 'closed' AND closed_at IS NOT NULL)
    )
) STRICT;

CREATE INDEX issue_repository_state
ON issue (repository_id, state, number DESC);

CREATE TABLE issue_comment (
    id TEXT PRIMARY KEY
        CHECK (
            length(id) = 32
            AND id = lower(id)
            AND id NOT GLOB '*[^0-9a-f]*'
        ),
    issue_id TEXT NOT NULL
        REFERENCES issue (id) ON DELETE RESTRICT,
    author_account_id INTEGER NOT NULL
        REFERENCES account (id) ON DELETE RESTRICT,
    body TEXT NOT NULL
        CHECK (length(CAST(body AS BLOB)) BETWEEN 1 AND 262144),
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;

CREATE INDEX issue_comment_history
ON issue_comment (issue_id, created_at, id);

CREATE TABLE label (
    id TEXT PRIMARY KEY
        CHECK (
            length(id) = 32
            AND id = lower(id)
            AND id NOT GLOB '*[^0-9a-f]*'
        ),
    repository_id TEXT NOT NULL
        REFERENCES repository (id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (length(CAST(name AS BLOB)) BETWEEN 1 AND 80),
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;

CREATE UNIQUE INDEX label_repository_name
ON label (repository_id, name COLLATE NOCASE);

CREATE TABLE issue_label (
    issue_id TEXT NOT NULL
        REFERENCES issue (id) ON DELETE RESTRICT,
    label_id TEXT NOT NULL
        REFERENCES label (id) ON DELETE RESTRICT,
    actor_account_id INTEGER NOT NULL
        REFERENCES account (id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (issue_id, label_id)
) STRICT;

CREATE INDEX issue_label_label
ON issue_label (label_id, issue_id);

CREATE TABLE issue_assignee (
    issue_id TEXT NOT NULL
        REFERENCES issue (id) ON DELETE RESTRICT,
    account_id INTEGER NOT NULL
        REFERENCES account (id) ON DELETE RESTRICT,
    actor_account_id INTEGER NOT NULL
        REFERENCES account (id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (issue_id, account_id)
) STRICT;

CREATE INDEX issue_assignee_account
ON issue_assignee (account_id, issue_id);

DROP INDEX repository_event_feed;
ALTER TABLE repository_event RENAME TO repository_event_v11;

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
    kind TEXT NOT NULL
        CHECK (kind IN (
            'repository-created', 'repository-imported', 'push',
            'ref-created', 'ref-updated', 'ref-deleted',
            'tag-created', 'tag-updated', 'tag-deleted',
            'issue-created', 'issue-edited', 'issue-commented',
            'issue-closed', 'issue-reopened',
            'issue-labeled', 'issue-unlabeled',
            'issue-assigned', 'issue-unassigned'
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
            AND issue_id IS NULL
            AND ref_name IS NULL AND old_target IS NULL AND new_target IS NULL)
        OR
        ((kind LIKE 'ref-%' OR kind LIKE 'tag-%')
            AND issue_id IS NULL
            AND ref_name IS NOT NULL
            AND (old_target IS NOT NULL OR new_target IS NOT NULL))
        OR
        (kind LIKE 'issue-%'
            AND issue_id IS NOT NULL
            AND source_intent_id IS NULL AND source_ordinal IS NULL
            AND ref_name IS NULL AND old_target IS NULL AND new_target IS NULL)
    )
) STRICT;

INSERT INTO repository_event
    (id, event_id, repository_id, sequence, source_intent_id, source_ordinal,
     issue_id, kind, actor, ref_name, old_target, new_target, payload_version,
     payload, created_at)
SELECT
    id, event_id, repository_id, sequence, source_intent_id, source_ordinal,
    NULL, kind, actor, ref_name, old_target, new_target, payload_version, payload,
    created_at
FROM repository_event_v11
ORDER BY id;

DROP TABLE repository_event_v11;

CREATE INDEX repository_event_feed
ON repository_event (repository_id, sequence DESC);

CREATE INDEX repository_event_issue_timeline
ON repository_event (issue_id, sequence)
WHERE issue_id IS NOT NULL;
