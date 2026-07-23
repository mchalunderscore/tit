CREATE TABLE m1a_parent (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 64),
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;

CREATE INDEX m1a_parent_created_at ON m1a_parent (created_at, id);

CREATE TABLE m1a_child (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES m1a_parent (id) ON DELETE RESTRICT,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    body TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'closed')),
    UNIQUE (parent_id, sequence)
) STRICT;

CREATE INDEX m1a_child_state_parent
ON m1a_child (state, parent_id, sequence);

CREATE TABLE git_operation_intent (
    id TEXT PRIMARY KEY CHECK (length(id) = 32),
    repository_path TEXT NOT NULL CHECK (length(repository_path) BETWEEN 1 AND 4096),
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 256),
    initial_refs BLOB NOT NULL,
    proposed_refs BLOB NOT NULL,
    event_payload BLOB NOT NULL,
    quarantine_path TEXT NOT NULL CHECK (length(quarantine_path) BETWEEN 1 AND 4096),
    state TEXT NOT NULL CHECK (state IN ('pending', 'promoted', 'completed', 'abandoned')),
    pack_name TEXT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;

CREATE INDEX git_operation_intent_incomplete
ON git_operation_intent (state, created_at, id)
WHERE state IN ('pending', 'promoted');

CREATE TABLE git_operation_event (
    id INTEGER PRIMARY KEY,
    intent_id TEXT NOT NULL UNIQUE
        REFERENCES git_operation_intent (id) ON DELETE RESTRICT,
    payload BLOB NOT NULL
) STRICT;

INSERT INTO m1a_parent (id, name, created_at)
VALUES (1, 'fixture', 1);

INSERT INTO m1a_child (id, parent_id, sequence, body, state)
VALUES (1, 1, 1, 'version three', 'closed');

PRAGMA user_version = 3;
