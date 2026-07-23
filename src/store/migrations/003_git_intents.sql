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
