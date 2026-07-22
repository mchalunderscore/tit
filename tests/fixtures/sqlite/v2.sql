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

INSERT INTO m1a_parent (id, name, created_at)
VALUES (1, 'fixture', 1);

INSERT INTO m1a_child (id, parent_id, sequence, body, state)
VALUES (1, 1, 1, 'version two', 'closed');

PRAGMA user_version = 2;
