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

CREATE TABLE account (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE
        CHECK (
            length(username) BETWEEN 1 AND 40
            AND username NOT GLOB '*[^a-z0-9-]*'
            AND substr(username, 1, 1) != '-'
            AND substr(username, -1, 1) != '-'
        ),
    is_administrator INTEGER NOT NULL
        CHECK (is_administrator IN (0, 1)),
    state TEXT NOT NULL
        CHECK (state IN ('active', 'suspended')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;

CREATE TABLE ssh_public_key (
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL
        REFERENCES account (id) ON DELETE RESTRICT,
    canonical_key TEXT NOT NULL
        CHECK (length(canonical_key) BETWEEN 1 AND 16384),
    fingerprint TEXT NOT NULL UNIQUE
        CHECK (length(fingerprint) BETWEEN 1 AND 256),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    UNIQUE (account_id, canonical_key)
) STRICT;

CREATE INDEX ssh_public_key_account
ON ssh_public_key (account_id, id);

CREATE TABLE recovery_credential (
    account_id INTEGER PRIMARY KEY
        REFERENCES account (id) ON DELETE RESTRICT,
    credential_hash BLOB NOT NULL UNIQUE
        CHECK (length(credential_hash) = 32),
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;

CREATE TABLE repository (
    id TEXT PRIMARY KEY
        CHECK (length(id) = 32 AND id NOT GLOB '*[^0-9a-f]*'),
    owner_account_id INTEGER NOT NULL
        REFERENCES account (id) ON DELETE RESTRICT,
    slug TEXT NOT NULL
        CHECK (
            length(slug) BETWEEN 1 AND 100
            AND slug NOT GLOB '*[^a-z0-9._-]*'
            AND substr(slug, 1, 1) GLOB '[a-z0-9]'
            AND substr(slug, -1, 1) GLOB '[a-z0-9]'
            AND substr(slug, -4) != '.git'
            AND slug NOT IN ('admin', 'api', 'assets', 'feeds', 'issues', 'setup')
        ),
    visibility TEXT NOT NULL DEFAULT 'public'
        CHECK (visibility IN ('public', 'private')),
    state TEXT NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'archived')),
    object_format TEXT NOT NULL
        CHECK (object_format IN ('sha1', 'sha256')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    archived_at INTEGER
        CHECK (archived_at IS NULL OR archived_at >= created_at),
    UNIQUE (owner_account_id, slug),
    CHECK (
        (state = 'active' AND archived_at IS NULL)
        OR (state = 'archived' AND archived_at IS NOT NULL)
    )
) STRICT;

INSERT INTO m1a_parent (id, name, created_at)
VALUES (1, 'fixture', 1);

INSERT INTO m1a_child (id, parent_id, sequence, body, state)
VALUES (1, 1, 1, 'version five', 'closed');

PRAGMA user_version = 5;

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

PRAGMA user_version = 6;

