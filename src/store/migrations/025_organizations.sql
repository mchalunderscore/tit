CREATE UNIQUE INDEX account_id_username
ON account (id, username);

CREATE TABLE namespace (
    id INTEGER PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE
        CHECK (
            length(slug) BETWEEN 1 AND 40
            AND slug NOT GLOB '*[^a-z0-9-]*'
            AND substr(slug, 1, 1) != '-'
            AND substr(slug, -1, 1) != '-'
            AND slug NOT IN ('admin', 'api', 'assets', 'feeds', 'issues', 'setup')
        ),
    kind TEXT NOT NULL
        CHECK (kind IN ('account', 'organization')),
    account_id INTEGER UNIQUE,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    CHECK (
        (kind = 'account' AND account_id IS NOT NULL)
        OR (kind = 'organization' AND account_id IS NULL)
    ),
    FOREIGN KEY (account_id, slug)
        REFERENCES account (id, username) ON DELETE RESTRICT
) STRICT;

INSERT INTO namespace (slug, kind, account_id, created_at)
SELECT username, 'account', id, created_at
FROM account;

CREATE TRIGGER account_namespace_after_insert
AFTER INSERT ON account
BEGIN
    INSERT INTO namespace (slug, kind, account_id, created_at)
    VALUES (NEW.username, 'account', NEW.id, NEW.created_at);
END;

CREATE UNIQUE INDEX namespace_id_kind
ON namespace (id, kind);

CREATE TABLE organization (
    namespace_id INTEGER PRIMARY KEY
        REFERENCES namespace (id) ON DELETE RESTRICT,
    namespace_kind TEXT NOT NULL DEFAULT 'organization'
        CHECK (namespace_kind = 'organization'),
    display_name TEXT NOT NULL
        CHECK (length(CAST(display_name AS BLOB)) BETWEEN 1 AND 100),
    description TEXT NOT NULL DEFAULT ''
        CHECK (length(CAST(description AS BLOB)) <= 512),
    state TEXT NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'archived')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    FOREIGN KEY (namespace_id, namespace_kind)
        REFERENCES namespace (id, kind) ON DELETE RESTRICT
) STRICT;

CREATE TABLE organization_member (
    organization_id INTEGER NOT NULL
        REFERENCES organization (namespace_id) ON DELETE RESTRICT,
    account_id INTEGER NOT NULL
        REFERENCES account (id) ON DELETE RESTRICT,
    role TEXT NOT NULL
        CHECK (role IN ('owner', 'maintainer', 'writer', 'reader')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (organization_id, account_id)
) STRICT;

CREATE INDEX organization_member_account
ON organization_member (account_id, organization_id);

CREATE TABLE repository_v25 (
    id TEXT PRIMARY KEY
        CHECK (length(id) = 32 AND id NOT GLOB '*[^0-9a-f]*'),
    owner_namespace_id INTEGER NOT NULL
        REFERENCES namespace (id) ON DELETE RESTRICT,
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
    UNIQUE (owner_namespace_id, slug),
    CHECK (
        (state = 'active' AND archived_at IS NULL)
        OR (state = 'archived' AND archived_at IS NOT NULL)
    )
) STRICT;

INSERT INTO repository_v25
    (id, owner_namespace_id, slug, visibility, state, object_format, created_at, archived_at)
SELECT repository.id, namespace.id, repository.slug,
       repository.visibility, repository.state, repository.object_format,
       repository.created_at, repository.archived_at
FROM repository
JOIN namespace ON namespace.account_id = repository.owner_account_id;

DROP TABLE repository;
ALTER TABLE repository_v25 RENAME TO repository;
