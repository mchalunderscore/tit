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
