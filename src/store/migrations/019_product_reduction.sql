ALTER TABLE account ADD COLUMN bio TEXT NOT NULL DEFAULT ''
    CHECK (length(CAST(bio AS BLOB)) <= 512);
ALTER TABLE account ADD COLUMN contact_email TEXT NOT NULL DEFAULT ''
    CHECK (length(CAST(contact_email AS BLOB)) <= 254);

DELETE FROM repository_event
WHERE kind IN (
    'issue-labeled', 'issue-unlabeled', 'issue-assigned', 'issue-unassigned'
);
DROP TABLE issue_label;
DROP TABLE label;
DROP TABLE issue_assignee;

ALTER TABLE watch RENAME TO watch_v18;
CREATE TABLE watch (
    id TEXT PRIMARY KEY
        CHECK (
            length(id) = 32
            AND id = lower(id)
            AND id NOT GLOB '*[^0-9a-f]*'
        ),
    repository_id TEXT NOT NULL
        REFERENCES repository (id) ON DELETE RESTRICT,
    account_id INTEGER NOT NULL
        REFERENCES account (id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    UNIQUE (repository_id, account_id)
) STRICT;
INSERT INTO watch (id, repository_id, account_id, created_at, updated_at)
SELECT id, repository_id, account_id, created_at, updated_at
FROM watch_v18;
DROP TABLE watch_v18;
CREATE INDEX watch_account_activity
ON watch (account_id, repository_id);

DELETE FROM feed_token WHERE scope != 'watched';
UPDATE feed_token
SET revoked_at = created_at
WHERE revoked_at IS NULL
  AND id NOT IN (
      SELECT max(id) FROM feed_token
      WHERE revoked_at IS NULL
      GROUP BY account_id
  );
CREATE UNIQUE INDEX feed_token_one_active_watched
ON feed_token (account_id)
WHERE revoked_at IS NULL;
