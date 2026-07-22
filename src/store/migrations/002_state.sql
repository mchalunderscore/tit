ALTER TABLE m1a_child
ADD COLUMN state TEXT NOT NULL DEFAULT 'open'
CHECK (state IN ('open', 'closed'));

CREATE INDEX m1a_child_state_parent
ON m1a_child (state, parent_id, sequence);
