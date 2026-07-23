CREATE TABLE audit_event (
    id INTEGER PRIMARY KEY,
    action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 80),
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 256),
    target TEXT NOT NULL CHECK (length(target) BETWEEN 1 AND 512),
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
    correlation_id TEXT NOT NULL CHECK (length(correlation_id) BETWEEN 1 AND 128),
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;

CREATE INDEX audit_event_history
ON audit_event (id DESC);

CREATE INDEX audit_event_correlation
ON audit_event (correlation_id, id);
