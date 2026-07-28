CREATE INDEX repository_event_actor_activity
ON repository_event (actor, created_at);
