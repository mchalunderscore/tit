# Architectural decision record 0016: Repository event service

Status: Accepted

Date: 2026-07-22

## Context

Repository changes need one durable event source for feeds and subsequent
subscriptions. A database row ID is not a public identifier. A global row order
also does not give a repository-local cursor.

Each event payload needs a version before issue and pull-request events add new
schemas. An event must not exist without its metadata change. A metadata change
must not exist without its event.

## Decision

Keep `repository_event` as the one canonical repository event table. Do not add
a parallel event history. Give each event these identifiers:

- `event_id` is a random 128-bit lowercase hexadecimal public ID.
- `sequence` is an integer that increases by one inside each repository.
- `id` stays as a private SQLite row key.

Allocate the next sequence in the same immediate transaction that inserts the
event. A unique constraint on `(repository_id, sequence)` prevents reuse. Read
event pages through the `(repository_id, sequence DESC)` index. Use the
repository sequence as the `before` cursor.

The stable version 1 event types are `repository-created`,
`repository-imported`, `push`, `ref-created`, `ref-updated`, `ref-deleted`,
`tag-created`, `tag-updated`, and `tag-deleted`.

Architectural decision record 0017 adds the version 1 issue event types to this
service.

Store `payload_version` as an explicit schema value and store `version` in each
JSON payload. The schema accepts only a JSON object whose inner version equals
the column value. Limit a payload to 1 MiB. Version 1 repository payloads have
`owner`, `repository`, and `object_format`. Push payloads have `operation_id`.
Ref and tag payloads have `name_hex`, `old_target`, and `new_target`. Hexadecimal
ref names preserve Git ref bytes without a text conversion.

Use one insertion helper for repository creation, repository import, initial
refs and tags, a completed push, and changed refs and tags. The helper runs in
the transaction that owns the related metadata mutation. If event insertion
fails, roll back the metadata change. A Git operation stays incomplete if its
completion events cannot be inserted.

Migration 011 assigns a random public ID and a repository sequence to each old
event. It creates a version 1 payload from the old typed columns. The old row ID
does not become the public ID.

Atom and RSS entry IDs now use this form:

```text
urn:tit:event:EVENT_ID
```

The value stays stable after a restart, repository rename, or later event
insert. Existing feed pages use the repository sequence for pagination.

## Failure and threat cases

Database constraints reject an invalid public ID, repeated sequence, unknown
event type, unsupported payload version, malformed JSON, non-object JSON,
missing inner version, mismatched version, oversized payload, invalid ref
shape, and invalid Git operation source.

The event payload is application output. Repository and account names pass the
domain validators. Ref names use hexadecimal text. Object IDs and operation IDs
use their validated canonical values. Event payload generation does not accept
an arbitrary JSON string from an HTTP or SSH request.

Git refs and SQLite still use the durable Git operation intent. The server
inserts push events only when it marks the intent complete. Restart recovery
uses the same completion transaction, so a feed cannot announce a push whose
refs are not reachable.

## Evidence

Migration tests upgrade each historical schema, including schema version 10.
They also kill a migration before and after commit. Storage tests verify random
public IDs, consecutive repository sequences, versioned JSON schemas, indexed
pagination, stable IDs after reopen, duplicate-sequence rejection, payload
rejection, and backfill.

Injected trigger failures prove that repository creation rolls back when its
event fails. They also prove that a Git operation stays incomplete and publishes
no events when its completion event fails. Production feed tests parse Atom and
RSS and follow sequence pagination. Git crash tests continue to stop the process
at each cross-store boundary.

## Consequences

Issue and pull-request milestones can add event types and payload versions to
this service. Consumers use a public event ID for identity and a repository
sequence for order. The private SQLite row key can change without changing
either contract.
