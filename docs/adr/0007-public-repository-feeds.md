# Architectural decision record 0007: public repository feeds

Status: Superseded by architectural decision record 0016

Date: 2026-07-23

## Context

`tit` must publish public repository events as Atom and RSS. Feed entries must
not describe a push before its Git refs are reachable. Feed pages need stable
entry IDs, bounded pagination, and HTTP cache validators.

## Decision

Add an append-only `repository_event` table. Insert the repository creation or
import event in the transaction that inserts the repository. For an import,
also insert one event for each initial branch and tag.

Insert a push event and one event for each changed branch or tag in the
transaction that completes a Git operation intent. Do not insert these events
for a pending, promoted, or abandoned intent. Use the immutable repository ID
to connect an event to a repository. Use the event row ID in the public entry
ID.

Migration 006 adds the event table. It also adds one creation event for each
repository that already exists. It cannot determine whether an old repository
was created or imported, so it uses the creation event type.

Publish `/{owner}/{repository}/atom.xml` and
`/{owner}/{repository}/rss.xml`. Return at most 20 entries. Accept a positive
`before` event ID and return older events. Add a `next` link when more events
exist. Do not publish feeds for private or archived repositories.

Use Atom entry IDs in this form:

```text
urn:tit:event:REPOSITORY_ID:EVENT_ID
```

Use SHA-256 over the response body for the ETag. Also return Last-Modified.
Honor If-None-Match before If-Modified-Since. Return 304 without a response
body when a validator matches.

Generate XML with a small escaping function. Use `feed-rs` version 2.4.0 as an
independent test parser for both output formats. Use `jiff` version 0.2.34 for
Atom dates and `httpdate` version 1.0.3 for RSS and HTTP dates.

## Evidence

Storage tests cover imports, initial branches and tags, completed pushes,
branch creation, and migration from schema version 5. The public-route test
parses Atom and RSS, checks stable entry IDs, follows pagination, checks GET and
HEAD, checks conditional requests, and hides feeds for private and archived
repositories.

## Consequences

A completed event is immutable and has a stable ID. A repository rename changes
the feed URL but does not change an entry ID. A feed reader can use the next
link to read old events without an unbounded database query.
