# Architectural decision record 0019: Scoped feeds

Status: Accepted

Date: 2026-07-23

## Context

Public issue activity needs Atom and RSS feeds. An account also needs feeds for
one private repository, watched activity, assignments, and mentions. A feed
reader cannot use the interactive Web login. Thus, a private feed URL is a
credential and must have a narrow authority.

## Decision

Add public issue feeds at these paths:

```text
/{owner}/{repository}/issues/atom.xml
/{owner}/{repository}/issues/rss.xml
```

Select only issue events from the canonical repository event stream. Keep the
entry ID and repository sequence unchanged. Thus, edits and restarts do not
change the order or identity of an entry.

Use a random 256-bit token for each private feed. Store only its SHA-256 hash.
Give each token one immutable scope:

- one repository;
- watched activity;
- assignments;
- mentions.

A repository token also stores one repository ID. A personalized token has no
repository ID. The database constraints enforce these combinations. The token
URL is `/feeds/{token}/atom.xml` or `/feeds/{token}/rss.xml`. The URL does not
accept a second scope value, so a token cannot request a different scope.

Show a new token only in the response that creates or rotates it. The token
list shows the stable token record ID, scope, target, time, and state, but it
does not show a token or its hash. Rotation revokes the old record and creates
the replacement in one immediate transaction. Revocation cannot be reversed.
An account can have at most 32 active tokens. The management page returns at
most 100 token records.

Check the account state and current repository access for each feed read. A
repository token returns only events from its repository. A watched feed
applies the stored push, issue, and pull-request selections. An assignment feed
selects assignment events for the token account. A mention feed selects exact
`@username` references from issue and comment bodies. A bounded scan of at most
1,000 recent issue events supplies at most 20 mention entries.

Return private feeds with `Cache-Control: private, no-store`. All Web responses
use `Referrer-Policy: no-referrer`. The HTTP layer does not log request URLs or
form bodies, so it does not put a feed token in an application log.

## Failure and threat cases

An invalid, unknown, rotated, revoked, or suspended-account token gets the same
not-found response. Token creation stops at the active-token limit. A public
feed cannot read a private repository. A private feed query checks current
visibility, ownership, and collaborator data, so a removed role cannot
continue to return private events.

The event queries sort by immutable repository sequence for one repository and
by immutable creation time plus event ID for multi-repository feeds. An edit
does not change these values. The queries have explicit limits.

The token value appears in the one-time result and in the feed URL because the
feed reader must send it. It does not appear in a later management page, an
error page, a referrer, or the database.

## Evidence

Storage tests cover all four scopes, exact mention matching, issue-only event
selection, access denial, hash lookup, rotation, revocation, and scope
separation. The production HTTP test parses public issue feeds and each private
feed format. It makes a repository private, proves that the public feed is
hidden, reads it with its repository token, verifies hash-only storage, proves
one-time display, rotates the token, and revokes the replacement.

## Consequences

Version 1 has feed delivery without an inbox or a background process. A person
must protect a private feed URL as they protect a password. A later inbox can
consume the same canonical events and current authorization data.
