# Architectural decision record 0020: Bounded metadata search

Status: Accepted

Date: 2026-07-23

## Context

An account must be able to search repository and issue metadata that it can
read. An anonymous user must be able to search public metadata. A permanent
index adds derived state, schema work, and update work. The first search
implementation must show that this additional state is necessary.

## Decision

Add a fixed-text, case-insensitive metadata search at `/search`. Search active
repositories, issue titles and bodies, and issue comment bodies. Return one
result for an issue when its issue record or one of its comments matches. Use a
stable repository or issue URL for each result.

Apply the repository authorization query before the metadata scan. An
anonymous search can read only public repositories. An authenticated search
can also read private repositories that the account owns or has permission to
read. Do not show an archived repository. Check current account and
collaborator state for each search.

Use these limits for one search:

- Accept a maximum of 256 query bytes.
- Scan a maximum of 10,000 metadata records.
- Read a maximum of 8 MiB of title and body content.
- Return a maximum of 100 results.
- Stop the application scan after 500 ms.

Return the completed prefix and tell the user when a limit stops the search.
Run the synchronous SQLite work as a bounded blocking job. Use a GET form that
operates without JavaScript. Read one candidate at a time. Limit each title and
body field to 8 MiB plus one byte in the SQL result. The additional byte shows
that the content limit was reached. Thus, candidate text uses a maximum of 16
MiB plus two bytes before the application stops the scan.

Do not add an index. The release-mode workload has one public repository and
9,999 issues. It searches 10,000 records and 449,972 bytes for text in the last
issue. On the development host, the search took 14.4 ms on 2026-07-23. The
index threshold is 250 ms for this workload. Keep the workload in
`tests/metadata_search.rs` so that a contributor can measure it again.
The retained candidate text threshold is 32 MiB. The field limits keep the
implementation below this threshold.

## Evidence

The storage test proves that the authorization query filters private metadata.
The search test covers public and private metadata, collaborator permission,
case-insensitive matching, comment result deduplication, query validation, and
stable result identity after a restart. The public-route test covers the form,
anonymous search, authenticated private search, hidden private results, and an
invalid query. The release-mode workload records the index decision.

## Consequences

Each request reads canonical SQLite metadata, so search results cannot become
out of date. A large instance can return an incomplete result when it reaches a
limit. Add a derivable embedded index only when repeat measurements exceed the
250 ms time threshold or the 32 MiB retained candidate text threshold.
