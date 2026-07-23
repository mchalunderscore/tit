# Architectural decision record 0008: bounded source search

Status: Accepted

Date: 2026-07-23

## Context

`tit` must search the source at a selected ref. The first implementation must
not have a permanent index. A search must have file, byte, result, and time
limits.

## Decision

Add a fixed-text, case-sensitive search to the repository read service. Resolve
the selected ref to a commit before the search starts. Search the tree of this
commit in Git path order. Do not search a submodule. Do not search a blob that
contains a null byte.

Use these default limits:

- Search a maximum of 10,000 files.
- Read a maximum total of 64 MiB of blob content.
- Return a maximum of 500 matching lines.
- Accept a maximum of 256 query bytes.
- Stop a search after 5 seconds.

The file, byte, and time limits stop the request with an error. The result
limit returns the first 500 matching lines and tells the user that more results
exist. Check the cancellation signal and the time limit during the tree and
line scans.

Publish `/{owner}/{repository}/search`. Use an HTTP GET form that operates
without JavaScript. The form supplies `q` and `ref` parameters. Accept only an
exact ref name that the repository read service returns. Use the resolved full
commit ID in each result link. Do not publish the search route for a private or
archived repository.

Do not add an index. The release-mode workload has 2,000 unique files of 4 KiB
each. It searches 8,192,000 bytes and the last file. On the development host,
the search took 18.8 ms on 2026-07-23. This result does not require the state,
migration, and update work of an index. Keep the workload in
`tests/git_reads.rs` so that a contributor can measure it again.

## Evidence

Repository read tests cover SHA-1, SHA-256, binary content, malformed UTF-8
content, cancellation, and each search limit. The public-route test covers the
form, exact ref selection, immutable result links, malformed UTF-8 content,
large content, HTML escaping, GET, HEAD, empty repositories, and hidden
repositories.

## Consequences

A search reads Git objects for each request. It does not create state that can
become out of date. Large repositories can reach a limit and must use more
specific search text or an external checkout. Add a derivable index only when
repeat measurements show that repositories inside the specified limits cannot
meet the search time limit.
