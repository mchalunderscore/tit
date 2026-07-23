# Architectural decision record 0022: Pull-request refs

Status: Accepted

Date: 2026-07-23

## Context

A pull request needs a stable repository number and a Git ref that a standard
Git client can fetch. Each revision must keep its original base and head object
IDs. Git refs and SQLite records cannot use one transaction. A process stop
must not leave the current pull-request ref and its metadata with different
heads.

## Decision

Store each pull request in SQLite with a random permanent ID and an increasing
repository number. Store its title, Markdown body, author, state, base branch,
head branch, current base object ID, and current head object ID. Store each
revision in an append-only record. A revision contains its own random ID,
revision number, author, base object ID, head object ID, and creation time.

Accept only full branch names that start with `refs/heads/`. Resolve each base
and head to a commit before the metadata mutation starts. Support the object-ID
length of the repository, so SHA-1 and SHA-256 repositories use the same code.

Publish the current head as this ordinary Git ref:

```text
refs/pull/<number>/head
```

Do not let Git push create or change this ref. The pull-request service changes
it with an expected old object ID. Thus, a concurrent change cannot overwrite
an unknown value.

Use a durable `pull_request_ref_intent` record for each open or revision
operation. The operation has these steps:

1. Store the pending intent and reserve the pull-request number.
2. Change the Git ref with the expected old value.
3. In one SQLite transaction, store the pull request or revision, append its
   repository event, and complete the intent.

At process startup, inspect each pending intent. If the ref has its old value,
apply the proposed value and complete the metadata. If the ref has the proposed
value, complete the metadata. Stop startup if the ref has another value. The
server uses one in-process lock for these operations. The instance lock stops a
second server process from changing the same stores.

Opening and revision require an active owner, maintainer, or writer. Anonymous
users can read a public pull request. A private pull request uses the current
repository read policy. A reader cannot open or revise a pull request.

## Failure and threat cases

Allocate a number before the Git ref changes. Do not reuse a number if the
operation fails. Stable URLs must not identify a different object later.

Reject a missing branch, a non-commit branch target, invalid content, an
archived repository, and a role that cannot write. Recheck the account and role
in the transaction that creates the intent. A change between initial Git
resolution and this transaction cannot bypass authorization.

The intent stores the expected and proposed object IDs. Recovery does not infer
state from branch names or from current source content. A third ref value is a
consistency error and requires operator inspection.

## Evidence

The pull-request integration test uses SHA-1 and SHA-256 repositories. It opens
and revises a pull request, checks the fetch ref, and proves that the first
revision keeps its original object IDs. It recovers once before the ref change
and once after the ref change. It also opens two pull requests concurrently and
proves that their numbers and refs are different.

The Web integration test opens and reads a pull request without JavaScript. The
migration test upgrades each historical schema and runs integrity checks.

## Consequences

Review code can use the immutable revision object IDs in the next milestone.
The current ref remains useful to stock Git clients. The intent table adds
recovery work, but it prevents a ref-only or metadata-only pull-request update.
