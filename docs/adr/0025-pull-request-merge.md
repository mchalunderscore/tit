# Architectural decision record 0025: Pull-request merge

Status: Accepted

Date: 2026-07-23

## Context

A pull-request merge changes a Git ref and SQLite metadata. These two stores
cannot use one transaction. A concurrent push can also move the base ref after
the server checks mergeability. A server-created merge commit must not need a
worktree, index, Git executable, or OpenSSH.

## Decision

Support `fast-forward` and `merge-commit` methods. The current pull-request
revision must match the current base and head refs. A fast-forward requires the
base commit to be an ancestor of the head commit. A merge commit requires a
clean three-way merge. Reject unrelated histories, conflicts, already-merged
heads, stale revisions, and a method that does not match the mergeability
state.

Only a repository owner or maintainer can merge in this milestone. Milestone
5.5 will move this rule into the common branch-policy service.

Create a merge commit without a worktree. Use `gix` rename detection and tree
merge code. Keep Git modes and byte paths. Use the base commit as the first
parent and the head commit as the second parent. Use the acting username for
the author and committer names. Use `<username>@users.tit` for both email
fields. Use UTC and the operation time. Use this message format:

```text
Merge pull request #<number> from <head-ref>

<title>
```

First, create the complete merge result in an in-memory object database. This
step gives the deterministic target ID and does not change the bare
repository. Then write the durable Git operation intent. Create the same merge
objects in the bare object database and require the same target ID. The new
objects stay unreachable until the ref transaction succeeds.

The merge intent extends the push intent. It stores the pull request, exact
revision, method, base ref, old target, and new target. The operation uses these
boundaries:

1. Write the intent and its pull-request data in one SQLite transaction.
2. Write the merge objects, if the method needs them.
3. Mark the objects as promoted.
4. Update the base ref only if it still has the expected old target.
5. Complete the Git intent, set the pull request to `merged`, and append the
   push, ref, pull-request, and audit events in one SQLite transaction.

Recovery uses the push intent state and the actual ref. Complete metadata when
the ref has the proposed target. Abandon the operation when its one ref still
has the initial target. A different target means that a concurrent ref update
won before this merge changed the ref, so recovery also abandons the merge.
Delete the pull-request extension for an abandoned intent so a later attempt
can start. Unreachable loose merge objects stay available for later object
maintenance.

## Failure and threat cases

Recheck repository access, the open state, the latest revision, and all stored
object IDs in the intent transaction. Use an expected-old ref update so a
concurrent base change cannot be overwritten. A unique pull-request merge
intent prevents two active merge operations for one pull request.

Do not run a custom merge command from repository content. The merge uses the
server-controlled bare repository configuration. Stop before the intent if the
bounded comparison fails. Abandon the intent if actual merge output is not the
prepared target.

## Evidence

The integration test fast-forwards SHA-1 and SHA-256 repositories. It checks
owner and reader permission, ref state, merged state, intent completion, and
event order. The worktree-free merge test checks SHA-1 and SHA-256, rename and
mode preservation, deterministic output, parent order, attribution, and the
absence of a bare index. Other tests reject conflicts and stale base refs.

The recovery test completes metadata after an interrupted ref update. It also
changes the base after object promotion and verifies that recovery keeps the
concurrent target, abandons the intent, and leaves the pull request open. The
Web integration test submits a fast-forward merge without JavaScript.

## Consequences

Each clean merge runs once in memory and once against the object database. This
cost gives the intent its exact proposed target before persistent object writes.
The base ref and pull-request state cannot disagree after recovery. A later
maintenance milestone must prune unreachable loose objects from abandoned
merge attempts.
