# Architectural decision record 0023: Pull-request comparison

Status: Accepted

Date: 2026-07-22

## Context

A pull-request revision stores immutable base and head commit IDs. A comparison
must use these IDs so a later branch update cannot change an old review. The
repository can contain large or damaged object graphs. Mergeability analysis
must not change the repository or depend on a Git executable.

## Decision

Compute each comparison from the selected pull-request revision and the bare
repository. Do not store a comparison cache. Git objects and the immutable
revision record can reproduce all comparison values.

Walk the base and head histories in breadth-first order. Compute the best Git
merge base after the bounded walks finish. The commit range contains each head
ancestor that is not a base ancestor. Compute the changed paths and unified
diff from the merge-base tree to the head tree. If the histories are unrelated,
use the empty tree for the diff and report that the histories are unrelated.

Classify mergeability as follows:

- `already merged` means that the head is an ancestor of the base.
- `fast-forward` means that the base is an ancestor of the head.
- `clean merge` means that an in-memory three-way merge has no unresolved
  conflict.
- `conflicts` means that the three-way merge has an unresolved conflict.
- `unrelated histories` means that Git cannot find a merge base.

Use `gix` for merge-base selection and the worktree-free three-way merge. Enable
an in-memory object overlay before the merge. Thus, temporary merge objects do
not enter the bare object database. Rename detection checks a maximum of
1,000,000 fuzzy candidate pairs. Stop the tree merge after its first unresolved
conflict.

## Work and output limits

One comparison has one 30-second deadline. It stops after a combined total of
10,000 visited base and head commits. A commit object can contain a maximum of
1 MiB. All returned commit messages can contain a maximum total of 64 MiB.

A path can contain a maximum of 4,096 bytes. A tree object can contain a
maximum of 16 MiB. A flattened tree can contain a maximum of 100,000 entries.
A blob can contain a maximum of 16 MiB. The diff limit is 64 MiB and includes
the old content, new content, and generated hunks. These limits apply before
the Web template creates output. Apply the diff limits to each side before a
divergent three-way merge starts.

The comparison API also accepts a cancellation signal. A caller can stop work
between bounded object operations.

## Failure and threat cases

Reject a missing object, a non-commit object, damaged object data, and an
invalid revision number. Apply the current repository read policy before object
access. Do not resolve the stored commit IDs through branch names.

An unrelated history is a valid result. Show all files in its head tree as
changes from the empty tree. Do not attempt an unrelated-history merge.

The merge implementation can read repository attributes. A pushed attribute
cannot define a process by itself because custom merge drivers require trusted
repository configuration. The service does not run Git or OpenSSH.

## Evidence

The pull-request integration test uses SHA-1 and SHA-256 repositories. It
checks the merge base, commit range, changed paths, diff, immutable revision
selection, fast-forward, clean merge, conflict, already-merged state, unrelated
histories, and a history-limit failure.

The Web integration test selects the current and first revisions without
JavaScript. It checks that the page shows comparison state and changed content.

## Consequences

Each request pays the object-read and merge-analysis cost, but it cannot read or
return unbounded data. A later cache can store only these reproducible values.
Review code can select an immutable revision and use its displayed paths and
commit IDs as comment anchors.
