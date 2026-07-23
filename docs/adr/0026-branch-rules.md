# Architectural decision record 0026: Branch rules

Status: Accepted

Date: 2026-07-23

## Context

Git transport and pull-request merge code had separate authorization checks.
This made it possible for the two paths to apply different rules. A repository
writer also had permission to update `refs/heads/main` directly.

## Decision

Use `RepositoryPolicy` as the common service for ref changes and pull-request
merges. The service reads the current repository state and collaborator role
for each operation. Do not cache this decision.

Apply these rules:

- `refs/heads/main` is the protected ref.
- An owner or maintainer can create or fast-forward the protected ref.
- A writer cannot change the protected ref.
- No role can delete the protected ref.
- A branch update must be a fast-forward. No role can force-push a branch.
- An owner, maintainer, or writer can create, fast-forward, or delete a topic
  branch.
- An owner, maintainer, or writer can create, update, or delete a tag.
- Only an owner or maintainer can merge a pull request.

The receive-pack service classifies each proposed ref change after it validates
the objects and before it writes an intent or makes an object visible. It sends
each classification to `RepositoryPolicy`. An unmanaged feasibility test
service keeps its original branch fast-forward rule.

The pull-request service asks `RepositoryPolicy` for merge permission before it
prepares a merge. The SQLite intent transaction checks the current role again.
This second check prevents a merge when a collaborator loses permission during
merge preparation.

This milestone does not add configurable branch-rule records. The first stable
release has one protected default ref, and all repositories use
`refs/heads/main` as that ref. A subsequent milestone must add stored rule
configuration before it lets an administrator select a different protected
ref.

## Failure and threat cases

Reject a policy failure before object promotion and before intent creation.
Return an accurate non-fast-forward status for a forced branch update. Return a
reference-policy status for a protected-ref or role failure.

Check all commands in an atomic push before an update starts. One rejected
command rejects the complete push. Read the account, repository, and
collaborator state from SQLite for the operation so a suspended account,
archived repository, or removed role takes effect immediately.

## Evidence

The policy test checks owner, maintainer, and writer behavior for the protected
ref, a topic branch, tags, force-push, deletion, and merge permission.

The production SSH test uses a stock Git client. It checks that a writer can
create, update, and delete a topic branch but cannot update the protected ref.
It checks that an owner can fast-forward the protected ref but cannot delete it
or force-push a topic branch. Existing receive-pack tests check SHA-1 and
SHA-256 fast-forward rules and atomic rejection. Pull-request tests check that
a writer cannot merge and that an owner can merge.

## Consequences

All production ref changes and pull-request merges use one policy service.
Repositories cannot yet select a protected ref other than
`refs/heads/main`. Tags remain mutable, and users with write permission can
delete topic branches and tags.
