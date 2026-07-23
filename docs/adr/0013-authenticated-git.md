# Architectural decision record 0013: Authenticated Git

Status: Accepted

Date: 2026-07-22

## Context

The built-in SSH server must use the same account and repository policy as the
Web UI. A key removal, account suspension, or role change must stop subsequent
Git access. A change during a push must not permit a ref update after access is
removed.

HTTP Git access stays read-only in the first stable release.

## Decision

Load each active, non-revoked SSH key with its account username. The key selects
the account. The username that an SSH client supplies does not select the
account. SQLite continues to own the account and key records.

Before `git-upload-pack` starts, verify that the key is still active and ask
`RepositoryPolicy` for read permission. Before `git-receive-pack` starts, do
the same key check and ask for write permission. Resolve the repository path
from its stable repository ID only after authorization.

Before a receive operation changes refs, verify the key-to-account binding
again and ask `RepositoryPolicy` for write permission again. Do these checks
while the server holds the one-push permit and immediately before
`ReceivePack::finish` applies the ref changes. `ReceivePack` then permits only
branch and tag refs. It rejects a non-fast-forward branch update and a ref that
was changed after the initial advertisement. It validates the pack and Git
objects before it changes a ref.

The Web recovery and key operations reload the active SSH key map after a
successful account change. Repository policy reads the current database state
for each decision. Offline repository access commands continue to require the
instance lock.

## Failure and threat cases

A revoked key and a key for a suspended account cannot authenticate after the
active key map reloads. A connection that authenticated before a key reload
cannot start a new Git service with the removed key. If removal occurs during a
receive operation, the check before the ref update rejects the push.

A removed or reduced collaborator role rejects a new Git service. If the role
changes during a receive operation, the second policy check rejects the ref
update. A reader can clone a private repository but cannot start
`git-receive-pack`. An account without a role cannot discover a private
repository.

An unsupported ref, a non-fast-forward branch update, an invalid pack, and a
concurrent ref change return a rejected push. These failures do not change a
ref. HTTP does not start `git-receive-pack` and has no write route.

## Evidence

The production server test uses stock Git and OpenSSH. It tests the owner,
maintainer, writer, reader, and account-without-role cases against a private
repository. It also tests a suspended account, a revoked key, a public
repository, a successful writer push, a rejected reader push, role removal, an
unsupported ref, and a non-fast-forward update.

The receive-pack tests test SHA-1 and SHA-256 pushes, malformed packs, invalid
objects, concurrent ref changes, process termination, and restart recovery.

## Consequences

SSH Git requires an account key, including reads of a public repository. This
keeps SSH identity unambiguous. Anonymous users can continue to clone a public
repository through HTTP.

Each Git service start uses a SQLite policy query. A push uses one additional
policy query before ref updates. This cost keeps authorization current and
prevents a server-side permission cache from extending access.
