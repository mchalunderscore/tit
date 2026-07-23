# Architectural decision record 0004: Milestone 1 feasibility

Status: Accepted

Date: 2026-07-23

## Context

`tit` must use one executable and must not use Git, OpenSSH, a database server,
or a shared SQLite library at runtime. Milestone 1 had to prove SQLite storage,
SSH identity, Git clone and fetch, and Git push before account and Web UI work
could start.

## Decision

Continue the project with the selected design. Use bundled SQLite through
`rusqlite` for metadata. Use `ssh-key` for SSH public keys and SSHSIG. Use
Russh for the built-in SSH server. Use `gix` and `gix-pack` for repository,
object, and pack operations. Use Axum for smart HTTP. Use Tokio for bounded
asynchronous adapters and blocking jobs.

Support Git protocol versions 0, 1, and 2 for upload-pack. Smart HTTP and SSH
use the same upload-pack service. Receive-pack uses the standard SSH protocol
and supports SHA-1 and SHA-256 repositories. It advertises only
`report-status`, `report-status-v2`, `delete-refs`, `atomic`, `ofs-delta`,
`object-format`, and `agent`.

Keep the custom Git protocol code small. The application owns packet-line
parsing, upload-pack request state, receive-pack command parsing, reference
policy, quarantine control, and status output. The selected crates own Git
object decoding, hash verification, delta resolution, pack indexing, and
reference transactions.

Use a durable SQLite intent for each push. Store the actor, repository path,
initial refs, proposed refs, event data, quarantine path, and state. Validate
the complete push before a ref update. Promote validated objects while they
are unreachable. Update all requested refs in one reference transaction. Mark
the intent complete and add its event in one SQLite transaction.

At startup, compare each incomplete intent with the repository refs. Abandon
an operation that did not update refs. Complete an operation that updated all
refs. Stop startup if the refs have a mixed state. Serialize push validation
and ref updates for one configured repository root. Reads can continue during
a push.

## Limits

- One packet-line request is at most 1 MiB.
- The SSH adapter accepts at most 128 MiB of pack input.
- Receive-pack accepts at most 256 ref commands and 100,000 objects.
- One decoded object is at most 64 MiB.
- A received pack is at most 256 MiB after thin-pack resolution.
- A delta chain has at most 64 levels.
- Object validation walks at most 500,000 objects.
- Pack indexing has a 30-second time limit and uses at most two threads.
- One repository root runs one push validation at a time and at most four
  blocking Git jobs at a time.

## Evidence

The storage gate kills processes during writes and each migration boundary. It
tests constraints, indexes, concurrent access, backup, restore, and all schema
fixtures. The current release workload has 10,000 issue-like rows and 1,000,000
event-like rows. Hosted run
[29970079293](https://github.com/mchalunderscore/tit/actions/runs/29970079293)
measured a 113,946,624-byte database. Ubuntu completed migration in 1,001 ms,
backup in 407 ms, and its 99th percentile query in 23 microseconds. macOS
completed migration in 2,660 ms, backup in 2,069 ms, and its 99th percentile
query in 35 microseconds. These results pass the storage limits by a large
margin.

The identity gate uses stock OpenSSH tools. It accepts Ed25519 and ECDSA P-256,
uses the SSH public-key fingerprint as identity, verifies stock SSHSIG
envelopes, prevents nonce replay, and rejects unsafe SSH capabilities. The
server does not start a shell, agent, subsystem, forward, or arbitrary command.

The read gate uses stock Git through smart HTTP and SSH. It clones empty and
non-empty SHA-1 and SHA-256 repositories, then does repeated fetches. The
fixtures include branches, an annotated tag, non-ASCII filenames, a 2 MiB
blob, and stored delta objects. A process test proves that only the external
test driver starts Git.

The write gate uses stock Git through SSH for SHA-1 and SHA-256. It creates and
updates branches, creates and deletes multiple refs atomically, deletes tags,
and reports per-ref status. It rejects a branch that targets a blob, a
non-fast-forward update, an atomic group with one invalid update, and a push
from a read-only key. Rejected objects and partial refs are not visible. Tests
kill the process after intent creation, object promotion, ref update, and event
completion. Startup recovery gives one full initial or proposed state. A
deterministic input set sends malformed packet-line and pack data to each
parser without a panic.

Run 29970079293 used Cargo 1.96.0. The quality job passed formatting, Clippy,
tests, dependency policy, and the release build. The Ubuntu 24.04 release job
completed in 4 minutes 26 seconds. The arm64 macOS 26 release job completed in
5 minutes 20 seconds. The stripped release executable is 3,239,288 bytes on
Ubuntu and 2,847,104 bytes on macOS.

## Known omissions

The upload-pack generator makes a complete pack without deltas and holds that
pack in memory. It does not support shallow fetches, partial clone filters,
hidden refs, replacement objects, or repository alternates policy.
Receive-pack is available through SSH only. It permits writes only to branches
and tags. It enforces fast-forward policy for branches and does not yet have an
account or collaborator-role source for permissions.

The feasibility server uses explicit key and repository inputs and is not
connected to `tit serve`. Login nonces are in process memory. Push events have
only the ref-change data that the feasibility gate needs. A process stop during
the two pack-file rename operations can leave an unreachable pack index, which
later maintenance must remove.

BSD remains outside the accepted platform set. Linux and macOS are the current
supported platforms. The project must add a platform gate before it claims
FreeBSD, OpenBSD, or NetBSD support.

## Consequences

All four Milestone 1 gates pass. The one-executable design and the selected
crates are feasible for the current product constraints. Milestone 2 can start.

The next work must connect these proven boundaries to instance bootstrap,
repository ownership, and read-only CDE routes. It must preserve the protocol,
security, resource, and recovery behavior that this record accepts.
