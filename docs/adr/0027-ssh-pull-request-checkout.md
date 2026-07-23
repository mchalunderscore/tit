# Architectural decision record 0027: SSH pull-request checkout

Status: Accepted

Date: 2026-07-23

## Context

A contributor needs a stable command to fetch the current pull-request head.
The command must use the same SSH authentication and repository read policy as
the other SSH commands. Scripts also need output that does not depend on human
text.

## Decision

Add this SSH command:

```text
pr checkout OWNER/REPOSITORY NUMBER [--output human|json]
```

The default output is exactly two Git commands:

```text
git fetch origin refs/pull/<number>/head:refs/heads/pr-<number>
git checkout pr-<number>
```

The fetch command creates or updates the local `pr-<number>` branch from the
server-owned pull-request ref. The checkout command selects that branch.

The JSON output has version `1`. It contains the repository owner and name,
the pull-request number, the remote ref, the local branch, and the two complete
Git commands. A JSON error contains version `1`, status `error`, and one stable
error code.

Read the pull request through `Store::pull_request`. This method applies the
current account, repository, visibility, and collaborator policy. The server
recovers incomplete pull-request ref intents before it starts the SSH
listener, so the command cannot observe an unrecovered ref intent.

## Failure and threat cases

Accept only ASCII command input with a bounded size. Require one repository
target, one positive decimal number, and at most one output option. Reject
extra input and duplicate options.

Use the same `pull-request-unavailable` error for a missing pull request and
one that the actor cannot read. This prevents private repository discovery.
Return errors on standard error for human output and on standard output for
JSON output.

Do not run Git or OpenSSH in the server. The output is text for the client to
run. The integration test uses stock Git only as an external test oracle.

## Evidence

The parser test checks valid human and JSON commands, invalid numbers, unsafe
repository targets, duplicate options, extra input, and the size limit.

The production SSH test creates a pull-request ref and metadata, checks the
exact human output, and checks each JSON field. It then runs the returned fetch
and checkout instructions with stock Git and verifies the selected object ID.
The test also makes the repository private and verifies that an unauthorized
account receives `pull-request-unavailable`.

## Consequences

The output contract is suitable for people and scripts. The local branch name
is fixed to `pr-<number>`. A subsequent version must add a new JSON version or
a new explicit option if it changes this naming contract.
