# Architectural decision record 0009: operational server

Status: Accepted

Date: 2026-07-23

## Context

The Milestone 2 services had test interfaces, but the `tit` executable did not
start them. The Milestone 2 gate requires an operator to import a repository and
let users browse and clone it through HTTP and SSH.

## Decision

Add `tit serve`. Hold the exclusive instance lock for the complete server run.
Start the Axum HTTP listener and the Russh SSH listener in one Tokio process.
Stop both listeners after SIGINT or SIGTERM. If one listener cannot start, stop
the listener that already started and return an error.

At startup, read the active SSH public keys and the active public repositories
from SQLite. Give the SSH transport a fixed map from each owner and repository
slug to its immutable repository ID. Resolve the final path below the canonical
repository directory. The instance lock prevents an offline command from
changing this map during the server run.

Create an Ed25519 SSH host key in `ssh_host_ed25519_key` during the first start.
Use mode 600 and refuse a symbolic link, a non-file path, unsafe permissions,
an encrypted key, a different key algorithm, and an oversized key file. Read
the same key during subsequent starts.

## Evidence

The executable test creates an administrator, imports a repository, and starts
`tit serve`. It browses and clones the managed repository through HTTP. It also
uses the administrator key and stock Git and OpenSSH to clone through SSH. The
test confirms that an offline command cannot acquire the instance lock. It
sends SIGTERM, confirms a clean stop, starts the server again, and confirms that
the SSH host key did not change.

## Consequences

The Web UI and both Git transports now use the repository layout that the admin
command creates. An operator must stop the server to use an offline admin
command. Milestone 3.1 adds the owner-only control socket for specified
online operations.
