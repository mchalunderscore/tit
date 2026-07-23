# Architectural decision record 0003: read-side Git protocol

Status: Accepted

Date: 2026-07-22

## Context

`tit` must serve Git repositories without the Git executable or another runtime
service. Stock Git clients must clone and fetch SHA-1 and SHA-256 repositories
through SSH and smart HTTP. The same repository path rules and object access
rules must apply to each transport.

## Decision

Use `gix` version 0.84.0 to open bare repositories, read references, decode
loose and packed objects, and identify each repository object format. Use
`gix-pack` version 0.71.0 to write pack version 2 with the repository hash
algorithm. Enable SHA-1, SHA-256, pack generation, and the thread-safe `gix`
mode. Use Axum version 0.8.9 for the smart HTTP adapter. Keep Russh version
0.62.4 for the SSH adapter.

Use one upload-pack service behind the HTTP and SSH adapters. Resolve
`owner/repository{,.git}` below one canonical repository root. Reject invalid
names, additional path components, commands other than `git-upload-pack`, and
paths that resolve outside the root. The SSH username does not select the
repository or account.

Support Git protocol versions 0, 1, and 2. Protocol versions 0 and 1 advertise
`agent` and `object-format`. Protocol version 1 also sends its version packet.
Protocol version 2 advertises `agent`, `object-format`,
`ls-refs` with `symrefs` and `peel`, and `fetch` with `wait-for-done`. Smart
HTTP uses the standard discovery and result content types and disables response
caching. SSH and HTTP use the same reference and pack functions.

The packet-line parser accepts data, flush, delimiter, and response-end
packets. It rejects an invalid hexadecimal length, reserved length, incomplete
header, incomplete payload, and oversized input. The server validates each
wanted object against its advertised references. It walks commits, trees, and
tags and does not follow a Gitlink into another repository. It removes objects
that are reachable from a client `have` line.

Generate a complete pack without deltas. This choice gives a small and
inspectable feasibility implementation and works when the source repository
stores objects in loose or delta form. It uses more CPU and network bytes than
an optimized pack. Milestone 2 must measure normal repositories before it adds
delta selection or bitmap traversal.

Run repository reads and pack generation as blocking jobs. Keep a maximum of
four blocking Git jobs for one repository root. The async HTTP and SSH loops do
not do object traversal or compression.

## Limits

- A packet-line is at most 65,520 bytes.
- One request is at most 1 MiB.
- One generated pack contains at most 100,000 reachable objects.
- One decoded object is at most 64 MiB.
- The total decoded data and the generated pack are each at most 256 MiB.
- One repository service runs at most four blocking Git jobs at the same time.

The service does not advertise shallow fetches, partial clone filters, or
side-band support in protocol versions 0 and 1. Protocol version 2 uses its
necessary pack side band. The service does not support hidden references,
replacement objects, or alternates policy in this milestone.

## Evidence

The local macOS gate uses stock Git 2.54.0 and Rust 1.96.0. Stock Git clones
and repeatedly fetches SHA-1 and SHA-256 repositories through smart HTTP and
SSH with protocol versions 1 and 2. SHA-1 tests also use protocol version 0. The
fixtures include an empty repository, branches, an annotated tag, non-ASCII
filenames, a 2 MiB blob, and packed delta objects. The tests compare the
received references and objects with the source.

Negative tests cover a damaged reachable object, an unadvertised want, the
wrong object format, an invalid repository path, an invalid SSH command, an
invalid HTTP service query, an invalid content type, an invalid protocol
version, malformed packet lines, and oversized requests. A separate test
process gives the server a `git` sentinel that fails and records use. An
absolute stock Git client clones through that server. The clone succeeds and
the sentinel is not used.

The stripped local arm64 macOS release executable is 2,863,648 bytes. Hosted
[CI run 29968062175](https://github.com/mchalunderscore/tit/actions/runs/29968062175)
passed on 2026-07-23. It used Cargo 1.96.0 on Ubuntu 24.04 and arm64 macOS 26.
The release executables were 3,239,192 bytes on Ubuntu and 2,847,136 bytes on
macOS.

## Consequences

The selected `gix` crates remove custom repository, object, and pack-file
decoders. The application still owns a small server-side upload-pack state
machine because the available `gix-protocol` API is client-oriented.

The initial pack generator holds the generated pack in memory and sends no
deltas. The explicit 256 MiB limit prevents unbounded allocation, but this
design is for the feasibility gate. A subsequent change can stream pack chunks
after it keeps the same request, object, time, and concurrency limits.
