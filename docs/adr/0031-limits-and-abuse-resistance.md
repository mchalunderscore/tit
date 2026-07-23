# Architectural decision record 0031: limits and abuse resistance

Status: Accepted

Date: 2026-07-23

## Context

HTTP, SSH, Git, and Markdown process data from clients and repositories. A
client can keep connections active, send large input, or start expensive Git
operations. A repository can also contain content that is expensive to render.

The configuration already has `max_request_bytes` and `max_connections`.
Before this decision, the server validated these fields but did not apply them
at each listener.

## Decision

Apply `max_request_bytes` as a hard limit to the complete HTTP request body.
A route can apply a smaller limit. The default is 1 MiB. Reject a request that
exceeds the limit with status 413. The `tower-http` request-body limit supplies
streaming enforcement and removes the need for a custom HTTP body wrapper.

Apply `max_connections` to concurrent HTTP requests and SSH sessions. The
default is 1024. An HTTP request can wait for one second for a permit. Reject it
with status 503 if no permit becomes available. Give each HTTP request 30
seconds, including body reads and handler work. Return status 408 after this
time. Russh closes an inactive SSH connection after 30 seconds.

Permit 10 Web login attempts from one client address in one minute. Permit 30
SSH public-key authentication attempts from one client address in one minute.
Track a maximum of 4096 client addresses for each interface. Reject a new
address when the table is full. Remove an address after its attempt window is
empty. These in-memory limits reset after a server restart. Russh also permits
only three authentication attempts on one connection.

Keep the existing Git limits. Upload-pack and receive-pack limit packet-line
input, pack bytes, object bytes, object counts, and generated pack bytes.
Receive-pack also limits command counts, delta depth, reachable-object walks,
and processing time. Repository views limit refs, history, paths, trees, blobs,
diffs, archives, searches, and operation time.

Accept a maximum of 256 KiB of Markdown source and 1 MiB of sanitized HTML.
Return a fixed safe message when a rendering limit is exceeded. Issue, comment,
pull-request, and review validation applies the same source limit before
storage. The Markdown limit also protects README rendering from a large Git
blob.

## Failure and threat cases

The rate tables use client network addresses, not usernames. Thus, an attacker
cannot use a victim username to prevent login by that user. A shared network
address shares one limit. This can delay users behind the same proxy, but it
also bounds work from that proxy. A subsequent change can use a trusted proxy
address only after the server has a complete forwarded-address policy.

The HTTP concurrency limit counts requests instead of TCP connections. An idle
HTTP connection does not consume an application permit, but the 30-second
request limit bounds an incomplete active request after request processing
starts. Operating-system file-descriptor limits remain a separate deployment
boundary.

## Evidence

Unit tests prove the attempt-window and tracked-address limits. Web server tests
send more than 10 login attempts and a request larger than 1 MiB. Markdown
tests exceed the source and rendered-output limits. Existing Git tests exceed
packet-line, pack, object, diff, archive, search, and operation limits. Stock
OpenSSH tests prove the per-connection authentication and inactivity settings.

The complete quality gate runs all tests and the release build. The hosted gate
runs on Linux and macOS.

## Consequences

The limits are process-local and use safe fixed defaults. The administrator can
decrease the HTTP request and concurrency limits, but cannot configure values
larger than 256 MiB and 100000 connections.

Repository read limits remain code constants because they are product safety
boundaries. They are not tuning settings.
