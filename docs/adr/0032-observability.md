# Architectural decision record 0032: observability

Status: Accepted

Date: 2026-07-23

## Context

An operator must identify slow requests, rejected access, active work, and
process lifecycle changes. Audit history supplies durable security and mutation
records, but it is not a process log or a metrics interface.

Observability data must not copy credentials or unbounded user values. URLs can
contain feed tokens. Headers can contain authorization values, cookies, and
signatures. Request bodies can contain recovery credentials, login challenges,
and raw signatures.

## Decision

Write structured JSON Lines events to standard error. Each event has a
millisecond Unix timestamp, a fixed level, and a fixed event name. An HTTP event
also has a random 128-bit request ID, normalized method, status, and duration in
milliseconds. The response includes the request ID in `X-Request-ID`.

An SSH connection gets a random 128-bit connection operation ID. Authentication
events use this ID. Each SSH exec request gets a new random 128-bit operation
ID. The server records that an operation started, but it does not record the
command, repository, username, public key, fingerprint, or client address.

Record lifecycle events for process start, listener readiness, shutdown start,
and shutdown completion. Keep the existing SQLite audit history for durable
account, login, repository, collaborator, issue, pull-request, and ref
mutations. Audit records keep their existing correlation IDs.

Add `GET /metrics`. It returns these fixed counters without labels:

- total HTTP requests;
- total HTTP responses with status 400 or higher;
- active HTTP requests;
- total SSH connections;
- total rejected SSH authentication attempts; and
- total SSH exec operations.

The metrics response uses `no-store`. It does not contain account, repository,
path, ref, client, or credential data. Fixed counter names prevent unbounded
metric dimensions.

The logging interface accepts only fixed event, outcome, and HTTP method values
plus generated IDs, numeric status values, and numeric durations. It does not
accept a URL, header, body, key, username, error string, or network address.
This API boundary supplies redaction instead of a list that can miss a new
secret field.

## Failure and threat cases

A feed token in a URL must not enter a log. HTTP logs do not contain the URL or
query. Authorization headers, cookies, recovery credentials, login challenges,
raw signatures, and SSH keys must not enter a log. The logger does not receive
these values.

Metrics can reveal the amount of process activity. They cannot identify a user
or repository. An operator that does not want public activity counters must
restrict `/metrics` in the reverse proxy.

Log output can fail when standard error is closed. A log failure does not stop
request processing or a security operation. Durable audit events remain part of
their SQLite transactions.

## Evidence

The production server test performs Web login, account recovery, a private
session, an invitation, HTTP repository access, and an SSH clone. It checks the
metrics response and parses each server log line as JSON. It requires HTTP
request IDs, SSH operation IDs, and completed lifecycle events. It also proves
that supplied authorization, cookie, feed-token, recovery, invitation,
challenge, session, and signature values do not occur in the logs.

The Milestone 3.5 gate continues to prove successful and failed audit events,
correlation IDs, and secret exclusion. Unit tests prove that the metrics output
has only the six fixed counters.

## Consequences

The implementation uses `serde_json`, which is already a dependency. It does
not add a logging framework or a metrics registry.

The process writes one line for each HTTP request, SSH connection, SSH
authentication result, SSH operation, and lifecycle change. A later release
can add sampling only if volume becomes an operational problem.
