# Architectural decision record 0014: Audit history

Status: Accepted

Date: 2026-07-22

## Context

Account and repository changes need a durable security history. An operator
must be able to relate a Web result to its audit event. A successful mutation
must not exist without its success event. A failed mutation must not change its
target state.

The audit history must not become a second store for credentials or login
data.

## Decision

Store audit events in the SQLite `audit_event` table. Each row has an action,
actor, target, outcome, creation time, and correlation ID. The outcome is
`success` or `failure`. Keep the target as a bounded identifier. Do not put a
request body or error text in the row.

Insert a success audit event in the same transaction as its account, session,
repository, collaborator, or ref mutation. If the mutation transaction fails,
roll it back and insert a failure audit event in a new transaction. If the
failure event cannot be stored, return the audit storage error. Do not report
the mutation as complete.

Use the HTTP request ID as the correlation ID for Web login, signup, and
recovery. Generate a random correlation ID for each offline administrator
mutation. Use the durable Git operation ID for a ref update. This rule lets an
operator relate a Web response, an administrator operation, or a Git push to
one audit history item.

For a Git push, insert the success audit event when the durable Git operation
becomes complete. Record a failed receive operation after protocol, pack,
object, or ref validation rejects it. If restart recovery finds that refs were
changed, it completes the operation and keeps only the success event. If refs
were not changed, the server can record the failure event.

The offline `tit admin audit` command shows as many as 1,000 recent events in
reverse creation order. The default limit is 100. The command uses the instance
lock and does not change the audit history.

## Failure and threat cases

The schema limits the length of each text field and permits only the two outcome
values. An index supports the newest-event query. A second index supports a
correlation-ID query. The first command does not expose a filter because the
bounded newest-event query is sufficient for this milestone.

Do not store invite codes, recovery credentials, login challenges, signatures,
session tokens, CSRF tokens, SSH private keys, or HTTP request bodies. A failed
login stores only a valid username or the value `invalid-account`. A key audit
target can contain a public-key fingerprint because the fingerprint is an
identifier and is not a credential.

The audit history is append-only through the application interface. This
milestone does not add an audit deletion or update command.

## Evidence

The schema migration tests migrate each historical fixture and test a killed
migration. The storage tests verify bounded history order and successful Git
and repository events. Account tests verify successful and failed key and
recovery events.

The production server tests verify Web request correlation, successful and
failed login events, recovery events, successful and rejected ref updates, and
secret exclusion. The administrator CLI test verifies successful and failed
repository and collaborator events through `tit admin audit`.

## Consequences

Security mutations add one SQLite row. Failed attempts add a separate short
transaction. The audit table grows until a subsequent operations milestone
defines backup retention and storage policy. No automatic deletion occurs in
this milestone.
