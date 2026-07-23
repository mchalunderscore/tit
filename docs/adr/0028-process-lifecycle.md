# Architectural decision record 0028: process lifecycle

Status: Accepted

Date: 2026-07-23

## Context

The server already held one instance lock and stopped its listeners after
SIGINT or SIGTERM. An active HTTP connection could stop shutdown for an
unlimited time. An operator also had no endpoint that showed when both public
listeners were ready.

## Decision

Keep the advisory lock in the empty `tit.lock` file for the full server run.
Do not write a process ID to this file. Refuse an unsafe lock-file path and
refuse a second process that requests the lock.

Add `GET /healthz` and `HEAD /healthz`. Return status 503 until the HTTP and SSH
listeners are bound. Then, return status 200 with `ready`. Set the state to not
ready before shutdown starts. Always send `Cache-Control: no-store`.

After SIGINT or SIGTERM, stop all listeners at the same time. Give HTTP, SSH,
and control-socket tasks 10 seconds to finish. Cancel a task that does not
finish during this time. Write one diagnostic to standard error if shutdown
cancels an unfinished connection.

## Failure and threat cases

A process ID can be stale and can identify an unrelated process after PID
reuse. The advisory file lock is the ownership authority, so the file stays
empty.

The readiness endpoint does not report ready while only HTTP is available. It
does not use a cached response after shutdown starts. A slow or incomplete
client cannot keep the process alive after the drain limit.

## Evidence

The production server test starts both listeners and checks the readiness
response. It starts a second server for the same instance and checks that the
instance lock rejects it. It also checks clean SIGTERM shutdown and restart.

The Web server test holds an incomplete HTTP request open. It uses a short test
drain limit and checks that shutdown cancels the connection after that limit.
The instance-lock test checks that the lock file is empty.

## Consequences

Supervisors can use `/healthz` as the readiness probe. Shutdown permits current
work to finish, but it has a fixed upper bound. A request that exceeds the
bound can be canceled.
