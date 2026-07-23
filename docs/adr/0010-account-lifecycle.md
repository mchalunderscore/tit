# Architectural decision record 0010: account lifecycle

Status: Accepted

Date: 2026-07-22

## Context

Account creation must use an invite code. An operator must create the code while
the server owns the instance lock. Recovery must remove access from keys that a
user can no longer control. The database must not contain an invite code or a
recovery credential in plain text.

## Decision

Add the owner-only `control.sock` below the instance directory. The server
refuses a symbolic link, a non-socket path, and an existing socket. The server
creates the socket with mode 600. `tit invite-code` sends one bounded request to
this socket. An invite code is valid for 24 hours and one signup. The database
stores its SHA-256 hash.

Signup requires an invite code, a valid username, and a supported SSH public
key. One SQLite transaction consumes the invitation and creates the account,
the first key, and the recovery credential hash. A failed transaction does not
consume the invitation. The Web UI shows the recovery credential one time.

Recovery requires the username, the current recovery credential, and a new SSH
public key. One transaction revokes all old keys, activates the new key, and
stores the hash of a new recovery credential. The Web UI shows the new
credential one time. The old credential cannot be used again. The running SSH
server reloads active keys after a successful signup or recovery.

An administrator can add and revoke keys, suspend accounts, and restore
accounts with offline `tit admin account` commands. The last active key cannot
be revoked through the key-revocation command. An account row is never deleted.
Thus, its unique username stays reserved after suspension.

## Failure and threat cases

The control protocol has a small fixed request and a five-second time limit.
The client refuses a symbolic link, a non-socket path, and group or other
permissions. Shutdown removes the socket only when its device and inode still
identify the socket that this process created. Thus, shutdown does not remove a
replacement path.

Signup and recovery errors do not put a credential in a log or an error page.
Malformed input has a fixed size limit. The account service parses SSH keys
before a transaction starts. SQLite constraints preserve the invitation,
username, key, and account-state invariants.

## Evidence

Storage tests cover one-time and expired invitations, transaction rollback,
username reservation, key addition and revocation, recovery rotation, and
account suspension. Control-socket tests cover permissions, cleanup, files, and
symbolic links. The executable test uses `tit invite-code`, creates an account
through the Web UI, uses its key through stock Git and OpenSSH, recovers the
account, and confirms that the old key stops before the server restarts.

## Consequences

Open signup is not available. An operator must remove a stale `control.sock`
after an unclean server stop, but the server does not automatically remove a
filesystem entry that it did not create. This choice makes the safe owner
action explicit.
