# Architectural decision record 0029: backup and restore

Status: Accepted

Date: 2026-07-23

## Context

An instance stores metadata and secrets in SQLite. It stores Git objects and
refs in bare repositories. It also stores the configuration and the SSH host
private key as files. A copy of only one storage type can contain a ref state
that does not agree with the database state.

The server must continue to operate during an online backup. A restore must not
replace an active instance or write outside the restore target.

## Decision

Add `tit backup FILE`. FILE must be a clean absolute path outside the instance
directory. The command creates a new mode-0600 tar archive and never replaces
an existing file. The archive contains:

- `manifest.json`;
- the configuration as `config.toml`;
- a SQLite online backup as `tit.sqlite3`;
- `ssh_host_ed25519_key`, if it exists; and
- the complete `repositories` directory.

The JSON manifest has version 1. It records the byte count, SHA-256 checksum,
entry type, and hexadecimal filesystem-path bytes for each file and directory.
The path encoding preserves paths that are not UTF-8. The `tar` crate supplies
the archive implementation and removes the need for a runtime tar command.

For an offline backup, the command takes the instance lock. If the server owns
the lock, the command sends the request through the mode-0600 control socket.
The server takes the global maintenance gate. This gate stops repository
creation, pull-request ref operations, receive-pack ref operations, and future
maintenance operations for the duration of the snapshot. The server first
makes the SQLite online backup. It then copies the repositories, configuration,
and host key while it continues to hold the gate.

Add `tit restore ARCHIVE DIRECTORY`. DIRECTORY must be an existing, empty,
private directory. Restore first reads and validates the complete archive. It
rejects an unknown version, an unknown entry, a duplicate entry, an unsafe
path, an unsupported entry type, a missing entry, and a checksum mismatch. It
then creates private directories and files without following symbolic links.
After extraction, it runs the database checks and validates each bare
repository, object format, ref, and reachable Git object. A validation failure
removes all extracted content.

Restore does not start a server and does not replace the source instance. The
operator must use the restored `config.toml` in a separate `serve` command to
activate the restored instance.

## Failure and threat cases

The archive contains account credentials, session hashes, feed-token hashes,
recovery-credential hashes, SSH public keys, and the SSH host private key.
The CLI and the manifest state that the archive contains credentials. The
archive has owner-only permissions.

An output path inside the instance can enter its own repository copy and can
make the backup unstable. The command rejects this path. `create_new` prevents
replacement through an existing file or symbolic link.

A tar archive can contain absolute paths, parent components, symbolic links,
hard links, devices, and entries that are not in its manifest. Restore rejects
these items before it writes a file. Restore always targets a separate empty
directory, so it cannot partly replace an active instance.

The online backup does not hold a borrowed lock guard across an asynchronous
wait. It moves the owned gate guard into the blocking backup job. This keeps the
gate active until all filesystem reads finish.

## Evidence

Unit tests create and restore an offline backup, check owner-only permissions,
reject an existing output, reject a nonempty target, and reject changed archive
data. A control-socket test holds a receive-pack mutation permit and checks that
an online backup waits.

The production server test imports a repository, starts the real server,
requests an online backup through the CLI, restores the archive through the
CLI, reads the restored SQLite record, and uses stock Git to read the restored
commit.

## Consequences

The archive is intentionally not compressed. This keeps restore simple and
makes each manifest checksum apply to the stored content. Operators can
compress an encrypted copy after the backup completes.

Online backup pauses Git writes while it copies repositories. Large
repositories increase this pause. The implementation favors a coherent
snapshot over write availability.
