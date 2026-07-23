# Architectural decision record 0030: read-only diagnostics

Status: Accepted

Date: 2026-07-23

## Context

The initial `tit doctor` command checked only the SQLite schema version,
database pages, and foreign keys. It opened a read-write connection and applied
the normal connection configuration. It did not check the filesystem, Git
state, incomplete cross-store operations, or backup archives.

An operator also needed stable ways to examine records. Direct SQLite queries
require knowledge of the schema and can accidentally change the database.

## Decision

`tit doctor` opens SQLite with `SQLITE_OPEN_READ_ONLY`. It does not take the
instance lock, migrate a schema, recover an intent, remove quarantine data, or
create a file. It checks:

- the instance, configuration, database, repository-root, and SSH host-key
  types and permissions;
- the current schema version, SQLite integrity, foreign keys, and all required
  indexes;
- incomplete Git operation intents and pull-request ref intents;
- the database record for each repository and each repository directory;
- the Git object format, refs, and all reachable Git objects;
- unknown repository-root entries and quarantine debris; and
- each backup archive supplied with `--backup`.

The configuration parser runs before these checks, so configuration syntax and
values are part of the doctor result. A missing SSH host key is an error because
the instance is not ready to preserve its SSH identity.

Add separate `repair intents` and `repair quarantine` commands. Each repair
command takes the instance lock. Intent repair uses the normal recovery logic.
Quarantine repair refuses to run while an incomplete intent exists. Doctor
never calls either repair command.

Add typed `inspect account`, `inspect repository`, and `inspect intent`
commands. Each command returns one version-independent JSON object for the
selected record type. Account inspection does not return the recovery hash or
canonical public-key text.

Add `tit dump`. It streams one JSON object for each SQLite row in deterministic
table and primary-key order. Each object identifies the table and gives each
column name, SQLite value type, and value. BLOB values and invalid UTF-8 text
use lowercase hexadecimal. Valid UTF-8 text stays text. Real values use a
deterministic 17-digit exponential form.

The dump is a raw operational artifact. It can contain credential hashes,
session hashes, feed-token hashes, invitation hashes, and SSH public keys.
Operators must store it as a secret.

## Failure and threat cases

Opening a normal `Store` can migrate an old schema and can create a migration
backup. Diagnostics use a separate read-only constructor, so a doctor,
inspection, or dump cannot do these operations.

Incomplete intents and quarantine directories can be necessary for recovery.
Doctor reports them and leaves them unchanged. The explicit repair commands
serialize with the server through the instance lock.

A repository directory can be a symbolic link or can have an identifier that
has no database record. Doctor rejects both cases. It also opens the repository
without a runtime Git command and walks reachable objects with the established
object-count limit.

A damaged backup can change between validation passes. Backup validation checks
the manifest entry type, size, and checksum. Restore checks them again while it
extracts each file.

## Evidence

The CLI tests run doctor on a correct instance and on instances with a foreign
key violation, a missing index, an incomplete intent, quarantine debris, an
invalid Git ref, unsafe permissions, and a changed backup. The test confirms
that doctor leaves the incomplete intent unchanged. It then runs each explicit
repair command and checks the result.

The same test checks typed account, repository, and intent JSON. It runs the
JSON Lines dump two times and checks byte-for-byte equality and valid typed
rows.

## Consequences

Doctor can run while the server is active because it does not change state.
The result is a point-in-time sequence of checks, not a global snapshot. Use an
online backup when one coherent cross-store snapshot is necessary.

The JSON Lines dump exposes storage details intentionally. It is suitable for
external inspection and comparison, but it is not a restore format.
