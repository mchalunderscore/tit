# Architectural decision record 0001: SQLite storage

Status: Accepted

Date: 2026-07-22

## Context

`tit` needs one inspectable metadata database in the instance directory. The
database must have transactions, constraints, indexes, online backup, and a
clear recovery procedure. The executable must not need an installed database
server or an installed SQLite shared library.

## Decision

Use `rusqlite` with the `bundled` and `backup` features. Keep SQL and
`rusqlite` types in the `store` module. Use numbered SQL migrations and
`PRAGMA user_version`. Apply all pending migrations in one exclusive
transaction. Create an online backup before an automatic migration of an
existing database.

Use WAL mode, `synchronous=FULL`, a five-second busy timeout, and foreign-key
enforcement on each connection. Verify each setting. Use `tit.sqlite3` as the
metadata database name. Require a local filesystem until a platform gate proves
that a different filesystem has correct WAL behavior.

`tit doctor` opens an existing database without the create flag. It does not
migrate the database. It verifies the schema version, SQLite integrity, and
foreign keys.

## Evidence

The local gate used Rust 1.96.0 on arm64 macOS 27.0 and a local APFS filesystem.
It killed child processes during writes and schema migrations. After each kill,
the database contained the initial full state or the new full state. Tests also
proved constraints, indexed scans, concurrent reads, serialized writes, busy
handling, rollback, WAL checkpoint, vacuum, online backup, restore, and
migration from each committed fixture.

The release workload used 10,000 parent records as issues and 1,000,000 child
records as events. The measured database size was 113,926,144 bytes. A safe
migration, including its required backup, took 774 ms. A subsequent online
backup took 509 ms. For 1,000 indexed queries that each read 25 events, the 50th,
95th, and 99th percentile times were 4, 5, and 8 microseconds.

The workload gate has these limits:

- the database must not be larger than 1 GiB.
- migration and backup must each complete in 120 seconds.
- the 99th percentile query time must not be more than 250 ms.

GitHub Actions run
[29964179974](https://github.com/mchalunderscore/tit/actions/runs/29964179974)
passed all quality checks and both hosted workload gates. The Ubuntu 24.04.4
LTS runner used Rust 1.96.0. Its migration took 1,528 ms, its backup took 954
ms, and its 99th percentile query time was 18 microseconds. The macOS 26.4
arm64 runner used Rust 1.96.0. Its migration took 1,774 ms, its backup took
1,333 ms, and its 99th percentile query time was 22 microseconds. Each database
was 113,926,144 bytes. BSD and non-local filesystem support stay outside the
current supported platform set.

## Consequences

SQLite adds a small amount of explicit SQL, but it gives standard inspection
and recovery tools and a stable file format. Bundled SQLite increases the
executable size, but it removes variation in the runtime SQLite version.

The application has one serialized SQLite writer. WAL lets readers continue
during a write. If the measured workload becomes too large for this model, the
project must review the evidence before it adds a database server, a connection
pool, or another persistence abstraction.
