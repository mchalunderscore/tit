# 0033: Release packages use native executable archives

- Status: accepted
- Date: 2026-07-23

## Context

An operator must be able to install and recover `tit` without a Rust build
environment. A release must also show which operating systems passed their
native gates.

## Decision

Each supported release job builds one native `tit` executable. The job puts the
executable, documentation, native service examples, a Caddy example, the
manual, and shell completions in a versioned archive. The job also makes a
SHA-256 checksum.

The release verification runs the packaged executable with an empty `PATH`.
It starts an instance, runs `doctor`, makes and checks a backup, damages a
disposable database, restores the backup to an empty directory, and runs
`doctor` again. The process security and recovery tests also use the executable
from the archive.

Linux and macOS are release gates. FreeBSD, OpenBSD, and NetBSD become release
gates when the current native Rust toolchain and the application pass on that
system. OpenBSD 7.9 is not a release gate while its native Rust package is older
than the `rust-version` in `Cargo.toml`.

GitHub Actions stores each successful archive and checksum. A `v` tag publishes
the stored files only after the required jobs pass.

## Consequences

The archive does not need Git, OpenSSH, or a Rust build environment at run
time. The operating system can still supply its normal C and system libraries.

An operating-system name in the release files means that the native build,
test, package, and clean-`PATH` verification passed. A platform that does not
pass its gate does not produce a release file.
