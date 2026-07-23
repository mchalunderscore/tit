# tit

`tit` is a small, self-hosted collaborative development environment (CDE) for
Git. The current implementation has a read-only Web UI, HTTP and SSH clone
services, public feeds, and bounded source search.

Read [PLAN.md](PLAN.md) for the product design and implementation gates. Read
[CONTRIBUTING.md](CONTRIBUTING.md) before you change code.

## Build

Install the Rust toolchain that `rust-toolchain.toml` specifies. Then, run:

```text
cargo build --locked
```

## Run

Create the first administrator and import a bare repository before you start
the server:

```text
tit --config /srv/tit/config.toml setup admin alice "SSH_PUBLIC_KEY"
tit --config /srv/tit/config.toml admin repository import alice example /absolute/path/example.git
tit --config /srv/tit/config.toml serve
```

The `serve` command starts the HTTP and SSH listeners in one process. It creates
`ssh_host_ed25519_key` with mode 600 during the first start and uses the same
host key during subsequent starts. Keep this file with the instance data.

The server owns the instance lock until it receives SIGINT or SIGTERM. Stop the
server before you run an offline administrator command. Create a signup code
through the control socket while the server runs:

```text
tit --config /srv/tit/config.toml invite-code
```

The code is valid for one signup during the next 24 hours. Open `/signup` to
create the account. Store the recovery credential offline when the Web UI shows
it. Open `/recover` to replace all account keys with a new key.

## Quality gate

Install `cargo-deny` version 0.20.2. Then, run this command from the repository
root:

```text
./scripts/check
```

This command formats, lints, tests, audits, and builds the release executable.

## Milestone 1A gate

Run the SQLite durability gate on a local filesystem:

```text
./scripts/check-m1a
```

This command also creates and measures a release database with 10,000 issue
records and 1,000,000 event records. Read the SQLite
[architectural decision record](docs/adr/0001-sqlite-storage.md) for the limits
and current platform evidence.

## Milestone 1B gate

Install stock OpenSSH. Then, run the SSH identity gate:

```text
./scripts/check-m1b
```

This command uses stock `ssh`, `ssh-agent`, `ssh-add`, and `ssh-keygen` to do
tests of public-key authentication, SSH request restrictions, and SSHSIG login
challenges. Read the SSH identity
[architectural decision record](docs/adr/0002-ssh-identity.md) for the supported
algorithms, limits, and current platform evidence.

## Milestone 1C gate

Install stock Git and OpenSSH. Then, run the read-side Git protocol gate:

```text
./scripts/check-m1c
```

This command uses stock Git to clone and fetch SHA-1 and SHA-256 repositories
through smart HTTP and SSH. Read the read-side Git
[architectural decision record](docs/adr/0003-read-side-git.md) for the protocol
versions, limits, known omissions, and current platform evidence.

## Database check

An initialized instance keeps its metadata in `tit.sqlite3`. Check an existing
database with this command:

```text
tit --config /absolute/path/to/tit/config.toml doctor
```

The command does not create or migrate a database. Successful validation writes
no output and returns exit code 0.

## Configuration validation

Copy `config.example.toml` into an empty instance directory. Change
`public_url` to the canonical HTTPS URL of the instance. Then, run:

```text
tit --config /absolute/path/to/tit/config.toml
```

Successful validation writes no output and returns exit code 0. A configuration
error writes a diagnostic to standard error and returns exit code 1. A CLI
syntax error returns exit code 2. Help and version output use standard output.

The directory that contains `config.toml` is the instance directory. HTTP clone
URLs use `public_url`. SSH clone URLs use `ssh.public_host` and
`ssh.public_port`. By default, `ssh.public_host` uses the host from `public_url`.
Listener addresses do not change public clone URLs.

`ssh.public_host` accepts a DNS hostname, an IP address, or an `.onion`
hostname. `tit` validates and normalizes this value without resolving it. A Tor
client supplies the necessary SSH `ProxyCommand` configuration.

Use `--user` instead of `--config` to read the configuration from
`$XDG_DATA_HOME/tit/config.toml`. If `XDG_DATA_HOME` is not set, `tit` uses
`$HOME/.local/share/tit/config.toml`.

The executable does not run Git or OpenSSH. Tests can use stock clients as
external test drivers.

## Milestone 2 gate

Install stock Git and OpenSSH. Then, run the read-only CDE gate:

```text
./scripts/check-m2-8
```

This command runs the quality gate, measures source search without an index,
and tests the public routes with SHA-1 and SHA-256 repositories. Read the
[source search architectural decision record](docs/adr/0008-bounded-source-search.md)
for the search limits and current measurement.

## Milestone 3.1 gate

Install stock Git and OpenSSH. Then, run the account lifecycle gate:

```text
./scripts/check-m3-1
```

This command tests invitation, signup, recovery, key revocation, account
suspension, and the owner-only control socket. Read the
[account lifecycle architectural decision record](docs/adr/0010-account-lifecycle.md)
for the credential and failure behavior.
