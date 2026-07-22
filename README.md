# tit

`tit` is a small, self-hosted collaborative development environment (CDE) for
Git. The project is in Milestone 1A and does not serve repositories at this time.

Read [PLAN.md](PLAN.md) for the product design and implementation gates. Read
[CONTRIBUTING.md](CONTRIBUTING.md) before you change code.

## Build

Install the Rust toolchain that `rust-toolchain.toml` specifies. Then, run:

```text
cargo build --locked
```

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
