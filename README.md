# tit

`tit` is a small, self-hosted collaborative development environment (CDE) for
Git. The current implementation has a read-only Web UI, HTTP and SSH clone
services, authenticated SSH push, public feeds, and bounded source search.

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

Stop the server before you change repository access with an offline
administrator command:

```text
tit --config /srv/tit/config.toml admin repository visibility alice example private
tit --config /srv/tit/config.toml admin repository collaborator-set alice example bob writer
tit --config /srv/tit/config.toml admin repository collaborator-remove alice example bob
```

The policy permits a reader to read and a writer to write. It permits a
maintainer to change repository settings and collaborators. Only the owner can
change ownership. An owner or collaborator can read a private repository in the
Web UI after login. The built-in SSH server binds the supplied key to its
account. The SSH username does not select the account. An owner, maintainer, or
writer can push branches and tags. A reader cannot push. HTTP Git access stays
read-only.

Stop the server and show the newest audit events with this command:

```text
tit --config /srv/tit/config.toml admin audit --limit 100
```

Each event shows its action, actor, target, outcome, time, and correlation ID.
The history does not store recovery credentials, login challenges, signatures,
session tokens, or SSH private keys.

An authenticated account can create a repository with SSH:

```text
ssh -p 2222 tit.example repo create project
```

The account that owns the SSH key becomes the repository owner. The SSH login
name does not select the owner. New repositories use SHA-1 unless the command
selects SHA-256:

```text
ssh -p 2222 tit.example repo create project --object-format sha256
```

Use the versioned JSON mode for scripts:

```text
ssh -p 2222 tit.example repo create project --output json
```

The complete command is `repo create NAME [--object-format sha1|sha256]
[--output human|json]`. Human output can change in a later release. The JSON
object has `version`, `status`, and `repository` fields after success. It has
`version`, `status`, and `error.code` fields after failure. The command returns
zero after success and nonzero after failure.

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

## Milestone 3.2 gate

Install stock OpenSSH. Then, run the Web login gate:

```text
./scripts/check-m3-2
```

Open `/login`, create a challenge, and sign its exact content with the
`tit-auth` SSHSIG namespace. The Web UI accepts the pasted SSHSIG envelope and
creates an opaque session. Read the
[Web login architectural decision record](docs/adr/0011-web-login-sessions.md)
for the session and CSRF behavior.

## Milestone 3.3 gate

Run the repository authorization gate:

```text
./scripts/check-m3-3
```

This command tests public and private visibility, each collaborator role,
suspended accounts, archived repositories, and anonymous HTTP routes. Read the
[repository authorization architectural decision record](docs/adr/0012-repository-authorization.md)
for the complete access matrix.

## Milestone 3.4 gate

Install stock Git and OpenSSH. Then, run the authenticated Git gate:

```text
./scripts/check-m3-4
```

This command tests account-bound SSH keys, each repository role, key revocation,
account suspension, role removal, push permission, and ref policy. Read the
[authenticated Git architectural decision record](docs/adr/0013-authenticated-git.md)
for the service and ref-update checks.

## Milestone 3.5 gate

Run the audit history gate:

```text
./scripts/check-m3-5
```

This command tests successful and failed account, login, repository,
collaborator, and ref audit events. It also tests correlation IDs and secret
exclusion. Read the
[audit history architectural decision record](docs/adr/0014-audit-history.md)
for the transaction and recovery rules.

## Milestone 3.6 gate

Run the SSH repository command gate:

```text
./scripts/check-m3-6
```

This command tests repository creation from the Web UI and SSH. It tests
account ownership, both object formats, human output, JSON output, failure
codes, audit events, and clone access. Read the
[SSH repository command architectural decision record](docs/adr/0015-ssh-repository-commands.md)
for the command and authorization rules.

## Milestone 3 gate

Run the complete account and authorization gate:

```text
./scripts/check-m3
```

This command tests one Web and SSH identity, account recovery, key revocation,
sessions, repository roles, private route isolation, push policy, audit history,
and repository creation from the Web UI and SSH.

## Milestone 4.1 gate

Run the repository event service gate:

```text
./scripts/check-m4-1
```

This command tests event migration, random public IDs, repository sequences,
versioned JSON payloads, atomic metadata and event writes, Git operation
recovery, feed parsing, and sequence pagination. Read the
[repository event service architectural decision record](docs/adr/0016-repository-event-service.md)
for the event type and payload contracts.

## Milestone 4.2 gate

Run the issue workflow gate:

```text
./scripts/check-m4-2
```

This command tests issue numbers, raw Markdown storage, safe rendering, roles,
comments, state, labels, assignees, the event timeline, transaction rollback,
sessions, CSRF checks, and forms that operate without JavaScript. Read the
[issue workflow architectural decision record](docs/adr/0017-issue-workflow.md)
for the permission and event contracts.

## Milestone 4.3 gate

Run the repository watch gate:

```text
./scripts/check-m4-3
```

This command tests granular push, issue, and pull-request preferences, the
“everything” selection, stable watch IDs, permission checks, removal, private
preference handling, CSRF checks, and forms that operate without JavaScript.
Read the [repository watches architectural decision record](docs/adr/0018-repository-watches.md)
for the storage and privacy contracts.

## Milestone 4.4 gate

Run the scoped feed gate:

```text
./scripts/check-m4-4
```

This command tests public issue feeds, hash-only feed tokens, one-time token
display, repository and personalized scopes, current private-repository access,
rotation, revocation, stable event selection, and Atom and RSS parsing. Read the
[scoped feeds architectural decision record](docs/adr/0019-scoped-feeds.md) for
the token, authorization, and ordering contracts.

## Milestone 4.5 gate

Run the metadata search gate:

```text
./scripts/check-m4-5
```

This command tests bounded repository and issue metadata search, public and
private visibility, current collaborator permission, stable result identity,
query validation, and the representative index workload. Read the
[bounded metadata search architectural decision record](docs/adr/0020-bounded-metadata-search.md)
for the limits, authorization, and index decision.

## Milestone 4.6 gate

Install stock OpenSSH. Then, run the SSH issue command gate:

```text
./scripts/check-m4-6
```

This command tests issue creation and listing with human and JSON output. It
tests owner and reader permission, hidden private repositories, suspended
account access, invalid input, raw Markdown storage, and atomic issue events.
Read the [SSH issue command architectural decision record](docs/adr/0021-ssh-issue-commands.md)
for the input, output, authorization, and error contracts.

## Milestone 5.1 gate

Install stock Git. Then, run the pull-request ref gate:

```text
./scripts/check-m5-1
```

This command tests increasing pull-request numbers, SHA-1 and SHA-256 refs,
immutable revision object IDs, concurrent opens, intent recovery before and
after a ref change, the Web forms, and historical schema migration. Read the
[pull-request ref architectural decision record](docs/adr/0022-pull-request-refs.md)
for the record, ref, permission, and recovery contracts.

## Milestone 5.2 gate

Run the pull-request comparison gate:

```text
./scripts/check-m5-2
```

This command tests SHA-1 and SHA-256 merge bases, commit ranges, changed paths,
diffs, immutable revision selection, mergeability states, unrelated histories,
work limits, and Web output. Read the
[pull-request comparison architectural decision record](docs/adr/0023-pull-request-comparison.md)
for the computation, limit, and cache contracts.

## Milestone 5.3 gate

Run the pull-request review gate:

```text
./scripts/check-m5-3
```

This command tests general comments, line comments, approvals, change requests,
immutable byte-path anchors, outdated display, repository permission, atomic
events, the chronological timeline, no-JavaScript Web forms, and historical
schema migration. Read the
[pull-request review architectural decision record](docs/adr/0024-pull-request-review.md)
for the anchor, permission, event, and outdated-state contracts.
