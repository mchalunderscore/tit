# tit

`tit` is a small, self-hosted collaborative development environment for Git.
One executable provides:

- a server-rendered Web UI;
- public HTTP clone and authenticated SSH clone and push;
- accounts that use SSH keys;
- repositories, issues, pull requests, reviews, and a protected default branch;
- repository and issue RSS feeds;
- repository name and source search;
- public user profiles;
- backup, restore, diagnostics, audit, and repair commands.

The server does not require Git, OpenSSH, JavaScript, or an external database
at run time. SQLite stores application data. Bare repository directories store
Git objects and refs.

## Build

Install the Rust toolchain that `rust-toolchain.toml` specifies. Build the
release executable:

```text
cargo build --locked --release
```

The executable is `target/release/tit`.

## Configure

Create a private instance directory and copy the example configuration:

```text
install -d -m 700 /srv/tit
install -m 600 config.example.toml /srv/tit/config.toml
```

Set `public_url`, the HTTP listener, and the SSH listener and advertised
hostname in `/srv/tit/config.toml`. Use HTTPS for a public instance. The
included files in `release/examples/` contain service definitions and a Caddy
example for Linux, macOS, FreeBSD, OpenBSD, and NetBSD.

Create the first administrator:

```text
tit --config /srv/tit/config.toml setup admin alice "SSH_PUBLIC_KEY"
```

The command prints one recovery credential. Store it offline.

Start the HTTP and SSH servers:

```text
tit --config /srv/tit/config.toml serve
```

The server creates and preserves an Ed25519 SSH host key in the instance
directory. It holds an instance lock until shutdown. Send SIGINT or SIGTERM for
a controlled shutdown.

Use `GET /healthz` as a readiness check. Use `GET /metrics` for the fixed,
unlabelled process counters.

## Accounts and login

Create a one-time signup code while the server runs:

```text
tit --config /srv/tit/config.toml invite-code
```

Open `/signup` and submit the code with an SSH public key. The Web UI displays
the new recovery credential one time.

Web login uses SSH approval. Start login in the browser, then run the displayed
`auth` SSH command. The fallback flow signs a short-lived challenge with
`ssh-keygen -Y sign`. Account recovery replaces the account keys, revokes
sessions and feed tokens, and issues a new recovery credential.

Each account has a public `/<username>` profile. The account can publish a
plain-text bio and contact email. The profile lists only public repositories.
The account page lists active and revoked SSH keys. A fresh SSH `auth`
approval is required to add or revoke a key.

## Repositories

An authenticated account can create a repository through SSH:

```text
ssh -p 2222 tit.example repo create project
```

List all SSH commands:

```text
ssh -p 2222 tit.example help
```

An invalid SSH command returns a nonzero status and directs the user to
`help`.

Clone a public repository through HTTP or SSH:

```text
git clone https://tit.example/alice/project.git
git clone ssh://tit@tit.example:2222/alice/project.git
```

HTTP Git access is read-only. SSH permits repository readers to clone and
writers, maintainers, and owners to push. The SSH login name does not select
the account; the SSH key does.

An administrator can import an existing bare repository while the server is
stopped:

```text
tit --config /srv/tit/config.toml admin repository import \
  alice project /absolute/path/project.git
```

Owners and maintainers can change a repository description, visibility, and
collaborators on the repository settings page. They can select an existing
branch as the default branch and archive the repository. The owner can rename
or unarchive the repository. A rename does not move the bare repository
directory.

The ref policy is fixed. `tit` rejects force updates, prevents deletion of the
default branch, and permits only owners and maintainers to update it.

Use the offline administrator commands to import or rename repositories and
to administer accounts. Run the applicable command with `--help` for its exact
arguments:

```text
tit admin repository --help
tit admin account --help
```

## Web UI

Anonymous users can browse recently updated public repositories and public
profiles. Authenticated users get an account overview and their repositories.

A repository page provides refs, commits, trees, blobs, blame, archives,
source search, issues, pull requests, watch state, and RSS. The recent commit
list shows ten commits and links to the complete commit view. Forms and
navigation operate without JavaScript.

Issue and pull-request comments use bounded Markdown. Raw HTML and unsafe links
do not render.

Authenticated accounts can open `/activity` to see recent events from watched
repositories. A commit page can download a `.patch` file. Each pull-request
revision has an immutable `.patch` download. These files work with
`git apply`.

The SSH interface can list and create issues and pull requests. It can also
comment on, close, and reopen issues, and close and reopen pull requests.
Commands support human output and versioned JSON output. Run
`ssh -p 2222 tit.example help` for the exact syntax.

## Backup and restore

Create a backup while the server is stopped or active:

```text
tit --config /srv/tit/config.toml backup /var/backups/tit-backup.tar
```

An online backup uses the private control socket and pauses Git ref mutations
while it copies consistent state. A backup contains credentials. Store it as a
secret.

Restore to a new, empty instance directory:

```text
install -d -m 700 /srv/tit-restored
tit restore /var/backups/tit-backup.tar /srv/tit-restored
tit --config /srv/tit-restored/config.toml doctor
```

Restore does not activate the new instance. Stop the old server before you
start the restored instance.

## Diagnostics

Check an instance without changing it:

```text
tit --config /srv/tit/config.toml doctor
tit --config /srv/tit/config.toml doctor \
  --backup /var/backups/tit-backup.tar
```

Inspect records or write deterministic JSON Lines:

```text
tit --config /srv/tit/config.toml inspect account alice
tit --config /srv/tit/config.toml inspect repository alice project
tit --config /srv/tit/config.toml dump >tit-dump.jsonl
```

The dump can contain credential and token hashes. Store it as a secret.

Run a repair command only after `doctor` reports the applicable problem and
only while the server is stopped:

```text
tit --config /srv/tit/config.toml repair intents
tit --config /srv/tit/config.toml repair quarantine
```

Run maintenance while the server is stopped. This command removes expired or
revoked workflow records and old audit events, then compacts SQLite. The
default retention period is 365 days:

```text
tit --config /srv/tit/config.toml maintenance
tit --config /srv/tit/config.toml maintenance --retention-days 90
```

## Upgrade

Make and verify a backup before an upgrade. Stop the server, replace the
executable, and start the server. `tit` applies forward-only SQLite migrations
during startup. Run `doctor` after startup.

To go back to an older version, restore the pre-upgrade backup into a new
instance directory. Do not run an older executable against a newer database.

## Release packages

Build a release archive for the current host:

```text
cargo build --locked --release
./scripts/package-release target/release/tit dist
```

Verify an archive and its checksum:

```text
./scripts/verify-release-artifact \
  dist/tit-VERSION-TARGET.tar.gz \
  dist/tit-VERSION-TARGET.tar.gz.sha256
```

The package contains the executable, example service files, shell
completions, the manual page, the example configuration, this README, and the
license.

## Development

Read [CONTRIBUTING.md](CONTRIBUTING.md) before you change code. Run the quality
gate directly:

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo deny check advisories licenses sources
cargo build --locked --release
```

The ignored workload tests are explicit performance checks:

```text
cargo test --locked --release --test git_reads \
  measures_bounded_search_without_an_index -- --ignored --nocapture
cargo test --locked --release --test metadata_search \
  measures_bounded_repository_name_search_without_an_index \
  -- --ignored --nocapture
cargo test --locked --release --test sqlite_workload \
  -- --ignored --nocapture
```

`tit` is licensed under the MIT License. See [LICENSE](LICENSE).
