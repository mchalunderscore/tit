# tit

`tit` (tiny git) is a small, self-hosted collaborative development environment
(CDE) for Git. It is written in Rust. Its logo is a small symbolic tit bird.
Its interface is equivalent to a small cgit interface. It also supplies a full
collaboration workflow: browse, clone, discuss, review, merge, publish, and subscribe.

The MIT License applies to `tit`.
The Cargo package is `tit-cde`, short for “the tit collaborative development
environment”, and it installs the `tit` executable.

Portability and security have the same highest priority. First, make sure that a
design has these properties and the necessary behavior. Then, select the design
with minimum code, state, dependencies, and operational surface.

All project documentation must conform to ASD-STE100 Simplified Technical
English, Issue 9. Git, Rust, protocol, command, and project terms are technical
terms where the standard lets writers use them.

The deployed application must be one executable with no necessary runtime
services, project-specific shared libraries, Git executable, or independently installed static
assets. `tit` can use Rust crate dependencies at build time. It can also use
statically linked native code and operating-system libraries. Repositories and
application data stay as standard files. An operator can make a backup of these files
while the application does not run.

System installations keep the full instance in `/srv/tit` by default.
This includes `config.toml`, the metadata database, bare repositories, SSH host
keys, instance secrets, and recoverable operational state.
The metadata database name is `tit.sqlite3`.

## Product boundaries

The initial users are persons and small groups. They want a CDE that is clear
and that they can operate. The primary features are an SSH-native
identity, a small cgit-like web interface, first-class feeds, and interoperable
Git workflows.

The first release will not include organizations, CI or actions, package
registries, project boards, chat, OAuth, or federation. These features will
increase the permission model and operational surface before the core CDE
passes its tests.

Accounts own repositories directly. New repositories use `main` as their
initial branch and are public by default. An owner can make a repository
private.

## Interfaces

### Web

The full web interface operates without JavaScript. It also operates in
browsers that do not implement JavaScript. Each operation uses server-rendered
semantic HTML, normal links, and HTML forms. The server validates all input.

Subsequent JavaScript is an optional progressive enhancement. It must not own
canonical state, give the only validation path, or gate a workflow. Use the
minimum HTML and embedded CSS for an interface that is clear and easy to use.
Version 1 has no frontend framework, client-side router, or asset pipeline.

Repository views must include:

- repository summary and rendered README.
- trees, blobs, raw files, commits, diffs, blame, branches, and tags.
- read-only repository search.
- archive downloads.
- stable clone, raw-file, issue, pull-request, and feed URLs.
- correct `GET` and `HEAD` behavior, redirects, cache validators, and content
  types.

The database stores user content as the plain-text Markdown that the user
supplied. The documentation specifies a small Markdown subset. An HTML sanitizer
must remove active content from the rendered HTML.

### SSH

The built-in SSH server gives Git transport without an external `git` process.
It will subsequently supply a small CDE command interface. This interface
uses the same SSH identity:

```text
ssh -p 2222 tit.example repo create NAME
ssh -p 2222 tit.example issue list OWNER/REPO
ssh -p 2222 tit.example issue create OWNER/REPO
ssh -p 2222 tit.example pr checkout OWNER/REPO NUMBER
```

Command output must be stable for scripts. A specified machine-readable format
supplies this output. Scripts must not use terminal text as data.

Repository clone endpoints accept these two formats:

- `https://host/owner/repo{,.git}`.
- `ssh://host[:port]/owner/repo{,.git}`.

The server ignores the SSH username for
identity and authorization. The public key identifies the account. Thus,
canonical URLs do not include a username. The built-in SSH service listens on
port 2222 by default. Thus,

`ssh://host:2222/owner/repo` is the normal clone URL. A configured port 22 does
not occur in the URL.

`ssh.public_host` sets the hostname in advertised SSH clone URLs. By default,
it uses the host from `public_url`. It accepts a DNS hostname, an IP address, or
an `.onion` hostname. `tit` validates and normalizes the hostname without
resolving it. A Tor client supplies the necessary SSH `ProxyCommand`
configuration.

### Git transport

Bare Git repositories are the canonical source-code storage. The server
publishes pull-request heads as ordinary refs, such as `refs/pull/42/head`.
Standard Git tools can fetch and review these refs when the web interface is
not available.

Git object handling is hash-agile from the first release and supports SHA-1 and
SHA-256 repositories without hard-coded object-ID lengths. New repositories
initially default to SHA-1 for compatibility, while repository creation and
instance configuration can select SHA-256. Version 1 serves public repositories
through HTTPS and all authorized repositories through SSH. Private Git clone and fetch
use SSH. Version 1 does not support Git push through HTTP.

## Accounts and authentication

Account creation asks for a username and an SSH public key. Users can register
multiple keys, label them, inspect their fingerprints and last use, and revoke
them. The server normalizes the case of each username and reserves it
permanently. Thus, it cannot assign links and attribution for that username to
a new account.

Signup must have a random, single-use invitation from `tit invite-code`.
The server stores only the code hash, applies an expiry, and consumes the code in
the same transaction that creates the account.

This offline command creates the first administrator:

```text
tit setup admin <username> "<ssh-public-key>"
```

The command is valid only for an uninitialized instance, creates exactly one
administrator, and prints its recovery code once.

Web login uses the standard SSH signature envelope rather than a custom
cryptographic format. The login page presents a challenge and an exact command
with `ssh-keygen -Y sign` and the dedicated `tit-auth` namespace. The
challenge contains these minimum items:

- protocol version and purpose.
- canonical CDE origin.
- normalized username and selected key fingerprint.
- cryptographically random nonce.
- issue and expiry times.

The server stores only a hash of each short-lived nonce and atomically consumes
it after successful verification. An attacker can replay a stateless challenge
before its expiry. Thus, the server keeps this small state. Successful login
issues a short-lived `Secure`, `HttpOnly`, `SameSite` session cookie. The server
changes this cookie regularly. State-changing requests also require CSRF
protection.

The loss of the sole SSH key must not require a manual database change. Initial
recovery uses a one-time offline recovery code. The server generates this code
during signup. The audit log records recovery, key addition, key removal, and
session revocation. A subsequent version can support SSH certificates. The
first release does not use them.

Authorization is independent from authentication. Repository visibility,
collaborator roles, protected branches, force pushes, and pull-request merges
have explicit rules. The server enforces these rules on the HTTP and SSH paths.

## Collaboration model

Issues support a title, Markdown body, open or closed state, author, assignees,
labels, comments, and an append-only timeline. Keep labels repository-local. Do
not add milestones or project boards initially.

Pull requests add base and head refs, review comments, approvals or requested
changes, mergeability, and merge state. Review comments must anchor to a
commit and file position so subsequent pushes cannot silently change what a comment
referred to. The initial merge strategies are merge commit and fast-forward.
Add squash and rebase subsequently only if their attribution and audit semantics
are clear.

Metadata mutations append their domain event in the same database transaction.
Git mutations use the durable intent protocol because Git refs and SQLite
cannot share a transaction. Feeds, audit history, notifications, and subsequent
webhooks derive from completed events rather than each feature inventing a
second history.

## Feeds and notifications

Atom is the canonical feed model, and the same events are also rendered as RSS.
Stable feeds must include:

- repository activity.
- branch or tag updates.
- issues and issue comments.
- pull requests, reviews, and merges.
- user activity.
- personalized activity such as assignments and mentions.

Watching a repository is granular: pushes, issues, pull requests, or everything.
Public feeds require no authentication. Private and personalized
feeds use random, scoped, revocable bearer URLs and must never expose unrelated
private events. The UI warns that feed URLs are credentials.

Version 1 does not include an in-application notification inbox. Add an inbox
only if feeds do not give sufficient information.
Webhooks can subsequently consume the same event stream, with signed deliveries,
bounded retries, and per-repository scopes.

## Storage

Application metadata belongs in one SQLite database. `tit` accesses it through
`rusqlite`. Source code belongs in bare Git repositories. Do not store issues
and reviews as Git refs or commits. Their transactions, indexes, permissions,
and stable IDs belong to the CDE.

Application-level IDs must not expose reusable storage keys. Public objects
receive stable, non-reassignable identifiers. Relations such as issue comments,
repository collaborators, and pull-request reviews use explicit IDs. SQLite
foreign keys enforce record relationships.

`UNIQUE`, `CHECK`, and `NOT NULL` constraints enforce applicable record rules.
Related mutations use one write transaction. `tit` enables foreign keys on
every database connection.

Metadata search starts with bounded scans or explicit, derived term-index
records. If that stops being adequate, add an embedded full-text index that can
be rebuilt entirely from canonical SQLite tables. Source search remains an
isolated bounded traversal of Git objects. Treat a subsequent index as
derivable state.

### Rust persistence layer

Use **`rusqlite` with bundled SQLite**. Enable only the necessary `bundled` and
`backup` crate features. This choice gives each supported operating system the
same SQLite version without a runtime shared-library dependency.

Do not add an ORM, query builder, connection pool, or migration framework at
this time. Keep SQL, row conversion, transactions, and connection setup inside
the `store` module. Use prepared statements and explicit column lists. Return
domain types from the module instead of database rows or `rusqlite` types.

Use WAL mode, `synchronous=FULL`, a bounded busy timeout, and foreign-key
enforcement. Apply these settings to each connection and verify their effective
values. The first feasibility spike must prove these properties:

- crash recovery.
- concurrent reads and writes.
- online backup and restore.
- transactional migrations across historical schemas.
- constraint and index consistency.
- restoration into the next application version.

Alternatives considered:

- **`native_db` with `redb`** avoids SQL, but it adds a young abstraction and a
  private data format. It also makes relationship checks and external inspection
  application responsibilities.
- **Diesel** supplies compile-time query checks, but its query DSL and generated
  types add a second persistence model.
- **SQLx** supplies asynchronous integration and query checks, but SQLite is
  synchronous and the application must still own its SQL and migrations.
- **System SQLite** decreases binary size, but behavior and enabled features can
  differ between supported operating systems. Bundled SQLite prevents this drift.

Schema migrations are numbered SQL files embedded in the executable. Apply all
pending migrations in one `BEGIN EXCLUSIVE` transaction. Update
`PRAGMA user_version` in that transaction. Keep historical migration files
unchanged. An unsupported migration gap stops startup and gives a clear
diagnostic.

Before an automatic migration, use the SQLite online backup API to create a
recoverable copy. Destructive or long migrations are explicit
`tit admin migrate` operations with a status view and a dry-run where possible.

## Packaging and operation

The executable embeds templates, CSS, model definitions, and other static
resources.
It gives these minimum command groups:

```text
tit serve
tit setup
tit invite-code
tit admin
tit backup
tit restore
tit doctor
```

Administrative commands that must mutate a running instance, such as
`tit invite-code`, use an owner-only Unix control socket beneath `/srv/tit`.
They never open the live SQLite database from a second process.
An offline command must first acquire the exclusive instance lock. If
`tit serve` owns that lock, the command uses the control socket. If this is not
possible, the command stops and gives a clear instruction.

`serve` runs HTTP and SSH listeners from one process, with each listener
independently configurable. HTTP binds to `127.0.0.1:3000` by default and uses a
necessary canonical `public_url`. A reverse proxy usually terminates TLS.
The system configuration path is `/srv/tit/config.toml`, alongside all other
instance data. Command-line overrides and environment variables for secrets are
supported, and precedence must be deterministic.

`backup` briefly establishes a consistent boundary. It uses the SQLite online
backup API. It copies or bundles all repositories and necessary configuration
into an archive with a specified format. `restore` verifies archive format, database
compatibility, and repository integrity before replacing live state. `doctor`
does checks of database records and indexes, schema versions, repository object
integrity, filesystem permissions, key configuration, and listener readiness.

The application produces structured logs without external infrastructure. It
keeps a durable audit trail for security operations. Access logs and metrics are
operational data. An operator can redirect or disable them.

## Remaining decisions

- exact recovery-code and key-rotation flows.
- Git library after the protocol spike.
- the exact release architectures and the meaning of a standalone executable on
  Linux, macOS, FreeBSD, OpenBSD, and NetBSD.

## Implementation plan

Work proceeds through milestone gates. Do not start a milestone before the
preceding gate passes. If a feasibility gate fails, change the design before
you continue the feature work.

**Current milestone:** Milestone 1A — SQLite durability.
Update this marker only after the current milestone gate passes.

### Architecture

Start as one Cargo package, not a workspace of small crates. Module boundaries
isolate the code without making each internal change a cross-crate API:

```text
src/
  main.rs             process startup and top-level error reporting
  cli.rs              command-line contract
  config.rs           configuration loading and validation
  domain/             IDs, entities, invariants, and domain operations
  store/              SQLite schema, queries, migrations, and repositories
  git/                object access, refs, wire protocol, and quarantine
  auth/               SSH keys, SSHSIG challenges, sessions, and recovery
  http/               routes, handlers, templates, and response policy
  ssh/                SSH server, authentication, and command dispatch
  control.rs          local administrative control socket
  feeds/              event projection into Atom and RSS
  ops/                backup, restore, doctor, and maintenance
  telemetry.rs        structured logs and request correlation
templates/            compile-time embedded HTML templates
assets/               compile-time embedded CSS and optional small images
tests/                 black-box and protocol integration tests
```

HTTP handlers, SSH handlers, and CLI commands call application services. They
must not open SQLite, manipulate repository paths, or update refs directly.
The `store` and `git` modules expose narrow interfaces so neither their concrete
crates nor generated types become part of the rest of the application.

`rusqlite` is synchronous. Thus, storage operations run as bounded blocking
jobs. A database transaction cannot stay active across an `.await`.
Begin with `tokio::task::spawn_blocking` behind a semaphore. Replace it with a
dedicated storage executor only if measurements show scheduling overhead or
write starvation.

#### Cross-store mutations

Git refs and SQLite cannot participate in one atomic transaction. Each
operation that changes Git refs and SQLite uses a durable intent record:

1. Validate authorization and write an operation intent containing repository,
   initial refs, proposed refs, actor, and event payload.
2. Receive objects into quarantine and validate size, object format,
   connectivity, and proposed ref policy.
3. Promote validated objects into the repository while they stay unreachable.
4. Atomically update all affected Git refs.
5. In one database transaction, mark the intent completed and append its domain
   and audit events.
6. During startup, compare incomplete intents with the actual refs. Finalize a
   full update. Abandon an update that did not start. During maintenance,
   prune unreachable promoted objects. Stop startup if the ref state is mixed.

Tests must inject process termination after each boundary. Feeds and webhooks
consume only completed events. Thus, recovery cannot announce a push that did
not make refs reachable.

### Technical choices to prove, not assume

Tentative dependencies are Tokio, Axum, `rusqlite`, `ssh-key`, Russh, Askama,
`pulldown-cmark`, an HTML sanitizer, and selected `gix-*` crates. Pin the exact
version in `Cargo.lock` when you add a dependency.

Two capabilities are already plausible but require interoperability tests at
this time. `ssh-key` can parse and verify OpenSSH SSHSIG envelopes. Russh gives
an asynchronous SSH server. Git serving is the blocking uncertainty. Current
`gix-protocol` functionality is client-oriented. libgit2 does not give a full
server-side replacement for `git-upload-pack` and `git-receive-pack`.

Consequently, milestone 1 must implement a small standards-based server that
uses reusable Git primitives. Initially, the server can advertise only the
capabilities that it fully supports. Current Git clients must clone, fetch, and
push without special configuration. If the spike cannot do this safely in its
time limit, stop the work. Select a larger Git implementation or remove the
no-Git-executable constraint.

Do not silently introduce a subprocess. Do not declare that a partial protocol
is ready for production.

### Core data model

All persistent records carry a creation time and stable typed ID. Serialized
event payloads also carry a version. Use random, non-reassignable IDs internally.
Use per-repository increasing issue and pull-request numbers for human-facing
URLs. Normalize usernames and repository slugs once at the domain boundary.
Store the canonical form and display form where necessary.

Initial record families are:

- identity: `Account`, `SshKey`, `RecoveryCredential`, `InviteCode`,
  `LoginNonce`, `Session`.
- repositories: `Repository`, `Collaborator`, `BranchRule`, `RepoCounter`.
- issues: `Issue`, `IssueComment`, `Label`, `IssueLabel`, `Watch`.
- pull requests: `PullRequest`, `Review`, `ReviewComment`.
- delivery and history: `DomainEvent`, `FeedToken`, `AuditEvent`,
  `GitOperationIntent`.

Usernames are lowercase ASCII and match
`[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?`. Repository slugs are lowercase ASCII,
one to 100 characters, can additionally contain internal `.`, `_`, and `-`, and
must not end in `.git`. Reject case variants rather than silently aliasing them.
Reserve route and operational names such as `admin`, `api`, `assets`, `feeds`,
`issues`, and `setup`.

Name each access pattern before you add its index. The store needs these unique
indexes:

- a normalized username.
- an SSH fingerprint.
- an owner and repository slug.
- a repository and issue number.
- a repository and pull-request number.

Secondary indexes cover child records, open items, events, active sessions, and
incomplete operation intents. Invite-code hashes are unique and indexed. The
store does not keep the clear text.

SQLite foreign keys use restrictive delete actions unless the schema specifies
a different action. Initially, do not delete an account or repository. Suspend
an account. Archive a repository. Do not reassign comments, events, usernames,
or public numbers.

`tit doctor` runs `PRAGMA integrity_check` and `PRAGMA foreign_key_check`. It
also checks domain invariants that SQL constraints cannot express. It reports
the exact record IDs in each inconsistency.

Schema migrations stay in source control. Each release fixture includes a
database created by the prior stable version. CI restores and migrates it before
running integrity checks.

### Milestones

#### Milestone 0 — repository and engineering baseline

Goal: establish a small codebase with repeatable quality gates before protocol
experiments create permanent structure.

- **M0.1 Bootstrap Cargo.** Create the `tit-cde` binary package with the MIT
  License, producing the `tit` executable. Pin the Rust toolchain, commit
  `Cargo.lock`, add `.gitignore` and `LICENSE`, and a minimum README that points
  to `PLAN.md` and `CONTRIBUTING.md`.
- **M0.2 Establish the CLI.** Implement `tit --version` and useful `--help`, then
  define stable exit-code, standard-output, and standard-error conventions.
  Add each operational command only in the milestone that implements it. Do not
  ship placeholder subcommands. Reserve the bootstrap syntax in this document:
  `tit setup admin <username> "<ssh-public-key>"` and invitation syntax
  `tit invite-code` without adding inert handlers.
- **M0.3 Establish configuration.** Define a versioned TOML configuration with
  CLI overrides. System installations use `/srv/tit/config.toml` and keep each
  other instance file beneath `/srv/tit`. Per-user installations keep the same
  self-contained layout beneath the platform's XDG data directory. Validate the
  necessary canonical `public_url`, instance directory, listener addresses,
  signup policy, limits, and proxy trust explicitly. Reject unknown fields.
  Bind HTTP to `127.0.0.1:3000` and SSH to port 2222 by default. Generate clone
  URLs from the effective externally advertised addresses rather than assuming
  they match the bind addresses.
- **M0.4 Establish CI.** Require locked builds, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features -- -D warnings`, and unit and
  integration tests. Require checks for dependency licenses and advisories.
  Require release builds on each available operating-system runner. Keep each
  operating-system exclusion explicit and temporary.
- **M0.5 Establish test infrastructure.** Add temporary data-directory helpers,
  real-process tests, fixture repositories, free-port allocation, and structured
  log capture. Use the stock `git`, `ssh`, and `ssh-keygen` clients as external
  test drivers. These clients are absent at runtime.
- **M0.6 Establish contribution checks.** Require `cargo fmt --check` and
  `cargo clippy --all-targets --all-features -- -D warnings` before each
  commit. Require commit messages to use `type(module): short description` as
  specified in `CONTRIBUTING.md`. Review all project documentation for
  conformance with ASD-STE100 Issue 9. Record the approved project-specific
  technical terms that the documentation uses.

Gate: a clean checkout passes each check with one command in the documentation. The
release binary starts when no Git executable is on its `PATH`. All documentation
passes the ASD-STE100 review.

#### Milestone 1 — feasibility and architectural gate

Goal: remove the risks that can make the single-binary design invalid.

##### M1A — SQLite durability

- Add `rusqlite` with only the `bundled` and `backup` features.
- Define two small fixture tables with primary keys, foreign keys, constraints,
  and unique and non-unique indexes.
- Prove insert, update, delete, indexed range scans, concurrent reads,
  serialized writes, busy handling, rollback, WAL checkpoint, and vacuum behavior.
- Prove online backup and restore while reads and writes continue.
- Generate earlier database fixtures with committed fixture programs. Migrate
  through a minimum of two schema versions with transactional SQL migrations.
- Kill a child process during representative writes and migrations. Open the
  database again. Make sure that it has the initial or new full state.
- Verify locking, `synchronous=FULL`, WAL recovery, and backup behavior on each
  supported filesystem and operating system. Do not infer BSD behavior from
  Linux or macOS results.
- Require a local filesystem unless a platform gate proves a different
  filesystem has correct WAL locking and shared-memory behavior.
- Use a workload of 10,000 issues and 1,000,000 events. Measure database growth,
  backup time, migration time, and request latency.

Gate: restored and migrated fixtures pass SQLite integrity checks and `doctor`.
No handler needs direct access to a `rusqlite` type or SQL statement.

The M1A evidence and limits are in
`docs/adr/0001-sqlite-storage.md`. The decision stays provisional until the
Linux and macOS CI workload gates pass.

##### M1B — SSH identity

- Parse and normalize supported OpenSSH public keys and fingerprints.
- Support Ed25519 first. Add ECDSA P-256 and RSA-SHA2 only after interoperability
  tests. Reject DSA, RSA-SHA1, malformed keys, and undersized RSA keys.
- Produce a versioned canonical challenge, verify a real
  `ssh-keygen -Y sign -n tit-auth` signature, enforce origin and namespace, and
  atomically consume the nonce.
- Start a Russh server with a generated host key. Authenticate a stock OpenSSH
  client. Restrict sessions to recognized Git or `tit` commands. Reject
  shells, PTYs, forwarding, agents, and arbitrary exec. Reject environment
  requests except for a strictly parsed `GIT_PROTOCOL` value necessary to negotiate
  supported Git protocol versions.

Gate: positive interoperability tests and negative tests for replay, expiry,
wrong origin, wrong namespace, wrong key, malformed envelopes, and unsupported
algorithms all pass.

##### M1C — read-side Git protocol

- Open, create, and inspect bare SHA-1 and SHA-256 repositories without invoking
  Git. Parameterize object IDs, empty-tree IDs, ref parsing, packet fields, and
  display formatting by repository object format.
- Implement packet-line parsing with strict length and allocation limits.
- Implement the minimum upload-pack negotiation and pack generation necessary
  for ordinary clone and fetch. First, establish SHA-1 interoperability with
  protocol v0/v1. Then, implement SHA-256 protocol negotiation with independent
  fixtures before this milestone passes.
- Expose the same service through SSH exec channels and smart HTTP, with identical
  repository resolution and authorization decisions.
- Use stock Git clients to do tests of empty repositories, branches, tags, deltas, and
  repeated fetches. Also do tests of limited large blobs, non-ASCII filenames, and
  damaged repositories.

Gate: HTTP and SSH clones reproduce each SHA-1 and SHA-256 fixture ref and
object. Fetches do the same. Malformed and oversized requests do not cause
excessive memory growth. Process instrumentation proves that the `tit` server
does not invoke Git. The black-box test driver can invoke Git.

##### M1D — write-side Git protocol

- Implement receive-pack command parsing for SHA-1 and SHA-256 repositories and
  advertise only supported capabilities.
- Stream incoming objects into a per-push quarantine directory with byte,
  object-count, depth, and wall-clock limits.
- Resolve deltas. Validate object hashes, types, reachability, connectivity, ref
  names, initial object IDs, fast-forward policy, and permissions. Do these
  checks before clients can see the refs.
- Promote validated objects, update multiple refs atomically, produce accurate
  per-ref status, and clean each abandoned quarantine.
- Exercise durable operation intents and kill/restart reconciliation at each
  cross-store boundary.

Gate: stock Git can create, update, delete, and reject refs correctly through SSH
for the two object formats. After a failed push, clients cannot see new objects or
partial refs.
The server rejects non-fast-forward and unauthorized updates. Fuzzed packet and
pack inputs do not cause a panic.

##### Milestone 1 decision record

Write an architecture decision record. Include the protocol versions,
capabilities, selected crates, custom protocol code, binary size, resource
measurements, and known omissions. Continue the project only if all four gates
pass. Otherwise, change the product constraints.

#### Milestone 2 — read-only CDE

Goal: ship a useful cgit-like browser before multi-user accounts and
collaboration expand the security model.

- **M2.1 Instance bootstrap.** Implement
  `tit setup admin <username> "<ssh-public-key>"` for an uninitialized instance.
  Validate and normalize the username and key. Create one administrator. Store
  a hashed recovery credential. Show the recovery code one time. Do not run this
  command after bootstrap.
- **M2.2 Repository administration.** Implement local admin commands to create,
  import, rename, archive, and inspect repositories. Canonicalize each path and
  keep filesystem names derived from immutable repository IDs, not user input.
  Accounts own repositories. New repositories use `main` as the initial branch
  and are public by default. Version 1 has no organizations.
- **M2.3 Repository reads.** Implement bounded services for refs, commits,
  history, trees, blobs, raw content, diffs, blame, README selection, and
  archive streaming. Expensive traversals receive limits and cancellation.
- **M2.4 HTTP shell.** Add semantic templates, embedded CSS, consistent
  navigation, and easy-to-use forms. Add security headers, request IDs, useful
  404/405 responses, and correct `GET`/`HEAD` behavior. Run the full black-box Web
  UI suite without JavaScript. Each acceptance test must operate without a
  script engine.
- **M2.5 Public routes.** Add repository summary, tree, blob, raw, commit, diff,
  blame, refs, archive, and clone-discovery routes with stable canonical URLs.
- **M2.6 Markdown.** Render the subset specified in the documentation. Sanitize
  links and HTML. Prevent repository content from injecting active markup into
  CDE pages.
- **M2.7 Public feeds.** Create Atom and RSS entries for repository creation,
  imports, refs, tags, and pushes. Give stable IDs, timestamps, pagination, and
  conditional requests. Validate each format with an independent feed parser.
- **M2.8 Source search.** Implement bounded search over the selected ref without
  a permanent index first. Enforce file-count, byte, result, and time limits.
  Add a derivable index only when measured repository sizes require it.

Gate: an operator can import a public repository. A user can browse, download,
and search it. A user can clone it through HTTP and SSH. Atom and RSS show its
events. Route and rendering snapshots cover empty, binary, large, malformed,
and non-UTF-8 repository content.

#### Milestone 3 — accounts, sessions, and authenticated push

Goal: establish one identity and authorization model shared by the web and SSH
interfaces.

- **M3.1 Account lifecycle.** Implement `/srv/tit/control.sock` with owner-only
  permissions, refusing symlink and non-socket replacements. `tit invite-code`
  submits an owner-authorized request to the running process through that
  socket. The server creates a random, single-use, expiring signup code, prints
  it once, and stores only its hash. Signup must have a valid code, username, and
  first SSH key. Successful signup atomically consumes the invitation, stores a
  hashed recovery credential, and presents the recovery code once. Implement
  use of recovery credentials, key addition and revocation, account suspension,
  and username reservation. Open signup is outside version 1.
- **M3.2 Web login.** Implement challenge display and upload/paste of the SSHSIG
  envelope. Consume each nonce one time. Store opaque session hashes on the
  server. Change sessions after privilege changes. Add CSRF tokens and a
  function that ends all sessions.
- **M3.3 Repository authorization.** Add public/private visibility and the
  `owner`, `maintainer`, `writer`, and `reader` roles. One policy service must
  answer HTTP and SSH decisions.
- **M3.4 Authenticated Git.** Bind SSH public-key authentication to accounts.
  Enforce read/write/ref policy before Git services start and before ref
  updates. HTTP remains read-only in the first stable release. A separate
  credential design can change this rule after project approval.
- **M3.5 Audit history.** Record login, recovery, key, collaborator, repository,
  visibility, and ref-policy mutations. Record the actor, target, outcome, time,
  and request correlation ID. Do not store challenge responses or secrets.
- **M3.6 SSH repository commands.** Implement `repo create` through the same
  application service and authorization policy as the Web UI. Give stable
  human-readable output plus an explicit machine-readable mode.

Gate: the browser and SSH map the same key to the same account. Private
repositories never appear in anonymous pages, feeds, archives, or Git discovery.
The full account recovery and revocation flows pass black-box tests.

#### Milestone 4 — issues, events, and subscriptions

Goal: add the smallest full issue workflow and make events the durable
source for subscriptions.

- **M4.1 Event service.** Assign a monotonically increasing repository event
  sequence and append each event in the same transaction as its metadata
  mutation. Define stable event types and versioned payloads.
- **M4.2 Issues.** Implement create, edit, comment, close, reopen, label, assign,
  and timeline operations. Each mutation validates repository visibility and
  role. It preserves the Markdown that the user supplied and emits one coherent event.
- **M4.3 Watches.** Store granular watch preferences for pushes, issues, and
  pull requests. Do not build an inbox or background mailer.
- **M4.4 Feeds.** Add public issue feeds plus scoped private and personalized
  Atom and RSS feeds for watched activity, assignments, and mentions. Store only
  token hashes, show each token once, permit rotation and revocation, and keep
  secrets out of logs and referrers.
- **M4.5 Search.** Begin with bounded metadata scans behind a search interface.
  Add a derivable embedded index only after representative benchmarks exceed a
  specified latency or memory threshold.
- **M4.6 SSH issue commands.** Implement `issue list` and `issue create` through
  the same issue service used by HTTP. Include the machine-readable output
  contract and identical authorization tests.

Gate: the issue state and its event are in one transaction. Public tokens cannot
retrieve private events. A token cannot retrieve events outside its scope. Feed
order stays stable after edits and restarts.

#### Milestone 5 — pull requests and review

Goal: complete the collaboration loop without turning the CDE into a project
management suite.

- **M5.1 Pull-request refs.** Create immutable numbered PR records and maintain
  `refs/pull/<number>/head`. Record base and head object IDs for each revision
  so reviews keep the context of their initial revision.
- **M5.2 Comparison.** Compute merge bases, commit ranges, diffs, changed paths,
  and mergeability with specified work and output limits. Cache only values
  that Git and PR records can regenerate.
- **M5.3 Review.** Add general comments, line comments anchored to commit/path/
  side/line, approvals, requested changes, outdated-comment display, and a
  chronological timeline.
- **M5.4 Merge.** Implement fast-forward first. Add server-created merge commits
  only after a worktree-free merge spike. The spike must handle renames, modes,
  conflicts, attribution, deterministic parents, and concurrent base changes.
  It must use the same intent recovery as a push.
- **M5.5 Branch rules.** Enforce protected refs, fast-forward-only policy,
  force-push prohibition, deletion prohibition, and merge permissions in the
  common ref-policy service.
- **M5.6 SSH pull-request commands.** Implement `pr checkout` as a stable
  command. Return the standard Git fetch and checkout instructions for the
  pull-request ref. Add a machine-readable mode.

Gate: a contributor can push a branch, open a PR, revise it, receive anchored
review, and merge it. Concurrent updates do not cause different refs and
metadata. Injected process termination does not cause this difference.

#### Milestone 6 — operations and stable release

Goal: make failure recovery as deliberate as normal operation.

- **M6.1 Process lifecycle.** Add graceful shutdown, bounded drain, and listener
  readiness. Lock the data directory without a PID. Do not start a second
  writer.
- **M6.2 Backup and restore.** First, give an offline backup procedure. Then
  add online backup. Take the global write and maintenance gate. Make a
  SQLite online backup. Pause ref mutations and repacking while you copy the
  repositories. Copy the configuration, keys, and secrets into a checksummed
  manifest.
  Create archives with owner-only permissions and state plainly that they
  contain credentials. Restore always targets an empty instance directory
  before an explicit activation step.
- **M6.3 Doctor.** Do checks of configuration, permissions, schema versions,
  record relations, indexes, and incomplete intents. Do checks of Git refs, reachable objects,
  quarantine debris, host keys, and backup manifests. Repair is a different,
  explicit command and never the default behavior. Add typed read-only inspect
  commands. Add a deterministic JSON Lines dump. These tools let operators
  examine SQLite records without application-specific decoding.
- **M6.4 Limits and abuse resistance.** Enforce request sizes, timeouts,
  concurrency, and login and SSH attempt rates. Enforce pack, diff, archive, and
  Markdown limits. Use safe defaults for slow clients.
- **M6.5 Observability.** Emit structured logs, request and operation IDs,
  bounded metrics, and audit records. Sensitive values, authorization headers,
  cookies, feed tokens, recovery codes, and raw signatures are always redacted.
- **M6.6 Release packaging.** Produce checksummed Linux and macOS binaries first,
  followed by FreeBSD, OpenBSD, and NetBSD as their platform gates pass. Include
  applicable native service examples and a minimum Caddy example. Include shell
  completions, a man page, an upgrade guide, and a disaster-recovery exercise.
  Verify each artifact on a clean host without Git or development libraries.

Gate: a new operator can use only the supplied documentation to install,
configure, make a backup, restore, upgrade, and remove `tit`. The operator can
also cause damage to a disposable copy and restore it. All security and recovery
tests use the release artifact, not a debug build.

### Test strategy

Unit tests cover canonicalization, policies, model conversions, challenge
encoding, event projection, packet framing, and ref rules. Property tests cover
path and ref parsing, packet round-trips, state-machine transitions, and model
conversion invariants. Fuzz targets cover these unauthenticated parsers:

- HTTP input that the framework processes.
- SSH commands.
- SSHSIG envelopes.
- Git packet lines.
- pack indexes and streams.
- refs.
- Markdown.

Integration tests start the actual binary with temporary storage and drive it
through HTTP, OpenSSH, `ssh-keygen`, and stock Git. They assert results that a user can see,
filesystem state, database records through public diagnostics, logs, exit
status, and restart behavior. No integration test substitutes a handler call
for the process boundary for which it is a test.

Security tests use an access matrix for each resource type and transport. The
matrix includes each role, suspended accounts, revoked keys, expired sessions,
and scoped feed tokens. Add each new route and SSH command to this matrix.

Performance tests prevent regressions. Use fixed fixtures to measure idle
memory, binary size, startup time, and page latency. Also measure clone
throughput, push memory, feed latency, backup time, and model-upgrade time.

### Definition of done for each task

A task is done only when the documentation describes its public behavior. The
applicable domain layer enforces its invariants. Errors have types and stable
transport results. Limits are explicit. Applicable unit tests and black-box
tests pass.
`cargo fmt --check`,
`cargo clippy --all-targets --all-features -- -D warnings`, locked tests,
dependency checks, and the release build must pass.

Changes to persistence, authentication, authorization, Git refs, backup, or
recovery also require a failure-path test and an entry in the threat model or
operations documentation. Review generated snapshots as assertions. Do not
accept them mechanically.

### Initial execution order

The first implementation cycle must complete only these tasks:

1. M0.1 through M0.6.
2. M1A. It gives the first SQLite decision record and fixtures.
3. M1B. It gives real OpenSSH and SSHSIG interoperability tests.
4. M1C before any HTML repository browser is built.
5. M1D before account, issue, or pull-request work begins.
6. The milestone 1 decision record and an explicit go/no-go review.

This order starts with the highest risks. Web and issue work has less technical
risk than replacement of `git-upload-pack` and `git-receive-pack`. Do a test of
the write protocol first. This shows a design that cannot operate before the
CDE shell is completed.
