# Contributor rules

Build the smallest correct version of `tit`. The laziness rule tells you not to
write code that is not necessary. You must include validation, security
boundaries, failure handling, and necessary tests.

Portability and security have the same highest priority. Do not decrease
portability or security to make performance better or a change easier. First,
make sure that a design has the necessary behavior. Then, select the design with
minimum code, state, dependencies, and maintenance.

Correct code is more important than speed or an easy method. Do not use an easier
or faster method to bypass a defect. Identify the incorrect invariant. Correct
the applicable layer. Do a test of the failure that caused the defect. The correct
design has only necessary code.

## Scope

- Read `PLAN.md` before you change code.
- Work only on the current milestone and its specified acceptance gate.
- Do not implement subsequent features, compatibility layers, extension points,
  or configuration settings for subsequent milestones.
- Make a small completed change. Do not make a large framework that is not
  completed.
- Preserve the one-binary, no-runtime-Git, no-runtime-OpenSSH design.
- Keep platform-specific code in isolated modules. Record the requirement for
  each module. Portable code must operate without Linux APIs, GNU userland,
  filesystem behavior, path encoding, or a shell.

## Commits

Before each commit, run these commands from the repository root:

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

Do not make the commit if a command fails. The initial Cargo setup must make
these commands available before its commit.

Use this format for each commit message:

```text
type(module): short description
```

Use a lowercase type. Approved types are `build`, `chore`, `ci`, `docs`, `feat`,
`fix`, `init`, `lint`, `perf`, `refactor`, `security`, and `test`. Use the Rust
module name for `module` when one module owns the change. Otherwise, use a short
project area such as `docs`, `web`, `git`, `ssh`, `store`, or `release`. Write
the description in lowercase, use the imperative form, and do not add a final
period.

## Documentation

Write all project documentation in ASD-STE100 Simplified Technical English,
Issue 9. This rule includes `AGENTS.md`, `CONTRIBUTING.md`, `PLAN.md`, the
README, manuals, help text, configuration descriptions, and Rust documentation.

Use the approved STE dictionary and writing rules. Treat established Git, Rust,
protocol, command, and project terms as technical names or technical verbs only
when STE lets you use them. Use one term for one meaning. Do not use an automated
language check as the only proof of conformance. Review each documentation
change against the standard.

### Project terms

Use the technical nouns in this list:

- account, administrator, application, archive, asset, backup, cache, client,
  code, command, configuration, database, executable, feed, and file.
- framework, instance, interface, key, log, module, package, repository,
  role, route, server, session, token, username, Web UI, and workflow.
- connection, constraint, index, parameter, query, query plan, row, schema,
  statement, and table.
- behavior, boundary, build, compatibility, content, crate, dependency,
  environment, feature, host, identity, implementation, and invariant.
- license, metadata, milestone, model, owner, permission, platform, portability,
  priority, scope, state, validation, version, and visibility.
- browser, description, design, documentation, enhancement, form, library,
  reader, rule, sanitizer, subset, summary, user, and writer.
- agent and contributor.
- action, admin, blob, checkout, collaboration, default, development, download,
  encoding, federation, filesystem, frontend, installation, link, organization,
  product, redirect, registry, requirement, secret, setting, and view.
- API, CDE, CLI, CSS, DNS, HTML, HTTP, HTTPS, JavaScript, JSON, Markdown, RSS,
  SQL, SSH, TOML, URL, WAL, and the names of operating systems.
- branch, clone, commit, diff, fetch, Git object, issue, merge, pack, pull
  request, push, ref, tag, and tree.
- Cargo, Git, OpenSSH, Rust, SQLite, and the exact names of crates, commands,
  types, files, paths, and configuration fields.
- acceptance gate, audit event, collaborator role, domain event, feed token,
  invite code, login nonce, recovery credential, and security boundary.
- architectural decision record, built-in SSH server, canonical URL,
  client-side router, progressive enhancement, recoverable runtime failure,
  server-rendered HTML, server-side validation, symbolic logo, and tit bird.
- first-class feed, operating-system library, platform-specific code, read-only
  repository, self-hosted CDE, shared library, and plain-text Markdown.
- blocking job, cgit-like interface, laziness rule, portable code, semantic
  HTML, and statically linked code.
- dependency audit, external test driver, fixture repository, loopback address,
  quality gate, Rust toolchain, standard error, and standard output.
- advertised hostname, hostname, onion hostname, and proxy command.
- database constraint, foreign key, online backup, prepared statement, and
  schema migration.
- durability gate, local filesystem, migration backup, percentile, and
  workload gate.

Use the technical verbs in this list:

- archive, authenticate, authorize, browse, cache, clone, commit, configure,
  fetch, lint, and merge.
- migrate, push, refactor, render, restore, review, serve, sign, subscribe, and
  validate.
- build, conform, create, discuss, implement, own, pass, preserve, rewrite,
  spawn, and store.
- bind, blame, download, publish, query, search, and watch.

Regular plural forms of the technical nouns are permitted. Use the technical
verbs only in the forms that STE permits. A compound technical noun must use
approved project terms and obey the STE multi-word-noun rules.

Names are proper nouns. Examples are ASD-STE100, BSD, cgit, GitHub, Linux,
macOS, MIT License, OAuth, OpenBSD, OpenSSH, and Tor. Keep exact quoted text for
code identifiers, commands, paths, configuration fields, and protocol values.

Do not use a different term for an item or operation in these lists. Add a term
to this section before you use a new project-specific term in documentation.

## Rust

- Write clear, idiomatic stable Rust. Use readable control flow and standard
  data types. Do not use macros, type tricks, or combinators that make the code
  difficult to read.
- Keep one Cargo package until a concrete build or ownership boundary justifies
  another crate.
- Add a type, trait, generic parameter, or module only for an applicable
  invariant or boundary. Do not abstract a single use only because a second use
  can appear subsequently.
- Keep public APIs small. Make items private by default. Give each caller only
  the necessary capability.
- Borrow data when this keeps the code clear. You can use a low-cost clone when
  it makes ownership clear. Do not make code difficult to read to remove small
  allocations.
- Use iterators when they improve clarity and loops when they do not.
- Keep domain rules below HTTP, SSH, and CLI handlers. Handlers translate input
  and output. They do not contain persistence, authorization, or Git policy.
- Do not hold locks, database transactions, or borrowed guards across `.await`.
- Use typed errors inside modules. Add context at process and transport
  boundaries. Do not panic on user input or recoverable runtime failures.
  You can use `unwrap` and `expect` in tests and for proven startup
  invariants with explanatory messages.
- Do not write unsafe Rust or custom cryptographic primitives without an
  explicit plan amendment and review.

## SQL

- Keep all SQL inside the `store` module. Return domain types instead of rows or
  `rusqlite` types.
- Bind all values as parameters. Do not construct SQL from user input.
- Use explicit column lists. Add a constraint or index only for a specified
  invariant or access pattern.
- Keep each committed schema migration unchanged. Test each supported migration
  path with a committed database fixture.
- Enable and verify foreign keys on every connection. Use SQLite integrity and
  foreign-key checks in tests and `tit doctor`.

## Dependencies

- Use the standard library and selected dependencies when they are sufficient.
- Add a crate only when it removes more code and risk than it adds. Record the
  requirement for the crate. Disable unused features and commit `Cargo.lock`
  changes.
- Use established parsing and cryptographic implementations, but keep them
  behind narrow local interfaces where the plan specifies a replaceable
  boundary.

## Web UI

- Each user-facing workflow must work with JavaScript disabled and in browsers
  that do not implement JavaScript. Server-rendered HTML forms, links, and HTTP
  semantics are the full interface.
- JavaScript can only be an optional progressive enhancement. It must not own
  canonical state, give the only validation path, or gate an operation.
- Use the minimum semantic HTML and embedded CSS for an interface that is clear
  and easy to use. Do not add a frontend framework, asset pipeline, client-side
  router, duplicated templates, or decorative markup without a current
  requirement.
- The server must validate all input. Return useful pages after correct and
  incorrect form submissions.

## Tests

- Do tests of public contracts, domain invariants, regressions, and risky
  failure paths. Do not add tests for trivial getters or implementation details.
- Use a real process and a stock Git, SSH, or `ssh-keygen` client for an
  interoperability test. Mocks do not prove a wire protocol.
- Add malformed-input, limit, and restart tests for unauthenticated parsers,
  persistence, ref updates, authentication, and cross-store operations.
- Keep fixtures small and intentional. Each snapshot must be readable enough
  to review as an assertion.
- Before you give code to another person, run `cargo fmt --check` and
  `cargo clippy --all-targets --all-features -- -D warnings`. Run locked tests
  and the applicable release build. A zero-test success is not validation.

## Maintenance

- Do not mix unrelated cleanup with the requested change.
- Do not bypass an issue with special cases, weak validation, duplicate state,
  ignored errors, or retries that hide repeatable failures. When the code can
  enforce the correct behavior, do not use a manual operation instead.
- Delete dead code instead of commenting it out. Do not leave speculative TODOs,
  placeholder implementations, or flags that do nothing.
- Comments explain constraints and non-obvious reasons, not what the syntax
  already says.
- Update `PLAN.md` when a product or architectural decision changes. Do not
  rewrite it to support an easy but incorrect method.
- When two designs are correct, select the design with minimum state and
  dependencies. Also select the design with the minimum number of parts and a
  recovery process that is clear.
