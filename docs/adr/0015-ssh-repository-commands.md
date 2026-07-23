# Architectural decision record 0015: SSH repository commands

Status: Accepted

Date: 2026-07-22

## Context

An account needs to create a repository without a browser. The SSH command
must use the account that the SSH public key selects. It must not start a shell
or parse a shell language. A script needs output that does not depend on the
human text.

Repository creation is also available in the account Web page. Both transports
must apply the same name rules, owner rules, storage steps, and audit rules.

## Decision

Use one `RepositoryService` for the Web form, the SSH command, and the offline
administrator create command. The Web and SSH methods set the owner to the
authenticated account. The administrator method can name an owner because it
runs only while the offline instance lock is held. The store rejects an owner
account that does not exist or is not active.

Accept this SSH command:

```text
repo create NAME [--object-format sha1|sha256] [--output human|json]
```

The default object format is SHA-1. The default output is human text. Options
can occur in either order, but each option can occur one time. Limit the full
command to 512 ASCII bytes. Reject control characters, unknown words, missing
values, repeated options, invalid names, and unsupported values. Do not use a
shell tokenizer or pass command data to a process.

The human success output has two lines. The first line identifies the owner and
repository. The second line identifies the object format. Human output is for
a person and is not a script interface.

JSON output is one UTF-8 line. A successful result has this form:

```json
{"version":1,"status":"success","repository":{"owner":"alice","name":"project","object_format":"sha1"}}
```

A failed result has this form:

```json
{"version":1,"status":"error","error":{"code":"repository-exists"}}
```

Version 1 error codes are `invalid-command`, `invalid-name`,
`repository-exists`, `account-unavailable`, `service-unavailable`, and
`repository-create-failed`. Send JSON results on standard output. Send human
errors on standard error. Return exit status zero for success and one for
failure.

Create a bare repository in a random pending path under the managed repository
root. Rename it to its random final path before the SQLite insert. If a later
step fails, remove the path that this request created. Insert the repository,
repository event, and successful audit event in one SQLite transaction. Record
a failed audit event in a separate transaction after a rejected create
operation.

## Failure and threat cases

The SSH username does not select the account or owner. The authenticated public
key selects the account. A current active-account check occurs again in the
repository transaction. This check rejects a key if its account became inactive
after SSH authentication.

Repository names use the common domain validator. They cannot contain a path
separator, begin or end with punctuation, use a reserved route name, or end in
`.git`. JSON strings contain only values that this validator and the account
validator accept, so command data cannot add JSON syntax.

The SSH server continues to reject shells, terminal allocation, forwarding,
subsystems, agent forwarding, and arbitrary commands. The repository command
uses the existing bounded worker pool. It does not run Git or OpenSSH at
runtime.

## Evidence

The production server test creates repositories as a non-administrator and as
an administrator. It compares the exact human and JSON output, checks a stable
JSON failure, clones the new empty repository with stock Git, and verifies the
stored owner, object format, and audit outcomes.

The Web production test creates a SHA-256 repository from the account page. It
checks the CSRF failure, redirect, public route, authenticated owner, and HTTP
request correlation ID. The existing SSH security tests continue to reject all
other exec commands and SSH features.

## Consequences

Future SSH issue and pull-request commands can use the same bounded parser and
versioned output rules. A later JSON version can add fields without changing
version 1. Scripts select JSON explicitly and do not parse human text.
