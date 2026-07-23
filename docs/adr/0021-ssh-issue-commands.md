# Architectural decision record 0021: SSH issue commands

Status: Accepted

Date: 2026-07-23

## Context

An account needs to list and create issues without a browser. The SSH public
key must select the account. The SSH commands must use the same issue service
and authorization rules as the Web UI. A script also needs output that does not
depend on human text.

## Decision

Accept these SSH commands:

```text
issue list OWNER/REPOSITORY [--output human|json]
issue create OWNER/REPOSITORY [--output human|json]
```

Limit each command to 512 ASCII bytes. Reject control characters, unknown
words, missing values, repeated options, invalid targets, and unsupported
output values. Do not use a shell tokenizer or pass command data to a process.

The create command reads UTF-8 content from standard input. The first line is
the issue title. All content after the first newline is the plain-text Markdown
body. A title can have a maximum of 200 bytes. A body can have a maximum of 256
KiB. Limit the complete input before UTF-8 parsing. The body can be empty.

The list command returns a maximum of 1,000 issues in decreasing issue-number
order. Human output has one issue on each line:

```text
#12 open Correct the backup check
```

The create command returns this human output:

```text
Created issue alice/project#12.
```

JSON output is one UTF-8 line. A list result has this form:

```json
{"version":1,"status":"success","repository":{"owner":"alice","name":"project"},"issues":[{"number":12,"title":"Correct the backup check","state":"open","author":"alice","created_at":1784800000,"updated_at":1784800000}]}
```

A create result has this form:

```json
{"version":1,"status":"success","repository":{"owner":"alice","name":"project"},"issue":{"number":12,"title":"Correct the backup check","state":"open","author":"alice","created_at":1784800000,"updated_at":1784800000}}
```

A failed result has this form:

```json
{"version":1,"status":"error","error":{"code":"permission-denied"}}
```

Version 1 error codes are `invalid-command`, `invalid-input`, `invalid-target`,
`repository-unavailable`, `permission-denied`, `account-unavailable`,
`service-unavailable`, and `issue-command-failed`. Send JSON results on
standard output. Send human errors on standard error. Return exit status zero
for success and one for failure.

Call `IssueService::list` and `IssueService::create` from a bounded blocking
job. The service applies the common validation and repository authorization.
Issue creation stores the issue and its `issue-created` event in one SQLite
transaction.

## Failure and threat cases

The SSH username does not select the account. The authenticated public key
selects the account. Check the current key identity before the create operation
starts. The store also checks the current account state and repository role.

Return `repository-unavailable` for a missing repository and for a repository
that the account cannot read. Thus, the command does not disclose a private
repository. A reader can list and create issues because the Web UI gives the
same permission to this role. A suspended account cannot use its repository
role or create an issue.

Read create input only for a valid create command. Stop and close the channel
when the input exceeds its limit. Do not interpret title or body content as a
shell language. Serialize JSON with `serde_json` so user content cannot change
the output structure.

## Evidence

The production server test uses stock OpenSSH. It creates an issue as an owner,
lists it in human and JSON modes, and creates an issue as a reader. It proves
that an unrelated account cannot list a private repository and that a suspended
account cannot list it. It also covers invalid create input and the versioned
error output.

The database assertions prove that both commands use the canonical issue
records. They prove exact Markdown preservation, the authenticated authors,
monotonic issue numbers, and one `issue-created` event for each successful
create operation.

## Consequences

The SSH interface has useful issue operations without a shell or a second
authorization implementation. A client must send the title and body on
standard input. A later command version can add fields without changing
version 1.
