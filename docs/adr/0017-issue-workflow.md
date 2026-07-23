# Architectural decision record 0017: Issue workflow

Status: Accepted

Date: 2026-07-22

## Context

An issue needs a stable repository number, a Markdown source, comments, labels,
assignees, state changes, and one chronological timeline. An issue mutation and
its event must not have different results.

The repository roles do not have a separate triage role. The issue workflow
must use the existing roles and must not add a second permission system.

## Decision

Store issues and comments in SQLite. Give each issue and comment a random,
non-reassignable ID. Allocate an increasing issue number from one repository
counter. Use the issue number in the public URL:

```text
/OWNER/REPOSITORY/issues/NUMBER
```

Store the exact Markdown source from the request. Render the supported subset
only when the server makes the HTML page. Limit an issue title to 200 bytes.
Limit an issue body or comment to 256 KiB. Reject control characters except
tab and line terminators in Markdown bodies.

Use these permissions:

- An authenticated account that can read the repository can create an issue
  and add a comment.
- The issue author, an owner, a maintainer, or a writer can edit, close, or
  reopen the issue.
- An owner or maintainer can add or remove labels and assignees.
- An assignee must be active and must be able to read the repository.

Run the permission query, metadata mutation, and event insert in one immediate
SQLite transaction. Use the repository event sequence as the issue timeline
order. Do not add a separate timeline table.

Add these version 1 event types: `issue-created`, `issue-edited`,
`issue-commented`, `issue-closed`, `issue-reopened`, `issue-labeled`,
`issue-unlabeled`, `issue-assigned`, and `issue-unassigned`. Each event payload
has the issue ID and issue number. An event also has the data that identifies
its change, such as the comment ID, label, assignee, state, title, or body.

Keep labels in one repository. Compare label names without ASCII case
differences. Keep a label record after its last removal so a subsequent use has
the same identity.

The Web interface uses server-rendered pages and normal HTML forms. Each
mutation requires an active session and a matching CSRF value. Private issue
reads use the same repository read rule as Git and repository pages.

## Failure and threat cases

An invalid repository, issue number, title, body, label, state, or assignee does
not change the database. A suspended account cannot mutate an issue. An
unauthorized account cannot learn whether an issue exists in a private
repository from a read response.

A database constraint rejects a repeated issue number, an invalid state, an
invalid ID, an invalid label relation, or an event without its issue. If event
insertion fails, SQLite rolls back the issue mutation. The event payload limit
is larger than the permitted Markdown source after JSON escaping of accepted
characters.

## Evidence

Storage tests run the complete workflow with reader, writer, maintainer, owner,
stranger, and suspended-account boundaries. They verify increasing numbers,
exact Markdown source, labels, assignees, comments, state, event payloads, and
timeline order. An injected event failure proves that a comment and its event
roll back together.

A production HTTP test creates, reads, edits, comments on, labels, assigns,
closes, and reopens an issue. It also verifies CSRF rejection, safe Markdown
rendering, the no-JavaScript form flow, and the repository Atom projection.

## Consequences

Issue pages and later SSH commands can use one issue service. Watches and
private feeds can select issue events from the repository event stream. A
subsequent triage role requires an explicit change to the common permission
contract.
