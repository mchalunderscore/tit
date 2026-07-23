# Architectural decision record 0024: Pull-request review

Status: Accepted

Date: 2026-07-23

## Context

A review must keep its original meaning after a branch update. General comments
need Markdown content. A line comment also needs an exact Git anchor. Approvals
and change requests must remain in the history. Each metadata mutation must
have one repository event in the same SQLite transaction.

## Decision

Store each review action as an append-only `pull_request_review` record with a
random permanent ID. Every action refers to one immutable pull-request
revision and one active account. Use these action kinds:

- `comment` stores a general comment.
- `line-comment` stores a line comment.
- `approved` stores an approval.
- `changes-requested` stores a change request.

A line comment stores the exact commit ID, path bytes, side, and one-based line
number. The side is `base` or `head`. The commit ID must equal that side of the
selected revision. The path must be a changed, non-binary file in that
revision. The selected side must contain the path and line. Perform the Git
checks with the bounded comparison and blob reader. Recheck the revision and
commit relation in the write transaction.

Store raw Markdown with a maximum size of 256 KiB. Use the common safe Markdown
renderer for Web output. A comment and a change request require nonempty text.
An approval can have empty text.

An active account that can read the repository can review. Thus, a repository
reader can comment, approve, or request changes. Apply the current repository
policy again in the write transaction. Do not accept review actions on a pull
request that is not open.

Append one specific repository event for each review action. The event payload
contains the review ID, pull-request number, revision number, body, and optional
line anchor. Repository event sequence gives one chronological timeline for
creation, revisions, and review actions.

## Outdated comments

A line comment is current only while its revision is the current pull-request
revision. Show `Outdated` after the pull request gets a later revision. Keep the
original commit, path, side, line, and Markdown visible. General comments,
approvals, and change requests stay in the timeline and do not get the
`Outdated` label.

This rule is conservative. It does not move an anchor to a similar line in a
later commit. Automatic line mapping can change the meaning of a comment, so it
needs a separate design and tests before use.

## Failure and threat cases

Reject an unknown revision, invalid kind, invalid or oversized body, missing
path, binary file, unchanged path, absent side, absent line, line outside the
file, and commit mismatch. Store path data as bytes so a Git path does not need
UTF-8. The no-JavaScript Web form sends the path as hexadecimal text.

If review insertion or event insertion fails, roll back both records. A later
permission change can hide existing review data because reads use the current
repository policy.

## Evidence

The integration test uses SHA-1 and SHA-256 repositories. A reader adds a
general comment, approval, and line comment. An owner requests changes. The
test checks the exact line anchor, rejects a missing line, records a later
revision, verifies event order, and denies the reader after private access is
removed.

The Web integration test submits review actions without JavaScript, renders
safe Markdown, shows the review events, and marks a line comment as outdated
after a later revision. The migration test upgrades every committed schema.

## Consequences

Review history is durable and reproducible from SQLite and immutable Git IDs.
The service does not silently move line comments. A later branch-rule milestone
can consume approval and change-request records without changing their history.
