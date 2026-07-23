# Architectural decision record 0018: Repository watches

Status: Accepted

Date: 2026-07-22

## Context

An account must be able to select repository activity for later personalized
feeds. The first release does not have an inbox or a background mail process.
Watch data is private preference data. It must not appear in the public
repository event stream.

## Decision

Store one optional watch record for an account and repository. Give the record
a random, non-reassignable ID. Store three independent Boolean preferences:

- pushes;
- issues;
- pull requests.

All three selected values mean “everything.” No selected value means “stop
watching.” Delete the watch record in that case. Do not store a record that has
no selected activity.

An active account can change a watch only when it can read the repository. Use
the common repository visibility and role data for this check. Anonymous users
can read the watch page for a public repository, but the page does not show
private preference data.

Use one upsert for a preference change. Keep the watch ID and creation time when
the account changes its selections. Add an index on account and repository for
the personalized feed query in Milestone 4.4.

Do not append a repository event for a watch change. A public event would expose
private preference data and could cause a watch to notify itself. The watch row
is the canonical preference state.

The Web page uses three normal HTML select controls. The page and form operate
without JavaScript. The form requires an active session and a matching CSRF
value.

## Failure and threat cases

A database constraint rejects an invalid ID, a non-Boolean value, a repeated
account and repository pair, or a row with no selected activity. A suspended
account and an account that cannot read a private repository cannot read or
change its watch through the service.

A private watch is selected only after the service checks current repository
access. A subsequent feed request must check access again. Thus, a retained
watch cannot restore access after a role is removed.

## Evidence

Storage tests select everything, change to issue-only activity, preserve the
watch ID and creation time, reject unauthorized accounts, reject an empty row,
and delete the row when all selections are clear. They also prove that watch
changes do not append repository events.

A production HTTP test reads the anonymous page, sets all preferences with an
authenticated form, reads the selected values, and clears the watch. The common
Web workflow test continues to verify CSRF rejection.

## Consequences

Milestone 4.4 can select watched event kinds without a schema change. A later
inbox or mail process can use the same preferences, but this milestone does not
add either process.
