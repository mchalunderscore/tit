# Architectural decision record 0012: Repository authorization

Status: Accepted

Date: 2026-07-23

## Context

A repository can be public or private. A private repository must not enter an
anonymous HTTP or SSH result. HTTP and SSH must not use different role rules.

## Decision

Keep the owner account ID in the repository row. Derive the `owner` role from
this row. Store only the `maintainer`, `writer`, and `reader` roles in the
`repository_collaborator` table. This design prevents a second account from
getting the `owner` role through a collaborator update.

Use one `RepositoryPolicy` service for repository decisions. Give this service
an optional active account, a repository, and an operation. Use these rules:

- A public, active repository permits read access to all users.
- A private, active repository permits read access to its owner and
  collaborators.
- The `owner`, `maintainer`, and `writer` roles permit write access.
- The `owner` and `maintainer` roles permit maintenance access.
- Only the `owner` role permits ownership access.
- A suspended account and an archived repository permit no transport access.

The repository-route middleware validates an optional Web session and supplies
its account to the policy. The public Web routes ask the policy before they open
repository metadata or Git objects. An owner or collaborator can use the Web
UI to read a private repository. Private raw responses and feeds use a private
no-store cache policy.

The SSH repository catalog also comes from the policy. Thus, an HTTP request
and an SSH Git request use the same read rule. Authenticated SSH Git supplies
the account and operation to this service before it starts a Git service.

Offline administrator commands set visibility, set a collaborator role, and
remove a collaborator. The instance lock requires the administrator to stop
the server before these commands change repository access.

## Failure and threat cases

Each policy query gets the account state and collaborator role in the same
SQLite query as the repository record. A suspended account cannot keep access
through an old collaborator row. A missing account has the same permissions as
an anonymous user. A private or archived repository returns the same HTTP 404
result as a missing repository to an anonymous user.

The schema permits only the three non-owner collaborator roles and one role per
account and repository. The application rejects an owner as a collaborator.
Repository ownership does not change when a collaborator role changes.

## Evidence

The policy access-matrix test covers anonymous users, each role, a stranger, a
suspended collaborator, a missing account, both visibility values, and an
archived repository. It also tests role change and removal. The server test
confirms that a Web session can read its private repository and that anonymous
HTTP and SSH Git discovery cannot find it. The public-route test confirms that
private repositories do not appear in summary, raw, feed, search, archive, or
Git discovery routes.

## Consequences

Role and visibility changes take effect on the next policy query. The policy
does not cache authorization state. Architectural decision record 0013 applies
this policy to authenticated Git and ref updates.
