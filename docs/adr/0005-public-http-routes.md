# Architectural decision record 0005: public HTTP routes

Status: Accepted

Date: 2026-07-22

## Context

`tit` needs stable public routes for repository content and Git clone
discovery. The routes must operate without JavaScript. Repository names can
change, refs can move, and Git paths can contain bytes that are not UTF-8.
Private, archived, and missing repositories must give the same public result.

## Decision

Use `/{owner}/{repository}` as the canonical repository summary and HTTP clone
URL. Accept `/{owner}/{repository}.git` for Git clients. Redirect a browser
request for that alias to the canonical summary. Use a full commit ID in tree,
blob, raw, commit, diff, blame, and archive URLs. Do not use a moving ref in a
content URL.

Encode each Git path byte with URL percent encoding when the byte is not an
ASCII letter, a digit, `-`, `.`, `_`, `~`, or `/`. Decode the path to bytes
before a repository read.
Do not convert a Git path to UTF-8 for object lookup. Display a replacement
character only when HTML must show a path that is not UTF-8.

Use Askama version 0.16.0 for compile-time HTML templates. Its automatic HTML
escaping keeps repository text out of active markup. Use `tokio-stream`
version 0.1.19 only for the interface between the bounded archive channel and
an Axum response body. This interface lets the archive writer send content
without storing the complete archive in memory.

Open repository records through the `store` module. Select only records with
public visibility and active state. Resolve the filesystem path from the
immutable repository ID. Require the canonical repository path to have the
canonical repository directory as its direct parent.

Run SQLite access, Git reads, archive generation, and upload-pack operations as
blocking jobs. Permit a maximum of eight public Web blocking jobs at one time.
Apply the read limits from milestone 2.3. Stream archive data through a bounded
channel. Stop archive work when the HTTP client closes the channel.

## Evidence

The black-box test starts one public server for each Git object format. It uses
real SQLite records and immutable repository paths. Raw HTTP requests browse
summary, refs, commit, diff, tree, blob, raw, blame, and archive routes. The
test verifies GET and HEAD behavior, percent-encoded paths, binary content,
security headers, cache policy, useful 404 pages, and archive content with the
system `tar` reader.

Stock Git protocol version 2 clones through the same public server. The test
also verifies that private and archived repositories do not appear in the
summary, raw, or Git discovery routes. Unit tests cover path bytes that are not
UTF-8 and malformed percent encoding.

## Consequences

A content URL identifies one immutable commit and does not change when a branch
moves. A repository rename changes its owner-and-repository URL, but the
filesystem name and repository ID do not change.

HTML repository views use server-rendered templates and embedded CSS. Raw files
use `application/octet-stream`. Archives use a streamed ustar body. ADR 0006
specifies Markdown rendering and sanitization for README content.
