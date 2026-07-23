# Architectural decision record 0006: safe Markdown

Status: Accepted

Date: 2026-07-23

## Context

`tit` stores Markdown source from users and repositories. A public page must not
let this source add active HTML, load a remote image, or use an unsafe link.
The same rules must apply to README files and later CDE text fields.

## Decision

Support these CommonMark elements:

- paragraphs and line breaks;
- headings from level 1 through level 6;
- strong text and emphasized text;
- block quotes;
- ordered and unordered lists;
- inline code and fenced or indented code blocks;
- thematic breaks; and
- links.

Do not support raw HTML, images, tables, task lists, footnotes, heading
attributes, or other extensions. Show the alternative text of an image as
plain text. Ignore a code-block language value.

Permit relative links and absolute `http`, `https`, and `mailto` links. Reject
scheme-relative links, backslashes, control characters, surrounding spaces,
and all other URL schemes. Add `rel="nofollow noopener noreferrer"` to each
link.

Parse Markdown with `pulldown-cmark` version 0.13.4. Remove unsupported parser
events before HTML generation. Clean the generated HTML with `ammonia` version
4.1.4 and an exact allowlist. Permit only the tags that the supported subset
can generate. Permit `href` and `title` on links, and permit `start` on ordered
lists. Do not permit generic attributes.

Ammonia uses `cssparser` version 0.37.0 and `dtoa-short` version 0.3.5. These
two crates use the MPL-2.0 license. Add a license exception for each exact crate
version. Do not add MPL-2.0 to the general license allowlist.

Return rendered content in a separate Rust type. The Askama template can mark
only this type as safe HTML. Continue to use normal Askama escaping for all
other repository content.

## Evidence

Unit tests render each supported element. They also use raw scripts, raw
images, Markdown images, active URL schemes, scheme-relative URLs, mixed-case
schemes, controls, and backslashes. The public-route test reads hostile content
from a real Git repository and checks the complete server-rendered page.

## Consequences

README files have a useful small format without an active-content path. Remote
images cannot track a page view. A future milestone can use the same renderer
for issue, pull-request, and comment bodies. A change to the subset or URL
policy needs a change to this record and its hostile-content tests.
