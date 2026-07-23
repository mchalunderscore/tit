use std::collections::{HashMap, HashSet};
use std::fmt;

use ammonia::{Builder, UrlRelative};
use pulldown_cmark::{Event, Parser, Tag, TagEnd, html};
use url::Url;

#[derive(Default)]
pub struct RenderedMarkdown(String);

impl fmt::Display for RenderedMarkdown {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub fn render(source: &str) -> RenderedMarkdown {
    let mut skipped_link = false;
    let events = Parser::new(source).filter_map(|event| match event {
        Event::Start(Tag::Link { ref dest_url, .. }) if !safe_link(dest_url) => {
            skipped_link = true;
            None
        }
        Event::End(TagEnd::Link) if skipped_link => {
            skipped_link = false;
            None
        }
        Event::Start(Tag::Image { .. }) | Event::End(TagEnd::Image) => None,
        Event::Html(_) | Event::InlineHtml(_) => None,
        event => Some(event),
    });

    let mut rendered = String::new();
    html::push_html(&mut rendered, events);

    let tags = HashSet::from([
        "a",
        "blockquote",
        "br",
        "code",
        "em",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "hr",
        "li",
        "ol",
        "p",
        "pre",
        "strong",
        "ul",
    ]);
    let tag_attributes = HashMap::from([
        ("a", HashSet::from(["href", "title"])),
        ("ol", HashSet::from(["start"])),
    ]);
    let url_schemes = HashSet::from(["http", "https", "mailto"]);
    let mut sanitizer = Builder::new();
    sanitizer
        .tags(tags)
        .tag_attributes(tag_attributes)
        .generic_attributes(HashSet::new())
        .url_schemes(url_schemes)
        .url_relative(UrlRelative::PassThrough)
        .link_rel(Some("nofollow noopener noreferrer"));

    RenderedMarkdown(sanitizer.clean(&rendered).to_string())
}

fn safe_link(destination: &str) -> bool {
    if destination.trim() != destination
        || destination.chars().any(char::is_control)
        || destination.contains('\\')
        || destination.starts_with("//")
    {
        return false;
    }

    match Url::parse(destination) {
        Ok(url) => matches!(url.scheme(), "http" | "https" | "mailto"),
        Err(url::ParseError::RelativeUrlWithoutBase) => true,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::render;

    #[test]
    fn renders_the_documented_subset() {
        let output = render(
            "# Title\n\nA **strong** and *short* paragraph.\n\n- one\n- two\n\n> quote\n\n```rust\nlet safe = true;\n```\n\n[local](docs/guide.md) [web](https://example.com).",
        )
        .to_string();

        assert!(output.contains("<h1>Title</h1>"));
        assert!(output.contains("<strong>strong</strong>"));
        assert!(output.contains("<em>short</em>"));
        assert!(output.contains("<ul>"));
        assert!(output.contains("<blockquote>"));
        assert!(output.contains("<pre><code>let safe = true;"));
        assert!(output.contains("href=\"docs/guide.md\""));
        assert!(output.contains("href=\"https://example.com\""));
        assert!(!output.contains("class="));
    }

    #[test]
    fn removes_html_images_and_active_links() {
        let output = render(
            "<script>alert(1)</script>\n\n<img src=x onerror=alert(2)>\n\n![alt](https://tracker.example/pixel)\n\n[bad](javascript:alert(3)) [data](data:text/html,x) [network](//example.com/x) [mail](mailto:user@example.com)",
        )
        .to_string();

        assert!(!output.contains("script"));
        assert!(!output.contains("img"));
        assert!(!output.contains("tracker.example"));
        assert!(!output.contains("javascript"));
        assert!(!output.contains("data:text"));
        assert!(!output.contains("//example.com"));
        assert!(output.contains("alt"));
        assert!(output.contains("href=\"mailto:user@example.com\""));
        assert!(output.contains("rel=\"nofollow noopener noreferrer\""));
    }

    #[test]
    fn escapes_text_and_rejects_obscure_schemes() {
        let output = render(
            "Text & <b>markup</b>. [case](JaVaScRiPt:alert(1)) [space]( javascript:alert(2)) [slash](\\\\example.com/x)",
        )
        .to_string();

        assert!(output.contains("Text &amp; markup."));
        assert!(!output.contains("href="));
    }
}
