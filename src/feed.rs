use std::fmt::Write;
use std::time::{Duration, UNIX_EPOCH};

use thiserror::Error;

use crate::store::{RepositoryEventRecord, RepositoryRecord};

pub(crate) const PAGE_SIZE: usize = 20;

pub(crate) enum FeedFormat {
    Atom,
    Rss,
}

pub(crate) struct FeedPage<'a> {
    pub(crate) repository: &'a RepositoryRecord,
    pub(crate) base_url: &'a str,
    pub(crate) feed_url: &'a str,
    pub(crate) self_url: &'a str,
    pub(crate) events: &'a [RepositoryEventRecord],
    pub(crate) next_before: Option<i64>,
}

impl FeedPage<'_> {
    pub(crate) fn render(&self, format: FeedFormat) -> Result<String, FeedError> {
        match format {
            FeedFormat::Atom => self.atom(),
            FeedFormat::Rss => self.rss(),
        }
    }

    fn atom(&self) -> Result<String, FeedError> {
        let repository_url = self.repository_url();
        let updated = self
            .events
            .iter()
            .map(|event| event.created_at)
            .max()
            .unwrap_or(self.repository.created_at);
        let mut output = String::from(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<feed xmlns=\"http://www.w3.org/2005/Atom\">\n",
        );
        element(&mut output, "id", &self.feed_id())?;
        element(&mut output, "title", &self.feed_title())?;
        element(&mut output, "updated", &atom_date(updated)?)?;
        empty_link(&mut output, "self", self.self_url)?;
        empty_link(&mut output, "alternate", &repository_url)?;
        if let Some(next) = self.next_url() {
            empty_link(&mut output, "next", &next)?;
        }
        for event in self.events {
            output.push_str("<entry>\n");
            element(&mut output, "id", &event_id(&event.event_id))?;
            element(&mut output, "title", &event_title(event))?;
            element(&mut output, "updated", &atom_date(event.created_at)?)?;
            empty_link(&mut output, "alternate", &repository_url)?;
            output.push_str("<author>");
            element(&mut output, "name", &event.actor)?;
            output.push_str("</author>\n<content type=\"text\">");
            escape_xml(&event_description(event), &mut output)?;
            output.push_str("</content>\n</entry>\n");
        }
        output.push_str("</feed>\n");
        Ok(output)
    }

    fn rss(&self) -> Result<String, FeedError> {
        let repository_url = self.repository_url();
        let updated = self
            .events
            .iter()
            .map(|event| event.created_at)
            .max()
            .unwrap_or(self.repository.created_at);
        let mut output = String::from(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<rss version=\"2.0\" xmlns:atom=\"http://www.w3.org/2005/Atom\">\n<channel>\n",
        );
        element(&mut output, "title", &self.feed_title())?;
        element(&mut output, "link", &repository_url)?;
        element(
            &mut output,
            "description",
            &format!("Public events for {}", self.feed_title()),
        )?;
        element(&mut output, "lastBuildDate", &rss_date(updated)?)?;
        atom_link(&mut output, "self", self.self_url)?;
        if let Some(next) = self.next_url() {
            atom_link(&mut output, "next", &next)?;
        }
        for event in self.events {
            output.push_str("<item>\n");
            element(&mut output, "title", &event_title(event))?;
            element(&mut output, "link", &repository_url)?;
            write!(output, "<guid isPermaLink=\"false\">")?;
            escape_xml(&event_id(&event.event_id), &mut output)?;
            output.push_str("</guid>\n");
            element(&mut output, "pubDate", &rss_date(event.created_at)?)?;
            element(&mut output, "description", &event_description(event))?;
            output.push_str("</item>\n");
        }
        output.push_str("</channel>\n</rss>\n");
        Ok(output)
    }

    fn feed_id(&self) -> String {
        format!("urn:tit:repository:{}:events", self.repository.id)
    }

    fn feed_title(&self) -> String {
        format!("{}/{} events", self.repository.owner, self.repository.slug)
    }

    fn repository_url(&self) -> String {
        format!(
            "{}/{}/{}",
            self.base_url, self.repository.owner, self.repository.slug
        )
    }

    fn next_url(&self) -> Option<String> {
        self.next_before
            .map(|before| format!("{}?before={before}", self.feed_url))
    }
}

fn event_id(event_id: &str) -> String {
    format!("urn:tit:event:{event_id}")
}

fn event_title(event: &RepositoryEventRecord) -> String {
    let reference = event
        .ref_name
        .as_deref()
        .map(display_reference)
        .unwrap_or_default();
    match event.kind.as_str() {
        "repository-created" => "Repository created".to_owned(),
        "repository-imported" => "Repository imported".to_owned(),
        "push" => format!("{} pushed", event.actor),
        "ref-created" => format!("Branch {reference} created"),
        "ref-updated" => format!("Branch {reference} updated"),
        "ref-deleted" => format!("Branch {reference} deleted"),
        "tag-created" => format!("Tag {reference} created"),
        "tag-updated" => format!("Tag {reference} updated"),
        "tag-deleted" => format!("Tag {reference} deleted"),
        "issue-created" => issue_title(event, "opened"),
        "issue-edited" => issue_title(event, "edited"),
        "issue-commented" => issue_title(event, "commented on"),
        "issue-closed" => issue_title(event, "closed"),
        "issue-reopened" => issue_title(event, "reopened"),
        "issue-labeled" => issue_value_title(event, "added label", "label"),
        "issue-unlabeled" => issue_value_title(event, "removed label", "label"),
        "issue-assigned" => issue_value_title(event, "assigned", "assignee"),
        "issue-unassigned" => issue_value_title(event, "unassigned", "assignee"),
        _ => "Repository event".to_owned(),
    }
}

fn issue_title(event: &RepositoryEventRecord, action: &str) -> String {
    let number = issue_payload(event)
        .and_then(|payload| payload.get("number")?.as_i64())
        .map(|number| format!("#{number}"))
        .unwrap_or_else(|| "Issue".to_owned());
    format!("{} {action} {number}", event.actor)
}

fn issue_value_title(event: &RepositoryEventRecord, action: &str, field: &str) -> String {
    let Some(payload) = issue_payload(event) else {
        return issue_title(event, action);
    };
    let number = payload
        .get("number")
        .and_then(serde_json::Value::as_i64)
        .map(|number| format!("#{number}"))
        .unwrap_or_else(|| "issue".to_owned());
    let value = payload
        .get(field)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    format!("{} {action} {value} on {number}", event.actor)
}

fn issue_payload(event: &RepositoryEventRecord) -> Option<serde_json::Value> {
    (event.payload_version == 1)
        .then(|| serde_json::from_str(&event.payload).ok())
        .flatten()
}

fn event_description(event: &RepositoryEventRecord) -> String {
    let mut description = event_title(event);
    if let Some(old) = &event.old_target {
        write!(description, " from {old}").expect("a string write cannot fail");
    }
    if let Some(new) = &event.new_target {
        write!(description, " to {new}").expect("a string write cannot fail");
    }
    description
}

fn display_reference(name: &[u8]) -> String {
    let short = name
        .strip_prefix(b"refs/heads/")
        .or_else(|| name.strip_prefix(b"refs/tags/"))
        .unwrap_or(name);
    String::from_utf8_lossy(short).into_owned()
}

fn atom_date(timestamp: i64) -> Result<String, FeedError> {
    Ok(jiff::Timestamp::from_second(timestamp)
        .map_err(|_| FeedError::Timestamp)?
        .to_string())
}

fn rss_date(timestamp: i64) -> Result<String, FeedError> {
    let seconds = u64::try_from(timestamp).map_err(|_| FeedError::Timestamp)?;
    let time = UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or(FeedError::Timestamp)?;
    Ok(httpdate::fmt_http_date(time))
}

fn element(output: &mut String, name: &str, value: &str) -> Result<(), FeedError> {
    write!(output, "<{name}>")?;
    escape_xml(value, output)?;
    writeln!(output, "</{name}>")?;
    Ok(())
}

fn empty_link(output: &mut String, relation: &str, href: &str) -> Result<(), FeedError> {
    write!(output, "<link rel=\"")?;
    escape_xml(relation, output)?;
    output.push_str("\" href=\"");
    escape_xml(href, output)?;
    output.push_str("\" />\n");
    Ok(())
}

fn atom_link(output: &mut String, relation: &str, href: &str) -> Result<(), FeedError> {
    write!(output, "<atom:link rel=\"")?;
    escape_xml(relation, output)?;
    output.push_str("\" href=\"");
    escape_xml(href, output)?;
    output.push_str("\" />\n");
    Ok(())
}

fn escape_xml(value: &str, output: &mut String) -> Result<(), FeedError> {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            character
                if (character.is_control() && !matches!(character, '\t' | '\n' | '\r'))
                    || matches!(character, '\u{fffe}' | '\u{ffff}') =>
            {
                output.push('\u{fffd}');
            }
            character => output.push(character),
        }
    }
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum FeedError {
    #[error("event timestamp is outside the supported range")]
    Timestamp,
    #[error("cannot render the feed")]
    Format(#[from] std::fmt::Error),
}
