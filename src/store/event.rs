use serde_json::json;

pub(super) const PAYLOAD_VERSION: i64 = 1;

#[derive(Clone, Copy)]
pub(super) enum EventKind {
    RepositoryCreated,
    RepositoryImported,
    Push,
    RefCreated,
    RefUpdated,
    RefDeleted,
    TagCreated,
    TagUpdated,
    TagDeleted,
    IssueCreated,
    IssueEdited,
    IssueCommented,
    IssueClosed,
    IssueReopened,
    IssueLabeled,
    IssueUnlabeled,
    IssueAssigned,
    IssueUnassigned,
    PullRequestCreated,
    PullRequestRevised,
}

impl EventKind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::RepositoryCreated => "repository-created",
            Self::RepositoryImported => "repository-imported",
            Self::Push => "push",
            Self::RefCreated => "ref-created",
            Self::RefUpdated => "ref-updated",
            Self::RefDeleted => "ref-deleted",
            Self::TagCreated => "tag-created",
            Self::TagUpdated => "tag-updated",
            Self::TagDeleted => "tag-deleted",
            Self::IssueCreated => "issue-created",
            Self::IssueEdited => "issue-edited",
            Self::IssueCommented => "issue-commented",
            Self::IssueClosed => "issue-closed",
            Self::IssueReopened => "issue-reopened",
            Self::IssueLabeled => "issue-labeled",
            Self::IssueUnlabeled => "issue-unlabeled",
            Self::IssueAssigned => "issue-assigned",
            Self::IssueUnassigned => "issue-unassigned",
            Self::PullRequestCreated => "pull-request-created",
            Self::PullRequestRevised => "pull-request-revised",
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the event payload stores the complete immutable pull-request revision"
)]
pub(super) fn pull_request(
    kind: EventKind,
    pull_request_id: &str,
    number: i64,
    revision: i64,
    title: &str,
    base_ref: &str,
    head_ref: &str,
    base_object_id: &str,
    head_object_id: &str,
) -> VersionedEvent {
    debug_assert!(matches!(
        kind,
        EventKind::PullRequestCreated | EventKind::PullRequestRevised
    ));
    VersionedEvent {
        kind,
        payload: json!({
            "version": PAYLOAD_VERSION,
            "pull_request_id": pull_request_id,
            "number": number,
            "revision": revision,
            "title": title,
            "base_ref": base_ref,
            "head_ref": head_ref,
            "base_object_id": base_object_id,
            "head_object_id": head_object_id,
        })
        .to_string(),
    }
}

pub(super) struct VersionedEvent {
    pub(super) kind: EventKind,
    pub(super) payload: String,
}

pub(super) fn repository(
    kind: EventKind,
    owner: &str,
    repository: &str,
    object_format: &str,
) -> VersionedEvent {
    debug_assert!(matches!(
        kind,
        EventKind::RepositoryCreated | EventKind::RepositoryImported
    ));
    VersionedEvent {
        kind,
        payload: json!({
            "version": PAYLOAD_VERSION,
            "owner": owner,
            "repository": repository,
            "object_format": object_format,
        })
        .to_string(),
    }
}

pub(super) fn push(operation_id: &str) -> VersionedEvent {
    VersionedEvent {
        kind: EventKind::Push,
        payload: json!({
            "version": PAYLOAD_VERSION,
            "operation_id": operation_id,
        })
        .to_string(),
    }
}

pub(super) fn reference(
    kind: EventKind,
    name: &[u8],
    old_target: Option<&str>,
    new_target: Option<&str>,
) -> VersionedEvent {
    debug_assert!(matches!(
        kind,
        EventKind::RefCreated
            | EventKind::RefUpdated
            | EventKind::RefDeleted
            | EventKind::TagCreated
            | EventKind::TagUpdated
            | EventKind::TagDeleted
    ));
    VersionedEvent {
        kind,
        payload: json!({
            "version": PAYLOAD_VERSION,
            "name_hex": encode_hex(name),
            "old_target": old_target,
            "new_target": new_target,
        })
        .to_string(),
    }
}

pub(super) fn issue(
    kind: EventKind,
    issue_id: &str,
    number: i64,
    title: &str,
    body: &str,
) -> VersionedEvent {
    debug_assert!(matches!(
        kind,
        EventKind::IssueCreated | EventKind::IssueEdited
    ));
    VersionedEvent {
        kind,
        payload: json!({
            "version": PAYLOAD_VERSION,
            "issue_id": issue_id,
            "number": number,
            "title": title,
            "body": body,
        })
        .to_string(),
    }
}

pub(super) fn issue_comment(
    issue_id: &str,
    number: i64,
    comment_id: &str,
    author: &str,
    body: &str,
) -> VersionedEvent {
    VersionedEvent {
        kind: EventKind::IssueCommented,
        payload: json!({
            "version": PAYLOAD_VERSION,
            "issue_id": issue_id,
            "number": number,
            "comment_id": comment_id,
            "author": author,
            "body": body,
        })
        .to_string(),
    }
}

pub(super) fn issue_state(
    kind: EventKind,
    issue_id: &str,
    number: i64,
    state: &str,
) -> VersionedEvent {
    debug_assert!(matches!(
        kind,
        EventKind::IssueClosed | EventKind::IssueReopened
    ));
    VersionedEvent {
        kind,
        payload: json!({
            "version": PAYLOAD_VERSION,
            "issue_id": issue_id,
            "number": number,
            "state": state,
        })
        .to_string(),
    }
}

pub(super) fn issue_label(
    kind: EventKind,
    issue_id: &str,
    number: i64,
    label_id: &str,
    label: &str,
) -> VersionedEvent {
    debug_assert!(matches!(
        kind,
        EventKind::IssueLabeled | EventKind::IssueUnlabeled
    ));
    VersionedEvent {
        kind,
        payload: json!({
            "version": PAYLOAD_VERSION,
            "issue_id": issue_id,
            "number": number,
            "label_id": label_id,
            "label": label,
        })
        .to_string(),
    }
}

pub(super) fn issue_assignee(
    kind: EventKind,
    issue_id: &str,
    number: i64,
    assignee: &str,
) -> VersionedEvent {
    debug_assert!(matches!(
        kind,
        EventKind::IssueAssigned | EventKind::IssueUnassigned
    ));
    VersionedEvent {
        kind,
        payload: json!({
            "version": PAYLOAD_VERSION,
            "issue_id": issue_id,
            "number": number,
            "assignee": assignee,
        })
        .to_string(),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write;
        write!(encoded, "{byte:02x}").expect("a string write cannot fail");
    }
    encoded
}
