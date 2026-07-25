use serde_json::json;

use crate::codec::encode_lower_hex;
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
    PullRequestCreated,
    PullRequestRevised,
    PullRequestEdited,
    PullRequestClosed,
    PullRequestReopened,
    PullRequestCommented,
    PullRequestLineCommented,
    PullRequestApproved,
    PullRequestChangesRequested,
    PullRequestMerged,
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
            Self::PullRequestCreated => "pull-request-created",
            Self::PullRequestRevised => "pull-request-revised",
            Self::PullRequestEdited => "pull-request-edited",
            Self::PullRequestClosed => "pull-request-closed",
            Self::PullRequestReopened => "pull-request-reopened",
            Self::PullRequestCommented => "pull-request-commented",
            Self::PullRequestLineCommented => "pull-request-line-commented",
            Self::PullRequestApproved => "pull-request-approved",
            Self::PullRequestChangesRequested => "pull-request-changes-requested",
            Self::PullRequestMerged => "pull-request-merged",
        }
    }
}

pub(super) fn pull_request_change(
    kind: EventKind,
    pull_request_id: &str,
    number: i64,
    title: &str,
    body: &str,
    state: &str,
) -> VersionedEvent {
    debug_assert!(matches!(
        kind,
        EventKind::PullRequestEdited
            | EventKind::PullRequestClosed
            | EventKind::PullRequestReopened
    ));
    VersionedEvent {
        kind,
        payload: json!({
            "version": PAYLOAD_VERSION,
            "pull_request_id": pull_request_id,
            "number": number,
            "title": title,
            "body": body,
            "state": state,
        })
        .to_string(),
    }
}

pub(super) fn pull_request_merge(
    pull_request_id: &str,
    number: i64,
    revision: i64,
    method: &str,
    base_ref: &str,
    old_target: &str,
    new_target: &str,
) -> VersionedEvent {
    VersionedEvent {
        kind: EventKind::PullRequestMerged,
        payload: json!({
            "version": PAYLOAD_VERSION,
            "pull_request_id": pull_request_id,
            "number": number,
            "revision": revision,
            "method": method,
            "base_ref": base_ref,
            "old_target": old_target,
            "new_target": new_target,
        })
        .to_string(),
    }
}

pub(super) struct PullRequestReview<'a> {
    pub(super) pull_request_id: &'a str,
    pub(super) number: i64,
    pub(super) review_id: &'a str,
    pub(super) revision: i64,
    pub(super) body: &'a str,
    pub(super) commit_object_id: Option<&'a str>,
    pub(super) path: Option<&'a [u8]>,
    pub(super) side: Option<&'a str>,
    pub(super) line: Option<i64>,
}

pub(super) fn pull_request_review(
    kind: EventKind,
    review: &PullRequestReview<'_>,
) -> VersionedEvent {
    debug_assert!(matches!(
        kind,
        EventKind::PullRequestCommented
            | EventKind::PullRequestLineCommented
            | EventKind::PullRequestApproved
            | EventKind::PullRequestChangesRequested
    ));
    VersionedEvent {
        kind,
        payload: json!({
            "version": PAYLOAD_VERSION,
            "pull_request_id": review.pull_request_id,
            "number": review.number,
            "review_id": review.review_id,
            "revision": review.revision,
            "body": review.body,
            "commit_object_id": review.commit_object_id,
            "path_hex": review.path.map(encode_lower_hex),
            "side": review.side,
            "line": review.line,
        })
        .to_string(),
    }
}

pub(super) struct PullRequestRevision<'a> {
    pub(super) pull_request_id: &'a str,
    pub(super) number: i64,
    pub(super) revision: i64,
    pub(super) title: &'a str,
    pub(super) base_ref: &'a str,
    pub(super) head_ref: &'a str,
    pub(super) base_object_id: &'a str,
    pub(super) head_object_id: &'a str,
}

pub(super) fn pull_request(kind: EventKind, revision: &PullRequestRevision<'_>) -> VersionedEvent {
    debug_assert!(matches!(
        kind,
        EventKind::PullRequestCreated | EventKind::PullRequestRevised
    ));
    VersionedEvent {
        kind,
        payload: json!({
            "version": PAYLOAD_VERSION,
            "pull_request_id": revision.pull_request_id,
            "number": revision.number,
            "revision": revision.revision,
            "title": revision.title,
            "base_ref": revision.base_ref,
            "head_ref": revision.head_ref,
            "base_object_id": revision.base_object_id,
            "head_object_id": revision.head_object_id,
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
            "name_hex": encode_lower_hex(name),
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
