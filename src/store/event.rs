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
        }
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

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write;
        write!(encoded, "{byte:02x}").expect("a string write cannot fail");
    }
    encoded
}
