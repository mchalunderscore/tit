#[path = "../src/policy.rs"]
mod policy;
#[allow(dead_code, reason = "the policy test uses only repository storage")]
#[path = "../src/store/mod.rs"]
mod store;

use policy::{PolicyError, RefChange, RepositoryOperation, RepositoryPolicy};
use store::{AuditContext, NewRepository, RepositoryOrigin, Store, StoreError};
use tempfile::TempDir;

#[test]
fn enforces_the_repository_role_matrix() {
    let directory = TempDir::new().expect("create a policy fixture directory");
    let database = directory.path().join("tit.sqlite3");
    let mut store = Store::open(&database).expect("create the policy database");
    for (id, username, state) in [
        (1, "owner", "active"),
        (2, "maintainer", "active"),
        (3, "writer", "active"),
        (4, "reader", "active"),
        (5, "stranger", "active"),
        (6, "suspended", "active"),
    ] {
        store
            .connection()
            .execute(
                "INSERT INTO account (id, username, is_administrator, state, created_at)
                 VALUES (?1, ?2, 0, ?3, 1)",
                rusqlite::params![id, username, state],
            )
            .expect("create a policy account");
    }
    store
        .create_repository(&NewRepository {
            id: "0123456789abcdef0123456789abcdef",
            owner: "owner",
            slug: "project",
            object_format: "sha1",
            default_branch: "refs/heads/main",
            created_at: 2,
            origin: RepositoryOrigin::Created,
            initial_references: &[],
            actor: "admin-cli",
            correlation_id: "test",
        })
        .expect("create a policy repository");
    for (username, role) in [
        ("maintainer", "maintainer"),
        ("writer", "writer"),
        ("reader", "reader"),
        ("suspended", "writer"),
    ] {
        store
            .set_repository_collaborator("owner", "project", username, role, &audit(3))
            .expect("set a collaborator role");
    }
    store
        .suspend_account("suspended", true, 4, "admin-cli", "test")
        .expect("suspend a collaborator");

    let policy = RepositoryPolicy::new(&database);
    assert_allowed(&policy, None, RepositoryOperation::Read);
    assert_denied(&policy, None, RepositoryOperation::Write);
    store
        .set_repository_visibility("owner", "project", "private", 5, "admin-cli", "test")
        .expect("make the repository private");

    for operation in operations() {
        assert_allowed(&policy, Some("owner"), operation);
    }
    assert_allowed(&policy, Some("maintainer"), RepositoryOperation::Read);
    assert_allowed(&policy, Some("maintainer"), RepositoryOperation::Write);
    assert_allowed(&policy, Some("maintainer"), RepositoryOperation::Maintain);
    assert_denied(&policy, Some("maintainer"), RepositoryOperation::Own);
    assert_allowed(&policy, Some("writer"), RepositoryOperation::Read);
    assert_allowed(&policy, Some("writer"), RepositoryOperation::Write);
    assert_denied(&policy, Some("writer"), RepositoryOperation::Maintain);
    assert_denied(&policy, Some("writer"), RepositoryOperation::Own);
    assert_allowed(&policy, Some("reader"), RepositoryOperation::Read);
    for operation in [
        RepositoryOperation::Write,
        RepositoryOperation::Maintain,
        RepositoryOperation::Own,
    ] {
        assert_denied(&policy, Some("reader"), operation);
    }
    for actor in [None, Some("stranger"), Some("suspended"), Some("missing")] {
        for operation in operations() {
            assert_denied(&policy, actor, operation);
        }
    }
}

#[test]
fn applies_role_visibility_and_archive_changes_immediately() {
    let directory = TempDir::new().expect("create a policy fixture directory");
    let database = directory.path().join("tit.sqlite3");
    let mut store = Store::open(&database).expect("create the policy database");
    for (id, username) in [(1, "owner"), (2, "member")] {
        store
            .connection()
            .execute(
                "INSERT INTO account (id, username, is_administrator, state, created_at)
                 VALUES (?1, ?2, 0, 'active', 1)",
                rusqlite::params![id, username],
            )
            .expect("create a policy account");
    }
    store
        .create_repository(&NewRepository {
            id: "fedcba9876543210fedcba9876543210",
            owner: "owner",
            slug: "project",
            object_format: "sha1",
            default_branch: "refs/heads/main",
            created_at: 2,
            origin: RepositoryOrigin::Created,
            initial_references: &[],
            actor: "admin-cli",
            correlation_id: "test",
        })
        .expect("create a policy repository");
    let policy = RepositoryPolicy::new(&database);
    assert_eq!(
        policy
            .public_repositories()
            .expect("list repositories")
            .len(),
        1
    );

    store
        .set_repository_visibility("owner", "project", "private", 3, "admin-cli", "test")
        .expect("make the repository private");
    assert!(
        policy
            .public_repositories()
            .expect("list repositories")
            .is_empty()
    );
    store
        .set_repository_collaborator("owner", "project", "member", "writer", &audit(3))
        .expect("add a writer");
    assert_allowed(&policy, Some("member"), RepositoryOperation::Write);
    store
        .set_repository_collaborator("owner", "project", "member", "reader", &audit(4))
        .expect("change the role");
    assert_denied(&policy, Some("member"), RepositoryOperation::Write);
    assert_allowed(&policy, Some("member"), RepositoryOperation::Read);
    store
        .remove_repository_collaborator("owner", "project", "member", 5, "admin-cli", "test")
        .expect("remove the collaborator");
    assert_denied(&policy, Some("member"), RepositoryOperation::Read);
    assert!(matches!(
        store.set_repository_collaborator("owner", "project", "owner", "reader", &audit(5)),
        Err(StoreError::OwnerCollaborator)
    ));
    store
        .archive_repository("owner", "project", 6, "admin-cli", "test")
        .expect("archive the repository");
    for operation in operations() {
        assert_denied(&policy, Some("owner"), operation);
    }
}

#[test]
fn applies_common_protected_ref_and_merge_rules() {
    let directory = TempDir::new().expect("create a ref-policy fixture directory");
    let database = directory.path().join("tit.sqlite3");
    let mut store = Store::open(&database).expect("create the ref-policy database");
    for (id, username) in [(1, "owner"), (2, "maintainer"), (3, "writer")] {
        store
            .connection()
            .execute(
                "INSERT INTO account (id, username, is_administrator, state, created_at)
                 VALUES (?1, ?2, 0, 'active', 1)",
                rusqlite::params![id, username],
            )
            .expect("create a ref-policy account");
    }
    store
        .create_repository(&NewRepository {
            id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            owner: "owner",
            slug: "project",
            object_format: "sha1",
            default_branch: "refs/heads/main",
            created_at: 2,
            origin: RepositoryOrigin::Created,
            initial_references: &[],
            actor: "admin-cli",
            correlation_id: "test",
        })
        .expect("create a ref-policy repository");
    for (username, role) in [("maintainer", "maintainer"), ("writer", "writer")] {
        store
            .set_repository_collaborator("owner", "project", username, role, &audit(3))
            .expect("set a ref-policy collaborator");
    }
    let policy = RepositoryPolicy::new(&database);
    for actor in ["owner", "maintainer"] {
        policy
            .authorize_ref_change(
                actor,
                "owner",
                "project",
                b"refs/heads/main",
                RefChange::FastForward,
            )
            .expect("allow a maintainer fast-forward on main");
        policy
            .authorize_merge(actor, "owner", "project")
            .expect("allow a maintainer merge");
    }
    assert!(matches!(
        policy.authorize_ref_change(
            "writer",
            "owner",
            "project",
            b"refs/heads/main",
            RefChange::FastForward,
        ),
        Err(PolicyError::Denied)
    ));
    assert!(matches!(
        policy.authorize_ref_change(
            "owner",
            "owner",
            "project",
            b"refs/heads/main",
            RefChange::Delete,
        ),
        Err(PolicyError::Denied)
    ));
    assert!(matches!(
        policy.authorize_ref_change(
            "owner",
            "owner",
            "project",
            b"refs/heads/topic",
            RefChange::Force,
        ),
        Err(PolicyError::Denied)
    ));
    policy
        .authorize_ref_change(
            "writer",
            "owner",
            "project",
            b"refs/heads/topic",
            RefChange::Create,
        )
        .expect("allow a writer topic branch");
    store
        .update_repository_default_branch(
            "owner",
            "project",
            "maintainer",
            "refs/heads/trunk",
            4,
            "default-branch",
        )
        .expect("change the protected default branch");
    policy
        .authorize_ref_change(
            "writer",
            "owner",
            "project",
            b"refs/heads/main",
            RefChange::FastForward,
        )
        .expect("allow a writer to update the former default branch");
    assert!(matches!(
        policy.authorize_ref_change(
            "writer",
            "owner",
            "project",
            b"refs/heads/trunk",
            RefChange::FastForward,
        ),
        Err(PolicyError::Denied)
    ));
    assert!(matches!(
        policy.authorize_ref_change(
            "owner",
            "owner",
            "project",
            b"refs/heads/trunk",
            RefChange::Delete,
        ),
        Err(PolicyError::Denied)
    ));
    policy
        .authorize_ref_change(
            "writer",
            "owner",
            "project",
            b"refs/tags/v1",
            RefChange::TagUpdate,
        )
        .expect("allow a writer tag update");
    assert!(matches!(
        policy.authorize_merge("writer", "owner", "project"),
        Err(PolicyError::Denied)
    ));
}

fn operations() -> [RepositoryOperation; 4] {
    [
        RepositoryOperation::Read,
        RepositoryOperation::Write,
        RepositoryOperation::Maintain,
        RepositoryOperation::Own,
    ]
}

fn audit(created_at: i64) -> AuditContext<'static> {
    AuditContext {
        actor: "admin-cli",
        correlation_id: "test",
        created_at,
    }
}

fn assert_allowed(policy: &RepositoryPolicy, actor: Option<&str>, operation: RepositoryOperation) {
    policy
        .authorize(actor, "owner", "project", operation)
        .expect("authorize the repository operation");
}

fn assert_denied(policy: &RepositoryPolicy, actor: Option<&str>, operation: RepositoryOperation) {
    assert!(matches!(
        policy.authorize(actor, "owner", "project", operation),
        Err(PolicyError::Denied)
    ));
}
