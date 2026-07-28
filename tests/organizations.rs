use tempfile::TempDir;

use crate::policy::{PolicyError, RepositoryOperation, RepositoryPolicy};
use crate::store::{NewRepository, RepositoryOrigin, RepositorySettingsUpdate, Store, StoreError};

#[test]
fn organization_namespaces_compose_membership_and_repository_roles() {
    let directory = TempDir::new().expect("create a temporary directory");
    let database = directory.path().join("tit.sqlite3");
    let mut store = Store::open(&database).expect("create the store");
    store
        .connection()
        .execute_batch(
            "INSERT INTO account
             (id, username, is_administrator, state, created_at) VALUES
             (1, 'alice', 1, 'active', 1),
             (2, 'bob', 0, 'active', 1),
             (3, 'carol', 0, 'active', 1);",
        )
        .expect("create organization accounts");

    store
        .create_organization("acme", "Acme", "An organization.", "alice", 2, "create-org")
        .expect("create the organization");
    assert_eq!(
        store
            .maintained_namespaces("alice")
            .expect("read maintained namespaces"),
        vec!["acme", "alice"]
    );
    store
        .set_organization_member("acme", "alice", "bob", "reader", 3, "add-bob")
        .expect("add an organization member");
    assert!(matches!(
        store.update_organization_profile(
            "acme",
            "bob",
            "Changed",
            "A changed profile.",
            4,
            "denied-profile"
        ),
        Err(StoreError::OrganizationDenied)
    ));
    store
        .update_organization_profile(
            "acme",
            "alice",
            "Acme Cooperative",
            "A changed profile.",
            4,
            "update-profile",
        )
        .expect("update the organization profile");
    store
        .create_repository(&NewRepository {
            id: "00112233445566778899aabbccddeeff",
            owner: "acme",
            slug: "project",
            object_format: "sha1",
            default_branch: "refs/heads/main",
            created_at: 4,
            origin: RepositoryOrigin::Created,
            initial_references: &[],
            actor: "alice",
            correlation_id: "create-repository",
        })
        .expect("create an organization repository");
    store
        .update_repository_settings(&RepositorySettingsUpdate {
            owner: "acme",
            slug: "project",
            actor: "alice",
            description: "Private organization code.",
            visibility: "private",
            changed_at: 5,
            correlation_id: "private",
        })
        .expect("make the organization repository private");

    let policy = RepositoryPolicy::new(&database);
    policy
        .authorize(
            Some("alice"),
            "acme",
            "project",
            RepositoryOperation::Maintain,
        )
        .expect("allow an organization owner to maintain");
    policy
        .authorize(Some("bob"), "acme", "project", RepositoryOperation::Read)
        .expect("allow an organization reader to read");
    assert!(matches!(
        policy.authorize(Some("bob"), "acme", "project", RepositoryOperation::Write),
        Err(PolicyError::Denied)
    ));
    assert!(matches!(
        policy.authorize(Some("carol"), "acme", "project", RepositoryOperation::Read),
        Err(PolicyError::Denied)
    ));
    store
        .set_organization_member("acme", "alice", "bob", "writer", 6, "make-writer")
        .expect("set the organization writer");
    policy
        .authorize(Some("bob"), "acme", "project", RepositoryOperation::Write)
        .expect("allow an organization writer to write");
    assert!(matches!(
        policy.authorize(
            Some("bob"),
            "acme",
            "project",
            RepositoryOperation::Maintain
        ),
        Err(PolicyError::Denied)
    ));
    store
        .set_organization_member("acme", "alice", "bob", "reader", 7, "make-reader")
        .expect("restore the organization reader");

    store
        .set_repository_collaborator(
            "acme",
            "project",
            "bob",
            "writer",
            &crate::store::AuditContext {
                actor: "alice",
                correlation_id: "promote-bob",
                created_at: 8,
            },
        )
        .expect("give the reader a repository role");
    policy
        .authorize(Some("bob"), "acme", "project", RepositoryOperation::Write)
        .expect("compose repository and organization roles");
    store
        .set_organization_member("acme", "alice", "bob", "maintainer", 9, "make-maintainer")
        .expect("set the organization maintainer");
    assert_eq!(
        store
            .maintained_namespaces("bob")
            .expect("read the maintainer namespaces"),
        vec!["acme", "bob"]
    );
    assert!(matches!(
        store.set_organization_member("acme", "bob", "carol", "reader", 10, "maintainer-member"),
        Err(StoreError::OrganizationDenied)
    ));
    policy
        .authorize(
            Some("bob"),
            "acme",
            "project",
            RepositoryOperation::Maintain,
        )
        .expect("allow an organization maintainer to maintain");
    store
        .update_organization_profile(
            "acme",
            "bob",
            "Acme Cooperative",
            "A changed profile.",
            11,
            "maintainer-profile",
        )
        .expect("let the maintainer update the organization profile");

    let profile = store
        .organization_profile("acme", 1, 20)
        .expect("read the organization profile");
    assert_eq!(profile.display_name, "Acme Cooperative");
    assert_eq!(profile.description, "A changed profile.");
    assert_eq!(profile.members.len(), 2);
    assert_eq!(profile.members[1].role, "maintainer");
    assert_eq!(profile.repositories.len(), 0);
}

#[test]
fn organization_membership_preserves_one_owner_and_global_namespace_uniqueness() {
    let directory = TempDir::new().expect("create a temporary directory");
    let database = directory.path().join("tit.sqlite3");
    let mut store = Store::open(&database).expect("create the store");
    store
        .connection()
        .execute_batch(
            "INSERT INTO account
             (id, username, is_administrator, state, created_at) VALUES
             (1, 'alice', 1, 'active', 1),
             (2, 'bob', 0, 'active', 1);",
        )
        .expect("create organization accounts");
    store
        .create_organization("acme", "Acme", "", "alice", 2, "create-org")
        .expect("create the organization");

    assert!(matches!(
        store.remove_organization_member("acme", "alice", "alice", 3, "remove-last"),
        Err(StoreError::LastOrganizationOwner)
    ));
    store
        .set_organization_member("acme", "alice", "bob", "owner", 3, "add-owner")
        .expect("add a second owner");
    store
        .remove_organization_member("acme", "alice", "alice", 4, "remove-first")
        .expect("remove the first owner");
    assert!(matches!(
        store.create_organization("bob", "Bob", "", "bob", 5, "collision"),
        Err(StoreError::NamespaceUnavailable(slug)) if slug == "bob"
    ));
}
