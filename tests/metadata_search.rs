#[allow(dead_code, reason = "the search test uses only username validation")]
#[path = "../src/auth.rs"]
mod auth;
#[path = "../src/domain/mod.rs"]
mod domain;
#[path = "../src/search.rs"]
mod search;
#[allow(dead_code, reason = "the search test uses only metadata storage")]
#[path = "../src/store/mod.rs"]
mod store;

use std::time::{Duration, Instant};

use search::{MetadataSearchError, MetadataSearchService};
use store::{InitialAdministrator, NewRepository, RepositoryOrigin, Store};
use tempfile::TempDir;

#[test]
fn searches_only_authorized_repository_names_with_limits() {
    let directory = TempDir::new().expect("create a search fixture directory");
    let database = directory.path().join("tit.sqlite3");
    let mut store = Store::open(&database).expect("create the search database");
    store
        .create_initial_administrator(&InitialAdministrator {
            username: "alice",
            canonical_key: "ssh-ed25519 AAAAalice",
            fingerprint: "SHA256:alice",
            recovery_hash: &[1; 32],
            created_at: 1,
        })
        .expect("create the search owner");
    store
        .connection()
        .execute_batch(
            "INSERT INTO account (id, username, is_administrator, state, created_at)
             VALUES (2, 'bob', 0, 'active', 1),
                    (3, 'stranger', 0, 'active', 1);",
        )
        .expect("create search accounts");
    create_repository(
        &mut store,
        "11111111111111111111111111111111",
        "public-project",
    );
    create_repository(
        &mut store,
        "22222222222222222222222222222222",
        "private-project",
    );
    store
        .connection()
        .execute_batch(
            "UPDATE repository SET visibility = 'private'
             WHERE slug = 'private-project';
             INSERT INTO repository_collaborator
                 (repository_id, account_id, role, created_at)
             VALUES ('22222222222222222222222222222222', 2, 'reader', 2);",
        )
        .expect("make one repository private");
    drop(store);

    let service = MetadataSearchService::new(&database);
    let public = service
        .search(None, "PUBLIC-PROJECT")
        .expect("search public repositories");
    assert_eq!(public.results.len(), 1);
    assert_eq!(public.query, "PUBLIC-PROJECT");
    assert_eq!(public.results[0].kind, "Repository");
    assert_eq!(public.results[0].url, "/alice/public-project");
    assert!(public.results[0].title.contains("public-project"));
    assert!(public.results[0].summary.is_empty());
    assert_eq!(public.results[0].stable_id.len(), 32);
    assert!(!public.truncated);
    assert!(public.rows_scanned >= 1);
    assert!(public.bytes_scanned > 0);

    let reader = service
        .search(Some("bob"), "private-project")
        .expect("search private repositories as a reader");
    assert_eq!(reader.results.len(), 1);
    assert_eq!(reader.results[0].url, "/alice/private-project");
    assert!(
        service
            .search(Some("stranger"), "private-project")
            .expect("search private repositories as a stranger")
            .results
            .is_empty()
    );

    let restarted = MetadataSearchService::new(&database)
        .search(None, "public-project")
        .expect("repeat repository search after restart");
    assert_eq!(
        restarted
            .results
            .iter()
            .map(|result| (&result.stable_id, &result.url))
            .collect::<Vec<_>>(),
        public
            .results
            .iter()
            .map(|result| (&result.stable_id, &result.url))
            .collect::<Vec<_>>()
    );
    for query in ["", "line\nbreak"] {
        assert!(matches!(
            service.search(None, query),
            Err(MetadataSearchError::InvalidQuery)
        ));
    }
    assert!(matches!(
        service.search(None, &"x".repeat(257)),
        Err(MetadataSearchError::InvalidQuery)
    ));
}

#[test]
#[ignore = "M4.5 representative repository name search measurement"]
fn measures_bounded_repository_name_search_without_an_index() {
    let directory = TempDir::new().expect("create a search measurement directory");
    let database = directory.path().join("tit.sqlite3");
    let mut store = Store::open(&database).expect("create the search measurement database");
    store
        .create_initial_administrator(&InitialAdministrator {
            username: "alice",
            canonical_key: "ssh-ed25519 AAAAalice",
            fingerprint: "SHA256:alice",
            recovery_hash: &[1; 32],
            created_at: 1,
        })
        .expect("create the search measurement owner");
    create_repository(
        &mut store,
        "33333333333333333333333333333333",
        "measurement",
    );
    store
        .connection()
        .execute_batch(
            "WITH RECURSIVE sequence(number) AS (
                 VALUES (1)
                 UNION ALL
                 SELECT number + 1 FROM sequence WHERE number < 9999
             )
             INSERT INTO repository
                 (id, owner_account_id, slug, visibility, state, object_format,
                  created_at, archived_at)
             SELECT printf('%032x', number),
                    1,
                    printf('repository-%05d', number),
                    'public', 'active', 'sha1', number + 2, NULL
             FROM sequence;",
        )
        .expect("create representative repositories");
    drop(store);

    let started = Instant::now();
    let outcome = MetadataSearchService::new(&database)
        .search(None, "repository-09999")
        .expect("measure repository name search");
    let elapsed = started.elapsed();
    assert_eq!(outcome.results.len(), 1);
    assert_eq!(outcome.rows_scanned, 10_000);
    assert!(!outcome.truncated);
    assert!(
        elapsed < Duration::from_millis(250),
        "metadata scan exceeded the 250 ms index threshold: {elapsed:?}"
    );
    eprintln!(
        "searched {} records and {} bytes in {elapsed:?}",
        outcome.rows_scanned, outcome.bytes_scanned
    );
}

fn create_repository(store: &mut Store, id: &str, slug: &str) {
    store
        .create_repository(&NewRepository {
            id,
            owner: "alice",
            slug,
            object_format: "sha1",
            default_branch: "refs/heads/main",
            created_at: 2,
            origin: RepositoryOrigin::Created,
            initial_references: &[],
            actor: "alice",
            correlation_id: "metadata-search",
        })
        .expect("create a search repository");
}
