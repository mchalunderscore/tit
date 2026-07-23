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
use store::{InitialAdministrator, NewIssue, NewRepository, RepositoryOrigin, Store};
use tempfile::TempDir;

#[test]
fn searches_only_authorized_repository_and_issue_metadata_with_limits() {
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
    store
        .create_issue(&NewIssue {
            owner: "alice",
            repository: "public-project",
            actor: "alice",
            title: "Public Needle",
            body: "The public body contains metadata.",
            created_at: 3,
        })
        .expect("create a public issue");
    store
        .comment_issue(
            "alice",
            "public-project",
            1,
            "alice",
            "A needle in a comment must not duplicate the issue result.",
            4,
        )
        .expect("create a matching comment");
    store
        .create_issue(&NewIssue {
            owner: "alice",
            repository: "private-project",
            actor: "alice",
            title: "Private Secret",
            body: "Only a repository reader can find this.",
            created_at: 5,
        })
        .expect("create a private issue");
    store
        .connection()
        .execute_batch(
            "WITH RECURSIVE sequence(number) AS (
                 VALUES (2)
                 UNION ALL
                 SELECT number + 1 FROM sequence WHERE number < 102
             )
             INSERT INTO issue
                 (id, repository_id, number, title, body, state,
                  author_account_id, created_at, updated_at, closed_at)
             SELECT printf('%032x', number + 1000),
                    '11111111111111111111111111111111',
                    number, printf('Bulk match %03d', number), '',
                    'open', 1, number + 10, number + 10, NULL
             FROM sequence;",
        )
        .expect("create enough matches to reach the result limit");
    drop(store);

    let service = MetadataSearchService::new(&database);
    let public = service
        .search(None, "NEEDLE")
        .expect("search public metadata");
    assert_eq!(public.results.len(), 1);
    assert_eq!(public.query, "NEEDLE");
    assert_eq!(public.results[0].kind, "Issue");
    assert_eq!(public.results[0].url, "/alice/public-project/issues/1");
    assert!(public.results[0].title.contains("Public Needle"));
    assert!(public.results[0].summary.contains("public body"));
    assert_eq!(public.results[0].stable_id.len(), 32);
    assert!(!public.truncated);
    assert!(public.rows_scanned >= 3);
    assert!(public.bytes_scanned > 0);

    let bounded = service
        .search(None, "bulk match")
        .expect("search more results than the output limit");
    assert_eq!(bounded.results.len(), 100);
    assert!(bounded.truncated);

    let reader = service
        .search(Some("bob"), "private secret")
        .expect("search private metadata as a reader");
    assert_eq!(reader.results.len(), 1);
    assert_eq!(reader.results[0].url, "/alice/private-project/issues/1");
    assert!(
        service
            .search(Some("stranger"), "private secret")
            .expect("search private metadata as a stranger")
            .results
            .is_empty()
    );

    let restarted = MetadataSearchService::new(&database)
        .search(None, "needle")
        .expect("repeat metadata search after restart");
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
#[ignore = "M4.5 representative metadata search measurement"]
fn measures_bounded_metadata_search_without_an_index() {
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
             INSERT INTO issue
                 (id, repository_id, number, title, body, state,
                  author_account_id, created_at, updated_at, closed_at)
             SELECT printf('%032x', number),
                    '33333333333333333333333333333333',
                    number,
                    printf('Issue %05d', number),
                    printf('Representative metadata body %05d', number),
                    'open', 1, number + 2, number + 2, NULL
             FROM sequence;",
        )
        .expect("create representative metadata");
    drop(store);

    let started = Instant::now();
    let outcome = MetadataSearchService::new(&database)
        .search(None, "representative metadata body 09999")
        .expect("measure metadata search");
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
            created_at: 2,
            origin: RepositoryOrigin::Created,
            initial_references: &[],
            actor: "alice",
            correlation_id: "metadata-search",
        })
        .expect("create a search repository");
}
