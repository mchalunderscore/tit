mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};
use support::{
    TestInstance, create_bare_git_fixture, create_ssh_key_fixture, free_address,
    read_stock_ssh_configuration,
};
use tempfile::TempDir;

const CURRENT_DATABASE: &str = concat!(
    include_str!("fixtures/sqlite/v5.sql"),
    include_str!("../src/store/migrations/006_repository_events.sql"),
    include_str!("../src/store/migrations/007_account_lifecycle.sql"),
    include_str!("../src/store/migrations/008_web_sessions.sql"),
    include_str!("../src/store/migrations/009_repository_authorization.sql"),
    include_str!("../src/store/migrations/010_audit_history.sql"),
    include_str!("../src/store/migrations/011_domain_events.sql"),
    include_str!("../src/store/migrations/012_issues.sql"),
    include_str!("../src/store/migrations/013_watches.sql"),
    "PRAGMA user_version = 13;\n",
);

#[test]
fn help_and_version_use_standard_output() {
    for argument in ["--help", "--version"] {
        let output = Command::new(env!("CARGO_BIN_EXE_tit"))
            .arg(argument)
            .output()
            .expect("run tit");
        assert!(output.status.success());
        assert!(!output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn a_cli_error_uses_exit_code_two_and_standard_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_tit"))
        .arg("--unknown")
        .output()
        .expect("run tit");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn validates_configuration_without_output() {
    let instance = TestInstance::new();
    let config = instance.config().to_str().expect("a UTF-8 path");
    let output = instance.run(&["--config", config]);

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn a_configuration_error_uses_exit_code_one_and_standard_error() {
    let instance = TestInstance::new();
    let missing = instance.path().join("missing.toml");
    let output = instance.run(&["--config", missing.to_str().expect("a UTF-8 path")]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).starts_with("tit: "));
}

#[test]
fn doctor_checks_an_existing_current_database() {
    let instance = TestInstance::new();
    let database = rusqlite::Connection::open(instance.path().join("tit.sqlite3"))
        .expect("open the instance database");
    database
        .execute_batch(CURRENT_DATABASE)
        .expect("create the current database");
    drop(database);

    let output = instance.run(&[
        "--config",
        instance.config().to_str().expect("a UTF-8 path"),
        "doctor",
    ]);

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn doctor_does_not_create_or_migrate_a_database() {
    let instance = TestInstance::new();
    let database_path = instance.path().join("tit.sqlite3");
    let arguments = [
        "--config",
        instance.config().to_str().expect("a UTF-8 path"),
        "doctor",
    ];

    let missing = instance.run(&arguments);
    assert_eq!(missing.status.code(), Some(1));
    assert!(!database_path.exists());

    let database = rusqlite::Connection::open(&database_path).expect("open the old database");
    database
        .execute_batch(include_str!("fixtures/sqlite/v1.sql"))
        .expect("create the old database");
    drop(database);

    let old = instance.run(&arguments);
    assert_eq!(old.status.code(), Some(1));
    let database = rusqlite::Connection::open(&database_path).expect("reopen the old database");
    assert_eq!(
        database
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .expect("read the schema version"),
        1
    );
}

#[test]
fn doctor_reports_a_foreign_key_violation() {
    let instance = TestInstance::new();
    let database = rusqlite::Connection::open(instance.path().join("tit.sqlite3"))
        .expect("open the instance database");
    database
        .execute_batch(CURRENT_DATABASE)
        .expect("create the current database");
    database
        .pragma_update(None, "foreign_keys", false)
        .expect("disable foreign keys for the damaged fixture");
    database
        .execute(
            "INSERT INTO m1a_child (id, parent_id, sequence, body) VALUES (2, 999, 1, 'orphan')",
            [],
        )
        .expect("create a foreign-key violation");
    drop(database);

    let output = instance.run(&[
        "--config",
        instance.config().to_str().expect("a UTF-8 path"),
        "doctor",
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("foreign key violation"));
}

#[test]
fn starts_without_git_or_openssh_on_the_path() {
    let instance = TestInstance::new();
    let config = instance.config().to_str().expect("a UTF-8 path");
    let output = Command::new(env!("CARGO_BIN_EXE_tit"))
        .args(["--config", config])
        .env("PATH", "")
        .output()
        .expect("run tit");

    assert!(output.status.success());
}

#[test]
fn reads_user_configuration_from_the_xdg_data_directory() {
    let data = TempDir::new().expect("create a temporary data directory");
    let instance = data.path().join("tit");
    fs::create_dir(&instance).expect("create the instance directory");
    fs::write(
        instance.join("config.toml"),
        "version = 1\npublic_url = \"https://tit.example/\"\n",
    )
    .expect("write the configuration");

    let output = Command::new(env!("CARGO_BIN_EXE_tit"))
        .arg("--user")
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("run tit");

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn test_support_allocates_a_port_and_external_client_fixtures() {
    let instance = TestInstance::new();
    assert_ne!(free_address().port(), 0);

    for object_format in ["sha1", "sha256"] {
        create_bare_git_fixture(
            &instance.path().join(format!("{object_format}.git")),
            object_format,
        );
    }

    create_ssh_key_fixture(&instance.path().join("test-key"));
    read_stock_ssh_configuration();
}

#[test]
fn setup_creates_one_administrator_and_shows_one_recovery_code() {
    let instance = TestInstance::new();
    let private_key = instance.path().join("administrator");
    create_ssh_key_fixture(&private_key);
    let public_key = fs::read_to_string(private_key.with_extension("pub"))
        .expect("read the administrator public key");
    let arguments = [
        "--config",
        instance.config().to_str().expect("a UTF-8 path"),
        "setup",
        "admin",
        "alice",
        public_key.trim(),
    ];

    let first = instance.run(&arguments);
    assert!(
        first.status.success(),
        "setup failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(first.stderr.is_empty());
    let output = String::from_utf8(first.stdout).expect("read setup output");
    let recovery_code = output
        .strip_prefix("Recovery code: tit-recovery-v1:")
        .and_then(|value| value.strip_suffix('\n'))
        .expect("read the recovery code");
    assert_eq!(recovery_code.len(), 64);
    assert!(
        recovery_code
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );

    let database_path = instance.path().join("tit.sqlite3");
    assert_eq!(
        fs::metadata(&database_path)
            .expect("inspect the database")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let database = rusqlite::Connection::open(&database_path).expect("open the database");
    let record: (String, i64, String, String, Vec<u8>) = database
        .query_row(
            "SELECT account.username, account.is_administrator,
                    ssh_public_key.canonical_key, ssh_public_key.fingerprint,
                    recovery_credential.credential_hash
             FROM account
             JOIN ssh_public_key ON ssh_public_key.account_id = account.id
             JOIN recovery_credential ON recovery_credential.account_id = account.id",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("read the administrator");
    assert_eq!(record.0, "alice");
    assert_eq!(record.1, 1);
    assert_eq!(record.2.split_whitespace().count(), 2);
    assert!(record.3.starts_with("SHA256:"));
    let full_code = format!("tit-recovery-v1:{recovery_code}");
    assert_eq!(record.4, Sha256::digest(full_code.as_bytes()).as_slice());
    for path in [
        database_path.clone(),
        database_path.with_extension("sqlite3-wal"),
    ] {
        if let Ok(bytes) = fs::read(path) {
            assert!(
                !bytes
                    .windows(full_code.len())
                    .any(|value| value == full_code.as_bytes()),
                "the database contains the clear recovery code"
            );
        }
    }

    let second = instance.run(&arguments);
    assert_eq!(second.status.code(), Some(1));
    assert!(second.stdout.is_empty());
    assert!(String::from_utf8_lossy(&second.stderr).contains("already has an administrator"));
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM account", [], |row| row
                .get::<_, i64>(0))
            .expect("count accounts"),
        1
    );
}

#[test]
fn setup_rejects_invalid_identity_before_it_creates_a_database() {
    for (username, key) in [
        ("Alice", "not a key"),
        ("admin", "not a key"),
        ("bad_name", "not a key"),
        ("alice", "not a key"),
    ] {
        let instance = TestInstance::new();
        let output = instance.run(&[
            "--config",
            instance.config().to_str().expect("a UTF-8 path"),
            "setup",
            "admin",
            username,
            key,
        ]);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(!instance.path().join("tit.sqlite3").exists());
    }
}

#[test]
fn concurrent_setup_creates_exactly_one_administrator() {
    let instance = TestInstance::new();
    let first_private = instance.path().join("first-key");
    let second_private = instance.path().join("second-key");
    create_ssh_key_fixture(&first_private);
    create_ssh_key_fixture(&second_private);
    let first_key =
        fs::read_to_string(first_private.with_extension("pub")).expect("read the first public key");
    let second_key = fs::read_to_string(second_private.with_extension("pub"))
        .expect("read the second public key");
    let start = |username: &str, key: &str| {
        Command::new(env!("CARGO_BIN_EXE_tit"))
            .args([
                "--config",
                instance.config().to_str().expect("a UTF-8 path"),
                "setup",
                "admin",
                username,
                key.trim(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start concurrent setup")
    };
    let mut first = start("alice", &first_key);
    let mut second = start("bob", &second_key);
    let first = first.wait().expect("wait for the first setup");
    let second = second.wait().expect("wait for the second setup");
    assert_ne!(first.success(), second.success());

    let database = rusqlite::Connection::open(instance.path().join("tit.sqlite3"))
        .expect("open the setup database");
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM account", [], |row| row
                .get::<_, i64>(0))
            .expect("count accounts"),
        1
    );
}

#[test]
fn administers_repositories_with_immutable_canonical_paths() {
    let instance = TestInstance::new();
    create_administrator(&instance, "alice");
    let config = instance.config().to_str().expect("a UTF-8 path");

    let created = Command::new(env!("CARGO_BIN_EXE_tit"))
        .args([
            "--config",
            config,
            "admin",
            "repository",
            "create",
            "alice",
            "project",
            "--object-format",
            "sha256",
        ])
        .env("PATH", "")
        .output()
        .expect("create a repository without runtime Git");
    assert!(
        created.status.success(),
        "create failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );
    let created = repository_output(&created.stdout);
    assert_eq!(created.get("owner").map(String::as_str), Some("alice"));
    assert_eq!(created.get("slug").map(String::as_str), Some("project"));
    assert_eq!(
        created.get("visibility").map(String::as_str),
        Some("public")
    );
    assert_eq!(created.get("state").map(String::as_str), Some("active"));
    assert_eq!(
        created.get("object-format").map(String::as_str),
        Some("sha256")
    );
    let id = created.get("id").expect("read the repository ID");
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let path = PathBuf::from(created.get("path").expect("read the repository path"));
    let repository_root = fs::canonicalize(instance.path().join("repositories"))
        .expect("canonicalize managed repositories");
    assert_eq!(path.parent(), Some(repository_root.as_path()));
    let expected_name = format!("{id}.git");
    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some(expected_name.as_str())
    );
    assert_eq!(
        fs::read_to_string(path.join("HEAD")).expect("read repository HEAD"),
        "ref: refs/heads/main\n"
    );

    let renamed = instance.run(&[
        "--config",
        config,
        "admin",
        "repository",
        "rename",
        "alice",
        "project",
        "renamed",
    ]);
    assert!(renamed.status.success());
    let renamed = repository_output(&renamed.stdout);
    assert_eq!(renamed.get("slug").map(String::as_str), Some("renamed"));
    assert_eq!(renamed.get("id"), Some(id));
    assert_eq!(renamed.get("path"), created.get("path"));

    let old_name = instance.run(&[
        "--config",
        config,
        "admin",
        "repository",
        "inspect",
        "alice",
        "project",
    ]);
    assert_eq!(old_name.status.code(), Some(1));
    let archived = instance.run(&[
        "--config",
        config,
        "admin",
        "repository",
        "archive",
        "alice",
        "renamed",
    ]);
    assert!(archived.status.success());
    let archived = repository_output(&archived.stdout);
    assert_eq!(archived.get("state").map(String::as_str), Some("archived"));
    assert_ne!(archived.get("archived-at").map(String::as_str), Some("-"));
    let second_archive = instance.run(&[
        "--config",
        config,
        "admin",
        "repository",
        "archive",
        "alice",
        "renamed",
    ]);
    assert_eq!(second_archive.status.code(), Some(1));

    let duplicate = instance.run(&[
        "--config",
        config,
        "admin",
        "repository",
        "create",
        "alice",
        "renamed",
    ]);
    assert_eq!(duplicate.status.code(), Some(1));
    let missing_owner = instance.run(&[
        "--config",
        config,
        "admin",
        "repository",
        "create",
        "bob",
        "project",
    ]);
    assert_eq!(missing_owner.status.code(), Some(1));
}

#[test]
fn administers_repository_visibility_and_collaborators() {
    let instance = TestInstance::new();
    create_administrator(&instance, "alice");
    let config = instance.config().to_str().expect("a UTF-8 path");
    let created = instance.run(&[
        "--config",
        config,
        "admin",
        "repository",
        "create",
        "alice",
        "project",
    ]);
    assert!(created.status.success());
    let database = rusqlite::Connection::open(instance.path().join("tit.sqlite3"))
        .expect("open the repository database");
    database
        .execute(
            "INSERT INTO account (username, is_administrator, state, created_at)
             VALUES ('bob', 0, 'active', 1)",
            [],
        )
        .expect("create a collaborator account");
    drop(database);

    let visibility = instance.run(&[
        "--config",
        config,
        "admin",
        "repository",
        "visibility",
        "alice",
        "project",
        "private",
    ]);
    assert!(visibility.status.success());
    assert_eq!(
        repository_output(&visibility.stdout)
            .get("visibility")
            .map(String::as_str),
        Some("private")
    );

    let collaborator = instance.run(&[
        "--config",
        config,
        "admin",
        "repository",
        "collaborator-set",
        "alice",
        "project",
        "bob",
        "reader",
    ]);
    assert!(collaborator.status.success());
    let database = rusqlite::Connection::open(instance.path().join("tit.sqlite3"))
        .expect("open the repository database");
    let role: String = database
        .query_row(
            "SELECT role FROM repository_collaborator
             JOIN account ON account.id = repository_collaborator.account_id
             WHERE account.username = 'bob'",
            [],
            |row| row.get(0),
        )
        .expect("read the collaborator role");
    assert_eq!(role, "reader");
    drop(database);

    let removed = instance.run(&[
        "--config",
        config,
        "admin",
        "repository",
        "collaborator-remove",
        "alice",
        "project",
        "bob",
    ]);
    assert!(removed.status.success());
    let database = rusqlite::Connection::open(instance.path().join("tit.sqlite3"))
        .expect("open the repository database");
    let collaborators: i64 = database
        .query_row("SELECT count(*) FROM repository_collaborator", [], |row| {
            row.get(0)
        })
        .expect("count repository collaborators");
    assert_eq!(collaborators, 0);
    drop(database);

    let rejected_remove = instance.run(&[
        "--config",
        config,
        "admin",
        "repository",
        "collaborator-remove",
        "alice",
        "project",
        "bob",
    ]);
    assert_eq!(rejected_remove.status.code(), Some(1));

    let audit = instance.run(&["--config", config, "admin", "audit", "--limit", "10"]);
    assert!(audit.status.success());
    let audit = String::from_utf8(audit.stdout).expect("read the audit history");
    assert!(audit.contains("action=repository.create\n"));
    assert!(audit.contains("action=repository.visibility\n"));
    assert!(audit.contains("action=collaborator.set\n"));
    assert!(audit.contains("action=collaborator.remove\n"));
    assert!(audit.contains("actor=admin-cli\n"));
    assert!(audit.contains("outcome=success\n"));
    assert!(audit.contains("outcome=failure\n"));
    assert!(audit.contains("correlation-id="));
}

#[test]
fn imports_bare_repositories_and_rejects_unsafe_sources() {
    let instance = TestInstance::new();
    create_administrator(&instance, "alice");
    let config = instance.config().to_str().expect("a UTF-8 path");
    let source = instance.path().join("source.git");
    create_bare_git_fixture(&source, "sha1");

    let imported = instance.run(&[
        "--config",
        config,
        "admin",
        "repository",
        "import",
        "alice",
        "imported",
        source.to_str().expect("a UTF-8 path"),
    ]);
    assert!(
        imported.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&imported.stderr)
    );
    let imported = repository_output(&imported.stdout);
    assert_eq!(
        imported.get("object-format").map(String::as_str),
        Some("sha1")
    );
    assert_ne!(imported.get("path"), Some(&source.display().to_string()));

    let unsafe_source = instance.path().join("unsafe.git");
    create_bare_git_fixture(&unsafe_source, "sha1");
    std::os::unix::fs::symlink("HEAD", unsafe_source.join("unsafe-link"))
        .expect("create a repository symlink");
    let unsafe_import = instance.run(&[
        "--config",
        config,
        "admin",
        "repository",
        "import",
        "alice",
        "unsafe",
        unsafe_source.to_str().expect("a UTF-8 path"),
    ]);
    assert_eq!(unsafe_import.status.code(), Some(1));
    assert!(unsafe_import.stdout.is_empty());
    assert!(
        fs::read_dir(instance.path().join("repositories"))
            .expect("read managed repositories")
            .all(|entry| !entry
                .expect("read a managed repository")
                .file_name()
                .to_string_lossy()
                .starts_with(".pending-"))
    );

    for slug in ["Project", "project.git", "../project", "admin"] {
        let rejected = instance.run(&[
            "--config",
            config,
            "admin",
            "repository",
            "create",
            "alice",
            slug,
        ]);
        assert_eq!(rejected.status.code(), Some(1), "accepted {slug:?}");
        assert!(rejected.stdout.is_empty());
    }
}

fn create_administrator(instance: &TestInstance, username: &str) {
    let private_key = instance.path().join("admin-key");
    create_ssh_key_fixture(&private_key);
    let public_key = fs::read_to_string(private_key.with_extension("pub"))
        .expect("read the administrator public key");
    let output = instance.run(&[
        "--config",
        instance.config().to_str().expect("a UTF-8 path"),
        "setup",
        "admin",
        username,
        public_key.trim(),
    ]);
    assert!(output.status.success());
}

fn repository_output(output: &[u8]) -> std::collections::BTreeMap<String, String> {
    String::from_utf8(output.to_vec())
        .expect("read repository output")
        .lines()
        .map(|line| {
            let (name, value) = line.split_once('=').expect("read a repository field");
            (name.to_owned(), value.to_owned())
        })
        .collect()
}
