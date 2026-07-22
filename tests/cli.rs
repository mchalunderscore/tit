mod support;

use std::fs;
use std::process::Command;

use support::{
    TestInstance, create_bare_git_fixture, create_ssh_key_fixture, free_address,
    read_stock_ssh_configuration,
};
use tempfile::TempDir;

const V2_DATABASE: &str = include_str!("fixtures/sqlite/v2.sql");

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
        .execute_batch(V2_DATABASE)
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
        .execute_batch(V2_DATABASE)
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
