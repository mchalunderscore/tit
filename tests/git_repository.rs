#[path = "../src/git/repository.rs"]
mod repository;

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use gix::hash::ObjectId;
use repository::{GitRepository, GitRepositoryError};
use tempfile::TempDir;

#[test]
fn opens_empty_sha1_and_sha256_bare_repositories() {
    let directory = TempDir::new().expect("create a repository directory");
    for format in ["sha1", "sha256"] {
        let path = directory.path().join(format);
        init_bare(&path, format);
        let repository = GitRepository::open(&path).expect("open the bare repository");
        assert_eq!(repository.object_format().to_string(), format);
        assert!(
            repository
                .references()
                .expect("read empty references")
                .is_empty()
        );
    }

    let non_bare = directory.path().join("worktree");
    run(Command::new("git").args(["init", "-q"]).arg(&non_bare));
    assert!(matches!(
        GitRepository::open(&non_bare),
        Err(GitRepositoryError::NotBare(_))
    ));
}

#[test]
fn creates_main_bare_repositories_and_copies_without_git() {
    let directory = TempDir::new().expect("create a repository directory");
    for kind in [gix::hash::Kind::Sha1, gix::hash::Kind::Sha256] {
        let source = directory.path().join(format!("source-{kind}"));
        GitRepository::create_bare(&source, kind).expect("create a bare repository");
        assert_eq!(
            fs::read_to_string(source.join("HEAD")).expect("read HEAD"),
            "ref: refs/heads/main\n"
        );
        let destination = directory.path().join(format!("copy-{kind}"));
        assert_eq!(
            GitRepository::copy_bare(&source, &destination).expect("copy a bare repository"),
            kind
        );
        assert_eq!(
            GitRepository::open(&destination)
                .expect("open the copy")
                .object_format(),
            kind
        );
    }

    let unsafe_source = directory.path().join("unsafe");
    GitRepository::create_bare(&unsafe_source, gix::hash::Kind::Sha1)
        .expect("create an unsafe-source repository");
    std::os::unix::fs::symlink("HEAD", unsafe_source.join("unsafe-link"))
        .expect("create a repository symlink");
    assert!(matches!(
        GitRepository::copy_bare(&unsafe_source, &directory.path().join("unsafe-copy")),
        Err(GitRepositoryError::UnsafeFile(_))
    ));
}

#[test]
fn reads_sorted_refs_and_generates_complete_packs_for_both_hashes() {
    let directory = TempDir::new().expect("create a repository directory");
    for format in ["sha1", "sha256"] {
        let source_path = directory.path().join(format!("source-{format}"));
        let first = make_fixture(&source_path, format);
        let source = GitRepository::open(&source_path).expect("open the source repository");
        let references = source.references().expect("read references");
        assert_eq!(references[0].name, b"HEAD");
        assert_eq!(
            references[0].symbolic_target.as_deref(),
            Some(b"refs/heads/main".as_slice())
        );
        assert!(
            references
                .windows(2)
                .skip(1)
                .all(|pair| pair[0].name < pair[1].name)
        );
        assert!(references.iter().any(|reference| {
            reference.name == b"refs/tags/v1" && reference.peeled == Some(first)
        }));

        let pack = source
            .make_pack(&[first], &[])
            .expect("generate a complete pack");
        assert!(pack.starts_with(b"PACK"));
        let destination = directory.path().join(format!("destination-{format}"));
        init_bare(&destination, format);
        index_pack(&destination, &pack);
        assert_object(&destination, first, "commit");

        let second = append_commit(&source_path, first, b"second payload", "second.txt");
        let source = GitRepository::open(&source_path).expect("open the updated repository");
        let incremental = source
            .make_pack(&[second], &[first])
            .expect("generate an incremental pack");
        index_pack(&destination, &incremental);
        assert_object(&destination, second, "commit");
    }
}

#[test]
fn rejects_unadvertised_wants_and_damaged_reachable_objects() {
    let directory = TempDir::new().expect("create a repository directory");
    let source_path = directory.path().join("source");
    let commit = make_fixture(&source_path, "sha1");
    let source = GitRepository::open(&source_path).expect("open the source repository");
    let unadvertised = ObjectId::from_hex(b"1111111111111111111111111111111111111111")
        .expect("parse an unadvertised ID");
    assert!(matches!(
        source.make_pack(&[unadvertised], &[]),
        Err(GitRepositoryError::UnadvertisedWant)
    ));
    let wrong_format =
        ObjectId::from_hex(b"1111111111111111111111111111111111111111111111111111111111111111")
            .expect("parse a SHA-256 ID");
    assert!(matches!(
        source.make_pack(&[commit], &[wrong_format]),
        Err(GitRepositoryError::WrongObjectFormat)
    ));
    drop(source);

    let object_path = loose_object_path(&source_path, commit);
    fs::set_permissions(&object_path, fs::Permissions::from_mode(0o600))
        .expect("make the commit object writable");
    fs::write(&object_path, b"damaged object").expect("damage the commit object");
    let damaged = GitRepository::open(&source_path).expect("open the damaged repository");
    assert!(matches!(
        damaged.make_pack(&[commit], &[]),
        Err(GitRepositoryError::References(_)
            | GitRepositoryError::Object { .. }
            | GitRepositoryError::DamagedObject { .. })
    ));
}

fn make_fixture(path: &Path, format: &str) -> ObjectId {
    init_bare(path, format);
    run(git(path).args(["config", "user.name", "Tit Test"]));
    run(git(path).args(["config", "user.email", "tit@example.invalid"]));
    run(git(path).args(["config", "tag.gpgsign", "false"]));
    let blob = write_blob(path, b"hello from tit\n");
    let tree = write_tree(path, blob, "non-ascii-\u{00e5}.txt");
    let commit = write_commit(path, tree, None, "first commit");
    update_ref(path, "refs/heads/main", commit);
    run(git(path).args(["symbolic-ref", "HEAD", "refs/heads/main"]));
    run(git(path).args(["tag", "-a", "v1", "-m", "version one", &commit.to_string()]));
    commit
}

fn append_commit(path: &Path, parent: ObjectId, contents: &[u8], filename: &str) -> ObjectId {
    let blob = write_blob(path, contents);
    let tree = write_tree(path, blob, filename);
    let commit = write_commit(path, tree, Some(parent), "second commit");
    update_ref(path, "refs/heads/main", commit);
    commit
}

fn init_bare(path: &Path, format: &str) {
    run(Command::new("git")
        .args(["init", "-q", "--bare", "--object-format", format])
        .arg(path));
}

fn write_blob(path: &Path, contents: &[u8]) -> ObjectId {
    let output = run_with_input(git(path).args(["hash-object", "-w", "--stdin"]), contents);
    parse_id(&output)
}

fn write_tree(path: &Path, blob: ObjectId, filename: &str) -> ObjectId {
    let record = format!("100644 blob {blob}\t{filename}\n");
    let output = run_with_input(git(path).arg("mktree"), record.as_bytes());
    parse_id(&output)
}

fn write_commit(path: &Path, tree: ObjectId, parent: Option<ObjectId>, message: &str) -> ObjectId {
    let mut command = git(path);
    command.arg("commit-tree").arg(tree.to_string());
    if let Some(parent) = parent {
        command.args(["-p", &parent.to_string()]);
    }
    command.args(["-m", message]);
    command.envs([
        ("GIT_AUTHOR_NAME", "Tit Test"),
        ("GIT_AUTHOR_EMAIL", "tit@example.invalid"),
        ("GIT_AUTHOR_DATE", "1700000000 +0000"),
        ("GIT_COMMITTER_NAME", "Tit Test"),
        ("GIT_COMMITTER_EMAIL", "tit@example.invalid"),
        ("GIT_COMMITTER_DATE", "1700000000 +0000"),
    ]);
    parse_id(&run(&mut command).stdout)
}

fn update_ref(path: &Path, name: &str, id: ObjectId) {
    run(git(path).args(["update-ref", name, &id.to_string()]));
}

fn index_pack(path: &Path, pack: &[u8]) {
    let output = run_with_input(git(path).args(["index-pack", "--stdin"]), pack);
    assert!(!output.is_empty());
}

fn assert_object(path: &Path, id: ObjectId, kind: &str) {
    let output = run(git(path).args(["cat-file", "-t", &id.to_string()]));
    assert_eq!(
        String::from_utf8(output.stdout)
            .expect("read object type")
            .trim(),
        kind
    );
}

fn loose_object_path(repository: &Path, id: ObjectId) -> PathBuf {
    let id = id.to_string();
    repository.join("objects").join(&id[..2]).join(&id[2..])
}

fn git(path: &Path) -> Command {
    let mut command = Command::new("git");
    command.arg("--git-dir").arg(path);
    command
}

fn run(command: &mut Command) -> std::process::Output {
    let output = command.output().expect("run stock Git");
    assert!(
        output.status.success(),
        "stock Git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn run_with_input(command: &mut Command, input: &[u8]) -> Vec<u8> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start stock Git");
    child
        .stdin
        .take()
        .expect("open stock Git input")
        .write_all(input)
        .expect("write stock Git input");
    let output = child.wait_with_output().expect("wait for stock Git");
    assert!(
        output.status.success(),
        "stock Git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn parse_id(input: &[u8]) -> ObjectId {
    ObjectId::from_hex(String::from_utf8_lossy(input).trim().as_bytes()).expect("parse object ID")
}
