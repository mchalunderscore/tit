#[allow(
    dead_code,
    reason = "the test uses each public read contract selectively"
)]
#[path = "../src/git/read.rs"]
mod read;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use gix::hash::ObjectId;
use read::{ReadCancellation, ReadError, ReadLimits, RepositoryReadService};
use tempfile::TempDir;

struct Fixture {
    _directory: TempDir,
    bare: PathBuf,
    first: ObjectId,
    second: ObjectId,
}

#[test]
fn reads_repository_content_for_both_object_formats() {
    for format in ["sha1", "sha256"] {
        let fixture = fixture(format);
        let service = RepositoryReadService::open(&fixture.bare, ReadLimits::default())
            .expect("open the read service");
        let cancellation = ReadCancellation::default();

        let references = service.references(&cancellation).expect("read refs");
        assert_eq!(references[0].name, b"HEAD");
        assert_eq!(
            references[0].symbolic_target.as_deref(),
            Some(b"refs/heads/main".as_slice())
        );
        assert!(references.iter().any(|reference| {
            reference.name == b"refs/heads/main" && reference.target == fixture.second
        }));
        assert!(references.iter().any(|reference| {
            reference.name == b"refs/tags/v1" && reference.peeled == Some(fixture.first)
        }));

        let commit = service
            .commit(fixture.second, &cancellation)
            .expect("read a commit");
        assert_eq!(commit.id, fixture.second);
        assert_eq!(commit.parents, [fixture.first]);
        assert_eq!(commit.author_name, b"Tit Test");
        assert_eq!(commit.author_email, b"tit@example.test");
        assert_eq!(commit.message, b"second\n");

        let history = service
            .history(fixture.second, &cancellation)
            .expect("read history");
        assert_eq!(
            history.iter().map(|commit| commit.id).collect::<Vec<_>>(),
            [fixture.second, fixture.first]
        );

        let root = service
            .tree(fixture.second, b"", &cancellation)
            .expect("read the root tree");
        assert_eq!(
            root.iter()
                .map(|entry| entry.name.as_slice())
                .collect::<Vec<_>>(),
            [
                b"README.md".as_slice(),
                b"binary".as_slice(),
                b"docs".as_slice(),
                b"src".as_slice()
            ]
        );
        let source = service
            .tree(fixture.second, b"src", &cancellation)
            .expect("read a nested tree");
        assert_eq!(source.len(), 1);
        assert_eq!(source[0].name, b"lib.rs");

        let blob = service
            .blob(fixture.second, b"src/lib.rs", &cancellation)
            .expect("read a blob");
        assert_eq!(blob.data, b"one\nchanged\nthree\n");
        assert_eq!(blob.mode, 0o100644);
        let mut raw = Vec::new();
        assert_eq!(
            service
                .raw(fixture.second, b"src/lib.rs", &cancellation, &mut raw)
                .expect("stream raw content"),
            raw.len()
        );
        assert_eq!(raw, blob.data);

        let readme = service
            .readme(fixture.second, &cancellation)
            .expect("select a README")
            .expect("find a README");
        assert_eq!(readme.path, b"README.md");
        assert_eq!(readme.blob.data, b"Tit read service\n");

        let search = service
            .search(fixture.second, b"changed", &cancellation)
            .expect("search source");
        assert_eq!(search.commit, fixture.second);
        assert_eq!(search.matches.len(), 1);
        assert_eq!(search.matches[0].path, b"src/lib.rs");
        assert_eq!(search.matches[0].line_number, 2);
        assert_eq!(search.matches[0].line, b"changed");
        assert!(!search.truncated);
        let non_utf8 = service
            .search(fixture.second, b"needle", &cancellation)
            .expect("search non-UTF-8 source");
        assert_eq!(non_utf8.matches[0].path, b"docs/note.txt");
        assert_eq!(non_utf8.matches[0].line, b"note \xff needle");
        assert_eq!(
            service
                .search(fixture.second, b"binary", &cancellation)
                .expect("skip binary content")
                .matches,
            []
        );
    }
}

#[test]
fn produces_bounded_diffs_blame_and_streaming_archives() {
    let fixture = fixture("sha1");
    let service = RepositoryReadService::open(&fixture.bare, ReadLimits::default())
        .expect("open the read service");
    let cancellation = ReadCancellation::default();

    let diff = service
        .diff(fixture.first, fixture.second, &cancellation)
        .expect("read a diff");
    let source = diff
        .iter()
        .find(|file| file.path == b"src/lib.rs")
        .expect("find the source diff");
    assert!(!source.binary);
    assert!(source.hunks.windows(5).any(|window| window == b"-two\n"));
    assert!(
        source
            .hunks
            .windows(9)
            .any(|window| window == b"+changed\n")
    );
    assert!(diff.iter().any(|file| file.path == b"docs/note.txt"));
    let binary = diff
        .iter()
        .find(|file| file.path == b"binary")
        .expect("find the binary diff");
    assert!(binary.binary);
    assert!(binary.hunks.is_empty());

    let blame = service
        .blame(fixture.second, b"src/lib.rs", &cancellation)
        .expect("blame a file");
    assert!(blame.iter().any(|hunk| hunk.commit_id == fixture.first));
    assert!(blame.iter().any(|hunk| hunk.commit_id == fixture.second));
    assert_eq!(
        blame
            .iter()
            .map(|hunk| usize::try_from(hunk.line_count).expect("count blame lines"))
            .sum::<usize>(),
        3
    );

    let mut archive = Vec::new();
    let stats = service
        .archive(fixture.second, &cancellation, &mut archive)
        .expect("stream an archive");
    assert_eq!(stats.bytes, archive.len());
    assert!(archive.ends_with(&[0_u8; 1024]));
    let names = tar_names(&archive);
    assert!(names.contains(b"README.md".as_slice()));
    assert!(names.contains(b"src/".as_slice()));
    assert!(names.contains(b"src/lib.rs".as_slice()));
    assert!(names.contains(b"docs/note.txt".as_slice()));
    let long_path = format!("docs/{}/{}.txt", "a".repeat(60), "b".repeat(60));
    assert!(names.contains(long_path.as_bytes()));
    let archive_path = fixture
        .bare
        .parent()
        .expect("a fixture parent")
        .join("repository.tar");
    fs::write(&archive_path, &archive).expect("write the streamed archive");
    let tar = Command::new("tar")
        .args(["-tf"])
        .arg(&archive_path)
        .output()
        .expect("run the system tar reader");
    assert!(
        tar.status.success(),
        "tar rejected the archive: {}",
        String::from_utf8_lossy(&tar.stderr)
    );
}

#[test]
fn enforces_each_read_boundary_and_rejects_unsafe_paths() {
    let fixture = fixture("sha1");
    let cancellation = ReadCancellation::default();

    let limits = ReadLimits {
        max_refs: 1,
        ..ReadLimits::default()
    };
    let service = RepositoryReadService::open(&fixture.bare, limits).expect("open the service");
    assert!(matches!(
        service.references(&cancellation),
        Err(ReadError::Limit("refs"))
    ));

    let limits = ReadLimits {
        max_history_commits: 1,
        ..ReadLimits::default()
    };
    let service = RepositoryReadService::open(&fixture.bare, limits).expect("open the service");
    assert!(matches!(
        service.history(fixture.second, &cancellation),
        Err(ReadError::Limit("history commits"))
    ));
    assert!(matches!(
        service.blame(fixture.second, b"src/lib.rs", &cancellation),
        Err(ReadError::Limit("history commits"))
    ));

    let limits = ReadLimits {
        max_blob_bytes: 4,
        ..ReadLimits::default()
    };
    let service = RepositoryReadService::open(&fixture.bare, limits).expect("open the service");
    assert!(matches!(
        service.blob(fixture.second, b"src/lib.rs", &cancellation),
        Err(ReadError::Limit("blob bytes"))
    ));

    let limits = ReadLimits {
        max_commit_bytes: 1,
        ..ReadLimits::default()
    };
    let service = RepositoryReadService::open(&fixture.bare, limits).expect("open the service");
    assert!(matches!(
        service.commit(fixture.second, &cancellation),
        Err(ReadError::Limit("commit bytes"))
    ));

    let limits = ReadLimits {
        max_path_bytes: 4,
        ..ReadLimits::default()
    };
    let service = RepositoryReadService::open(&fixture.bare, limits).expect("open the service");
    assert!(matches!(
        service.blob(fixture.second, b"src/lib.rs", &cancellation),
        Err(ReadError::Limit("path bytes"))
    ));

    let limits = ReadLimits {
        max_tree_entries: 1,
        ..ReadLimits::default()
    };
    let service = RepositoryReadService::open(&fixture.bare, limits).expect("open the service");
    assert!(matches!(
        service.tree(fixture.second, b"", &cancellation),
        Err(ReadError::Limit("tree entries"))
    ));

    let limits = ReadLimits {
        max_diff_bytes: 8,
        ..ReadLimits::default()
    };
    let service = RepositoryReadService::open(&fixture.bare, limits).expect("open the service");
    assert!(matches!(
        service.diff(fixture.first, fixture.second, &cancellation),
        Err(ReadError::Limit("diff bytes"))
    ));

    let limits = ReadLimits {
        max_archive_entries: 1,
        ..ReadLimits::default()
    };
    let service = RepositoryReadService::open(&fixture.bare, limits).expect("open the service");
    assert!(matches!(
        service.archive(fixture.second, &cancellation, &mut Vec::new()),
        Err(ReadError::Limit("archive entries"))
    ));

    let limits = ReadLimits {
        max_archive_bytes: 1024,
        ..ReadLimits::default()
    };
    let service = RepositoryReadService::open(&fixture.bare, limits).expect("open the service");
    assert!(matches!(
        service.archive(fixture.second, &cancellation, &mut Vec::new()),
        Err(ReadError::Limit("archive bytes"))
    ));

    let limits = ReadLimits {
        max_search_files: 1,
        ..ReadLimits::default()
    };
    let service = RepositoryReadService::open(&fixture.bare, limits).expect("open the service");
    assert!(matches!(
        service.search(fixture.second, b"missing", &cancellation),
        Err(ReadError::Limit("search files"))
    ));

    let limits = ReadLimits {
        max_search_bytes: 1,
        ..ReadLimits::default()
    };
    let service = RepositoryReadService::open(&fixture.bare, limits).expect("open the service");
    assert!(matches!(
        service.search(fixture.second, b"missing", &cancellation),
        Err(ReadError::Limit("search bytes"))
    ));

    let limits = ReadLimits {
        max_search_results: 1,
        ..ReadLimits::default()
    };
    let service = RepositoryReadService::open(&fixture.bare, limits).expect("open the service");
    let search = service
        .search(fixture.second, b"e", &cancellation)
        .expect("truncate search results");
    assert_eq!(search.matches.len(), 1);
    assert!(search.truncated);

    let limits = ReadLimits {
        max_search_query_bytes: 3,
        ..ReadLimits::default()
    };
    let service = RepositoryReadService::open(&fixture.bare, limits).expect("open the service");
    assert!(matches!(
        service.search(fixture.second, b"four", &cancellation),
        Err(ReadError::Limit("search query bytes"))
    ));
    assert!(matches!(
        service.search(fixture.second, b"", &cancellation),
        Err(ReadError::InvalidSearchQuery)
    ));

    let limits = ReadLimits {
        max_search_duration: Duration::from_nanos(1),
        ..ReadLimits::default()
    };
    let service = RepositoryReadService::open(&fixture.bare, limits).expect("open the service");
    assert!(matches!(
        service.search(fixture.second, b"changed", &cancellation),
        Err(ReadError::Deadline)
    ));

    let service = RepositoryReadService::open(&fixture.bare, ReadLimits::default())
        .expect("open the service");
    for path in [b"".as_slice(), b"/src", b"src/", b"src//lib.rs", b"../HEAD"] {
        assert!(matches!(
            service.blob(fixture.second, path, &cancellation),
            Err(ReadError::InvalidPath)
        ));
    }
    let cancelled = ReadCancellation::default();
    cancelled.cancel();
    assert!(matches!(
        service.history(fixture.second, &cancelled),
        Err(ReadError::Cancelled)
    ));
    assert!(matches!(
        service.search(fixture.second, b"changed", &cancelled),
        Err(ReadError::Cancelled)
    ));

    let limits = ReadLimits {
        max_duration: Duration::ZERO,
        ..ReadLimits::default()
    };
    assert!(matches!(
        RepositoryReadService::open(&fixture.bare, limits),
        Err(ReadError::InvalidLimits)
    ));
}

#[test]
#[ignore = "M2.8 representative search measurement"]
fn measures_bounded_search_without_an_index() {
    let directory = TempDir::new().expect("create a measurement directory");
    let worktree = directory.path().join("worktree");
    run(Command::new("git")
        .args(["init", "-q", "-b", "main"])
        .arg(&worktree));
    run(Command::new("git")
        .args(["config", "commit.gpgsign", "false"])
        .current_dir(&worktree));
    for index in 0..2_000 {
        let mut content = format!("file {index:05} needle-{index:05}\n").into_bytes();
        content.resize(4_096, b'x');
        fs::write(worktree.join(format!("file-{index:05}.txt")), content)
            .expect("write a measurement file");
    }
    run(Command::new("git")
        .args(["add", "."])
        .current_dir(&worktree));
    run(Command::new("git")
        .args(["commit", "-q", "-m", "measurement"])
        .env("GIT_AUTHOR_NAME", "Tit Test")
        .env("GIT_AUTHOR_EMAIL", "tit@example.test")
        .env("GIT_COMMITTER_NAME", "Tit Test")
        .env("GIT_COMMITTER_EMAIL", "tit@example.test")
        .current_dir(&worktree));
    let head = revision(&worktree, "HEAD");
    let bare = directory.path().join("repository.git");
    run(Command::new("git")
        .args(["clone", "-q", "--bare", "--no-local"])
        .arg(&worktree)
        .arg(&bare));
    let service = RepositoryReadService::open(&bare, ReadLimits::default())
        .expect("open the measurement repository");
    let started = Instant::now();
    let outcome = service
        .search(head, b"needle-01999", &ReadCancellation::default())
        .expect("search the measurement repository");
    let elapsed = started.elapsed();
    assert_eq!(outcome.files_scanned, 2_000);
    assert_eq!(outcome.bytes_scanned, 2_000 * 4_096);
    assert_eq!(outcome.matches.len(), 1);
    assert!(!outcome.truncated);
    eprintln!(
        "searched {} files and {} bytes in {elapsed:?}",
        outcome.files_scanned, outcome.bytes_scanned
    );
}

fn fixture(object_format: &str) -> Fixture {
    let directory = TempDir::new().expect("create a fixture directory");
    let worktree = directory.path().join("worktree");
    run(Command::new("git")
        .args(["init", "-q", "-b", "main", "--object-format", object_format])
        .arg(&worktree));
    run(Command::new("git")
        .args(["config", "user.name", "Tit Test"])
        .current_dir(&worktree));
    run(Command::new("git")
        .args(["config", "user.email", "tit@example.test"])
        .current_dir(&worktree));
    run(Command::new("git")
        .args(["config", "commit.gpgsign", "false"])
        .current_dir(&worktree));
    run(Command::new("git")
        .args(["config", "tag.gpgsign", "false"])
        .current_dir(&worktree));
    fs::create_dir(worktree.join("src")).expect("create a source directory");
    fs::write(worktree.join("README.md"), b"Tit read service\n").expect("write a README");
    fs::write(worktree.join("src/lib.rs"), b"one\ntwo\n").expect("write source");
    fs::write(worktree.join("binary"), b"old\0binary").expect("write binary content");
    run(Command::new("git")
        .args(["add", "."])
        .current_dir(&worktree));
    run(Command::new("git")
        .args(["commit", "-q", "-m", "first"])
        .env("GIT_AUTHOR_DATE", "1700000000 +0000")
        .env("GIT_COMMITTER_DATE", "1700000000 +0000")
        .current_dir(&worktree));
    let first = revision(&worktree, "HEAD");
    run(Command::new("git")
        .args(["tag", "-a", "v1", "-m", "version one"])
        .current_dir(&worktree));

    fs::create_dir(worktree.join("docs")).expect("create a documentation directory");
    fs::write(worktree.join("src/lib.rs"), b"one\nchanged\nthree\n").expect("change source");
    fs::write(worktree.join("binary"), b"new\0binary").expect("change binary content");
    fs::write(worktree.join("docs/note.txt"), b"note \xff needle\n").expect("write documentation");
    let long_directory = worktree.join("docs").join("a".repeat(60));
    fs::create_dir(&long_directory).expect("create a long archive directory");
    fs::write(
        long_directory.join(format!("{}.txt", "b".repeat(60))),
        b"long archive path\n",
    )
    .expect("write a long archive path");
    run(Command::new("git")
        .args(["add", "."])
        .current_dir(&worktree));
    run(Command::new("git")
        .args(["commit", "-q", "-m", "second"])
        .env("GIT_AUTHOR_DATE", "1700000100 +0000")
        .env("GIT_COMMITTER_DATE", "1700000100 +0000")
        .current_dir(&worktree));
    let second = revision(&worktree, "HEAD");
    let bare = directory.path().join("repository.git");
    run(Command::new("git")
        .args(["clone", "-q", "--bare"])
        .arg(&worktree)
        .arg(&bare));
    Fixture {
        _directory: directory,
        bare,
        first,
        second,
    }
}

fn revision(repository: &Path, name: &str) -> ObjectId {
    let output = Command::new("git")
        .args(["rev-parse", name])
        .current_dir(repository)
        .output()
        .expect("run git rev-parse");
    assert!(output.status.success());
    ObjectId::from_hex(output.stdout.trim_ascii()).expect("parse a fixture revision")
}

fn run(command: &mut Command) {
    let output = command.output().expect("run the stock Git client");
    assert!(
        output.status.success(),
        "Git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn tar_names(archive: &[u8]) -> BTreeSet<Vec<u8>> {
    let mut names = BTreeSet::new();
    let mut offset = 0_usize;
    while offset + 512 <= archive.len() {
        let header = &archive[offset..offset + 512];
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        let name_end = header[..100]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(100);
        let prefix_end = header[345..500]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(155);
        let mut path = header[345..345 + prefix_end].to_vec();
        if !path.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(&header[..name_end]);
        names.insert(path);
        let size_end = header[124..136]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(12);
        let size = std::str::from_utf8(&header[124..124 + size_end])
            .expect("read a tar size")
            .trim_start_matches('0');
        let size = if size.is_empty() {
            0
        } else {
            usize::from_str_radix(size, 8).expect("parse a tar size")
        };
        offset += 512 + size.div_ceil(512) * 512;
    }
    names
}
