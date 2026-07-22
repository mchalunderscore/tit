use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

pub(crate) struct TestInstance {
    directory: TempDir,
    config: PathBuf,
}

impl TestInstance {
    pub(crate) fn new() -> Self {
        let directory = TempDir::new().expect("create a temporary instance");
        let config = directory.path().join("config.toml");
        fs::write(
            &config,
            "version = 1\npublic_url = \"https://tit.example/\"\n",
        )
        .expect("write the configuration");
        Self { directory, config }
    }

    pub(crate) fn path(&self) -> &Path {
        self.directory.path()
    }

    pub(crate) fn config(&self) -> &Path {
        &self.config
    }

    pub(crate) fn run(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_tit"))
            .args(arguments)
            .output()
            .expect("run tit")
    }
}

pub(crate) fn free_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a temporary port");
    listener.local_addr().expect("read the temporary address")
}

pub(crate) fn create_bare_git_fixture(path: &Path, object_format: &str) {
    let output = Command::new("git")
        .args(["init", "--bare", "--object-format", object_format])
        .arg(path)
        .output()
        .expect("run the stock Git client");
    assert!(
        output.status.success(),
        "create a bare Git fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub(crate) fn create_ssh_key_fixture(path: &Path) {
    let output = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path)
        .output()
        .expect("run the stock ssh-keygen client");
    assert!(
        output.status.success(),
        "create an SSH key fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub(crate) fn read_stock_ssh_configuration() {
    let output = Command::new("ssh")
        .args(["-G", "-F", "/dev/null", "localhost"])
        .output()
        .expect("run the stock SSH client");
    assert!(
        output.status.success(),
        "read the SSH configuration: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.stdout.is_empty());
}
