use std::path::Path;
use std::process::Command;

pub(crate) fn create_ssh_key(path: &Path) {
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
