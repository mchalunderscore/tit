use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::{Archive, Builder, EntryType, Header};
use thiserror::Error;

use crate::git::repository::{GitRepository, GitRepositoryError};
use crate::instance::{InstanceError, InstanceLock, REPOSITORY_DIRECTORY};
use crate::maintenance::MaintenanceGate;
use crate::store::{DATABASE_FILE, Store, StoreError};

const FORMAT_VERSION: u32 = 1;
const CONFIG_ARCHIVE_PATH: &str = "config.toml";
const DATABASE_ARCHIVE_PATH: &str = "tit.sqlite3";
const HOST_KEY_FILE: &str = "ssh_host_ed25519_key";
const MANIFEST_PATH: &str = "manifest.json";
const WARNING: &str = "This backup contains credentials.";
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct OnlineBackupService {
    instance_dir: PathBuf,
    config_path: PathBuf,
    maintenance: MaintenanceGate,
}

impl OnlineBackupService {
    pub(crate) fn new(
        instance_dir: PathBuf,
        config_path: PathBuf,
        maintenance: MaintenanceGate,
    ) -> Self {
        Self {
            instance_dir,
            config_path,
            maintenance,
        }
    }

    pub(crate) async fn create(&self, output: PathBuf) -> Result<(), BackupError> {
        let asynchronous = self.maintenance.maintenance_async().await;
        let instance_dir = self.instance_dir.clone();
        let config_path = self.config_path.clone();
        let maintenance = self.maintenance.clone();
        tokio::task::spawn_blocking(move || {
            let _asynchronous = asynchronous;
            let _synchronous = maintenance.maintenance();
            create_archive(&instance_dir, &config_path, &output)
        })
        .await
        .map_err(|_| BackupError::Task)??;
        Ok(())
    }
}

pub(crate) fn create_offline(
    instance_dir: &Path,
    config_path: &Path,
    output: &Path,
) -> Result<(), BackupError> {
    let _lock = InstanceLock::acquire(instance_dir)?;
    create_archive(instance_dir, config_path, output)
}

pub(crate) fn restore(archive_path: &Path, target: &Path) -> Result<(), BackupError> {
    validate_absolute_clean(archive_path)?;
    validate_absolute_clean(target)?;
    validate_empty_private_directory(target)?;

    let manifest = read_manifest(archive_path)?;
    let expected = expected_files(&manifest)?;
    verify_archive(archive_path, &expected)?;
    extract_archive(archive_path, target, &expected)?;

    if let Err(error) = validate_restored_instance(target) {
        let _ = remove_directory_contents(target);
        return Err(error);
    }
    Ok(())
}

fn create_archive(
    instance_dir: &Path,
    config_path: &Path,
    output: &Path,
) -> Result<(), BackupError> {
    validate_absolute_clean(instance_dir)?;
    validate_absolute_clean(config_path)?;
    validate_absolute_clean(output)?;
    if output.starts_with(instance_dir) {
        return Err(BackupError::OutputInsideInstance);
    }

    let temporary_database = instance_dir.join(format!(
        ".tit-backup-{:032x}.sqlite3",
        rand::random::<u128>()
    ));
    let temporary = TemporaryFile::create(&temporary_database)?;
    Store::open(&instance_dir.join(DATABASE_FILE))?.backup(&temporary_database)?;

    let mut files = Vec::new();
    add_file(
        &mut files,
        config_path.to_owned(),
        PathBuf::from(CONFIG_ARCHIVE_PATH),
    )?;
    add_file(
        &mut files,
        temporary_database.clone(),
        PathBuf::from(DATABASE_ARCHIVE_PATH),
    )?;
    let host_key = instance_dir.join(HOST_KEY_FILE);
    if host_key.exists() {
        add_file(&mut files, host_key, PathBuf::from(HOST_KEY_FILE))?;
    }
    collect_repository_files(
        &instance_dir.join(REPOSITORY_DIRECTORY),
        Path::new(REPOSITORY_DIRECTORY),
        &mut files,
    )?;
    files.sort_by(|left, right| {
        left.archive_path
            .as_os_str()
            .as_bytes()
            .cmp(right.archive_path.as_os_str().as_bytes())
    });

    let manifest = BackupManifest {
        version: FORMAT_VERSION,
        warning: WARNING.to_owned(),
        files: files
            .iter()
            .map(|file| ManifestFile {
                path_hex: encode_hex(file.archive_path.as_os_str().as_bytes()),
                bytes: file.bytes,
                sha256: file.sha256.clone(),
                kind: file.kind.as_str().to_owned(),
            })
            .collect(),
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;

    let mut output_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)
        .map_err(|source| BackupError::Io {
            path: output.to_owned(),
            source,
        })?;
    let result = (|| -> Result<(), BackupError> {
        {
            let mut builder = Builder::new(&mut output_file);
            append_bytes(
                &mut builder,
                Path::new(MANIFEST_PATH),
                &manifest_bytes,
                0o600,
            )?;
            for archived in &files {
                match archived.kind {
                    ArchiveKind::File => {
                        let mut source = File::open(&archived.source_path).map_err(|source| {
                            BackupError::Io {
                                path: archived.source_path.clone(),
                                source,
                            }
                        })?;
                        append_reader(
                            &mut builder,
                            &archived.archive_path,
                            &mut source,
                            archived.bytes,
                            archived.mode,
                        )?;
                    }
                    ArchiveKind::Directory => {
                        append_directory(&mut builder, &archived.archive_path, archived.mode)?;
                    }
                }
            }
            builder.finish()?;
        }
        output_file.sync_all().map_err(|source| BackupError::Io {
            path: output.to_owned(),
            source,
        })
    })();
    drop(temporary);
    if result.is_err() {
        let _ = fs::remove_file(output);
    }
    result
}

fn add_file(
    files: &mut Vec<ArchivedFile>,
    source_path: PathBuf,
    archive_path: PathBuf,
) -> Result<(), BackupError> {
    validate_archive_path(&archive_path)?;
    let metadata = fs::symlink_metadata(&source_path).map_err(|source| BackupError::Io {
        path: source_path.clone(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(BackupError::UnsafeSource(source_path));
    }
    let (bytes, sha256) = hash_file(&source_path)?;
    files.push(ArchivedFile {
        source_path,
        archive_path,
        bytes,
        sha256,
        mode: metadata.permissions().mode() & 0o700,
        kind: ArchiveKind::File,
    });
    Ok(())
}

fn collect_repository_files(
    source: &Path,
    archive_path: &Path,
    files: &mut Vec<ArchivedFile>,
) -> Result<(), BackupError> {
    let metadata = fs::symlink_metadata(source).map_err(|source_error| BackupError::Io {
        path: source.to_owned(),
        source: source_error,
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(BackupError::UnsafeSource(source.to_owned()));
    }
    files.push(ArchivedFile {
        source_path: source.to_owned(),
        archive_path: archive_path.to_owned(),
        bytes: 0,
        sha256: encode_hex(Sha256::digest([])),
        mode: metadata.permissions().mode() & 0o700,
        kind: ArchiveKind::Directory,
    });
    let mut entries = fs::read_dir(source)
        .map_err(|source_error| BackupError::Io {
            path: source.to_owned(),
            source: source_error,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source_error| BackupError::Io {
            path: source.to_owned(),
            source: source_error,
        })?;
    entries.sort_by(|left, right| {
        left.file_name()
            .as_bytes()
            .cmp(right.file_name().as_bytes())
    });
    for entry in entries {
        let child_source = entry.path();
        let child_archive = archive_path.join(entry.file_name());
        let child_metadata =
            fs::symlink_metadata(&child_source).map_err(|source_error| BackupError::Io {
                path: child_source.clone(),
                source: source_error,
            })?;
        if child_metadata.file_type().is_dir() {
            collect_repository_files(&child_source, &child_archive, files)?;
        } else if child_metadata.file_type().is_file() {
            add_file(files, child_source, child_archive)?;
        } else {
            return Err(BackupError::UnsafeSource(child_source));
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<(u64, String), BackupError> {
    let mut file = File::open(path).map_err(|source| BackupError::Io {
        path: path.to_owned(),
        source,
    })?;
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|source| BackupError::Io {
            path: path.to_owned(),
            source,
        })?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .ok_or(BackupError::SizeOverflow)?;
        digest.update(&buffer[..count]);
    }
    Ok((bytes, encode_hex(digest.finalize())))
}

fn append_bytes(
    builder: &mut Builder<&mut File>,
    path: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<(), BackupError> {
    let mut reader = bytes;
    append_reader(builder, path, &mut reader, bytes.len() as u64, mode)
}

fn append_reader(
    builder: &mut Builder<&mut File>,
    path: &Path,
    reader: &mut impl Read,
    bytes: u64,
    mode: u32,
) -> Result<(), BackupError> {
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Regular);
    header.set_size(bytes);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    builder.append_data(&mut header, path, reader)?;
    Ok(())
}

fn append_directory(
    builder: &mut Builder<&mut File>,
    path: &Path,
    mode: u32,
) -> Result<(), BackupError> {
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Directory);
    header.set_size(0);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    builder.append_data(&mut header, path, std::io::empty())?;
    Ok(())
}

fn read_manifest(archive_path: &Path) -> Result<BackupManifest, BackupError> {
    let file = File::open(archive_path).map_err(|source| BackupError::Io {
        path: archive_path.to_owned(),
        source,
    })?;
    let mut archive = Archive::new(file);
    let mut entries = archive.entries()?;
    let mut entry = entries.next().ok_or(BackupError::MissingManifest)??;
    if entry.path_bytes().as_ref() != MANIFEST_PATH.as_bytes()
        || entry.header().entry_type() != EntryType::Regular
        || entry.size() > MAX_MANIFEST_BYTES
    {
        return Err(BackupError::MissingManifest);
    }
    let mut contents = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut contents)?;
    let manifest: BackupManifest = serde_json::from_slice(&contents)?;
    if manifest.version != FORMAT_VERSION || manifest.warning != WARNING {
        return Err(BackupError::InvalidManifest);
    }
    Ok(manifest)
}

fn expected_files(
    manifest: &BackupManifest,
) -> Result<BTreeMap<Vec<u8>, ManifestFile>, BackupError> {
    let mut expected = BTreeMap::new();
    for file in &manifest.files {
        let bytes = decode_hex(&file.path_hex)?;
        let path = PathBuf::from(OsString::from_vec(bytes.clone()));
        validate_archive_path(&path)?;
        if decode_hex(&file.sha256)?.len() != 32
            || !matches!(file.kind.as_str(), "file" | "directory")
            || (file.kind == "directory"
                && (file.bytes != 0 || file.sha256 != encode_hex(Sha256::digest([]))))
            || expected.insert(bytes, file.clone()).is_some()
        {
            return Err(BackupError::InvalidManifest);
        }
    }
    for required in [
        CONFIG_ARCHIVE_PATH.as_bytes(),
        DATABASE_ARCHIVE_PATH.as_bytes(),
    ] {
        if !expected.contains_key(required) {
            return Err(BackupError::InvalidManifest);
        }
    }
    Ok(expected)
}

fn verify_archive(
    archive_path: &Path,
    expected: &BTreeMap<Vec<u8>, ManifestFile>,
) -> Result<(), BackupError> {
    let file = File::open(archive_path).map_err(|source| BackupError::Io {
        path: archive_path.to_owned(),
        source,
    })?;
    let mut archive = Archive::new(file);
    let mut seen = HashSet::new();
    for (index, entry) in archive.entries()?.enumerate() {
        let mut entry = entry?;
        let path = entry.path_bytes().into_owned();
        if index == 0 && path == MANIFEST_PATH.as_bytes() {
            continue;
        }
        let entry_kind = if entry.header().entry_type() == EntryType::Regular {
            "file"
        } else if entry.header().entry_type() == EntryType::Directory {
            "directory"
        } else {
            return Err(BackupError::UnsafeArchivePath(PathBuf::from(
                OsString::from_vec(path),
            )));
        };
        let Some(file) = expected.get(path.as_slice()) else {
            return Err(BackupError::UnexpectedArchiveEntry(PathBuf::from(
                OsString::from_vec(path),
            )));
        };
        if !seen.insert(path.clone()) || entry.size() != file.bytes || entry_kind != file.kind {
            return Err(BackupError::Checksum(PathBuf::from(OsString::from_vec(
                path,
            ))));
        }
        let mut digest = Sha256::new();
        let copied = std::io::copy(&mut entry, &mut DigestWriter(&mut digest))?;
        if copied != file.bytes || encode_hex(digest.finalize()) != file.sha256 {
            return Err(BackupError::Checksum(PathBuf::from(OsString::from_vec(
                path,
            ))));
        }
    }
    if seen.len() != expected.len() {
        return Err(BackupError::MissingArchiveEntry);
    }
    Ok(())
}

fn extract_archive(
    archive_path: &Path,
    target: &Path,
    expected: &BTreeMap<Vec<u8>, ManifestFile>,
) -> Result<(), BackupError> {
    let result = (|| -> Result<(), BackupError> {
        let file = File::open(archive_path).map_err(|source| BackupError::Io {
            path: archive_path.to_owned(),
            source,
        })?;
        let mut archive = Archive::new(file);
        let mut seen = HashSet::new();
        for (index, entry) in archive.entries()?.enumerate() {
            let mut entry = entry?;
            let path_bytes = entry.path_bytes().into_owned();
            if index == 0 && path_bytes == MANIFEST_PATH.as_bytes() {
                continue;
            }
            let manifest_file = expected
                .get(path_bytes.as_slice())
                .ok_or(BackupError::InvalidManifest)?;
            let relative = PathBuf::from(OsString::from_vec(path_bytes));
            let expected_type = if manifest_file.kind == "directory" {
                EntryType::Directory
            } else {
                EntryType::Regular
            };
            if !seen.insert(relative.clone())
                || entry.header().entry_type() != expected_type
                || entry.size() != manifest_file.bytes
            {
                return Err(BackupError::Checksum(relative));
            }
            let destination = target.join(&relative);
            create_private_parents(target, &relative)?;
            if manifest_file.kind == "directory" {
                match fs::create_dir(&destination) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(source) => {
                        return Err(BackupError::Io {
                            path: destination,
                            source,
                        });
                    }
                }
                fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).map_err(
                    |source| BackupError::Io {
                        path: destination,
                        source,
                    },
                )?;
            } else {
                let mut output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&destination)
                    .map_err(|source| BackupError::Io {
                        path: destination.clone(),
                        source,
                    })?;
                std::io::copy(&mut entry, &mut output)?;
                output.sync_all().map_err(|source| BackupError::Io {
                    path: destination.clone(),
                    source,
                })?;
                let (bytes, sha256) = hash_file(&destination)?;
                if bytes != manifest_file.bytes || sha256 != manifest_file.sha256 {
                    return Err(BackupError::Checksum(relative));
                }
            }
        }
        if seen.len() != expected.len() {
            return Err(BackupError::MissingArchiveEntry);
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = remove_directory_contents(target);
    }
    result
}

fn create_private_parents(target: &Path, relative: &Path) -> Result<(), BackupError> {
    let Some(parent) = relative.parent() else {
        return Ok(());
    };
    let mut current = target.to_owned();
    for component in parent.components() {
        let Component::Normal(name) = component else {
            return Err(BackupError::UnsafeArchivePath(relative.to_owned()));
        };
        current.push(name);
        match fs::create_dir(&current) {
            Ok(()) => fs::set_permissions(&current, fs::Permissions::from_mode(0o700)).map_err(
                |source| BackupError::Io {
                    path: current.clone(),
                    source,
                },
            )?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(BackupError::Io {
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn validate_restored_instance(target: &Path) -> Result<(), BackupError> {
    crate::store::doctor(target)?;
    let store = Store::open(&target.join(DATABASE_FILE))?;
    for repository in store.all_repositories()? {
        let path = target
            .join(REPOSITORY_DIRECTORY)
            .join(format!("{}.git", repository.id));
        let git = GitRepository::open(&path)?;
        let expected = match repository.object_format.as_str() {
            "sha1" => gix::hash::Kind::Sha1,
            "sha256" => gix::hash::Kind::Sha256,
            _ => return Err(BackupError::RepositoryFormat(repository.object_format)),
        };
        if git.object_format() != expected {
            return Err(BackupError::RepositoryFormat(repository.id));
        }
        git.integrity_check()?;
    }
    Ok(())
}

fn validate_empty_private_directory(path: &Path) -> Result<(), BackupError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| BackupError::Io {
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(BackupError::UnsafeTarget(path.to_owned()));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(BackupError::TargetPermissions { mode });
    }
    if fs::read_dir(path)
        .map_err(|source| BackupError::Io {
            path: path.to_owned(),
            source,
        })?
        .next()
        .is_some()
    {
        return Err(BackupError::TargetNotEmpty);
    }
    Ok(())
}

fn validate_absolute_clean(path: &Path) -> Result<(), BackupError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(BackupError::UncleanPath(path.to_owned()));
    }
    Ok(())
}

fn validate_archive_path(path: &Path) -> Result<(), BackupError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|part| {
            !matches!(part, Component::Normal(_))
                || matches!(part, Component::Normal(name) if name.as_bytes().is_empty())
        })
    {
        return Err(BackupError::UnsafeArchivePath(path.to_owned()));
    }
    Ok(())
}

fn remove_directory_contents(path: &Path) -> std::io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_dir() {
            fs::remove_dir_all(entry.path())?;
        } else {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn encode_hex(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[(byte >> 4) as usize]));
        encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    encoded
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>, BackupError> {
    if !encoded.len().is_multiple_of(2) {
        return Err(BackupError::InvalidManifest);
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_nibble(pair[0])?;
            let low = decode_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn decode_nibble(byte: u8) -> Result<u8, BackupError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(BackupError::InvalidManifest),
    }
}

struct DigestWriter<'a>(&'a mut Sha256);

impl Write for DigestWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0.update(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct ArchivedFile {
    source_path: PathBuf,
    archive_path: PathBuf,
    bytes: u64,
    sha256: String,
    mode: u32,
    kind: ArchiveKind,
}

#[derive(Clone, Copy)]
enum ArchiveKind {
    File,
    Directory,
}

impl ArchiveKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupManifest {
    version: u32,
    warning: String,
    files: Vec<ManifestFile>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    path_hex: String,
    bytes: u64,
    sha256: String,
    kind: String,
}

struct TemporaryFile {
    path: PathBuf,
}

impl TemporaryFile {
    fn create(path: &Path) -> Result<Self, BackupError> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|source| BackupError::Io {
                path: path.to_owned(),
                source,
            })?;
        Ok(Self {
            path: path.to_owned(),
        })
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[derive(Debug, Error)]
pub(crate) enum BackupError {
    #[error("backup path is not a clean absolute path: {0}")]
    UncleanPath(PathBuf),
    #[error("the backup output must be outside the instance directory")]
    OutputInsideInstance,
    #[error("backup source path is unsafe: {0}")]
    UnsafeSource(PathBuf),
    #[error("backup archive path is unsafe: {0}")]
    UnsafeArchivePath(PathBuf),
    #[error("backup archive has an unexpected file: {0}")]
    UnexpectedArchiveEntry(PathBuf),
    #[error("backup archive does not have a manifest")]
    MissingManifest,
    #[error("backup manifest is invalid")]
    InvalidManifest,
    #[error("backup archive does not have all manifest files")]
    MissingArchiveEntry,
    #[error("backup checksum does not match for: {0}")]
    Checksum(PathBuf),
    #[error("restore target is unsafe: {0}")]
    UnsafeTarget(PathBuf),
    #[error("restore target permissions are {mode:o}, expected 700 or more restrictive")]
    TargetPermissions { mode: u32 },
    #[error("restore target is not empty")]
    TargetNotEmpty,
    #[error("repository object format is invalid: {0}")]
    RepositoryFormat(String),
    #[error("backup size is too large")]
    SizeOverflow,
    #[error("backup task failed")]
    Task,
    #[error("backup I/O failed for {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(transparent)]
    Archive(#[from] std::io::Error),
    #[error(transparent)]
    Manifest(#[from] serde_json::Error),
    #[error(transparent)]
    Instance(#[from] InstanceError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Git(#[from] GitRepositoryError),
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::TempDir;

    use super::*;

    fn private_directory() -> TempDir {
        let directory = TempDir::new().expect("create a temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("make the directory private");
        directory
    }

    fn source_instance() -> (TempDir, PathBuf) {
        let instance = private_directory();
        let config = instance.path().join(CONFIG_ARCHIVE_PATH);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&config)
            .expect("create the configuration");
        file.write_all(
            b"version = 1\npublic_url = \"http://localhost:3000/\"\n\n[http]\nlisten = \"127.0.0.1:3000\"\n",
        )
        .expect("write the configuration");
        Store::open(&instance.path().join(DATABASE_FILE)).expect("create the database");
        fs::create_dir(instance.path().join(REPOSITORY_DIRECTORY))
            .expect("create the repository directory");
        fs::set_permissions(
            instance.path().join(REPOSITORY_DIRECTORY),
            fs::Permissions::from_mode(0o700),
        )
        .expect("make the repository directory private");
        (instance, config)
    }

    #[test]
    fn creates_and_restores_a_private_offline_backup() {
        let (instance, config) = source_instance();
        let output_directory = private_directory();
        let archive = output_directory.path().join("instance.tar");
        create_offline(instance.path(), &config, &archive).expect("create a backup");
        assert_eq!(
            fs::metadata(&archive)
                .expect("inspect the backup")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let target = private_directory();
        restore(&archive, target.path()).expect("restore the backup");
        assert_eq!(
            fs::read(target.path().join(CONFIG_ARCHIVE_PATH))
                .expect("read the restored configuration"),
            fs::read(config).expect("read the source configuration")
        );
        crate::store::doctor(target.path()).expect("check the restored database");
    }

    #[test]
    fn refuses_a_nonempty_target_and_a_second_archive() {
        let (instance, config) = source_instance();
        let output_directory = private_directory();
        let archive = output_directory.path().join("instance.tar");
        create_offline(instance.path(), &config, &archive).expect("create a backup");
        assert!(matches!(
            create_offline(instance.path(), &config, &archive),
            Err(BackupError::Io { .. })
        ));

        let target = private_directory();
        fs::write(target.path().join("keep"), b"keep").expect("make the target nonempty");
        assert!(matches!(
            restore(&archive, target.path()),
            Err(BackupError::TargetNotEmpty)
        ));
        assert_eq!(
            fs::read(target.path().join("keep")).expect("read the existing file"),
            b"keep"
        );
    }

    #[test]
    fn rejects_archive_data_that_does_not_match_the_manifest() {
        let (instance, config) = source_instance();
        let output_directory = private_directory();
        let archive = output_directory.path().join("instance.tar");
        create_offline(instance.path(), &config, &archive).expect("create a backup");
        let mut bytes = fs::read(&archive).expect("read the backup");
        let position = bytes
            .windows(b"version = 1".len())
            .position(|candidate| candidate == b"version = 1")
            .expect("find configuration data");
        bytes[position] ^= 1;
        fs::write(&archive, bytes).expect("damage the backup");

        let target = private_directory();
        assert!(restore(&archive, target.path()).is_err());
        assert!(
            fs::read_dir(target.path())
                .expect("inspect the restore target")
                .next()
                .is_none()
        );
    }
}
