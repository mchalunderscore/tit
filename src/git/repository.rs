use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use gix::hash::{Kind, ObjectId};
use gix::objs::{Data, Kind as ObjectKind, tree::EntryKind};
use gix::refs::transaction::{Change, LogChange, PreviousValue, RefEdit, RefLog};
use gix::refs::{FullName, Target};
use gix_pack::data::Version;
use gix_pack::data::output::{Count, Entry, bytes::FromEntriesIter};
use thiserror::Error;

const MAX_OBJECTS_PER_PACK: usize = 100_000;
const MAX_OBJECT_BYTES: usize = 64 * 1024 * 1024;
const MAX_PACK_BYTES: usize = 256 * 1024 * 1024;

pub(crate) struct GitRepository {
    repository: gix::Repository,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GitReference {
    pub(crate) name: Vec<u8>,
    pub(crate) target: ObjectId,
    pub(crate) peeled: Option<ObjectId>,
    pub(crate) symbolic_target: Option<Vec<u8>>,
}

impl GitRepository {
    pub(crate) fn open(path: &Path) -> Result<Self, GitRepositoryError> {
        let repository = gix::open(path).map_err(|error| GitRepositoryError::Open {
            path: path.to_owned(),
            reason: error.to_string(),
        })?;
        if !repository.is_bare() {
            return Err(GitRepositoryError::NotBare(path.to_owned()));
        }
        Ok(Self { repository })
    }

    pub(crate) fn object_format(&self) -> Kind {
        self.repository.object_hash()
    }

    pub(crate) fn create_bare(path: &Path, object_format: Kind) -> Result<(), GitRepositoryError> {
        let options = gix::create::Options {
            object_hash: (object_format == Kind::Sha256).then_some(Kind::Sha256),
            ..Default::default()
        };
        let repository = gix::ThreadSafeRepository::init(path, gix::create::Kind::Bare, options)
            .map_err(|error| GitRepositoryError::Create {
                path: path.to_owned(),
                reason: error.to_string(),
            })?;
        drop(repository);
        fs::write(path.join("HEAD"), b"ref: refs/heads/main\n").map_err(|source| {
            GitRepositoryError::Filesystem {
                path: path.join("HEAD"),
                source,
            }
        })?;
        let created = Self::open(path)?;
        if created.object_format() != object_format {
            return Err(GitRepositoryError::WrongObjectFormat);
        }
        Ok(())
    }

    pub(crate) fn copy_bare(source: &Path, destination: &Path) -> Result<Kind, GitRepositoryError> {
        let source_repository = Self::open(source)?;
        let object_format = source_repository.object_format();
        copy_repository_tree(source, destination)?;
        let copy = Self::open(destination)?;
        if copy.object_format() != object_format {
            return Err(GitRepositoryError::WrongObjectFormat);
        }
        Ok(object_format)
    }

    pub(crate) fn references(&self) -> Result<Vec<GitReference>, GitRepositoryError> {
        let mut references = Vec::new();
        let platform = self
            .repository
            .references()
            .map_err(|error| GitRepositoryError::References(error.to_string()))?;
        let iterator = platform
            .all()
            .map_err(|error| GitRepositoryError::References(error.to_string()))?;

        for reference in iterator {
            let reference =
                reference.map_err(|error| GitRepositoryError::References(error.to_string()))?;
            let Some(target) = reference.try_id().map(gix::Id::detach) else {
                continue;
            };
            let name = reference.name().as_bstr().to_vec();
            let peeled = if name.starts_with(b"refs/tags/") {
                let mut candidate = reference.clone();
                let candidate = candidate
                    .peel_to_id()
                    .map_err(|error| GitRepositoryError::References(error.to_string()))?
                    .detach();
                (candidate != target).then_some(candidate)
            } else {
                None
            };
            references.push(GitReference {
                name,
                target,
                peeled,
                symbolic_target: None,
            });
        }
        references.sort_by(|left, right| left.name.cmp(&right.name));

        if let Some(head) = self
            .repository
            .head_ref()
            .map_err(|error| GitRepositoryError::References(error.to_string()))?
        {
            let target = head.id().detach();
            references.insert(
                0,
                GitReference {
                    name: b"HEAD".to_vec(),
                    target,
                    peeled: None,
                    symbolic_target: Some(head.name().as_bstr().to_vec()),
                },
            );
        }
        Ok(references)
    }

    pub(crate) fn resolve_branch(&self, name: &str) -> Result<ObjectId, GitRepositoryError> {
        if !name.starts_with("refs/heads/") || name.len() > 1024 {
            return Err(GitRepositoryError::InvalidBranch);
        }
        let reference = self
            .repository
            .try_find_reference(name)
            .map_err(|error| GitRepositoryError::References(error.to_string()))?
            .ok_or_else(|| GitRepositoryError::MissingReference(name.to_owned()))?;
        let target = reference
            .try_id()
            .map(gix::Id::detach)
            .ok_or_else(|| GitRepositoryError::MissingReference(name.to_owned()))?;
        if self.find_object(target)?.kind != ObjectKind::Commit {
            return Err(GitRepositoryError::BranchNotCommit);
        }
        Ok(target)
    }

    pub(crate) fn reference_target(
        &self,
        name: &str,
    ) -> Result<Option<ObjectId>, GitRepositoryError> {
        self.repository
            .try_find_reference(name)
            .map(|reference| {
                reference.and_then(|reference| reference.try_id().map(gix::Id::detach))
            })
            .map_err(|error| GitRepositoryError::References(error.to_string()))
    }

    pub(crate) fn update_reference(
        &self,
        name: &str,
        expected: Option<ObjectId>,
        new: ObjectId,
    ) -> Result<(), GitRepositoryError> {
        if new.kind() != self.object_format() {
            return Err(GitRepositoryError::WrongObjectFormat);
        }
        let name = FullName::try_from(name)
            .map_err(|_| GitRepositoryError::InvalidReference(name.to_owned()))?;
        let edit = RefEdit {
            name,
            deref: false,
            change: Change::Update {
                expected: expected.map_or(PreviousValue::MustNotExist, |id| {
                    PreviousValue::MustExistAndMatch(Target::Object(id))
                }),
                new: Target::Object(new),
                log: LogChange {
                    mode: RefLog::AndReference,
                    force_create_reflog: false,
                    message: "pull request revision".into(),
                },
            },
        };
        self.repository
            .edit_references_as([edit], None)
            .map_err(|error| GitRepositoryError::RefTransaction(error.to_string()))?;
        Ok(())
    }

    pub(crate) fn make_pack(
        &self,
        wants: &[ObjectId],
        haves: &[ObjectId],
    ) -> Result<Vec<u8>, GitRepositoryError> {
        if wants.iter().any(|want| want.kind() != self.object_format())
            || haves.iter().any(|have| have.kind() != self.object_format())
        {
            return Err(GitRepositoryError::WrongObjectFormat);
        }
        let advertised: HashSet<_> = self
            .references()?
            .into_iter()
            .flat_map(|reference| [Some(reference.target), reference.peeled])
            .flatten()
            .collect();
        if wants.is_empty() || wants.iter().any(|want| !advertised.contains(want)) {
            return Err(GitRepositoryError::UnadvertisedWant);
        }
        let excluded = self.walk_reachable(haves, true)?;
        let mut objects: Vec<_> = self
            .walk_reachable(wants, false)?
            .into_iter()
            .filter(|id| !excluded.contains(id))
            .collect();
        objects.sort();

        let object_count =
            u32::try_from(objects.len()).map_err(|_| GitRepositoryError::ObjectLimit)?;
        let mut entries = Vec::with_capacity(objects.len());
        let mut total_object_bytes = 0_usize;
        for id in objects {
            let object = self.find_object(id)?;
            total_object_bytes = total_object_bytes
                .checked_add(object.data.len())
                .ok_or(GitRepositoryError::ObjectLimit)?;
            if object.data.len() > MAX_OBJECT_BYTES || total_object_bytes > MAX_PACK_BYTES {
                return Err(GitRepositoryError::ObjectLimit);
            }
            let count = Count::from_data(id, None);
            let data = Data::new(&object.data, object.kind, self.object_format());
            entries.push(
                Entry::from_data(&count, &data)
                    .map_err(|error| GitRepositoryError::Pack(error.to_string()))?,
            );
        }

        let chunks = entries
            .into_iter()
            .map(|entry| Ok::<_, std::io::Error>(vec![entry]));
        let mut writer = FromEntriesIter::new(
            chunks,
            Vec::new(),
            object_count,
            Version::V2,
            self.object_format(),
        );
        for result in writer.by_ref() {
            result.map_err(|error| GitRepositoryError::Pack(error.to_string()))?;
        }
        let pack = writer.into_write();
        if pack.len() > MAX_PACK_BYTES {
            return Err(GitRepositoryError::PackLimit);
        }
        Ok(pack)
    }

    fn walk_reachable(
        &self,
        roots: &[ObjectId],
        permit_missing_roots: bool,
    ) -> Result<HashSet<ObjectId>, GitRepositoryError> {
        let mut seen = HashSet::new();
        let mut pending = roots.to_vec();
        while let Some(id) = pending.pop() {
            if !seen.insert(id) {
                continue;
            }
            if seen.len() > MAX_OBJECTS_PER_PACK {
                return Err(GitRepositoryError::ObjectLimit);
            }
            let object = match self.repository.try_find_object(id) {
                Ok(Some(object)) => object,
                Ok(None) if permit_missing_roots && roots.contains(&id) => {
                    seen.remove(&id);
                    continue;
                }
                Ok(None) => return Err(GitRepositoryError::MissingObject(id)),
                Err(error) => {
                    return Err(GitRepositoryError::Object {
                        id,
                        reason: error.to_string(),
                    });
                }
            };
            match object.kind {
                ObjectKind::Blob => {}
                ObjectKind::Commit => {
                    let commit = object.try_to_commit_ref().map_err(|error| {
                        GitRepositoryError::DamagedObject {
                            id,
                            reason: error.to_string(),
                        }
                    })?;
                    pending.push(self.parse_id(commit.tree, id)?);
                    for parent in commit.parents {
                        pending.push(self.parse_id(parent, id)?);
                    }
                }
                ObjectKind::Tree => {
                    let tree = object.into_tree();
                    for entry in tree.iter() {
                        let entry = entry.map_err(|error| GitRepositoryError::DamagedObject {
                            id,
                            reason: error.to_string(),
                        })?;
                        if entry.kind() != EntryKind::Commit {
                            pending.push(entry.oid().to_owned());
                        }
                    }
                }
                ObjectKind::Tag => {
                    let tag = object.try_to_tag_ref().map_err(|error| {
                        GitRepositoryError::DamagedObject {
                            id,
                            reason: error.to_string(),
                        }
                    })?;
                    pending.push(self.parse_id(tag.target, id)?);
                }
            }
        }
        Ok(seen)
    }

    fn find_object(&self, id: ObjectId) -> Result<gix::Object<'_>, GitRepositoryError> {
        self.repository
            .find_object(id)
            .map_err(|error| GitRepositoryError::Object {
                id,
                reason: error.to_string(),
            })
    }

    fn parse_id(&self, input: &[u8], owner: ObjectId) -> Result<ObjectId, GitRepositoryError> {
        let id = ObjectId::from_hex(input).map_err(|error| GitRepositoryError::DamagedObject {
            id: owner,
            reason: error.to_string(),
        })?;
        if id.kind() != self.object_format() {
            return Err(GitRepositoryError::DamagedObject {
                id: owner,
                reason: "object ID uses the wrong hash format".to_owned(),
            });
        }
        Ok(id)
    }
}

#[derive(Debug, Error)]
pub(crate) enum GitRepositoryError {
    #[error("cannot create Git repository {path}: {reason}")]
    Create { path: PathBuf, reason: String },
    #[error("cannot open Git repository {path}: {reason}")]
    Open { path: PathBuf, reason: String },
    #[error("Git repository is not bare: {0}")]
    NotBare(PathBuf),
    #[error("cannot read Git references: {0}")]
    References(String),
    #[error("Git branch name is not valid")]
    InvalidBranch,
    #[error("Git reference name is not valid: {0}")]
    InvalidReference(String),
    #[error("Git reference does not exist: {0}")]
    MissingReference(String),
    #[error("Git branch does not point to a commit")]
    BranchNotCommit,
    #[error("cannot update Git references: {0}")]
    RefTransaction(String),
    #[error("cannot read Git object {id}: {reason}")]
    Object { id: ObjectId, reason: String },
    #[error("Git object does not exist: {0}")]
    MissingObject(ObjectId),
    #[error("Git object {id} is damaged: {reason}")]
    DamagedObject { id: ObjectId, reason: String },
    #[error("client requested an object that was not advertised")]
    UnadvertisedWant,
    #[error("object ID uses the wrong repository hash format")]
    WrongObjectFormat,
    #[error("Git repository contains a symbolic link or special file: {0}")]
    UnsafeFile(PathBuf),
    #[error("cannot access Git repository path {path}: {source}")]
    Filesystem {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Git object count or decoded size exceeds the limit")]
    ObjectLimit,
    #[error("generated Git pack exceeds the limit")]
    PackLimit,
    #[error("cannot generate Git pack: {0}")]
    Pack(String),
}

fn copy_repository_tree(source: &Path, destination: &Path) -> Result<(), GitRepositoryError> {
    fs::create_dir(destination).map_err(|source_error| GitRepositoryError::Filesystem {
        path: destination.to_owned(),
        source: source_error,
    })?;
    for entry in fs::read_dir(source).map_err(|source_error| GitRepositoryError::Filesystem {
        path: source.to_owned(),
        source: source_error,
    })? {
        let entry = entry.map_err(|source_error| GitRepositoryError::Filesystem {
            path: source.to_owned(),
            source: source_error,
        })?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type =
            entry
                .file_type()
                .map_err(|source_error| GitRepositoryError::Filesystem {
                    path: source_path.clone(),
                    source: source_error,
                })?;
        if file_type.is_dir() {
            copy_repository_tree(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path).map_err(|source_error| {
                GitRepositoryError::Filesystem {
                    path: source_path,
                    source: source_error,
                }
            })?;
        } else {
            return Err(GitRepositoryError::UnsafeFile(source_path));
        }
    }
    Ok(())
}
