use std::collections::{BTreeMap, HashSet, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use gix::bstr::ByteSlice;
use gix::hash::ObjectId;
use gix::objs::Kind as ObjectKind;
use gix::objs::tree::{EntryKind, EntryMode};
use gix::prelude::HeaderExt;
use thiserror::Error;

#[derive(Clone, Debug)]
pub(crate) struct ReadLimits {
    pub(crate) max_refs: usize,
    pub(crate) max_history_commits: usize,
    pub(crate) max_path_bytes: usize,
    pub(crate) max_tree_bytes: usize,
    pub(crate) max_tree_entries: usize,
    pub(crate) max_commit_bytes: usize,
    pub(crate) max_blob_bytes: usize,
    pub(crate) max_diff_bytes: usize,
    pub(crate) max_archive_entries: usize,
    pub(crate) max_archive_bytes: usize,
    pub(crate) max_archive_depth: usize,
    pub(crate) max_search_files: usize,
    pub(crate) max_search_bytes: usize,
    pub(crate) max_search_results: usize,
    pub(crate) max_search_query_bytes: usize,
    pub(crate) max_search_duration: Duration,
    pub(crate) max_duration: Duration,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_refs: 10_000,
            max_history_commits: 10_000,
            max_path_bytes: 4096,
            max_tree_bytes: 16 * 1024 * 1024,
            max_tree_entries: 100_000,
            max_commit_bytes: 1024 * 1024,
            max_blob_bytes: 16 * 1024 * 1024,
            max_diff_bytes: 64 * 1024 * 1024,
            max_archive_entries: 100_000,
            max_archive_bytes: 256 * 1024 * 1024,
            max_archive_depth: 128,
            max_search_files: 10_000,
            max_search_bytes: 64 * 1024 * 1024,
            max_search_results: 500,
            max_search_query_bytes: 256,
            max_search_duration: Duration::from_secs(5),
            max_duration: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ReadCancellation {
    cancelled: Arc<AtomicBool>,
}

impl ReadCancellation {
    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

pub(crate) struct RepositoryReadService {
    repository: gix::Repository,
    limits: ReadLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RefInfo {
    pub(crate) name: Vec<u8>,
    pub(crate) target: ObjectId,
    pub(crate) peeled: Option<ObjectId>,
    pub(crate) symbolic_target: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommitInfo {
    pub(crate) id: ObjectId,
    pub(crate) tree: ObjectId,
    pub(crate) parents: Vec<ObjectId>,
    pub(crate) author_name: Vec<u8>,
    pub(crate) author_email: Vec<u8>,
    pub(crate) committed_at: i64,
    pub(crate) message: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TreeEntryInfo {
    pub(crate) name: Vec<u8>,
    pub(crate) id: ObjectId,
    pub(crate) mode: u16,
    pub(crate) kind: EntryKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlobInfo {
    pub(crate) id: ObjectId,
    pub(crate) mode: u16,
    pub(crate) data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadmeInfo {
    pub(crate) path: Vec<u8>,
    pub(crate) blob: BlobInfo,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DiffFile {
    pub(crate) path: Vec<u8>,
    pub(crate) old_id: Option<ObjectId>,
    pub(crate) new_id: Option<ObjectId>,
    pub(crate) old_mode: Option<u16>,
    pub(crate) new_mode: Option<u16>,
    pub(crate) binary: bool,
    pub(crate) hunks: Vec<u8>,
    pub(crate) old_data: Option<Vec<u8>>,
    pub(crate) new_data: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Mergeability {
    Unrelated,
    AlreadyMerged,
    FastForward,
    Clean,
    Conflicting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Comparison {
    pub(crate) merge_base: Option<ObjectId>,
    pub(crate) commits: Vec<CommitInfo>,
    pub(crate) changed_paths: Vec<Vec<u8>>,
    pub(crate) files: Vec<DiffFile>,
    pub(crate) mergeability: Mergeability,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlameHunk {
    pub(crate) start_line: u32,
    pub(crate) source_start_line: u32,
    pub(crate) line_count: u32,
    pub(crate) commit_id: ObjectId,
    pub(crate) source_path: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArchiveStats {
    pub(crate) entries: usize,
    pub(crate) bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SearchMatch {
    pub(crate) path: Vec<u8>,
    pub(crate) line_number: usize,
    pub(crate) line: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SearchOutcome {
    pub(crate) commit: ObjectId,
    pub(crate) matches: Vec<SearchMatch>,
    pub(crate) files_scanned: usize,
    pub(crate) bytes_scanned: usize,
    pub(crate) truncated: bool,
}

impl RepositoryReadService {
    pub(crate) fn open(path: &Path, limits: ReadLimits) -> Result<Self, ReadError> {
        let repository = gix::open(path).map_err(|error| ReadError::Open {
            path: path.to_owned(),
            reason: error.to_string(),
        })?;
        if !repository.is_bare() {
            return Err(ReadError::NotBare(path.to_owned()));
        }
        validate_limits(&limits)?;
        Ok(Self {
            repository: repository.with_object_memory(),
            limits,
        })
    }

    pub(crate) fn references(
        &self,
        cancellation: &ReadCancellation,
    ) -> Result<Vec<RefInfo>, ReadError> {
        let budget = self.budget(cancellation);
        let platform = self
            .repository
            .references()
            .map_err(|error| ReadError::Git(error.to_string()))?;
        let iterator = platform
            .all()
            .map_err(|error| ReadError::Git(error.to_string()))?;
        let mut references = Vec::new();
        for reference in iterator {
            budget.check()?;
            if references.len() >= self.limits.max_refs {
                return Err(ReadError::Limit("refs"));
            }
            let reference = reference.map_err(|error| ReadError::Git(error.to_string()))?;
            if reference.name().as_bstr().len() > self.limits.max_path_bytes {
                return Err(ReadError::Limit("ref name bytes"));
            }
            let Some(target) = reference.try_id().map(gix::Id::detach) else {
                continue;
            };
            let name = reference.name().as_bstr().to_vec();
            let peeled = if name.starts_with(b"refs/tags/") {
                let mut candidate = reference.clone();
                let candidate = candidate
                    .peel_to_id()
                    .map_err(|error| ReadError::Git(error.to_string()))?
                    .detach();
                (candidate != target).then_some(candidate)
            } else {
                None
            };
            references.push(RefInfo {
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
            .map_err(|error| ReadError::Git(error.to_string()))?
        {
            if references.len() >= self.limits.max_refs {
                return Err(ReadError::Limit("refs"));
            }
            references.insert(
                0,
                RefInfo {
                    name: b"HEAD".to_vec(),
                    target: head.id().detach(),
                    peeled: None,
                    symbolic_target: Some(head.name().as_bstr().to_vec()),
                },
            );
        }
        Ok(references)
    }

    pub(crate) fn commit(
        &self,
        id: ObjectId,
        cancellation: &ReadCancellation,
    ) -> Result<CommitInfo, ReadError> {
        let budget = self.budget(cancellation);
        self.read_commit(id, &budget)
    }

    pub(crate) fn history(
        &self,
        start: ObjectId,
        cancellation: &ReadCancellation,
    ) -> Result<Vec<CommitInfo>, ReadError> {
        let budget = self.budget(cancellation);
        self.history_with_budget(start, &budget)
    }

    pub(crate) fn tree(
        &self,
        commit: ObjectId,
        path: &[u8],
        cancellation: &ReadCancellation,
    ) -> Result<Vec<TreeEntryInfo>, ReadError> {
        validate_path(path, true, self.limits.max_path_bytes)?;
        let budget = self.budget(cancellation);
        let commit = self.read_commit(commit, &budget)?;
        let tree_id = self.resolve_tree(commit.tree, path, &budget)?;
        let tree = self.read_tree(tree_id, &budget)?;
        if tree.entries.len() > self.limits.max_tree_entries {
            return Err(ReadError::Limit("tree entries"));
        }
        tree.entries
            .into_iter()
            .map(|entry| {
                budget.check()?;
                Ok(TreeEntryInfo {
                    name: entry.filename.to_vec(),
                    id: entry.oid.to_owned(),
                    mode: entry.mode.value(),
                    kind: entry.mode.kind(),
                })
            })
            .collect()
    }

    pub(crate) fn blob(
        &self,
        commit: ObjectId,
        path: &[u8],
        cancellation: &ReadCancellation,
    ) -> Result<BlobInfo, ReadError> {
        validate_path(path, false, self.limits.max_path_bytes)?;
        let budget = self.budget(cancellation);
        let commit = self.read_commit(commit, &budget)?;
        let (id, mode) = self.resolve_blob(commit.tree, path, &budget)?;
        self.read_blob(id, mode, &budget)
    }

    pub(crate) fn raw(
        &self,
        commit: ObjectId,
        path: &[u8],
        cancellation: &ReadCancellation,
        output: &mut impl Write,
    ) -> Result<usize, ReadError> {
        validate_path(path, false, self.limits.max_path_bytes)?;
        let budget = self.budget(cancellation);
        let commit = self.read_commit(commit, &budget)?;
        let (id, mode) = self.resolve_blob(commit.tree, path, &budget)?;
        let blob = self.read_blob(id, mode, &budget)?;
        budget.check()?;
        output.write_all(&blob.data).map_err(ReadError::Output)?;
        Ok(blob.data.len())
    }

    pub(crate) fn readme(
        &self,
        commit: ObjectId,
        cancellation: &ReadCancellation,
    ) -> Result<Option<ReadmeInfo>, ReadError> {
        let budget = self.budget(cancellation);
        let commit = self.read_commit(commit, &budget)?;
        let tree = self.read_tree(commit.tree, &budget)?;
        let mut candidates = Vec::new();
        for entry in tree.entries {
            budget.check()?;
            if !entry.mode.is_blob() {
                continue;
            }
            if let Some(priority) = readme_priority(&entry.filename) {
                candidates.push((
                    priority,
                    entry.filename.to_vec(),
                    entry.oid.to_owned(),
                    entry.mode,
                ));
            }
        }
        candidates.sort_by(|left, right| (left.0, &left.1).cmp(&(right.0, &right.1)));
        let Some((_, path, id, mode)) = candidates.into_iter().next() else {
            return Ok(None);
        };
        Ok(Some(ReadmeInfo {
            path,
            blob: self.read_blob(id, mode, &budget)?,
        }))
    }

    pub(crate) fn diff(
        &self,
        old_commit: ObjectId,
        new_commit: ObjectId,
        cancellation: &ReadCancellation,
    ) -> Result<Vec<DiffFile>, ReadError> {
        let budget = self.budget(cancellation);
        self.diff_with_budget(old_commit, new_commit, &budget)
    }

    pub(crate) fn commit_diff(
        &self,
        commit_id: ObjectId,
        cancellation: &ReadCancellation,
    ) -> Result<Vec<DiffFile>, ReadError> {
        let budget = self.budget(cancellation);
        let commit = self.read_commit(commit_id, &budget)?;
        match commit.parents.first() {
            Some(parent) => self.diff_with_budget(*parent, commit_id, &budget),
            None => self.diff_trees_with_budget(
                ObjectId::empty_tree(self.repository.object_hash()),
                commit.tree,
                &budget,
            ),
        }
    }

    pub(crate) fn comparison(
        &self,
        base_commit: ObjectId,
        head_commit: ObjectId,
        cancellation: &ReadCancellation,
    ) -> Result<Comparison, ReadError> {
        let budget = self.budget(cancellation);
        let base_history = self.history_with_budget(base_commit, &budget)?;
        let head_history = self.history_with_budget(head_commit, &budget)?;
        if base_history.len().saturating_add(head_history.len()) > self.limits.max_history_commits {
            return Err(ReadError::Limit("comparison commits"));
        }
        let base_ids: HashSet<_> = base_history.iter().map(|commit| commit.id).collect();
        let head_ids: HashSet<_> = head_history.iter().map(|commit| commit.id).collect();
        let head_tree = head_history
            .first()
            .ok_or(ReadError::ObjectNotFound(head_commit))?
            .tree;
        budget.check()?;
        let merge_base = match self.repository.merge_base(base_commit, head_commit) {
            Ok(id) => Some(id.detach()),
            Err(gix::repository::merge_base::Error::NotFound { .. }) => None,
            Err(error) => return Err(ReadError::Git(error.to_string())),
        };
        let mut commit_bytes = 0_usize;
        let mut commits = Vec::new();
        for commit in head_history
            .into_iter()
            .filter(|commit| !base_ids.contains(&commit.id))
        {
            budget.check()?;
            commit_bytes = checked_add(
                commit_bytes,
                commit.message.len(),
                self.limits.max_diff_bytes,
                "comparison output bytes",
            )?;
            commits.push(commit);
        }
        let files = match merge_base {
            Some(merge_base) => self.diff_with_budget(merge_base, head_commit, &budget)?,
            None => self.diff_trees_with_budget(
                ObjectId::empty_tree(self.repository.object_hash()),
                head_tree,
                &budget,
            )?,
        };
        let changed_paths = files.iter().map(|file| file.path.clone()).collect();
        let mergeability = match merge_base {
            None => Mergeability::Unrelated,
            Some(_) if base_ids.contains(&head_commit) => Mergeability::AlreadyMerged,
            Some(_) if head_ids.contains(&base_commit) => Mergeability::FastForward,
            Some(merge_base) => {
                budget.check()?;
                self.diff_with_budget(merge_base, base_commit, &budget)?;
                let options = self
                    .repository
                    .tree_merge_options()
                    .map_err(|error| ReadError::Git(error.to_string()))?
                    .with_rewrites(Some(Default::default()))
                    .with_fail_on_conflict(Some(Default::default()));
                let outcome = self
                    .repository
                    .merge_commits(base_commit, head_commit, Default::default(), options.into())
                    .map_err(|error| ReadError::Git(error.to_string()))?;
                if outcome
                    .tree_merge
                    .has_unresolved_conflicts(Default::default())
                {
                    Mergeability::Conflicting
                } else {
                    Mergeability::Clean
                }
            }
        };
        budget.check()?;
        Ok(Comparison {
            merge_base,
            commits,
            changed_paths,
            files,
            mergeability,
        })
    }

    fn diff_with_budget(
        &self,
        old_commit: ObjectId,
        new_commit: ObjectId,
        budget: &ReadBudget<'_>,
    ) -> Result<Vec<DiffFile>, ReadError> {
        let old = self.read_commit(old_commit, budget)?;
        let new = self.read_commit(new_commit, budget)?;
        self.diff_trees_with_budget(old.tree, new.tree, budget)
    }

    fn diff_trees_with_budget(
        &self,
        old_tree: ObjectId,
        new_tree: ObjectId,
        budget: &ReadBudget<'_>,
    ) -> Result<Vec<DiffFile>, ReadError> {
        let old_files = self.flatten_tree(old_tree, budget)?;
        let new_files = self.flatten_tree(new_tree, budget)?;
        let paths: BTreeMap<&[u8], ()> = old_files
            .keys()
            .chain(new_files.keys())
            .map(|path| (path.as_slice(), ()))
            .collect();
        let mut files = Vec::new();
        let mut bytes = 0_usize;
        for path in paths.keys() {
            budget.check()?;
            let old = old_files.get(*path);
            let new = new_files.get(*path);
            if old == new {
                continue;
            }
            let old_data = self.diff_blob(old, budget)?;
            let new_data = self.diff_blob(new, budget)?;
            bytes = checked_add(
                bytes,
                old_data.len(),
                self.limits.max_diff_bytes,
                "diff bytes",
            )?;
            bytes = checked_add(
                bytes,
                new_data.len(),
                self.limits.max_diff_bytes,
                "diff bytes",
            )?;
            let binary = old.is_some_and(|file| file.mode.is_commit())
                || new.is_some_and(|file| file.mode.is_commit())
                || old_data.contains(&0)
                || new_data.contains(&0);
            let hunks = if binary {
                Vec::new()
            } else {
                unified_diff(&old_data, &new_data)?
            };
            bytes = checked_add(bytes, hunks.len(), self.limits.max_diff_bytes, "diff bytes")?;
            files.push(DiffFile {
                path: path.to_vec(),
                old_id: old.map(|file| file.id),
                new_id: new.map(|file| file.id),
                old_mode: old.map(|file| file.mode.value()),
                new_mode: new.map(|file| file.mode.value()),
                binary,
                hunks,
                old_data: old.map(|_| old_data),
                new_data: new.map(|_| new_data),
            });
        }
        Ok(files)
    }

    pub(crate) fn blame(
        &self,
        commit: ObjectId,
        path: &[u8],
        cancellation: &ReadCancellation,
    ) -> Result<Vec<BlameHunk>, ReadError> {
        validate_path(path, false, self.limits.max_path_bytes)?;
        let budget = self.budget(cancellation);
        let history = self.history_with_budget(commit, &budget)?;
        let mut candidate_bytes = 0_usize;
        for candidate in &history {
            budget.check()?;
            if let Ok((id, _)) = self.resolve_blob(candidate.tree, path, &budget) {
                let header = self
                    .repository
                    .objects
                    .header(id)
                    .map_err(|error| ReadError::Git(error.to_string()))?;
                candidate_bytes = checked_add(
                    candidate_bytes,
                    usize::try_from(header.size()).map_err(|_| ReadError::Limit("blame bytes"))?,
                    self.limits.max_diff_bytes,
                    "blame bytes",
                )?;
            }
        }
        budget.check()?;
        let outcome = self
            .repository
            .blame_file(path.as_bstr(), commit, Default::default())
            .map_err(|error| ReadError::Git(error.to_string()))?;
        budget.check()?;
        if outcome.statistics.commits_traversed > self.limits.max_history_commits
            || outcome.blob.len() > self.limits.max_blob_bytes
        {
            return Err(ReadError::Limit("blame"));
        }
        outcome
            .entries
            .into_iter()
            .map(|entry| {
                Ok(BlameHunk {
                    start_line: entry.start_in_blamed_file + 1,
                    source_start_line: entry.start_in_source_file + 1,
                    line_count: entry.len.get(),
                    commit_id: entry.commit_id,
                    source_path: entry.source_file_name.map(|path| path.to_vec()),
                })
            })
            .collect()
    }

    pub(crate) fn archive(
        &self,
        commit: ObjectId,
        cancellation: &ReadCancellation,
        output: &mut impl Write,
    ) -> Result<ArchiveStats, ReadError> {
        let budget = self.budget(cancellation);
        let commit = self.read_commit(commit, &budget)?;
        let mut writer = BoundedWriter {
            output,
            budget: &budget,
            written: 0,
            maximum: self.limits.max_archive_bytes,
            failure: None,
        };
        let mut entries = 0_usize;
        let result = self.archive_tree(
            commit.tree,
            commit.committed_at.max(0) as u64,
            &budget,
            &mut writer,
            &mut entries,
        );
        if let Err(error) = result {
            return Err(writer.failure.take().map_or(error, ReadFailure::into_error));
        }
        if let Err(error) = writer.write_all(&[0_u8; 1024]) {
            return Err(writer
                .failure
                .take()
                .map_or(ReadError::Output(error), ReadFailure::into_error));
        }
        Ok(ArchiveStats {
            entries,
            bytes: writer.written,
        })
    }

    pub(crate) fn search(
        &self,
        commit: ObjectId,
        query: &[u8],
        cancellation: &ReadCancellation,
    ) -> Result<SearchOutcome, ReadError> {
        if query.is_empty() || query.contains(&0) {
            return Err(ReadError::InvalidSearchQuery);
        }
        if query.len() > self.limits.max_search_query_bytes {
            return Err(ReadError::Limit("search query bytes"));
        }
        let budget = self.budget_for(cancellation, self.limits.max_search_duration);
        let commit_info = self.read_commit(commit, &budget)?;
        let files = self.flatten_tree(commit_info.tree, &budget)?;
        let mut matches = Vec::new();
        let mut files_scanned = 0_usize;
        let mut bytes_scanned = 0_usize;
        let mut truncated = false;

        'files: for (path, file) in files {
            budget.check()?;
            if file.mode.is_commit() {
                continue;
            }
            files_scanned += 1;
            if files_scanned > self.limits.max_search_files {
                return Err(ReadError::Limit("search files"));
            }
            let header = self
                .repository
                .objects
                .header(file.id)
                .map_err(|error| ReadError::Git(error.to_string()))?;
            let size =
                usize::try_from(header.size()).map_err(|_| ReadError::Limit("search bytes"))?;
            bytes_scanned = checked_add(
                bytes_scanned,
                size,
                self.limits.max_search_bytes,
                "search bytes",
            )?;
            let blob = self.read_blob(file.id, file.mode, &budget)?;
            if blob.data.contains(&0) {
                continue;
            }
            for (index, line) in blob.data.split(|byte| *byte == b'\n').enumerate() {
                budget.check()?;
                if !contains_bytes(line, query) {
                    continue;
                }
                if matches.len() == self.limits.max_search_results {
                    truncated = true;
                    break 'files;
                }
                matches.push(SearchMatch {
                    path: path.clone(),
                    line_number: index + 1,
                    line: line.strip_suffix(b"\r").unwrap_or(line).to_vec(),
                });
            }
        }
        Ok(SearchOutcome {
            commit,
            matches,
            files_scanned,
            bytes_scanned,
            truncated,
        })
    }

    fn budget<'a>(&self, cancellation: &'a ReadCancellation) -> ReadBudget<'a> {
        self.budget_for(cancellation, self.limits.max_duration)
    }

    fn budget_for<'a>(
        &self,
        cancellation: &'a ReadCancellation,
        duration: Duration,
    ) -> ReadBudget<'a> {
        ReadBudget {
            cancellation,
            deadline: Instant::now() + duration,
        }
    }

    fn read_commit(&self, id: ObjectId, budget: &ReadBudget<'_>) -> Result<CommitInfo, ReadError> {
        budget.check()?;
        let object = self
            .repository
            .try_find_object(id)
            .map_err(|error| ReadError::Git(error.to_string()))?
            .ok_or(ReadError::ObjectNotFound(id))?;
        if object.kind != ObjectKind::Commit {
            return Err(ReadError::WrongObjectKind {
                expected: "commit",
                actual: object.kind,
            });
        }
        if object.data.len() > self.limits.max_commit_bytes {
            return Err(ReadError::Limit("commit bytes"));
        }
        let commit = object
            .try_to_commit_ref()
            .map_err(|error| ReadError::Git(error.to_string()))?;
        let tree = self.parse_id(commit.tree, id)?;
        let parents = commit
            .parents
            .iter()
            .map(|parent| self.parse_id(parent, id))
            .collect::<Result<Vec<_>, _>>()?;
        let author = commit
            .author()
            .map_err(|error| ReadError::Git(error.to_string()))?;
        let committed_at = commit
            .time()
            .map_err(|error| ReadError::Git(error.to_string()))?
            .seconds;
        Ok(CommitInfo {
            id,
            tree,
            parents,
            author_name: author.name.to_vec(),
            author_email: author.email.to_vec(),
            committed_at,
            message: commit.message.to_vec(),
        })
    }

    fn history_with_budget(
        &self,
        start: ObjectId,
        budget: &ReadBudget<'_>,
    ) -> Result<Vec<CommitInfo>, ReadError> {
        let mut pending = VecDeque::from([start]);
        let mut seen = HashSet::new();
        let mut history = Vec::new();
        while let Some(id) = pending.pop_front() {
            budget.check()?;
            if !seen.insert(id) {
                continue;
            }
            if history.len() >= self.limits.max_history_commits {
                return Err(ReadError::Limit("history commits"));
            }
            let commit = self.read_commit(id, budget)?;
            pending.extend(commit.parents.iter().copied());
            history.push(commit);
        }
        Ok(history)
    }

    fn read_tree(
        &self,
        id: ObjectId,
        budget: &ReadBudget<'_>,
    ) -> Result<gix::objs::Tree, ReadError> {
        budget.check()?;
        let object = self
            .repository
            .try_find_object(id)
            .map_err(|error| ReadError::Git(error.to_string()))?
            .ok_or(ReadError::ObjectNotFound(id))?;
        if object.kind != ObjectKind::Tree {
            return Err(ReadError::WrongObjectKind {
                expected: "tree",
                actual: object.kind,
            });
        }
        if object.data.len() > self.limits.max_tree_bytes {
            return Err(ReadError::Limit("tree bytes"));
        }
        gix::objs::Tree::try_from(object.into_tree())
            .map_err(|error| ReadError::Git(error.to_string()))
    }

    fn resolve_tree(
        &self,
        root: ObjectId,
        path: &[u8],
        budget: &ReadBudget<'_>,
    ) -> Result<ObjectId, ReadError> {
        let mut tree_id = root;
        if path.is_empty() {
            return Ok(tree_id);
        }
        for component in path.split(|byte| *byte == b'/') {
            budget.check()?;
            let tree = self.read_tree(tree_id, budget)?;
            let entry = tree
                .entries
                .iter()
                .find(|entry| entry.filename.as_bytes() == component)
                .ok_or_else(|| ReadError::PathNotFound(path.to_vec()))?;
            if !entry.mode.is_tree() {
                return Err(ReadError::NotTree(path.to_vec()));
            }
            tree_id = entry.oid.to_owned();
        }
        Ok(tree_id)
    }

    fn resolve_blob(
        &self,
        root: ObjectId,
        path: &[u8],
        budget: &ReadBudget<'_>,
    ) -> Result<(ObjectId, EntryMode), ReadError> {
        let mut components = path.split(|byte| *byte == b'/').peekable();
        let mut tree_id = root;
        while let Some(component) = components.next() {
            budget.check()?;
            let tree = self.read_tree(tree_id, budget)?;
            let entry = tree
                .entries
                .iter()
                .find(|entry| entry.filename.as_bytes() == component)
                .ok_or_else(|| ReadError::PathNotFound(path.to_vec()))?;
            if components.peek().is_some() {
                if !entry.mode.is_tree() {
                    return Err(ReadError::NotTree(path.to_vec()));
                }
                tree_id = entry.oid.to_owned();
            } else if entry.mode.is_blob_or_symlink() {
                return Ok((entry.oid.to_owned(), entry.mode));
            } else {
                return Err(ReadError::NotBlob(path.to_vec()));
            }
        }
        Err(ReadError::NotBlob(path.to_vec()))
    }

    fn read_blob(
        &self,
        id: ObjectId,
        mode: EntryMode,
        budget: &ReadBudget<'_>,
    ) -> Result<BlobInfo, ReadError> {
        budget.check()?;
        let object = self
            .repository
            .try_find_object(id)
            .map_err(|error| ReadError::Git(error.to_string()))?
            .ok_or(ReadError::ObjectNotFound(id))?;
        if object.kind != ObjectKind::Blob {
            return Err(ReadError::WrongObjectKind {
                expected: "blob",
                actual: object.kind,
            });
        }
        if object.data.len() > self.limits.max_blob_bytes {
            return Err(ReadError::Limit("blob bytes"));
        }
        Ok(BlobInfo {
            id,
            mode: mode.value(),
            data: object.data.to_vec(),
        })
    }

    fn flatten_tree(
        &self,
        root: ObjectId,
        budget: &ReadBudget<'_>,
    ) -> Result<BTreeMap<Vec<u8>, TreeFile>, ReadError> {
        let mut files = BTreeMap::new();
        let mut pending = vec![(Vec::new(), root)];
        let mut entries = 0_usize;
        while let Some((prefix, tree_id)) = pending.pop() {
            budget.check()?;
            let tree = self.read_tree(tree_id, budget)?;
            for entry in tree.entries {
                budget.check()?;
                entries += 1;
                if entries > self.limits.max_tree_entries {
                    return Err(ReadError::Limit("tree entries"));
                }
                let path = join_git_path(&prefix, &entry.filename, self.limits.max_path_bytes)?;
                if entry.mode.is_tree() {
                    pending.push((path, entry.oid.to_owned()));
                } else if entry.mode.is_blob_or_symlink() || entry.mode.is_commit() {
                    files.insert(
                        path,
                        TreeFile {
                            id: entry.oid.to_owned(),
                            mode: entry.mode,
                        },
                    );
                }
            }
        }
        Ok(files)
    }

    fn diff_blob(
        &self,
        file: Option<&TreeFile>,
        budget: &ReadBudget<'_>,
    ) -> Result<Vec<u8>, ReadError> {
        match file {
            Some(file) if file.mode.is_commit() => Ok(Vec::new()),
            Some(file) => Ok(self.read_blob(file.id, file.mode, budget)?.data),
            None => Ok(Vec::new()),
        }
    }

    fn archive_tree(
        &self,
        tree_id: ObjectId,
        modified_at: u64,
        budget: &ReadBudget<'_>,
        writer: &mut BoundedWriter<'_, impl Write>,
        entries: &mut usize,
    ) -> Result<(), ReadError> {
        let mut pending = vec![(tree_id, Vec::new(), 0_usize)];
        while let Some((tree_id, prefix, depth)) = pending.pop() {
            budget.check()?;
            if depth > self.limits.max_archive_depth {
                return Err(ReadError::Limit("archive tree depth"));
            }
            let tree = self.read_tree(tree_id, budget)?;
            let mut child_trees = Vec::new();
            for entry in tree.entries {
                budget.check()?;
                *entries += 1;
                if *entries > self.limits.max_archive_entries {
                    return Err(ReadError::Limit("archive entries"));
                }
                let path = join_git_path(&prefix, &entry.filename, self.limits.max_path_bytes)?;
                if entry.mode.is_tree() {
                    let mut directory = path.clone();
                    directory.push(b'/');
                    write_tar_header(writer, &directory, 0o755, 0, modified_at, b'5')?;
                    child_trees.push((entry.oid.to_owned(), path, depth + 1));
                } else if entry.mode.is_blob_or_symlink() {
                    let blob = self.read_blob(entry.oid.to_owned(), entry.mode, budget)?;
                    // Store symbolic-link content as a regular file. Extraction cannot create a link outside its destination.
                    let mode = if entry.mode.is_executable() {
                        0o755
                    } else {
                        0o644
                    };
                    write_tar_header(
                        writer,
                        &path,
                        mode,
                        u64::try_from(blob.data.len())
                            .map_err(|_| ReadError::Limit("archive bytes"))?,
                        modified_at,
                        b'0',
                    )?;
                    writer.write_all(&blob.data).map_err(ReadError::Output)?;
                    let padding = (512 - blob.data.len() % 512) % 512;
                    if padding != 0 {
                        writer
                            .write_all(&[0_u8; 512][..padding])
                            .map_err(ReadError::Output)?;
                    }
                } else if entry.mode.is_commit() {
                    let mut directory = path;
                    directory.push(b'/');
                    write_tar_header(writer, &directory, 0o755, 0, modified_at, b'5')?;
                }
            }
            for child in child_trees.into_iter().rev() {
                pending.push(child);
            }
        }
        Ok(())
    }

    fn parse_id(&self, input: &[u8], owner: ObjectId) -> Result<ObjectId, ReadError> {
        let id = ObjectId::from_hex(input).map_err(|error| ReadError::DamagedObject {
            id: owner,
            reason: error.to_string(),
        })?;
        if id.kind() != self.repository.object_hash() {
            return Err(ReadError::DamagedObject {
                id: owner,
                reason: "object ID uses the wrong hash format".to_owned(),
            });
        }
        Ok(id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TreeFile {
    id: ObjectId,
    mode: EntryMode,
}

struct ReadBudget<'a> {
    cancellation: &'a ReadCancellation,
    deadline: Instant,
}

impl ReadBudget<'_> {
    fn check(&self) -> Result<(), ReadError> {
        if self.cancellation.cancelled.load(Ordering::Relaxed) {
            return Err(ReadError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(ReadError::Deadline);
        }
        Ok(())
    }
}

struct BoundedWriter<'a, W> {
    output: &'a mut W,
    budget: &'a ReadBudget<'a>,
    written: usize,
    maximum: usize,
    failure: Option<ReadFailure>,
}

impl<W: Write> Write for BoundedWriter<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if let Err(error) = self.budget.check() {
            self.failure = Some(match error {
                ReadError::Cancelled => ReadFailure::Cancelled,
                ReadError::Deadline => ReadFailure::Deadline,
                _ => unreachable!("a budget check has only cancellation and deadline errors"),
            });
            return Err(std::io::Error::other("repository read stopped"));
        }
        let remaining = self.maximum.saturating_sub(self.written);
        if buffer.len() > remaining {
            self.failure = Some(ReadFailure::Limit);
            return Err(std::io::Error::other(
                "repository archive reached its byte limit",
            ));
        }
        let written = self.output.write(buffer)?;
        self.written += written;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.output.flush()
    }
}

#[derive(Clone, Copy)]
enum ReadFailure {
    Cancelled,
    Deadline,
    Limit,
}

impl ReadFailure {
    fn into_error(self) -> ReadError {
        match self {
            Self::Cancelled => ReadError::Cancelled,
            Self::Deadline => ReadError::Deadline,
            Self::Limit => ReadError::Limit("archive bytes"),
        }
    }
}

fn validate_limits(limits: &ReadLimits) -> Result<(), ReadError> {
    if limits.max_refs == 0
        || limits.max_history_commits == 0
        || limits.max_path_bytes == 0
        || limits.max_tree_bytes == 0
        || limits.max_tree_entries == 0
        || limits.max_commit_bytes == 0
        || limits.max_blob_bytes == 0
        || limits.max_diff_bytes == 0
        || limits.max_archive_entries == 0
        || limits.max_archive_bytes < 1024
        || limits.max_search_files == 0
        || limits.max_search_bytes == 0
        || limits.max_search_results == 0
        || limits.max_search_query_bytes == 0
        || limits.max_search_duration.is_zero()
        || limits.max_duration.is_zero()
    {
        return Err(ReadError::InvalidLimits);
    }
    Ok(())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|candidate| candidate == needle)
}

fn validate_path(path: &[u8], permit_empty: bool, maximum: usize) -> Result<(), ReadError> {
    if path.is_empty() {
        return if permit_empty {
            Ok(())
        } else {
            Err(ReadError::InvalidPath)
        };
    }
    if path.len() > maximum {
        return Err(ReadError::Limit("path bytes"));
    }
    if path.starts_with(b"/")
        || path.ends_with(b"/")
        || path.contains(&0)
        || path
            .split(|byte| *byte == b'/')
            .any(|component| component.is_empty() || component == b"." || component == b"..")
    {
        return Err(ReadError::InvalidPath);
    }
    Ok(())
}

fn join_git_path(prefix: &[u8], name: &[u8], maximum: usize) -> Result<Vec<u8>, ReadError> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') || name.contains(&0)
    {
        return Err(ReadError::UnsafeTreeEntry(name.to_vec()));
    }
    let mut path = Vec::with_capacity(prefix.len() + usize::from(!prefix.is_empty()) + name.len());
    path.extend_from_slice(prefix);
    if !prefix.is_empty() {
        path.push(b'/');
    }
    path.extend_from_slice(name);
    if path.len() > maximum {
        return Err(ReadError::Limit("path bytes"));
    }
    Ok(path)
}

fn readme_priority(name: &[u8]) -> Option<usize> {
    const NAMES: [&[u8]; 6] = [
        b"README",
        b"README.md",
        b"README.markdown",
        b"README.txt",
        b"README.rst",
        b"README.adoc",
    ];
    NAMES
        .iter()
        .position(|candidate| name.eq_ignore_ascii_case(candidate))
}

fn checked_add(
    current: usize,
    additional: usize,
    maximum: usize,
    limit: &'static str,
) -> Result<usize, ReadError> {
    let total = current
        .checked_add(additional)
        .ok_or(ReadError::Limit(limit))?;
    if total > maximum {
        return Err(ReadError::Limit(limit));
    }
    Ok(total)
}

fn unified_diff(old: &[u8], new: &[u8]) -> Result<Vec<u8>, ReadError> {
    use gix::diff::blob::unified_diff::{ConsumeBinaryHunk, ContextSize};
    use gix::diff::blob::{Algorithm, Diff, InternedInput, UnifiedDiff};

    let input = InternedInput::new(old, new);
    let diff = Diff::compute(Algorithm::Histogram, &input);
    UnifiedDiff::new(
        &diff,
        &input,
        ConsumeBinaryHunk::new(Vec::new(), "\n"),
        ContextSize::default(),
    )
    .consume()
    .map_err(ReadError::Output)
}

fn write_tar_header(
    writer: &mut impl Write,
    path: &[u8],
    mode: u64,
    size: u64,
    modified_at: u64,
    kind: u8,
) -> Result<(), ReadError> {
    let (name, prefix) = split_tar_path(path)?;
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name);
    header[345..345 + prefix.len()].copy_from_slice(prefix);
    write_tar_octal(&mut header[100..108], mode)?;
    write_tar_octal(&mut header[108..116], 0)?;
    write_tar_octal(&mut header[116..124], 0)?;
    write_tar_octal(&mut header[124..136], size)?;
    write_tar_octal(&mut header[136..148], modified_at)?;
    header[148..156].fill(b' ');
    header[156] = kind;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    let checksum_text = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(checksum_text.as_bytes());
    writer.write_all(&header).map_err(ReadError::Output)
}

fn split_tar_path(path: &[u8]) -> Result<(&[u8], &[u8]), ReadError> {
    if path.len() <= 100 {
        return Ok((path, &[]));
    }
    for split in (1..path.len()).rev() {
        if path[split] == b'/'
            && split + 1 < path.len()
            && path.len() - split - 1 <= 100
            && split <= 155
        {
            return Ok((&path[split + 1..], &path[..split]));
        }
    }
    Err(ReadError::ArchivePath(path.to_vec()))
}

fn write_tar_octal(field: &mut [u8], value: u64) -> Result<(), ReadError> {
    let text = format!("{value:o}");
    if text.len() + 1 > field.len() {
        return Err(ReadError::ArchiveMetadata);
    }
    field.fill(b'0');
    let start = field.len() - text.len() - 1;
    field[start..start + text.len()].copy_from_slice(text.as_bytes());
    field[field.len() - 1] = 0;
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum ReadError {
    #[error("cannot open Git repository {path}: {reason}")]
    Open { path: PathBuf, reason: String },
    #[error("Git repository is not bare: {0}")]
    NotBare(PathBuf),
    #[error("Git read failed: {0}")]
    Git(String),
    #[error("Git object does not exist: {0}")]
    ObjectNotFound(ObjectId),
    #[error("expected a {expected} object, found {actual}")]
    WrongObjectKind {
        expected: &'static str,
        actual: ObjectKind,
    },
    #[error("Git object {id} is damaged: {reason}")]
    DamagedObject { id: ObjectId, reason: String },
    #[error("repository read reached the {0} limit")]
    Limit(&'static str),
    #[error("repository read was cancelled")]
    Cancelled,
    #[error("repository read reached its time limit")]
    Deadline,
    #[error("repository read limits are not valid")]
    InvalidLimits,
    #[error("repository path is not valid")]
    InvalidPath,
    #[error("repository search query is not valid")]
    InvalidSearchQuery,
    #[error("repository path does not exist: {0:?}")]
    PathNotFound(Vec<u8>),
    #[error("repository path is not a tree: {0:?}")]
    NotTree(Vec<u8>),
    #[error("repository path is not a blob: {0:?}")]
    NotBlob(Vec<u8>),
    #[error("Git tree entry is not safe: {0:?}")]
    UnsafeTreeEntry(Vec<u8>),
    #[error("repository archive path is too long: {0:?}")]
    ArchivePath(Vec<u8>),
    #[error("repository archive metadata is too large")]
    ArchiveMetadata,
    #[error("cannot write repository content: {0}")]
    Output(#[from] std::io::Error),
}
