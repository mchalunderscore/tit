use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gix::bstr::ByteSlice;
use gix::hash::{Kind, ObjectId};
use gix::objs::{CommitRef, Kind as ObjectKind, TagRef, TreeRefIter};
use gix::refs::transaction::{Change, LogChange, PreviousValue, RefEdit, RefLog};
use gix::refs::{FullName, Target};
use rand::TryRng;
use thiserror::Error;

use super::packetline::{Packet, PacketLineError, decode, encode_data, encode_flush};
use super::upload_pack::hash_name;
use crate::store::{GitIntentRecord, GitOperationIntent, Store};

const MAX_COMMANDS: usize = 256;
const MAX_OBJECTS: usize = 100_000;
const MAX_OBJECT_BYTES: usize = 64 * 1024 * 1024;
const MAX_PACK_BYTES: u64 = 256 * 1024 * 1024;
const MAX_WALK_OBJECTS: usize = 500_000;
const MAX_DELTA_DEPTH: usize = 64;
const MAX_PROCESSING_TIME: Duration = Duration::from_secs(30);

pub(crate) struct ReceivePack {
    repository_path: PathBuf,
    database_path: PathBuf,
    actor: String,
    object_format: Kind,
    intent_id: String,
    quarantine: PathBuf,
    incoming_pack: PathBuf,
    cleanup_on_drop: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RefCommand {
    old: ObjectId,
    new: ObjectId,
    name: FullName,
}

impl ReceivePack {
    pub(crate) fn open(
        repository_path: &Path,
        database_path: &Path,
        actor: String,
    ) -> Result<Self, ReceivePackError> {
        let repository = open_bare(repository_path)?;
        let object_format = repository.object_hash();
        let intent_id = random_id()?;
        let quarantine = repository_path
            .join("objects")
            .join("tit-quarantine")
            .join(&intent_id);
        fs::create_dir_all(quarantine.join("pack"))?;
        let incoming_pack = quarantine.join("incoming.pack");
        Ok(Self {
            repository_path: repository_path.to_owned(),
            database_path: database_path.to_owned(),
            actor,
            object_format,
            intent_id,
            quarantine,
            incoming_pack,
            cleanup_on_drop: true,
        })
    }

    pub(crate) fn incoming_pack(&self) -> &Path {
        &self.incoming_pack
    }

    pub(crate) fn advertisement(&self) -> Result<Vec<u8>, ReceivePackError> {
        let repository = open_bare(&self.repository_path)?;
        let mut references = repository
            .references()
            .map_err(|error| ReceivePackError::Repository(error.to_string()))?
            .all()
            .map_err(|error| ReceivePackError::Repository(error.to_string()))?
            .filter_map(|reference| reference.ok())
            .filter_map(|reference| {
                let id = reference.try_id()?.detach();
                Some((reference.name().as_bstr().to_vec(), id))
            })
            .collect::<Vec<_>>();
        references.sort_by(|left, right| left.0.cmp(&right.0));
        let capabilities = format!(
            "report-status report-status-v2 delete-refs atomic ofs-delta object-format={} agent=tit/{}",
            hash_name(self.object_format),
            env!("CARGO_PKG_VERSION")
        );
        let mut output = Vec::new();
        if references.is_empty() {
            encode_data(
                format!(
                    "{} capabilities^{{}}\0{capabilities}\n",
                    self.object_format.null()
                )
                .as_bytes(),
                &mut output,
            )?;
        } else {
            for (index, (name, id)) in references.iter().enumerate() {
                let suffix = if index == 0 {
                    format!("\0{capabilities}")
                } else {
                    String::new()
                };
                encode_data(
                    format!("{id} {}{suffix}\n", String::from_utf8_lossy(name)).as_bytes(),
                    &mut output,
                )?;
            }
        }
        encode_flush(&mut output);
        Ok(output)
    }

    pub(crate) fn expects_pack(&self, command_bytes: &[u8]) -> Result<bool, ReceivePackError> {
        Ok(parse_commands(command_bytes, self.object_format)?
            .iter()
            .any(|command| !command.new.is_null()))
    }

    pub(crate) fn finish(&mut self, command_bytes: &[u8]) -> Result<Vec<u8>, ReceivePackError> {
        let commands = parse_commands(command_bytes, self.object_format)?;
        let repository = open_bare(&self.repository_path)?;
        validate_initial_refs(&repository, &commands)?;

        let initial = serialize_refs(&commands, false);
        let proposed = serialize_refs(&commands, true);
        let repository_text = path_text(&self.repository_path)?;
        let quarantine_text = path_text(&self.quarantine)?;
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ReceivePackError::Clock)?
            .as_secs()
            .try_into()
            .map_err(|_| ReceivePackError::Clock)?;
        let mut store = Store::open(&self.database_path)?;
        store.begin_git_intent(&GitOperationIntent {
            id: &self.intent_id,
            repository_path: repository_text,
            actor: &self.actor,
            initial_refs: &initial,
            proposed_refs: &proposed,
            event_payload: &proposed,
            quarantine_path: quarantine_text,
            created_at,
        })?;
        self.cleanup_on_drop = false;
        crash_point("intent");

        let result = (|| {
            let has_pack =
                self.incoming_pack.exists() && fs::metadata(&self.incoming_pack)?.len() != 0;
            let needs_objects = commands.iter().any(|command| !command.new.is_null());
            let pack_name = if has_pack {
                self.index_and_validate_pack(&repository, &commands)?
            } else {
                if needs_objects {
                    validate_proposed_objects(&repository, None, &commands)?;
                }
                None
            };

            let pack_name = match pack_name.as_ref() {
                Some(path) => Some(
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .ok_or(ReceivePackError::Path)?,
                ),
                None => None,
            };
            store.mark_git_objects_promoted(&self.intent_id, pack_name)?;
            crash_point("objects");
            apply_ref_transaction(&repository, &commands)?;
            crash_point("refs");
            store.complete_git_intent(&self.intent_id)?;
            let _ = fs::remove_dir_all(&self.quarantine);
            crash_point("completed");
            Ok(status_response(&commands, None)?)
        })();
        if result.is_err() {
            drop(store);
            recover_incomplete_pushes(&self.database_path)?;
            self.cleanup_on_drop = true;
        }
        result
    }

    pub(crate) fn rejection_response(
        &self,
        command_bytes: &[u8],
        error: &ReceivePackError,
    ) -> Vec<u8> {
        let Ok(commands) = parse_commands(command_bytes, self.object_format) else {
            return Vec::new();
        };
        let mut output = Vec::new();
        let unpack = if error.is_unpack_error() {
            format!("unpack {}\n", error.client_reason())
        } else {
            "unpack ok\n".to_owned()
        };
        if encode_data(unpack.as_bytes(), &mut output).is_err() {
            return Vec::new();
        }
        for command in commands {
            let name = String::from_utf8_lossy(command.name.as_bstr());
            let line = format!("ng {name} {}\n", error.client_reason());
            if encode_data(line.as_bytes(), &mut output).is_err() {
                return Vec::new();
            }
        }
        encode_flush(&mut output);
        output
    }

    fn index_and_validate_pack(
        &self,
        repository: &gix::Repository,
        commands: &[RefCommand],
    ) -> Result<Option<PathBuf>, ReceivePackError> {
        let metadata = fs::metadata(&self.incoming_pack)?;
        if metadata.len() == 0 || metadata.len() > MAX_PACK_BYTES {
            return Err(ReceivePackError::PackLimit);
        }
        let mut reader = BufReader::new(File::open(&self.incoming_pack)?);
        let mut progress = gix::progress::Discard;
        let interrupt = Arc::new(AtomicBool::new(false));
        let timer_interrupt = Arc::clone(&interrupt);
        let (done_sender, done_receiver) = std::sync::mpsc::channel();
        let timer = std::thread::spawn(move || {
            if done_receiver.recv_timeout(MAX_PROCESSING_TIME).is_err() {
                timer_interrupt.store(true, Ordering::Relaxed);
            }
        });
        let outcome = gix_pack::Bundle::write_to_directory(
            &mut reader,
            Some(self.quarantine.join("pack").as_path()),
            &mut progress,
            &interrupt,
            Some(Box::new(repository.objects.clone())),
            gix_pack::bundle::write::Options {
                thread_limit: Some(2),
                iteration_mode: gix_pack::data::input::Mode::Verify,
                index_version: gix_pack::index::Version::V2,
                object_hash: self.object_format,
            },
        );
        let _ = done_sender.send(());
        let _ = timer.join();
        let outcome = outcome.map_err(|error| {
            if interrupt.load(Ordering::Relaxed) {
                ReceivePackError::WallClockLimit
            } else {
                ReceivePackError::Pack(error.to_string())
            }
        })?;
        if outcome.index.num_objects > MAX_OBJECTS as u32 {
            return Err(ReceivePackError::ObjectLimit);
        }
        if outcome.index.num_objects == 0 {
            validate_proposed_objects(repository, None, commands)?;
            if let Some(path) = outcome.data_path {
                let _ = fs::remove_file(path);
            }
            if let Some(path) = outcome.index_path {
                let _ = fs::remove_file(path);
            }
            if let Some(path) = outcome.keep_path {
                let _ = fs::remove_file(path);
            }
            return Ok(None);
        }
        let bundle = outcome
            .to_bundle()
            .ok_or(ReceivePackError::MissingPack)?
            .map_err(|error| ReceivePackError::Pack(error.to_string()))?;
        validate_delta_depth(&bundle)?;
        validate_proposed_objects(repository, Some(&bundle), commands)?;

        let source_pack = outcome.data_path.ok_or(ReceivePackError::MissingPack)?;
        let source_index = outcome.index_path.ok_or(ReceivePackError::MissingPack)?;
        if fs::metadata(&source_pack)?.len() > MAX_PACK_BYTES {
            return Err(ReceivePackError::PackLimit);
        }
        let destination = self.repository_path.join("objects/pack");
        fs::create_dir_all(&destination)?;
        let destination_pack =
            destination.join(source_pack.file_name().ok_or(ReceivePackError::Path)?);
        let destination_index =
            destination.join(source_index.file_name().ok_or(ReceivePackError::Path)?);
        let pack_exists = destination_pack.exists();
        let index_exists = destination_index.exists();
        if pack_exists != index_exists {
            return Err(ReceivePackError::Repository(
                "a pack file and its index do not match".to_owned(),
            ));
        }
        let promoted = if pack_exists {
            fs::remove_file(&source_pack)?;
            fs::remove_file(&source_index)?;
            false
        } else {
            fs::rename(&source_index, &destination_index)?;
            if let Err(error) = fs::rename(&source_pack, &destination_pack) {
                let _ = fs::remove_file(&destination_index);
                return Err(error.into());
            }
            true
        };
        if let Some(keep) = outcome.keep_path {
            let _ = fs::remove_file(keep);
        }
        sync_directory(&destination)?;
        Ok(promoted.then_some(destination_pack))
    }
}

fn validate_delta_depth(bundle: &gix_pack::Bundle) -> Result<(), ReceivePackError> {
    let entries = bundle.index.iter().collect::<Vec<_>>();
    let offsets_by_id = entries
        .iter()
        .map(|entry| (entry.oid, entry.pack_offset))
        .collect::<HashMap<_, _>>();
    let headers = entries
        .iter()
        .map(|entry| {
            bundle
                .pack
                .entry(entry.pack_offset)
                .map(|pack_entry| (entry.pack_offset, pack_entry.header))
                .map_err(|error| ReceivePackError::Pack(error.to_string()))
        })
        .collect::<Result<HashMap<_, _>, _>>()?;
    let mut depths = HashMap::new();
    let mut visiting = HashSet::new();
    for offset in headers.keys().copied() {
        let depth = delta_depth(offset, &headers, &offsets_by_id, &mut depths, &mut visiting)?;
        if depth > MAX_DELTA_DEPTH {
            return Err(ReceivePackError::DeltaDepthLimit);
        }
    }
    Ok(())
}

fn delta_depth(
    offset: u64,
    headers: &HashMap<u64, gix_pack::data::entry::Header>,
    offsets_by_id: &HashMap<ObjectId, u64>,
    depths: &mut HashMap<u64, usize>,
    visiting: &mut HashSet<u64>,
) -> Result<usize, ReceivePackError> {
    if let Some(depth) = depths.get(&offset) {
        return Ok(*depth);
    }
    if !visiting.insert(offset) {
        return Err(ReceivePackError::DeltaDepthLimit);
    }
    let header = headers.get(&offset).ok_or(ReceivePackError::RecoveryData)?;
    let depth = match header {
        gix_pack::data::entry::Header::OfsDelta { base_distance } => {
            let base = offset
                .checked_sub(*base_distance)
                .ok_or(ReceivePackError::DeltaDepthLimit)?;
            delta_depth(base, headers, offsets_by_id, depths, visiting)? + 1
        }
        gix_pack::data::entry::Header::RefDelta { base_id } => {
            if let Some(base) = offsets_by_id.get(base_id) {
                delta_depth(*base, headers, offsets_by_id, depths, visiting)? + 1
            } else {
                1
            }
        }
        _ => 0,
    };
    visiting.remove(&offset);
    depths.insert(offset, depth);
    Ok(depth)
}

impl Drop for ReceivePack {
    fn drop(&mut self) {
        if self.cleanup_on_drop {
            let _ = fs::remove_dir_all(&self.quarantine);
        }
    }
}

pub(crate) fn recover_incomplete_pushes(database_path: &Path) -> Result<(), ReceivePackError> {
    let mut store = Store::open(database_path)?;
    for intent in store.incomplete_git_intents()? {
        recover_intent(&mut store, &intent)?;
    }
    Ok(())
}

fn recover_intent(store: &mut Store, intent: &GitIntentRecord) -> Result<(), ReceivePackError> {
    let repository_path = Path::new(&intent.repository_path);
    let repository = open_bare(repository_path)?;
    let initial = parse_ref_snapshot(&intent.initial_refs, repository.object_hash())?;
    let proposed = parse_ref_snapshot(&intent.proposed_refs, repository.object_hash())?;
    let at_initial = refs_match(&repository, &initial)?;
    let at_proposed = refs_match(&repository, &proposed)?;

    match (intent.state.as_str(), at_initial, at_proposed) {
        ("pending", true, false) | ("pending", true, true) => {
            store.abandon_git_intent(&intent.id)?;
        }
        ("promoted", false, true) => {
            store.complete_git_intent(&intent.id)?;
        }
        ("promoted", true, false) | ("promoted", true, true) => {
            remove_promoted_pack(repository_path, intent.pack_name.as_deref())?;
            store.abandon_git_intent(&intent.id)?;
        }
        _ => return Err(ReceivePackError::MixedRecovery(intent.id.clone())),
    }
    let quarantine = Path::new(&intent.quarantine_path);
    let expected_parent = repository_path.join("objects/tit-quarantine");
    if quarantine.parent() != Some(expected_parent.as_path())
        || quarantine.file_name().and_then(|name| name.to_str()) != Some(intent.id.as_str())
    {
        return Err(ReceivePackError::RecoveryData);
    }
    let _ = fs::remove_dir_all(quarantine);
    Ok(())
}

fn parse_ref_snapshot(
    bytes: &[u8],
    object_format: Kind,
) -> Result<Vec<(FullName, ObjectId)>, ReceivePackError> {
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            let mut fields = line.splitn(2, |byte| *byte == b' ');
            let id = parse_id(fields.next(), object_format)?;
            let name = fields.next().ok_or(ReceivePackError::RecoveryData)?;
            let name =
                FullName::try_from(name.as_bstr()).map_err(|_| ReceivePackError::RecoveryData)?;
            Ok((name, id))
        })
        .collect()
}

fn refs_match(
    repository: &gix::Repository,
    expected: &[(FullName, ObjectId)],
) -> Result<bool, ReceivePackError> {
    for (name, expected_id) in expected {
        let current = repository
            .try_find_reference(name)
            .map_err(|error| ReceivePackError::Repository(error.to_string()))?
            .and_then(|reference| reference.try_id().map(gix::Id::detach));
        if (expected_id.is_null() && current.is_some())
            || (!expected_id.is_null() && current != Some(*expected_id))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn remove_promoted_pack(
    repository_path: &Path,
    pack_name: Option<&str>,
) -> Result<(), ReceivePackError> {
    let Some(pack_name) = pack_name else {
        return Ok(());
    };
    if Path::new(pack_name)
        .file_name()
        .and_then(|name| name.to_str())
        != Some(pack_name)
        || !pack_name.starts_with("pack-")
        || !pack_name.ends_with(".pack")
    {
        return Err(ReceivePackError::RecoveryData);
    }
    let pack = repository_path.join("objects/pack").join(pack_name);
    let index = pack.with_extension("idx");
    if pack.exists() {
        fs::remove_file(pack)?;
    }
    if index.exists() {
        fs::remove_file(index)?;
    }
    sync_directory(&repository_path.join("objects/pack"))?;
    Ok(())
}

fn parse_commands(input: &[u8], object_format: Kind) -> Result<Vec<RefCommand>, ReceivePackError> {
    let packets = decode(input)?;
    if packets.last() != Some(&Packet::Flush) {
        return Err(ReceivePackError::Commands);
    }
    let mut commands = Vec::new();
    let mut names = HashSet::new();
    for (index, packet) in packets[..packets.len() - 1].iter().enumerate() {
        let Packet::Data(line) = packet else {
            return Err(ReceivePackError::Commands);
        };
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        let command = if index == 0 {
            line.split(|byte| *byte == 0).next().unwrap_or_default()
        } else if line.contains(&0) {
            return Err(ReceivePackError::Commands);
        } else {
            line
        };
        let mut fields = command.split(|byte| *byte == b' ');
        let old = parse_id(fields.next(), object_format)?;
        let new = parse_id(fields.next(), object_format)?;
        let name = fields.next().ok_or(ReceivePackError::Commands)?;
        if fields.next().is_some() || old == new {
            return Err(ReceivePackError::Commands);
        }
        let name = FullName::try_from(name.as_bstr()).map_err(|_| ReceivePackError::RefName)?;
        if !(name.as_bstr().starts_with(b"refs/heads/")
            || name.as_bstr().starts_with(b"refs/tags/"))
            || !names.insert(name.clone())
        {
            return Err(ReceivePackError::RefName);
        }
        commands.push(RefCommand { old, new, name });
    }
    if commands.is_empty() || commands.len() > MAX_COMMANDS {
        return Err(ReceivePackError::CommandLimit);
    }
    Ok(commands)
}

fn parse_id(input: Option<&[u8]>, object_format: Kind) -> Result<ObjectId, ReceivePackError> {
    let id = ObjectId::from_hex(input.ok_or(ReceivePackError::Commands)?)
        .map_err(|_| ReceivePackError::Commands)?;
    if id.kind() != object_format {
        return Err(ReceivePackError::ObjectFormat);
    }
    Ok(id)
}

fn validate_initial_refs(
    repository: &gix::Repository,
    commands: &[RefCommand],
) -> Result<(), ReceivePackError> {
    for command in commands {
        let current = repository
            .try_find_reference(&command.name)
            .map_err(|error| ReceivePackError::Repository(error.to_string()))?
            .and_then(|reference| reference.try_id().map(gix::Id::detach));
        match (command.old.is_null(), current) {
            (true, None) => {}
            (false, Some(current)) if current == command.old => {}
            _ => return Err(ReceivePackError::StaleRef),
        }
    }
    Ok(())
}

fn validate_proposed_objects(
    repository: &gix::Repository,
    bundle: Option<&gix_pack::Bundle>,
    commands: &[RefCommand],
) -> Result<(), ReceivePackError> {
    let mut finder = CombinedObjects::new(repository, bundle);
    for command in commands {
        if command.new.is_null() {
            continue;
        }
        let kind = finder.kind_and_links(command.new)?.0;
        if command.name.as_bstr().starts_with(b"refs/heads/") && kind != ObjectKind::Commit {
            return Err(ReceivePackError::BranchNotCommit);
        }
        finder.validate_reachable(command.new)?;
        if !command.old.is_null()
            && command.name.as_bstr().starts_with(b"refs/heads/")
            && !finder.is_ancestor(command.old, command.new)?
        {
            return Err(ReceivePackError::NonFastForward);
        }
    }
    Ok(())
}

struct CombinedObjects<'a> {
    repository: &'a gix::Repository,
    bundle: Option<&'a gix_pack::Bundle>,
}

impl<'a> CombinedObjects<'a> {
    fn new(repository: &'a gix::Repository, bundle: Option<&'a gix_pack::Bundle>) -> Self {
        Self { repository, bundle }
    }

    fn object(&self, id: ObjectId) -> Result<(ObjectKind, Vec<u8>), ReceivePackError> {
        let mut buffer = Vec::new();
        let mut inflate = gix::features::zlib::Inflate::default();
        let mut cache = gix_pack::cache::Never;
        if let Some(bundle) = self.bundle
            && let Some((data, _)) = bundle
                .find(&id, &mut buffer, &mut inflate, &mut cache)
                .map_err(|error| ReceivePackError::Object(error.to_string()))?
        {
            if data.data.len() > MAX_OBJECT_BYTES {
                return Err(ReceivePackError::ObjectLimit);
            }
            return Ok((data.kind, data.data.to_vec()));
        }
        let object = self
            .repository
            .try_find_object(id)
            .map_err(|error| ReceivePackError::Object(error.to_string()))?
            .ok_or(ReceivePackError::MissingObject(id))?;
        if object.data.len() > MAX_OBJECT_BYTES {
            return Err(ReceivePackError::ObjectLimit);
        }
        Ok((object.kind, object.data.clone()))
    }

    fn kind_and_links(
        &self,
        id: ObjectId,
    ) -> Result<(ObjectKind, Vec<ObjectId>), ReceivePackError> {
        let (kind, data) = self.object(id)?;
        let links = match kind {
            ObjectKind::Blob => Vec::new(),
            ObjectKind::Commit => {
                let commit = CommitRef::from_bytes(&data, id.kind())
                    .map_err(|_| ReceivePackError::MalformedObject(kind))?;
                std::iter::once(commit.tree())
                    .chain(commit.parents())
                    .collect()
            }
            ObjectKind::Tree => TreeRefIter::from_bytes(&data, id.kind())
                .map(|entry| {
                    let entry = entry.map_err(|_| ReceivePackError::MalformedObject(kind))?;
                    Ok((entry.mode.kind() != gix::objs::tree::EntryKind::Commit)
                        .then(|| entry.oid.to_owned()))
                })
                .collect::<Result<Vec<_>, ReceivePackError>>()?
                .into_iter()
                .flatten()
                .collect(),
            ObjectKind::Tag => vec![
                TagRef::from_bytes(&data, id.kind())
                    .map_err(|_| ReceivePackError::MalformedObject(kind))?
                    .target(),
            ],
        };
        Ok((kind, links))
    }

    fn validate_reachable(&mut self, root: ObjectId) -> Result<(), ReceivePackError> {
        let mut pending = vec![root];
        let mut seen = HashSet::new();
        while let Some(id) = pending.pop() {
            if !seen.insert(id) {
                continue;
            }
            if seen.len() > MAX_WALK_OBJECTS {
                return Err(ReceivePackError::ObjectLimit);
            }
            pending.extend(self.kind_and_links(id)?.1);
        }
        Ok(())
    }

    fn is_ancestor(
        &self,
        ancestor: ObjectId,
        descendant: ObjectId,
    ) -> Result<bool, ReceivePackError> {
        let mut pending = vec![descendant];
        let mut seen = HashSet::new();
        while let Some(id) = pending.pop() {
            if id == ancestor {
                return Ok(true);
            }
            if !seen.insert(id) {
                continue;
            }
            if seen.len() > MAX_WALK_OBJECTS {
                return Err(ReceivePackError::ObjectLimit);
            }
            let (kind, links) = self.kind_and_links(id)?;
            if kind != ObjectKind::Commit {
                return Err(ReceivePackError::BranchNotCommit);
            }
            pending.extend(links.into_iter().skip(1));
        }
        Ok(false)
    }
}

fn apply_ref_transaction(
    repository: &gix::Repository,
    commands: &[RefCommand],
) -> Result<(), ReceivePackError> {
    let edits = commands.iter().map(|command| RefEdit {
        name: command.name.clone(),
        deref: false,
        change: if command.new.is_null() {
            Change::Delete {
                expected: PreviousValue::MustExistAndMatch(Target::Object(command.old)),
                log: RefLog::AndReference,
            }
        } else {
            Change::Update {
                expected: if command.old.is_null() {
                    PreviousValue::MustNotExist
                } else {
                    PreviousValue::MustExistAndMatch(Target::Object(command.old))
                },
                new: Target::Object(command.new),
                log: LogChange {
                    mode: RefLog::AndReference,
                    force_create_reflog: false,
                    message: "push".into(),
                },
            }
        },
    });
    repository
        .edit_references_as(edits, None)
        .map_err(|error| ReceivePackError::RefTransaction(error.to_string()))?;
    Ok(())
}

fn status_response(
    commands: &[RefCommand],
    error: Option<&str>,
) -> Result<Vec<u8>, PacketLineError> {
    let mut output = Vec::new();
    encode_data(b"unpack ok\n", &mut output)?;
    for command in commands {
        let name = String::from_utf8_lossy(command.name.as_bstr());
        let line = match error {
            Some(error) => format!("ng {name} {error}\n"),
            None => format!("ok {name}\n"),
        };
        encode_data(line.as_bytes(), &mut output)?;
    }
    encode_flush(&mut output);
    Ok(output)
}

fn serialize_refs(commands: &[RefCommand], proposed: bool) -> Vec<u8> {
    let mut output = Vec::new();
    for command in commands {
        let id = if proposed { command.new } else { command.old };
        writeln!(
            output,
            "{id} {}",
            String::from_utf8_lossy(command.name.as_bstr())
        )
        .expect("a vector write cannot fail");
    }
    output
}

fn open_bare(path: &Path) -> Result<gix::Repository, ReceivePackError> {
    let repository =
        gix::open(path).map_err(|error| ReceivePackError::Repository(error.to_string()))?;
    if !repository.is_bare() {
        return Err(ReceivePackError::NotBare);
    }
    Ok(repository)
}

fn random_id() -> Result<String, ReceivePackError> {
    let mut bytes = [0_u8; 16];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| ReceivePackError::Random)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn path_text(path: &Path) -> Result<&str, ReceivePackError> {
    path.to_str().ok_or(ReceivePackError::Path)
}

fn sync_directory(path: &Path) -> Result<(), ReceivePackError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
fn crash_point(point: &str) {
    if std::env::var("TIT_M1D_CRASH_AFTER").as_deref() != Ok(point) {
        return;
    }
    let ready = std::env::var_os("TIT_M1D_READY").expect("read the M1D ready path");
    fs::write(ready, point.as_bytes()).expect("write the M1D ready file");
    loop {
        std::thread::park();
    }
}

#[cfg(not(test))]
fn crash_point(_point: &str) {}

#[derive(Debug, Error)]
pub(crate) enum ReceivePackError {
    #[error(transparent)]
    PacketLine(#[from] PacketLineError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    #[error("cannot read Git repository: {0}")]
    Repository(String),
    #[error("Git repository is not bare")]
    NotBare,
    #[error("receive-pack commands are not valid")]
    Commands,
    #[error("receive-pack command count exceeds the limit")]
    CommandLimit,
    #[error("receive-pack object ID uses the wrong hash format")]
    ObjectFormat,
    #[error("receive-pack reference name is not allowed")]
    RefName,
    #[error("receive-pack initial reference does not match")]
    StaleRef,
    #[error("receive-pack input is missing a pack")]
    MissingPack,
    #[error("receive-pack input has an unexpected pack")]
    UnexpectedPack,
    #[error("receive-pack exceeds the pack limit")]
    PackLimit,
    #[error("receive-pack exceeds the object limit")]
    ObjectLimit,
    #[error("receive-pack exceeds the delta depth limit")]
    DeltaDepthLimit,
    #[error("receive-pack exceeds the processing time limit")]
    WallClockLimit,
    #[error("cannot index receive-pack input: {0}")]
    Pack(String),
    #[error("cannot read received object: {0}")]
    Object(String),
    #[error("received object {0} does not exist")]
    MissingObject(ObjectId),
    #[error("received {0:?} object is malformed")]
    MalformedObject(ObjectKind),
    #[error("a branch target is not a commit")]
    BranchNotCommit,
    #[error("a branch update is not a fast-forward")]
    NonFastForward,
    #[error("cannot update Git references: {0}")]
    RefTransaction(String),
    #[error("incomplete Git operation {0} has mixed reference state")]
    MixedRecovery(String),
    #[error("an incomplete Git operation has invalid recovery data")]
    RecoveryData,
    #[error("cannot create a random operation ID")]
    Random,
    #[error("system clock is before the Unix epoch")]
    Clock,
    #[error("filesystem path is not valid UTF-8")]
    Path,
}

impl ReceivePackError {
    fn is_unpack_error(&self) -> bool {
        matches!(
            self,
            Self::MissingPack
                | Self::UnexpectedPack
                | Self::PackLimit
                | Self::ObjectLimit
                | Self::Pack(_)
                | Self::Object(_)
                | Self::MissingObject(_)
                | Self::MalformedObject(_)
        )
    }

    fn client_reason(&self) -> &'static str {
        match self {
            Self::StaleRef => "stale reference",
            Self::NonFastForward => "non-fast-forward",
            Self::BranchNotCommit => "branch target is not a commit",
            Self::RefName => "reference name is not allowed",
            Self::ObjectFormat => "object format does not match",
            Self::CommandLimit => "too many reference commands",
            Self::PackLimit => "pack exceeds the byte limit",
            Self::ObjectLimit => "object limit exceeded",
            Self::DeltaDepthLimit => "delta depth limit exceeded",
            Self::WallClockLimit => "processing time limit exceeded",
            Self::MissingObject(_) => "object connectivity check failed",
            Self::MixedRecovery(_) => "repository recovery is required",
            _ if self.is_unpack_error() => "pack validation failed",
            _ => "push validation failed",
        }
    }
}
