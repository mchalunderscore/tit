use std::collections::HashSet;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::AtomicBool;

use gix::hash::{Kind, ObjectId};
use thiserror::Error;

use super::packetline::{
    Packet, PacketLineError, decode, encode_data, encode_flush, encode_sideband,
};
use super::repository::{GitReference, GitRepository, GitRepositoryError};

const AGENT: &str = concat!("tit/", env!("CARGO_PKG_VERSION"));
const MAX_NEGOTIATION_IDS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProtocolVersion {
    V0,
    V1,
    V2,
}

pub(crate) struct UploadPack {
    repository: GitRepository,
}

impl UploadPack {
    pub(crate) fn open(path: &Path) -> Result<Self, UploadPackError> {
        Ok(Self {
            repository: GitRepository::open(path)?,
        })
    }

    pub(crate) fn advertisement(
        &self,
        version: ProtocolVersion,
        http: bool,
    ) -> Result<Vec<u8>, UploadPackError> {
        let mut output = Vec::new();
        if http && version != ProtocolVersion::V2 {
            encode_data(b"# service=git-upload-pack\n", &mut output)?;
            encode_flush(&mut output);
        }
        match version {
            ProtocolVersion::V0 => self.advertise_v0_or_v1(&mut output, false)?,
            ProtocolVersion::V1 => self.advertise_v0_or_v1(&mut output, true)?,
            ProtocolVersion::V2 => self.advertise_v2(&mut output)?,
        }
        Ok(output)
    }

    pub(crate) fn respond(
        &self,
        version: ProtocolVersion,
        request: &[u8],
    ) -> Result<Vec<u8>, UploadPackError> {
        self.respond_with_cancellation(version, request, &AtomicBool::new(false))
    }

    pub(crate) fn respond_with_cancellation(
        &self,
        version: ProtocolVersion,
        request: &[u8],
        cancelled: &AtomicBool,
    ) -> Result<Vec<u8>, UploadPackError> {
        let packets = decode(request)?;
        match version {
            ProtocolVersion::V0 | ProtocolVersion::V1 => self.respond_v1(&packets, cancelled),
            ProtocolVersion::V2 => self.respond_v2(&packets, cancelled),
        }
    }

    fn advertise_v0_or_v1(
        &self,
        output: &mut Vec<u8>,
        version_packet: bool,
    ) -> Result<(), UploadPackError> {
        if version_packet {
            encode_data(b"version 1\n", output)?;
        }
        let references = self.repository.references()?;
        let capabilities = format!(
            "agent={AGENT} object-format={}",
            hash_name(self.repository.object_format())
        );
        if references.is_empty() {
            let zero = "0".repeat(self.repository.object_format().len_in_hex());
            encode_data(
                format!("{zero} capabilities^{{}}\0{capabilities}\n").as_bytes(),
                output,
            )?;
        } else {
            for (index, reference) in references.iter().enumerate() {
                let suffix = if index == 0 {
                    format!("\0{capabilities}")
                } else {
                    String::new()
                };
                encode_data(
                    format!(
                        "{} {}{suffix}\n",
                        reference.target,
                        String::from_utf8_lossy(&reference.name)
                    )
                    .as_bytes(),
                    output,
                )?;
                if let Some(peeled) = reference.peeled {
                    encode_data(
                        format!(
                            "{peeled} {}^{{}}\n",
                            String::from_utf8_lossy(&reference.name)
                        )
                        .as_bytes(),
                        output,
                    )?;
                }
            }
        }
        encode_flush(output);
        Ok(())
    }

    fn advertise_v2(&self, output: &mut Vec<u8>) -> Result<(), UploadPackError> {
        for capability in [
            "version 2\n".to_owned(),
            format!("agent={AGENT}\n"),
            format!(
                "object-format={}\n",
                hash_name(self.repository.object_format())
            ),
            "ls-refs=symrefs peel\n".to_owned(),
            "fetch=wait-for-done\n".to_owned(),
        ] {
            encode_data(capability.as_bytes(), output)?;
        }
        encode_flush(output);
        Ok(())
    }

    fn respond_v1(
        &self,
        packets: &[Packet],
        cancelled: &AtomicBool,
    ) -> Result<Vec<u8>, UploadPackError> {
        let mut wants = Vec::new();
        let mut haves = Vec::new();
        let mut unique_wants = HashSet::new();
        let mut unique_haves = HashSet::new();
        let mut done = false;
        for packet in packets {
            let Packet::Data(line) = packet else {
                continue;
            };
            let line = trim_line(line);
            if let Some(value) = line.strip_prefix(b"want ") {
                let id = value.split(|byte| *byte == b' ').next().unwrap_or_default();
                let id = self.parse_id(id)?;
                if unique_wants.insert(id) {
                    wants.push(id);
                }
            } else if let Some(value) = line.strip_prefix(b"have ") {
                let id = self.parse_id(value)?;
                if unique_haves.insert(id) {
                    haves.push(id);
                }
            } else if line == b"done" {
                done = true;
            } else {
                return Err(UploadPackError::UnsupportedRequest);
            }
            if wants.len() > MAX_NEGOTIATION_IDS || haves.len() > MAX_NEGOTIATION_IDS {
                return Err(UploadPackError::NegotiationLimit);
            }
        }
        if !done || wants.is_empty() {
            return Err(UploadPackError::IncompleteNegotiation);
        }

        let mut output = Vec::new();
        encode_data(b"NAK\n", &mut output)?;
        self.repository
            .write_pack(&wants, &haves, &mut output, cancelled)?;
        Ok(output)
    }

    fn respond_v2(
        &self,
        packets: &[Packet],
        cancelled: &AtomicBool,
    ) -> Result<Vec<u8>, UploadPackError> {
        let delimiter = packets
            .iter()
            .position(|packet| *packet == Packet::Delimiter)
            .ok_or(UploadPackError::UnsupportedRequest)?;
        let command = command_name(&packets[..delimiter], self.repository.object_format())?;
        let arguments = &packets[delimiter + 1..];
        match command {
            b"ls-refs" => self.respond_ls_refs(arguments),
            b"fetch" => self.respond_fetch(arguments, cancelled),
            _ => Err(UploadPackError::UnsupportedRequest),
        }
    }

    fn respond_ls_refs(&self, packets: &[Packet]) -> Result<Vec<u8>, UploadPackError> {
        let mut symrefs = false;
        let mut peel = false;
        let mut prefixes = Vec::new();
        for packet in packets {
            match packet {
                Packet::Data(line) => {
                    let line = trim_line(line);
                    if line == b"symrefs" {
                        symrefs = true;
                    } else if line == b"peel" {
                        peel = true;
                    } else if let Some(prefix) = line.strip_prefix(b"ref-prefix ") {
                        prefixes.push(prefix.to_vec());
                    } else {
                        return Err(UploadPackError::UnsupportedRequest);
                    }
                }
                Packet::Flush => {}
                Packet::Delimiter | Packet::ResponseEnd => {
                    return Err(UploadPackError::UnsupportedRequest);
                }
            }
        }

        let mut output = Vec::new();
        for reference in self.repository.references()? {
            if !prefixes.is_empty()
                && !prefixes
                    .iter()
                    .any(|prefix| reference.name.starts_with(prefix))
            {
                continue;
            }
            encode_data(&format_ref(&reference, symrefs, peel), &mut output)?;
        }
        encode_flush(&mut output);
        Ok(output)
    }

    fn respond_fetch(
        &self,
        packets: &[Packet],
        cancelled: &AtomicBool,
    ) -> Result<Vec<u8>, UploadPackError> {
        let mut wants = Vec::new();
        let mut haves = Vec::new();
        let mut unique_wants = HashSet::new();
        let mut unique_haves = HashSet::new();
        let mut done = false;
        for packet in packets {
            match packet {
                Packet::Data(line) => {
                    let line = trim_line(line);
                    if let Some(value) = line.strip_prefix(b"want ") {
                        let id = self.parse_id(value)?;
                        if unique_wants.insert(id) {
                            wants.push(id);
                        }
                    } else if let Some(value) = line.strip_prefix(b"have ") {
                        let id = self.parse_id(value)?;
                        if unique_haves.insert(id) {
                            haves.push(id);
                        }
                    } else if line == b"done" {
                        done = true;
                    } else if !matches!(
                        line,
                        b"thin-pack" | b"no-progress" | b"include-tag" | b"ofs-delta"
                    ) {
                        return Err(UploadPackError::UnsupportedRequest);
                    }
                    if wants.len() > MAX_NEGOTIATION_IDS || haves.len() > MAX_NEGOTIATION_IDS {
                        return Err(UploadPackError::NegotiationLimit);
                    }
                }
                Packet::Flush => {}
                Packet::Delimiter | Packet::ResponseEnd => {
                    return Err(UploadPackError::UnsupportedRequest);
                }
            }
        }
        if wants.is_empty() {
            return Err(UploadPackError::IncompleteNegotiation);
        }
        if !done {
            let mut output = Vec::new();
            encode_data(b"acknowledgments\n", &mut output)?;
            encode_data(b"NAK\n", &mut output)?;
            encode_flush(&mut output);
            return Ok(output);
        }

        let mut output = Vec::new();
        encode_data(b"packfile\n", &mut output)?;
        self.repository.write_pack(
            &wants,
            &haves,
            SidebandWriter {
                output: &mut output,
            },
            cancelled,
        )?;
        encode_flush(&mut output);
        Ok(output)
    }

    fn parse_id(&self, input: &[u8]) -> Result<ObjectId, UploadPackError> {
        let id = ObjectId::from_hex(input).map_err(|_| UploadPackError::InvalidObjectId)?;
        if id.kind() != self.repository.object_format() {
            return Err(UploadPackError::InvalidObjectId);
        }
        Ok(id)
    }
}

struct SidebandWriter<'a> {
    output: &'a mut Vec<u8>,
}

impl Write for SidebandWriter<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        encode_sideband(data, self.output).map_err(std::io::Error::other)?;
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn command_name(packets: &[Packet], object_format: Kind) -> Result<&[u8], UploadPackError> {
    let mut command = None;
    for packet in packets {
        let Packet::Data(line) = packet else {
            return Err(UploadPackError::UnsupportedRequest);
        };
        let line = trim_line(line);
        if let Some(value) = line.strip_prefix(b"command=") {
            if command.replace(value).is_some() {
                return Err(UploadPackError::UnsupportedRequest);
            }
        } else if let Some(value) = line.strip_prefix(b"object-format=") {
            if value != hash_name(object_format).as_bytes() {
                return Err(UploadPackError::InvalidObjectId);
            }
        } else if !line.starts_with(b"agent=") {
            return Err(UploadPackError::UnsupportedRequest);
        }
    }
    command.ok_or(UploadPackError::UnsupportedRequest)
}

fn format_ref(reference: &GitReference, symrefs: bool, peel: bool) -> Vec<u8> {
    let mut output = format!(
        "{} {}",
        reference.target,
        String::from_utf8_lossy(&reference.name)
    )
    .into_bytes();
    if symrefs && let Some(target) = &reference.symbolic_target {
        output.extend_from_slice(b" symref-target:");
        output.extend_from_slice(target);
    }
    if peel && let Some(target) = reference.peeled {
        output.extend_from_slice(format!(" peeled:{target}").as_bytes());
    }
    output.push(b'\n');
    output
}

fn trim_line(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\n").unwrap_or(line)
}

pub(crate) fn hash_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Sha1 => "sha1",
        Kind::Sha256 => "sha256",
        _ => unreachable!("gix returned an unsupported object hash"),
    }
}

#[derive(Debug, Error)]
pub(crate) enum UploadPackError {
    #[error(transparent)]
    Repository(#[from] GitRepositoryError),
    #[error(transparent)]
    PacketLine(#[from] PacketLineError),
    #[error("upload-pack request is not supported")]
    UnsupportedRequest,
    #[error("upload-pack object ID is not valid for this repository")]
    InvalidObjectId,
    #[error("upload-pack negotiation exceeds the object ID limit")]
    NegotiationLimit,
    #[error("upload-pack negotiation is incomplete")]
    IncompleteNegotiation,
}
