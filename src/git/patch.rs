use std::io::Write;

use gix::hash::ObjectId;

use super::read::{DiffFile, ReadError};

const MAX_PATCH_BYTES: usize = 32 * 1024 * 1024;
const BASE85: &[u8; 85] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

pub(crate) fn write_patch(files: &[DiffFile], output: &mut impl Write) -> Result<usize, ReadError> {
    let mut output = PatchWriter {
        inner: output,
        written: 0,
    };
    for file in files {
        write_file(file, &mut output)?;
    }
    Ok(output.written)
}

fn write_file(file: &DiffFile, output: &mut PatchWriter<'_, impl Write>) -> Result<(), ReadError> {
    let old_path = patch_path(b'a', &file.path);
    let new_path = patch_path(b'b', &file.path);
    writeln_bytes(
        output,
        &[
            b"diff --git ".as_slice(),
            &old_path,
            b" ".as_slice(),
            &new_path,
        ],
    )?;
    match (file.old_mode, file.new_mode) {
        (None, Some(mode)) => writeln!(output, "new file mode {mode:06o}")?,
        (Some(mode), None) => writeln!(output, "deleted file mode {mode:06o}")?,
        (Some(old), Some(new)) if old != new => {
            write!(output, "old mode {old:06o}\nnew mode {new:06o}\n")?;
        }
        _ => {}
    }
    let hash_length = file
        .old_id
        .or(file.new_id)
        .map_or(40, |id| id.kind().len_in_hex());
    let old_id = object_name(file.old_id, hash_length);
    let new_id = object_name(file.new_id, hash_length);
    match file.new_mode.or(file.old_mode) {
        Some(mode) if file.old_mode == file.new_mode => {
            writeln!(output, "index {old_id}..{new_id} {mode:06o}")?;
        }
        _ => writeln!(output, "index {old_id}..{new_id}")?,
    }
    if file.binary {
        writeln_bytes(
            output,
            &[
                b"Binary files ".as_slice(),
                &old_path,
                b" and ",
                &new_path,
                b" differ",
            ],
        )?;
        output.write_all(b"GIT binary patch\n")?;
        write_binary_literal(file.new_data.as_deref().unwrap_or_default(), output)?;
        return Ok(());
    }
    if file.old_id == file.new_id {
        return Ok(());
    }
    if file.old_id.is_some() {
        writeln_bytes(output, &[b"--- ".as_slice(), &old_path])?;
    } else {
        output.write_all(b"--- /dev/null\n")?;
    }
    if file.new_id.is_some() {
        writeln_bytes(output, &[b"+++ ".as_slice(), &new_path])?;
    } else {
        output.write_all(b"+++ /dev/null\n")?;
    }
    output.write_all(&file.hunks)?;
    Ok(())
}

fn write_binary_literal(
    data: &[u8],
    output: &mut PatchWriter<'_, impl Write>,
) -> Result<(), ReadError> {
    writeln!(output, "literal {}", data.len())?;
    let compressed = zlib_store(data);
    for chunk in compressed.chunks(52) {
        output.write_all(&[encoded_length(chunk.len())])?;
        let mut padded = [0_u8; 52];
        padded[..chunk.len()].copy_from_slice(chunk);
        for word in padded[..chunk.len().div_ceil(4) * 4].chunks_exact(4) {
            let mut value = u32::from_be_bytes(word.try_into().expect("four bytes"));
            let mut encoded = [0_u8; 5];
            for byte in encoded.iter_mut().rev() {
                *byte = BASE85[(value % 85) as usize];
                value /= 85;
            }
            output.write_all(&encoded)?;
        }
        output.write_all(b"\n")?;
    }
    output.write_all(b"\n")?;
    Ok(())
}

fn zlib_store(data: &[u8]) -> Vec<u8> {
    let mut output = vec![0x78, 0x01];
    if data.is_empty() {
        output.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    } else {
        for (index, chunk) in data.chunks(u16::MAX as usize).enumerate() {
            output.push(u8::from(
                index + 1 == data.len().div_ceil(u16::MAX as usize),
            ));
            let length = u16::try_from(chunk.len()).expect("stored block length");
            output.extend_from_slice(&length.to_le_bytes());
            output.extend_from_slice(&(!length).to_le_bytes());
            output.extend_from_slice(chunk);
        }
    }
    output.extend_from_slice(&adler32(data).to_be_bytes());
    output
}

fn adler32(data: &[u8]) -> u32 {
    const MODULUS: u32 = 65_521;
    let mut first = 1_u32;
    let mut second = 0_u32;
    for byte in data {
        first = (first + u32::from(*byte)) % MODULUS;
        second = (second + first) % MODULUS;
    }
    (second << 16) | first
}

fn encoded_length(length: usize) -> u8 {
    match length {
        1..=26 => b'A' + u8::try_from(length - 1).expect("base85 line length"),
        27..=52 => b'a' + u8::try_from(length - 27).expect("base85 line length"),
        _ => unreachable!("binary patch lines contain between 1 and 52 bytes"),
    }
}

fn object_name(id: Option<ObjectId>, length: usize) -> String {
    id.map_or_else(|| "0".repeat(length), |id| id.to_string())
}

fn patch_path(prefix: u8, path: &[u8]) -> Vec<u8> {
    let mut prefixed = Vec::with_capacity(path.len() + 2);
    prefixed.push(prefix);
    prefixed.push(b'/');
    prefixed.extend_from_slice(path);
    if prefixed
        .iter()
        .all(|byte| matches!(byte, b'!'..=b'~') && !matches!(byte, b'"' | b'\\'))
    {
        return prefixed;
    }
    let mut quoted = vec![b'"'];
    for byte in prefixed {
        match byte {
            b'"' | b'\\' => {
                quoted.push(b'\\');
                quoted.push(byte);
            }
            b'\t' => quoted.extend_from_slice(b"\\t"),
            b'\n' => quoted.extend_from_slice(b"\\n"),
            b'\r' => quoted.extend_from_slice(b"\\r"),
            b' '..=b'~' => quoted.push(byte),
            _ => quoted.extend_from_slice(format!("\\{byte:03o}").as_bytes()),
        }
    }
    quoted.push(b'"');
    quoted
}

fn writeln_bytes(
    output: &mut PatchWriter<'_, impl Write>,
    parts: &[&[u8]],
) -> Result<(), ReadError> {
    for part in parts {
        output.write_all(part)?;
    }
    output.write_all(b"\n")?;
    Ok(())
}

struct PatchWriter<'a, W> {
    inner: &'a mut W,
    written: usize,
}

impl<W: Write> Write for PatchWriter<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let next = self
            .written
            .checked_add(buffer.len())
            .ok_or_else(|| std::io::Error::other("patch output is too large"))?;
        if next > MAX_PATCH_BYTES {
            return Err(std::io::Error::other("patch output is too large"));
        }
        self.inner.write_all(buffer)?;
        self.written = next;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
