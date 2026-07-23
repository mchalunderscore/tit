use thiserror::Error;

pub(crate) const MAX_PACKET_BYTES: usize = 65_520;
pub(crate) const MAX_REQUEST_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Packet {
    Data(Vec<u8>),
    Flush,
    Delimiter,
    ResponseEnd,
}

pub(crate) fn encode_data(data: &[u8], output: &mut Vec<u8>) -> Result<(), PacketLineError> {
    let length = data
        .len()
        .checked_add(4)
        .ok_or(PacketLineError::PacketTooLarge)?;
    if length > MAX_PACKET_BYTES {
        return Err(PacketLineError::PacketTooLarge);
    }
    output.extend_from_slice(format!("{length:04x}").as_bytes());
    output.extend_from_slice(data);
    Ok(())
}

pub(crate) fn encode_flush(output: &mut Vec<u8>) {
    output.extend_from_slice(b"0000");
}

pub(crate) fn encode_delimiter(output: &mut Vec<u8>) {
    output.extend_from_slice(b"0001");
}

pub(crate) fn encode_sideband(data: &[u8], output: &mut Vec<u8>) -> Result<(), PacketLineError> {
    for chunk in data.chunks(MAX_PACKET_BYTES - 5) {
        let mut payload = Vec::with_capacity(chunk.len() + 1);
        payload.push(1);
        payload.extend_from_slice(chunk);
        encode_data(&payload, output)?;
    }
    Ok(())
}

pub(crate) fn decode(input: &[u8]) -> Result<Vec<Packet>, PacketLineError> {
    if input.len() > MAX_REQUEST_BYTES {
        return Err(PacketLineError::RequestTooLarge);
    }

    let mut packets = Vec::new();
    let mut offset = 0;
    while offset < input.len() {
        let header = input
            .get(offset..offset + 4)
            .ok_or(PacketLineError::TruncatedHeader)?;
        if !header.iter().all(u8::is_ascii_hexdigit) {
            return Err(PacketLineError::InvalidLength);
        }
        let header = std::str::from_utf8(header).map_err(|_| PacketLineError::InvalidLength)?;
        let length =
            usize::from_str_radix(header, 16).map_err(|_| PacketLineError::InvalidLength)?;
        offset += 4;
        match length {
            0 => packets.push(Packet::Flush),
            1 => packets.push(Packet::Delimiter),
            2 => packets.push(Packet::ResponseEnd),
            3 | 4 => return Err(PacketLineError::InvalidLength),
            length if length > MAX_PACKET_BYTES => return Err(PacketLineError::PacketTooLarge),
            length => {
                let payload_length = length - 4;
                let payload = input
                    .get(offset..offset + payload_length)
                    .ok_or(PacketLineError::TruncatedPacket)?;
                packets.push(Packet::Data(payload.to_vec()));
                offset += payload_length;
            }
        }
    }
    Ok(packets)
}

pub(crate) fn first_flush_end(input: &[u8]) -> Result<Option<usize>, PacketLineError> {
    let mut offset = 0;
    while offset < input.len() {
        if offset >= MAX_REQUEST_BYTES {
            return Err(PacketLineError::RequestTooLarge);
        }
        let Some(header) = input.get(offset..offset + 4) else {
            return Ok(None);
        };
        if !header.iter().all(u8::is_ascii_hexdigit) {
            return Err(PacketLineError::InvalidLength);
        }
        let header = std::str::from_utf8(header).map_err(|_| PacketLineError::InvalidLength)?;
        let length =
            usize::from_str_radix(header, 16).map_err(|_| PacketLineError::InvalidLength)?;
        match length {
            0 if offset + 4 <= MAX_REQUEST_BYTES => return Ok(Some(offset + 4)),
            0 => return Err(PacketLineError::RequestTooLarge),
            1 | 2 => offset += 4,
            3 | 4 => return Err(PacketLineError::InvalidLength),
            length if length > MAX_PACKET_BYTES => return Err(PacketLineError::PacketTooLarge),
            length => {
                let end = offset
                    .checked_add(length)
                    .ok_or(PacketLineError::PacketTooLarge)?;
                if end > input.len() {
                    return Ok(None);
                }
                if end > MAX_REQUEST_BYTES {
                    return Err(PacketLineError::RequestTooLarge);
                }
                offset = end;
            }
        }
    }
    Ok(None)
}

#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum PacketLineError {
    #[error("packet-line request is too large")]
    RequestTooLarge,
    #[error("packet-line header is incomplete")]
    TruncatedHeader,
    #[error("packet-line length is not valid")]
    InvalidLength,
    #[error("packet-line is too large")]
    PacketTooLarge,
    #[error("packet-line payload is incomplete")]
    TruncatedPacket,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_data_and_control_packets() {
        let mut encoded = Vec::new();
        encode_data(b"want object\n", &mut encoded).expect("encode data");
        encode_delimiter(&mut encoded);
        encode_flush(&mut encoded);

        assert_eq!(
            decode(&encoded).expect("decode packets"),
            vec![
                Packet::Data(b"want object\n".to_vec()),
                Packet::Delimiter,
                Packet::Flush
            ]
        );
    }

    #[test]
    fn rejects_truncated_invalid_and_oversized_packets() {
        assert_eq!(decode(b"000"), Err(PacketLineError::TruncatedHeader));
        assert_eq!(decode(b"zzzz"), Err(PacketLineError::InvalidLength));
        assert_eq!(decode(b"0004"), Err(PacketLineError::InvalidLength));
        assert_eq!(decode(b"0008abc"), Err(PacketLineError::TruncatedPacket));
        assert_eq!(
            decode(&vec![b'0'; MAX_REQUEST_BYTES + 1]),
            Err(PacketLineError::RequestTooLarge)
        );
        assert_eq!(
            encode_data(&vec![0; MAX_PACKET_BYTES - 3], &mut Vec::new()),
            Err(PacketLineError::PacketTooLarge)
        );
    }

    #[test]
    fn finds_the_first_complete_flush_boundary() {
        assert_eq!(first_flush_end(b"0008abc"), Ok(None));
        assert_eq!(first_flush_end(b"0008abcd0000PACK"), Ok(Some(12)));
        assert_eq!(first_flush_end(b"0008abcd0001"), Ok(None));
        assert_eq!(
            first_flush_end(b"0004"),
            Err(PacketLineError::InvalidLength)
        );
    }
}
