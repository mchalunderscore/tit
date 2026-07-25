pub(crate) fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(crate) fn decode_lower_hex(encoded: &[u8]) -> Option<Vec<u8>> {
    decode_hex(encoded, false)
}

pub(crate) fn decode_ascii_hex(encoded: &[u8]) -> Option<Vec<u8>> {
    decode_hex(encoded, true)
}

fn decode_hex(encoded: &[u8], uppercase: bool) -> Option<Vec<u8>> {
    if !encoded.len().is_multiple_of(2) {
        return None;
    }
    encoded
        .chunks_exact(2)
        .map(|pair| {
            Some((decode_nibble(pair[0], uppercase)? << 4) | decode_nibble(pair[1], uppercase)?)
        })
        .collect()
}

fn decode_nibble(byte: u8, uppercase: bool) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' if uppercase => Some(byte - b'A' + 10),
        _ => None,
    }
}
