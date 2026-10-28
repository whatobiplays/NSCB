//! Shared pure parsing for the header-key aliases in a complete key file.
//!
//! Callers retain ownership of the original bytes. The provider can serialize
//! the parsed header key for its helper, while standalone key replacement can
//! validate the header and persist every original entry unchanged.

use std::fmt;

pub(crate) const MAX_KEY_FILE_BYTES: u64 = 1024 * 1024;
const HEADER_KEY_ALIASES: [&str; 2] = ["header_key", "nca_header_key"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyFileParseError {
    Malformed,
    MissingHeaderKey,
}

/// Parsed key bytes whose debug form and drop behavior avoid retaining secrets.
pub(crate) struct HeaderKey {
    bytes: [u8; 32],
    present: bool,
}

impl HeaderKey {
    #[allow(dead_code)]
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    fn set(&mut self, bytes: [u8; 32]) -> Result<(), KeyFileParseError> {
        if self.present && self.bytes != bytes {
            return Err(KeyFileParseError::Malformed);
        }
        self.bytes = bytes;
        self.present = true;
        Ok(())
    }
}

impl fmt::Debug for HeaderKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HeaderKey([REDACTED])")
    }
}

impl Drop for HeaderKey {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// Validates key-file syntax and extracts the first recognized header key.
/// Unrelated key entries remain opaque and do not appear in the returned value.
pub(crate) fn parse_header_key_bytes(bytes: &[u8]) -> Result<HeaderKey, KeyFileParseError> {
    let mut key = HeaderKey {
        bytes: [0; 32],
        present: false,
    };
    let mut malformed = false;
    for line in bytes.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let line = trim_ascii(line);
        if line.is_empty() || line.starts_with(b"#") || line.starts_with(b";") {
            continue;
        }
        let Some(separator) = line.iter().position(|byte| *byte == b'=') else {
            malformed = true;
            continue;
        };
        let name = trim_ascii(&line[..separator]);
        let value = trim_ascii(&line[separator + 1..]);
        let Ok(name) = std::str::from_utf8(name) else {
            malformed = true;
            continue;
        };
        if !HEADER_KEY_ALIASES.contains(&name) {
            continue;
        }
        let Some(decoded) = decode_hex_32(value) else {
            malformed = true;
            continue;
        };
        if key.set(decoded).is_err() {
            malformed = true;
        }
    }
    if malformed {
        return Err(KeyFileParseError::Malformed);
    }
    if !key.present {
        return Err(KeyFileParseError::MissingHeaderKey);
    }
    Ok(key)
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(|byte| byte.is_ascii_whitespace()) {
        value = &value[1..];
    }
    while value.last().is_some_and(|byte| byte.is_ascii_whitespace()) {
        value = &value[..value.len() - 1];
    }
    value
}

fn decode_hex_32(value: &[u8]) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut result = [0_u8; 32];
    for (index, pair) in value.as_chunks::<2>().0.iter().enumerate() {
        result[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Some(result)
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
