//! Shared pure parsing for the header-key aliases in a complete key file.
//!
//! Callers retain ownership of the original bytes. The provider can serialize
//! the parsed header key for its helper, while standalone key replacement can
//! validate the header and persist every original entry unchanged.

use crate::allocation::{AllocationSite, reserve_exact};
use std::fmt;
use std::io::Read;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const MAX_KEY_FILE_BYTES: u64 = 1024 * 1024;
const HEADER_KEY_ALIASES: [&str; 2] = ["header_key", "nca_header_key"];
const APPLICATION_KAEK_REVISION_ZERO: &str = "key_area_key_application_00";

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

    fn set(&mut self, mut bytes: [u8; 32]) -> Result<(), KeyFileParseError> {
        if self.present && self.bytes != bytes {
            bytes.zeroize();
            return Err(KeyFileParseError::Malformed);
        }
        self.bytes = bytes;
        bytes.zeroize();
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
        self.bytes.zeroize();
    }
}

pub(crate) struct ApplicationKeyAreaKey {
    bytes: [u8; 16],
}

impl ApplicationKeyAreaKey {
    pub(crate) fn as_bytes(&self) -> &[u8; 16] {
        &self.bytes
    }
}

impl fmt::Debug for ApplicationKeyAreaKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApplicationKeyAreaKey([REDACTED])")
    }
}

impl Drop for ApplicationKeyAreaKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

pub(crate) struct NspQualificationKeys {
    pub(crate) header_key: HeaderKey,
    pub(crate) application_kaek: ApplicationKeyAreaKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NspKeyFileError {
    Unavailable,
    LimitExceeded,
    AllocationFailed,
    Malformed,
    MissingHeaderKey,
    MissingApplicationKeyAreaKey,
}

/// Reads the explicit keys required by the supported semantic profile.
pub(crate) fn read_nsp_qualification_keys(
    reader: &mut impl Read,
    file_size: u64,
) -> Result<NspQualificationKeys, NspKeyFileError> {
    if file_size > MAX_KEY_FILE_BYTES {
        return Err(NspKeyFileError::LimitExceeded);
    }
    let size = usize::try_from(file_size).map_err(|_| NspKeyFileError::LimitExceeded)?;
    let mut bytes = Zeroizing::new(Vec::new());
    reserve_exact(&mut bytes, size, AllocationSite::KeyFileBytes)
        .map_err(|_| NspKeyFileError::AllocationFailed)?;
    bytes.resize(size, 0);
    reader
        .read_exact(&mut bytes)
        .map_err(|_| NspKeyFileError::Unavailable)?;

    let header_key = parse_header_key_bytes(&bytes).map_err(|error| match error {
        KeyFileParseError::Malformed => NspKeyFileError::Malformed,
        KeyFileParseError::MissingHeaderKey => NspKeyFileError::MissingHeaderKey,
    })?;
    let application_kaek = parse_application_kaek(&bytes)?;
    Ok(NspQualificationKeys {
        header_key,
        application_kaek,
    })
}

fn parse_application_kaek(bytes: &[u8]) -> Result<ApplicationKeyAreaKey, NspKeyFileError> {
    let mut found = None;
    for line in bytes.split(|byte| *byte == b'\n') {
        let line = trim_ascii(line.strip_suffix(b"\r").unwrap_or(line));
        if line.is_empty() || line.starts_with(b"#") || line.starts_with(b";") {
            continue;
        }
        let Some(separator) = line.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        let name = trim_ascii(&line[..separator]);
        if name != APPLICATION_KAEK_REVISION_ZERO.as_bytes() {
            continue;
        }
        let value = trim_ascii(&line[separator + 1..]);
        let decoded = decode_hex_16(value).ok_or(NspKeyFileError::Malformed)?;
        if found
            .as_ref()
            .is_some_and(|previous: &Zeroizing<[u8; 16]>| previous.as_ref() != decoded.as_ref())
        {
            return Err(NspKeyFileError::Malformed);
        }
        found = Some(decoded);
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(
        found
            .as_ref()
            .ok_or(NspKeyFileError::MissingApplicationKeyAreaKey)?
            .as_ref(),
    );
    Ok(ApplicationKeyAreaKey { bytes })
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
        if key.set(*decoded).is_err() {
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

fn decode_hex_32(value: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    if value.len() != 64 {
        return None;
    }
    let mut result = Zeroizing::new([0_u8; 32]);
    for (index, pair) in value.as_chunks::<2>().0.iter().enumerate() {
        result[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Some(result)
}

fn decode_hex_16(value: &[u8]) -> Option<Zeroizing<[u8; 16]>> {
    if value.len() != 32 {
        return None;
    }
    let mut result = Zeroizing::new([0_u8; 16]);
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

#[cfg(test)]
mod qualification_tests {
    use super::{MAX_KEY_FILE_BYTES, NspKeyFileError, read_nsp_qualification_keys};
    use std::io::{self, Cursor, Read};

    fn valid_text() -> Vec<u8> {
        format!(
            "header_key = {}\nkey_area_key_application_00 = {}\n",
            "42".repeat(32),
            "24".repeat(16)
        )
        .into_bytes()
    }

    #[test]
    fn reads_both_explicit_keys_and_redacts_the_application_key_debug_form() {
        let bytes = valid_text();
        let keys = read_nsp_qualification_keys(&mut Cursor::new(bytes.clone()), bytes.len() as u64)
            .unwrap();

        assert_eq!(keys.header_key.as_bytes(), &[0x42; 32]);
        assert_eq!(keys.application_kaek.as_bytes(), &[0x24; 16]);
        assert_eq!(
            format!("{:?}", keys.application_kaek),
            "ApplicationKeyAreaKey([REDACTED])"
        );
    }

    #[test]
    fn missing_key_material_is_distinct_from_malformed_key_material() {
        let header_only = format!("header_key = {}\n", "42".repeat(32)).into_bytes();
        assert_eq!(
            read_nsp_qualification_keys(
                &mut Cursor::new(header_only.clone()),
                header_only.len() as u64,
            )
            .err()
            .expect("the Application key is required"),
            NspKeyFileError::MissingApplicationKeyAreaKey
        );

        let application_only =
            format!("key_area_key_application_00 = {}\n", "24".repeat(16)).into_bytes();
        assert_eq!(
            read_nsp_qualification_keys(
                &mut Cursor::new(application_only.clone()),
                application_only.len() as u64,
            )
            .err()
            .expect("the header key is required"),
            NspKeyFileError::MissingHeaderKey
        );

        let malformed = format!(
            "header_key = {}\nkey_area_key_application_00 = short\n",
            "42".repeat(32)
        )
        .into_bytes();
        assert_eq!(
            read_nsp_qualification_keys(
                &mut Cursor::new(malformed.clone()),
                malformed.len() as u64,
            )
            .err()
            .expect("malformed key material is rejected"),
            NspKeyFileError::Malformed
        );
    }

    #[test]
    fn conflicting_application_key_definitions_are_rejected_without_values() {
        let text = format!(
            "header_key = {}\nkey_area_key_application_00 = {}\nkey_area_key_application_00 = {}\n",
            "42".repeat(32),
            "24".repeat(16),
            "25".repeat(16)
        );
        let error = read_nsp_qualification_keys(
            &mut Cursor::new(text.as_bytes().to_vec()),
            text.len() as u64,
        )
        .err()
        .expect("conflicting key definitions are rejected");
        assert_eq!(error, NspKeyFileError::Malformed);
        assert!(!format!("{error:?}").contains(&"24".repeat(16)));
    }

    #[test]
    fn key_file_reader_enforces_the_shared_size_limit_and_sanitizes_io_errors() {
        assert_eq!(
            read_nsp_qualification_keys(&mut Cursor::new(Vec::new()), MAX_KEY_FILE_BYTES + 1)
                .err()
                .expect("oversized key files are rejected"),
            NspKeyFileError::LimitExceeded
        );

        struct FailsAfterPrefix(bool);
        impl Read for FailsAfterPrefix {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.0 {
                    return Err(io::Error::other("secret-marker"));
                }
                self.0 = true;
                buffer[..4].copy_from_slice(b"head");
                Ok(4)
            }
        }
        let error = read_nsp_qualification_keys(&mut FailsAfterPrefix(false), 8)
            .err()
            .expect("partial reads fail closed");
        assert_eq!(error, NspKeyFileError::Unavailable);
        assert!(!format!("{error:?}").contains("secret-marker"));
    }
}
