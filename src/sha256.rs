//! SHA-256 digest values used by Split-set evidence and manifests.
//!
//! Digests are stored as raw bytes in memory and rendered as lowercase
//! hexadecimal when they cross a JSON or human-readable boundary. Parsing is
//! deliberately strict: uppercase hexadecimal, shortened values, whitespace,
//! and non-ASCII characters are rejected.

use serde::{Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::str::FromStr;

/// Number of characters in a lowercase hexadecimal SHA-256 digest.
pub const SHA256_HEX_LENGTH: usize = 64;

/// A validated 32-byte SHA-256 digest.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Creates a digest from its raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Computes the SHA-256 digest of `bytes`.
    pub fn digest(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Returns the digest as 64 lowercase hexadecimal characters.
    pub fn to_hex(self) -> String {
        let mut result = String::with_capacity(SHA256_HEX_LENGTH);
        for byte in self.0 {
            result.push(hex_digit(byte >> 4));
            result.push(hex_digit(byte & 0x0f));
        }
        result
    }

    /// Parses exactly 64 lowercase hexadecimal characters.
    pub fn parse_hex(value: &str) -> Result<Self, InvalidSha256Digest> {
        let bytes = value.as_bytes();
        if bytes.len() != SHA256_HEX_LENGTH {
            return Err(InvalidSha256Digest);
        }
        let mut digest = [0_u8; 32];
        for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
            let high = decode_hex_digit(pair[0])?;
            let low = decode_hex_digit(pair[1])?;
            digest[index] = (high << 4) | low;
        }
        Ok(Self(digest))
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl FromStr for Sha256Digest {
    type Err = InvalidSha256Digest;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse_hex(value)
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

/// A value that is not 64 lowercase hexadecimal SHA-256 characters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidSha256Digest;

impl fmt::Display for InvalidSha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a SHA-256 digest must be 64 lowercase hexadecimal characters")
    }
}

impl std::error::Error for InvalidSha256Digest {}

fn hex_digit(value: u8) -> char {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    DIGITS[usize::from(value)] as char
}

fn decode_hex_digit(value: u8) -> Result<u8, InvalidSha256Digest> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(InvalidSha256Digest),
    }
}

#[cfg(test)]
mod tests {
    use super::{InvalidSha256Digest, SHA256_HEX_LENGTH, Sha256Digest};

    const EMPTY_DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn known_vector_round_trips_as_lowercase_hex() {
        let digest = Sha256Digest::digest(b"");
        assert_eq!(digest.to_hex(), EMPTY_DIGEST);
        assert_eq!(Sha256Digest::parse_hex(EMPTY_DIGEST).unwrap(), digest);
        assert_eq!(digest.to_string(), EMPTY_DIGEST);
    }

    #[test]
    fn invalid_spellings_are_rejected() {
        for value in [
            "",
            "abc",
            &EMPTY_DIGEST[..SHA256_HEX_LENGTH - 1],
            &EMPTY_DIGEST.to_ascii_uppercase(),
            " e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85g",
        ] {
            assert_eq!(Sha256Digest::parse_hex(value), Err(InvalidSha256Digest));
        }
    }

    #[test]
    fn serializes_as_hex_string() {
        let digest = Sha256Digest::digest(b"");
        assert_eq!(
            serde_json::to_string(&digest).unwrap(),
            format!("\"{EMPTY_DIGEST}\"")
        );
    }
}
