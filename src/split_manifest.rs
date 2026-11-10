//! Strict parser for the version 1 `nscb.split_manifest` sidecar.
//!
//! A manifest is an unsigned consistency declaration. It is never trusted on
//! its own; the resolver binds the exact sidecar bytes to a host-owned receipt
//! that records independently observed source evidence. This module only
//! validates the declaration's shape, grammar, bounds, and internal arithmetic.

use crate::input_resolution::{InputResolutionError, InputResolutionErrorCode};
use crate::sha256::Sha256Digest;
use crate::strict_json::{self, StrictJsonValue};
#[cfg(any(target_os = "macos", test))]
use serde::Serialize;
use std::collections::HashSet;

/// Maximum sidecar byte length accepted by the v1 manifest contract.
pub(crate) const MAX_SPLIT_MANIFEST_BYTES: u64 = 262_144;

/// Maximum number of physical segments in one canonical Split set.
pub(crate) const MAX_SPLIT_SEGMENTS: usize = 100;

const MAX_SPLIT_MANIFEST_DEPTH: usize = 16;
const MANIFEST_KIND: &str = "nscb.split_manifest";

/// A validated Split manifest with checked source and segment expectations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SplitManifest {
    pub(crate) source_size: u64,
    pub(crate) source_sha256: Sha256Digest,
    pub(crate) segments: Vec<SplitManifestSegment>,
}

/// One ordered physical segment declared by a manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SplitManifestSegment {
    pub(crate) index: u8,
    pub(crate) size: u64,
    pub(crate) sha256: Sha256Digest,
}

impl SplitManifestSegment {
    /// Returns the canonical two-digit basename for this segment.
    #[cfg(test)]
    pub(crate) fn name(&self) -> String {
        format!("{:02}", self.index)
    }
}

#[cfg(any(target_os = "macos", test))]
#[derive(Serialize)]
struct ManifestDocument {
    schema_version: u8,
    kind: &'static str,
    required_features: [&'static str; 0],
    source: ManifestSource,
    segments: Vec<ManifestSegment>,
}

#[cfg(any(target_os = "macos", test))]
#[derive(Serialize)]
struct ManifestSource {
    size_bytes: u64,
    sha256: String,
}

#[cfg(any(target_os = "macos", test))]
#[derive(Serialize)]
struct ManifestSegment {
    name: String,
    size_bytes: u64,
    sha256: String,
}

/// Encodes deterministic v1 sidecar bytes after checking their segment arithmetic.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn encode_manifest(
    source_size: u64,
    source_sha256: Sha256Digest,
    segments: &[SplitManifestSegment],
) -> Result<Vec<u8>, InputResolutionError> {
    if source_size == 0 || segments.is_empty() || segments.len() > MAX_SPLIT_SEGMENTS {
        return Err(invalid());
    }

    let mut checked_source_size = 0_u64;
    let mut encoded_segments = Vec::with_capacity(segments.len());
    for (position, segment) in segments.iter().enumerate() {
        if usize::from(segment.index) != position || segment.size == 0 {
            return Err(invalid());
        }
        checked_source_size = checked_source_size
            .checked_add(segment.size)
            .ok_or_else(invalid)?;
        encoded_segments.push(ManifestSegment {
            name: format!("{position:02}"),
            size_bytes: segment.size,
            sha256: segment.sha256.to_hex(),
        });
    }
    if checked_source_size != source_size {
        return Err(invalid());
    }

    let document = ManifestDocument {
        schema_version: 1,
        kind: MANIFEST_KIND,
        required_features: [],
        source: ManifestSource {
            size_bytes: source_size,
            sha256: source_sha256.to_hex(),
        },
        segments: encoded_segments,
    };
    serde_json::to_vec_pretty(&document).map_err(|_| invalid())
}

/// Parses and validates one manifest document.
pub(crate) fn parse_manifest(bytes: &[u8]) -> Result<SplitManifest, InputResolutionError> {
    if bytes.len() as u64 > MAX_SPLIT_MANIFEST_BYTES {
        return Err(error(InputResolutionErrorCode::ResourceLimitExceeded));
    }
    let document = strict_json::parse(bytes).map_err(|_| invalid())?;
    if strict_json::depth(&document) > MAX_SPLIT_MANIFEST_DEPTH {
        return Err(invalid());
    }
    let StrictJsonValue::Object(fields) = document else {
        return Err(invalid());
    };

    validate_schema_version(&fields)?;
    match required(&fields, "kind")? {
        StrictJsonValue::String(kind) if kind == MANIFEST_KIND => {}
        _ => return Err(invalid()),
    }
    validate_required_features(&fields)?;

    let (source_size, source_sha256) = match required(&fields, "source")? {
        StrictJsonValue::Object(source_fields) => (
            required_u64(source_fields, "size_bytes")?,
            required_digest(source_fields, "sha256")?,
        ),
        _ => return Err(invalid()),
    };
    if source_size == 0 {
        return Err(invalid());
    }

    let StrictJsonValue::Array(segment_values) = required(&fields, "segments")? else {
        return Err(invalid());
    };
    if segment_values.is_empty() || segment_values.len() > MAX_SPLIT_SEGMENTS {
        return Err(invalid());
    }

    let mut segments = Vec::with_capacity(segment_values.len());
    let mut checked_source_size = 0_u64;
    for (position, segment_value) in segment_values.iter().enumerate() {
        let StrictJsonValue::Object(segment_fields) = segment_value else {
            return Err(invalid());
        };
        let expected_name = format!("{position:02}");
        match required(segment_fields, "name")? {
            StrictJsonValue::String(name) if name == &expected_name => {}
            _ => return Err(invalid()),
        }
        let size = required_u64(segment_fields, "size_bytes")?;
        if size == 0 {
            return Err(invalid());
        }
        checked_source_size = checked_source_size.checked_add(size).ok_or_else(invalid)?;
        let sha256 = required_digest(segment_fields, "sha256")?;
        segments.push(SplitManifestSegment {
            index: position as u8,
            size,
            sha256,
        });
    }
    if checked_source_size != source_size {
        return Err(invalid());
    }

    Ok(SplitManifest {
        source_size,
        source_sha256,
        segments,
    })
}

fn validate_schema_version(
    fields: &[(String, StrictJsonValue)],
) -> Result<(), InputResolutionError> {
    match required(fields, "schema_version")? {
        StrictJsonValue::Number(number) if number.as_u64() == Some(1) => Ok(()),
        StrictJsonValue::Number(number) if number.as_u64().is_some() => Err(error(
            InputResolutionErrorCode::SplitManifestVersionUnsupported,
        )),
        _ => Err(invalid()),
    }
}

fn validate_required_features(
    fields: &[(String, StrictJsonValue)],
) -> Result<(), InputResolutionError> {
    let StrictJsonValue::Array(features) = required(fields, "required_features")? else {
        return Err(invalid());
    };
    let mut unique = HashSet::new();
    let mut unsupported = false;
    for feature in features {
        let StrictJsonValue::String(feature) = feature else {
            return Err(invalid());
        };
        if !unique.insert(feature) {
            return Err(invalid());
        }
        unsupported = true;
    }
    if unsupported {
        return Err(error(
            InputResolutionErrorCode::SplitManifestVersionUnsupported,
        ));
    }
    Ok(())
}

fn required<'a>(
    fields: &'a [(String, StrictJsonValue)],
    name: &str,
) -> Result<&'a StrictJsonValue, InputResolutionError> {
    strict_json::required_field(fields, name).ok_or_else(invalid)
}

fn required_u64(
    fields: &[(String, StrictJsonValue)],
    name: &str,
) -> Result<u64, InputResolutionError> {
    match required(fields, name)? {
        StrictJsonValue::Number(number) => number.as_u64().ok_or_else(invalid),
        _ => Err(invalid()),
    }
}

fn required_digest(
    fields: &[(String, StrictJsonValue)],
    name: &str,
) -> Result<Sha256Digest, InputResolutionError> {
    match required(fields, name)? {
        StrictJsonValue::String(value) => Sha256Digest::parse_hex(value).map_err(|_| invalid()),
        _ => Err(invalid()),
    }
}

fn invalid() -> InputResolutionError {
    error(InputResolutionErrorCode::SplitManifestInvalid)
}

fn error(code: InputResolutionErrorCode) -> InputResolutionError {
    InputResolutionError::new(code)
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_SPLIT_MANIFEST_BYTES, MAX_SPLIT_SEGMENTS, SplitManifestSegment, encode_manifest,
        parse_manifest,
    };
    use crate::input_resolution::InputResolutionErrorCode;
    use crate::sha256::Sha256Digest;

    const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn manifest(segment_sizes: &[u64]) -> Vec<u8> {
        let source_size: u64 = segment_sizes.iter().sum();
        let segments = segment_sizes
            .iter()
            .enumerate()
            .map(|(index, size)| {
                format!("{{\"name\":\"{index:02}\",\"size_bytes\":{size},\"sha256\":\"{DIGEST}\"}}")
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"schema_version\":1,\"kind\":\"nscb.split_manifest\",\"required_features\":[],\"source\":{{\"size_bytes\":{source_size},\"sha256\":\"{DIGEST}\"}},\"segments\":[{segments}]}}"
        )
        .into_bytes()
    }

    #[test]
    fn accepts_one_and_multiple_contiguous_segments() {
        let one = parse_manifest(&manifest(&[7])).unwrap();
        assert_eq!(one.source_size, 7);
        assert_eq!(one.segments[0].name(), "00");

        let three = parse_manifest(&manifest(&[3, 2, 1])).unwrap();
        assert_eq!(three.source_size, 6);
        assert_eq!(three.segments.len(), 3);
        assert_eq!(three.segments[2].name(), "02");
    }

    #[test]
    fn rejects_cumulative_segment_length_overflow() {
        let document = format!(
            "{{\"schema_version\":1,\"kind\":\"nscb.split_manifest\",\"required_features\":[],\"source\":{{\"size_bytes\":{},\"sha256\":\"{DIGEST}\"}},\"segments\":[{{\"name\":\"00\",\"size_bytes\":{},\"sha256\":\"{DIGEST}\"}},{{\"name\":\"01\",\"size_bytes\":1,\"sha256\":\"{DIGEST}\"}}]}}",
            u64::MAX,
            u64::MAX
        );
        let error = parse_manifest(document.as_bytes()).unwrap_err();
        assert_eq!(error.code(), InputResolutionErrorCode::SplitManifestInvalid);
    }

    #[test]
    fn rejects_versions_features_and_malformed_shapes() {
        let documents = [
            br#"{"schema_version":2,"kind":"nscb.split_manifest","required_features":[],"source":{"size_bytes":1,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},"segments":[{"name":"00","size_bytes":1,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]}"#.as_slice(),
            br#"{"schema_version":1,"kind":"nscb.split_manifest","required_features":["future"],"source":{"size_bytes":1,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},"segments":[{"name":"00","size_bytes":1,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]}"#.as_slice(),
        ];
        for document in documents {
            let error = parse_manifest(document).unwrap_err();
            assert_eq!(
                error.code(),
                InputResolutionErrorCode::SplitManifestVersionUnsupported
            );
        }
        let wrong_kind = br#"{"schema_version":1,"kind":"wrong","required_features":[],"source":{"size_bytes":1,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},"segments":[{"name":"00","size_bytes":1,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]}"#;
        assert_eq!(
            parse_manifest(wrong_kind).unwrap_err().code(),
            InputResolutionErrorCode::SplitManifestInvalid
        );
        assert_eq!(
            parse_manifest(&manifest(&[1, 0])).unwrap_err().code(),
            InputResolutionErrorCode::SplitManifestInvalid
        );
        assert_eq!(
            parse_manifest(&manifest(&[1])[..20]).unwrap_err().code(),
            InputResolutionErrorCode::SplitManifestInvalid
        );
    }

    #[test]
    fn rejects_inconsistent_sizes_hashes_names_and_duplicate_keys() {
        let valid = String::from_utf8(manifest(&[1])).unwrap();
        for document in [
            valid.replace(
                "\"source\":{\"size_bytes\":1",
                "\"source\":{\"size_bytes\":2",
            ),
            valid.replace(DIGEST, &DIGEST.to_ascii_uppercase()),
            valid.replace("\"00\"", "\"01\""),
            valid.replace(
                "\"kind\":\"nscb.split_manifest\"",
                "\"kind\":\"nscb.split_manifest\",\"kind\":\"nscb.split_manifest\"",
            ),
        ] {
            if let Ok(error) = parse_manifest(document.as_bytes()) {
                panic!("expected rejection: {error:?}");
            }
        }
    }

    #[test]
    fn enforces_bounds_and_zero_length_rejection() {
        let segments = vec![1_u64; MAX_SPLIT_SEGMENTS + 1];
        assert_eq!(
            parse_manifest(&manifest(&segments)).unwrap_err().code(),
            InputResolutionErrorCode::SplitManifestInvalid
        );
        assert_eq!(
            parse_manifest(&manifest(&[0])).unwrap_err().code(),
            InputResolutionErrorCode::SplitManifestInvalid
        );
        let oversized = vec![b' '; MAX_SPLIT_MANIFEST_BYTES as usize + 1];
        assert_eq!(
            parse_manifest(&oversized).unwrap_err().code(),
            InputResolutionErrorCode::ResourceLimitExceeded
        );
    }

    #[test]
    fn stores_the_declared_source_digest() {
        let parsed = parse_manifest(&manifest(&[2])).unwrap();
        assert_eq!(
            parsed.source_sha256,
            Sha256Digest::parse_hex(DIGEST).unwrap()
        );
    }

    #[test]
    fn deterministic_writer_emits_parser_accepted_source_backed_manifest() {
        let source = b"source bytes";
        let first = b"source ";
        let second = b"bytes";
        let segments = [
            SplitManifestSegment {
                index: 0,
                size: first.len() as u64,
                sha256: Sha256Digest::digest(first),
            },
            SplitManifestSegment {
                index: 1,
                size: second.len() as u64,
                sha256: Sha256Digest::digest(second),
            },
        ];
        let source_sha256 = Sha256Digest::digest(source);

        let encoded = encode_manifest(source.len() as u64, source_sha256, &segments).unwrap();

        assert_eq!(
            encoded,
            format!(
                concat!(
                    "{{\n",
                    "  \"schema_version\": 1,\n",
                    "  \"kind\": \"nscb.split_manifest\",\n",
                    "  \"required_features\": [],\n",
                    "  \"source\": {{\n",
                    "    \"size_bytes\": 12,\n",
                    "    \"sha256\": \"{}\"\n",
                    "  }},\n",
                    "  \"segments\": [\n",
                    "    {{\n",
                    "      \"name\": \"00\",\n",
                    "      \"size_bytes\": 7,\n",
                    "      \"sha256\": \"{}\"\n",
                    "    }},\n",
                    "    {{\n",
                    "      \"name\": \"01\",\n",
                    "      \"size_bytes\": 5,\n",
                    "      \"sha256\": \"{}\"\n",
                    "    }}\n",
                    "  ]\n",
                    "}}"
                ),
                source_sha256.to_hex(),
                Sha256Digest::digest(first).to_hex(),
                Sha256Digest::digest(second).to_hex(),
            )
            .into_bytes()
        );

        let parsed = parse_manifest(&encoded).unwrap();
        assert_eq!(parsed.source_size, source.len() as u64);
        assert_eq!(parsed.source_sha256, source_sha256);
        assert_eq!(parsed.segments, segments);
    }
}
