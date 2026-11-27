//! Strict parser for versioned `nscb.split_manifest` sidecars.
//!
//! A manifest is an unsigned consistency declaration. It is never trusted on
//! its own; the resolver binds the exact sidecar bytes to a host-owned receipt
//! that records independently observed source evidence. This module only
//! validates the declaration's shape, grammar, bounds, and internal arithmetic.

use crate::input_resolution::{InputResolutionError, InputResolutionErrorCode};
use crate::sha256::Sha256Digest;
use crate::strict_json::{self, StrictJsonValue};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Maximum sidecar byte length accepted by the Split manifest contract.
pub(crate) const MAX_SPLIT_MANIFEST_BYTES: u64 = 262_144;

/// Maximum number of physical segments in one canonical Split set.
pub(crate) const MAX_SPLIT_SEGMENTS: usize = 100;

const MAX_SPLIT_MANIFEST_DEPTH: usize = 16;
const MANIFEST_KIND: &str = "nscb.split_manifest";
#[cfg(any(target_os = "macos", test))]
pub(crate) const MAX_LEGACY_SPLIT_SEGMENTS: usize = 10;

/// Names the on-disk layout used for a Split set.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitLayout {
    /// NSCB's canonical two-digit segment layout.
    Canonical,
    /// The legacy `.xcN` layout consumed by NSC_BUILDER.
    LegacyXc,
    /// The legacy `.nsN` layout consumed by NSC_BUILDER.
    LegacyNs,
}

impl SplitLayout {
    pub(crate) const fn is_canonical(&self) -> bool {
        matches!(self, Self::Canonical)
    }

    #[cfg(any(target_os = "macos", test))]
    fn manifest_name(self) -> Option<&'static str> {
        match self {
            Self::Canonical => None,
            Self::LegacyXc => Some("legacy_xc"),
            Self::LegacyNs => Some("legacy_ns"),
        }
    }

    pub(crate) fn legacy_suffix(self) -> Option<&'static str> {
        match self {
            Self::Canonical => None,
            Self::LegacyXc => Some("xc"),
            Self::LegacyNs => Some("ns"),
        }
    }
}

/// A validated Split manifest with checked source and segment expectations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SplitManifest {
    pub(crate) schema_version: u8,
    pub(crate) layout: SplitLayout,
    pub(crate) source_size: u64,
    pub(crate) source_sha256: Sha256Digest,
    pub(crate) segments: Vec<SplitManifestSegment>,
}

/// One ordered physical segment declared by a manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SplitManifestSegment {
    pub(crate) index: u8,
    pub(crate) name: String,
    pub(crate) size: u64,
    pub(crate) sha256: Sha256Digest,
}

impl SplitManifestSegment {
    /// Returns the basename recorded by the manifest.
    #[cfg(test)]
    pub(crate) fn name(&self) -> &str {
        &self.name
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
struct LegacyManifestDocument {
    schema_version: u8,
    kind: &'static str,
    required_features: [&'static str; 0],
    layout: &'static str,
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

/// Encodes a v2 manifest whose segment names use one of the legacy layouts.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn encode_legacy_manifest(
    layout: SplitLayout,
    source_size: u64,
    source_sha256: Sha256Digest,
    segments: &[SplitManifestSegment],
) -> Result<Vec<u8>, InputResolutionError> {
    let layout_name = layout.manifest_name().ok_or_else(invalid)?;
    if source_size == 0 || segments.is_empty() || segments.len() > MAX_LEGACY_SPLIT_SEGMENTS {
        return Err(invalid());
    }

    let suffix = layout.legacy_suffix().ok_or_else(invalid)?;
    let mut checked_source_size = 0_u64;
    let mut encoded_segments = Vec::with_capacity(segments.len());
    let mut expected_stem: Option<String> = None;
    for (position, segment) in segments.iter().enumerate() {
        if usize::from(segment.index) != position || segment.size == 0 {
            return Err(invalid());
        }
        checked_source_size = checked_source_size
            .checked_add(segment.size)
            .ok_or_else(invalid)?;
        let stem = parse_legacy_segment_name(&segment.name, suffix, segment.index)?;
        if expected_stem
            .as_ref()
            .is_some_and(|expected| expected != &stem)
        {
            return Err(invalid());
        }
        expected_stem = Some(stem);
        encoded_segments.push(ManifestSegment {
            name: segment.name.clone(),
            size_bytes: segment.size,
            sha256: segment.sha256.to_hex(),
        });
    }
    if checked_source_size != source_size {
        return Err(invalid());
    }

    let document = LegacyManifestDocument {
        schema_version: 2,
        kind: MANIFEST_KIND,
        required_features: [],
        layout: layout_name,
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

    let schema_version = validate_schema_version(&fields)?;
    if schema_version == 2 {
        validate_exact_fields(
            &fields,
            &[
                "schema_version",
                "kind",
                "required_features",
                "layout",
                "source",
                "segments",
            ],
        )?;
    }
    match required(&fields, "kind")? {
        StrictJsonValue::String(kind) if kind == MANIFEST_KIND => {}
        _ => return Err(invalid()),
    }
    validate_required_features(&fields)?;
    let layout = if schema_version == 1 {
        SplitLayout::Canonical
    } else {
        match required(&fields, "layout")? {
            StrictJsonValue::String(value) if value == "legacy_xc" => SplitLayout::LegacyXc,
            StrictJsonValue::String(value) if value == "legacy_ns" => SplitLayout::LegacyNs,
            StrictJsonValue::String(_) => {
                return Err(error(InputResolutionErrorCode::UnsupportedSplitLayout));
            }
            _ => return Err(invalid()),
        }
    };

    let (source_size, source_sha256) = match required(&fields, "source")? {
        StrictJsonValue::Object(source_fields) => {
            if schema_version == 2 {
                validate_exact_fields(source_fields, &["size_bytes", "sha256"])?;
            }
            (
                required_u64(source_fields, "size_bytes")?,
                required_digest(source_fields, "sha256")?,
            )
        }
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
    let mut legacy_stem: Option<String> = None;
    for (position, segment_value) in segment_values.iter().enumerate() {
        let StrictJsonValue::Object(segment_fields) = segment_value else {
            return Err(invalid());
        };
        if schema_version == 2 {
            validate_exact_fields(segment_fields, &["name", "size_bytes", "sha256"])?;
        }
        let name = match required(segment_fields, "name")? {
            StrictJsonValue::String(name) if schema_version == 1 => {
                let expected_name = format!("{position:02}");
                if name != &expected_name {
                    return Err(invalid());
                }
                name.clone()
            }
            StrictJsonValue::String(name) => {
                let suffix = layout.legacy_suffix().ok_or_else(invalid)?;
                let stem = parse_legacy_segment_name(name, suffix, position as u8)?;
                if legacy_stem
                    .as_ref()
                    .is_some_and(|expected| expected != &stem)
                {
                    return Err(invalid());
                }
                legacy_stem = Some(stem);
                name.clone()
            }
            _ => return Err(invalid()),
        };
        let size = required_u64(segment_fields, "size_bytes")?;
        if size == 0 {
            return Err(invalid());
        }
        checked_source_size = checked_source_size.checked_add(size).ok_or_else(invalid)?;
        let sha256 = required_digest(segment_fields, "sha256")?;
        segments.push(SplitManifestSegment {
            index: position as u8,
            name,
            size,
            sha256,
        });
    }
    if checked_source_size != source_size {
        return Err(invalid());
    }

    Ok(SplitManifest {
        schema_version,
        layout,
        source_size,
        source_sha256,
        segments,
    })
}

fn validate_schema_version(
    fields: &[(String, StrictJsonValue)],
) -> Result<u8, InputResolutionError> {
    match required(fields, "schema_version")? {
        StrictJsonValue::Number(number) => match number.as_u64() {
            Some(version @ (1 | 2)) => Ok(version as u8),
            Some(_) => Err(error(
                InputResolutionErrorCode::SplitManifestVersionUnsupported,
            )),
            None => Err(invalid()),
        },
        _ => Err(invalid()),
    }
}

fn validate_exact_fields(
    fields: &[(String, StrictJsonValue)],
    expected: &[&str],
) -> Result<(), InputResolutionError> {
    if fields.len() != expected.len()
        || fields
            .iter()
            .any(|(name, _)| !expected.iter().any(|expected| name == expected))
    {
        return Err(invalid());
    }
    Ok(())
}

fn parse_legacy_segment_name(
    name: &str,
    suffix: &str,
    expected_index: u8,
) -> Result<String, InputResolutionError> {
    if !is_safe_component_name(name) {
        return Err(invalid());
    }
    let marker = match suffix {
        "xc" => ".xc",
        "ns" => ".ns",
        _ => return Err(invalid()),
    };
    let Some((stem, index)) = name.rsplit_once(marker) else {
        return Err(invalid());
    };
    if index != expected_index.to_string() || !is_safe_component_name(stem) {
        return Err(invalid());
    }
    Ok(stem.to_owned())
}

pub(crate) fn legacy_segment_name(layout: SplitLayout, stem: &str, index: u8) -> Option<String> {
    let suffix = layout.legacy_suffix()?;
    let name = format!("{stem}.{suffix}{index}");
    is_safe_component_name(&name).then_some(name)
}

/// Returns the layout and index encoded in a valid legacy member name.
pub(crate) fn legacy_segment_layout_and_index(name: &str) -> Option<(SplitLayout, u8)> {
    if !is_safe_component_name(name) {
        return None;
    }
    for layout in [SplitLayout::LegacyXc, SplitLayout::LegacyNs] {
        let marker = format!(".{}", layout.legacy_suffix()?);
        let Some((stem, digits)) = name.rsplit_once(&marker) else {
            continue;
        };
        let Ok(index) = digits.parse::<u8>() else {
            continue;
        };
        if digits == index.to_string()
            && usize::from(index) < MAX_SPLIT_SEGMENTS
            && legacy_segment_name(layout, stem, index).as_deref() == Some(name)
        {
            return Some((layout, index));
        }
    }
    None
}

pub(crate) fn is_safe_component_name(name: &str) -> bool {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > 255
        || name.encode_utf16().count() > 255
        || name.ends_with(' ')
        || name.ends_with('.')
        || name.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*'
                )
        })
    {
        return false;
    }

    let device_name = name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    !matches!(
        device_name.as_str(),
        "con"
            | "prn"
            | "aux"
            | "nul"
            | "com1"
            | "com2"
            | "com3"
            | "com4"
            | "com5"
            | "com6"
            | "com7"
            | "com8"
            | "com9"
            | "lpt1"
            | "lpt2"
            | "lpt3"
            | "lpt4"
            | "lpt5"
            | "lpt6"
            | "lpt7"
            | "lpt8"
            | "lpt9"
            | "com¹"
            | "com²"
            | "com³"
            | "lpt¹"
            | "lpt²"
            | "lpt³"
    )
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
        MAX_LEGACY_SPLIT_SEGMENTS, MAX_SPLIT_MANIFEST_BYTES, MAX_SPLIT_SEGMENTS, SplitLayout,
        SplitManifestSegment, encode_legacy_manifest, encode_manifest, parse_manifest,
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

    fn legacy_manifest(layout: &str, stem: &str, segment_count: usize) -> Vec<u8> {
        let segments = (0..segment_count)
            .map(|index| {
                let suffix = match layout {
                    "legacy_xc" => "xc",
                    "legacy_ns" => "ns",
                    _ => unreachable!("test layout is supported"),
                };
                format!(
                    "{{\"name\":\"{stem}.{suffix}{index}\",\"size_bytes\":1,\"sha256\":\"{DIGEST}\"}}"
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"schema_version\":2,\"kind\":\"nscb.split_manifest\",\"required_features\":[],\"layout\":\"{layout}\",\"source\":{{\"size_bytes\":{segment_count},\"sha256\":\"{DIGEST}\"}},\"segments\":[{segments}]}}"
        )
        .into_bytes()
    }

    #[test]
    fn accepts_version_two_legacy_xc_with_unpadded_names_through_index_99() {
        let parsed = parse_manifest(&legacy_manifest("legacy_xc", "game", 100))
            .expect("v2 legacy segment names through index 99 are valid");

        assert_eq!(parsed.schema_version, 2);
        assert_eq!(parsed.layout, SplitLayout::LegacyXc);
        assert_eq!(parsed.segments.len(), 100);
        assert_eq!(parsed.segments.last().unwrap().name(), "game.xc99");
    }

    #[test]
    fn accepts_legacy_ns_layout() {
        let parsed = parse_manifest(&legacy_manifest("legacy_ns", "game", 2)).unwrap();

        assert_eq!(parsed.layout, SplitLayout::LegacyNs);
        assert_eq!(parsed.segments[0].name(), "game.ns0");
        assert_eq!(parsed.segments[1].name(), "game.ns1");
    }

    #[test]
    fn rejects_invalid_legacy_fields_names_and_stems() {
        let valid = String::from_utf8(legacy_manifest("legacy_xc", "game", 2)).unwrap();
        for document in [
            valid.replace("\"layout\":\"legacy_xc\"", "\"layout\":\"future\""),
            valid.replace("\"game.xc1\"", "\"other.xc1\""),
            valid.replace("\"game.xc0\"", "\"game.xc00\""),
            valid.replace("\"game.xc0\"", "\"game.XC0\""),
            valid.replace("\"game.xc0\"", "\"game.ns0\""),
            valid.replace("\"game.xc0\"", "\"CON.xc0\""),
            valid.replace("\"game.xc0\"", "\"../game.xc0\""),
            valid.replace("\"schema_version\":2", "\"schema_version\":2,\"future\":0"),
            valid.replace("\"layout\":\"legacy_xc\",", ""),
            valid.replace(
                "\"required_features\":[]",
                "\"required_features\":[\"future\"]",
            ),
        ] {
            assert!(
                parse_manifest(document.as_bytes()).is_err(),
                "accepted {document}"
            );
        }
        assert_eq!(
            parse_manifest(
                valid
                    .replace("\"layout\":\"legacy_xc\"", "\"layout\":\"future\"")
                    .as_bytes()
            )
            .unwrap_err()
            .code(),
            InputResolutionErrorCode::UnsupportedSplitLayout
        );
        assert_eq!(
            parse_manifest(
                valid
                    .replace(
                        "\"required_features\":[]",
                        "\"required_features\":[\"future\"]"
                    )
                    .as_bytes()
            )
            .unwrap_err()
            .code(),
            InputResolutionErrorCode::SplitManifestVersionUnsupported
        );
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
            br#"{"schema_version":3,"kind":"nscb.split_manifest","required_features":[],"source":{"size_bytes":1,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},"segments":[{"name":"00","size_bytes":1,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]}"#.as_slice(),
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
                name: "00".to_owned(),
                size: first.len() as u64,
                sha256: Sha256Digest::digest(first),
            },
            SplitManifestSegment {
                index: 1,
                name: "01".to_owned(),
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

    #[test]
    fn deterministic_legacy_writer_emits_v2_names_and_layout() {
        let source = b"abcd";
        let first = b"ab";
        let second = b"cd";
        let segments = [
            SplitManifestSegment {
                index: 0,
                name: "game.xc0".to_owned(),
                size: first.len() as u64,
                sha256: Sha256Digest::digest(first),
            },
            SplitManifestSegment {
                index: 1,
                name: "game.xc1".to_owned(),
                size: second.len() as u64,
                sha256: Sha256Digest::digest(second),
            },
        ];
        let source_sha256 = Sha256Digest::digest(source);

        let encoded = encode_legacy_manifest(
            SplitLayout::LegacyXc,
            source.len() as u64,
            source_sha256,
            &segments,
        )
        .unwrap();

        assert_eq!(
            encoded,
            format!(
                concat!(
                    "{{\n",
                    "  \"schema_version\": 2,\n",
                    "  \"kind\": \"nscb.split_manifest\",\n",
                    "  \"required_features\": [],\n",
                    "  \"layout\": \"legacy_xc\",\n",
                    "  \"source\": {{\n",
                    "    \"size_bytes\": 4,\n",
                    "    \"sha256\": \"{}\"\n",
                    "  }},\n",
                    "  \"segments\": [\n",
                    "    {{\n",
                    "      \"name\": \"game.xc0\",\n",
                    "      \"size_bytes\": 2,\n",
                    "      \"sha256\": \"{}\"\n",
                    "    }},\n",
                    "    {{\n",
                    "      \"name\": \"game.xc1\",\n",
                    "      \"size_bytes\": 2,\n",
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
        assert_eq!(parsed.schema_version, 2);
        assert_eq!(parsed.layout, SplitLayout::LegacyXc);
        assert_eq!(parsed.segments[0].name(), "game.xc0");
        assert_eq!(parsed.segments[1].name(), "game.xc1");
    }

    #[test]
    fn legacy_writer_enforces_its_ten_segment_limit() {
        let segments = (0..=MAX_LEGACY_SPLIT_SEGMENTS)
            .map(|index| SplitManifestSegment {
                index: index as u8,
                name: format!("game.xc{index}"),
                size: 1,
                sha256: Sha256Digest::digest(&[index as u8]),
            })
            .collect::<Vec<_>>();

        assert_eq!(
            encode_legacy_manifest(
                SplitLayout::LegacyXc,
                segments.len() as u64,
                Sha256Digest::digest(b"source"),
                &segments,
            )
            .unwrap_err()
            .code(),
            InputResolutionErrorCode::SplitManifestInvalid
        );
    }
}
