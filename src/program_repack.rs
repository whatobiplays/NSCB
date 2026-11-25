//! Manifest and PFS0 layout rules for the one-member Program repack profile.

use crate::allocation::{AllocationSite, reserve_exact};
use crate::partition_fs::{PartitionFsValidation, PartitionFsValidationError};
use crate::strict_json::StrictJsonValue;
use sha2::{Digest as _, Sha256};

pub(crate) const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MANIFEST_DEPTH: usize = 16;
const MAX_MANIFEST_NODES: usize = 4 * 65_536;
const MAX_MANIFEST_COLLECTION_ITEMS: usize = 4 * 65_536;
const MAX_MANIFEST_ALLOCATION_BYTES: usize = 128 * 1024 * 1024;
const MAX_DIRECTORY_RECORDS: usize = 65_536;
const PFS0_HEADER_SIZE: usize = 16;
const PFS0_ENTRY_SIZE: usize = 24;
const MAX_PFS0_ENTRIES: usize = 65_536;
const MAX_STRING_TABLE_SIZE: usize = 16 * 1024 * 1024;
const MAX_PATH_BYTES: usize = MAX_STRING_TABLE_SIZE - 1;
const MEDIA_UNIT: u64 = 0x200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManifestError {
    Malformed,
    Unsupported,
    Incomplete,
    MissingPayload,
    ResourceLimit,
    AllocationFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProgramManifest {
    pub(crate) program_id: u64,
    pub(crate) content_index: u32,
    pub(crate) partitions: Vec<ManifestPartition>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManifestPartition {
    pub(crate) index: u8,
    pub(crate) directories: Vec<String>,
    pub(crate) files: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PartitionPfs0Layout {
    pub(crate) metadata: Vec<u8>,
    pub(crate) payload_size: u64,
    pub(crate) padded_size: u64,
    pub(crate) files: Vec<PartitionPfs0File>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PartitionPfs0File {
    pub(crate) path: String,
    pub(crate) size: u64,
    pub(crate) data_offset: u64,
    pub(crate) name_offset: u32,
}

/// Parses one complete standalone Program manifest and derives its path tree.
pub(crate) fn parse_manifest(bytes: &[u8]) -> Result<ProgramManifest, ManifestError> {
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(ManifestError::ResourceLimit);
    }
    let strict = crate::strict_json::parse_program_manifest_bounded(
        bytes,
        crate::strict_json::ParseLimits {
            max_depth: MAX_MANIFEST_DEPTH,
            max_nodes: MAX_MANIFEST_NODES,
            max_collection_items: MAX_MANIFEST_COLLECTION_ITEMS,
            max_string_bytes: MAX_MANIFEST_BYTES as usize,
            max_allocation_bytes: MAX_MANIFEST_ALLOCATION_BYTES,
        },
        crate::strict_json::ProgramManifestLimits {
            max_files: MAX_PFS0_ENTRIES,
            max_directories: MAX_DIRECTORY_RECORDS,
            max_partitions: 4,
            max_file_name_bytes: MAX_PATH_BYTES,
            max_total_file_name_bytes: crate::partition_fs::MAX_TOTAL_NAME_BYTES,
            max_string_table_bytes: MAX_STRING_TABLE_SIZE,
            max_directory_path_bytes: crate::partition_fs::MAX_TOTAL_PATH_BYTES,
        },
    )
    .map_err(map_strict_json_error)?;
    let mut root = into_object(strict)?;
    let schema_version = take_u64(&mut root, "schema_version")?;
    let kind = take_string(&mut root, "kind")?;
    let selection_mode = take_string(&mut root, "selection_mode")?;
    let content_root = take_string(&mut root, "content_root")?;
    let required_features = take_value(&mut root, "required_features")?;
    let completeness = take_string(&mut root, "completeness")?;
    let mut source = into_object(take_value(&mut root, "source")?)?;
    let source_profile = take_string(&mut source, "profile")?;
    let source_role = take_string(&mut source, "role")?;
    let nca_type = take_string(&mut source, "nca_type")?;
    let program_id = parse_program_id(&take_string(&mut source, "program_id")?)?;
    let content_index = take_u32(&mut source, "content_index")?;
    if let Some(container) = take_optional_value(&mut source, "container") {
        match container {
            StrictJsonValue::Object(fields)
                if fields.iter().any(|(name, _)| {
                    matches!(name.as_str(), "profile" | "title_id" | "program_content_id")
                }) =>
            {
                return Err(ManifestError::Unsupported);
            }
            StrictJsonValue::Object(_) | StrictJsonValue::Null => {}
            _ => return Err(ManifestError::Malformed),
        }
    }

    if schema_version != 1
        || kind != "extracted_content_manifest"
        || content_root != "content"
        || source_profile != "nca3_program_partition_fs"
        || source_role != "program"
        || nca_type != "program"
        || !is_single_string(&required_features, "nca3_program_partition_fs")?
        || !matches!(selection_mode.as_str(), "all" | "selectors")
    {
        return Err(ManifestError::Unsupported);
    }
    match completeness.as_str() {
        "complete" => {}
        "incomplete" => return Err(ManifestError::Incomplete),
        _ => return Err(ManifestError::Malformed),
    }

    let partition_values = into_array(take_value(&mut root, "partitions")?)?;
    if partition_values.is_empty() || partition_values.len() > 4 {
        return Err(ManifestError::Unsupported);
    }

    let mut validation = PartitionFsValidation::default();
    let mut partitions = Vec::new();
    partitions
        .try_reserve_exact(partition_values.len())
        .map_err(|_| ManifestError::AllocationFailed)?;
    let mut total_files = 0_usize;
    let mut total_directories = 0_usize;
    let mut total_file_name_bytes = 0_usize;
    let mut total_inner_string_table_bytes = 0_usize;

    for (expected_index, partition_value) in partition_values.into_iter().enumerate() {
        let index = u8::try_from(expected_index).map_err(|_| ManifestError::Unsupported)?;
        let mut partition = into_object(partition_value)?;
        let partition_index = take_u8(&mut partition, "index")?;
        let filesystem = take_string(&mut partition, "filesystem")?;
        let directory_values = into_array(take_value(&mut partition, "directories")?)?;
        let file_values = into_array(take_value(&mut partition, "files")?)?;
        if partition_index != index || filesystem != "partition_fs" {
            return Err(ManifestError::Unsupported);
        }
        total_directories = total_directories
            .checked_add(directory_values.len())
            .ok_or(ManifestError::ResourceLimit)?;
        if total_directories > MAX_DIRECTORY_RECORDS {
            return Err(ManifestError::ResourceLimit);
        }
        total_files = total_files
            .checked_add(file_values.len())
            .ok_or(ManifestError::ResourceLimit)?;
        if total_files > MAX_PFS0_ENTRIES {
            return Err(ManifestError::ResourceLimit);
        }

        let prefix = format!("{index}/");
        let mut file_paths = Vec::new();
        file_paths
            .try_reserve_exact(file_values.len())
            .map_err(|_| ManifestError::AllocationFailed)?;
        for file_value in file_values {
            let mut file = into_object(file_value)?;
            let mut path = take_string(&mut file, "path")?;
            crate::extraction::validate_selected_relative_path(&path)
                .map_err(|_| ManifestError::Malformed)?;
            let inner_path = path.strip_prefix(&prefix).ok_or(ManifestError::Malformed)?;
            if inner_path.is_empty() {
                return Err(ManifestError::Malformed);
            }
            if inner_path.len() > MAX_PATH_BYTES {
                return Err(ManifestError::ResourceLimit);
            }
            total_file_name_bytes = total_file_name_bytes
                .checked_add(inner_path.len())
                .ok_or(ManifestError::ResourceLimit)?;
            total_inner_string_table_bytes = total_inner_string_table_bytes
                .checked_add(inner_path.len())
                .and_then(|size| size.checked_add(1))
                .ok_or(ManifestError::ResourceLimit)?;
            if total_file_name_bytes > crate::partition_fs::MAX_TOTAL_NAME_BYTES
                || total_inner_string_table_bytes > MAX_STRING_TABLE_SIZE
            {
                return Err(ManifestError::ResourceLimit);
            }
            path.drain(..prefix.len());
            file_paths.push(path);
        }

        let checked = validation
            .validate_partition(index, file_paths.iter().map(|path| (path.as_str(), 0)))
            .map_err(map_partition_error)?;
        if checked.len() != file_paths.len() {
            return Err(ManifestError::Malformed);
        }

        let mut expected_directories = Vec::new();
        expected_directories
            .try_reserve_exact(validation.expected_directories().len())
            .map_err(|_| ManifestError::AllocationFailed)?;
        for directory in validation.expected_directories() {
            if directory == &index.to_string() || directory.starts_with(&prefix) {
                expected_directories.push(directory.clone());
            }
        }
        let mut declared_directories = Vec::new();
        declared_directories
            .try_reserve_exact(directory_values.len())
            .map_err(|_| ManifestError::AllocationFailed)?;
        for directory_value in directory_values {
            let directory = into_string(directory_value)?;
            crate::extraction::validate_selected_relative_path(&directory)
                .map_err(|_| ManifestError::Malformed)?;
            declared_directories.push(directory);
        }
        expected_directories.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        declared_directories.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        if expected_directories != declared_directories {
            return Err(ManifestError::Malformed);
        }

        file_paths.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let mut full_paths = Vec::new();
        full_paths
            .try_reserve_exact(file_paths.len())
            .map_err(|_| ManifestError::AllocationFailed)?;
        for path in file_paths {
            let mut full = String::new();
            full.try_reserve_exact(prefix.len().saturating_add(path.len()))
                .map_err(|_| ManifestError::AllocationFailed)?;
            full.push_str(&prefix);
            full.push_str(&path);
            full_paths.push(full);
        }
        crate::extraction::validate_selected_path_aliases(
            &full_paths,
            &declared_directories,
            &full_paths,
            &declared_directories,
        )
        .map_err(|error| match error {
            crate::extraction::ExtractionValidationError::PathCollision => ManifestError::Malformed,
            crate::extraction::ExtractionValidationError::ResourceLimitExceeded => {
                ManifestError::AllocationFailed
            }
            _ => ManifestError::Malformed,
        })?;
        partitions.push(ManifestPartition {
            index,
            directories: declared_directories,
            files: full_paths,
        });
    }

    if total_files == 0 {
        return Err(ManifestError::MissingPayload);
    }
    Ok(ProgramManifest {
        program_id,
        content_index,
        partitions,
    })
}

/// Builds deterministic PFS0 metadata for one clear PartitionFs section.
pub(crate) fn build_partition_layout(
    files: &[(String, u64)],
) -> Result<PartitionPfs0Layout, ManifestError> {
    if files.len() > MAX_PFS0_ENTRIES {
        return Err(ManifestError::ResourceLimit);
    }
    let mut string_table_size = 0_usize;
    for (path, _) in files {
        crate::extraction::validate_selected_relative_path(path)
            .map_err(|_| ManifestError::Malformed)?;
        if path.len() > MAX_PATH_BYTES {
            return Err(ManifestError::ResourceLimit);
        }
        string_table_size = string_table_size
            .checked_add(path.len())
            .and_then(|size| size.checked_add(1))
            .ok_or(ManifestError::ResourceLimit)?;
        if string_table_size > MAX_STRING_TABLE_SIZE {
            return Err(ManifestError::ResourceLimit);
        }
    }
    let mut ordered = Vec::new();
    ordered
        .try_reserve_exact(files.len())
        .map_err(|_| ManifestError::AllocationFailed)?;
    for (path, size) in files {
        let mut copied_path = String::new();
        copied_path
            .try_reserve_exact(path.len())
            .map_err(|_| ManifestError::AllocationFailed)?;
        copied_path.push_str(path);
        ordered.push((copied_path, *size));
    }
    ordered.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));

    let mut string_table = Vec::new();
    let mut layout_files = Vec::new();
    let mut name_offsets = Vec::new();
    let mut payload_size = 0_u64;
    layout_files
        .try_reserve_exact(ordered.len())
        .map_err(|_| ManifestError::AllocationFailed)?;
    name_offsets
        .try_reserve_exact(ordered.len())
        .map_err(|_| ManifestError::AllocationFailed)?;
    for (path, size) in ordered {
        if path.len() > MAX_PATH_BYTES
            || layout_files
                .last()
                .is_some_and(|previous: &PartitionPfs0File| previous.path == path)
        {
            return Err(ManifestError::Malformed);
        }
        crate::extraction::validate_selected_relative_path(&path)
            .map_err(|_| ManifestError::Malformed)?;
        let name_offset =
            u32::try_from(string_table.len()).map_err(|_| ManifestError::ResourceLimit)?;
        let next_table_size = string_table
            .len()
            .checked_add(path.len())
            .and_then(|size| size.checked_add(1))
            .ok_or(ManifestError::ResourceLimit)?;
        if next_table_size > MAX_STRING_TABLE_SIZE {
            return Err(ManifestError::ResourceLimit);
        }
        string_table
            .try_reserve(path.len().saturating_add(1))
            .map_err(|_| ManifestError::AllocationFailed)?;
        string_table.extend_from_slice(path.as_bytes());
        string_table.push(0);
        name_offsets.push(name_offset);
        layout_files.push(PartitionPfs0File {
            path,
            size,
            data_offset: payload_size,
            name_offset,
        });
        payload_size = payload_size
            .checked_add(size)
            .ok_or(ManifestError::ResourceLimit)?;
    }

    let entry_bytes = layout_files
        .len()
        .checked_mul(PFS0_ENTRY_SIZE)
        .ok_or(ManifestError::ResourceLimit)?;
    let metadata_size = PFS0_HEADER_SIZE
        .checked_add(entry_bytes)
        .and_then(|size| size.checked_add(string_table.len()))
        .ok_or(ManifestError::ResourceLimit)?;
    let mut metadata = Vec::new();
    reserve_exact(&mut metadata, metadata_size, AllocationSite::Pfs0Metadata)
        .map_err(|_| ManifestError::AllocationFailed)?;
    let mut header = [0_u8; PFS0_HEADER_SIZE];
    header[..4].copy_from_slice(b"PFS0");
    header[4..8].copy_from_slice(
        &u32::try_from(layout_files.len())
            .map_err(|_| ManifestError::ResourceLimit)?
            .to_le_bytes(),
    );
    header[8..12].copy_from_slice(
        &u32::try_from(string_table.len())
            .map_err(|_| ManifestError::ResourceLimit)?
            .to_le_bytes(),
    );
    metadata.extend_from_slice(&header);
    for (index, file) in layout_files.iter().enumerate() {
        metadata.extend_from_slice(&file.data_offset.to_le_bytes());
        metadata.extend_from_slice(&file.size.to_le_bytes());
        metadata.extend_from_slice(
            &name_offsets
                .get(index)
                .copied()
                .ok_or(ManifestError::Malformed)?
                .to_le_bytes(),
        );
        metadata.extend_from_slice(&0_u32.to_le_bytes());
    }
    metadata.extend_from_slice(&string_table);

    let unpadded = u64::try_from(metadata.len())
        .map_err(|_| ManifestError::ResourceLimit)?
        .checked_add(payload_size)
        .ok_or(ManifestError::ResourceLimit)?;
    let padded_size = align_up(unpadded, MEDIA_UNIT)?;
    Ok(PartitionPfs0Layout {
        metadata,
        payload_size,
        padded_size,
        files: layout_files,
    })
}

fn map_strict_json_error(error: crate::strict_json::BoundedParseError) -> ManifestError {
    match error {
        crate::strict_json::BoundedParseError::Malformed => ManifestError::Malformed,
        crate::strict_json::BoundedParseError::ResourceLimit => ManifestError::ResourceLimit,
        crate::strict_json::BoundedParseError::AllocationFailed => ManifestError::AllocationFailed,
    }
}

fn into_object(value: StrictJsonValue) -> Result<Vec<(String, StrictJsonValue)>, ManifestError> {
    match value {
        StrictJsonValue::Object(fields) => Ok(fields),
        _ => Err(ManifestError::Malformed),
    }
}

fn into_array(value: StrictJsonValue) -> Result<Vec<StrictJsonValue>, ManifestError> {
    match value {
        StrictJsonValue::Array(values) => Ok(values),
        _ => Err(ManifestError::Malformed),
    }
}

fn into_string(value: StrictJsonValue) -> Result<String, ManifestError> {
    match value {
        StrictJsonValue::String(value) => Ok(value),
        _ => Err(ManifestError::Malformed),
    }
}

fn take_value(
    fields: &mut Vec<(String, StrictJsonValue)>,
    name: &str,
) -> Result<StrictJsonValue, ManifestError> {
    take_optional_value(fields, name).ok_or(ManifestError::Malformed)
}

fn take_optional_value(
    fields: &mut Vec<(String, StrictJsonValue)>,
    name: &str,
) -> Option<StrictJsonValue> {
    fields
        .iter()
        .position(|(field_name, _)| field_name == name)
        .map(|index| fields.swap_remove(index).1)
}

fn take_string(
    fields: &mut Vec<(String, StrictJsonValue)>,
    name: &str,
) -> Result<String, ManifestError> {
    into_string(take_value(fields, name)?)
}

fn take_u64(fields: &mut Vec<(String, StrictJsonValue)>, name: &str) -> Result<u64, ManifestError> {
    match take_value(fields, name)? {
        StrictJsonValue::Number(value) => value.as_u64().ok_or(ManifestError::Malformed),
        _ => Err(ManifestError::Malformed),
    }
}

fn take_u32(fields: &mut Vec<(String, StrictJsonValue)>, name: &str) -> Result<u32, ManifestError> {
    u32::try_from(take_u64(fields, name)?).map_err(|_| ManifestError::Malformed)
}

fn take_u8(fields: &mut Vec<(String, StrictJsonValue)>, name: &str) -> Result<u8, ManifestError> {
    u8::try_from(take_u64(fields, name)?).map_err(|_| ManifestError::Malformed)
}

fn is_single_string(value: &StrictJsonValue, expected: &str) -> Result<bool, ManifestError> {
    let StrictJsonValue::Array(values) = value else {
        return Err(ManifestError::Malformed);
    };
    match values.as_slice() {
        [StrictJsonValue::String(value)] => Ok(value == expected),
        values
            if values
                .iter()
                .all(|value| matches!(value, StrictJsonValue::String(_))) =>
        {
            Ok(false)
        }
        _ => Err(ManifestError::Malformed),
    }
}

pub(crate) fn build_nca_header(
    manifest: &ProgramManifest,
    partition_sizes: &[u64],
    total_size: u64,
) -> Result<[u8; crate::nca::HEADER_SIZE], ManifestError> {
    if partition_sizes.len() != manifest.partitions.len() {
        return Err(ManifestError::Malformed);
    }
    let mut header = [0_u8; crate::nca::HEADER_SIZE];
    header[0x200..0x204].copy_from_slice(b"NCA3");
    header[0x204] = 0;
    header[0x205] = 0;
    header[0x206] = 0;
    header[0x207] = 0;
    header[0x208..0x210].copy_from_slice(&total_size.to_le_bytes());
    header[0x210..0x218].copy_from_slice(&manifest.program_id.to_le_bytes());
    header[0x218..0x21c].copy_from_slice(&manifest.content_index.to_le_bytes());
    header[0x220] = 0;
    header[0x221] = 0;

    let mut offset = crate::nca::HEADER_SIZE as u64;
    for (index, size) in partition_sizes.iter().copied().enumerate() {
        if size == 0 || !size.is_multiple_of(MEDIA_UNIT) {
            return Err(ManifestError::Malformed);
        }
        let end = offset
            .checked_add(size)
            .ok_or(ManifestError::ResourceLimit)?;
        let start_page =
            u32::try_from(offset / MEDIA_UNIT).map_err(|_| ManifestError::ResourceLimit)?;
        let end_page = u32::try_from(end / MEDIA_UNIT).map_err(|_| ManifestError::ResourceLimit)?;
        let descriptor = 0x240 + index * 0x10;
        header[descriptor..descriptor + 4].copy_from_slice(&start_page.to_le_bytes());
        header[descriptor + 4..descriptor + 8].copy_from_slice(&end_page.to_le_bytes());
        header[descriptor + 8] = 1;

        let fs_offset = 0x400 + index * 0x200;
        header[fs_offset..fs_offset + 6].copy_from_slice(&[2, 0, 1, 1, 1, 0]);
        let digest = Sha256::digest(&header[fs_offset..fs_offset + 0x200]);
        let digest_offset = 0x280 + index * 0x20;
        header[digest_offset..digest_offset + 0x20].copy_from_slice(&digest);
        offset = end;
    }
    if offset != total_size {
        return Err(ManifestError::Malformed);
    }
    Ok(header)
}

pub(crate) fn align_up(value: u64, alignment: u64) -> Result<u64, ManifestError> {
    value
        .checked_add(alignment - 1)
        .map(|rounded| rounded / alignment * alignment)
        .ok_or(ManifestError::ResourceLimit)
}

fn parse_program_id(value: &str) -> Result<u64, ManifestError> {
    if value.len() != 16
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ManifestError::Malformed);
    }
    u64::from_str_radix(value, 16).map_err(|_| ManifestError::Malformed)
}

fn map_partition_error(error: PartitionFsValidationError) -> ManifestError {
    match error {
        PartitionFsValidationError::UnsupportedProfile
        | PartitionFsValidationError::MalformedInput => ManifestError::Malformed,
        PartitionFsValidationError::InputLimitExceeded => ManifestError::ResourceLimit,
        PartitionFsValidationError::AllocationFailed => ManifestError::AllocationFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_PFS0_ENTRIES, MAX_STRING_TABLE_SIZE, ManifestError, build_partition_layout,
        parse_manifest,
    };
    use crate::nca::{ContentType, Distribution, parse_header_block};
    use std::fmt::Write as _;

    const MANIFEST: &[u8] = br#"{"schema_version":1,"kind":"extracted_content_manifest","selection_mode":"all","content_root":"content","required_features":["nca3_program_partition_fs"],"completeness":"complete","source":{"profile":"nca3_program_partition_fs","role":"program","nca_type":"program","program_id":"0102030405060708","content_index":0},"partitions":[{"index":0,"filesystem":"partition_fs","directories":["0","0/nested"],"files":[{"path":"0/nested/data.bin"},{"path":"0/empty.bin"}]},{"index":1,"filesystem":"partition_fs","directories":["1"],"files":[]}]}"#;

    #[test]
    fn accepts_complete_standalone_manifests_with_additive_fields() {
        let bytes = String::from_utf8(MANIFEST.to_vec()).unwrap().replace(
            "\"content_root\":\"content\"",
            "\"content_root\":\"content\",\"future_optional\":true",
        );
        let parsed = parse_manifest(bytes.as_bytes()).unwrap();

        assert_eq!(parsed.program_id, 0x0102_0304_0506_0708);
        assert_eq!(parsed.partitions.len(), 2);
        assert_eq!(
            parsed.partitions[0].files,
            ["0/empty.bin", "0/nested/data.bin"]
        );
        assert_eq!(parsed.partitions[1].directories, ["1"]);
    }

    #[test]
    fn accepts_a_complete_selector_manifest() {
        let bytes = String::from_utf8(MANIFEST.to_vec()).unwrap().replace(
            "\"selection_mode\":\"all\"",
            "\"selection_mode\":\"selectors\"",
        );

        assert!(parse_manifest(bytes.as_bytes()).is_ok());
    }

    #[test]
    fn rejects_portable_file_and_directory_aliases() {
        let cases = [
            (
                "\"directories\":[\"0\",\"0/nested\"],\"files\":[{\"path\":\"0/nested/data.bin\"},{\"path\":\"0/empty.bin\"}]",
                "\"directories\":[\"0\"],\"files\":[{\"path\":\"0/Foo.bin\"},{\"path\":\"0/foo.bin\"}]",
            ),
            (
                "\"directories\":[\"0\",\"0/nested\"],\"files\":[{\"path\":\"0/nested/data.bin\"},{\"path\":\"0/empty.bin\"}]",
                "\"directories\":[\"0\",\"0/data\"],\"files\":[{\"path\":\"0/Data\"},{\"path\":\"0/data/child.bin\"}]",
            ),
            (
                "\"directories\":[\"0\",\"0/nested\"],\"files\":[{\"path\":\"0/nested/data.bin\"},{\"path\":\"0/empty.bin\"}]",
                "\"directories\":[\"0\",\"0/A\",\"0/a\"],\"files\":[{\"path\":\"0/A/one.bin\"},{\"path\":\"0/a/two.bin\"}]",
            ),
        ];

        for (old, new) in cases {
            let bytes = String::from_utf8(MANIFEST.to_vec())
                .unwrap()
                .replace(old, new);
            assert_eq!(
                parse_manifest(bytes.as_bytes()),
                Err(ManifestError::Malformed),
                "{new}"
            );
        }
    }

    #[test]
    fn rejects_known_container_metadata_but_accepts_unknown_optional_fields() {
        let standalone_with_container = String::from_utf8(MANIFEST.to_vec()).unwrap().replace(
            "\"content_index\":0",
            "\"content_index\":0,\"container\":{\"profile\":\"rights_free_base_application_v1\"}",
        );
        assert_eq!(
            parse_manifest(standalone_with_container.as_bytes()),
            Err(ManifestError::Unsupported)
        );

        let standalone_with_unknown_container_field =
            String::from_utf8(MANIFEST.to_vec()).unwrap().replace(
                "\"content_index\":0",
                "\"content_index\":0,\"container\":{\"future_optional\":true}",
            );
        assert!(parse_manifest(standalone_with_unknown_container_field.as_bytes()).is_ok());

        let nsp_program = String::from_utf8(MANIFEST.to_vec())
            .unwrap()
            .replace(
                "nca3_program_partition_fs",
                "nca3_program_partition_fs_hierarchical_sha256_aes_ctr",
            )
            .replace(
                "\"required_features\":[\"nca3_program_partition_fs_hierarchical_sha256_aes_ctr\"]",
                "\"required_features\":[\"nca3_program_partition_fs_hierarchical_sha256_aes_ctr\",\"rights_free_base_application_v1\"]",
            )
            .replace(
                "\"content_index\":0",
                "\"content_index\":0,\"container\":{\"profile\":\"rights_free_base_application_v1\",\"title_id\":\"0102030405060708\",\"program_content_id\":\"0123456789abcdef0123456789abcdef\"}",
            );
        assert_eq!(
            parse_manifest(nsp_program.as_bytes()),
            Err(ManifestError::Unsupported)
        );
    }

    #[test]
    fn rejects_extractor_emitted_nsp_features_for_standalone_repack() {
        let nsp_required_features = String::from_utf8(MANIFEST.to_vec())
            .unwrap()
            .replace(
                "\"required_features\":[\"nca3_program_partition_fs\"]",
                "\"required_features\":[\"nca3_program_partition_fs_hierarchical_sha256_aes_ctr\",\"rights_free_base_application_v1\"]",
            );
        assert_eq!(
            parse_manifest(nsp_required_features.as_bytes()),
            Err(ManifestError::Unsupported)
        );
    }

    #[test]
    fn distinguishes_incomplete_and_unsupported_manifests() {
        let incomplete = String::from_utf8(MANIFEST.to_vec()).unwrap().replace(
            "\"completeness\":\"complete\"",
            "\"completeness\":\"incomplete\"",
        );
        assert_eq!(
            parse_manifest(incomplete.as_bytes()),
            Err(ManifestError::Incomplete)
        );

        let unsupported = String::from_utf8(MANIFEST.to_vec())
            .unwrap()
            .replace("nca3_program_partition_fs", "unsupported_profile");
        assert_eq!(
            parse_manifest(unsupported.as_bytes()),
            Err(ManifestError::Unsupported)
        );

        let unknown_completeness = String::from_utf8(MANIFEST.to_vec()).unwrap().replace(
            "\"completeness\":\"complete\"",
            "\"completeness\":\"partial\"",
        );
        assert_eq!(
            parse_manifest(unknown_completeness.as_bytes()),
            Err(ManifestError::Malformed)
        );

        let malformed_completeness = String::from_utf8(MANIFEST.to_vec())
            .unwrap()
            .replace("\"completeness\":\"complete\"", "\"completeness\":false");
        assert_eq!(
            parse_manifest(malformed_completeness.as_bytes()),
            Err(ManifestError::Malformed)
        );

        let unsupported_schema = String::from_utf8(MANIFEST.to_vec())
            .unwrap()
            .replace("\"schema_version\":1", "\"schema_version\":2");
        assert_eq!(
            parse_manifest(unsupported_schema.as_bytes()),
            Err(ManifestError::Unsupported)
        );

        let unsupported_feature = String::from_utf8(MANIFEST.to_vec())
            .unwrap()
            .replace("nca3_program_partition_fs", "unsupported_program_feature");
        assert_eq!(
            parse_manifest(unsupported_feature.as_bytes()),
            Err(ManifestError::Unsupported)
        );
    }

    #[test]
    fn rejects_duplicate_keys_and_empty_manifest_file_sets() {
        assert_eq!(
            parse_manifest(br#"{"schema_version":1,"schema_version":1}"#),
            Err(ManifestError::Malformed)
        );
        let empty = String::from_utf8(MANIFEST.to_vec())
            .unwrap()
            .replace(
                "\"directories\":[\"0\",\"0/nested\"],\"files\":[{\"path\":\"0/nested/data.bin\"},{\"path\":\"0/empty.bin\"}]",
                "\"directories\":[\"0\"],\"files\":[]",
            );
        assert_eq!(
            parse_manifest(empty.as_bytes()),
            Err(ManifestError::MissingPayload)
        );
    }

    #[test]
    fn accepts_file_and_directory_record_limits_and_rejects_one_over() {
        let exact_files = manifest_with_flat_files(MAX_PFS0_ENTRIES);
        let parsed = parse_manifest(exact_files.as_bytes()).unwrap();
        assert_eq!(parsed.partitions[0].files.len(), MAX_PFS0_ENTRIES);

        let excess_files = manifest_with_flat_files(MAX_PFS0_ENTRIES + 1);
        assert_eq!(
            parse_manifest(excess_files.as_bytes()),
            Err(ManifestError::ResourceLimit)
        );

        let exact_directories = manifest_with_child_directories(MAX_PFS0_ENTRIES - 1);
        let parsed = parse_manifest(exact_directories.as_bytes()).unwrap();
        assert_eq!(parsed.partitions[0].directories.len(), MAX_PFS0_ENTRIES);

        let excess_directories = manifest_with_child_directories(MAX_PFS0_ENTRIES);
        assert_eq!(
            parse_manifest(excess_directories.as_bytes()),
            Err(ManifestError::ResourceLimit)
        );
    }

    #[test]
    fn accepts_extractor_valid_paths_longer_than_four_kib() {
        let long_name = relative_path_with_length(4351);
        let manifest = manifest_with_one_path(&long_name);
        assert!(parse_manifest(manifest.as_bytes()).is_ok());
    }

    #[test]
    fn enforces_manifest_depth_at_the_limit_and_before_one_over() {
        let exact_nested_value = format!("{}null{}", "[".repeat(14), "]".repeat(14));
        let exact_depth = String::from_utf8(MANIFEST.to_vec()).unwrap().replace(
            "\"content_root\":\"content\"",
            &format!("\"content_root\":\"content\",\"future_optional\":{exact_nested_value}"),
        );
        assert!(parse_manifest(exact_depth.as_bytes()).is_ok());

        let over_nested_value = format!("{}null{}", "[".repeat(15), "]".repeat(15));
        let over_depth = String::from_utf8(MANIFEST.to_vec()).unwrap().replace(
            "\"content_root\":\"content\"",
            &format!("\"content_root\":\"content\",\"future_optional\":{over_nested_value}"),
        );
        assert_eq!(
            parse_manifest(over_depth.as_bytes()),
            Err(ManifestError::ResourceLimit)
        );
    }

    #[test]
    fn enforces_the_inner_pfs0_string_table_boundary_before_copying_names() {
        const LONG_LAYOUT_ENTRY_BYTES: usize = 4 * 1024;
        let exact = long_layout_paths(MAX_STRING_TABLE_SIZE / LONG_LAYOUT_ENTRY_BYTES);
        let layout = build_partition_layout(&exact).unwrap();
        assert_eq!(
            layout.metadata.len() - 16 - layout.files.len() * 24,
            MAX_STRING_TABLE_SIZE
        );

        let over = long_layout_paths(MAX_STRING_TABLE_SIZE / LONG_LAYOUT_ENTRY_BYTES + 1);
        assert_eq!(
            build_partition_layout(&over),
            Err(ManifestError::ResourceLimit)
        );
    }

    #[test]
    fn inner_pfs0_layout_preserves_nested_and_zero_length_files() {
        let layout = build_partition_layout(&[
            ("nested/data.bin".to_owned(), 3),
            ("empty.bin".to_owned(), 0),
        ])
        .unwrap();
        assert_eq!(layout.files[0].path, "empty.bin");
        assert_eq!(layout.files[0].size, 0);
        assert!(layout.padded_size.is_multiple_of(0x200));
        assert_eq!(&layout.metadata[..4], b"PFS0");
    }

    #[test]
    fn canonical_header_parses_as_clear_program_partition_fs() {
        let manifest = parse_manifest(MANIFEST).unwrap();
        let header = super::build_nca_header(&manifest, &[0x200, 0x200], 0x1000).unwrap();
        let parsed = parse_header_block(&header, 0x1000).unwrap();

        assert_eq!(parsed.distribution, Distribution::Download);
        assert_eq!(parsed.content_type, ContentType::Program);
        assert_eq!(parsed.program_id, manifest.program_id);
        assert_eq!(parsed.content_index, manifest.content_index);
        assert_eq!(parsed.partitions.len(), 2);
        assert!(crate::verification::fs_header_hash_matches(&header, 0));
        assert!(crate::verification::fs_header_hash_matches(&header, 1));
    }

    fn manifest_with_flat_files(file_count: usize) -> String {
        let mut files = String::new();
        for index in 0..file_count {
            if index > 0 {
                files.push(',');
            }
            write!(files, "{{\"path\":\"0/file-{index:05}.bin\"}}").unwrap();
        }
        wrap_manifest("[\"0\"]", &files)
    }

    fn manifest_with_child_directories(directory_count: usize) -> String {
        let mut directories = String::from("\"0\"");
        let mut files = String::new();
        for index in 0..directory_count {
            let directory = format!("d{index:05}");
            write!(directories, ",\"0/{directory}\"").unwrap();
            if index > 0 {
                files.push(',');
            }
            write!(files, "{{\"path\":\"0/{directory}/file.bin\"}}").unwrap();
        }
        let mut manifest = wrap_manifest("[]", &files);
        manifest = manifest.replace(
            "\"directories\":[]",
            &format!("\"directories\":[{directories}]"),
        );
        manifest
    }

    fn manifest_with_one_path(path: &str) -> String {
        let mut directories = vec!["0".to_owned()];
        let mut prefix = String::from("0");
        let components = path.split('/').collect::<Vec<_>>();
        for component in &components[..components.len() - 1] {
            prefix.push('/');
            prefix.push_str(component);
            directories.push(prefix.clone());
        }
        directories.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let directory_json = directories
            .iter()
            .map(|directory| format!("\"{directory}\""))
            .collect::<Vec<_>>()
            .join(",");
        let files = format!("{{\"path\":\"0/{path}\"}}");
        wrap_manifest(&format!("[{directory_json}]"), &files)
    }

    fn wrap_manifest(directories: &str, files: &str) -> String {
        format!(
            "{{\"schema_version\":1,\"kind\":\"extracted_content_manifest\",\"selection_mode\":\"all\",\"content_root\":\"content\",\"required_features\":[\"nca3_program_partition_fs\"],\"completeness\":\"complete\",\"source\":{{\"profile\":\"nca3_program_partition_fs\",\"role\":\"program\",\"nca_type\":\"program\",\"program_id\":\"0102030405060708\",\"content_index\":0}},\"partitions\":[{{\"index\":0,\"filesystem\":\"partition_fs\",\"directories\":{directories},\"files\":[{files}]}}]}}"
        )
    }

    fn relative_path_with_length(length: usize) -> String {
        let component_count = (length + 1).div_ceil(256);
        let total_component_bytes = length - (component_count - 1);
        let base = total_component_bytes / component_count;
        let extra = total_component_bytes % component_count;
        let components = (0..component_count)
            .map(|index| "a".repeat(base + usize::from(index < extra)))
            .collect::<Vec<_>>();
        components.join("/")
    }

    fn long_layout_paths(file_count: usize) -> Vec<(String, u64)> {
        (0..file_count)
            .map(|index| {
                let first = format!("f{index:04}{}", "a".repeat(250));
                let mut path = first;
                for _ in 1..16 {
                    path.push('/');
                    path.push_str(&"b".repeat(255));
                }
                (path, 0)
            })
            .collect()
    }
}
