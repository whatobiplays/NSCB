//! Shared, bounded validation for qualified PartitionFs metadata.
//!
//! The container probe validates the PFS0 table's byte ranges. This module adds
//! the path-level checks used by both Inspection and Verification: accepted
//! relative names, unique paths within a partition, regular-file/directory
//! hierarchy conflicts, path-segment limits, and cumulative entry, name, and
//! path budgets.

use std::collections::{BTreeMap, HashSet};

pub(crate) const MAX_TOTAL_ENTRIES: usize = 65_536;
pub(crate) const MAX_TOTAL_NAME_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_TOTAL_PATH_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_PATH_SEGMENTS: usize = 62;

/// A stable validation category independent of a caller's public error type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PartitionFsValidationError {
    /// A name is not a normalized relative path in the qualified profile.
    UnsupportedProfile,
    /// Two entries resolve to the same normalized path, or a path must be both
    /// a regular file and a directory.
    MalformedInput,
    /// One of the explicit entry, name, path, or segment limits was exceeded.
    InputLimitExceeded,
    /// A bounded allocation could not be reserved.
    AllocationFailed,
}

/// Accumulates budgets and expected tree paths across all validated partitions.
#[derive(Default)]
pub(crate) struct PartitionFsValidation {
    total_entries: usize,
    total_name_bytes: usize,
    total_path_bytes: usize,
    expected_directories: HashSet<String>,
    expected_files: HashSet<String>,
}

impl PartitionFsValidation {
    /// Validates one partition and returns its normalized path-to-size map.
    pub(crate) fn validate_partition<'a, I>(
        &mut self,
        partition_index: u8,
        entries: I,
    ) -> Result<BTreeMap<String, u64>, PartitionFsValidationError>
    where
        I: IntoIterator<Item = (&'a str, u64)>,
    {
        let partition_directory = partition_index.to_string();
        charge_expected_path(&mut self.total_path_bytes, partition_directory.len())?;
        self.expected_directories
            .try_reserve(1)
            .map_err(|_| PartitionFsValidationError::AllocationFailed)?;
        self.expected_directories.insert(partition_directory);

        let mut validated_entries = BTreeMap::new();
        for (name, size) in entries {
            let normalized = normalize_entry_name(name)?;
            self.total_entries = self
                .total_entries
                .checked_add(1)
                .ok_or(PartitionFsValidationError::InputLimitExceeded)?;
            if self.total_entries > MAX_TOTAL_ENTRIES {
                return Err(PartitionFsValidationError::InputLimitExceeded);
            }
            self.total_name_bytes = self
                .total_name_bytes
                .checked_add(normalized.len())
                .ok_or(PartitionFsValidationError::InputLimitExceeded)?;
            if self.total_name_bytes > MAX_TOTAL_NAME_BYTES {
                return Err(PartitionFsValidationError::InputLimitExceeded);
            }

            let mut entry_path = String::new();
            entry_path
                .try_reserve_exact(normalized.len())
                .map_err(|_| PartitionFsValidationError::AllocationFailed)?;
            entry_path.push_str(&normalized);
            if validated_entries.insert(entry_path.clone(), size).is_some() {
                return Err(PartitionFsValidationError::MalformedInput);
            }
            add_expected_path(
                partition_index,
                &normalized,
                &mut self.expected_directories,
                &mut self.expected_files,
                &mut self.total_path_bytes,
            )?;
        }
        Ok(validated_entries)
    }

    /// Returns the expected provider directory paths accumulated so far.
    pub(crate) fn expected_directories(&self) -> &HashSet<String> {
        &self.expected_directories
    }

    /// Returns the expected provider file paths accumulated so far.
    pub(crate) fn expected_files(&self) -> &HashSet<String> {
        &self.expected_files
    }

    /// Returns the number of entries accepted across all partitions so far.
    pub(crate) fn total_entries(&self) -> usize {
        self.total_entries
    }
}

fn add_expected_path(
    partition: u8,
    path: &str,
    directories: &mut HashSet<String>,
    files: &mut HashSet<String>,
    total_path_bytes: &mut usize,
) -> Result<(), PartitionFsValidationError> {
    let mut current = partition.to_string();
    current
        .try_reserve_exact(path.len().saturating_add(1))
        .map_err(|_| PartitionFsValidationError::AllocationFailed)?;
    let mut segments = path.split('/').peekable();
    let mut segment_count = 0_usize;
    while let Some(segment) = segments.next() {
        segment_count = segment_count
            .checked_add(1)
            .ok_or(PartitionFsValidationError::InputLimitExceeded)?;
        if segment_count > MAX_PATH_SEGMENTS {
            return Err(PartitionFsValidationError::InputLimitExceeded);
        }
        current.push('/');
        current.push_str(segment);
        if segments.peek().is_some() && !directories.contains(&current) {
            if files.contains(&current) {
                return Err(PartitionFsValidationError::MalformedInput);
            }
            charge_expected_path(total_path_bytes, current.len())?;
            directories
                .try_reserve(1)
                .map_err(|_| PartitionFsValidationError::AllocationFailed)?;
            let mut directory = String::new();
            directory
                .try_reserve_exact(current.len())
                .map_err(|_| PartitionFsValidationError::AllocationFailed)?;
            directory.push_str(&current);
            directories.insert(directory);
        }
    }
    if directories.contains(&current) || files.contains(&current) {
        return Err(PartitionFsValidationError::MalformedInput);
    }
    charge_expected_path(total_path_bytes, current.len())?;
    files
        .try_reserve(1)
        .map_err(|_| PartitionFsValidationError::AllocationFailed)?;
    files.insert(current);
    Ok(())
}

fn charge_expected_path(
    total: &mut usize,
    amount: usize,
) -> Result<(), PartitionFsValidationError> {
    *total = total
        .checked_add(amount)
        .ok_or(PartitionFsValidationError::InputLimitExceeded)?;
    if *total > MAX_TOTAL_PATH_BYTES {
        return Err(PartitionFsValidationError::InputLimitExceeded);
    }
    Ok(())
}

fn normalize_entry_name(name: &str) -> Result<String, PartitionFsValidationError> {
    if name.is_empty()
        || name.starts_with('/')
        || name.ends_with('/')
        || name.contains("//")
        || name.contains('\\')
        || name.chars().any(char::is_control)
    {
        return Err(PartitionFsValidationError::UnsupportedProfile);
    }
    for segment in name.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." || segment.trim() != segment {
            return Err(PartitionFsValidationError::UnsupportedProfile);
        }
    }
    Ok(name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_PATH_SEGMENTS, MAX_TOTAL_ENTRIES, PartitionFsValidation, PartitionFsValidationError,
    };

    #[test]
    fn accepts_normalized_paths_and_tracks_tree_paths() {
        let mut validation = PartitionFsValidation::default();
        let entries = validation
            .validate_partition(0, [("dir/file.bin", 3), ("root.bin", 1)])
            .unwrap();
        assert_eq!(entries.get("dir/file.bin"), Some(&3));
        assert!(validation.expected_directories().contains("0/dir"));
        assert!(validation.expected_files().contains("0/dir/file.bin"));
        assert!(validation.expected_files().contains("0/root.bin"));
    }

    #[test]
    fn rejects_file_and_directory_hierarchy_conflicts() {
        for entries in [
            [("a", 1), ("a/b", 2)],
            [("a/b", 2), ("a", 1)],
            [("a/b/c", 3), ("a/b", 1)],
            [("a/b", 1), ("a/b/c", 3)],
            [("a", 1), ("a/b/c/d", 4)],
            [("a/b/c/d", 4), ("a", 1)],
        ] {
            assert_eq!(
                PartitionFsValidation::default()
                    .validate_partition(0, entries)
                    .unwrap_err(),
                PartitionFsValidationError::MalformedInput
            );
        }
    }

    #[test]
    fn accepts_valid_nested_paths() {
        let mut validation = PartitionFsValidation::default();
        validation
            .validate_partition(0, [("a/b", 1), ("a/c", 2), ("d/e/f", 3)])
            .unwrap();
        assert!(validation.expected_directories().contains("0/a"));
        assert!(validation.expected_directories().contains("0/d"));
        assert!(validation.expected_directories().contains("0/d/e"));
        assert!(validation.expected_files().contains("0/a/b"));
        assert!(validation.expected_files().contains("0/d/e/f"));
    }

    #[test]
    fn rejects_duplicate_and_non_normalized_names() {
        let mut duplicate = PartitionFsValidation::default();
        assert_eq!(
            duplicate
                .validate_partition(0, [("same.bin", 1), ("same.bin", 2)])
                .unwrap_err(),
            PartitionFsValidationError::MalformedInput
        );
        for name in ["../x", "./x", "/x", "x/", "x//y", "x\\y", "x/../y"] {
            assert_eq!(
                PartitionFsValidation::default()
                    .validate_partition(0, [(name, 1)])
                    .unwrap_err(),
                PartitionFsValidationError::UnsupportedProfile,
                "{name}"
            );
        }
    }

    #[test]
    fn enforces_segment_and_global_entry_budgets() {
        let at_limit = std::iter::repeat_n("x", MAX_PATH_SEGMENTS)
            .collect::<Vec<_>>()
            .join("/");
        PartitionFsValidation::default()
            .validate_partition(0, [(at_limit.as_str(), 1)])
            .expect("the maximum supported path depth should be accepted");

        let too_deep = std::iter::repeat_n("x", MAX_PATH_SEGMENTS + 1)
            .collect::<Vec<_>>()
            .join("/");
        assert_eq!(
            PartitionFsValidation::default()
                .validate_partition(0, [(too_deep.as_str(), 1)])
                .unwrap_err(),
            PartitionFsValidationError::InputLimitExceeded
        );

        let entries = (0..=MAX_TOTAL_ENTRIES)
            .map(|index| (format!("file-{index}"), 0_u64))
            .collect::<Vec<_>>();
        let names = entries.iter().map(|(name, size)| (name.as_str(), *size));
        assert_eq!(
            PartitionFsValidation::default()
                .validate_partition(0, names)
                .unwrap_err(),
            PartitionFsValidationError::InputLimitExceeded
        );
    }

    #[test]
    fn generated_paths_obey_the_cumulative_path_byte_limit() {
        let entries = (0..60_000)
            .map(|index| {
                (
                    format!(
                        "directory-{index:05}-{}/file-{index:05}-{}",
                        "d".repeat(100),
                        "f".repeat(100)
                    ),
                    0_u64,
                )
            })
            .collect::<Vec<_>>();
        let raw_name_bytes: usize = entries.iter().map(|(name, _)| name.len()).sum();
        assert!(raw_name_bytes < super::MAX_TOTAL_NAME_BYTES);
        let names = entries.iter().map(|(name, size)| (name.as_str(), *size));
        assert_eq!(
            PartitionFsValidation::default()
                .validate_partition(0, names)
                .unwrap_err(),
            PartitionFsValidationError::InputLimitExceeded
        );
    }

    #[test]
    fn name_byte_budget_accumulates_across_partitions() {
        let mut validation = PartitionFsValidation {
            total_name_bytes: super::MAX_TOTAL_NAME_BYTES - 1,
            ..PartitionFsValidation::default()
        };

        validation
            .validate_partition(0, [("a", 1)])
            .expect("the final name byte should fit");

        assert_eq!(
            validation.validate_partition(1, [("b", 2)]).unwrap_err(),
            PartitionFsValidationError::InputLimitExceeded
        );
    }

    #[test]
    fn path_byte_budget_accumulates_across_partitions() {
        // Leave six bytes after partition 0: partition 1's prefix and final file
        // fit, but the implicit "1/a" directory must also consume that budget.
        let mut validation = PartitionFsValidation {
            total_path_bytes: super::MAX_TOTAL_PATH_BYTES - 10,
            ..PartitionFsValidation::default()
        };
        validation
            .validate_partition(0, [("a", 1)])
            .expect("the first partition should exactly fit");
        assert_eq!(
            validation.validate_partition(1, [("a/b", 2)]).unwrap_err(),
            PartitionFsValidationError::InputLimitExceeded
        );
    }

    #[test]
    fn partition_prefixes_distinguish_identical_member_names() {
        let mut validation = PartitionFsValidation::default();
        validation.validate_partition(0, [("same.bin", 1)]).unwrap();
        validation.validate_partition(1, [("same.bin", 2)]).unwrap();

        assert_eq!(validation.total_entries(), 2);
        assert!(validation.expected_files().contains("0/same.bin"));
        assert!(validation.expected_files().contains("1/same.bin"));
    }
}
