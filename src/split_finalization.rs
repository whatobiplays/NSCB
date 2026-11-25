//! Finalization of a canonical Split directory after it has been transferred.
//!
//! The finalizer verifies the manifest and exact inner-directory inventory
//! before changing the archive attribute. It never consults or creates a
//! source trust receipt. A successful check does not establish source-backed
//! completeness or Horizon consumer interoperability.

use crate::file_identity::{FileIdentity, handle_identity, open_directory_handle, path_identity};
use crate::split_operation::{DEFAULT_SEGMENT_SIZE_BYTES, MAX_SEGMENT_COUNT};
use crate::split_resolution::{
    SplitInventoryPolicy, VerifiedSplitDirectory, verify_split_directory,
};
use std::fmt;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

#[cfg(any(windows, test))]
const ARCHIVE_ATTRIBUTE: u32 = 0x20;

/// Result of checking the target platform's archive-attribute capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SplitArchiveAttributeStatus {
    /// The native setter wrote and independently read back the archive bit.
    Set,
    /// The archive bit was already set and read back successfully.
    AlreadySet,
    /// The directory is ready for a documented external finalization step.
    ExternalFinalizationRequired,
    /// The destination filesystem is not positively identified as FAT32.
    UnsupportedFilesystem,
    /// The platform's FAT32 attribute path has not been qualified.
    UnqualifiedPlatform,
}

impl SplitArchiveAttributeStatus {
    /// Returns a stable CLI label for this result.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Set => "set",
            Self::AlreadySet => "already_set",
            Self::ExternalFinalizationRequired => "external_finalization_required",
            Self::UnsupportedFilesystem => "unsupported_filesystem",
            Self::UnqualifiedPlatform => "unqualified_platform",
        }
    }

    /// Returns the level of platform support established by this run.
    pub const fn platform_capability(self) -> &'static str {
        match self {
            Self::Set | Self::AlreadySet => "native_supported",
            Self::ExternalFinalizationRequired => "external_finalization_required",
            Self::UnsupportedFilesystem => "unsupported_filesystem",
            Self::UnqualifiedPlatform => "unqualified",
        }
    }
}

/// Failure category for a Split-set finalization attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SplitFinalizationErrorCode {
    /// The manifest, segment profile, bytes, or exact inventory is invalid.
    InvalidSplitSet,
    /// The selected directory changed during finalization.
    DestinationChanged,
    /// The current archive attribute could not be read.
    AttributeReadFailed,
    /// The archive attribute could not be written.
    AttributeSetFailed,
    /// Readback did not confirm the archive bit and preserved attributes.
    AttributeReadbackFailed,
}

impl SplitFinalizationErrorCode {
    /// Returns a stable CLI label for this failure.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidSplitSet => "invalid_split_set",
            Self::DestinationChanged => "destination_changed",
            Self::AttributeReadFailed => "attribute_read_failed",
            Self::AttributeSetFailed => "attribute_set_failed",
            Self::AttributeReadbackFailed => "attribute_readback_failed",
        }
    }
}

/// Sanitized failure from Split-set validation or archive-bit finalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SplitFinalizationError {
    code: SplitFinalizationErrorCode,
    manifest_consistency_verified: bool,
}

impl SplitFinalizationError {
    /// Returns the failure category without exposing host paths or OS details.
    pub const fn code(self) -> SplitFinalizationErrorCode {
        self.code
    }

    /// Reports whether manifest consistency was established before this failure.
    pub const fn manifest_consistency_verified(self) -> bool {
        self.manifest_consistency_verified
    }

    fn with_manifest_consistency_verified(self) -> Self {
        Self {
            manifest_consistency_verified: true,
            ..self
        }
    }
}

impl fmt::Display for SplitFinalizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for SplitFinalizationError {}

/// Verifies a transferred canonical Split set and finalizes its archive bit where supported.
///
/// Validation requires an exact inventory of canonical numbered parts and the
/// production segment-size profile. It does not require or create a local
/// receipt, and it does not establish source-backed completeness or consumer
/// interoperability.
pub fn finalize_split_directory(
    directory: impl AsRef<Path>,
) -> Result<SplitArchiveAttributeStatus, SplitFinalizationError> {
    let binding = SelectedDirectoryBinding::open(directory.as_ref())?;
    let verified = verify_split_directory(
        &binding.selected_path,
        SplitInventoryPolicy::RequireExactMembers,
    )
    .map_err(|_| error(SplitFinalizationErrorCode::InvalidSplitSet))?;
    if verified.identity != binding.identity {
        return Err(error(SplitFinalizationErrorCode::DestinationChanged));
    }
    let sizes = verified
        .segments
        .iter()
        .map(|segment| segment.size)
        .collect::<Vec<_>>();
    if !valid_segment_profile(&sizes, DEFAULT_SEGMENT_SIZE_BYTES, MAX_SEGMENT_COUNT) {
        return Err(
            error(SplitFinalizationErrorCode::InvalidSplitSet).with_manifest_consistency_verified()
        );
    }

    #[cfg(windows)]
    {
        let mut backend = WindowsArchiveAttributeBackend;
        finalize_with_backend(&verified, &binding, &mut backend)
    }

    #[cfg(target_os = "macos")]
    {
        ensure_directory_identity(&verified, &binding)?;
        Ok(SplitArchiveAttributeStatus::ExternalFinalizationRequired)
    }

    #[cfg(target_os = "linux")]
    {
        ensure_directory_identity(&verified, &binding)?;
        Ok(SplitArchiveAttributeStatus::UnqualifiedPlatform)
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        ensure_directory_identity(&verified, &binding)?;
        Ok(SplitArchiveAttributeStatus::UnqualifiedPlatform)
    }
}

struct SelectedDirectoryBinding {
    selected_path: PathBuf,
    handle: File,
    identity: FileIdentity,
}

impl SelectedDirectoryBinding {
    fn open(selected_path: &Path) -> Result<Self, SplitFinalizationError> {
        reject_selected_alias(selected_path)?;
        let handle = open_directory_handle(selected_path)
            .ok_or_else(|| error(SplitFinalizationErrorCode::InvalidSplitSet))?;
        if !handle.metadata().is_ok_and(|metadata| metadata.is_dir()) {
            return Err(error(SplitFinalizationErrorCode::InvalidSplitSet));
        }
        let identity = handle_identity(&handle)
            .ok_or_else(|| error(SplitFinalizationErrorCode::InvalidSplitSet))?;
        if path_identity(selected_path) != Some(identity) {
            return Err(error(SplitFinalizationErrorCode::DestinationChanged));
        }
        Ok(Self {
            selected_path: selected_path.to_path_buf(),
            handle,
            identity,
        })
    }
}

fn reject_selected_alias(directory: &Path) -> Result<(), SplitFinalizationError> {
    let metadata = fs::symlink_metadata(directory)
        .map_err(|_| error(SplitFinalizationErrorCode::InvalidSplitSet))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(error(SplitFinalizationErrorCode::InvalidSplitSet));
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, GetFileAttributesW, INVALID_FILE_ATTRIBUTES,
        };

        let path = wide_path(directory);
        let attributes = unsafe { GetFileAttributesW(path.as_ptr()) };
        if attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(error(SplitFinalizationErrorCode::InvalidSplitSet));
        }
    }
    Ok(())
}

fn valid_segment_profile(sizes: &[u64], segment_limit: u64, max_segments: usize) -> bool {
    let Some((&last, preceding)) = sizes.split_last() else {
        return false;
    };
    sizes.len() <= max_segments
        && preceding.iter().all(|size| *size == segment_limit)
        && last > 0
        && last <= segment_limit
}

fn ensure_directory_identity(
    verified: &VerifiedSplitDirectory,
    binding: &SelectedDirectoryBinding,
) -> Result<(), SplitFinalizationError> {
    if binding.identity != verified.identity
        || handle_identity(&binding.handle) != Some(binding.identity)
        || !path_matches_directory_identity(&binding.selected_path, binding.identity)
        || !path_matches_directory_identity(&verified.directory, binding.identity)
    {
        return Err(error(SplitFinalizationErrorCode::DestinationChanged)
            .with_manifest_consistency_verified());
    }
    Ok(())
}

fn path_matches_directory_identity(path: &Path, identity: FileIdentity) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return false;
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, GetFileAttributesW, INVALID_FILE_ATTRIBUTES,
        };

        let path = wide_path(path);
        // SAFETY: `path` is a nul-terminated UTF-16 path buffer.
        let attributes = unsafe { GetFileAttributesW(path.as_ptr()) };
        if attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return false;
        }
    }

    path_identity(path) == Some(identity)
}

#[cfg(any(windows, test))]
trait ArchiveAttributeBackend {
    fn is_fat32(&mut self, directory: &Path) -> bool;
    fn get_attributes(&mut self, directory: &Path) -> Result<u32, SplitFinalizationError>;
    fn set_attributes(
        &mut self,
        directory: &Path,
        attributes: u32,
    ) -> Result<(), SplitFinalizationError>;
}

#[cfg(any(windows, test))]
fn finalize_with_backend(
    verified: &VerifiedSplitDirectory,
    binding: &SelectedDirectoryBinding,
    backend: &mut impl ArchiveAttributeBackend,
) -> Result<SplitArchiveAttributeStatus, SplitFinalizationError> {
    ensure_directory_identity(verified, binding)?;
    let is_fat32 = backend.is_fat32(&verified.directory);
    ensure_directory_identity(verified, binding)?;
    if !is_fat32 {
        return Ok(SplitArchiveAttributeStatus::UnsupportedFilesystem);
    }
    let before = backend.get_attributes(&verified.directory);
    let before = complete_attribute_call(verified, binding, before)?;
    let was_set = before & ARCHIVE_ATTRIBUTE != 0;
    if !was_set {
        ensure_directory_identity(verified, binding)?;
        let set = backend.set_attributes(&verified.directory, before | ARCHIVE_ATTRIBUTE);
        complete_attribute_call(verified, binding, set)?;
    }
    let after = backend.get_attributes(&verified.directory);
    let after = complete_attribute_call(verified, binding, after)?;
    if after & ARCHIVE_ATTRIBUTE == 0 || (before ^ after) & !ARCHIVE_ATTRIBUTE != 0 {
        return Err(error(SplitFinalizationErrorCode::AttributeReadbackFailed)
            .with_manifest_consistency_verified());
    }
    Ok(if was_set {
        SplitArchiveAttributeStatus::AlreadySet
    } else {
        SplitArchiveAttributeStatus::Set
    })
}

#[cfg(any(windows, test))]
fn complete_attribute_call<T>(
    verified: &VerifiedSplitDirectory,
    binding: &SelectedDirectoryBinding,
    result: Result<T, SplitFinalizationError>,
) -> Result<T, SplitFinalizationError> {
    ensure_directory_identity(verified, binding)?;
    result.map_err(SplitFinalizationError::with_manifest_consistency_verified)
}

#[cfg(windows)]
struct WindowsArchiveAttributeBackend;

#[cfg(windows)]
impl ArchiveAttributeBackend for WindowsArchiveAttributeBackend {
    fn is_fat32(&mut self, directory: &Path) -> bool {
        use windows_sys::Win32::Storage::FileSystem::{GetVolumeInformationW, GetVolumePathNameW};

        let path = wide_path(directory);
        let mut volume_path = vec![0_u16; 32_768];
        let resolved = unsafe {
            GetVolumePathNameW(
                path.as_ptr(),
                volume_path.as_mut_ptr(),
                volume_path.len() as u32,
            )
        };
        if resolved == 0 {
            return false;
        }
        let mut filesystem_name = vec![0_u16; 64];
        let information = unsafe {
            GetVolumeInformationW(
                volume_path.as_ptr(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                filesystem_name.as_mut_ptr(),
                filesystem_name.len() as u32,
            )
        };
        if information == 0 {
            return false;
        }
        let length = filesystem_name
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(filesystem_name.len());
        String::from_utf16_lossy(&filesystem_name[..length]).eq_ignore_ascii_case("FAT32")
    }

    fn get_attributes(&mut self, directory: &Path) -> Result<u32, SplitFinalizationError> {
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileAttributesW, INVALID_FILE_ATTRIBUTES,
        };

        let path = wide_path(directory);
        let attributes = unsafe { GetFileAttributesW(path.as_ptr()) };
        if attributes == INVALID_FILE_ATTRIBUTES {
            return Err(error(SplitFinalizationErrorCode::AttributeReadFailed));
        }
        Ok(attributes)
    }

    fn set_attributes(
        &mut self,
        directory: &Path,
        attributes: u32,
    ) -> Result<(), SplitFinalizationError> {
        use windows_sys::Win32::Storage::FileSystem::SetFileAttributesW;

        let path = wide_path(directory);
        let changed = unsafe { SetFileAttributesW(path.as_ptr(), attributes) };
        if changed == 0 {
            return Err(error(SplitFinalizationErrorCode::AttributeSetFailed));
        }
        Ok(())
    }
}

#[cfg(windows)]
fn wide_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn error(code: SplitFinalizationErrorCode) -> SplitFinalizationError {
    SplitFinalizationError {
        code,
        manifest_consistency_verified: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_identity::path_identity;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("nscb-finalization-{}-{id}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn verified(&self) -> VerifiedSplitDirectory {
            VerifiedSplitDirectory {
                directory: self.0.clone(),
                identity: path_identity(&self.0).unwrap(),
                source_size: 1,
                source_sha256: crate::Sha256Digest::digest(b"x"),
                segments: Vec::new(),
            }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
            let mut old = self.0.clone();
            old.set_extension("old");
            let _ = fs::remove_dir_all(old);
        }
    }

    #[derive(Default)]
    struct FakeBackend {
        supported: bool,
        attributes: u32,
        fail_get: bool,
        fail_set: bool,
        omit_archive_on_set: bool,
        replace_directory_on_get: bool,
        replace_directory_on_set: bool,
        set_calls: usize,
    }

    impl ArchiveAttributeBackend for FakeBackend {
        fn is_fat32(&mut self, _: &Path) -> bool {
            self.supported
        }

        fn get_attributes(&mut self, directory: &Path) -> Result<u32, SplitFinalizationError> {
            if self.replace_directory_on_get {
                let mut old = directory.to_path_buf();
                old.set_extension("old");
                fs::rename(directory, old).unwrap();
                fs::create_dir(directory).unwrap();
            }
            if self.fail_get {
                return Err(error(SplitFinalizationErrorCode::AttributeReadFailed));
            }
            Ok(self.attributes)
        }

        fn set_attributes(
            &mut self,
            directory: &Path,
            attributes: u32,
        ) -> Result<(), SplitFinalizationError> {
            self.set_calls += 1;
            if self.fail_set {
                if self.replace_directory_on_set {
                    let mut old = directory.to_path_buf();
                    old.set_extension("old");
                    fs::rename(directory, old).unwrap();
                    fs::create_dir(directory).unwrap();
                }
                return Err(error(SplitFinalizationErrorCode::AttributeSetFailed));
            }
            self.attributes = if self.omit_archive_on_set {
                attributes & !ARCHIVE_ATTRIBUTE
            } else {
                attributes
            };
            if self.replace_directory_on_set {
                let mut old = directory.to_path_buf();
                old.set_extension("old");
                fs::rename(directory, old).unwrap();
                fs::create_dir(directory).unwrap();
            }
            Ok(())
        }
    }

    #[test]
    fn production_profile_requires_full_nonfinal_parts_and_bounded_final_part() {
        assert!(valid_segment_profile(&[8, 3], 8, 100));
        assert!(valid_segment_profile(&[8], 8, 100));
        assert!(!valid_segment_profile(&[7, 3], 8, 100));
        assert!(!valid_segment_profile(&[8, 0], 8, 100));
        assert!(!valid_segment_profile(&[8, 9], 8, 100));
        assert!(!valid_segment_profile(&[8, 3, 1], 8, 2));
        assert!(!valid_segment_profile(&[], 8, 100));
    }

    #[test]
    fn status_and_error_labels_are_stable() {
        let statuses = [
            (SplitArchiveAttributeStatus::Set, "set", "native_supported"),
            (
                SplitArchiveAttributeStatus::AlreadySet,
                "already_set",
                "native_supported",
            ),
            (
                SplitArchiveAttributeStatus::ExternalFinalizationRequired,
                "external_finalization_required",
                "external_finalization_required",
            ),
            (
                SplitArchiveAttributeStatus::UnsupportedFilesystem,
                "unsupported_filesystem",
                "unsupported_filesystem",
            ),
            (
                SplitArchiveAttributeStatus::UnqualifiedPlatform,
                "unqualified_platform",
                "unqualified",
            ),
        ];
        for (status, label, capability) in statuses {
            assert_eq!(status.as_str(), label);
            assert_eq!(status.platform_capability(), capability);
        }

        let errors = [
            (
                SplitFinalizationErrorCode::InvalidSplitSet,
                "invalid_split_set",
            ),
            (
                SplitFinalizationErrorCode::DestinationChanged,
                "destination_changed",
            ),
            (
                SplitFinalizationErrorCode::AttributeReadFailed,
                "attribute_read_failed",
            ),
            (
                SplitFinalizationErrorCode::AttributeSetFailed,
                "attribute_set_failed",
            ),
            (
                SplitFinalizationErrorCode::AttributeReadbackFailed,
                "attribute_readback_failed",
            ),
        ];
        for (code, label) in errors {
            let failure = error(code);
            assert_eq!(code.as_str(), label);
            assert_eq!(failure.to_string(), label);
        }
    }

    #[test]
    fn archive_bit_is_added_idempotently_and_other_attributes_are_preserved() {
        let directory = TestDirectory::new();
        let verified = directory.verified();
        let binding = SelectedDirectoryBinding::open(&directory.0).unwrap();
        let mut backend = FakeBackend {
            supported: true,
            attributes: 0x12,
            ..FakeBackend::default()
        };

        assert_eq!(
            finalize_with_backend(&verified, &binding, &mut backend).unwrap(),
            SplitArchiveAttributeStatus::Set
        );
        assert_eq!(backend.attributes, 0x32);
        assert_eq!(
            finalize_with_backend(&verified, &binding, &mut backend).unwrap(),
            SplitArchiveAttributeStatus::AlreadySet
        );
        assert_eq!(backend.set_calls, 1);
    }

    #[test]
    fn unsupported_filesystem_is_left_untouched() {
        let directory = TestDirectory::new();
        let verified = directory.verified();
        let binding = SelectedDirectoryBinding::open(&directory.0).unwrap();
        let mut backend = FakeBackend {
            attributes: 0x12,
            ..FakeBackend::default()
        };

        assert_eq!(
            finalize_with_backend(&verified, &binding, &mut backend).unwrap(),
            SplitArchiveAttributeStatus::UnsupportedFilesystem
        );
        assert_eq!(backend.attributes, 0x12);
        assert_eq!(backend.set_calls, 0);
    }

    #[test]
    fn setter_and_readback_failures_are_not_reported_as_success() {
        let directory = TestDirectory::new();
        let verified = directory.verified();
        let binding = SelectedDirectoryBinding::open(&directory.0).unwrap();
        let mut read_failure = FakeBackend {
            supported: true,
            fail_get: true,
            ..FakeBackend::default()
        };
        let error = finalize_with_backend(&verified, &binding, &mut read_failure).unwrap_err();
        assert_eq!(
            error.code(),
            SplitFinalizationErrorCode::AttributeReadFailed
        );
        assert!(error.manifest_consistency_verified());

        let mut setter_failure = FakeBackend {
            supported: true,
            attributes: 0x10,
            fail_set: true,
            ..FakeBackend::default()
        };
        let error = finalize_with_backend(&verified, &binding, &mut setter_failure).unwrap_err();
        assert_eq!(error.code(), SplitFinalizationErrorCode::AttributeSetFailed);
        assert!(error.manifest_consistency_verified());

        let mut readback_failure = FakeBackend {
            supported: true,
            attributes: 0x10,
            omit_archive_on_set: true,
            ..FakeBackend::default()
        };
        let error = finalize_with_backend(&verified, &binding, &mut readback_failure).unwrap_err();
        assert_eq!(
            error.code(),
            SplitFinalizationErrorCode::AttributeReadbackFailed
        );
        assert!(error.manifest_consistency_verified());
    }

    #[test]
    fn attribute_failures_report_observed_displacement_with_manifest_evidence() {
        let read_directory = TestDirectory::new();
        let read_verified = read_directory.verified();
        let read_binding = SelectedDirectoryBinding::open(&read_directory.0).unwrap();
        let mut read_backend = FakeBackend {
            supported: true,
            fail_get: true,
            replace_directory_on_get: true,
            ..FakeBackend::default()
        };
        let read_error =
            finalize_with_backend(&read_verified, &read_binding, &mut read_backend).unwrap_err();
        assert_eq!(
            read_error.code(),
            SplitFinalizationErrorCode::DestinationChanged
        );
        assert!(read_error.manifest_consistency_verified());

        let set_directory = TestDirectory::new();
        let set_verified = set_directory.verified();
        let set_binding = SelectedDirectoryBinding::open(&set_directory.0).unwrap();
        let mut set_backend = FakeBackend {
            supported: true,
            attributes: 0x10,
            fail_set: true,
            replace_directory_on_set: true,
            ..FakeBackend::default()
        };
        let set_error =
            finalize_with_backend(&set_verified, &set_binding, &mut set_backend).unwrap_err();
        assert_eq!(
            set_error.code(),
            SplitFinalizationErrorCode::DestinationChanged
        );
        assert!(set_error.manifest_consistency_verified());
    }

    #[test]
    fn selected_directory_binding_detects_displacement_after_open() {
        let directory = TestDirectory::new();
        let binding = SelectedDirectoryBinding::open(&directory.0).unwrap();
        let verified = directory.verified();
        let mut old = directory.0.clone();
        old.set_extension("old");
        fs::rename(&directory.0, &old).unwrap();
        fs::create_dir(&directory.0).unwrap();

        let error = ensure_directory_identity(&verified, &binding).unwrap_err();

        assert_eq!(error.code(), SplitFinalizationErrorCode::DestinationChanged);
        assert!(error.manifest_consistency_verified());
    }

    #[test]
    fn directory_identity_is_checked_before_mutation_and_after_readback() {
        let directory = TestDirectory::new();
        let verified = directory.verified();
        let binding = SelectedDirectoryBinding::open(&directory.0).unwrap();
        let mut before = directory.0.clone();
        before.set_extension("old");
        fs::rename(&directory.0, &before).unwrap();
        fs::create_dir(&directory.0).unwrap();
        let mut backend = FakeBackend {
            supported: true,
            attributes: 0x10,
            ..FakeBackend::default()
        };
        assert_eq!(
            finalize_with_backend(&verified, &binding, &mut backend)
                .unwrap_err()
                .code(),
            SplitFinalizationErrorCode::DestinationChanged
        );
        assert_eq!(backend.set_calls, 0);

        let after = TestDirectory::new();
        let verified_after = after.verified();
        let binding_after = SelectedDirectoryBinding::open(&after.0).unwrap();
        let mut backend_after = FakeBackend {
            supported: true,
            attributes: 0x10,
            replace_directory_on_set: true,
            ..FakeBackend::default()
        };
        assert_eq!(
            finalize_with_backend(&verified_after, &binding_after, &mut backend_after)
                .unwrap_err()
                .code(),
            SplitFinalizationErrorCode::DestinationChanged
        );
    }

    #[test]
    fn directory_identity_check_rejects_a_replaced_directory() {
        let directory = TestDirectory::new();
        let verified = directory.verified();
        let binding = SelectedDirectoryBinding::open(&directory.0).unwrap();
        let mut old = directory.0.clone();
        old.set_extension("old");
        fs::rename(&directory.0, old).unwrap();
        fs::create_dir(&directory.0).unwrap();

        assert_eq!(
            ensure_directory_identity(&verified, &binding)
                .unwrap_err()
                .code(),
            SplitFinalizationErrorCode::DestinationChanged
        );
    }
}
