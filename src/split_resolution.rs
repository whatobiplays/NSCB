//! Split directory qualification.
//!
//! A directory is only accepted as a Split input after the adjacent manifest,
//! a host-owned receipt, every physical member, both digest levels, and a final
//! stability recheck all agree. Manifest discovery alone never establishes
//! completeness, and untrusted candidates never become provisional inputs.

use crate::file_identity::{
    FileIdentity, FileSnapshot, file_snapshot, handle_identity, path_identity,
};
use crate::input_resolution::{
    InputResolutionControl, InputResolutionError, InputResolutionErrorCode, SplitQualification,
    SplitQualificationKind, looks_like_split_segment, read_directory,
};
use crate::sha256::Sha256Digest;
use crate::split_manifest::{MAX_SPLIT_MANIFEST_BYTES, SplitLayout, SplitManifest, parse_manifest};
use crate::split_reader::{SegmentOpenError, open_segment_file, revalidate_segment};
use crate::split_trust::{SourceEvidence, SplitTrustStore, trust_store_error};
use sha2::{Digest as _, Sha256};
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

const HASH_BUFFER_BYTES: usize = 1_048_576;

/// Per-request capabilities used while qualifying one Split directory.
pub(crate) struct SplitResolutionContext<'a> {
    pub(crate) trust_store: Option<&'a dyn SplitTrustStore>,
    pub(crate) control: Option<&'a InputResolutionControl>,
    pub(crate) visited_entries: &'a mut usize,
    pub(crate) validated_bytes: &'a mut u64,
    pub(crate) max_validated_bytes: u64,
    pub(crate) input_index: usize,
}

/// One physical segment accepted after full validation.
pub(crate) struct QualifiedSegment {
    pub(crate) path: PathBuf,
    pub(crate) size: u64,
    pub(crate) identity: Option<FileIdentity>,
}

/// A complete logical Split input.
pub(crate) struct QualifiedSplit {
    pub(crate) segments: Vec<QualifiedSegment>,
    pub(crate) manifest_sha256: Sha256Digest,
    pub(crate) qualification: SplitQualification,
}

/// A Split directory whose bytes agree with its manifest, without a trust claim.
pub(crate) struct VerifiedSplitDirectory {
    pub(crate) directory: PathBuf,
    pub(crate) identity: FileIdentity,
    /// Layout declared by the validated manifest.
    pub(crate) layout: SplitLayout,
    pub(crate) source_size: u64,
    pub(crate) source_sha256: Sha256Digest,
    pub(crate) segments: Vec<QualifiedSegment>,
}

/// Controls whether a Split directory may contain entries outside its members.
#[derive(Clone, Copy)]
pub(crate) enum SplitInventoryPolicy {
    /// Preserve resolver behavior for unrelated files and metadata.
    AllowUnrelatedEntries,
    /// Require every entry to be declared as a member in the manifest.
    RequireExactMembers,
}

struct SplitManifestCandidate {
    directory: PathBuf,
    directory_identity: FileIdentity,
    sidecar: PathBuf,
    sidecar_snapshot: FileSnapshot,
    manifest_sha256: Sha256Digest,
    manifest: SplitManifest,
    source: SourceEvidence,
}

/// Qualifies the Split directory at `directory`.
pub(crate) fn qualify_directory(
    directory: &Path,
    context: &mut SplitResolutionContext<'_>,
) -> Result<QualifiedSplit, InputResolutionError> {
    let candidate = read_manifest_candidate(directory, context)?;
    let manifest_schema_version = candidate.manifest.schema_version;
    require_receipt(
        &candidate.manifest_sha256,
        candidate.source,
        context.trust_store,
    )?;
    let manifest_sha256 = candidate.manifest_sha256;
    let source = candidate.source;
    let verified = verify_manifest_candidate(
        candidate,
        context,
        SplitInventoryPolicy::AllowUnrelatedEntries,
    )?;
    recheck_receipt(&manifest_sha256, source, context.trust_store)?;
    if let Some(control) = context.control {
        control.check_cancelled()?;
    }

    Ok(QualifiedSplit {
        segments: verified.segments,
        manifest_sha256,
        qualification: SplitQualification {
            kind: SplitQualificationKind::LocalSplitReceipt,
            manifest_schema_version: u16::from(manifest_schema_version),
            original_size_bytes: verified.source_size,
            original_sha256: verified.source_sha256,
        },
    })
}

/// Verifies a Split directory without consulting or creating a trust receipt.
pub(crate) fn verify_split_directory(
    directory: &Path,
    inventory_policy: SplitInventoryPolicy,
) -> Result<VerifiedSplitDirectory, InputResolutionError> {
    let mut visited_entries = 0;
    let mut validated_bytes = 0;
    let mut context = SplitResolutionContext {
        trust_store: None,
        control: None,
        visited_entries: &mut visited_entries,
        validated_bytes: &mut validated_bytes,
        max_validated_bytes: u64::MAX,
        input_index: 0,
    };
    let candidate = read_manifest_candidate(directory, &mut context)?;
    verify_manifest_candidate(candidate, &mut context, inventory_policy)
}

fn read_manifest_candidate(
    directory: &Path,
    context: &mut SplitResolutionContext<'_>,
) -> Result<SplitManifestCandidate, InputResolutionError> {
    let directory = fs::canonicalize(directory)
        .map_err(|_| error(InputResolutionErrorCode::InputUnavailable))?;
    let directory_metadata =
        fs::metadata(&directory).map_err(|_| error(InputResolutionErrorCode::InputUnavailable))?;
    if !directory_metadata.is_dir() {
        return Err(error(InputResolutionErrorCode::InputUnavailable));
    }
    if let Some(control) = context.control {
        control.check_cancelled()?;
    }
    let directory_identity = path_identity(&directory)
        .ok_or_else(|| error(InputResolutionErrorCode::SplitSetIncomplete))?;

    let sidecar = sidecar_path(&directory)?;
    let (manifest_bytes, sidecar_snapshot) = read_sidecar(&sidecar)?;
    let manifest_sha256 = Sha256Digest::digest(&manifest_bytes);
    let manifest = parse_manifest(&manifest_bytes)?;
    let source = SourceEvidence {
        size: manifest.source_size,
        sha256: manifest.source_sha256,
    };

    *context.validated_bytes = context
        .validated_bytes
        .checked_add(manifest.source_size)
        .ok_or_else(|| error(InputResolutionErrorCode::ResourceLimitExceeded))?;
    if *context.validated_bytes > context.max_validated_bytes {
        return Err(error(InputResolutionErrorCode::ResourceLimitExceeded));
    }

    Ok(SplitManifestCandidate {
        directory,
        directory_identity,
        sidecar,
        sidecar_snapshot,
        manifest_sha256,
        manifest,
        source,
    })
}

fn verify_manifest_candidate(
    candidate: SplitManifestCandidate,
    context: &mut SplitResolutionContext<'_>,
    inventory_policy: SplitInventoryPolicy,
) -> Result<VerifiedSplitDirectory, InputResolutionError> {
    let SplitManifestCandidate {
        directory,
        directory_identity,
        sidecar,
        sidecar_snapshot,
        manifest_sha256: _,
        manifest,
        source: _,
    } = candidate;
    let layout = manifest.layout;
    // Version 2 legacy member stems must match the inner directory basename's file stem.
    // Check this relationship before opening any members.
    if manifest.schema_version == 2 && !layout.is_canonical() {
        let directory_stem = directory
            .file_name()
            .and_then(|basename| Path::new(basename).file_stem())
            .ok_or_else(|| error(InputResolutionErrorCode::SplitManifestInvalid))?;
        let member_stem = manifest
            .segments
            .first()
            .and_then(|segment| Path::new(&segment.name).file_stem())
            .ok_or_else(|| error(InputResolutionErrorCode::SplitManifestInvalid))?;
        if directory_stem != member_stem {
            return Err(error(InputResolutionErrorCode::SplitManifestInvalid));
        }
    }

    let expected_names = manifest
        .segments
        .iter()
        .map(|segment| segment.name.clone())
        .collect::<Vec<_>>();
    let entries = read_split_members(&directory, &expected_names, context, inventory_policy)?;

    if let Some(control) = context.control {
        control.begin_split_input(context.input_index, manifest.source_size);
        control.check_cancelled()?;
    }

    let mut opened = Vec::with_capacity(expected_names.len());
    for (segment, member) in manifest.segments.iter().zip(entries.iter()) {
        let Some((path, size)) = member else {
            return Err(error(InputResolutionErrorCode::SplitSetIncomplete));
        };
        if *size != segment.size {
            return Err(error(InputResolutionErrorCode::SplitIntegrityMismatch));
        }
        let opened_segment = open_segment_file(path, segment.size).map_err(open_error)?;
        opened.push((segment, opened_segment));
    }

    let mut identities = HashSet::with_capacity(opened.len());
    for (_, segment) in &opened {
        let identity = segment
            .identity()
            .ok_or_else(|| error(InputResolutionErrorCode::SplitSetIncomplete))?;
        if !identities.insert(identity) {
            return Err(error(InputResolutionErrorCode::SplitSetIncomplete));
        }
    }

    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    let mut whole = Sha256::new();
    let mut checked_total = 0_u64;
    for (declared, segment) in &mut opened {
        let mut part = Sha256::new();
        let mut remaining = segment.len();
        while remaining > 0 {
            if let Some(control) = context.control {
                control.check_cancelled()?;
            }
            let count = usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(buffer.len());
            let read = segment
                .file_mut()
                .read(&mut buffer[..count])
                .map_err(|_| error(InputResolutionErrorCode::SplitInputChanged))?;
            if read == 0 {
                return Err(error(InputResolutionErrorCode::SplitInputChanged));
            }
            part.update(&buffer[..read]);
            whole.update(&buffer[..read]);
            checked_total = checked_total
                .checked_add(read as u64)
                .ok_or_else(|| error(InputResolutionErrorCode::SplitIntegrityMismatch))?;
            remaining -= read as u64;
            if let Some(control) = context.control {
                control.add_completed(read as u64)?;
            }
        }
        let observed: [u8; 32] = part.finalize().into();
        if Sha256Digest::from_bytes(observed) != declared.sha256 {
            return Err(error(InputResolutionErrorCode::SplitIntegrityMismatch));
        }
        if revalidate_segment(segment).is_err() {
            return Err(error(InputResolutionErrorCode::SplitInputChanged));
        }
    }

    if checked_total != manifest.source_size {
        return Err(error(InputResolutionErrorCode::SplitIntegrityMismatch));
    }
    let observed: [u8; 32] = whole.finalize().into();
    if Sha256Digest::from_bytes(observed) != manifest.source_sha256 {
        return Err(error(InputResolutionErrorCode::SplitIntegrityMismatch));
    }
    revalidate_sidecar(&sidecar, &sidecar_snapshot)?;
    for (_, segment) in &opened {
        if revalidate_segment(segment).is_err() {
            return Err(error(InputResolutionErrorCode::SplitInputChanged));
        }
    }
    let rechecked_entries =
        read_split_members(&directory, &expected_names, context, inventory_policy)?;
    if rechecked_entries != entries {
        return Err(error(InputResolutionErrorCode::SplitInputChanged));
    }
    for (_, segment) in &opened {
        if revalidate_segment(segment).is_err() {
            return Err(error(InputResolutionErrorCode::SplitInputChanged));
        }
    }
    let final_directory_metadata = fs::symlink_metadata(&directory)
        .map_err(|_| error(InputResolutionErrorCode::SplitInputChanged))?;
    if !final_directory_metadata.is_dir() || path_identity(&directory) != Some(directory_identity) {
        return Err(error(InputResolutionErrorCode::SplitInputChanged));
    }
    if let Some(control) = context.control {
        control.check_cancelled()?;
    }

    Ok(VerifiedSplitDirectory {
        directory,
        identity: directory_identity,
        layout,
        source_size: manifest.source_size,
        source_sha256: manifest.source_sha256,
        segments: opened
            .into_iter()
            .map(|(_, segment)| QualifiedSegment {
                path: segment.path().to_path_buf(),
                size: segment.len(),
                identity: segment.identity(),
            })
            .collect(),
    })
}

/// Returns the deterministic sibling sidecar for a canonical directory.
pub(crate) fn sidecar_path(directory: &Path) -> Result<PathBuf, InputResolutionError> {
    let name = directory
        .file_name()
        .ok_or_else(|| error(InputResolutionErrorCode::SplitManifestMissing))?;
    let mut sidecar = name.to_os_string();
    sidecar.push(".nscb-split.json");
    Ok(directory.with_file_name(sidecar))
}

/// Reports whether a sibling manifest exists, without following it yet.
pub(crate) fn has_adjacent_sidecar(directory: &Path) -> Result<bool, InputResolutionError> {
    let sidecar = sidecar_path(directory)?;
    match fs::symlink_metadata(&sidecar) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(error(InputResolutionErrorCode::InputUnavailable)),
    }
}

/// Reports whether a directory directly contains a non-directory canonical
/// member name.
///
/// Numeric subdirectories are ordinary directory content. Treating them as
/// Split members would make an unrelated `00/` child turn an ordinary
/// directory selection into a missing-manifest failure. A numeric regular
/// file, symlink, or special file remains a suspect Split candidate and fails
/// closed when no sidecar is present.
pub(crate) fn directory_has_canonical_member(
    directory: &Path,
) -> Result<bool, InputResolutionError> {
    for index in 0..100 {
        let candidate = directory.join(format!("{index:02}"));
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if !metadata.file_type().is_dir() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(error(InputResolutionErrorCode::InputUnavailable)),
        }
    }
    Ok(false)
}

/// Returns the numeric index of an exact ASCII two-digit member basename.
pub(crate) fn canonical_member_index(name: &OsStr) -> Option<u8> {
    let bytes = name.to_str()?.as_bytes();
    if bytes.len() != 2 || !bytes[0].is_ascii_digit() || !bytes[1].is_ascii_digit() {
        return None;
    }
    Some((bytes[0] - b'0') * 10 + (bytes[1] - b'0'))
}

fn read_split_members(
    directory: &Path,
    expected_names: &[String],
    context: &mut SplitResolutionContext<'_>,
    inventory_policy: SplitInventoryPolicy,
) -> Result<Vec<Option<(PathBuf, u64)>>, InputResolutionError> {
    let entries = read_directory(directory, context.visited_entries)?;
    let mut members: Vec<Option<(PathBuf, u64)>> = vec![None; expected_names.len()];
    for (position, entry) in entries.into_iter().enumerate() {
        if position % 1024 == 0
            && let Some(control) = context.control
        {
            control.check_cancelled()?;
        }
        let name = entry.file_name();
        let path = directory.join(&name);
        if let Some(index) = expected_names
            .iter()
            .position(|expected| name == OsStr::new(expected))
        {
            if members[index].is_some() {
                return Err(error(InputResolutionErrorCode::SplitSetIncomplete));
            }
            let file_type = entry
                .file_type()
                .map_err(|_| error(InputResolutionErrorCode::InputUnavailable))?;
            if file_type.is_symlink() || !file_type.is_file() {
                return Err(error(InputResolutionErrorCode::SplitSetIncomplete));
            }
            let metadata = entry
                .metadata()
                .map_err(|_| error(InputResolutionErrorCode::InputUnavailable))?;
            members[index] = Some((path, metadata.len()));
        } else if matches!(inventory_policy, SplitInventoryPolicy::RequireExactMembers)
            || looks_like_split_segment(&path)
        {
            return Err(error(InputResolutionErrorCode::SplitSetIncomplete));
        }
    }
    if members.iter().any(Option::is_none) {
        return Err(error(InputResolutionErrorCode::SplitSetIncomplete));
    }
    Ok(members)
}

fn require_receipt(
    manifest_sha256: &Sha256Digest,
    source: SourceEvidence,
    store: Option<&dyn SplitTrustStore>,
) -> Result<crate::split_trust::SplitTrustReceipt, InputResolutionError> {
    let Some(store) = store else {
        return Err(error(InputResolutionErrorCode::SplitEvidenceUntrusted));
    };
    let receipt = store
        .lookup(manifest_sha256)
        .map_err(trust_store_error)?
        .ok_or_else(|| error(InputResolutionErrorCode::SplitEvidenceUntrusted))?;
    if receipt.is_revoked() || !receipt.binds(manifest_sha256, &source) {
        return Err(error(InputResolutionErrorCode::SplitEvidenceUntrusted));
    }
    Ok(receipt)
}

fn recheck_receipt(
    manifest_sha256: &Sha256Digest,
    source: SourceEvidence,
    store: Option<&dyn SplitTrustStore>,
) -> Result<(), InputResolutionError> {
    require_receipt(manifest_sha256, source, store).map(|_| ())
}

fn read_sidecar(path: &Path) -> Result<(Vec<u8>, FileSnapshot), InputResolutionError> {
    let link_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(io_error) if io_error.kind() == std::io::ErrorKind::NotFound => {
            return Err(error(InputResolutionErrorCode::SplitManifestMissing));
        }
        Err(_) => return Err(error(InputResolutionErrorCode::InputUnavailable)),
    };
    if link_metadata.file_type().is_symlink() || !link_metadata.file_type().is_file() {
        return Err(error(InputResolutionErrorCode::SplitManifestInvalid));
    }
    if link_metadata.len() > MAX_SPLIT_MANIFEST_BYTES {
        return Err(error(InputResolutionErrorCode::ResourceLimitExceeded));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000);
    }
    let file = options
        .open(path)
        .map_err(|_| error(InputResolutionErrorCode::InputUnavailable))?;
    let handle_metadata = file
        .metadata()
        .map_err(|_| error(InputResolutionErrorCode::InputUnavailable))?;
    let Some(identity) = handle_identity(&file) else {
        return Err(error(InputResolutionErrorCode::InputUnavailable));
    };
    if !handle_metadata.file_type().is_file()
        || path_identity(path) != Some(identity)
        || handle_metadata.len() != link_metadata.len()
    {
        return Err(error(InputResolutionErrorCode::SplitInputChanged));
    }
    let snapshot = file_snapshot(&handle_metadata, Some(identity));
    let mut bytes = Vec::with_capacity(handle_metadata.len() as usize);
    file.take(MAX_SPLIT_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| error(InputResolutionErrorCode::InputUnavailable))?;
    if bytes.len() as u64 > MAX_SPLIT_MANIFEST_BYTES {
        return Err(error(InputResolutionErrorCode::ResourceLimitExceeded));
    }
    revalidate_sidecar(path, &snapshot)?;
    Ok((bytes, snapshot))
}

fn revalidate_sidecar(path: &Path, expected: &FileSnapshot) -> Result<(), InputResolutionError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| error(InputResolutionErrorCode::SplitInputChanged))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(error(InputResolutionErrorCode::SplitInputChanged));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000);
    }
    let file = options
        .open(path)
        .map_err(|_| error(InputResolutionErrorCode::SplitInputChanged))?;
    let handle_metadata = file
        .metadata()
        .map_err(|_| error(InputResolutionErrorCode::SplitInputChanged))?;
    let Some(identity) = handle_identity(&file) else {
        return Err(error(InputResolutionErrorCode::SplitInputChanged));
    };
    if !handle_metadata.file_type().is_file()
        || Some(identity) != expected.identity
        || path_identity(path) != Some(identity)
        || file_snapshot(&handle_metadata, Some(identity)) != *expected
    {
        return Err(error(InputResolutionErrorCode::SplitInputChanged));
    }
    Ok(())
}

fn open_error(error_kind: SegmentOpenError) -> InputResolutionError {
    match error_kind {
        SegmentOpenError::Unavailable | SegmentOpenError::Changed => {
            error(InputResolutionErrorCode::SplitInputChanged)
        }
        SegmentOpenError::NotRegular | SegmentOpenError::IdentityUnavailable => {
            error(InputResolutionErrorCode::SplitSetIncomplete)
        }
        SegmentOpenError::SizeMismatch => error(InputResolutionErrorCode::SplitIntegrityMismatch),
    }
}

fn error(code: InputResolutionErrorCode) -> InputResolutionError {
    InputResolutionError::new(code)
}
