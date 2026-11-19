#[cfg(target_os = "macos")]
use super::{OperationFailureCode, OperationPlan};
#[cfg(target_os = "macos")]
use crate::file_identity::handle_identity;
#[cfg(target_os = "macos")]
use crate::inspection::CancellationHandle;
#[cfg(target_os = "macos")]
use crate::sha256::Sha256Digest;
#[cfg(target_os = "macos")]
use std::fs::File;
#[cfg(target_os = "macos")]
use std::io::{Read, Seek, SeekFrom};
#[cfg(target_os = "macos")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::path::PathBuf;

#[cfg(target_os = "macos")]
#[derive(Clone, Debug)]
struct SelectedExtractionSpan {
    relative_path: String,
    offset: u64,
    size: u64,
    sha256: Sha256Digest,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExtractionIoFailurePoint {
    #[cfg(test)]
    PayloadWrite,
    BundlePrepromotion,
    StageParentAfterRename,
    DestinationParentDurability,
}

#[cfg(all(test, target_os = "macos"))]
std::thread_local! {
    static EXTRACTION_IO_FAILURE_POINT: std::cell::Cell<Option<ExtractionIoFailurePoint>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(all(test, target_os = "macos"))]
struct InjectedExtractionIoFailure {
    previous: Option<ExtractionIoFailurePoint>,
}

#[cfg(all(test, target_os = "macos"))]
impl InjectedExtractionIoFailure {
    fn at(point: ExtractionIoFailurePoint) -> Self {
        let previous = EXTRACTION_IO_FAILURE_POINT.with(|current| current.replace(Some(point)));
        Self { previous }
    }
}

#[cfg(all(test, target_os = "macos"))]
impl Drop for InjectedExtractionIoFailure {
    fn drop(&mut self) {
        EXTRACTION_IO_FAILURE_POINT.with(|current| current.set(self.previous));
    }
}

#[cfg(all(test, target_os = "macos"))]
fn take_injected_io_failure(point: ExtractionIoFailurePoint) -> bool {
    EXTRACTION_IO_FAILURE_POINT.with(|current| {
        if current.get() == Some(point) {
            current.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(target_os = "macos")]
fn write_payload_chunk(destination: &mut File, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(test)]
    if take_injected_io_failure(ExtractionIoFailurePoint::PayloadWrite) {
        return Err(std::io::Error::other(
            "injected extraction payload write failure",
        ));
    }

    use std::io::Write as _;
    destination.write_all(bytes)
}

#[cfg(target_os = "macos")]
fn sync_for_extraction(
    file: &File,
    point: ExtractionIoFailurePoint,
) -> Result<(), OperationFailureCode> {
    #[cfg(test)]
    if take_injected_io_failure(point) {
        return Err(OperationFailureCode::WriteFailed);
    }

    let _ = point;
    file.sync_all()
        .map_err(|_| OperationFailureCode::WriteFailed)
}

/// Private evidence required to execute an extraction plan.
#[cfg(target_os = "macos")]
pub(super) struct ExtractionOperationPlan {
    key_file: super::ResolvedFile,
    key_baseline: super::FileEvidence,
    selected_files: Vec<SelectedExtractionSpan>,
    directories: Vec<String>,
    manifest: crate::extraction::ExtractionManifest,
    total_bytes: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn plan(
    request: crate::extraction::ExtractionRequest,
    cancellation: CancellationHandle,
) -> Result<OperationPlan, super::OperationError> {
    use super::{
        ConflictPolicy, DestinationBaseline, OperationArtifactRole, OperationKind,
        OperationPlanSnapshot, PlannedArtifact, PlannedEffect, PlannedSource, StagingStrategy,
    };
    use crate::extraction::resolve_extraction;
    use crate::provider::keys::{MAX_KEY_FILE_BYTES, read_header_key};
    use std::ffi::OsStr;

    if cancellation.is_cancelled() {
        return Err(super::OperationError::new(OperationFailureCode::Cancelled));
    }

    let source = super::resolve_file(request.source(), OperationFailureCode::SourceUnavailable)?;
    let key_file =
        super::resolve_file(request.key_file(), OperationFailureCode::KeyFileUnavailable)?;
    let bundle_leaf = request
        .destination()
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| super::OperationError::new(OperationFailureCode::UnsafePath))?;
    crate::extraction::validate_bundle_leaf(bundle_leaf)
        .map_err(|_| super::OperationError::new(OperationFailureCode::UnsafePath))?;
    let destination = super::resolve_destination_file(request.destination())?;
    if source.path == key_file.path
        || source.path == destination.path
        || key_file.path == destination.path
    {
        return Err(super::OperationError::new(OperationFailureCode::UnsafePath));
    }

    super::validate_file_route(&source, None).map_err(super::OperationError::new)?;
    super::validate_file_route(&key_file, None).map_err(super::OperationError::new)?;
    super::validate_file_route(&destination, None).map_err(super::OperationError::new)?;

    let destination_anchor = super::open_directory(destination.anchor())
        .map_err(|_| super::OperationError::new(OperationFailureCode::DestinationUnavailable))?;
    let destination_identity = super::required_identity(&destination_anchor)?;
    if !super::qualified_local_apfs_volume(&destination_anchor) {
        return Err(super::OperationError::new(
            OperationFailureCode::UnsupportedCapability,
        ));
    }
    super::require_directory_writable(&destination_anchor).map_err(super::OperationError::new)?;

    match std::fs::symlink_metadata(&destination.path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(entry) if entry.file_type().is_symlink() => {
            return Err(super::OperationError::new(OperationFailureCode::UnsafePath));
        }
        Ok(_) => {
            return Err(super::OperationError::new(
                OperationFailureCode::DestinationConflict,
            ));
        }
        Err(_) => {
            return Err(super::OperationError::new(
                OperationFailureCode::DestinationUnavailable,
            ));
        }
    }

    let source_directory = super::open_directory(&source.parent)
        .map_err(|_| super::OperationError::new(OperationFailureCode::SourceUnavailable))?;
    let key_directory = super::open_directory(&key_file.parent)
        .map_err(|_| super::OperationError::new(OperationFailureCode::KeyFileUnavailable))?;
    if handle_identity(&source_directory) != Some(source.parent_identity)
        || handle_identity(&key_directory) != Some(key_file.parent_identity)
    {
        return Err(super::OperationError::new(OperationFailureCode::StalePlan));
    }
    let mut source_file = super::open_file_at(&source_directory, &source.name)
        .map_err(|_| super::OperationError::new(OperationFailureCode::SourceUnavailable))?;
    let source_baseline = inspect_planning_file(
        &mut source_file,
        &cancellation,
        OperationFailureCode::SourceChanged,
    )?;
    let mut key_handle = super::open_file_at(&key_directory, &key_file.name)
        .map_err(|_| super::OperationError::new(OperationFailureCode::KeyFileUnavailable))?;
    let key_size = key_handle
        .metadata()
        .map_err(|_| super::OperationError::new(OperationFailureCode::KeyFileUnavailable))?
        .len();
    if key_size > MAX_KEY_FILE_BYTES {
        return Err(super::OperationError::new(
            OperationFailureCode::ResourceLimitExceeded,
        ));
    }
    let key_baseline = inspect_planning_file(
        &mut key_handle,
        &cancellation,
        OperationFailureCode::KeyFileChanged,
    )?;
    if source_baseline.identity == key_baseline.identity {
        return Err(super::OperationError::new(OperationFailureCode::UnsafePath));
    }

    key_handle
        .seek(SeekFrom::Start(0))
        .map_err(|_| super::OperationError::new(OperationFailureCode::KeyFileUnavailable))?;
    let header_key = read_header_key(&mut key_handle, key_size).map_err(|error| {
        super::OperationError::new(match error {
            crate::inspection::InspectionErrorCode::MissingHeaderKey => {
                OperationFailureCode::RequiredKeyMissing
            }
            crate::inspection::InspectionErrorCode::KeyFileMalformed => {
                OperationFailureCode::KeyFileMalformed
            }
            crate::inspection::InspectionErrorCode::KeyFileUnavailable => {
                OperationFailureCode::KeyFileUnavailable
            }
            crate::inspection::InspectionErrorCode::KeyFileLimitExceeded
            | crate::inspection::InspectionErrorCode::AllocationFailed => {
                OperationFailureCode::ResourceLimitExceeded
            }
            _ => OperationFailureCode::KeyFileMalformed,
        })
    })?;
    super::verify_file_evidence(&mut key_handle, &key_baseline)
        .map_err(|_| super::OperationError::new(OperationFailureCode::KeyFileChanged))?;

    let header = crate::nca::read_header(
        &mut source_file,
        source_baseline.snapshot.len,
        header_key.as_bytes(),
    )
    .map_err(|_| super::OperationError::new(OperationFailureCode::ValidationFailed))?;
    let inventory = crate::inspection::validate_native_inventory(&mut source_file, &header)
        .map_err(|_| super::OperationError::new(OperationFailureCode::ValidationFailed))?;
    let resolved = resolve_extraction(request.selection(), &inventory).map_err(|error| {
        use crate::extraction::ExtractionValidationError as Validation;
        super::OperationError::new(match error {
            Validation::EmptySelectors | Validation::EmptySelection | Validation::SelectorMiss => {
                OperationFailureCode::EmptySelection
            }
            Validation::UnsupportedPath | Validation::PathCollision => {
                OperationFailureCode::UnsafePath
            }
            Validation::ResourceLimitExceeded => OperationFailureCode::ResourceLimitExceeded,
        })
    })?;

    let mut selected_files = Vec::new();
    selected_files
        .try_reserve_exact(resolved.selected_files.len())
        .map_err(|_| super::OperationError::new(OperationFailureCode::ResourceLimitExceeded))?;
    let mut total_bytes = 0_u64;
    for span in &resolved.selected_files {
        if cancellation.is_cancelled() {
            return Err(super::OperationError::new(OperationFailureCode::Cancelled));
        }
        let relative_path = format!("{}/{}", span.partition_index, span.path);
        let digest = digest_source_span(&mut source_file, span.offset, span.size, &cancellation)
            .map_err(super::OperationError::new)?;
        total_bytes = total_bytes.checked_add(span.size).ok_or_else(|| {
            super::OperationError::new(OperationFailureCode::ResourceLimitExceeded)
        })?;
        selected_files.push(SelectedExtractionSpan {
            relative_path,
            offset: span.offset,
            size: span.size,
            sha256: digest,
        });
    }
    selected_files.sort_unstable_by(|left, right| {
        left.relative_path
            .as_bytes()
            .cmp(right.relative_path.as_bytes())
    });
    let source_after_planning = inspect_planning_file(
        &mut source_file,
        &cancellation,
        OperationFailureCode::SourceChanged,
    )?;
    if source_after_planning != source_baseline {
        return Err(super::OperationError::new(
            OperationFailureCode::SourceChanged,
        ));
    }
    let key_after_planning = inspect_planning_file(
        &mut key_handle,
        &cancellation,
        OperationFailureCode::KeyFileChanged,
    )?;
    if key_after_planning != key_baseline {
        return Err(super::OperationError::new(
            OperationFailureCode::KeyFileChanged,
        ));
    }

    let workspace = super::destination_local_workspace(destination.anchor(), destination_identity);
    let staging_strategy = StagingStrategy::DestinationLocalFallback;
    let destination_lock_path = destination
        .parent
        .join(super::destination_lock_name(&destination.path));
    let lock_name = destination_lock_path
        .file_name()
        .ok_or_else(|| super::OperationError::new(OperationFailureCode::UnsafePath))?;
    if source.path == destination_lock_path
        || key_file.path == destination_lock_path
        || (source.parent == destination.parent && source.name == lock_name)
        || (key_file.parent == destination.parent && key_file.name == lock_name)
    {
        return Err(super::OperationError::new(OperationFailureCode::UnsafePath));
    }
    let stage_directory_name = super::planned_artifact_name(&workspace.path, "extract-stage", true)
        .map_err(super::OperationError::new)?;
    let stage_path = workspace.path.join(&stage_directory_name);
    let destination_name = OsStr::new("bundle");
    let destination_state = DestinationBaseline::Absent;
    let manifest = resolved.manifest;
    let child_path_count = resolved
        .directories
        .len()
        .checked_add(selected_files.len())
        .and_then(|count| count.checked_add(2))
        .ok_or_else(|| super::OperationError::new(OperationFailureCode::ResourceLimitExceeded))?;
    if child_path_count > crate::partition_fs::MAX_TOTAL_ENTRIES {
        return Err(super::OperationError::new(
            OperationFailureCode::ResourceLimitExceeded,
        ));
    }
    let output_path_capacity = child_path_count
        .checked_add(1)
        .ok_or_else(|| super::OperationError::new(OperationFailureCode::ResourceLimitExceeded))?;
    let mut output_paths = Vec::new();
    output_paths
        .try_reserve_exact(output_path_capacity)
        .map_err(|_| super::OperationError::new(OperationFailureCode::ResourceLimitExceeded))?;
    output_paths.push(destination.path.clone());
    output_paths.push(destination.path.join("manifest.json"));
    output_paths.push(destination.path.join("content"));
    output_paths.extend(
        resolved
            .directories
            .iter()
            .map(|path| destination.path.join("content").join(path)),
    );
    output_paths.extend(
        selected_files
            .iter()
            .map(|file| destination.path.join("content").join(&file.relative_path)),
    );
    output_paths[1..].sort();
    let snapshot = OperationPlanSnapshot {
        kind: "operation_plan",
        operation_kind: OperationKind::Extract,
        nscb_version: env!("CARGO_PKG_VERSION"),
        source: PlannedSource {
            path: source.path.clone(),
            identity: source_baseline.identity.fingerprint(),
            size: source_baseline.snapshot.len,
            sha256: source_baseline.sha256,
        },
        sources: Vec::new(),
        content_groups: Vec::new(),
        extraction_manifest: Some(manifest.clone()),
        output_paths,
        destination: destination.path.clone(),
        workspace: workspace.path.clone(),
        staging_strategy,
        staging_parent_identity: destination_identity.fingerprint(),
        destination_lock_path,
        conflict_policy: ConflictPolicy::Fail,
        destination_baseline: destination_state,
        required_providers: Vec::new(),
        required_keys: vec!["nca_header_key".to_owned()],
        effects: vec![
            PlannedEffect::ReadSource,
            PlannedEffect::CoordinateDestination,
            PlannedEffect::CreatePrivateStagingDirectory,
            PlannedEffect::CreateStagingFile,
            PlannedEffect::CreateDestination,
        ],
        planned_artifacts: vec![
            PlannedArtifact {
                role: OperationArtifactRole::PrivateStagingDirectory,
                path: stage_path.clone(),
                expected_length: None,
                expected_sha256: None,
            },
            PlannedArtifact {
                role: OperationArtifactRole::StagedOutput,
                path: stage_path.join(destination_name),
                expected_length: None,
                expected_sha256: None,
            },
            PlannedArtifact {
                role: OperationArtifactRole::PublishedDestination,
                path: destination.path.clone(),
                expected_length: None,
                expected_sha256: None,
            },
        ],
    };

    super::validate_file_route(&source, None).map_err(super::OperationError::new)?;
    super::validate_file_route(&key_file, None).map_err(super::OperationError::new)?;
    super::validate_file_route(&destination, None).map_err(super::OperationError::new)?;
    super::validate_directory_route(&workspace, None).map_err(super::OperationError::new)?;
    let final_destination_anchor = super::open_directory(destination.anchor())
        .map_err(|_| super::OperationError::new(OperationFailureCode::DestinationUnavailable))?;
    if handle_identity(&final_destination_anchor) != Some(destination.parent_identity)
        || handle_identity(&final_destination_anchor) != Some(destination_identity)
    {
        return Err(super::OperationError::new(OperationFailureCode::StalePlan));
    }
    let source_after_routes = inspect_planning_file(
        &mut source_file,
        &cancellation,
        OperationFailureCode::SourceChanged,
    )?;
    if source_after_routes != source_baseline {
        return Err(super::OperationError::new(
            OperationFailureCode::SourceChanged,
        ));
    }
    let key_after_routes = inspect_planning_file(
        &mut key_handle,
        &cancellation,
        OperationFailureCode::KeyFileChanged,
    )?;
    if key_after_routes != key_baseline {
        return Err(super::OperationError::new(
            OperationFailureCode::KeyFileChanged,
        ));
    }
    match std::fs::symlink_metadata(&destination.path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(entry) if entry.file_type().is_symlink() => {
            return Err(super::OperationError::new(OperationFailureCode::UnsafePath));
        }
        Ok(_) => {
            return Err(super::OperationError::new(
                OperationFailureCode::DestinationConflict,
            ));
        }
        Err(_) => {
            return Err(super::OperationError::new(
                OperationFailureCode::DestinationUnavailable,
            ));
        }
    }

    Ok(OperationPlan {
        snapshot,
        source,
        source_baseline,
        workspace,
        destination,
        destination_baseline: None,
        already_up_to_date: false,
        skipped: false,
        stage_directory_name: Some(stage_directory_name),
        stage_file_name: None,
        backup_name: None,
        published_recovery_name: None,
        multi_content: None,
        xci_to_nsp: None,
        xci_to_xcz: None,
        nsp_nsz: None,
        xcz_to_xci: None,
        extraction: Some(ExtractionOperationPlan {
            key_file,
            key_baseline,
            selected_files,
            directories: resolved.directories,
            manifest,
            total_bytes,
        }),
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn inspect_planning_file(
    file: &mut File,
    cancellation: &CancellationHandle,
    changed: OperationFailureCode,
) -> Result<super::FileEvidence, super::OperationError> {
    let length = file
        .metadata()
        .map_err(|_| super::OperationError::new(changed))?
        .len();
    super::inspect_file_with_length_and_fallible_checkpoint(file, length, || {
        if cancellation.is_cancelled() {
            Err(OperationFailureCode::Cancelled)
        } else {
            Ok(())
        }
    })
    .map_err(super::OperationError::new)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn digest_source_span(
    source: &mut File,
    offset: u64,
    size: u64,
    cancellation: &CancellationHandle,
) -> Result<Sha256Digest, OperationFailureCode> {
    use sha2::{Digest as _, Sha256};

    source
        .seek(SeekFrom::Start(offset))
        .map_err(|_| OperationFailureCode::SourceChanged)?;
    let mut digest = Sha256::new();
    let mut remaining = size;
    let mut buffer = [0_u8; super::IO_BUFFER_SIZE];
    while remaining != 0 {
        if cancellation.is_cancelled() {
            return Err(OperationFailureCode::Cancelled);
        }
        let length = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
        let read = source
            .read(&mut buffer[..length])
            .map_err(|_| OperationFailureCode::SourceChanged)?;
        if read == 0 {
            return Err(OperationFailureCode::SourceChanged);
        }
        digest.update(&buffer[..read]);
        remaining -= read as u64;
    }
    Ok(Sha256Digest::from_bytes(digest.finalize().into()))
}

#[cfg(target_os = "macos")]
pub(super) fn execute_unix(
    plan: &OperationPlan,
    session: &super::OperationSession,
    outputs: &mut super::ExecutionOutputs<'_>,
    checkpoint: &mut impl FnMut(super::ExecutionCheckpoint),
) -> Result<super::OperationOutcome, OperationFailureCode> {
    use super::{OperationMilestone, OperationOutcome};
    use std::ffi::OsStr;

    let extraction = plan
        .extraction
        .as_ref()
        .ok_or(OperationFailureCode::StalePlan)?;
    super::check_cancelled(session)?;
    super::validate_file_route(&plan.source, None).map_err(|_| OperationFailureCode::StalePlan)?;
    super::validate_file_route(&plan.destination, None)
        .map_err(|_| OperationFailureCode::StalePlan)?;
    super::validate_file_route(&extraction.key_file, None)
        .map_err(|_| OperationFailureCode::StalePlan)?;
    super::validate_directory_route(&plan.workspace, None)
        .map_err(|_| OperationFailureCode::StalePlan)?;

    let source_directory = super::open_directory(&plan.source.parent)
        .map_err(|_| OperationFailureCode::SourceUnavailable)?;
    let destination_anchor = super::open_directory(plan.destination.anchor())
        .map_err(|_| OperationFailureCode::DestinationUnavailable)?;
    let workspace_anchor = plan
        .workspace
        .identity
        .map(|_| plan.workspace.path.as_path())
        .or(plan.workspace.creation_parent.as_deref())
        .ok_or(OperationFailureCode::WorkspaceUnavailable)?;
    let workspace_directory = super::open_directory(workspace_anchor)
        .map_err(|_| OperationFailureCode::WorkspaceUnavailable)?;
    super::verify_directory_identity(&source_directory, plan.source.parent_identity)?;
    super::verify_directory_identity(&destination_anchor, plan.destination.parent_identity)?;
    let workspace_identity = plan
        .workspace
        .identity
        .or(plan.workspace.creation_parent_identity)
        .ok_or(OperationFailureCode::WorkspaceUnavailable)?;
    super::verify_directory_identity(&workspace_directory, workspace_identity)?;
    if !super::qualified_local_apfs_volume(&destination_anchor)
        || !super::qualified_local_apfs_volume(&workspace_directory)
        || !handle_identity(&workspace_directory)
            .zip(handle_identity(&destination_anchor))
            .is_some_and(|(workspace, destination)| workspace.same_filesystem_as(destination))
    {
        return Err(OperationFailureCode::UnsupportedCapability);
    }
    super::require_directory_writable(&workspace_directory)?;

    let mut source_file = super::open_file_at(&source_directory, &plan.source.name)
        .map_err(|_| OperationFailureCode::SourceUnavailable)?;
    super::verify_file_evidence(&mut source_file, &plan.source_baseline)
        .map_err(|_| OperationFailureCode::SourceChanged)?;
    let source_guard = outputs
        .source_lock
        .insert(super::SourceLockGuard { file: source_file });
    super::acquire_source_lock(
        &source_guard.file,
        &source_directory,
        plan,
        session,
        checkpoint,
    )?;
    let source_file = &mut source_guard.file;
    super::verify_file_evidence(source_file, &plan.source_baseline)
        .map_err(|_| OperationFailureCode::SourceChanged)?;
    super::verify_conversion_key_identity(plan)?;

    let mut destination_directory = destination_anchor;
    if plan.destination.creation_parent.is_some() {
        super::validate_file_route(&plan.destination, None)
            .map_err(|_| OperationFailureCode::StalePlan)?;
        let parent_name = plan
            .destination
            .parent
            .file_name()
            .ok_or(OperationFailureCode::UnsafePath)?;
        match super::make_directory_at(&destination_directory, parent_name) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(OperationFailureCode::StalePlan);
            }
            Err(_) => return Err(OperationFailureCode::DestinationUnavailable),
        }
        destination_directory
            .sync_all()
            .map_err(|_| OperationFailureCode::DestinationUnavailable)?;
        destination_directory = super::open_directory_at(&destination_directory, parent_name)
            .map_err(|_| OperationFailureCode::DestinationUnavailable)?;
        let identity = handle_identity(&destination_directory)
            .ok_or(OperationFailureCode::UnsupportedCapability)?;
        if !super::qualified_local_apfs_volume(&destination_directory)
            || !handle_identity(&workspace_directory)
                .is_some_and(|workspace| workspace.same_filesystem_as(identity))
        {
            return Err(OperationFailureCode::UnsupportedCapability);
        }
        super::require_directory_writable(&destination_directory)
            .map_err(|_| OperationFailureCode::DestinationUnavailable)?;
        *outputs.destination_parent_identity = Some(identity);
    }
    let destination_parent_identity = handle_identity(&destination_directory)
        .ok_or(OperationFailureCode::UnsupportedCapability)?;
    if plan.destination.creation_parent.is_none()
        && destination_parent_identity != plan.destination.parent_identity
    {
        return Err(OperationFailureCode::StalePlan);
    }
    *outputs.destination_parent_identity = Some(destination_parent_identity);
    super::validate_file_route(&plan.destination, Some(destination_parent_identity))
        .map_err(|_| OperationFailureCode::StalePlan)?;
    ensure_destination_absent(&destination_directory, &plan.destination.name)?;

    let lock_name = plan
        .snapshot
        .destination_lock_path
        .file_name()
        .ok_or(OperationFailureCode::UnsafePath)?
        .to_os_string();
    if lock_name == plan.destination.name
        || (plan.source.parent == plan.destination.parent && lock_name == plan.source.name)
        || (extraction.key_file.parent == plan.destination.parent
            && lock_name == extraction.key_file.name)
    {
        return Err(OperationFailureCode::UnsafePath);
    }
    let destination_lock = super::acquire_destination_lock(
        &destination_directory,
        &lock_name,
        &plan.destination.parent,
        &plan.source_baseline,
        None,
        session,
        checkpoint,
    )?;
    super::validate_destination_lock(
        &destination_lock,
        &destination_directory,
        plan,
        destination_parent_identity,
    )?;
    super::validate_plan_routes(
        plan,
        Some(workspace_identity),
        Some(destination_parent_identity),
    )?;
    super::verify_source_entry(plan, &source_directory)?;
    super::verify_conversion_key_identity(plan)?;
    ensure_destination_absent(&destination_directory, &plan.destination.name)?;

    let manifest_bytes = extraction
        .manifest
        .to_json_bytes()
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    let required_space = extraction
        .total_bytes
        .checked_add(manifest_bytes.len() as u64)
        .ok_or(OperationFailureCode::ResourceLimitExceeded)?;
    let available = super::available_space_on_open_directory(&workspace_directory)?;
    super::ensure_storage_capacity(
        available,
        required_space,
        None,
        super::MINIMUM_FREE_SPACE_RESERVE,
    )?;

    let stage_directory_name = plan
        .stage_directory_name
        .as_deref()
        .ok_or(OperationFailureCode::StalePlan)?;
    let stage_directory_path = plan.workspace.path.join(stage_directory_name);
    let stage_directory = super::create_private_stage_directory(
        &workspace_directory,
        &plan.workspace.path,
        stage_directory_name,
        outputs.artifacts,
        outputs.cleanup_artifact_retained,
    )?;
    let bundle_name = OsStr::new("bundle");
    let bundle_path = stage_directory_path.join(bundle_name);
    let (bundle_directory, bundle_artifact_id, bundle_identity) = create_bundle_root(
        &stage_directory,
        &stage_directory_path,
        bundle_name,
        &bundle_path,
        outputs.artifacts,
        outputs.cleanup_artifact_retained,
    )?;

    write_extraction_tree(
        source_file,
        &bundle_directory,
        extraction,
        &manifest_bytes,
        session,
    )?;
    let bundle_manifest_sha256 = super::directory_manifest(&bundle_path, &bundle_directory)?;
    sync_for_extraction(
        &bundle_directory,
        ExtractionIoFailurePoint::BundlePrepromotion,
    )?;
    verify_source_for_promotion(plan, &source_directory, source_file, session, checkpoint)?;
    super::verify_conversion_key_identity(plan)?;
    super::validate_plan_routes(
        plan,
        Some(workspace_identity),
        Some(destination_parent_identity),
    )?;
    ensure_destination_absent(&destination_directory, &plan.destination.name)?;

    let destination_artifact_directory = destination_directory
        .try_clone()
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    checkpoint(super::ExecutionCheckpoint::BeforeAtomicPromotion);
    super::check_cancelled(session)?;
    super::validate_destination_lock(
        &destination_lock,
        &destination_directory,
        plan,
        destination_parent_identity,
    )?;
    super::validate_plan_routes(
        plan,
        Some(workspace_identity),
        Some(destination_parent_identity),
    )?;
    verify_source_for_promotion(plan, &source_directory, source_file, session, checkpoint)?;
    super::verify_conversion_key_identity(plan)?;
    ensure_destination_absent(&destination_directory, &plan.destination.name)?;
    validate_bundle_tree(
        &bundle_directory,
        extraction,
        &manifest_bytes,
        Some(session),
    )?;
    super::verify_directory_identity(&workspace_directory, workspace_identity)?;
    super::verify_directory_identity(&destination_directory, destination_parent_identity)?;
    let named_bundle = super::open_directory_at(&stage_directory, bundle_name)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    if handle_identity(&named_bundle) != Some(bundle_identity) {
        return Err(OperationFailureCode::ValidationFailed);
    }
    super::validate_destination_lock(
        &destination_lock,
        &destination_directory,
        plan,
        destination_parent_identity,
    )?;
    super::validate_plan_routes(
        plan,
        Some(workspace_identity),
        Some(destination_parent_identity),
    )?;
    if !session
        .begin_promotion()
        .map_err(|_| OperationFailureCode::SessionUnavailable)?
    {
        return Err(OperationFailureCode::Cancelled);
    }
    checkpoint(super::ExecutionCheckpoint::AtomicPromotionStarted);
    let promotion = super::rename_exclusive_at(
        &stage_directory,
        bundle_name,
        &destination_directory,
        &plan.destination.name,
    );
    if promotion.is_ok() {
        outputs.milestones.push(OperationMilestone::Published);
        session.record_milestone(OperationMilestone::Published);
    }
    if session.finish_promotion().is_err() {
        return if promotion.is_ok() {
            Err(mark_publication_uncertain(
                outputs.artifacts,
                outputs.cleanup_artifact_retained,
                bundle_artifact_id,
                plan,
                &destination_directory,
            ))
        } else {
            Err(OperationFailureCode::SessionUnavailable)
        };
    }
    if let Err(error) = promotion {
        return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
            OperationFailureCode::DestinationConflict
        } else if super::is_unsupported_rename_error(&error) {
            OperationFailureCode::UnsupportedCapability
        } else {
            OperationFailureCode::PublicationFailed
        });
    }
    if update_published_artifact(
        outputs.artifacts,
        bundle_artifact_id,
        plan,
        destination_artifact_directory,
        destination_parent_identity,
        bundle_identity,
        bundle_manifest_sha256,
    )
    .is_err()
    {
        return Err(mark_publication_uncertain(
            outputs.artifacts,
            outputs.cleanup_artifact_retained,
            bundle_artifact_id,
            plan,
            &destination_directory,
        ));
    }
    if sync_for_extraction(
        &stage_directory,
        ExtractionIoFailurePoint::StageParentAfterRename,
    )
    .is_err()
        || sync_for_extraction(
            &destination_directory,
            ExtractionIoFailurePoint::DestinationParentDurability,
        )
        .is_err()
    {
        return Err(mark_publication_uncertain(
            outputs.artifacts,
            outputs.cleanup_artifact_retained,
            bundle_artifact_id,
            plan,
            &destination_directory,
        ));
    }
    checkpoint(super::ExecutionCheckpoint::AfterPromotion);

    let postcondition = (|| {
        super::validate_file_route(&plan.destination, Some(destination_parent_identity))
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        let current_parent = super::open_directory(&plan.destination.parent)
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        if handle_identity(&current_parent) != Some(destination_parent_identity) {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        let published = super::open_directory_at(&destination_directory, &plan.destination.name)
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        if handle_identity(&published) != Some(bundle_identity) {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        validate_bundle_tree(&published, extraction, &manifest_bytes, Some(session))
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        verify_source_for_promotion(plan, &source_directory, source_file, session, checkpoint)
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        super::verify_conversion_key_identity(plan)
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        let named_again = super::open_directory_at(&destination_directory, &plan.destination.name)
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        if handle_identity(&named_again) != Some(bundle_identity) {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        super::validate_file_route(&plan.destination, Some(destination_parent_identity))
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        let final_parent = super::open_directory(&plan.destination.parent)
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        if handle_identity(&final_parent) != Some(destination_parent_identity) {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        Ok(())
    })();
    if postcondition.is_err() {
        return Err(mark_publication_uncertain(
            outputs.artifacts,
            outputs.cleanup_artifact_retained,
            bundle_artifact_id,
            plan,
            &destination_directory,
        ));
    }

    outputs.milestones.push(OperationMilestone::Validated);
    session.record_milestone(OperationMilestone::Validated);
    Ok(OperationOutcome::Extracted)
}

#[cfg(target_os = "macos")]
fn create_bundle_root(
    parent: &File,
    parent_path: &std::path::Path,
    name: &std::ffi::OsStr,
    path: &std::path::Path,
    artifacts: &mut Vec<super::OwnedArtifact>,
    cleanup_artifact_retained: &mut bool,
) -> Result<(File, u64, crate::file_identity::FileIdentity), OperationFailureCode> {
    let parent_handle = parent
        .try_clone()
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    let parent_identity = handle_identity(parent);
    let artifact_id = super::next_artifact_id(artifacts);
    let parent_artifact_id =
        super::parent_artifact_id_for_path(artifacts, parent_path, parent_identity);
    if let Err(error) = super::make_directory_at(parent, name) {
        return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
            OperationFailureCode::StalePlan
        } else {
            OperationFailureCode::WriteFailed
        });
    }
    let directory = match super::open_directory_at(parent, name) {
        Ok(directory) => directory,
        Err(_) => {
            artifacts.push(super::OwnedArtifact {
                id: artifact_id,
                parent_artifact_id,
                relative_name: PathBuf::from(name),
                parent_identity,
                directory: parent_handle,
                name: name.to_os_string(),
                path: path.to_path_buf(),
                identity: None,
                kind: super::OwnedArtifactKind::Directory,
                role: super::OperationArtifactRole::StagedOutput,
                length: None,
                sha256: None,
                path_identity: None,
                path_length: None,
                keep: true,
            });
            *cleanup_artifact_retained = true;
            return Err(OperationFailureCode::PublicationUncertain);
        }
    };
    let identity = handle_identity(&directory);
    artifacts.push(super::OwnedArtifact {
        id: artifact_id,
        parent_artifact_id,
        relative_name: PathBuf::from(name),
        parent_identity,
        directory: parent_handle,
        name: name.to_os_string(),
        path: path.to_path_buf(),
        identity,
        kind: super::OwnedArtifactKind::Directory,
        role: super::OperationArtifactRole::StagedOutput,
        length: None,
        sha256: None,
        path_identity: identity,
        path_length: None,
        keep: identity.is_none(),
    });
    let Some(identity) = identity else {
        *cleanup_artifact_retained = true;
        return Err(OperationFailureCode::UnsupportedCapability);
    };
    Ok((directory, artifact_id, identity))
}

#[cfg(target_os = "macos")]
fn update_published_artifact(
    artifacts: &mut [super::OwnedArtifact],
    artifact_id: u64,
    plan: &OperationPlan,
    destination_directory: File,
    destination_parent_identity: crate::file_identity::FileIdentity,
    identity: crate::file_identity::FileIdentity,
    directory_manifest_sha256: Sha256Digest,
) -> Result<(), OperationFailureCode> {
    let artifact = artifacts
        .iter_mut()
        .find(|artifact| artifact.id == artifact_id)
        .ok_or(OperationFailureCode::PublicationUncertain)?;
    artifact.parent_artifact_id = None;
    artifact.relative_name = PathBuf::from(&plan.destination.name);
    artifact.parent_identity = Some(destination_parent_identity);
    artifact.directory = destination_directory;
    artifact.name = plan.destination.name.clone();
    artifact.path = plan.destination.path.clone();
    artifact.identity = Some(identity);
    artifact.kind = super::OwnedArtifactKind::Directory;
    artifact.role = super::OperationArtifactRole::PublishedDestination;
    artifact.length = None;
    artifact.sha256 = Some(directory_manifest_sha256);
    artifact.path_identity = Some(identity);
    artifact.path_length = None;
    artifact.keep = true;
    Ok(())
}

#[cfg(target_os = "macos")]
fn mark_publication_uncertain(
    artifacts: &mut [super::OwnedArtifact],
    cleanup_artifact_retained: &mut bool,
    artifact_id: u64,
    plan: &OperationPlan,
    held_destination_parent: &File,
) -> OperationFailureCode {
    let observed = observed_destination_entry(plan, held_destination_parent);
    if let Some(artifact) = artifacts
        .iter_mut()
        .find(|artifact| artifact.id == artifact_id)
    {
        artifact.role = super::OperationArtifactRole::UncertainEntry;
        artifact.keep = true;
        artifact.path_identity = observed.map(|(identity, _)| identity);
        artifact.path_length = observed.and_then(|(_, length)| length);
    }
    *cleanup_artifact_retained = true;
    OperationFailureCode::PublicationUncertain
}

#[cfg(target_os = "macos")]
fn observed_destination_entry(
    plan: &OperationPlan,
    held_destination_parent: &File,
) -> Option<(crate::file_identity::FileIdentity, Option<u64>)> {
    let current_parent = std::fs::canonicalize(&plan.destination.requested_parent)
        .ok()
        .and_then(|path| super::open_directory(&path).ok());
    let parent = current_parent.as_ref().unwrap_or(held_destination_parent);
    if let Ok(directory) = super::open_directory_at(parent, &plan.destination.name) {
        return handle_identity(&directory).map(|identity| (identity, None));
    }
    let file = super::open_file_at(parent, &plan.destination.name).ok()?;
    let identity = handle_identity(&file)?;
    let length = file.metadata().ok().map(|metadata| metadata.len());
    Some((identity, length))
}

#[cfg(target_os = "macos")]
fn ensure_destination_absent(
    directory: &File,
    name: &std::ffi::OsStr,
) -> Result<(), OperationFailureCode> {
    use std::os::fd::AsRawFd;

    let name = super::c_name(name).map_err(|_| OperationFailureCode::UnsafePath)?;
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the directory descriptor is open and status points to an output buffer.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            status.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Err(OperationFailureCode::DestinationConflict);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(OperationFailureCode::DestinationUnavailable)
    }
}

#[cfg(target_os = "macos")]
fn verify_source_for_promotion(
    plan: &OperationPlan,
    source_directory: &File,
    locked_source: &mut File,
    session: &super::OperationSession,
    checkpoint: &mut impl FnMut(super::ExecutionCheckpoint),
) -> Result<(), OperationFailureCode> {
    super::check_cancelled(session)?;
    super::validate_file_route(&plan.source, None).map_err(|_| OperationFailureCode::StalePlan)?;
    let mut named_source = super::open_file_at(source_directory, &plan.source.name)
        .map_err(|_| OperationFailureCode::SourceChanged)?;
    let expected_identity = Some(plan.source_baseline.identity);
    if handle_identity(locked_source) != expected_identity
        || handle_identity(&named_source) != expected_identity
    {
        return Err(OperationFailureCode::SourceChanged);
    }
    let observed = super::inspect_file_with_length_and_fallible_checkpoint(
        &mut named_source,
        plan.source_baseline.snapshot.len,
        || {
            checkpoint(super::ExecutionCheckpoint::SourceEvidenceReadChunk);
            super::check_cancelled(session)
        },
    )?;
    if observed != plan.source_baseline {
        return Err(OperationFailureCode::SourceChanged);
    }
    super::validate_file_route(&plan.source, None).map_err(|_| OperationFailureCode::StalePlan)?;
    let named_again = super::open_file_at(source_directory, &plan.source.name)
        .map_err(|_| OperationFailureCode::SourceChanged)?;
    if handle_identity(&named_again) != expected_identity
        || handle_identity(locked_source) != expected_identity
    {
        return Err(OperationFailureCode::SourceChanged);
    }
    super::check_cancelled(session)
}

#[cfg(target_os = "macos")]
fn write_extraction_tree(
    source: &mut File,
    bundle: &File,
    extraction: &ExtractionOperationPlan,
    manifest_bytes: &[u8],
    session: &super::OperationSession,
) -> Result<(), OperationFailureCode> {
    use std::ffi::OsStr;
    use std::io::Write;

    let content_name = OsStr::new("content");
    super::make_directory_at(bundle, content_name)
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    bundle
        .sync_all()
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    let content = super::open_directory_at(bundle, content_name)
        .map_err(|_| OperationFailureCode::WriteFailed)?;

    for relative in &extraction.directories {
        let (parent_path, leaf) = split_parent_and_leaf(relative)?;
        let parent = open_relative_directory(&content, parent_path)?;
        let name = OsStr::new(leaf);
        super::make_directory_at(&parent, name)
            .map_err(|_| OperationFailureCode::ValidationFailed)?;
        parent
            .sync_all()
            .map_err(|_| OperationFailureCode::WriteFailed)?;
    }

    let mut completed = 0_u64;
    for selected in &extraction.selected_files {
        super::check_cancelled(session)?;
        let (parent_path, leaf) = split_parent_and_leaf(&selected.relative_path)?;
        let parent = open_relative_directory(&content, parent_path)?;
        let mut output = create_output_file_at(&parent, OsStr::new(leaf))?;
        let copied = copy_selected_span(source, &mut output, selected, completed, session)?;
        completed = completed
            .checked_add(copied)
            .ok_or(OperationFailureCode::ResourceLimitExceeded)?;
        output
            .sync_all()
            .map_err(|_| OperationFailureCode::WriteFailed)?;
        parent
            .sync_all()
            .map_err(|_| OperationFailureCode::WriteFailed)?;
    }
    if completed != extraction.total_bytes {
        return Err(OperationFailureCode::ValidationFailed);
    }

    let mut manifest = create_output_file_at(bundle, OsStr::new("manifest.json"))?;
    manifest
        .write_all(manifest_bytes)
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    manifest
        .sync_all()
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    bundle
        .sync_all()
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    content
        .sync_all()
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn copy_selected_span(
    source: &mut File,
    destination: &mut File,
    selected: &SelectedExtractionSpan,
    completed_before: u64,
    session: &super::OperationSession,
) -> Result<u64, OperationFailureCode> {
    use sha2::{Digest as _, Sha256};
    source
        .seek(SeekFrom::Start(selected.offset))
        .map_err(|_| OperationFailureCode::SourceChanged)?;
    let mut remaining = selected.size;
    let mut copied = 0_u64;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; super::IO_BUFFER_SIZE];
    while remaining != 0 {
        super::check_cancelled(session)?;
        let capacity = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
        let read = source
            .read(&mut buffer[..capacity])
            .map_err(|_| OperationFailureCode::SourceChanged)?;
        if read == 0 {
            return Err(OperationFailureCode::SourceChanged);
        }
        write_payload_chunk(destination, &buffer[..read])
            .map_err(|_| OperationFailureCode::WriteFailed)?;
        digest.update(&buffer[..read]);
        copied = copied
            .checked_add(read as u64)
            .ok_or(OperationFailureCode::ResourceLimitExceeded)?;
        remaining -= read as u64;
        session.record_progress(completed_before.saturating_add(copied));
    }
    let digest = Sha256Digest::from_bytes(digest.finalize().into());
    if copied != selected.size || digest != selected.sha256 {
        return Err(OperationFailureCode::SourceChanged);
    }
    Ok(copied)
}

#[cfg(target_os = "macos")]
fn split_parent_and_leaf(path: &str) -> Result<(&str, &str), OperationFailureCode> {
    crate::extraction::validate_selected_relative_path(path)
        .map_err(|_| OperationFailureCode::UnsafePath)?;
    match path.rsplit_once('/') {
        Some((parent, leaf)) => Ok((parent, leaf)),
        None => Ok(("", path)),
    }
}

#[cfg(target_os = "macos")]
fn open_relative_directory(root: &File, relative: &str) -> Result<File, OperationFailureCode> {
    let mut current = root
        .try_clone()
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    if relative.is_empty() {
        return Ok(current);
    }
    crate::extraction::validate_selected_relative_path(relative)
        .map_err(|_| OperationFailureCode::UnsafePath)?;
    for component in relative.split('/') {
        current = super::open_directory_at(&current, std::ffi::OsStr::new(component))
            .map_err(|_| OperationFailureCode::ValidationFailed)?;
    }
    Ok(current)
}

#[cfg(target_os = "macos")]
fn create_output_file_at(
    parent: &File,
    name: &std::ffi::OsStr,
) -> Result<File, OperationFailureCode> {
    super::create_file_at(parent, name).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            OperationFailureCode::ValidationFailed
        } else {
            OperationFailureCode::WriteFailed
        }
    })
}

#[cfg(target_os = "macos")]
pub(super) fn validate_published_bundle_tree(
    bundle: &File,
    extraction: &ExtractionOperationPlan,
) -> Result<(), OperationFailureCode> {
    let manifest_bytes = extraction
        .manifest
        .to_json_bytes()
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    validate_bundle_tree(bundle, extraction, &manifest_bytes, None)
}

#[cfg(target_os = "macos")]
fn validate_bundle_tree(
    bundle: &File,
    extraction: &ExtractionOperationPlan,
    manifest_bytes: &[u8],
    session: Option<&super::OperationSession>,
) -> Result<(), OperationFailureCode> {
    let mut expected_directories = Vec::new();
    expected_directories
        .try_reserve_exact(extraction.directories.len().saturating_add(1))
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    expected_directories.push("content".to_owned());
    for relative in &extraction.directories {
        expected_directories.push(prefixed_path("content", relative)?);
    }
    expected_directories.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

    let mut expected_files = Vec::new();
    expected_files
        .try_reserve_exact(extraction.selected_files.len().saturating_add(1))
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    expected_files.push("manifest.json".to_owned());
    for selected in &extraction.selected_files {
        expected_files.push(prefixed_path("content", &selected.relative_path)?);
    }
    expected_files.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

    let mut actual_directories = Vec::new();
    actual_directories
        .try_reserve_exact(expected_directories.len())
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    let mut actual_files = Vec::new();
    actual_files
        .try_reserve_exact(expected_files.len())
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    let mut pending_directories = Vec::new();
    pending_directories
        .try_reserve_exact(expected_directories.len())
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    pending_directories.push(String::new());

    while let Some(relative_directory) = pending_directories.pop() {
        if let Some(session) = session {
            super::check_cancelled(session)?;
        }
        let directory = open_relative_directory(bundle, &relative_directory)?;
        visit_directory_entries(&directory, |name, is_directory| {
            if let Some(session) = session {
                super::check_cancelled(session)?;
            }
            let leaf = name
                .to_str()
                .ok_or(OperationFailureCode::ValidationFailed)?;
            let relative = if relative_directory.is_empty() {
                copy_path_component(leaf)?
            } else {
                prefixed_path(&relative_directory, leaf)?
            };
            if is_directory {
                if expected_directories
                    .binary_search_by(|expected| expected.as_bytes().cmp(relative.as_bytes()))
                    .is_err()
                {
                    return Err(OperationFailureCode::ValidationFailed);
                }
                actual_directories
                    .try_reserve(1)
                    .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
                pending_directories
                    .try_reserve(1)
                    .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
                actual_directories.push(relative.clone());
                pending_directories.push(relative);
                return Ok(());
            }

            if expected_files
                .binary_search_by(|expected| expected.as_bytes().cmp(relative.as_bytes()))
                .is_err()
            {
                return Err(OperationFailureCode::ValidationFailed);
            }
            actual_files
                .try_reserve(1)
                .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
            actual_files.push(relative.clone());
            if relative == "manifest.json" {
                validate_regular_file_at(&directory, name, |manifest_file| {
                    validate_manifest_file(manifest_file, &extraction.manifest, manifest_bytes)
                })
            } else {
                let payload_path = relative
                    .strip_prefix("content/")
                    .ok_or(OperationFailureCode::ValidationFailed)?;
                let selected_index = extraction
                    .selected_files
                    .binary_search_by(|selected| {
                        selected
                            .relative_path
                            .as_bytes()
                            .cmp(payload_path.as_bytes())
                    })
                    .map_err(|_| OperationFailureCode::ValidationFailed)?;
                let expected = &extraction.selected_files[selected_index];
                validate_regular_file_at(&directory, name, |file| {
                    validate_payload_file(file, expected, session)
                })
            }
        })?;
    }

    actual_directories.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    actual_files.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    if actual_directories != expected_directories || actual_files != expected_files {
        return Err(OperationFailureCode::ValidationFailed);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_regular_file_at(
    parent: &File,
    name: &std::ffi::OsStr,
    validate_contents: impl FnOnce(&mut File) -> Result<(), OperationFailureCode>,
) -> Result<(), OperationFailureCode> {
    let mut file =
        super::open_file_at(parent, name).map_err(|_| OperationFailureCode::ValidationFailed)?;
    let expected_identity = single_link_file_identity(&file)?;
    validate_contents(&mut file)?;
    if single_link_file_identity(&file)? != expected_identity {
        return Err(OperationFailureCode::ValidationFailed);
    }

    let named_again =
        super::open_file_at(parent, name).map_err(|_| OperationFailureCode::ValidationFailed)?;
    if single_link_file_identity(&named_again)? != expected_identity {
        return Err(OperationFailureCode::ValidationFailed);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn single_link_file_identity(file: &File) -> Result<(u64, u64), OperationFailureCode> {
    let metadata = file
        .metadata()
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(OperationFailureCode::ValidationFailed);
    }
    let identity = crate::file_identity::file_identity(&metadata)
        .ok_or(OperationFailureCode::ValidationFailed)?;
    Ok((identity.device(), identity.inode()))
}

#[cfg(target_os = "macos")]
fn validate_manifest_file(
    file: &mut File,
    manifest: &crate::extraction::ExtractionManifest,
    expected_bytes: &[u8],
) -> Result<(), OperationFailureCode> {
    let observed_length = file
        .metadata()
        .map_err(|_| OperationFailureCode::ValidationFailed)?
        .len();
    if observed_length != expected_bytes.len() as u64 {
        return Err(OperationFailureCode::ValidationFailed);
    }
    let mut observed = Vec::new();
    observed
        .try_reserve_exact(expected_bytes.len())
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    observed.resize(expected_bytes.len(), 0);
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.read_exact(&mut observed))
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    let mut trailing_byte = [0_u8; 1];
    if file
        .read(&mut trailing_byte)
        .map_err(|_| OperationFailureCode::ValidationFailed)?
        != 0
        || observed != expected_bytes
    {
        return Err(OperationFailureCode::ValidationFailed);
    }
    let parsed: serde_json::Value =
        serde_json::from_slice(&observed).map_err(|_| OperationFailureCode::ValidationFailed)?;
    let expected =
        serde_json::to_value(manifest).map_err(|_| OperationFailureCode::ValidationFailed)?;
    if parsed == expected {
        Ok(())
    } else {
        Err(OperationFailureCode::ValidationFailed)
    }
}

#[cfg(target_os = "macos")]
fn validate_payload_file(
    file: &mut File,
    expected: &SelectedExtractionSpan,
    session: Option<&super::OperationSession>,
) -> Result<(), OperationFailureCode> {
    let observed =
        super::inspect_file_with_length_and_fallible_checkpoint(file, expected.size, || {
            session.map_or(Ok(()), super::check_cancelled)
        })
        .map_err(|error| {
            if error == OperationFailureCode::Cancelled {
                error
            } else {
                OperationFailureCode::ValidationFailed
            }
        })?;
    if observed.snapshot.len == expected.size && observed.sha256 == expected.sha256 {
        Ok(())
    } else {
        Err(OperationFailureCode::ValidationFailed)
    }
}

#[cfg(target_os = "macos")]
fn prefixed_path(prefix: &str, suffix: &str) -> Result<String, OperationFailureCode> {
    let length = prefix
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(suffix.len()))
        .ok_or(OperationFailureCode::ResourceLimitExceeded)?;
    let mut result = String::new();
    result
        .try_reserve_exact(length)
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    result.push_str(prefix);
    result.push('/');
    result.push_str(suffix);
    Ok(result)
}

#[cfg(target_os = "macos")]
fn copy_path_component(component: &str) -> Result<String, OperationFailureCode> {
    let mut result = String::new();
    result
        .try_reserve_exact(component.len())
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    result.push_str(component);
    Ok(result)
}

#[cfg(target_os = "macos")]
struct DirectoryStream(*mut libc::DIR);

#[cfg(target_os = "macos")]
impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: this stream was returned by fdopendir and is closed once here.
        unsafe {
            libc::closedir(self.0);
        }
    }
}

#[cfg(target_os = "macos")]
fn visit_directory_entries(
    directory: &File,
    mut visit: impl FnMut(&std::ffi::OsStr, bool) -> Result<(), OperationFailureCode>,
) -> Result<(), OperationFailureCode> {
    use std::ffi::CStr;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: directory is open; dup creates the descriptor owned by fdopendir.
    let duplicate = unsafe { libc::dup(directory.as_raw_fd()) };
    if duplicate < 0 {
        return Err(OperationFailureCode::ValidationFailed);
    }
    // SAFETY: duplicate is a valid descriptor and fdopendir takes ownership.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        // SAFETY: fdopendir failed and therefore did not take ownership.
        unsafe {
            libc::close(duplicate);
        }
        return Err(OperationFailureCode::ValidationFailed);
    }
    let stream = DirectoryStream(stream);
    loop {
        // SAFETY: __error returns this thread's errno slot.
        unsafe {
            *libc::__error() = 0;
        }
        // SAFETY: stream is a live DIR pointer and remains valid until closedir.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            // SAFETY: __error returns this thread's errno slot.
            if unsafe { *libc::__error() } != 0 {
                return Err(OperationFailureCode::ValidationFailed);
            }
            break;
        }
        // SAFETY: d_name is NUL terminated in the live dirent returned by readdir.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: entry name is NUL terminated; status is a full output structure.
        let stat_result = unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                status.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if stat_result != 0 {
            return Err(OperationFailureCode::ValidationFailed);
        }
        // SAFETY: fstatat returned success and initialized status.
        let status = unsafe { status.assume_init() };
        let entry_type = status.st_mode & libc::S_IFMT;
        let is_directory = if entry_type == libc::S_IFDIR {
            true
        } else if entry_type == libc::S_IFREG {
            false
        } else {
            return Err(OperationFailureCode::ValidationFailed);
        };
        visit(std::ffi::OsStr::from_bytes(bytes), is_directory)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn verify_key_identity(
    extraction: &ExtractionOperationPlan,
) -> Result<(), OperationFailureCode> {
    super::validate_file_route(&extraction.key_file, None)
        .map_err(|_| OperationFailureCode::KeyFileChanged)?;
    let directory = super::open_directory(&extraction.key_file.parent)
        .map_err(|_| OperationFailureCode::KeyFileChanged)?;
    if handle_identity(&directory) != Some(extraction.key_file.parent_identity) {
        return Err(OperationFailureCode::KeyFileChanged);
    }
    let mut key_file = super::open_file_at(&directory, &extraction.key_file.name)
        .map_err(|_| OperationFailureCode::KeyFileChanged)?;
    super::verify_file_evidence(&mut key_file, &extraction.key_baseline)
        .map_err(|_| OperationFailureCode::KeyFileChanged)
}

#[cfg(test)]
mod tests;
