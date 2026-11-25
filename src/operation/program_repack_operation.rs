//! Plan-bound reconstruction of one standalone Program NCA inside a PFS0.

use super::{
    CopyThroughRequest, FileEvidence, OperationArtifactRole, OperationFailureCode, OperationKind,
    OperationPlan, OperationSession, PlannedArtifact, PlannedQualificationKey, ResolvedDirectory,
    ResolvedFile, check_cancelled, inspect_file, open_directory, open_file_at,
    plan_copy_through_unix_for_output_inner, required_identity, resolve_directory, resolve_file,
    validate_directory_route, validate_file_route, verify_directory_identity, verify_file_evidence,
};
use crate::file_identity::{FileIdentity, handle_identity};
use crate::inspection::{NativeNcaFileSpan, NativeNcaInventory};
use crate::multi_content_format::{Pfs0SourceMember, Pfs0WriteLayout};
use crate::program_repack::{ManifestError, PartitionPfs0Layout, ProgramManifest};
use crate::sha256::Sha256Digest;
use sha2::{Digest as _, Sha256};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroizing;

const REPACK_COPY_CHUNK_SIZE: usize = 64 * 1024;
const INTERMEDIATE_NCA_NAME: &str = ".program-repack-intermediate.nca";

/// Input evidence and deterministic identities captured by the immutable plan.
pub(super) struct ProgramRepackOperationPlan {
    bundle: ResolvedDirectory,
    bundle_identity: FileIdentity,
    manifest_file: ResolvedFile,
    manifest_name: String,
    manifest_baseline: FileEvidence,
    manifest: ProgramManifest,
    member_name: String,
    key_file: ResolvedFile,
    key_baseline: FileEvidence,
    header_key: crate::key_file::HeaderKey,
    directories: Vec<DirectoryEvidence>,
    payloads: Vec<PayloadEvidence>,
    partitions: Vec<RepackPartition>,
    outer_layout: Pfs0WriteLayout,
    pub(super) nca_length: u64,
    nca_sha256: Sha256Digest,
    pub(super) output_length: u64,
    pub(super) output_sha256: Sha256Digest,
    pub(super) progress_total: u64,
    staging_directory_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectoryEvidence {
    relative_path: String,
    identity: FileIdentity,
}

struct BundlePayloadTree<'a> {
    root: &'a File,
    identity: FileIdentity,
    directories: &'a [DirectoryEvidence],
}

struct PayloadEvidence {
    manifest_path: String,
    bundle_relative_path: String,
    baseline: FileEvidence,
}

struct RepackPartition {
    index: u8,
    layout: PartitionPfs0Layout,
}

/// Fixed inputs used while rebuilding one deterministic Program NCA.
struct NcaRebuildInput<'a> {
    manifest: &'a ProgramManifest,
    bundle: &'a ResolvedDirectory,
    bundle_identity: FileIdentity,
    directories: &'a [DirectoryEvidence],
    partitions: &'a [RepackPartition],
    payloads: &'a [PayloadEvidence],
    header_key: &'a crate::key_file::HeaderKey,
    length: u64,
}

/// Plans a complete standalone Program bundle as a deterministic one-member PFS0.
pub(super) fn plan(request: super::RepackRequest) -> Result<OperationPlan, super::OperationError> {
    if request.destination.extension() != Some(OsStr::new("pfs0")) {
        return Err(super::OperationError::new(
            OperationFailureCode::InvalidDestination,
        ));
    }

    let manifest_file = resolve_file(&request.manifest, OperationFailureCode::SourceUnavailable)?;
    let bundle = resolve_directory(&manifest_file.parent)
        .map_err(|_| super::OperationError::new(OperationFailureCode::SourceUnavailable))?;
    let bundle_directory = open_directory(&bundle.path)
        .map_err(|_| super::OperationError::new(OperationFailureCode::SourceUnavailable))?;
    let bundle_identity = required_identity(&bundle_directory)?;
    if bundle.identity != Some(bundle_identity) {
        return Err(super::OperationError::new(OperationFailureCode::StalePlan));
    }

    if manifest_file.parent != bundle.path || manifest_file.parent_identity != bundle_identity {
        return Err(super::OperationError::new(OperationFailureCode::UnsafePath));
    }
    let manifest_name = manifest_file
        .name
        .to_str()
        .ok_or_else(|| super::OperationError::new(OperationFailureCode::UnsafePath))?;
    crate::extraction::validate_selected_relative_path(manifest_name)
        .map_err(|_| super::OperationError::new(OperationFailureCode::UnsafePath))?;
    let mut owned_manifest_name = String::new();
    owned_manifest_name
        .try_reserve_exact(manifest_name.len())
        .map_err(|_| super::OperationError::new(OperationFailureCode::ResourceLimitExceeded))?;
    owned_manifest_name.push_str(manifest_name);
    let mut manifest_handle = open_file_at(&bundle_directory, &manifest_file.name)
        .map_err(|_| super::OperationError::new(OperationFailureCode::SourceUnavailable))?;
    let manifest_len = manifest_handle
        .metadata()
        .map_err(|_| super::OperationError::new(OperationFailureCode::SourceUnavailable))?
        .len();
    if manifest_len > crate::program_repack::MAX_MANIFEST_BYTES {
        return Err(super::OperationError::new(
            OperationFailureCode::ResourceLimitExceeded,
        ));
    }
    let manifest_baseline =
        inspect_file(&mut manifest_handle).map_err(super::OperationError::new)?;
    let manifest_bytes = read_bounded(
        &mut manifest_handle,
        crate::program_repack::MAX_MANIFEST_BYTES,
        OperationFailureCode::InvalidRepackManifest,
    )?;
    verify_bytes_match_evidence(&manifest_bytes, &manifest_baseline)
        .map_err(super::OperationError::new)?;
    let manifest = crate::program_repack::parse_manifest(&manifest_bytes)
        .map_err(|error| super::OperationError::new(map_manifest_error(error)))?;

    let (expected_directories, expected_files) =
        expected_bundle_paths(&manifest, &owned_manifest_name)
            .map_err(super::OperationError::new)?;
    let mut payloads = Vec::new();
    let directories = scan_bundle_tree(
        &bundle_directory,
        &expected_directories,
        &expected_files,
        &owned_manifest_name,
        None,
        None,
        |relative, parent, name, file| {
            if relative == owned_manifest_name {
                return verify_file_evidence(file, &manifest_baseline)
                    .map_err(|_| OperationFailureCode::InvalidRepackManifest);
            }
            let manifest_path = relative
                .strip_prefix("content/")
                .ok_or(OperationFailureCode::ValidationFailed)?;
            let baseline =
                inspect_file(file).map_err(|_| OperationFailureCode::MissingRepackPayload)?;
            let mut owned_path = String::new();
            owned_path
                .try_reserve_exact(manifest_path.len())
                .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
            owned_path.push_str(manifest_path);
            payloads
                .try_reserve(1)
                .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
            let mut bundle_relative_path = String::new();
            bundle_relative_path
                .try_reserve_exact(relative.len())
                .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
            bundle_relative_path.push_str(relative);
            if handle_identity(parent).is_none() {
                return Err(OperationFailureCode::UnsupportedCapability);
            }
            payloads.push(PayloadEvidence {
                manifest_path: owned_path,
                bundle_relative_path,
                baseline,
            });
            let _ = name;
            Ok(())
        },
    )
    .map_err(super::OperationError::new)?;
    payloads.sort_unstable_by(|left, right| {
        left.manifest_path
            .as_bytes()
            .cmp(right.manifest_path.as_bytes())
    });
    if payloads.len()
        != manifest
            .partitions
            .iter()
            .map(|part| part.files.len())
            .sum::<usize>()
    {
        return Err(super::OperationError::new(
            OperationFailureCode::MissingRepackPayload,
        ));
    }

    let (key_file, key_baseline, header_key) = read_header_key(&request.key_file)?;
    let mut partitions =
        build_partition_layouts(&manifest, &payloads).map_err(super::OperationError::new)?;
    let partition_sizes = partitions
        .iter()
        .map(|partition| partition.layout.padded_size)
        .collect::<Vec<_>>();
    let nca_length = partition_sizes
        .iter()
        .try_fold(crate::nca::HEADER_SIZE as u64, |total, size| {
            total.checked_add(*size)
        })
        .ok_or_else(|| super::OperationError::new(OperationFailureCode::ResourceLimitExceeded))?;
    let member_name =
        crate::multi_content_format::output_name(manifest.program_id, manifest.content_index)
            .map_err(|error| super::OperationError::new(super::map_content_format_error(error)))?;
    let outer_layout =
        crate::multi_content_format::build_pfs0_layout(&[(member_name.clone(), nca_length)])
            .map_err(|error| super::OperationError::new(super::map_content_format_error(error)))?;
    let mut digest_writer = DigestWriter::new(&outer_layout.metadata);
    write_nca(
        &mut digest_writer,
        &NcaRebuildInput {
            manifest: &manifest,
            bundle: &bundle,
            bundle_identity,
            directories: &directories,
            partitions: &partitions,
            payloads: &payloads,
            header_key: &header_key,
            length: nca_length,
        },
        || Ok(()),
        |_| Ok(()),
    )
    .map_err(super::OperationError::new)?;
    if digest_writer.length != nca_length
        || outer_layout.length
            != u64::try_from(outer_layout.metadata.len())
                .ok()
                .and_then(|size| size.checked_add(nca_length))
                .ok_or_else(|| {
                    super::OperationError::new(OperationFailureCode::ResourceLimitExceeded)
                })?
    {
        return Err(super::OperationError::new(
            OperationFailureCode::ValidationFailed,
        ));
    }
    let nca_sha256 = digest_writer.nca_digest();
    let output_sha256 = digest_writer.package_digest();
    let output_length = outer_layout.length;
    let progress_total = nca_length
        .checked_add(output_length)
        .ok_or_else(|| super::OperationError::new(OperationFailureCode::ResourceLimitExceeded))?;

    let mut repack = ProgramRepackOperationPlan {
        bundle,
        bundle_identity,
        manifest_file,
        manifest_name: owned_manifest_name,
        manifest_baseline: manifest_baseline.clone(),
        manifest,
        member_name,
        key_file,
        key_baseline,
        header_key,
        directories,
        payloads,
        partitions: std::mem::take(&mut partitions),
        outer_layout,
        nca_length,
        nca_sha256,
        output_length,
        output_sha256,
        progress_total,
        staging_directory_path: None,
    };
    verify_repack_inputs(&repack, None).map_err(super::OperationError::new)?;

    let copy_request = CopyThroughRequest::new(
        &repack.manifest_file.path,
        &request.destination,
        &request.workspace,
    )
    .with_conflict_policy(request.conflict_policy);
    let mut plan = plan_copy_through_unix_for_output_inner(
        copy_request,
        Some((output_length, output_sha256)),
        false,
        None,
    )?;
    if plan.source_baseline != repack.manifest_baseline {
        return Err(super::OperationError::new(
            OperationFailureCode::SourceChanged,
        ));
    }
    if plan.destination.path.starts_with(&repack.bundle.path)
        || plan.workspace.path.starts_with(&repack.bundle.path)
        || plan.destination.path == repack.key_file.path
        || plan
            .destination_baseline
            .as_ref()
            .is_some_and(|existing| existing.identity == repack.key_baseline.identity)
        || repack.payloads.iter().any(|payload| {
            plan.destination.path == repack.bundle.path.join(&payload.bundle_relative_path)
                || plan
                    .destination_baseline
                    .as_ref()
                    .is_some_and(|existing| existing.identity == payload.baseline.identity)
        })
    {
        return Err(super::OperationError::new(OperationFailureCode::UnsafePath));
    }
    let lock_name = plan
        .snapshot
        .destination_lock_path
        .file_name()
        .ok_or_else(|| super::OperationError::new(OperationFailureCode::UnsafePath))?;
    let payload_lock_conflict = repack.payloads.iter().any(|payload| {
        let Some((parent, name)) = payload.bundle_relative_path.rsplit_once('/') else {
            return false;
        };
        repack.bundle.path.join(&payload.bundle_relative_path)
            == plan.snapshot.destination_lock_path
            || (repack.bundle.path.join(parent) == plan.destination.parent
                && OsStr::new(name) == lock_name)
    });
    if std::iter::once(&repack.manifest_file)
        .chain(std::iter::once(&repack.key_file))
        .any(|file| {
            file.path == plan.snapshot.destination_lock_path
                || (file.parent == plan.destination.parent && file.name == lock_name)
        })
        || payload_lock_conflict
    {
        return Err(super::OperationError::new(OperationFailureCode::UnsafePath));
    }
    if let Some(staging_name) = plan.stage_directory_name.as_ref() {
        let staging_directory_path = plan.workspace.path.join(staging_name);
        let spool_path = staging_directory_path.join(INTERMEDIATE_NCA_NAME);
        plan.snapshot
            .planned_artifacts
            .try_reserve(1)
            .map_err(|_| super::OperationError::new(OperationFailureCode::ResourceLimitExceeded))?;
        plan.snapshot.planned_artifacts.push(PlannedArtifact {
            role: OperationArtifactRole::PrivateMemberSpool,
            path: spool_path,
            expected_length: Some(nca_length),
            expected_sha256: Some(nca_sha256),
        });
        repack.staging_directory_path = Some(staging_directory_path);
    }
    plan.snapshot.operation_kind = OperationKind::Repack;
    plan.snapshot.output_paths = vec![plan.destination.path.clone()];
    plan.snapshot.qualification_key = Some(PlannedQualificationKey {
        path: repack.key_file.path.clone(),
        identity: repack.key_baseline.identity.fingerprint(),
        size: repack.key_baseline.snapshot.len,
    });
    if let Some(artifact) = plan
        .snapshot
        .planned_artifacts
        .iter_mut()
        .find(|artifact| artifact.role == super::OperationArtifactRole::StagedOutput)
    {
        artifact.expected_length = Some(output_length);
        artifact.expected_sha256 = Some(output_sha256);
    }
    plan.program_repack = Some(Arc::new(repack));
    Ok(plan)
}

fn read_header_key(
    path: &Path,
) -> Result<(ResolvedFile, FileEvidence, crate::key_file::HeaderKey), super::OperationError> {
    let file = resolve_file(path, OperationFailureCode::KeyFileUnavailable)?;
    let directory = open_directory(&file.parent)
        .map_err(|_| super::OperationError::new(OperationFailureCode::KeyFileUnavailable))?;
    verify_directory_identity(&directory, file.parent_identity)
        .map_err(super::OperationError::new)?;
    let mut key_file = open_file_at(&directory, &file.name)
        .map_err(|_| super::OperationError::new(OperationFailureCode::KeyFileUnavailable))?;
    let length = key_file
        .metadata()
        .map_err(|_| super::OperationError::new(OperationFailureCode::KeyFileUnavailable))?
        .len();
    if length > crate::key_file::MAX_KEY_FILE_BYTES {
        return Err(super::OperationError::new(
            OperationFailureCode::ResourceLimitExceeded,
        ));
    }
    let baseline = inspect_file(&mut key_file).map_err(super::OperationError::new)?;
    let bytes = read_bounded(
        &mut key_file,
        crate::key_file::MAX_KEY_FILE_BYTES,
        OperationFailureCode::KeyFileUnavailable,
    )?;
    let parse_result = crate::key_file::parse_header_key_bytes(&bytes);
    let bytes_digest = Sha256Digest::from_bytes(Sha256::digest(&bytes).into());
    if bytes_digest != baseline.sha256 {
        return Err(super::OperationError::new(
            OperationFailureCode::KeyFileChanged,
        ));
    }
    verify_file_evidence(&mut key_file, &baseline)
        .map_err(|_| super::OperationError::new(OperationFailureCode::KeyFileChanged))?;
    let key = parse_result.map_err(|error| {
        super::OperationError::new(match error {
            crate::key_file::KeyFileParseError::Malformed => OperationFailureCode::KeyFileMalformed,
            crate::key_file::KeyFileParseError::MissingHeaderKey => {
                OperationFailureCode::RequiredKeyMissing
            }
        })
    })?;
    Ok((file, baseline, key))
}

fn read_bounded(
    file: &mut File,
    maximum: u64,
    read_failure: OperationFailureCode,
) -> Result<Zeroizing<Vec<u8>>, super::OperationError> {
    let length = file
        .metadata()
        .map_err(|_| super::OperationError::new(read_failure))?
        .len();
    if length > maximum {
        return Err(super::OperationError::new(
            OperationFailureCode::ResourceLimitExceeded,
        ));
    }
    let length = usize::try_from(length)
        .map_err(|_| super::OperationError::new(OperationFailureCode::ResourceLimitExceeded))?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length)
        .map_err(|_| super::OperationError::new(OperationFailureCode::ResourceLimitExceeded))?;
    bytes.resize(length, 0);
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.read_exact(&mut bytes))
        .map_err(|_| super::OperationError::new(read_failure))?;
    Ok(bytes)
}

fn verify_bytes_match_evidence(
    bytes: &[u8],
    evidence: &FileEvidence,
) -> Result<(), OperationFailureCode> {
    if u64::try_from(bytes.len()).ok() != Some(evidence.snapshot.len)
        || Sha256Digest::from_bytes(Sha256::digest(bytes).into()) != evidence.sha256
    {
        return Err(OperationFailureCode::SourceChanged);
    }
    Ok(())
}

fn map_manifest_error(error: ManifestError) -> OperationFailureCode {
    match error {
        ManifestError::Malformed => OperationFailureCode::InvalidRepackManifest,
        ManifestError::Unsupported => OperationFailureCode::UnsupportedRepackProfile,
        ManifestError::Incomplete => OperationFailureCode::IncompleteRepackManifest,
        ManifestError::MissingPayload => OperationFailureCode::MissingRepackPayload,
        ManifestError::ResourceLimit | ManifestError::AllocationFailed => {
            OperationFailureCode::ResourceLimitExceeded
        }
    }
}

fn expected_bundle_paths(
    manifest: &ProgramManifest,
    manifest_name: &str,
) -> Result<(Vec<String>, Vec<String>), OperationFailureCode> {
    let mut directories = Vec::new();
    let mut files = Vec::new();
    let directory_count = manifest
        .partitions
        .iter()
        .try_fold(1_usize, |total, partition| {
            total.checked_add(partition.directories.len())
        })
        .ok_or(OperationFailureCode::ResourceLimitExceeded)?;
    let file_count = manifest
        .partitions
        .iter()
        .try_fold(1_usize, |total, partition| {
            total.checked_add(partition.files.len())
        })
        .ok_or(OperationFailureCode::ResourceLimitExceeded)?;
    directories
        .try_reserve_exact(directory_count)
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    files
        .try_reserve_exact(file_count)
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    directories.push("content".to_owned());
    let mut copied_manifest_name = String::new();
    copied_manifest_name
        .try_reserve_exact(manifest_name.len())
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    copied_manifest_name.push_str(manifest_name);
    files.push(copied_manifest_name);
    for partition in &manifest.partitions {
        for directory in &partition.directories {
            directories.push(crate::operation::extraction::prefixed_path(
                "content", directory,
            )?);
        }
        for file in &partition.files {
            files.push(crate::operation::extraction::prefixed_path(
                "content", file,
            )?);
        }
    }
    directories.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    files.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Ok((directories, files))
}

fn scan_bundle_tree(
    root: &File,
    expected_directories: &[String],
    expected_files: &[String],
    manifest_name: &str,
    expected_directory_evidence: Option<&[DirectoryEvidence]>,
    session: Option<&OperationSession>,
    mut validate_file: impl FnMut(&str, &File, &OsStr, &mut File) -> Result<(), OperationFailureCode>,
) -> Result<Vec<DirectoryEvidence>, OperationFailureCode> {
    let mut actual_directories = Vec::new();
    let mut actual_files = Vec::new();
    let mut pending_directories = Vec::new();
    let limit = expected_directories
        .len()
        .checked_add(expected_files.len())
        .ok_or(OperationFailureCode::ResourceLimitExceeded)?;
    actual_directories
        .try_reserve_exact(expected_directories.len())
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    actual_files
        .try_reserve_exact(expected_files.len())
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    pending_directories
        .try_reserve_exact(expected_directories.len())
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    let mut observed_directories = Vec::new();
    observed_directories
        .try_reserve_exact(expected_directories.len().saturating_add(1))
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    pending_directories.push(String::new());

    while let Some(relative_directory) = pending_directories.pop() {
        if let Some(session) = session {
            check_cancelled(session)?;
        }
        let directory =
            crate::operation::extraction::open_relative_directory(root, &relative_directory)?;
        let identity =
            handle_identity(&directory).ok_or(OperationFailureCode::UnsupportedCapability)?;
        observed_directories.push(DirectoryEvidence {
            relative_path: relative_directory.clone(),
            identity,
        });
        crate::operation::extraction::visit_directory_entries(
            &directory,
            OperationFailureCode::ValidationFailed,
            |name, is_directory| {
                if let Some(session) = session {
                    check_cancelled(session)?;
                }
                let leaf = name.to_str().ok_or(OperationFailureCode::UnsafePath)?;
                let relative = if relative_directory.is_empty() {
                    crate::operation::extraction::copy_path_component(leaf)?
                } else {
                    crate::operation::extraction::prefixed_path(&relative_directory, leaf)?
                };
                if is_directory {
                    if expected_directories
                        .binary_search_by(|expected| expected.as_bytes().cmp(relative.as_bytes()))
                        .is_err()
                    {
                        return Err(OperationFailureCode::ValidationFailed);
                    }
                    if actual_directories.len() >= limit {
                        return Err(OperationFailureCode::ResourceLimitExceeded);
                    }
                    actual_directories.push(relative.clone());
                    pending_directories
                        .try_reserve(1)
                        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
                    pending_directories.push(relative);
                    return Ok(());
                }
                if expected_files
                    .binary_search_by(|expected| expected.as_bytes().cmp(relative.as_bytes()))
                    .is_err()
                {
                    return Err(OperationFailureCode::ValidationFailed);
                }
                if actual_files.len() >= limit {
                    return Err(OperationFailureCode::ResourceLimitExceeded);
                }
                actual_files
                    .try_reserve(1)
                    .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
                actual_files.push(relative.clone());
                crate::operation::extraction::validate_regular_file_at(&directory, name, |file| {
                    validate_file(&relative, &directory, name, file)
                })
            },
        )?;
    }

    actual_directories.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    actual_files.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    observed_directories.sort_unstable_by(|left, right| {
        left.relative_path
            .as_bytes()
            .cmp(right.relative_path.as_bytes())
    });
    if expected_directories != actual_directories
        || expected_files != actual_files
        || expected_directory_evidence.is_some_and(|expected| expected != observed_directories)
    {
        let missing_file = expected_files
            .iter()
            .any(|path| actual_files.binary_search(path).is_err() && path != manifest_name);
        let missing_directory = expected_directories
            .iter()
            .any(|path| actual_directories.binary_search(path).is_err());
        if missing_file || missing_directory {
            return Err(OperationFailureCode::MissingRepackPayload);
        }
        return Err(OperationFailureCode::RepackPayloadChanged);
    }
    Ok(observed_directories)
}

fn build_partition_layouts(
    manifest: &ProgramManifest,
    payloads: &[PayloadEvidence],
) -> Result<Vec<RepackPartition>, OperationFailureCode> {
    let mut partitions = Vec::new();
    partitions
        .try_reserve_exact(manifest.partitions.len())
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    for partition in &manifest.partitions {
        let mut files = Vec::new();
        files
            .try_reserve_exact(partition.files.len())
            .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
        let prefix = format!("{}/", partition.index);
        for manifest_path in &partition.files {
            let path = manifest_path
                .strip_prefix(&prefix)
                .ok_or(OperationFailureCode::InvalidRepackManifest)?;
            let payload = payloads
                .binary_search_by(|candidate| {
                    candidate
                        .manifest_path
                        .as_bytes()
                        .cmp(manifest_path.as_bytes())
                })
                .ok()
                .and_then(|index| payloads.get(index))
                .ok_or(OperationFailureCode::MissingRepackPayload)?;
            files.push((path.to_owned(), payload.baseline.snapshot.len));
        }
        let layout =
            crate::program_repack::build_partition_layout(&files).map_err(map_manifest_error)?;
        partitions.push(RepackPartition {
            index: partition.index,
            layout,
        });
    }
    Ok(partitions)
}

fn write_nca<W: Write>(
    writer: &mut W,
    input: &NcaRebuildInput<'_>,
    mut checkpoint: impl FnMut() -> Result<(), OperationFailureCode>,
    mut on_chunk: impl FnMut(u64) -> Result<(), OperationFailureCode>,
) -> Result<(), OperationFailureCode> {
    let manifest = input.manifest;
    let bundle_root = open_directory(&input.bundle.path)
        .map_err(|_| OperationFailureCode::RepackPayloadChanged)?;
    verify_directory_identity(&bundle_root, input.bundle_identity)
        .map_err(|_| OperationFailureCode::RepackPayloadChanged)?;
    let payload_tree = BundlePayloadTree {
        root: &bundle_root,
        identity: input.bundle_identity,
        directories: input.directories,
    };
    let partitions = input.partitions;
    let payloads = input.payloads;
    let header_key = input.header_key;
    let nca_length = input.length;
    if partitions.len() != manifest.partitions.len() {
        return Err(OperationFailureCode::ValidationFailed);
    }
    let partition_sizes: Vec<u64> = partitions
        .iter()
        .map(|partition| partition.layout.padded_size)
        .collect();
    let plain_header =
        crate::program_repack::build_nca_header(manifest, &partition_sizes, nca_length)
            .map_err(map_manifest_error)?;
    let encrypted_header = crate::nca::encrypt_header_block(plain_header, header_key.as_bytes());
    checkpoint()?;
    writer
        .write_all(&encrypted_header)
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    on_chunk(crate::nca::HEADER_SIZE as u64)?;
    let mut written = crate::nca::HEADER_SIZE as u64;

    for partition in partitions {
        checkpoint()?;
        let section_start = written;
        writer
            .write_all(&partition.layout.metadata)
            .map_err(|_| OperationFailureCode::WriteFailed)?;
        let metadata_len = u64::try_from(partition.layout.metadata.len())
            .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
        written = written
            .checked_add(metadata_len)
            .ok_or(OperationFailureCode::ResourceLimitExceeded)?;
        on_chunk(metadata_len)?;
        for entry in &partition.layout.files {
            let manifest_path = join_partition_path(partition.index, &entry.path)?;
            let payload = find_payload(payloads, &manifest_path)?;
            write_payload(
                writer,
                &payload_tree,
                payload,
                &mut checkpoint,
                &mut on_chunk,
                &mut written,
            )?;
        }
        let section_written = written
            .checked_sub(section_start)
            .ok_or(OperationFailureCode::ValidationFailed)?;
        if section_written > partition.layout.padded_size {
            return Err(OperationFailureCode::ValidationFailed);
        }
        write_zero_padding(
            writer,
            partition.layout.padded_size - section_written,
            &mut checkpoint,
            &mut on_chunk,
            &mut written,
        )?;
        if written
            .checked_sub(section_start)
            .ok_or(OperationFailureCode::ValidationFailed)?
            != partition.layout.padded_size
        {
            return Err(OperationFailureCode::ValidationFailed);
        }
    }
    if written != nca_length {
        return Err(OperationFailureCode::ValidationFailed);
    }
    Ok(())
}

fn write_payload<W: Write>(
    writer: &mut W,
    payload_tree: &BundlePayloadTree<'_>,
    payload: &PayloadEvidence,
    checkpoint: &mut impl FnMut() -> Result<(), OperationFailureCode>,
    on_chunk: &mut impl FnMut(u64) -> Result<(), OperationFailureCode>,
    written: &mut u64,
) -> Result<(), OperationFailureCode> {
    with_payload_file(payload_tree, payload, |source| {
        source
            .seek(SeekFrom::Start(0))
            .map_err(|_| OperationFailureCode::RepackPayloadChanged)?;
        let mut remaining = payload.baseline.snapshot.len;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; REPACK_COPY_CHUNK_SIZE];
        while remaining > 0 {
            checkpoint()?;
            let wanted = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
            let count = source
                .read(&mut buffer[..wanted])
                .map_err(|_| OperationFailureCode::RepackPayloadChanged)?;
            if count == 0 {
                return Err(OperationFailureCode::RepackPayloadChanged);
            }
            writer
                .write_all(&buffer[..count])
                .map_err(|_| OperationFailureCode::WriteFailed)?;
            hasher.update(&buffer[..count]);
            let count =
                u64::try_from(count).map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
            remaining -= count;
            *written = written
                .checked_add(count)
                .ok_or(OperationFailureCode::ResourceLimitExceeded)?;
            on_chunk(count)?;
        }
        if Sha256Digest::from_bytes(hasher.finalize().into()) != payload.baseline.sha256 {
            return Err(OperationFailureCode::RepackPayloadChanged);
        }
        Ok(())
    })
}

fn with_payload_file(
    payload_tree: &BundlePayloadTree<'_>,
    payload: &PayloadEvidence,
    use_file: impl FnOnce(&mut File) -> Result<(), OperationFailureCode>,
) -> Result<(), OperationFailureCode> {
    verify_directory_identity(payload_tree.root, payload_tree.identity)
        .map_err(|_| OperationFailureCode::RepackPayloadChanged)?;
    let (parent_path, name) = payload
        .bundle_relative_path
        .rsplit_once('/')
        .ok_or(OperationFailureCode::RepackPayloadChanged)?;
    let expected_parent = payload_tree
        .directories
        .binary_search_by(|directory| {
            directory
                .relative_path
                .as_bytes()
                .cmp(parent_path.as_bytes())
        })
        .ok()
        .and_then(|index| payload_tree.directories.get(index))
        .ok_or(OperationFailureCode::RepackPayloadChanged)?;
    let parent =
        crate::operation::extraction::open_relative_directory(payload_tree.root, parent_path)
            .map_err(|_| OperationFailureCode::RepackPayloadChanged)?;
    verify_directory_identity(&parent, expected_parent.identity)
        .map_err(|_| OperationFailureCode::RepackPayloadChanged)?;

    let mut callback_failure = None;
    let validation =
        crate::operation::extraction::validate_regular_file_at(&parent, OsStr::new(name), |file| {
            verify_file_evidence(file, &payload.baseline)
                .map_err(|_| OperationFailureCode::RepackPayloadChanged)?;
            if let Err(error) = use_file(file) {
                callback_failure = Some(error);
                return Err(error);
            }
            Ok(())
        });
    match validation {
        Ok(()) => Ok(()),
        Err(_) => Err(callback_failure.unwrap_or(OperationFailureCode::RepackPayloadChanged)),
    }
}

fn write_zero_padding<W: Write>(
    writer: &mut W,
    mut remaining: u64,
    checkpoint: &mut impl FnMut() -> Result<(), OperationFailureCode>,
    on_chunk: &mut impl FnMut(u64) -> Result<(), OperationFailureCode>,
    written: &mut u64,
) -> Result<(), OperationFailureCode> {
    let zeros = [0_u8; 0x200];
    while remaining > 0 {
        checkpoint()?;
        let count = usize::try_from(remaining.min(zeros.len() as u64))
            .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
        writer
            .write_all(&zeros[..count])
            .map_err(|_| OperationFailureCode::WriteFailed)?;
        let count =
            u64::try_from(count).map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
        remaining -= count;
        *written = written
            .checked_add(count)
            .ok_or(OperationFailureCode::ResourceLimitExceeded)?;
        on_chunk(count)?;
    }
    Ok(())
}

fn join_partition_path(index: u8, path: &str) -> Result<String, OperationFailureCode> {
    let prefix = format!("{index}/");
    let mut joined = String::new();
    joined
        .try_reserve_exact(prefix.len().saturating_add(path.len()))
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    joined.push_str(&prefix);
    joined.push_str(path);
    Ok(joined)
}

fn find_payload<'a>(
    payloads: &'a [PayloadEvidence],
    manifest_path: &str,
) -> Result<&'a PayloadEvidence, OperationFailureCode> {
    payloads
        .binary_search_by(|candidate| {
            candidate
                .manifest_path
                .as_bytes()
                .cmp(manifest_path.as_bytes())
        })
        .ok()
        .and_then(|index| payloads.get(index))
        .ok_or(OperationFailureCode::MissingRepackPayload)
}

struct DigestWriter {
    nca_hasher: Sha256,
    package_hasher: Sha256,
    length: u64,
}

impl DigestWriter {
    fn new(outer_metadata: &[u8]) -> Self {
        let mut package_hasher = Sha256::new();
        package_hasher.update(outer_metadata);
        Self {
            nca_hasher: Sha256::new(),
            package_hasher,
            length: 0,
        }
    }

    fn nca_digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(self.nca_hasher.clone().finalize().into())
    }

    fn package_digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(self.package_hasher.clone().finalize().into())
    }
}

impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.length = self
            .length
            .checked_add(u64::try_from(bytes.len()).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("repack output length overflow"))?;
        self.nca_hasher.update(bytes);
        self.package_hasher.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn verify_key_identity(
    plan: &ProgramRepackOperationPlan,
) -> Result<(), OperationFailureCode> {
    validate_file_route(&plan.key_file, None).map_err(|_| OperationFailureCode::KeyFileChanged)?;
    let directory =
        open_directory(&plan.key_file.parent).map_err(|_| OperationFailureCode::KeyFileChanged)?;
    verify_directory_identity(&directory, plan.key_file.parent_identity)
        .map_err(|_| OperationFailureCode::KeyFileChanged)?;
    let mut file = open_file_at(&directory, &plan.key_file.name)
        .map_err(|_| OperationFailureCode::KeyFileChanged)?;
    verify_file_evidence(&mut file, &plan.key_baseline)
        .map_err(|_| OperationFailureCode::KeyFileChanged)
}

fn verify_repack_file(
    file: &mut File,
    expected: &super::FileEvidence,
    session: Option<&OperationSession>,
    changed_code: OperationFailureCode,
) -> Result<(), OperationFailureCode> {
    match super::verify_file_evidence_with_fallible_checkpoint(file, expected, || {
        if let Some(session) = session {
            check_cancelled(session)?;
        }
        Ok(())
    }) {
        Ok(()) => Ok(()),
        Err(OperationFailureCode::Cancelled) => Err(OperationFailureCode::Cancelled),
        Err(_) => Err(changed_code),
    }
}

pub(super) fn verify_repack_inputs(
    plan: &ProgramRepackOperationPlan,
    session: Option<&OperationSession>,
) -> Result<(), OperationFailureCode> {
    validate_directory_route(&plan.bundle, None).map_err(|_| OperationFailureCode::StalePlan)?;
    let root =
        open_directory(&plan.bundle.path).map_err(|_| OperationFailureCode::SourceUnavailable)?;
    verify_directory_identity(&root, plan.bundle_identity)
        .map_err(|_| OperationFailureCode::RepackPayloadChanged)?;
    validate_file_route(&plan.manifest_file, None).map_err(|_| OperationFailureCode::StalePlan)?;
    let manifest_parent = open_directory(&plan.manifest_file.parent)
        .map_err(|_| OperationFailureCode::SourceUnavailable)?;
    verify_directory_identity(&manifest_parent, plan.manifest_file.parent_identity)
        .map_err(|_| OperationFailureCode::SourceChanged)?;
    let mut manifest = open_file_at(&manifest_parent, &plan.manifest_file.name)
        .map_err(|_| OperationFailureCode::SourceUnavailable)?;
    verify_repack_file(
        &mut manifest,
        &plan.manifest_baseline,
        session,
        OperationFailureCode::SourceChanged,
    )?;
    verify_key_identity(plan)?;
    let (expected_directories, expected_files) =
        expected_bundle_paths(&plan.manifest, &plan.manifest_name)?;
    let directories = scan_bundle_tree(
        &root,
        &expected_directories,
        &expected_files,
        &plan.manifest_name,
        Some(&plan.directories),
        session,
        |relative, _parent, _name, file| {
            if relative == plan.manifest_name {
                verify_repack_file(
                    file,
                    &plan.manifest_baseline,
                    session,
                    OperationFailureCode::SourceChanged,
                )
            } else {
                let path = relative
                    .strip_prefix("content/")
                    .ok_or(OperationFailureCode::ValidationFailed)?;
                let payload = find_payload(&plan.payloads, path)?;
                verify_repack_file(
                    file,
                    &payload.baseline,
                    session,
                    OperationFailureCode::RepackPayloadChanged,
                )
            }
        },
    )?;
    if directories != plan.directories {
        return Err(OperationFailureCode::RepackPayloadChanged);
    }
    Ok(())
}

pub(super) fn execute(
    plan: &ProgramRepackOperationPlan,
    staging_directory_handle: &File,
    staging_directory_identity: FileIdentity,
    stage: &mut File,
    session: &OperationSession,
    artifacts: &mut Vec<super::OwnedArtifact>,
    cleanup_artifact_retained: &mut bool,
) -> Result<(), OperationFailureCode> {
    verify_repack_inputs(plan, Some(session))?;
    check_cancelled(session)?;
    let staging_directory_path = plan
        .staging_directory_path
        .as_deref()
        .ok_or(OperationFailureCode::StalePlan)?;
    let (mut nca, nca_identity) = create_intermediate_nca(
        staging_directory_path,
        staging_directory_handle,
        staging_directory_identity,
        artifacts,
        cleanup_artifact_retained,
    )?;
    let mut completed = 0_u64;
    write_nca(
        &mut nca,
        &NcaRebuildInput {
            manifest: &plan.manifest,
            bundle: &plan.bundle,
            bundle_identity: plan.bundle_identity,
            directories: &plan.directories,
            partitions: &plan.partitions,
            payloads: &plan.payloads,
            header_key: &plan.header_key,
            length: plan.nca_length,
        },
        || check_cancelled(session),
        |count| {
            completed = completed
                .checked_add(count)
                .ok_or(OperationFailureCode::ResourceLimitExceeded)?;
            session.record_progress(completed);
            Ok(())
        },
    )?;
    nca.sync_all()
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    let nca_evidence = super::record_private_spool_evidence(
        &mut nca,
        nca_identity,
        OsStr::new(INTERMEDIATE_NCA_NAME),
        artifacts,
    )?;
    if nca_evidence.snapshot.len != plan.nca_length || nca_evidence.sha256 != plan.nca_sha256 {
        return Err(OperationFailureCode::ValidationFailed);
    }
    validate_rebuilt_nca(&mut nca, plan, session)?;
    verify_repack_inputs(plan, Some(session))?;

    stage
        .seek(SeekFrom::Start(0))
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    let source_member = Pfs0SourceMember {
        source_index: 0,
        name: plan.member_name.clone(),
        source_offset: 0,
        size: plan.nca_length,
        sha256: plan.nca_sha256,
    };
    let mut package_progress = 0_u64;
    let mut cancellation_observed = false;
    crate::multi_content_format::write_pfs0_from_source(
        stage,
        &mut nca,
        &plan.outer_layout,
        std::slice::from_ref(&source_member),
        |count| {
            cancellation_observed |= check_cancelled(session).is_err();
            if cancellation_observed {
                return Err(crate::multi_content_format::FormatError::OutputUnavailable);
            }
            package_progress = package_progress
                .checked_add(count)
                .ok_or(crate::multi_content_format::FormatError::ResourceLimit)?;
            let total = plan
                .nca_length
                .checked_add(package_progress)
                .ok_or(crate::multi_content_format::FormatError::ResourceLimit)?;
            session.record_progress(total);
            Ok(())
        },
    )
    .map_err(|error| {
        if cancellation_observed {
            OperationFailureCode::Cancelled
        } else {
            super::map_content_format_error(error)
        }
    })?;
    stage
        .flush()
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    stage
        .sync_all()
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    validate_final_package(stage, plan, session)
}

fn create_intermediate_nca(
    staging_directory_path: &Path,
    staging_directory: &File,
    expected_identity: FileIdentity,
    artifacts: &mut Vec<super::OwnedArtifact>,
    cleanup_artifact_retained: &mut bool,
) -> Result<(File, FileIdentity), OperationFailureCode> {
    if handle_identity(staging_directory) != Some(expected_identity) {
        return Err(OperationFailureCode::StalePlan);
    }
    let path_handle = open_directory(staging_directory_path)
        .map_err(|_| OperationFailureCode::WorkspaceUnavailable)?;
    if handle_identity(&path_handle) != Some(expected_identity) {
        return Err(OperationFailureCode::WorkspaceUnavailable);
    }

    super::create_artifact(
        staging_directory,
        staging_directory_path,
        OsStr::new(INTERMEDIATE_NCA_NAME),
        OperationArtifactRole::PrivateMemberSpool,
        artifacts,
        cleanup_artifact_retained,
    )
}

#[cfg(test)]
mod tests {
    use super::create_intermediate_nca;
    use crate::file_identity::handle_identity;
    use crate::operation::{OperationFailureCode, open_directory};
    use std::fs;

    #[test]
    fn rejects_a_replaced_stage_directory_before_creating_an_intermediate() {
        let root = tempfile::tempdir().unwrap();
        let stage_path = root.path().join("stage");
        let moved_path = root.path().join("stage-original");
        fs::create_dir(&stage_path).unwrap();
        let stage_handle = open_directory(&stage_path).unwrap();
        let stage_identity = handle_identity(&stage_handle).unwrap();

        fs::rename(&stage_path, &moved_path).unwrap();
        fs::create_dir(&stage_path).unwrap();

        let mut artifacts = Vec::new();
        let mut cleanup_artifact_retained = false;
        let error = create_intermediate_nca(
            &stage_path,
            &stage_handle,
            stage_identity,
            &mut artifacts,
            &mut cleanup_artifact_retained,
        )
        .unwrap_err();

        assert_eq!(error, OperationFailureCode::WorkspaceUnavailable);
        assert_eq!(fs::read_dir(&stage_path).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&moved_path).unwrap().count(), 0);
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
mod acceptance_tests {
    use super::{INTERMEDIATE_NCA_NAME, NcaRebuildInput, plan, validate_rebuilt_nca, write_nca};
    use crate::engine::Engine;
    use crate::extraction::{ExtractionRequest, ExtractionSelection};
    use crate::operation::{
        ExecutionCheckpoint, OperationArtifactRole, OperationFailureCode, OperationPlan,
        OperationSession, RepackRequest,
    };
    use crate::test_synthetic_extraction::SyntheticExtractionFixture;
    use crate::{ContainerProbeRequest, JobState};
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};

    fn extracted_bundle(fixture: &SyntheticExtractionFixture, name: &str) -> std::path::PathBuf {
        let root = fixture.source.parent().expect("fixture root");
        let bundle = root.join(name);
        let cancellation = crate::CancellationHandle::new();
        let extraction = Engine::new()
            .plan_extraction(
                ExtractionRequest::new(
                    &fixture.source,
                    &bundle,
                    &fixture.key_file,
                    ExtractionSelection::all(),
                ),
                cancellation.clone(),
            )
            .expect("plan synthetic Program extraction");
        let result = Engine::new().execute_operation_with_cancellation(
            extraction,
            &OperationSession::new(),
            cancellation,
        );
        assert_eq!(
            result.state(),
            JobState::Succeeded,
            "{:?}",
            result.failure()
        );
        bundle
    }

    fn repack_plan(
        fixture: &SyntheticExtractionFixture,
        bundle: &std::path::Path,
        destination_name: &str,
    ) -> crate::operation::OperationPlan {
        let root = fixture.source.parent().expect("fixture root");
        plan(RepackRequest::new(
            bundle.join("manifest.json"),
            root.join(destination_name),
            root,
            &fixture.key_file,
        ))
        .expect("plan synthetic Program repack")
    }

    fn planned_artifact_path(
        plan: &OperationPlan,
        role: OperationArtifactRole,
    ) -> std::path::PathBuf {
        plan.snapshot()
            .planned_artifacts()
            .iter()
            .find(|artifact| artifact.role() == role)
            .expect("planned artifact with requested role")
            .path()
            .to_path_buf()
    }

    #[test]
    fn rebuilt_nca_validation_rejects_corrupted_payload_bytes() {
        let fixture = SyntheticExtractionFixture::populated();
        let bundle = extracted_bundle(&fixture, "intermediate-corruption-bundle");
        let plan = repack_plan(&fixture, &bundle, "intermediate-corruption.pfs0");
        let repack = plan.program_repack.as_ref().expect("Program repack plan");
        let mut nca = tempfile::tempfile().expect("create anonymous NCA test file");
        write_nca(
            &mut nca,
            &NcaRebuildInput {
                manifest: &repack.manifest,
                bundle: &repack.bundle,
                bundle_identity: repack.bundle_identity,
                directories: &repack.directories,
                partitions: &repack.partitions,
                payloads: &repack.payloads,
                header_key: &repack.header_key,
                length: repack.nca_length,
            },
            || Ok(()),
            |_| Ok(()),
        )
        .expect("rebuild valid intermediate NCA");

        let mut partition_offset = crate::nca::HEADER_SIZE as u64;
        let mut payload_offset = None;
        for partition in &repack.partitions {
            if let Some(file) = partition.layout.files.iter().find(|file| file.size > 0) {
                payload_offset = Some(
                    partition_offset
                        + u64::try_from(partition.layout.metadata.len()).unwrap()
                        + file.data_offset,
                );
                break;
            }
            partition_offset += partition.layout.padded_size;
        }
        let payload_offset = payload_offset.expect("synthetic Program has a nonempty file");
        nca.seek(SeekFrom::Start(payload_offset)).unwrap();
        let mut byte = [0_u8; 1];
        nca.read_exact(&mut byte).unwrap();
        byte[0] ^= 0xff;
        nca.seek(SeekFrom::Start(payload_offset)).unwrap();
        nca.write_all(&byte).unwrap();

        let error = validate_rebuilt_nca(&mut nca, repack, &OperationSession::new())
            .expect_err("independent NCA validation must detect altered payload data");
        assert_eq!(
            error,
            crate::operation::OperationFailureCode::ValidationFailed
        );
    }

    #[test]
    fn corrupted_embedded_nca_is_rejected_before_final_publication() {
        let fixture = SyntheticExtractionFixture::populated();
        let bundle = extracted_bundle(&fixture, "final-corruption-bundle");
        let plan = repack_plan(&fixture, &bundle, "final-corruption.pfs0");
        let destination = plan.snapshot().destination().to_path_buf();
        let staged_output = planned_artifact_path(&plan, OperationArtifactRole::StagedOutput);
        let session = OperationSession::new();
        let mut corrupted_before_promotion = false;
        let result = crate::operation::execute_with_producer_and_checkpoint(
            plan,
            &session,
            |_, _, _| Ok(()),
            |checkpoint| {
                if checkpoint != ExecutionCheckpoint::BeforePromotion {
                    return;
                }
                let package = Engine::new()
                    .probe_container(ContainerProbeRequest::new(&staged_output))
                    .expect("staged PFS0 remains parseable before mutation");
                let member = package.entries.first().expect("one staged member");
                let mut stage = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&staged_output)
                    .expect("open staged package at publication checkpoint");
                stage.seek(SeekFrom::Start(member.file_offset)).unwrap();
                let mut byte = [0_u8; 1];
                stage.read_exact(&mut byte).unwrap();
                byte[0] ^= 0xff;
                stage.seek(SeekFrom::Start(member.file_offset)).unwrap();
                stage.write_all(&byte).unwrap();
                stage.sync_all().unwrap();
                corrupted_before_promotion = true;
            },
        );

        assert!(
            corrupted_before_promotion,
            "reach the pre-publication checkpoint"
        );
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::ValidationFailed
        );
        assert!(!destination.exists());
    }

    #[test]
    fn cancellation_before_promotion_prevents_repack_publication() {
        let fixture = SyntheticExtractionFixture::populated();
        let bundle = extracted_bundle(&fixture, "cancelled-repack-bundle");
        let plan = repack_plan(&fixture, &bundle, "cancelled-repack.pfs0");
        let destination = plan.snapshot().destination().to_path_buf();
        let session = OperationSession::new();
        let mut accepted = false;
        let result = crate::operation::execute_with_producer_and_checkpoint(
            plan,
            &session,
            |_, _, _| Ok(()),
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforePromotion {
                    accepted = session.cancel();
                }
            },
        );

        assert!(accepted);
        assert_eq!(result.state(), JobState::Cancelled);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::Cancelled
        );
        assert!(!destination.exists());
    }

    #[test]
    fn cancellation_is_refused_after_repack_enters_the_promotion_cutoff() {
        let fixture = SyntheticExtractionFixture::populated();
        let bundle = extracted_bundle(&fixture, "promotion-cutoff-repack-bundle");
        let plan = repack_plan(&fixture, &bundle, "promotion-cutoff-repack.pfs0");
        let destination = plan.snapshot().destination().to_path_buf();
        let session = OperationSession::new();
        let mut refused = false;
        let result = crate::operation::execute_with_producer_and_checkpoint(
            plan,
            &session,
            |_, _, _| Ok(()),
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AtomicPromotionStarted {
                    refused = !session.cancel();
                }
            },
        );

        assert!(refused);
        assert_eq!(
            result.state(),
            JobState::Succeeded,
            "{:?}",
            result.failure()
        );
        assert!(destination.is_file());
    }

    #[test]
    fn post_promotion_change_reports_uncertainty_and_retains_repack_evidence() {
        let fixture = SyntheticExtractionFixture::populated();
        let bundle = extracted_bundle(&fixture, "uncertain-repack-bundle");
        let plan = repack_plan(&fixture, &bundle, "uncertain-repack.pfs0");
        let destination = plan.snapshot().destination().to_path_buf();
        let session = OperationSession::new();
        let mut changed_after_promotion = false;
        let result = crate::operation::execute_with_producer_and_checkpoint(
            plan,
            &session,
            |_, _, _| Ok(()),
            |checkpoint| {
                if checkpoint != ExecutionCheckpoint::AfterPromotion {
                    return;
                }
                let mut published = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&destination)
                    .expect("open published PFS0 at post-promotion checkpoint");
                let mut byte = [0_u8; 1];
                published.read_exact(&mut byte).unwrap();
                byte[0] ^= 0xff;
                published.seek(SeekFrom::Start(0)).unwrap();
                published.write_all(&byte).unwrap();
                published.sync_all().unwrap();
                changed_after_promotion = true;
            },
        );

        assert!(changed_after_promotion);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert!(result.artifacts().iter().any(|artifact| {
            artifact.role() == OperationArtifactRole::PublishedDestination
                && artifact.path() == destination
        }));
        assert!(
            result
                .artifacts()
                .iter()
                .any(|artifact| artifact.retained())
        );
        assert!(destination.is_file());
    }

    #[test]
    fn unowned_stage_entry_is_reported_as_a_repack_cleanup_warning() {
        let fixture = SyntheticExtractionFixture::populated();
        let bundle = extracted_bundle(&fixture, "cleanup-warning-repack-bundle");
        let plan = repack_plan(&fixture, &bundle, "cleanup-warning-repack.pfs0");
        let destination = plan.snapshot().destination().to_path_buf();
        let stage_directory =
            planned_artifact_path(&plan, OperationArtifactRole::PrivateStagingDirectory);
        let session = OperationSession::new();
        let mut inserted_entry = false;
        let result = crate::operation::execute_with_producer_and_checkpoint(
            plan,
            &session,
            |_, _, _| Ok(()),
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AfterPromotion {
                    fs::write(
                        stage_directory.join("test-unowned-entry"),
                        b"preserve for inventory",
                    )
                    .unwrap();
                    inserted_entry = true;
                }
            },
        );

        assert!(inserted_entry);
        assert_eq!(
            result.state(),
            JobState::Succeeded,
            "{:?}",
            result.failure()
        );
        assert_eq!(
            result.outcome(),
            Some(crate::operation::OperationOutcome::Repacked)
        );
        assert_eq!(
            result.cleanup_warning().unwrap().code(),
            OperationFailureCode::CleanupIncomplete
        );
        assert!(result.cleanup_artifact_retained());
        assert!(destination.is_file());
    }

    #[test]
    fn substituted_intermediate_spool_is_preserved_and_reported() {
        let fixture = SyntheticExtractionFixture::populated();
        let bundle = extracted_bundle(&fixture, "substituted-spool-repack-bundle");
        let plan = repack_plan(&fixture, &bundle, "substituted-spool-repack.pfs0");
        let stage_directory =
            planned_artifact_path(&plan, OperationArtifactRole::PrivateStagingDirectory);
        let spool_path = stage_directory.join(INTERMEDIATE_NCA_NAME);
        let planned_spool = plan
            .snapshot()
            .planned_artifacts()
            .iter()
            .find(|artifact| artifact.role() == OperationArtifactRole::PrivateMemberSpool)
            .expect("repack plan records its intermediate spool");
        let planned_spool_path = planned_spool.path().to_path_buf();
        let expected_spool_sha256 = planned_spool
            .expected_sha256()
            .expect("repack plan predicts the rebuilt NCA digest");
        let replacement = b"unproven intermediate replacement";
        let mut spool_was_present = false;
        let mut substituted = false;
        let result = crate::operation::execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            |_, _, _| Ok(()),
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforeArtifactInventory {
                    spool_was_present = spool_path.is_file();
                    if spool_was_present {
                        fs::remove_file(&spool_path).expect("remove original spool entry");
                        fs::write(&spool_path, replacement).expect("substitute spool entry");
                        substituted = true;
                    }
                }
            },
        );

        assert_eq!(planned_spool_path, spool_path);
        assert!(
            spool_was_present,
            "registered spool must remain linked through inventory"
        );
        assert!(substituted);
        assert_eq!(result.state(), JobState::Succeeded, "{result:?}");
        assert_eq!(
            result.outcome(),
            Some(crate::operation::OperationOutcome::Repacked)
        );
        assert_eq!(fs::read(&spool_path).unwrap(), replacement);
        let spool = result
            .artifacts()
            .iter()
            .find(|artifact| artifact.role() == OperationArtifactRole::PrivateMemberSpool)
            .expect("intermediate spool is included in artifact inventory");
        assert_eq!(spool.path(), spool_path);
        assert_eq!(spool.path_identity_matches(), Some(false));
        assert_eq!(spool.recorded_sha256(), Some(expected_spool_sha256));
    }
}

fn validate_rebuilt_nca(
    nca: &mut File,
    plan: &ProgramRepackOperationPlan,
    session: &OperationSession,
) -> Result<(), OperationFailureCode> {
    check_cancelled(session)?;
    let block = crate::nca::read_header_block(nca, plan.nca_length, plan.header_key.as_bytes())
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    let header = crate::nca::parse_header_block(&block, plan.nca_length)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    crate::inspection::validate_nca_profile(&header)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    if header.content_type != crate::nca::ContentType::Program
        || header.program_id != plan.manifest.program_id
        || header.content_index != plan.manifest.content_index
        || header.declared_size != plan.nca_length
        || header.partitions.len() != plan.partitions.len()
    {
        return Err(OperationFailureCode::ValidationFailed);
    }
    let mut expected_offset = crate::nca::HEADER_SIZE as u64;
    for (index, (actual, expected)) in header.partitions.iter().zip(&plan.partitions).enumerate() {
        if usize::from(actual.index) != index
            || actual.offset != expected_offset
            || actual.size != expected.layout.padded_size
        {
            return Err(OperationFailureCode::ValidationFailed);
        }
        if !crate::verification::fs_header_hash_matches(&block, index) {
            return Err(OperationFailureCode::ValidationFailed);
        }
        expected_offset = expected_offset
            .checked_add(actual.size)
            .ok_or(OperationFailureCode::ResourceLimitExceeded)?;
    }
    if expected_offset != plan.nca_length {
        return Err(OperationFailureCode::ValidationFailed);
    }

    let inventory = crate::inspection::validate_native_inventory(nca, &header)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    compare_inventory_and_payloads(nca, &inventory, plan, session)
}

fn compare_inventory_and_payloads(
    nca: &mut File,
    inventory: &NativeNcaInventory,
    plan: &ProgramRepackOperationPlan,
    session: &OperationSession,
) -> Result<(), OperationFailureCode> {
    let bundle_root = open_directory(&plan.bundle.path)
        .map_err(|_| OperationFailureCode::RepackPayloadChanged)?;
    verify_directory_identity(&bundle_root, plan.bundle_identity)
        .map_err(|_| OperationFailureCode::RepackPayloadChanged)?;
    let payload_tree = BundlePayloadTree {
        root: &bundle_root,
        identity: plan.bundle_identity,
        directories: &plan.directories,
    };
    let expected_file_count = plan
        .partitions
        .iter()
        .try_fold(0_usize, |total, partition| {
            total.checked_add(partition.layout.files.len())
        })
        .ok_or(OperationFailureCode::ResourceLimitExceeded)?;
    if inventory.files.len() != expected_file_count {
        return Err(OperationFailureCode::ValidationFailed);
    }
    let mut file_index = 0_usize;
    for partition in &plan.partitions {
        for expected in &partition.layout.files {
            check_cancelled(session)?;
            let span = inventory
                .files
                .get(file_index)
                .ok_or(OperationFailureCode::ValidationFailed)?;
            if span.partition_index != partition.index
                || span.path != expected.path
                || span.size != expected.size
            {
                return Err(OperationFailureCode::ValidationFailed);
            }
            let manifest_path = join_partition_path(partition.index, &expected.path)?;
            let payload = find_payload(&plan.payloads, &manifest_path)?;
            compare_payload_span(nca, &payload_tree, span, payload, session)?;
            file_index = file_index
                .checked_add(1)
                .ok_or(OperationFailureCode::ResourceLimitExceeded)?;
        }
    }

    let mut expected_directories = Vec::new();
    for partition in &plan.manifest.partitions {
        expected_directories
            .try_reserve(partition.directories.len())
            .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
        expected_directories.extend(partition.directories.iter().cloned());
    }
    let mut actual_directories = inventory.directories.clone();
    expected_directories.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    actual_directories.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    if actual_directories != expected_directories {
        return Err(OperationFailureCode::ValidationFailed);
    }
    Ok(())
}

fn compare_payload_span(
    nca: &mut File,
    payload_tree: &BundlePayloadTree<'_>,
    span: &NativeNcaFileSpan,
    payload: &PayloadEvidence,
    session: &OperationSession,
) -> Result<(), OperationFailureCode> {
    with_payload_file(payload_tree, payload, |source| {
        source
            .seek(SeekFrom::Start(0))
            .and_then(|_| nca.seek(SeekFrom::Start(span.offset)))
            .map_err(|_| OperationFailureCode::ValidationFailed)?;
        let mut remaining = span.size;
        let mut source_buffer = [0_u8; REPACK_COPY_CHUNK_SIZE];
        let mut output_buffer = [0_u8; REPACK_COPY_CHUNK_SIZE];
        let mut hasher = Sha256::new();
        while remaining > 0 {
            check_cancelled(session)?;
            let count = usize::try_from(remaining.min(source_buffer.len() as u64))
                .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
            source
                .read_exact(&mut source_buffer[..count])
                .map_err(|_| OperationFailureCode::RepackPayloadChanged)?;
            nca.read_exact(&mut output_buffer[..count])
                .map_err(|_| OperationFailureCode::ValidationFailed)?;
            if source_buffer[..count] != output_buffer[..count] {
                return Err(OperationFailureCode::ValidationFailed);
            }
            hasher.update(&output_buffer[..count]);
            remaining -=
                u64::try_from(count).map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
        }
        if Sha256Digest::from_bytes(hasher.finalize().into()) != payload.baseline.sha256 {
            return Err(OperationFailureCode::ValidationFailed);
        }
        Ok(())
    })
}

fn validate_final_package(
    stage: &mut File,
    plan: &ProgramRepackOperationPlan,
    session: &OperationSession,
) -> Result<(), OperationFailureCode> {
    check_cancelled(session)?;
    let evidence = inspect_file(stage).map_err(|_| OperationFailureCode::ValidationFailed)?;
    if evidence.snapshot.len != plan.output_length || evidence.sha256 != plan.output_sha256 {
        return Err(OperationFailureCode::ValidationFailed);
    }
    stage
        .seek(SeekFrom::Start(0))
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    let probed = crate::pfs0::probe(stage, plan.output_length)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    let Some(entry) = probed.entries.first() else {
        return Err(OperationFailureCode::ValidationFailed);
    };
    if probed.format != crate::engine::ContainerFormat::Pfs0
        || probed.file_size != plan.output_length
        || probed.payload_size != plan.nca_length
        || probed.entries.len() != 1
        || entry.name != plan.member_name
        || entry.offset != 0
        || entry.size != plan.nca_length
        || entry.file_offset != plan.outer_layout.payload_offset
        || entry.file_offset.checked_add(entry.size) != Some(plan.output_length)
    {
        return Err(OperationFailureCode::ValidationFailed);
    }
    stage
        .seek(SeekFrom::Start(entry.file_offset))
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    let digest = hash_exact(stage, plan.nca_length, || check_cancelled(session))?;
    if digest != plan.nca_sha256 {
        return Err(OperationFailureCode::ValidationFailed);
    }
    Ok(())
}

pub(super) fn validate_existing_package(
    file: &mut File,
    plan: &ProgramRepackOperationPlan,
    session: &OperationSession,
) -> Result<(), OperationFailureCode> {
    validate_final_package(file, plan, session)
}

fn hash_exact(
    reader: &mut impl Read,
    mut remaining: u64,
    mut checkpoint: impl FnMut() -> Result<(), OperationFailureCode>,
) -> Result<Sha256Digest, OperationFailureCode> {
    let mut buffer = [0_u8; REPACK_COPY_CHUNK_SIZE];
    let mut hasher = Sha256::new();
    while remaining > 0 {
        checkpoint()?;
        let count = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
        reader
            .read_exact(&mut buffer[..count])
            .map_err(|_| OperationFailureCode::ValidationFailed)?;
        hasher.update(&buffer[..count]);
        remaining -=
            u64::try_from(count).map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    }
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}
