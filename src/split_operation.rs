//! Source-backed canonical Split planning and publication.
//!
//! A Split job publishes one outer bundle containing the canonical numbered
//! directory and its adjacent sidecar. The existing resolver receives the
//! exact canonical-directory path; it never searches for wrapper directories.

#[cfg(target_os = "macos")]
use crate::operation::OperationOutcome;
use crate::operation::{
    ConflictPolicy, OperationError, OperationFailureCode, OperationMilestone, OperationResult,
    OperationSession, PlannedSource,
};
#[cfg(target_os = "macos")]
use crate::operation::{OperationArtifact, OperationArtifactRole, SplitArtifactInventoryRecord};
use crate::sha256::Sha256Digest;
use crate::split_trust::SplitTrustWriter;
#[cfg(target_os = "macos")]
use crate::split_trust::{
    SplitTrustCleanupLease, SplitTrustReceipt, SplitTrustStore, SplitTrustStoreError,
};
#[cfg(target_os = "macos")]
use serde::Deserialize;
use serde::Serialize;
use std::fmt;
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
use crate::file_identity::{
    FileIdentity, FileSnapshot, file_snapshot, handle_identity, path_identity,
};
#[cfg(target_os = "macos")]
use crate::input_resolution::{InputResolutionCapabilities, InputResolutionRequest};
use crate::inspection::CancellationHandle;
#[cfg(target_os = "macos")]
use crate::split_manifest::{MAX_SPLIT_MANIFEST_BYTES, SplitManifestSegment, encode_manifest};
#[cfg(target_os = "macos")]
use fs2::FileExt as _;
#[cfg(target_os = "macos")]
use sha2::{Digest as _, Sha256};
#[cfg(target_os = "macos")]
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "macos")]
use std::ffi::CStr;
#[cfg(target_os = "macos")]
use std::ffi::{CString, OsStr, OsString};
#[cfg(target_os = "macos")]
use std::fs::{self, File, OpenOptions};
#[cfg(target_os = "macos")]
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(target_os = "macos")]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(target_os = "macos")]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(target_os = "macos")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(target_os = "macos")]
static NEXT_SPLIT_TRANSACTION: AtomicU64 = AtomicU64::new(1);

#[cfg(target_os = "macos")]
const SPLIT_IO_BUFFER_SIZE: usize = 64 * 1024;
#[cfg(target_os = "macos")]
const SPLIT_LOCK_DIRECTORY_NAME: &str = ".nscb-split-locks";
#[cfg(target_os = "macos")]
const SPLIT_RECEIPT_LOCK_DIRECTORY_NAME: &str = ".receipt-state-locks";
#[cfg(target_os = "macos")]
const SPLIT_RECEIPT_LOCK_NAME: &str = ".receipt-state.lock";
#[cfg(target_os = "macos")]
const LEGACY_SPLIT_LOCK_NAME: &str = ".nscb-operation-directory.lock";
#[cfg(target_os = "macos")]
const MAX_SPLIT_JOURNAL_BYTES: usize = 32 * 1024 * 1024;

const DEFAULT_SEGMENT_SIZE_BYTES: u64 = 0xFFFF_0000;
#[cfg(any(target_os = "macos", test))]
const MAX_SEGMENT_COUNT: usize = 100;

/// A request to split one explicitly selected regular file into a bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SplitRequest {
    source: PathBuf,
    bundle_directory: PathBuf,
    conflict_policy: ConflictPolicy,
}

impl SplitRequest {
    /// Creates a request with an explicit source and outer bundle destination.
    pub fn new(source: impl Into<PathBuf>, bundle_directory: impl Into<PathBuf>) -> Self {
        Self {
            source: source.into(),
            bundle_directory: bundle_directory.into(),
            conflict_policy: ConflictPolicy::Fail,
        }
    }

    /// Selects how the operation handles a bundle that already exists.
    #[must_use]
    pub fn with_conflict_policy(mut self, policy: ConflictPolicy) -> Self {
        self.conflict_policy = policy;
        self
    }

    /// Returns the selected source path.
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Returns the outer bundle destination.
    pub fn bundle_directory(&self) -> &Path {
        &self.bundle_directory
    }

    /// Returns the selected destination conflict policy.
    pub const fn conflict_policy(&self) -> ConflictPolicy {
        self.conflict_policy
    }
}

/// The destination state captured by a Split plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SplitBundleBaseline {
    /// No outer bundle existed when the plan was created.
    Absent,
    /// An outer bundle directory existed when the plan was created.
    Existing {
        /// Opaque identity of the existing bundle directory.
        identity: Sha256Digest,
    },
}

/// An inspection-only view of a non-replayable Split plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SplitPlanSnapshot {
    kind: &'static str,
    nscb_version: &'static str,
    source: PlannedSource,
    bundle_directory: PathBuf,
    canonical_directory: PathBuf,
    manifest_path: PathBuf,
    segment_size_bytes: u64,
    segment_lengths: Vec<u64>,
    conflict_policy: ConflictPolicy,
    destination_baseline: SplitBundleBaseline,
}

impl SplitPlanSnapshot {
    /// Returns the serialized kind identifying this plan snapshot.
    pub const fn kind(&self) -> &'static str {
        self.kind
    }

    /// Returns the NSCB package version that produced this snapshot.
    pub const fn nscb_version(&self) -> &'static str {
        self.nscb_version
    }

    /// Returns the source evidence observed during planning.
    pub const fn source(&self) -> &PlannedSource {
        &self.source
    }

    /// Returns the outer directory published as one bundle.
    pub fn bundle_directory(&self) -> &Path {
        &self.bundle_directory
    }

    /// Returns the canonical Split directory inside the bundle.
    pub fn canonical_directory(&self) -> &Path {
        &self.canonical_directory
    }

    /// Returns the manifest adjacent to the canonical directory.
    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    /// Returns the fixed production segment size in bytes.
    pub const fn segment_size_bytes(&self) -> u64 {
        self.segment_size_bytes
    }

    /// Returns the checked length of each planned physical segment.
    pub fn segment_lengths(&self) -> &[u64] {
        &self.segment_lengths
    }

    /// Returns the destination policy captured by the plan.
    pub const fn conflict_policy(&self) -> ConflictPolicy {
        self.conflict_policy
    }

    /// Returns the destination state that execution must revalidate.
    pub const fn destination_baseline(&self) -> &SplitBundleBaseline {
        &self.destination_baseline
    }
}

/// The planned outer bundle and inner canonical Split directory paths.
///
/// The result can contain these paths before publication or after an uncertain
/// failure. Check the operation outcome to determine whether the bundle was
/// published.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SplitOutputPaths {
    bundle_directory: PathBuf,
    canonical_directory: PathBuf,
    manifest_path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_bundle_directory: Option<PathBuf>,
}

impl SplitOutputPaths {
    /// Returns the planned outer bundle directory.
    pub fn bundle_directory(&self) -> &Path {
        &self.bundle_directory
    }

    /// Returns the canonical Split directory accepted by the existing resolver.
    pub fn canonical_directory(&self) -> &Path {
        &self.canonical_directory
    }

    /// Returns the versioned manifest adjacent to the canonical directory.
    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    /// Returns the recovery location recorded for retained transaction data.
    /// The location is present only when the recorded Split directory identity
    /// still matches the destination or staging entry under the validated parent.
    /// It is absent when displacement or journal evidence leaves the location
    /// uncertain.
    pub fn recovery_bundle_directory(&self) -> Option<&Path> {
        self.recovery_bundle_directory.as_deref()
    }
}

/// Durable receipt state observed by a Split job.
///
/// Downstream code should include a wildcard arm when matching this enum so
/// future receipt states remain compatible with the 1.x API.
///
/// ```compile_fail
/// use nscb::SplitReceiptCommitState;
///
/// fn exhaustive_match(state: SplitReceiptCommitState) {
///     match state {
///         SplitReceiptCommitState::NotAttempted => (),
///         SplitReceiptCommitState::ConfirmedUncommitted => (),
///         SplitReceiptCommitState::ConfirmedCommitted => (),
///         SplitReceiptCommitState::Uncertain => (),
///     }
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SplitReceiptCommitState {
    /// The receipt operation was not started.
    NotAttempted,
    /// Durable lookup confirmed that no active matching receipt was committed.
    ConfirmedUncommitted,
    /// The host store confirmed the receipt commit for these exact bytes.
    ConfirmedCommitted,
    /// The store could not establish whether the receipt commit took effect.
    Uncertain,
}

/// An immutable, in-memory Split plan that can be consumed by one execution.
pub struct SplitPlan<'a> {
    snapshot: SplitPlanSnapshot,
    #[cfg(target_os = "macos")]
    state: SplitPlanState<'a>,
    #[cfg(not(target_os = "macos"))]
    _trust_store: std::marker::PhantomData<&'a dyn SplitTrustWriter>,
}

#[cfg(target_os = "macos")]
struct SplitPlanState<'a> {
    source_file: File,
    source_parent: File,
    source_parent_path: PathBuf,
    source_parent_identity: FileIdentity,
    source_name: OsString,
    source_identity: FileIdentity,
    source_snapshot: FileSnapshot,
    source_sha256: Sha256Digest,
    destination_parent: File,
    destination_parent_identity: FileIdentity,
    destination_name: OsString,
    destination_identity: Option<FileIdentity>,
    already_up_to_date: bool,
    skipped: bool,
    trust_store: &'a dyn SplitTrustWriter,
    #[cfg(test)]
    test_failpoint: Option<SplitTestFailpoint>,
}

/// Carries the plan state and cancellation probe shared by cleanup steps.
#[cfg(target_os = "macos")]
struct SplitCleanupOperationContext<'operation, 'plan> {
    state: &'operation SplitPlanState<'plan>,
    session: Option<&'operation OperationSession>,
}

impl SplitPlan<'_> {
    /// Returns the inspection-only snapshot associated with this plan.
    pub const fn snapshot(&self) -> &SplitPlanSnapshot {
        &self.snapshot
    }
}

impl fmt::Debug for SplitPlan<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SplitPlan")
            .field("snapshot", &self.snapshot)
            .finish_non_exhaustive()
    }
}

/// Plans a production-size Split operation using the fixed v1 segment size.
pub(crate) fn plan_split<'a>(
    request: SplitRequest,
    trust_store: &'a dyn SplitTrustWriter,
) -> Result<SplitPlan<'a>, OperationError> {
    plan_split_inner(request, trust_store, None)
}

pub(crate) fn plan_split_with_cancellation<'a>(
    request: SplitRequest,
    trust_store: &'a dyn SplitTrustWriter,
    cancellation: CancellationHandle,
) -> Result<SplitPlan<'a>, OperationError> {
    plan_split_inner(request, trust_store, Some(cancellation))
}

fn plan_split_inner<'a>(
    request: SplitRequest,
    trust_store: &'a dyn SplitTrustWriter,
    cancellation: Option<CancellationHandle>,
) -> Result<SplitPlan<'a>, OperationError> {
    #[cfg(test)]
    {
        plan_split_with_size(
            request,
            trust_store,
            DEFAULT_SEGMENT_SIZE_BYTES,
            None,
            cancellation.as_ref(),
            None,
        )
    }
    #[cfg(not(test))]
    {
        plan_split_with_size(
            request,
            trust_store,
            DEFAULT_SEGMENT_SIZE_BYTES,
            cancellation.as_ref(),
        )
    }
}

fn plan_split_with_size<'a>(
    request: SplitRequest,
    trust_store: &'a dyn SplitTrustWriter,
    segment_size: u64,
    #[cfg(test)] failpoint: Option<SplitTestFailpoint>,
    cancellation: Option<&CancellationHandle>,
    #[cfg(test)] progress_observer: Option<&mut dyn FnMut(u64)>,
) -> Result<SplitPlan<'a>, OperationError> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (request, trust_store, segment_size);
        let _ = cancellation;
        #[cfg(test)]
        let _ = (failpoint, progress_observer);
        Err(OperationError::new(
            OperationFailureCode::UnsupportedCapability,
        ))
    }
    #[cfg(target_os = "macos")]
    {
        #[cfg(test)]
        {
            plan_split_macos(
                request,
                trust_store,
                segment_size,
                cancellation,
                failpoint,
                progress_observer,
            )
        }
        #[cfg(not(test))]
        {
            plan_split_macos(request, trust_store, segment_size, cancellation)
        }
    }
}

pub(crate) fn validate_split_output_parent(path: &Path) -> Result<(), OperationFailureCode> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Err(OperationFailureCode::UnsupportedCapability)
    }
    #[cfg(target_os = "macos")]
    {
        validate_split_output_parent_with(path, crate::operation::qualified_local_apfs_volume)
    }
}

#[cfg(target_os = "macos")]
fn validate_split_output_parent_with(
    path: &Path,
    supports_volume: impl Fn(&File) -> bool,
) -> Result<(), OperationFailureCode> {
    let mut candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| OperationFailureCode::DestinationUnavailable)?
            .join(path)
    };
    loop {
        match fs::metadata(&candidate) {
            Ok(metadata) if metadata.is_dir() => {
                let canonical = fs::canonicalize(&candidate)
                    .map_err(|_| OperationFailureCode::DestinationUnavailable)?;
                let directory = open_directory(&canonical)
                    .map_err(|_| OperationFailureCode::DestinationUnavailable)?;
                return if supports_volume(&directory) {
                    Ok(())
                } else {
                    Err(OperationFailureCode::UnsupportedCapability)
                };
            }
            Ok(_) => return Err(OperationFailureCode::DestinationConflict),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if !candidate.pop() {
                    return Err(OperationFailureCode::UnsafePath);
                }
            }
            Err(_) => return Err(OperationFailureCode::DestinationUnavailable),
        }
    }
}

#[cfg(target_os = "macos")]
fn plan_split_macos<'a>(
    request: SplitRequest,
    trust_store: &'a dyn SplitTrustWriter,
    segment_size: u64,
    cancellation: Option<&CancellationHandle>,
    #[cfg(test)] failpoint: Option<SplitTestFailpoint>,
    #[cfg(test)] progress_observer: Option<&mut dyn FnMut(u64)>,
) -> Result<SplitPlan<'a>, OperationError> {
    if cancellation.is_some_and(CancellationHandle::is_cancelled) {
        return Err(OperationError::new(OperationFailureCode::Cancelled));
    }
    let (source_parent_path, source_name) =
        resolve_parent_and_name(request.source()).map_err(OperationError::new)?;
    let (destination_parent_path, destination_name) =
        resolve_parent_and_name(request.bundle_directory()).map_err(OperationError::new)?;
    if source_name == destination_name && source_parent_path == destination_parent_path {
        return Err(OperationError::new(OperationFailureCode::UnsafePath));
    }

    let source_parent = open_directory(&source_parent_path)
        .map_err(|_| OperationError::new(OperationFailureCode::SourceUnavailable))?;
    let destination_parent = open_directory(&destination_parent_path)
        .map_err(|_| OperationError::new(OperationFailureCode::DestinationUnavailable))?;
    let source_parent_identity = required_identity(&source_parent)?;
    let destination_parent_identity = required_identity(&destination_parent)
        .map_err(|_| OperationError::new(OperationFailureCode::UnsupportedCapability))?;
    if !crate::operation::qualified_local_apfs_volume(&destination_parent) {
        return Err(OperationError::new(
            OperationFailureCode::UnsupportedCapability,
        ));
    }
    if is_reserved_split_namespace_name(&destination_name)
        || is_reserved_split_namespace_name(&source_name)
    {
        return Err(OperationError::new(OperationFailureCode::UnsafePath));
    }

    let mut source_file = open_file_at(&source_parent, &source_name)
        .map_err(|_| OperationError::new(OperationFailureCode::SourceUnavailable))?;
    let source_identity = required_identity(&source_file)?;
    let metadata = source_file
        .metadata()
        .map_err(|_| OperationError::new(OperationFailureCode::SourceUnavailable))?;
    if !metadata.file_type().is_file() {
        return Err(OperationError::new(OperationFailureCode::SourceUnavailable));
    }
    let source_size = metadata.len();
    let lengths = segment_lengths(source_size, segment_size)?;
    let source_snapshot = file_snapshot(&metadata, Some(source_identity));
    let (observed_size, source_sha256) = hash_file_with_check(
        &mut source_file,
        || {
            if cancellation.is_some_and(CancellationHandle::is_cancelled) {
                Err(OperationFailureCode::Cancelled)
            } else {
                Ok(())
            }
        },
        #[cfg(test)]
        progress_observer,
    )
    .map_err(|error| match error {
        HashFileFailure::Operation(code) => OperationError::new(code),
        HashFileFailure::Io => OperationError::new(OperationFailureCode::SourceUnavailable),
    })?;
    if observed_size != source_size || snapshot_of(&source_file)? != source_snapshot {
        return Err(OperationError::new(OperationFailureCode::SourceChanged));
    }

    let destination_path = destination_parent_path.join(&destination_name);
    let canonical_directory = destination_path.join(&source_name);
    let manifest_name = append_suffix(&source_name, ".nscb-split.json");
    let manifest_path = destination_path.join(&manifest_name);
    let destination_identity =
        match open_optional_directory_at(&destination_parent, &destination_name) {
            Ok(directory) => directory
                .map(|directory| required_identity(&directory))
                .transpose()?,
            Err(error)
                if request.conflict_policy == ConflictPolicy::Replace
                    && error.code() == OperationFailureCode::DestinationConflict =>
            {
                return Err(OperationError::new(
                    OperationFailureCode::SplitReplacementUnsupported,
                ));
            }
            Err(error) => return Err(error),
        };
    let source_path = source_parent_path.join(&source_name);
    if source_path_within(&source_path, &destination_path) {
        return Err(OperationError::new(OperationFailureCode::UnsafePath));
    }
    let snapshot = SplitPlanSnapshot {
        kind: "split_plan",
        nscb_version: env!("CARGO_PKG_VERSION"),
        source: PlannedSource::new(
            source_path,
            source_identity.fingerprint(),
            source_size,
            source_sha256,
        ),
        bundle_directory: destination_path,
        canonical_directory,
        manifest_path,
        segment_size_bytes: segment_size,
        segment_lengths: lengths,
        conflict_policy: request.conflict_policy,
        destination_baseline: destination_identity.map_or(
            SplitBundleBaseline::Absent,
            |identity| SplitBundleBaseline::Existing {
                identity: identity.fingerprint(),
            },
        ),
    };
    let already_up_to_date = destination_identity.is_some()
        && bundle_is_up_to_date(&snapshot, &source_name, trust_store, cancellation);
    if cancellation.is_some_and(CancellationHandle::is_cancelled) {
        return Err(OperationError::new(OperationFailureCode::Cancelled));
    }
    if destination_identity.is_some()
        && request.conflict_policy == ConflictPolicy::Replace
        && !already_up_to_date
    {
        return Err(OperationError::new(
            OperationFailureCode::SplitReplacementUnsupported,
        ));
    }
    let skipped = destination_identity.is_some()
        && request.conflict_policy == ConflictPolicy::Skip
        && !already_up_to_date;
    Ok(SplitPlan {
        snapshot,
        state: SplitPlanState {
            source_file,
            source_parent,
            source_parent_path,
            source_parent_identity,
            source_name,
            source_identity,
            source_snapshot,
            source_sha256,
            destination_parent,
            destination_parent_identity,
            destination_name,
            destination_identity,
            already_up_to_date,
            skipped,
            trust_store,
            #[cfg(test)]
            test_failpoint: failpoint,
        },
    })
}

#[cfg(test)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SplitTestFailpoint {
    FailureBeforeSegmentSync,
    FailureBeforeManifestSync,
    FailureAtPromotion,
    SubstituteDestinationAfterPromotion,
    SubstituteDestinationBetweenCheckAndSwap,
    SubstituteStagingBeforeRollbackIdentityCheck,
    SubstituteStagingBeforeRecoveryIdentityCheck,
    SubstituteArtifactBeforeFinalIdentityCheck,
    SubstituteArtifactAfterFinalIdentityCheck,
    SubstituteArtifactAfterCleanupPreflight,
    ModifyAndRestoreArtifactAfterCleanupPreflight,
    SubstituteCleanupAliasAfterIdentityCheck,
    CancelBeforeArtifactUnlink,
    SimulatedUnrelatedEntryAfterPublication,
    SimulatedModifiedSegmentAfterPublication,
    SimulatedSubstitutedSegmentAfterPublication,
    SimulatedAliasedSegmentAfterPublication,
    CancelDuringStagedVerification,
    CancelAfterPublicationBeforeReceiptCommit,
    SimulatedInterruptionAfterPublication,
    SimulatedInterruptionAfterCleanupQuarantine,
    SimulatedInterruptionAfterCleanupArtifactUnlink,
    SimulatedTornPublishedJournalAfterPromotion,
    FailureBeforeReceiptCommit,
    FailureBeforeReceiptCommitWithCancelDuringCleanupHash,
    SimulatedInterruptionAfterReceiptCommitted,
    SimulatedAcknowledgementBeforeReceiptJournalUpdate,
    SimulatedFailureAfterJournalCreateBeforeIdentityRecord,
}

#[cfg(all(test, target_os = "macos"))]
fn plan_split_for_tests<'a>(
    request: SplitRequest,
    trust_store: &'a dyn SplitTrustWriter,
    segment_size: u64,
    failpoint: Option<SplitTestFailpoint>,
) -> Result<SplitPlan<'a>, OperationError> {
    plan_split_with_size(request, trust_store, segment_size, failpoint, None, None)
}

#[cfg(all(test, target_os = "macos"))]
fn plan_split_for_tests_with_cancellation<'a>(
    request: SplitRequest,
    trust_store: &'a dyn SplitTrustWriter,
    segment_size: u64,
    cancellation: &CancellationHandle,
    progress_observer: &mut dyn FnMut(u64),
) -> Result<SplitPlan<'a>, OperationError> {
    plan_split_with_size(
        request,
        trust_store,
        segment_size,
        None,
        Some(cancellation),
        Some(progress_observer),
    )
}

#[cfg(target_os = "macos")]
/// Rejects Unicode case spellings that can resolve to a reserved Split namespace on APFS.
fn is_reserved_split_namespace_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    [SPLIT_LOCK_DIRECTORY_NAME, LEGACY_SPLIT_LOCK_NAME]
        .into_iter()
        .any(|reserved| {
            name.to_lowercase() == reserved.to_lowercase()
                || name.to_uppercase() == reserved.to_uppercase()
        })
}

#[cfg(target_os = "macos")]
fn resolve_parent_and_name(
    path: &Path,
) -> Result<(PathBuf, std::ffi::OsString), OperationFailureCode> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| OperationFailureCode::DestinationUnavailable)?
            .join(path)
    };
    let name = absolute
        .file_name()
        .filter(|name| *name != OsStr::new(".") && *name != OsStr::new(".."))
        .ok_or(OperationFailureCode::UnsafePath)?
        .to_os_string();
    let parent = absolute.parent().ok_or(OperationFailureCode::UnsafePath)?;
    let parent =
        fs::canonicalize(parent).map_err(|_| OperationFailureCode::DestinationUnavailable)?;
    if !fs::metadata(&parent)
        .map_err(|_| OperationFailureCode::DestinationUnavailable)?
        .is_dir()
    {
        return Err(OperationFailureCode::DestinationUnavailable);
    }
    Ok((parent, name))
}

#[cfg(target_os = "macos")]
fn source_path_within(source: &Path, directory: &Path) -> bool {
    source.starts_with(directory)
}

#[cfg(target_os = "macos")]
fn append_suffix(name: &OsStr, suffix: &str) -> std::ffi::OsString {
    let mut result = name.to_os_string();
    result.push(suffix);
    result
}

#[cfg(target_os = "macos")]
fn open_directory(path: &Path) -> io::Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    if !directory.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a directory",
        ));
    }
    Ok(directory)
}

#[cfg(target_os = "macos")]
fn open_file_at(directory: &File, name: &OsStr) -> io::Result<File> {
    let name = c_name(name)?;
    // SAFETY: the open directory remains valid and name is one component.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor owned by this function.
    let file = unsafe { File::from_raw_fd(descriptor) };
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(target_os = "macos")]
fn open_optional_directory_at(
    directory: &File,
    name: &OsStr,
) -> Result<Option<File>, OperationError> {
    let name = c_name(name).map_err(|_| OperationError::new(OperationFailureCode::UnsafePath))?;
    // SAFETY: the open directory remains valid and name is one component.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor >= 0 {
        // SAFETY: openat returned a new descriptor owned by this function.
        return Ok(Some(unsafe { File::from_raw_fd(descriptor) }));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(None)
    } else if matches!(
        error.raw_os_error(),
        Some(libc::ENOTDIR) | Some(libc::ELOOP)
    ) {
        Err(OperationError::new(
            OperationFailureCode::DestinationConflict,
        ))
    } else {
        Err(OperationError::new(
            OperationFailureCode::DestinationUnavailable,
        ))
    }
}

#[cfg(target_os = "macos")]
fn required_identity(file: &File) -> Result<FileIdentity, OperationError> {
    handle_identity(file)
        .ok_or_else(|| OperationError::new(OperationFailureCode::UnsupportedCapability))
}

#[cfg(target_os = "macos")]
fn snapshot_of(file: &File) -> Result<FileSnapshot, OperationError> {
    let metadata = file
        .metadata()
        .map_err(|_| OperationError::new(OperationFailureCode::SourceChanged))?;
    Ok(file_snapshot(&metadata, handle_identity(file)))
}

#[cfg(target_os = "macos")]
fn c_name(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
enum HashFileFailure {
    Io,
    Operation(OperationFailureCode),
}

#[cfg(target_os = "macos")]
fn hash_file_with_check(
    file: &mut File,
    mut check: impl FnMut() -> Result<(), OperationFailureCode>,
    #[cfg(test)] mut progress_observer: Option<&mut dyn FnMut(u64)>,
) -> Result<(u64, Sha256Digest), HashFileFailure> {
    check().map_err(HashFileFailure::Operation)?;
    let length = file.metadata().map_err(|_| HashFileFailure::Io)?.len();
    file.seek(SeekFrom::Start(0))
        .map_err(|_| HashFileFailure::Io)?;
    let mut hasher = Sha256::new();
    let mut remaining = length;
    #[cfg(test)]
    let mut completed = 0_u64;
    let mut buffer = [0_u8; SPLIT_IO_BUFFER_SIZE];
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| {
            HashFileFailure::Operation(OperationFailureCode::SplitSourceSizeUnsupported)
        })?;
        let count = file
            .read(&mut buffer[..requested])
            .map_err(|_| HashFileFailure::Io)?;
        if count == 0 {
            return Err(HashFileFailure::Io);
        }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
        #[cfg(test)]
        {
            completed += count as u64;
            if let Some(observer) = progress_observer.as_deref_mut() {
                observer(completed);
            }
        }
        check().map_err(HashFileFailure::Operation)?;
    }
    if file.read(&mut [0_u8; 1]).map_err(|_| HashFileFailure::Io)? != 0 {
        return Err(HashFileFailure::Io);
    }
    check().map_err(HashFileFailure::Operation)?;
    Ok((length, Sha256Digest::from_bytes(hasher.finalize().into())))
}

#[cfg(target_os = "macos")]
struct PlanningSplitTrustStore<'a> {
    writer: &'a dyn SplitTrustWriter,
    cancellation: Option<&'a CancellationHandle>,
}

#[cfg(target_os = "macos")]
impl SplitTrustStore for PlanningSplitTrustStore<'_> {
    fn lookup(
        &self,
        manifest_sha256: &Sha256Digest,
    ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
        let is_cancelled = || {
            self.cancellation
                .is_some_and(CancellationHandle::is_cancelled)
        };
        self.writer
            .lookup_for_planning(manifest_sha256, &is_cancelled)
    }
}

#[cfg(target_os = "macos")]
fn bundle_is_up_to_date(
    snapshot: &SplitPlanSnapshot,
    canonical_name: &OsStr,
    trust_store: &dyn SplitTrustWriter,
    cancellation: Option<&CancellationHandle>,
) -> bool {
    let planning_trust_store = PlanningSplitTrustStore {
        writer: trust_store,
        cancellation,
    };
    bundle_is_up_to_date_with_store(
        snapshot,
        canonical_name,
        &planning_trust_store,
        cancellation,
    )
}

#[cfg(target_os = "macos")]
fn bundle_is_up_to_date_with_store(
    snapshot: &SplitPlanSnapshot,
    canonical_name: &OsStr,
    trust_store: &dyn SplitTrustStore,
    cancellation: Option<&CancellationHandle>,
) -> bool {
    let Some(manifest_name) = snapshot.manifest_path.file_name() else {
        return false;
    };
    if !bundle_has_exact_shape(&snapshot.bundle_directory, canonical_name, manifest_name) {
        return false;
    }
    let Ok(manifest_bytes) = read_split_manifest_bytes(&snapshot.manifest_path) else {
        return false;
    };
    let Ok(manifest) = crate::split_manifest::parse_manifest(&manifest_bytes) else {
        return false;
    };
    let Ok(canonical_manifest) = crate::split_manifest::encode_manifest(
        manifest.source_size,
        manifest.source_sha256,
        &manifest.segments,
    ) else {
        return false;
    };
    if manifest_bytes != canonical_manifest
        || manifest.source_size != snapshot.source.size()
        || manifest.source_sha256 != snapshot.source.sha256()
        || manifest
            .segments
            .iter()
            .map(|segment| segment.size)
            .collect::<Vec<_>>()
            != snapshot.segment_lengths
    {
        return false;
    }
    let manifest_digest = Sha256Digest::digest(&manifest_bytes);
    let Some(resolved) = resolve_split_bundle_at(
        &snapshot.bundle_directory,
        &snapshot.canonical_directory,
        trust_store,
        cancellation,
    ) else {
        return false;
    };
    if cancellation.is_some_and(CancellationHandle::is_cancelled) {
        return false;
    }
    if resolved.inputs.len() != 1 {
        return false;
    }
    let input = &resolved.inputs[0];
    let Some(qualification) = &input.qualification else {
        return false;
    };
    input.split_manifest_sha256() == Some(&manifest_digest)
        && read_split_manifest_bytes(&snapshot.manifest_path)
            .ok()
            .as_deref()
            == Some(manifest_bytes.as_slice())
        && qualification.original_size_bytes == snapshot.source.size()
        && qualification.original_sha256 == snapshot.source.sha256()
        && input
            .segments
            .iter()
            .map(|segment| segment.size)
            .collect::<Vec<_>>()
            == snapshot.segment_lengths
}

#[cfg(target_os = "macos")]
fn resolve_split_bundle_at(
    bundle_directory: &Path,
    canonical_directory: &Path,
    trust_store: &dyn SplitTrustStore,
    cancellation: Option<&CancellationHandle>,
) -> Option<crate::input_resolution::InputResolutionResult> {
    let resolution_control = match cancellation {
        Some(cancellation) => crate::input_resolution::InputResolutionControl::new()
            .with_cancellation(cancellation.clone()),
        None => crate::input_resolution::InputResolutionControl::new(),
    };
    crate::Engine::new()
        .resolve_inputs_with(
            InputResolutionRequest::new(bundle_directory).with_path(canonical_directory),
            InputResolutionCapabilities::new()
                .with_control(&resolution_control)
                .with_split_trust_store(trust_store),
        )
        .ok()
}

#[cfg(target_os = "macos")]
fn bundle_is_qualified_at(
    bundle_directory: &Path,
    canonical_directory: &Path,
    trust_store: &dyn SplitTrustWriter,
    cancellation: Option<&CancellationHandle>,
) -> bool {
    let planning_trust_store = PlanningSplitTrustStore {
        writer: trust_store,
        cancellation,
    };
    let Some(resolved) = resolve_split_bundle_at(
        bundle_directory,
        canonical_directory,
        &planning_trust_store,
        cancellation,
    ) else {
        return false;
    };
    !cancellation.is_some_and(CancellationHandle::is_cancelled)
        && resolved.inputs.len() == 1
        && resolved.inputs[0].qualification.is_some()
}

#[cfg(target_os = "macos")]
/// Confirms an occupied output contains exactly one qualified Split bundle.
fn bundle_contains_one_qualified_split_set(
    snapshot: &SplitPlanSnapshot,
    trust_store: &dyn SplitTrustWriter,
    cancellation: Option<&CancellationHandle>,
) -> bool {
    let Ok(entries) = fs::read_dir(&snapshot.bundle_directory) else {
        return false;
    };
    has_one_qualified_candidate(
        entries.map(|entry| entry.map(|entry| entry.path())),
        cancellation,
        |canonical_directory| {
            let Ok(file_type) = fs::symlink_metadata(canonical_directory) else {
                return false;
            };
            if !file_type.file_type().is_dir() {
                return false;
            }
            let Some(canonical_name) = canonical_directory.file_name() else {
                return false;
            };
            let manifest_name = append_suffix(canonical_name, ".nscb-split.json");
            bundle_has_exact_shape(&snapshot.bundle_directory, canonical_name, &manifest_name)
                && bundle_is_qualified_at(
                    &snapshot.bundle_directory,
                    canonical_directory,
                    trust_store,
                    cancellation,
                )
        },
    )
}

#[cfg(target_os = "macos")]
/// Returns true only when one candidate qualifies and cancellation stays clear.
fn has_one_qualified_candidate(
    candidates: impl IntoIterator<Item = io::Result<PathBuf>>,
    cancellation: Option<&CancellationHandle>,
    mut is_qualified: impl FnMut(&Path) -> bool,
) -> bool {
    let mut candidates = candidates.into_iter();
    let mut found_qualified_candidate = false;
    loop {
        if cancellation.is_some_and(CancellationHandle::is_cancelled) {
            return false;
        }
        let Some(candidate) = candidates.next() else {
            break;
        };
        if cancellation.is_some_and(CancellationHandle::is_cancelled) {
            return false;
        }
        let Ok(candidate) = candidate else {
            return false;
        };
        if !is_qualified(&candidate) {
            continue;
        }
        if cancellation.is_some_and(CancellationHandle::is_cancelled) {
            return false;
        }
        if found_qualified_candidate {
            return false;
        }
        found_qualified_candidate = true;
    }
    found_qualified_candidate && !cancellation.is_some_and(CancellationHandle::is_cancelled)
}

#[cfg(target_os = "macos")]
fn bundle_has_exact_shape(bundle: &Path, canonical_name: &OsStr, manifest_name: &OsStr) -> bool {
    let Ok(entries) = fs::read_dir(bundle) else {
        return false;
    };
    entry_names_match_exact_split_shape(
        entries.map(|entry| entry.map(|entry| entry.file_name())),
        canonical_name,
        manifest_name,
    )
}

#[cfg(target_os = "macos")]
fn entry_names_match_exact_split_shape(
    entries: impl IntoIterator<Item = io::Result<OsString>>,
    canonical_name: &OsStr,
    manifest_name: &OsStr,
) -> bool {
    let mut entries = entries.into_iter();
    let Some(Ok(first)) = entries.next() else {
        return false;
    };
    let Some(Ok(second)) = entries.next() else {
        return false;
    };
    if entries.next().is_some() {
        return false;
    }
    (first == canonical_name && second == manifest_name)
        || (first == manifest_name && second == canonical_name)
}

#[cfg(target_os = "macos")]
fn read_split_manifest_bytes(path: &Path) -> io::Result<Vec<u8>> {
    let link_metadata = fs::symlink_metadata(path)?;
    if link_metadata.file_type().is_symlink() || !link_metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "split manifest is not a regular file",
        ));
    }
    if link_metadata.len() > MAX_SPLIT_MANIFEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "split manifest exceeds the v1 size limit",
        ));
    }

    let parent_path = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "split manifest has no parent")
    })?;
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "split manifest has no filename",
        )
    })?;
    let parent = open_directory(parent_path)?;
    let mut file = open_file_at(&parent, name)?;
    let metadata = file.metadata()?;
    let identity = handle_identity(&file)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "file identity unavailable"))?;
    let before = file_snapshot(&metadata, Some(identity));
    if !metadata.file_type().is_file()
        || metadata.len() != link_metadata.len()
        || path_identity(path) != Some(identity)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "split manifest changed while opening",
        ));
    }

    let capacity = usize::try_from(metadata.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "split manifest too large"))?;
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(MAX_SPLIT_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SPLIT_MANIFEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "split manifest exceeds the v1 size limit",
        ));
    }

    let after_metadata = file.metadata()?;
    if file_snapshot(&after_metadata, handle_identity(&file)) != before
        || path_identity(path) != Some(identity)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "split manifest changed while reading",
        ));
    }
    Ok(bytes)
}

/// Executes a consumed Split plan in the caller's shared operation session.
pub(crate) fn execute_split(
    plan: SplitPlan<'_>,
    session: &OperationSession,
    cancellation: Option<CancellationHandle>,
) -> OperationResult {
    #[cfg(not(target_os = "macos"))]
    {
        let output = output_paths_from_snapshot(&plan.snapshot, None);
        let _ = (plan, session, cancellation);
        OperationResult::split_failure(
            OperationFailureCode::UnsupportedCapability,
            vec![OperationMilestone::Planned],
            output,
            SplitReceiptCommitState::NotAttempted,
            false,
            false,
            Vec::new(),
        )
    }
    #[cfg(target_os = "macos")]
    {
        execute_split_macos(plan, session, cancellation)
    }
}

fn output_paths_from_snapshot(
    snapshot: &SplitPlanSnapshot,
    recovery_bundle_directory: Option<PathBuf>,
) -> SplitOutputPaths {
    SplitOutputPaths {
        bundle_directory: snapshot.bundle_directory.clone(),
        canonical_directory: snapshot.canonical_directory.clone(),
        manifest_path: snapshot.manifest_path.clone(),
        recovery_bundle_directory,
    }
}

#[cfg(target_os = "macos")]
struct SplitRunFailure {
    code: OperationFailureCode,
    receipt_state: SplitReceiptCommitState,
    recovery_path: Option<PathBuf>,
    retained: bool,
}

#[cfg(target_os = "macos")]
struct SplitRunSuccess {
    outcome: OperationOutcome,
    receipt_state: SplitReceiptCommitState,
    recovery_path: Option<PathBuf>,
    retained: bool,
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct SplitArtifactSources {
    journal_names: Vec<OsString>,
    staging_names: Vec<OsString>,
}

#[cfg(target_os = "macos")]
impl SplitArtifactSources {
    fn record_transaction(&mut self, names: &TransactionNames) {
        self.push_journal(names.journal.clone());
        let mut initializing_name = names.journal.clone();
        initializing_name.push(".initializing");
        self.push_journal(initializing_name);
        if !self.staging_names.contains(&names.staging) {
            self.staging_names.push(names.staging.clone());
        }
    }

    fn push_journal(&mut self, name: OsString) {
        if !self.journal_names.contains(&name) {
            self.journal_names.push(name);
        }
    }

    fn is_empty(&self) -> bool {
        self.journal_names.is_empty() && self.staging_names.is_empty()
    }
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct SplitArtifactInventory {
    artifacts: Vec<OperationArtifact>,
    retained: bool,
    retained_storage_unknown: bool,
}

#[cfg(target_os = "macos")]
struct SplitArtifactRoot {
    file: File,
    path: PathBuf,
    published: bool,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
struct SplitObservedEntry {
    identity: FileIdentity,
    length: Option<u64>,
    sha256: Option<Sha256Digest>,
}

#[cfg(target_os = "macos")]
struct SplitArtifactLocation<'a> {
    artifact_id: u64,
    parent_artifact_id: Option<u64>,
    relative_name: &'a OsStr,
    path: &'a Path,
    parent_identity: Option<FileIdentity>,
    parent_identity_matches: Option<bool>,
}

#[cfg(target_os = "macos")]
fn split_result_artifacts(
    snapshot: &SplitPlanSnapshot,
    state: &SplitPlanState<'_>,
    sources: &SplitArtifactSources,
    retain_published_output: bool,
) -> SplitArtifactInventory {
    let mut inventory = SplitArtifactInventory::default();
    if sources.is_empty() {
        return inventory;
    }
    let Some(parent_path) = snapshot.bundle_directory.parent() else {
        inventory.retained = true;
        return inventory;
    };
    let lock = acquire_destination_lock(
        &state.destination_parent,
        state.destination_parent_identity,
        parent_path,
        &state.destination_name,
    )
    .ok();
    let destination_parent_matches = lock.as_ref().is_some_and(|lock| {
        lock.validate(
            &state.destination_parent,
            state.destination_parent_identity,
            parent_path,
        )
        .is_ok()
    });
    if !destination_parent_matches {
        inventory.retained = true;
    }

    let target_name = encode_os_name(&state.destination_name);
    let mut next_artifact_id = 1_u64;
    let mut observed_staging_names = HashSet::new();
    let mut journal_transactions = HashSet::new();
    let mut ambiguous_journal = false;
    for journal_name in &sources.journal_names {
        if !entry_exists_at(&state.destination_parent, journal_name).unwrap_or(false) {
            continue;
        }
        match open_journal_writer(&state.destination_parent, journal_name) {
            Ok(writer) if writer.record.destination_name_hex == target_name => {
                let record = writer.record.clone();
                observed_staging_names.insert(record.staging_name_hex.clone());
                if !journal_transactions.insert(record.transaction_id.clone()) {
                    continue;
                }
                next_artifact_id = append_split_journal_inventory(
                    snapshot,
                    state,
                    &record,
                    retain_published_output,
                    next_artifact_id,
                    &mut inventory,
                );
            }
            Ok(_) => {}
            Err(_) => {
                ambiguous_journal = true;
                let path = parent_path.join(journal_name);
                append_uncertain_split_entry(
                    &mut inventory,
                    SplitArtifactLocation {
                        artifact_id: next_artifact_id,
                        parent_artifact_id: None,
                        relative_name: journal_name,
                        path: &path,
                        parent_identity: Some(state.destination_parent_identity),
                        parent_identity_matches: None,
                    },
                    &state.destination_parent,
                    true,
                );
                next_artifact_id = next_artifact_id.saturating_add(1);
            }
        }
    }

    for staging_name in &sources.staging_names {
        let encoded = encode_os_name(staging_name);
        if observed_staging_names.contains(&encoded) {
            continue;
        }
        let Ok(Some(_directory)) =
            open_optional_directory_at(&state.destination_parent, staging_name)
        else {
            continue;
        };
        append_uncertain_split_entry(
            &mut inventory,
            SplitArtifactLocation {
                artifact_id: next_artifact_id,
                parent_artifact_id: None,
                relative_name: staging_name,
                path: &parent_path.join(staging_name),
                parent_identity: Some(state.destination_parent_identity),
                parent_identity_matches: None,
            },
            &state.destination_parent,
            true,
        );
        next_artifact_id = next_artifact_id.saturating_add(1);
    }

    let destination_exists =
        match entry_exists_at(&state.destination_parent, &state.destination_name) {
            Ok(exists) => exists,
            Err(_) => ambiguous_journal,
        };
    if ambiguous_journal
        && destination_exists
        && !inventory
            .artifacts
            .iter()
            .any(|artifact| artifact.path() == snapshot.bundle_directory)
    {
        append_uncertain_split_entry(
            &mut inventory,
            SplitArtifactLocation {
                artifact_id: next_artifact_id,
                parent_artifact_id: None,
                relative_name: &state.destination_name,
                path: &snapshot.bundle_directory,
                parent_identity: Some(state.destination_parent_identity),
                parent_identity_matches: destination_parent_matches.then_some(true),
            },
            &state.destination_parent,
            true,
        );
    }
    inventory
}

#[cfg(target_os = "macos")]
fn append_split_journal_inventory(
    snapshot: &SplitPlanSnapshot,
    state: &SplitPlanState<'_>,
    record: &JournalRecord,
    retain_published_output: bool,
    first_artifact_id: u64,
    inventory: &mut SplitArtifactInventory,
) -> u64 {
    let mut next_artifact_id = first_artifact_id
        .saturating_add(record.artifacts.len() as u64)
        .max(first_artifact_id.saturating_add(1));
    let root = locate_split_artifact_root(snapshot, state, record);
    let published = root.as_ref().is_some_and(|root| root.published)
        || root.is_none() && journal_phase_is_published(record.phase);
    let Some(staging_name) = decode_os_name(&record.staging_name_hex) else {
        inventory.retained = true;
        return next_artifact_id;
    };
    let Some(parent_path) = snapshot.bundle_directory.parent() else {
        inventory.retained = true;
        return next_artifact_id;
    };
    let planned_root = if published {
        snapshot.bundle_directory.clone()
    } else {
        parent_path.join(&staging_name)
    };
    let cleanup_complete = record.phase == JournalPhase::CleanupComplete;
    let retained_directory_exists = !cleanup_complete
        && (!published || retain_published_output)
        && record.artifacts.iter().any(|artifact| {
            artifact.kind == ArtifactKind::Directory
                && matches!(
                    &artifact.state,
                    ArtifactState::Created(_) | ArtifactState::Verified(_)
                )
        });
    if root.is_none() && retained_directory_exists {
        inventory.retained_storage_unknown = true;
    }
    let mut artifact_ids = HashMap::new();
    for (index, artifact) in record.artifacts.iter().enumerate() {
        let id = first_artifact_id.saturating_add(index as u64);
        artifact_ids.insert(artifact.relative_path_hex.clone(), id);
    }

    for (index, artifact) in record.artifacts.iter().enumerate() {
        let artifact_id = first_artifact_id.saturating_add(index as u64);
        let Some(path) = split_journal_artifact_path(&planned_root, artifact) else {
            inventory.retained = true;
            continue;
        };
        let Some(relative_name) = artifact
            .relative_path_hex
            .last()
            .and_then(|name| decode_os_name(name))
        else {
            inventory.retained = true;
            continue;
        };
        let relative_name = if index == 0 && published {
            decode_os_name(&record.destination_name_hex).unwrap_or(relative_name)
        } else {
            relative_name
        };
        let parent_artifact_id = if artifact.relative_path_hex.len() > 1 {
            artifact_ids
                .get(&artifact.relative_path_hex[..artifact.relative_path_hex.len() - 1])
                .copied()
        } else {
            None
        };
        let expected_parent = parse_identity(&artifact.parent_identity);
        let planned_parent_path = path.parent();
        let planned_parent = planned_parent_path.and_then(|path| open_directory(path).ok());
        let planned_parent_identity = planned_parent.as_ref().and_then(handle_identity);
        let parent_identity_matches = expected_parent
            .zip(planned_parent_identity)
            .map(|(expected, observed)| expected == observed);
        let planned_observation = match planned_parent.as_ref() {
            Some(parent) => observe_split_entry(parent, &relative_name).ok().flatten(),
            None => None,
        };
        let path_is_authoritative = parent_identity_matches == Some(true)
            && planned_parent_path
                .and_then(|path| open_directory(path).ok())
                .as_ref()
                .and_then(handle_identity)
                == expected_parent;
        let actual_location = root
            .as_ref()
            .and_then(|root| locate_split_journal_artifact(root, record, index, artifact));
        let actual_observation = actual_location
            .as_ref()
            .and_then(|(parent, name, _)| observe_split_entry(parent, name).ok().flatten());
        let recorded_evidence = match &artifact.state {
            ArtifactState::Created(evidence) | ArtifactState::Verified(evidence) => Some(evidence),
            ArtifactState::Planned => None,
        };
        let recorded_identity =
            recorded_evidence.and_then(|evidence| parse_identity(&evidence.identity));
        let owned_observation = actual_observation
            .filter(|observed| Some(observed.identity) == recorded_identity)
            .or_else(|| {
                planned_observation.filter(|observed| Some(observed.identity) == recorded_identity)
            });
        let role = if published {
            OperationArtifactRole::PublishedDestination
        } else if artifact.kind == ArtifactKind::Directory {
            OperationArtifactRole::PrivateStagingDirectory
        } else {
            OperationArtifactRole::StagedOutput
        };
        let retained = !cleanup_complete
            && recorded_evidence.is_some()
            && (!published || retain_published_output);
        inventory.retained |= retained;
        let path_identity_matches = if path_is_authoritative {
            recorded_identity
                .zip(planned_observation.map(|observed| observed.identity))
                .map(|(expected, observed)| expected == observed)
        } else {
            None
        };
        let current_path_identity = path_is_authoritative
            .then(|| planned_observation.map(|observed| observed.identity))
            .flatten();
        let current_path_length = path_is_authoritative
            .then(|| planned_observation.and_then(|observed| observed.length))
            .flatten();
        let current_content = owned_observation;
        let recorded_length = recorded_evidence.and_then(|evidence| evidence.length);
        let recorded_sha256 = recorded_evidence
            .and_then(|evidence| evidence.sha256.as_deref())
            .and_then(|digest| Sha256Digest::parse_hex(digest).ok());
        inventory
            .artifacts
            .push(OperationArtifact::from_split_inventory(
                SplitArtifactInventoryRecord {
                    artifact_id,
                    parent_artifact_id,
                    relative_name: PathBuf::from(&relative_name),
                    parent_identity: expected_parent,
                    parent_identity_matches,
                    role,
                    path: path.clone(),
                    identity: recorded_identity,
                    length: current_content.and_then(|observed| observed.length),
                    sha256: current_content.and_then(|observed| observed.sha256),
                    recorded_length,
                    recorded_sha256,
                    path_identity_matches,
                    path_identity: current_path_identity,
                    path_length: current_path_length,
                    retained,
                },
            ));

        if let Some(observed) = planned_observation.filter(|observed| {
            path_is_authoritative && Some(observed.identity) != recorded_identity
        }) {
            append_uncertain_split_observation(
                inventory,
                SplitArtifactLocation {
                    artifact_id: next_artifact_id,
                    parent_artifact_id,
                    relative_name: &relative_name,
                    path: &path,
                    parent_identity: expected_parent,
                    parent_identity_matches,
                },
                Some(observed),
            );
            next_artifact_id = next_artifact_id.saturating_add(1);
        }
        if let Some((actual_parent, actual_name, actual_path)) = actual_location
            && actual_path != path
            && let Some(observed) = observe_split_entry(&actual_parent, &actual_name)
                .ok()
                .flatten()
        {
            let current_parent_identity = handle_identity(&actual_parent);
            let alias_matches = recorded_identity.map(|identity| identity == observed.identity);
            if alias_matches == Some(true) {
                append_split_alias_observation(
                    inventory,
                    SplitArtifactLocation {
                        artifact_id: next_artifact_id,
                        parent_artifact_id,
                        relative_name: &actual_name,
                        path: &actual_path,
                        parent_identity: parse_identity(&artifact.parent_identity),
                        parent_identity_matches: parse_identity(&artifact.parent_identity)
                            .zip(current_parent_identity)
                            .map(|(expected, observed)| expected == observed),
                    },
                    Some(observed),
                    recorded_evidence,
                    artifact.kind == ArtifactKind::RegularFile,
                );
            } else {
                append_uncertain_split_observation(
                    inventory,
                    SplitArtifactLocation {
                        artifact_id: next_artifact_id,
                        parent_artifact_id,
                        relative_name: &actual_name,
                        path: &actual_path,
                        parent_identity: current_parent_identity,
                        parent_identity_matches: Some(true),
                    },
                    Some(observed),
                );
            }
            next_artifact_id = next_artifact_id.saturating_add(1);
        }
    }
    if let Some(root) = root.as_ref() {
        next_artifact_id = append_unjournaled_split_children(
            record,
            root,
            first_artifact_id,
            next_artifact_id,
            retain_published_output,
            inventory,
        );
    }
    next_artifact_id =
        next_artifact_id.max(first_artifact_id.saturating_add(record.artifacts.len() as u64));
    next_artifact_id
}

#[cfg(target_os = "macos")]
fn append_unjournaled_split_children(
    record: &JournalRecord,
    root: &SplitArtifactRoot,
    first_artifact_id: u64,
    mut next_artifact_id: u64,
    retain_published_output: bool,
    inventory: &mut SplitArtifactInventory,
) -> u64 {
    let cleanup_complete = record.phase == JournalPhase::CleanupComplete;
    for directory_artifact in record
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::Directory)
    {
        let directory_retained = !cleanup_complete
            && (!root.published || retain_published_output)
            && matches!(
                &directory_artifact.state,
                ArtifactState::Created(_) | ArtifactState::Verified(_)
            );
        let Some((directory, directory_path)) =
            open_split_inventory_directory(root, record, directory_artifact)
        else {
            inventory.retained_storage_unknown |= directory_retained;
            continue;
        };
        let Some(parent_identity) = recorded_artifact_identity(directory_artifact) else {
            inventory.retained = true;
            inventory.retained_storage_unknown |= directory_retained;
            continue;
        };
        let parent_identity_matches =
            handle_identity(&directory).map(|identity| identity == parent_identity);
        let mut allowed_names = HashSet::new();
        for (index, child) in record.artifacts.iter().enumerate().filter(|(_, child)| {
            child.relative_path_hex.len() == directory_artifact.relative_path_hex.len() + 1
                && child
                    .relative_path_hex
                    .starts_with(&directory_artifact.relative_path_hex)
        }) {
            if let Some(name) = child
                .relative_path_hex
                .last()
                .and_then(|encoded| decode_os_name(encoded))
            {
                allowed_names.insert(name.as_bytes().to_vec());
            }
            allowed_names.insert(cleanup_quarantine_name(record, index).as_bytes().to_vec());
        }
        let Ok(names_before) = directory_child_names(&directory) else {
            inventory.retained = true;
            inventory.retained_storage_unknown |= directory_retained;
            continue;
        };
        let mut names = names_before.iter().cloned().collect::<Vec<_>>();
        names.sort();
        for name_bytes in names {
            if allowed_names.contains(&name_bytes) {
                continue;
            }
            let name = OsString::from_vec(name_bytes);
            let observation = observe_split_entry(&directory, &name).ok().flatten();
            let path = directory_path.join(&name);
            let parent_artifact_id = record
                .artifacts
                .iter()
                .position(|candidate| {
                    candidate.relative_path_hex == directory_artifact.relative_path_hex
                })
                .map(|index| first_artifact_id.saturating_add(index as u64));
            append_uncertain_split_observation(
                inventory,
                SplitArtifactLocation {
                    artifact_id: next_artifact_id,
                    parent_artifact_id,
                    relative_name: &name,
                    path: &path,
                    parent_identity: Some(parent_identity),
                    parent_identity_matches,
                },
                observation,
            );
            next_artifact_id = next_artifact_id.saturating_add(1);
        }
        if directory_child_names(&directory).ok().as_ref() != Some(&names_before) {
            inventory.retained = true;
            inventory.retained_storage_unknown |= directory_retained;
        }
    }
    next_artifact_id
}

#[cfg(target_os = "macos")]
fn open_split_inventory_directory(
    root: &SplitArtifactRoot,
    record: &JournalRecord,
    artifact: &JournalArtifact,
) -> Option<(File, PathBuf)> {
    let root_path = vec![record.staging_name_hex.clone()];
    let root_artifact = record
        .artifacts
        .iter()
        .find(|candidate| candidate.relative_path_hex == root_path)?;
    let mut directory = root.file.try_clone().ok()?;
    if !cleanup_directory_matches(&directory, root_artifact).ok()? {
        return None;
    }
    let mut directory_path = root.path.clone();
    let mut prefix = root_path;
    for encoded_name in artifact.relative_path_hex.iter().skip(1) {
        prefix.push(encoded_name.clone());
        let nested_artifact = record
            .artifacts
            .iter()
            .find(|candidate| candidate.relative_path_hex == prefix)?;
        let index = record
            .artifacts
            .iter()
            .position(|candidate| candidate.relative_path_hex == prefix)?;
        let name = decode_os_name(encoded_name)?;
        let quarantine_name = cleanup_quarantine_name(record, index);
        let (opened_name, opened) = match open_directory_at(&directory, &name) {
            Ok(opened) if cleanup_directory_matches(&opened, nested_artifact).ok()? => {
                (name, opened)
            }
            _ => {
                let opened = open_directory_at(&directory, &quarantine_name).ok()?;
                if !cleanup_directory_matches(&opened, nested_artifact).ok()? {
                    return None;
                }
                (quarantine_name, opened)
            }
        };
        directory_path.push(opened_name);
        directory = opened;
    }
    Some((directory, directory_path))
}

#[cfg(target_os = "macos")]
fn recorded_artifact_identity(artifact: &JournalArtifact) -> Option<FileIdentity> {
    match &artifact.state {
        ArtifactState::Created(evidence) | ArtifactState::Verified(evidence) => {
            parse_identity(&evidence.identity)
        }
        ArtifactState::Planned => None,
    }
}

#[cfg(target_os = "macos")]
fn locate_split_artifact_root(
    snapshot: &SplitPlanSnapshot,
    state: &SplitPlanState<'_>,
    record: &JournalRecord,
) -> Option<SplitArtifactRoot> {
    let root_path_hex = vec![record.staging_name_hex.clone()];
    let root_artifact = record
        .artifacts
        .iter()
        .find(|artifact| artifact.relative_path_hex == root_path_hex);
    let expected_identity = record
        .staging_identity
        .as_deref()
        .and_then(parse_identity)
        .or_else(|| {
            root_artifact.and_then(|artifact| match &artifact.state {
                ArtifactState::Created(evidence) | ArtifactState::Verified(evidence) => {
                    parse_identity(&evidence.identity)
                }
                ArtifactState::Planned => None,
            })
        });
    if let Some(path) = recovery_path_for_recorded_bundle(snapshot, record)
        && let Ok(file) = open_directory(&path)
        && expected_identity == handle_identity(&file)
    {
        return Some(SplitArtifactRoot {
            published: path == snapshot.bundle_directory,
            file,
            path,
        });
    }

    let staging_name = decode_os_name(&record.staging_name_hex)?;
    let mut candidates = vec![
        (
            staging_name.clone(),
            snapshot.bundle_directory.parent()?.join(&staging_name),
        ),
        (
            decode_os_name(&record.destination_name_hex)?,
            snapshot.bundle_directory.clone(),
        ),
    ];
    if journal_phase_is_published(record.phase) {
        candidates.reverse();
    }
    for (name, path) in candidates {
        let Ok(directory) = open_directory_at(&state.destination_parent, &name) else {
            continue;
        };
        let identity = handle_identity(&directory);
        if expected_identity.is_some_and(|expected| Some(expected) != identity) {
            continue;
        }
        return Some(SplitArtifactRoot {
            published: path == snapshot.bundle_directory && expected_identity == identity,
            file: directory,
            path,
        });
    }
    None
}

#[cfg(target_os = "macos")]
fn locate_split_journal_artifact(
    root: &SplitArtifactRoot,
    record: &JournalRecord,
    index: usize,
    artifact: &JournalArtifact,
) -> Option<(File, OsString, PathBuf)> {
    if artifact.relative_path_hex.len() == 1 {
        let parent_path = root.path.parent()?;
        let parent = open_directory(parent_path).ok()?;
        let name = root.path.file_name()?.to_os_string();
        return Some((parent, name, root.path.clone()));
    }
    let parent = open_artifact_parent_from_root(&root.file, record, artifact).ok()??;
    let original_name = artifact
        .relative_path_hex
        .last()
        .and_then(|name| decode_os_name(name))?;
    let original_present = entry_exists_at(&parent, &original_name).ok()?;
    let quarantine_name = cleanup_quarantine_name(record, index);
    let (actual_name, suffix) = if original_present {
        (original_name, None)
    } else if entry_exists_at(&parent, &quarantine_name).ok()? {
        (quarantine_name.clone(), Some(quarantine_name))
    } else {
        return None;
    };
    let mut parent_path = root.path.clone();
    for encoded in &artifact.relative_path_hex[1..artifact.relative_path_hex.len() - 1] {
        parent_path.push(decode_os_name(encoded)?);
    }
    let actual_path = parent_path.join(suffix.unwrap_or_else(|| actual_name.clone()));
    Some((parent, actual_name, actual_path))
}

#[cfg(target_os = "macos")]
fn split_journal_artifact_path(root: &Path, artifact: &JournalArtifact) -> Option<PathBuf> {
    if artifact.relative_path_hex.is_empty() {
        return None;
    }
    let mut path = root.to_path_buf();
    for encoded in artifact.relative_path_hex.iter().skip(1) {
        path.push(decode_os_name(encoded)?);
    }
    Some(path)
}

#[cfg(target_os = "macos")]
fn journal_phase_is_published(phase: JournalPhase) -> bool {
    matches!(
        phase,
        JournalPhase::Published
            | JournalPhase::ReceiptCommitStarted
            | JournalPhase::ReceiptCommitted
            | JournalPhase::Completed
    )
}

#[cfg(target_os = "macos")]
fn observe_split_entry(
    parent: &File,
    name: &OsStr,
) -> Result<Option<SplitObservedEntry>, OperationFailureCode> {
    let name_c = c_name(name).map_err(|_| OperationFailureCode::UnsafePath)?;
    // SAFETY: the parent descriptor is open and name is one path component.
    let mut before = unsafe { std::mem::zeroed::<libc::stat>() };
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name_c.as_ptr(),
            &mut before,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let identity = FileIdentity::from_parts(before.st_dev as u64, before.st_ino as u64);
    let mode = before.st_mode & 0o7777;
    let file_type = before.st_mode & libc::S_IFMT;
    let (_kind, length, sha256) = if file_type == libc::S_IFDIR {
        let directory = open_directory_at(parent, name)
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        if handle_identity(&directory) != Some(identity) {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        (Some(ArtifactKind::Directory), None, None)
    } else if file_type == libc::S_IFREG {
        let file =
            open_file_at(parent, name).map_err(|_| OperationFailureCode::PublicationUncertain)?;
        let metadata = file
            .metadata()
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        if handle_identity(&file) != Some(identity) || !metadata.file_type().is_file() {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        let (length, sha256) = hash_open_file(&file)?;
        let after = file
            .metadata()
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        if handle_identity(&file) != Some(identity)
            || after.len() != length
            || after.mode() & 0o7777 != mode as u32
            || after.nlink() != metadata.nlink()
        {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        (Some(ArtifactKind::RegularFile), Some(length), Some(sha256))
    } else {
        (None, None, None)
    };
    let mut after = unsafe { std::mem::zeroed::<libc::stat>() };
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name_c.as_ptr(),
            &mut after,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0
        || FileIdentity::from_parts(after.st_dev as u64, after.st_ino as u64) != identity
        || after.st_mode & 0o7777 != mode
        || after.st_mode & libc::S_IFMT != file_type
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    Ok(Some(SplitObservedEntry {
        identity,
        length,
        sha256,
    }))
}

#[cfg(target_os = "macos")]
fn append_uncertain_split_entry(
    inventory: &mut SplitArtifactInventory,
    location: SplitArtifactLocation<'_>,
    parent: &File,
    retained: bool,
) {
    let observation = observe_split_entry(parent, location.relative_name)
        .ok()
        .flatten();
    append_uncertain_split_observation(inventory, location, observation);
    inventory.retained |= retained;
}

#[cfg(target_os = "macos")]
fn append_uncertain_split_observation(
    inventory: &mut SplitArtifactInventory,
    location: SplitArtifactLocation<'_>,
    observation: Option<SplitObservedEntry>,
) {
    let path_identity_matches = None;
    inventory
        .artifacts
        .push(OperationArtifact::from_split_inventory(
            SplitArtifactInventoryRecord {
                artifact_id: location.artifact_id,
                parent_artifact_id: location.parent_artifact_id,
                relative_name: PathBuf::from(location.relative_name),
                parent_identity: location.parent_identity,
                parent_identity_matches: location.parent_identity_matches,
                role: OperationArtifactRole::UncertainEntry,
                path: location.path.to_path_buf(),
                identity: observation.map(|observed| observed.identity),
                length: observation.and_then(|observed| observed.length),
                sha256: observation.and_then(|observed| observed.sha256),
                recorded_length: None,
                recorded_sha256: None,
                path_identity_matches,
                path_identity: observation.map(|observed| observed.identity),
                path_length: observation.and_then(|observed| observed.length),
                retained: true,
            },
        ));
    inventory.retained = true;
}

#[cfg(target_os = "macos")]
fn append_split_alias_observation(
    inventory: &mut SplitArtifactInventory,
    location: SplitArtifactLocation<'_>,
    observation: Option<SplitObservedEntry>,
    recorded_evidence: Option<&ArtifactEvidence>,
    retained: bool,
) {
    inventory
        .artifacts
        .push(OperationArtifact::from_split_inventory(
            SplitArtifactInventoryRecord {
                artifact_id: location.artifact_id,
                parent_artifact_id: location.parent_artifact_id,
                relative_name: PathBuf::from(location.relative_name),
                parent_identity: location.parent_identity,
                parent_identity_matches: location.parent_identity_matches,
                role: OperationArtifactRole::UncertainEntry,
                path: location.path.to_path_buf(),
                identity: observation.map(|observed| observed.identity),
                length: observation.and_then(|observed| observed.length),
                sha256: observation.and_then(|observed| observed.sha256),
                recorded_length: recorded_evidence.and_then(|evidence| evidence.length),
                recorded_sha256: recorded_evidence
                    .and_then(|evidence| evidence.sha256.as_deref())
                    .and_then(|digest| Sha256Digest::parse_hex(digest).ok()),
                path_identity_matches: Some(true),
                path_identity: observation.map(|observed| observed.identity),
                path_length: observation.and_then(|observed| observed.length),
                retained,
            },
        ));
    inventory.retained |= retained;
}

#[cfg(target_os = "macos")]
fn execute_split_macos(
    mut plan: SplitPlan<'_>,
    session: &OperationSession,
    cancellation: Option<CancellationHandle>,
) -> OperationResult {
    let output = output_paths_from_snapshot(&plan.snapshot, None);
    let mut admission = match session
        .admit_with_cancellation(cancellation.as_ref(), Some(plan.snapshot.source.size()))
    {
        Ok(admission) => admission,
        Err(code) => {
            return OperationResult::split_failure(
                code,
                vec![OperationMilestone::Planned],
                output,
                SplitReceiptCommitState::NotAttempted,
                false,
                false,
                Vec::new(),
            );
        }
    };
    let mut milestones = vec![OperationMilestone::Planned, OperationMilestone::Executing];
    session.record_milestone(OperationMilestone::Executing);
    let mut artifact_sources = SplitArtifactSources::default();
    let transaction_result = run_split_transaction(
        &mut plan,
        session,
        &mut milestones,
        &mut artifact_sources,
        cancellation.as_ref(),
    );
    let retain_published_output = matches!(
        &transaction_result,
        Err(failure)
            if failure.retained
                && failure.receipt_state != SplitReceiptCommitState::ConfirmedCommitted
    );
    let inventory = split_result_artifacts(
        &plan.snapshot,
        &plan.state,
        &artifact_sources,
        retain_published_output,
    );
    let result = match transaction_result {
        Ok(success) => OperationResult::split_success(
            success.outcome,
            milestones,
            output_paths_from_snapshot(&plan.snapshot, success.recovery_path),
            success.receipt_state,
            success.retained || inventory.retained,
            inventory.retained_storage_unknown,
            inventory.artifacts,
        ),
        Err(failure) => OperationResult::split_failure(
            failure.code,
            milestones,
            output_paths_from_snapshot(&plan.snapshot, failure.recovery_path),
            failure.receipt_state,
            failure.retained || inventory.retained,
            inventory.retained_storage_unknown,
            inventory.artifacts,
        ),
    };
    admission.finish(&result);
    result
}

#[cfg(target_os = "macos")]
fn run_split_transaction(
    plan: &mut SplitPlan<'_>,
    session: &OperationSession,
    milestones: &mut Vec<OperationMilestone>,
    artifact_sources: &mut SplitArtifactSources,
    cancellation: Option<&CancellationHandle>,
) -> Result<SplitRunSuccess, SplitRunFailure> {
    let SplitPlan { snapshot, state } = plan;
    let destination_path = snapshot.bundle_directory.as_path();
    let destination_parent_path = destination_path.parent().ok_or(SplitRunFailure {
        code: OperationFailureCode::UnsafePath,
        receipt_state: SplitReceiptCommitState::NotAttempted,
        recovery_path: None,
        retained: false,
    })?;

    check_cancelled(session).map_err(plain_failure)?;
    validate_parent_identity(destination_parent_path, state.destination_parent_identity)
        .map_err(plain_failure)?;
    validate_source(state, Some(session)).map_err(plain_failure)?;
    let destination_before_lock =
        current_directory_identity(&state.destination_parent, &state.destination_name)
            .map_err(plain_failure)?;
    if destination_before_lock != state.destination_identity {
        return Err(plain_failure(OperationFailureCode::DestinationChanged));
    }
    if state.already_up_to_date {
        // This outcome is read-only. It verifies the source and receipt-backed
        // bundle without creating a lock entry or reconciling unrelated journals.
        let current_destination =
            current_directory_identity(&state.destination_parent, &state.destination_name)
                .map_err(plain_failure)?;
        let bundle_is_current = bundle_is_up_to_date(
            snapshot,
            &state.source_name,
            state.trust_store,
            cancellation,
        );
        check_cancelled(session).map_err(plain_failure)?;
        if current_destination != state.destination_identity || !bundle_is_current {
            return Err(plain_failure(OperationFailureCode::DestinationChanged));
        }
        milestones.push(OperationMilestone::Validated);
        session.record_milestone(OperationMilestone::Validated);
        return Ok(SplitRunSuccess {
            outcome: OperationOutcome::AlreadyUpToDate,
            receipt_state: SplitReceiptCommitState::ConfirmedCommitted,
            recovery_path: None,
            retained: false,
        });
    }

    let lock = acquire_destination_lock(
        &state.destination_parent,
        state.destination_parent_identity,
        destination_parent_path,
        &state.destination_name,
    )
    .map_err(plain_failure)?;

    lock.validate(
        &state.destination_parent,
        state.destination_parent_identity,
        destination_parent_path,
    )
    .map_err(plain_failure)?;
    let destination_before_recovery =
        current_directory_identity(&state.destination_parent, &state.destination_name)
            .map_err(plain_failure)?;
    if destination_before_recovery != state.destination_identity {
        return Err(plain_failure(OperationFailureCode::DestinationChanged));
    }
    recover_incomplete_for_destination(snapshot, state, &lock, Some(session), artifact_sources)?;
    validate_source(state, Some(session)).map_err(plain_failure)?;
    let current_destination =
        current_directory_identity(&state.destination_parent, &state.destination_name)
            .map_err(plain_failure)?;
    if current_destination != state.destination_identity {
        return Err(plain_failure(OperationFailureCode::DestinationChanged));
    }

    if state.skipped {
        let bundle_is_qualified =
            bundle_contains_one_qualified_split_set(snapshot, state.trust_store, cancellation);
        check_cancelled(session).map_err(plain_failure)?;
        if !bundle_is_qualified {
            return Err(plain_failure(OperationFailureCode::DestinationConflict));
        }
        let current_destination =
            current_directory_identity(&state.destination_parent, &state.destination_name)
                .map_err(plain_failure)?;
        if current_destination != state.destination_identity {
            return Err(plain_failure(OperationFailureCode::DestinationChanged));
        }
        lock.validate(
            &state.destination_parent,
            state.destination_parent_identity,
            destination_parent_path,
        )
        .map_err(plain_failure)?;
        return Ok(SplitRunSuccess {
            outcome: OperationOutcome::Skipped,
            receipt_state: SplitReceiptCommitState::NotAttempted,
            recovery_path: None,
            retained: false,
        });
    }
    if current_destination.is_some() && snapshot.conflict_policy == ConflictPolicy::Fail {
        return Err(plain_failure(OperationFailureCode::DestinationConflict));
    }
    if current_destination.is_some() && snapshot.conflict_policy == ConflictPolicy::Replace {
        return Err(plain_failure(
            OperationFailureCode::SplitReplacementUnsupported,
        ));
    }

    lock.validate(
        &state.destination_parent,
        state.destination_parent_identity,
        destination_parent_path,
    )
    .map_err(plain_failure)?;

    let names = transaction_names();
    artifact_sources.record_transaction(&names);
    let mut journal = create_journal(
        &state.destination_parent,
        &names.journal,
        JournalRecord::new(
            names.transaction_id,
            snapshot,
            state,
            &names.staging,
            current_destination,
        ),
        #[cfg(test)]
        state.test_failpoint,
    )
    .map_err(|failure| SplitRunFailure {
        code: failure.code,
        receipt_state: SplitReceiptCommitState::NotAttempted,
        recovery_path: None,
        retained: failure.retained,
    })?;
    journal
        .append(JournalPhase::Staging, |_| {})
        .map_err(|code| {
            retained_failure(
                code,
                recovery_path_for_recorded_bundle(snapshot, &journal.record),
            )
        })?;

    let staged = match stage_and_verify(snapshot, state, session, &names.staging, &mut journal) {
        Ok(staged) => staged,
        Err(code) => {
            return Err(cleanup_or_retain_prepublication_failure(
                snapshot,
                state,
                session,
                &journal,
                &names.journal,
                &lock,
                code,
            ));
        }
    };
    milestones.push(OperationMilestone::Validated);
    session.record_milestone(OperationMilestone::Validated);
    if let Err(code) = check_cancelled(session) {
        return Err(cleanup_or_retain_prepublication_failure(
            snapshot,
            state,
            session,
            &journal,
            &names.journal,
            &lock,
            code,
        ));
    }
    if let Err(code) = validate_source(state, Some(session)) {
        return Err(cleanup_or_retain_prepublication_failure(
            snapshot,
            state,
            session,
            &journal,
            &names.journal,
            &lock,
            code,
        ));
    }
    if current_directory_identity(&state.destination_parent, &state.destination_name).map_err(
        |code| {
            retained_failure(
                code,
                recovery_path_for_recorded_bundle(snapshot, &journal.record),
            )
        },
    )? != current_destination
    {
        return Err(cleanup_or_retain_prepublication_failure(
            snapshot,
            state,
            session,
            &journal,
            &names.journal,
            &lock,
            OperationFailureCode::DestinationChanged,
        ));
    }

    journal
        .append(JournalPhase::Publishing, |record| {
            record.staging_identity = Some(identity_string(staged.identity));
            record.manifest_sha256 = Some(staged.manifest_sha256.to_hex());
        })
        .map_err(|code| {
            retained_failure(
                code,
                recovery_path_for_recorded_bundle(snapshot, &journal.record),
            )
        })?;
    // The injected error exercises the publication-failure path at the same
    // point where the platform rename operation would be attempted.
    #[cfg(test)]
    if matches!(
        state.test_failpoint,
        Some(
            SplitTestFailpoint::FailureAtPromotion
                | SplitTestFailpoint::SimulatedInterruptionAfterCleanupQuarantine
                | SplitTestFailpoint::SimulatedInterruptionAfterCleanupArtifactUnlink
        )
    ) {
        return Err(cleanup_or_retain_prepublication_failure(
            snapshot,
            state,
            session,
            &journal,
            &names.journal,
            &lock,
            OperationFailureCode::PublicationFailed,
        ));
    }
    let publication_context = DestinationPublication {
        parent: &state.destination_parent,
        destination_name: &state.destination_name,
        lock: &lock,
        parent_identity: state.destination_parent_identity,
        parent_path: destination_parent_path,
        #[cfg(test)]
        test_failpoint: state.test_failpoint,
    };
    let publication = publish_bundle(
        &publication_context,
        &names.staging,
        staged.identity,
        current_destination,
    );
    if let Err(code) = publication {
        let mut failure = cleanup_or_retain_prepublication_failure(
            snapshot,
            state,
            session,
            &journal,
            &names.journal,
            &lock,
            code,
        );
        if failure.retained {
            failure.recovery_path = recovery_path_after_failed_publication(
                &state.destination_parent,
                &state.destination_name,
                &names.staging,
                &lock,
                state.destination_parent_identity,
                destination_parent_path,
                staged.identity,
            );
        }
        return Err(failure);
    }
    #[cfg(test)]
    if state.test_failpoint == Some(SplitTestFailpoint::SimulatedTornPublishedJournalAfterPromotion)
    {
        journal
            .file
            .write_all(b"{\"torn\":")
            .and_then(|()| journal.file.sync_all())
            .and_then(|()| journal.parent.sync_all())
            .map_err(|_| {
                retained_failure(
                    OperationFailureCode::WriteFailed,
                    recovery_path_after_failed_publication(
                        &state.destination_parent,
                        &state.destination_name,
                        &names.staging,
                        &lock,
                        state.destination_parent_identity,
                        destination_parent_path,
                        staged.identity,
                    ),
                )
            })?;
        return Err(SplitRunFailure {
            code: OperationFailureCode::PublicationUncertain,
            receipt_state: SplitReceiptCommitState::NotAttempted,
            recovery_path: recovery_path_after_failed_publication(
                &state.destination_parent,
                &state.destination_name,
                &names.staging,
                &lock,
                state.destination_parent_identity,
                destination_parent_path,
                staged.identity,
            ),
            retained: true,
        });
    }
    if let Err(code) = journal.append(JournalPhase::Published, |_| {}) {
        return rollback_published(snapshot, state, &mut journal, &lock, Some(session), code);
    }
    milestones.push(OperationMilestone::Published);
    session.record_milestone(OperationMilestone::Published);

    #[cfg(test)]
    match state.test_failpoint {
        Some(SplitTestFailpoint::SimulatedInterruptionAfterPublication) => {
            return Err(SplitRunFailure {
                code: OperationFailureCode::PublicationUncertain,
                receipt_state: SplitReceiptCommitState::NotAttempted,
                recovery_path: recovery_path_after_failed_publication(
                    &state.destination_parent,
                    &state.destination_name,
                    &names.staging,
                    &lock,
                    state.destination_parent_identity,
                    destination_parent_path,
                    staged.identity,
                ),
                retained: true,
            });
        }
        Some(SplitTestFailpoint::SimulatedUnrelatedEntryAfterPublication) => {
            let unrelated = snapshot.bundle_directory.join("unrelated-split-entry");
            if fs::write(&unrelated, b"unrelated user data").is_err() {
                return Err(plain_failure(OperationFailureCode::WriteFailed));
            }
            return Err(SplitRunFailure {
                code: OperationFailureCode::PublicationUncertain,
                receipt_state: SplitReceiptCommitState::NotAttempted,
                recovery_path: Some(snapshot.bundle_directory.clone()),
                retained: true,
            });
        }
        Some(SplitTestFailpoint::SimulatedModifiedSegmentAfterPublication) => {
            let segment = snapshot.canonical_directory.join("00");
            if fs::write(&segment, b"XXXX").is_err() {
                return Err(plain_failure(OperationFailureCode::WriteFailed));
            }
            return Err(SplitRunFailure {
                code: OperationFailureCode::PublicationUncertain,
                receipt_state: SplitReceiptCommitState::NotAttempted,
                recovery_path: Some(snapshot.bundle_directory.clone()),
                retained: true,
            });
        }
        Some(SplitTestFailpoint::SimulatedSubstitutedSegmentAfterPublication) => {
            let segment = snapshot.canonical_directory.join("00");
            let original = match OpenOptions::new().read(true).open(&segment) {
                Ok(original) => original,
                Err(_) => return Err(plain_failure(OperationFailureCode::WriteFailed)),
            };
            let substitute = snapshot.bundle_directory.with_extension("split-substitute");
            if fs::write(&substitute, b"WXYZ").is_err()
                || fs::remove_file(&segment).is_err()
                || fs::rename(&substitute, &segment).is_err()
            {
                return Err(plain_failure(OperationFailureCode::WriteFailed));
            }
            drop(original);
            return Err(SplitRunFailure {
                code: OperationFailureCode::PublicationUncertain,
                receipt_state: SplitReceiptCommitState::NotAttempted,
                recovery_path: Some(snapshot.bundle_directory.clone()),
                retained: true,
            });
        }
        Some(SplitTestFailpoint::SimulatedAliasedSegmentAfterPublication) => {
            let segment = snapshot.canonical_directory.join("00");
            let first_alias = snapshot.bundle_directory.join("retained-alias-a");
            let second_alias = snapshot.bundle_directory.join("retained-alias-b");
            let substitute = snapshot.bundle_directory.with_extension("split-substitute");
            if fs::hard_link(&segment, &first_alias).is_err()
                || fs::hard_link(&segment, &second_alias).is_err()
                || fs::write(&substitute, b"WXYZ").is_err()
                || fs::remove_file(&segment).is_err()
                || fs::rename(&substitute, &segment).is_err()
            {
                return Err(plain_failure(OperationFailureCode::WriteFailed));
            }
            return Err(SplitRunFailure {
                code: OperationFailureCode::PublicationUncertain,
                receipt_state: SplitReceiptCommitState::NotAttempted,
                recovery_path: Some(snapshot.bundle_directory.clone()),
                retained: true,
            });
        }
        Some(
            SplitTestFailpoint::FailureBeforeReceiptCommit
            | SplitTestFailpoint::FailureBeforeReceiptCommitWithCancelDuringCleanupHash
            | SplitTestFailpoint::CancelBeforeArtifactUnlink,
        ) => {
            return rollback_published(
                snapshot,
                state,
                &mut journal,
                &lock,
                Some(session),
                OperationFailureCode::WriteFailed,
            );
        }
        Some(SplitTestFailpoint::SubstituteStagingBeforeRollbackIdentityCheck) => {
            return rollback_published(
                snapshot,
                state,
                &mut journal,
                &lock,
                Some(session),
                OperationFailureCode::WriteFailed,
            );
        }
        Some(
            SplitTestFailpoint::FailureBeforeSegmentSync
            | SplitTestFailpoint::FailureBeforeManifestSync
            | SplitTestFailpoint::FailureAtPromotion
            | SplitTestFailpoint::SubstituteDestinationAfterPromotion
            | SplitTestFailpoint::SubstituteDestinationBetweenCheckAndSwap
            | SplitTestFailpoint::SubstituteStagingBeforeRecoveryIdentityCheck
            | SplitTestFailpoint::SubstituteArtifactBeforeFinalIdentityCheck
            | SplitTestFailpoint::SubstituteArtifactAfterFinalIdentityCheck
            | SplitTestFailpoint::SubstituteArtifactAfterCleanupPreflight
            | SplitTestFailpoint::ModifyAndRestoreArtifactAfterCleanupPreflight
            | SplitTestFailpoint::SubstituteCleanupAliasAfterIdentityCheck
            | SplitTestFailpoint::CancelDuringStagedVerification
            | SplitTestFailpoint::CancelAfterPublicationBeforeReceiptCommit
            | SplitTestFailpoint::SimulatedTornPublishedJournalAfterPromotion
            | SplitTestFailpoint::SimulatedInterruptionAfterCleanupQuarantine
            | SplitTestFailpoint::SimulatedInterruptionAfterCleanupArtifactUnlink
            | SplitTestFailpoint::SimulatedInterruptionAfterReceiptCommitted
            | SplitTestFailpoint::SimulatedAcknowledgementBeforeReceiptJournalUpdate
            | SplitTestFailpoint::SimulatedFailureAfterJournalCreateBeforeIdentityRecord,
        )
        | None => {}
    }

    if let Err(code) = published_bundle_matches(snapshot, state, &staged, Some(session)) {
        return rollback_published(snapshot, state, &mut journal, &lock, Some(session), code);
    }
    if let Err(code) = validate_source(state, Some(session)) {
        return rollback_published(snapshot, state, &mut journal, &lock, Some(session), code);
    }
    #[cfg(test)]
    if state.test_failpoint == Some(SplitTestFailpoint::CancelAfterPublicationBeforeReceiptCommit) {
        assert!(session.cancel());
    }
    if let Err(code) = check_cancelled(session) {
        return rollback_published(snapshot, state, &mut journal, &lock, Some(session), code);
    }

    let receipt_lock =
        match ReceiptStateLock::acquire(&state.destination_parent, &lock, Some(session)) {
            Ok(receipt_lock) => receipt_lock,
            Err(acquire_error) => {
                return Err(SplitRunFailure {
                    code: if acquire_error == OperationFailureCode::Cancelled {
                        OperationFailureCode::Cancelled
                    } else {
                        OperationFailureCode::PublicationUncertain
                    },
                    receipt_state: SplitReceiptCommitState::Uncertain,
                    recovery_path: recovery_path_after_failed_publication(
                        &state.destination_parent,
                        &state.destination_name,
                        &names.staging,
                        &lock,
                        state.destination_parent_identity,
                        destination_parent_path,
                        staged.identity,
                    ),
                    retained: true,
                });
            }
        };
    let is_cancelled = || {
        matches!(session.cancellation_requested(), Ok(true))
            || cancellation.is_some_and(CancellationHandle::is_cancelled)
    };
    let predecessor_lookup = state
        .trust_store
        .lookup_for_recovery(&staged.manifest_sha256, &is_cancelled);
    if let Err(code) = check_cancelled(session) {
        return rollback_published_with_receipt_lock(
            snapshot,
            state,
            &mut journal,
            &lock,
            &receipt_lock,
            Some(session),
            code,
        );
    }
    let predecessor = match predecessor_lookup {
        Ok(receipt) => receipt.map_or(0, |receipt| receipt.predecessor_revision()),
        Err(_) => {
            return rollback_published_with_receipt_lock(
                snapshot,
                state,
                &mut journal,
                &lock,
                &receipt_lock,
                Some(session),
                OperationFailureCode::SplitTrustUnavailable,
            );
        }
    };
    if lock
        .validate(
            &state.destination_parent,
            state.destination_parent_identity,
            destination_parent_path,
        )
        .is_err()
    {
        return Err(SplitRunFailure {
            code: OperationFailureCode::PublicationUncertain,
            receipt_state: SplitReceiptCommitState::NotAttempted,
            recovery_path: recovery_path_after_failed_publication(
                &state.destination_parent,
                &state.destination_name,
                &names.staging,
                &lock,
                state.destination_parent_identity,
                destination_parent_path,
                staged.identity,
            ),
            retained: true,
        });
    }
    if let Err(code) = journal.append(JournalPhase::ReceiptCommitStarted, |_| {}) {
        return rollback_published_with_receipt_lock(
            snapshot,
            state,
            &mut journal,
            &lock,
            &receipt_lock,
            Some(session),
            code,
        );
    }
    match session.begin_promotion() {
        Ok(true) => {}
        Ok(false) => {
            return rollback_published_with_receipt_lock(
                snapshot,
                state,
                &mut journal,
                &lock,
                &receipt_lock,
                Some(session),
                OperationFailureCode::Cancelled,
            );
        }
        Err(code) => {
            return rollback_published_with_receipt_lock(
                snapshot,
                state,
                &mut journal,
                &lock,
                &receipt_lock,
                Some(session),
                code,
            );
        }
    }

    let receipt = SplitTrustReceipt::new(
        staged.manifest_sha256,
        snapshot.source.size(),
        state.source_sha256,
    )
    .with_predecessor_revision(predecessor);
    let mut receipt_state = SplitReceiptCommitState::Uncertain;
    let mut commit_failure = None;
    #[cfg(test)]
    let mut simulated_interruption = false;
    let mut success = None;
    let commit_result = state.trust_store.issue_with_commit_state(
        receipt,
        &mut |issue_result: Result<(), SplitTrustStoreError>,
              receipt_lookup: Result<Option<SplitTrustReceipt>, SplitTrustStoreError>,
              locked_store: Option<&dyn SplitTrustStore>,
              serialized: bool| {
            receipt_state = match receipt_lookup {
                Ok(Some(receipt))
                    if !receipt.is_revoked()
                        && receipt.source_size_bytes() == snapshot.source.size()
                        && *receipt.source_sha256() == state.source_sha256
                        && *receipt.manifest_sha256() == staged.manifest_sha256 =>
                {
                    SplitReceiptCommitState::ConfirmedCommitted
                }
                // A missing active receipt cannot prove that no receipt was
                // committed earlier. Only the writer's exclusive cleanup
                // lease can establish never-committed state.
                Ok(None) | Ok(Some(_)) | Err(_) => SplitReceiptCommitState::Uncertain,
            };

            if !serialized || locked_store.is_none() {
                receipt_state = SplitReceiptCommitState::Uncertain;
                commit_failure = Some(OperationFailureCode::PublicationUncertain);
                return Err(SplitTrustStoreError::Unavailable);
            }
            if receipt_state != SplitReceiptCommitState::ConfirmedCommitted {
                commit_failure = Some(if issue_result.is_err() {
                    OperationFailureCode::SplitTrustUnavailable
                } else {
                    OperationFailureCode::PublicationUncertain
                });
                return Err(SplitTrustStoreError::Unavailable);
            }
            let Some(locked_store) = locked_store else {
                unreachable!("serialized receipt state requires a locked store view");
            };

            milestones.push(OperationMilestone::ReceiptCommitted);
            session.record_milestone(OperationMilestone::ReceiptCommitted);
            #[cfg(test)]
            if state.test_failpoint
                == Some(SplitTestFailpoint::SimulatedAcknowledgementBeforeReceiptJournalUpdate)
                && issue_result.is_ok()
            {
                commit_failure = Some(OperationFailureCode::PublicationUncertain);
                simulated_interruption = true;
                return Err(SplitTrustStoreError::Unavailable);
            }
            let journal_commit_recorded = journal
                .append(JournalPhase::ReceiptCommitted, |_| {})
                .is_ok();
            #[cfg(test)]
            if state.test_failpoint
                == Some(SplitTestFailpoint::SimulatedInterruptionAfterReceiptCommitted)
                && journal_commit_recorded
            {
                commit_failure = Some(OperationFailureCode::PublicationUncertain);
                simulated_interruption = true;
                return Err(SplitTrustStoreError::Unavailable);
            }
            let _ = session.finish_promotion();
            if published_bundle_matches(snapshot, state, &staged, None).is_err()
                || !bundle_is_up_to_date_with_store(
                    snapshot,
                    &state.source_name,
                    locked_store,
                    None,
                )
            {
                commit_failure = Some(OperationFailureCode::PublicationUncertain);
                return Err(SplitTrustStoreError::Unavailable);
            }
            let completed =
                journal_commit_recorded && journal.append(JournalPhase::Completed, |_| {}).is_ok();
            success = Some(SplitRunSuccess {
                outcome: OperationOutcome::SplitCreated,
                receipt_state,
                recovery_path: current_destination
                    .as_ref()
                    .map(|_| path_for_name(destination_parent_path, &names.staging))
                    .or_else(|| {
                        (!completed)
                            .then(|| {
                                recovery_path_after_failed_publication(
                                    &state.destination_parent,
                                    &state.destination_name,
                                    &names.staging,
                                    &lock,
                                    state.destination_parent_identity,
                                    destination_parent_path,
                                    staged.identity,
                                )
                            })
                            .flatten()
                    }),
                retained: !completed,
            });
            Ok(())
        },
    );
    if let Some(success) = success {
        return Ok(success);
    }
    #[cfg(test)]
    if simulated_interruption {
        return Err(SplitRunFailure {
            code: commit_failure.unwrap_or(OperationFailureCode::PublicationUncertain),
            receipt_state,
            recovery_path: recovery_path_after_failed_publication(
                &state.destination_parent,
                &state.destination_name,
                &names.staging,
                &lock,
                state.destination_parent_identity,
                destination_parent_path,
                staged.identity,
            ),
            retained: true,
        });
    }
    let code = commit_failure.unwrap_or_else(|| {
        if commit_result.is_err() {
            OperationFailureCode::SplitTrustUnavailable
        } else {
            OperationFailureCode::PublicationUncertain
        }
    });
    rollback_published_with_receipt_lock(
        snapshot,
        state,
        &mut journal,
        &lock,
        &receipt_lock,
        Some(session),
        code,
    )
}

#[cfg(target_os = "macos")]
fn plain_failure(code: OperationFailureCode) -> SplitRunFailure {
    SplitRunFailure {
        code,
        receipt_state: SplitReceiptCommitState::NotAttempted,
        recovery_path: None,
        retained: false,
    }
}

#[cfg(target_os = "macos")]
fn retained_failure(code: OperationFailureCode, recovery_path: Option<PathBuf>) -> SplitRunFailure {
    SplitRunFailure {
        code,
        receipt_state: SplitReceiptCommitState::NotAttempted,
        recovery_path,
        retained: true,
    }
}

#[cfg(target_os = "macos")]
fn cleanup_or_retain_prepublication_failure(
    snapshot: &SplitPlanSnapshot,
    state: &SplitPlanState<'_>,
    session: &OperationSession,
    journal: &JournalWriter,
    journal_name: &OsStr,
    lock: &DestinationLock,
    code: OperationFailureCode,
) -> SplitRunFailure {
    let receipt_state = SplitReceiptCommitState::NotAttempted;
    let cleanup = if journal.poisoned {
        Err(OperationFailureCode::PublicationUncertain)
    } else {
        cleanup_provisional_artifacts_with_lock(
            snapshot,
            state,
            journal_name,
            receipt_state,
            lock,
            Some(session),
        )
    };
    match cleanup {
        Ok(()) => SplitRunFailure {
            code,
            receipt_state,
            recovery_path: None,
            retained: false,
        },
        Err(cleanup_code) => {
            let reported_code = if matches!(
                cleanup_code,
                OperationFailureCode::Cancelled | OperationFailureCode::SessionUnavailable
            ) {
                cleanup_code
            } else {
                code
            };
            SplitRunFailure {
                code: reported_code,
                receipt_state: SplitReceiptCommitState::Uncertain,
                recovery_path: recovery_path_for_recorded_bundle(snapshot, &journal.record),
                retained: true,
            }
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(Clone)]
struct TransactionNames {
    transaction_id: String,
    staging: OsString,
    journal: OsString,
}

#[cfg(target_os = "macos")]
fn transaction_names() -> TransactionNames {
    use std::time::{SystemTime, UNIX_EPOCH};

    let sequence = NEXT_SPLIT_TRANSACTION.fetch_add(1, Ordering::Relaxed);
    let ticks = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let transaction_id = format!("{}-{ticks:x}-{sequence:x}", std::process::id());
    TransactionNames {
        staging: format!(".nscb-split-{transaction_id}.bundle").into(),
        journal: format!(".nscb-split-{transaction_id}.journal").into(),
        transaction_id,
    }
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum JournalPhase {
    Prepared,
    Staging,
    Verified,
    Publishing,
    Published,
    ReceiptCommitStarted,
    ReceiptCommitted,
    Completed,
    RolledBack,
    Cleaning,
    CleanupComplete,
    Uncertain,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ArtifactKind {
    Directory,
    RegularFile,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ArtifactEvidence {
    identity: String,
    mode: u32,
    link_count: Option<u64>,
    length: Option<u64>,
    sha256: Option<String>,
    change_seconds: Option<i64>,
    change_nanoseconds: Option<i64>,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", content = "evidence", rename_all = "snake_case")]
enum ArtifactState {
    Planned,
    Created(ArtifactEvidence),
    Verified(ArtifactEvidence),
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct JournalArtifact {
    /// Hex-encoded single path components, starting at the transaction root.
    relative_path_hex: Vec<String>,
    parent_identity: String,
    kind: ArtifactKind,
    state: ArtifactState,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Deserialize, Serialize)]
struct JournalRecord {
    version: u8,
    transaction_id: String,
    phase: JournalPhase,
    destination_name_hex: String,
    staging_name_hex: String,
    canonical_name_hex: String,
    source_identity: String,
    source_size: u64,
    source_sha256: String,
    #[serde(default)]
    destination_parent_identity: Option<String>,
    #[serde(default)]
    journal_identity: Option<String>,
    #[serde(default)]
    journal_mode: Option<u32>,
    destination_identity: Option<String>,
    staging_identity: Option<String>,
    manifest_sha256: Option<String>,
    segment_lengths: Vec<u64>,
    #[serde(default)]
    artifacts: Vec<JournalArtifact>,
    #[serde(default)]
    cleanup_name_hex: Option<String>,
    #[serde(default)]
    cleanup_parent_identity: Option<String>,
}

#[cfg(target_os = "macos")]
impl JournalRecord {
    fn new(
        transaction_id: String,
        snapshot: &SplitPlanSnapshot,
        state: &SplitPlanState<'_>,
        staging_name: &OsStr,
        destination_identity: Option<FileIdentity>,
    ) -> Self {
        Self {
            version: 1,
            transaction_id,
            phase: JournalPhase::Prepared,
            destination_name_hex: encode_os_name(&state.destination_name),
            staging_name_hex: encode_os_name(staging_name),
            canonical_name_hex: encode_os_name(&state.source_name),
            source_identity: snapshot.source.identity().to_hex(),
            source_size: snapshot.source.size(),
            source_sha256: state.source_sha256.to_hex(),
            destination_parent_identity: Some(identity_string(state.destination_parent_identity)),
            journal_identity: None,
            journal_mode: None,
            destination_identity: destination_identity.map(identity_string),
            staging_identity: None,
            manifest_sha256: None,
            segment_lengths: snapshot.segment_lengths.clone(),
            artifacts: Vec::new(),
            cleanup_name_hex: None,
            cleanup_parent_identity: None,
        }
    }
}

#[cfg(target_os = "macos")]
struct JournalWriter {
    file: File,
    parent: File,
    record: JournalRecord,
    poisoned: bool,
}

#[cfg(target_os = "macos")]
impl JournalWriter {
    fn append(
        &mut self,
        phase: JournalPhase,
        update: impl FnOnce(&mut JournalRecord),
    ) -> Result<(), OperationFailureCode> {
        if self.poisoned {
            return Err(OperationFailureCode::WriteFailed);
        }
        let mut next = self.record.clone();
        next.phase = phase;
        update(&mut next);
        if !journal_record_is_valid(&next) || !journal_transition_is_valid(&self.record, &next) {
            self.poisoned = true;
            return Err(OperationFailureCode::WriteFailed);
        }
        let mut encoded =
            serde_json::to_vec(&next).map_err(|_| OperationFailureCode::WriteFailed)?;
        encoded.push(b'\n');
        let current_length = match self.file.metadata() {
            Ok(metadata) => metadata.len(),
            Err(_) => {
                self.poisoned = true;
                return Err(OperationFailureCode::WriteFailed);
            }
        };
        let append_length = match u64::try_from(encoded.len()) {
            Ok(length) => length,
            Err(_) => {
                self.poisoned = true;
                return Err(OperationFailureCode::WriteFailed);
            }
        };
        if current_length
            .checked_add(append_length)
            .is_none_or(|length| length > MAX_SPLIT_JOURNAL_BYTES as u64)
        {
            self.poisoned = true;
            return Err(OperationFailureCode::WriteFailed);
        }
        let result = self
            .file
            .write_all(&encoded)
            .and_then(|()| self.file.sync_all())
            .and_then(|()| self.parent.sync_all());
        if result.is_err() {
            self.poisoned = true;
            return Err(OperationFailureCode::WriteFailed);
        }
        self.record = next;
        Ok(())
    }
}

/// Identifies whether a failed journal creation may have left its file behind.
#[cfg(target_os = "macos")]
#[derive(Debug)]
struct JournalCreationFailure {
    code: OperationFailureCode,
    retained: bool,
}

#[cfg(target_os = "macos")]
impl From<OperationFailureCode> for JournalCreationFailure {
    fn from(code: OperationFailureCode) -> Self {
        Self {
            code,
            retained: true,
        }
    }
}

#[cfg(target_os = "macos")]
fn create_journal(
    parent: &File,
    name: &OsStr,
    record: JournalRecord,
    #[cfg(test)] test_failpoint: Option<SplitTestFailpoint>,
) -> Result<JournalWriter, JournalCreationFailure> {
    let mut initializing_name = name.to_os_string();
    initializing_name.push(".initializing");
    let file = create_file_at(parent, &initializing_name).map_err(|_| JournalCreationFailure {
        code: OperationFailureCode::WriteFailed,
        retained: false,
    })?;
    file.sync_all()
        .and_then(|()| parent.sync_all())
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    #[cfg(test)]
    if test_failpoint
        == Some(SplitTestFailpoint::SimulatedFailureAfterJournalCreateBeforeIdentityRecord)
    {
        return Err(OperationFailureCode::UnsupportedCapability.into());
    }
    let metadata = file
        .metadata()
        .map_err(|_| OperationFailureCode::UnsupportedCapability)?;
    let journal_identity =
        handle_identity(&file).ok_or(OperationFailureCode::UnsupportedCapability)?;
    let mut journal = JournalWriter {
        file,
        parent: parent
            .try_clone()
            .map_err(|_| OperationFailureCode::WriteFailed)?,
        record: JournalRecord {
            journal_identity: Some(identity_string(journal_identity)),
            journal_mode: Some(metadata.mode() & 0o7777),
            ..record
        },
        poisoned: false,
    };
    journal.append(JournalPhase::Prepared, |_| {})?;
    rename_exclusive_at(parent, &initializing_name, name)
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    parent
        .sync_all()
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    Ok(journal)
}

#[cfg(target_os = "macos")]
struct StagedBundle {
    identity: FileIdentity,
    manifest_sha256: Sha256Digest,
}

#[cfg(target_os = "macos")]
fn stage_and_verify(
    snapshot: &SplitPlanSnapshot,
    state: &mut SplitPlanState<'_>,
    session: &OperationSession,
    staging_name: &OsStr,
    journal: &mut JournalWriter,
) -> Result<StagedBundle, OperationFailureCode> {
    let staging_path = vec![encode_os_name(staging_name)];
    plan_journal_artifacts(
        journal,
        vec![planned_artifact(
            staging_path.clone(),
            state.destination_parent_identity,
            ArtifactKind::Directory,
        )],
    )?;
    let bundle_directory = create_journaled_directory(
        &state.destination_parent,
        staging_name,
        &staging_path,
        journal,
        true,
    )?;
    let staging_identity =
        handle_identity(&bundle_directory).ok_or(OperationFailureCode::UnsupportedCapability)?;

    let canonical_name = snapshot
        .canonical_directory
        .file_name()
        .ok_or(OperationFailureCode::UnsafePath)?;
    let canonical_path = vec![encode_os_name(staging_name), encode_os_name(canonical_name)];
    plan_journal_artifacts(
        journal,
        vec![planned_artifact(
            canonical_path.clone(),
            staging_identity,
            ArtifactKind::Directory,
        )],
    )?;
    let canonical_directory = create_journaled_directory(
        &bundle_directory,
        canonical_name,
        &canonical_path,
        journal,
        false,
    )?;
    let canonical_identity =
        handle_identity(&canonical_directory).ok_or(OperationFailureCode::UnsupportedCapability)?;

    let manifest_name = snapshot
        .manifest_path
        .file_name()
        .ok_or(OperationFailureCode::UnsafePath)?;
    let mut planned_children = Vec::with_capacity(snapshot.segment_lengths.len() + 1);
    for index in 0..snapshot.segment_lengths.len() {
        planned_children.push(planned_artifact(
            vec![
                encode_os_name(staging_name),
                encode_os_name(canonical_name),
                encode_os_name(OsStr::new(&format!("{index:02}"))),
            ],
            canonical_identity,
            ArtifactKind::RegularFile,
        ));
    }
    planned_children.push(planned_artifact(
        vec![encode_os_name(staging_name), encode_os_name(manifest_name)],
        staging_identity,
        ArtifactKind::RegularFile,
    ));
    plan_journal_artifacts(journal, planned_children)?;

    let mut source_hasher = Sha256::new();
    let mut total_written = 0_u64;
    let mut segments = Vec::with_capacity(snapshot.segment_lengths.len());
    state
        .source_file
        .seek(SeekFrom::Start(0))
        .map_err(|_| OperationFailureCode::SourceChanged)?;

    for (index, &length) in snapshot.segment_lengths.iter().enumerate() {
        check_cancelled(session)?;
        let name = format!("{index:02}");
        let part_path = vec![
            encode_os_name(staging_name),
            encode_os_name(canonical_name),
            encode_os_name(OsStr::new(&name)),
        ];
        let mut part =
            create_journaled_file(&canonical_directory, OsStr::new(&name), &part_path, journal)?;
        let mut remaining = length;
        let mut part_hasher = Sha256::new();
        let mut buffer = [0_u8; SPLIT_IO_BUFFER_SIZE];
        while remaining > 0 {
            check_cancelled(session)?;
            let requested = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| OperationFailureCode::SplitSourceSizeUnsupported)?;
            let count = state
                .source_file
                .read(&mut buffer[..requested])
                .map_err(|_| OperationFailureCode::SourceChanged)?;
            if count == 0 {
                return Err(OperationFailureCode::SourceChanged);
            }
            part.write_all(&buffer[..count])
                .map_err(|_| OperationFailureCode::WriteFailed)?;
            part_hasher.update(&buffer[..count]);
            source_hasher.update(&buffer[..count]);
            remaining -= count as u64;
            total_written = total_written
                .checked_add(count as u64)
                .ok_or(OperationFailureCode::SplitSourceSizeUnsupported)?;
            session.record_progress(total_written);
        }
        #[cfg(test)]
        if state.test_failpoint == Some(SplitTestFailpoint::FailureBeforeSegmentSync) {
            return Err(OperationFailureCode::WriteFailed);
        }
        part.sync_all()
            .map_err(|_| OperationFailureCode::WriteFailed)?;
        let part_digest = Sha256Digest::from_bytes(part_hasher.finalize().into());
        segments.push(SplitManifestSegment {
            index: index as u8,
            size: length,
            sha256: part_digest,
        });
    }
    if state
        .source_file
        .read(&mut [0_u8; 1])
        .map_err(|_| OperationFailureCode::SourceChanged)?
        != 0
        || total_written != snapshot.source.size()
        || Sha256Digest::from_bytes(source_hasher.finalize().into()) != state.source_sha256
    {
        return Err(OperationFailureCode::SourceChanged);
    }
    validate_source(state, Some(session))?;

    let manifest_bytes = encode_manifest(snapshot.source.size(), state.source_sha256, &segments)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    let manifest_path = vec![encode_os_name(staging_name), encode_os_name(manifest_name)];
    let mut manifest_file =
        create_journaled_file(&bundle_directory, manifest_name, &manifest_path, journal)?;
    manifest_file
        .write_all(&manifest_bytes)
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    #[cfg(test)]
    if state.test_failpoint == Some(SplitTestFailpoint::FailureBeforeManifestSync) {
        return Err(OperationFailureCode::WriteFailed);
    }
    manifest_file
        .sync_all()
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    let manifest_sha256 = Sha256Digest::digest(&manifest_bytes);
    let manifest_evidence = verify_regular_file_at(
        &bundle_directory,
        manifest_name,
        &manifest_path,
        manifest_bytes.len() as u64,
        manifest_sha256,
        journal,
    )?;
    record_verified_file(
        &bundle_directory,
        manifest_name,
        &manifest_path,
        &manifest_evidence,
        session,
        journal,
    )?;
    canonical_directory
        .sync_all()
        .and_then(|()| bundle_directory.sync_all())
        .and_then(|()| state.destination_parent.sync_all())
        .map_err(|_| OperationFailureCode::WriteFailed)?;

    let stage_path = snapshot
        .bundle_directory
        .parent()
        .ok_or(OperationFailureCode::UnsafePath)?
        .join(staging_name);
    let verified_segments =
        verify_bundle_parts(snapshot, state, &stage_path, &segments, Some(session))?;
    for (index, evidence) in verified_segments.iter().enumerate() {
        let name = format!("{index:02}");
        record_verified_file(
            &canonical_directory,
            OsStr::new(&name),
            &[
                encode_os_name(staging_name),
                encode_os_name(canonical_name),
                encode_os_name(OsStr::new(&name)),
            ],
            evidence,
            session,
            journal,
        )?;
    }
    journal.append(JournalPhase::Verified, |record| {
        record.staging_identity = Some(identity_string(staging_identity));
        record.manifest_sha256 = Some(manifest_sha256.to_hex());
    })?;
    Ok(StagedBundle {
        identity: staging_identity,
        manifest_sha256,
    })
}

#[cfg(target_os = "macos")]
fn verify_bundle_parts(
    snapshot: &SplitPlanSnapshot,
    state: &SplitPlanState<'_>,
    bundle_path: &Path,
    expected: &[SplitManifestSegment],
    session: Option<&OperationSession>,
) -> Result<Vec<ArtifactEvidence>, OperationFailureCode> {
    use crate::split_reader::{SegmentedFileReader, open_segment_file, revalidate_segment};
    use std::collections::HashSet;

    let canonical_name = snapshot
        .canonical_directory
        .file_name()
        .ok_or(OperationFailureCode::UnsafePath)?;
    let manifest_name = snapshot
        .manifest_path
        .file_name()
        .ok_or(OperationFailureCode::UnsafePath)?;
    if !bundle_has_exact_shape(bundle_path, canonical_name, manifest_name) {
        return Err(OperationFailureCode::ValidationFailed);
    }
    check_cancelled_if_attached(session)?;
    let canonical_path = bundle_path.join(canonical_name);
    let entries =
        fs::read_dir(&canonical_path).map_err(|_| OperationFailureCode::ValidationFailed)?;
    let mut actual_names = Vec::new();
    for entry in entries {
        actual_names.push(
            entry
                .map_err(|_| OperationFailureCode::ValidationFailed)?
                .file_name(),
        );
    }
    if actual_names.len() != expected.len()
        || expected.iter().enumerate().any(|(index, _)| {
            !actual_names
                .iter()
                .any(|name| name == &OsString::from(format!("{index:02}")))
        })
    {
        return Err(OperationFailureCode::ValidationFailed);
    }

    let mut identities = HashSet::new();
    let mut opened = Vec::with_capacity(expected.len());
    let mut evidence = Vec::with_capacity(expected.len());
    for segment in expected {
        check_cancelled_if_attached(session)?;
        let path = canonical_path.join(format!("{:02}", segment.index));
        let mut opened_segment = open_segment_file(&path, segment.size)
            .map_err(|_| OperationFailureCode::ValidationFailed)?;
        let identity = opened_segment
            .identity()
            .ok_or(OperationFailureCode::UnsupportedCapability)?;
        if !identities.insert(identity) {
            return Err(OperationFailureCode::ValidationFailed);
        }
        #[cfg(test)]
        let mut cancel_during_readback = |completed_bytes| {
            if state.test_failpoint == Some(SplitTestFailpoint::CancelDuringStagedVerification)
                && completed_bytes > 0
                && let Some(session) = session
            {
                let _ = session.cancel();
            }
        };
        let (size, digest) = hash_file_with_check(
            opened_segment.file_mut(),
            || check_cancelled_if_attached(session),
            #[cfg(test)]
            Some(&mut cancel_during_readback),
        )
        .map_err(|error| match error {
            HashFileFailure::Io => OperationFailureCode::ValidationFailed,
            HashFileFailure::Operation(code) => code,
        })?;
        if size != segment.size || digest != segment.sha256 {
            return Err(OperationFailureCode::ValidationFailed);
        }
        opened_segment
            .seek(SeekFrom::Start(0))
            .map_err(|_| OperationFailureCode::ValidationFailed)?;
        revalidate_segment(&opened_segment).map_err(|_| OperationFailureCode::ValidationFailed)?;
        let segment_evidence = regular_file_evidence(opened_segment.file_mut(), size, digest)?;
        revalidate_segment(&opened_segment).map_err(|_| OperationFailureCode::ValidationFailed)?;
        evidence.push(segment_evidence);
        opened.push(opened_segment);
    }

    let mut reader = SegmentedFileReader::from_segments(opened)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    let mut whole_hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; SPLIT_IO_BUFFER_SIZE];
    loop {
        check_cancelled_if_attached(session)?;
        let count = reader
            .read(&mut buffer)
            .map_err(|_| OperationFailureCode::ValidationFailed)?;
        if count == 0 {
            break;
        }
        whole_hasher.update(&buffer[..count]);
        total = total
            .checked_add(count as u64)
            .ok_or(OperationFailureCode::ValidationFailed)?;
    }
    if total != snapshot.source.size()
        || Sha256Digest::from_bytes(whole_hasher.finalize().into()) != state.source_sha256
    {
        return Err(OperationFailureCode::ValidationFailed);
    }
    Ok(evidence)
}

#[cfg(target_os = "macos")]
struct DestinationLock {
    file: File,
    name: OsString,
    identity: FileIdentity,
    directory_identity: FileIdentity,
    receipt_directory: File,
    receipt_directory_identity: FileIdentity,
}

#[cfg(target_os = "macos")]
struct ReceiptStateLock {
    file: File,
    directory: File,
    receipt_directory: File,
    file_identity: FileIdentity,
    directory_identity: FileIdentity,
    receipt_directory_identity: FileIdentity,
}

#[cfg(target_os = "macos")]
fn open_or_create_private_directory_at(parent: &File, name: &OsStr) -> io::Result<File> {
    let directory = match open_directory_at(parent, name) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let child_name = c_name(name)?;
            // SAFETY: parent is an open private directory and name is one child entry.
            let created = unsafe { libc::mkdirat(parent.as_raw_fd(), child_name.as_ptr(), 0o700) };
            if created != 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(error);
                }
            } else {
                parent.sync_all()?;
            }
            open_directory_at(parent, name)?
        }
        Err(error) => return Err(error),
    };
    let metadata = directory.metadata()?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private lock directory has unsafe ownership or permissions",
        ));
    }
    Ok(directory)
}

#[cfg(target_os = "macos")]
impl Drop for ReceiptStateLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

#[cfg(target_os = "macos")]
impl ReceiptStateLock {
    fn acquire(
        parent: &File,
        destination_lock: &DestinationLock,
        session: Option<&OperationSession>,
    ) -> Result<Self, OperationFailureCode> {
        Self::acquire_inner(parent, destination_lock, session, || {})
    }

    fn acquire_inner(
        parent: &File,
        destination_lock: &DestinationLock,
        session: Option<&OperationSession>,
        mut on_contention: impl FnMut(),
    ) -> Result<Self, OperationFailureCode> {
        let directory = open_directory_at(parent, OsStr::new(SPLIT_LOCK_DIRECTORY_NAME))
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        let directory_identity =
            handle_identity(&directory).ok_or(OperationFailureCode::UnsupportedCapability)?;
        if directory_identity != destination_lock.directory_identity {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        let receipt_directory = destination_lock
            .receipt_directory
            .try_clone()
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        let receipt_directory_identity = handle_identity(&receipt_directory)
            .ok_or(OperationFailureCode::UnsupportedCapability)?;
        if receipt_directory_identity != destination_lock.receipt_directory_identity {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        let name = c_name(OsStr::new(SPLIT_RECEIPT_LOCK_NAME))
            .map_err(|_| OperationFailureCode::UnsafePath)?;
        // Receipt-state coordination has its own child namespace. A destination
        // basename can therefore never alias this lock file.
        // SAFETY: receipt_directory is private and name is one child component.
        let descriptor = unsafe {
            libc::openat(
                receipt_directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if descriptor < 0 {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        // SAFETY: openat returned a new descriptor owned by this function.
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file
            .metadata()
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        let identity = handle_identity(&file).ok_or(OperationFailureCode::UnsupportedCapability)?;
        let owner = unsafe { libc::geteuid() };
        if !metadata.file_type().is_file()
            || metadata.uid() != owner
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
            || identity == directory_identity
            || identity == receipt_directory_identity
        {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        // A blocking flock would hide cancellation until another recovery
        // releases the lock. Poll without blocking and retain artifacts if the
        // operation is cancelled before this guard is acquired.
        loop {
            check_cancelled_if_attached(session)?;
            match file.try_lock_exclusive() {
                Ok(()) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    on_contention();
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(OperationFailureCode::PublicationUncertain),
            }
        }
        let guard = Self {
            file,
            directory,
            receipt_directory,
            file_identity: identity,
            directory_identity,
            receipt_directory_identity,
        };
        check_cancelled_if_attached(session)?;
        guard
            .receipt_directory
            .sync_all()
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        guard.validate(parent, destination_lock)?;
        Ok(guard)
    }

    fn validate(
        &self,
        parent: &File,
        destination_lock: &DestinationLock,
    ) -> Result<(), OperationFailureCode> {
        let current_directory = open_directory_at(parent, OsStr::new(SPLIT_LOCK_DIRECTORY_NAME))
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        if handle_identity(&self.directory) != Some(self.directory_identity)
            || handle_identity(&current_directory) != Some(self.directory_identity)
            || self.directory_identity != destination_lock.directory_identity
        {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        let current_receipt_directory = open_directory_at(
            &current_directory,
            OsStr::new(SPLIT_RECEIPT_LOCK_DIRECTORY_NAME),
        )
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        if handle_identity(&self.receipt_directory) != Some(self.receipt_directory_identity)
            || handle_identity(&current_receipt_directory) != Some(self.receipt_directory_identity)
            || self.receipt_directory_identity != destination_lock.receipt_directory_identity
        {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        let current_file = open_file_at(
            &current_receipt_directory,
            OsStr::new(SPLIT_RECEIPT_LOCK_NAME),
        )
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        if handle_identity(&self.file) != Some(self.file_identity)
            || handle_identity(&current_file) != Some(self.file_identity)
        {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        Ok(())
    }
}

/// Carries the open parent and destination lock used by publication and recovery.
#[cfg(target_os = "macos")]
struct DestinationPublication<'a> {
    parent: &'a File,
    destination_name: &'a OsStr,
    lock: &'a DestinationLock,
    parent_identity: FileIdentity,
    parent_path: &'a Path,
    #[cfg(test)]
    test_failpoint: Option<SplitTestFailpoint>,
}

#[cfg(target_os = "macos")]
impl DestinationPublication<'_> {
    fn validate_lock(&self) -> Result<(), OperationFailureCode> {
        self.lock
            .validate(self.parent, self.parent_identity, self.parent_path)
            .map_err(|_| OperationFailureCode::PublicationUncertain)
    }
}

#[cfg(target_os = "macos")]
impl Drop for DestinationLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

#[cfg(target_os = "macos")]
/// Creates a stable lock entry for one destination in the parent's private lock directory.
/// The entry uses the destination's basename so the volume applies the same name-matching rules.
fn acquire_destination_lock(
    parent: &File,
    expected_parent_identity: FileIdentity,
    parent_path: &Path,
    destination_name: &OsStr,
) -> Result<DestinationLock, OperationFailureCode> {
    if is_reserved_split_namespace_name(destination_name) {
        return Err(OperationFailureCode::UnsafePath);
    }
    let parent_identity =
        handle_identity(parent).ok_or(OperationFailureCode::UnsupportedCapability)?;
    if parent_identity != expected_parent_identity
        || validate_parent_identity(parent_path, expected_parent_identity).is_err()
    {
        return Err(OperationFailureCode::StalePlan);
    }

    let directory_name = OsStr::new(SPLIT_LOCK_DIRECTORY_NAME);
    let directory = match open_directory_at(parent, directory_name) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let directory_c =
                c_name(directory_name).map_err(|_| OperationFailureCode::UnsafePath)?;
            // SAFETY: parent is open and directory_c names one child entry.
            let created = unsafe { libc::mkdirat(parent.as_raw_fd(), directory_c.as_ptr(), 0o700) };
            if created != 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(OperationFailureCode::DestinationUnavailable);
                }
            } else {
                parent
                    .sync_all()
                    .map_err(|_| OperationFailureCode::DestinationUnavailable)?;
            }
            open_directory_at(parent, directory_name)
                .map_err(|_| OperationFailureCode::UnsafePath)?
        }
        Err(_) => return Err(OperationFailureCode::UnsafePath),
    };
    let directory_metadata = directory
        .metadata()
        .map_err(|_| OperationFailureCode::DestinationUnavailable)?;
    let effective_uid = unsafe { libc::geteuid() };
    if !directory_metadata.file_type().is_dir()
        || directory_metadata.uid() != effective_uid
        || directory_metadata.mode() & 0o077 != 0
    {
        return Err(OperationFailureCode::UnsafePath);
    }
    let directory_identity =
        handle_identity(&directory).ok_or(OperationFailureCode::UnsupportedCapability)?;
    let receipt_directory = open_or_create_private_directory_at(
        &directory,
        OsStr::new(SPLIT_RECEIPT_LOCK_DIRECTORY_NAME),
    )
    .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    let receipt_directory_identity =
        handle_identity(&receipt_directory).ok_or(OperationFailureCode::UnsupportedCapability)?;
    // Resolve the name through the volume so case and normalization aliases match.
    match open_directory_at(&directory, destination_name) {
        Ok(candidate) => {
            if handle_identity(&candidate).ok_or(OperationFailureCode::UnsupportedCapability)?
                == receipt_directory_identity
            {
                return Err(OperationFailureCode::UnsafePath);
            }
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) => {}
        Err(_) => return Err(OperationFailureCode::UnsafePath),
    }
    let marker = c_name(destination_name).map_err(|_| OperationFailureCode::UnsafePath)?;
    // SAFETY: directory is open and marker names one child entry. O_NOFOLLOW
    // rejects symlink substitution; the descriptor is owned below.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            marker.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(OperationFailureCode::DestinationUnavailable);
    }
    // SAFETY: openat returned a new descriptor owned by this function.
    let file = unsafe { File::from_raw_fd(descriptor) };
    let file_metadata = file
        .metadata()
        .map_err(|_| OperationFailureCode::DestinationUnavailable)?;
    if !file_metadata.file_type().is_file()
        || file_metadata.uid() != effective_uid
        || file_metadata.mode() & 0o077 != 0
        || file_metadata.nlink() != 1
    {
        return Err(OperationFailureCode::UnsafePath);
    }
    let identity = handle_identity(&file).ok_or(OperationFailureCode::UnsupportedCapability)?;
    if identity == directory_identity || identity == parent_identity {
        return Err(OperationFailureCode::UnsafePath);
    }
    match file.try_lock_exclusive() {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            return Err(OperationFailureCode::DestinationBusy);
        }
        Err(_) => return Err(OperationFailureCode::DestinationUnavailable),
    }
    let lock = DestinationLock {
        file,
        name: destination_name.to_os_string(),
        identity,
        directory_identity,
        receipt_directory,
        receipt_directory_identity,
    };
    lock.validate(parent, expected_parent_identity, parent_path)?;
    Ok(lock)
}

#[cfg(target_os = "macos")]
impl DestinationLock {
    fn validate(
        &self,
        parent: &File,
        expected_parent_identity: FileIdentity,
        parent_path: &Path,
    ) -> Result<(), OperationFailureCode> {
        if handle_identity(parent) != Some(expected_parent_identity)
            || handle_identity(&self.file) != Some(self.identity)
            || validate_parent_identity(parent_path, expected_parent_identity).is_err()
        {
            return Err(OperationFailureCode::StalePlan);
        }
        let directory = open_directory_at(parent, OsStr::new(SPLIT_LOCK_DIRECTORY_NAME))
            .map_err(|_| OperationFailureCode::StalePlan)?;
        if handle_identity(&directory) != Some(self.directory_identity) {
            return Err(OperationFailureCode::StalePlan);
        }
        let file =
            open_file_at(&directory, &self.name).map_err(|_| OperationFailureCode::StalePlan)?;
        if handle_identity(&file) != Some(self.identity) {
            return Err(OperationFailureCode::StalePlan);
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn validate_parent_identity(
    path: &Path,
    expected: FileIdentity,
) -> Result<(), OperationFailureCode> {
    let directory = open_directory(path).map_err(|_| OperationFailureCode::StalePlan)?;
    if handle_identity(&directory) == Some(expected) {
        Ok(())
    } else {
        Err(OperationFailureCode::StalePlan)
    }
}

#[cfg(target_os = "macos")]
fn validate_source(
    state: &mut SplitPlanState<'_>,
    session: Option<&OperationSession>,
) -> Result<(), OperationFailureCode> {
    let parent = open_directory(&state.source_parent_path)
        .map_err(|_| OperationFailureCode::SourceChanged)?;
    if handle_identity(&parent) != Some(state.source_parent_identity)
        || handle_identity(&state.source_parent) != Some(state.source_parent_identity)
    {
        return Err(OperationFailureCode::SourceChanged);
    }
    let path_file = open_file_at(&parent, &state.source_name)
        .map_err(|_| OperationFailureCode::SourceChanged)?;
    if handle_identity(&path_file) != Some(state.source_identity) {
        return Err(OperationFailureCode::SourceChanged);
    }
    if snapshot_of(&state.source_file).map_err(|error| error.code())? != state.source_snapshot {
        return Err(OperationFailureCode::SourceChanged);
    }
    let (size, digest) = hash_file_with_check(
        &mut state.source_file,
        || check_cancelled_if_attached(session),
        #[cfg(test)]
        None,
    )
    .map_err(|error| match error {
        HashFileFailure::Io => OperationFailureCode::SourceChanged,
        HashFileFailure::Operation(code) => code,
    })?;
    if size != state.source_snapshot.len || digest != state.source_sha256 {
        return Err(OperationFailureCode::SourceChanged);
    }
    if snapshot_of(&state.source_file).map_err(|error| error.code())? != state.source_snapshot
        || handle_identity(&path_file) != Some(state.source_identity)
    {
        return Err(OperationFailureCode::SourceChanged);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn current_directory_identity(
    parent: &File,
    name: &OsStr,
) -> Result<Option<FileIdentity>, OperationFailureCode> {
    let Some(directory) = open_optional_directory_at(parent, name).map_err(|error| error.code())?
    else {
        return Ok(None);
    };
    handle_identity(&directory)
        .map(Some)
        .ok_or(OperationFailureCode::UnsupportedCapability)
}

#[cfg(target_os = "macos")]
fn create_file_at(parent: &File, name: &OsStr) -> io::Result<File> {
    let name = c_name(name)?;
    // SAFETY: parent is open and name is a single component. Exclusive create
    // prevents replacing an existing entry.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor owned by this function.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(target_os = "macos")]
fn mkdir_at(parent: &File, name: &OsStr) -> Result<(), OperationFailureCode> {
    let name = c_name(name).map_err(|_| OperationFailureCode::UnsafePath)?;
    // SAFETY: parent is open and name is one path component.
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if result == 0 {
        Ok(())
    } else {
        Err(OperationFailureCode::WriteFailed)
    }
}

#[cfg(target_os = "macos")]
fn planned_artifact(
    relative_path_hex: Vec<String>,
    parent_identity: FileIdentity,
    kind: ArtifactKind,
) -> JournalArtifact {
    JournalArtifact {
        relative_path_hex,
        parent_identity: identity_string(parent_identity),
        kind,
        state: ArtifactState::Planned,
    }
}

#[cfg(target_os = "macos")]
fn plan_journal_artifacts(
    journal: &mut JournalWriter,
    artifacts: Vec<JournalArtifact>,
) -> Result<(), OperationFailureCode> {
    journal.append(JournalPhase::Staging, |record| {
        record.artifacts.extend(artifacts);
    })
}

#[cfg(target_os = "macos")]
fn create_journaled_directory(
    parent: &File,
    name: &OsStr,
    relative_path_hex: &[String],
    journal: &mut JournalWriter,
    staging_root: bool,
) -> Result<File, OperationFailureCode> {
    let planned = journal
        .record
        .artifacts
        .iter()
        .find(|artifact| artifact.relative_path_hex == relative_path_hex)
        .ok_or(OperationFailureCode::PublicationUncertain)?;
    if !matches!(planned.state, ArtifactState::Planned)
        || parse_identity(&planned.parent_identity) != handle_identity(parent)
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    mkdir_at(parent, name)?;
    parent
        .sync_all()
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    let directory =
        open_directory_at(parent, name).map_err(|_| OperationFailureCode::WriteFailed)?;
    directory
        .sync_all()
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    let evidence = directory_evidence(&directory)?;
    let staging_identity = evidence.identity.clone();
    let path = relative_path_hex.to_vec();
    journal.append(JournalPhase::Staging, |record| {
        if let Some(artifact) = record
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.relative_path_hex == path)
        {
            artifact.state = ArtifactState::Created(evidence);
        }
        if staging_root {
            record.staging_identity = Some(staging_identity);
        }
    })?;
    Ok(directory)
}

#[cfg(target_os = "macos")]
fn create_journaled_file(
    parent: &File,
    name: &OsStr,
    relative_path_hex: &[String],
    journal: &mut JournalWriter,
) -> Result<File, OperationFailureCode> {
    let planned = journal
        .record
        .artifacts
        .iter()
        .find(|artifact| artifact.relative_path_hex == relative_path_hex)
        .ok_or(OperationFailureCode::PublicationUncertain)?;
    if !matches!(planned.state, ArtifactState::Planned)
        || planned.kind != ArtifactKind::RegularFile
        || parse_identity(&planned.parent_identity) != handle_identity(parent)
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let file = create_file_at(parent, name).map_err(|_| OperationFailureCode::WriteFailed)?;
    file.sync_all()
        .and_then(|()| parent.sync_all())
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    let evidence = regular_file_evidence(&file, 0, Sha256Digest::digest(&[]))?;
    let path = relative_path_hex.to_vec();
    journal.append(JournalPhase::Staging, |record| {
        if let Some(artifact) = record
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.relative_path_hex == path)
        {
            artifact.state = ArtifactState::Created(evidence);
        }
    })?;
    Ok(file)
}

#[cfg(target_os = "macos")]
fn record_verified_file(
    parent: &File,
    name: &OsStr,
    relative_path_hex: &[String],
    evidence: &ArtifactEvidence,
    session: &OperationSession,
    journal: &mut JournalWriter,
) -> Result<(), OperationFailureCode> {
    let path_file = open_file_at(parent, name).map_err(|_| OperationFailureCode::WriteFailed)?;
    if !artifact_evidence_matches_with_check(
        &path_file,
        ArtifactKind::RegularFile,
        evidence,
        || check_cancelled(session),
    )? {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let path = relative_path_hex.to_vec();
    let previous = journal
        .record
        .artifacts
        .iter()
        .find(|artifact| artifact.relative_path_hex == path)
        .ok_or(OperationFailureCode::PublicationUncertain)?;
    if !matches!(
        &previous.state,
        ArtifactState::Created(created)
            if created.identity == evidence.identity
                && created.mode == evidence.mode
                && created.link_count == evidence.link_count
    ) {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let evidence = evidence.clone();
    journal.append(JournalPhase::Staging, |record| {
        if let Some(artifact) = record
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.relative_path_hex == path)
        {
            artifact.state = ArtifactState::Verified(evidence);
        }
    })
}

#[cfg(target_os = "macos")]
fn verify_regular_file_at(
    parent: &File,
    name: &OsStr,
    relative_path_hex: &[String],
    expected_length: u64,
    expected_digest: Sha256Digest,
    journal: &JournalWriter,
) -> Result<ArtifactEvidence, OperationFailureCode> {
    let planned = journal
        .record
        .artifacts
        .iter()
        .find(|artifact| artifact.relative_path_hex == relative_path_hex)
        .ok_or(OperationFailureCode::PublicationUncertain)?;
    let created = match &planned.state {
        ArtifactState::Created(evidence) if planned.kind == ArtifactKind::RegularFile => evidence,
        _ => return Err(OperationFailureCode::PublicationUncertain),
    };
    let mut file =
        open_file_at(parent, name).map_err(|_| OperationFailureCode::ValidationFailed)?;
    if handle_identity(&file).map(identity_string).as_deref() != Some(&created.identity) {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let (length, digest) = hash_regular_file(&mut file)?;
    if length != expected_length || digest != expected_digest {
        return Err(OperationFailureCode::ValidationFailed);
    }
    let evidence = regular_file_evidence(&file, length, digest)?;
    if evidence.identity != created.identity
        || evidence.mode != created.mode
        || evidence.link_count != created.link_count
        || !artifact_evidence_matches(&file, ArtifactKind::RegularFile, &evidence)?
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    Ok(evidence)
}

#[cfg(target_os = "macos")]
fn hash_regular_file(file: &mut File) -> Result<(u64, Sha256Digest), OperationFailureCode> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; SPLIT_IO_BUFFER_SIZE];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| OperationFailureCode::ValidationFailed)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        total = total
            .checked_add(count as u64)
            .ok_or(OperationFailureCode::SplitSourceSizeUnsupported)?;
    }
    Ok((total, Sha256Digest::from_bytes(hasher.finalize().into())))
}

#[cfg(target_os = "macos")]
fn directory_evidence(file: &File) -> Result<ArtifactEvidence, OperationFailureCode> {
    let metadata = file
        .metadata()
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    if !metadata.file_type().is_dir() {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let identity = handle_identity(file).ok_or(OperationFailureCode::UnsupportedCapability)?;
    Ok(ArtifactEvidence {
        identity: identity_string(identity),
        mode: metadata.mode() & 0o7777,
        link_count: None,
        length: None,
        sha256: None,
        change_seconds: None,
        change_nanoseconds: None,
    })
}

#[cfg(target_os = "macos")]
fn regular_file_evidence(
    file: &File,
    expected_length: u64,
    expected_digest: Sha256Digest,
) -> Result<ArtifactEvidence, OperationFailureCode> {
    let metadata = file
        .metadata()
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    if !metadata.file_type().is_file() || metadata.len() != expected_length || metadata.nlink() != 1
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let identity = handle_identity(file).ok_or(OperationFailureCode::UnsupportedCapability)?;
    Ok(ArtifactEvidence {
        identity: identity_string(identity),
        mode: metadata.mode() & 0o7777,
        link_count: Some(metadata.nlink()),
        length: Some(metadata.len()),
        sha256: Some(expected_digest.to_hex()),
        change_seconds: Some(metadata.ctime()),
        change_nanoseconds: Some(metadata.ctime_nsec()),
    })
}

#[cfg(target_os = "macos")]
fn artifact_metadata_matches(
    file: &File,
    kind: ArtifactKind,
    evidence: &ArtifactEvidence,
) -> Result<bool, OperationFailureCode> {
    let metadata = file
        .metadata()
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    if handle_identity(file).map(identity_string).as_deref() != Some(&evidence.identity)
        || metadata.mode() & 0o7777 != evidence.mode
    {
        return Ok(false);
    }
    match kind {
        ArtifactKind::Directory => Ok(metadata.file_type().is_dir()),
        ArtifactKind::RegularFile => Ok(metadata.file_type().is_file()
            && Some(metadata.nlink()) == evidence.link_count
            && Some(metadata.len()) == evidence.length
            && Some(metadata.ctime()) == evidence.change_seconds
            && Some(metadata.ctime_nsec()) == evidence.change_nanoseconds
            && evidence
                .sha256
                .as_deref()
                .is_some_and(|digest| Sha256Digest::parse_hex(digest).is_ok())),
    }
}

#[cfg(target_os = "macos")]
fn artifact_evidence_matches(
    file: &File,
    kind: ArtifactKind,
    evidence: &ArtifactEvidence,
) -> Result<bool, OperationFailureCode> {
    artifact_evidence_matches_with_check(file, kind, evidence, || Ok(()))
}

#[cfg(target_os = "macos")]
fn artifact_evidence_matches_with_check(
    file: &File,
    kind: ArtifactKind,
    evidence: &ArtifactEvidence,
    mut check: impl FnMut() -> Result<(), OperationFailureCode>,
) -> Result<bool, OperationFailureCode> {
    if !artifact_metadata_matches(file, kind, evidence)? {
        return Ok(false);
    }
    if kind == ArtifactKind::Directory {
        return Ok(true);
    }
    let Some(expected_length) = evidence.length else {
        return Ok(false);
    };
    let Some(expected_digest) = evidence
        .sha256
        .as_deref()
        .and_then(|digest| Sha256Digest::parse_hex(digest).ok())
    else {
        return Ok(false);
    };
    let (actual_length, actual_digest) = hash_open_file_with_check(file, &mut check)?;
    Ok(actual_length == expected_length
        && actual_digest == expected_digest
        && artifact_metadata_matches(file, kind, evidence)?)
}

#[cfg(target_os = "macos")]
fn cleanup_artifact_evidence_matches(
    state: &SplitPlanState<'_>,
    session: Option<&OperationSession>,
    file: &File,
    kind: ArtifactKind,
    evidence: &ArtifactEvidence,
) -> Result<bool, OperationFailureCode> {
    #[cfg(not(test))]
    let _ = state;
    #[cfg(test)]
    let mut chunk_checks = 0usize;

    artifact_evidence_matches_with_check(file, kind, evidence, || {
        #[cfg(test)]
        {
            if chunk_checks == 1
                && state.test_failpoint
                    == Some(
                        SplitTestFailpoint::FailureBeforeReceiptCommitWithCancelDuringCleanupHash,
                    )
                && let Some(session) = session
            {
                let _ = session.cancel();
            }
            chunk_checks = chunk_checks.saturating_add(1);
        }
        check_cancelled_if_attached(session)
    })
}

#[cfg(target_os = "macos")]
fn refresh_regular_file_change_time(
    file: &File,
    evidence: &ArtifactEvidence,
    session: Option<&OperationSession>,
) -> Result<ArtifactEvidence, OperationFailureCode> {
    check_cancelled_if_attached(session)?;
    let before = file
        .metadata()
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    let expected_identity =
        parse_identity(&evidence.identity).ok_or(OperationFailureCode::PublicationUncertain)?;
    let expected_length = evidence
        .length
        .ok_or(OperationFailureCode::PublicationUncertain)?;
    let expected_digest = evidence
        .sha256
        .as_deref()
        .and_then(|digest| Sha256Digest::parse_hex(digest).ok())
        .ok_or(OperationFailureCode::PublicationUncertain)?;
    if handle_identity(file) != Some(expected_identity)
        || !before.file_type().is_file()
        || before.mode() & 0o7777 != evidence.mode
        || Some(before.nlink()) != evidence.link_count
        || before.len() != expected_length
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let before_change_time = (before.ctime(), before.ctime_nsec());
    let (actual_length, actual_digest) =
        hash_open_file_with_check(file, || check_cancelled_if_attached(session))?;
    check_cancelled_if_attached(session)?;
    let after = file
        .metadata()
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    if actual_length != expected_length
        || actual_digest != expected_digest
        || handle_identity(file) != Some(expected_identity)
        || !after.file_type().is_file()
        || after.mode() & 0o7777 != evidence.mode
        || Some(after.nlink()) != evidence.link_count
        || after.len() != expected_length
        || (after.ctime(), after.ctime_nsec()) != before_change_time
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let mut refreshed = evidence.clone();
    refreshed.change_seconds = Some(after.ctime());
    refreshed.change_nanoseconds = Some(after.ctime_nsec());
    Ok(refreshed)
}

#[cfg(target_os = "macos")]
fn refresh_quarantined_file_evidence(
    root: &File,
    root_artifact: &JournalArtifact,
    record: &JournalRecord,
    session: Option<&OperationSession>,
) -> Result<Vec<(usize, ArtifactEvidence)>, OperationFailureCode> {
    let root_path = &root_artifact.relative_path_hex;
    let mut refreshed = Vec::new();
    for (index, artifact) in record.artifacts.iter().enumerate() {
        if artifact.kind != ArtifactKind::RegularFile
            || artifact.relative_path_hex.len() <= root_path.len()
            || artifact.relative_path_hex[..root_path.len()] != root_path[..]
        {
            continue;
        }
        check_cancelled_if_attached(session)?;
        let evidence = match &artifact.state {
            ArtifactState::Created(evidence) | ArtifactState::Verified(evidence) => evidence,
            ArtifactState::Planned => return Err(OperationFailureCode::PublicationUncertain),
        };
        let parent = open_artifact_parent_from_root(root, record, artifact)?
            .ok_or(OperationFailureCode::PublicationUncertain)?;
        let name = artifact
            .relative_path_hex
            .last()
            .and_then(|component| decode_os_name(component))
            .ok_or(OperationFailureCode::PublicationUncertain)?;
        let file =
            open_file_at(&parent, &name).map_err(|_| OperationFailureCode::PublicationUncertain)?;
        let updated = refresh_regular_file_change_time(&file, evidence, session)?;
        if evidence.change_seconds != updated.change_seconds
            || evidence.change_nanoseconds != updated.change_nanoseconds
        {
            refreshed.push((index, updated));
        }
    }
    Ok(refreshed)
}

#[cfg(target_os = "macos")]
fn append_cleanup_artifact_evidence_updates(
    journal: &mut JournalWriter,
    updates: &[(usize, ArtifactEvidence)],
) -> Result<(), OperationFailureCode> {
    if journal.record.phase != JournalPhase::Cleaning {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    for (index, updated) in updates {
        let artifact = journal
            .record
            .artifacts
            .get(*index)
            .ok_or(OperationFailureCode::PublicationUncertain)?;
        if artifact.kind != ArtifactKind::RegularFile
            || updated.change_seconds.is_none()
            || updated.change_nanoseconds.is_none()
        {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        let current = match &artifact.state {
            ArtifactState::Created(evidence) | ArtifactState::Verified(evidence) => evidence,
            ArtifactState::Planned => return Err(OperationFailureCode::PublicationUncertain),
        };
        if !artifact_evidence_equal_except_change_time(current, updated) {
            return Err(OperationFailureCode::PublicationUncertain);
        }
    }
    if updates.is_empty() {
        return Ok(());
    }
    journal.append(JournalPhase::Cleaning, |record| {
        for (index, updated) in updates {
            let Some(artifact) = record.artifacts.get_mut(*index) else {
                continue;
            };
            match &mut artifact.state {
                ArtifactState::Created(evidence) | ArtifactState::Verified(evidence) => {
                    *evidence = updated.clone();
                }
                ArtifactState::Planned => {}
            }
        }
    })
}

#[cfg(target_os = "macos")]
fn hash_open_file(file: &File) -> Result<(u64, Sha256Digest), OperationFailureCode> {
    hash_open_file_with_check(file, || Ok(()))
}

/// Hashes an opened artifact, checking cancellation before each read chunk.
#[cfg(target_os = "macos")]
fn hash_open_file_with_check(
    file: &File,
    mut check: impl FnMut() -> Result<(), OperationFailureCode>,
) -> Result<(u64, Sha256Digest), OperationFailureCode> {
    let mut hasher = Sha256::new();
    let mut offset: libc::off_t = 0;
    let mut total = 0_u64;
    let mut buffer = [0_u8; SPLIT_IO_BUFFER_SIZE];
    loop {
        check()?;
        // pread leaves the descriptor's shared seek offset untouched.
        // SAFETY: file is open, buffer is writable, and offset is nonnegative.
        let count = unsafe {
            libc::pread(
                file.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                offset,
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(OperationFailureCode::PublicationUncertain);
        }
        if count == 0 {
            break;
        }
        let count = count as usize;
        hasher.update(&buffer[..count]);
        total = total
            .checked_add(count as u64)
            .ok_or(OperationFailureCode::SplitSourceSizeUnsupported)?;
        offset = offset
            .checked_add(count as libc::off_t)
            .ok_or(OperationFailureCode::SplitSourceSizeUnsupported)?;
    }
    Ok((total, Sha256Digest::from_bytes(hasher.finalize().into())))
}

#[cfg(target_os = "macos")]
fn directory_child_names(directory: &File) -> io::Result<HashSet<Vec<u8>>> {
    // openat on `.` creates an independent open-file description so repeated
    // directory scans do not share and advance one directory-stream offset.
    let dot = b".\0";
    // SAFETY: directory is open and dot is a NUL-terminated child name.
    let duplicate = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            dot.as_ptr().cast(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fdopendir takes ownership of the duplicate descriptor on success.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir failed and did not take ownership of the descriptor.
        unsafe { libc::close(duplicate) };
        return Err(error);
    }
    // SAFETY: errno is thread-local on Darwin.
    unsafe { *libc::__error() = 0 };
    let mut names = HashSet::new();
    loop {
        // SAFETY: stream is a valid DIR pointer until closed below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: d_name is NUL-terminated by readdir.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.insert(name.to_vec());
        }
    }
    // SAFETY: errno remains thread-local and stream is still open.
    let read_error = unsafe { *libc::__error() };
    // SAFETY: closes the stream and its owned descriptor exactly once.
    let close_result = unsafe { libc::closedir(stream) };
    if read_error != 0 {
        return Err(io::Error::from_raw_os_error(read_error));
    }
    if close_result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(names)
}

#[cfg(target_os = "macos")]
fn open_recorded_artifact_parent(
    base: &File,
    record: &JournalRecord,
    artifact: &JournalArtifact,
) -> io::Result<File> {
    let mut parent = base.try_clone()?;
    let mut prefix = Vec::<String>::new();
    for encoded_component in
        &artifact.relative_path_hex[..artifact.relative_path_hex.len().saturating_sub(1)]
    {
        prefix.push(encoded_component.clone());
        let parent_record = record
            .artifacts
            .iter()
            .find(|candidate| candidate.relative_path_hex == prefix)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "parent not recorded"))?;
        let evidence = match &parent_record.state {
            ArtifactState::Created(evidence) | ArtifactState::Verified(evidence)
                if parent_record.kind == ArtifactKind::Directory =>
            {
                evidence
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "parent identity not recorded",
                ));
            }
        };
        let name = decode_os_name(encoded_component)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad parent name"))?;
        let opened = open_directory_at(&parent, &name)?;
        if !artifact_evidence_matches(&opened, ArtifactKind::Directory, evidence)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "parent identity changed",
            ));
        }
        parent = opened;
    }
    if handle_identity(&parent).map(identity_string).as_deref() != Some(&artifact.parent_identity) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recorded parent identity changed",
        ));
    }
    Ok(parent)
}

#[cfg(target_os = "macos")]
fn preflight_owned_directory(
    state: &SplitPlanState<'_>,
    session: Option<&OperationSession>,
    directory: &File,
    artifact: &JournalArtifact,
    record: &JournalRecord,
) -> Result<(), OperationFailureCode> {
    check_cancelled_if_attached(session)?;
    let evidence = match &artifact.state {
        ArtifactState::Created(evidence) | ArtifactState::Verified(evidence)
            if artifact.kind == ArtifactKind::Directory =>
        {
            evidence
        }
        _ => return Err(OperationFailureCode::PublicationUncertain),
    };
    if !artifact_evidence_matches(directory, ArtifactKind::Directory, evidence)? {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let actual =
        directory_child_names(directory).map_err(|_| OperationFailureCode::PublicationUncertain)?;
    let mut prefix = artifact.relative_path_hex.clone();
    let planned_children = record
        .artifacts
        .iter()
        .filter(|child| {
            child.relative_path_hex.len() == prefix.len() + 1
                && child.relative_path_hex[..prefix.len()] == prefix
        })
        .map(|child| child.relative_path_hex[prefix.len()].clone())
        .collect::<HashSet<_>>();
    let actual_names = actual
        .iter()
        .map(|name| encode_os_name(OsStr::from_bytes(name)))
        .collect::<HashSet<_>>();
    let expected_present = record
        .artifacts
        .iter()
        .filter(|child| {
            child.relative_path_hex.len() == prefix.len() + 1
                && child.relative_path_hex[..prefix.len()] == prefix
                && !matches!(child.state, ArtifactState::Planned)
        })
        .map(|child| child.relative_path_hex[prefix.len()].clone())
        .collect::<HashSet<_>>();
    if !actual_names.is_subset(&planned_children) || !expected_present.is_subset(&actual_names) {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    for encoded_name in actual_names {
        check_cancelled_if_attached(session)?;
        prefix.push(encoded_name.clone());
        let child = record
            .artifacts
            .iter()
            .find(|candidate| candidate.relative_path_hex == prefix)
            .ok_or(OperationFailureCode::PublicationUncertain)?;
        if parse_identity(&child.parent_identity) != handle_identity(directory) {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        let child_evidence = match &child.state {
            ArtifactState::Created(evidence) | ArtifactState::Verified(evidence) => evidence,
            ArtifactState::Planned => return Err(OperationFailureCode::PublicationUncertain),
        };
        let name =
            decode_os_name(&encoded_name).ok_or(OperationFailureCode::PublicationUncertain)?;
        match child.kind {
            ArtifactKind::Directory => {
                let opened = open_directory_at(directory, &name)
                    .map_err(|_| OperationFailureCode::PublicationUncertain)?;
                if !artifact_evidence_matches(&opened, child.kind, child_evidence)? {
                    return Err(OperationFailureCode::PublicationUncertain);
                }
                preflight_owned_directory(state, session, &opened, child, record)?;
            }
            ArtifactKind::RegularFile => {
                let opened = open_file_at(directory, &name)
                    .map_err(|_| OperationFailureCode::PublicationUncertain)?;
                if !cleanup_artifact_evidence_matches(
                    state,
                    session,
                    &opened,
                    child.kind,
                    child_evidence,
                )? {
                    return Err(OperationFailureCode::PublicationUncertain);
                }
            }
        }
        prefix.pop();
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn preflight_recorded_bundle_at(
    state: &SplitPlanState<'_>,
    session: Option<&OperationSession>,
    parent: &File,
    name: &OsStr,
    record: &JournalRecord,
    expected_identity: FileIdentity,
) -> Result<(), OperationFailureCode> {
    if current_directory_identity(parent, name)? != Some(expected_identity) {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let root =
        open_directory_at(parent, name).map_err(|_| OperationFailureCode::PublicationUncertain)?;
    if handle_identity(&root) != Some(expected_identity) {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let root_path = vec![record.staging_name_hex.clone()];
    let root_artifact = record
        .artifacts
        .iter()
        .find(|artifact| artifact.relative_path_hex == root_path)
        .ok_or(OperationFailureCode::PublicationUncertain)?;
    preflight_owned_directory(state, session, &root, root_artifact, record)
}

#[cfg(target_os = "macos")]
fn revalidate_recorded_artifact_for_cleanup(
    state: &SplitPlanState<'_>,
    session: Option<&OperationSession>,
    record: &JournalRecord,
    artifact: &JournalArtifact,
) -> Result<(), OperationFailureCode> {
    check_cancelled_if_attached(session)?;
    let Some(parent_identity) = parse_identity(&artifact.parent_identity) else {
        return Err(OperationFailureCode::PublicationUncertain);
    };
    let parent = open_recorded_artifact_parent(&state.destination_parent, record, artifact)
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    if handle_identity(&parent) != Some(parent_identity) {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let encoded_name = artifact
        .relative_path_hex
        .last()
        .ok_or(OperationFailureCode::PublicationUncertain)?;
    let name = decode_os_name(encoded_name).ok_or(OperationFailureCode::PublicationUncertain)?;
    let encoded_name_c = c_name(&name).map_err(|_| OperationFailureCode::UnsafePath)?;
    let exists = {
        // SAFETY: parent is an open directory and encoded_name_c is one component.
        let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
        let result = unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                encoded_name_c.as_ptr(),
                &mut status,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            true
        } else {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                false
            } else {
                return Err(OperationFailureCode::PublicationUncertain);
            }
        }
    };
    if !exists {
        return Ok(());
    }
    let evidence = match &artifact.state {
        ArtifactState::Created(evidence) | ArtifactState::Verified(evidence) => evidence,
        ArtifactState::Planned => return Err(OperationFailureCode::PublicationUncertain),
    };
    let opened = match artifact.kind {
        ArtifactKind::Directory => open_directory_at(&parent, &name),
        ArtifactKind::RegularFile => open_file_at(&parent, &name),
    }
    .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    if !cleanup_artifact_evidence_matches(state, session, &opened, artifact.kind, evidence)?
        || handle_identity(&parent) != Some(parent_identity)
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    if artifact.kind == ArtifactKind::Directory
        && !directory_child_names(&opened)
            .map_err(|_| OperationFailureCode::PublicationUncertain)?
            .is_empty()
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }

    let immediate = match artifact.kind {
        ArtifactKind::Directory => open_directory_at(&parent, &name),
        ArtifactKind::RegularFile => open_file_at(&parent, &name),
    }
    .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    if handle_identity(&immediate) != handle_identity(&opened)
        || !artifact_evidence_matches(&immediate, artifact.kind, evidence)?
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }

    #[cfg(test)]
    if state.test_failpoint == Some(SplitTestFailpoint::SubstituteArtifactBeforeFinalIdentityCheck)
        && artifact.kind == ArtifactKind::RegularFile
    {
        substitute_artifact_entry_for_test(&parent, &name)?;
    }

    // Revalidate the directory entry without following a symlink. A match
    // still cannot bind a later path-based deletion to this object.
    // SAFETY: parent is open and encoded_name_c is one path component.
    let mut final_status = unsafe { std::mem::zeroed::<libc::stat>() };
    let final_stat_result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            encoded_name_c.as_ptr(),
            &mut final_status,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if final_stat_result != 0 {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let final_path_identity =
        FileIdentity::from_parts(final_status.st_dev as u64, final_status.st_ino as u64);
    let expected_file_type = match artifact.kind {
        ArtifactKind::Directory => libc::S_IFDIR,
        ArtifactKind::RegularFile => libc::S_IFREG,
    };
    if Some(final_path_identity) != handle_identity(&immediate)
        || final_status.st_mode & libc::S_IFMT != expected_file_type
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }

    #[cfg(test)]
    if state.test_failpoint == Some(SplitTestFailpoint::SubstituteArtifactAfterFinalIdentityCheck)
        && artifact.kind == ArtifactKind::RegularFile
    {
        substitute_artifact_entry_for_test(&parent, &name)?;
        return Err(OperationFailureCode::PublicationUncertain);
    }

    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
fn substitute_artifact_entry_for_test(
    parent: &File,
    name: &OsStr,
) -> Result<(), OperationFailureCode> {
    let mut preserved_name = name.to_os_string();
    preserved_name.push(".preserved");
    rename_exclusive_at(parent, name, &preserved_name)
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    let name_c = c_name(name).map_err(|_| OperationFailureCode::UnsafePath)?;
    let target_c = c_name(OsStr::new("missing-cleanup-target"))
        .map_err(|_| OperationFailureCode::UnsafePath)?;
    // SAFETY: parent is open and both C strings are valid single components.
    let result = unsafe { libc::symlinkat(target_c.as_ptr(), parent.as_raw_fd(), name_c.as_ptr()) };
    if result == 0 {
        Ok(())
    } else {
        Err(OperationFailureCode::PublicationUncertain)
    }
}

#[cfg(all(test, target_os = "macos"))]
fn modify_and_restore_artifact_for_test(
    parent: &File,
    name: &OsStr,
) -> Result<(), OperationFailureCode> {
    use std::os::unix::fs::PermissionsExt;

    let name_c = c_name(name).map_err(|_| OperationFailureCode::UnsafePath)?;
    // SAFETY: parent is open and name_c is one path component.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    // SAFETY: openat returned a new descriptor owned by this function.
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file
        .metadata()
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    let original_mode = metadata.mode() & 0o7777;
    let original_change_time = (metadata.ctime(), metadata.ctime_nsec());
    let mut original = Vec::new();
    file.read_to_end(&mut original)
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    let Some(first_byte) = original.first().copied() else {
        return Err(OperationFailureCode::PublicationUncertain);
    };

    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.write_all(&[first_byte ^ 0x01]))
        .and_then(|()| file.sync_all())
        .and_then(|()| file.seek(SeekFrom::Start(0)).map(|_| ()))
        .and_then(|()| file.write_all(&original))
        .and_then(|()| file.sync_all())
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    file.set_permissions(std::fs::Permissions::from_mode(original_mode ^ 0o100))
        .and_then(|()| file.set_permissions(std::fs::Permissions::from_mode(original_mode)))
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    let restored = file
        .metadata()
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    if restored.mode() & 0o7777 != original_mode
        || (restored.ctime(), restored.ctime_nsec()) == original_change_time
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
#[cfg(test)]
fn cleanup_provisional_artifacts(
    snapshot: &SplitPlanSnapshot,
    state: &SplitPlanState<'_>,
    journal_name: &OsStr,
    receipt_state: SplitReceiptCommitState,
) -> Result<(), OperationFailureCode> {
    let parent_path = snapshot
        .bundle_directory
        .parent()
        .ok_or(OperationFailureCode::UnsafePath)?;
    let lock = acquire_destination_lock(
        &state.destination_parent,
        state.destination_parent_identity,
        parent_path,
        &state.destination_name,
    )?;
    cleanup_provisional_artifacts_with_lock(
        snapshot,
        state,
        journal_name,
        receipt_state,
        &lock,
        None,
    )
}

#[cfg(target_os = "macos")]
fn cleanup_provisional_artifacts_with_lock(
    snapshot: &SplitPlanSnapshot,
    state: &SplitPlanState<'_>,
    journal_name: &OsStr,
    receipt_state: SplitReceiptCommitState,
    lock: &DestinationLock,
    session: Option<&OperationSession>,
) -> Result<(), OperationFailureCode> {
    // Lock order is the destination marker under `.nscb-split-locks`, the
    // receipt-state lock under `.receipt-state-locks`, then the trust-store
    // `.lock`. Store issue,
    // revoke, and restore never acquire a Split lock, so this order has no
    // reverse edge. The lease spans only final ownership checks and cleanup;
    // do not call another trust-store method while it is held.
    let receipt_lock = ReceiptStateLock::acquire(&state.destination_parent, lock, session)?;
    cleanup_provisional_artifacts_with_locks(
        snapshot,
        state,
        journal_name,
        receipt_state,
        lock,
        &receipt_lock,
        session,
    )
}

#[cfg(target_os = "macos")]
fn cleanup_provisional_artifacts_with_locks(
    snapshot: &SplitPlanSnapshot,
    state: &SplitPlanState<'_>,
    journal_name: &OsStr,
    receipt_state: SplitReceiptCommitState,
    lock: &DestinationLock,
    receipt_lock: &ReceiptStateLock,
    session: Option<&OperationSession>,
) -> Result<(), OperationFailureCode> {
    cleanup_provisional_artifacts_with_locks_and_lease(
        snapshot,
        SplitCleanupOperationContext { state, session },
        journal_name,
        receipt_state,
        lock,
        receipt_lock,
        None,
    )
}

#[cfg(target_os = "macos")]
fn cleanup_provisional_artifacts_with_locks_and_lease(
    snapshot: &SplitPlanSnapshot,
    operation: SplitCleanupOperationContext<'_, '_>,
    journal_name: &OsStr,
    receipt_state: SplitReceiptCommitState,
    lock: &DestinationLock,
    receipt_lock: &ReceiptStateLock,
    mut cleanup_lease: Option<Box<dyn SplitTrustCleanupLease>>,
) -> Result<(), OperationFailureCode> {
    let state = operation.state;
    let session = operation.session;
    check_cancelled_if_attached(session)?;
    if !matches!(
        receipt_state,
        SplitReceiptCommitState::NotAttempted
            | SplitReceiptCommitState::ConfirmedUncommitted
            | SplitReceiptCommitState::Uncertain
    ) {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let mut journal = open_journal_writer(&state.destination_parent, journal_name)
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    let record = journal.record.clone();
    let mut cleanup_record = record.clone();
    if record.phase == JournalPhase::CleanupComplete {
        return Ok(());
    }
    if record.phase == JournalPhase::Completed {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    if !matches!(
        record.phase,
        JournalPhase::Prepared
            | JournalPhase::Staging
            | JournalPhase::Verified
            | JournalPhase::Publishing
            | JournalPhase::RolledBack
            | JournalPhase::Cleaning
    ) {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let parent_path = snapshot
        .bundle_directory
        .parent()
        .ok_or(OperationFailureCode::UnsafePath)?;
    let expected_parent = record
        .destination_parent_identity
        .as_deref()
        .and_then(parse_identity)
        .ok_or(OperationFailureCode::PublicationUncertain)?;
    if expected_parent != state.destination_parent_identity
        || handle_identity(&state.destination_parent) != Some(expected_parent)
        || validate_parent_identity(parent_path, expected_parent).is_err()
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let destination_name = decode_os_name(&record.destination_name_hex)
        .ok_or(OperationFailureCode::PublicationUncertain)?;
    let expected_destination = match record.destination_identity.as_deref() {
        Some(value) => {
            Some(parse_identity(value).ok_or(OperationFailureCode::PublicationUncertain)?)
        }
        None => None,
    };
    if current_directory_identity(&state.destination_parent, &destination_name)?
        != expected_destination
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    if record.journal_identity.is_none() {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    if !journal_record_is_valid(&record) {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    lock.validate(
        &state.destination_parent,
        state.destination_parent_identity,
        parent_path,
    )?;
    receipt_lock.validate(&state.destination_parent, lock)?;
    let staging_name = decode_os_name(&record.staging_name_hex)
        .ok_or(OperationFailureCode::PublicationUncertain)?;
    let root_path = vec![record.staging_name_hex.clone()];
    let root_artifact = record
        .artifacts
        .iter()
        .find(|artifact| artifact.relative_path_hex == root_path);
    let root_index = record
        .artifacts
        .iter()
        .position(|artifact| artifact.relative_path_hex == root_path);
    let public_root = open_optional_directory_at(&state.destination_parent, &staging_name)
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    let (cleanup_name, record_cleanup_intent) = if record.phase == JournalPhase::Cleaning {
        if record
            .cleanup_parent_identity
            .as_deref()
            .and_then(parse_identity)
            != Some(receipt_lock.directory_identity)
        {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        (
            record
                .cleanup_name_hex
                .as_deref()
                .and_then(decode_os_name)
                .ok_or(OperationFailureCode::PublicationUncertain)?,
            false,
        )
    } else {
        let cleanup_name = OsString::from(format!(".nscb-split-cleanup-{}", record.transaction_id));
        (cleanup_name, true)
    };
    let root_quarantine_name = root_index.map(|index| cleanup_quarantine_name(&record, index));
    let private_root = open_optional_directory_at(&receipt_lock.directory, &cleanup_name)
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    let private_root_quarantine = root_quarantine_name
        .as_deref()
        .map(|name| open_optional_directory_at(&receipt_lock.directory, name))
        .transpose()
        .map_err(|_| OperationFailureCode::PublicationUncertain)?
        .flatten();
    if public_root.is_some() && (private_root.is_some() || private_root_quarantine.is_some())
        || private_root.is_some() && private_root_quarantine.is_some()
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let Some(root_artifact) = root_artifact else {
        if public_root.is_none()
            && private_root.is_none()
            && private_root_quarantine.is_none()
            && record.phase != JournalPhase::Cleaning
        {
            return journal.append(JournalPhase::CleanupComplete, |_| {});
        }
        return Err(OperationFailureCode::PublicationUncertain);
    };
    let expected_root_identity = match &root_artifact.state {
        ArtifactState::Created(evidence) | ArtifactState::Verified(evidence) => {
            parse_identity(&evidence.identity).ok_or(OperationFailureCode::PublicationUncertain)?
        }
        ArtifactState::Planned => {
            if public_root.is_none()
                && private_root.is_none()
                && private_root_quarantine.is_none()
                && record.phase != JournalPhase::Cleaning
            {
                return journal.append(JournalPhase::CleanupComplete, |_| {});
            }
            return Err(OperationFailureCode::PublicationUncertain);
        }
    };
    let manifest_digest = record
        .manifest_sha256
        .as_deref()
        .and_then(|value| Sha256Digest::parse_hex(value).ok())
        .ok_or(OperationFailureCode::PublicationUncertain)?;
    if cleanup_lease.is_none() {
        let is_cancelled = || check_cancelled_if_attached(session).is_err();
        let acquired = state
            .trust_store
            .acquire_cleanup_lease(&manifest_digest, &is_cancelled);
        check_cancelled_if_attached(session)?;
        cleanup_lease = acquired.map_err(|_| OperationFailureCode::PublicationUncertain)?;
    }
    let _cleanup_lease = cleanup_lease.ok_or(OperationFailureCode::PublicationUncertain)?;
    check_cancelled_if_attached(session)?;
    if public_root.is_none()
        && private_root.is_none()
        && private_root_quarantine.is_none()
        && record.phase == JournalPhase::Cleaning
    {
        return journal.append(JournalPhase::CleanupComplete, |_| {});
    }
    if record_cleanup_intent {
        let cleanup_name_hex = encode_os_name(&cleanup_name);
        let cleanup_parent_identity = identity_string(receipt_lock.directory_identity);
        journal.append(JournalPhase::Cleaning, |record| {
            record.cleanup_name_hex = Some(cleanup_name_hex);
            record.cleanup_parent_identity = Some(cleanup_parent_identity);
        })?;
        cleanup_record = journal.record.clone();
    }
    let root = if let Some(root) = private_root.or(private_root_quarantine) {
        if handle_identity(&root) != Some(expected_root_identity) {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        preflight_cleanup_remainder(session, &root, root_artifact, &cleanup_record)?;
        root
    } else if let Some(root) = public_root {
        if handle_identity(&root) != Some(expected_root_identity)
            || parse_identity(&root_artifact.parent_identity)
                != Some(state.destination_parent_identity)
        {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        preflight_owned_directory(state, session, &root, root_artifact, &cleanup_record)?;
        let mut files = record
            .artifacts
            .iter()
            .filter(|artifact| artifact.kind == ArtifactKind::RegularFile)
            .collect::<Vec<_>>();
        files.sort_by_key(|artifact| std::cmp::Reverse(artifact.relative_path_hex.len()));
        #[cfg(test)]
        if matches!(
            state.test_failpoint,
            Some(
                SplitTestFailpoint::SubstituteArtifactAfterCleanupPreflight
                    | SplitTestFailpoint::ModifyAndRestoreArtifactAfterCleanupPreflight
            )
        ) {
            let artifact = record
                .artifacts
                .iter()
                .find(|artifact| artifact.kind == ArtifactKind::RegularFile)
                .ok_or(OperationFailureCode::PublicationUncertain)?;
            let parent =
                open_recorded_artifact_parent(&state.destination_parent, &record, artifact)
                    .map_err(|_| OperationFailureCode::PublicationUncertain)?;
            let name = artifact
                .relative_path_hex
                .last()
                .and_then(|value| decode_os_name(value))
                .ok_or(OperationFailureCode::PublicationUncertain)?;
            match state.test_failpoint {
                Some(SplitTestFailpoint::SubstituteArtifactAfterCleanupPreflight) => {
                    substitute_artifact_entry_for_test(&parent, &name)?;
                }
                Some(SplitTestFailpoint::ModifyAndRestoreArtifactAfterCleanupPreflight) => {
                    modify_and_restore_artifact_for_test(&parent, &name)?;
                }
                _ => unreachable!("guarded by the matching failpoint check"),
            }
        }
        ensure_destination_still_original(&state.destination_parent, &record)?;
        lock.validate(
            &state.destination_parent,
            state.destination_parent_identity,
            parent_path,
        )?;
        receipt_lock.validate(&state.destination_parent, lock)?;
        for artifact in files {
            revalidate_recorded_artifact_for_cleanup(state, session, &cleanup_record, artifact)?;
        }
        rename_exclusive_between_at(
            &state.destination_parent,
            &staging_name,
            &receipt_lock.directory,
            &cleanup_name,
        )
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        state
            .destination_parent
            .sync_all()
            .and_then(|()| receipt_lock.directory.sync_all())
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        check_cancelled_if_attached(session)?;
        let root = open_directory_at(&receipt_lock.directory, &cleanup_name)
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        if handle_identity(&root) != Some(expected_root_identity) {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        let refreshed =
            refresh_quarantined_file_evidence(&root, root_artifact, &cleanup_record, session)?;
        append_cleanup_artifact_evidence_updates(&mut journal, &refreshed)?;
        cleanup_record = journal.record.clone();
        let root_artifact_index = root_index.ok_or(OperationFailureCode::PublicationUncertain)?;
        let refreshed_root_artifact = cleanup_record
            .artifacts
            .get(root_artifact_index)
            .ok_or(OperationFailureCode::PublicationUncertain)?;
        #[cfg(test)]
        if state.test_failpoint
            == Some(SplitTestFailpoint::SimulatedInterruptionAfterCleanupQuarantine)
        {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        preflight_cleanup_remainder(session, &root, refreshed_root_artifact, &cleanup_record)?;
        root
    } else {
        return Err(OperationFailureCode::PublicationUncertain);
    };
    let root_artifact_index = root_index.ok_or(OperationFailureCode::PublicationUncertain)?;
    let cleanup_root_artifact = cleanup_record
        .artifacts
        .get(root_artifact_index)
        .ok_or(OperationFailureCode::PublicationUncertain)?;
    ensure_destination_still_original(&state.destination_parent, &record)?;
    receipt_lock.validate(&state.destination_parent, lock)?;
    check_cancelled_if_attached(session)?;
    delete_recorded_artifacts_from_root(
        &operation,
        &receipt_lock.directory,
        &cleanup_name,
        &root,
        cleanup_root_artifact,
        &cleanup_record,
        &mut journal,
    )?;
    receipt_lock
        .directory
        .sync_all()
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    check_cancelled_if_attached(session)?;
    journal.append(JournalPhase::CleanupComplete, |_| {})
}

#[cfg(target_os = "macos")]
fn cleanup_directory_matches(
    directory: &File,
    artifact: &JournalArtifact,
) -> Result<bool, OperationFailureCode> {
    let evidence = match &artifact.state {
        ArtifactState::Created(evidence) | ArtifactState::Verified(evidence)
            if artifact.kind == ArtifactKind::Directory =>
        {
            evidence
        }
        _ => return Ok(false),
    };
    let metadata = directory
        .metadata()
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    Ok(
        handle_identity(directory) == parse_identity(&evidence.identity)
            && metadata.file_type().is_dir()
            && metadata.mode() & 0o7777 == evidence.mode,
    )
}

#[cfg(target_os = "macos")]
fn preflight_cleanup_remainder(
    session: Option<&OperationSession>,
    directory: &File,
    artifact: &JournalArtifact,
    record: &JournalRecord,
) -> Result<(), OperationFailureCode> {
    check_cancelled_if_attached(session)?;
    if !cleanup_directory_matches(directory, artifact)? {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let actual_names = directory_child_names(directory)
        .map_err(|_| OperationFailureCode::PublicationUncertain)?
        .iter()
        .map(|name| encode_os_name(OsStr::from_bytes(name)))
        .collect::<HashSet<_>>();
    let prefix = artifact.relative_path_hex.clone();
    let parent_identity = handle_identity(directory);
    let children = record
        .artifacts
        .iter()
        .enumerate()
        .filter(|(_, child)| {
            child.relative_path_hex.len() == prefix.len() + 1
                && child.relative_path_hex[..prefix.len()] == prefix
        })
        .collect::<Vec<_>>();
    let mut allowed_names = HashSet::new();
    for (index, child) in children {
        check_cancelled_if_attached(session)?;
        let original_name = child.relative_path_hex[prefix.len()].clone();
        let quarantine_name = encode_os_name(&cleanup_quarantine_name(record, index));
        if original_name == quarantine_name
            || !allowed_names.insert(original_name.clone())
            || !allowed_names.insert(quarantine_name.clone())
        {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        let original_present = actual_names.contains(&original_name);
        let quarantine_present = actual_names.contains(&quarantine_name);
        if original_present && quarantine_present {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        if !original_present && !quarantine_present {
            continue;
        }
        if parse_identity(&child.parent_identity) != parent_identity {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        let child_evidence = match &child.state {
            ArtifactState::Created(evidence) | ArtifactState::Verified(evidence) => evidence,
            ArtifactState::Planned => return Err(OperationFailureCode::PublicationUncertain),
        };
        let name = decode_os_name(if quarantine_present {
            &quarantine_name
        } else {
            &original_name
        })
        .ok_or(OperationFailureCode::PublicationUncertain)?;
        match child.kind {
            ArtifactKind::Directory => {
                let opened = open_directory_at(directory, &name)
                    .map_err(|_| OperationFailureCode::PublicationUncertain)?;
                if !cleanup_directory_matches(&opened, child)? {
                    return Err(OperationFailureCode::PublicationUncertain);
                }
                if quarantine_present {
                    if !directory_child_names(&opened)
                        .map_err(|_| OperationFailureCode::PublicationUncertain)?
                        .is_empty()
                    {
                        return Err(OperationFailureCode::PublicationUncertain);
                    }
                } else {
                    preflight_cleanup_remainder(session, &opened, child, record)?;
                }
            }
            ArtifactKind::RegularFile => {
                let opened = open_file_at(directory, &name)
                    .map_err(|_| OperationFailureCode::PublicationUncertain)?;
                if !artifact_metadata_matches(&opened, child.kind, child_evidence)? {
                    return Err(OperationFailureCode::PublicationUncertain);
                }
            }
        }
    }
    if !actual_names.is_subset(&allowed_names) {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn cleanup_quarantine_name(record: &JournalRecord, artifact_index: usize) -> OsString {
    let transaction_key = Sha256Digest::digest(record.transaction_id.as_bytes()).to_hex();
    format!(".nscb-split-remove-{transaction_key}-{artifact_index:08x}").into()
}

#[cfg(target_os = "macos")]
fn open_artifact_parent_from_root(
    root: &File,
    record: &JournalRecord,
    artifact: &JournalArtifact,
) -> Result<Option<File>, OperationFailureCode> {
    if artifact.relative_path_hex.len() < 2 {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let mut parent = root
        .try_clone()
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    let mut prefix = vec![artifact.relative_path_hex[0].clone()];
    for encoded_name in &artifact.relative_path_hex[1..artifact.relative_path_hex.len() - 1] {
        prefix.push(encoded_name.clone());
        let directory_artifact = record
            .artifacts
            .iter()
            .find(|candidate| candidate.relative_path_hex == prefix)
            .ok_or(OperationFailureCode::PublicationUncertain)?;
        let name =
            decode_os_name(encoded_name).ok_or(OperationFailureCode::PublicationUncertain)?;
        let opened = match open_directory_at(&parent, &name) {
            Ok(opened) => opened,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(OperationFailureCode::PublicationUncertain),
        };
        if !cleanup_directory_matches(&opened, directory_artifact)? {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        parent = opened;
    }
    if handle_identity(&parent) != parse_identity(&artifact.parent_identity) {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    Ok(Some(parent))
}

#[cfg(target_os = "macos")]
fn entry_exists_at(parent: &File, name: &OsStr) -> Result<bool, OperationFailureCode> {
    let name = c_name(name).map_err(|_| OperationFailureCode::UnsafePath)?;
    // SAFETY: parent is open and name is one component. No symlink is followed.
    let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut status,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        Ok(true)
    } else {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(OperationFailureCode::PublicationUncertain)
        }
    }
}

#[cfg(target_os = "macos")]
fn remove_recorded_entry_at(
    operation: &SplitCleanupOperationContext<'_, '_>,
    parent: &File,
    original_name: &OsStr,
    quarantine_name: &OsStr,
    expected_parent_identity: FileIdentity,
    artifact_index: usize,
    journal: &mut JournalWriter,
) -> Result<(), OperationFailureCode> {
    let state = operation.state;
    let session = operation.session;
    let artifact = journal
        .record
        .artifacts
        .get(artifact_index)
        .cloned()
        .ok_or(OperationFailureCode::PublicationUncertain)?;
    check_cancelled_if_attached(session)?;
    #[cfg(not(test))]
    let _ = state;
    if handle_identity(parent) != Some(expected_parent_identity) {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let original_present = entry_exists_at(parent, original_name)?;
    let quarantine_present = entry_exists_at(parent, quarantine_name)?;
    if original_present && quarantine_present {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    if !original_present && !quarantine_present {
        return Ok(());
    }
    let original_evidence = match &artifact.state {
        ArtifactState::Created(evidence) | ArtifactState::Verified(evidence) => evidence.clone(),
        _ => return Err(OperationFailureCode::PublicationUncertain),
    };
    if original_present {
        let original = match artifact.kind {
            ArtifactKind::Directory => open_directory_at(parent, original_name),
            ArtifactKind::RegularFile => open_file_at(parent, original_name),
        }
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        if !artifact_metadata_matches(&original, artifact.kind, &original_evidence)?
            || artifact.kind == ArtifactKind::Directory
                && !directory_child_names(&original)
                    .map_err(|_| OperationFailureCode::PublicationUncertain)?
                    .is_empty()
        {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        // RENAME_EXCL atomically moves the entry that will be checked and
        // removed. A replacement left at the original name is never unlinked.
        // The destination is an owner-only 0700 namespace, and cooperating
        // NSCB operations hold the destination lock. This relies on same-volume
        // atomic rename semantics and excludes an uncoordinated process running
        // as the same effective user, which can bypass advisory locks.
        rename_exclusive_at(parent, original_name, quarantine_name)
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        parent
            .sync_all()
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    }

    let quarantined = match artifact.kind {
        ArtifactKind::Directory => open_directory_at(parent, quarantine_name),
        ArtifactKind::RegularFile => open_file_at(parent, quarantine_name),
    }
    .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    // This rename may update ctime. Persist its verified value before unlink; if interrupted before the journal append, stale evidence makes recovery retain the entry.
    if artifact.kind == ArtifactKind::RegularFile && original_present {
        let refreshed =
            refresh_regular_file_change_time(&quarantined, &original_evidence, session)?;
        append_cleanup_artifact_evidence_updates(journal, &[(artifact_index, refreshed)])?;
    }
    let evidence = match journal
        .record
        .artifacts
        .get(artifact_index)
        .map(|recorded| &recorded.state)
    {
        Some(ArtifactState::Created(evidence) | ArtifactState::Verified(evidence)) => evidence,
        _ => return Err(OperationFailureCode::PublicationUncertain),
    };
    let content_matches = match artifact.kind {
        ArtifactKind::Directory => cleanup_directory_matches(&quarantined, &artifact)?,
        ArtifactKind::RegularFile => cleanup_artifact_evidence_matches(
            state,
            session,
            &quarantined,
            artifact.kind,
            evidence,
        )?,
    };
    if !content_matches
        || artifact.kind == ArtifactKind::Directory
            && !directory_child_names(&quarantined)
                .map_err(|_| OperationFailureCode::PublicationUncertain)?
                .is_empty()
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }

    #[cfg(test)]
    if state.test_failpoint == Some(SplitTestFailpoint::SubstituteCleanupAliasAfterIdentityCheck)
        && artifact.kind == ArtifactKind::RegularFile
    {
        substitute_artifact_entry_for_test(parent, quarantine_name)?;
    }

    let final_entry = match artifact.kind {
        ArtifactKind::Directory => open_directory_at(parent, quarantine_name),
        ArtifactKind::RegularFile => open_file_at(parent, quarantine_name),
    }
    .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    let final_matches = match artifact.kind {
        ArtifactKind::Directory => cleanup_directory_matches(&final_entry, &artifact)?,
        ArtifactKind::RegularFile => {
            artifact_metadata_matches(&final_entry, artifact.kind, evidence)?
        }
    };
    if handle_identity(&final_entry) != handle_identity(&quarantined)
        || !final_matches
        || handle_identity(parent) != Some(expected_parent_identity)
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    if artifact.kind == ArtifactKind::Directory
        && !directory_child_names(&final_entry)
            .map_err(|_| OperationFailureCode::PublicationUncertain)?
            .is_empty()
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    #[cfg(test)]
    if state.test_failpoint == Some(SplitTestFailpoint::CancelBeforeArtifactUnlink)
        && let Some(session) = session
    {
        let _ = session.cancel();
    }
    check_cancelled_if_attached(session)?;
    unlink_owned_entry_at(parent, quarantine_name, artifact.kind)?;
    parent
        .sync_all()
        .map_err(|_| OperationFailureCode::PublicationUncertain)
}

#[cfg(target_os = "macos")]
fn delete_recorded_artifacts_from_root(
    operation: &SplitCleanupOperationContext<'_, '_>,
    private_directory: &File,
    cleanup_name: &OsStr,
    root: &File,
    root_artifact: &JournalArtifact,
    record: &JournalRecord,
    journal: &mut JournalWriter,
) -> Result<(), OperationFailureCode> {
    #[cfg(test)]
    let state = operation.state;
    let session = operation.session;
    let cleanup_parent_identity = record
        .cleanup_parent_identity
        .as_deref()
        .and_then(parse_identity)
        .ok_or(OperationFailureCode::PublicationUncertain)?;
    let mut files = record
        .artifacts
        .iter()
        .enumerate()
        .filter(|(_, artifact)| artifact.kind == ArtifactKind::RegularFile)
        .collect::<Vec<_>>();
    files.sort_by_key(|(_, artifact)| std::cmp::Reverse(artifact.relative_path_hex.len()));
    for (index, artifact) in files {
        check_cancelled_if_attached(session)?;
        let Some(parent) = open_artifact_parent_from_root(root, record, artifact)? else {
            continue;
        };
        let name = artifact
            .relative_path_hex
            .last()
            .and_then(|value| decode_os_name(value))
            .ok_or(OperationFailureCode::PublicationUncertain)?;
        let expected_parent = parse_identity(&artifact.parent_identity)
            .ok_or(OperationFailureCode::PublicationUncertain)?;
        remove_recorded_entry_at(
            operation,
            &parent,
            &name,
            &cleanup_quarantine_name(record, index),
            expected_parent,
            index,
            journal,
        )?;
        #[cfg(test)]
        if state.test_failpoint
            == Some(SplitTestFailpoint::SimulatedInterruptionAfterCleanupArtifactUnlink)
        {
            return Err(OperationFailureCode::PublicationUncertain);
        }
    }

    let mut directories = record
        .artifacts
        .iter()
        .enumerate()
        .filter(|(_, artifact)| {
            artifact.kind == ArtifactKind::Directory && artifact.relative_path_hex.len() > 1
        })
        .collect::<Vec<_>>();
    directories.sort_by_key(|(_, artifact)| std::cmp::Reverse(artifact.relative_path_hex.len()));
    for (index, artifact) in directories {
        check_cancelled_if_attached(session)?;
        let Some(parent) = open_artifact_parent_from_root(root, record, artifact)? else {
            continue;
        };
        let name = artifact
            .relative_path_hex
            .last()
            .and_then(|value| decode_os_name(value))
            .ok_or(OperationFailureCode::PublicationUncertain)?;
        let expected_parent = parse_identity(&artifact.parent_identity)
            .ok_or(OperationFailureCode::PublicationUncertain)?;
        remove_recorded_entry_at(
            operation,
            &parent,
            &name,
            &cleanup_quarantine_name(record, index),
            expected_parent,
            index,
            journal,
        )?;
    }

    let root_index = record
        .artifacts
        .iter()
        .position(|candidate| candidate.relative_path_hex == root_artifact.relative_path_hex)
        .ok_or(OperationFailureCode::PublicationUncertain)?;
    let root_identity = match &root_artifact.state {
        ArtifactState::Created(evidence) | ArtifactState::Verified(evidence) => {
            parse_identity(&evidence.identity)
        }
        ArtifactState::Planned => None,
    }
    .ok_or(OperationFailureCode::PublicationUncertain)?;
    if handle_identity(root) != Some(root_identity) {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    check_cancelled_if_attached(session)?;
    remove_recorded_entry_at(
        operation,
        private_directory,
        cleanup_name,
        &cleanup_quarantine_name(record, root_index),
        cleanup_parent_identity,
        root_index,
        journal,
    )
}

#[cfg(target_os = "macos")]
fn unlink_owned_entry_at(
    parent: &File,
    name: &OsStr,
    kind: ArtifactKind,
) -> Result<(), OperationFailureCode> {
    let name = c_name(name).map_err(|_| OperationFailureCode::UnsafePath)?;
    let flags = if kind == ArtifactKind::Directory {
        libc::AT_REMOVEDIR
    } else {
        0
    };
    // SAFETY: parent is an open directory and name is one path component.
    let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if result == 0 {
        Ok(())
    } else {
        Err(OperationFailureCode::PublicationUncertain)
    }
}

#[cfg(target_os = "macos")]
fn ensure_destination_still_original(
    parent: &File,
    record: &JournalRecord,
) -> Result<(), OperationFailureCode> {
    let name = decode_os_name(&record.destination_name_hex)
        .ok_or(OperationFailureCode::PublicationUncertain)?;
    let expected = match record.destination_identity.as_deref() {
        Some(value) => {
            Some(parse_identity(value).ok_or(OperationFailureCode::PublicationUncertain)?)
        }
        None => None,
    };
    if current_directory_identity(parent, &name)? == expected {
        Ok(())
    } else {
        Err(OperationFailureCode::PublicationUncertain)
    }
}

#[cfg(target_os = "macos")]
fn open_directory_at(parent: &File, name: &OsStr) -> io::Result<File> {
    let name = c_name(name)?;
    // SAFETY: parent is open and name is one component.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor owned by this function.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(target_os = "macos")]
fn publish_bundle(
    publication: &DestinationPublication<'_>,
    staging_name: &OsStr,
    staged_identity: FileIdentity,
    old_identity: Option<FileIdentity>,
) -> Result<(), OperationFailureCode> {
    let parent = publication.parent;
    let destination_name = publication.destination_name;
    publication.validate_lock()?;
    if current_directory_identity(parent, destination_name)? != old_identity
        || current_directory_identity(parent, staging_name)? != Some(staged_identity)
    {
        return Err(OperationFailureCode::DestinationChanged);
    }
    publication.validate_lock()?;
    if let Some(old_identity) = old_identity {
        if !crate::operation::volume_supports_rename_swap(parent) {
            return Err(OperationFailureCode::UnsupportedCapability);
        }
        #[cfg(test)]
        if publication.test_failpoint
            == Some(SplitTestFailpoint::SubstituteDestinationBetweenCheckAndSwap)
        {
            substitute_destination_for_test(parent, destination_name)?;
        }
        if current_directory_identity(parent, destination_name)? != Some(old_identity) {
            return Err(OperationFailureCode::DestinationChanged);
        }
        publication.validate_lock()?;
        rename_swap_at(parent, staging_name, destination_name)
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    } else {
        rename_exclusive_at(parent, staging_name, destination_name)
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    }
    #[cfg(test)]
    if publication.test_failpoint == Some(SplitTestFailpoint::SubstituteDestinationAfterPromotion) {
        substitute_destination_for_test(parent, destination_name)?;
    }
    let destination_after = current_directory_identity(parent, destination_name)
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    let staging_after = current_directory_identity(parent, staging_name)
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    if destination_after != Some(staged_identity)
        || staging_after != old_identity
        || publication.validate_lock().is_err()
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    parent
        .sync_all()
        .map_err(|_| OperationFailureCode::PublicationUncertain)
}

#[cfg(all(test, target_os = "macos"))]
fn substitute_destination_for_test(
    parent: &File,
    destination_name: &OsStr,
) -> Result<(), OperationFailureCode> {
    let mut preserved_name = destination_name.to_os_string();
    preserved_name.push(".external-original");
    rename_exclusive_at(parent, destination_name, &preserved_name)
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    create_foreign_destination_for_test(parent, destination_name)
}

#[cfg(all(test, target_os = "macos"))]
fn create_foreign_destination_for_test(
    parent: &File,
    destination_name: &OsStr,
) -> Result<(), OperationFailureCode> {
    mkdir_at(parent, destination_name)?;
    let foreign_directory = open_directory_at(parent, destination_name)
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    let mut sentinel = create_file_at(&foreign_directory, OsStr::new("concurrent-owner-data"))
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    sentinel
        .write_all(b"concurrent destination")
        .and_then(|()| sentinel.sync_all())
        .and_then(|()| foreign_directory.sync_all())
        .map_err(|_| OperationFailureCode::PublicationUncertain)
}

#[cfg(target_os = "macos")]
fn rename_exclusive_at(parent: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
    let from = c_name(from)?;
    let to = c_name(to)?;
    // SAFETY: parent is open and both names are single components. RENAME_EXCL
    // refuses a concurrently appearing destination instead of replacing it.
    let result = unsafe {
        libc::renameatx_np(
            parent.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn rename_swap_at(parent: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
    let from = c_name(from)?;
    let to = c_name(to)?;
    // SAFETY: parent is open and both names are single components. RENAME_SWAP
    // exchanges both entries atomically, preserving the previous destination.
    let result = unsafe {
        libc::renameatx_np(
            parent.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_SWAP,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn rename_exclusive_between_at(
    source_parent: &File,
    source_name: &OsStr,
    destination_parent: &File,
    destination_name: &OsStr,
) -> io::Result<()> {
    let source_name = c_name(source_name)?;
    let destination_name = c_name(destination_name)?;
    // SAFETY: both parents are open directories and both names are one component.
    let result = unsafe {
        libc::renameatx_np(
            source_parent.as_raw_fd(),
            source_name.as_ptr(),
            destination_parent.as_raw_fd(),
            destination_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn identity_string(identity: FileIdentity) -> String {
    format!("{:016x}:{:016x}", identity.device(), identity.inode())
}

#[cfg(target_os = "macos")]
fn parse_identity(value: &str) -> Option<FileIdentity> {
    let (device, inode) = value.split_once(':')?;
    Some(FileIdentity::from_parts(
        u64::from_str_radix(device, 16).ok()?,
        u64::from_str_radix(inode, 16).ok()?,
    ))
}

#[cfg(target_os = "macos")]
fn encode_os_name(name: &OsStr) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(name.as_bytes().len() * 2);
    for byte in name.as_bytes() {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

#[cfg(target_os = "macos")]
fn decode_os_name(value: &str) -> Option<OsString> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().as_chunks::<2>().0 {
        let high = u8::from_str_radix(std::str::from_utf8(&pair[..1]).ok()?, 16).ok()?;
        let low = u8::from_str_radix(std::str::from_utf8(&pair[1..]).ok()?, 16).ok()?;
        bytes.push((high << 4) | low);
    }
    let name = OsString::from_vec(bytes);
    if Path::new(&name).components().count() == 1
        && name != OsStr::new(".")
        && name != OsStr::new("..")
    {
        Some(name)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn path_for_name(parent: &Path, name: &OsStr) -> PathBuf {
    parent.join(name)
}

#[cfg(target_os = "macos")]
fn recovery_path_after_failed_publication(
    parent: &File,
    destination_name: &OsStr,
    staging_name: &OsStr,
    lock: &DestinationLock,
    expected_parent_identity: FileIdentity,
    parent_path: &Path,
    staged_identity: FileIdentity,
) -> Option<PathBuf> {
    lock.validate(parent, expected_parent_identity, parent_path)
        .ok()?;
    if current_directory_identity(parent, destination_name).ok() == Some(Some(staged_identity)) {
        Some(path_for_name(parent_path, destination_name))
    } else if current_directory_identity(parent, staging_name).ok() == Some(Some(staged_identity)) {
        Some(path_for_name(parent_path, staging_name))
    } else {
        // The journal remains the durable inventory when displacement leaves no
        // planned name bound to the staged directory identity.
        None
    }
}

#[cfg(target_os = "macos")]
fn recovery_path_for_recorded_bundle(
    snapshot: &SplitPlanSnapshot,
    record: &JournalRecord,
) -> Option<PathBuf> {
    let parent_path = snapshot.bundle_directory.parent()?;
    let expected_parent = record
        .destination_parent_identity
        .as_deref()
        .and_then(parse_identity)?;
    if validate_parent_identity(parent_path, expected_parent).is_err() {
        return None;
    }
    let parent = open_directory(parent_path).ok()?;
    if handle_identity(&parent) != Some(expected_parent) {
        return None;
    }
    let staged_identity = record
        .staging_identity
        .as_deref()
        .and_then(parse_identity)
        .or_else(|| {
            let root_path = vec![record.staging_name_hex.clone()];
            record
                .artifacts
                .iter()
                .find(|artifact| artifact.relative_path_hex == root_path)
                .and_then(|artifact| match &artifact.state {
                    ArtifactState::Created(evidence) | ArtifactState::Verified(evidence) => {
                        parse_identity(&evidence.identity)
                    }
                    ArtifactState::Planned => None,
                })
        })?;
    let destination_name = decode_os_name(&record.destination_name_hex)?;
    if current_directory_identity(&parent, &destination_name).ok() == Some(Some(staged_identity)) {
        return Some(parent_path.join(destination_name));
    }
    let staging_name = decode_os_name(&record.staging_name_hex)?;
    if current_directory_identity(&parent, &staging_name).ok() == Some(Some(staged_identity)) {
        return Some(parent_path.join(staging_name));
    }
    if record.phase == JournalPhase::Cleaning {
        let expected_cleanup_parent = record
            .cleanup_parent_identity
            .as_deref()
            .and_then(parse_identity)?;
        let lock_directory =
            open_directory_at(&parent, OsStr::new(SPLIT_LOCK_DIRECTORY_NAME)).ok()?;
        if handle_identity(&lock_directory) != Some(expected_cleanup_parent) {
            return None;
        }
        let cleanup_name = record
            .cleanup_name_hex
            .as_deref()
            .and_then(decode_os_name)?;
        if current_directory_identity(&lock_directory, &cleanup_name).ok()
            == Some(Some(staged_identity))
        {
            return Some(
                parent_path
                    .join(SPLIT_LOCK_DIRECTORY_NAME)
                    .join(cleanup_name),
            );
        }
        let root_path = vec![record.staging_name_hex.clone()];
        let root_index = record
            .artifacts
            .iter()
            .position(|artifact| artifact.relative_path_hex == root_path)?;
        let quarantine_name = cleanup_quarantine_name(record, root_index);
        if current_directory_identity(&lock_directory, &quarantine_name).ok()
            == Some(Some(staged_identity))
        {
            return Some(
                parent_path
                    .join(SPLIT_LOCK_DIRECTORY_NAME)
                    .join(quarantine_name),
            );
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn check_cancelled(session: &OperationSession) -> Result<(), OperationFailureCode> {
    if session.cancellation_requested()? {
        session.record_observed_cancellation();
        Err(OperationFailureCode::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn check_cancelled_if_attached(
    session: Option<&OperationSession>,
) -> Result<(), OperationFailureCode> {
    session.map_or(Ok(()), check_cancelled)
}

#[cfg(target_os = "macos")]
fn published_bundle_matches(
    snapshot: &SplitPlanSnapshot,
    state: &SplitPlanState<'_>,
    staged: &StagedBundle,
    session: Option<&OperationSession>,
) -> Result<(), OperationFailureCode> {
    check_cancelled_if_attached(session)?;
    let bytes = read_split_manifest_bytes(&snapshot.manifest_path)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    if Sha256Digest::digest(&bytes) != staged.manifest_sha256 {
        return Err(OperationFailureCode::ValidationFailed);
    }
    let manifest = crate::split_manifest::parse_manifest(&bytes)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    let expected_lengths = manifest
        .segments
        .iter()
        .map(|item| item.size)
        .collect::<Vec<_>>();
    if manifest.source_size != snapshot.source.size()
        || manifest.source_sha256 != state.source_sha256
        || expected_lengths != snapshot.segment_lengths
    {
        return Err(OperationFailureCode::ValidationFailed);
    }
    verify_bundle_parts(
        snapshot,
        state,
        &snapshot.bundle_directory,
        &manifest.segments,
        session,
    )
    .map(|_| ())
}

#[cfg(target_os = "macos")]
fn rollback_published(
    snapshot: &SplitPlanSnapshot,
    state: &SplitPlanState<'_>,
    journal: &mut JournalWriter,
    lock: &DestinationLock,
    session: Option<&OperationSession>,
    code: OperationFailureCode,
) -> Result<SplitRunSuccess, SplitRunFailure> {
    let receipt_lock = ReceiptStateLock::acquire(&state.destination_parent, lock, session)
        .map_err(|acquire_error| SplitRunFailure {
            code: if acquire_error == OperationFailureCode::Cancelled {
                OperationFailureCode::Cancelled
            } else {
                OperationFailureCode::PublicationUncertain
            },
            receipt_state: SplitReceiptCommitState::Uncertain,
            recovery_path: recovery_path_for_recorded_bundle(snapshot, &journal.record),
            retained: true,
        })?;
    rollback_published_with_receipt_lock(
        snapshot,
        state,
        journal,
        lock,
        &receipt_lock,
        session,
        code,
    )
}

#[cfg(target_os = "macos")]
fn rollback_published_with_receipt_lock(
    snapshot: &SplitPlanSnapshot,
    state: &SplitPlanState<'_>,
    journal: &mut JournalWriter,
    lock: &DestinationLock,
    receipt_lock: &ReceiptStateLock,
    session: Option<&OperationSession>,
    code: OperationFailureCode,
) -> Result<SplitRunSuccess, SplitRunFailure> {
    rollback_published_with_cleanup_lease(
        snapshot,
        SplitCleanupOperationContext { state, session },
        journal,
        lock,
        receipt_lock,
        code,
        None,
    )
}

#[cfg(target_os = "macos")]
fn rollback_published_with_cleanup_lease(
    snapshot: &SplitPlanSnapshot,
    operation: SplitCleanupOperationContext<'_, '_>,
    journal: &mut JournalWriter,
    lock: &DestinationLock,
    receipt_lock: &ReceiptStateLock,
    code: OperationFailureCode,
    mut cleanup_lease: Option<Box<dyn SplitTrustCleanupLease>>,
) -> Result<SplitRunSuccess, SplitRunFailure> {
    let state = operation.state;
    let session = operation.session;
    let Some(parent_path) = snapshot.bundle_directory.parent() else {
        return Err(plain_failure(OperationFailureCode::UnsafePath));
    };
    macro_rules! failure {
        ($code:expr, $receipt_state:expr, $retained:expr $(,)?) => {
            SplitRunFailure {
                code: $code,
                receipt_state: $receipt_state,
                recovery_path: recovery_path_for_recorded_bundle(snapshot, &journal.record),
                retained: $retained,
            }
        };
    }
    if lock
        .validate(
            &state.destination_parent,
            state.destination_parent_identity,
            parent_path,
        )
        .is_err()
        || receipt_lock
            .validate(&state.destination_parent, lock)
            .is_err()
    {
        return Err(failure!(
            OperationFailureCode::PublicationUncertain,
            SplitReceiptCommitState::Uncertain,
            true,
        ));
    }
    let publication = DestinationPublication {
        parent: &state.destination_parent,
        destination_name: &state.destination_name,
        lock,
        parent_identity: state.destination_parent_identity,
        parent_path,
        #[cfg(test)]
        test_failpoint: state.test_failpoint,
    };
    let staging_name = decode_os_name(&journal.record.staging_name_hex).ok_or_else(|| {
        failure!(
            OperationFailureCode::PublicationUncertain,
            SplitReceiptCommitState::Uncertain,
            true,
        )
    })?;
    let staged_identity = journal
        .record
        .staging_identity
        .as_deref()
        .and_then(parse_identity)
        .ok_or_else(|| {
            failure!(
                OperationFailureCode::PublicationUncertain,
                SplitReceiptCommitState::Uncertain,
                true,
            )
        })?;
    let old_identity = match journal.record.destination_identity.as_deref() {
        Some(value) => Some(parse_identity(value).ok_or_else(|| {
            failure!(
                OperationFailureCode::PublicationUncertain,
                SplitReceiptCommitState::Uncertain,
                true,
            )
        })?),
        None => None,
    };
    let manifest_digest = journal
        .record
        .manifest_sha256
        .as_deref()
        .and_then(|value| Sha256Digest::parse_hex(value).ok())
        .ok_or_else(|| {
            failure!(
                OperationFailureCode::PublicationUncertain,
                SplitReceiptCommitState::Uncertain,
                true,
            )
        })?;
    let cleanup_lease = match cleanup_lease.take() {
        Some(lease) => lease,
        None => {
            let is_cancelled = || check_cancelled_if_attached(session).is_err();
            let acquired = state
                .trust_store
                .acquire_cleanup_lease(&manifest_digest, &is_cancelled);
            if let Err(code) = check_cancelled_if_attached(session) {
                return Err(failure!(code, SplitReceiptCommitState::Uncertain, true));
            }
            match acquired {
                Ok(Some(lease)) => lease,
                Ok(None) | Err(_) => {
                    return Err(failure!(
                        OperationFailureCode::PublicationUncertain,
                        SplitReceiptCommitState::Uncertain,
                        true,
                    ));
                }
            }
        }
    };
    if let Err(code) = check_cancelled_if_attached(session) {
        return Err(failure!(code, SplitReceiptCommitState::Uncertain, true));
    }

    #[cfg(test)]
    if publication.test_failpoint
        == Some(SplitTestFailpoint::SubstituteStagingBeforeRollbackIdentityCheck)
    {
        if old_identity.is_some() {
            substitute_destination_for_test(publication.parent, &staging_name)
                .expect("rollback race fixture must substitute the staging entry");
        } else {
            create_foreign_destination_for_test(publication.parent, &staging_name)
                .expect("rollback race fixture must occupy the staging entry");
        }
    }

    let receipt_state = SplitReceiptCommitState::ConfirmedUncommitted;
    let paths_match = publication.validate_lock().is_ok()
        && current_directory_identity(publication.parent, publication.destination_name)
            .is_ok_and(|identity| identity == Some(staged_identity))
        && current_directory_identity(publication.parent, &staging_name)
            .is_ok_and(|identity| identity == old_identity);
    if !paths_match {
        return Err(failure!(
            OperationFailureCode::PublicationUncertain,
            receipt_state,
            true,
        ));
    }
    if let Err(preflight_error) = preflight_recorded_bundle_at(
        state,
        session,
        publication.parent,
        publication.destination_name,
        &journal.record,
        staged_identity,
    ) {
        let _ = journal.append(JournalPhase::Uncertain, |_| {});
        return Err(failure!(
            if preflight_error == OperationFailureCode::Cancelled {
                OperationFailureCode::Cancelled
            } else {
                OperationFailureCode::PublicationUncertain
            },
            SplitReceiptCommitState::ConfirmedUncommitted,
            true,
        ));
    }
    receipt_lock
        .validate(&state.destination_parent, lock)
        .map_err(|_| {
            failure!(
                OperationFailureCode::PublicationUncertain,
                SplitReceiptCommitState::Uncertain,
                true,
            )
        })?;
    publication.validate_lock().map_err(|_| {
        failure!(
            OperationFailureCode::PublicationUncertain,
            SplitReceiptCommitState::Uncertain,
            true,
        )
    })?;
    if old_identity.is_some() {
        rename_swap_at(
            publication.parent,
            &staging_name,
            publication.destination_name,
        )
        .map_err(|_| {
            failure!(
                OperationFailureCode::PublicationUncertain,
                SplitReceiptCommitState::ConfirmedUncommitted,
                true,
            )
        })?;
    } else {
        rename_exclusive_at(
            publication.parent,
            publication.destination_name,
            &staging_name,
        )
        .map_err(|_| {
            failure!(
                OperationFailureCode::PublicationUncertain,
                SplitReceiptCommitState::ConfirmedUncommitted,
                true,
            )
        })?;
    }
    let restored_destination =
        current_directory_identity(publication.parent, publication.destination_name).map_err(
            |_| {
                failure!(
                    OperationFailureCode::PublicationUncertain,
                    SplitReceiptCommitState::Uncertain,
                    true,
                )
            },
        )?;
    let restored_staging =
        current_directory_identity(publication.parent, &staging_name).map_err(|_| {
            failure!(
                OperationFailureCode::PublicationUncertain,
                SplitReceiptCommitState::Uncertain,
                true,
            )
        })?;
    if restored_destination != old_identity || restored_staging != Some(staged_identity) {
        let _ = journal.append(JournalPhase::Uncertain, |_| {});
        return Err(failure!(
            OperationFailureCode::PublicationUncertain,
            SplitReceiptCommitState::ConfirmedUncommitted,
            true,
        ));
    }
    publication.parent.sync_all().map_err(|_| {
        failure!(
            OperationFailureCode::PublicationUncertain,
            SplitReceiptCommitState::ConfirmedUncommitted,
            true,
        )
    })?;
    journal
        .append(JournalPhase::RolledBack, |_| {})
        .map_err(|_| {
            failure!(
                OperationFailureCode::PublicationUncertain,
                SplitReceiptCommitState::ConfirmedUncommitted,
                true,
            )
        })?;
    let journal_name = OsString::from(format!(
        ".nscb-split-{}.journal",
        journal.record.transaction_id
    ));
    match cleanup_provisional_artifacts_with_locks_and_lease(
        snapshot,
        operation,
        &journal_name,
        SplitReceiptCommitState::ConfirmedUncommitted,
        lock,
        receipt_lock,
        Some(cleanup_lease),
    ) {
        Ok(()) => Err(SplitRunFailure {
            code,
            receipt_state: SplitReceiptCommitState::ConfirmedUncommitted,
            recovery_path: None,
            retained: false,
        }),
        Err(cleanup_code) => Err(failure!(
            if matches!(
                cleanup_code,
                OperationFailureCode::Cancelled | OperationFailureCode::SessionUnavailable
            ) {
                cleanup_code
            } else {
                OperationFailureCode::PublicationUncertain
            },
            SplitReceiptCommitState::ConfirmedUncommitted,
            true,
        )),
    }
}

#[cfg(target_os = "macos")]
fn recover_incomplete_for_destination(
    snapshot: &SplitPlanSnapshot,
    state: &SplitPlanState<'_>,
    lock: &DestinationLock,
    session: Option<&OperationSession>,
    artifact_sources: &mut SplitArtifactSources,
) -> Result<(), SplitRunFailure> {
    let parent_path = snapshot
        .bundle_directory
        .parent()
        .ok_or_else(|| plain_failure(OperationFailureCode::UnsafePath))?;
    if lock
        .validate(
            &state.destination_parent,
            state.destination_parent_identity,
            parent_path,
        )
        .is_err()
    {
        return Err(SplitRunFailure {
            code: OperationFailureCode::PublicationUncertain,
            receipt_state: SplitReceiptCommitState::Uncertain,
            recovery_path: None,
            retained: true,
        });
    }
    let receipt_lock = ReceiptStateLock::acquire(&state.destination_parent, lock, session)
        .map_err(|acquire_error| SplitRunFailure {
            code: if acquire_error == OperationFailureCode::Cancelled {
                OperationFailureCode::Cancelled
            } else {
                OperationFailureCode::PublicationUncertain
            },
            receipt_state: SplitReceiptCommitState::Uncertain,
            recovery_path: None,
            retained: true,
        })?;
    let entries = fs::read_dir(parent_path)
        .map_err(|_| plain_failure(OperationFailureCode::DestinationUnavailable))?;
    let target_name = encode_os_name(&state.destination_name);
    for entry in entries {
        check_cancelled_if_attached(session).map_err(|code| SplitRunFailure {
            code,
            receipt_state: SplitReceiptCommitState::Uncertain,
            recovery_path: None,
            retained: true,
        })?;
        let entry =
            entry.map_err(|_| plain_failure(OperationFailureCode::DestinationUnavailable))?;
        let name = entry.file_name();
        let bytes = name.as_bytes();
        if !bytes.starts_with(b".nscb-split-") || !bytes.ends_with(b".journal") {
            continue;
        }
        let mut writer = match open_journal_writer(&state.destination_parent, &name) {
            Ok(writer) => writer,
            Err(_) => {
                artifact_sources.push_journal(name);
                return Err(SplitRunFailure {
                    code: OperationFailureCode::PublicationUncertain,
                    receipt_state: SplitReceiptCommitState::Uncertain,
                    recovery_path: None,
                    retained: true,
                });
            }
        };
        let record = writer.record.clone();
        if record.destination_name_hex != target_name {
            continue;
        }
        if matches!(
            record.phase,
            JournalPhase::Completed | JournalPhase::CleanupComplete
        ) {
            continue;
        }
        artifact_sources.push_journal(name.clone());
        if record.phase == JournalPhase::Uncertain {
            return Err(recovery_failure(
                snapshot,
                &record,
                SplitReceiptCommitState::Uncertain,
            ));
        }
        if record
            .destination_parent_identity
            .as_deref()
            .and_then(parse_identity)
            != Some(state.destination_parent_identity)
        {
            return Err(recovery_failure(
                snapshot,
                &record,
                SplitReceiptCommitState::Uncertain,
            ));
        }
        if matches!(
            record.phase,
            JournalPhase::Prepared
                | JournalPhase::Staging
                | JournalPhase::Verified
                | JournalPhase::Cleaning
        ) {
            let original_identity = match record.destination_identity.as_deref() {
                Some(value) => Some(parse_identity(value).ok_or_else(|| {
                    recovery_failure(snapshot, &record, SplitReceiptCommitState::Uncertain)
                })?),
                None => None,
            };
            if current_directory_identity(&state.destination_parent, &state.destination_name)
                .map_err(|_| {
                    recovery_failure(snapshot, &record, SplitReceiptCommitState::Uncertain)
                })?
                != original_identity
            {
                return Err(recovery_failure(
                    snapshot,
                    &record,
                    SplitReceiptCommitState::Uncertain,
                ));
            }
            cleanup_provisional_artifacts_with_locks(
                snapshot,
                state,
                &name,
                SplitReceiptCommitState::Uncertain,
                lock,
                &receipt_lock,
                session,
            )
            .map_err(|code| {
                recovery_cleanup_failure(
                    snapshot,
                    &record,
                    SplitReceiptCommitState::Uncertain,
                    code,
                )
            })?;
            continue;
        }
        if record.phase == JournalPhase::RolledBack {
            let original_identity = match record.destination_identity.as_deref() {
                Some(value) => Some(parse_identity(value).ok_or_else(|| {
                    recovery_failure(snapshot, &record, SplitReceiptCommitState::Uncertain)
                })?),
                None => None,
            };
            if current_directory_identity(&state.destination_parent, &state.destination_name)
                .map_err(|_| {
                    recovery_failure(snapshot, &record, SplitReceiptCommitState::Uncertain)
                })?
                != original_identity
            {
                return Err(recovery_failure(
                    snapshot,
                    &record,
                    SplitReceiptCommitState::Uncertain,
                ));
            }
            cleanup_provisional_artifacts_with_locks(
                snapshot,
                state,
                &name,
                SplitReceiptCommitState::Uncertain,
                lock,
                &receipt_lock,
                session,
            )
            .map_err(|code| {
                recovery_cleanup_failure(
                    snapshot,
                    &record,
                    SplitReceiptCommitState::Uncertain,
                    code,
                )
            })?;
            continue;
        }
        let Some(staged_identity) = record.staging_identity.as_deref().and_then(parse_identity)
        else {
            return Err(recovery_failure(
                snapshot,
                &record,
                SplitReceiptCommitState::Uncertain,
            ));
        };
        let old_identity = match record.destination_identity.as_deref() {
            Some(value) => Some(parse_identity(value).ok_or_else(|| {
                recovery_failure(snapshot, &record, SplitReceiptCommitState::Uncertain)
            })?),
            None => None,
        };
        let staging_name = decode_os_name(&record.staging_name_hex).ok_or_else(|| {
            recovery_failure(snapshot, &record, SplitReceiptCommitState::Uncertain)
        })?;
        let _canonical_name = decode_os_name(&record.canonical_name_hex).ok_or_else(|| {
            recovery_failure(snapshot, &record, SplitReceiptCommitState::Uncertain)
        })?;
        let manifest_digest = record
            .manifest_sha256
            .as_deref()
            .and_then(|value| Sha256Digest::parse_hex(value).ok())
            .ok_or_else(|| {
                recovery_failure(snapshot, &record, SplitReceiptCommitState::Uncertain)
            })?;
        let destination_now =
            current_directory_identity(&state.destination_parent, &state.destination_name)
                .map_err(|_| {
                    recovery_failure(snapshot, &record, SplitReceiptCommitState::Uncertain)
                })?;
        let staging_now = current_directory_identity(&state.destination_parent, &staging_name)
            .map_err(|_| recovery_failure(snapshot, &record, SplitReceiptCommitState::Uncertain))?;
        let (published, not_published) = if let Some(old_identity) = old_identity {
            (
                destination_now == Some(staged_identity) && staging_now == Some(old_identity),
                destination_now == Some(old_identity) && staging_now == Some(staged_identity),
            )
        } else {
            (
                destination_now == Some(staged_identity) && staging_now.is_none(),
                destination_now.is_none() && staging_now == Some(staged_identity),
            )
        };
        if !published && !not_published {
            return Err(recovery_failure(
                snapshot,
                &record,
                SplitReceiptCommitState::Uncertain,
            ));
        }

        let is_cancelled = || check_cancelled_if_attached(session).is_err();
        let receipt_result = state
            .trust_store
            .lookup_for_recovery(&manifest_digest, &is_cancelled);
        if let Err(code) = check_cancelled_if_attached(session) {
            return Err(SplitRunFailure {
                code,
                receipt_state: SplitReceiptCommitState::Uncertain,
                recovery_path: recovery_path_for_recorded_bundle(snapshot, &record),
                retained: true,
            });
        }
        let receipt = receipt_result
            .map_err(|_| recovery_failure(snapshot, &record, SplitReceiptCommitState::Uncertain))?;
        match receipt {
            Some(receipt)
                if !receipt.is_revoked()
                    && receipt.source_size_bytes() == record.source_size
                    && receipt.source_sha256().to_hex() == record.source_sha256
                    && receipt.manifest_sha256() == &manifest_digest =>
            {
                if !published
                    || !recorded_bundle_is_trusted(parent_path, &record, &manifest_digest, &receipt)
                {
                    return Err(recovery_failure(
                        snapshot,
                        &record,
                        SplitReceiptCommitState::Uncertain,
                    ));
                }
                if let Err(code) = check_cancelled_if_attached(session) {
                    return Err(SplitRunFailure {
                        code,
                        receipt_state: SplitReceiptCommitState::Uncertain,
                        recovery_path: recovery_path_for_recorded_bundle(snapshot, &record),
                        retained: true,
                    });
                }
                writer
                    .append(JournalPhase::ReceiptCommitted, |_| {})
                    .and_then(|()| writer.append(JournalPhase::Completed, |_| {}))
                    .map_err(|_| {
                        recovery_failure(
                            snapshot,
                            &record,
                            SplitReceiptCommitState::ConfirmedCommitted,
                        )
                    })?;
            }
            None if record.phase == JournalPhase::ReceiptCommitted => {
                let _ = writer.append(JournalPhase::Uncertain, |_| {});
                return Err(recovery_failure(
                    snapshot,
                    &record,
                    SplitReceiptCommitState::Uncertain,
                ));
            }
            None => {
                let publication_context = DestinationPublication {
                    parent: &state.destination_parent,
                    destination_name: &state.destination_name,
                    lock,
                    parent_identity: state.destination_parent_identity,
                    parent_path,
                    #[cfg(test)]
                    test_failpoint: state.test_failpoint,
                };
                validate_interrupted_transaction(
                    &publication_context,
                    &staging_name,
                    staged_identity,
                    old_identity,
                    published,
                )
                .map_err(|_| SplitRunFailure {
                    code: OperationFailureCode::PublicationUncertain,
                    receipt_state: SplitReceiptCommitState::Uncertain,
                    recovery_path: recovery_path_for_recorded_bundle(snapshot, &record),
                    retained: true,
                })?;
                let is_cancelled = || check_cancelled_if_attached(session).is_err();
                let cleanup_lease = state
                    .trust_store
                    .acquire_cleanup_lease(&manifest_digest, &is_cancelled);
                if let Err(code) = check_cancelled_if_attached(session) {
                    return Err(SplitRunFailure {
                        code,
                        receipt_state: SplitReceiptCommitState::Uncertain,
                        recovery_path: recovery_path_for_recorded_bundle(snapshot, &record),
                        retained: true,
                    });
                }
                let cleanup_lease = cleanup_lease.map_err(|_| {
                    recovery_failure(snapshot, &record, SplitReceiptCommitState::Uncertain)
                })?;
                let Some(cleanup_lease) = cleanup_lease else {
                    return Err(recovery_failure(
                        snapshot,
                        &record,
                        SplitReceiptCommitState::Uncertain,
                    ));
                };
                if published {
                    match rollback_published_with_cleanup_lease(
                        snapshot,
                        SplitCleanupOperationContext { state, session },
                        &mut writer,
                        lock,
                        &receipt_lock,
                        OperationFailureCode::PublicationUncertain,
                        Some(cleanup_lease),
                    ) {
                        Err(failure) if !failure.retained => continue,
                        Err(failure) => return Err(failure),
                        Ok(_) => unreachable!("rollback never reports success"),
                    }
                }
                writer
                    .append(JournalPhase::RolledBack, |_| {})
                    .map_err(|_| {
                        recovery_failure(
                            snapshot,
                            &record,
                            SplitReceiptCommitState::ConfirmedUncommitted,
                        )
                    })?;
                cleanup_provisional_artifacts_with_locks_and_lease(
                    snapshot,
                    SplitCleanupOperationContext { state, session },
                    &name,
                    SplitReceiptCommitState::ConfirmedUncommitted,
                    lock,
                    &receipt_lock,
                    Some(cleanup_lease),
                )
                .map_err(|code| {
                    recovery_cleanup_failure(
                        snapshot,
                        &record,
                        SplitReceiptCommitState::ConfirmedUncommitted,
                        code,
                    )
                })?;
            }
            Some(_) => {
                let _ = writer.append(JournalPhase::Uncertain, |_| {});
                return Err(recovery_failure(
                    snapshot,
                    &record,
                    SplitReceiptCommitState::Uncertain,
                ));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn recovery_failure(
    snapshot: &SplitPlanSnapshot,
    record: &JournalRecord,
    receipt_state: SplitReceiptCommitState,
) -> SplitRunFailure {
    SplitRunFailure {
        code: OperationFailureCode::PublicationUncertain,
        receipt_state,
        recovery_path: recovery_path_for_recorded_bundle(snapshot, record),
        retained: true,
    }
}

#[cfg(target_os = "macos")]
fn recovery_cleanup_failure(
    snapshot: &SplitPlanSnapshot,
    record: &JournalRecord,
    receipt_state: SplitReceiptCommitState,
    code: OperationFailureCode,
) -> SplitRunFailure {
    if matches!(
        code,
        OperationFailureCode::Cancelled | OperationFailureCode::SessionUnavailable
    ) {
        SplitRunFailure {
            code,
            receipt_state,
            recovery_path: recovery_path_for_recorded_bundle(snapshot, record),
            retained: true,
        }
    } else {
        recovery_failure(snapshot, record, receipt_state)
    }
}

#[cfg(target_os = "macos")]
fn validate_interrupted_transaction(
    publication: &DestinationPublication<'_>,
    staging_name: &OsStr,
    staged_identity: FileIdentity,
    old_identity: Option<FileIdentity>,
    published: bool,
) -> Result<(), OperationFailureCode> {
    #[cfg(test)]
    if published
        && publication.test_failpoint
            == Some(SplitTestFailpoint::SubstituteStagingBeforeRecoveryIdentityCheck)
    {
        if old_identity.is_some() {
            substitute_destination_for_test(publication.parent, staging_name)?;
        } else {
            create_foreign_destination_for_test(publication.parent, staging_name)?;
        }
    }

    publication.validate_lock()?;
    let expected_destination = if published {
        Some(staged_identity)
    } else {
        old_identity
    };
    let expected_staging = if published {
        old_identity
    } else {
        Some(staged_identity)
    };
    if current_directory_identity(publication.parent, publication.destination_name)?
        != expected_destination
        || current_directory_identity(publication.parent, staging_name)? != expected_staging
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
/// Supplies recovery's lock-protected receipt to the resolver without another store lookup.
struct RecoveryReceiptTrustStore<'a> {
    manifest_sha256: &'a Sha256Digest,
    receipt: &'a SplitTrustReceipt,
}

#[cfg(target_os = "macos")]
impl SplitTrustStore for RecoveryReceiptTrustStore<'_> {
    fn lookup(
        &self,
        manifest_sha256: &Sha256Digest,
    ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
        Ok((manifest_sha256 == self.manifest_sha256).then(|| self.receipt.clone()))
    }
}

#[cfg(target_os = "macos")]
/// Reads a journaled manifest within the v1 size limit and revalidates its recorded metadata afterward.
fn read_verified_recovery_manifest(
    file: &mut File,
    evidence: &ArtifactEvidence,
    manifest_digest: &Sha256Digest,
) -> Option<Vec<u8>> {
    let metadata = file.metadata().ok()?;
    if metadata.len() > MAX_SPLIT_MANIFEST_BYTES
        || !artifact_metadata_matches(file, ArtifactKind::RegularFile, evidence).ok()?
    {
        return None;
    }

    let mut manifest_bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut *file)
        .take(MAX_SPLIT_MANIFEST_BYTES + 1)
        .read_to_end(&mut manifest_bytes)
        .ok()?;
    if manifest_bytes.len() as u64 > MAX_SPLIT_MANIFEST_BYTES
        || !artifact_metadata_matches(file, ArtifactKind::RegularFile, evidence).ok()?
        || Sha256Digest::digest(&manifest_bytes) != *manifest_digest
    {
        return None;
    }

    Some(manifest_bytes)
}

#[cfg(target_os = "macos")]
fn recorded_bundle_is_trusted(
    parent_path: &Path,
    record: &JournalRecord,
    manifest_digest: &Sha256Digest,
    receipt: &SplitTrustReceipt,
) -> bool {
    let Some(parent_identity) = record
        .destination_parent_identity
        .as_deref()
        .and_then(parse_identity)
    else {
        return false;
    };
    let Some(staged_identity) = record.staging_identity.as_deref().and_then(parse_identity) else {
        return false;
    };
    let Some(bundle_name) = decode_os_name(&record.destination_name_hex) else {
        return false;
    };
    let Some(staging_name) = decode_os_name(&record.staging_name_hex) else {
        return false;
    };
    let Some(canonical_name) = decode_os_name(&record.canonical_name_hex) else {
        return false;
    };
    let parent = match open_directory(parent_path) {
        Ok(parent) if handle_identity(&parent) == Some(parent_identity) => parent,
        _ => return false,
    };
    let bundle_directory = match open_directory_at(&parent, &bundle_name) {
        Ok(directory) if handle_identity(&directory) == Some(staged_identity) => directory,
        _ => return false,
    };
    let canonical_directory = match open_directory_at(&bundle_directory, &canonical_name) {
        Ok(directory) => directory,
        Err(_) => return false,
    };
    let staging_hex = encode_os_name(&staging_name);
    let canonical_path = vec![staging_hex.clone(), record.canonical_name_hex.clone()];
    let Some(canonical_artifact) = record.artifacts.iter().find(|artifact| {
        artifact.relative_path_hex == canonical_path && artifact.kind == ArtifactKind::Directory
    }) else {
        return false;
    };
    let canonical_evidence = match &canonical_artifact.state {
        ArtifactState::Created(evidence) | ArtifactState::Verified(evidence) => evidence,
        ArtifactState::Planned => return false,
    };
    if artifact_evidence_matches(
        &canonical_directory,
        ArtifactKind::Directory,
        canonical_evidence,
    )
    .ok()
        != Some(true)
    {
        return false;
    }

    let manifest_name = append_suffix(&canonical_name, ".nscb-split.json");
    let manifest_path = vec![staging_hex.clone(), encode_os_name(&manifest_name)];
    let Some(manifest_artifact) = record.artifacts.iter().find(|artifact| {
        artifact.relative_path_hex == manifest_path && artifact.kind == ArtifactKind::RegularFile
    }) else {
        return false;
    };
    let ArtifactState::Verified(manifest_evidence) = &manifest_artifact.state else {
        return false;
    };
    let manifest_digest_hex = manifest_digest.to_hex();
    if manifest_evidence.sha256.as_deref() != Some(manifest_digest_hex.as_str()) {
        return false;
    }
    let mut manifest_file = match open_file_at(&bundle_directory, &manifest_name) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let Some(manifest_bytes) =
        read_verified_recovery_manifest(&mut manifest_file, manifest_evidence, manifest_digest)
    else {
        return false;
    };
    let Ok(manifest) = crate::split_manifest::parse_manifest(&manifest_bytes) else {
        return false;
    };
    if manifest.source_size != record.source_size
        || manifest.source_sha256.to_hex() != record.source_sha256
        || manifest.segments.len() != record.segment_lengths.len()
    {
        return false;
    }

    let canonical_identity = handle_identity(&canonical_directory);
    for (index, segment) in manifest.segments.iter().enumerate() {
        if record.segment_lengths.get(index) != Some(&segment.size) {
            return false;
        }
        let segment_name = OsString::from(format!("{:02}", segment.index));
        let segment_path = vec![
            staging_hex.clone(),
            record.canonical_name_hex.clone(),
            encode_os_name(&segment_name),
        ];
        let Some(segment_artifact) = record.artifacts.iter().find(|artifact| {
            artifact.relative_path_hex == segment_path && artifact.kind == ArtifactKind::RegularFile
        }) else {
            return false;
        };
        if canonical_identity.map(identity_string).as_deref()
            != Some(segment_artifact.parent_identity.as_str())
        {
            return false;
        }
        let ArtifactState::Verified(segment_evidence) = &segment_artifact.state else {
            return false;
        };
        if segment_evidence.length != Some(segment.size)
            || segment_evidence.sha256.as_deref() != Some(segment.sha256.to_hex().as_str())
        {
            return false;
        }
        let segment_file = match open_file_at(&canonical_directory, &segment_name) {
            Ok(file) => file,
            Err(_) => return false,
        };
        if artifact_evidence_matches(&segment_file, ArtifactKind::RegularFile, segment_evidence)
            .ok()
            != Some(true)
        {
            return false;
        }
    }

    let bundle = parent_path.join(&bundle_name);
    let canonical = bundle.join(&canonical_name);
    let recovery_trust = RecoveryReceiptTrustStore {
        manifest_sha256: manifest_digest,
        receipt,
    };
    let Ok(resolved) = crate::Engine::new().resolve_inputs_with(
        InputResolutionRequest::new(&bundle).with_path(&canonical),
        InputResolutionCapabilities::new().with_split_trust_store(&recovery_trust),
    ) else {
        return false;
    };
    if resolved.inputs.len() != 1 {
        return false;
    }
    let input = &resolved.inputs[0];
    let Some(qualification) = &input.qualification else {
        return false;
    };
    if qualification.original_size_bytes != record.source_size
        || qualification.original_sha256.to_hex() != record.source_sha256
        || input
            .segments
            .iter()
            .map(|segment| segment.size)
            .collect::<Vec<_>>()
            != record.segment_lengths
    {
        return false;
    }

    handle_identity(&parent) == Some(parent_identity)
        && open_directory_at(&parent, &bundle_name)
            .ok()
            .and_then(|directory| handle_identity(&directory))
            == Some(staged_identity)
        && open_directory_at(&bundle_directory, &canonical_name)
            .ok()
            .and_then(|directory| handle_identity(&directory))
            == canonical_identity
}

#[cfg(target_os = "macos")]
fn open_journal_writer(parent: &File, name: &OsStr) -> io::Result<JournalWriter> {
    let c_name = c_name(name)?;
    // SAFETY: parent is open, the name is a single component, and O_NOFOLLOW
    // keeps journal inspection bound to a regular file entry.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c_name.as_ptr(),
            libc::O_RDWR | libc::O_APPEND | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor owned by this function.
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal is not a file",
        ));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    Read::take(&mut file, MAX_SPLIT_JOURNAL_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SPLIT_JOURNAL_BYTES || !bytes.ends_with(b"\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal is oversized or has a torn final record",
        ));
    }
    let mut records = Vec::new();
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        if line.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal contains an empty record",
            ));
        }
        records.push(
            serde_json::from_slice::<JournalRecord>(line).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "journal record invalid")
            })?,
        );
    }
    let record = records
        .pop()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "journal empty"))?;
    let metadata = file.metadata()?;
    let expected_journal_name = format!(".nscb-split-{}.journal", record.transaction_id);
    if name != OsStr::new(&expected_journal_name)
        || !journal_record_is_valid(&record)
        || records.windows(2).any(|pair| {
            !same_journal_identity(&pair[0], &pair[1])
                || !journal_transition_is_valid(&pair[0], &pair[1])
        })
        || records.last().is_some_and(|prior| {
            !same_journal_identity(prior, &record) || !journal_transition_is_valid(prior, &record)
        })
        || !record.journal_identity.as_deref().is_some_and(|identity| {
            parse_identity(identity) == handle_identity(&file)
                && record.journal_mode == Some(metadata.mode() & 0o7777)
                && metadata.nlink() == 1
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal identity or transition is inconsistent",
        ));
    }
    file.seek(SeekFrom::End(0))?;
    Ok(JournalWriter {
        file,
        parent: parent.try_clone()?,
        record,
        poisoned: false,
    })
}

#[cfg(target_os = "macos")]
fn same_journal_identity(left: &JournalRecord, right: &JournalRecord) -> bool {
    left.version == right.version
        && left.transaction_id == right.transaction_id
        && left.destination_name_hex == right.destination_name_hex
        && left.staging_name_hex == right.staging_name_hex
        && left.canonical_name_hex == right.canonical_name_hex
        && left.source_identity == right.source_identity
        && left.source_size == right.source_size
        && left.source_sha256 == right.source_sha256
        && left.destination_parent_identity == right.destination_parent_identity
        && (left.journal_identity.is_none()
            || right.journal_identity.as_ref() == left.journal_identity.as_ref())
        && (left.journal_mode.is_none() || right.journal_mode == left.journal_mode)
        && left.destination_identity == right.destination_identity
        && left.segment_lengths == right.segment_lengths
        && (left.staging_identity.is_none()
            || right.staging_identity.as_ref() == left.staging_identity.as_ref())
        && (left.manifest_sha256.is_none()
            || right.manifest_sha256.as_ref() == left.manifest_sha256.as_ref())
}

#[cfg(target_os = "macos")]
fn journal_record_is_valid(record: &JournalRecord) -> bool {
    if record.version != 1 {
        return false;
    }
    let Some(_staging) = decode_os_name(&record.staging_name_hex) else {
        return false;
    };
    let Some(canonical) = decode_os_name(&record.canonical_name_hex) else {
        return false;
    };
    if decode_os_name(&record.destination_name_hex).is_none()
        || record.staging_name_hex
            != encode_os_name(OsStr::new(&format!(
                ".nscb-split-{}.bundle",
                record.transaction_id
            )))
        || record.transaction_id.is_empty()
        || record.source_size == 0
        || Sha256Digest::parse_hex(&record.source_identity).is_err()
        || Sha256Digest::parse_hex(&record.source_sha256).is_err()
        || record.segment_lengths.is_empty()
        || record.segment_lengths.len() > MAX_SEGMENT_COUNT
        || record.segment_lengths.contains(&0)
        || record
            .segment_lengths
            .iter()
            .try_fold(0_u64, |total, length| total.checked_add(*length))
            != Some(record.source_size)
        || record
            .destination_parent_identity
            .as_deref()
            .is_some_and(|value| parse_identity(value).is_none())
        || record
            .journal_identity
            .as_deref()
            .is_some_and(|value| parse_identity(value).is_none())
        || record
            .destination_identity
            .as_deref()
            .is_some_and(|value| parse_identity(value).is_none())
        || record
            .staging_identity
            .as_deref()
            .is_some_and(|value| parse_identity(value).is_none())
        || record
            .manifest_sha256
            .as_deref()
            .is_some_and(|value| Sha256Digest::parse_hex(value).is_err())
        || record.journal_mode.is_some_and(|mode| mode & !0o7777 != 0)
    {
        return false;
    }

    let mut paths = HashSet::new();
    for artifact in &record.artifacts {
        if artifact.relative_path_hex.is_empty()
            || artifact.relative_path_hex.len() > 3
            || artifact
                .relative_path_hex
                .iter()
                .any(|part| decode_os_name(part).is_none())
            || artifact.relative_path_hex[0] != record.staging_name_hex
            || parse_identity(&artifact.parent_identity).is_none()
            || !paths.insert(artifact.relative_path_hex.clone())
        {
            return false;
        }

        let expected_kind = match artifact.relative_path_hex.as_slice() {
            [root] if root == &record.staging_name_hex => ArtifactKind::Directory,
            [root, inner]
                if root == &record.staging_name_hex && inner == &record.canonical_name_hex =>
            {
                ArtifactKind::Directory
            }
            [root, inner]
                if root == &record.staging_name_hex
                    && *inner == encode_os_name(&append_suffix(&canonical, ".nscb-split.json")) =>
            {
                ArtifactKind::RegularFile
            }
            [root, inner, segment]
                if root == &record.staging_name_hex
                    && inner == &record.canonical_name_hex
                    && record.segment_lengths.iter().enumerate().any(|(index, _)| {
                        *segment == encode_os_name(OsStr::new(&format!("{index:02}")))
                    }) =>
            {
                ArtifactKind::RegularFile
            }
            _ => return false,
        };
        if artifact.kind != expected_kind {
            return false;
        }
        if let Some(parent_path) = artifact
            .relative_path_hex
            .get(..artifact.relative_path_hex.len() - 1)
        {
            if !parent_path.is_empty() {
                let Some(parent_artifact) = record
                    .artifacts
                    .iter()
                    .find(|candidate| candidate.relative_path_hex == parent_path)
                else {
                    return false;
                };
                if parent_artifact.kind != ArtifactKind::Directory
                    || !matches!(
                        &parent_artifact.state,
                        ArtifactState::Created(evidence) | ArtifactState::Verified(evidence)
                            if artifact.parent_identity == evidence.identity
                    )
                {
                    return false;
                }
            } else if record
                .destination_parent_identity
                .as_deref()
                .is_some_and(|identity| identity != artifact.parent_identity)
            {
                return false;
            }
        }

        match &artifact.state {
            ArtifactState::Planned => {}
            ArtifactState::Created(evidence) | ArtifactState::Verified(evidence) => {
                if parse_identity(&evidence.identity).is_none() || evidence.mode & !0o7777 != 0 {
                    return false;
                }
                match artifact.kind {
                    ArtifactKind::Directory => {
                        if evidence.link_count.is_some()
                            || evidence.length.is_some()
                            || evidence.sha256.is_some()
                            || evidence.change_seconds.is_some()
                            || evidence.change_nanoseconds.is_some()
                            || matches!(artifact.state, ArtifactState::Verified(_))
                        {
                            return false;
                        }
                    }
                    ArtifactKind::RegularFile => {
                        let (Some(links), Some(length), Some(digest), Some(_), Some(_)) = (
                            evidence.link_count,
                            evidence.length,
                            evidence.sha256.as_deref(),
                            evidence.change_seconds,
                            evidence.change_nanoseconds,
                        ) else {
                            return false;
                        };
                        if links != 1
                            || Sha256Digest::parse_hex(digest).is_err()
                            || matches!(artifact.state, ArtifactState::Created(_))
                                && (length != 0 || digest != Sha256Digest::digest(&[]).to_hex())
                        {
                            return false;
                        }
                        if let [_, _, encoded_segment] = artifact.relative_path_hex.as_slice() {
                            let Some(segment_index) =
                                decode_os_name(encoded_segment).and_then(|name| {
                                    name.to_str().and_then(|value| value.parse::<usize>().ok())
                                })
                            else {
                                return false;
                            };
                            if matches!(artifact.state, ArtifactState::Verified(_))
                                && record.segment_lengths.get(segment_index) != Some(&length)
                            {
                                return false;
                            }
                        } else if matches!(artifact.state, ArtifactState::Verified(_))
                            && record
                                .manifest_sha256
                                .as_deref()
                                .is_some_and(|manifest| manifest != digest)
                        {
                            return false;
                        }
                    }
                }
            }
        }
    }

    let staging_path = vec![record.staging_name_hex.clone()];
    if let Some(staging_identity) = record.staging_identity.as_deref() {
        let Some(staging_artifact) = record
            .artifacts
            .iter()
            .find(|artifact| artifact.relative_path_hex == staging_path)
        else {
            return false;
        };
        if !matches!(
            &staging_artifact.state,
            ArtifactState::Created(evidence) if evidence.identity == staging_identity
        ) {
            return false;
        }
    }
    if matches!(
        record.phase,
        JournalPhase::Verified
            | JournalPhase::Publishing
            | JournalPhase::Published
            | JournalPhase::ReceiptCommitStarted
            | JournalPhase::ReceiptCommitted
            | JournalPhase::Completed
            | JournalPhase::RolledBack
            | JournalPhase::Uncertain
    ) && !record.artifacts.is_empty()
    {
        if record.staging_identity.is_none() || record.manifest_sha256.is_none() {
            return false;
        }
        let expected_file_count = record.segment_lengths.len() + 1;
        let verified_file_count = record
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact.kind == ArtifactKind::RegularFile
                    && matches!(artifact.state, ArtifactState::Verified(_))
            })
            .count();
        if verified_file_count != expected_file_count {
            return false;
        }
    }

    if !record.artifacts.is_empty() && record.destination_parent_identity.is_none() {
        return false;
    }
    true
}

#[cfg(target_os = "macos")]
fn journal_transition_is_valid(previous: &JournalRecord, next: &JournalRecord) -> bool {
    if !same_journal_identity(previous, next)
        || !journal_phase_can_advance(previous.phase, next.phase)
        || next.artifacts.len() < previous.artifacts.len()
    {
        return false;
    }
    for (prior, current) in previous.artifacts.iter().zip(&next.artifacts) {
        if prior.relative_path_hex != current.relative_path_hex
            || prior.parent_identity != current.parent_identity
            || prior.kind != current.kind
        {
            return false;
        }
        if prior == current {
            continue;
        }
        match (&prior.state, &current.state) {
            (ArtifactState::Planned, ArtifactState::Created(_)) => {}
            (ArtifactState::Created(old), ArtifactState::Verified(new))
                if prior.kind == ArtifactKind::RegularFile
                    && old.identity == new.identity
                    && old.mode == new.mode
                    && old.link_count == new.link_count => {}
            (ArtifactState::Created(old), ArtifactState::Created(new))
            | (ArtifactState::Verified(old), ArtifactState::Verified(new))
                if previous.phase == JournalPhase::Cleaning
                    && next.phase == JournalPhase::Cleaning
                    && artifact_evidence_equal_except_change_time(old, new) => {}
            _ => return false,
        }
    }
    next.artifacts[previous.artifacts.len()..]
        .iter()
        .all(|artifact| matches!(artifact.state, ArtifactState::Planned))
}

#[cfg(target_os = "macos")]
fn artifact_evidence_equal_except_change_time(
    left: &ArtifactEvidence,
    right: &ArtifactEvidence,
) -> bool {
    left.identity == right.identity
        && left.mode == right.mode
        && left.link_count == right.link_count
        && left.length == right.length
        && left.sha256 == right.sha256
}

#[cfg(target_os = "macos")]
fn journal_phase_can_advance(previous: JournalPhase, next: JournalPhase) -> bool {
    if previous == next {
        return true;
    }
    match previous {
        JournalPhase::Prepared => matches!(
            next,
            JournalPhase::Staging
                | JournalPhase::Cleaning
                | JournalPhase::CleanupComplete
                | JournalPhase::Uncertain
        ),
        JournalPhase::Staging => matches!(
            next,
            JournalPhase::Verified
                | JournalPhase::Publishing
                | JournalPhase::Cleaning
                | JournalPhase::CleanupComplete
                | JournalPhase::Uncertain
        ),
        JournalPhase::Verified => matches!(
            next,
            JournalPhase::Publishing
                | JournalPhase::Cleaning
                | JournalPhase::CleanupComplete
                | JournalPhase::Uncertain
        ),
        JournalPhase::Publishing => matches!(
            next,
            JournalPhase::Published
                | JournalPhase::RolledBack
                | JournalPhase::Cleaning
                | JournalPhase::CleanupComplete
                | JournalPhase::Uncertain
        ),
        JournalPhase::Published => matches!(
            next,
            JournalPhase::ReceiptCommitStarted | JournalPhase::RolledBack | JournalPhase::Uncertain
        ),
        JournalPhase::ReceiptCommitStarted => matches!(
            next,
            JournalPhase::ReceiptCommitted | JournalPhase::RolledBack | JournalPhase::Uncertain
        ),
        JournalPhase::ReceiptCommitted => {
            matches!(next, JournalPhase::Completed | JournalPhase::Uncertain)
        }
        JournalPhase::RolledBack => {
            matches!(next, JournalPhase::Cleaning | JournalPhase::CleanupComplete)
        }
        JournalPhase::Cleaning => matches!(next, JournalPhase::CleanupComplete),
        JournalPhase::Completed | JournalPhase::CleanupComplete | JournalPhase::Uncertain => false,
    }
}

#[cfg(any(target_os = "macos", test))]
fn segment_lengths(source_size: u64, segment_size: u64) -> Result<Vec<u64>, OperationError> {
    if source_size == 0 || segment_size == 0 {
        return Err(OperationError::new(
            crate::operation::OperationFailureCode::SplitSourceSizeUnsupported,
        ));
    }
    let full_segments = source_size / segment_size;
    let has_tail = u64::from(!source_size.is_multiple_of(segment_size));
    let count = full_segments.checked_add(has_tail).ok_or_else(|| {
        OperationError::new(crate::operation::OperationFailureCode::SplitSourceSizeUnsupported)
    })?;
    if count == 0 || count > MAX_SEGMENT_COUNT as u64 {
        return Err(OperationError::new(
            crate::operation::OperationFailureCode::SplitSourceSizeUnsupported,
        ));
    }

    let mut remaining = source_size;
    let mut lengths = Vec::with_capacity(count as usize);
    while remaining > 0 {
        let length = remaining.min(segment_size);
        lengths.push(length);
        remaining -= length;
    }
    Ok(lengths)
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_SEGMENT_SIZE_BYTES, OperationError, segment_lengths};
    use crate::operation::OperationFailureCode;

    #[test]
    fn production_segment_boundaries_use_checked_fixed_size_arithmetic() {
        let size = DEFAULT_SEGMENT_SIZE_BYTES;
        let cases = [
            (size - 1, vec![size - 1]),
            (size, vec![size]),
            (size + 1, vec![size, 1]),
            (2 * size - 1, vec![size, size - 1]),
            (2 * size, vec![size, size]),
            (2 * size + 1, vec![size, size, 1]),
        ];
        for (source_size, expected) in cases {
            assert_eq!(segment_lengths(source_size, size).unwrap(), expected);
        }
        assert_eq!(segment_lengths(100 * size, size).unwrap().len(), 100);
        assert_eq!(
            segment_lengths(100 * size + 1, size).unwrap_err().code(),
            OperationFailureCode::SplitSourceSizeUnsupported
        );
    }

    #[test]
    fn private_test_segment_size_seam_preserves_nonempty_tail_rules() {
        assert_eq!(segment_lengths(9, 4).unwrap(), vec![4, 4, 1]);
        assert_eq!(segment_lengths(8, 4).unwrap(), vec![4, 4]);
        assert_eq!(segment_lengths(1, 4).unwrap(), vec![1]);
    }

    #[test]
    fn zero_source_and_zero_segment_size_fail_without_a_zero_length_tail() {
        for (source_size, segment_size) in [(0, 4), (1, 0)] {
            let error: OperationError = segment_lengths(source_size, segment_size).unwrap_err();
            assert_eq!(
                error.code(),
                OperationFailureCode::SplitSourceSizeUnsupported
            );
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod producer_tests {
    use super::{
        JournalPhase, SPLIT_IO_BUFFER_SIZE, SPLIT_RECEIPT_LOCK_NAME, SplitRequest,
        SplitTestFailpoint, acquire_destination_lock, has_one_qualified_candidate,
        open_journal_writer, plan_split_for_tests, plan_split_for_tests_with_cancellation,
        recover_incomplete_for_destination, validate_split_output_parent_with,
    };
    use crate::Engine;
    use crate::OperationFailureCode;
    use crate::OperationOutcome;
    use crate::OperationSession;
    use crate::SplitReceiptCommitState;
    use crate::input_resolution::{InputResolutionCapabilities, InputResolutionRequest};
    use crate::inspection::CancellationHandle;
    use crate::split_reader::{SegmentedFileReader, open_segment_file};
    use crate::split_trust::{
        LocalSplitTrustStore, SplitTrustReceipt, SplitTrustStore, SplitTrustStoreError,
        SplitTrustWriter,
    };
    use std::ffi::CString;
    use std::ffi::OsStr;
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, Mutex};

    #[test]
    fn unsupported_implicit_destination_volume_fails_before_directory_creation() {
        let root = tempfile::tempdir().unwrap();
        let output_directory = root.path().join("not-created").join("NSCB_output");

        let result = validate_split_output_parent_with(&output_directory, |_| false);

        assert_eq!(result, Err(OperationFailureCode::UnsupportedCapability));
        assert!(!output_directory.exists());
        assert!(!output_directory.parent().unwrap().exists());
    }

    #[test]
    fn planning_reads_existing_output_directory_and_leaves_missing_directory_absent() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("loose.nca");
        fs::write(&source, b"planning is read only").unwrap();
        let output_directory = root.path().join("existing-output");
        fs::create_dir(&output_directory).unwrap();
        let trust = LocalSplitTrustStore::new(root.path().join("state").join("split-trust"));
        let bundle = output_directory.join("loose.nca.split");
        let root_entries = || {
            let mut entries = fs::read_dir(root.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>();
            entries.sort();
            entries
        };

        let before_existing_plan = root_entries();
        let plan = Engine::new()
            .plan_split(SplitRequest::new(&source, &bundle), &trust)
            .unwrap();
        assert_eq!(root_entries(), before_existing_plan);
        assert!(!bundle.exists());
        drop(plan);

        let missing_output_directory = root.path().join("not-created").join("NSCB_output");
        let missing_bundle = missing_output_directory.join("loose.nca.split");
        let before_failed_plan = root_entries();
        let error = Engine::new()
            .plan_split(SplitRequest::new(&source, &missing_bundle), &trust)
            .unwrap_err();

        assert_eq!(error.code(), OperationFailureCode::DestinationUnavailable);
        assert_eq!(root_entries(), before_failed_plan);
        assert!(!missing_output_directory.exists());
        assert!(!missing_output_directory.parent().unwrap().exists());
    }

    #[test]
    fn exact_bundle_shape_stops_after_the_third_directory_entry() {
        let mut yielded = 0;
        let entries = std::iter::from_fn(|| {
            yielded += 1;
            match yielded {
                1 => Some(Ok(std::ffi::OsString::from("canonical"))),
                2 => Some(Ok(std::ffi::OsString::from("manifest"))),
                3 => Some(Ok(std::ffi::OsString::from("extra"))),
                _ => panic!("exact-shape check read past the third entry"),
            }
        });

        assert!(!super::entry_names_match_exact_split_shape(
            entries,
            OsStr::new("canonical"),
            OsStr::new("manifest"),
        ));
        assert_eq!(yielded, 3);
    }

    #[test]
    fn destination_lock_namespace_is_separate_from_receipt_state() {
        let root = tempfile::tempdir().unwrap();
        let parent = fs::File::open(root.path()).unwrap();
        let parent_identity = super::handle_identity(&parent).unwrap();
        let destination_name = OsStr::new(SPLIT_RECEIPT_LOCK_NAME);

        let destination_lock =
            acquire_destination_lock(&parent, parent_identity, root.path(), destination_name)
                .unwrap();
        let receipt_lock =
            super::ReceiptStateLock::acquire(&parent, &destination_lock, None).unwrap();

        assert_ne!(destination_lock.identity, receipt_lock.file_identity);
        assert_eq!(
            destination_lock.directory_identity,
            receipt_lock.directory_identity
        );
        assert_ne!(
            destination_lock.identity,
            receipt_lock.receipt_directory_identity
        );
    }

    #[test]
    fn destination_named_receipt_state_directory_does_not_poison_lock_namespace() {
        let root = tempfile::tempdir().unwrap();
        let parent = fs::File::open(root.path()).unwrap();
        let parent_identity = super::handle_identity(&parent).unwrap();

        let collision = acquire_destination_lock(
            &parent,
            parent_identity,
            root.path(),
            OsStr::new(super::SPLIT_RECEIPT_LOCK_DIRECTORY_NAME),
        );
        assert!(matches!(collision, Err(OperationFailureCode::UnsafePath)));

        let lock_directory =
            super::open_directory_at(&parent, OsStr::new(super::SPLIT_LOCK_DIRECTORY_NAME))
                .unwrap();
        let receipt_directory = super::open_directory_at(
            &lock_directory,
            OsStr::new(super::SPLIT_RECEIPT_LOCK_DIRECTORY_NAME),
        )
        .unwrap();
        assert!(super::handle_identity(&receipt_directory).is_some());

        let destination_lock =
            acquire_destination_lock(&parent, parent_identity, root.path(), OsStr::new("bundle"))
                .unwrap();
        let receipt_lock =
            super::ReceiptStateLock::acquire(&parent, &destination_lock, None).unwrap();
        receipt_lock.validate(&parent, &destination_lock).unwrap();
    }

    #[test]
    fn destination_lock_rejects_case_alias_of_its_namespace_before_creation() {
        let root = tempfile::tempdir().unwrap();
        let parent = super::open_directory(root.path()).unwrap();
        let parent_identity = super::handle_identity(&parent).unwrap();
        let alias_name = OsStr::new(".NSCB-SPLIT-LOCKS");

        let result = acquire_destination_lock(&parent, parent_identity, root.path(), alias_name);

        assert!(matches!(result, Err(OperationFailureCode::UnsafePath)));
        assert!(!root.path().join(super::SPLIT_LOCK_DIRECTORY_NAME).exists());
        assert!(!root.path().join(alias_name).exists());
    }

    #[test]
    fn skip_rejects_missing_case_alias_of_lock_namespace_without_creating_it() {
        let root = tempfile::tempdir().unwrap();
        let (source, _, state_path) = setup(root.path(), b"lock alias source");
        let alias = root.path().join(".NSCB-SPLIT-LOCKS");
        let trust = LocalSplitTrustStore::new(state_path.clone());

        let error = plan_split_for_tests(
            SplitRequest::new(&source, &alias).with_conflict_policy(crate::ConflictPolicy::Skip),
            &trust,
            4,
            None,
        )
        .unwrap_err();

        assert_eq!(error.code(), OperationFailureCode::UnsafePath);
        assert!(!root.path().join(super::SPLIT_LOCK_DIRECTORY_NAME).exists());
        assert!(!alias.exists());
    }

    #[test]
    fn skip_rejects_unicode_alias_of_existing_lock_namespace_without_mutating_it() {
        let root = tempfile::tempdir().unwrap();
        let (source, _, state_path) = setup(root.path(), b"lock alias source");
        let lock_directory = root.path().join(super::SPLIT_LOCK_DIRECTORY_NAME);
        fs::create_dir(&lock_directory).unwrap();
        let sentinel = lock_directory.join("keep.txt");
        fs::write(&sentinel, b"existing lock namespace contents").unwrap();
        let before = fs::read_dir(&lock_directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<std::collections::BTreeSet<_>>();
        let alias = root.path().join(".nscb-split-locKs");
        let trust = LocalSplitTrustStore::new(state_path);

        let error = plan_split_for_tests(
            SplitRequest::new(&source, &alias).with_conflict_policy(crate::ConflictPolicy::Skip),
            &trust,
            4,
            None,
        )
        .unwrap_err();

        assert_eq!(error.code(), OperationFailureCode::UnsafePath);
        let after = fs::read_dir(&lock_directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(after, before);
        assert_eq!(
            fs::read(&sentinel).unwrap(),
            b"existing lock namespace contents"
        );
        assert!(
            !lock_directory
                .join(super::SPLIT_RECEIPT_LOCK_DIRECTORY_NAME)
                .exists()
        );
    }

    #[test]
    fn destination_name_resolved_as_receipt_state_directory_alias_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let parent = super::open_directory(root.path()).unwrap();
        let parent_identity = super::handle_identity(&parent).unwrap();
        let lock_directory = super::open_or_create_private_directory_at(
            &parent,
            OsStr::new(super::SPLIT_LOCK_DIRECTORY_NAME),
        )
        .unwrap();
        let receipt_directory = super::open_or_create_private_directory_at(
            &lock_directory,
            OsStr::new(super::SPLIT_RECEIPT_LOCK_DIRECTORY_NAME),
        )
        .unwrap();
        let alias_name = OsStr::new(".RECEIPT-STATE-LOCKS");
        let alias_resolves_to_receipt_directory =
            super::open_directory_at(&lock_directory, alias_name)
                .ok()
                .and_then(|alias| super::handle_identity(&alias))
                == super::handle_identity(&receipt_directory);

        let destination_lock =
            acquire_destination_lock(&parent, parent_identity, root.path(), alias_name);
        if alias_resolves_to_receipt_directory {
            assert!(matches!(
                destination_lock,
                Err(OperationFailureCode::UnsafePath)
            ));
        } else {
            let destination_lock = destination_lock.unwrap();
            let receipt_lock =
                super::ReceiptStateLock::acquire(&parent, &destination_lock, None).unwrap();
            receipt_lock.validate(&parent, &destination_lock).unwrap();
        }
    }

    #[test]
    fn receipt_state_lock_validation_detects_receipt_directory_replacement() {
        let root = tempfile::tempdir().unwrap();
        let parent = super::open_directory(root.path()).unwrap();
        let parent_identity = super::handle_identity(&parent).unwrap();
        let destination_lock = super::acquire_destination_lock(
            &parent,
            parent_identity,
            root.path(),
            OsStr::new("bundle"),
        )
        .unwrap();
        let receipt_lock =
            super::ReceiptStateLock::acquire(&parent, &destination_lock, None).unwrap();
        let lock_directory = root.path().join(super::SPLIT_LOCK_DIRECTORY_NAME);
        let receipt_directory = lock_directory.join(super::SPLIT_RECEIPT_LOCK_DIRECTORY_NAME);
        let displaced_directory = lock_directory.join(".receipt-state-locks.displaced");

        fs::rename(&receipt_directory, &displaced_directory).unwrap();
        fs::create_dir(&receipt_directory).unwrap();

        assert_eq!(
            receipt_lock.validate(&parent, &destination_lock),
            Err(OperationFailureCode::PublicationUncertain)
        );
        assert!(displaced_directory.join(SPLIT_RECEIPT_LOCK_NAME).is_file());
    }

    #[test]
    fn destination_named_receipt_lock_can_commit_a_split_receipt() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("loose.nca");
        fs::write(&source, b"lock namespace fixture").unwrap();
        let bundle = root.path().join(SPLIT_RECEIPT_LOCK_NAME);
        let trust = LocalSplitTrustStore::new(root.path().join("state").join("split-trust"));
        let plan = Engine::new()
            .plan_split(SplitRequest::new(&source, &bundle), &trust)
            .unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(result.outcome(), Some(OperationOutcome::SplitCreated));
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::ConfirmedCommitted)
        );
        assert!(bundle.is_dir());
    }

    #[test]
    fn planning_rejects_fifo_manifest_without_blocking() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, trust_path) = setup(root.path(), b"fifo manifest fixture");
        fs::create_dir(&bundle).unwrap();
        fs::create_dir(bundle.join("loose.nca")).unwrap();
        let manifest = bundle.join("loose.nca.nscb-split.json");
        let manifest_c = CString::new(manifest.as_os_str().as_bytes()).unwrap();
        // SAFETY: manifest_c is NUL-terminated and names a new test fixture.
        assert_eq!(unsafe { libc::mkfifo(manifest_c.as_ptr(), 0o600) }, 0);
        let trust = LocalSplitTrustStore::new(trust_path);

        let plan = Engine::new().plan_split(SplitRequest::new(source, bundle), &trust);

        assert!(plan.is_ok());
    }

    #[test]
    fn recovery_rejects_oversized_manifest_before_reading_it() {
        let root = tempfile::tempdir().unwrap();
        let manifest = root
            .path()
            .join("oversized-recovery-manifest.nscb-split.json");
        let bytes = vec![b' '; (super::MAX_SPLIT_MANIFEST_BYTES + 1) as usize];
        fs::write(&manifest, &bytes).unwrap();

        let mut file = fs::File::open(&manifest).unwrap();
        let digest = super::Sha256Digest::digest(&bytes);
        let evidence = super::regular_file_evidence(&file, bytes.len() as u64, digest).unwrap();
        let manifest_bytes = super::read_verified_recovery_manifest(&mut file, &evidence, &digest);

        assert!(manifest_bytes.is_none());
        assert_eq!(std::io::Seek::stream_position(&mut file).unwrap(), 0);
    }

    #[test]
    fn producer_manifest_reader_rejects_sidecars_over_v1_limit() {
        let root = tempfile::tempdir().unwrap();
        let manifest = root.path().join("oversized.nscb-split.json");
        fs::write(
            &manifest,
            vec![b' '; (super::MAX_SPLIT_MANIFEST_BYTES + 1) as usize],
        )
        .unwrap();

        let error = super::read_split_manifest_bytes(&manifest).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn maximum_split_journal_stays_readable_with_a_long_source_name() {
        let root = tempfile::tempdir().unwrap();
        let source_name = "s".repeat(239);
        let source = root.path().join(&source_name);
        fs::write(&source, vec![0x42; super::MAX_SEGMENT_COUNT]).unwrap();
        let output = root.path().join("output");
        fs::create_dir(&output).unwrap();
        let bundle = output.join("bundle");
        let trust = LocalSplitTrustStore::new(root.path().join("state").join("split-trust"));
        let mut plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 1, None).unwrap();
        let names = super::transaction_names();
        let mut journal = start_staging_journal(&plan, &names);

        super::stage_and_verify(
            &plan.snapshot,
            &mut plan.state,
            &OperationSession::new(),
            &names.staging,
            &mut journal,
        )
        .unwrap();
        let journal_length = journal.file.metadata().unwrap().len() as usize;
        drop(journal);

        assert!(
            journal_length > 16 * 1024 * 1024,
            "long-name journal should exceed the former reader limit"
        );
        assert!(
            journal_length <= super::MAX_SPLIT_JOURNAL_BYTES,
            "journal length was {journal_length} bytes"
        );
        let parent = super::open_directory(&output).unwrap();
        assert!(open_journal_writer(&parent, &names.journal).is_ok());
    }

    #[test]
    fn artifact_hash_checks_cancellation_between_chunks() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("artifact");
        fs::write(&path, vec![0x42; super::SPLIT_IO_BUFFER_SIZE * 2]).unwrap();
        let file = fs::File::open(path).unwrap();
        let mut checks = 0;

        let result = super::hash_open_file_with_check(&file, || {
            checks += 1;
            if checks == 2 {
                Err(OperationFailureCode::Cancelled)
            } else {
                Ok(())
            }
        });

        assert_eq!(result.unwrap_err(), OperationFailureCode::Cancelled);
        assert_eq!(checks, 2);
    }

    fn setup(root: &Path, source_bytes: &[u8]) -> (PathBuf, PathBuf, PathBuf) {
        let source = root.join("loose.nca");
        let output_directory = root.join("output");
        fs::create_dir(&output_directory).unwrap();
        fs::write(&source, source_bytes).unwrap();
        let bundle = output_directory.join("loose.nca.split");
        let trust = root.join("state").join("split-trust");
        (source, bundle, trust)
    }

    struct NoCleanupLeaseWriter {
        inner: LocalSplitTrustStore,
    }

    impl SplitTrustStore for NoCleanupLeaseWriter {
        fn lookup(
            &self,
            digest: &crate::Sha256Digest,
        ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
            self.inner.lookup(digest)
        }
    }

    impl SplitTrustWriter for NoCleanupLeaseWriter {
        fn issue(&self, receipt: SplitTrustReceipt) -> Result<(), SplitTrustStoreError> {
            self.inner.issue(receipt)
        }

        fn revoke(&self, digest: &crate::Sha256Digest) -> Result<(), SplitTrustStoreError> {
            self.inner.revoke(digest)
        }
    }

    struct WaitNotifyingCleanupLeaseWriter {
        inner: LocalSplitTrustStore,
        lock_wait_sender: std::sync::mpsc::Sender<()>,
    }

    impl SplitTrustStore for WaitNotifyingCleanupLeaseWriter {
        fn lookup(
            &self,
            manifest_sha256: &crate::Sha256Digest,
        ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
            self.inner.lookup(manifest_sha256)
        }
    }

    impl SplitTrustWriter for WaitNotifyingCleanupLeaseWriter {
        fn acquire_cleanup_lease(
            &self,
            manifest_sha256: &crate::Sha256Digest,
            is_cancelled: &dyn Fn() -> bool,
        ) -> Result<Option<Box<dyn crate::SplitTrustCleanupLease>>, SplitTrustStoreError> {
            let poll_count = std::cell::Cell::new(0);
            let notified = std::cell::Cell::new(false);
            let observed_cancellation = || {
                let count = poll_count.get() + 1;
                poll_count.set(count);
                if count == 2 && !notified.replace(true) {
                    self.lock_wait_sender.send(()).unwrap();
                }
                is_cancelled()
            };
            self.inner
                .acquire_cleanup_lease(manifest_sha256, &observed_cancellation)
        }

        fn issue(&self, receipt: SplitTrustReceipt) -> Result<(), SplitTrustStoreError> {
            self.inner.issue(receipt)
        }

        fn revoke(
            &self,
            manifest_sha256: &crate::Sha256Digest,
        ) -> Result<(), SplitTrustStoreError> {
            self.inner.revoke(manifest_sha256)
        }
    }

    fn start_staging_journal(
        plan: &super::SplitPlan<'_>,
        names: &super::TransactionNames,
    ) -> super::JournalWriter {
        let state = &plan.state;
        let mut journal = super::create_journal(
            &state.destination_parent,
            &names.journal,
            super::JournalRecord::new(
                names.transaction_id.clone(),
                &plan.snapshot,
                state,
                &names.staging,
                state.destination_identity,
            ),
            None,
        )
        .unwrap();
        journal
            .append(super::JournalPhase::Staging, |_| {})
            .unwrap();
        journal
    }

    fn plan_staging_root(
        plan: &super::SplitPlan<'_>,
        names: &super::TransactionNames,
        journal: &mut super::JournalWriter,
    ) -> Vec<String> {
        let path = vec![super::encode_os_name(&names.staging)];
        super::plan_journal_artifacts(
            journal,
            vec![super::planned_artifact(
                path.clone(),
                plan.state.destination_parent_identity,
                super::ArtifactKind::Directory,
            )],
        )
        .unwrap();
        path
    }

    fn seed_cleanup_lease_state(trust: &LocalSplitTrustStore) {
        let cleanup_manifest = super::Sha256Digest::digest(b"split cleanup lease fixture");
        if trust.lookup(&cleanup_manifest).unwrap().is_none() {
            trust
                .issue(super::SplitTrustReceipt::new(
                    cleanup_manifest,
                    0,
                    super::Sha256Digest::digest(b"split cleanup lease source"),
                ))
                .unwrap();
        }
    }

    fn stage_only<'a>(
        source: &Path,
        bundle: &Path,
        trust: &'a LocalSplitTrustStore,
        segment_size: u64,
    ) -> (super::SplitPlan<'a>, super::TransactionNames, PathBuf) {
        let mut plan =
            plan_split_for_tests(SplitRequest::new(source, bundle), trust, segment_size, None)
                .unwrap();
        seed_cleanup_lease_state(trust);
        let names = super::transaction_names();
        let mut journal = start_staging_journal(&plan, &names);
        super::stage_and_verify(
            &plan.snapshot,
            &mut plan.state,
            &OperationSession::new(),
            &names.staging,
            &mut journal,
        )
        .unwrap();
        drop(journal);
        let staging = bundle.parent().unwrap().join(&names.staging);
        (plan, names, staging)
    }

    fn run_with_size(
        source: &Path,
        bundle: &Path,
        trust: &LocalSplitTrustStore,
        segment_size: u64,
    ) -> crate::OperationResult {
        let plan =
            plan_split_for_tests(SplitRequest::new(source, bundle), trust, segment_size, None)
                .unwrap();
        Engine::new().execute_split(plan, &OperationSession::new())
    }

    fn resolve_bytes(bundle: &Path, canonical: &Path, trust: &dyn SplitTrustStore) -> Vec<u8> {
        let resolution = Engine::new()
            .resolve_inputs_with(
                InputResolutionRequest::new(bundle).with_path(canonical),
                InputResolutionCapabilities::new().with_split_trust_store(trust),
            )
            .unwrap();
        assert_eq!(resolution.inputs.len(), 1);
        let opened = resolution.inputs[0]
            .segments
            .iter()
            .map(|segment| open_segment_file(&segment.path, segment.size).unwrap())
            .collect();
        let mut reader = SegmentedFileReader::from_segments(opened).unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn real_multipart_writer_resolver_and_virtual_reader_round_trip() {
        let root = tempfile::tempdir().unwrap();
        let source_bytes = b"abcdefghij";
        let (source, bundle, state_path) = setup(root.path(), source_bytes);
        let trust = LocalSplitTrustStore::new(state_path);
        let progress = Arc::new(Mutex::new(Vec::new()));
        let observed_progress = Arc::clone(&progress);
        let session = OperationSession::with_progress_observer(move |bytes| {
            observed_progress.lock().unwrap().push(bytes);
        });
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 4, None).unwrap();
        assert_eq!(plan.snapshot().segment_size_bytes(), 4);
        assert_eq!(plan.snapshot().segment_lengths(), [4, 4, 2]);
        let result = Engine::new().execute_split(plan, &session);
        assert_eq!(result.outcome(), Some(OperationOutcome::SplitCreated));
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::ConfirmedCommitted)
        );
        let output = result.split_output_paths().unwrap();
        assert_eq!(
            fs::read(output.canonical_directory().join("00")).unwrap(),
            b"abcd"
        );
        assert_eq!(
            fs::read(output.canonical_directory().join("01")).unwrap(),
            b"efgh"
        );
        assert_eq!(
            fs::read(output.canonical_directory().join("02")).unwrap(),
            b"ij"
        );
        assert_eq!(
            resolve_bytes(&bundle, output.canonical_directory(), &trust),
            source_bytes
        );

        let member = output.canonical_directory().join("01");
        let resolved_member = Engine::new()
            .resolve_inputs_with(
                InputResolutionRequest::new(&bundle).with_path(&member),
                InputResolutionCapabilities::new().with_split_trust_store(&trust),
            )
            .unwrap();
        let opened = resolved_member.inputs[0]
            .segments
            .iter()
            .map(|segment| open_segment_file(&segment.path, segment.size).unwrap())
            .collect();
        let mut reader = SegmentedFileReader::from_segments(opened).unwrap();
        reader.seek(SeekFrom::Start(3)).unwrap();
        let mut crossing = [0_u8; 6];
        reader.read_exact(&mut crossing).unwrap();
        assert_eq!(&crossing, b"defghi");
        assert_eq!(session.current_operation().unwrap().completed_bytes(), 10);
        assert!(!progress.lock().unwrap().is_empty());

        let journal_path = fs::read_dir(bundle.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "journal")
            })
            .expect("completed transaction journal");
        let journal = fs::read_to_string(journal_path).unwrap();
        let phases = journal
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["phase"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        let mut previous = None;
        for phase in [
            "prepared",
            "staging",
            "verified",
            "publishing",
            "published",
            "receipt_commit_started",
            "receipt_committed",
            "completed",
        ] {
            let next = phases
                .iter()
                .enumerate()
                .find(|(index, observed)| {
                    previous.is_none_or(|previous| *index > previous) && observed.as_str() == phase
                })
                .map(|(index, _)| index)
                .unwrap_or_else(|| panic!("journal is missing ordered phase {phase}"));
            previous = Some(next);
        }

        let same_plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 4, None).unwrap();
        let same_result = Engine::new().execute_split(same_plan, &OperationSession::new());
        assert_eq!(
            same_result.outcome(),
            Some(OperationOutcome::AlreadyUpToDate)
        );
        assert_eq!(
            same_result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::ConfirmedCommitted)
        );

        let different_representation =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 8, None).unwrap();
        assert_eq!(
            different_representation.snapshot().segment_lengths(),
            [8, 2]
        );
        let different_result =
            Engine::new().execute_split(different_representation, &OperationSession::new());
        assert_eq!(
            different_result.failure().unwrap().code(),
            OperationFailureCode::DestinationConflict
        );
        assert_eq!(
            resolve_bytes(&bundle, output.canonical_directory(), &trust),
            source_bytes
        );

        fs::remove_file(&source).unwrap();
        assert_eq!(
            resolve_bytes(&bundle, output.canonical_directory(), &trust),
            source_bytes
        );
    }

    #[test]
    fn destination_created_after_planning_is_preserved_and_rejected() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"planned source");
        let trust = LocalSplitTrustStore::new(state_path);
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 4, None).unwrap();
        fs::create_dir(&bundle).unwrap();
        fs::write(bundle.join("user-data"), b"keep this directory").unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::DestinationChanged
        );
        assert_eq!(
            fs::read(bundle.join("user-data")).unwrap(),
            b"keep this directory"
        );
        assert!(!bundle.join("loose.nca").exists());
    }

    #[test]
    fn source_backed_output_resolves_after_bundle_and_canonical_names_change() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"portable evidence");
        let trust = LocalSplitTrustStore::new(state_path);
        let result = run_with_size(&source, &bundle, &trust, 5);
        let output = result.split_output_paths().unwrap();
        assert_eq!(
            fs::canonicalize(output.bundle_directory()).unwrap(),
            fs::canonicalize(&bundle).unwrap()
        );
        let moved_bundle = bundle.with_file_name("renamed-bundle");
        fs::rename(&bundle, &moved_bundle).unwrap();
        let canonical = moved_bundle.join("loose.nca");
        let renamed_canonical = moved_bundle.join("backup.zip");
        fs::rename(&canonical, &renamed_canonical).unwrap();
        fs::rename(
            moved_bundle.join("loose.nca.nscb-split.json"),
            moved_bundle.join("backup.zip.nscb-split.json"),
        )
        .unwrap();

        assert_eq!(
            resolve_bytes(&moved_bundle, &renamed_canonical, &trust),
            b"portable evidence"
        );
        assert_eq!(
            resolve_bytes(&moved_bundle, &renamed_canonical.join("01"), &trust),
            b"portable evidence"
        );
    }

    #[test]
    fn source_mutation_during_staging_prevents_publication() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"original source bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 4, None).unwrap();
        let changed = Arc::new(AtomicBool::new(false));
        let changed_source = Arc::clone(&changed);
        let source_for_observer = source.clone();
        let session = OperationSession::with_progress_observer(move |_| {
            if !changed_source.swap(true, Ordering::SeqCst) {
                fs::write(&source_for_observer, b"changed source bytes!").unwrap();
            }
        });

        let result = Engine::new().execute_split(plan, &session);

        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::SourceChanged
        );
        assert!(!bundle.exists());
        assert!(changed.load(Ordering::SeqCst));
    }

    #[test]
    fn source_path_replacement_after_planning_preserves_both_files_and_rejects_output() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"planned source bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 8, None).unwrap();
        let replacement = source.with_extension("replacement");
        let original = source.with_extension("original");
        fs::write(&replacement, b"replacement source bytes").unwrap();
        fs::rename(&source, &original).unwrap();
        fs::rename(&replacement, &source).unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::SourceChanged
        );
        assert!(!bundle.exists());
        assert_eq!(fs::read(&original).unwrap(), b"planned source bytes");
        assert_eq!(fs::read(&source).unwrap(), b"replacement source bytes");
    }

    #[test]
    fn source_and_destination_symlink_aliases_fail_closed_before_mutation() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"symlink source bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        let target = root.path().join("target.bin");
        let source_alias = root.path().join("source-alias.bin");
        fs::write(&target, b"symlink source bytes").unwrap();
        symlink(&target, &source_alias).unwrap();

        let source_error = Engine::new()
            .plan_split(SplitRequest::new(&source_alias, &bundle), &trust)
            .unwrap_err();
        assert_eq!(source_error.code(), OperationFailureCode::SourceUnavailable);
        assert!(!bundle.exists());

        let real_destination = bundle.with_file_name("real-bundle");
        fs::create_dir(&real_destination).unwrap();
        let destination_alias = bundle.with_file_name("bundle-alias");
        symlink(&real_destination, &destination_alias).unwrap();
        let destination_error = Engine::new()
            .plan_split(SplitRequest::new(&source, &destination_alias), &trust)
            .unwrap_err();
        assert_eq!(
            destination_error.code(),
            OperationFailureCode::DestinationConflict
        );
        assert!(fs::read_dir(&real_destination).unwrap().next().is_none());
    }

    #[test]
    fn source_nested_in_destination_bundle_is_rejected_as_a_path_alias() {
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("output");
        fs::create_dir(&output).unwrap();
        let bundle = output.join("bundle");
        fs::create_dir(&bundle).unwrap();
        let source = bundle.join("source.bin");
        fs::write(&source, b"source inside destination").unwrap();
        let trust = LocalSplitTrustStore::new(root.path().join("state").join("split-trust"));

        let error = Engine::new()
            .plan_split(SplitRequest::new(&source, &bundle), &trust)
            .unwrap_err();

        assert_eq!(error.code(), OperationFailureCode::UnsafePath);
        assert_eq!(fs::read(&source).unwrap(), b"source inside destination");
        assert_eq!(fs::read_dir(&bundle).unwrap().count(), 1);
    }

    #[test]
    fn concurrent_plans_for_one_destination_publish_at_most_one_bundle() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"concurrent source bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        let first_plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 8, None).unwrap();
        let second_plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 8, None).unwrap();
        let barrier = Barrier::new(2);

        let (first, second) = std::thread::scope(|scope| {
            let first_barrier = &barrier;
            let second_barrier = &barrier;
            let first_worker = scope.spawn(move || {
                first_barrier.wait();
                Engine::new().execute_split(first_plan, &OperationSession::new())
            });
            let second_worker = scope.spawn(move || {
                second_barrier.wait();
                Engine::new().execute_split(second_plan, &OperationSession::new())
            });
            (first_worker.join().unwrap(), second_worker.join().unwrap())
        });

        let results = [first, second];
        assert_eq!(
            results
                .iter()
                .filter(|result| result.outcome() == Some(OperationOutcome::SplitCreated))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| result.failure().is_some())
                .count(),
            1
        );
        assert_eq!(
            resolve_bytes(&bundle, &bundle.join("loose.nca"), &trust),
            b"concurrent source bytes"
        );
    }

    #[test]
    fn destination_locks_exclude_the_same_name_and_allow_independent_names() {
        let root = tempfile::tempdir().unwrap();
        let parent = super::open_directory(root.path()).unwrap();
        let parent_identity = super::handle_identity(&parent).unwrap();
        let first = super::acquire_destination_lock(
            &parent,
            parent_identity,
            root.path(),
            OsStr::new("bundle-a"),
        )
        .unwrap();

        let same_destination = super::acquire_destination_lock(
            &parent,
            parent_identity,
            root.path(),
            OsStr::new("bundle-a"),
        );
        assert!(matches!(
            same_destination,
            Err(OperationFailureCode::DestinationBusy)
        ));

        let independent = super::acquire_destination_lock(
            &parent,
            parent_identity,
            root.path(),
            OsStr::new("bundle-b"),
        )
        .unwrap();
        assert!(
            first
                .validate(&parent, parent_identity, root.path())
                .is_ok()
        );
        assert!(
            independent
                .validate(&parent, parent_identity, root.path())
                .is_ok()
        );
    }

    #[test]
    fn destination_lock_validation_detects_lock_directory_replacement_and_parent_route_change() {
        let root = tempfile::tempdir().unwrap();
        let parent = super::open_directory(root.path()).unwrap();
        let parent_identity = super::handle_identity(&parent).unwrap();
        let lock = super::acquire_destination_lock(
            &parent,
            parent_identity,
            root.path(),
            OsStr::new("bundle"),
        )
        .unwrap();

        let other_parent = tempfile::tempdir().unwrap();
        assert_eq!(
            lock.validate(&parent, parent_identity, other_parent.path()),
            Err(OperationFailureCode::StalePlan)
        );

        let lock_directory = root.path().join(super::SPLIT_LOCK_DIRECTORY_NAME);
        let lock_path = lock_directory.join("bundle");
        let displaced_lock = lock_directory.join("bundle.displaced");
        fs::rename(&lock_path, &displaced_lock).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .unwrap()
            .sync_all()
            .unwrap();
        assert_eq!(
            lock.validate(&parent, parent_identity, root.path()),
            Err(OperationFailureCode::StalePlan)
        );

        let displaced_directory = root.path().join("displaced-split-locks");
        fs::rename(&lock_directory, &displaced_directory).unwrap();
        fs::create_dir(&lock_directory).unwrap();
        assert_eq!(
            lock.validate(&parent, parent_identity, root.path()),
            Err(OperationFailureCode::StalePlan)
        );
        assert!(displaced_directory.join("bundle").is_file());
        assert!(displaced_directory.join("bundle.displaced").is_file());
    }

    #[test]
    fn cancellation_during_plan_hash_stops_before_admission_or_output_creation() {
        let root = tempfile::tempdir().unwrap();
        let source_bytes = vec![0x5a; SPLIT_IO_BUFFER_SIZE * 2];
        let (source, bundle, state_path) = setup(root.path(), b"replace with larger source");
        fs::write(&source, &source_bytes).unwrap();
        let trust = LocalSplitTrustStore::new(state_path);
        let cancellation = CancellationHandle::new();
        let cancellation_from_progress = cancellation.clone();
        let mut observed_bytes = 0;
        let mut cancel_after_first_chunk = |completed_bytes| {
            observed_bytes = completed_bytes;
            cancellation_from_progress.cancel();
        };

        let error = plan_split_for_tests_with_cancellation(
            SplitRequest::new(&source, &bundle),
            &trust,
            (source_bytes.len() as u64) + 1,
            &cancellation,
            &mut cancel_after_first_chunk,
        )
        .unwrap_err();

        assert_eq!(error.code(), OperationFailureCode::Cancelled);
        assert_eq!(observed_bytes, SPLIT_IO_BUFFER_SIZE as u64);
        assert!(!bundle.exists());
        assert_eq!(fs::read(&source).unwrap(), source_bytes);
    }

    #[test]
    fn cancellation_during_streaming_prevents_publication_and_receipt() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"cancel during streaming");
        let trust = LocalSplitTrustStore::new(state_path);
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 4, None).unwrap();
        let cancellation = CancellationHandle::new();
        let cancellation_from_progress = cancellation.clone();
        let session = OperationSession::with_progress_observer(move |_| {
            cancellation_from_progress.cancel();
        });

        let result = Engine::new().execute_split_with_cancellation(plan, &session, cancellation);

        assert_eq!(result.state(), crate::JobState::Cancelled);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::Cancelled
        );
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::Uncertain)
        );
        assert!(!bundle.exists());
        assert_eq!(fs::read(source).unwrap(), b"cancel during streaming");
    }

    #[test]
    fn cancellation_during_staged_readback_prevents_publication_and_receipt() {
        let root = tempfile::tempdir().unwrap();
        let source_bytes = vec![0x37; SPLIT_IO_BUFFER_SIZE * 2];
        let (source, bundle, state_path) = setup(root.path(), b"replace with readback fixture");
        fs::write(&source, &source_bytes).unwrap();
        let trust = LocalSplitTrustStore::new(state_path);
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            (source_bytes.len() as u64) + 1,
            Some(SplitTestFailpoint::CancelDuringStagedVerification),
        )
        .unwrap();
        let session = OperationSession::new();

        let result = Engine::new().execute_split(plan, &session);

        assert_eq!(result.state(), crate::JobState::Cancelled);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::Cancelled
        );
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::Uncertain)
        );
        assert!(result.cleanup_artifact_retained());
        assert!(
            result
                .split_output_paths()
                .unwrap()
                .recovery_bundle_directory()
                .is_some_and(|path| path.is_dir())
        );
        assert!(!bundle.exists());
        assert_eq!(fs::read(&source).unwrap(), source_bytes);
    }

    #[test]
    fn staging_sync_sidecar_sync_and_rename_failures_never_publish_or_issue_trust() {
        let cases = [
            (
                SplitTestFailpoint::FailureBeforeSegmentSync,
                OperationFailureCode::WriteFailed,
            ),
            (
                SplitTestFailpoint::FailureBeforeManifestSync,
                OperationFailureCode::WriteFailed,
            ),
            (
                SplitTestFailpoint::FailureAtPromotion,
                OperationFailureCode::PublicationFailed,
            ),
        ];
        for (failpoint, expected_failure) in cases {
            let root = tempfile::tempdir().unwrap();
            let (source, bundle, state_path) = setup(root.path(), b"staging fault fixture");
            let trust = LocalSplitTrustStore::new(state_path);
            let plan = plan_split_for_tests(
                SplitRequest::new(&source, &bundle),
                &trust,
                4,
                Some(failpoint),
            )
            .unwrap();

            let result = Engine::new().execute_split(plan, &OperationSession::new());

            assert_eq!(result.failure().unwrap().code(), expected_failure);
            assert_eq!(
                result.split_receipt_commit_state(),
                Some(SplitReceiptCommitState::Uncertain)
            );
            assert!(result.cleanup_artifact_retained());
            assert!(!bundle.exists());
            assert_eq!(fs::read(&source).unwrap(), b"staging fault fixture");
            let recovery = result
                .split_output_paths()
                .unwrap()
                .recovery_bundle_directory()
                .unwrap();
            assert!(recovery.is_dir());
            assert!(
                Engine::new()
                    .resolve_inputs_with(
                        InputResolutionRequest::new(recovery).with_path(recovery.join("loose.nca")),
                        InputResolutionCapabilities::new().with_split_trust_store(&trust),
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn failed_promotion_retains_a_fully_verified_provisional_bundle_without_safe_unlink() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"verified provisional bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            5,
            Some(SplitTestFailpoint::FailureAtPromotion),
        )
        .unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::PublicationFailed)
        );
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::Uncertain)
        );
        assert!(result.cleanup_artifact_retained());
        let recovery = result
            .split_output_paths()
            .unwrap()
            .recovery_bundle_directory()
            .unwrap();
        assert!(recovery.is_dir());
        assert!(recovery.join("loose.nca").join("00").is_file());
        let retained_bytes = fs::read_dir(recovery.join("loose.nca"))
            .unwrap()
            .map(|entry| fs::metadata(entry.unwrap().path()).unwrap().len())
            .sum::<u64>()
            + fs::metadata(recovery.join("loose.nca.nscb-split.json"))
                .unwrap()
                .len();
        assert_eq!(result.retained_storage_bytes(), Some(retained_bytes));
        assert!(
            Engine::new()
                .resolve_inputs_with(
                    InputResolutionRequest::new(recovery).with_path(recovery.join("loose.nca")),
                    InputResolutionCapabilities::new().with_split_trust_store(&trust),
                )
                .is_err()
        );
        assert!(!bundle.exists());
        assert_eq!(fs::read(source).unwrap(), b"verified provisional bytes");
    }

    #[test]
    fn restart_reconciles_and_cleans_a_fully_owned_unpublished_bundle() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"restart cleanup fixture");
        let trust = LocalSplitTrustStore::new(state_path);
        let (staged_plan, names, staging_path) = stage_only(&source, &bundle, &trust, 7);
        drop(staged_plan);
        assert!(staging_path.is_dir());

        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 7, None).unwrap();
        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert!(result.failure().is_none());
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::ConfirmedCommitted)
        );
        assert!(!result.cleanup_artifact_retained());
        assert!(!staging_path.exists());
        assert!(bundle.is_dir());
        assert_eq!(
            (0..4)
                .flat_map(|index| {
                    fs::read(bundle.join("loose.nca").join(format!("{index:02}"))).unwrap()
                })
                .collect::<Vec<_>>(),
            b"restart cleanup fixture"
        );
        let parent = super::open_directory(bundle.parent().unwrap()).unwrap();
        let journal = super::open_journal_writer(&parent, &names.journal).unwrap();
        assert_eq!(journal.record.phase, super::JournalPhase::CleanupComplete);
    }

    #[test]
    fn cleanup_preserves_a_created_root_moved_out_of_its_recorded_path() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"moved staging root");
        let trust = LocalSplitTrustStore::new(state_path);
        let (plan, names, staging_path) = stage_only(&source, &bundle, &trust, 6);
        let moved_path = bundle.parent().unwrap().join("moved-staging-root");
        fs::rename(&staging_path, &moved_path).unwrap();

        let cleanup = super::cleanup_provisional_artifacts(
            &plan.snapshot,
            &plan.state,
            &names.journal,
            SplitReceiptCommitState::NotAttempted,
        );

        assert_eq!(cleanup, Err(OperationFailureCode::PublicationUncertain));
        assert!(moved_path.is_dir());
        assert!(moved_path.join("loose.nca").join("00").is_file());
        let parent = super::open_directory(bundle.parent().unwrap()).unwrap();
        let journal = super::open_journal_writer(&parent, &names.journal).unwrap();
        assert_eq!(journal.record.phase, super::JournalPhase::Cleaning);
    }

    #[test]
    fn planned_but_uncreated_artifact_is_closed_as_clean_without_removal() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"planned fixture");
        let trust = LocalSplitTrustStore::new(state_path);
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 4, None).unwrap();
        let names = super::transaction_names();
        let mut journal = start_staging_journal(&plan, &names);
        let _staging_path_hex = plan_staging_root(&plan, &names, &mut journal);
        let staging_path = bundle.parent().unwrap().join(&names.staging);
        drop(journal);

        super::cleanup_provisional_artifacts(
            &plan.snapshot,
            &plan.state,
            &names.journal,
            SplitReceiptCommitState::NotAttempted,
        )
        .unwrap();

        assert!(!staging_path.exists());
        assert!(bundle.parent().unwrap().join(&names.journal).is_file());
        let parent = super::open_directory(bundle.parent().unwrap()).unwrap();
        let journal = super::open_journal_writer(&parent, &names.journal).unwrap();
        assert_eq!(journal.record.phase, super::JournalPhase::CleanupComplete);
    }

    #[test]
    fn empty_initialization_journal_is_preserved_without_blocking_recovery() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"journal initialization crash");
        let trust = LocalSplitTrustStore::new(state_path);
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 5, None).unwrap();
        let names = super::transaction_names();
        let initializing_name = format!("{}.initializing", names.journal.to_string_lossy());
        let initializing_path = bundle.parent().unwrap().join(initializing_name);
        let initializing_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&initializing_path)
            .unwrap();
        initializing_file.sync_all().unwrap();
        drop(initializing_file);

        let parent_path = plan.snapshot.bundle_directory.parent().unwrap();
        let lock = super::acquire_destination_lock(
            &plan.state.destination_parent,
            plan.state.destination_parent_identity,
            parent_path,
            &plan.state.destination_name,
        )
        .unwrap();
        assert!(
            super::recover_incomplete_for_destination(
                &plan.snapshot,
                &plan.state,
                &lock,
                None,
                &mut super::SplitArtifactSources::default(),
            )
            .is_ok()
        );
        assert!(initializing_path.is_file());
        drop(lock);

        let result = run_with_size(&source, &bundle, &trust, 5);

        assert_eq!(result.outcome(), Some(OperationOutcome::SplitCreated));
        assert!(initializing_path.is_file());
        assert_eq!(fs::read(source).unwrap(), b"journal initialization crash");
    }

    #[test]
    fn artifact_created_before_identity_record_is_preserved() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"creation window fixture");
        let trust = LocalSplitTrustStore::new(state_path);
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 4, None).unwrap();
        let names = super::transaction_names();
        let mut journal = start_staging_journal(&plan, &names);
        plan_staging_root(&plan, &names, &mut journal);
        let staging_path = bundle.parent().unwrap().join(&names.staging);
        super::mkdir_at(&plan.state.destination_parent, &names.staging).unwrap();
        plan.state.destination_parent.sync_all().unwrap();
        drop(journal);

        assert!(
            super::cleanup_provisional_artifacts(
                &plan.snapshot,
                &plan.state,
                &names.journal,
                SplitReceiptCommitState::NotAttempted,
            )
            .is_err()
        );

        assert!(staging_path.is_dir());
    }

    #[test]
    fn child_created_before_identity_record_is_preserved() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"child creation window");
        let trust = LocalSplitTrustStore::new(state_path);
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 4, None).unwrap();
        let names = super::transaction_names();
        let mut journal = start_staging_journal(&plan, &names);
        let staging_path = plan_staging_root(&plan, &names, &mut journal);
        let stage = super::create_journaled_directory(
            &plan.state.destination_parent,
            &names.staging,
            &staging_path,
            &mut journal,
            true,
        )
        .unwrap();
        let canonical_name = plan.snapshot.canonical_directory.file_name().unwrap();
        let canonical_path = vec![
            super::encode_os_name(&names.staging),
            super::encode_os_name(canonical_name),
        ];
        super::plan_journal_artifacts(
            &mut journal,
            vec![super::planned_artifact(
                canonical_path,
                super::handle_identity(&stage).unwrap(),
                super::ArtifactKind::Directory,
            )],
        )
        .unwrap();
        super::mkdir_at(&stage, canonical_name).unwrap();
        stage.sync_all().unwrap();
        let canonical = bundle
            .parent()
            .unwrap()
            .join(&names.staging)
            .join(canonical_name);
        drop(journal);

        assert!(
            super::cleanup_provisional_artifacts(
                &plan.snapshot,
                &plan.state,
                &names.journal,
                SplitReceiptCommitState::NotAttempted,
            )
            .is_err()
        );

        assert!(canonical.is_dir());
        assert!(canonical.parent().unwrap().is_dir());
    }

    #[test]
    fn partial_file_after_created_identity_record_is_preserved() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"partial file fixture");
        let trust = LocalSplitTrustStore::new(state_path);
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 4, None).unwrap();
        let names = super::transaction_names();
        let mut journal = start_staging_journal(&plan, &names);
        let stage_path = plan_staging_root(&plan, &names, &mut journal);
        let stage = super::create_journaled_directory(
            &plan.state.destination_parent,
            &names.staging,
            &stage_path,
            &mut journal,
            true,
        )
        .unwrap();
        let canonical_name = plan.snapshot.canonical_directory.file_name().unwrap();
        let canonical_path = vec![
            super::encode_os_name(&names.staging),
            super::encode_os_name(canonical_name),
        ];
        super::plan_journal_artifacts(
            &mut journal,
            vec![super::planned_artifact(
                canonical_path.clone(),
                super::handle_identity(&stage).unwrap(),
                super::ArtifactKind::Directory,
            )],
        )
        .unwrap();
        let canonical = super::create_journaled_directory(
            &stage,
            canonical_name,
            &canonical_path,
            &mut journal,
            false,
        )
        .unwrap();
        let part_name = "00";
        let part_path = vec![
            super::encode_os_name(&names.staging),
            super::encode_os_name(canonical_name),
            super::encode_os_name(OsStr::new(part_name)),
        ];
        super::plan_journal_artifacts(
            &mut journal,
            vec![super::planned_artifact(
                part_path.clone(),
                super::handle_identity(&canonical).unwrap(),
                super::ArtifactKind::RegularFile,
            )],
        )
        .unwrap();
        let mut part = super::create_journaled_file(
            &canonical,
            OsStr::new(part_name),
            &part_path,
            &mut journal,
        )
        .unwrap();
        part.write_all(b"part").unwrap();
        part.sync_all().unwrap();
        drop(part);
        drop(journal);
        let part_path = bundle
            .parent()
            .unwrap()
            .join(&names.staging)
            .join(canonical_name)
            .join(part_name);

        assert!(
            super::cleanup_provisional_artifacts(
                &plan.snapshot,
                &plan.state,
                &names.journal,
                SplitReceiptCommitState::NotAttempted,
            )
            .is_err()
        );

        assert_eq!(fs::read(part_path).unwrap(), b"part");
    }

    #[test]
    fn file_created_before_identity_record_is_preserved() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"unrecorded file fixture");
        let trust = LocalSplitTrustStore::new(state_path);
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 4, None).unwrap();
        let names = super::transaction_names();
        let mut journal = start_staging_journal(&plan, &names);
        let stage_path = plan_staging_root(&plan, &names, &mut journal);
        let stage = super::create_journaled_directory(
            &plan.state.destination_parent,
            &names.staging,
            &stage_path,
            &mut journal,
            true,
        )
        .unwrap();
        let canonical_name = plan.snapshot.canonical_directory.file_name().unwrap();
        let canonical_path = vec![
            super::encode_os_name(&names.staging),
            super::encode_os_name(canonical_name),
        ];
        super::plan_journal_artifacts(
            &mut journal,
            vec![super::planned_artifact(
                canonical_path.clone(),
                super::handle_identity(&stage).unwrap(),
                super::ArtifactKind::Directory,
            )],
        )
        .unwrap();
        let canonical = super::create_journaled_directory(
            &stage,
            canonical_name,
            &canonical_path,
            &mut journal,
            false,
        )
        .unwrap();
        let part_name = OsStr::new("00");
        let part_path = vec![
            super::encode_os_name(&names.staging),
            super::encode_os_name(canonical_name),
            super::encode_os_name(part_name),
        ];
        super::plan_journal_artifacts(
            &mut journal,
            vec![super::planned_artifact(
                part_path,
                super::handle_identity(&canonical).unwrap(),
                super::ArtifactKind::RegularFile,
            )],
        )
        .unwrap();
        let mut part = super::create_file_at(&canonical, part_name).unwrap();
        part.write_all(b"foreign").unwrap();
        part.sync_all().unwrap();
        canonical.sync_all().unwrap();
        drop(part);
        drop(journal);
        let part_path = bundle
            .parent()
            .unwrap()
            .join(&names.staging)
            .join(canonical_name)
            .join(part_name);

        assert!(
            super::cleanup_provisional_artifacts(
                &plan.snapshot,
                &plan.state,
                &names.journal,
                SplitReceiptCommitState::NotAttempted,
            )
            .is_err()
        );

        assert_eq!(fs::read(part_path).unwrap(), b"foreign");
    }

    #[test]
    fn empty_file_with_durable_created_identity_is_retained_without_safe_unlink() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"empty file fixture");
        let trust = LocalSplitTrustStore::new(state_path);
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 4, None).unwrap();
        let names = super::transaction_names();
        let mut journal = start_staging_journal(&plan, &names);
        let stage_path = plan_staging_root(&plan, &names, &mut journal);
        let stage = super::create_journaled_directory(
            &plan.state.destination_parent,
            &names.staging,
            &stage_path,
            &mut journal,
            true,
        )
        .unwrap();
        let canonical_name = plan.snapshot.canonical_directory.file_name().unwrap();
        let canonical_path = vec![
            super::encode_os_name(&names.staging),
            super::encode_os_name(canonical_name),
        ];
        super::plan_journal_artifacts(
            &mut journal,
            vec![super::planned_artifact(
                canonical_path.clone(),
                super::handle_identity(&stage).unwrap(),
                super::ArtifactKind::Directory,
            )],
        )
        .unwrap();
        let canonical = super::create_journaled_directory(
            &stage,
            canonical_name,
            &canonical_path,
            &mut journal,
            false,
        )
        .unwrap();
        let part_name = OsStr::new("00");
        let part_path = vec![
            super::encode_os_name(&names.staging),
            super::encode_os_name(canonical_name),
            super::encode_os_name(part_name),
        ];
        super::plan_journal_artifacts(
            &mut journal,
            vec![super::planned_artifact(
                part_path,
                super::handle_identity(&canonical).unwrap(),
                super::ArtifactKind::RegularFile,
            )],
        )
        .unwrap();
        let part = super::create_journaled_file(
            &canonical,
            part_name,
            &[
                super::encode_os_name(&names.staging),
                super::encode_os_name(canonical_name),
                super::encode_os_name(part_name),
            ],
            &mut journal,
        )
        .unwrap();
        drop(part);
        drop(journal);
        let staging_path = bundle.parent().unwrap().join(&names.staging);

        assert_eq!(
            super::cleanup_provisional_artifacts(
                &plan.snapshot,
                &plan.state,
                &names.journal,
                SplitReceiptCommitState::NotAttempted,
            ),
            Err(OperationFailureCode::PublicationUncertain)
        );

        assert!(staging_path.is_dir());
        assert_eq!(
            fs::metadata(staging_path.join("loose.nca").join("00"))
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn recovery_preserves_owned_children_after_interrupted_partial_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"partial cleanup fixture");
        let trust = LocalSplitTrustStore::new(state_path);
        let (plan, names, staging_path) = stage_only(&source, &bundle, &trust, 8);
        let missing_part = staging_path.join("loose.nca").join("00");
        fs::remove_file(&missing_part).unwrap();

        assert_eq!(
            super::cleanup_provisional_artifacts(
                &plan.snapshot,
                &plan.state,
                &names.journal,
                SplitReceiptCommitState::NotAttempted,
            ),
            Err(OperationFailureCode::PublicationUncertain)
        );

        assert!(!missing_part.exists());
        assert!(staging_path.join("loose.nca").join("01").is_file());
        assert!(staging_path.is_dir());
    }

    #[test]
    fn concurrent_recovery_and_writers_serialize_stale_stage_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"concurrent recovery fixture");
        let trust = LocalSplitTrustStore::new(state_path);
        let (staged_plan, names, staging_path) = stage_only(&source, &bundle, &trust, 9);
        drop(staged_plan);
        let plans = [
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 9, None).unwrap(),
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 9, None).unwrap(),
        ];
        let results = std::thread::scope(|scope| {
            let workers = plans
                .into_iter()
                .map(|plan| {
                    scope.spawn(move || Engine::new().execute_split(plan, &OperationSession::new()))
                })
                .collect::<Vec<_>>();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });

        let dispositions = results
            .iter()
            .map(|result| {
                (
                    result.outcome(),
                    result.failure().map(|failure| failure.code()),
                    result.cleanup_artifact_retained(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            results
                .iter()
                .filter(|result| result.failure().is_none())
                .count(),
            1,
            "exactly one concurrent operation should succeed: {dispositions:?}"
        );
        assert!(
            results
                .iter()
                .filter_map(|result| result.failure())
                .all(|failure| {
                    matches!(
                        failure.code(),
                        OperationFailureCode::DestinationBusy
                            | OperationFailureCode::Busy
                            | OperationFailureCode::StalePlan
                    )
                })
        );
        assert!(!staging_path.exists());
        assert_eq!(
            (0..3)
                .flat_map(|index| {
                    fs::read(bundle.join("loose.nca").join(format!("{index:02}"))).unwrap()
                })
                .collect::<Vec<_>>(),
            b"concurrent recovery fixture"
        );
        let parent = super::open_directory(bundle.parent().unwrap()).unwrap();
        let journal = super::open_journal_writer(&parent, &names.journal).unwrap();
        assert_eq!(journal.record.phase, super::JournalPhase::CleanupComplete);
    }

    #[test]
    fn cleanup_preserves_a_same_length_modified_segment() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"abcdefgh");
        let trust = LocalSplitTrustStore::new(state_path);
        let (plan, names, staging_path) = stage_only(&source, &bundle, &trust, 4);
        let part = staging_path.join("loose.nca").join("00");
        fs::write(&part, b"XXXXXXXX").unwrap();
        let modified = fs::read(&part).unwrap();

        assert!(
            super::cleanup_provisional_artifacts(
                &plan.snapshot,
                &plan.state,
                &names.journal,
                SplitReceiptCommitState::NotAttempted,
            )
            .is_err()
        );

        assert_eq!(fs::read(part).unwrap(), modified);
        assert!(staging_path.is_dir());
    }

    #[test]
    fn cleanup_preserves_a_directory_with_modified_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"directory mode fixture");
        let trust = LocalSplitTrustStore::new(state_path);
        let (plan, names, staging_path) = stage_only(&source, &bundle, &trust, 8);
        let canonical = staging_path.join("loose.nca");
        fs::set_permissions(&canonical, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            super::cleanup_provisional_artifacts(
                &plan.snapshot,
                &plan.state,
                &names.journal,
                SplitReceiptCommitState::NotAttempted,
            )
            .is_err()
        );

        assert!(canonical.is_dir());
        assert!(staging_path.is_dir());
    }

    #[test]
    fn cleanup_preserves_all_staged_data_when_a_foreign_child_is_added() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"foreign child fixture");
        let trust = LocalSplitTrustStore::new(state_path);
        let (plan, names, staging_path) = stage_only(&source, &bundle, &trust, 8);
        let foreign = staging_path.join("loose.nca").join("owner-data");
        fs::write(&foreign, b"keep this file").unwrap();
        let part = staging_path.join("loose.nca").join("00");

        assert!(
            super::cleanup_provisional_artifacts(
                &plan.snapshot,
                &plan.state,
                &names.journal,
                SplitReceiptCommitState::NotAttempted,
            )
            .is_err()
        );

        assert_eq!(fs::read(&foreign).unwrap(), b"keep this file");
        assert!(part.is_file());
        assert!(staging_path.is_dir());
    }

    #[test]
    fn cleanup_does_not_follow_a_symlink_substituted_for_a_segment() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"symlink substitution");
        let trust = LocalSplitTrustStore::new(state_path);
        let (plan, names, staging_path) = stage_only(&source, &bundle, &trust, 8);
        let part = staging_path.join("loose.nca").join("00");
        fs::remove_file(&part).unwrap();
        symlink(&source, &part).unwrap();

        assert!(
            super::cleanup_provisional_artifacts(
                &plan.snapshot,
                &plan.state,
                &names.journal,
                SplitReceiptCommitState::NotAttempted,
            )
            .is_err()
        );

        assert!(
            fs::symlink_metadata(&part)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&source).unwrap(), b"symlink substitution");
        assert!(staging_path.is_dir());
    }

    #[test]
    fn cleanup_revalidates_the_name_after_opening_the_owned_file() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"revalidate before unlink");
        let trust = LocalSplitTrustStore::new(state_path);
        let (mut plan, names, staging_path) = stage_only(&source, &bundle, &trust, 8);
        plan.state.test_failpoint =
            Some(SplitTestFailpoint::SubstituteArtifactBeforeFinalIdentityCheck);
        let part = staging_path.join("loose.nca").join("00");
        let original_part = fs::read(&part).unwrap();

        let cleanup = super::cleanup_provisional_artifacts(
            &plan.snapshot,
            &plan.state,
            &names.journal,
            SplitReceiptCommitState::NotAttempted,
        );

        assert_eq!(cleanup, Err(OperationFailureCode::PublicationUncertain));
        assert_eq!(
            fs::read(part.with_file_name("00.preserved")).unwrap(),
            original_part
        );
        assert!(
            fs::symlink_metadata(&part)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_link(&part).unwrap(),
            Path::new("missing-cleanup-target")
        );
        assert!(staging_path.is_dir());
    }

    #[test]
    fn cleanup_preserves_a_replacement_after_the_final_identity_check() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"replace after final check");
        let trust = LocalSplitTrustStore::new(state_path);
        let (mut plan, names, staging_path) = stage_only(&source, &bundle, &trust, 8);
        plan.state.test_failpoint =
            Some(SplitTestFailpoint::SubstituteArtifactAfterFinalIdentityCheck);
        let part = staging_path.join("loose.nca").join("00");
        let original_part = fs::read(&part).unwrap();

        let cleanup = super::cleanup_provisional_artifacts(
            &plan.snapshot,
            &plan.state,
            &names.journal,
            SplitReceiptCommitState::NotAttempted,
        );

        assert_eq!(cleanup, Err(OperationFailureCode::PublicationUncertain));
        assert_eq!(
            fs::read(part.with_file_name("00.preserved")).unwrap(),
            original_part
        );
        assert!(
            fs::symlink_metadata(&part)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&source).unwrap(), b"replace after final check");
        assert!(staging_path.is_dir());
    }

    #[test]
    fn cleanup_rechecks_the_atomically_quarantined_entry_before_unlink() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"replace quarantine entry");
        let trust = LocalSplitTrustStore::new(state_path);
        let (mut plan, names, staging_path) = stage_only(&source, &bundle, &trust, 8);
        plan.state.test_failpoint =
            Some(SplitTestFailpoint::SubstituteCleanupAliasAfterIdentityCheck);
        let original_part = fs::read(staging_path.join("loose.nca").join("00")).unwrap();

        let cleanup = super::cleanup_provisional_artifacts(
            &plan.snapshot,
            &plan.state,
            &names.journal,
            SplitReceiptCommitState::NotAttempted,
        );

        assert_eq!(cleanup, Err(OperationFailureCode::PublicationUncertain));
        assert!(!staging_path.exists());
        let quarantined_root = bundle
            .parent()
            .unwrap()
            .join(super::SPLIT_LOCK_DIRECTORY_NAME)
            .join(format!(".nscb-split-cleanup-{}", names.transaction_id));
        let parent = super::open_directory(bundle.parent().unwrap()).unwrap();
        let journal = super::open_journal_writer(&parent, &names.journal).unwrap();
        let index = journal
            .record
            .artifacts
            .iter()
            .position(|artifact| {
                artifact.kind == super::ArtifactKind::RegularFile
                    && artifact.relative_path_hex.last().is_some_and(|name| {
                        super::decode_os_name(name).as_deref() == Some(std::ffi::OsStr::new("00"))
                    })
            })
            .unwrap();
        let alias_name = super::cleanup_quarantine_name(&journal.record, index);
        let alias = quarantined_root.join("loose.nca").join(&alias_name);
        let mut preserved_name = alias_name;
        preserved_name.push(".preserved");
        let preserved = alias.with_file_name(preserved_name);
        assert_eq!(fs::read(preserved).unwrap(), original_part);
        assert!(
            fs::symlink_metadata(alias)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(journal.record.phase, super::JournalPhase::Cleaning);
        assert_eq!(fs::read(source).unwrap(), b"replace quarantine entry");
    }

    #[test]
    fn cleanup_retains_artifacts_when_store_state_is_missing() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"missing store cleanup");
        let trust = LocalSplitTrustStore::new(&state_path);
        let (plan, names, staging_path) = stage_only(&source, &bundle, &trust, 8);
        fs::remove_dir_all(state_path).unwrap();

        let cleanup = super::cleanup_provisional_artifacts(
            &plan.snapshot,
            &plan.state,
            &names.journal,
            SplitReceiptCommitState::Uncertain,
        );

        assert_eq!(cleanup, Err(OperationFailureCode::PublicationUncertain));
        assert!(staging_path.is_dir());
        assert!(staging_path.join("loose.nca").join("00").is_file());
        let parent = super::open_directory(bundle.parent().unwrap()).unwrap();
        let journal = super::open_journal_writer(&parent, &names.journal).unwrap();
        assert_eq!(journal.record.phase, super::JournalPhase::Verified);
    }

    #[test]
    fn cleanup_removes_a_fully_owned_uncommitted_bundle() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"safe cleanup fixture");
        let trust = LocalSplitTrustStore::new(state_path);
        trust
            .issue(SplitTrustReceipt::new(
                crate::Sha256Digest::digest(b"unrelated committed manifest"),
                1,
                crate::Sha256Digest::digest(b"unrelated source"),
            ))
            .unwrap();
        let (plan, names, staging_path) = stage_only(&source, &bundle, &trust, 8);

        let cleanup = super::cleanup_provisional_artifacts(
            &plan.snapshot,
            &plan.state,
            &names.journal,
            SplitReceiptCommitState::NotAttempted,
        );

        assert_eq!(cleanup, Ok(()));
        assert!(!staging_path.exists());
        let parent = super::open_directory(bundle.parent().unwrap()).unwrap();
        let journal = super::open_journal_writer(&parent, &names.journal).unwrap();
        assert_eq!(journal.record.phase, super::JournalPhase::CleanupComplete);
    }

    #[test]
    fn cancellation_while_waiting_for_receipt_state_lock_releases_the_waiter() {
        use std::sync::mpsc;
        use std::thread;

        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"cancel receipt lock wait");
        let trust = LocalSplitTrustStore::new(state_path);
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 8, None).unwrap();
        let destination_lock = acquire_destination_lock(
            &plan.state.destination_parent,
            plan.state.destination_parent_identity,
            bundle.parent().unwrap(),
            &plan.state.destination_name,
        )
        .unwrap();
        let held_receipt_lock = super::ReceiptStateLock::acquire(
            &plan.state.destination_parent,
            &destination_lock,
            None,
        )
        .unwrap();
        let session = OperationSession::new();
        let _admission = session.admit_with_cancellation(None, Some(1)).unwrap();
        let waiter_session = session.clone();
        let (contended_tx, contended_rx) = mpsc::channel();

        let result = thread::scope(|scope| {
            let waiter = scope.spawn(|| {
                let mut contended_tx = Some(contended_tx);
                super::ReceiptStateLock::acquire_inner(
                    &plan.state.destination_parent,
                    &destination_lock,
                    Some(&waiter_session),
                    || {
                        if let Some(contended_tx) = contended_tx.take() {
                            contended_tx.send(()).unwrap();
                        }
                    },
                )
                .map(drop)
            });
            contended_rx.recv().unwrap();
            assert!(session.cancel());
            waiter.join().unwrap()
        });

        assert_eq!(result, Err(OperationFailureCode::Cancelled));
        drop(held_receipt_lock);
        assert!(
            super::ReceiptStateLock::acquire(
                &plan.state.destination_parent,
                &destination_lock,
                None,
            )
            .is_ok()
        );
    }

    #[test]
    fn concurrent_issuance_waits_until_owned_cleanup_finishes() {
        use fs2::FileExt as _;
        use std::sync::mpsc;
        use std::thread;

        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"lease serializes cleanup");
        let trust = LocalSplitTrustStore::new(&state_path);
        trust
            .issue(SplitTrustReceipt::new(
                crate::Sha256Digest::digest(b"initialized trust store"),
                1,
                crate::Sha256Digest::digest(b"store initializer"),
            ))
            .unwrap();
        let (plan, names, staging_path) = stage_only(&source, &bundle, &trust, 8);
        let parent = super::open_directory(bundle.parent().unwrap()).unwrap();
        let journal = super::open_journal_writer(&parent, &names.journal).unwrap();
        let manifest_digest =
            crate::Sha256Digest::parse_hex(journal.record.manifest_sha256.as_deref().unwrap())
                .unwrap();
        let source_digest = crate::Sha256Digest::parse_hex(&journal.record.source_sha256).unwrap();
        drop(journal);

        let cleanup_lease = trust
            .acquire_cleanup_lease(&manifest_digest, &|| false)
            .unwrap()
            .unwrap();
        let contender_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(state_path.join(".lock"))
            .unwrap();
        assert!(contender_lock.try_lock_exclusive().is_err());

        let destination_lock = acquire_destination_lock(
            &plan.state.destination_parent,
            plan.state.destination_parent_identity,
            bundle.parent().unwrap(),
            &plan.state.destination_name,
        )
        .unwrap();
        let receipt_lock = super::ReceiptStateLock::acquire(
            &plan.state.destination_parent,
            &destination_lock,
            None,
        )
        .unwrap();
        let concurrent_store = trust.clone();
        let concurrent_manifest = crate::Sha256Digest::digest(b"concurrent issuance");
        let (ready_tx, ready_rx) = mpsc::channel();
        let issuer = thread::spawn(move || {
            ready_tx.send(()).unwrap();
            concurrent_store.issue(SplitTrustReceipt::new(
                concurrent_manifest,
                5,
                source_digest,
            ))
        });
        ready_rx.recv().unwrap();

        let cleanup = super::cleanup_provisional_artifacts_with_locks_and_lease(
            &plan.snapshot,
            super::SplitCleanupOperationContext {
                state: &plan.state,
                session: None,
            },
            &names.journal,
            SplitReceiptCommitState::NotAttempted,
            &destination_lock,
            &receipt_lock,
            Some(cleanup_lease),
        );

        assert_eq!(cleanup, Ok(()));
        assert!(!staging_path.exists());
        issuer.join().unwrap().unwrap();
        assert!(trust.lookup(&concurrent_manifest).unwrap().is_some());
    }

    #[test]
    fn cancellation_while_waiting_for_store_lock_retains_provisional_artifacts() {
        use fs2::FileExt as _;

        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"cancelled cleanup fixture");
        let inner = LocalSplitTrustStore::new(&state_path);
        seed_cleanup_lease_state(&inner);
        let (wait_sender, wait_receiver) = std::sync::mpsc::channel();
        let trust = WaitNotifyingCleanupLeaseWriter {
            inner,
            lock_wait_sender: wait_sender,
        };
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            7,
            Some(SplitTestFailpoint::FailureAtPromotion),
        )
        .unwrap();
        let held_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(state_path.join(".lock"))
            .unwrap();
        held_lock.try_lock_exclusive().unwrap();
        let session = OperationSession::new();

        let result = std::thread::scope(|scope| {
            let session_ref = &session;
            let worker = scope.spawn(move || Engine::new().execute_split(plan, session_ref));
            wait_receiver.recv().unwrap();
            assert!(session.cancel());
            held_lock.unlock().unwrap();
            worker.join().unwrap()
        });

        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::Cancelled)
        );
        assert!(result.cleanup_artifact_retained());
        assert!(!bundle.exists());
        assert_eq!(fs::read(source).unwrap(), b"cancelled cleanup fixture");
    }

    #[test]
    fn cleanup_preserves_a_bundle_covered_by_an_exact_receipt() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"receipt protects cleanup");
        let trust = LocalSplitTrustStore::new(state_path);
        let (plan, names, staging_path) = stage_only(&source, &bundle, &trust, 8);
        let parent = super::open_directory(bundle.parent().unwrap()).unwrap();
        let journal = super::open_journal_writer(&parent, &names.journal).unwrap();
        let manifest_digest =
            crate::Sha256Digest::parse_hex(journal.record.manifest_sha256.as_deref().unwrap())
                .unwrap();
        let source_digest = crate::Sha256Digest::parse_hex(&journal.record.source_sha256).unwrap();
        trust
            .issue(
                super::SplitTrustReceipt::new(
                    manifest_digest,
                    journal.record.source_size,
                    source_digest,
                )
                .with_predecessor_revision(0),
            )
            .unwrap();

        let cleanup = super::cleanup_provisional_artifacts(
            &plan.snapshot,
            &plan.state,
            &names.journal,
            SplitReceiptCommitState::NotAttempted,
        );

        assert_eq!(cleanup, Err(OperationFailureCode::PublicationUncertain));
        assert!(staging_path.is_dir());
        assert!(trust.lookup(&manifest_digest).unwrap().is_some());
    }

    #[test]
    fn cleanup_preserves_a_replaced_child_before_quarantine() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"replacement during cleanup");
        let trust = LocalSplitTrustStore::new(state_path);
        let (mut plan, names, staging_path) = stage_only(&source, &bundle, &trust, 8);
        plan.state.test_failpoint =
            Some(SplitTestFailpoint::SubstituteArtifactAfterCleanupPreflight);
        let part = staging_path.join("loose.nca").join("00");
        let original_part = fs::read(&part).unwrap();

        let cleanup = super::cleanup_provisional_artifacts(
            &plan.snapshot,
            &plan.state,
            &names.journal,
            SplitReceiptCommitState::NotAttempted,
        );

        assert_eq!(cleanup, Err(OperationFailureCode::PublicationUncertain));
        assert!(staging_path.is_dir());
        let preserved_part = part.with_file_name("00.preserved");
        assert_eq!(fs::read(&preserved_part).unwrap(), original_part);
        assert!(
            fs::symlink_metadata(&part)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let parent = super::open_directory(bundle.parent().unwrap()).unwrap();
        let journal = super::open_journal_writer(&parent, &names.journal).unwrap();
        assert_eq!(journal.record.phase, super::JournalPhase::Cleaning);
    }

    #[test]
    fn cleanup_preserves_same_inode_file_rewritten_to_original_after_preflight() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"same inode edit and restore");
        let trust = LocalSplitTrustStore::new(state_path);
        let (mut plan, names, staging_path) = stage_only(&source, &bundle, &trust, 8);
        plan.state.test_failpoint =
            Some(SplitTestFailpoint::ModifyAndRestoreArtifactAfterCleanupPreflight);
        let part = staging_path.join("loose.nca").join("00");
        let original_part = fs::read(&part).unwrap();

        let cleanup = super::cleanup_provisional_artifacts(
            &plan.snapshot,
            &plan.state,
            &names.journal,
            SplitReceiptCommitState::NotAttempted,
        );

        assert_eq!(cleanup, Err(OperationFailureCode::PublicationUncertain));
        assert!(staging_path.is_dir());
        assert_eq!(fs::read(part).unwrap(), original_part);
    }

    #[test]
    fn cleanup_preserves_a_hardlink_substituted_for_a_segment() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"hardlink substitution");
        let trust = LocalSplitTrustStore::new(state_path);
        let (plan, names, staging_path) = stage_only(&source, &bundle, &trust, 8);
        let part = staging_path.join("loose.nca").join("00");
        let foreign = root.path().join("foreign-owner-data");
        fs::write(&foreign, b"foreign").unwrap();
        fs::remove_file(&part).unwrap();
        fs::hard_link(&foreign, &part).unwrap();

        assert!(
            super::cleanup_provisional_artifacts(
                &plan.snapshot,
                &plan.state,
                &names.journal,
                SplitReceiptCommitState::NotAttempted,
            )
            .is_err()
        );

        assert_eq!(fs::read(&foreign).unwrap(), b"foreign");
        assert_eq!(fs::read(part).unwrap(), b"foreign");
        assert!(staging_path.is_dir());
    }

    #[test]
    fn cleanup_preserves_a_replaced_parent_directory() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"parent identity fixture");
        let trust = LocalSplitTrustStore::new(state_path);
        let (plan, names, staging_path) = stage_only(&source, &bundle, &trust, 8);
        let output = bundle.parent().unwrap().to_path_buf();
        let displaced = root.path().join("output-displaced");
        fs::rename(&output, &displaced).unwrap();
        fs::create_dir(&output).unwrap();

        assert!(
            super::cleanup_provisional_artifacts(
                &plan.snapshot,
                &plan.state,
                &names.journal,
                SplitReceiptCommitState::NotAttempted,
            )
            .is_err()
        );

        assert!(displaced.join(names.staging).is_dir());
        assert!(!staging_path.exists());
        assert_eq!(fs::read_dir(&output).unwrap().count(), 0);
    }

    #[test]
    fn cleanup_preserves_owned_artifacts_when_the_journal_is_torn() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"torn journal fixture");
        let trust = LocalSplitTrustStore::new(state_path);
        let (plan, names, staging_path) = stage_only(&source, &bundle, &trust, 8);
        let journal_path = bundle.parent().unwrap().join(&names.journal);
        let mut journal_file = OpenOptions::new().append(true).open(journal_path).unwrap();
        journal_file.write_all(b"{\"torn\":").unwrap();
        journal_file.sync_all().unwrap();

        assert!(
            super::cleanup_provisional_artifacts(
                &plan.snapshot,
                &plan.state,
                &names.journal,
                SplitReceiptCommitState::NotAttempted,
            )
            .is_err()
        );

        assert!(staging_path.is_dir());
        assert!(staging_path.join("loose.nca").join("00").is_file());
    }

    #[test]
    fn malformed_transaction_journal_stops_recovery_without_mutation() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"preserve this source");
        let trust = LocalSplitTrustStore::new(state_path);
        let journal = bundle.parent().unwrap().join(".nscb-split-torn.journal");
        fs::write(&journal, b"{\"truncated\":").unwrap();
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 4, None).unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::Uncertain)
        );
        assert!(!bundle.exists());
        assert_eq!(fs::read(source).unwrap(), b"preserve this source");
        assert_eq!(fs::read(&journal).unwrap(), b"{\"truncated\":");
    }

    #[test]
    fn journal_without_its_recorded_identity_cannot_authorize_recovery() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"old source bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        fs::write(&source, b"new source bytes").unwrap();
        let interrupted = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            4,
            Some(SplitTestFailpoint::SimulatedInterruptionAfterPublication),
        )
        .unwrap();
        let interruption = Engine::new().execute_split(interrupted, &OperationSession::new());
        let recovery = interruption
            .split_output_paths()
            .unwrap()
            .recovery_bundle_directory()
            .unwrap()
            .to_path_buf();
        assert_eq!(
            fs::canonicalize(&recovery).unwrap(),
            fs::canonicalize(&bundle).unwrap()
        );
        assert_eq!(
            (0..4)
                .flat_map(|index| {
                    fs::read(bundle.join("loose.nca").join(format!("{index:02}"))).unwrap()
                })
                .collect::<Vec<_>>(),
            b"new source bytes"
        );

        let parent_path = bundle.parent().unwrap();
        let journal_path = fs::read_dir(parent_path)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.extension() == Some(OsStr::new("journal")))
            .unwrap();
        let mut identityless_journal = Vec::new();
        for line in fs::read(&journal_path)
            .unwrap()
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let mut record: serde_json::Value = serde_json::from_slice(line).unwrap();
            assert!(
                record
                    .as_object_mut()
                    .unwrap()
                    .remove("journal_identity")
                    .is_some()
            );
            identityless_journal.extend(serde_json::to_vec(&record).unwrap());
            identityless_journal.push(b'\n');
        }
        fs::write(&journal_path, &identityless_journal).unwrap();

        let parent = super::open_directory(parent_path).unwrap();
        let destination_name = bundle.file_name().unwrap();
        let staging_name = recovery.file_name().unwrap();
        let destination_before =
            super::current_directory_identity(&parent, destination_name).unwrap();
        let staging_before = super::current_directory_identity(&parent, staging_name).unwrap();
        let reopened =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 4, None).unwrap();

        let result = Engine::new().execute_split(reopened, &OperationSession::new());

        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert_eq!(
            super::current_directory_identity(&parent, destination_name).unwrap(),
            destination_before
        );
        assert_eq!(
            super::current_directory_identity(&parent, staging_name).unwrap(),
            staging_before
        );
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::Uncertain)
        );
        assert_eq!(fs::read(&journal_path).unwrap(), identityless_journal);
        assert_eq!(fs::read(&source).unwrap(), b"new source bytes");
    }

    #[test]
    fn recovery_preserves_output_when_journal_parent_identity_mismatches() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"old source bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        fs::write(&source, b"new source bytes").unwrap();
        let interrupted = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            4,
            Some(SplitTestFailpoint::SimulatedInterruptionAfterPublication),
        )
        .unwrap();
        let interruption = Engine::new().execute_split(interrupted, &OperationSession::new());
        let recovery = interruption
            .split_output_paths()
            .unwrap()
            .recovery_bundle_directory()
            .unwrap()
            .to_path_buf();
        assert_eq!(
            fs::canonicalize(&recovery).unwrap(),
            fs::canonicalize(&bundle).unwrap()
        );

        let different_parent = root.path().join("different-parent");
        fs::create_dir(&different_parent).unwrap();
        let different_parent_handle = super::open_directory(&different_parent).unwrap();
        let different_parent_identity =
            super::identity_string(super::handle_identity(&different_parent_handle).unwrap());
        let parent_path = bundle.parent().unwrap();
        let target_destination_name_hex = super::encode_os_name(bundle.file_name().unwrap());
        let journal_path = fs::read_dir(parent_path)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                if path.extension() != Some(OsStr::new("journal")) {
                    return false;
                }
                let bytes = fs::read(path).unwrap();
                let last_record = bytes
                    .split(|byte| *byte == b'\n')
                    .rev()
                    .find(|line| !line.is_empty())
                    .unwrap();
                let record: serde_json::Value = serde_json::from_slice(last_record).unwrap();
                record["destination_name_hex"].as_str()
                    == Some(target_destination_name_hex.as_str())
            })
            .unwrap();
        let last_record = fs::read(&journal_path)
            .unwrap()
            .split(|byte| *byte == b'\n')
            .rev()
            .find(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
            .unwrap();
        let staging_name =
            super::decode_os_name(last_record["staging_name_hex"].as_str().unwrap()).unwrap();
        let mut mismatched_journal = Vec::new();
        for line in fs::read(&journal_path)
            .unwrap()
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let mut record: serde_json::Value = serde_json::from_slice(line).unwrap();
            record["destination_parent_identity"] =
                serde_json::Value::String(different_parent_identity.clone());
            for artifact in record["artifacts"].as_array_mut().unwrap() {
                if artifact["relative_path_hex"]
                    .as_array()
                    .is_some_and(|path| path.len() == 1)
                {
                    artifact["parent_identity"] =
                        serde_json::Value::String(different_parent_identity.clone());
                }
            }
            mismatched_journal.extend(serde_json::to_vec(&record).unwrap());
            mismatched_journal.push(b'\n');
        }
        fs::write(&journal_path, &mismatched_journal).unwrap();

        let parent = super::open_directory(parent_path).unwrap();
        let destination_name = bundle.file_name().unwrap();
        let destination_before =
            super::current_directory_identity(&parent, destination_name).unwrap();
        let staging_before = super::current_directory_identity(&parent, &staging_name).unwrap();
        let reopened =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 4, None).unwrap();

        let result = Engine::new().execute_split(reopened, &OperationSession::new());

        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert_eq!(
            super::current_directory_identity(&parent, destination_name).unwrap(),
            destination_before
        );
        assert_eq!(
            super::current_directory_identity(&parent, &staging_name).unwrap(),
            staging_before
        );
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::Uncertain)
        );
        assert_eq!(fs::read(&journal_path).unwrap(), mismatched_journal);
        assert_eq!(fs::read(&source).unwrap(), b"new source bytes");
        assert_eq!(
            (0..4)
                .flat_map(|index| {
                    fs::read(bundle.join("loose.nca").join(format!("{index:02}"))).unwrap()
                })
                .collect::<Vec<_>>(),
            b"new source bytes"
        );
    }

    #[test]
    fn skip_keeps_a_different_qualified_bundle_without_issuing_a_receipt() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"old source bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        let original = run_with_size(&source, &bundle, &trust, 4);
        let original_directory = original
            .split_output_paths()
            .unwrap()
            .canonical_directory()
            .to_path_buf();
        fs::write(&source, b"new source bytes").unwrap();
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle).with_conflict_policy(crate::ConflictPolicy::Skip),
            &trust,
            4,
            None,
        )
        .unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(result.outcome(), Some(OperationOutcome::Skipped));
        assert!(result.artifacts().is_empty());
        assert_eq!(result.retained_storage_bytes(), Some(0));
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::NotAttempted)
        );
        assert_eq!(
            resolve_bytes(&bundle, &original_directory, &trust),
            b"old source bytes"
        );
    }

    #[test]
    fn split_skip_scan_stops_before_fetching_more_entries_after_cancellation() {
        let cancellation = CancellationHandle::new();
        let mut yielded = false;
        let candidates = std::iter::from_fn(|| {
            assert!(!yielded, "scan requested another entry after cancellation");
            yielded = true;
            Some(Ok(PathBuf::from("candidate")))
        });
        let mut qualification_checks = 0;

        let result = has_one_qualified_candidate(candidates, Some(&cancellation), |_| {
            qualification_checks += 1;
            cancellation.cancel();
            true
        });

        assert!(!result);
        assert_eq!(qualification_checks, 1);
    }

    #[test]
    fn skip_accepts_a_qualified_bundle_with_a_different_inner_name_without_mutation() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"old source bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        let differently_named_source = source.with_file_name("previous.nca");
        fs::rename(&source, &differently_named_source).unwrap();
        let original = run_with_size(&differently_named_source, &bundle, &trust, 4);
        let original_directory = original
            .split_output_paths()
            .unwrap()
            .canonical_directory()
            .to_path_buf();
        assert_eq!(
            original_directory.file_name().unwrap(),
            std::ffi::OsStr::new("previous.nca")
        );

        fs::write(&source, b"new source bytes").unwrap();
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle).with_conflict_policy(crate::ConflictPolicy::Skip),
            &trust,
            4,
            None,
        )
        .unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(result.outcome(), Some(OperationOutcome::Skipped));
        assert!(result.artifacts().is_empty());
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::NotAttempted)
        );
        assert!(!bundle.join("loose.nca").exists());
        assert!(!bundle.join("loose.nca.nscb-split.json").exists());
        assert_eq!(fs::read_dir(&bundle).unwrap().count(), 2);
        assert_eq!(
            resolve_bytes(&bundle, &original_directory, &trust),
            b"old source bytes"
        );
    }

    #[test]
    fn skip_rejects_an_unqualified_existing_bundle_without_mutation() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"new source bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        fs::create_dir(&bundle).unwrap();
        let foreign_file = bundle.join("foreign.bin");
        fs::write(&foreign_file, b"preserve this occupant").unwrap();
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle).with_conflict_policy(crate::ConflictPolicy::Skip),
            &trust,
            4,
            None,
        )
        .unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(result.outcome(), None);
        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::DestinationConflict)
        );
        assert_eq!(fs::read(&foreign_file).unwrap(), b"preserve this occupant");
        assert_eq!(fs::read_dir(&bundle).unwrap().count(), 1);
        assert!(!bundle.join("source.nca.nscb-split.json").exists());
    }

    #[test]
    fn skip_rechecks_existing_bundle_qualification_after_planning() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"old source bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        let original = run_with_size(&source, &bundle, &trust, 4);
        let output_paths = original.split_output_paths().unwrap();
        let canonical_directory = output_paths.canonical_directory().to_path_buf();
        let manifest_path = output_paths.manifest_path().to_path_buf();
        let manifest_bytes = fs::read(&manifest_path).unwrap();
        let manifest_digest = crate::Sha256Digest::digest(&manifest_bytes);
        assert!(trust.lookup(&manifest_digest).unwrap().is_some());
        fs::write(&source, b"new source bytes").unwrap();
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle).with_conflict_policy(crate::ConflictPolicy::Skip),
            &trust,
            4,
            None,
        )
        .unwrap();
        let changed_segment = canonical_directory.join("00");
        fs::write(&changed_segment, b"bad!").unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(result.outcome(), None);
        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::DestinationConflict)
        );
        assert_eq!(fs::read(&changed_segment).unwrap(), b"bad!");
        assert_eq!(fs::read(&manifest_path).unwrap(), manifest_bytes);
        assert!(trust.lookup(&manifest_digest).unwrap().is_some());
    }

    #[test]
    fn replace_rejects_occupied_nonmatching_destination_during_planning() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"old source bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        let original = run_with_size(&source, &bundle, &trust, 4);
        let previous_manifest = original
            .split_output_paths()
            .unwrap()
            .manifest_path()
            .to_path_buf();
        fs::write(&source, b"new source bytes").unwrap();
        let error = plan_split_for_tests(
            SplitRequest::new(&source, &bundle)
                .with_conflict_policy(crate::ConflictPolicy::Replace),
            &trust,
            4,
            None,
        )
        .unwrap_err();

        assert_eq!(
            error.code(),
            OperationFailureCode::SplitReplacementUnsupported
        );
        assert_eq!(
            resolve_bytes(&bundle, &bundle.join("loose.nca"), &trust),
            b"old source bytes"
        );
        assert!(previous_manifest.is_file());
    }

    #[test]
    fn replace_rejects_an_occupied_file_destination_as_unsupported() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"old source bytes");
        fs::write(&bundle, b"foreign destination bytes").unwrap();
        let trust = LocalSplitTrustStore::new(state_path.clone());

        let error = plan_split_for_tests(
            SplitRequest::new(&source, &bundle)
                .with_conflict_policy(crate::ConflictPolicy::Replace),
            &trust,
            4,
            None,
        )
        .unwrap_err();

        assert_eq!(
            error.code(),
            OperationFailureCode::SplitReplacementUnsupported
        );
        assert_eq!(fs::read(&bundle).unwrap(), b"foreign destination bytes");
        assert_eq!(fs::read(&source).unwrap(), b"old source bytes");
        assert!(!state_path.exists());
    }

    #[test]
    fn replace_rejects_an_occupied_symlink_destination_as_unsupported() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"old source bytes");
        let target = root.path().join("foreign-directory");
        fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, &bundle).unwrap();
        let trust = LocalSplitTrustStore::new(state_path.clone());

        let error = plan_split_for_tests(
            SplitRequest::new(&source, &bundle)
                .with_conflict_policy(crate::ConflictPolicy::Replace),
            &trust,
            4,
            None,
        )
        .unwrap_err();

        assert_eq!(
            error.code(),
            OperationFailureCode::SplitReplacementUnsupported
        );
        assert!(
            fs::symlink_metadata(&bundle)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(target.is_dir());
        assert_eq!(fs::read(&source).unwrap(), b"old source bytes");
        assert!(!state_path.exists());
    }

    #[test]
    fn replace_rejects_a_qualified_noncanonical_manifest_without_mutating_the_bundle() {
        let root = tempfile::tempdir().unwrap();
        let source_bytes = b"same source bytes";
        let (source, bundle, state_path) = setup(root.path(), source_bytes);
        let trust = LocalSplitTrustStore::new(state_path.clone());
        let original = run_with_size(&source, &bundle, &trust, 4);
        let manifest_path = original
            .split_output_paths()
            .unwrap()
            .manifest_path()
            .to_path_buf();
        let canonical_manifest = fs::read(&manifest_path).unwrap();
        let canonical_digest = crate::Sha256Digest::digest(&canonical_manifest);
        let mut noncanonical_manifest = canonical_manifest.clone();
        noncanonical_manifest.push(b'\n');
        fs::write(&manifest_path, &noncanonical_manifest).unwrap();
        let noncanonical_digest = crate::Sha256Digest::digest(&noncanonical_manifest);
        trust
            .issue(SplitTrustReceipt::new(
                noncanonical_digest,
                source_bytes.len() as u64,
                crate::Sha256Digest::digest(source_bytes),
            ))
            .unwrap();

        let resolved = Engine::new()
            .resolve_inputs_with(
                InputResolutionRequest::new(&bundle).with_path(bundle.join("loose.nca")),
                InputResolutionCapabilities::new().with_split_trust_store(&trust),
            )
            .unwrap();
        assert_eq!(resolved.inputs.len(), 1);
        assert_eq!(
            resolved.inputs[0].split_manifest_sha256().copied(),
            Some(noncanonical_digest)
        );

        fn snapshot_store_files(root: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
            fn visit(
                root: &std::path::Path,
                directory: &std::path::Path,
                files: &mut Vec<(std::path::PathBuf, Vec<u8>)>,
            ) {
                let mut entries = fs::read_dir(directory)
                    .unwrap()
                    .map(Result::unwrap)
                    .collect::<Vec<_>>();
                entries.sort_by_key(|entry| entry.file_name());
                for entry in entries {
                    let path = entry.path();
                    let file_type = entry.file_type().unwrap();
                    if file_type.is_dir() {
                        visit(root, &path, files);
                    } else if file_type.is_file() {
                        files.push((
                            path.strip_prefix(root).unwrap().to_path_buf(),
                            fs::read(path).unwrap(),
                        ));
                    }
                }
            }

            let mut files = Vec::new();
            visit(root, root, &mut files);
            files.sort_by(|left, right| left.0.cmp(&right.0));
            files
        }

        let trust_store_before = snapshot_store_files(&state_path);

        let entries_before = fs::read_dir(bundle.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<std::collections::BTreeSet<_>>();
        let error = plan_split_for_tests(
            SplitRequest::new(&source, &bundle)
                .with_conflict_policy(crate::ConflictPolicy::Replace),
            &trust,
            4,
            None,
        )
        .unwrap_err();

        assert_eq!(
            error.code(),
            OperationFailureCode::SplitReplacementUnsupported
        );
        assert_eq!(fs::read(&manifest_path).unwrap(), noncanonical_manifest);
        assert_eq!(
            fs::read(bundle.join("loose.nca").join("00")).unwrap(),
            b"same"
        );
        assert_eq!(
            fs::read_dir(bundle.parent().unwrap())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<std::collections::BTreeSet<_>>(),
            entries_before
        );
        assert_eq!(snapshot_store_files(&state_path), trust_store_before);
        assert!(trust.lookup(&canonical_digest).unwrap().is_some());
        assert!(trust.lookup(&noncanonical_digest).unwrap().is_some());
    }

    #[test]
    fn replace_policy_keeps_a_fully_qualified_identical_destination_up_to_date() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"same source bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        run_with_size(&source, &bundle, &trust, 4);
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle)
                .with_conflict_policy(crate::ConflictPolicy::Replace),
            &trust,
            4,
            None,
        )
        .unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(result.outcome(), Some(OperationOutcome::AlreadyUpToDate));
        assert!(result.artifacts().is_empty());
        assert_eq!(result.retained_storage_bytes(), Some(0));
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::ConfirmedCommitted)
        );
    }

    #[test]
    fn already_up_to_date_does_not_mutate_a_pending_recovery_journal() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"same source bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        run_with_size(&source, &bundle, &trust, 4);
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 4, None).unwrap();
        let names = super::transaction_names();
        let record = super::JournalRecord::new(
            names.transaction_id.clone(),
            &plan.snapshot,
            &plan.state,
            &names.staging,
            plan.state.destination_identity,
        );
        let journal_path = bundle.parent().unwrap().join(&names.journal);
        drop(
            super::create_journal(&plan.state.destination_parent, &names.journal, record, None)
                .unwrap(),
        );
        let journal_before = fs::read(&journal_path).unwrap();
        let lock_directory = bundle
            .parent()
            .unwrap()
            .join(super::SPLIT_LOCK_DIRECTORY_NAME);
        fs::remove_dir_all(&lock_directory).unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(result.outcome(), Some(OperationOutcome::AlreadyUpToDate));
        assert_eq!(fs::read(&journal_path).unwrap(), journal_before);
        assert!(!bundle.parent().unwrap().join(names.staging).exists());
        assert!(!lock_directory.exists());
    }

    #[test]
    fn promotion_displacement_returns_uncertain_without_compensating_rename() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"old source bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            4,
            Some(SplitTestFailpoint::SubstituteDestinationAfterPromotion),
        )
        .unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::PublicationUncertain)
        );
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::Uncertain)
        );
        assert!(result.cleanup_artifact_retained());
        assert_eq!(
            result
                .split_output_paths()
                .unwrap()
                .recovery_bundle_directory(),
            None
        );
        let foreign_destination = bundle.join("concurrent-owner-data");
        assert_eq!(
            fs::read(foreign_destination).unwrap(),
            b"concurrent destination"
        );
        let displaced_candidate = bundle.with_file_name("loose.nca.split.external-original");
        assert_eq!(
            (0..4)
                .flat_map(|index| {
                    fs::read(
                        displaced_candidate
                            .join("loose.nca")
                            .join(format!("{index:02}")),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>(),
            b"old source bytes"
        );
        assert!(
            Engine::new()
                .resolve_inputs_with(
                    InputResolutionRequest::new(&displaced_candidate)
                        .with_path(displaced_candidate.join("loose.nca")),
                    InputResolutionCapabilities::new().with_split_trust_store(&trust),
                )
                .is_err()
        );
    }

    #[test]
    fn create_new_rollback_preserves_foreign_staging_substitution() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"old source bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        seed_cleanup_lease_state(&trust);
        fs::write(&source, b"new source bytes").unwrap();
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            4,
            Some(SplitTestFailpoint::SubstituteStagingBeforeRollbackIdentityCheck),
        )
        .unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        let recovery = result
            .split_output_paths()
            .unwrap()
            .recovery_bundle_directory()
            .unwrap()
            .to_path_buf();
        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::PublicationUncertain)
        );
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::ConfirmedUncommitted)
        );
        assert!(result.cleanup_artifact_retained());
        assert_eq!(
            fs::canonicalize(&recovery).unwrap(),
            fs::canonicalize(&bundle).unwrap()
        );
        let foreign_staging = fs::read_dir(bundle.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.join("concurrent-owner-data").is_file())
            .expect("foreign staging entry remains available for reconciliation");
        assert_eq!(
            fs::read(foreign_staging.join("concurrent-owner-data")).unwrap(),
            b"concurrent destination"
        );
        assert_eq!(
            (0..4)
                .flat_map(|index| {
                    fs::read(bundle.join("loose.nca").join(format!("{index:02}"))).unwrap()
                })
                .collect::<Vec<_>>(),
            b"new source bytes"
        );
    }

    #[test]
    fn interrupted_create_new_recovery_preserves_foreign_staging_substitution() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"old source bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        seed_cleanup_lease_state(&trust);
        fs::write(&source, b"new source bytes").unwrap();
        let interrupted = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            4,
            Some(SplitTestFailpoint::SimulatedInterruptionAfterPublication),
        )
        .unwrap();
        let interruption = Engine::new().execute_split(interrupted, &OperationSession::new());
        let first_recovery = interruption
            .split_output_paths()
            .unwrap()
            .recovery_bundle_directory()
            .unwrap()
            .to_path_buf();
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            4,
            Some(SplitTestFailpoint::SubstituteStagingBeforeRecoveryIdentityCheck),
        )
        .unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        let recovery = result
            .split_output_paths()
            .unwrap()
            .recovery_bundle_directory()
            .unwrap()
            .to_path_buf();
        assert_eq!(
            fs::canonicalize(&recovery).unwrap(),
            fs::canonicalize(&first_recovery).unwrap()
        );
        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::PublicationUncertain)
        );
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::Uncertain)
        );
        assert_eq!(
            fs::canonicalize(&recovery).unwrap(),
            fs::canonicalize(&bundle).unwrap()
        );
        let foreign_staging = fs::read_dir(bundle.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.join("concurrent-owner-data").is_file())
            .expect("foreign staging entry remains available for reconciliation");
        assert_eq!(
            fs::read(foreign_staging.join("concurrent-owner-data")).unwrap(),
            b"concurrent destination"
        );
        assert_eq!(
            (0..4)
                .flat_map(|index| {
                    fs::read(bundle.join("loose.nca").join(format!("{index:02}"))).unwrap()
                })
                .collect::<Vec<_>>(),
            b"new source bytes"
        );
    }

    #[test]
    fn recovery_does_not_swap_a_substituted_staging_entry_into_destination() {
        let root = tempfile::tempdir().unwrap();
        let destination_name = OsStr::new("destination.bundle");
        let staging_name = OsStr::new(".destination.recovery");
        let destination_path = root.path().join(destination_name);
        let staging_path = root.path().join(staging_name);
        fs::create_dir(&destination_path).unwrap();
        fs::write(destination_path.join("candidate"), b"published candidate").unwrap();
        fs::create_dir(&staging_path).unwrap();
        fs::write(staging_path.join("original"), b"original destination").unwrap();

        let parent = super::open_directory(root.path()).unwrap();
        let parent_identity = super::handle_identity(&parent).unwrap();
        let staged_identity = super::current_directory_identity(&parent, destination_name)
            .unwrap()
            .unwrap();
        let old_identity = super::current_directory_identity(&parent, staging_name)
            .unwrap()
            .unwrap();
        let lock = super::acquire_destination_lock(
            &parent,
            parent_identity,
            root.path(),
            destination_name,
        )
        .unwrap();
        let publication = super::DestinationPublication {
            parent: &parent,
            destination_name,
            lock: &lock,
            parent_identity,
            parent_path: root.path(),
            test_failpoint: Some(SplitTestFailpoint::SubstituteStagingBeforeRecoveryIdentityCheck),
        };

        let result = super::validate_interrupted_transaction(
            &publication,
            staging_name,
            staged_identity,
            Some(old_identity),
            true,
        );

        assert_eq!(result, Err(OperationFailureCode::PublicationUncertain));
        assert_eq!(
            fs::read(destination_path.join("candidate")).unwrap(),
            b"published candidate"
        );
        assert_eq!(
            fs::read(staging_path.join("concurrent-owner-data")).unwrap(),
            b"concurrent destination"
        );
        assert_eq!(
            fs::read(
                root.path()
                    .join(".destination.recovery.external-original")
                    .join("original")
            )
            .unwrap(),
            b"original destination"
        );
    }

    #[test]
    fn recovery_retains_published_bundle_when_custom_writer_has_no_cleanup_lease() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"old source bytes");
        let inner = LocalSplitTrustStore::new(state_path);
        inner
            .issue(SplitTrustReceipt::new(
                super::Sha256Digest::digest(b"unrelated manifest"),
                1,
                super::Sha256Digest::digest(b"unrelated source"),
            ))
            .unwrap();
        let trust = NoCleanupLeaseWriter { inner };
        fs::write(&source, b"new source bytes").unwrap();
        let interrupted = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            4,
            Some(SplitTestFailpoint::SimulatedInterruptionAfterPublication),
        )
        .unwrap();
        let interruption = Engine::new().execute_split(interrupted, &OperationSession::new());
        assert_eq!(
            interruption.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::PublicationUncertain)
        );
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 4, None).unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::PublicationUncertain)
        );
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::Uncertain)
        );
        assert!(result.cleanup_artifact_retained());
        assert_eq!(
            result.artifacts().len(),
            b"new source bytes".len().div_ceil(4) + 3
        );
        assert!(result.artifacts().iter().all(|artifact| {
            artifact.role() == crate::OperationArtifactRole::PublishedDestination
                && artifact.path_identity_matches() == Some(true)
                && artifact.retained()
        }));
        assert_eq!(result.retained_storage_bytes(), Some(0));
        let recovery = result
            .split_output_paths()
            .unwrap()
            .recovery_bundle_directory()
            .unwrap();
        let recovered = (0..4)
            .flat_map(|index| {
                fs::read(recovery.join("loose.nca").join(format!("{index:02}"))).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(recovered, b"new source bytes");
        assert!(
            Engine::new()
                .resolve_inputs_with(
                    InputResolutionRequest::new(recovery).with_path(recovery.join("loose.nca")),
                    InputResolutionCapabilities::new().with_split_trust_store(&trust),
                )
                .is_err()
        );
        assert_eq!(recovery, bundle.canonicalize().unwrap());
    }

    #[test]
    fn recovery_does_not_synthesize_a_receipt_for_a_modified_published_bundle() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"old source bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        fs::write(&source, b"new source bytes").unwrap();
        let interrupted = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            4,
            Some(SplitTestFailpoint::SimulatedInterruptionAfterPublication),
        )
        .unwrap();
        let interruption = Engine::new().execute_split(interrupted, &OperationSession::new());
        assert_eq!(
            interruption.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        let part = bundle.join("loose.nca").join("00");
        fs::write(&part, b"XXXX").unwrap();

        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 4, None).unwrap();
        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::PublicationUncertain)
        );
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::Uncertain)
        );
        assert!(result.cleanup_artifact_retained());
        assert_eq!(fs::read(part).unwrap(), b"XXXX");
        let manifest_digest = super::Sha256Digest::digest(
            &fs::read(bundle.join("loose.nca.nscb-split.json")).unwrap(),
        );
        assert!(trust.lookup(&manifest_digest).unwrap().is_none());
    }

    #[test]
    fn rollback_retains_published_bundle_when_custom_writer_has_no_cleanup_lease() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"old source bytes");
        let inner = LocalSplitTrustStore::new(state_path);
        inner
            .issue(SplitTrustReceipt::new(
                super::Sha256Digest::digest(b"unrelated manifest"),
                1,
                super::Sha256Digest::digest(b"unrelated source"),
            ))
            .unwrap();
        let trust = NoCleanupLeaseWriter { inner };
        fs::write(&source, b"new source bytes").unwrap();
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            4,
            Some(SplitTestFailpoint::FailureBeforeReceiptCommit),
        )
        .unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::PublicationUncertain)
        );
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::Uncertain)
        );
        assert!(result.cleanup_artifact_retained());
        let recovery = result
            .split_output_paths()
            .unwrap()
            .recovery_bundle_directory()
            .unwrap();
        let recovered = (0..4)
            .flat_map(|index| {
                fs::read(recovery.join("loose.nca").join(format!("{index:02}"))).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(recovered, b"new source bytes");
        assert!(
            Engine::new()
                .resolve_inputs_with(
                    InputResolutionRequest::new(recovery).with_path(recovery.join("loose.nca")),
                    InputResolutionCapabilities::new().with_split_trust_store(&trust),
                )
                .is_err()
        );
        assert_eq!(recovery, bundle.canonicalize().unwrap());
    }

    #[test]
    fn precommit_failure_with_cleanup_lease_removes_the_provisional_bundle() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"precommit cleanup fixture");
        let trust = LocalSplitTrustStore::new(state_path);
        seed_cleanup_lease_state(&trust);
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            7,
            Some(SplitTestFailpoint::FailureBeforeReceiptCommit),
        )
        .unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::WriteFailed)
        );
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::ConfirmedUncommitted)
        );
        assert!(!result.cleanup_artifact_retained());
        assert!(!result.artifacts().is_empty());
        assert!(
            result
                .artifacts()
                .iter()
                .all(|artifact| !artifact.retained())
        );
        assert_eq!(result.retained_storage_bytes(), Some(0));
        assert!(!bundle.exists());
        assert_eq!(fs::read(source).unwrap(), b"precommit cleanup fixture");
    }

    #[test]
    fn cancellation_at_final_cleanup_boundary_reports_retained_artifact_evidence() {
        let root = tempfile::tempdir().unwrap();
        let source_bytes = b"cancel before final owned unlink";
        let (source, bundle, state_path) = setup(root.path(), source_bytes);
        let trust = LocalSplitTrustStore::new(state_path);
        seed_cleanup_lease_state(&trust);
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            7,
            Some(SplitTestFailpoint::CancelBeforeArtifactUnlink),
        )
        .unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::Cancelled)
        );
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::ConfirmedUncommitted)
        );
        assert!(result.cleanup_artifact_retained());
        assert!(result.artifacts().iter().any(|artifact| {
            artifact.retained()
                && artifact.recorded_sha256().is_some()
                && artifact.sha256().is_some()
                && artifact.recorded_length() == artifact.length()
        }));
        assert!(result.retained_storage_bytes().unwrap() > 0);
        assert_eq!(fs::read(source).unwrap(), source_bytes);
    }

    #[test]
    fn cancellation_during_multichunk_cleanup_hash_retains_provisional_artifacts() {
        let root = tempfile::tempdir().unwrap();
        let source_bytes = vec![0x63; SPLIT_IO_BUFFER_SIZE * 2 + 13];
        let (source, bundle, state_path) = setup(root.path(), b"placeholder source bytes");
        fs::write(&source, &source_bytes).unwrap();
        let trust = LocalSplitTrustStore::new(state_path);
        seed_cleanup_lease_state(&trust);
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            (SPLIT_IO_BUFFER_SIZE * 2) as u64,
            Some(SplitTestFailpoint::FailureBeforeReceiptCommitWithCancelDuringCleanupHash),
        )
        .unwrap();
        let session = OperationSession::new();

        let result = Engine::new().execute_split(plan, &session);

        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::Cancelled)
        );
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::ConfirmedUncommitted)
        );
        assert!(result.cleanup_artifact_retained());
        assert!(result.artifacts().iter().any(|artifact| {
            artifact.retained()
                && artifact.recorded_sha256().is_some()
                && artifact.sha256().is_some()
                && artifact.recorded_length() == artifact.length()
        }));
        assert_eq!(result.retained_storage_bytes(), Some(0));
        assert!(bundle.exists());
        assert_eq!(fs::read(source).unwrap(), source_bytes);
    }

    #[test]
    fn result_inventory_is_empty_when_execution_fails_before_artifact_creation() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"source before plan");
        let trust = LocalSplitTrustStore::new(state_path);
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 7, None).unwrap();
        fs::write(&source, b"changed after plan").unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::SourceChanged)
        );
        assert!(result.artifacts().is_empty());
        assert!(!result.cleanup_artifact_retained());
        assert_eq!(result.retained_storage_bytes(), Some(0));
        assert!(!bundle.exists());
        assert_eq!(fs::read(source).unwrap(), b"changed after plan");
    }

    #[test]
    fn result_inventory_distinguishes_modified_content_from_recorded_content() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"abcdefgh");
        let trust = LocalSplitTrustStore::new(state_path);
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            4,
            Some(SplitTestFailpoint::SimulatedModifiedSegmentAfterPublication),
        )
        .unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::PublicationUncertain)
        );
        assert!(result.cleanup_artifact_retained());
        let published_bundle = fs::canonicalize(&bundle).unwrap();
        let segment = result
            .artifacts()
            .iter()
            .find(|artifact| artifact.path() == published_bundle.join("loose.nca/00"))
            .unwrap();
        assert_eq!(
            segment.role(),
            crate::OperationArtifactRole::PublishedDestination
        );
        assert!(segment.retained());
        assert_eq!(segment.path_identity_matches(), Some(true));
        assert_eq!(segment.recorded_length(), Some(4));
        assert_eq!(segment.length(), Some(4));
        assert_eq!(
            segment.recorded_sha256(),
            Some(crate::Sha256Digest::digest(b"abcd"))
        );
        assert_eq!(segment.sha256(), Some(crate::Sha256Digest::digest(b"XXXX")));
        assert_ne!(segment.recorded_sha256(), segment.sha256());
    }

    #[test]
    fn result_inventory_reports_substituted_output_identity_as_uncertain() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"abcdefgh");
        let trust = LocalSplitTrustStore::new(state_path);
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            4,
            Some(SplitTestFailpoint::SimulatedSubstitutedSegmentAfterPublication),
        )
        .unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::PublicationUncertain)
        );
        let published_bundle = fs::canonicalize(&bundle).unwrap();
        let segment_path = published_bundle.join("loose.nca/00");
        let recorded = result
            .artifacts()
            .iter()
            .find(|artifact| artifact.path() == segment_path)
            .unwrap();
        assert_eq!(
            recorded.role(),
            crate::OperationArtifactRole::PublishedDestination
        );
        assert_eq!(recorded.path_identity_matches(), Some(false));
        assert!(recorded.retained());
        assert_eq!(recorded.sha256(), None);
        let substitute = result
            .artifacts()
            .iter()
            .find(|artifact| {
                artifact.role() == crate::OperationArtifactRole::UncertainEntry
                    && artifact.path() == segment_path
            })
            .unwrap();
        assert!(substitute.retained());
        assert_eq!(substitute.length(), Some(4));
        assert_eq!(
            substitute.sha256(),
            Some(crate::Sha256Digest::digest(b"WXYZ"))
        );
        assert_ne!(
            recorded.device().zip(recorded.inode()),
            substitute.device().zip(substitute.inode())
        );
    }

    #[test]
    fn result_inventory_reports_unjournaled_entries_with_current_evidence() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"publish with user data");
        let trust = LocalSplitTrustStore::new(state_path);
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            7,
            Some(SplitTestFailpoint::SimulatedUnrelatedEntryAfterPublication),
        )
        .unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::PublicationUncertain)
        );
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::NotAttempted)
        );
        let published_bundle = fs::canonicalize(&bundle).unwrap();
        let unrelated_path = published_bundle.join("unrelated-split-entry");
        let unrelated = result
            .artifacts()
            .iter()
            .find(|artifact| artifact.path() == unrelated_path)
            .unwrap();
        assert_eq!(
            unrelated.role(),
            crate::OperationArtifactRole::UncertainEntry
        );
        assert!(unrelated.retained());
        assert_eq!(unrelated.path_identity_matches(), None);
        assert_eq!(unrelated.parent_identity_matches(), Some(true));
        assert_eq!(
            unrelated.length(),
            Some(b"unrelated user data".len() as u64)
        );
        assert_eq!(
            unrelated.sha256(),
            Some(crate::Sha256Digest::digest(b"unrelated user data"))
        );
        let bundle_artifact = result
            .artifacts()
            .iter()
            .find(|artifact| artifact.path() == published_bundle)
            .unwrap();
        assert_eq!(
            unrelated.parent_artifact_id(),
            Some(bundle_artifact.artifact_id())
        );
        assert_eq!(
            result.retained_storage_bytes(),
            Some(b"unrelated user data".len() as u64)
        );
        assert!(unrelated_path.is_file());
    }

    #[test]
    fn result_inventory_deduplicates_retained_hard_link_alias_storage() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"abcdefgh");
        let trust = LocalSplitTrustStore::new(state_path);
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            4,
            Some(SplitTestFailpoint::SimulatedAliasedSegmentAfterPublication),
        )
        .unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::PublicationUncertain)
        );
        let bundle = fs::canonicalize(bundle).unwrap();
        let aliases = ["retained-alias-a", "retained-alias-b"].map(|name| {
            result
                .artifacts()
                .iter()
                .find(|artifact| {
                    artifact.path() == bundle.join(name)
                        && artifact.role() == crate::OperationArtifactRole::UncertainEntry
                })
                .unwrap()
        });
        assert!(aliases.iter().all(|alias| alias.retained()));
        assert!(aliases.iter().all(|alias| alias.length() == Some(4)
            && alias.sha256() == Some(crate::Sha256Digest::digest(b"abcd"))));
        assert_eq!(
            aliases[0].device().zip(aliases[0].inode()),
            aliases[1].device().zip(aliases[1].inode())
        );
        assert_eq!(result.retained_storage_bytes(), Some(8));
    }

    #[test]
    fn unopenable_retained_directory_marks_retained_storage_unknown() {
        let root = tempfile::tempdir().unwrap();
        let staging_path = root.path().join(".nscb-split-staging");
        let nested_path = staging_path.join("loose.nca");
        fs::create_dir_all(&nested_path).unwrap();
        let unrelated_path = staging_path.join("unrecorded.bin");
        fs::write(&unrelated_path, b"retained provisional output").unwrap();
        let root_file = std::fs::File::open(&staging_path).unwrap();
        let parent_file = std::fs::File::open(root.path()).unwrap();
        let other = tempfile::tempdir().unwrap();
        let other_file = std::fs::File::open(other.path()).unwrap();
        let root_identity = super::handle_identity(&root_file).unwrap();
        let root_evidence = super::directory_evidence(&root_file).unwrap();
        let mismatched_nested_evidence = super::directory_evidence(&other_file).unwrap();
        let staging_name = super::encode_os_name(std::ffi::OsStr::new(".nscb-split-staging"));
        let mut record = super::JournalRecord {
            version: 1,
            transaction_id: "inventory-test".to_owned(),
            phase: JournalPhase::Cleaning,
            destination_name_hex: super::encode_os_name(std::ffi::OsStr::new("destination")),
            staging_name_hex: staging_name.clone(),
            canonical_name_hex: super::encode_os_name(std::ffi::OsStr::new("source.nsp")),
            source_identity: super::identity_string(root_identity),
            source_size: 0,
            source_sha256: String::new(),
            destination_parent_identity: None,
            journal_identity: None,
            journal_mode: None,
            destination_identity: None,
            staging_identity: None,
            manifest_sha256: None,
            segment_lengths: Vec::new(),
            artifacts: Vec::new(),
            cleanup_name_hex: None,
            cleanup_parent_identity: None,
        };
        record.artifacts = vec![
            super::JournalArtifact {
                relative_path_hex: vec![staging_name.clone()],
                parent_identity: super::identity_string(
                    super::handle_identity(&parent_file).unwrap(),
                ),
                kind: super::ArtifactKind::Directory,
                state: super::ArtifactState::Created(root_evidence),
            },
            super::JournalArtifact {
                relative_path_hex: vec![
                    staging_name,
                    super::encode_os_name(std::ffi::OsStr::new("loose.nca")),
                ],
                parent_identity: super::identity_string(root_identity),
                kind: super::ArtifactKind::Directory,
                state: super::ArtifactState::Created(mismatched_nested_evidence),
            },
        ];
        let split_root = super::SplitArtifactRoot {
            file: root_file,
            path: staging_path.clone(),
            published: false,
        };
        let mut inventory = super::SplitArtifactInventory::default();

        super::append_unjournaled_split_children(&record, &split_root, 1, 3, false, &mut inventory);

        assert!(inventory.retained_storage_unknown);
        assert!(inventory.retained);
        assert!(inventory.artifacts.iter().any(|artifact| {
            artifact.role() == super::OperationArtifactRole::UncertainEntry
                && artifact.path() == unrelated_path
                && artifact.length() == Some(b"retained provisional output".len() as u64)
                && artifact.sha256().is_some()
                && artifact.retained()
        }));
        assert!(nested_path.is_dir());

        let result = super::OperationResult::split_failure(
            super::OperationFailureCode::PublicationUncertain,
            vec![super::OperationMilestone::Planned],
            super::SplitOutputPaths {
                bundle_directory: root.path().join("destination"),
                canonical_directory: staging_path.clone(),
                manifest_path: staging_path.join("split.json"),
                recovery_bundle_directory: None,
            },
            super::SplitReceiptCommitState::NotAttempted,
            inventory.retained,
            inventory.retained_storage_unknown,
            inventory.artifacts,
        );
        assert_eq!(result.retained_storage_bytes(), None);
    }

    fn assert_cleanup_recovery_after_interruption(failpoint: SplitTestFailpoint) {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"interrupted cleanup fixture");
        let trust = LocalSplitTrustStore::new(state_path);
        seed_cleanup_lease_state(&trust);
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            7,
            Some(failpoint),
        )
        .unwrap();

        let interrupted = Engine::new().execute_split(plan, &OperationSession::new());

        assert!(interrupted.cleanup_artifact_retained());
        assert!(!bundle.exists());
        let cleanup_parent = bundle.parent().unwrap().join(".nscb-split-locks");
        let cleanup_path = fs::read_dir(&cleanup_parent)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".nscb-split-cleanup-"))
            })
            .expect("interrupted cleanup leaves its private quarantine for recovery");
        assert!(cleanup_path.is_dir());
        let cleanup_path = fs::canonicalize(cleanup_path).unwrap();
        assert!(
            interrupted.artifacts().iter().any(|artifact| {
                artifact.retained() && artifact.path().starts_with(&cleanup_path)
            }),
            "terminal inventory did not include retained quarantine entries: {:#?}",
            interrupted.artifacts()
        );
        match failpoint {
            SplitTestFailpoint::SimulatedInterruptionAfterCleanupArtifactUnlink => {
                assert_eq!(interrupted.retained_storage_bytes(), None);
                assert!(interrupted.artifacts().iter().any(|artifact| {
                    artifact.retained()
                        && artifact.recorded_length().is_some()
                        && artifact.length().is_none()
                        && artifact.path_identity_matches().is_none()
                }));
            }
            SplitTestFailpoint::SimulatedInterruptionAfterCleanupQuarantine => {
                assert!(interrupted.retained_storage_bytes().unwrap() > 0);
            }
            _ => unreachable!("only cleanup interruption failpoints reach this helper"),
        }
        let destination_parent = super::open_directory(bundle.parent().unwrap()).unwrap();
        let journal_name = fs::read_dir(bundle.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .find(|name| {
                let name = name.to_string_lossy();
                name.starts_with(".nscb-split-") && name.ends_with(".journal")
            })
            .expect("interrupted cleanup keeps its durable journal");
        let journal = super::open_journal_writer(&destination_parent, &journal_name).unwrap();
        assert_eq!(journal.record.phase, JournalPhase::Cleaning);
        let manifest_digest =
            crate::Sha256Digest::parse_hex(journal.record.manifest_sha256.as_deref().unwrap())
                .unwrap();
        drop(journal);
        drop(destination_parent);

        let recovery_plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 7, None).unwrap();
        let destination_lock = acquire_destination_lock(
            &recovery_plan.state.destination_parent,
            recovery_plan.state.destination_parent_identity,
            bundle.parent().unwrap(),
            &recovery_plan.state.destination_name,
        )
        .unwrap();
        let recovered = recover_incomplete_for_destination(
            &recovery_plan.snapshot,
            &recovery_plan.state,
            &destination_lock,
            None,
            &mut super::SplitArtifactSources::default(),
        );
        assert!(recovered.is_ok());

        assert!(!cleanup_path.exists());
        assert_eq!(fs::read(source).unwrap(), b"interrupted cleanup fixture");
        assert!(trust.lookup(&manifest_digest).unwrap().is_none());
    }

    #[test]
    fn recovery_resumes_cleanup_after_quarantine_rename_interruption() {
        assert_cleanup_recovery_after_interruption(
            SplitTestFailpoint::SimulatedInterruptionAfterCleanupQuarantine,
        );
    }

    #[test]
    fn recovery_resumes_cleanup_after_first_unlink_interruption() {
        assert_cleanup_recovery_after_interruption(
            SplitTestFailpoint::SimulatedInterruptionAfterCleanupArtifactUnlink,
        );
    }

    #[test]
    fn create_new_failure_before_receipt_commit_retains_unqualified_output() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"old source bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        fs::write(&source, b"new source bytes").unwrap();
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            4,
            Some(SplitTestFailpoint::FailureBeforeReceiptCommit),
        )
        .unwrap();
        let failed = Engine::new().execute_split(plan, &OperationSession::new());
        assert_eq!(
            failed.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert_eq!(
            failed.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::Uncertain)
        );
        assert!(failed.cleanup_artifact_retained());
        let recovery = failed
            .split_output_paths()
            .unwrap()
            .recovery_bundle_directory()
            .unwrap();
        assert!(recovery.is_dir());
        assert_eq!(
            (0..4)
                .flat_map(|index| {
                    fs::read(recovery.join("loose.nca").join(format!("{index:02}"))).unwrap()
                })
                .collect::<Vec<_>>(),
            b"new source bytes"
        );
        assert_eq!(recovery, bundle.canonicalize().unwrap());
    }

    #[test]
    fn restart_recovery_retains_published_uncommitted_create_new_output() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"old source bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        fs::write(&source, b"new source bytes").unwrap();
        let interrupted = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            4,
            Some(SplitTestFailpoint::SimulatedInterruptionAfterPublication),
        )
        .unwrap();
        let interruption = Engine::new().execute_split(interrupted, &OperationSession::new());
        assert_eq!(
            interruption.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert_eq!(
            interruption.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::NotAttempted)
        );
        assert!(
            Engine::new()
                .resolve_inputs_with(
                    InputResolutionRequest::new(&bundle).with_path(bundle.join("loose.nca")),
                    InputResolutionCapabilities::new().with_split_trust_store(&trust),
                )
                .is_err()
        );

        let reopened =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 4, None).unwrap();
        let recovery_result = Engine::new().execute_split(reopened, &OperationSession::new());
        assert_eq!(
            recovery_result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert!(recovery_result.cleanup_artifact_retained());
        let retained_output = recovery_result
            .split_output_paths()
            .unwrap()
            .recovery_bundle_directory()
            .unwrap();
        assert!(retained_output.is_dir());
        assert_eq!(
            (0..4)
                .flat_map(|index| {
                    fs::read(
                        retained_output
                            .join("loose.nca")
                            .join(format!("{index:02}")),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>(),
            b"new source bytes"
        );
        assert!(
            Engine::new()
                .resolve_inputs_with(
                    InputResolutionRequest::new(retained_output)
                        .with_path(retained_output.join("loose.nca")),
                    InputResolutionCapabilities::new().with_split_trust_store(&trust),
                )
                .is_err()
        );
        assert_eq!(retained_output, bundle.canonicalize().unwrap());
    }

    #[test]
    fn torn_published_journal_preserves_unqualified_create_new_output() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"previous qualified bytes");
        let trust = LocalSplitTrustStore::new(state_path);
        fs::write(&source, b"new source bytes").unwrap();
        let interrupted = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            4,
            Some(SplitTestFailpoint::SimulatedTornPublishedJournalAfterPromotion),
        )
        .unwrap();

        let interrupted_result = Engine::new().execute_split(interrupted, &OperationSession::new());

        assert_eq!(
            interrupted_result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert_eq!(
            interrupted_result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::NotAttempted)
        );
        let canonical_bundle = fs::canonicalize(&bundle).unwrap();
        let published_bundle = interrupted_result
            .artifacts()
            .iter()
            .find(|artifact| artifact.path() == canonical_bundle)
            .expect("torn journal inventory should include the published bundle path");
        assert_eq!(
            published_bundle.role(),
            crate::OperationArtifactRole::UncertainEntry
        );
        assert!(published_bundle.retained());
        assert!(published_bundle.device().is_some());
        assert!(published_bundle.inode().is_some());
        assert_eq!(published_bundle.length(), None);
        assert_eq!(published_bundle.sha256(), None);
        assert_eq!(published_bundle.recorded_length(), None);
        assert_eq!(published_bundle.recorded_sha256(), None);
        assert_eq!(published_bundle.parent_identity_matches(), Some(true));
        assert_eq!(interrupted_result.retained_storage_bytes(), None);
        let recovery = interrupted_result
            .split_output_paths()
            .unwrap()
            .recovery_bundle_directory()
            .unwrap()
            .to_path_buf();
        assert!(
            Engine::new()
                .resolve_inputs_with(
                    InputResolutionRequest::new(&bundle).with_path(bundle.join("loose.nca")),
                    InputResolutionCapabilities::new().with_split_trust_store(&trust),
                )
                .is_err()
        );

        let reopen =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 4, None).unwrap();
        let reopen_result = Engine::new().execute_split(reopen, &OperationSession::new());
        assert_eq!(
            reopen_result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert_eq!(
            reopen_result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::Uncertain)
        );
        assert!(bundle.is_dir());
        let reopened_bundle = fs::canonicalize(&bundle).unwrap();
        let reopened_artifact = reopen_result
            .artifacts()
            .iter()
            .find(|artifact| artifact.path() == reopened_bundle)
            .expect("recovery inventory should include the published bundle path");
        assert_eq!(
            reopened_artifact.role(),
            crate::OperationArtifactRole::UncertainEntry
        );
        assert!(reopened_artifact.retained());
        assert_eq!(fs::canonicalize(&recovery).unwrap(), reopened_bundle);
        assert_eq!(
            (0..4)
                .flat_map(|index| {
                    fs::read(bundle.join("loose.nca").join(format!("{index:02}"))).unwrap()
                })
                .collect::<Vec<_>>(),
            b"new source bytes"
        );
    }

    #[test]
    fn journal_identity_failure_reports_retained_initializer() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"journal initialization failure");
        let trust = LocalSplitTrustStore::new(state_path);
        let interrupted = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            4,
            Some(SplitTestFailpoint::SimulatedFailureAfterJournalCreateBeforeIdentityRecord),
        )
        .unwrap();

        let interrupted_result = Engine::new().execute_split(interrupted, &OperationSession::new());

        assert_eq!(
            interrupted_result.failure().unwrap().code(),
            OperationFailureCode::UnsupportedCapability
        );
        assert!(interrupted_result.cleanup_artifact_retained());
        let initializing_journal = fs::read_dir(bundle.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.ends_with(".journal.initializing"))
            })
            .unwrap();
        assert_eq!(fs::metadata(&initializing_journal).unwrap().len(), 0);

        assert!(initializing_journal.exists());
        assert!(!bundle.exists());
        assert_eq!(
            fs::read(&source).unwrap(),
            b"journal initialization failure"
        );
    }

    struct CommitThenError {
        inner: LocalSplitTrustStore,
        session: Option<OperationSession>,
        cancel_was_refused: Arc<AtomicBool>,
    }

    impl SplitTrustStore for CommitThenError {
        fn lookup(
            &self,
            digest: &crate::Sha256Digest,
        ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
            self.inner.lookup(digest)
        }
    }

    impl SplitTrustWriter for CommitThenError {
        fn issue(&self, receipt: SplitTrustReceipt) -> Result<(), SplitTrustStoreError> {
            if let Some(session) = &self.session {
                self.cancel_was_refused
                    .store(!session.cancel(), Ordering::SeqCst);
            }
            self.inner.issue(receipt)?;
            Err(SplitTrustStoreError::Unavailable)
        }

        fn issue_with_commit_state(
            &self,
            receipt: SplitTrustReceipt,
            after_issue: &mut crate::split_trust::SplitTrustCommitAction<'_>,
        ) -> Result<(), SplitTrustStoreError> {
            if let Some(session) = &self.session {
                self.cancel_was_refused
                    .store(!session.cancel(), Ordering::SeqCst);
            }
            self.inner
                .issue_with_commit_state(receipt, &mut |issue_result, state, view, locked| {
                    let issue_result = issue_result.and(Err(SplitTrustStoreError::Unavailable));
                    after_issue(issue_result, state, view, locked)
                })
        }

        fn revoke(&self, digest: &crate::Sha256Digest) -> Result<(), SplitTrustStoreError> {
            self.inner.revoke(digest)
        }
    }

    #[test]
    fn receipt_error_after_durable_commit_is_reconciled_and_kept_as_success() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"commit despite error");
        let inner = LocalSplitTrustStore::new(state_path);
        let session = OperationSession::new();
        let cancel_was_refused = Arc::new(AtomicBool::new(false));
        let trust = CommitThenError {
            inner,
            session: Some(session.clone()),
            cancel_was_refused: Arc::clone(&cancel_was_refused),
        };
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 5, None).unwrap();
        let result = Engine::new().execute_split(plan, &session);
        assert_eq!(result.outcome(), Some(OperationOutcome::SplitCreated));
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::ConfirmedCommitted)
        );
        assert!(cancel_was_refused.load(Ordering::SeqCst));
        assert_eq!(
            resolve_bytes(&bundle, &bundle.join("loose.nca"), &trust),
            b"commit despite error"
        );
    }

    struct AcknowledgedButMissingReceipt {
        inner: LocalSplitTrustStore,
        committed: AtomicBool,
    }

    impl SplitTrustStore for AcknowledgedButMissingReceipt {
        fn lookup(
            &self,
            digest: &crate::Sha256Digest,
        ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
            if self.committed.load(Ordering::SeqCst) {
                Ok(None)
            } else {
                self.inner.lookup(digest)
            }
        }
    }

    impl SplitTrustWriter for AcknowledgedButMissingReceipt {
        fn issue(&self, receipt: SplitTrustReceipt) -> Result<(), SplitTrustStoreError> {
            self.inner.issue(receipt)?;
            self.committed.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn revoke(&self, digest: &crate::Sha256Digest) -> Result<(), SplitTrustStoreError> {
            self.inner.revoke(digest)
        }
    }

    #[test]
    fn acknowledged_commit_with_missing_lookup_is_uncertain_and_preserved() {
        let root = tempfile::tempdir().unwrap();
        let source_bytes = b"acknowledged commit with inconsistent lookup";
        let (source, bundle, state_path) = setup(root.path(), source_bytes);
        let trust = AcknowledgedButMissingReceipt {
            inner: LocalSplitTrustStore::new(state_path),
            committed: AtomicBool::new(false),
        };
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 7, None).unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::PublicationUncertain)
        );
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::Uncertain)
        );
        assert!(bundle.is_dir());
        assert_eq!(
            resolve_bytes(&bundle, &bundle.join("loose.nca"), &trust.inner),
            source_bytes
        );
    }

    struct LegacyCommitWriter {
        inner: LocalSplitTrustStore,
    }

    impl SplitTrustStore for LegacyCommitWriter {
        fn lookup(
            &self,
            digest: &crate::Sha256Digest,
        ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
            self.inner.lookup(digest)
        }
    }

    impl SplitTrustWriter for LegacyCommitWriter {
        fn issue(&self, receipt: SplitTrustReceipt) -> Result<(), SplitTrustStoreError> {
            self.inner.issue(receipt)
        }

        fn revoke(&self, digest: &crate::Sha256Digest) -> Result<(), SplitTrustStoreError> {
            self.inner.revoke(digest)
        }
    }

    #[test]
    fn legacy_writer_without_commit_scope_retains_output_and_reports_uncertainty() {
        let root = tempfile::tempdir().unwrap();
        let source_bytes = b"legacy writer cannot serialize terminal journal";
        let (source, bundle, state_path) = setup(root.path(), source_bytes);
        let trust = LegacyCommitWriter {
            inner: LocalSplitTrustStore::new(state_path),
        };
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 7, None).unwrap();

        let result = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::PublicationUncertain)
        );
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::Uncertain)
        );
        assert!(result.cleanup_artifact_retained());
        assert!(bundle.is_dir());
        assert_eq!(
            resolve_bytes(&bundle, &bundle.join("loose.nca"), &trust),
            source_bytes
        );
    }

    #[test]
    fn acknowledged_commit_with_stale_journal_is_reconciled_without_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let source_bytes = b"receipt acknowledged before journal update";
        let (source, bundle, state_path) = setup(root.path(), source_bytes);
        let trust = LocalSplitTrustStore::new(state_path);
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            7,
            Some(SplitTestFailpoint::SimulatedAcknowledgementBeforeReceiptJournalUpdate),
        )
        .unwrap();

        let interrupted = Engine::new().execute_split(plan, &OperationSession::new());

        assert_eq!(
            interrupted.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::PublicationUncertain)
        );
        assert_eq!(
            interrupted.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::ConfirmedCommitted)
        );
        assert_eq!(
            interrupted.artifacts().len(),
            source_bytes.len().div_ceil(7) + 3
        );
        assert!(interrupted.artifacts().iter().all(|artifact| {
            artifact.role() == crate::OperationArtifactRole::PublishedDestination
                && artifact.path_identity_matches() == Some(true)
                && !artifact.retained()
        }));
        assert_eq!(interrupted.retained_storage_bytes(), Some(0));
        assert!(bundle.is_dir());

        let recovery_plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 7, None).unwrap();
        let parent_path = bundle.parent().unwrap();
        let lock = acquire_destination_lock(
            &recovery_plan.state.destination_parent,
            recovery_plan.state.destination_parent_identity,
            parent_path,
            &recovery_plan.state.destination_name,
        )
        .unwrap();

        let recovery = recover_incomplete_for_destination(
            &recovery_plan.snapshot,
            &recovery_plan.state,
            &lock,
            None,
            &mut super::SplitArtifactSources::default(),
        );
        assert!(recovery.is_ok());

        let journal_name = fs::read_dir(parent_path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .find(|name| {
                name.to_str().is_some_and(|name| {
                    name.starts_with(".nscb-split-") && name.ends_with(".journal")
                })
            })
            .unwrap();
        let journal =
            open_journal_writer(&recovery_plan.state.destination_parent, &journal_name).unwrap();
        assert_eq!(journal.record.phase, JournalPhase::Completed);
        assert_eq!(
            resolve_bytes(&bundle, &bundle.join("loose.nca"), &trust),
            source_bytes
        );
    }

    struct CancelDuringPlanningTrustLookup {
        inner: LocalSplitTrustStore,
        cancellation: CancellationHandle,
        lookup_calls: std::sync::atomic::AtomicUsize,
    }

    impl SplitTrustStore for CancelDuringPlanningTrustLookup {
        fn lookup(
            &self,
            digest: &crate::Sha256Digest,
        ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
            self.lookup_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let receipt = self.inner.lookup(digest)?;
            self.cancellation.cancel();
            Ok(receipt)
        }
    }

    impl SplitTrustWriter for CancelDuringPlanningTrustLookup {
        fn issue(&self, receipt: SplitTrustReceipt) -> Result<(), SplitTrustStoreError> {
            self.inner.issue(receipt)
        }

        fn revoke(&self, digest: &crate::Sha256Digest) -> Result<(), SplitTrustStoreError> {
            self.inner.revoke(digest)
        }
    }

    #[test]
    fn cancellation_during_existing_bundle_trust_lookup_stops_planning() {
        let root = tempfile::tempdir().unwrap();
        let source_bytes = b"cancel while checking an existing qualified bundle";
        let (source, bundle, state_path) = setup(root.path(), source_bytes);
        let inner = LocalSplitTrustStore::new(state_path);
        let initial_plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &inner, 9, None).unwrap();
        let published = Engine::new().execute_split(initial_plan, &OperationSession::new());
        assert_eq!(published.outcome(), Some(OperationOutcome::SplitCreated));

        let cancellation = CancellationHandle::new();
        let trust = CancelDuringPlanningTrustLookup {
            inner,
            cancellation: cancellation.clone(),
            lookup_calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let mut observe_progress = |_: u64| {};
        let error = plan_split_for_tests_with_cancellation(
            SplitRequest::new(&source, &bundle)
                .with_conflict_policy(super::ConflictPolicy::Replace),
            &trust,
            9,
            &cancellation,
            &mut observe_progress,
        )
        .unwrap_err();

        assert_eq!(error.code(), OperationFailureCode::Cancelled);
        assert_eq!(
            trust.lookup_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "exact-bundle validation must stop after its trust lookup cancels"
        );
        assert!(bundle.is_dir());
        assert_eq!(fs::read(&source).unwrap(), source_bytes);
    }

    struct CancelDuringPrecommitLookup {
        inner: LocalSplitTrustStore,
        session: OperationSession,
        published_bundle: PathBuf,
        recovery_lookups: std::sync::atomic::AtomicUsize,
        issue_calls: std::sync::atomic::AtomicUsize,
    }

    impl SplitTrustStore for CancelDuringPrecommitLookup {
        fn lookup(
            &self,
            digest: &crate::Sha256Digest,
        ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
            self.inner.lookup(digest)
        }
    }

    impl SplitTrustWriter for CancelDuringPrecommitLookup {
        fn lookup_for_recovery(
            &self,
            digest: &crate::Sha256Digest,
            is_cancelled: &dyn Fn() -> bool,
        ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
            if self.published_bundle.is_dir() {
                self.recovery_lookups
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.session.cancel();
            }
            self.inner.lookup_for_recovery(digest, is_cancelled)
        }

        fn issue(&self, receipt: SplitTrustReceipt) -> Result<(), SplitTrustStoreError> {
            self.issue_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.issue(receipt)
        }

        fn revoke(&self, digest: &crate::Sha256Digest) -> Result<(), SplitTrustStoreError> {
            self.inner.revoke(digest)
        }
    }

    #[test]
    fn cancellation_during_precommit_receipt_lookup_prevents_issue() {
        let root = tempfile::tempdir().unwrap();
        let source_bytes = b"cancel at the precommit trust lookup";
        let (source, bundle, state_path) = setup(root.path(), source_bytes);
        let session = OperationSession::new();
        let trust = CancelDuringPrecommitLookup {
            inner: LocalSplitTrustStore::new(state_path),
            session: session.clone(),
            published_bundle: bundle.clone(),
            recovery_lookups: std::sync::atomic::AtomicUsize::new(0),
            issue_calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 8, None).unwrap();

        let result = Engine::new().execute_split(plan, &session);

        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::Cancelled)
        );
        assert_eq!(
            trust
                .recovery_lookups
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            trust.issue_calls.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(fs::read(&source).unwrap(), source_bytes);
    }

    struct CancelDuringRecoveryLookup {
        inner: LocalSplitTrustStore,
        session: OperationSession,
    }

    impl SplitTrustStore for CancelDuringRecoveryLookup {
        fn lookup(
            &self,
            digest: &crate::Sha256Digest,
        ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
            self.inner.lookup(digest)
        }
    }

    impl SplitTrustWriter for CancelDuringRecoveryLookup {
        fn lookup_for_recovery(
            &self,
            digest: &crate::Sha256Digest,
            is_cancelled: &dyn Fn() -> bool,
        ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
            self.session.cancel();
            self.inner.lookup_for_recovery(digest, is_cancelled)
        }

        fn issue(&self, receipt: SplitTrustReceipt) -> Result<(), SplitTrustStoreError> {
            self.inner.issue(receipt)
        }

        fn revoke(&self, digest: &crate::Sha256Digest) -> Result<(), SplitTrustStoreError> {
            self.inner.revoke(digest)
        }
    }

    #[test]
    fn cancellation_during_recovery_receipt_lookup_retains_committed_bundle() {
        let root = tempfile::tempdir().unwrap();
        let source_bytes = b"cancel while recovering a committed receipt";
        let (source, bundle, state_path) = setup(root.path(), source_bytes);
        let trust = LocalSplitTrustStore::new(state_path.clone());
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            7,
            Some(SplitTestFailpoint::SimulatedAcknowledgementBeforeReceiptJournalUpdate),
        )
        .unwrap();
        let interrupted = Engine::new().execute_split(plan, &OperationSession::new());
        assert_eq!(
            interrupted.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::ConfirmedCommitted)
        );

        let session = OperationSession::new();
        let recovery_trust = CancelDuringRecoveryLookup {
            inner: trust.clone(),
            session: session.clone(),
        };
        let recovery_plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &recovery_trust,
            7,
            None,
        )
        .unwrap();
        let _admission = session.admit_with_cancellation(None, None).unwrap();
        let parent_path = bundle.parent().unwrap();
        let destination_lock = acquire_destination_lock(
            &recovery_plan.state.destination_parent,
            recovery_plan.state.destination_parent_identity,
            parent_path,
            &recovery_plan.state.destination_name,
        )
        .unwrap();
        let recovery = recover_incomplete_for_destination(
            &recovery_plan.snapshot,
            &recovery_plan.state,
            &destination_lock,
            Some(&session),
            &mut super::SplitArtifactSources::default(),
        );

        let Err(failure) = recovery else {
            panic!("cancelled recovery must preserve the committed bundle");
        };
        assert_eq!(failure.code, OperationFailureCode::Cancelled);
        assert!(failure.retained);
        assert!(bundle.is_dir());
        let journal_name = fs::read_dir(parent_path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .find(|name| {
                name.to_str().is_some_and(|name| {
                    name.starts_with(".nscb-split-") && name.ends_with(".journal")
                })
            })
            .unwrap();
        let journal =
            open_journal_writer(&recovery_plan.state.destination_parent, &journal_name).unwrap();
        assert_eq!(journal.record.phase, JournalPhase::ReceiptCommitStarted);
    }

    struct CancelAfterIssue {
        inner: LocalSplitTrustStore,
        cancellation: CancellationHandle,
    }

    impl SplitTrustStore for CancelAfterIssue {
        fn lookup(
            &self,
            digest: &crate::Sha256Digest,
        ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
            self.inner.lookup(digest)
        }
    }

    impl SplitTrustWriter for CancelAfterIssue {
        fn issue(&self, receipt: SplitTrustReceipt) -> Result<(), SplitTrustStoreError> {
            self.inner.issue(receipt)?;
            self.cancellation.cancel();
            Ok(())
        }

        fn issue_with_commit_state(
            &self,
            receipt: SplitTrustReceipt,
            after_issue: &mut crate::split_trust::SplitTrustCommitAction<'_>,
        ) -> Result<(), SplitTrustStoreError> {
            self.inner
                .issue_with_commit_state(receipt, &mut |issue_result, state, view, locked| {
                    if issue_result.is_ok() {
                        self.cancellation.cancel();
                    }
                    after_issue(issue_result, state, view, locked)
                })
        }

        fn revoke(&self, digest: &crate::Sha256Digest) -> Result<(), SplitTrustStoreError> {
            self.inner.revoke(digest)
        }
    }

    #[test]
    fn external_cancellation_after_receipt_commit_keeps_committed_success() {
        let root = tempfile::tempdir().unwrap();
        let source_bytes = b"commit before late cancellation";
        let (source, bundle, state_path) = setup(root.path(), source_bytes);
        let cancellation = CancellationHandle::new();
        let trust = CancelAfterIssue {
            inner: LocalSplitTrustStore::new(state_path),
            cancellation: cancellation.clone(),
        };
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 7, None).unwrap();
        let session = OperationSession::new();

        let result =
            Engine::new().execute_split_with_cancellation(plan, &session, cancellation.clone());

        assert!(cancellation.is_cancelled());
        assert_eq!(result.outcome(), Some(OperationOutcome::SplitCreated));
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::ConfirmedCommitted)
        );
        assert_eq!(
            resolve_bytes(&bundle, &bundle.join("loose.nca"), &trust),
            source_bytes
        );
    }

    #[derive(Debug, Eq, PartialEq)]
    enum ReceiptCommitEvent {
        Scoped,
        Legacy,
    }

    struct PauseAfterCommitWriter {
        inner: LocalSplitTrustStore,
        event_sender: std::sync::mpsc::SyncSender<ReceiptCommitEvent>,
        resume_receiver: Mutex<std::sync::mpsc::Receiver<()>>,
        callback_finished: Arc<AtomicBool>,
    }

    impl SplitTrustStore for PauseAfterCommitWriter {
        fn lookup(
            &self,
            digest: &crate::Sha256Digest,
        ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
            self.inner.lookup(digest)
        }
    }

    impl SplitTrustWriter for PauseAfterCommitWriter {
        fn issue(&self, receipt: SplitTrustReceipt) -> Result<(), SplitTrustStoreError> {
            self.event_sender.send(ReceiptCommitEvent::Legacy).unwrap();
            self.inner.issue(receipt)
        }

        fn issue_with_commit_state(
            &self,
            receipt: SplitTrustReceipt,
            after_issue: &mut crate::split_trust::SplitTrustCommitAction<'_>,
        ) -> Result<(), SplitTrustStoreError> {
            self.inner
                .issue_with_commit_state(receipt, &mut |issue_result, state, view, locked| {
                    self.event_sender.send(ReceiptCommitEvent::Scoped).unwrap();
                    self.resume_receiver.lock().unwrap().recv().unwrap();
                    let result = after_issue(issue_result, state, view, locked);
                    if result.is_ok() {
                        self.callback_finished.store(true, Ordering::SeqCst);
                    }
                    result
                })
        }

        fn revoke(&self, digest: &crate::Sha256Digest) -> Result<(), SplitTrustStoreError> {
            self.inner.revoke(digest)
        }
    }

    #[test]
    fn concurrent_revoke_waits_until_receipt_journal_completion() {
        let root = tempfile::tempdir().unwrap();
        let source_bytes = b"receipt commit lock spans terminal journal";
        let (source, bundle, state_path) = setup(root.path(), source_bytes);
        let callback_finished = Arc::new(AtomicBool::new(false));
        let (event_sender, event_receiver) = std::sync::mpsc::sync_channel(0);
        let (resume_sender, resume_receiver) = std::sync::mpsc::sync_channel(0);
        let trust = PauseAfterCommitWriter {
            inner: LocalSplitTrustStore::new(state_path.clone()),
            event_sender,
            resume_receiver: Mutex::new(resume_receiver),
            callback_finished: Arc::clone(&callback_finished),
        };
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 7, None).unwrap();
        let session = OperationSession::new();

        let result = std::thread::scope(|scope| {
            let producer = scope.spawn(move || Engine::new().execute_split(plan, &session));
            let event = event_receiver.recv().unwrap();
            if event == ReceiptCommitEvent::Legacy {
                let _ = producer.join().unwrap();
                panic!("producer bypassed the receipt commit scope");
            }

            let (revoke_started_sender, revoke_started_receiver) = std::sync::mpsc::sync_channel(0);
            let trust_ref = &trust;
            let bundle_ref = &bundle;
            let callback_finished_ref = &callback_finished;
            let revoker = scope.spawn(move || {
                revoke_started_sender.send(()).unwrap();
                trust_ref
                    .inner
                    .revoke(&crate::Sha256Digest::digest(
                        &fs::read(bundle_ref.join("loose.nca.nscb-split.json")).unwrap(),
                    ))
                    .unwrap();
                assert!(callback_finished_ref.load(Ordering::SeqCst));
            });
            revoke_started_receiver.recv().unwrap();

            let probe = OpenOptions::new()
                .read(true)
                .write(true)
                .open(state_path.join(".lock"))
                .unwrap();
            let blocked_by_commit = fs2::FileExt::try_lock_exclusive(&probe).is_err();
            if !blocked_by_commit {
                fs2::FileExt::unlock(&probe).unwrap();
            }
            resume_sender.send(()).unwrap();
            let result = producer.join().unwrap();
            revoker.join().unwrap();
            assert!(blocked_by_commit);
            result
        });

        assert_eq!(result.outcome(), Some(OperationOutcome::SplitCreated));
        assert!(callback_finished.load(Ordering::SeqCst));
        let parent = File::open(bundle.parent().unwrap()).unwrap();
        let journal_name = fs::read_dir(bundle.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .find(|name| {
                name.to_str().is_some_and(|name| {
                    name.starts_with(".nscb-split-") && name.ends_with(".journal")
                })
            })
            .unwrap();
        let journal = open_journal_writer(&parent, &journal_name).unwrap();
        assert_eq!(journal.record.phase, JournalPhase::Completed);
    }

    #[test]
    fn cancellation_after_publication_before_receipt_commit_retains_the_bundle() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"published but uncommitted");
        let trust = LocalSplitTrustStore::new(&state_path);
        seed_cleanup_lease_state(&trust);
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            7,
            Some(SplitTestFailpoint::CancelAfterPublicationBeforeReceiptCommit),
        )
        .unwrap();
        let manifest_path = plan.snapshot.manifest_path.clone();
        let session = OperationSession::new();

        let result = Engine::new().execute_split(plan, &session);

        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::Cancelled)
        );
        assert!(result.cleanup_artifact_retained());
        assert!(bundle.is_dir());
        let manifest_digest = crate::Sha256Digest::digest(&fs::read(manifest_path).unwrap());
        assert!(trust.lookup(&manifest_digest).unwrap().is_none());
        assert_eq!(fs::read(source).unwrap(), b"published but uncommitted");
    }

    #[test]
    fn missing_receipt_after_committed_journal_preserves_published_bundle() {
        let root = tempfile::tempdir().unwrap();
        let source_bytes = b"receipt committed before recovery";
        let (source, bundle, state_path) = setup(root.path(), source_bytes);
        let trust = LocalSplitTrustStore::new(state_path.clone());
        let plan = plan_split_for_tests(
            SplitRequest::new(&source, &bundle),
            &trust,
            7,
            Some(SplitTestFailpoint::SimulatedInterruptionAfterReceiptCommitted),
        )
        .unwrap();
        let interrupted = Engine::new().execute_split(plan, &OperationSession::new());
        assert_eq!(
            interrupted.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::PublicationUncertain)
        );
        assert_eq!(
            interrupted.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::ConfirmedCommitted)
        );

        drop(trust);
        fs::remove_dir_all(state_path.parent().unwrap()).unwrap();
        let empty_trust = LocalSplitTrustStore::new(state_path);
        let recovery_plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &empty_trust, 7, None)
                .unwrap();
        let recovered = Engine::new().execute_split(recovery_plan, &OperationSession::new());

        assert_eq!(
            recovered.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::PublicationUncertain)
        );
        assert_eq!(
            recovered.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::Uncertain)
        );
        let canonical = bundle.join("loose.nca");
        let recovered_bytes = (0..source_bytes.len().div_ceil(7))
            .flat_map(|index| fs::read(canonical.join(format!("{index:02}"))).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(recovered_bytes, source_bytes);
        assert!(bundle.join("loose.nca.nscb-split.json").is_file());
    }

    struct CommitButHideLookup {
        inner: LocalSplitTrustStore,
        committed: AtomicBool,
        lookup_count: AtomicUsize,
    }

    impl SplitTrustStore for CommitButHideLookup {
        fn lookup(
            &self,
            digest: &crate::Sha256Digest,
        ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
            let count = self.lookup_count.fetch_add(1, Ordering::SeqCst);
            if self.committed.load(Ordering::SeqCst) && count > 0 {
                return Err(SplitTrustStoreError::Unavailable);
            }
            self.inner.lookup(digest)
        }
    }

    impl SplitTrustWriter for CommitButHideLookup {
        fn issue(&self, receipt: SplitTrustReceipt) -> Result<(), SplitTrustStoreError> {
            self.inner.issue(receipt)?;
            self.committed.store(true, Ordering::SeqCst);
            Err(SplitTrustStoreError::Unavailable)
        }

        fn revoke(&self, digest: &crate::Sha256Digest) -> Result<(), SplitTrustStoreError> {
            self.inner.revoke(digest)
        }
    }

    #[test]
    fn unavailable_receipt_lookup_preserves_possibly_committed_output() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"uncertain commit state");
        let inner = LocalSplitTrustStore::new(state_path);
        let trust = CommitButHideLookup {
            inner,
            committed: AtomicBool::new(false),
            lookup_count: AtomicUsize::new(0),
        };
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 6, None).unwrap();
        let result = Engine::new().execute_split(plan, &OperationSession::new());
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert_eq!(
            result.split_receipt_commit_state(),
            Some(SplitReceiptCommitState::Uncertain)
        );
        assert!(bundle.is_dir());
        assert_eq!(
            resolve_bytes(&bundle, &bundle.join("loose.nca"), &trust.inner),
            b"uncertain commit state"
        );
    }

    #[test]
    fn pre_cancelled_execution_creates_no_transaction_artifacts() {
        let root = tempfile::tempdir().unwrap();
        let (source, bundle, state_path) = setup(root.path(), b"cancel before write");
        let trust = LocalSplitTrustStore::new(state_path);
        let plan =
            plan_split_for_tests(SplitRequest::new(&source, &bundle), &trust, 4, None).unwrap();
        let cancellation = CancellationHandle::new();
        cancellation.cancel();
        let result = Engine::new().execute_split_with_cancellation(
            plan,
            &OperationSession::new(),
            cancellation,
        );
        assert_eq!(result.state(), crate::JobState::Cancelled);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::Cancelled
        );
        assert!(!bundle.exists());
        assert_eq!(fs::read_dir(bundle.parent().unwrap()).unwrap().count(), 0);
    }
}
