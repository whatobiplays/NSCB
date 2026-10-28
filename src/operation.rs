//! Plan-first copy operations with validated, fail-closed publication.
//!
//! A plan records the resolved source and destination state before an
//! operation can write. Execution consumes that plan, rechecks the recorded
//! state, writes to a private staging file, validates the staged bytes, and
//! only then promotes the file into the destination.
//!
use crate::file_identity::{FileIdentity, FileSnapshot};
#[cfg(target_os = "macos")]
use crate::file_identity::{file_snapshot, handle_identity};
#[cfg(target_os = "macos")]
use crate::input_resolution::{
    InputResolutionErrorCode, InputResolutionRequest, looks_like_split_segment,
};
use crate::inspection::CancellationHandle;
use crate::sha256::Sha256Digest;
#[cfg(target_os = "macos")]
use crate::split_resolution::{directory_has_canonical_member, has_adjacent_sidecar};
#[cfg(target_os = "macos")]
use fs2::FileExt as _;
use serde::Serialize;
#[cfg(target_os = "macos")]
use sha2::{Digest as _, Sha256};
#[cfg(target_os = "macos")]
use std::ffi::CString;
#[cfg(target_os = "macos")]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fmt;
#[cfg(target_os = "macos")]
use std::fs::File;
#[cfg(target_os = "macos")]
use std::fs::{self, OpenOptions};
#[cfg(target_os = "macos")]
use std::io;
#[cfg(target_os = "macos")]
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(target_os = "macos")]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "macos")]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(target_os = "macos")]
const IO_BUFFER_SIZE: usize = 64 * 1024;
#[cfg(target_os = "macos")]
const MAX_STAGE_NAME_ATTEMPTS: usize = 128;
#[cfg(target_os = "macos")]
const LOCK_FILE_OPEN_ATTEMPTS: usize = 16;
#[cfg(target_os = "macos")]
const MINIMUM_FREE_SPACE_RESERVE: u64 = 64 * 1024 * 1024;
#[cfg(target_os = "macos")]
static NEXT_ARTIFACT_ID: AtomicU64 = AtomicU64::new(1);

/// Selects how an operation handles a destination that already exists.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConflictPolicy {
    /// Refuse to replace a different existing destination.
    #[default]
    Fail,
    /// Replace using qualified Darwin renameatx_np(RENAME_SWAP) exchange semantics.
    Replace,
}

/// Describes one byte-preserving regular-file copy operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopyThroughRequest {
    source: PathBuf,
    destination: PathBuf,
    workspace: PathBuf,
    workspace_selection: WorkspaceSelection,
    conflict_policy: ConflictPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkspaceSelection {
    Explicit,
    HostDefault,
}

/// Identifies the staging location selected by an immutable copy-through plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StagingStrategy {
    /// The operation uses the host-provided workspace on the qualified destination volume.
    HostWorkspace,
    /// The operation uses a workspace explicitly selected for this request.
    ExplicitWorkspace,
    /// The host workspace could not be qualified on the destination volume, so staging uses the
    /// selected destination's existing anchor on the same filesystem. When one safe final
    /// directory is missing, this anchor is its creation parent and execution creates that
    /// directory before staging begins.
    DestinationLocalFallback,
}

impl CopyThroughRequest {
    /// Creates a copy request with an explicit source, destination, and staging workspace.
    ///
    /// The workspace is an explicit staging location on the same filesystem
    /// as the destination directory. If its final directory is missing and its
    /// parent is stable, execution may create that directory; no fallback
    /// workspace is selected. The default policy refuses to replace a different file.
    pub fn new(
        source: impl Into<PathBuf>,
        destination: impl Into<PathBuf>,
        workspace: impl Into<PathBuf>,
    ) -> Self {
        Self {
            source: source.into(),
            destination: destination.into(),
            workspace: workspace.into(),
            workspace_selection: WorkspaceSelection::Explicit,
            conflict_policy: ConflictPolicy::Fail,
        }
    }

    /// Creates a request using the host's non-persistent default staging workspace.
    ///
    /// The host supplies its platform-appropriate cache or temporary directory.
    /// The path is carried only by this request and its plan; NSCB does not store
    /// it in global or application configuration. Use with_workspace_override
    /// to select a different workspace for one request.
    pub fn with_host_default_workspace(
        source: impl Into<PathBuf>,
        destination: impl Into<PathBuf>,
        workspace: impl Into<PathBuf>,
    ) -> Self {
        let mut request = Self::new(source, destination, workspace);
        request.workspace_selection = WorkspaceSelection::HostDefault;
        request
    }

    /// Selects an explicit workspace for this request instead of its host default.
    #[must_use]
    pub fn with_workspace_override(mut self, workspace: impl Into<PathBuf>) -> Self {
        self.workspace = workspace.into();
        self.workspace_selection = WorkspaceSelection::Explicit;
        self
    }

    /// Selects the destination behavior that the plan records and execution enforces.
    #[must_use]
    pub fn with_conflict_policy(mut self, policy: ConflictPolicy) -> Self {
        self.conflict_policy = policy;
        self
    }
}

/// The terminal state of a synchronous operation job.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JobState {
    /// The operation reached a validated publication outcome.
    Succeeded,
    /// The operation did not reach a validated publication outcome.
    Failed,
    /// The host cancelled the operation before promotion or result finalization began.
    Cancelled,
}

/// Describes the publication outcome reached by a copy-through operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OperationOutcome {
    /// A destination was published or replaced with the planned source bytes.
    Copied,
    /// The destination was already proven byte-identical to the planned source.
    AlreadyUpToDate,
}

/// A stable category for planning, execution, and publication failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OperationFailureCode {
    /// The source path is missing, unreadable, or not a regular file.
    SourceUnavailable,
    /// Copy-through does not accept physical members or directories resolved as Split inputs.
    SplitInputUnsupported,
    /// A source changed after the immutable plan was made.
    SourceChanged,
    /// A requested path no longer resolves to the path captured by the plan.
    StalePlan,
    /// The workspace is unavailable, unsafe, or not a directory.
    WorkspaceUnavailable,
    /// The destination path or its parent is unavailable or unsafe.
    DestinationUnavailable,
    /// A destination exists and the selected policy does not permit replacing it.
    DestinationConflict,
    /// The destination changed from the baseline captured by the plan.
    DestinationChanged,
    /// A required path aliases another operation input or output unsafely.
    UnsafePath,
    /// The host platform cannot prove the filesystem guarantees required by this operation.
    UnsupportedCapability,
    /// The workspace volume cannot safely hold the planned staging and recovery data.
    InsufficientStorage,
    /// Another operation is already active in the same shared session.
    #[serde(rename = "operation_session_busy")]
    Busy,
    /// The session already has a live semantic-event consumer, or a
    /// subscription was attempted while an execution was active.
    #[serde(rename = "event_consumer_unavailable")]
    EventConsumerUnavailable,
    /// The shared operation session could not be accessed safely.
    #[serde(rename = "operation_session_unavailable")]
    SessionUnavailable,
    /// The host explicitly cancelled this operation before promotion began.
    Cancelled,
    /// Staging could not be written or synchronized.
    WriteFailed,
    /// The staged file did not independently match the planned source.
    #[serde(rename = "staged_output_invalid")]
    ValidationFailed,
    /// The filesystem could not atomically promote the validated staging file.
    PublicationFailed,
    /// The destination state is uncertain; publication could not be confirmed.
    PublicationUncertain,
    /// Execution ended with an artifact retained because safe removal could not be proven.
    CleanupIncomplete,
}

impl OperationFailureCode {
    /// Returns the canonical machine-readable name used by serialization and display.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceUnavailable => "source_unavailable",
            Self::SplitInputUnsupported => "split_input_unsupported",
            Self::SourceChanged => "source_changed",
            Self::StalePlan => "stale_plan",
            Self::WorkspaceUnavailable => "workspace_unavailable",
            Self::DestinationUnavailable => "destination_unavailable",
            Self::DestinationConflict => "destination_conflict",
            Self::DestinationChanged => "destination_changed",
            Self::UnsafePath => "unsafe_path",
            Self::UnsupportedCapability => "unsupported_capability",
            Self::InsufficientStorage => "insufficient_storage",
            Self::Busy => "operation_session_busy",
            Self::EventConsumerUnavailable => "event_consumer_unavailable",
            Self::SessionUnavailable => "operation_session_unavailable",
            Self::Cancelled => "cancelled",
            Self::WriteFailed => "write_failed",
            Self::ValidationFailed => "staged_output_invalid",
            Self::PublicationFailed => "publication_failed",
            Self::PublicationUncertain => "publication_uncertain",
            Self::CleanupIncomplete => "cleanup_incomplete",
        }
    }
}

impl fmt::Display for OperationFailureCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A sanitized planning error that does not include host paths or OS diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationError {
    code: OperationFailureCode,
}

impl OperationError {
    fn new(code: OperationFailureCode) -> Self {
        Self { code }
    }

    /// Returns the stable category for this planning error.
    pub const fn code(&self) -> OperationFailureCode {
        self.code
    }
}

impl fmt::Display for OperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for OperationError {}

/// A sanitized diagnostic attached to an operation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct OperationFailure {
    code: OperationFailureCode,
}

impl OperationFailure {
    fn new(code: OperationFailureCode) -> Self {
        Self { code }
    }

    /// Returns the stable category for this operation failure.
    pub const fn code(&self) -> OperationFailureCode {
        self.code
    }
}

impl fmt::Display for OperationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

/// A recorded operation milestone, in the order it was reached.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OperationMilestone {
    /// The caller resolved and inspected an immutable plan.
    Planned,
    /// Execution acquired admission in its shared session.
    Executing,
    /// The staged output or existing destination matched independent plan evidence.
    Validated,
    /// Atomic promotion made the validated output visible at its destination.
    Published,
    /// Execution stopped with a typed failure.
    Failed,
    /// Execution stopped after explicit host cancellation.
    Cancelled,
    /// One or more filesystem artifacts were retained because safe removal could not be proven.
    CleanupIncomplete,
}

/// The result of executing one immutable operation plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperationResult {
    state: JobState,
    outcome: Option<OperationOutcome>,
    failure: Option<OperationFailure>,
    cleanup_warning: Option<OperationFailure>,
    milestones: Vec<OperationMilestone>,
    cleanup_artifact_retained: bool,
    artifacts: Vec<OperationArtifact>,
}

impl OperationResult {
    /// Returns the terminal job state.
    pub const fn state(&self) -> JobState {
        self.state
    }

    /// Returns the publication outcome, if one was reached.
    ///
    /// A publication outcome may accompany `CleanupIncomplete` when the
    /// destination was published but a staging artifact had to be preserved.
    pub const fn outcome(&self) -> Option<OperationOutcome> {
        self.outcome
    }

    /// Returns the typed failure, if execution did not succeed.
    pub const fn failure(&self) -> Option<&OperationFailure> {
        self.failure.as_ref()
    }

    /// Returns a cleanup warning when an artifact was retained after execution.
    ///
    /// A cleanup warning does not change a validated publication outcome from
    /// `Succeeded` to `Failed`.
    pub const fn cleanup_warning(&self) -> Option<&OperationFailure> {
        self.cleanup_warning.as_ref()
    }

    /// Returns the milestones recorded during execution.
    pub fn milestones(&self) -> &[OperationMilestone] {
        &self.milestones
    }

    /// Reports whether an artifact was retained or its state could not be proven safe to remove.
    pub const fn cleanup_artifact_retained(&self) -> bool {
        self.cleanup_artifact_retained
    }

    /// Returns paths and observed metadata for operation-owned artifacts.
    ///
    /// Retained artifacts must be reconciled using their reported role and
    /// identity. A path prefix alone does not establish ownership.
    /// An `UncertainEntry` may carry complete identity and content evidence
    /// even when it is not retained. Inspect the artifact fields and
    /// [`OperationArtifact::retained`] rather than assuming that the role means
    /// every field is unknown or that the operation owns the entry.
    /// An `UncertainEntry` can be either retained or unretained. A complete
    /// alias evidence record with `retained() == false` describes the object
    /// actually linked but does not claim that it matches the object observed
    /// before linking. Check both the retained flag and the evidence fields.
    pub fn artifacts(&self) -> &[OperationArtifact] {
        &self.artifacts
    }

    /// Returns the known bytes retained beyond the published destination.
    ///
    /// File identities are deduplicated because a successfully published file
    /// may share an inode with its retained staging name. A published identity
    /// is excluded only when the destination path is positively verified to
    /// still identify that inode. `None` means at least one retained data file
    /// lacks enough identity or size evidence to compute a safe total.
    /// Unretained evidence records contribute no bytes. This includes a
    /// path-linked competitor alias that has a complete alias identity and
    /// digest but does not match the competitor observed before linking.
    pub fn retained_storage_bytes(&self) -> Option<u64> {
        let mut identities = std::collections::BTreeSet::new();
        let published_identities = self
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact.role == OperationArtifactRole::PublishedDestination
                    && artifact.path_identity_matches == Some(true)
            })
            .filter_map(|artifact| {
                let recorded_identity = artifact.device.zip(artifact.inode)?;
                let current_path_identity = artifact.path_device.zip(artifact.path_inode)?;
                (recorded_identity == current_path_identity).then_some(recorded_identity)
            })
            .collect::<std::collections::BTreeSet<_>>();
        let mut total = 0_u64;
        for artifact in self.artifacts.iter().filter(|artifact| {
            artifact.retained
                && matches!(
                    artifact.role,
                    OperationArtifactRole::StagedOutput
                        | OperationArtifactRole::DestinationBackup
                        | OperationArtifactRole::DisplacedDestination
                        | OperationArtifactRole::UncertainEntry
                )
        }) {
            let length = artifact.length?;
            let identity = (artifact.device?, artifact.inode?);
            if !published_identities.contains(&identity) && identities.insert(identity) {
                total = total.checked_add(length)?;
            }
        }
        Some(total)
    }
}

/// The purpose of an artifact path created or preserved by an operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OperationArtifactRole {
    /// An explicitly requested workspace created for the operation.
    WorkspaceDirectory,
    /// A private directory containing the operation's temporary files.
    PrivateStagingDirectory,
    /// The file containing validated source bytes before or after publication.
    StagedOutput,
    /// The planned output name after publication.
    PublishedDestination,
    /// A copy of the destination baseline retained for recovery.
    DestinationBackup,
    /// An entry displaced from the destination during replacement.
    DisplacedDestination,
    /// An entry preserved for reconciliation but not classified as a planned
    /// output, destination, backup, or displaced destination.
    ///
    /// This role covers retained and unretained competitor hard-link aliases
    /// plus genuinely uncertain entries. The role alone does not mean that
    /// every identity or content field is unknown, retained, or attributable
    /// to an earlier observation. Check [`OperationArtifact::retained`] and the
    /// evidence fields to distinguish a retained match from an evidenced alias
    /// that could not be attributed to the object observed before linking.
    ///
    /// Complete evidence does not by itself mean that an entry is retained.
    /// [`OperationArtifact::retained`] distinguishes a retained match from an
    /// unretained alias record, and `retained_storage_bytes()` counts only the
    /// former.
    UncertainEntry,
}

/// A retained or uncertain artifact with evidence useful for reconciliation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperationArtifact {
    artifact_id: u64,
    parent_artifact_id: Option<u64>,
    relative_name: PathBuf,
    parent_device: Option<u64>,
    parent_inode: Option<u64>,
    parent_identity_matches: Option<bool>,
    role: OperationArtifactRole,
    path: PathBuf,
    device: Option<u64>,
    inode: Option<u64>,
    length: Option<u64>,
    sha256: Option<Sha256Digest>,
    recorded_length: Option<u64>,
    recorded_sha256: Option<Sha256Digest>,
    path_identity_matches: Option<bool>,
    path_device: Option<u64>,
    path_inode: Option<u64>,
    path_length: Option<u64>,
    retained: bool,
}

impl OperationArtifact {
    /// Returns the stable identifier used to link this entry to its parent.
    pub const fn artifact_id(&self) -> u64 {
        self.artifact_id
    }

    /// Returns the identifier of the artifact containing this entry, if known.
    pub const fn parent_artifact_id(&self) -> Option<u64> {
        self.parent_artifact_id
    }

    /// Returns the entry name relative to its recorded parent directory.
    pub fn relative_name(&self) -> &Path {
        &self.relative_name
    }

    /// Returns the recorded parent directory's device identifier.
    pub const fn parent_device(&self) -> Option<u64> {
        self.parent_device
    }

    /// Returns the recorded parent directory's file identifier.
    pub const fn parent_inode(&self) -> Option<u64> {
        self.parent_inode
    }

    /// Reports whether the absolute parent path still resolves to the recorded directory.
    pub const fn parent_identity_matches(&self) -> Option<bool> {
        self.parent_identity_matches
    }

    /// Returns the artifact's role in the operation.
    pub const fn role(&self) -> OperationArtifactRole {
        self.role
    }

    /// Returns the planned absolute path; use the identity evidence to determine whether it is current.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the filesystem or volume identifier observed through an open handle.
    pub const fn device(&self) -> Option<u64> {
        self.device
    }

    /// Returns the file identifier observed through an open handle.
    pub const fn inode(&self) -> Option<u64> {
        self.inode
    }

    /// Returns the inventory-time byte length for the recorded identity when
    /// a current entry or known alias can be verified.
    pub const fn length(&self) -> Option<u64> {
        self.length
    }

    /// Returns inventory-time SHA-256 when the recorded file identity is present
    /// through a current entry or known alias and its contents can be read
    /// within the recorded length.
    pub const fn sha256(&self) -> Option<Sha256Digest> {
        self.sha256
    }

    /// Returns the content length recorded before the inventory-time refresh.
    pub const fn recorded_length(&self) -> Option<u64> {
        self.recorded_length
    }

    /// Returns the digest recorded before the inventory-time refresh.
    pub const fn recorded_sha256(&self) -> Option<Sha256Digest> {
        self.recorded_sha256
    }

    /// Reports whether the planned name still identifies the recorded artifact.
    pub const fn path_identity_matches(&self) -> Option<bool> {
        self.path_identity_matches
    }

    /// Returns the device or volume identifier currently observed at the path.
    pub const fn path_device(&self) -> Option<u64> {
        self.path_device
    }

    /// Returns the file identifier currently observed at the path.
    pub const fn path_inode(&self) -> Option<u64> {
        self.path_inode
    }

    /// Returns the current path entry length when it is a regular file.
    pub const fn path_length(&self) -> Option<u64> {
        self.path_length
    }

    /// Reports whether the artifact remains present or could not be safely removed.
    /// A `false` value can describe an evidenced alias that remains at its
    /// path but was linked after pathname substitution and is not attributed to
    /// the object observed before linking. Such an alias contributes no bytes
    /// to `OperationResult::retained_storage_bytes()`.
    pub const fn retained(&self) -> bool {
        self.retained
    }
}

/// The path and expected content evidence for a possible execution artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlannedArtifact {
    role: OperationArtifactRole,
    path: PathBuf,
    expected_length: Option<u64>,
    expected_sha256: Option<Sha256Digest>,
}

impl PlannedArtifact {
    /// Returns the role assigned to this planned artifact.
    pub const fn role(&self) -> OperationArtifactRole {
        self.role
    }

    /// Returns the absolute path reserved by the immutable plan.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the expected length if the artifact contains known file bytes.
    pub const fn expected_length(&self) -> Option<u64> {
        self.expected_length
    }

    /// Returns the expected content digest if it is known at planning time.
    pub const fn expected_sha256(&self) -> Option<Sha256Digest> {
        self.expected_sha256
    }
}

/// A resolved source file recorded in an inspectable operation-plan snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlannedSource {
    path: PathBuf,
    identity: Sha256Digest,
    size: u64,
    sha256: Sha256Digest,
}

impl PlannedSource {
    /// Returns the canonical path that execution will open.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns an opaque digest of the filesystem identity observed during planning.
    pub const fn identity(&self) -> Sha256Digest {
        self.identity
    }

    /// Returns the source length in bytes observed during planning.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Returns the SHA-256 digest of the source bytes observed during planning.
    pub const fn sha256(&self) -> Sha256Digest {
        self.sha256
    }
}

/// The destination state that execution must revalidate before publication.
///
/// Downstream code should include a wildcard arm when matching this enum so
/// future baseline states remain compatible with the 1.x API.
///
/// ```compile_fail
/// use nscb::DestinationBaseline;
///
/// fn exhaustive_match(value: DestinationBaseline) {
///     match value {
///         DestinationBaseline::Absent => (),
///         DestinationBaseline::Existing { .. } => (),
///     }
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[non_exhaustive]
pub enum DestinationBaseline {
    /// No destination entry existed during planning.
    Absent,
    /// A regular destination file existed during planning.
    Existing {
        /// Opaque digest of the destination filesystem identity.
        identity: Sha256Digest,
        /// Destination length observed during planning.
        size: u64,
        /// SHA-256 digest of destination bytes observed during planning.
        sha256: Sha256Digest,
    },
}

/// A declared filesystem effect of the planned operation.
///
/// Downstream code should include a wildcard arm when matching this enum so
/// future effects remain compatible with the 1.x API.
///
/// ```compile_fail
/// use nscb::PlannedEffect;
///
/// fn exhaustive_match(value: PlannedEffect) {
///     match value {
///         PlannedEffect::ReadSource => (),
///         PlannedEffect::CoordinateDestination => (),
///         PlannedEffect::CreateWorkspaceDirectory => (),
///         PlannedEffect::CreatePrivateStagingDirectory => (),
///         PlannedEffect::CreateStagingFile => (),
///         PlannedEffect::CreateDestinationParent => (),
///         PlannedEffect::CreateDestination => (),
///         PlannedEffect::CreateDestinationBackup => (),
///         PlannedEffect::ReplaceDestination => (),
///     }
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PlannedEffect {
    /// Read and revalidate the source without modifying it.
    ReadSource,
    /// Coordinate publication through persistent destination-scoped protocol state.
    CoordinateDestination,
    /// Create the explicitly requested workspace after execution revalidates its parent.
    CreateWorkspaceDirectory,
    /// Create the private directory that contains staging and recovery files.
    CreatePrivateStagingDirectory,
    /// Create an exclusive staging file inside the planned private staging directory.
    CreateStagingFile,
    /// Create the missing final destination-directory component after revalidating its existing anchor.
    CreateDestinationParent,
    /// Create a new destination entry after validation.
    CreateDestination,
    /// Preserve an existing destination with a recovery copy.
    CreateDestinationBackup,
    /// Atomically replace the planned existing destination after validation.
    ReplaceDestination,
}

/// A public, read-only view of the decisions captured by an operation plan.
///
/// This snapshot is serializable for inspection, but it cannot be deserialized
/// into an executable plan. Execution accepts only the in-memory plan produced
/// by `Engine::plan_copy_through`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperationPlanSnapshot {
    kind: &'static str,
    nscb_version: &'static str,
    source: PlannedSource,
    destination: PathBuf,
    workspace: PathBuf,
    staging_strategy: StagingStrategy,
    staging_parent_identity: Sha256Digest,
    destination_lock_path: PathBuf,
    conflict_policy: ConflictPolicy,
    destination_baseline: DestinationBaseline,
    required_providers: Vec<String>,
    required_keys: Vec<String>,
    effects: Vec<PlannedEffect>,
    planned_artifacts: Vec<PlannedArtifact>,
}

impl OperationPlanSnapshot {
    /// Returns the serialized kind identifying this inspection snapshot.
    pub const fn kind(&self) -> &'static str {
        self.kind
    }

    /// Returns the NSCB package version that produced this snapshot.
    pub const fn nscb_version(&self) -> &'static str {
        self.nscb_version
    }

    /// Returns the complete source identity and content evidence captured by planning.
    pub const fn source(&self) -> &PlannedSource {
        &self.source
    }

    /// Returns the canonical destination path that execution will publish to.
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    /// Returns the canonical workspace selected for private staging.
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// Returns how the plan selected its staging location.
    pub const fn staging_strategy(&self) -> StagingStrategy {
        self.staging_strategy
    }

    /// Returns an opaque fingerprint for the opened directory anchoring staging.
    pub const fn staging_parent_identity(&self) -> Sha256Digest {
        self.staging_parent_identity
    }

    /// Returns the destination-scoped coordination file path used during publication.
    pub fn destination_lock_path(&self) -> &Path {
        &self.destination_lock_path
    }

    /// Returns the conflict policy selected by the caller.
    pub const fn conflict_policy(&self) -> ConflictPolicy {
        self.conflict_policy
    }

    /// Returns the destination baseline that execution must still observe.
    pub const fn destination_baseline(&self) -> &DestinationBaseline {
        &self.destination_baseline
    }

    /// Returns required managed providers; copy-through requires none.
    pub fn required_providers(&self) -> &[String] {
        &self.required_providers
    }

    /// Returns required key resources; copy-through requires none.
    pub fn required_keys(&self) -> &[String] {
        &self.required_keys
    }

    /// Returns the filesystem effects execution may perform.
    pub fn effects(&self) -> &[PlannedEffect] {
        &self.effects
    }

    /// Returns every staging, recovery, or workspace path execution may create.
    pub fn planned_artifacts(&self) -> &[PlannedArtifact] {
        &self.planned_artifacts
    }
}

/// An immutable, non-replayable plan created by the Engine.
///
/// The plan has private state and is consumed by execution. Its snapshot is
/// inspection-only and does not contain enough authority to reconstruct a plan.
pub struct OperationPlan {
    snapshot: OperationPlanSnapshot,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    source: ResolvedFile,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    source_baseline: FileEvidence,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    workspace: ResolvedDirectory,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    destination: ResolvedFile,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    destination_baseline: Option<FileEvidence>,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    already_up_to_date: bool,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    stage_directory_name: Option<OsString>,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    stage_file_name: Option<OsString>,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    backup_name: Option<OsString>,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    published_recovery_name: Option<OsString>,
}

impl OperationPlan {
    /// Returns the inspection-only view associated with this plan.
    pub const fn snapshot(&self) -> &OperationPlanSnapshot {
        &self.snapshot
    }
}

/// Explicit host-owned admission and cancellation state for mutating operations.
///
/// Cloning a session shares its active-operation and cancellation state. Each
/// independently constructed session has independent admission, while
/// destinations in the same parent directory coordinate through a persistent
/// filesystem marker shared by those sessions.
///
/// The current-operation snapshot is ephemeral. It describes only this shared
/// session, contains no operation history, and is cleared when the next
/// operation is admitted.
#[derive(Clone, Debug, Default)]
pub struct OperationSession {
    state: Arc<Mutex<SessionState>>,
}

/// The current execution phase of one shared operation session.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OperationSessionPhase {
    /// No operation is currently admitted.
    #[default]
    Idle,
    /// An admitted operation is checking inputs, staging output, or performing
    /// full final source, destination, and staged-file verification.
    /// Cancellation is accepted during this phase.
    Executing,
    /// The operation has passed its cancellation cutoff and is checking final
    /// workspace, staging-entry, and lock-marker operands before, or while
    /// executing, the atomic destination publication syscall. Cancellation is
    /// refused during this phase.
    Promoting,
    /// Publication has returned, or an already-identical destination has
    /// completed its final comparison, and the operation is checking
    /// postconditions, inventorying retained evidence, or finalizing a result.
    /// Cancellation is refused during this phase. The execution wrapper enters
    /// this phase before cleanup, competitor capture, artifact inventory, and
    /// result assembly, including finalization after an earlier execution failure.
    Completing,
}

/// The current or most recent terminal status in one shared operation session.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OperationSessionStatus {
    /// No operation has run since the session was created or last reset by admission.
    #[default]
    Idle,
    /// An operation is executing.
    Running,
    /// The host requested cancellation and execution has not yet stopped.
    CancellationRequested,
    /// The latest admitted operation completed successfully.
    Succeeded,
    /// The latest admitted operation failed.
    Failed,
    /// The latest admitted operation was cancelled.
    Cancelled,
}

/// An ephemeral snapshot of the current or most recently completed session operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct OperationSessionSnapshot {
    phase: OperationSessionPhase,
    status: OperationSessionStatus,
    milestone: Option<OperationMilestone>,
    outcome: Option<OperationOutcome>,
    failure: Option<OperationFailureCode>,
    completed_bytes: u64,
    total_bytes: Option<u64>,
}

impl OperationSessionSnapshot {
    /// Returns the current execution phase.
    pub const fn phase(&self) -> OperationSessionPhase {
        self.phase
    }

    /// Returns the active or terminal status.
    pub const fn status(&self) -> OperationSessionStatus {
        self.status
    }

    /// Returns the most recently reached milestone, if execution has started.
    pub const fn milestone(&self) -> Option<OperationMilestone> {
        self.milestone
    }

    /// Returns the terminal publication outcome when the operation succeeded.
    pub const fn outcome(&self) -> Option<OperationOutcome> {
        self.outcome
    }

    /// Returns the terminal failure code when the operation failed or was cancelled.
    pub const fn failure(&self) -> Option<OperationFailureCode> {
        self.failure
    }

    /// Returns source bytes successfully written into private staging.
    ///
    /// This value counts complete source chunks confirmed written by the copy
    /// loop. A chunk whose write fails is not counted even when the operating
    /// system accepted part of it. The value remains zero for
    /// `AlreadyUpToDate` and for failures or cancellation before copying.
    /// Reaching `total_bytes` does not imply that validation, promotion, or
    /// publication succeeded.
    pub const fn completed_bytes(&self) -> u64 {
        self.completed_bytes
    }

    /// Returns the planned source length for the most recently admitted execution.
    ///
    /// The value is `None` only before the first successful admission. Admission
    /// publishes the length in the same locked state transition that marks the
    /// session as executing. A refused busy admission leaves the previous snapshot,
    /// including any previous value, unchanged.
    pub const fn total_bytes(&self) -> Option<u64> {
        self.total_bytes
    }
}

/// One ordered semantic event observed during an operation execution.
///
/// The sequence number is local to a single admitted execution and starts at
/// zero. Progress is not an event: hosts read the authoritative latest value
/// from [`OperationSessionSnapshot`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperationEvent {
    sequence: u64,
    snapshot: OperationSessionSnapshot,
    #[serde(flatten)]
    event: OperationEventKind,
}

impl OperationEvent {
    /// Returns the execution-local sequence number assigned to this event.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the immutable session state captured with this transition.
    pub const fn snapshot(&self) -> OperationSessionSnapshot {
        self.snapshot
    }

    /// Returns the typed semantic payload.
    pub const fn event(&self) -> &OperationEventKind {
        &self.event
    }
}

/// The authoritative terminal event envelope retained by an operation session.
///
/// Hosts can recover this value after synchronous execution even when no event
/// consumer was subscribed or event delivery failed. It is the latest result,
/// not an event history; a successful later admission replaces it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationCompletion {
    sequence: u64,
    snapshot: OperationSessionSnapshot,
    result: OperationResult,
}

impl OperationCompletion {
    /// Returns the sequence number assigned to the logical `Completed` event.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the terminal state captured when the completion was emitted.
    pub const fn snapshot(&self) -> OperationSessionSnapshot {
        self.snapshot
    }

    /// Returns the complete authoritative filesystem operation result.
    pub const fn result(&self) -> &OperationResult {
        &self.result
    }
}

/// A bounded semantic transition reported by an admitted operation execution.
///
/// Implementations emit at most one start, one event per recorded milestone,
/// at most one cancellation decision, one failure diagnostic, one cleanup
/// warning, and one terminal completion. The number of events therefore does
/// not depend on the input size.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
#[non_exhaustive]
pub enum OperationEventKind {
    /// Admission succeeded and the planned source length is known.
    Started {
        /// Planned source length in bytes.
        total_bytes: u64,
    },
    /// Execution reached the recorded milestone.
    Milestone {
        /// Milestone reached by the execution.
        milestone: OperationMilestone,
    },
    /// A cancellation request was accepted or refused.
    CancellationRequested {
        /// Whether the active execution accepted the request.
        accepted: bool,
    },
    /// Execution failed with a stable diagnostic after its Failed milestone.
    Failure {
        /// Sanitized failure category; no filesystem paths or OS diagnostics.
        code: OperationFailureCode,
    },
    /// Cleanup retained artifacts after its CleanupIncomplete milestone.
    Warning {
        /// Sanitized warning category; reconciliation data is in the result.
        code: OperationFailureCode,
    },
    /// Execution produced its authoritative terminal result.
    Completed {
        /// Complete result, including any retained-artifact reconciliation data.
        result: OperationResult,
    },
}

/// The single logical semantic-event consumer associated with a session execution.
///
/// Dropping the consumer never blocks or fails execution. The authoritative
/// terminal result remains available through [`OperationSession::last_result`].
#[derive(Debug)]
pub struct OperationEventConsumer {
    receiver: std::sync::mpsc::Receiver<OperationEvent>,
    state: Arc<Mutex<SessionState>>,
    subscription: u64,
}

impl OperationEventConsumer {
    /// Blocks until the next event arrives or the producer disconnects.
    pub fn recv(&self) -> Result<OperationEvent, std::sync::mpsc::RecvError> {
        self.receiver.recv()
    }

    /// Waits up to `timeout` for the next event.
    pub fn recv_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> Result<OperationEvent, std::sync::mpsc::RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }

    /// Returns the next queued event without blocking.
    pub fn try_recv(&self) -> Result<OperationEvent, std::sync::mpsc::TryRecvError> {
        self.receiver.try_recv()
    }
}

impl Drop for OperationEventConsumer {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock()
            && state.phase == OperationSessionPhase::Idle
            && state.event_subscription == Some(self.subscription)
        {
            state.event_subscription = None;
            state.event_sender = None;
        }
    }
}

#[derive(Debug, Default)]
struct SessionState {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    generation: u64,
    phase: OperationSessionPhase,
    status: OperationSessionStatus,
    cancel_requested: bool,
    milestone: Option<OperationMilestone>,
    outcome: Option<OperationOutcome>,
    failure: Option<OperationFailureCode>,
    completed_bytes: u64,
    total_bytes: Option<u64>,
    terminal_result: Option<OperationResult>,
    terminal_completion: Option<OperationCompletion>,
    #[cfg(target_os = "macos")]
    execution_cancellation: Option<CancellationHandle>,
    event_sender: Option<std::sync::mpsc::Sender<OperationEvent>>,
    event_subscription: Option<u64>,
    next_subscription: u64,
    event_sequence: u64,
    cancellation_event_emitted: bool,
    #[cfg(target_os = "macos")]
    emitted_milestone: Option<OperationMilestone>,
}

impl SessionState {
    #[cfg(target_os = "macos")]
    fn cancellation_flag(&self) -> bool {
        self.cancel_requested
            || self
                .execution_cancellation
                .as_ref()
                .is_some_and(CancellationHandle::is_cancelled)
    }

    fn snapshot(&self) -> OperationSessionSnapshot {
        OperationSessionSnapshot {
            phase: self.phase,
            status: self.status,
            milestone: self.milestone,
            outcome: self.outcome,
            failure: self.failure,
            completed_bytes: self.completed_bytes,
            total_bytes: self.total_bytes,
        }
    }
}

fn emit_session_event(state: &mut SessionState, event: OperationEventKind) -> OperationEvent {
    let sequence = state.event_sequence;
    state.event_sequence = state.event_sequence.saturating_add(1);
    let event = OperationEvent {
        sequence,
        snapshot: state.snapshot(),
        event,
    };
    if let Some(sender) = state.event_sender.as_ref() {
        let _ = sender.send(event.clone());
    }
    event
}

#[cfg(target_os = "macos")]
fn record_session_milestone(state: &mut SessionState, milestone: OperationMilestone) {
    state.milestone = Some(milestone);
    if state.emitted_milestone != Some(milestone) {
        state.emitted_milestone = Some(milestone);
        emit_session_event(state, OperationEventKind::Milestone { milestone });
    }
}

fn record_accepted_cancellation(state: &mut SessionState) {
    state.status = OperationSessionStatus::CancellationRequested;
    if !state.cancellation_event_emitted {
        state.cancellation_event_emitted = true;
        emit_session_event(
            state,
            OperationEventKind::CancellationRequested { accepted: true },
        );
    }
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionCheckpoint {
    SourceLockWait,
    SourceLockAcquired,
    DestinationLockWait,
    DestinationLockAcquired,
    AlreadyUpToDateComparisonChunk,
    AlreadyUpToDateCompared,
    SourceEvidenceReadChunk,
    BeforeCompletion,
    BeforePromotion,
    FinalValidationHashChunk,
    AfterFinalDestinationValidation,
    AfterFinalSourceValidation,
    BeforeFinalization,
    #[cfg(test)]
    DestinationCompetitorFirstRead,
    BeforeAtomicPromotion,
    AtomicPromotionStarted,
    AfterPromotion,
    AfterNoClobberLinkBeforeEvidence,
    AfterDisplacedEntryValidation,
    BeforeArtifactInventory,
    AfterPublishedDestinationContentInspection,
    BeforeCompetitorLink,
    AfterCompetitorLink,
    AfterCompetitorRetention,
    #[cfg(test)]
    DestinationCompetitorBeforeOpen,
}

impl OperationSession {
    /// Creates an idle operation session without a runtime or global registration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current-operation state shared by this session's clones.
    ///
    /// A completed snapshot remains available until another operation is
    /// admitted. Independently created sessions do not share this state.
    pub fn current_operation(&self) -> Result<OperationSessionSnapshot, OperationFailureCode> {
        self.state
            .lock()
            .map(|state| OperationSessionSnapshot {
                phase: state.phase,
                status: state.status,
                milestone: state.milestone,
                outcome: state.outcome,
                failure: state.failure,
                completed_bytes: state.completed_bytes,
                total_bytes: state.total_bytes,
            })
            .map_err(|_| OperationFailureCode::SessionUnavailable)
    }

    /// Requests cancellation while an operation is executing.
    ///
    /// Returns `true` when cancellation was recorded. Cancellation is refused
    /// once the operation enters `Promoting` or `Completing`. The finalization
    /// wrapper observes cancellation accepted before that handoff and returns
    /// `Cancelled` unless publication evidence is uncertain, in which case
    /// `PublicationUncertain` takes precedence. It enters `Completing` before
    /// non-cancellable cleanup,
    /// inventory, and result construction.
    pub fn cancel(&self) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state.phase == OperationSessionPhase::Executing {
            if !state.cancel_requested {
                state.cancel_requested = true;
                record_accepted_cancellation(&mut state);
            }
            return true;
        }
        if matches!(
            state.phase,
            OperationSessionPhase::Promoting | OperationSessionPhase::Completing
        ) && !state.cancellation_event_emitted
            && matches!(
                state.status,
                OperationSessionStatus::Running | OperationSessionStatus::CancellationRequested
            )
        {
            state.cancellation_event_emitted = true;
            emit_session_event(
                &mut state,
                OperationEventKind::CancellationRequested { accepted: false },
            );
        }
        false
    }

    /// Reports whether this shared session currently owns an executing operation.
    pub fn is_busy(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.phase != OperationSessionPhase::Idle)
            .unwrap_or(true)
    }

    #[cfg(all(test, target_os = "macos"))]
    fn admit(&self) -> Result<AdmissionGuard, OperationFailureCode> {
        self.admit_with_cancellation(None, None)
    }

    #[cfg(target_os = "macos")]
    fn admit_with_cancellation(
        &self,
        cancellation: Option<&CancellationHandle>,
        total_bytes: Option<u64>,
    ) -> Result<AdmissionGuard, OperationFailureCode> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OperationFailureCode::SessionUnavailable)?;
        if state.phase != OperationSessionPhase::Idle {
            return Err(OperationFailureCode::Busy);
        }
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(OperationFailureCode::SessionUnavailable)?;
        let generation = state.generation;
        state.phase = OperationSessionPhase::Executing;
        state.status = OperationSessionStatus::Running;
        state.cancel_requested = cancellation.is_some_and(CancellationHandle::is_cancelled);
        state.milestone = Some(OperationMilestone::Executing);
        state.outcome = None;
        state.failure = None;
        state.completed_bytes = 0;
        state.total_bytes = total_bytes;
        state.terminal_result = None;
        state.terminal_completion = None;
        state.execution_cancellation = cancellation.cloned();
        state.event_sequence = 0;
        state.cancellation_event_emitted = false;
        state.emitted_milestone = None;
        if let Some(total_bytes) = total_bytes {
            emit_session_event(&mut state, OperationEventKind::Started { total_bytes });
        }
        if state.cancellation_flag() {
            record_accepted_cancellation(&mut state);
        }
        Ok(AdmissionGuard {
            state: Arc::clone(&self.state),
            generation,
            active: true,
        })
    }

    #[cfg(target_os = "macos")]
    fn cancellation_requested(&self) -> Result<bool, OperationFailureCode> {
        self.state
            .lock()
            .map(|state| state.cancellation_flag())
            .map_err(|_| OperationFailureCode::SessionUnavailable)
    }

    #[cfg(target_os = "macos")]
    fn record_observed_cancellation(&self) {
        if let Ok(mut state) = self.state.lock()
            && state.cancellation_flag()
        {
            record_accepted_cancellation(&mut state);
        }
    }

    #[cfg(target_os = "macos")]
    fn begin_promotion(&self) -> Result<bool, OperationFailureCode> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OperationFailureCode::SessionUnavailable)?;
        if state.cancellation_flag() {
            record_accepted_cancellation(&mut state);
            return Ok(false);
        }
        if state.phase != OperationSessionPhase::Executing {
            return Err(OperationFailureCode::SessionUnavailable);
        }
        state.phase = OperationSessionPhase::Promoting;
        Ok(true)
    }

    #[cfg(target_os = "macos")]
    fn finish_promotion(&self) -> Result<(), OperationFailureCode> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OperationFailureCode::SessionUnavailable)?;
        if state.phase != OperationSessionPhase::Promoting {
            return Err(OperationFailureCode::SessionUnavailable);
        }
        state.phase = OperationSessionPhase::Completing;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn begin_finalization(&self) -> Result<bool, OperationFailureCode> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OperationFailureCode::SessionUnavailable)?;
        let cancellation_accepted = match state.phase {
            OperationSessionPhase::Executing => state.cancellation_flag(),
            OperationSessionPhase::Promoting | OperationSessionPhase::Completing => false,
            OperationSessionPhase::Idle => return Err(OperationFailureCode::SessionUnavailable),
        };
        if cancellation_accepted {
            record_accepted_cancellation(&mut state);
        }
        state.phase = OperationSessionPhase::Completing;
        Ok(!cancellation_accepted)
    }

    #[cfg(target_os = "macos")]
    fn begin_completion(&self) -> Result<bool, OperationFailureCode> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OperationFailureCode::SessionUnavailable)?;
        if state.cancellation_flag() {
            record_accepted_cancellation(&mut state);
            return Ok(false);
        }
        if state.phase != OperationSessionPhase::Executing {
            return Err(OperationFailureCode::SessionUnavailable);
        }
        state.phase = OperationSessionPhase::Completing;
        Ok(true)
    }

    #[cfg(target_os = "macos")]
    fn record_milestone(&self, milestone: OperationMilestone) {
        if let Ok(mut state) = self.state.lock() {
            record_session_milestone(&mut state, milestone);
        }
    }

    #[cfg(target_os = "macos")]
    fn record_progress(&self, completed_bytes: u64) {
        if let Ok(mut state) = self.state.lock() {
            state.completed_bytes = completed_bytes;
        }
    }

    /// Returns the authoritative terminal result of the most recent execution.
    ///
    /// The result remains available until the next operation is admitted, even
    /// when no event consumer exists or the consumer was dropped. An admission
    /// refused as busy does not replace the active or previous result.
    pub fn last_result(&self) -> Result<Option<OperationResult>, OperationFailureCode> {
        self.state
            .lock()
            .map(|state| state.terminal_result.clone())
            .map_err(|_| OperationFailureCode::SessionUnavailable)
    }

    /// Returns the latest complete terminal event and result, if an operation
    /// has completed since the most recent successful admission.
    ///
    /// This recovery value is independent of event subscription and delivery.
    /// A successful admission clears the previous completion; the new terminal
    /// envelope is stored when that execution completes. A busy or failed
    /// admission leaves the previous completion intact.
    pub fn last_completion(&self) -> Result<Option<OperationCompletion>, OperationFailureCode> {
        self.state
            .lock()
            .map(|state| state.terminal_completion.clone())
            .map_err(|_| OperationFailureCode::SessionUnavailable)
    }

    /// Claims the single semantic-event consumer for the next execution.
    ///
    /// The subscription must be created while the session is idle. A second
    /// live consumer, or a claim attempted during execution, is refused with
    /// [`OperationFailureCode::EventConsumerUnavailable`]. Dropping the consumer
    /// before execution releases the claim.
    pub fn subscribe_events(&self) -> Result<OperationEventConsumer, OperationFailureCode> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OperationFailureCode::SessionUnavailable)?;
        if state.phase != OperationSessionPhase::Idle || state.event_subscription.is_some() {
            return Err(OperationFailureCode::EventConsumerUnavailable);
        }
        state.next_subscription = state
            .next_subscription
            .checked_add(1)
            .ok_or(OperationFailureCode::SessionUnavailable)?;
        let subscription = state.next_subscription;
        let (sender, receiver) = std::sync::mpsc::channel();
        state.event_subscription = Some(subscription);
        state.event_sender = Some(sender);
        state.event_sequence = 0;
        Ok(OperationEventConsumer {
            receiver,
            state: Arc::clone(&self.state),
            subscription,
        })
    }
}

#[cfg(target_os = "macos")]
struct AdmissionGuard {
    state: Arc<Mutex<SessionState>>,
    generation: u64,
    active: bool,
}

#[cfg(target_os = "macos")]
impl AdmissionGuard {
    fn finish(&mut self, result: &OperationResult) {
        if let Ok(mut state) = self.state.lock()
            && state.generation == self.generation
        {
            let cancellation_observed = state.cancellation_flag();
            state.phase = OperationSessionPhase::Idle;
            state.cancel_requested = false;
            state.execution_cancellation = None;
            state.status = match result.state() {
                JobState::Succeeded => OperationSessionStatus::Succeeded,
                JobState::Failed => OperationSessionStatus::Failed,
                JobState::Cancelled => OperationSessionStatus::Cancelled,
            };
            state.milestone = result.milestones().last().copied();
            state.outcome = result.outcome();
            state.failure = result.failure().map(OperationFailure::code);
            if cancellation_observed && !state.cancellation_event_emitted {
                state.cancellation_event_emitted = true;
                emit_session_event(
                    &mut state,
                    OperationEventKind::CancellationRequested {
                        accepted: result.state() == JobState::Cancelled,
                    },
                );
            }
            // The authoritative result is recorded before the terminal event is
            // published, so a failed or absent delivery cannot lose completion.
            state.terminal_result = Some(result.clone());
            // Final inventory can change a failure into PublicationUncertain.
            // Emit finalization transitions from that authoritative result,
            // in its milestone order, without replaying execution milestones.
            for &milestone in result.milestones() {
                let diagnostic = match milestone {
                    OperationMilestone::Failed => {
                        result.failure().map(|failure| OperationEventKind::Failure {
                            code: failure.code(),
                        })
                    }
                    OperationMilestone::Cancelled => None,
                    OperationMilestone::CleanupIncomplete => {
                        result
                            .cleanup_warning()
                            .map(|warning| OperationEventKind::Warning {
                                code: warning.code(),
                            })
                    }
                    _ => continue,
                };
                record_session_milestone(&mut state, milestone);
                if let Some(event) = diagnostic {
                    emit_session_event(&mut state, event);
                }
            }
            let completed = emit_session_event(
                &mut state,
                OperationEventKind::Completed {
                    result: result.clone(),
                },
            );
            state.terminal_completion = Some(OperationCompletion {
                sequence: completed.sequence,
                snapshot: completed.snapshot,
                result: result.clone(),
            });
            state.event_sender = None;
            state.event_subscription = None;
        }
        self.active = false;
    }
}

#[cfg(target_os = "macos")]
impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(mut state) = self.state.lock() {
            if state.generation != self.generation {
                return;
            }
            state.phase = OperationSessionPhase::Idle;
            state.cancel_requested = false;
            state.execution_cancellation = None;
            state.event_sender = None;
            state.event_subscription = None;
            if matches!(
                state.status,
                OperationSessionStatus::Running | OperationSessionStatus::CancellationRequested
            ) {
                state.status = OperationSessionStatus::Idle;
                state.milestone = None;
                state.outcome = None;
                state.failure = None;
            }
        }
        self.active = false;
    }
}

#[derive(Clone, Debug)]
struct ResolvedFile {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    requested_parent: PathBuf,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    parent: PathBuf,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    name: OsString,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    path: PathBuf,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    parent_identity: FileIdentity,
    /// Existing directory anchoring a missing destination parent. The identity
    /// above belongs to this directory when present.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    creation_parent: Option<PathBuf>,
}

#[cfg(target_os = "macos")]
impl ResolvedFile {
    fn anchor(&self) -> &Path {
        self.creation_parent.as_deref().unwrap_or(&self.parent)
    }
}

#[derive(Clone, Debug)]
struct ResolvedDirectory {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    requested: PathBuf,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    path: PathBuf,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    identity: Option<FileIdentity>,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    creation_parent: Option<PathBuf>,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    creation_parent_identity: Option<FileIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileEvidence {
    snapshot: FileSnapshot,
    identity: FileIdentity,
    sha256: Sha256Digest,
}

/// Resolves a copy-through request into an immutable, inspectable plan.
pub(crate) fn plan_copy_through(
    request: CopyThroughRequest,
) -> Result<OperationPlan, OperationError> {
    #[cfg(all(test, target_os = "macos"))]
    run_copy_planning_checkpoint();

    #[cfg(not(target_os = "macos"))]
    {
        let _ = request;
        Err(OperationError::new(
            OperationFailureCode::UnsupportedCapability,
        ))
    }

    #[cfg(target_os = "macos")]
    {
        plan_copy_through_unix(request)
    }
}

#[cfg(all(test, target_os = "macos"))]
fn run_copy_planning_checkpoint() {
    COPY_PLANNING_CHECKPOINT.with(|slot| {
        if let Some(checkpoint) = slot.take() {
            checkpoint();
        }
    });
}

#[cfg(target_os = "macos")]
fn plan_copy_through_unix(request: CopyThroughRequest) -> Result<OperationPlan, OperationError> {
    reject_split_input(&request.source)?;
    let source = resolve_file(&request.source, OperationFailureCode::SourceUnavailable)?;
    let destination = resolve_destination_file(&request.destination)?;
    let requested_workspace = resolve_directory(&request.workspace)?;

    if is_filesystem_root(destination.anchor()) || is_filesystem_root(&requested_workspace.path) {
        return Err(OperationError::new(OperationFailureCode::UnsafePath));
    }

    let source_directory = open_directory(&source.parent)
        .map_err(|_| OperationError::new(OperationFailureCode::SourceUnavailable))?;
    let destination_directory = open_directory(destination.anchor())
        .map_err(|_| OperationError::new(OperationFailureCode::DestinationUnavailable))?;
    let workspace_anchor = requested_workspace
        .identity
        .map(|_| requested_workspace.path.as_path())
        .or(requested_workspace.creation_parent.as_deref())
        .ok_or_else(|| OperationError::new(OperationFailureCode::WorkspaceUnavailable))?;
    let requested_workspace_directory = open_directory(workspace_anchor)
        .map_err(|_| OperationError::new(OperationFailureCode::WorkspaceUnavailable))?;
    let source_parent_identity = required_identity(&source_directory)?;
    let destination_parent_identity = required_identity(&destination_directory)
        .map_err(|_| OperationError::new(OperationFailureCode::UnsupportedCapability))?;
    let requested_workspace_identity = required_identity(&requested_workspace_directory)
        .map_err(|_| OperationError::new(OperationFailureCode::UnsupportedCapability))?;
    if !qualified_local_apfs_volume(&destination_directory) {
        return Err(OperationError::new(
            OperationFailureCode::UnsupportedCapability,
        ));
    }

    let workspace_on_qualified_destination_volume =
        qualified_local_apfs_volume(&requested_workspace_directory)
            && requested_workspace_identity.same_filesystem_as(destination_parent_identity);
    // Destination-local fallback stages beside the destination. When the final
    // output directory is safely missing, that anchor is the creation parent
    // that execution creates before staging begins.
    let (workspace, staging_strategy) = select_staging_workspace(
        request.workspace_selection,
        requested_workspace,
        workspace_on_qualified_destination_volume,
        destination.anchor(),
        destination_parent_identity,
    )
    .map_err(OperationError::new)?;
    let (workspace_directory, workspace_identity) =
        if staging_strategy == StagingStrategy::DestinationLocalFallback {
            (
                destination_directory
                    .try_clone()
                    .map_err(|_| OperationError::new(OperationFailureCode::WorkspaceUnavailable))?,
                destination_parent_identity,
            )
        } else {
            (requested_workspace_directory, requested_workspace_identity)
        };
    require_directory_writable(&workspace_directory).map_err(OperationError::new)?;
    let expected_workspace_identity = workspace
        .identity
        .or(workspace.creation_parent_identity)
        .ok_or_else(|| OperationError::new(OperationFailureCode::WorkspaceUnavailable))?;

    if source_parent_identity != source.parent_identity
        || destination_parent_identity != destination.parent_identity
        || workspace_identity != expected_workspace_identity
    {
        return Err(OperationError::new(OperationFailureCode::StalePlan));
    }
    let mut source_file = open_file_at(&source_directory, &source.name)
        .map_err(|_| OperationError::new(OperationFailureCode::SourceUnavailable))?;
    let source_baseline = inspect_file(&mut source_file)
        .map_err(|_| OperationError::new(OperationFailureCode::SourceUnavailable))?;

    let destination_baseline = if destination.creation_parent.is_some() {
        None
    } else {
        match inspect_destination(&destination_directory, &destination.name) {
            Ok(baseline) => baseline,
            Err(code) => return Err(OperationError::new(code)),
        }
    };

    if destination_baseline
        .as_ref()
        .is_some_and(|baseline| baseline.identity == source_baseline.identity)
        || source.path == destination.path
    {
        return Err(OperationError::new(OperationFailureCode::UnsafePath));
    }

    let already_up_to_date = if let Some(existing) = &destination_baseline {
        if existing.snapshot.len == source_baseline.snapshot.len
            && existing.sha256 == source_baseline.sha256
        {
            let mut destination_file = open_file_at(&destination_directory, &destination.name)
                .map_err(|_| OperationError::new(OperationFailureCode::DestinationChanged))?;
            let identical = files_equal(
                &mut source_file,
                &mut destination_file,
                source_baseline.snapshot.len,
            )
            .map_err(|_| OperationError::new(OperationFailureCode::SourceChanged))?;
            verify_file_evidence(&mut source_file, &source_baseline)
                .map_err(|_| OperationError::new(OperationFailureCode::SourceChanged))?;
            verify_destination_evidence(&mut destination_file, existing)
                .map_err(OperationError::new)?;
            identical
        } else {
            false
        }
    } else {
        false
    };

    validate_file_route(&source, None).map_err(OperationError::new)?;
    validate_file_route(&destination, None).map_err(OperationError::new)?;
    validate_directory_route(&workspace, None).map_err(OperationError::new)?;
    verify_file_evidence(&mut source_file, &source_baseline)
        .map_err(|_| OperationError::new(OperationFailureCode::SourceChanged))?;

    let lock_name = destination_lock_name(&destination.path);
    if lock_name == destination.name
        || (source.parent == destination.parent && lock_name == source.name)
    {
        return Err(OperationError::new(OperationFailureCode::UnsafePath));
    }
    let destination_lock_path = destination.parent.join(&lock_name);
    let destination_state = match &destination_baseline {
        None => DestinationBaseline::Absent,
        Some(evidence) => DestinationBaseline::Existing {
            identity: evidence.identity.fingerprint(),
            size: evidence.snapshot.len,
            sha256: evidence.sha256,
        },
    };
    let mut effects = vec![PlannedEffect::ReadSource];
    let known_conflict = destination_baseline.is_some()
        && request.conflict_policy == ConflictPolicy::Fail
        && !already_up_to_date;
    let mut planned_artifacts = Vec::new();
    let mut stage_directory_name = None;
    let mut stage_file_name = None;
    let mut backup_name = None;
    let mut published_recovery_name = None;
    if !known_conflict {
        effects.push(PlannedEffect::CoordinateDestination);
        if !already_up_to_date {
            if workspace.identity.is_none() {
                effects.push(PlannedEffect::CreateWorkspaceDirectory);
                planned_artifacts.push(PlannedArtifact {
                    role: OperationArtifactRole::WorkspaceDirectory,
                    path: workspace.path.clone(),
                    expected_length: None,
                    expected_sha256: None,
                });
            }
            let planned_stage_directory =
                planned_artifact_name(&workspace.path, "stage-area", workspace.identity.is_some())
                    .map_err(OperationError::new)?;
            let stage_directory_path = workspace.path.join(&planned_stage_directory);
            let planned_stage_file = planned_artifact_name(&stage_directory_path, "stage", false)
                .map_err(OperationError::new)?;
            planned_artifacts.push(PlannedArtifact {
                role: OperationArtifactRole::PrivateStagingDirectory,
                path: stage_directory_path.clone(),
                expected_length: None,
                expected_sha256: None,
            });
            planned_artifacts.push(PlannedArtifact {
                role: OperationArtifactRole::StagedOutput,
                path: stage_directory_path.join(&planned_stage_file),
                expected_length: Some(source_baseline.snapshot.len),
                expected_sha256: Some(source_baseline.sha256),
            });
            planned_artifacts.push(PlannedArtifact {
                role: OperationArtifactRole::PublishedDestination,
                path: destination.path.clone(),
                expected_length: Some(source_baseline.snapshot.len),
                expected_sha256: Some(source_baseline.sha256),
            });
            stage_directory_name = Some(planned_stage_directory);
            stage_file_name = Some(planned_stage_file);
            effects.push(PlannedEffect::CreatePrivateStagingDirectory);
            effects.push(PlannedEffect::CreateStagingFile);
            match (&destination_baseline, request.conflict_policy) {
                (Some(existing), ConflictPolicy::Replace) => {
                    let planned_recovery =
                        planned_artifact_name(&stage_directory_path, "published-output", false)
                            .map_err(OperationError::new)?;
                    planned_artifacts.push(PlannedArtifact {
                        role: OperationArtifactRole::StagedOutput,
                        path: stage_directory_path.join(&planned_recovery),
                        expected_length: Some(source_baseline.snapshot.len),
                        expected_sha256: Some(source_baseline.sha256),
                    });
                    published_recovery_name = Some(planned_recovery);
                    let planned_backup =
                        planned_artifact_name(&stage_directory_path, "backup", false)
                            .map_err(OperationError::new)?;
                    planned_artifacts.push(PlannedArtifact {
                        role: OperationArtifactRole::DestinationBackup,
                        path: stage_directory_path.join(&planned_backup),
                        expected_length: Some(existing.snapshot.len),
                        expected_sha256: Some(existing.sha256),
                    });
                    backup_name = Some(planned_backup);
                    effects.push(PlannedEffect::CreateDestinationBackup);
                    effects.push(PlannedEffect::ReplaceDestination);
                }
                (None, _) => {
                    if destination.creation_parent.is_some() {
                        effects.push(PlannedEffect::CreateDestinationParent);
                    }
                    effects.push(PlannedEffect::CreateDestination);
                }
                _ => {}
            }
        }
    }

    let snapshot = OperationPlanSnapshot {
        kind: "operation_plan",
        nscb_version: env!("CARGO_PKG_VERSION"),
        source: PlannedSource {
            path: source.path.clone(),
            identity: source_baseline.identity.fingerprint(),
            size: source_baseline.snapshot.len,
            sha256: source_baseline.sha256,
        },
        destination: destination.path.clone(),
        workspace: workspace.path.clone(),
        staging_strategy,
        staging_parent_identity: workspace_identity.fingerprint(),
        destination_lock_path,
        conflict_policy: request.conflict_policy,
        destination_baseline: destination_state,
        required_providers: Vec::new(),
        required_keys: Vec::new(),
        effects,
        planned_artifacts,
    };

    Ok(OperationPlan {
        snapshot,
        source,
        source_baseline,
        workspace,
        destination,
        destination_baseline,
        already_up_to_date,
        stage_directory_name,
        stage_file_name,
        backup_name,
        published_recovery_name,
    })
}

#[cfg(target_os = "macos")]
fn planned_artifact_name(
    parent: &Path,
    role: &str,
    inspect_parent: bool,
) -> Result<OsString, OperationFailureCode> {
    for _ in 0..MAX_STAGE_NAME_ATTEMPTS {
        let name = next_artifact_name(role)?;
        if !inspect_parent {
            return Ok(name);
        }
        match fs::symlink_metadata(parent.join(&name)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(name),
            Ok(_) => continue,
            Err(_) => return Err(OperationFailureCode::WorkspaceUnavailable),
        }
    }
    Err(OperationFailureCode::WriteFailed)
}

#[cfg(target_os = "macos")]
fn reject_split_input(path: &Path) -> Result<(), OperationError> {
    let requested = absolute_path(path)
        .map_err(|_| OperationError::new(OperationFailureCode::SourceUnavailable))?;
    let metadata = fs::metadata(&requested)
        .map_err(|_| OperationError::new(OperationFailureCode::SourceUnavailable))?;

    let is_split_candidate = if metadata.is_file() {
        requested
            .file_name()
            .is_some_and(|name| looks_like_split_segment(Path::new(name)))
    } else if metadata.is_dir() {
        let canonical = fs::canonicalize(&requested)
            .map_err(|_| OperationError::new(OperationFailureCode::SourceUnavailable))?;
        has_adjacent_sidecar(&canonical)
            .map_err(|_| OperationError::new(OperationFailureCode::SourceUnavailable))?
            || directory_has_canonical_member(&canonical)
                .map_err(|_| OperationError::new(OperationFailureCode::SourceUnavailable))?
    } else {
        false
    };

    if !is_split_candidate {
        return Ok(());
    }

    let base = requested
        .parent()
        .ok_or_else(|| OperationError::new(OperationFailureCode::SourceUnavailable))?;
    match crate::Engine::new()
        .resolve_inputs(InputResolutionRequest::new(base).with_path(&requested))
    {
        Ok(resolved)
            if resolved
                .inputs
                .iter()
                .any(|input| input.qualification.is_some() || input.segments.len() != 1) =>
        {
            Err(OperationError::new(
                OperationFailureCode::SplitInputUnsupported,
            ))
        }
        Ok(_) => Ok(()),
        Err(error)
            if matches!(
                error.code(),
                InputResolutionErrorCode::UnsupportedSplitLayout
                    | InputResolutionErrorCode::SplitManifestMissing
                    | InputResolutionErrorCode::SplitEvidenceUntrusted
                    | InputResolutionErrorCode::SplitManifestInvalid
                    | InputResolutionErrorCode::SplitManifestVersionUnsupported
                    | InputResolutionErrorCode::SplitSetIncomplete
                    | InputResolutionErrorCode::SplitIntegrityMismatch
                    | InputResolutionErrorCode::SplitInputChanged
            ) =>
        {
            Err(OperationError::new(
                OperationFailureCode::SplitInputUnsupported,
            ))
        }
        Err(_) => Err(OperationError::new(OperationFailureCode::SourceUnavailable)),
    }
}

#[cfg(target_os = "macos")]
fn resolve_file(
    path: &Path,
    unavailable: OperationFailureCode,
) -> Result<ResolvedFile, OperationError> {
    let requested = absolute_path(path).map_err(|_| OperationError::new(unavailable))?;
    let name = requested
        .file_name()
        .filter(|name| *name != OsStr::new(".") && *name != OsStr::new(".."))
        .ok_or_else(|| OperationError::new(OperationFailureCode::UnsafePath))?
        .to_os_string();
    let requested_parent = requested
        .parent()
        .ok_or_else(|| OperationError::new(OperationFailureCode::UnsafePath))?
        .to_path_buf();
    let parent =
        fs::canonicalize(&requested_parent).map_err(|_| OperationError::new(unavailable))?;
    let directory = open_directory(&parent).map_err(|_| OperationError::new(unavailable))?;
    let parent_identity = required_identity(&directory)?;
    let resolved = parent.join(&name);
    Ok(ResolvedFile {
        requested_parent,
        parent,
        name,
        path: resolved,
        parent_identity,
        creation_parent: None,
    })
}

#[cfg(target_os = "macos")]
fn resolve_destination_file(path: &Path) -> Result<ResolvedFile, OperationError> {
    let unavailable = OperationFailureCode::DestinationUnavailable;
    let requested = absolute_path(path).map_err(|_| OperationError::new(unavailable))?;
    let name = requested
        .file_name()
        .filter(|name| *name != OsStr::new(".") && *name != OsStr::new(".."))
        .ok_or_else(|| OperationError::new(OperationFailureCode::UnsafePath))?
        .to_os_string();
    let requested_parent = requested
        .parent()
        .ok_or_else(|| OperationError::new(OperationFailureCode::UnsafePath))?
        .to_path_buf();
    match fs::canonicalize(&requested_parent) {
        Ok(parent) => {
            let directory =
                open_directory(&parent).map_err(|_| OperationError::new(unavailable))?;
            let parent_identity = required_identity(&directory)?;
            Ok(ResolvedFile {
                requested_parent,
                path: parent.join(&name),
                parent,
                name,
                parent_identity,
                creation_parent: None,
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let missing_name = requested_parent
                .file_name()
                .filter(|name| *name != OsStr::new(".") && *name != OsStr::new(".."))
                .ok_or_else(|| OperationError::new(OperationFailureCode::UnsafePath))?;
            let anchor_requested = requested_parent
                .parent()
                .ok_or_else(|| OperationError::new(OperationFailureCode::UnsafePath))?;
            let anchor =
                fs::canonicalize(anchor_requested).map_err(|_| OperationError::new(unavailable))?;
            let anchor_directory =
                open_directory(&anchor).map_err(|_| OperationError::new(unavailable))?;
            let parent_identity = required_identity(&anchor_directory)?;
            match fs::symlink_metadata(&requested_parent) {
                Err(entry_error) if entry_error.kind() == io::ErrorKind::NotFound => {}
                _ => return Err(OperationError::new(OperationFailureCode::StalePlan)),
            }
            let parent = anchor.join(missing_name);
            Ok(ResolvedFile {
                requested_parent,
                path: parent.join(&name),
                parent,
                name,
                parent_identity,
                creation_parent: Some(anchor),
            })
        }
        Err(_) => Err(OperationError::new(unavailable)),
    }
}

#[cfg(target_os = "macos")]
fn resolve_directory(path: &Path) -> Result<ResolvedDirectory, OperationError> {
    let requested = absolute_path(path)
        .map_err(|_| OperationError::new(OperationFailureCode::WorkspaceUnavailable))?;
    match fs::symlink_metadata(&requested) {
        Ok(entry) => {
            if entry.file_type().is_symlink() || !entry.is_dir() {
                return Err(OperationError::new(
                    OperationFailureCode::WorkspaceUnavailable,
                ));
            }
            let resolved = fs::canonicalize(&requested)
                .map_err(|_| OperationError::new(OperationFailureCode::WorkspaceUnavailable))?;
            if is_filesystem_root(&resolved) {
                return Err(OperationError::new(OperationFailureCode::UnsafePath));
            }
            let directory = open_directory(&resolved)
                .map_err(|_| OperationError::new(OperationFailureCode::WorkspaceUnavailable))?;
            let identity = required_identity(&directory)?;
            Ok(ResolvedDirectory {
                requested,
                path: resolved,
                identity: Some(identity),
                creation_parent: None,
                creation_parent_identity: None,
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let name = requested
                .file_name()
                .filter(|name| *name != OsStr::new(".") && *name != OsStr::new(".."))
                .ok_or_else(|| OperationError::new(OperationFailureCode::UnsafePath))?
                .to_os_string();
            let requested_parent = requested
                .parent()
                .ok_or_else(|| OperationError::new(OperationFailureCode::UnsafePath))?;
            let parent = fs::canonicalize(requested_parent)
                .map_err(|_| OperationError::new(OperationFailureCode::WorkspaceUnavailable))?;
            let parent_directory = open_directory(&parent)
                .map_err(|_| OperationError::new(OperationFailureCode::WorkspaceUnavailable))?;
            let parent_identity = required_identity(&parent_directory)?;
            let resolved = parent.join(name);
            match fs::symlink_metadata(&resolved) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                _ => return Err(OperationError::new(OperationFailureCode::StalePlan)),
            }
            Ok(ResolvedDirectory {
                requested,
                path: resolved,
                identity: None,
                creation_parent: Some(parent),
                creation_parent_identity: Some(parent_identity),
            })
        }
        Err(_) => Err(OperationError::new(
            OperationFailureCode::WorkspaceUnavailable,
        )),
    }
}

#[cfg(target_os = "macos")]
fn select_staging_strategy(
    selection: WorkspaceSelection,
    same_qualified_filesystem: bool,
) -> Result<StagingStrategy, OperationFailureCode> {
    match (selection, same_qualified_filesystem) {
        (WorkspaceSelection::HostDefault, true) => Ok(StagingStrategy::HostWorkspace),
        (WorkspaceSelection::HostDefault, false) => Ok(StagingStrategy::DestinationLocalFallback),
        (WorkspaceSelection::Explicit, true) => Ok(StagingStrategy::ExplicitWorkspace),
        (WorkspaceSelection::Explicit, false) => Err(OperationFailureCode::UnsupportedCapability),
    }
}

#[cfg(target_os = "macos")]
fn destination_local_workspace(
    destination_anchor: &Path,
    destination_anchor_identity: FileIdentity,
) -> ResolvedDirectory {
    ResolvedDirectory {
        requested: destination_anchor.to_path_buf(),
        path: destination_anchor.to_path_buf(),
        identity: Some(destination_anchor_identity),
        creation_parent: None,
        creation_parent_identity: None,
    }
}

#[cfg(target_os = "macos")]
fn select_staging_workspace(
    selection: WorkspaceSelection,
    requested_workspace: ResolvedDirectory,
    same_qualified_filesystem: bool,
    destination_anchor: &Path,
    destination_anchor_identity: FileIdentity,
) -> Result<(ResolvedDirectory, StagingStrategy), OperationFailureCode> {
    let strategy = select_staging_strategy(selection, same_qualified_filesystem)?;
    let workspace = if strategy == StagingStrategy::DestinationLocalFallback {
        destination_local_workspace(destination_anchor, destination_anchor_identity)
    } else {
        requested_workspace
    };
    Ok((workspace, strategy))
}

#[cfg(target_os = "macos")]
fn qualified_local_apfs_volume(directory: &File) -> bool {
    let mut status = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: the open directory remains valid for the call and status points to a full statfs
    // output structure.
    if unsafe { libc::fstatfs(directory.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return false;
    }
    // SAFETY: fstatfs returned success and initialized the complete structure.
    let status = unsafe { status.assume_init() };
    let filesystem_type = status
        .f_fstypename
        .iter()
        .map(|byte| *byte as u8)
        .take_while(|byte| *byte != 0)
        .collect::<Vec<_>>();
    filesystem_type == b"apfs"
        && status.f_flags & libc::MNT_LOCAL as u32 != 0
        && status.f_flags & libc::MNT_RDONLY as u32 == 0
}

#[cfg(target_os = "macos")]
fn require_directory_writable(directory: &File) -> Result<(), OperationFailureCode> {
    let dot = c_name(OsStr::new(".")).map_err(|_| OperationFailureCode::UnsafePath)?;
    // SAFETY: directory is an open directory descriptor and dot is one NUL-terminated component.
    let result = unsafe {
        libc::faccessat(
            directory.as_raw_fd(),
            dot.as_ptr(),
            libc::W_OK,
            libc::AT_EACCESS,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if matches!(error.raw_os_error(), Some(libc::EACCES) | Some(libc::EROFS)) {
        Err(OperationFailureCode::WorkspaceUnavailable)
    } else {
        Err(OperationFailureCode::UnsupportedCapability)
    }
}

#[cfg(target_os = "macos")]
fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

#[cfg(target_os = "macos")]
fn is_filesystem_root(path: &Path) -> bool {
    path.parent().is_none()
}

#[cfg(target_os = "macos")]
fn required_identity(file: &File) -> Result<FileIdentity, OperationError> {
    handle_identity(file)
        .ok_or_else(|| OperationError::new(OperationFailureCode::UnsupportedCapability))
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
    // SAFETY: `directory` is an open directory handle and `name` is a
    // NUL-terminated single path component. The returned descriptor is owned
    // by the `File` constructed below.
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
    // SAFETY: `openat` returned a new descriptor that has not been adopted by
    // another owner.
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
fn create_file_at(directory: &File, name: &OsStr) -> io::Result<File> {
    let name = c_name(name)?;
    // SAFETY: `directory` is an open directory handle and `name` is a
    // NUL-terminated single path component. `O_EXCL` prevents replacing an
    // existing entry, and the returned descriptor is owned below.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a new descriptor that has not been adopted by
    // another owner.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(target_os = "macos")]
fn open_lock_file_at(directory: &File, name: &OsStr) -> io::Result<File> {
    let name = c_name(name)?;
    let mut last_error = None;
    // Cooperating operations may create the same marker at the same time. A
    // short bounded retry handles a transient missing-entry result while the
    // directory entry is being established; persistent failures still fail closed.
    for _ in 0..LOCK_FILE_OPEN_ATTEMPTS {
        // SAFETY: `directory` is an open directory handle and `name` is a
        // NUL-terminated single path component. `O_NOFOLLOW` rejects a symlink
        // and the returned descriptor is owned below.
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if descriptor >= 0 {
            // SAFETY: `openat` returned a new descriptor that has not been
            // adopted by another owner.
            let file = unsafe { File::from_raw_fd(descriptor) };
            if !file.metadata()?.file_type().is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "not a regular file",
                ));
            }
            return Ok(file);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(error);
        }
        last_error = Some(error);
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    Err(last_error.unwrap_or_else(|| io::Error::from(io::ErrorKind::NotFound)))
}

#[cfg(target_os = "macos")]
fn hard_link_at(
    from_directory: &File,
    from: &OsStr,
    to_directory: &File,
    to: &OsStr,
) -> io::Result<()> {
    let from = c_name(from)?;
    let to = c_name(to)?;
    // SAFETY: both descriptors refer to open directories and both C strings
    // contain one path component. `linkat` creates the destination entry
    // atomically and fails if that entry already exists.
    let result = unsafe {
        libc::linkat(
            from_directory.as_raw_fd(),
            from.as_ptr(),
            to_directory.as_raw_fd(),
            to.as_ptr(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn rename_swap_at(
    from_directory: &File,
    from: &OsStr,
    to_directory: &File,
    to: &OsStr,
) -> io::Result<()> {
    let from = c_name(from)?;
    let to = c_name(to)?;
    // SAFETY: both descriptors refer to open directories and both names are
    // single path components. RENAME_SWAP atomically exchanges the entries
    // currently named by those paths; it does not condition the exchange on
    // either entry having a previously observed identity.
    let result = unsafe {
        libc::renameatx_np(
            from_directory.as_raw_fd(),
            from.as_ptr(),
            to_directory.as_raw_fd(),
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
fn qualify_rename_swap(directory: &File) -> Result<(), OperationFailureCode> {
    if volume_supports_rename_swap(directory) {
        Ok(())
    } else {
        Err(OperationFailureCode::UnsupportedCapability)
    }
}

#[cfg(target_os = "macos")]
fn volume_supports_rename_swap(directory: &File) -> bool {
    #[repr(C)]
    struct CapabilityOutput {
        length: u32,
        capabilities: libc::vol_capabilities_attr_t,
    }

    let mut attributes = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: 0,
        volattr: libc::ATTR_VOL_INFO | libc::ATTR_VOL_CAPABILITIES,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut output = std::mem::MaybeUninit::<CapabilityOutput>::zeroed();
    // SAFETY: the attribute list requests a fixed-size volume capability
    // structure after the required four-byte attribute-buffer length prefix.
    let result = unsafe {
        libc::fgetattrlist(
            directory.as_raw_fd(),
            (&mut attributes as *mut libc::attrlist).cast(),
            output.as_mut_ptr().cast(),
            std::mem::size_of::<CapabilityOutput>(),
            0,
        )
    };
    if result != 0 {
        return false;
    }
    // SAFETY: fgetattrlist returned success into the initialized-sized buffer.
    let capabilities = unsafe { output.assume_init() }.capabilities;
    let interface = libc::VOL_CAPABILITIES_INTERFACES;
    let bit = libc::VOL_CAP_INT_RENAME_SWAP;
    capabilities.valid[interface] & bit != 0 && capabilities.capabilities[interface] & bit != 0
}

#[cfg(target_os = "macos")]
fn c_name(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

#[cfg(target_os = "macos")]
fn inspect_destination(
    directory: &File,
    name: &OsStr,
) -> Result<Option<FileEvidence>, OperationFailureCode> {
    inspect_destination_with_checkpoint(directory, name, || {})
}

#[cfg(target_os = "macos")]
fn inspect_destination_with_checkpoint(
    directory: &File,
    name: &OsStr,
    checkpoint: impl FnMut(),
) -> Result<Option<FileEvidence>, OperationFailureCode> {
    match open_file_at(directory, name) {
        Ok(mut file) => inspect_file_with_checkpoint(&mut file, checkpoint)
            .map(Some)
            .map_err(|code| match code {
                OperationFailureCode::SourceChanged => OperationFailureCode::DestinationChanged,
                OperationFailureCode::UnsupportedCapability => {
                    OperationFailureCode::UnsupportedCapability
                }
                _ => OperationFailureCode::DestinationUnavailable,
            }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            Err(OperationFailureCode::UnsafePath)
        }
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
            Err(OperationFailureCode::UnsafePath)
        }
        Err(_) => Err(OperationFailureCode::DestinationUnavailable),
    }
}

#[cfg(target_os = "macos")]
fn inspect_file(file: &mut File) -> Result<FileEvidence, OperationFailureCode> {
    inspect_file_with_checkpoint(file, || {})
}

#[cfg(target_os = "macos")]
fn inspect_file_with_checkpoint(
    file: &mut File,
    checkpoint: impl FnMut(),
) -> Result<FileEvidence, OperationFailureCode> {
    let metadata = file
        .metadata()
        .map_err(|_| OperationFailureCode::SourceUnavailable)?;
    if !metadata.file_type().is_file() {
        return Err(OperationFailureCode::SourceUnavailable);
    }
    inspect_file_with_length_and_checkpoint(file, metadata.len(), checkpoint)
}

#[cfg(target_os = "macos")]
fn inspect_file_with_length_and_checkpoint(
    file: &mut File,
    planned_length: u64,
    checkpoint: impl FnMut(),
) -> Result<FileEvidence, OperationFailureCode> {
    let metadata = file
        .metadata()
        .map_err(|_| OperationFailureCode::SourceUnavailable)?;
    if !metadata.file_type().is_file() {
        return Err(OperationFailureCode::SourceUnavailable);
    }
    if metadata.len() != planned_length {
        return Err(OperationFailureCode::SourceChanged);
    }
    let identity = handle_identity(file).ok_or(OperationFailureCode::UnsupportedCapability)?;
    let before = file_snapshot(&metadata, Some(identity));
    let (read_size, sha256) =
        hash_open_file_with_length_and_checkpoint(file, planned_length, checkpoint)?;
    let metadata_after = file
        .metadata()
        .map_err(|_| OperationFailureCode::SourceChanged)?;
    let identity_after =
        handle_identity(file).ok_or(OperationFailureCode::UnsupportedCapability)?;
    let after = file_snapshot(&metadata_after, Some(identity_after));
    if before != after || read_size != before.len {
        return Err(OperationFailureCode::SourceChanged);
    }
    Ok(FileEvidence {
        snapshot: before,
        identity,
        sha256,
    })
}

#[cfg(target_os = "macos")]
fn hash_open_file_with_length_and_checkpoint(
    file: &mut File,
    planned_length: u64,
    mut checkpoint: impl FnMut(),
) -> Result<(u64, Sha256Digest), OperationFailureCode> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| OperationFailureCode::SourceUnavailable)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; IO_BUFFER_SIZE];
    let mut remaining = planned_length;
    while remaining > 0 {
        let chunk = remaining.min(IO_BUFFER_SIZE as u64) as usize;
        if let Err(error) = file.read_exact(&mut buffer[..chunk]) {
            return Err(if error.kind() == io::ErrorKind::UnexpectedEof {
                OperationFailureCode::SourceChanged
            } else {
                OperationFailureCode::SourceUnavailable
            });
        }
        hasher.update(&buffer[..chunk]);
        remaining -= chunk as u64;
        checkpoint();
    }
    let mut probe = [0_u8; 1];
    match file.read(&mut probe) {
        Ok(0) => {}
        Ok(_) => return Err(OperationFailureCode::SourceChanged),
        Err(_) => return Err(OperationFailureCode::SourceUnavailable),
    }
    Ok((
        planned_length,
        Sha256Digest::from_bytes(hasher.finalize().into()),
    ))
}

#[cfg(target_os = "macos")]
fn files_equal(left: &mut File, right: &mut File, planned_length: u64) -> io::Result<bool> {
    left.seek(SeekFrom::Start(0))?;
    right.seek(SeekFrom::Start(0))?;
    let mut left_buffer = [0_u8; IO_BUFFER_SIZE];
    let mut right_buffer = [0_u8; IO_BUFFER_SIZE];
    let mut remaining = planned_length;
    while remaining > 0 {
        let chunk = remaining.min(IO_BUFFER_SIZE as u64) as usize;
        if left.read_exact(&mut left_buffer[..chunk]).is_err()
            || right.read_exact(&mut right_buffer[..chunk]).is_err()
        {
            return Ok(false);
        }
        if left_buffer[..chunk] != right_buffer[..chunk] {
            return Ok(false);
        }
        remaining -= chunk as u64;
    }
    let mut probe = [0_u8; 1];
    Ok(left.read(&mut probe)? == 0 && right.read(&mut probe)? == 0)
}

#[cfg(target_os = "macos")]
fn files_equal_with_checkpoint(
    left: &mut File,
    right: &mut File,
    planned_length: u64,
    left_failure: OperationFailureCode,
    right_failure: OperationFailureCode,
    mut checkpoint: impl FnMut() -> Result<(), OperationFailureCode>,
) -> Result<bool, OperationFailureCode> {
    left.seek(SeekFrom::Start(0))
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    right
        .seek(SeekFrom::Start(0))
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    let mut left_buffer = [0_u8; IO_BUFFER_SIZE];
    let mut right_buffer = [0_u8; IO_BUFFER_SIZE];
    let mut remaining = planned_length;
    while remaining > 0 {
        let chunk = remaining.min(IO_BUFFER_SIZE as u64) as usize;
        left.read_exact(&mut left_buffer[..chunk])
            .map_err(|_| left_failure)?;
        right
            .read_exact(&mut right_buffer[..chunk])
            .map_err(|_| right_failure)?;
        checkpoint()?;
        if left_buffer[..chunk] != right_buffer[..chunk] {
            return Ok(false);
        }
        remaining -= chunk as u64;
    }
    let mut probe = [0_u8; 1];
    if left.read(&mut probe).map_err(|_| left_failure)? != 0 {
        return Err(left_failure);
    }
    if right.read(&mut probe).map_err(|_| right_failure)? != 0 {
        return Err(right_failure);
    }
    Ok(true)
}

#[cfg(target_os = "macos")]
fn verify_file_evidence_with_checkpoint(
    file: &mut File,
    expected: &FileEvidence,
    checkpoint: impl FnMut(),
) -> Result<(), OperationFailureCode> {
    let observed =
        inspect_file_with_length_and_checkpoint(file, expected.snapshot.len, checkpoint)?;
    if observed == *expected {
        Ok(())
    } else {
        Err(OperationFailureCode::SourceChanged)
    }
}

#[cfg(target_os = "macos")]
fn verify_file_evidence(
    file: &mut File,
    expected: &FileEvidence,
) -> Result<(), OperationFailureCode> {
    let observed = inspect_file_with_length_and_checkpoint(file, expected.snapshot.len, || {})?;
    if observed == *expected {
        Ok(())
    } else {
        Err(OperationFailureCode::SourceChanged)
    }
}

#[cfg(target_os = "macos")]
fn validate_file_route(
    file: &ResolvedFile,
    runtime_parent_identity: Option<FileIdentity>,
) -> Result<(), OperationFailureCode> {
    if let Some(anchor) = file.creation_parent.as_deref() {
        return match runtime_parent_identity {
            None => {
                if fs::canonicalize(&file.requested_parent).is_ok() {
                    return Err(OperationFailureCode::StalePlan);
                }
                let requested_anchor = file
                    .requested_parent
                    .parent()
                    .ok_or(OperationFailureCode::StalePlan)?;
                if fs::canonicalize(requested_anchor)
                    .map_err(|_| OperationFailureCode::StalePlan)?
                    != anchor
                {
                    return Err(OperationFailureCode::StalePlan);
                }
                let directory =
                    open_directory(anchor).map_err(|_| OperationFailureCode::StalePlan)?;
                if handle_identity(&directory) != Some(file.parent_identity) {
                    Err(OperationFailureCode::StalePlan)
                } else {
                    Ok(())
                }
            }
            Some(identity) => {
                let current = fs::canonicalize(&file.requested_parent)
                    .map_err(|_| OperationFailureCode::StalePlan)?;
                if current != file.parent {
                    return Err(OperationFailureCode::StalePlan);
                }
                let directory =
                    open_directory(&file.parent).map_err(|_| OperationFailureCode::StalePlan)?;
                if handle_identity(&directory) == Some(identity) {
                    Ok(())
                } else {
                    Err(OperationFailureCode::StalePlan)
                }
            }
        };
    }

    let current_parent =
        fs::canonicalize(&file.requested_parent).map_err(|_| OperationFailureCode::StalePlan)?;
    if current_parent != file.parent {
        return Err(OperationFailureCode::StalePlan);
    }
    let directory = open_directory(&file.parent).map_err(|_| OperationFailureCode::StalePlan)?;
    if handle_identity(&directory) != Some(file.parent_identity) {
        return Err(OperationFailureCode::StalePlan);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_directory_route(
    directory: &ResolvedDirectory,
    runtime_identity: Option<FileIdentity>,
) -> Result<(), OperationFailureCode> {
    if let Some(identity) = directory.identity {
        if runtime_identity.is_some_and(|runtime| runtime != identity) {
            return Err(OperationFailureCode::StalePlan);
        }
        let current =
            fs::canonicalize(&directory.requested).map_err(|_| OperationFailureCode::StalePlan)?;
        if current != directory.path {
            return Err(OperationFailureCode::StalePlan);
        }
        let opened =
            open_directory(&directory.path).map_err(|_| OperationFailureCode::StalePlan)?;
        if handle_identity(&opened) != Some(identity) {
            return Err(OperationFailureCode::StalePlan);
        }
        return Ok(());
    }

    let parent = directory
        .creation_parent
        .as_deref()
        .ok_or(OperationFailureCode::StalePlan)?;
    let expected_parent_identity = directory
        .creation_parent_identity
        .ok_or(OperationFailureCode::StalePlan)?;
    let requested_parent = directory
        .requested
        .parent()
        .ok_or(OperationFailureCode::StalePlan)?;
    if fs::canonicalize(requested_parent).map_err(|_| OperationFailureCode::StalePlan)? != parent {
        return Err(OperationFailureCode::StalePlan);
    }
    let parent_handle = open_directory(parent).map_err(|_| OperationFailureCode::StalePlan)?;
    if handle_identity(&parent_handle) != Some(expected_parent_identity) {
        return Err(OperationFailureCode::StalePlan);
    }

    match runtime_identity {
        None => match fs::symlink_metadata(&directory.requested) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            _ => Err(OperationFailureCode::StalePlan),
        },
        Some(expected_identity) => {
            if fs::canonicalize(&directory.requested)
                .map_err(|_| OperationFailureCode::StalePlan)?
                != directory.path
            {
                return Err(OperationFailureCode::StalePlan);
            }
            let opened =
                open_directory(&directory.path).map_err(|_| OperationFailureCode::StalePlan)?;
            if handle_identity(&opened) == Some(expected_identity) {
                Ok(())
            } else {
                Err(OperationFailureCode::StalePlan)
            }
        }
    }
}

/// Returns the shared coordination marker name for one destination parent.
///
/// The marker is opened relative to the already validated parent directory
/// descriptor. Every destination in that directory therefore uses the same
/// entry, including final path spellings that the filesystem treats as aliases.
#[cfg(target_os = "macos")]
fn destination_lock_name(_path: &Path) -> OsString {
    ".nscb-operation-directory.lock".into()
}

/// Executes a consumed plan in an explicitly supplied host session.
pub(crate) fn execute_operation(
    plan: OperationPlan,
    session: &OperationSession,
) -> OperationResult {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (plan, session);
        failed_result(
            vec![OperationMilestone::Planned],
            OperationFailureCode::UnsupportedCapability,
            false,
        )
    }

    #[cfg(target_os = "macos")]
    {
        let planned_length = plan.source_baseline.snapshot.len;
        execute_with_producer(plan, session, move |source, stage, session| {
            copy_source_to_stage_with_length(source, stage, planned_length, session)
        })
    }
}

/// Executes a consumed plan with cancellation bound to this invocation.
///
/// The handle is attached only while this execution holds admission. A request
/// made before admission is observed before any workspace or staging entry is
/// created. The existing OperationSession::cancel path is unchanged.
pub(crate) fn execute_operation_with_cancellation(
    plan: OperationPlan,
    session: &OperationSession,
    cancellation: &CancellationHandle,
) -> OperationResult {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (plan, session, cancellation);
        failed_result(
            vec![OperationMilestone::Planned],
            OperationFailureCode::UnsupportedCapability,
            false,
        )
    }
    #[cfg(target_os = "macos")]
    {
        let planned_length = plan.source_baseline.snapshot.len;
        execute_with_producer_with_cancellation(
            plan,
            session,
            move |source, stage, session| {
                copy_source_to_stage_with_length(source, stage, planned_length, session)
            },
            Some(cancellation),
        )
    }
}

#[cfg(target_os = "macos")]
fn execute_with_producer<P>(
    plan: OperationPlan,
    session: &OperationSession,
    producer: P,
) -> OperationResult
where
    P: FnOnce(&mut File, &mut File, &OperationSession) -> Result<(), OperationFailureCode>,
{
    execute_with_producer_with_cancellation(plan, session, producer, None)
}

#[cfg(target_os = "macos")]
fn execute_with_producer_with_cancellation<P>(
    plan: OperationPlan,
    session: &OperationSession,
    producer: P,
    cancellation: Option<&CancellationHandle>,
) -> OperationResult
where
    P: FnOnce(&mut File, &mut File, &OperationSession) -> Result<(), OperationFailureCode>,
{
    execute_with_producer_and_checkpoint_with_cancellation(
        plan,
        session,
        producer,
        |_| {},
        cancellation,
    )
}

#[cfg(target_os = "macos")]
#[cfg(test)]
fn execute_with_producer_and_checkpoint<P, H>(
    plan: OperationPlan,
    session: &OperationSession,
    producer: P,
    checkpoint: H,
) -> OperationResult
where
    P: FnOnce(&mut File, &mut File, &OperationSession) -> Result<(), OperationFailureCode>,
    H: FnMut(ExecutionCheckpoint),
{
    execute_with_producer_and_checkpoint_with_cancellation(
        plan, session, producer, checkpoint, None,
    )
}

#[cfg(target_os = "macos")]
#[cfg(test)]
fn execute_with_producer_and_checkpoint_and_cancellation<P, H>(
    plan: OperationPlan,
    session: &OperationSession,
    producer: P,
    checkpoint: H,
    cancellation: &CancellationHandle,
) -> OperationResult
where
    P: FnOnce(&mut File, &mut File, &OperationSession) -> Result<(), OperationFailureCode>,
    H: FnMut(ExecutionCheckpoint),
{
    execute_with_producer_and_checkpoint_with_cancellation(
        plan,
        session,
        producer,
        checkpoint,
        Some(cancellation),
    )
}

#[cfg(target_os = "macos")]
fn execute_with_producer_and_checkpoint_with_cancellation<P, H>(
    plan: OperationPlan,
    session: &OperationSession,
    producer: P,
    mut checkpoint: H,
    cancellation: Option<&CancellationHandle>,
) -> OperationResult
where
    P: FnOnce(&mut File, &mut File, &OperationSession) -> Result<(), OperationFailureCode>,
    H: FnMut(ExecutionCheckpoint),
{
    let mut milestones = vec![OperationMilestone::Planned];
    let admission =
        session.admit_with_cancellation(cancellation, Some(plan.source_baseline.snapshot.len));
    let mut admission = match admission {
        Ok(admission) => admission,
        Err(code) => return failed_result(milestones, code, false),
    };
    milestones.push(OperationMilestone::Executing);
    session.record_milestone(OperationMilestone::Executing);

    let mut artifacts = Vec::new();
    let mut cleanup_artifact_retained = false;
    let mut destination_parent_identity = plan
        .destination
        .creation_parent
        .is_none()
        .then_some(plan.destination.parent_identity);
    // This guard outlives `execute_unix` so the cooperative source lock covers
    // every source-derived result postcondition and the final result assembly.
    let mut source_lock = None;
    let mut execution = {
        let mut outputs = ExecutionOutputs {
            milestones: &mut milestones,
            artifacts: &mut artifacts,
            cleanup_artifact_retained: &mut cleanup_artifact_retained,
            source_lock: &mut source_lock,
            destination_parent_identity: &mut destination_parent_identity,
        };
        execute_unix(&plan, session, producer, &mut outputs, &mut checkpoint)
    };
    checkpoint(ExecutionCheckpoint::BeforeFinalization);
    let finalization = session.begin_finalization();
    if matches!(execution, Err(OperationFailureCode::DestinationChanged))
        && !artifacts
            .iter()
            .any(|artifact| artifact.role == OperationArtifactRole::PublishedDestination)
    {
        match capture_current_destination_competitor(
            &plan,
            destination_parent_identity,
            &artifacts,
            &mut checkpoint,
        ) {
            Ok(Some(captured)) => {
                if !captured.evidence_verified {
                    execution = Err(OperationFailureCode::PublicationUncertain);
                }
                artifacts.push(captured.artifact);
            }
            Ok(None) => execution = Err(OperationFailureCode::PublicationUncertain),
            Err(_) => execution = Err(OperationFailureCode::PublicationUncertain),
        }
    }
    match finalization {
        Ok(true) => {}
        Ok(false) => {
            // A cancellation decision cannot turn uncertain publication evidence into a
            // clean cancellation. Inventorying the competitor below usually discovers the
            // same condition, but terminal-result precedence must not depend on that later
            // inventory step succeeding.
            if !matches!(execution, Err(OperationFailureCode::PublicationUncertain)) {
                execution = Err(OperationFailureCode::Cancelled);
            }
        }
        Err(_) => execution = Err(OperationFailureCode::SessionUnavailable),
    }
    cleanup_artifact_retained |= cleanup_artifacts(&mut artifacts);
    checkpoint(ExecutionCheckpoint::BeforeArtifactInventory);
    if retain_late_destination_competitors(
        &mut artifacts,
        &mut cleanup_artifact_retained,
        &mut checkpoint,
    )
    .is_err()
    {
        execution = Err(OperationFailureCode::PublicationUncertain);
    }
    let (operation_artifacts, inventory_failure) =
        artifact_inventory_with_checkpoint(&artifacts, &mut checkpoint);
    match inventory_failure {
        Some(OperationFailureCode::PublicationUncertain) => {
            execution = Err(OperationFailureCode::PublicationUncertain);
        }
        Some(OperationFailureCode::DestinationChanged)
            if matches!(
                execution,
                Ok(_) | Err(OperationFailureCode::DestinationChanged)
            ) =>
        {
            execution = Err(OperationFailureCode::DestinationChanged);
        }
        _ => {}
    }

    let result = match execution {
        Ok(outcome) => {
            if cleanup_artifact_retained {
                milestones.push(OperationMilestone::CleanupIncomplete);
            }
            OperationResult {
                state: JobState::Succeeded,
                outcome: Some(outcome),
                failure: None,
                cleanup_warning: cleanup_artifact_retained
                    .then(|| OperationFailure::new(OperationFailureCode::CleanupIncomplete)),
                milestones,
                cleanup_artifact_retained,
                artifacts: operation_artifacts,
            }
        }
        Err(code) => {
            let state = if code == OperationFailureCode::Cancelled {
                milestones.push(OperationMilestone::Cancelled);
                JobState::Cancelled
            } else {
                milestones.push(OperationMilestone::Failed);
                JobState::Failed
            };
            if cleanup_artifact_retained {
                milestones.push(OperationMilestone::CleanupIncomplete);
            }
            OperationResult {
                state,
                outcome: None,
                failure: Some(OperationFailure::new(code)),
                cleanup_warning: cleanup_artifact_retained
                    .then(|| OperationFailure::new(OperationFailureCode::CleanupIncomplete)),
                milestones,
                cleanup_artifact_retained,
                artifacts: operation_artifacts,
            }
        }
    };
    admission.finish(&result);
    drop(source_lock);
    result
}

fn failed_result(
    mut milestones: Vec<OperationMilestone>,
    code: OperationFailureCode,
    cleanup_artifact_retained: bool,
) -> OperationResult {
    let state = if code == OperationFailureCode::Cancelled {
        milestones.push(OperationMilestone::Cancelled);
        JobState::Cancelled
    } else {
        milestones.push(OperationMilestone::Failed);
        JobState::Failed
    };
    OperationResult {
        state,
        outcome: None,
        failure: Some(OperationFailure::new(code)),
        cleanup_warning: cleanup_artifact_retained
            .then(|| OperationFailure::new(OperationFailureCode::CleanupIncomplete)),
        milestones,
        cleanup_artifact_retained,
        artifacts: Vec::new(),
    }
}

#[cfg(target_os = "macos")]
fn required_storage_bytes(
    source_length: u64,
    destination_backup_length: Option<u64>,
    safety_reserve: u64,
) -> Result<u64, OperationFailureCode> {
    source_length
        .checked_add(destination_backup_length.unwrap_or(0))
        .and_then(|required| required.checked_add(safety_reserve))
        .ok_or(OperationFailureCode::InsufficientStorage)
}

#[cfg(target_os = "macos")]
fn ensure_storage_capacity(
    available: u64,
    source_length: u64,
    destination_backup_length: Option<u64>,
    safety_reserve: u64,
) -> Result<(), OperationFailureCode> {
    let required =
        required_storage_bytes(source_length, destination_backup_length, safety_reserve)?;
    if available < required {
        Err(OperationFailureCode::InsufficientStorage)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn check_storage_capacity(
    workspace_directory: &File,
    plan: &OperationPlan,
) -> Result<(), OperationFailureCode> {
    let backup_length = if plan.snapshot.conflict_policy == ConflictPolicy::Replace {
        plan.destination_baseline
            .as_ref()
            .map(|baseline| baseline.snapshot.len)
    } else {
        None
    };
    let available = available_space_on_open_directory(workspace_directory)?;
    ensure_storage_capacity(
        available,
        plan.source_baseline.snapshot.len,
        backup_length,
        MINIMUM_FREE_SPACE_RESERVE,
    )
}

#[cfg(target_os = "macos")]
fn available_space_on_open_directory(directory: &File) -> Result<u64, OperationFailureCode> {
    let mut status = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `directory` remains open for the call, and `status` points to
    // writable storage for the statfs structure expected by fstatfs.
    let result = unsafe { libc::fstatfs(directory.as_raw_fd(), status.as_mut_ptr()) };
    if result != 0 {
        return Err(OperationFailureCode::UnsupportedCapability);
    }
    // SAFETY: fstatfs returned success and initialized the complete structure.
    let status = unsafe { status.assume_init() };
    let (available_blocks, block_size) = (status.f_bavail, u64::from(status.f_bsize));
    if block_size == 0 {
        return Err(OperationFailureCode::UnsupportedCapability);
    }
    available_blocks
        .checked_mul(block_size)
        .ok_or(OperationFailureCode::UnsupportedCapability)
}

#[cfg(target_os = "macos")]
struct ExecutionOutputs<'a> {
    milestones: &'a mut Vec<OperationMilestone>,
    artifacts: &'a mut Vec<OwnedArtifact>,
    cleanup_artifact_retained: &'a mut bool,
    source_lock: &'a mut Option<SourceLockGuard>,
    destination_parent_identity: &'a mut Option<FileIdentity>,
}

#[cfg(target_os = "macos")]
fn execute_unix<P>(
    plan: &OperationPlan,
    session: &OperationSession,
    producer: P,
    outputs: &mut ExecutionOutputs<'_>,
    checkpoint: &mut impl FnMut(ExecutionCheckpoint),
) -> Result<OperationOutcome, OperationFailureCode>
where
    P: FnOnce(&mut File, &mut File, &OperationSession) -> Result<(), OperationFailureCode>,
{
    let milestones = &mut *outputs.milestones;
    let artifacts = &mut *outputs.artifacts;
    let cleanup_artifact_retained = &mut *outputs.cleanup_artifact_retained;
    let source_lock = &mut *outputs.source_lock;
    let destination_parent_identity = &mut *outputs.destination_parent_identity;
    check_cancelled(session)?;
    validate_file_route(&plan.source, None).map_err(|_| OperationFailureCode::StalePlan)?;
    validate_file_route(&plan.destination, None).map_err(|_| OperationFailureCode::StalePlan)?;
    validate_directory_route(&plan.workspace, None).map_err(|_| OperationFailureCode::StalePlan)?;

    let source_directory =
        open_directory(&plan.source.parent).map_err(|_| OperationFailureCode::SourceUnavailable)?;
    let destination_anchor_directory = open_directory(plan.destination.anchor())
        .map_err(|_| OperationFailureCode::DestinationUnavailable)?;
    let workspace_anchor = plan
        .workspace
        .identity
        .map(|_| plan.workspace.path.as_path())
        .or(plan.workspace.creation_parent.as_deref())
        .ok_or(OperationFailureCode::WorkspaceUnavailable)?;
    let mut workspace_directory =
        open_directory(workspace_anchor).map_err(|_| OperationFailureCode::WorkspaceUnavailable)?;
    verify_directory_identity(&source_directory, plan.source.parent_identity)?;
    verify_directory_identity(
        &destination_anchor_directory,
        plan.destination.parent_identity,
    )?;
    let workspace_anchor_identity = plan
        .workspace
        .identity
        .or(plan.workspace.creation_parent_identity)
        .ok_or(OperationFailureCode::WorkspaceUnavailable)?;
    verify_directory_identity(&workspace_directory, workspace_anchor_identity)?;
    if !qualified_local_apfs_volume(&destination_anchor_directory)
        || !qualified_local_apfs_volume(&workspace_directory)
        || !handle_identity(&workspace_directory)
            .zip(handle_identity(&destination_anchor_directory))
            .is_some_and(|(workspace, destination)| workspace.same_filesystem_as(destination))
    {
        return Err(OperationFailureCode::UnsupportedCapability);
    }
    require_directory_writable(&workspace_directory)?;
    let mut workspace_runtime_identity = plan.workspace.identity;
    let replacing_existing_destination = plan.destination_baseline.is_some()
        && plan.snapshot.conflict_policy == ConflictPolicy::Replace;
    let mut source_file = open_file_at(&source_directory, &plan.source.name)
        .map_err(|_| OperationFailureCode::SourceUnavailable)?;
    verify_file_evidence(&mut source_file, &plan.source_baseline)
        .map_err(|_| OperationFailureCode::SourceChanged)?;
    let source_guard = source_lock.insert(SourceLockGuard { file: source_file });
    acquire_source_lock(
        &source_guard.file,
        &source_directory,
        plan,
        session,
        checkpoint,
    )?;
    let source_file = &mut source_guard.file;
    verify_file_evidence(source_file, &plan.source_baseline)
        .map_err(|_| OperationFailureCode::SourceChanged)?;
    let mut destination_directory = destination_anchor_directory;
    if plan.destination.creation_parent.is_some() {
        validate_file_route(&plan.destination, None)
            .map_err(|_| OperationFailureCode::StalePlan)?;
        let parent_name = plan
            .destination
            .parent
            .file_name()
            .ok_or(OperationFailureCode::UnsafePath)?;
        match make_directory_at(&destination_directory, parent_name) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(OperationFailureCode::StalePlan);
            }
            Err(_) => return Err(OperationFailureCode::DestinationUnavailable),
        }
        destination_directory = open_directory_at(&destination_directory, parent_name)
            .map_err(|_| OperationFailureCode::DestinationUnavailable)?;
        let created_identity = handle_identity(&destination_directory)
            .ok_or(OperationFailureCode::UnsupportedCapability)?;
        if !qualified_local_apfs_volume(&destination_directory)
            || !handle_identity(&workspace_directory)
                .is_some_and(|workspace| workspace.same_filesystem_as(created_identity))
        {
            return Err(OperationFailureCode::UnsupportedCapability);
        }
        if require_directory_writable(&destination_directory).is_err() {
            return Err(OperationFailureCode::DestinationUnavailable);
        }
        *destination_parent_identity = Some(created_identity);
    }
    let destination_parent_identity =
        destination_parent_identity.ok_or(OperationFailureCode::DestinationUnavailable)?;
    validate_file_route(&plan.destination, Some(destination_parent_identity))
        .map_err(|_| OperationFailureCode::StalePlan)?;
    ensure_destination_baseline(plan, &destination_directory)?;
    if plan.snapshot.conflict_policy == ConflictPolicy::Fail
        && plan.destination_baseline.is_some()
        && !plan.already_up_to_date
    {
        return Err(OperationFailureCode::DestinationConflict);
    }
    let lock_name = plan
        .snapshot
        .destination_lock_path
        .file_name()
        .ok_or(OperationFailureCode::UnsafePath)?
        .to_os_string();
    if lock_name == plan.destination.name
        || (plan.source.parent == plan.destination.parent && lock_name == plan.source.name)
    {
        return Err(OperationFailureCode::UnsafePath);
    }

    let destination_lock = acquire_destination_lock(
        &destination_directory,
        &lock_name,
        &plan.destination.parent,
        &plan.source_baseline,
        plan.destination_baseline.as_ref(),
        session,
        checkpoint,
    )?;
    validate_destination_lock(
        &destination_lock,
        &destination_directory,
        plan,
        destination_parent_identity,
    )?;
    validate_plan_routes(
        plan,
        workspace_runtime_identity,
        Some(destination_parent_identity),
    )?;
    verify_source_entry(plan, &source_directory)?;
    ensure_destination_baseline(plan, &destination_directory)?;
    if plan.snapshot.conflict_policy == ConflictPolicy::Fail
        && plan.destination_baseline.is_some()
        && !plan.already_up_to_date
    {
        return Err(OperationFailureCode::DestinationConflict);
    }

    if plan.already_up_to_date {
        validate_plan_routes(
            plan,
            workspace_runtime_identity,
            Some(destination_parent_identity),
        )?;
        let mut current_source = open_file_at(&source_directory, &plan.source.name)
            .map_err(|_| OperationFailureCode::SourceChanged)?;
        verify_file_evidence(&mut current_source, &plan.source_baseline)
            .map_err(|_| OperationFailureCode::SourceChanged)?;
        let mut current_destination = open_file_at(&destination_directory, &plan.destination.name)
            .map_err(|_| OperationFailureCode::DestinationChanged)?;
        let expected_destination = plan
            .destination_baseline
            .as_ref()
            .ok_or(OperationFailureCode::DestinationChanged)?;
        verify_destination_evidence(&mut current_destination, expected_destination)?;
        let identical = files_equal_with_checkpoint(
            &mut current_source,
            &mut current_destination,
            plan.source_baseline.snapshot.len,
            OperationFailureCode::SourceChanged,
            OperationFailureCode::DestinationChanged,
            || {
                checkpoint(ExecutionCheckpoint::AlreadyUpToDateComparisonChunk);
                check_cancelled(session)
            },
        )?;
        checkpoint(ExecutionCheckpoint::AlreadyUpToDateCompared);
        if !identical {
            return Err(OperationFailureCode::DestinationChanged);
        }

        check_cancelled(session)?;
        let mut final_source = open_file_at(&source_directory, &plan.source.name)
            .map_err(|_| OperationFailureCode::SourceChanged)?;
        verify_file_evidence(&mut final_source, &plan.source_baseline)
            .map_err(|_| OperationFailureCode::SourceChanged)?;
        verify_destination_entry(
            &destination_directory,
            &plan.destination.name,
            expected_destination,
        )?;
        checkpoint(ExecutionCheckpoint::BeforeCompletion);
        verify_destination_on_current_route(
            plan,
            destination_parent_identity,
            expected_destination,
        )?;
        if !session
            .begin_completion()
            .map_err(|_| OperationFailureCode::SessionUnavailable)?
        {
            return Err(OperationFailureCode::Cancelled);
        }
        milestones.push(OperationMilestone::Validated);
        session.record_milestone(OperationMilestone::Validated);
        return Ok(OperationOutcome::AlreadyUpToDate);
    }

    // Cancellation can be accepted while the destination lock and read-only
    // pre-staging checks are active. This is the last checkpoint before the
    // first operation-owned workspace or staging entry can be created.
    check_cancelled(session)?;
    require_directory_writable(&workspace_directory)?;
    check_storage_capacity(&workspace_directory, plan)?;

    if workspace_runtime_identity.is_none() {
        let workspace_name = plan
            .workspace
            .path
            .file_name()
            .ok_or(OperationFailureCode::UnsafePath)?;
        // Reserve the inventory descriptor before creating an owned directory.
        // A later open/identity failure must still leave a reportable artifact.
        let parent_handle = workspace_directory
            .try_clone()
            .map_err(|_| OperationFailureCode::WriteFailed)?;
        match make_directory_at(&workspace_directory, workspace_name) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(OperationFailureCode::StalePlan);
            }
            Err(_) => return Err(OperationFailureCode::WorkspaceUnavailable),
        }
        let created_directory = open_directory_at(&workspace_directory, workspace_name).ok();
        let created_identity = created_directory.as_ref().and_then(handle_identity);
        let parent_identity = handle_identity(&workspace_directory);
        let id = next_artifact_id(artifacts);
        let parent_artifact_id =
            parent_artifact_id_for_path(artifacts, workspace_anchor, parent_identity);
        artifacts.push(OwnedArtifact {
            id,
            parent_artifact_id,
            relative_name: PathBuf::from(workspace_name),
            parent_identity,
            directory: parent_handle,
            name: workspace_name.to_os_string(),
            path: plan.workspace.path.clone(),
            identity: created_identity,
            kind: OwnedArtifactKind::Directory,
            role: OperationArtifactRole::WorkspaceDirectory,
            length: None,
            sha256: None,
            path_identity: created_identity,
            path_length: None,
            keep: true,
        });
        *cleanup_artifact_retained = true;
        workspace_directory =
            created_directory.ok_or(OperationFailureCode::UnsupportedCapability)?;
        workspace_runtime_identity =
            Some(created_identity.ok_or(OperationFailureCode::UnsupportedCapability)?);
        validate_directory_route(&plan.workspace, workspace_runtime_identity)?;
    }

    let stage_directory_name = plan
        .stage_directory_name
        .as_deref()
        .ok_or(OperationFailureCode::StalePlan)?;
    let stage_file_name = plan
        .stage_file_name
        .as_deref()
        .ok_or(OperationFailureCode::StalePlan)?;
    let stage_directory_path = plan.workspace.path.join(stage_directory_name);
    let stage_directory = create_private_stage_directory(
        &workspace_directory,
        &plan.workspace.path,
        stage_directory_name,
        artifacts,
        cleanup_artifact_retained,
    )?;
    let (mut stage_file, stage_identity) = create_artifact(
        &stage_directory,
        &stage_directory_path,
        stage_file_name,
        OperationArtifactRole::StagedOutput,
        artifacts,
        cleanup_artifact_retained,
    )?;
    let stage_name = stage_file_name.to_os_string();
    let produced = producer(source_file, &mut stage_file, session);
    let stage_after_production = inspect_file(&mut stage_file);
    match &stage_after_production {
        Ok(observed) => update_artifact_evidence(
            artifacts,
            &stage_name,
            Some(observed.identity),
            OperationArtifactRole::StagedOutput,
            Some(observed.snapshot.len),
            Some(observed.sha256),
        ),
        Err(_) => set_artifact_unverified(artifacts, &stage_name),
    }
    if let Err(producer_failure) = produced {
        if let Ok(observed) = &stage_after_production {
            let stage_matches_plan = observed.snapshot.len == plan.source_baseline.snapshot.len
                && observed.sha256 == plan.source_baseline.sha256;
            if !stage_matches_plan
                && !matches!(
                    producer_failure,
                    OperationFailureCode::SourceChanged | OperationFailureCode::Cancelled
                )
            {
                return Err(OperationFailureCode::ValidationFailed);
            }
        }
        return Err(producer_failure);
    }
    let stage_after_production =
        stage_after_production.map_err(|_| OperationFailureCode::ValidationFailed)?;
    if stage_after_production.snapshot.len != plan.source_baseline.snapshot.len
        || stage_after_production.sha256 != plan.source_baseline.sha256
    {
        return Err(OperationFailureCode::ValidationFailed);
    }
    stage_file
        .sync_all()
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    check_cancelled(session)?;

    verify_file_evidence_with_checkpoint(source_file, &plan.source_baseline, || {
        checkpoint(ExecutionCheckpoint::SourceEvidenceReadChunk);
    })
    .map_err(|_| OperationFailureCode::SourceChanged)?;
    let mut staged =
        inspect_file(&mut stage_file).map_err(|_| OperationFailureCode::ValidationFailed)?;
    if staged.snapshot.len != plan.source_baseline.snapshot.len
        || staged.sha256 != plan.source_baseline.sha256
    {
        return Err(OperationFailureCode::ValidationFailed);
    }
    if !files_equal_with_checkpoint(
        source_file,
        &mut stage_file,
        plan.source_baseline.snapshot.len,
        OperationFailureCode::SourceChanged,
        OperationFailureCode::ValidationFailed,
        || check_cancelled(session),
    )? {
        return Err(OperationFailureCode::ValidationFailed);
    }
    verify_file_evidence(source_file, &plan.source_baseline)
        .map_err(|_| OperationFailureCode::SourceChanged)?;
    staged = inspect_file(&mut stage_file).map_err(|_| OperationFailureCode::ValidationFailed)?;
    if staged.snapshot.len != plan.source_baseline.snapshot.len
        || staged.sha256 != plan.source_baseline.sha256
        || staged.identity != stage_identity
    {
        return Err(OperationFailureCode::ValidationFailed);
    }
    update_artifact_evidence(
        artifacts,
        &stage_name,
        Some(stage_identity),
        OperationArtifactRole::StagedOutput,
        Some(staged.snapshot.len),
        Some(staged.sha256),
    );
    let mut staged_path = open_file_at(&stage_directory, &stage_name)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    verify_file_evidence(&mut staged_path, &staged)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    milestones.push(OperationMilestone::Validated);
    session.record_milestone(OperationMilestone::Validated);

    check_cancelled(session)?;
    validate_plan_routes(
        plan,
        workspace_runtime_identity,
        Some(destination_parent_identity),
    )?;
    let mut current_source = open_file_at(&source_directory, &plan.source.name)
        .map_err(|_| OperationFailureCode::SourceChanged)?;
    verify_file_evidence(&mut current_source, &plan.source_baseline)
        .map_err(|_| OperationFailureCode::SourceChanged)?;
    ensure_destination_baseline(plan, &destination_directory)?;
    let mut current_stage = open_file_at(&stage_directory, &stage_name)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    verify_file_evidence(&mut current_stage, &staged)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;

    let backup_name = if replacing_existing_destination {
        let name = plan
            .backup_name
            .as_deref()
            .ok_or(OperationFailureCode::StalePlan)?;
        create_destination_backup(
            plan,
            &destination_directory,
            &stage_directory,
            &stage_directory_path,
            session,
            artifacts,
            cleanup_artifact_retained,
        )?;
        Some(name.to_os_string())
    } else {
        None
    };

    // Backup creation can take time. Revalidate every planned entry again so
    // the replacement commit follows the freshest available evidence.
    validate_plan_routes(
        plan,
        workspace_runtime_identity,
        Some(destination_parent_identity),
    )?;
    verify_source_entry(plan, &source_directory)?;
    ensure_destination_baseline(plan, &destination_directory)?;
    let mut current_stage = open_file_at(&stage_directory, &stage_name)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    verify_file_evidence(&mut current_stage, &staged)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;

    checkpoint(ExecutionCheckpoint::BeforePromotion);
    verify_source_entry(plan, &source_directory)?;
    let destination_artifact_directory = destination_directory
        .try_clone()
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    let publication = PublicationContext {
        plan,
        source_directory: &source_directory,
        destination_directory: &destination_directory,
        destination_artifact_directory,
        destination_lock: &destination_lock,
        destination_parent_identity,
        stage_directory: &stage_directory,
        workspace_runtime_identity,
        stage_name: &stage_name,
        stage_identity,
        staged: &staged,
        session,
        backup_name: backup_name.as_deref(),
        checkpoint,
        milestones,
        artifacts,
        cleanup_artifact_retained,
    };
    let result = if replacing_existing_destination {
        publish_replacement(publication)?
    } else {
        publish_new(publication)?
    };
    if let Some(milestone) = milestones.last().copied() {
        session.record_milestone(milestone);
    }
    Ok(result)
}

#[cfg(target_os = "macos")]
fn verify_directory_identity(
    directory: &File,
    expected: FileIdentity,
) -> Result<(), OperationFailureCode> {
    if handle_identity(directory) == Some(expected) {
        Ok(())
    } else {
        Err(OperationFailureCode::StalePlan)
    }
}

#[cfg(target_os = "macos")]
fn validate_plan_routes(
    plan: &OperationPlan,
    workspace_runtime_identity: Option<FileIdentity>,
    destination_parent_identity: Option<FileIdentity>,
) -> Result<(), OperationFailureCode> {
    validate_file_route(&plan.source, None).map_err(|_| OperationFailureCode::StalePlan)?;
    validate_file_route(&plan.destination, destination_parent_identity)
        .map_err(|_| OperationFailureCode::StalePlan)?;
    validate_directory_route(&plan.workspace, workspace_runtime_identity)
        .map_err(|_| OperationFailureCode::StalePlan)
}

#[cfg(target_os = "macos")]
fn ensure_destination_baseline(
    plan: &OperationPlan,
    destination_directory: &File,
) -> Result<(), OperationFailureCode> {
    ensure_destination_baseline_with_checkpoint(plan, destination_directory, || {})
}

#[cfg(target_os = "macos")]
fn ensure_destination_baseline_with_checkpoint(
    plan: &OperationPlan,
    destination_directory: &File,
    checkpoint: impl FnMut(),
) -> Result<(), OperationFailureCode> {
    let observed = inspect_destination_with_checkpoint(
        destination_directory,
        &plan.destination.name,
        checkpoint,
    )?;
    match (&plan.destination_baseline, observed) {
        (None, None) => Ok(()),
        (Some(expected), Some(observed)) if *expected == observed => Ok(()),
        _ => Err(OperationFailureCode::DestinationChanged),
    }
}

#[cfg(target_os = "macos")]
fn verify_destination_evidence(
    file: &mut File,
    expected: &FileEvidence,
) -> Result<(), OperationFailureCode> {
    let observed = inspect_file(file).map_err(|_| OperationFailureCode::DestinationChanged)?;
    if observed == *expected {
        Ok(())
    } else {
        Err(OperationFailureCode::DestinationChanged)
    }
}

#[cfg(target_os = "macos")]
fn verify_destination_entry(
    directory: &File,
    name: &OsStr,
    expected: &FileEvidence,
) -> Result<(), OperationFailureCode> {
    let mut file =
        open_file_at(directory, name).map_err(|_| OperationFailureCode::DestinationChanged)?;
    verify_destination_evidence(&mut file, expected)
}

#[cfg(target_os = "macos")]
fn verify_destination_on_current_route(
    plan: &OperationPlan,
    destination_parent_identity: FileIdentity,
    expected: &FileEvidence,
) -> Result<(), OperationFailureCode> {
    let directory = open_destination_parent_on_current_route(plan, destination_parent_identity)?;
    verify_destination_entry(&directory, &plan.destination.name, expected)?;
    validate_file_route(&plan.destination, Some(destination_parent_identity))
        .map_err(|_| OperationFailureCode::DestinationChanged)
}

#[cfg(target_os = "macos")]
fn open_destination_parent_on_current_route(
    plan: &OperationPlan,
    destination_parent_identity: FileIdentity,
) -> Result<File, OperationFailureCode> {
    validate_file_route(&plan.destination, Some(destination_parent_identity))
        .map_err(|_| OperationFailureCode::DestinationChanged)?;
    let directory = open_directory(&plan.destination.parent)
        .map_err(|_| OperationFailureCode::DestinationChanged)?;
    verify_directory_identity(&directory, destination_parent_identity)
        .map_err(|_| OperationFailureCode::DestinationChanged)?;
    Ok(directory)
}

#[cfg(target_os = "macos")]
fn verify_published_destination_on_current_route(
    plan: &OperationPlan,
    destination_parent_identity: FileIdentity,
    identity: FileIdentity,
    expected: &FileEvidence,
) -> Result<(), OperationFailureCode> {
    let directory = open_destination_parent_on_current_route(plan, destination_parent_identity)?;
    validate_published_file(&directory, &plan.destination.name, identity, expected)?;
    validate_file_route(&plan.destination, Some(destination_parent_identity))
        .map_err(|_| OperationFailureCode::PublicationUncertain)
}

#[cfg(target_os = "macos")]
fn same_file_identity_and_content(observed: &FileEvidence, expected: &FileEvidence) -> bool {
    observed.identity == expected.identity
        && observed.snapshot.len == expected.snapshot.len
        && observed.sha256 == expected.sha256
}

#[cfg(target_os = "macos")]
fn check_cancelled(session: &OperationSession) -> Result<(), OperationFailureCode> {
    if session
        .cancellation_requested()
        .map_err(|_| OperationFailureCode::SessionUnavailable)?
    {
        session.record_observed_cancellation();
        Err(OperationFailureCode::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(all(test, target_os = "macos"))]
fn copy_source_to_stage(
    source: &mut File,
    stage: &mut File,
    session: &OperationSession,
) -> Result<(), OperationFailureCode> {
    let planned_length = source
        .metadata()
        .map_err(|_| OperationFailureCode::SourceUnavailable)?
        .len();
    copy_source_to_stage_with_length(source, stage, planned_length, session)
}

#[cfg(target_os = "macos")]
fn copy_source_to_stage_with_length(
    source: &mut File,
    stage: &mut File,
    planned_length: u64,
    session: &OperationSession,
) -> Result<(), OperationFailureCode> {
    copy_source_to_stage_with_length_and_checkpoint(source, stage, planned_length, session, || {})
}

#[cfg(target_os = "macos")]
fn copy_source_to_stage_with_length_and_checkpoint(
    source: &mut File,
    stage: &mut File,
    planned_length: u64,
    session: &OperationSession,
    mut after_chunk: impl FnMut(),
) -> Result<(), OperationFailureCode> {
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| OperationFailureCode::SourceUnavailable)?;
    stage
        .seek(SeekFrom::Start(0))
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    let mut buffer = [0_u8; IO_BUFFER_SIZE];
    let mut remaining = planned_length;
    while remaining > 0 {
        check_cancelled(session)?;
        let capacity = usize::try_from(remaining.min(IO_BUFFER_SIZE as u64))
            .map_err(|_| OperationFailureCode::SourceChanged)?;
        let read = loop {
            match source.read(&mut buffer[..capacity]) {
                Ok(0) => return Err(OperationFailureCode::SourceChanged),
                Ok(read) => break read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(OperationFailureCode::SourceChanged),
            }
        };
        stage
            .write_all(&buffer[..read])
            .map_err(|_| OperationFailureCode::WriteFailed)?;
        remaining = remaining
            .checked_sub(read as u64)
            .ok_or(OperationFailureCode::SourceChanged)?;
        session.record_progress(planned_length.saturating_sub(remaining));
        after_chunk();
    }

    check_cancelled(session)?;
    let mut extra_byte = [0_u8; 1];
    loop {
        match source.read(&mut extra_byte) {
            Ok(0) => break,
            Ok(_) => return Err(OperationFailureCode::SourceChanged),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                check_cancelled(session)?;
            }
            Err(_) => return Err(OperationFailureCode::SourceChanged),
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn acquire_destination_lock(
    directory: &File,
    name: &OsStr,
    parent_path: &Path,
    source: &FileEvidence,
    destination: Option<&FileEvidence>,
    session: &OperationSession,
    checkpoint: &mut impl FnMut(ExecutionCheckpoint),
) -> Result<DestinationLock, OperationFailureCode> {
    let parent_identity =
        handle_identity(directory).ok_or(OperationFailureCode::UnsupportedCapability)?;
    let lock =
        open_lock_file_at(directory, name).map_err(|error| destination_lock_failure(&error))?;
    let lock_identity =
        handle_identity(&lock).ok_or(OperationFailureCode::UnsupportedCapability)?;
    if lock_identity == source.identity
        || destination.is_some_and(|evidence| evidence.identity == lock_identity)
    {
        return Err(OperationFailureCode::UnsafePath);
    }
    // Own the descriptor before any locked validation can fail. Closing it
    // alone does not release a lock inherited by another process.
    let lock = DestinationLock {
        _file: lock,
        marker_name: name.to_os_string(),
        marker_identity: lock_identity,
        parent_identity,
        parent_path: parent_path.to_path_buf(),
    };
    loop {
        check_cancelled(session)?;
        match lock._file.try_lock_exclusive() {
            Ok(()) => break,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                checkpoint(ExecutionCheckpoint::DestinationLockWait);
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => return Err(destination_lock_failure(&error)),
        }
    }
    checkpoint(ExecutionCheckpoint::DestinationLockAcquired);
    let named_lock =
        open_file_at(directory, name).map_err(|error| destination_lock_failure(&error))?;
    if handle_identity(&named_lock) != Some(lock_identity) {
        return Err(OperationFailureCode::StalePlan);
    }
    Ok(lock)
}

#[cfg(target_os = "macos")]
fn validate_destination_lock(
    lock: &DestinationLock,
    directory: &File,
    plan: &OperationPlan,
    destination_parent_identity: FileIdentity,
) -> Result<(), OperationFailureCode> {
    if lock.parent_path != plan.destination.parent
        || lock.parent_identity != destination_parent_identity
        || handle_identity(directory) != Some(lock.parent_identity)
        || handle_identity(&lock._file) != Some(lock.marker_identity)
    {
        return Err(OperationFailureCode::StalePlan);
    }

    let current_parent =
        open_directory(&lock.parent_path).map_err(|_| OperationFailureCode::StalePlan)?;
    if handle_identity(&current_parent) != Some(lock.parent_identity) {
        return Err(OperationFailureCode::StalePlan);
    }

    let named_lock =
        open_file_at(directory, &lock.marker_name).map_err(|_| OperationFailureCode::StalePlan)?;
    if handle_identity(&named_lock) != Some(lock.marker_identity) {
        return Err(OperationFailureCode::StalePlan);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn acquire_source_lock(
    source_file: &File,
    source_directory: &File,
    plan: &OperationPlan,
    session: &OperationSession,
    checkpoint: &mut impl FnMut(ExecutionCheckpoint),
) -> Result<(), OperationFailureCode> {
    let expected_identity =
        handle_identity(source_file).ok_or(OperationFailureCode::UnsupportedCapability)?;
    loop {
        check_cancelled(session)?;
        match fs2::FileExt::try_lock_shared(source_file) {
            Ok(()) => break,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                checkpoint(ExecutionCheckpoint::SourceLockWait);
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) if is_unsupported_capability_error(&error) => {
                return Err(OperationFailureCode::UnsupportedCapability);
            }
            Err(_) => return Err(OperationFailureCode::SourceUnavailable),
        }
    }
    checkpoint(ExecutionCheckpoint::SourceLockAcquired);

    let mut current_source = open_file_at(source_directory, &plan.source.name)
        .map_err(|_| OperationFailureCode::SourceChanged)?;
    if handle_identity(&current_source) != Some(expected_identity) {
        return Err(OperationFailureCode::SourceChanged);
    }
    verify_file_evidence(&mut current_source, &plan.source_baseline)
        .map_err(|_| OperationFailureCode::SourceChanged)
}

#[cfg(target_os = "macos")]
struct SourceLockGuard {
    /// Locked source descriptor held until terminal result construction ends.
    file: File,
}

#[cfg(target_os = "macos")]
impl Drop for SourceLockGuard {
    fn drop(&mut self) {
        // Closing this descriptor alone may leave the lock held by a descriptor
        // inherited across fork. Release the shared lock at terminal finalization
        // even when another reference to the open file description survives.
        while let Err(error) = fs2::FileExt::unlock(&self.file) {
            if error.kind() != io::ErrorKind::Interrupted {
                break;
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn create_artifact(
    directory: &File,
    directory_path: &Path,
    name: &OsStr,
    role: OperationArtifactRole,
    artifacts: &mut Vec<OwnedArtifact>,
    cleanup_artifact_retained: &mut bool,
) -> Result<(File, FileIdentity), OperationFailureCode> {
    let directory_handle = directory
        .try_clone()
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    let parent_identity = handle_identity(directory);
    let id = next_artifact_id(artifacts);
    let parent_artifact_id =
        parent_artifact_id_for_path(artifacts, directory_path, parent_identity);
    let file = match create_file_at(directory, name) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(OperationFailureCode::StalePlan);
        }
        Err(_) => return Err(OperationFailureCode::WriteFailed),
    };
    let identity = handle_identity(&file);
    artifacts.push(OwnedArtifact {
        id,
        parent_artifact_id,
        relative_name: PathBuf::from(name),
        parent_identity,
        directory: directory_handle,
        name: name.to_os_string(),
        path: directory_path.join(name),
        identity,
        kind: OwnedArtifactKind::File,
        role,
        length: Some(0),
        sha256: None,
        path_identity: identity,
        path_length: Some(0),
        keep: false,
    });
    match identity {
        Some(identity) => Ok((file, identity)),
        None => {
            *cleanup_artifact_retained = true;
            Err(OperationFailureCode::UnsupportedCapability)
        }
    }
}

#[cfg(target_os = "macos")]
fn create_private_stage_directory(
    parent: &File,
    parent_path: &Path,
    name: &OsStr,
    artifacts: &mut Vec<OwnedArtifact>,
    cleanup_artifact_retained: &mut bool,
) -> Result<File, OperationFailureCode> {
    let parent_handle = parent
        .try_clone()
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    let parent_identity = handle_identity(parent);
    let id = next_artifact_id(artifacts);
    let parent_artifact_id = parent_artifact_id_for_path(artifacts, parent_path, parent_identity);
    match make_directory_at(parent, name) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(OperationFailureCode::StalePlan);
        }
        Err(_) => return Err(OperationFailureCode::WriteFailed),
    }
    let path = parent_path.join(name);
    let directory = match open_directory_at(parent, name) {
        Ok(directory) => directory,
        Err(_) => {
            artifacts.push(OwnedArtifact {
                id,
                parent_artifact_id,
                relative_name: PathBuf::from(name),
                parent_identity,
                directory: parent_handle,
                name: name.to_os_string(),
                path,
                identity: None,
                kind: OwnedArtifactKind::Directory,
                role: OperationArtifactRole::PrivateStagingDirectory,
                length: None,
                sha256: None,
                path_identity: None,
                path_length: None,
                keep: true,
            });
            *cleanup_artifact_retained = true;
            return Err(OperationFailureCode::UnsupportedCapability);
        }
    };
    let identity = handle_identity(&directory);
    artifacts.push(OwnedArtifact {
        id,
        parent_artifact_id,
        relative_name: PathBuf::from(name),
        parent_identity,
        directory: parent_handle,
        name: name.to_os_string(),
        path,
        identity,
        kind: OwnedArtifactKind::Directory,
        role: OperationArtifactRole::PrivateStagingDirectory,
        length: None,
        sha256: None,
        path_identity: identity,
        path_length: None,
        keep: identity.is_none(),
    });
    if identity.is_none() {
        *cleanup_artifact_retained = true;
        return Err(OperationFailureCode::UnsupportedCapability);
    }
    Ok(directory)
}

#[cfg(target_os = "macos")]
fn make_directory_at(parent: &File, name: &OsStr) -> io::Result<()> {
    let name = c_name(name)?;
    // SAFETY: the descriptor refers to an open directory and the C string is
    // a single path component. Mode 0700 isolates the operation's stage names
    // from filesystem users with different effective user IDs.
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn open_directory_at(parent: &File, name: &OsStr) -> io::Result<File> {
    #[cfg(test)]
    if TEST_DIRECTORY_OPEN_FAILURE.with(|failure| {
        let mut failure = failure.borrow_mut();
        if failure.as_deref() == Some(name) {
            failure.take();
            true
        } else {
            false
        }
    }) {
        return Err(io::Error::from_raw_os_error(libc::EMFILE));
    }
    let name = c_name(name)?;
    // SAFETY: the descriptor refers to an open directory; flags prevent
    // following a symbolic link or opening a non-directory entry.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: openat returned a new owned file descriptor.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

#[cfg(target_os = "macos")]
fn create_destination_backup(
    plan: &OperationPlan,
    destination_directory: &File,
    stage_directory: &File,
    stage_directory_path: &Path,
    session: &OperationSession,
    artifacts: &mut Vec<OwnedArtifact>,
    cleanup_artifact_retained: &mut bool,
) -> Result<(), OperationFailureCode> {
    let backup_name = plan
        .backup_name
        .as_deref()
        .ok_or(OperationFailureCode::StalePlan)?;
    let expected = plan
        .destination_baseline
        .as_ref()
        .ok_or(OperationFailureCode::UnsupportedCapability)?;
    let (mut backup, backup_identity) = create_artifact(
        stage_directory,
        stage_directory_path,
        backup_name,
        OperationArtifactRole::DestinationBackup,
        artifacts,
        cleanup_artifact_retained,
    )?;
    let mut destination = open_file_at(destination_directory, &plan.destination.name)
        .map_err(|_| OperationFailureCode::DestinationChanged)?;
    verify_destination_evidence(&mut destination, expected)?;

    destination
        .seek(SeekFrom::Start(0))
        .map_err(|_| OperationFailureCode::DestinationChanged)?;
    backup
        .seek(SeekFrom::Start(0))
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    let mut buffer = [0_u8; IO_BUFFER_SIZE];
    let mut remaining = expected.snapshot.len;
    while remaining > 0 {
        check_cancelled(session)?;
        let chunk = remaining.min(IO_BUFFER_SIZE as u64) as usize;
        destination
            .read_exact(&mut buffer[..chunk])
            .map_err(|_| OperationFailureCode::DestinationChanged)?;
        backup
            .write_all(&buffer[..chunk])
            .map_err(|_| OperationFailureCode::WriteFailed)?;
        remaining -= chunk as u64;
    }
    let mut probe = [0_u8; 1];
    if destination
        .read(&mut probe)
        .map_err(|_| OperationFailureCode::DestinationChanged)?
        != 0
    {
        return Err(OperationFailureCode::DestinationChanged);
    }
    backup
        .sync_all()
        .map_err(|_| OperationFailureCode::WriteFailed)?;

    if !files_equal(&mut destination, &mut backup, expected.snapshot.len)
        .map_err(|_| OperationFailureCode::DestinationChanged)?
    {
        return Err(OperationFailureCode::DestinationChanged);
    }
    verify_destination_evidence(&mut destination, expected)?;
    ensure_destination_baseline(plan, destination_directory)?;
    let observed_backup =
        inspect_file(&mut backup).map_err(|_| OperationFailureCode::ValidationFailed)?;
    if observed_backup.identity != backup_identity
        || observed_backup.snapshot.len != expected.snapshot.len
        || observed_backup.sha256 != expected.sha256
    {
        return Err(OperationFailureCode::ValidationFailed);
    }
    update_artifact_evidence(
        artifacts,
        backup_name,
        Some(backup_identity),
        OperationArtifactRole::DestinationBackup,
        Some(observed_backup.snapshot.len),
        Some(observed_backup.sha256),
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn next_artifact_name(role: &str) -> Result<OsString, OperationFailureCode> {
    #[cfg(all(test, target_os = "macos"))]
    if let Some(name) = TEST_ARTIFACT_NAME_QUEUE.with(|queue| queue.borrow_mut().pop_front()) {
        return Ok(name);
    }

    random_artifact_name(role)
}

#[cfg(target_os = "macos")]
fn random_artifact_name(role: &str) -> Result<OsString, OperationFailureCode> {
    let mut entropy =
        File::open("/dev/urandom").map_err(|_| OperationFailureCode::UnsupportedCapability)?;
    let mut random = [0_u8; 16];
    entropy
        .read_exact(&mut random)
        .map_err(|_| OperationFailureCode::UnsupportedCapability)?;
    let id = NEXT_ARTIFACT_ID.fetch_add(1, Ordering::Relaxed);
    let nonce = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!(".nscb-{role}-{}-{id}-{nonce}", std::process::id()).into())
}

#[cfg(target_os = "macos")]
fn cleanup_artifacts(artifacts: &mut [OwnedArtifact]) -> bool {
    cleanup_artifacts_with_probe(artifacts, |_| {})
}

#[cfg(target_os = "macos")]
fn cleanup_artifacts_with_probe(
    artifacts: &mut [OwnedArtifact],
    mut after_probe: impl FnMut(&OwnedArtifact),
) -> bool {
    for artifact in artifacts.iter_mut().rev() {
        after_probe(artifact);
        match artifact.kind {
            OwnedArtifactKind::File => {
                if let Ok(file) = open_file_at(&artifact.directory, &artifact.name) {
                    let metadata = file.metadata().ok();
                    artifact.path_identity = handle_identity(&file);
                    artifact.path_length = metadata.as_ref().map(std::fs::Metadata::len);
                } else {
                    artifact.path_identity = None;
                    artifact.path_length = None;
                }
            }
            OwnedArtifactKind::Directory => {
                if let Ok(directory) = open_directory_at(&artifact.directory, &artifact.name) {
                    artifact.path_identity = handle_identity(&directory);
                    artifact.path_length = None;
                } else {
                    artifact.path_identity = None;
                    artifact.path_length = None;
                }
            }
        }
        artifact.keep = true;
    }
    !artifacts.is_empty()
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnedArtifactKind {
    File,
    Directory,
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct OwnedArtifact {
    id: u64,
    parent_artifact_id: Option<u64>,
    relative_name: PathBuf,
    parent_identity: Option<FileIdentity>,
    directory: File,
    name: OsString,
    path: PathBuf,
    identity: Option<FileIdentity>,
    kind: OwnedArtifactKind,
    role: OperationArtifactRole,
    length: Option<u64>,
    sha256: Option<Sha256Digest>,
    path_identity: Option<FileIdentity>,
    path_length: Option<u64>,
    keep: bool,
}

#[cfg(target_os = "macos")]
fn retain_late_destination_competitors(
    artifacts: &mut Vec<OwnedArtifact>,
    cleanup_artifact_retained: &mut bool,
    checkpoint: &mut impl FnMut(ExecutionCheckpoint),
) -> Result<(), OperationFailureCode> {
    const MAX_ANCHORED_COMPETITORS: usize = 32;
    const PRIVATE_DIRECTORY_ATTEMPTS: usize = 8;

    let published_indices = artifacts
        .iter()
        .enumerate()
        .filter_map(|(index, artifact)| {
            (artifact.kind == OwnedArtifactKind::File
                && artifact.role == OperationArtifactRole::PublishedDestination)
                .then_some(index)
        })
        .collect::<Vec<_>>();
    let mut anchored_identities = Vec::new();
    let mut anchored_count = 0;

    loop {
        let mut competitor = None;
        for index in &published_indices {
            let artifact = &artifacts[*index];
            let published_identity = artifact
                .identity
                .ok_or(OperationFailureCode::PublicationUncertain)?;
            let parent_identity = artifact
                .parent_identity
                .ok_or(OperationFailureCode::PublicationUncertain)?;
            if handle_identity(&artifact.directory) != Some(parent_identity) {
                return Err(OperationFailureCode::PublicationUncertain);
            }
            let parent_path = artifact
                .path
                .parent()
                .ok_or(OperationFailureCode::PublicationUncertain)?;
            if open_directory(parent_path)
                .ok()
                .as_ref()
                .and_then(handle_identity)
                != Some(parent_identity)
            {
                return Err(OperationFailureCode::PublicationUncertain);
            }

            let mut current = match open_file_at(&artifact.directory, &artifact.name) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => return Err(OperationFailureCode::PublicationUncertain),
            };
            let current_identity =
                handle_identity(&current).ok_or(OperationFailureCode::PublicationUncertain)?;
            if current_identity == published_identity
                || anchored_identities.contains(&current_identity)
            {
                continue;
            }
            let current_length = current
                .metadata()
                .map_err(|_| OperationFailureCode::PublicationUncertain)?
                .len();
            let evidence =
                inspect_file_with_length_and_checkpoint(&mut current, current_length, || {})
                    .map_err(|_| OperationFailureCode::PublicationUncertain)?;
            if evidence.identity != current_identity {
                return Err(OperationFailureCode::PublicationUncertain);
            }
            let directory = artifact
                .directory
                .try_clone()
                .map_err(|_| OperationFailureCode::PublicationUncertain)?;
            competitor = Some((
                directory,
                parent_path.to_path_buf(),
                artifact.name.to_os_string(),
                parent_identity,
                published_identity,
                evidence,
                current,
            ));
            break;
        }

        let Some((
            parent_directory,
            parent_path,
            destination_name,
            parent_identity,
            published_identity,
            observed_evidence,
            held_competitor,
        )) = competitor
        else {
            return Ok(());
        };
        if handle_identity(&parent_directory) != Some(parent_identity) {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        if anchored_count >= MAX_ANCHORED_COMPETITORS {
            return Err(OperationFailureCode::PublicationUncertain);
        }

        let mut private_directory = None;
        for _ in 0..PRIVATE_DIRECTORY_ATTEMPTS {
            let directory_name = random_artifact_name("late-competitor")
                .map_err(|_| OperationFailureCode::PublicationUncertain)?;
            match create_private_stage_directory(
                &parent_directory,
                &parent_path,
                &directory_name,
                artifacts,
                cleanup_artifact_retained,
            ) {
                Ok(directory) => {
                    private_directory = Some((directory_name, directory));
                    break;
                }
                Err(OperationFailureCode::StalePlan) => continue,
                Err(_) => return Err(OperationFailureCode::PublicationUncertain),
            }
        }
        let Some((private_directory_name, private_directory)) = private_directory else {
            return Err(OperationFailureCode::PublicationUncertain);
        };
        *cleanup_artifact_retained = true;
        let private_directory_index = artifacts.len() - 1;
        let private_directory_path = parent_path.join(&private_directory_name);
        let private_directory_identity = handle_identity(&private_directory)
            .ok_or(OperationFailureCode::PublicationUncertain)?;
        if open_directory_at(&parent_directory, &private_directory_name)
            .ok()
            .as_ref()
            .and_then(handle_identity)
            != Some(private_directory_identity)
        {
            return Err(OperationFailureCode::PublicationUncertain);
        }

        let alias_name = OsString::from("entry");
        // Reserve bookkeeping before linkat. Once it succeeds, register the
        // alias before any observation can fail, keeping unknown evidence unknown.
        let alias_parent = clone_competitor_inventory_directory(&private_directory)
            .map_err(|_| OperationFailureCode::PublicationUncertain)?;
        let alias_parent_identity = private_directory_identity;
        let alias_parent_artifact_id = parent_artifact_id_for_path(
            artifacts,
            &private_directory_path,
            Some(alias_parent_identity),
        );
        checkpoint(ExecutionCheckpoint::BeforeCompetitorLink);
        if hard_link_at(
            &parent_directory,
            &destination_name,
            &private_directory,
            &alias_name,
        )
        .is_err()
        {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        let alias_path = private_directory_path.join(&alias_name);
        let alias_artifact_id = next_artifact_id(artifacts);
        let alias_index = artifacts.len();
        artifacts.push(OwnedArtifact {
            id: alias_artifact_id,
            parent_artifact_id: alias_parent_artifact_id,
            relative_name: PathBuf::from(&alias_name),
            parent_identity: Some(alias_parent_identity),
            directory: alias_parent,
            name: alias_name.clone(),
            path: alias_path,
            identity: None,
            kind: OwnedArtifactKind::File,
            role: OperationArtifactRole::UncertainEntry,
            length: None,
            sha256: None,
            path_identity: None,
            path_length: None,
            keep: false,
        });
        checkpoint(ExecutionCheckpoint::AfterCompetitorLink);

        let mut alias_file = open_file_at(&private_directory, &alias_name).ok();
        let alias_path_identity = alias_file.as_ref().and_then(handle_identity);
        let alias_path_length = alias_file
            .as_ref()
            .and_then(|file| file.metadata().ok())
            .map(|metadata| metadata.len());
        let alias_evidence = match (&mut alias_file, alias_path_length) {
            (Some(file), Some(length)) => {
                inspect_file_with_length_and_checkpoint(file, length, || {}).ok()
            }
            _ => None,
        };
        // Keep the observed descriptor open until the pathname link and alias
        // have both been verified. An open descriptor prevents the observed
        // inode from being reallocated, so equal content on a replacement
        // inode cannot be mistaken for the object observed before `linkat`.
        let held_competitor_identity =
            handle_identity(&held_competitor).ok_or(OperationFailureCode::PublicationUncertain)?;
        if held_competitor_identity != observed_evidence.identity {
            return Err(OperationFailureCode::PublicationUncertain);
        }
        let alias_verified = alias_evidence.as_ref().is_some_and(|evidence| {
            evidence.identity == observed_evidence.identity
                && evidence.snapshot.len == observed_evidence.snapshot.len
                && evidence.sha256 == observed_evidence.sha256
                && Some(evidence.identity) == alias_path_identity
                && evidence.identity != published_identity
                && handle_identity(&held_competitor) == Some(observed_evidence.identity)
        });
        let alias_identity = alias_evidence
            .as_ref()
            .map(|evidence| evidence.identity)
            .or(alias_path_identity);
        let alias_length = alias_evidence
            .as_ref()
            .map(|evidence| evidence.snapshot.len)
            .or(alias_path_length);
        let alias_digest = alias_evidence
            .as_ref()
            .map(|evidence| evidence.sha256)
            .or_else(|| {
                (alias_path_identity == Some(observed_evidence.identity))
                    .then_some(observed_evidence.sha256)
            });
        let alias_artifact = &mut artifacts[alias_index];
        alias_artifact.identity = alias_identity;
        alias_artifact.length = alias_length;
        alias_artifact.sha256 = alias_digest;
        alias_artifact.path_identity = alias_path_identity;
        alias_artifact.path_length = alias_path_length;
        if !alias_verified {
            return Err(OperationFailureCode::PublicationUncertain);
        }

        artifacts[private_directory_index].keep = true;
        artifacts
            .last_mut()
            .ok_or(OperationFailureCode::PublicationUncertain)?
            .keep = true;
        anchored_identities.push(observed_evidence.identity);
        anchored_count += 1;
        checkpoint(ExecutionCheckpoint::AfterCompetitorRetention);
    }
}

#[cfg(target_os = "macos")]
fn clone_competitor_inventory_directory(directory: &File) -> io::Result<File> {
    #[cfg(test)]
    if TEST_COMPETITOR_INVENTORY_DUP_FAILURE.with(|failure| failure.replace(false)) {
        return Err(io::Error::from_raw_os_error(libc::EMFILE));
    }
    directory.try_clone()
}

#[cfg(all(test, target_os = "macos"))]
fn artifact_inventory(
    artifacts: &[OwnedArtifact],
) -> (Vec<OperationArtifact>, Option<OperationFailureCode>) {
    artifact_inventory_with_checkpoint(artifacts, &mut |_| {})
}

#[cfg(target_os = "macos")]
fn artifact_inventory_with_checkpoint(
    artifacts: &[OwnedArtifact],
    checkpoint: &mut dyn FnMut(ExecutionCheckpoint),
) -> (Vec<OperationArtifact>, Option<OperationFailureCode>) {
    let mut inventory_failure = None;
    let mut operation_artifacts = Vec::with_capacity(artifacts.len() + 1);
    let mut next_synthetic_id = next_artifact_id(artifacts);
    for artifact in artifacts {
        let mut current_entry = match artifact.kind {
            OwnedArtifactKind::File => open_file_at(&artifact.directory, &artifact.name).ok(),
            OwnedArtifactKind::Directory => {
                open_directory_at(&artifact.directory, &artifact.name).ok()
            }
        };
        let current_entry_identity = current_entry.as_ref().and_then(handle_identity);
        let current_entry_length = if artifact.kind == OwnedArtifactKind::File {
            current_entry
                .as_ref()
                .and_then(|entry| entry.metadata().ok())
                .map(|metadata| metadata.len())
        } else {
            None
        };
        let identity_matches = artifact
            .identity
            .zip(current_entry_identity)
            .is_some_and(|(recorded, observed)| recorded == observed);
        let refreshed_content = if artifact.kind == OwnedArtifactKind::File && identity_matches {
            current_entry.as_mut().map(|entry| {
                let current_length =
                    current_entry_length.ok_or(OperationFailureCode::PublicationUncertain)?;
                if artifact.length != Some(current_length) {
                    return Err(OperationFailureCode::DestinationChanged);
                }
                let evidence =
                    inspect_file_with_length_and_checkpoint(entry, current_length, || {})?;
                if Some(evidence.identity) != artifact.identity {
                    return Err(OperationFailureCode::PublicationUncertain);
                }
                Ok(evidence)
            })
        } else {
            None
        };
        let competing_content =
            if artifact.role == OperationArtifactRole::PublishedDestination && !identity_matches {
                current_entry.as_mut().and_then(|entry| {
                    let length = current_entry_length?;
                    inspect_file_with_length_and_checkpoint(entry, length, || {})
                        .ok()
                        .filter(|evidence| Some(evidence.identity) == current_entry_identity)
                })
            } else {
                None
            };
        if artifact.role == OperationArtifactRole::PublishedDestination {
            checkpoint(ExecutionCheckpoint::AfterPublishedDestinationContentInspection);
        }
        // Reopen after content inspection so path evidence never comes from a stale handle.
        let post_inspection_entry = match artifact.kind {
            OwnedArtifactKind::File => open_file_at(&artifact.directory, &artifact.name).ok(),
            OwnedArtifactKind::Directory => {
                open_directory_at(&artifact.directory, &artifact.name).ok()
            }
        };
        let post_inspection_entry_identity =
            post_inspection_entry.as_ref().and_then(handle_identity);
        let post_inspection_entry_length = if artifact.kind == OwnedArtifactKind::File {
            post_inspection_entry
                .as_ref()
                .and_then(|entry| entry.metadata().ok())
                .map(|metadata| metadata.len())
        } else {
            None
        };
        let path_stable_after_inspection = current_entry_identity == post_inspection_entry_identity
            && current_entry_length == post_inspection_entry_length;
        let refreshed_identity_alias =
            if artifact.kind == OwnedArtifactKind::File && !identity_matches {
                artifact
                    .identity
                    .and_then(|identity| refresh_owned_file_identity(artifacts, identity))
            } else {
                None
            };
        let parent_path_identity = artifact
            .path
            .parent()
            .and_then(|path| open_directory(path).ok())
            .as_ref()
            .and_then(handle_identity);
        let parent_identity_matches = artifact
            .parent_identity
            .zip(parent_path_identity)
            .map(|(recorded, observed)| recorded == observed);
        let parent_path_verified = parent_identity_matches == Some(true);
        let retained_uncertain_entry_verified = artifact.role
            != OperationArtifactRole::UncertainEntry
            || !artifact.keep
            || (parent_path_verified
                && identity_matches
                && path_stable_after_inspection
                && current_entry_length == artifact.length
                && matches!(
                    refreshed_content.as_ref(),
                    Some(Ok(evidence))
                        if Some(evidence.identity) == artifact.identity
                            && Some(evidence.snapshot.len) == artifact.length
                            && Some(evidence.sha256) == artifact.sha256
                ));
        let classification = if !path_stable_after_inspection {
            Some(OperationFailureCode::PublicationUncertain)
        } else {
            match artifact.role {
                OperationArtifactRole::DisplacedDestination => {
                    if !identity_matches || current_entry_length.is_none() {
                        Some(OperationFailureCode::PublicationUncertain)
                    } else if current_entry_length != artifact.length {
                        Some(OperationFailureCode::DestinationChanged)
                    } else {
                        match refreshed_content.as_ref() {
                            Some(Ok(evidence)) if Some(evidence.sha256) != artifact.sha256 => {
                                Some(OperationFailureCode::DestinationChanged)
                            }
                            Some(Ok(_)) => None,
                            Some(Err(OperationFailureCode::SourceChanged))
                            | Some(Err(OperationFailureCode::DestinationChanged)) => {
                                Some(OperationFailureCode::DestinationChanged)
                            }
                            Some(Err(_)) | None => Some(OperationFailureCode::PublicationUncertain),
                        }
                    }
                }
                OperationArtifactRole::PublishedDestination => {
                    let planned_output_still_matches = identity_matches
                        && current_entry_length == artifact.length
                        && matches!(
                            refreshed_content.as_ref(),
                            Some(Ok(evidence)) if Some(evidence.sha256) == artifact.sha256
                        );
                    (!planned_output_still_matches)
                        .then_some(OperationFailureCode::PublicationUncertain)
                }
                OperationArtifactRole::UncertainEntry
                    if artifact.keep && !retained_uncertain_entry_verified =>
                {
                    Some(OperationFailureCode::PublicationUncertain)
                }
                OperationArtifactRole::UncertainEntry => None,
                _ => None,
            }
        };
        inventory_failure = classification
            .filter(|failure| *failure == OperationFailureCode::PublicationUncertain)
            .or(inventory_failure)
            .or(classification);
        let (length, sha256) = if artifact.kind == OwnedArtifactKind::File {
            if identity_matches {
                (
                    current_entry_length,
                    refreshed_content
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        .map(|evidence| evidence.sha256),
                )
            } else {
                refreshed_identity_alias.unwrap_or((None, None))
            }
        } else {
            (None, None)
        };
        operation_artifacts.push(OperationArtifact {
            artifact_id: artifact.id,
            parent_artifact_id: artifact.parent_artifact_id,
            relative_name: artifact.relative_name.clone(),
            parent_device: artifact.parent_identity.map(FileIdentity::device),
            parent_inode: artifact.parent_identity.map(FileIdentity::inode),
            parent_identity_matches,
            role: artifact.role,
            path: artifact.path.clone(),
            device: artifact.identity.map(FileIdentity::device),
            inode: artifact.identity.map(FileIdentity::inode),
            length,
            sha256,
            recorded_length: artifact.length,
            recorded_sha256: artifact.sha256,
            path_identity_matches: parent_path_verified
                .then(|| {
                    artifact
                        .identity
                        .zip(post_inspection_entry_identity)
                        .map(|(recorded, observed)| recorded == observed)
                })
                .flatten(),
            path_device: parent_path_verified
                .then(|| post_inspection_entry_identity.map(FileIdentity::device))
                .flatten(),
            path_inode: parent_path_verified
                .then(|| post_inspection_entry_identity.map(FileIdentity::inode))
                .flatten(),
            path_length: parent_path_verified
                .then_some(post_inspection_entry_length)
                .flatten(),
            retained: artifact.keep
                && (artifact.role != OperationArtifactRole::UncertainEntry
                    || retained_uncertain_entry_verified),
        });

        if artifact.role == OperationArtifactRole::PublishedDestination
            && !identity_matches
            && path_stable_after_inspection
        {
            let already_inventoried = artifacts.iter().any(|candidate| {
                candidate.role == OperationArtifactRole::UncertainEntry
                    && candidate.path == artifact.path
                    && candidate.identity == post_inspection_entry_identity
            });
            if !already_inventoried && post_inspection_entry_identity.is_some() {
                let observed = competing_content.as_ref();
                if observed.is_none() {
                    inventory_failure = Some(OperationFailureCode::PublicationUncertain);
                }
                operation_artifacts.push(OperationArtifact {
                    artifact_id: next_synthetic_id,
                    parent_artifact_id: artifact.parent_artifact_id,
                    relative_name: artifact.relative_name.clone(),
                    parent_device: artifact.parent_identity.map(FileIdentity::device),
                    parent_inode: artifact.parent_identity.map(FileIdentity::inode),
                    parent_identity_matches,
                    role: OperationArtifactRole::UncertainEntry,
                    path: artifact.path.clone(),
                    device: post_inspection_entry_identity.map(FileIdentity::device),
                    inode: post_inspection_entry_identity.map(FileIdentity::inode),
                    length: observed
                        .map(|evidence| evidence.snapshot.len)
                        .or(post_inspection_entry_length),
                    sha256: observed.map(|evidence| evidence.sha256),
                    recorded_length: observed
                        .map(|evidence| evidence.snapshot.len)
                        .or(post_inspection_entry_length),
                    recorded_sha256: observed.map(|evidence| evidence.sha256),
                    path_identity_matches: parent_path_verified
                        .then(|| post_inspection_entry_identity.map(|_| true))
                        .flatten(),
                    path_device: parent_path_verified
                        .then(|| post_inspection_entry_identity.map(FileIdentity::device))
                        .flatten(),
                    path_inode: parent_path_verified
                        .then(|| post_inspection_entry_identity.map(FileIdentity::inode))
                        .flatten(),
                    path_length: parent_path_verified
                        .then_some(post_inspection_entry_length)
                        .flatten(),
                    retained: false,
                });
                next_synthetic_id = next_synthetic_id.saturating_add(1);
            }
        }
    }
    (operation_artifacts, inventory_failure)
}

#[cfg(target_os = "macos")]
fn refresh_owned_file_identity(
    artifacts: &[OwnedArtifact],
    identity: FileIdentity,
) -> Option<(Option<u64>, Option<Sha256Digest>)> {
    let mut observed_length = None;
    for alias in artifacts.iter().filter(|artifact| {
        artifact.kind == OwnedArtifactKind::File && artifact.identity == Some(identity)
    }) {
        let Ok(mut file) = open_file_at(&alias.directory, &alias.name) else {
            continue;
        };
        if handle_identity(&file) != Some(identity) {
            continue;
        }
        let Some(length) = file.metadata().ok().map(|metadata| metadata.len()) else {
            continue;
        };
        observed_length = Some(length);
        if alias.length != Some(length) {
            continue;
        }
        if let Ok(evidence) = inspect_file_with_length_and_checkpoint(&mut file, length, || {})
            && evidence.identity == identity
        {
            return Some((Some(evidence.snapshot.len), Some(evidence.sha256)));
        }
    }
    observed_length.map(|length| (Some(length), None))
}

#[cfg(target_os = "macos")]
fn next_artifact_id(artifacts: &[OwnedArtifact]) -> u64 {
    artifacts
        .iter()
        .map(|artifact| artifact.id)
        .max()
        .unwrap_or(0)
        .saturating_add(1)
}

#[cfg(target_os = "macos")]
fn parent_artifact_id_for_path(
    artifacts: &[OwnedArtifact],
    path: &Path,
    identity: Option<FileIdentity>,
) -> Option<u64> {
    artifacts
        .iter()
        .find(|artifact| {
            artifact.kind == OwnedArtifactKind::Directory
                && artifact.path == path
                && artifact.identity == identity
        })
        .map(|artifact| artifact.id)
}

/// Holds the validated paths and staging evidence needed during publication.
#[cfg(target_os = "macos")]
struct PublicationContext<'a> {
    plan: &'a OperationPlan,
    source_directory: &'a File,
    destination_directory: &'a File,
    destination_artifact_directory: File,
    destination_lock: &'a DestinationLock,
    destination_parent_identity: FileIdentity,
    stage_directory: &'a File,
    workspace_runtime_identity: Option<FileIdentity>,
    stage_name: &'a OsStr,
    stage_identity: FileIdentity,
    staged: &'a FileEvidence,
    session: &'a OperationSession,
    backup_name: Option<&'a OsStr>,
    checkpoint: &'a mut dyn FnMut(ExecutionCheckpoint),
    milestones: &'a mut Vec<OperationMilestone>,
    artifacts: &'a mut Vec<OwnedArtifact>,
    cleanup_artifact_retained: &'a mut bool,
}

/// Immutable evidence and handles shared by both final pre-promotion checks.
#[cfg(target_os = "macos")]
struct PromotionValidation<'a> {
    plan: &'a OperationPlan,
    workspace_runtime_identity: Option<FileIdentity>,
    destination_directory: &'a File,
    destination_lock: &'a DestinationLock,
    destination_parent_identity: FileIdentity,
    stage_directory: &'a File,
    stage_name: &'a OsStr,
    stage_identity: FileIdentity,
    staged: &'a FileEvidence,
}

#[cfg(target_os = "macos")]
fn validate_promotion_operands(
    validation: &PromotionValidation<'_>,
) -> Result<(), OperationFailureCode> {
    let plan = validation.plan;
    let workspace_runtime_identity = validation.workspace_runtime_identity;
    let destination_directory = validation.destination_directory;
    let destination_lock = validation.destination_lock;
    let destination_parent_identity = validation.destination_parent_identity;
    let stage_directory = validation.stage_directory;
    let stage_name = validation.stage_name;
    let stage_identity = validation.stage_identity;
    let staged = validation.staged;
    validate_directory_route(&plan.workspace, workspace_runtime_identity)
        .map_err(|_| OperationFailureCode::StalePlan)?;

    let stage_directory_name = plan
        .stage_directory_name
        .as_deref()
        .ok_or(OperationFailureCode::StalePlan)?;
    let stage_directory_path = plan.workspace.path.join(stage_directory_name);
    let named_stage_directory = open_directory(&stage_directory_path)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    if handle_identity(&named_stage_directory) != handle_identity(stage_directory) {
        return Err(OperationFailureCode::ValidationFailed);
    }

    let current_stage = open_file_at(stage_directory, stage_name)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    let current_stage_length = current_stage
        .metadata()
        .map_err(|_| OperationFailureCode::ValidationFailed)?
        .len();
    if handle_identity(&current_stage) != Some(stage_identity)
        || current_stage_length != staged.snapshot.len
    {
        return Err(OperationFailureCode::ValidationFailed);
    }

    // Check the marker last so this path check is adjacent to the promotion syscall.
    validate_destination_lock(
        destination_lock,
        destination_directory,
        plan,
        destination_parent_identity,
    )
}

#[cfg(target_os = "macos")]
fn revalidate_before_promotion(
    validation: &PromotionValidation<'_>,
    source_directory: &File,
    checkpoint: &mut dyn FnMut(ExecutionCheckpoint),
) -> Result<(), OperationFailureCode> {
    let plan = validation.plan;
    let workspace_runtime_identity = validation.workspace_runtime_identity;
    let destination_directory = validation.destination_directory;
    let destination_lock = validation.destination_lock;
    let destination_parent_identity = validation.destination_parent_identity;
    let stage_directory = validation.stage_directory;
    let stage_name = validation.stage_name;
    let stage_identity = validation.stage_identity;
    let staged = validation.staged;
    validate_destination_lock(
        destination_lock,
        destination_directory,
        plan,
        destination_parent_identity,
    )?;
    validate_plan_routes(
        plan,
        workspace_runtime_identity,
        Some(destination_parent_identity),
    )?;
    verify_source_entry_with_checkpoint(plan, source_directory, || {
        checkpoint(ExecutionCheckpoint::FinalValidationHashChunk);
    })?;
    ensure_destination_baseline_with_checkpoint(plan, destination_directory, || {
        checkpoint(ExecutionCheckpoint::FinalValidationHashChunk);
    })?;

    let stage_directory_name = plan
        .stage_directory_name
        .as_deref()
        .ok_or(OperationFailureCode::StalePlan)?;
    let stage_directory_path = plan.workspace.path.join(stage_directory_name);
    let named_stage_directory = open_directory(&stage_directory_path)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    if handle_identity(&named_stage_directory) != handle_identity(stage_directory) {
        return Err(OperationFailureCode::ValidationFailed);
    }
    let mut current_stage = open_file_at(stage_directory, stage_name)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    let observed = inspect_file_with_checkpoint(&mut current_stage, || {
        checkpoint(ExecutionCheckpoint::FinalValidationHashChunk);
    })
    .map_err(|_| OperationFailureCode::ValidationFailed)?;
    if observed.identity != stage_identity
        || observed.snapshot.len != staged.snapshot.len
        || observed.sha256 != staged.sha256
        || observed != *staged
    {
        return Err(OperationFailureCode::ValidationFailed);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn record_published_destination(
    plan: &OperationPlan,
    destination_directory: File,
    stage_identity: FileIdentity,
    staged: &FileEvidence,
    artifacts: &mut Vec<OwnedArtifact>,
) -> Result<(), OperationFailureCode> {
    let observed_file = open_file_at(&destination_directory, &plan.destination.name).ok();
    let observed_length = observed_file
        .as_ref()
        .and_then(|file| file.metadata().ok())
        .map(|metadata| metadata.len());
    let observed_identity = observed_file.as_ref().and_then(handle_identity);
    let evidence = observed_file.as_ref().and_then(|file| {
        (observed_length == Some(staged.snapshot.len))
            .then(|| {
                let mut file = file.try_clone().ok()?;
                inspect_file_with_length_and_checkpoint(&mut file, staged.snapshot.len, || {}).ok()
            })
            .flatten()
    });
    let published = evidence.as_ref().is_some_and(|observed| {
        observed.identity == stage_identity
            && observed.snapshot.len == staged.snapshot.len
            && observed.sha256 == staged.sha256
    });
    let identity = evidence
        .as_ref()
        .map(|observed| observed.identity)
        .or(observed_identity);
    let length = evidence
        .as_ref()
        .map(|observed| observed.snapshot.len)
        .or(observed_length);
    let parent_identity = handle_identity(&destination_directory);
    if published
        && artifacts.iter().any(|artifact| {
            artifact.role == OperationArtifactRole::PublishedDestination
                && artifact.path == plan.destination.path
        })
    {
        return Ok(());
    }
    let id = next_artifact_id(artifacts);
    let parent_artifact_id =
        parent_artifact_id_for_path(artifacts, &plan.destination.parent, parent_identity);
    artifacts.push(OwnedArtifact {
        id,
        parent_artifact_id,
        relative_name: PathBuf::from(&plan.destination.name),
        parent_identity,
        directory: destination_directory,
        name: plan.destination.name.clone(),
        path: plan.destination.path.clone(),
        identity,
        kind: OwnedArtifactKind::File,
        role: if published {
            OperationArtifactRole::PublishedDestination
        } else {
            OperationArtifactRole::UncertainEntry
        },
        length,
        sha256: evidence.as_ref().map(|observed| observed.sha256),
        path_identity: identity,
        path_length: length,
        keep: true,
    });
    if published {
        Ok(())
    } else {
        Err(OperationFailureCode::PublicationUncertain)
    }
}

#[cfg(target_os = "macos")]
fn register_published_destination(
    plan: &OperationPlan,
    directory: File,
    stage_identity: FileIdentity,
    staged: &FileEvidence,
    artifacts: &mut Vec<OwnedArtifact>,
) {
    let parent_identity = handle_identity(&directory);
    let id = next_artifact_id(artifacts);
    let parent_artifact_id =
        parent_artifact_id_for_path(artifacts, &plan.destination.parent, parent_identity);
    artifacts.push(OwnedArtifact {
        id,
        parent_artifact_id,
        relative_name: PathBuf::from(&plan.destination.name),
        parent_identity,
        directory,
        name: plan.destination.name.clone(),
        path: plan.destination.path.clone(),
        identity: Some(stage_identity),
        kind: OwnedArtifactKind::File,
        role: OperationArtifactRole::PublishedDestination,
        length: Some(staged.snapshot.len),
        sha256: Some(staged.sha256),
        path_identity: Some(stage_identity),
        path_length: Some(staged.snapshot.len),
        keep: true,
    });
}

#[cfg(target_os = "macos")]
fn recovery_output_artifact(
    plan: &OperationPlan,
    stage_directory: &File,
    name: &OsStr,
    identity: FileIdentity,
    staged: &FileEvidence,
    artifacts: &[OwnedArtifact],
) -> Result<OwnedArtifact, OperationFailureCode> {
    let directory = stage_directory
        .try_clone()
        .map_err(|_| OperationFailureCode::WriteFailed)?;
    let parent_identity =
        handle_identity(stage_directory).ok_or(OperationFailureCode::UnsupportedCapability)?;
    let stage_directory_name = plan
        .stage_directory_name
        .as_deref()
        .ok_or(OperationFailureCode::StalePlan)?;
    let path = plan.workspace.path.join(stage_directory_name).join(name);
    Ok(OwnedArtifact {
        id: next_artifact_id(artifacts),
        parent_artifact_id: parent_artifact_id_for_path(
            artifacts,
            path.parent().ok_or(OperationFailureCode::UnsafePath)?,
            Some(parent_identity),
        ),
        relative_name: PathBuf::from(name),
        parent_identity: Some(parent_identity),
        directory,
        name: name.to_os_string(),
        path,
        identity: Some(identity),
        kind: OwnedArtifactKind::File,
        role: OperationArtifactRole::StagedOutput,
        length: Some(staged.snapshot.len),
        sha256: Some(staged.sha256),
        path_identity: Some(identity),
        path_length: Some(staged.snapshot.len),
        keep: true,
    })
}

#[cfg(target_os = "macos")]
struct DestinationCompetitorEvidence {
    identity: Option<FileIdentity>,
    length: Option<u64>,
    sha256: Option<Sha256Digest>,
    path_identity: Option<FileIdentity>,
    path_length: Option<u64>,
}

#[cfg(target_os = "macos")]
fn destination_competitor_artifact(
    plan: &OperationPlan,
    artifacts: &[OwnedArtifact],
    directory: File,
    parent_identity: FileIdentity,
    evidence: DestinationCompetitorEvidence,
) -> OwnedArtifact {
    let parent_artifact_id =
        parent_artifact_id_for_path(artifacts, &plan.destination.parent, Some(parent_identity));
    OwnedArtifact {
        id: next_artifact_id(artifacts),
        parent_artifact_id,
        relative_name: PathBuf::from(&plan.destination.name),
        parent_identity: Some(parent_identity),
        directory,
        name: plan.destination.name.clone(),
        path: plan.destination.path.clone(),
        identity: evidence.identity,
        kind: OwnedArtifactKind::File,
        role: OperationArtifactRole::UncertainEntry,
        length: evidence.length,
        sha256: evidence.sha256,
        path_identity: evidence.path_identity,
        path_length: evidence.path_length,
        keep: true,
    }
}

#[cfg(target_os = "macos")]
struct CapturedDestinationCompetitor {
    artifact: OwnedArtifact,
    evidence_verified: bool,
}

#[cfg(target_os = "macos")]
fn capture_current_destination_competitor(
    plan: &OperationPlan,
    destination_parent_identity: Option<FileIdentity>,
    artifacts: &[OwnedArtifact],
    _checkpoint: &mut dyn FnMut(ExecutionCheckpoint),
) -> Result<Option<CapturedDestinationCompetitor>, OperationFailureCode> {
    let Some(destination_parent_identity) = destination_parent_identity else {
        return Ok(None);
    };
    let directory = open_destination_parent_on_current_route(plan, destination_parent_identity)
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    let parent_identity =
        handle_identity(&directory).ok_or(OperationFailureCode::UnsupportedCapability)?;
    let artifact_directory = directory
        .try_clone()
        .map_err(|_| OperationFailureCode::PublicationUncertain)?;
    #[cfg(test)]
    _checkpoint(ExecutionCheckpoint::DestinationCompetitorBeforeOpen);
    let mut file = match open_file_at(&directory, &plan.destination.name) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // EEXIST proved a competitor existed; retain path-only uncertainty without inventing bytes.
            return Ok(Some(CapturedDestinationCompetitor {
                artifact: destination_competitor_artifact(
                    plan,
                    artifacts,
                    artifact_directory,
                    parent_identity,
                    DestinationCompetitorEvidence {
                        identity: None,
                        length: None,
                        sha256: None,
                        path_identity: None,
                        path_length: None,
                    },
                ),
                evidence_verified: false,
            }));
        }
        Err(_) => {
            return Ok(Some(CapturedDestinationCompetitor {
                artifact: destination_competitor_artifact(
                    plan,
                    artifacts,
                    artifact_directory,
                    parent_identity,
                    DestinationCompetitorEvidence {
                        identity: None,
                        length: None,
                        sha256: None,
                        path_identity: None,
                        path_length: None,
                    },
                ),
                evidence_verified: false,
            }));
        }
    };
    let identity = handle_identity(&file);
    let length = file.metadata().ok().map(|metadata| metadata.len());
    let mut first_evidence = match (identity, length) {
        (Some(_), Some(length)) => {
            inspect_file_with_length_and_checkpoint(&mut file, length, || {}).ok()
        }
        _ => None,
    };
    #[cfg(test)]
    _checkpoint(ExecutionCheckpoint::DestinationCompetitorFirstRead);

    let mut evidence_verified = false;
    if let (Some(expected_identity), Some(expected_length), Some(expected)) =
        (identity, length, first_evidence.as_ref())
    {
        let second = open_file_at(&directory, &plan.destination.name).and_then(|mut second| {
            if handle_identity(&second) != Some(expected_identity) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "destination identity changed after first inspection",
                ));
            }
            let second =
                inspect_file_with_length_and_checkpoint(&mut second, expected_length, || {})
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "destination content could not be revalidated",
                        )
                    })?;
            if second != *expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "destination content changed after first inspection",
                ));
            }
            let final_entry = open_file_at(&directory, &plan.destination.name)?;
            if handle_identity(&final_entry) != Some(expected_identity)
                || final_entry.metadata()?.len() != expected_length
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "destination entry changed after content inspection",
                ));
            }
            Ok(())
        });
        evidence_verified = second.is_ok();
    }

    let recorded = if evidence_verified {
        first_evidence.take()
    } else {
        None
    };
    let artifact = destination_competitor_artifact(
        plan,
        artifacts,
        artifact_directory,
        parent_identity,
        DestinationCompetitorEvidence {
            identity,
            length,
            sha256: recorded.as_ref().map(|evidence| evidence.sha256),
            path_identity: if evidence_verified { identity } else { None },
            path_length: if evidence_verified { length } else { None },
        },
    );
    Ok(Some(CapturedDestinationCompetitor {
        artifact,
        evidence_verified,
    }))
}

#[cfg(target_os = "macos")]
struct DestinationLock {
    _file: File,
    marker_name: OsString,
    marker_identity: FileIdentity,
    parent_identity: FileIdentity,
    parent_path: PathBuf,
}

#[cfg(target_os = "macos")]
impl Drop for DestinationLock {
    fn drop(&mut self) {
        while let Err(error) = fs2::FileExt::unlock(&self._file) {
            if error.kind() != io::ErrorKind::Interrupted {
                break;
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn publish_new(context: PublicationContext<'_>) -> Result<OperationOutcome, OperationFailureCode> {
    let PublicationContext {
        plan,
        source_directory,
        destination_directory,
        destination_artifact_directory,
        destination_lock,
        destination_parent_identity,
        stage_directory,
        workspace_runtime_identity,
        stage_name,
        stage_identity,
        staged,
        session,
        backup_name: _,
        checkpoint,
        milestones,
        artifacts,
        cleanup_artifact_retained,
    } = context;
    ensure_destination_baseline_with_checkpoint(plan, destination_directory, || {
        checkpoint(ExecutionCheckpoint::FinalValidationHashChunk);
    })?;
    let mut current_stage = open_file_at(stage_directory, stage_name)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    verify_file_evidence_with_checkpoint(&mut current_stage, staged, || {
        checkpoint(ExecutionCheckpoint::FinalValidationHashChunk);
    })
    .map_err(|_| OperationFailureCode::ValidationFailed)?;
    checkpoint(ExecutionCheckpoint::AfterFinalDestinationValidation);
    check_cancelled(session)?;
    verify_source_entry_with_checkpoint(plan, source_directory, || {
        checkpoint(ExecutionCheckpoint::FinalValidationHashChunk);
    })?;
    checkpoint(ExecutionCheckpoint::AfterFinalSourceValidation);
    validate_destination_lock(
        destination_lock,
        destination_directory,
        plan,
        destination_parent_identity,
    )?;
    let publication_inventory_directory = destination_artifact_directory
        .try_clone()
        .map_err(|_| OperationFailureCode::PublicationFailed)?;
    checkpoint(ExecutionCheckpoint::BeforeAtomicPromotion);
    let promotion = PromotionValidation {
        plan,
        workspace_runtime_identity,
        destination_directory,
        destination_lock,
        destination_parent_identity,
        stage_directory,
        stage_name,
        stage_identity,
        staged,
    };
    revalidate_before_promotion(&promotion, source_directory, checkpoint)?;
    if !session
        .begin_promotion()
        .map_err(|_| OperationFailureCode::SessionUnavailable)?
    {
        return Err(OperationFailureCode::Cancelled);
    }
    checkpoint(ExecutionCheckpoint::AtomicPromotionStarted);
    if let Err(failure) = validate_promotion_operands(&promotion) {
        return Err(match session.finish_promotion() {
            Ok(()) => failure,
            Err(session_failure) => session_failure,
        });
    }
    let link_result = hard_link_at(
        stage_directory,
        stage_name,
        destination_directory,
        &plan.destination.name,
    );
    if link_result.is_ok() {
        milestones.push(OperationMilestone::Published);
        session.record_milestone(OperationMilestone::Published);
        register_published_destination(
            plan,
            publication_inventory_directory,
            stage_identity,
            staged,
            artifacts,
        );
    }
    if session.finish_promotion().is_err() {
        return Err(if link_result.is_ok() {
            OperationFailureCode::PublicationUncertain
        } else {
            OperationFailureCode::SessionUnavailable
        });
    }
    if let Err(error) = link_result {
        if let Some(code) = no_clobber_link_error_code(&error) {
            return Err(code);
        }
        let destination_exists = inspect_destination(destination_directory, &plan.destination.name)
            .ok()
            .flatten()
            .is_some();
        return Err(no_clobber_link_failure(&error, destination_exists));
    }
    checkpoint(ExecutionCheckpoint::AfterNoClobberLinkBeforeEvidence);
    if record_published_destination(
        plan,
        destination_artifact_directory,
        stage_identity,
        staged,
        artifacts,
    )
    .is_err()
    {
        mark_artifact_retained(artifacts, stage_name);
        *cleanup_artifact_retained = true;
        return Err(OperationFailureCode::PublicationUncertain);
    }
    checkpoint(ExecutionCheckpoint::AfterPromotion);
    let validation = validate_published_file(
        destination_directory,
        &plan.destination.name,
        stage_identity,
        staged,
    );
    if validation.is_err() {
        mark_artifact_retained(artifacts, stage_name);
        *cleanup_artifact_retained = true;
        return Err(OperationFailureCode::PublicationUncertain);
    }
    if verify_source_entry(plan, source_directory).is_err() {
        mark_artifact_retained(artifacts, stage_name);
        *cleanup_artifact_retained = true;
        return Err(OperationFailureCode::PublicationUncertain);
    }
    if validate_published_file(
        destination_directory,
        &plan.destination.name,
        stage_identity,
        staged,
    )
    .is_err()
    {
        mark_artifact_retained(artifacts, stage_name);
        *cleanup_artifact_retained = true;
        return Err(OperationFailureCode::PublicationUncertain);
    }
    if verify_source_entry(plan, source_directory).is_err() {
        mark_artifact_retained(artifacts, stage_name);
        *cleanup_artifact_retained = true;
        return Err(OperationFailureCode::PublicationUncertain);
    }
    if verify_published_destination_on_current_route(
        plan,
        destination_parent_identity,
        stage_identity,
        staged,
    )
    .is_err()
    {
        mark_artifact_retained(artifacts, stage_name);
        *cleanup_artifact_retained = true;
        return Err(OperationFailureCode::PublicationUncertain);
    }
    Ok(OperationOutcome::Copied)
}

#[cfg(target_os = "macos")]
fn publish_replacement(
    context: PublicationContext<'_>,
) -> Result<OperationOutcome, OperationFailureCode> {
    let PublicationContext {
        plan,
        source_directory,
        destination_directory,
        destination_artifact_directory,
        destination_lock,
        destination_parent_identity,
        stage_directory,
        workspace_runtime_identity,
        stage_name,
        stage_identity,
        staged,
        session,
        backup_name,
        checkpoint,
        milestones,
        artifacts,
        cleanup_artifact_retained,
    } = context;
    let recovery_name = plan
        .published_recovery_name
        .as_deref()
        .ok_or(OperationFailureCode::StalePlan)?;
    let recovery_artifact = recovery_output_artifact(
        plan,
        stage_directory,
        recovery_name,
        stage_identity,
        staged,
        artifacts,
    )?;
    hard_link_at(stage_directory, stage_name, stage_directory, recovery_name)
        .map_err(|_| OperationFailureCode::PublicationFailed)?;
    artifacts.push(recovery_artifact);
    *cleanup_artifact_retained = true;
    let mut stage_after_recovery = open_file_at(stage_directory, stage_name)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    let stage_after_recovery = inspect_file(&mut stage_after_recovery)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    if stage_after_recovery.identity != stage_identity
        || stage_after_recovery.snapshot.len != staged.snapshot.len
        || stage_after_recovery.sha256 != staged.sha256
    {
        return Err(OperationFailureCode::ValidationFailed);
    }
    let staged = &stage_after_recovery;
    let expected_destination = plan
        .destination_baseline
        .as_ref()
        .ok_or(OperationFailureCode::UnsupportedCapability)?;
    qualify_rename_swap(destination_directory)?;
    ensure_destination_baseline_with_checkpoint(plan, destination_directory, || {
        checkpoint(ExecutionCheckpoint::FinalValidationHashChunk);
    })?;
    let mut current_stage = open_file_at(stage_directory, stage_name)
        .map_err(|_| OperationFailureCode::ValidationFailed)?;
    verify_file_evidence_with_checkpoint(&mut current_stage, staged, || {
        checkpoint(ExecutionCheckpoint::FinalValidationHashChunk);
    })
    .map_err(|_| OperationFailureCode::ValidationFailed)?;
    checkpoint(ExecutionCheckpoint::AfterFinalDestinationValidation);
    check_cancelled(session)?;
    verify_source_entry_with_checkpoint(plan, source_directory, || {
        checkpoint(ExecutionCheckpoint::FinalValidationHashChunk);
    })?;
    checkpoint(ExecutionCheckpoint::AfterFinalSourceValidation);
    validate_destination_lock(
        destination_lock,
        destination_directory,
        plan,
        destination_parent_identity,
    )?;
    let publication_inventory_directory = destination_artifact_directory
        .try_clone()
        .map_err(|_| OperationFailureCode::PublicationFailed)?;
    checkpoint(ExecutionCheckpoint::BeforeAtomicPromotion);
    let promotion = PromotionValidation {
        plan,
        workspace_runtime_identity,
        destination_directory,
        destination_lock,
        destination_parent_identity,
        stage_directory,
        stage_name,
        stage_identity,
        staged,
    };
    revalidate_before_promotion(&promotion, source_directory, checkpoint)?;
    if !session
        .begin_promotion()
        .map_err(|_| OperationFailureCode::SessionUnavailable)?
    {
        return Err(OperationFailureCode::Cancelled);
    }
    checkpoint(ExecutionCheckpoint::AtomicPromotionStarted);
    if let Err(failure) = validate_promotion_operands(&promotion) {
        return Err(match session.finish_promotion() {
            Ok(()) => failure,
            Err(session_failure) => session_failure,
        });
    }
    let swap_result = rename_swap_at(
        stage_directory,
        stage_name,
        destination_directory,
        &plan.destination.name,
    );
    if swap_result.is_ok() {
        milestones.push(OperationMilestone::Published);
        session.record_milestone(OperationMilestone::Published);
        register_published_destination(
            plan,
            publication_inventory_directory,
            stage_identity,
            staged,
            artifacts,
        );
    }
    if session.finish_promotion().is_err() {
        return Err(if swap_result.is_ok() {
            OperationFailureCode::PublicationUncertain
        } else {
            OperationFailureCode::SessionUnavailable
        });
    }
    swap_result.map_err(|error| {
        if ensure_destination_baseline(plan, destination_directory).is_err() {
            OperationFailureCode::DestinationChanged
        } else if is_unsupported_rename_error(&error) || is_unsupported_capability_error(&error) {
            OperationFailureCode::UnsupportedCapability
        } else {
            OperationFailureCode::PublicationFailed
        }
    })?;

    if record_published_destination(
        plan,
        destination_artifact_directory,
        stage_identity,
        staged,
        artifacts,
    )
    .is_err()
    {
        mark_artifact_retained(artifacts, stage_name);
        *cleanup_artifact_retained = true;
        return Err(OperationFailureCode::PublicationUncertain);
    }

    if let Some(backup_name) = backup_name {
        mark_artifact_retained(artifacts, backup_name);
        *cleanup_artifact_retained = true;
    }

    checkpoint(ExecutionCheckpoint::AfterPromotion);

    let mut displaced = match open_file_at(stage_directory, stage_name) {
        Ok(file) => file,
        Err(_) => {
            mark_artifact_retained(artifacts, stage_name);
            set_artifact_unverified(artifacts, stage_name);
            *cleanup_artifact_retained = true;
            return Err(OperationFailureCode::PublicationUncertain);
        }
    };
    let displaced_evidence = match inspect_file(&mut displaced) {
        Ok(evidence) => evidence,
        Err(_) => {
            mark_artifact_retained(artifacts, stage_name);
            set_artifact_unverified(artifacts, stage_name);
            *cleanup_artifact_retained = true;
            return Err(OperationFailureCode::PublicationUncertain);
        }
    };
    update_artifact_evidence(
        artifacts,
        stage_name,
        Some(displaced_evidence.identity),
        OperationArtifactRole::DisplacedDestination,
        Some(displaced_evidence.snapshot.len),
        Some(displaced_evidence.sha256),
    );
    let mut destination_changed = false;
    if displaced_evidence.identity != expected_destination.identity
        || displaced_evidence.snapshot.len != expected_destination.snapshot.len
        || displaced_evidence.sha256 != expected_destination.sha256
    {
        mark_artifact_retained(artifacts, stage_name);
        *cleanup_artifact_retained = true;
        destination_changed = true;
    }
    checkpoint(ExecutionCheckpoint::AfterDisplacedEntryValidation);
    let mut current_displaced = match open_file_at(stage_directory, stage_name) {
        Ok(file) => file,
        Err(_) => {
            mark_artifact_retained(artifacts, stage_name);
            set_artifact_unverified(artifacts, stage_name);
            *cleanup_artifact_retained = true;
            return Err(OperationFailureCode::PublicationUncertain);
        }
    };
    let current_displaced_evidence = match inspect_file(&mut current_displaced) {
        Ok(evidence) => evidence,
        Err(_) => {
            mark_artifact_retained(artifacts, stage_name);
            set_artifact_unverified(artifacts, stage_name);
            *cleanup_artifact_retained = true;
            return Err(OperationFailureCode::PublicationUncertain);
        }
    };
    if current_displaced_evidence.identity == displaced_evidence.identity {
        // Same-inode content changes refresh evidence. A different identity at
        // this pathname is an unrelated current-path object, not the displaced
        // destination, so preserve the original recorded identity.
        update_artifact_evidence(
            artifacts,
            stage_name,
            Some(current_displaced_evidence.identity),
            OperationArtifactRole::DisplacedDestination,
            Some(current_displaced_evidence.snapshot.len),
            Some(current_displaced_evidence.sha256),
        );
    }
    if current_displaced_evidence != displaced_evidence {
        mark_artifact_retained(artifacts, stage_name);
        *cleanup_artifact_retained = true;
        destination_changed = true;
    }
    if validate_published_file(
        destination_directory,
        &plan.destination.name,
        stage_identity,
        staged,
    )
    .is_err()
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    if verify_source_entry(plan, source_directory).is_err() {
        mark_artifact_retained(artifacts, stage_name);
        *cleanup_artifact_retained = true;
        return Err(OperationFailureCode::PublicationUncertain);
    }
    if validate_published_file(
        destination_directory,
        &plan.destination.name,
        stage_identity,
        staged,
    )
    .is_err()
    {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    if verify_source_entry(plan, source_directory).is_err() {
        mark_artifact_retained(artifacts, stage_name);
        *cleanup_artifact_retained = true;
        return Err(OperationFailureCode::PublicationUncertain);
    }
    if verify_published_destination_on_current_route(
        plan,
        destination_parent_identity,
        stage_identity,
        staged,
    )
    .is_err()
    {
        mark_artifact_retained(artifacts, stage_name);
        *cleanup_artifact_retained = true;
        return Err(OperationFailureCode::PublicationUncertain);
    }

    if destination_changed {
        return Err(OperationFailureCode::DestinationChanged);
    }
    Ok(OperationOutcome::Copied)
}

#[cfg(target_os = "macos")]
fn update_artifact_evidence(
    artifacts: &mut [OwnedArtifact],
    name: &OsStr,
    identity: Option<FileIdentity>,
    role: OperationArtifactRole,
    length: Option<u64>,
    sha256: Option<Sha256Digest>,
) {
    if let Some(artifact) = artifacts.iter_mut().find(|artifact| artifact.name == name) {
        artifact.identity = identity;
        artifact.role = role;
        artifact.length = length;
        artifact.sha256 = sha256;
    }
}

#[cfg(target_os = "macos")]
fn set_artifact_unverified(artifacts: &mut [OwnedArtifact], name: &OsStr) {
    update_artifact_evidence(
        artifacts,
        name,
        None,
        OperationArtifactRole::UncertainEntry,
        None,
        None,
    );
}

#[cfg(target_os = "macos")]
fn is_unsupported_capability_error(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::Unsupported
        || error.raw_os_error().is_some_and(|code| {
            code == libc::ENOSYS || code == libc::ENOTSUP || code == libc::EOPNOTSUPP
        })
}

#[cfg(target_os = "macos")]
fn is_unsupported_filesystem_path_operation_error(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EXDEV) || is_unsupported_capability_error(error)
}

#[cfg(target_os = "macos")]
fn destination_lock_failure(error: &io::Error) -> OperationFailureCode {
    if is_unsupported_capability_error(error) {
        OperationFailureCode::UnsupportedCapability
    } else {
        OperationFailureCode::DestinationUnavailable
    }
}

#[cfg(target_os = "macos")]
fn no_clobber_link_failure(error: &io::Error, destination_exists: bool) -> OperationFailureCode {
    if let Some(code) = no_clobber_link_error_code(error) {
        code
    } else if destination_exists {
        OperationFailureCode::DestinationChanged
    } else {
        OperationFailureCode::PublicationFailed
    }
}

#[cfg(target_os = "macos")]
fn no_clobber_link_error_code(error: &io::Error) -> Option<OperationFailureCode> {
    if error.kind() == io::ErrorKind::AlreadyExists {
        Some(OperationFailureCode::DestinationChanged)
    } else if is_unsupported_filesystem_path_operation_error(error) {
        Some(OperationFailureCode::UnsupportedCapability)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn is_unsupported_rename_error(error: &io::Error) -> bool {
    is_unsupported_filesystem_path_operation_error(error)
}

#[cfg(target_os = "macos")]
fn verify_source_entry(
    plan: &OperationPlan,
    source_directory: &File,
) -> Result<(), OperationFailureCode> {
    verify_source_entry_with_checkpoint(plan, source_directory, || {})
}

#[cfg(target_os = "macos")]
fn verify_source_entry_with_checkpoint(
    plan: &OperationPlan,
    source_directory: &File,
    checkpoint: impl FnMut(),
) -> Result<(), OperationFailureCode> {
    validate_file_route(&plan.source, None).map_err(|_| OperationFailureCode::StalePlan)?;
    let mut source = open_file_at(source_directory, &plan.source.name)
        .map_err(|_| OperationFailureCode::SourceChanged)?;
    verify_file_evidence_with_checkpoint(&mut source, &plan.source_baseline, checkpoint)
        .map_err(|_| OperationFailureCode::SourceChanged)
}

#[cfg(target_os = "macos")]
fn validate_published_file(
    directory: &File,
    name: &OsStr,
    identity: FileIdentity,
    expected: &FileEvidence,
) -> Result<(), OperationFailureCode> {
    let mut file =
        open_file_at(directory, name).map_err(|_| OperationFailureCode::PublicationUncertain)?;
    if handle_identity(&file) != Some(identity) {
        return Err(OperationFailureCode::PublicationUncertain);
    }
    let observed =
        inspect_file(&mut file).map_err(|_| OperationFailureCode::PublicationUncertain)?;
    if same_file_identity_and_content(&observed, expected) {
        Ok(())
    } else {
        Err(OperationFailureCode::ValidationFailed)
    }
}

#[cfg(target_os = "macos")]
fn mark_artifact_retained(artifacts: &mut [OwnedArtifact], name: &OsStr) {
    if let Some(artifact) = artifacts.iter_mut().find(|artifact| artifact.name == name) {
        artifact.keep = true;
    }
}

#[cfg(all(test, target_os = "macos"))]
thread_local! {
    static TEST_COMPETITOR_INVENTORY_DUP_FAILURE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    // A single named open fails after mkdirat, without exhausting the process's
    // descriptors or affecting tests running on other threads.
    static TEST_DIRECTORY_OPEN_FAILURE: std::cell::RefCell<Option<OsString>> =
        const { std::cell::RefCell::new(None) };
    static TEST_ARTIFACT_NAME_QUEUE:
        std::cell::RefCell<std::collections::VecDeque<OsString>> =
        const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::mpsc;
    use std::time::Duration;
    use tempfile::TempDir;

    fn fixture() -> (TempDir, PathBuf, PathBuf, PathBuf) {
        let root = tempfile::tempdir().expect("create operation fixture");
        let source = root.path().join("source.bin");
        let destination = root.path().join("destination.bin");
        let workspace = root.path().join("workspace");
        fs::write(&source, b"operation test source bytes").expect("write source fixture");
        fs::create_dir(&workspace).expect("create workspace");
        (root, source, destination, workspace)
    }

    fn plan(source: &Path, destination: &Path, workspace: &Path) -> OperationPlan {
        plan_copy_through(CopyThroughRequest::new(source, destination, workspace))
            .expect("create operation plan")
    }

    /// Holds inherited descriptors until the parent signals the release socket.
    /// The fork child uses only async-signal-safe syscalls and never resumes Rust
    /// execution or destructors from the multithreaded test harness.
    struct InheritedDescriptorHolder {
        release: Option<std::os::unix::net::UnixStream>,
        child: libc::pid_t,
    }

    impl InheritedDescriptorHolder {
        fn new() -> Self {
            let (parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
            let parent_fd = parent.as_raw_fd();
            let child_fd = child.as_raw_fd();
            // SAFETY: the child only closes, reads, and exits via libc. It does
            // not touch locks, allocation, or Rust-owned resources after fork.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork descriptor holder");
            if pid == 0 {
                let mut byte = 0_u8;
                // SAFETY: the descriptors are valid inherited socket ends, and
                // byte is writable storage. _exit avoids inherited destructors.
                unsafe {
                    libc::close(parent_fd);
                    loop {
                        let count = libc::read(child_fd, (&mut byte as *mut u8).cast(), 1);
                        if count >= 0 || *libc::__error() != libc::EINTR {
                            break;
                        }
                    }
                    libc::_exit(0);
                }
            }
            drop(child);
            Self {
                release: Some(parent),
                child: pid,
            }
        }
    }

    impl Drop for InheritedDescriptorHolder {
        fn drop(&mut self) {
            if let Some(mut release) = self.release.take() {
                // An explicit byte also works when another concurrent fork
                // inherited a reference to the parent's socket endpoint.
                let _ = release.write_all(&[1]);
            }
            // SAFETY: this holder owns the child PID; no other code reaps it.
            while unsafe { libc::waitpid(self.child, std::ptr::null_mut(), 0) } < 0 {
                if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    break;
                }
            }
        }
    }

    fn assert_destination_lock_released_with_inherited_reference(retarget: bool) {
        let (root, source, destination, workspace) = fixture();
        let plan = plan(&source, &destination, &workspace);
        let marker = plan.snapshot().destination_lock_path().to_path_buf();
        let displaced = root.path().join("displaced-destination-marker");
        let mut holder = None;
        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::DestinationLockAcquired && holder.is_none() {
                    holder = Some(InheritedDescriptorHolder::new());
                    if retarget {
                        fs::rename(&marker, &displaced).unwrap();
                        fs::write(&marker, b"replacement marker").unwrap();
                    }
                }
            },
        );
        assert!(holder.is_some());
        if retarget {
            assert_eq!(
                result.failure().unwrap().code(),
                OperationFailureCode::StalePlan
            );
            assert!(!destination.exists());
        } else {
            assert_eq!(result.state(), JobState::Succeeded, "{result:?}");
        }
        let contender = File::open(if retarget { &displaced } else { &marker }).unwrap();
        let acquired = fs2::FileExt::try_lock_exclusive(&contender);
        drop(holder);
        acquired.expect("destination lock must release before the inherited reference closes");
        fs2::FileExt::unlock(&contender).unwrap();
    }

    #[test]
    fn destination_lock_release_does_not_wait_for_inherited_descriptor_close() {
        assert_destination_lock_released_with_inherited_reference(false);
    }

    #[test]
    fn destination_lock_validation_failure_releases_inherited_lock() {
        assert_destination_lock_released_with_inherited_reference(true);
    }

    #[test]
    fn competitor_inventory_descriptor_failure_does_not_leave_unreported_alias() {
        let (_root, source, destination, workspace) = fixture();
        let plan = plan(&source, &destination, &workspace);
        let temporary = workspace.join("competitor.tmp");
        let mut installed = false;
        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforeArtifactInventory && !installed {
                    installed = true;
                    fs::write(&temporary, b"late competitor").unwrap();
                    fs::rename(&temporary, &destination).unwrap();
                    TEST_COMPETITOR_INVENTORY_DUP_FAILURE.with(|failure| failure.set(true));
                }
            },
        );
        assert!(installed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert!(result.cleanup_artifact_retained());
        assert!(result.cleanup_warning().is_some());
        let mut checked = false;
        for artifact in result.artifacts() {
            if artifact.role() == OperationArtifactRole::PrivateStagingDirectory
                && artifact.path().exists()
            {
                checked = true;
                for entry in fs::read_dir(artifact.path()).unwrap() {
                    let path = entry.unwrap().path();
                    assert!(
                        result
                            .artifacts()
                            .iter()
                            .any(|record| record.path() == path),
                        "created alias is missing from terminal inventory: {}",
                        path.display()
                    );
                }
            }
        }
        assert!(checked, "inspect retained competitor directory");
        assert_eq!(fs::read(destination).unwrap(), b"late competitor");
    }

    fn stage_file_in(workspace: &Path) -> PathBuf {
        let stage_area = fs::read_dir(workspace)
            .expect("read operation workspace")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.is_dir()
                    && path
                        .file_name()
                        .is_some_and(|name| name.to_string_lossy().starts_with(".nscb-stage-area-"))
            })
            .expect("find private staging directory");
        fs::read_dir(stage_area)
            .expect("read private staging directory")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.is_file()
                    && path
                        .file_name()
                        .is_some_and(|name| name.to_string_lossy().starts_with(".nscb-stage-"))
            })
            .expect("find staging file")
    }

    fn retained_artifact(
        result: &OperationResult,
        role: OperationArtifactRole,
    ) -> &OperationArtifact {
        result
            .artifacts()
            .iter()
            .find(|artifact| artifact.role() == role)
            .unwrap_or_else(|| {
                panic!(
                    "missing retained {role:?} artifact: {:?}",
                    result.artifacts()
                )
            })
    }

    fn destination_competitor<'a>(
        result: &'a OperationResult,
        path: &Path,
    ) -> &'a OperationArtifact {
        result
            .artifacts()
            .iter()
            .find(|artifact| {
                artifact.role() == OperationArtifactRole::UncertainEntry
                    && artifact.path() == path
                    && artifact.retained()
            })
            .unwrap_or_else(|| {
                panic!(
                    "missing retained destination competitor {path:?}: {:?}",
                    result.artifacts()
                )
            })
    }

    fn assert_cleanup_incomplete(result: &OperationResult) {
        assert!(result.cleanup_artifact_retained(), "{result:?}");
        assert_eq!(
            result.cleanup_warning().map(|warning| warning.code()),
            Some(OperationFailureCode::CleanupIncomplete),
            "{result:?}"
        );
        assert!(!result.artifacts().is_empty(), "{result:?}");

        for artifact in result.artifacts() {
            if !artifact.retained() {
                // A live destination observation is reported without claiming ownership.
                assert_eq!(
                    artifact.role(),
                    OperationArtifactRole::UncertainEntry,
                    "{artifact:?}"
                );
            }
            assert!(artifact.path().is_absolute(), "{artifact:?}");
            if artifact.parent_identity_matches() != Some(true) {
                assert_eq!(artifact.path_identity_matches(), None, "{artifact:?}");
                continue;
            }
            let metadata = fs::symlink_metadata(artifact.path())
                .unwrap_or_else(|error| panic!("missing reported artifact {artifact:?}: {error}"));
            let handle = if metadata.is_dir() {
                open_directory(artifact.path()).expect("open reported artifact directory")
            } else {
                File::open(artifact.path()).expect("open reported artifact file")
            };
            let current = handle_identity(&handle).expect("read current path identity");
            assert_eq!(
                artifact.path_device(),
                Some(current.device()),
                "{artifact:?}"
            );
            assert_eq!(artifact.path_inode(), Some(current.inode()), "{artifact:?}");

            match artifact.path_identity_matches() {
                Some(true) => {
                    assert_eq!(artifact.device(), Some(current.device()), "{artifact:?}");
                    assert_eq!(artifact.inode(), Some(current.inode()), "{artifact:?}");
                    if let (false, Some(length), Some(digest)) =
                        (metadata.is_dir(), artifact.length(), artifact.sha256())
                    {
                        let bytes = fs::read(artifact.path()).expect("read reported artifact");
                        assert_eq!(bytes.len() as u64, length, "{artifact:?}");
                        assert_eq!(Sha256Digest::digest(&bytes), digest, "{artifact:?}");
                    }
                }
                Some(false) => {
                    assert_ne!(
                        artifact.device().zip(artifact.inode()),
                        Some((current.device(), current.inode())),
                        "{artifact:?}"
                    );
                    assert_eq!(artifact.path_length(), Some(metadata.len()), "{artifact:?}");
                }
                None => assert!(artifact.device().is_none() || artifact.inode().is_none()),
            }
        }
    }

    fn contains_file_with_bytes(directory: &Path, expected: &[u8]) -> bool {
        fs::read_dir(directory)
            .expect("read artifact directory")
            .filter_map(Result::ok)
            .any(|entry| {
                let path = entry.path();
                if path.is_dir() {
                    contains_file_with_bytes(&path, expected)
                } else {
                    fs::read(path).is_ok_and(|bytes| bytes.as_slice() == expected)
                }
            })
    }

    #[test]
    fn bounded_copy_rejects_source_truncation_after_planning() {
        let root = tempfile::tempdir().expect("create bounded-copy fixture");
        let source_path = root.path().join("source.bin");
        let stage_path = root.path().join("stage.bin");
        fs::write(&source_path, b"planned").expect("write planned source");
        let mut source = File::open(&source_path).expect("open planned source");
        let mut stage = File::create(&stage_path).expect("create stage");
        fs::write(&source_path, b"short").expect("truncate source after planning");

        let result =
            copy_source_to_stage_with_length(&mut source, &mut stage, 7, &OperationSession::new());

        assert_eq!(result, Err(OperationFailureCode::SourceChanged));
        assert_eq!(fs::read(&stage_path).unwrap(), b"short");
    }

    #[test]
    fn bounded_copy_rejects_source_growth_without_staging_extra_bytes() {
        let root = tempfile::tempdir().expect("create bounded-copy fixture");
        let source_path = root.path().join("source.bin");
        let stage_path = root.path().join("stage.bin");
        fs::write(&source_path, b"base").expect("write planned source");
        let mut source = File::open(&source_path).expect("open planned source");
        let mut stage = File::create(&stage_path).expect("create stage");
        OpenOptions::new()
            .append(true)
            .open(&source_path)
            .expect("open source for growth")
            .write_all(b"unbounded growth")
            .expect("grow source after planning");

        let result =
            copy_source_to_stage_with_length(&mut source, &mut stage, 4, &OperationSession::new());

        assert_eq!(result, Err(OperationFailureCode::SourceChanged));
        assert_eq!(fs::read(&stage_path).unwrap(), b"base");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn failed_producer_output_is_still_checked_against_planned_length_and_digest() {
        let (_root, source, destination, workspace) = fixture();
        let operation_plan = plan(&source, &destination, &workspace);

        let result =
            execute_with_producer(operation_plan, &OperationSession::new(), |_, stage, _| {
                stage.write_all(b"invalid partial output").unwrap();
                Err(OperationFailureCode::WriteFailed)
            });

        assert_eq!(result.state(), JobState::Failed, "{result:?}");
        assert_eq!(
            result.failure().map(OperationFailure::code),
            Some(OperationFailureCode::ValidationFailed),
            "{result:?}"
        );
        assert!(!destination.exists());
    }

    #[test]
    fn source_evidence_hash_bounds_growth_to_one_probe_byte() {
        let root = tempfile::tempdir().expect("create bounded-hash fixture");
        let source_path = root.path().join("source.bin");
        fs::write(&source_path, b"base").expect("write planned source");
        let mut source = File::open(&source_path).expect("open source evidence");
        let mut grew = false;

        let result = inspect_file_with_checkpoint(&mut source, || {
            if !grew {
                grew = true;
                OpenOptions::new()
                    .append(true)
                    .open(&source_path)
                    .expect("open source for concurrent growth")
                    .write_all(&vec![0x5a; 2 * 1024 * 1024])
                    .expect("grow source during evidence hashing");
            }
        });

        assert_eq!(result, Err(OperationFailureCode::SourceChanged));
        assert!(grew);
        assert_eq!(source.stream_position().unwrap(), 5);
    }

    #[test]
    fn storage_capacity_reserves_source_backup_and_safety_margin() {
        assert_eq!(MINIMUM_FREE_SPACE_RESERVE, 64 * 1024 * 1024);
        assert_eq!(required_storage_bytes(8, Some(4), 16), Ok(28));
        assert_eq!(ensure_storage_capacity(28, 8, Some(4), 16), Ok(()));
        assert_eq!(
            ensure_storage_capacity(27, 8, Some(4), 16),
            Err(OperationFailureCode::InsufficientStorage)
        );
        assert_eq!(
            required_storage_bytes(u64::MAX, Some(1), 1),
            Err(OperationFailureCode::InsufficientStorage)
        );
    }

    #[test]
    fn cross_filesystem_host_workspace_selects_destination_local_fallback() {
        assert_eq!(
            select_staging_strategy(WorkspaceSelection::HostDefault, false),
            Ok(StagingStrategy::DestinationLocalFallback)
        );
        assert_eq!(
            select_staging_strategy(WorkspaceSelection::HostDefault, true),
            Ok(StagingStrategy::HostWorkspace)
        );
        assert_eq!(
            select_staging_strategy(WorkspaceSelection::Explicit, false),
            Err(OperationFailureCode::UnsupportedCapability)
        );
        assert_eq!(
            select_staging_strategy(WorkspaceSelection::Explicit, true),
            Ok(StagingStrategy::ExplicitWorkspace)
        );
    }

    #[test]
    fn destination_local_fallback_anchors_the_selected_parent_identity() {
        let root = tempfile::tempdir().expect("create destination-parent fixture");
        let destination_parent = root.path().canonicalize().expect("canonicalize parent");
        let parent = open_directory(&destination_parent).expect("open destination parent");
        let identity = required_identity(&parent).expect("identify destination parent");

        let workspace = destination_local_workspace(&destination_parent, identity);

        assert_eq!(workspace.requested, destination_parent);
        assert_eq!(workspace.path, destination_parent);
        assert_eq!(workspace.identity, Some(identity));
        assert!(workspace.creation_parent.is_none());
        assert!(workspace.creation_parent_identity.is_none());
    }

    #[test]
    fn selected_host_fallback_records_destination_workspace_and_identity() {
        let root = tempfile::tempdir().expect("create fallback-selection fixture");
        let destination_parent = root.path().canonicalize().expect("canonicalize parent");
        let destination_directory = open_directory(&destination_parent).expect("open parent");
        let destination_identity =
            required_identity(&destination_directory).expect("identify parent");
        let requested_path = destination_parent.join("host-cache");
        let requested_workspace = ResolvedDirectory {
            requested: requested_path.clone(),
            path: requested_path,
            identity: None,
            creation_parent: Some(destination_parent.clone()),
            creation_parent_identity: Some(destination_identity),
        };

        let (workspace, strategy) = select_staging_workspace(
            WorkspaceSelection::HostDefault,
            requested_workspace,
            false,
            &destination_parent,
            destination_identity,
        )
        .expect("select destination-local fallback");

        assert_eq!(strategy, StagingStrategy::DestinationLocalFallback);
        assert_eq!(workspace.path, destination_parent);
        assert_eq!(workspace.identity, Some(destination_identity));
        assert_eq!(
            workspace.identity.unwrap().fingerprint(),
            destination_identity.fingerprint()
        );
    }

    #[test]
    fn available_space_uses_the_open_workspace_directory_after_path_retarget() {
        let root = tempfile::tempdir().expect("create workspace capacity fixture");
        let workspace = root.path().join("workspace");
        let moved_workspace = root.path().join("workspace-opened-before-retarget");
        fs::create_dir(&workspace).expect("create original workspace");
        let opened_workspace = open_directory(&workspace).expect("open original workspace");
        let opened_identity = handle_identity(&opened_workspace).expect("identify open workspace");

        fs::rename(&workspace, &moved_workspace).expect("retarget the workspace path");
        fs::create_dir(&workspace).expect("create a different entry at the original path");
        let retargeted_identity = handle_identity(&open_directory(&workspace).unwrap())
            .expect("identify retargeted path");
        assert_ne!(opened_identity, retargeted_identity);

        assert!(available_space_on_open_directory(&opened_workspace).is_ok());
    }

    #[test]
    fn bounded_copy_stops_promptly_when_cancelled_between_chunks() {
        let root = tempfile::tempdir().expect("create bounded-copy fixture");
        let source_path = root.path().join("source.bin");
        let stage_path = root.path().join("stage.bin");
        fs::write(&source_path, vec![0x5a; IO_BUFFER_SIZE * 3]).expect("write large source");
        let mut source = File::open(&source_path).expect("open source");
        let mut stage = File::create(&stage_path).expect("create stage");
        let session = OperationSession::new();
        let _admission = session.admit().expect("admit test operation");
        let mut chunks = 0;

        let result = copy_source_to_stage_with_length_and_checkpoint(
            &mut source,
            &mut stage,
            (IO_BUFFER_SIZE * 3) as u64,
            &session,
            || {
                chunks += 1;
                session.cancel();
            },
        );

        assert_eq!(result, Err(OperationFailureCode::Cancelled));
        assert_eq!(chunks, 1);
        assert_eq!(
            fs::metadata(&stage_path).unwrap().len(),
            IO_BUFFER_SIZE as u64
        );
    }

    #[test]
    fn unsupported_advisory_lock_errors_map_to_unsupported_capability() {
        for error in [
            io::Error::from(io::ErrorKind::Unsupported),
            io::Error::from_raw_os_error(libc::ENOSYS),
            io::Error::from_raw_os_error(libc::ENOTSUP),
        ] {
            assert_eq!(
                destination_lock_failure(&error),
                OperationFailureCode::UnsupportedCapability
            );
        }
        assert_eq!(
            destination_lock_failure(&io::Error::from_raw_os_error(libc::EIO)),
            OperationFailureCode::DestinationUnavailable
        );
    }

    #[test]
    fn unsupported_no_clobber_link_errors_map_to_unsupported_capability() {
        for error in [
            io::Error::from(io::ErrorKind::Unsupported),
            io::Error::from_raw_os_error(libc::ENOSYS),
            io::Error::from_raw_os_error(libc::ENOTSUP),
            io::Error::from_raw_os_error(libc::EXDEV),
        ] {
            assert_eq!(
                no_clobber_link_failure(&error, false),
                OperationFailureCode::UnsupportedCapability
            );
        }
        assert_eq!(
            no_clobber_link_failure(&io::Error::from_raw_os_error(libc::EIO), false),
            OperationFailureCode::PublicationFailed
        );
    }

    #[test]
    fn linkat_eexist_is_destination_changed_when_entry_disappears_before_inspection() {
        let error = io::Error::from_raw_os_error(libc::EEXIST);
        let destination_exists_after_inspection = false;

        assert_eq!(
            no_clobber_link_error_code(&error),
            Some(OperationFailureCode::DestinationChanged)
        );
        assert_eq!(
            no_clobber_link_failure(&error, destination_exists_after_inspection),
            OperationFailureCode::DestinationChanged
        );
    }

    #[test]
    fn stage_name_equal_to_destination_never_exposes_partial_bytes() {
        let root = tempfile::tempdir().expect("create operation fixture");
        let source = root.path().join("source.bin");
        let destination = root.path().join("destination.bin");
        fs::write(&source, b"operation test source bytes").expect("write source fixture");
        let plan = plan(&source, &destination, root.path());
        let names = VecDeque::from([
            destination.file_name().unwrap().to_os_string(),
            OsString::from(".nscb-stage-safe-retry"),
        ]);

        TEST_ARTIFACT_NAME_QUEUE.with(|queue| {
            *queue.borrow_mut() = names;
        });

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            |_, stage, _| {
                stage
                    .write_all(b"incomplete stage bytes")
                    .map_err(|_| OperationFailureCode::WriteFailed)?;
                assert!(
                    !destination.exists(),
                    "partial staging bytes must never appear at the destination"
                );
                Err(OperationFailureCode::WriteFailed)
            },
            |_| {},
        );

        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(result.outcome(), None);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::ValidationFailed
        );
        assert!(!destination.exists());
    }

    #[test]
    fn artifact_names_include_a_random_collision_resistant_suffix() {
        let first = next_artifact_name("stage").expect("read system entropy");
        let second = next_artifact_name("stage").expect("read system entropy");
        let first_text = first.to_string_lossy();
        let nonce = first_text.rsplit('-').next().expect("find random suffix");

        assert_eq!(nonce.len(), 32);
        assert!(nonce.chars().all(|character| character.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }

    #[test]
    fn destination_inserted_before_promotion_is_not_overwritten() {
        let (_root, source, destination, workspace) = fixture();
        let competing_bytes = b"destination inserted after the final check";
        let mut inserted = false;

        let result = execute_with_producer_and_checkpoint(
            plan(&source, &destination, &workspace),
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforePromotion && !inserted {
                    fs::write(&destination, competing_bytes)
                        .expect("insert destination after lock-time validation");
                    inserted = true;
                }
            },
        );

        assert!(inserted);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(result.outcome(), None);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::DestinationChanged
        );
        assert_eq!(fs::read(destination).unwrap(), competing_bytes);
    }

    #[test]
    fn producer_with_corrupt_output_is_rejected_and_stage_is_reported_for_reconciliation() {
        let (_root, source, destination, workspace) = fixture();
        let plan = plan(&source, &destination, &workspace);

        let result = execute_with_producer(plan, &OperationSession::new(), |_, stage, _| {
            stage
                .write_all(b"producer reported success but wrote bad bytes")
                .map_err(|_| OperationFailureCode::WriteFailed)
        });

        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::ValidationFailed
        );
        assert_cleanup_incomplete(&result);
        let stage = retained_artifact(&result, OperationArtifactRole::StagedOutput);
        let corrupt_bytes = b"producer reported success but wrote bad bytes";
        assert_eq!(stage.length(), Some(corrupt_bytes.len() as u64));
        assert_eq!(stage.sha256(), Some(Sha256Digest::digest(corrupt_bytes)));
        assert_eq!(fs::read(stage.path()).unwrap(), corrupt_bytes);
        assert!(!destination.exists());
        assert_eq!(fs::read_dir(workspace).unwrap().count(), 1);
    }

    #[test]
    fn cleanup_keeps_an_unrelated_file_that_replaced_the_staging_entry() {
        let (_root, source, destination, workspace) = fixture();
        let plan = plan(&source, &destination, &workspace);

        let result = execute_with_producer(plan, &OperationSession::new(), |_, _, _| {
            let stage_path = stage_file_in(&workspace);
            fs::remove_file(&stage_path).expect("remove original staging entry");
            fs::write(&stage_path, b"unrelated replacement").expect("replace staging entry");
            Err(OperationFailureCode::WriteFailed)
        });

        assert_eq!(result.state(), JobState::Failed);
        assert_cleanup_incomplete(&result);
        let retained = stage_file_in(&workspace);
        assert_eq!(fs::read(&retained).unwrap(), b"unrelated replacement");
        let stage = retained_artifact(&result, OperationArtifactRole::StagedOutput);
        assert_eq!(
            stage.path().canonicalize().unwrap(),
            retained.canonicalize().unwrap()
        );
        assert_eq!(stage.path_identity_matches(), Some(false));
        assert_eq!(
            stage.path_length(),
            Some(b"unrelated replacement".len() as u64)
        );
        let stage = retained_artifact(&result, OperationArtifactRole::StagedOutput);
        assert_eq!(stage.path_identity_matches(), Some(false));
        assert_eq!(
            stage.path_length(),
            Some(b"unrelated replacement".len() as u64)
        );
        assert!(!destination.exists());
    }

    #[test]
    fn parent_directory_substitution_suppresses_child_absolute_path() {
        let (_root, _source, _destination, workspace) = fixture();
        let parent_name: OsString = ".nscb-private-stage-parent-race".into();
        let child_name: OsString = ".nscb-stage-child".into();
        let parent_path = workspace.join(&parent_name);
        let moved_parent_path = workspace.join("private-stage-before-swap");
        fs::create_dir(&parent_path).expect("create private parent directory");
        let workspace_directory = open_directory(&workspace).expect("open workspace");
        let workspace_identity = handle_identity(&workspace_directory).expect("workspace identity");
        let parent_directory = open_directory(&parent_path).expect("open private parent");
        let parent_identity = handle_identity(&parent_directory).expect("parent identity");
        let child_path = parent_path.join(&child_name);
        fs::write(&child_path, b"owned child bytes").expect("create child artifact");
        let child_file = open_file_at(&parent_directory, &child_name).expect("open child artifact");
        let child_identity = handle_identity(&child_file).expect("child identity");
        drop(child_file);

        let artifacts = vec![
            OwnedArtifact {
                id: 1,
                parent_artifact_id: None,
                relative_name: PathBuf::from(&parent_name),
                parent_identity: Some(workspace_identity),
                directory: workspace_directory,
                name: parent_name.clone(),
                path: parent_path.clone(),
                identity: Some(parent_identity),
                kind: OwnedArtifactKind::Directory,
                role: OperationArtifactRole::PrivateStagingDirectory,
                length: None,
                sha256: None,
                path_identity: Some(parent_identity),
                path_length: None,
                keep: true,
            },
            OwnedArtifact {
                id: 2,
                parent_artifact_id: Some(1),
                relative_name: PathBuf::from(&child_name),
                parent_identity: Some(parent_identity),
                directory: parent_directory,
                name: child_name.clone(),
                path: child_path.clone(),
                identity: Some(child_identity),
                kind: OwnedArtifactKind::File,
                role: OperationArtifactRole::StagedOutput,
                length: Some(b"owned child bytes".len() as u64),
                sha256: Some(Sha256Digest::digest(b"owned child bytes")),
                path_identity: Some(child_identity),
                path_length: Some(b"owned child bytes".len() as u64),
                keep: true,
            },
        ];

        fs::rename(&parent_path, &moved_parent_path).expect("move private parent directory");
        fs::create_dir(&parent_path).expect("substitute private parent directory");
        fs::write(parent_path.join(&child_name), b"unrelated substitute")
            .expect("create substitute child");

        let (inventory, inventory_failure) = artifact_inventory(&artifacts);
        assert_eq!(inventory_failure, None);
        let parent = &inventory[0];
        assert_eq!(parent.artifact_id(), 1);
        assert_eq!(parent.path(), parent_path.as_path());
        assert_eq!(parent.path_identity_matches(), Some(false));
        assert_eq!(parent.parent_identity_matches(), Some(true));

        let child = &inventory[1];
        assert_eq!(child.artifact_id(), 2);
        assert_eq!(child.path(), child_path.as_path());
        assert_eq!(child.relative_name(), Path::new(&child_name));
        assert_eq!(child.parent_artifact_id(), Some(1));
        assert_eq!(child.parent_device(), Some(parent_identity.device()));
        assert_eq!(child.parent_inode(), Some(parent_identity.inode()));
        assert_eq!(child.parent_identity_matches(), Some(false));
        assert_eq!(child.path_identity_matches(), None);
        assert_eq!(child.path_device(), None);
        assert_eq!(child.path_inode(), None);
        assert_eq!(child.path_length(), None);
        assert_eq!(child.device(), Some(child_identity.device()));
        assert_eq!(child.inode(), Some(child_identity.inode()));
        assert_eq!(child.length(), Some(b"owned child bytes".len() as u64));
        assert_eq!(
            child.sha256(),
            Some(Sha256Digest::digest(b"owned child bytes"))
        );

        let serialized = serde_json::to_value(&inventory).expect("serialize artifact inventory");
        assert_eq!(serialized[1]["path"], child_path.to_string_lossy().as_ref());
        assert_eq!(serialized[1]["relative_name"], ".nscb-stage-child");
        assert_eq!(serialized[1]["parent_artifact_id"], 1);
        assert_eq!(serialized[1]["parent_identity_matches"], false);
        assert_eq!(
            fs::read(moved_parent_path.join(&child_name)).unwrap(),
            b"owned child bytes"
        );
        assert_eq!(
            fs::read(parent_path.join(&child_name)).unwrap(),
            b"unrelated substitute"
        );
    }

    #[test]
    fn cleanup_path_substitution_is_never_unlinked_and_is_reported() {
        let (_root, _source, _destination, workspace) = fixture();
        let name: OsString = ".nscb-stage-cleanup-race".into();
        let stage_path = workspace.join(&name);
        let moved_path = workspace.join("stage-before-swap");
        fs::write(&stage_path, b"owned staging bytes").expect("create stage entry");
        let directory = open_directory(&workspace).expect("open workspace directory");
        let parent_identity = handle_identity(&directory).expect("read workspace identity");
        let file = open_file_at(&directory, &name).expect("open stage entry");
        let identity = handle_identity(&file).expect("read stage identity");
        drop(file);
        let mut artifacts = vec![OwnedArtifact {
            id: 1,
            parent_artifact_id: None,
            relative_name: PathBuf::from(&name),
            parent_identity: Some(parent_identity),
            directory: directory.try_clone().expect("clone workspace handle"),
            name: name.clone(),
            path: stage_path.clone(),
            identity: Some(identity),
            kind: OwnedArtifactKind::File,
            role: OperationArtifactRole::StagedOutput,
            length: Some(b"owned staging bytes".len() as u64),
            sha256: Some(Sha256Digest::digest(b"owned staging bytes")),
            path_identity: Some(identity),
            path_length: Some(b"owned staging bytes".len() as u64),
            keep: false,
        }];

        let retained = cleanup_artifacts_with_probe(&mut artifacts, |_| {
            fs::rename(&stage_path, &moved_path).expect("move checked stage entry");
            fs::write(&stage_path, b"unrelated replacement")
                .expect("substitute the path at the cleanup boundary");
        });

        assert!(retained);
        assert_eq!(fs::read(&moved_path).unwrap(), b"owned staging bytes");
        assert_eq!(fs::read(&stage_path).unwrap(), b"unrelated replacement");
        let (inventory, inventory_failure) = artifact_inventory(&artifacts);
        assert_eq!(inventory_failure, None);
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].role(), OperationArtifactRole::StagedOutput);
        assert_eq!(inventory[0].path(), stage_path.as_path());
        assert!(inventory[0].retained());
        assert_eq!(inventory[0].path_identity_matches(), Some(false));
        assert_eq!(
            inventory[0].device().zip(inventory[0].inode()),
            Some((identity.device(), identity.inode()))
        );
        assert_eq!(inventory[0].length(), None);
        assert_eq!(inventory[0].sha256(), None);
        assert_eq!(
            inventory[0].recorded_length(),
            Some(b"owned staging bytes".len() as u64)
        );
        assert_eq!(
            inventory[0].recorded_sha256(),
            Some(Sha256Digest::digest(b"owned staging bytes"))
        );
        assert_eq!(
            inventory[0].path_length(),
            Some(b"unrelated replacement".len() as u64)
        );
        assert_eq!(fs::read(moved_path).unwrap(), b"owned staging bytes");
    }

    #[test]
    fn already_up_to_date_cancellation_during_comparison_is_reported() {
        let (_root, source, destination, workspace) = fixture();
        fs::copy(&source, &destination).expect("create identical destination");
        let plan = plan(&source, &destination, &workspace);
        let session = OperationSession::new();

        let result = execute_with_producer_and_checkpoint(
            plan,
            &session,
            |_, _, _| Ok(()),
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AlreadyUpToDateComparisonChunk {
                    assert!(session.cancel());
                }
            },
        );

        assert_eq!(result.state(), JobState::Cancelled);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::Cancelled
        );
        assert_eq!(result.outcome(), None);
        assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
    }

    #[test]
    fn already_up_to_date_cancellation_wins_at_completion_handshake() {
        let (_root, source, destination, workspace) = fixture();
        fs::copy(&source, &destination).expect("create identical destination");
        let plan = plan(&source, &destination, &workspace);
        let session = OperationSession::new();

        let result = execute_with_producer_and_checkpoint(
            plan,
            &session,
            |_, _, _| Ok(()),
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforeCompletion {
                    assert!(session.cancel());
                }
            },
        );

        assert_eq!(result.state(), JobState::Cancelled);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::Cancelled
        );
        assert_eq!(result.outcome(), None);
    }

    #[test]
    fn already_up_to_date_reopens_and_revalidates_destination_after_comparison() {
        let (root, source, destination, workspace) = fixture();
        fs::copy(&source, &destination).expect("create identical destination");
        let plan = plan(&source, &destination, &workspace);
        let displaced = root.path().join("displaced-identical-destination");
        let competing_bytes = b"competing destination";
        let expected_destination_path = fs::canonicalize(destination.parent().unwrap())
            .unwrap()
            .join(destination.file_name().unwrap());

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            |_, _, _| Ok(()),
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AlreadyUpToDateCompared {
                    fs::rename(&destination, &displaced).expect("displace checked destination");
                    fs::write(&destination, competing_bytes)
                        .expect("install replacement destination");
                }
            },
        );

        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::DestinationChanged
        );
        assert_eq!(fs::read(&destination).unwrap(), competing_bytes);
        let competitor = destination_competitor(&result, &expected_destination_path);
        let destination_file =
            File::open(&destination).expect("open the current competing destination");
        let destination_identity =
            handle_identity(&destination_file).expect("read competing identity");
        assert_eq!(
            competitor.device().zip(competitor.inode()),
            Some((destination_identity.device(), destination_identity.inode()))
        );
        assert_eq!(competitor.length(), Some(competing_bytes.len() as u64));
        assert_eq!(
            competitor.sha256(),
            Some(Sha256Digest::digest(competing_bytes))
        );
        assert_eq!(competitor.path_identity_matches(), Some(true));
        assert_eq!(
            result.retained_storage_bytes(),
            Some(competing_bytes.len() as u64)
        );
        assert_eq!(fs::read(&displaced).unwrap(), fs::read(&source).unwrap());
    }

    #[test]
    fn already_up_to_date_rejects_a_retargeted_destination_parent_before_success() {
        let (root, source, _destination, workspace) = fixture();
        let destination_parent = root.path().join("destination-parent");
        fs::create_dir(&destination_parent).expect("create destination parent");
        let destination = destination_parent.join("destination.bin");
        fs::copy(&source, &destination).expect("create identical destination");
        let plan = plan(&source, &destination, &workspace);
        let displaced_parent = root.path().join("displaced-destination-parent");

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            |_, _, _| Ok(()),
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforeCompletion {
                    fs::rename(&destination_parent, &displaced_parent)
                        .expect("displace planned destination parent");
                    fs::create_dir(&destination_parent).expect("replace destination parent");
                    fs::write(&destination, b"competing destination")
                        .expect("install a destination at the retargeted path");
                }
            },
        );

        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert_eq!(fs::read(&destination).unwrap(), b"competing destination");
        assert_eq!(
            fs::read(displaced_parent.join("destination.bin")).unwrap(),
            fs::read(&source).unwrap()
        );
        assert!(!result.cleanup_artifact_retained(), "{result:?}");
        assert!(result.artifacts().is_empty(), "{result:?}");
        assert_eq!(result.retained_storage_bytes(), Some(0));
    }

    #[test]
    fn copy_publication_rejects_destination_parent_retarget_before_promotion() {
        let (root, source, _destination, workspace) = fixture();
        let destination_parent = root.path().join("destination-parent");
        fs::create_dir(&destination_parent).expect("create destination parent");
        let destination = destination_parent.join("destination.bin");
        let plan = plan(&source, &destination, &workspace);
        let displaced_parent = root.path().join("displaced-destination-parent");
        let mut retargeted = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforePromotion && !retargeted {
                    fs::rename(&destination_parent, &displaced_parent)
                        .expect("displace planned destination parent");
                    fs::create_dir(&destination_parent).expect("replace destination parent");
                    retargeted = true;
                }
            },
        );

        assert!(retargeted);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::StalePlan
        );
        assert!(!result.milestones().contains(&OperationMilestone::Published));
        assert!(!destination.exists());
        assert!(!displaced_parent.join("destination.bin").exists());
        assert!(result.cleanup_artifact_retained());
        assert!(contains_file_with_bytes(
            &workspace,
            &fs::read(&source).unwrap()
        ));
    }

    #[test]
    fn replacement_reports_uncertain_and_preserves_recovery_data_if_parent_is_retargeted() {
        let (root, source, _destination, workspace) = fixture();
        let destination_parent = root.path().join("destination-parent");
        fs::create_dir(&destination_parent).expect("create destination parent");
        let destination = destination_parent.join("destination.bin");
        let original_destination = b"previous destination bytes";
        fs::write(&destination, original_destination).expect("create prior destination");
        let plan = plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace)
                .with_conflict_policy(ConflictPolicy::Replace),
        )
        .expect("create explicit-replacement plan");
        let displaced_parent = root.path().join("displaced-destination-parent");
        let mut retargeted = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AfterPromotion && !retargeted {
                    fs::rename(&destination_parent, &displaced_parent)
                        .expect("displace planned destination parent");
                    fs::create_dir(&destination_parent).expect("replace destination parent");
                    retargeted = true;
                }
            },
        );

        assert!(retargeted);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert!(!destination.exists());
        assert_eq!(
            fs::read(displaced_parent.join("destination.bin")).unwrap(),
            fs::read(&source).unwrap()
        );
        assert_cleanup_incomplete(&result);
        let published = retained_artifact(&result, OperationArtifactRole::PublishedDestination);
        assert_eq!(published.parent_identity_matches(), Some(false));
        assert_eq!(published.path_identity_matches(), None);
        let moved_output = displaced_parent.join("destination.bin");
        assert_eq!(fs::read(&moved_output).unwrap(), fs::read(&source).unwrap());
        let moved_identity = handle_identity(&File::open(moved_output).unwrap()).unwrap();
        assert_eq!(published.device(), Some(moved_identity.device()));
        assert_eq!(published.inode(), Some(moved_identity.inode()));
        let backup = retained_artifact(&result, OperationArtifactRole::DestinationBackup);
        assert_eq!(backup.length(), Some(original_destination.len() as u64));
        assert_eq!(
            backup.sha256(),
            Some(Sha256Digest::digest(original_destination))
        );
        assert_eq!(fs::read(backup.path()).unwrap(), original_destination);
    }

    #[test]
    fn cancellation_while_waiting_for_destination_lock_is_reported() {
        let (_root, source, destination, workspace) = fixture();
        let plan = plan(&source, &destination, &workspace);
        let lock_path = plan.snapshot().destination_lock_path().to_path_buf();
        let held_lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .expect("create destination lock marker");
        held_lock.lock_exclusive().expect("hold destination lock");
        let session = OperationSession::new();
        let worker_session = session.clone();
        let (waiting_sender, waiting_receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut notified = false;
            execute_with_producer_and_checkpoint(
                plan,
                &worker_session,
                copy_source_to_stage,
                move |checkpoint| {
                    if checkpoint == ExecutionCheckpoint::DestinationLockWait && !notified {
                        notified = true;
                        waiting_sender.send(()).unwrap();
                    }
                },
            )
        });

        waiting_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("operation is waiting for the held destination lock");
        assert!(session.cancel());
        let result = worker.join().unwrap();

        assert_eq!(result.state(), JobState::Cancelled);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::Cancelled
        );
        assert!(!result.cleanup_artifact_retained(), "{result:?}");
        assert!(result.cleanup_warning().is_none(), "{result:?}");
        assert!(result.artifacts().is_empty(), "{result:?}");
        assert_eq!(fs::read_dir(workspace).unwrap().count(), 0);
        assert!(!destination.exists());
        drop(held_lock);
    }

    #[test]
    fn replaced_lock_marker_is_rejected_after_lock_acquisition() {
        let (_root, source, destination, workspace) = fixture();
        let plan = plan(&source, &destination, &workspace);
        let lock_path = plan.snapshot().destination_lock_path().to_path_buf();
        let displaced = workspace.join("displaced-lock-marker");
        let mut replaced = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::DestinationLockAcquired && !replaced {
                    replaced = true;
                    fs::rename(&lock_path, &displaced).expect("displace locked marker");
                    fs::write(&lock_path, b"replacement lock marker")
                        .expect("install replacement marker");
                }
            },
        );

        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::StalePlan
        );
        assert!(!result.cleanup_artifact_retained(), "{result:?}");
        assert!(result.cleanup_warning().is_none(), "{result:?}");
        assert!(result.artifacts().is_empty(), "{result:?}");
        assert_eq!(fs::read(&lock_path).unwrap(), b"replacement lock marker");
        assert!(displaced.exists());
        assert_eq!(fs::read_dir(workspace).unwrap().count(), 1);
        assert!(!destination.exists());
    }

    #[test]
    fn retargeted_lock_marker_after_final_destination_check_fails_before_publication() {
        let (_root, source, destination, workspace) = fixture();
        let original_destination = b"planned destination baseline";
        fs::write(&destination, original_destination).expect("write destination baseline");
        let plan = plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace)
                .with_conflict_policy(ConflictPolicy::Replace),
        )
        .expect("plan replacement");
        let lock_path = plan.snapshot().destination_lock_path().to_path_buf();
        let displaced = workspace.join("displaced-final-lock-marker");
        let mut retargeted = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AfterFinalDestinationValidation && !retargeted
                {
                    retargeted = true;
                    fs::rename(&lock_path, &displaced).expect("displace checked lock marker");
                    fs::write(&lock_path, b"replacement lock marker")
                        .expect("install replacement lock marker");
                }
            },
        );

        assert!(
            retargeted,
            "test must retarget after the final destination check"
        );
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::StalePlan
        );
        assert!(!result.milestones().contains(&OperationMilestone::Published));
        assert_cleanup_incomplete(&result);
        assert_eq!(fs::read(&destination).unwrap(), original_destination);
        assert_eq!(fs::read(&lock_path).unwrap(), b"replacement lock marker");
        assert!(displaced.exists());
    }

    #[test]
    fn retargeted_destination_parent_after_final_check_fails_before_publication() {
        let (root, source, _fixture_destination, workspace) = fixture();
        let destination_parent = root.path().join("destination-parent");
        fs::create_dir(&destination_parent).expect("create destination parent");
        let destination = destination_parent.join("output.bin");
        let original_destination = b"planned destination baseline";
        fs::write(&destination, original_destination).expect("write destination baseline");
        let plan = plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace)
                .with_conflict_policy(ConflictPolicy::Replace),
        )
        .expect("plan replacement");
        let displaced_parent = root.path().join("displaced-destination-parent");
        let mut retargeted = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AfterFinalDestinationValidation && !retargeted
                {
                    retargeted = true;
                    fs::rename(&destination_parent, &displaced_parent)
                        .expect("displace checked destination parent");
                    fs::create_dir(&destination_parent)
                        .expect("install replacement destination parent");
                }
            },
        );

        assert!(
            retargeted,
            "test must retarget after the final destination check"
        );
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::StalePlan
        );
        assert!(!result.milestones().contains(&OperationMilestone::Published));
        assert_cleanup_incomplete(&result);
        assert!(!destination.exists());
        assert_eq!(
            fs::read(displaced_parent.join("output.bin")).unwrap(),
            original_destination
        );
        assert!(
            fs::read_dir(&destination_parent)
                .expect("read replacement parent")
                .next()
                .is_none()
        );
    }

    #[test]
    fn source_mutation_during_final_evidence_read_is_detected() {
        let (_root, source, destination, workspace) = fixture();
        let plan = plan(&source, &destination, &workspace);
        let mut mutated = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::SourceEvidenceReadChunk && !mutated {
                    mutated = true;
                    let mut file = OpenOptions::new()
                        .append(true)
                        .open(&source)
                        .expect("open source for concurrent mutation");
                    file.write_all(b"+")
                        .expect("append during source evidence read");
                }
            },
        );

        assert!(mutated);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::SourceChanged
        );
        assert_cleanup_incomplete(&result);
        assert!(!destination.exists());
    }

    #[test]
    fn source_mutation_before_promotion_is_rejected_without_publication() {
        let (_root, source, destination, workspace) = fixture();
        let planned_source = fs::read(&source).expect("read planned source bytes");
        let plan = plan(&source, &destination, &workspace);
        let mut mutated = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforePromotion && !mutated {
                    mutated = true;
                    let mut file = OpenOptions::new()
                        .append(true)
                        .open(&source)
                        .expect("open source after its final validation");
                    file.write_all(b"+")
                        .expect("mutate source before promotion");
                }
            },
        );

        assert!(mutated);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::SourceChanged
        );
        assert!(!result.milestones().contains(&OperationMilestone::Published));
        assert_cleanup_incomplete(&result);
        assert!(!destination.exists());
        assert_ne!(fs::read(&source).unwrap(), planned_source);
    }

    #[test]
    fn replacement_conflict_after_atomic_commit_is_not_rolled_back_over() {
        let (_root, source, destination, workspace) = fixture();
        let old_destination = b"original destination bytes";
        let competing_destination = b"noncooperating writer bytes";
        fs::write(&destination, old_destination).expect("write original destination");
        let planned_source = fs::read(&source).expect("read planned source");
        let plan = plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace)
                .with_conflict_policy(ConflictPolicy::Replace),
        )
        .expect("plan explicit replacement");
        let mut swapped = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AfterPromotion && !swapped {
                    swapped = true;
                    fs::remove_file(&destination).expect("remove committed destination");
                    fs::write(&destination, competing_destination)
                        .expect("write competing destination");
                }
            },
        );

        assert!(swapped);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(result.outcome(), None);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert!(result.milestones().contains(&OperationMilestone::Published));
        assert_cleanup_incomplete(&result);
        assert_eq!(fs::read(&destination).unwrap(), competing_destination);
        let backup = retained_artifact(&result, OperationArtifactRole::DestinationBackup);
        assert_eq!(backup.path_identity_matches(), Some(true));
        assert_eq!(backup.length(), Some(old_destination.len() as u64));
        assert_eq!(backup.sha256(), Some(Sha256Digest::digest(old_destination)));
        assert_eq!(fs::read(backup.path()).unwrap(), old_destination);
        assert_ne!(fs::read(&destination).unwrap(), planned_source);
    }

    #[test]
    fn replacement_inventory_refreshes_digest_for_mutated_retained_inode() {
        let (_root, source, destination, workspace) = fixture();
        let planned_source = fs::read(&source).expect("read planned source");
        fs::write(&destination, b"old destination contents").expect("write original destination");
        let plan = plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace)
                .with_conflict_policy(ConflictPolicy::Replace),
        )
        .expect("plan explicit replacement");
        let current_bytes = vec![b'x'; planned_source.len()];
        let mut mutated = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AfterPromotion && !mutated {
                    mutated = true;
                    let mut published = OpenOptions::new()
                        .write(true)
                        .open(&destination)
                        .expect("open published inode for same-length rewrite");
                    published
                        .set_len(0)
                        .expect("truncate published inode in place");
                    published
                        .write_all(&current_bytes)
                        .expect("rewrite published inode in place");
                    published
                        .sync_all()
                        .expect("sync rewritten published inode");
                }
            },
        );

        assert!(mutated);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        let published = retained_artifact(&result, OperationArtifactRole::PublishedDestination);
        assert_eq!(published.path_identity_matches(), Some(true));
        assert_eq!(published.length(), Some(current_bytes.len() as u64));
        assert_eq!(
            published.sha256(),
            Some(Sha256Digest::digest(&current_bytes))
        );
        assert_eq!(
            published.recorded_sha256(),
            Some(Sha256Digest::digest(&planned_source))
        );
        assert_eq!(fs::read(&destination).unwrap(), current_bytes);
    }

    #[test]
    fn combined_replacement_source_and_destination_race_retains_both_entries() {
        let (_root, source, destination, workspace) = fixture();
        let old_destination = b"planned destination bytes";
        let competing_destination = b"unexpected competing entry";
        fs::write(&destination, old_destination).expect("write original destination");
        let old_destination_identity = handle_identity(&File::open(&destination).unwrap()).unwrap();
        let planned_source = fs::read(&source).expect("read planned source");
        let plan = plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace)
                .with_conflict_policy(ConflictPolicy::Replace),
        )
        .expect("plan explicit replacement");
        let competing_path = workspace.join("competing-destination.bin");
        let mut destination_raced = false;
        let mut source_raced = false;
        let mut competing_identity = None;
        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| match checkpoint {
                ExecutionCheckpoint::AtomicPromotionStarted if !destination_raced => {
                    destination_raced = true;
                    fs::write(&competing_path, competing_destination)
                        .expect("write noncooperating destination entry");
                    competing_identity =
                        Some(handle_identity(&File::open(&competing_path).unwrap()).unwrap());
                    fs::rename(&competing_path, &destination)
                        .expect("replace destination after final revalidation");
                }
                ExecutionCheckpoint::AfterPromotion if !source_raced => {
                    source_raced = true;
                    let mut changed_source = OpenOptions::new()
                        .append(true)
                        .open(&source)
                        .expect("open source after promotion");
                    changed_source
                        .write_all(b" mutated")
                        .expect("mutate source after promotion");
                    changed_source.sync_all().expect("sync mutated source");
                }
                _ => {}
            },
        );

        assert!(destination_raced && source_raced);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert!(result.milestones().contains(&OperationMilestone::Published));
        assert_cleanup_incomplete(&result);
        assert_eq!(fs::read(&destination).unwrap(), planned_source);
        assert_ne!(fs::read(&source).unwrap(), planned_source);

        let published = retained_artifact(&result, OperationArtifactRole::PublishedDestination);
        assert_eq!(published.path_identity_matches(), Some(true));
        assert_eq!(
            published.sha256(),
            Some(Sha256Digest::digest(&planned_source))
        );
        assert_eq!(fs::read(published.path()).unwrap(), planned_source);

        let displaced = retained_artifact(&result, OperationArtifactRole::DisplacedDestination);
        assert_eq!(displaced.path_identity_matches(), Some(true));
        assert_eq!(
            displaced.device().zip(displaced.inode()),
            competing_identity.map(|identity| (identity.device(), identity.inode()))
        );
        assert_eq!(displaced.length(), Some(competing_destination.len() as u64));
        assert_eq!(
            displaced.sha256(),
            Some(Sha256Digest::digest(competing_destination))
        );
        assert_eq!(fs::read(displaced.path()).unwrap(), competing_destination);

        let backup = retained_artifact(&result, OperationArtifactRole::DestinationBackup);
        assert_eq!(backup.path_identity_matches(), Some(true));
        assert_ne!(
            backup.device().zip(backup.inode()),
            Some((
                old_destination_identity.device(),
                old_destination_identity.inode()
            ))
        );
        assert_eq!(backup.length(), Some(old_destination.len() as u64));
        assert_eq!(backup.sha256(), Some(Sha256Digest::digest(old_destination)));
        assert_eq!(fs::read(backup.path()).unwrap(), old_destination);
    }

    #[test]
    fn destination_lock_marker_retarget_is_rejected_before_promotion() {
        let (root, source, destination, workspace) = fixture();
        let first_plan = plan(&source, &destination, &workspace);
        let second_plan = plan(&source, &destination, &workspace);
        let marker_path = first_plan.snapshot().destination_lock_path().to_path_buf();
        let displaced_marker_path = root.path().join("displaced-lock-marker");
        let first_session = OperationSession::new();
        let second_session = OperationSession::new();
        let mut second_plan = Some(second_plan);
        let mut second_result = None;
        let mut retargeted = false;

        let first_result = execute_with_producer_and_checkpoint(
            first_plan,
            &first_session,
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AtomicPromotionStarted && !retargeted {
                    retargeted = true;
                    fs::rename(&marker_path, &displaced_marker_path)
                        .expect("retarget the persistent destination marker");
                    fs::write(&marker_path, b"replacement marker")
                        .expect("create a replacement destination marker");
                    second_result = Some(execute_with_producer_and_checkpoint(
                        second_plan.take().expect("consume independent plan once"),
                        &second_session,
                        copy_source_to_stage,
                        |_| {},
                    ));
                }
            },
        );

        assert!(retargeted, "test must retarget after final revalidation");
        let second_result = second_result.expect("run the independent session");
        assert_eq!(
            second_result.state(),
            JobState::Succeeded,
            "{second_result:?}"
        );
        assert_eq!(second_result.outcome(), Some(OperationOutcome::Copied));
        assert_eq!(first_result.state(), JobState::Failed, "{first_result:?}");
        assert_eq!(
            first_result.failure().unwrap().code(),
            OperationFailureCode::StalePlan
        );
        assert!(first_result.outcome().is_none());
        assert!(
            !first_result
                .milestones()
                .contains(&OperationMilestone::Published)
        );
        assert_cleanup_incomplete(&first_result);
        assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
        assert!(
            marker_path.exists(),
            "replacement marker remains persistent"
        );
        assert!(
            displaced_marker_path.exists(),
            "original marker is preserved"
        );
    }

    #[test]
    fn staging_operand_retarget_is_rejected_before_promotion() {
        let (_root, source, destination, workspace) = fixture();
        let plan = plan(&source, &destination, &workspace);
        let replacement_bytes = b"unexpected staging operand";
        let mut replaced = false;
        let mut replacement_identity = None;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AtomicPromotionStarted && !replaced {
                    replaced = true;
                    let stage_path = stage_file_in(&workspace);
                    let replacement_path = stage_path.with_file_name("replacement-staging-operand");
                    fs::write(&replacement_path, replacement_bytes)
                        .expect("write replacement staging operand");
                    replacement_identity = handle_identity(&File::open(&replacement_path).unwrap());
                    fs::rename(&replacement_path, &stage_path)
                        .expect("replace the validated staging path");
                }
            },
        );

        assert!(
            replaced,
            "test must replace the stage after final revalidation"
        );
        assert_eq!(result.state(), JobState::Failed, "{result:?}");
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::ValidationFailed
        );
        assert!(result.outcome().is_none());
        assert!(!result.milestones().contains(&OperationMilestone::Published));
        assert!(!destination.exists());
        assert_cleanup_incomplete(&result);
        let staging = retained_artifact(&result, OperationArtifactRole::StagedOutput);
        assert_eq!(staging.path_identity_matches(), Some(false));
        assert_eq!(
            handle_identity(&File::open(staging.path()).unwrap()),
            replacement_identity
        );
        assert_eq!(fs::read(staging.path()).unwrap(), replacement_bytes);
    }

    #[test]
    fn operation_session_snapshot_tracks_progress_and_terminal_results() {
        let (_root, source, destination, workspace) = fixture();
        let copy_plan = plan(&source, &destination, &workspace);
        let session = OperationSession::new();
        let observer = session.clone();
        let mut saw_validated = false;
        let mut saw_published = false;

        let result = execute_with_producer_and_checkpoint(
            copy_plan,
            &session,
            copy_source_to_stage,
            |checkpoint| {
                let snapshot = observer.current_operation().unwrap();
                if checkpoint == ExecutionCheckpoint::BeforePromotion {
                    saw_validated = true;
                    assert_eq!(snapshot.phase(), OperationSessionPhase::Executing);
                    assert_eq!(snapshot.status(), OperationSessionStatus::Running);
                    assert_eq!(snapshot.milestone(), Some(OperationMilestone::Validated));
                }
                if checkpoint == ExecutionCheckpoint::AfterPromotion {
                    saw_published = true;
                    assert_eq!(snapshot.phase(), OperationSessionPhase::Completing);
                    assert_eq!(snapshot.milestone(), Some(OperationMilestone::Published));
                }
            },
        );

        assert!(saw_validated && saw_published);
        assert_eq!(result.state(), JobState::Succeeded);
        let snapshot = observer.current_operation().unwrap();
        assert_eq!(snapshot.phase(), OperationSessionPhase::Idle);
        assert_eq!(snapshot.status(), OperationSessionStatus::Succeeded);
        assert_eq!(snapshot.outcome(), Some(OperationOutcome::Copied));
        assert_eq!(snapshot.failure(), None);

        let (_root, source, destination, workspace) = fixture();
        let failed_plan = plan(&source, &destination, &workspace);
        let failed_session = OperationSession::new();
        let failed = execute_with_producer(failed_plan, &failed_session, |_, _, _| {
            Err(OperationFailureCode::WriteFailed)
        });
        let failure_snapshot = failed_session.current_operation().unwrap();
        assert_eq!(failed.state(), JobState::Failed);
        assert_eq!(failure_snapshot.status(), OperationSessionStatus::Failed);
        assert_eq!(
            failure_snapshot.failure(),
            Some(OperationFailureCode::ValidationFailed)
        );
        assert_eq!(failure_snapshot.outcome(), None);

        let (_root, source, destination, workspace) = fixture();
        let cancelled_plan = plan(&source, &destination, &workspace);
        let cancelled_session = OperationSession::new();
        let cancel_request_session = cancelled_session.clone();
        let cancelled =
            execute_with_producer(cancelled_plan, &cancelled_session, |source, stage, _| {
                source
                    .seek(SeekFrom::Start(0))
                    .map_err(|_| OperationFailureCode::SourceChanged)?;
                std::io::copy(source, stage).map_err(|_| OperationFailureCode::WriteFailed)?;
                assert!(cancel_request_session.cancel());
                Ok(())
            });
        let cancelled_snapshot = cancelled_session.current_operation().unwrap();
        assert_eq!(cancelled.state(), JobState::Cancelled, "{cancelled:?}");
        assert_eq!(
            cancelled_snapshot.status(),
            OperationSessionStatus::Cancelled
        );
        assert_eq!(
            cancelled_snapshot.failure(),
            Some(OperationFailureCode::Cancelled)
        );

        let (_root, source, destination, workspace) = fixture();
        fs::copy(&source, &destination).expect("make destination already current");
        let current_plan = plan(&source, &destination, &workspace);
        let current_session = OperationSession::new();
        let current = execute_with_producer(current_plan, &current_session, |_, _, _| {
            panic!("already-current destination must not stage output")
        });
        let current_snapshot = current_session.current_operation().unwrap();
        assert_eq!(current.state(), JobState::Succeeded);
        assert_eq!(current.outcome(), Some(OperationOutcome::AlreadyUpToDate));
        assert_eq!(current_snapshot.status(), OperationSessionStatus::Succeeded);
        assert_eq!(
            current_snapshot.outcome(),
            Some(OperationOutcome::AlreadyUpToDate)
        );
    }

    #[test]
    fn replacement_source_race_returns_uncertain_and_preserves_old_destination_backup() {
        let (_root, source, destination, workspace) = fixture();
        let old_destination = b"prior destination contents";
        fs::write(&destination, old_destination).expect("write original destination");
        let planned_source = fs::read(&source).expect("read planned source");
        let plan = plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace)
                .with_conflict_policy(ConflictPolicy::Replace),
        )
        .expect("plan explicit replacement");
        let mut mutated = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforePromotion && !mutated {
                    mutated = true;
                    let mut file = OpenOptions::new()
                        .append(true)
                        .open(&source)
                        .expect("open source after final validation");
                    file.write_all(b"+")
                        .expect("mutate source before the atomic commit");
                }
            },
        );

        assert!(mutated);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(result.outcome(), None);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::SourceChanged
        );
        assert!(!result.milestones().contains(&OperationMilestone::Published));
        assert_eq!(fs::read(&destination).unwrap(), old_destination);
        assert_ne!(fs::read(&source).unwrap(), planned_source);
        assert_cleanup_incomplete(&result);
    }

    #[test]
    fn cooperating_source_mutation_after_planning_is_rejected_after_lock_release() {
        use fs2::FileExt as _;

        let (_root, source, destination, workspace) = fixture();
        let plan = plan(&source, &destination, &workspace);
        let mut source_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source)
            .expect("open source for cooperating writer");
        source_lock
            .lock_exclusive()
            .expect("lock source before execution");
        let (waiting_tx, waiting_rx) = mpsc::channel();
        let operation = std::thread::spawn(move || {
            execute_with_producer_and_checkpoint(
                plan,
                &OperationSession::new(),
                copy_source_to_stage,
                |checkpoint| {
                    if checkpoint == ExecutionCheckpoint::SourceLockWait {
                        waiting_tx.send(()).expect("report source lock wait");
                    }
                },
            )
        });

        waiting_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("execution waits for the cooperating source writer");
        source_lock
            .set_len(0)
            .expect("truncate source while locked");
        source_lock
            .write_all(b"cooperating mutation")
            .expect("write cooperating source mutation");
        source_lock.sync_all().expect("sync cooperating mutation");
        source_lock
            .unlock()
            .expect("release source lock after mutation");

        let result = operation.join().expect("join copy operation");
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::SourceChanged
        );
        assert!(!destination.exists());
    }

    #[test]
    fn cooperating_source_writer_is_blocked_through_publication() {
        use fs2::FileExt as _;
        use std::io::Seek;

        let (_root, source, destination, workspace) = fixture();
        let planned_source = fs::read(&source).expect("read planned source");
        let plan = plan(&source, &destination, &workspace);
        let session = OperationSession::new();
        let mut writer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source)
            .expect("open cooperating writer descriptor");
        let mut before_promotion = None;
        let mut after_promotion = None;
        let result = execute_with_producer_and_checkpoint(
            plan,
            &session,
            copy_source_to_stage,
            |checkpoint| match checkpoint {
                ExecutionCheckpoint::BeforeAtomicPromotion => {
                    assert_eq!(
                        session.current_operation().unwrap().phase(),
                        OperationSessionPhase::Executing
                    );
                    before_promotion = Some(
                        writer
                            .try_lock_exclusive()
                            .expect_err("writer must be blocked before promotion")
                            .kind(),
                    );
                }
                ExecutionCheckpoint::AfterPromotion => {
                    after_promotion = Some(
                        writer
                            .try_lock_exclusive()
                            .expect_err("writer must remain blocked after promotion")
                            .kind(),
                    );
                }
                _ => {}
            },
        );

        assert_eq!(result.state(), JobState::Succeeded, "{result:?}");
        assert_eq!(result.outcome(), Some(OperationOutcome::Copied));
        assert_cleanup_incomplete(&result);
        assert_eq!(before_promotion, Some(io::ErrorKind::WouldBlock));
        assert_eq!(after_promotion, Some(io::ErrorKind::WouldBlock));
        writer
            .try_lock_exclusive()
            .expect("writer acquires source lock after terminal release");
        writer
            .seek(std::io::SeekFrom::Start(0))
            .expect("seek to source start");
        writer.set_len(0).expect("truncate source after release");
        writer
            .write_all(b"writer after publication")
            .expect("write after release");
        assert_eq!(fs::read(destination).unwrap(), planned_source);
        assert_eq!(fs::read(source).unwrap(), b"writer after publication");
    }

    #[test]
    fn cooperating_source_lock_is_held_through_artifact_inventory_and_finalization() {
        use fs2::FileExt as _;

        let (_root, source, destination, workspace) = fixture();
        let planned_source = fs::read(&source).expect("read planned source");
        let plan = plan(&source, &destination, &workspace);
        let session = OperationSession::new();
        let worker_session = session.clone();
        let checkpoint_session = worker_session.clone();
        let (paused_sender, paused_receiver) = mpsc::channel();
        let (resume_sender, resume_receiver) = mpsc::channel();
        let operation = std::thread::spawn(move || {
            let mut paused = false;
            execute_with_producer_and_checkpoint(
                plan,
                &worker_session,
                copy_source_to_stage,
                move |checkpoint| {
                    if checkpoint == ExecutionCheckpoint::BeforeArtifactInventory && !paused {
                        paused = true;
                        assert_eq!(
                            checkpoint_session.current_operation().unwrap().phase(),
                            OperationSessionPhase::Completing
                        );
                        assert!(
                            !checkpoint_session.cancel(),
                            "cancellation must be refused during finalization"
                        );
                        paused_sender
                            .send(())
                            .expect("report finalization inventory pause");
                        resume_receiver
                            .recv_timeout(Duration::from_secs(5))
                            .expect("resume finalization inventory");
                    }
                },
            )
        });

        paused_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("operation pauses before artifact inventory");
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source)
            .expect("open competing cooperative source handle");
        let error = contender
            .try_lock_exclusive()
            .expect_err("source lock must remain held through finalization inventory");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        resume_sender
            .send(())
            .expect("resume finalization inventory");

        let result = operation.join().expect("join completed operation");
        assert_eq!(result.state(), JobState::Succeeded, "{result:?}");
        contender
            .try_lock_exclusive()
            .expect("cooperating writer acquires source lock after terminal return");
        contender.unlock().expect("release cooperating writer lock");
        assert_eq!(fs::read(destination).unwrap(), planned_source);
    }

    #[test]
    fn source_lock_release_does_not_wait_for_inherited_descriptor_close() {
        let (_root, source, _destination, _workspace) = fixture();
        let file = File::open(&source).expect("open source");
        fs2::FileExt::try_lock_shared(&file).expect("lock source");
        let guard = SourceLockGuard { file };
        // dup and fork retain references to the same open file description.
        // Keeping a duplicate alive deterministically exercises that lifetime
        // without forking the multithreaded Rust test process.
        let inherited = guard.file.try_clone().expect("duplicate locked descriptor");
        let contender = File::open(&source).expect("open independent contender");
        assert_eq!(
            fs2::FileExt::try_lock_exclusive(&contender)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        drop(guard);
        fs2::FileExt::try_lock_exclusive(&contender)
            .expect("terminal release must unlock even while an inherited reference survives");
        fs2::FileExt::unlock(&contender).expect("unlock contender");
        drop(inherited);
    }

    #[test]
    fn created_workspace_open_failure_is_reported_in_terminal_artifacts() {
        let (_root, source, destination, workspace) = fixture();
        fs::remove_dir(&workspace).expect("request a new workspace");
        let plan = plan(&source, &destination, &workspace);
        TEST_DIRECTORY_OPEN_FAILURE.with(|failure| {
            *failure.borrow_mut() = workspace.file_name().map(OsStr::to_os_string);
        });
        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |_| {},
        );
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::UnsupportedCapability
        );
        assert!(
            workspace.is_dir(),
            "mkdirat succeeded before the injected open failure"
        );
        assert_cleanup_incomplete(&result);
        let retained = retained_artifact(&result, OperationArtifactRole::WorkspaceDirectory);
        assert_eq!(retained.path(), workspace.canonicalize().unwrap());
        assert!(!destination.exists());
        assert_eq!(fs::read(source).unwrap(), b"operation test source bytes");
    }

    #[test]
    fn independent_sessions_serialize_and_revalidate_the_same_destination() {
        let (_root, source, destination, workspace) = fixture();
        let first_plan = plan(&source, &destination, &workspace);
        let second_plan = plan(&source, &destination, &workspace);
        let first_session = OperationSession::new();
        let second_session = OperationSession::new();
        let (first_locked_sender, first_locked_receiver) = mpsc::channel();
        let (release_first_sender, release_first_receiver) = mpsc::channel();

        let first_worker = std::thread::spawn(move || {
            let mut lock_reported = false;
            execute_with_producer_and_checkpoint(
                first_plan,
                &first_session,
                copy_source_to_stage,
                move |checkpoint| {
                    if checkpoint == ExecutionCheckpoint::DestinationLockAcquired && !lock_reported
                    {
                        lock_reported = true;
                        first_locked_sender.send(()).unwrap();
                        release_first_receiver.recv().unwrap();
                    }
                },
            )
        });

        first_locked_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("first operation holds destination coordination lock");

        let (second_waiting_sender, second_waiting_receiver) = mpsc::channel();
        let second_worker = std::thread::spawn(move || {
            let mut wait_reported = false;
            execute_with_producer_and_checkpoint(
                second_plan,
                &second_session,
                copy_source_to_stage,
                move |checkpoint| {
                    if checkpoint == ExecutionCheckpoint::DestinationLockWait && !wait_reported {
                        wait_reported = true;
                        second_waiting_sender.send(()).unwrap();
                    }
                },
            )
        });

        second_waiting_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("independent session waits on the same destination lock");
        release_first_sender
            .send(())
            .expect("allow first operation to publish");

        let first = first_worker.join().unwrap();
        let second = second_worker.join().unwrap();
        assert_eq!(first.state(), JobState::Succeeded, "{first:?}");
        assert_eq!(first.outcome(), Some(OperationOutcome::Copied));
        assert_eq!(second.state(), JobState::Failed, "{second:?}");
        assert_eq!(
            second.failure().unwrap().code(),
            OperationFailureCode::DestinationChanged
        );
        assert_cleanup_incomplete(&second);
        let competing_bytes = fs::read(&destination).unwrap();
        assert_eq!(competing_bytes, fs::read(&source).unwrap());
        let expected_destination_path = fs::canonicalize(destination.parent().unwrap())
            .unwrap()
            .join(destination.file_name().unwrap());
        let competitor = destination_competitor(&second, &expected_destination_path);
        assert_eq!(competitor.length(), Some(competing_bytes.len() as u64));
        assert_eq!(
            competitor.sha256(),
            Some(Sha256Digest::digest(&competing_bytes))
        );
        assert_eq!(competitor.path_identity_matches(), Some(true));
        assert_eq!(
            second.retained_storage_bytes(),
            Some(competing_bytes.len() as u64)
        );
    }

    #[test]
    fn independent_sessions_serialize_distinct_destinations_in_the_same_parent() {
        let (root, first_source, first_destination, workspace) = fixture();
        let second_source = root.path().join("second-source.bin");
        let second_destination = root.path().join("second-destination.bin");
        fs::write(&second_source, b"second operation source bytes")
            .expect("write second source fixture");
        let first_plan = plan(&first_source, &first_destination, &workspace);
        let second_plan = plan(&second_source, &second_destination, &workspace);
        let first_session = OperationSession::new();
        let second_session = OperationSession::new();
        let (first_locked_sender, first_locked_receiver) = mpsc::channel();
        let (release_first_sender, release_first_receiver) = mpsc::channel();
        let first_worker = std::thread::spawn(move || {
            let mut lock_reported = false;
            execute_with_producer_and_checkpoint(
                first_plan,
                &first_session,
                copy_source_to_stage,
                move |checkpoint| {
                    if checkpoint == ExecutionCheckpoint::DestinationLockAcquired && !lock_reported
                    {
                        lock_reported = true;
                        first_locked_sender.send(()).unwrap();
                        release_first_receiver.recv().unwrap();
                    }
                },
            )
        });
        first_locked_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("first operation holds its parent-directory lock");
        let (second_waiting_sender, second_waiting_receiver) = mpsc::channel();
        let second_worker = std::thread::spawn(move || {
            let mut wait_reported = false;
            execute_with_producer_and_checkpoint(
                second_plan,
                &second_session,
                copy_source_to_stage,
                move |checkpoint| {
                    if checkpoint == ExecutionCheckpoint::DestinationLockWait && !wait_reported {
                        wait_reported = true;
                        second_waiting_sender.send(()).unwrap();
                    }
                },
            )
        });
        second_waiting_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("distinct destination waits on the same parent-directory lock");
        release_first_sender
            .send(())
            .expect("allow both independent operations to complete");
        let first = first_worker.join().unwrap();
        let second = second_worker.join().unwrap();
        assert_eq!(first.state(), JobState::Succeeded, "{first:?}");
        assert_eq!(second.state(), JobState::Succeeded, "{second:?}");
        assert_eq!(first.outcome(), Some(OperationOutcome::Copied));
        assert_eq!(second.outcome(), Some(OperationOutcome::Copied));
        assert_eq!(
            fs::read(&first_destination).unwrap(),
            fs::read(&first_source).unwrap()
        );
        assert_eq!(
            fs::read(&second_destination).unwrap(),
            fs::read(&second_source).unwrap()
        );
    }

    #[test]
    fn independent_sessions_serialize_replace_and_revalidate_the_same_destination() {
        let (_root, source, destination, workspace) = fixture();
        let original_destination = b"original destination bytes";
        fs::write(&destination, original_destination).expect("create destination baseline");
        let replace_plan = || {
            plan_copy_through(
                CopyThroughRequest::new(&source, &destination, &workspace)
                    .with_conflict_policy(ConflictPolicy::Replace),
            )
            .expect("create replacement plan")
        };
        let first_plan = replace_plan();
        let second_plan = replace_plan();
        let first_session = OperationSession::new();
        let second_session = OperationSession::new();
        let (first_locked_sender, first_locked_receiver) = mpsc::channel();
        let (release_first_sender, release_first_receiver) = mpsc::channel();

        let first_worker = std::thread::spawn(move || {
            let mut lock_reported = false;
            execute_with_producer_and_checkpoint(
                first_plan,
                &first_session,
                copy_source_to_stage,
                move |checkpoint| {
                    if checkpoint == ExecutionCheckpoint::DestinationLockAcquired && !lock_reported
                    {
                        lock_reported = true;
                        first_locked_sender.send(()).unwrap();
                        release_first_receiver.recv().unwrap();
                    }
                },
            )
        });

        first_locked_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("first replacement holds destination coordination lock");

        let (second_waiting_sender, second_waiting_receiver) = mpsc::channel();
        let second_worker = std::thread::spawn(move || {
            let mut wait_reported = false;
            execute_with_producer_and_checkpoint(
                second_plan,
                &second_session,
                copy_source_to_stage,
                move |checkpoint| {
                    if checkpoint == ExecutionCheckpoint::DestinationLockWait && !wait_reported {
                        wait_reported = true;
                        second_waiting_sender.send(()).unwrap();
                    }
                },
            )
        });

        second_waiting_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("independent replacement waits on the same destination lock");
        release_first_sender
            .send(())
            .expect("allow first replacement to publish");

        let first = first_worker.join().unwrap();
        let second = second_worker.join().unwrap();
        assert_eq!(first.state(), JobState::Succeeded, "{first:?}");
        assert_eq!(first.outcome(), Some(OperationOutcome::Copied));
        assert_eq!(second.state(), JobState::Failed, "{second:?}");
        assert_eq!(
            second.failure().unwrap().code(),
            OperationFailureCode::DestinationChanged
        );
        assert_cleanup_incomplete(&second);
        let competing_bytes = fs::read(&destination).unwrap();
        assert_eq!(competing_bytes, fs::read(&source).unwrap());
        let expected_destination_path = fs::canonicalize(destination.parent().unwrap())
            .unwrap()
            .join(destination.file_name().unwrap());
        let competitor = destination_competitor(&second, &expected_destination_path);
        assert_eq!(competitor.length(), Some(competing_bytes.len() as u64));
        assert_eq!(
            competitor.sha256(),
            Some(Sha256Digest::digest(&competing_bytes))
        );
        assert_eq!(competitor.path_identity_matches(), Some(true));
        assert_eq!(
            second.retained_storage_bytes(),
            Some(competing_bytes.len() as u64)
        );

        let backup = first
            .artifacts()
            .iter()
            .find(|artifact| artifact.role() == OperationArtifactRole::DestinationBackup)
            .expect("inventory original destination recovery copy");
        assert!(backup.retained(), "{backup:?}");
        assert_eq!(backup.path_identity_matches(), Some(true), "{backup:?}");
        assert_eq!(backup.length(), Some(original_destination.len() as u64));
        assert_eq!(
            backup.sha256(),
            Some(Sha256Digest::digest(original_destination))
        );
        assert_eq!(fs::read(backup.path()).unwrap(), original_destination);
    }

    #[test]
    fn noncooperating_replace_before_promotion_preserves_competitor_and_baseline() {
        let (root, source, destination, workspace) = fixture();
        let original_destination = b"planned destination baseline";
        let competing_bytes = b"noncooperating replacement bytes";
        fs::write(&destination, original_destination).expect("write destination baseline");
        let original_identity =
            handle_identity(&File::open(&destination).expect("open destination baseline")).unwrap();
        let competitor = root.path().join("competing-writer.bin");
        fs::write(&competitor, competing_bytes).expect("write competing destination");
        let competing_identity =
            handle_identity(&File::open(&competitor).expect("open competitor")).unwrap();
        let plan = plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace)
                .with_conflict_policy(ConflictPolicy::Replace),
        )
        .expect("plan explicit replacement");
        let mut replaced = false;
        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AfterFinalDestinationValidation && !replaced {
                    replaced = true;
                    fs::rename(&competitor, &destination)
                        .expect("noncooperating writer replaces validated destination");
                }
            },
        );

        assert!(replaced, "test must race before final revalidation");
        assert_eq!(result.state(), JobState::Failed, "{result:?}");
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::DestinationChanged
        );
        assert!(result.outcome().is_none());
        assert!(!result.milestones().contains(&OperationMilestone::Published));
        assert_cleanup_incomplete(&result);
        assert_eq!(fs::read(&destination).unwrap(), competing_bytes);
        assert_eq!(
            handle_identity(&File::open(&destination).unwrap()),
            Some(competing_identity)
        );

        let backup = retained_artifact(&result, OperationArtifactRole::DestinationBackup);
        assert_eq!(backup.path_identity_matches(), Some(true));
        assert_ne!(
            backup.device().zip(backup.inode()),
            Some((original_identity.device(), original_identity.inode()))
        );
        assert_eq!(backup.length(), Some(original_destination.len() as u64));
        assert_eq!(
            backup.sha256(),
            Some(Sha256Digest::digest(original_destination))
        );
        assert_eq!(fs::read(backup.path()).unwrap(), original_destination);
    }

    #[test]
    fn cooperative_source_lock_remains_held_through_replace_publication() {
        use fs2::FileExt as _;

        let (_root, source, destination, workspace) = fixture();
        fs::write(&destination, b"planned destination baseline")
            .expect("write destination baseline");
        let plan = plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace)
                .with_conflict_policy(ConflictPolicy::Replace),
        )
        .expect("plan replacement");
        let session = OperationSession::new();
        let worker_session = session.clone();
        let (paused_sender, paused_receiver) = mpsc::channel();
        let (resume_sender, resume_receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut paused = false;
            execute_with_producer_and_checkpoint(
                plan,
                &worker_session,
                copy_source_to_stage,
                move |checkpoint| {
                    if checkpoint == ExecutionCheckpoint::AfterPromotion && !paused {
                        paused = true;
                        paused_sender.send(()).expect("report publication pause");
                        resume_receiver.recv().expect("resume publication");
                    }
                },
            )
        });

        paused_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("operation pauses after promotion");
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source)
            .expect("open competing cooperative source handle");
        let error = contender
            .try_lock_exclusive()
            .expect_err("operation holds the source lock while publication is paused");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

        resume_sender.send(()).expect("resume operation");
        let result = worker.join().unwrap();
        assert_eq!(result.state(), JobState::Succeeded, "{result:?}");
        assert_eq!(result.outcome(), Some(OperationOutcome::Copied));
        contender
            .try_lock_exclusive()
            .expect("operation releases the source lock after it exits");
        contender.unlock().expect("release test source lock");
        assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
    }

    #[test]
    fn replace_revalidates_a_held_source_handle_after_final_destination_check() {
        let (_root, source, destination, workspace) = fixture();
        let original_destination = b"planned destination baseline";
        let mutated_source = b"noncooperating source mutation";
        fs::write(&destination, original_destination).expect("write destination baseline");
        let plan = plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace)
                .with_conflict_policy(ConflictPolicy::Replace),
        )
        .expect("plan replacement");
        let mut held_source = OpenOptions::new()
            .write(true)
            .open(&source)
            .expect("open source descriptor before execution");
        let mut mutated = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AfterFinalDestinationValidation && !mutated {
                    mutated = true;
                    held_source
                        .set_len(0)
                        .and_then(|()| held_source.seek(SeekFrom::Start(0)).map(|_| ()))
                        .and_then(|()| held_source.write_all(mutated_source))
                        .expect("mutate source through the already-open descriptor");
                    held_source
                        .sync_all()
                        .expect("synchronize held source mutation");
                }
            },
        );

        assert!(mutated, "test must mutate after destination validation");
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::SourceChanged
        );
        assert!(!result.milestones().contains(&OperationMilestone::Published));
        assert_cleanup_incomplete(&result);
        assert_eq!(fs::read(&destination).unwrap(), original_destination);
        assert_eq!(fs::read(&source).unwrap(), mutated_source);
    }

    #[test]
    fn source_mutation_after_final_source_validation_is_rejected_before_promotion() {
        let (_root, source, destination, workspace) = fixture();
        let original_destination = b"planned destination baseline";
        fs::write(&destination, original_destination).expect("write destination baseline");
        let planned_source = fs::read(&source).expect("read planned source bytes");
        let mutated_source = b"source changed after last recheck";
        let plan = plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace)
                .with_conflict_policy(ConflictPolicy::Replace),
        )
        .expect("plan replacement");
        let mut held_source = OpenOptions::new()
            .write(true)
            .open(&source)
            .expect("open a noncooperating source writer descriptor");
        let mut mutated = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AfterFinalSourceValidation && !mutated {
                    mutated = true;
                    held_source
                        .set_len(0)
                        .and_then(|()| held_source.seek(SeekFrom::Start(0)).map(|_| ()))
                        .and_then(|()| held_source.write_all(mutated_source))
                        .expect("mutate source through the held descriptor");
                    held_source.sync_all().expect("synchronize source mutation");
                }
            },
        );

        assert!(mutated, "test must mutate after final source validation");
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::SourceChanged
        );
        assert!(!result.milestones().contains(&OperationMilestone::Published));
        assert_eq!(fs::read(&destination).unwrap(), original_destination);
        assert_eq!(fs::read(&source).unwrap(), mutated_source);
        assert_cleanup_incomplete(&result);
        let staging = retained_artifact(&result, OperationArtifactRole::StagedOutput);
        assert_eq!(staging.length(), Some(planned_source.len() as u64));
        assert_eq!(
            staging.sha256(),
            Some(Sha256Digest::digest(&planned_source))
        );
        assert_eq!(fs::read(staging.path()).unwrap(), planned_source);
        let backup = retained_artifact(&result, OperationArtifactRole::DestinationBackup);
        assert_eq!(backup.length(), Some(original_destination.len() as u64));
        assert_eq!(
            backup.sha256(),
            Some(Sha256Digest::digest(original_destination))
        );
        assert_eq!(fs::read(backup.path()).unwrap(), original_destination);
    }

    #[test]
    fn replace_retains_displaced_inode_mutated_after_its_first_verification() {
        let (_root, source, destination, workspace) = fixture();
        let original_destination = b"planned destination baseline";
        let concurrent_bytes = b"writer changed displaced inode";
        fs::write(&destination, original_destination).expect("write destination baseline");
        let mut held_displaced = OpenOptions::new()
            .write(true)
            .open(&destination)
            .expect("hold a writer descriptor for the destination inode");
        let original_identity =
            handle_identity(&File::open(&destination).unwrap()).expect("read destination identity");
        let plan = plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace)
                .with_conflict_policy(ConflictPolicy::Replace),
        )
        .expect("plan replacement");
        let mut mutated = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AfterDisplacedEntryValidation && !mutated {
                    mutated = true;
                    held_displaced
                        .set_len(0)
                        .and_then(|()| held_displaced.seek(SeekFrom::Start(0)).map(|_| ()))
                        .and_then(|()| held_displaced.write_all(concurrent_bytes))
                        .expect("mutate displaced inode through held descriptor");
                    held_displaced
                        .sync_all()
                        .expect("synchronize concurrent displaced-entry mutation");
                }
            },
        );

        assert!(
            mutated,
            "test must mutate after displaced-entry verification"
        );
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::DestinationChanged
        );
        assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
        assert_cleanup_incomplete(&result);
        let retained = retained_artifact(&result, OperationArtifactRole::DisplacedDestination);
        assert_eq!(retained.path_identity_matches(), Some(true));
        assert_eq!(retained.device(), Some(original_identity.device()));
        assert_eq!(retained.inode(), Some(original_identity.inode()));
        assert_eq!(retained.length(), Some(concurrent_bytes.len() as u64));
        assert_eq!(
            retained.sha256(),
            Some(Sha256Digest::digest(concurrent_bytes))
        );
        assert_eq!(fs::read(retained.path()).unwrap(), concurrent_bytes);
    }

    #[test]
    fn replacement_substitution_preserves_displaced_identity_and_reports_current_uncertainty() {
        let (root, source, destination, workspace) = fixture();
        let original_destination = b"planned destination baseline";
        let substitute_bytes = b"unowned replacement at displaced stage path";
        let moved_original = root.path().join("retained-original-destination.bin");
        fs::write(&destination, original_destination).expect("write destination baseline");
        let original_identity =
            handle_identity(&File::open(&destination).unwrap()).expect("read destination identity");
        let plan = plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace)
                .with_conflict_policy(ConflictPolicy::Replace),
        )
        .expect("plan replacement");
        let mut substituted = false;
        let mut substituted_stage_path = None;
        let mut substitute_identity = None;
        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AfterDisplacedEntryValidation && !substituted
                {
                    substituted = true;
                    let stage_directory = fs::read_dir(&workspace)
                        .expect("read operation workspace")
                        .filter_map(Result::ok)
                        .map(|entry| entry.path())
                        .find(|path| {
                            path.is_dir()
                                && path.file_name().is_some_and(|name| {
                                    name.to_string_lossy().starts_with(".nscb-stage-area-")
                                })
                        })
                        .expect("find private staging directory");
                    let stage_path = fs::read_dir(stage_directory)
                        .expect("read private staging directory")
                        .filter_map(Result::ok)
                        .map(|entry| entry.path())
                        .find(|path| {
                            path.is_file()
                                && handle_identity(&File::open(path).unwrap())
                                    == Some(original_identity)
                        })
                        .expect("find displaced destination entry");
                    fs::rename(&stage_path, &moved_original)
                        .expect("move originally displaced destination");
                    fs::write(&stage_path, substitute_bytes)
                        .expect("substitute displaced stage pathname");
                    substitute_identity = handle_identity(&File::open(&stage_path).unwrap());
                    substituted_stage_path = Some(stage_path);
                }
            },
        );
        assert!(
            substituted,
            "test must substitute the path after displaced-entry validation"
        );
        let substituted_stage_path = substituted_stage_path.expect("record substituted stage path");
        let substitute_identity = substitute_identity.expect("record substitute identity");
        assert_eq!(result.state(), JobState::Failed, "{result:?}");
        assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
        assert_eq!(fs::read(&moved_original).unwrap(), original_destination);
        assert_eq!(fs::read(&substituted_stage_path).unwrap(), substitute_bytes);
        assert_cleanup_incomplete(&result);

        let displaced = retained_artifact(&result, OperationArtifactRole::DisplacedDestination);
        assert_eq!(
            fs::canonicalize(displaced.path()).unwrap(),
            fs::canonicalize(&substituted_stage_path).unwrap()
        );
        assert_eq!(displaced.device(), Some(original_identity.device()));
        assert_eq!(displaced.inode(), Some(original_identity.inode()));
        assert_eq!(
            displaced.recorded_length(),
            Some(original_destination.len() as u64)
        );
        assert_eq!(
            displaced.recorded_sha256(),
            Some(Sha256Digest::digest(original_destination))
        );
        assert_eq!(displaced.length(), None);
        assert_eq!(displaced.sha256(), None);
        assert_eq!(displaced.path_identity_matches(), Some(false));
        assert_eq!(
            displaced.path_device().zip(displaced.path_inode()),
            Some((substitute_identity.device(), substitute_identity.inode()))
        );
        assert_eq!(displaced.path_length(), Some(substitute_bytes.len() as u64));
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );

        let backup = retained_artifact(&result, OperationArtifactRole::DestinationBackup);
        assert_eq!(fs::read(backup.path()).unwrap(), original_destination);
        let published = retained_artifact(&result, OperationArtifactRole::PublishedDestination);
        assert_eq!(
            fs::read(published.path()).unwrap(),
            fs::read(&source).unwrap()
        );
        assert_eq!(result.retained_storage_bytes(), None);
    }

    #[test]
    fn replacement_inventory_detects_late_displaced_inode_mutation() {
        let (_root, source, destination, workspace) = fixture();
        let planned_destination = b"planned destination baseline";
        let mutated_destination = b"updated destination baseline";
        fs::write(&destination, planned_destination).expect("write destination baseline");
        let mut held_displaced = OpenOptions::new()
            .write(true)
            .open(&destination)
            .expect("hold a writer descriptor for the destination inode");
        let original_identity =
            handle_identity(&File::open(&destination).unwrap()).expect("read destination identity");
        let plan = plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace)
                .with_conflict_policy(ConflictPolicy::Replace),
        )
        .expect("plan replacement");
        let mut mutated = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforeArtifactInventory && !mutated {
                    mutated = true;
                    held_displaced
                        .set_len(0)
                        .and_then(|()| held_displaced.seek(SeekFrom::Start(0)).map(|_| ()))
                        .and_then(|()| held_displaced.write_all(mutated_destination))
                        .expect("mutate displaced inode before inventory");
                    held_displaced
                        .sync_all()
                        .expect("synchronize displaced-entry mutation");
                }
            },
        );

        assert!(mutated, "test must mutate after publication comparison");
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::DestinationChanged
        );
        assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
        let displaced = retained_artifact(&result, OperationArtifactRole::DisplacedDestination);
        assert_eq!(displaced.path_identity_matches(), Some(true));
        assert_eq!(displaced.device(), Some(original_identity.device()));
        assert_eq!(displaced.inode(), Some(original_identity.inode()));
        assert_eq!(
            displaced.sha256(),
            Some(Sha256Digest::digest(mutated_destination))
        );
        assert_eq!(fs::read(displaced.path()).unwrap(), mutated_destination);
    }

    #[test]
    fn published_inventory_detects_late_same_inode_content_mutation() {
        let (_root, source, destination, workspace) = fixture();
        let planned_source = fs::read(&source).expect("read planned source");
        let mut mutated_bytes = planned_source.clone();
        mutated_bytes[0] ^= 0xff;
        let plan = plan(&source, &destination, &workspace);
        let mut mutated = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforeArtifactInventory && !mutated {
                    mutated = true;
                    let mut published = OpenOptions::new()
                        .write(true)
                        .open(&destination)
                        .expect("open published destination inode");
                    published
                        .seek(SeekFrom::Start(0))
                        .and_then(|_| published.write_all(&mutated_bytes))
                        .expect("rewrite published destination in place");
                    published
                        .sync_all()
                        .expect("synchronize published destination mutation");
                }
            },
        );

        assert!(mutated, "test must mutate after publication checks");
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(result.outcome(), None);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert!(result.milestones().contains(&OperationMilestone::Published));
        let published = retained_artifact(&result, OperationArtifactRole::PublishedDestination);
        assert_eq!(published.path_identity_matches(), Some(true));
        assert_eq!(published.length(), Some(planned_source.len() as u64));
        assert_eq!(
            published.sha256(),
            Some(Sha256Digest::digest(&mutated_bytes))
        );
        assert_eq!(
            published.recorded_sha256(),
            Some(Sha256Digest::digest(&planned_source))
        );
        assert_eq!(fs::read(&destination).unwrap(), mutated_bytes);
    }

    #[test]
    fn published_inventory_detects_late_destination_identity_change() {
        let (_root, source, destination, workspace) = fixture();
        let planned_source = fs::read(&source).expect("read planned source");
        let competing_bytes = b"competing destination bytes";
        let plan = plan(&source, &destination, &workspace);
        let mut replaced = false;
        let mut held_published: Option<File> = None;
        let mut original_identity: Option<FileIdentity> = None;
        let mut competing_identity: Option<FileIdentity> = None;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforeArtifactInventory && !replaced {
                    replaced = true;
                    let held = File::open(&destination).expect("hold published destination inode");
                    original_identity = handle_identity(&held);
                    fs::remove_file(&destination).expect("remove published destination");
                    fs::write(&destination, competing_bytes)
                        .expect("create competing destination entry");
                    competing_identity =
                        handle_identity(&File::open(&destination).expect("open competing entry"));
                    held_published = Some(held);
                }
            },
        );

        assert!(
            replaced,
            "test must replace the destination before inventory"
        );
        assert!(held_published.is_some());
        assert_ne!(original_identity, competing_identity);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(result.outcome(), None);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert!(result.milestones().contains(&OperationMilestone::Published));
        let published = retained_artifact(&result, OperationArtifactRole::PublishedDestination);
        assert_eq!(published.path_identity_matches(), Some(false));
        assert_eq!(
            published.path_device(),
            competing_identity.map(|identity| identity.device())
        );
        assert_eq!(
            published.path_inode(),
            competing_identity.map(|identity| identity.inode())
        );
        assert_eq!(published.length(), Some(planned_source.len() as u64));
        assert_eq!(
            published.sha256(),
            Some(Sha256Digest::digest(&planned_source))
        );
        assert_eq!(published.path_length(), Some(competing_bytes.len() as u64));
        assert_eq!(
            published.recorded_length(),
            Some(planned_source.len() as u64)
        );
        assert_eq!(
            published.recorded_sha256(),
            Some(Sha256Digest::digest(&planned_source))
        );
        assert_eq!(fs::read(&destination).unwrap(), competing_bytes);
    }

    #[test]
    fn published_inventory_revalidates_destination_name_after_content_read() {
        let (root, source, destination, workspace) = fixture();
        let planned_source = fs::read(&source).expect("read planned source");
        let competing_bytes = b"destination retargeted after inventory hashing";
        let displaced = root.path().join("displaced-published-output.bin");
        let expected_destination_path = fs::canonicalize(destination.parent().unwrap())
            .unwrap()
            .join(destination.file_name().unwrap());
        let plan = plan(&source, &destination, &workspace);
        let mut retargeted = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AfterPublishedDestinationContentInspection
                    && !retargeted
                {
                    retargeted = true;
                    fs::rename(&destination, &displaced)
                        .expect("displace the published destination after hashing");
                    fs::write(&destination, competing_bytes)
                        .expect("install a late destination name");
                }
            },
        );

        assert!(
            retargeted,
            "test must retarget after published content hashing"
        );
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert_eq!(fs::read(&destination).unwrap(), competing_bytes);
        assert_eq!(fs::read(&displaced).unwrap(), planned_source);

        let published = retained_artifact(&result, OperationArtifactRole::PublishedDestination);
        let competing_identity =
            handle_identity(&File::open(&destination).expect("open late destination"));
        assert_eq!(published.path_identity_matches(), Some(false));
        assert_eq!(
            published.path_device(),
            competing_identity.map(|identity| identity.device())
        );
        assert_eq!(
            published.path_inode(),
            competing_identity.map(|identity| identity.inode())
        );
        assert_eq!(published.path_length(), Some(competing_bytes.len() as u64));
        assert!(!result.artifacts().iter().any(|artifact| {
            artifact.role() == OperationArtifactRole::UncertainEntry
                && artifact.path() == expected_destination_path
        }));
        assert_cleanup_incomplete(&result);
        assert_eq!(
            result.retained_storage_bytes(),
            Some(planned_source.len() as u64)
        );
    }

    #[test]
    fn published_inventory_detects_late_destination_removal() {
        let (_root, source, destination, workspace) = fixture();
        let planned_source = fs::read(&source).expect("read planned source");
        let plan = plan(&source, &destination, &workspace);
        let mut removed = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforeArtifactInventory && !removed {
                    removed = true;
                    fs::remove_file(&destination).expect("remove published destination");
                }
            },
        );

        assert!(removed, "test must remove the destination before inventory");
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(result.outcome(), None);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert!(result.milestones().contains(&OperationMilestone::Published));
        let published = retained_artifact(&result, OperationArtifactRole::PublishedDestination);
        assert_eq!(published.path_identity_matches(), None);
        assert_eq!(published.length(), Some(planned_source.len() as u64));
        assert_eq!(
            published.sha256(),
            Some(Sha256Digest::digest(&planned_source))
        );
        assert_eq!(published.path_length(), None);
        assert_eq!(
            published.recorded_sha256(),
            Some(Sha256Digest::digest(&planned_source))
        );
        assert!(!destination.exists());
    }

    #[test]
    fn late_fail_destination_competitor_is_hashed_and_counted_separately() {
        let (_root, source, destination, workspace) = fixture();
        let planned_source = fs::read(&source).expect("read planned source");
        let competing_bytes = b"late Fail-policy competitor has distinct bytes";
        let competing_path = workspace.join("late-fail-competitor.bin");
        let expected_destination_path = fs::canonicalize(destination.parent().unwrap())
            .unwrap()
            .join(destination.file_name().unwrap());
        let plan = plan(&source, &destination, &workspace);
        let mut replaced = false;
        let mut held_published: Option<File> = None;
        let mut published_identity = None;
        let mut competing_identity = None;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforeArtifactInventory && !replaced {
                    replaced = true;
                    let held = File::open(&destination).expect("hold published inode");
                    published_identity = handle_identity(&held);
                    held_published = Some(held);
                    fs::write(&competing_path, competing_bytes).expect("write competitor");
                    fs::rename(&competing_path, &destination).expect("replace published name");
                    competing_identity =
                        handle_identity(&File::open(&destination).expect("open competitor"));
                }
            },
        );

        assert!(
            replaced,
            "test must replace the name after publication checks"
        );
        assert!(held_published.is_some());
        assert_ne!(published_identity, competing_identity);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert_eq!(fs::read(&destination).unwrap(), competing_bytes);

        let published = retained_artifact(&result, OperationArtifactRole::PublishedDestination);
        assert_eq!(
            published.device().zip(published.inode()),
            published_identity.map(|identity| (identity.device(), identity.inode()))
        );
        assert_eq!(published.path_identity_matches(), Some(false));
        assert_eq!(
            published.path_device().zip(published.path_inode()),
            competing_identity.map(|identity| (identity.device(), identity.inode()))
        );
        assert_eq!(published.length(), Some(planned_source.len() as u64));
        assert_eq!(
            published.sha256(),
            Some(Sha256Digest::digest(&planned_source))
        );
        assert_eq!(published.path_length(), Some(competing_bytes.len() as u64));

        assert!(
            result.artifacts().iter().any(|artifact| {
                artifact.role() == OperationArtifactRole::UncertainEntry
                    && artifact.path() == expected_destination_path
            }),
            "inventory roles and paths: {:?}",
            result
                .artifacts()
                .iter()
                .map(|artifact| (artifact.role(), artifact.path().to_path_buf()))
                .collect::<Vec<_>>()
        );
        let competitor = result
            .artifacts()
            .iter()
            .find(|artifact| {
                artifact.role() == OperationArtifactRole::UncertainEntry
                    && artifact.path() == expected_destination_path
            })
            .expect("inventory must separate the competing destination entry");
        assert_eq!(
            competitor.device().zip(competitor.inode()),
            competing_identity.map(|identity| (identity.device(), identity.inode()))
        );
        assert_eq!(competitor.length(), Some(competing_bytes.len() as u64));
        assert_eq!(
            competitor.sha256(),
            Some(Sha256Digest::digest(competing_bytes))
        );
        assert_eq!(competitor.path_identity_matches(), Some(true));

        let staging = retained_artifact(&result, OperationArtifactRole::StagedOutput);
        assert!(staging.retained());
        assert_eq!(
            staging.device().zip(staging.inode()),
            published_identity.map(|identity| { (identity.device(), identity.inode()) })
        );
        assert_eq!(
            result.retained_storage_bytes(),
            Some((planned_source.len() + competing_bytes.len()) as u64)
        );
    }

    #[test]
    fn late_replace_destination_competitor_is_hashed_and_counted_separately() {
        let (_root, source, destination, workspace) = fixture();
        let old_destination = b"replacement baseline retained through inventory";
        let competing_bytes = b"late Replace-policy competitor has distinct bytes";
        fs::write(&destination, old_destination).expect("write destination baseline");
        let expected_destination_path = fs::canonicalize(destination.parent().unwrap())
            .unwrap()
            .join(destination.file_name().unwrap());
        let old_destination_identity =
            handle_identity(&File::open(&destination).unwrap()).expect("read baseline identity");
        let planned_source = fs::read(&source).expect("read planned source");
        let competing_path = workspace.join("late-replace-competitor.bin");
        let plan = plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace)
                .with_conflict_policy(ConflictPolicy::Replace),
        )
        .expect("plan explicit replacement");
        let mut replaced = false;
        let mut held_published: Option<File> = None;
        let mut published_identity = None;
        let mut competing_identity = None;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforeArtifactInventory && !replaced {
                    replaced = true;
                    let held = File::open(&destination).expect("hold published inode");
                    published_identity = handle_identity(&held);
                    held_published = Some(held);
                    fs::write(&competing_path, competing_bytes).expect("write competitor");
                    fs::rename(&competing_path, &destination).expect("replace published name");
                    competing_identity =
                        handle_identity(&File::open(&destination).expect("open competitor"));
                }
            },
        );

        assert!(
            replaced,
            "test must replace the name after publication checks"
        );
        assert!(held_published.is_some());
        assert_ne!(published_identity, competing_identity);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert_eq!(fs::read(&destination).unwrap(), competing_bytes);

        let published = retained_artifact(&result, OperationArtifactRole::PublishedDestination);
        assert_eq!(
            published.device().zip(published.inode()),
            published_identity.map(|identity| (identity.device(), identity.inode()))
        );
        assert_eq!(published.path_identity_matches(), Some(false));
        assert_eq!(
            published.path_device().zip(published.path_inode()),
            competing_identity.map(|identity| (identity.device(), identity.inode()))
        );
        assert_eq!(published.length(), Some(planned_source.len() as u64));
        assert_eq!(
            published.sha256(),
            Some(Sha256Digest::digest(&planned_source))
        );

        assert!(
            result.artifacts().iter().any(|artifact| {
                artifact.role() == OperationArtifactRole::UncertainEntry
                    && artifact.path() == expected_destination_path
            }),
            "inventory roles and paths: {:?}",
            result
                .artifacts()
                .iter()
                .map(|artifact| (artifact.role(), artifact.path().to_path_buf()))
                .collect::<Vec<_>>()
        );
        let competitor = result
            .artifacts()
            .iter()
            .find(|artifact| {
                artifact.role() == OperationArtifactRole::UncertainEntry
                    && artifact.path() == expected_destination_path
            })
            .expect("inventory must separate the competing destination entry");
        assert_eq!(
            competitor.device().zip(competitor.inode()),
            competing_identity.map(|identity| (identity.device(), identity.inode()))
        );
        assert_eq!(competitor.length(), Some(competing_bytes.len() as u64));
        assert_eq!(
            competitor.sha256(),
            Some(Sha256Digest::digest(competing_bytes))
        );
        assert_eq!(competitor.path_identity_matches(), Some(true));

        let recovery = result
            .artifacts()
            .iter()
            .find(|artifact| {
                artifact.retained()
                    && artifact.role() == OperationArtifactRole::StagedOutput
                    && artifact.device().zip(artifact.inode())
                        == published_identity.map(|identity| (identity.device(), identity.inode()))
            })
            .expect("replacement must retain a recovery alias for the published inode");
        assert_eq!(recovery.length(), Some(planned_source.len() as u64));
        assert_eq!(
            recovery.sha256(),
            Some(Sha256Digest::digest(&planned_source))
        );

        let displaced = retained_artifact(&result, OperationArtifactRole::DisplacedDestination);
        assert_eq!(
            displaced.device().zip(displaced.inode()),
            Some((
                old_destination_identity.device(),
                old_destination_identity.inode()
            ))
        );
        assert_eq!(displaced.length(), Some(old_destination.len() as u64));
        assert_eq!(
            displaced.sha256(),
            Some(Sha256Digest::digest(old_destination))
        );

        let mut retained_identities = std::collections::BTreeMap::new();
        for artifact in result.artifacts().iter().filter(|artifact| {
            artifact.retained()
                && matches!(
                    artifact.role(),
                    OperationArtifactRole::StagedOutput
                        | OperationArtifactRole::DestinationBackup
                        | OperationArtifactRole::DisplacedDestination
                        | OperationArtifactRole::UncertainEntry
                )
        }) {
            retained_identities.insert(
                (artifact.device().unwrap(), artifact.inode().unwrap()),
                artifact.length().unwrap(),
            );
        }
        let expected_retained_bytes = retained_identities.values().sum::<u64>();
        assert_eq!(
            result.retained_storage_bytes(),
            Some(expected_retained_bytes)
        );
        assert!(retained_identities.contains_key(&(
            competing_identity.unwrap().device(),
            competing_identity.unwrap().inode()
        )));
    }

    #[test]
    fn fail_linkat_competitor_is_inventoried_with_content_evidence() {
        let (_root, source, destination, workspace) = fixture();
        let planned_source = fs::read(&source).expect("read planned source");
        let competing_bytes = b"Fail competitor inserted at the no-clobber syscall";
        let expected_destination_path = fs::canonicalize(destination.parent().unwrap())
            .unwrap()
            .join(destination.file_name().unwrap());
        let plan = plan(&source, &destination, &workspace);
        let mut inserted = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AtomicPromotionStarted && !inserted {
                    fs::write(&destination, competing_bytes).expect("insert Fail competitor");
                    inserted = true;
                }
            },
        );

        assert!(inserted);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::DestinationChanged
        );
        assert_eq!(fs::read(&destination).unwrap(), competing_bytes);

        let competitor = destination_competitor(&result, &expected_destination_path);
        let destination_file = File::open(&destination).expect("open competing destination");
        let destination_identity =
            handle_identity(&destination_file).expect("read competing identity");
        assert_eq!(
            competitor.device().zip(competitor.inode()),
            Some((destination_identity.device(), destination_identity.inode()))
        );
        assert_eq!(competitor.length(), Some(competing_bytes.len() as u64));
        assert_eq!(
            competitor.sha256(),
            Some(Sha256Digest::digest(competing_bytes))
        );
        assert_eq!(competitor.path_identity_matches(), Some(true));
        assert_eq!(
            result.retained_storage_bytes(),
            Some((planned_source.len() + competing_bytes.len()) as u64)
        );
    }

    #[test]
    fn fail_linkat_competitor_vanished_before_capture_is_uncertain() {
        let (_root, source, destination, workspace) = fixture();
        let planned_source = fs::read(&source).expect("read planned source");
        let competing_bytes = b"Fail competitor removed before capture";
        let expected_destination_path = fs::canonicalize(destination.parent().unwrap())
            .unwrap()
            .join(destination.file_name().unwrap());
        let plan = plan(&source, &destination, &workspace);
        let mut inserted = false;
        let mut vanished = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| match checkpoint {
                ExecutionCheckpoint::AtomicPromotionStarted if !inserted => {
                    fs::write(&destination, competing_bytes).expect("insert Fail competitor");
                    inserted = true;
                }
                ExecutionCheckpoint::DestinationCompetitorBeforeOpen => {
                    fs::remove_file(&destination)
                        .expect("remove competitor before first capture open");
                    vanished = true;
                }
                _ => {}
            },
        );

        assert!(inserted, "test must force no-clobber EEXIST");
        assert!(vanished, "test must vanish the competitor before capture");
        assert!(!destination.exists());
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        let competitor = result
            .artifacts()
            .iter()
            .find(|artifact| {
                artifact.role() == OperationArtifactRole::UncertainEntry
                    && artifact.path() == expected_destination_path
            })
            .expect("vanished competitor must remain inventoried as uncertain");
        assert!(!competitor.retained());
        assert_eq!(competitor.device(), None);
        assert_eq!(competitor.inode(), None);
        assert_eq!(competitor.length(), None);
        assert_eq!(competitor.sha256(), None);
        assert_eq!(competitor.path_identity_matches(), None);
        assert_eq!(competitor.recorded_length(), None);
        assert_eq!(competitor.recorded_sha256(), None);
        assert!(result.cleanup_artifact_retained());
        assert_eq!(
            result.cleanup_warning().map(|warning| warning.code()),
            Some(OperationFailureCode::CleanupIncomplete)
        );
        assert_eq!(
            result.retained_storage_bytes(),
            Some(planned_source.len() as u64)
        );
    }

    #[test]
    fn unverified_destination_competitor_is_inventoried_without_retention_claim() {
        let (_root, source, destination, workspace) = fixture();
        let planned_source = fs::read(&source).expect("read planned source");
        let first_bytes = b"competitor bytes first";
        let second_bytes = b"competitor bytes later";
        assert_eq!(first_bytes.len(), second_bytes.len());
        let expected_destination_path = fs::canonicalize(destination.parent().unwrap())
            .unwrap()
            .join(destination.file_name().unwrap());
        let plan = plan(&source, &destination, &workspace);
        let mut inserted = false;
        let mut mutated = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| match checkpoint {
                ExecutionCheckpoint::AtomicPromotionStarted if !inserted => {
                    fs::write(&destination, first_bytes).expect("insert Fail competitor");
                    inserted = true;
                }
                ExecutionCheckpoint::DestinationCompetitorFirstRead if !mutated => {
                    fs::write(&destination, second_bytes)
                        .expect("mutate competitor after its first inspection");
                    mutated = true;
                }
                _ => {}
            },
        );

        assert!(inserted);
        assert!(mutated);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert_eq!(fs::read(&destination).unwrap(), second_bytes);

        let competitor = result
            .artifacts()
            .iter()
            .find(|artifact| {
                artifact.role() == OperationArtifactRole::UncertainEntry
                    && artifact.path() == expected_destination_path
            })
            .expect("unverified competitor must remain inventoried");
        assert!(!competitor.retained(), "{competitor:?}");
        assert_eq!(competitor.recorded_sha256(), None);
        assert_eq!(
            competitor.sha256(),
            Some(Sha256Digest::digest(second_bytes))
        );
        assert_eq!(competitor.path_identity_matches(), Some(true));
        assert_eq!(
            result.retained_storage_bytes(),
            Some(planned_source.len() as u64)
        );
    }

    #[test]
    fn replace_baseline_competitor_is_inventoried_before_promotion() {
        let (_root, source, destination, workspace) = fixture();
        let old_destination = b"Replace baseline replaced after lock acquisition";
        let competing_bytes = b"Replace competitor observed before promotion";
        fs::write(&destination, old_destination).expect("write Replace baseline");
        let expected_destination_path = fs::canonicalize(destination.parent().unwrap())
            .unwrap()
            .join(destination.file_name().unwrap());
        let plan = plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace)
                .with_conflict_policy(ConflictPolicy::Replace),
        )
        .expect("plan explicit replacement");
        let mut replaced = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforeAtomicPromotion && !replaced {
                    fs::write(&destination, competing_bytes)
                        .expect("replace destination baseline before promotion");
                    replaced = true;
                }
            },
        );

        assert!(replaced);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::DestinationChanged
        );
        assert_eq!(fs::read(&destination).unwrap(), competing_bytes);

        let competitor = destination_competitor(&result, &expected_destination_path);
        let destination_file = File::open(&destination).expect("open competing destination");
        let destination_identity =
            handle_identity(&destination_file).expect("read competing identity");
        assert_eq!(
            competitor.device().zip(competitor.inode()),
            Some((destination_identity.device(), destination_identity.inode()))
        );
        assert_eq!(competitor.length(), Some(competing_bytes.len() as u64));
        assert_eq!(
            competitor.sha256(),
            Some(Sha256Digest::digest(competing_bytes))
        );
        assert_eq!(competitor.path_identity_matches(), Some(true));
    }

    #[test]
    fn published_bytes_remain_inventoried_when_evidence_recording_fails_after_linkat() {
        let (_root, source, destination, workspace) = fixture();
        let planned_source = fs::read(&source).expect("read planned source");
        let plan = plan(&source, &destination, &workspace);
        let mut removed = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AfterNoClobberLinkBeforeEvidence && !removed {
                    removed = true;
                    fs::remove_file(&destination)
                        .expect("remove destination after successful linkat");
                }
            },
        );

        assert!(removed, "test must remove the destination after linkat");
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(result.outcome(), None);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert!(result.milestones().contains(&OperationMilestone::Published));

        let published = retained_artifact(&result, OperationArtifactRole::PublishedDestination);
        let expected_published_path = fs::canonicalize(destination.parent().unwrap())
            .unwrap()
            .join(destination.file_name().unwrap());
        assert_eq!(published.path(), expected_published_path);
        assert_eq!(published.path_identity_matches(), None);
        assert_eq!(
            published.recorded_length(),
            Some(planned_source.len() as u64)
        );
        assert_eq!(
            published.recorded_sha256(),
            Some(Sha256Digest::digest(&planned_source))
        );
        assert!(!published.path().exists());

        let recovery = result
            .artifacts()
            .iter()
            .find(|artifact| {
                artifact.retained()
                    && artifact.path().exists()
                    && fs::read(artifact.path()).ok().as_deref() == Some(&planned_source)
            })
            .expect("inventory must retain the published bytes under a recovery path");
        assert_eq!(
            recovery.sha256(),
            Some(Sha256Digest::digest(&planned_source))
        );
        assert_eq!(fs::read(recovery.path()).unwrap(), planned_source);
        assert!(result.cleanup_artifact_retained());
    }

    #[test]
    fn retained_verified_competitor_alias_uses_uncertain_role_with_complete_identity_evidence() {
        let (_root, source, destination, workspace) = fixture();
        let planned_source = fs::read(&source).expect("read planned source");
        let competing_bytes = vec![b'x'; planned_source.len()];
        let plan = plan(&source, &destination, &workspace);
        let mut replaced = false;
        let mut held_published: Option<File> = None;
        let mut published_identity: Option<FileIdentity> = None;
        let mut competing_identity: Option<FileIdentity> = None;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AfterNoClobberLinkBeforeEvidence && !replaced
                {
                    replaced = true;
                    let held = File::open(&destination).expect("hold published inode");
                    published_identity = handle_identity(&held);
                    fs::remove_file(&destination).expect("remove linked destination");
                    fs::write(&destination, &competing_bytes)
                        .expect("create competing destination entry");
                    competing_identity =
                        handle_identity(&File::open(&destination).expect("open competitor"));
                    held_published = Some(held);
                }
            },
        );

        assert!(
            replaced,
            "test must replace the name after successful linkat"
        );
        assert!(held_published.is_some());
        assert_ne!(published_identity, competing_identity);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(result.outcome(), None);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert!(result.milestones().contains(&OperationMilestone::Published));

        let published = retained_artifact(&result, OperationArtifactRole::PublishedDestination);
        assert_eq!(
            published.device().zip(published.inode()),
            published_identity.map(|identity| (identity.device(), identity.inode()))
        );
        assert_eq!(published.length(), Some(planned_source.len() as u64));
        assert_eq!(
            published.sha256(),
            Some(Sha256Digest::digest(&planned_source))
        );
        assert_eq!(published.path_identity_matches(), Some(false));
        assert_eq!(
            published.path_device().zip(published.path_inode()),
            competing_identity.map(|identity| (identity.device(), identity.inode()))
        );
        assert_eq!(published.path_length(), Some(competing_bytes.len() as u64));
        assert_eq!(
            published.recorded_sha256(),
            Some(Sha256Digest::digest(&planned_source))
        );

        let competitor = retained_artifact(&result, OperationArtifactRole::UncertainEntry);
        assert_eq!(
            competitor.device().zip(competitor.inode()),
            competing_identity.map(|identity| (identity.device(), identity.inode()))
        );
        assert_eq!(competitor.length(), Some(competing_bytes.len() as u64));
        assert_eq!(
            competitor.sha256(),
            Some(Sha256Digest::digest(&competing_bytes))
        );
        assert_eq!(competitor.path_identity_matches(), Some(true));
        assert_eq!(fs::read(&destination).unwrap(), competing_bytes);

        let staging = retained_artifact(&result, OperationArtifactRole::StagedOutput);
        assert!(staging.retained());
        assert_eq!(staging.path_identity_matches(), Some(true));
        assert_eq!(
            staging.device().zip(staging.inode()),
            published_identity.map(|identity| (identity.device(), identity.inode()))
        );
        assert_eq!(staging.length(), Some(planned_source.len() as u64));
        assert_eq!(
            staging.sha256(),
            Some(Sha256Digest::digest(&planned_source))
        );
        assert_eq!(fs::read(staging.path()).unwrap(), planned_source);
        assert_eq!(
            result.retained_storage_bytes(),
            Some((planned_source.len() + competing_bytes.len()) as u64)
        );
    }

    #[test]
    fn cloned_session_rejects_concurrent_work_and_cancels_before_promotion() {
        let (_root, source, first_destination, workspace) = fixture();
        let second_destination = workspace.join("second-output.bin");
        let first_plan = plan(&source, &first_destination, &workspace);
        let second_plan = plan(&source, &second_destination, &workspace);
        let session = OperationSession::new();
        let worker_session = session.clone();
        let (entered_sender, entered_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            execute_with_producer(first_plan, &worker_session, |source, stage, _| {
                source
                    .seek(SeekFrom::Start(0))
                    .map_err(|_| OperationFailureCode::SourceUnavailable)?;
                std::io::copy(source, stage).map_err(|_| OperationFailureCode::WriteFailed)?;
                entered_sender.send(()).unwrap();
                release_receiver.recv().unwrap();
                Ok(())
            })
        });

        entered_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("worker reached its staging producer");
        let busy = execute_with_producer(second_plan, &session, |_, _, _| Ok(()));
        assert_eq!(busy.failure().unwrap().code(), OperationFailureCode::Busy);
        assert!(session.cancel());
        release_sender.send(()).unwrap();
        let cancelled = worker.join().unwrap();

        assert_eq!(cancelled.state(), JobState::Cancelled, "{cancelled:?}");
        assert_eq!(
            cancelled.failure().unwrap().code(),
            OperationFailureCode::Cancelled
        );
        assert_cleanup_incomplete(&cancelled);
        let staged = retained_artifact(&cancelled, OperationArtifactRole::StagedOutput);
        let planned_source = fs::read(&source).expect("read planned source bytes");
        assert_eq!(staged.length(), Some(planned_source.len() as u64));
        assert_eq!(staged.sha256(), Some(Sha256Digest::digest(&planned_source)));
        assert_eq!(fs::read(staged.path()).unwrap(), planned_source);
        assert!(!session.is_busy());
        assert!(!first_destination.exists());
        assert!(!second_destination.exists());
    }

    #[test]
    fn cancellation_at_destination_lock_acquisition_creates_no_owned_artifacts() {
        let root = tempfile::tempdir().expect("create cancellation fixture");
        let source = root.path().join("source.bin");
        let destination = root.path().join("destination.bin");
        let workspace = root.path().join("workspace");
        fs::write(&source, b"cancel before workspace creation").expect("write source fixture");
        let plan = plan(&source, &destination, &workspace);
        let session = OperationSession::new();
        let mut cancellation_accepted = false;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &session,
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::DestinationLockAcquired {
                    cancellation_accepted = session.cancel();
                }
            },
        );

        assert!(cancellation_accepted);
        assert_eq!(result.state(), JobState::Cancelled, "{result:?}");
        assert_eq!(
            result.failure().map(OperationFailure::code),
            Some(OperationFailureCode::Cancelled)
        );
        assert!(result.artifacts().is_empty(), "{result:?}");
        assert!(!result.cleanup_artifact_retained(), "{result:?}");
        assert!(!workspace.exists());
        assert!(!destination.exists());
        assert!(!session.is_busy());
        let current = session
            .current_operation()
            .expect("read terminal session state");
        assert_eq!(current.phase(), OperationSessionPhase::Idle);
        assert_eq!(current.status(), OperationSessionStatus::Cancelled);
        assert_eq!(current.failure(), Some(OperationFailureCode::Cancelled));
    }

    #[test]
    fn cancellation_is_refused_during_the_atomic_promotion_syscall_window() {
        let session = OperationSession::new();
        let _admission = session.admit().expect("admit test operation");
        assert!(session.begin_promotion().unwrap());
        assert!(!session.cancel());
        assert!(session.is_busy());
    }

    #[test]
    fn finished_admission_guard_drop_does_not_clear_a_newer_shared_session_operation() {
        let session_a = OperationSession::new();
        let mut admission_a = session_a.admit().expect("admit operation A");
        let result_a = failed_result(
            vec![OperationMilestone::Planned],
            OperationFailureCode::WriteFailed,
            false,
        );
        admission_a.finish(&result_a);

        // A completed guard is inactive before a later operation can be
        // admitted. Dropping it afterward must not clear that newer operation.
        let session_b = session_a.clone();
        let admission_b = session_b.admit().expect("admit operation B");
        drop(admission_a);

        let current = session_a.current_operation().unwrap();
        assert!(session_a.is_busy());
        assert_eq!(current.phase(), OperationSessionPhase::Executing);
        assert_eq!(current.status(), OperationSessionStatus::Running);
        assert_eq!(current.milestone(), Some(OperationMilestone::Executing));

        let session_c = session_a.clone();
        assert_eq!(session_c.admit().err(), Some(OperationFailureCode::Busy));

        drop(admission_b);
        assert!(!session_a.is_busy());
    }

    #[test]
    fn late_fail_competitor_anchor_survives_second_replacement() {
        assert_late_competitor_anchor_survives_second_replacement(ConflictPolicy::Fail);
    }

    #[test]
    fn late_replace_competitor_anchor_survives_second_replacement() {
        assert_late_competitor_anchor_survives_second_replacement(ConflictPolicy::Replace);
    }

    fn assert_late_competitor_anchor_survives_second_replacement(policy: ConflictPolicy) {
        let (_root, source, destination, workspace) = fixture();
        let old_destination = b"replacement baseline bytes";
        if policy == ConflictPolicy::Replace {
            fs::write(&destination, old_destination).expect("write replacement baseline");
        }
        let planned_source = fs::read(&source).expect("read planned source");
        let first_bytes: &[u8] = b"first competitor retained by operation alias";
        let second_bytes: &[u8] = b"second competitor remains at destination";
        let first_temporary = workspace.join("first-competitor.tmp");
        let second_temporary = workspace.join("second-competitor.tmp");
        let plan = plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace).with_conflict_policy(policy),
        )
        .expect("plan copy-through");
        let expected_destination = fs::canonicalize(destination.parent().unwrap())
            .unwrap()
            .join(destination.file_name().unwrap());
        let mut first_replaced = false;
        let mut second_replaced = false;
        let mut first_identity = None;
        let mut second_identity = None;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| match checkpoint {
                ExecutionCheckpoint::BeforeArtifactInventory if !first_replaced => {
                    first_replaced = true;
                    fs::write(&first_temporary, first_bytes).expect("write first competitor");
                    fs::rename(&first_temporary, &destination)
                        .expect("replace published destination with first competitor");
                    first_identity = Some(
                        handle_identity(&File::open(&destination).expect("open first competitor"))
                            .expect("read first competitor identity"),
                    );
                }
                ExecutionCheckpoint::AfterCompetitorRetention if !second_replaced => {
                    second_replaced = true;
                    fs::write(&second_temporary, second_bytes).expect("write second competitor");
                    fs::rename(&second_temporary, &destination)
                        .expect("replace destination with second competitor");
                    second_identity = Some(
                        handle_identity(&File::open(&destination).expect("open second competitor"))
                            .expect("read second competitor identity"),
                    );
                }
                _ => {}
            },
        );

        assert!(first_replaced, "test must install the first competitor");
        assert!(
            second_replaced,
            "test must replace the destination after the first competitor is anchored"
        );
        let first_identity = first_identity.expect("record first competitor identity");
        let second_identity = second_identity.expect("record second competitor identity");
        assert_ne!(first_identity, second_identity);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(result.outcome(), None);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert_eq!(fs::read(&destination).unwrap(), second_bytes);

        let observed_destination = result
            .artifacts()
            .iter()
            .find(|artifact| {
                artifact.role() == OperationArtifactRole::UncertainEntry
                    && artifact.path() == expected_destination
            })
            .expect("inventory current destination entry separately");
        assert!(!observed_destination.retained());
        assert_eq!(
            observed_destination
                .device()
                .zip(observed_destination.inode()),
            Some((second_identity.device(), second_identity.inode()))
        );
        assert_eq!(
            observed_destination.length(),
            Some(second_bytes.len() as u64)
        );
        assert_eq!(
            observed_destination.sha256(),
            Some(Sha256Digest::digest(second_bytes))
        );
        assert_eq!(fs::read(observed_destination.path()).unwrap(), second_bytes);

        let retained_first = result
            .artifacts()
            .iter()
            .find(|artifact| {
                artifact.role() == OperationArtifactRole::UncertainEntry
                    && artifact.path() != expected_destination
                    && artifact.device().zip(artifact.inode())
                        == Some((first_identity.device(), first_identity.inode()))
            })
            .expect("inventory an operation-owned alias for the first competitor");
        assert!(retained_first.retained());
        assert_eq!(retained_first.path_identity_matches(), Some(true));
        assert_eq!(retained_first.length(), Some(first_bytes.len() as u64));
        assert_eq!(
            retained_first.sha256(),
            Some(Sha256Digest::digest(first_bytes))
        );
        assert_eq!(fs::read(retained_first.path()).unwrap(), first_bytes);

        let retained_second = result
            .artifacts()
            .iter()
            .find(|artifact| {
                artifact.role() == OperationArtifactRole::UncertainEntry
                    && artifact.path() != expected_destination
                    && artifact.device().zip(artifact.inode())
                        == Some((second_identity.device(), second_identity.inode()))
            })
            .expect("inventory an operation-owned alias for the second competitor");
        assert!(retained_second.retained());
        assert_eq!(retained_second.path_identity_matches(), Some(true));
        assert_eq!(retained_second.length(), Some(second_bytes.len() as u64));
        assert_eq!(
            retained_second.sha256(),
            Some(Sha256Digest::digest(second_bytes))
        );
        assert_eq!(fs::read(retained_second.path()).unwrap(), second_bytes);

        let planned_output_digest = Sha256Digest::digest(&planned_source);
        let retained_planned_output = result
            .artifacts()
            .iter()
            .find(|artifact| {
                artifact.retained()
                    && artifact.path_identity_matches() == Some(true)
                    && artifact.length() == Some(planned_source.len() as u64)
                    && artifact.sha256() == Some(planned_output_digest)
            })
            .expect("planned output bytes remain available through a verified alias");
        assert_eq!(
            fs::read(retained_planned_output.path()).unwrap(),
            planned_source
        );

        let mut retained_identities = std::collections::BTreeMap::new();
        for artifact in result.artifacts().iter().filter(|artifact| {
            artifact.retained()
                && matches!(
                    artifact.role(),
                    OperationArtifactRole::StagedOutput
                        | OperationArtifactRole::DestinationBackup
                        | OperationArtifactRole::DisplacedDestination
                        | OperationArtifactRole::UncertainEntry
                )
        }) {
            if let (Some(device), Some(inode), Some(length)) =
                (artifact.device(), artifact.inode(), artifact.length())
            {
                let previous = retained_identities.insert((device, inode), length);
                assert!(
                    previous.is_none_or(|previous| previous == length),
                    "one retained identity must not have conflicting lengths"
                );
            }
        }
        let accounted = retained_identities.values().copied().sum::<u64>();
        assert_eq!(result.retained_storage_bytes(), Some(accounted));
        assert_eq!(
            retained_identities.get(&(first_identity.device(), first_identity.inode())),
            Some(&(first_bytes.len() as u64))
        );
        assert_eq!(
            retained_identities.get(&(second_identity.device(), second_identity.inode())),
            Some(&(second_bytes.len() as u64))
        );
        if policy == ConflictPolicy::Fail {
            assert_eq!(
                result.retained_storage_bytes(),
                Some((planned_source.len() + first_bytes.len() + second_bytes.len()) as u64)
            );
        }
    }

    #[test]
    fn late_competitor_replaced_before_link_is_uncertain_and_not_counted() {
        let (_root, source, destination, workspace) = fixture();
        let observed_bytes: &[u8] = b"competitor observed before link";
        let replacement_bytes: &[u8] = b"different inode installed before link";
        let observed_path = workspace.join("before-link-observed.bin");
        let observed_temporary = workspace.join("before-link-observed.tmp");
        let replacement_temporary = workspace.join("before-link-replacement.tmp");
        let plan = plan_copy_through(CopyThroughRequest::new(&source, &destination, &workspace))
            .expect("plan copy-through");
        let expected_destination = fs::canonicalize(destination.parent().unwrap())
            .unwrap()
            .join(destination.file_name().unwrap());
        let mut competitor_installed = false;
        let mut link_race_installed = false;
        let mut observed_identity = None;
        let mut replacement_identity = None;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| match checkpoint {
                ExecutionCheckpoint::BeforeArtifactInventory if !competitor_installed => {
                    competitor_installed = true;
                    fs::write(&observed_temporary, observed_bytes)
                        .expect("write observed competitor");
                    fs::rename(&observed_temporary, &destination)
                        .expect("install observed competitor");
                    observed_identity = Some(
                        handle_identity(&File::open(&destination).expect("open competitor"))
                            .expect("read competitor identity"),
                    );
                }
                ExecutionCheckpoint::BeforeCompetitorLink if !link_race_installed => {
                    link_race_installed = true;
                    fs::rename(&destination, &observed_path)
                        .expect("preserve observed competitor for assertion");
                    fs::write(&replacement_temporary, replacement_bytes)
                        .expect("write replacement competitor");
                    fs::rename(&replacement_temporary, &destination)
                        .expect("replace destination before link");
                    replacement_identity = Some(
                        handle_identity(&File::open(&destination).expect("open replacement"))
                            .expect("read replacement identity"),
                    );
                }
                _ => {}
            },
        );

        assert!(competitor_installed);
        assert!(link_race_installed, "the pre-link checkpoint must run");
        let observed_identity = observed_identity.expect("record observed inode");
        let replacement_identity = replacement_identity.expect("record replacement inode");
        assert_ne!(observed_identity, replacement_identity);
        assert_eq!(fs::read(&observed_path).unwrap(), observed_bytes);
        assert_eq!(fs::read(&destination).unwrap(), replacement_bytes);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert!(!result.artifacts().iter().any(|artifact| {
            artifact.retained()
                && artifact.device().zip(artifact.inode())
                    == Some((observed_identity.device(), observed_identity.inode()))
        }));

        let mismatched_alias = result
            .artifacts()
            .iter()
            .find(|artifact| {
                artifact.role() == OperationArtifactRole::UncertainEntry
                    && artifact.path() != expected_destination
                    && artifact.device().zip(artifact.inode())
                        == Some((replacement_identity.device(), replacement_identity.inode()))
            })
            .expect("inventory the path-linked replacement separately");
        assert!(!mismatched_alias.retained());
        assert_eq!(mismatched_alias.path_identity_matches(), Some(true));
        assert_eq!(
            mismatched_alias.length(),
            Some(replacement_bytes.len() as u64)
        );
        assert_eq!(
            mismatched_alias.sha256(),
            Some(Sha256Digest::digest(replacement_bytes))
        );
        assert_eq!(
            fs::read(mismatched_alias.path()).unwrap(),
            replacement_bytes
        );

        let mut retained_identities = std::collections::BTreeMap::new();
        for artifact in result
            .artifacts()
            .iter()
            .filter(|artifact| artifact.retained())
        {
            if let (Some(device), Some(inode), Some(length)) =
                (artifact.device(), artifact.inode(), artifact.length())
            {
                let previous = retained_identities.insert((device, inode), length);
                assert!(previous.is_none_or(|previous| previous == length));
            }
        }
        assert!(
            !retained_identities
                .contains_key(&(observed_identity.device(), observed_identity.inode()))
        );
        assert_eq!(
            result.retained_storage_bytes(),
            Some(retained_identities.values().copied().sum())
        );
    }

    #[test]
    fn equal_content_pre_link_replacement_cannot_be_retained_as_observed_inode() {
        let (_root, source, destination, workspace) = fixture();
        let competitor_bytes: &[u8] = b"equal bytes on both competitor inodes";
        let first_temporary = workspace.join("equal-content-first.tmp");
        let replacement_temporary = workspace.join("equal-content-replacement.tmp");
        let plan = plan_copy_through(CopyThroughRequest::new(&source, &destination, &workspace))
            .expect("plan copy-through");
        let expected_destination = fs::canonicalize(destination.parent().unwrap())
            .unwrap()
            .join(destination.file_name().unwrap());
        let mut competitor_installed = false;
        let mut path_replaced_before_link = false;
        let mut observed_identity = None;
        let mut replacement_identity = None;
        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| match checkpoint {
                ExecutionCheckpoint::BeforeArtifactInventory if !competitor_installed => {
                    competitor_installed = true;
                    fs::write(&first_temporary, competitor_bytes)
                        .expect("write observed competitor");
                    fs::rename(&first_temporary, &destination)
                        .expect("install observed competitor");
                    observed_identity = Some(
                        handle_identity(&File::open(&destination).expect("open competitor"))
                            .expect("read competitor identity"),
                    );
                }
                ExecutionCheckpoint::BeforeCompetitorLink if !path_replaced_before_link => {
                    path_replaced_before_link = true;
                    fs::remove_file(&destination).expect("remove observed competitor name");
                    fs::write(&replacement_temporary, competitor_bytes)
                        .expect("write equal-content replacement");
                    fs::rename(&replacement_temporary, &destination)
                        .expect("install equal-content replacement");
                    replacement_identity = Some(
                        handle_identity(&File::open(&destination).expect("open replacement"))
                            .expect("read replacement identity"),
                    );
                }
                _ => {}
            },
        );

        assert!(competitor_installed);
        assert!(
            path_replaced_before_link,
            "the pre-link replacement checkpoint must run"
        );
        let observed_identity = observed_identity.expect("record observed competitor identity");
        let replacement_identity = replacement_identity.expect("record replacement identity");
        // Holding the observation descriptor keeps the original inode allocated,
        // so recreating the same bytes at the same name requires another inode.
        assert_ne!(observed_identity, replacement_identity);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );
        assert!(!result.artifacts().iter().any(|artifact| {
            artifact.retained()
                && artifact.device().zip(artifact.inode())
                    == Some((observed_identity.device(), observed_identity.inode()))
        }));
        let replacement_alias = result
            .artifacts()
            .iter()
            .find(|artifact| {
                artifact.role() == OperationArtifactRole::UncertainEntry
                    && artifact.path() != expected_destination
                    && artifact.device().zip(artifact.inode())
                        == Some((replacement_identity.device(), replacement_identity.inode()))
            })
            .expect("inventory the unverified path-linked replacement");
        assert!(!replacement_alias.retained());
        assert_eq!(replacement_alias.path_identity_matches(), Some(true));
        assert_eq!(
            replacement_alias.length(),
            Some(competitor_bytes.len() as u64)
        );
        assert_eq!(
            replacement_alias.sha256(),
            Some(Sha256Digest::digest(competitor_bytes))
        );
    }

    #[test]
    fn late_competitor_link_alias_survives_replacement_after_link() {
        let (_root, source, destination, workspace) = fixture();
        let planned_bytes = fs::read(&source).expect("read planned output");
        let first_bytes: &[u8] = b"inode linked before path replacement";
        let second_bytes: &[u8] = b"replacement after successful link";
        let first_temporary = workspace.join("after-link-first.tmp");
        let second_temporary = workspace.join("after-link-second.tmp");
        let plan = plan_copy_through(CopyThroughRequest::new(&source, &destination, &workspace))
            .expect("plan copy-through");
        let expected_destination = fs::canonicalize(destination.parent().unwrap())
            .unwrap()
            .join(destination.file_name().unwrap());
        let mut competitor_installed = false;
        let mut path_replaced_after_link = false;
        let mut first_identity = None;
        let mut second_identity = None;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &OperationSession::new(),
            copy_source_to_stage,
            |checkpoint| match checkpoint {
                ExecutionCheckpoint::BeforeArtifactInventory if !competitor_installed => {
                    competitor_installed = true;
                    fs::write(&first_temporary, first_bytes).expect("write first competitor");
                    fs::rename(&first_temporary, &destination).expect("install first competitor");
                    first_identity = Some(
                        handle_identity(&File::open(&destination).expect("open first competitor"))
                            .expect("read first competitor identity"),
                    );
                }
                ExecutionCheckpoint::AfterCompetitorLink if !path_replaced_after_link => {
                    path_replaced_after_link = true;
                    fs::write(&second_temporary, second_bytes).expect("write second competitor");
                    fs::rename(&second_temporary, &destination)
                        .expect("replace path after the alias was linked");
                    second_identity = Some(
                        handle_identity(&File::open(&destination).expect("open second competitor"))
                            .expect("read second competitor identity"),
                    );
                }
                _ => {}
            },
        );

        assert!(competitor_installed);
        assert!(
            path_replaced_after_link,
            "the post-link checkpoint must run"
        );
        let first_identity = first_identity.expect("record first competitor identity");
        let second_identity = second_identity.expect("record second competitor identity");
        assert_ne!(first_identity, second_identity);
        assert_eq!(fs::read(&destination).unwrap(), second_bytes);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::PublicationUncertain
        );

        for (identity, expected_bytes) in [
            (first_identity, first_bytes),
            (second_identity, second_bytes),
        ] {
            let retained = result
                .artifacts()
                .iter()
                .find(|artifact| {
                    artifact.role() == OperationArtifactRole::UncertainEntry
                        && artifact.path() != expected_destination
                        && artifact.device().zip(artifact.inode())
                            == Some((identity.device(), identity.inode()))
                })
                .expect("inventory a private alias for each competitor");
            assert!(retained.retained());
            assert_eq!(retained.path_identity_matches(), Some(true));
            assert_eq!(retained.length(), Some(expected_bytes.len() as u64));
            assert_eq!(
                retained.sha256(),
                Some(Sha256Digest::digest(expected_bytes))
            );
            assert_eq!(fs::read(retained.path()).unwrap(), expected_bytes);
        }

        let planned_output_digest = Sha256Digest::digest(&planned_bytes);
        let retained_planned_output = result
            .artifacts()
            .iter()
            .find(|artifact| {
                artifact.retained()
                    && artifact.path_identity_matches() == Some(true)
                    && artifact.length() == Some(planned_bytes.len() as u64)
                    && artifact.sha256() == Some(planned_output_digest)
            })
            .expect("planned output remains available through a verified alias");
        assert_eq!(
            fs::read(retained_planned_output.path()).unwrap(),
            planned_bytes
        );
    }

    #[test]
    fn destination_coordination_serializes_paths_proven_to_be_filesystem_aliases() {
        let (root, source, _destination, workspace) = fixture();
        let destination_parent = root.path().join("alias-destination-parent");
        fs::create_dir(&destination_parent).expect("create destination parent");
        let destination = destination_parent.join("Output.bin");
        let alias = destination_parent.join("output.bin");
        fs::write(&destination, b"planned destination baseline").expect("write baseline");

        let canonical_destination = fs::canonicalize(&destination).unwrap_or_else(|error| {
            panic!("ALIAS_TEST_STATUS=INCOMPLETE: cannot resolve destination spelling: {error}")
        });
        let canonical_alias = match fs::canonicalize(&alias) {
            Ok(path) => path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                eprintln!(
                    "ALIAS_TEST_STATUS=SKIPPED: filesystem resolves the spellings to distinct entries"
                );
                return;
            }
            Err(error) => {
                panic!("ALIAS_TEST_STATUS=INCOMPLETE: cannot resolve alias spelling: {error}")
            }
        };
        let destination_file = File::open(&destination).unwrap_or_else(|error| {
            panic!("ALIAS_TEST_STATUS=INCOMPLETE: cannot open destination spelling: {error}")
        });
        let alias_file = File::open(&alias).unwrap_or_else(|error| {
            panic!("ALIAS_TEST_STATUS=INCOMPLETE: cannot open alias spelling: {error}")
        });
        let destination_identity = handle_identity(&destination_file).unwrap_or_else(|| {
            panic!("ALIAS_TEST_STATUS=INCOMPLETE: destination identity is unavailable")
        });
        let alias_identity = handle_identity(&alias_file).unwrap_or_else(|| {
            panic!("ALIAS_TEST_STATUS=INCOMPLETE: alias identity is unavailable")
        });
        if canonical_destination != canonical_alias || destination_identity != alias_identity {
            eprintln!("ALIAS_TEST_STATUS=SKIPPED: spellings identify distinct directory entries");
            return;
        }
        eprintln!("ALIAS_TEST_STATUS=EXERCISED: both spellings identify the same directory entry");
        let plan_a = plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace)
                .with_conflict_policy(ConflictPolicy::Replace),
        )
        .expect("plan first alias operation");
        let plan_b = plan_copy_through(
            CopyThroughRequest::new(&source, &alias, &workspace)
                .with_conflict_policy(ConflictPolicy::Replace),
        )
        .expect("plan second alias operation");
        assert_eq!(
            plan_a.snapshot().destination_lock_path(),
            plan_b.snapshot().destination_lock_path(),
            "one filesystem parent must use one destination coordination lock"
        );

        let (acquired_sender, acquired_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let session_a = OperationSession::new();
        let worker_session_a = session_a.clone();
        let worker_a = std::thread::spawn(move || {
            let mut paused = false;
            execute_with_producer_and_checkpoint(
                plan_a,
                &worker_session_a,
                copy_source_to_stage,
                |checkpoint| {
                    if checkpoint == ExecutionCheckpoint::DestinationLockAcquired && !paused {
                        paused = true;
                        acquired_sender
                            .send(())
                            .expect("signal first lock acquired");
                        release_receiver
                            .recv()
                            .expect("wait to release first destination lock");
                    }
                },
            )
        });
        acquired_receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("first operation must hold the destination lock");

        let (waiting_sender, waiting_receiver) = std::sync::mpsc::channel();
        let session_b = OperationSession::new();
        let worker_session_b = session_b.clone();
        let worker_b = std::thread::spawn(move || {
            let mut reported_wait = false;
            execute_with_producer_and_checkpoint(
                plan_b,
                &worker_session_b,
                copy_source_to_stage,
                |checkpoint| {
                    if checkpoint == ExecutionCheckpoint::DestinationLockWait && !reported_wait {
                        reported_wait = true;
                        waiting_sender
                            .send(())
                            .expect("signal second operation is waiting");
                    }
                },
            )
        });
        let second_waited = waiting_receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .is_ok();
        release_sender
            .send(())
            .expect("release first destination lock");
        let result_a = worker_a.join().expect("join first operation");
        let result_b = worker_b.join().expect("join second operation");

        assert!(
            second_waited,
            "the alias operation must wait while the first session holds the parent lock"
        );
        assert_eq!(result_a.state(), JobState::Succeeded);
        assert_eq!(result_b.state(), JobState::Failed);
        assert_eq!(
            result_b.failure().unwrap().code(),
            OperationFailureCode::DestinationChanged
        );
        assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
    }

    #[test]
    fn cancellation_during_final_file_hashing_is_accepted_before_promotion() {
        let (_root, source, destination, workspace) = fixture();
        let planned_source = vec![0x5a; IO_BUFFER_SIZE * 3];
        fs::write(&source, &planned_source).expect("write multi-chunk source");
        let plan = plan(&source, &destination, &workspace);
        let session = OperationSession::new();
        let mut final_hash_chunks = 0;

        let result = execute_with_producer_and_checkpoint(
            plan,
            &session,
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::FinalValidationHashChunk {
                    final_hash_chunks += 1;
                    let snapshot = session.current_operation().unwrap();
                    assert_eq!(snapshot.phase(), OperationSessionPhase::Executing);
                    if final_hash_chunks == 1 {
                        assert_eq!(snapshot.status(), OperationSessionStatus::Running);
                        assert!(session.cancel());
                    }
                }
            },
        );

        assert!(
            final_hash_chunks >= 2,
            "final validation must hash by chunks"
        );
        assert_eq!(result.state(), JobState::Cancelled);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::Cancelled
        );
        assert!(!destination.exists());
        let terminal = session.current_operation().unwrap();
        assert_eq!(terminal.phase(), OperationSessionPhase::Idle);
        assert_eq!(terminal.status(), OperationSessionStatus::Cancelled);
    }

    #[test]
    fn cancellation_is_accepted_after_final_revalidation_until_promotion_starts() {
        let (_root, source, destination, workspace) = fixture();
        let session = OperationSession::new();
        let mut reached_boundary = false;

        let result = execute_with_producer_and_checkpoint(
            plan(&source, &destination, &workspace),
            &session,
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforeAtomicPromotion {
                    reached_boundary = true;
                    let current = session.current_operation().unwrap();
                    assert_eq!(current.phase(), OperationSessionPhase::Executing);
                    assert_eq!(current.status(), OperationSessionStatus::Running);
                    assert!(session.cancel());
                }
            },
        );

        assert!(
            reached_boundary,
            "final revalidation must reach the transition"
        );
        assert_eq!(result.state(), JobState::Cancelled);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::Cancelled
        );
        assert!(!destination.exists());
    }

    #[test]
    fn cancellation_accepted_at_finalization_boundary_is_not_ignored() {
        let (_root, source, destination, workspace) = fixture();
        let planned_source = fs::read(&source).expect("read planned source");
        let competing_bytes = b"destination competitor installed after staging".to_vec();
        let plan = plan(&source, &destination, &workspace);
        let session = OperationSession::new();
        let worker_session = session.clone();
        let checkpoint_session = session.clone();
        let destination_for_checkpoint = destination.clone();
        let competing_for_checkpoint = competing_bytes.clone();
        let (paused_sender, paused_receiver) = mpsc::channel();
        let (resume_sender, resume_receiver) = mpsc::channel();
        let operation = std::thread::spawn(move || {
            let reached_finalization = std::rc::Rc::new(std::cell::Cell::new(false));
            let reached_finalization_checkpoint = std::rc::Rc::clone(&reached_finalization);
            let mut paused = false;
            let result = execute_with_producer_and_checkpoint(
                plan,
                &worker_session,
                copy_source_to_stage,
                move |checkpoint| match checkpoint {
                    ExecutionCheckpoint::BeforePromotion => {
                        fs::write(&destination_for_checkpoint, &competing_for_checkpoint)
                            .expect("install destination competitor after staging");
                    }
                    ExecutionCheckpoint::BeforeFinalization => {
                        reached_finalization_checkpoint.set(true);
                        let current = checkpoint_session.current_operation().unwrap();
                        assert_eq!(current.phase(), OperationSessionPhase::Executing);
                        assert_eq!(current.status(), OperationSessionStatus::Running);
                        assert!(
                            checkpoint_session.cancel(),
                            "cancellation must still be accepted before finalization locks"
                        );
                    }
                    ExecutionCheckpoint::BeforeArtifactInventory if !paused => {
                        paused = true;
                        let current = checkpoint_session.current_operation().unwrap();
                        assert_eq!(current.phase(), OperationSessionPhase::Completing);
                        assert_eq!(
                            current.status(),
                            OperationSessionStatus::CancellationRequested
                        );
                        assert_eq!(current.failure(), None);
                        assert_eq!(current.outcome(), None);
                        assert!(
                            !checkpoint_session.cancel(),
                            "cancellation must be refused during finalization"
                        );
                        paused_sender.send(()).expect("report inventory pause");
                        resume_receiver
                            .recv_timeout(Duration::from_secs(5))
                            .expect("resume inventory");
                    }
                    _ => {}
                },
            );
            (result, reached_finalization.get())
        });

        paused_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("operation pauses during post-handoff inventory");
        assert_eq!(fs::read(&destination).unwrap(), competing_bytes);
        resume_sender.send(()).expect("resume inventory");
        let (result, reached_finalization) = operation.join().expect("join operation");

        assert!(reached_finalization);
        assert_eq!(result.state(), JobState::Cancelled, "{result:?}");
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::Cancelled
        );
        assert_eq!(fs::read(&destination).unwrap(), competing_bytes);
        let artifacts = result.artifacts();
        let staged = artifacts
            .iter()
            .find(|artifact| artifact.role() == OperationArtifactRole::StagedOutput)
            .expect("retain staged output evidence");
        assert!(staged.retained(), "{staged:?}");
        assert_eq!(fs::read(staged.path()).unwrap(), planned_source);
        let competitor = artifacts
            .iter()
            .find(|artifact| artifact.role() == OperationArtifactRole::UncertainEntry)
            .unwrap_or_else(|| {
                panic!("retain current destination competitor evidence: {artifacts:?}")
            });
        assert_eq!(
            fs::canonicalize(competitor.path()).unwrap(),
            fs::canonicalize(&destination).unwrap()
        );
        let competitor_file = File::open(&destination).expect("open retained competitor");
        let competitor_identity = handle_identity(&competitor_file).expect("competitor identity");
        assert_eq!(
            competitor.device().zip(competitor.inode()),
            Some((competitor_identity.device(), competitor_identity.inode()))
        );
        assert_eq!(competitor.length(), Some(competing_bytes.len() as u64));
        assert_eq!(
            competitor.sha256(),
            Some(Sha256Digest::digest(&competing_bytes))
        );
        assert_eq!(competitor.path_identity_matches(), Some(true));
        assert!(competitor.retained(), "{competitor:?}");
    }

    #[test]
    fn accepted_cancellation_does_not_mask_unverified_publication_uncertainty() {
        let (_root, source, destination, workspace) = fixture();
        let first_bytes = b"competitor bytes first";
        let plan = plan(&source, &destination, &workspace);
        let session = OperationSession::new();
        let consumer = session.subscribe_events().expect("claim event consumer");
        let cancellation = CancellationHandle::new();
        let mut inserted = false;
        let mut removed = false;

        let result = execute_with_producer_and_checkpoint_and_cancellation(
            plan,
            &session,
            copy_source_to_stage,
            |checkpoint| match checkpoint {
                ExecutionCheckpoint::BeforePromotion if !inserted => {
                    fs::write(&destination, first_bytes).expect("install destination competitor");
                    inserted = true;
                }
                ExecutionCheckpoint::DestinationCompetitorBeforeOpen if !removed => {
                    fs::remove_file(&destination).expect("remove destination competitor");
                    removed = true;
                }
                ExecutionCheckpoint::BeforeFinalization => {
                    cancellation.cancel();
                }
                _ => {}
            },
            &cancellation,
        );

        assert!(inserted);
        assert!(removed);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::PublicationUncertain)
        );
        assert!(!destination.exists());
        assert!(result.milestones().contains(&OperationMilestone::Failed));
        assert!(!result.milestones().contains(&OperationMilestone::Cancelled));
        let events = std::iter::from_fn(|| consumer.try_recv().ok()).collect::<Vec<_>>();
        assert!(!events.iter().any(|event| matches!(
            event.event(),
            OperationEventKind::Milestone {
                milestone: OperationMilestone::Cancelled
            }
        )));
        let failed = events
            .iter()
            .position(|event| {
                matches!(
                    event.event(),
                    OperationEventKind::Milestone {
                        milestone: OperationMilestone::Failed
                    }
                )
            })
            .expect("final failure milestone");
        assert!(matches!(
            events[failed + 1].event(),
            OperationEventKind::Failure {
                code: OperationFailureCode::PublicationUncertain
            }
        ));
        assert!(matches!(
            events.last().map(OperationEvent::event),
            Some(OperationEventKind::Completed { result: terminal }) if terminal == &result
        ));
        assert!(events.iter().any(|event| matches!(
            event.event(),
            OperationEventKind::CancellationRequested { accepted: true }
        )));
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event.event(), OperationEventKind::Completed { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn accepted_cancellation_before_replacement_preserves_the_destination() {
        let (_root, source, destination, workspace) = fixture();
        let source_bytes = b"replacement source bytes".to_vec();
        let destination_bytes = b"original destination bytes".to_vec();
        fs::write(&source, &source_bytes).expect("write replacement source");
        fs::write(&destination, &destination_bytes).expect("write original destination");
        let plan = crate::Engine::new()
            .plan_copy_through(
                CopyThroughRequest::new(&source, &destination, &workspace)
                    .with_conflict_policy(ConflictPolicy::Replace),
            )
            .expect("create replacement plan");
        let session = OperationSession::new();
        let consumer = session.subscribe_events().expect("claim event consumer");
        let cancellation = CancellationHandle::new();

        let result = execute_with_producer_and_checkpoint_and_cancellation(
            plan,
            &session,
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforeAtomicPromotion {
                    cancellation.cancel();
                }
            },
            &cancellation,
        );

        assert_eq!(result.state(), JobState::Cancelled);
        assert_eq!(
            fs::read(&destination).expect("read destination"),
            destination_bytes
        );
        assert_eq!(fs::read(&source).expect("read source"), source_bytes);
        assert!(!result.milestones().contains(&OperationMilestone::Published));
        let events = std::iter::from_fn(|| consumer.try_recv().ok()).collect::<Vec<_>>();
        assert!(events.iter().any(|event| matches!(
            event.event(),
            OperationEventKind::CancellationRequested { accepted: true }
        )));
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event.event(), OperationEventKind::Completed { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn accepted_handle_cancellation_sets_the_live_cancellation_status() {
        let (_root, source, destination, workspace) = fixture();
        let plan = plan(&source, &destination, &workspace);
        let session = OperationSession::new();
        let cancellation = CancellationHandle::new();
        let mut observed_cancellation_status = false;

        let result = execute_with_producer_and_checkpoint_and_cancellation(
            plan,
            &session,
            copy_source_to_stage,
            |checkpoint| match checkpoint {
                ExecutionCheckpoint::BeforeAtomicPromotion => {
                    cancellation.cancel();
                }
                ExecutionCheckpoint::BeforeArtifactInventory => {
                    let snapshot = session.current_operation().expect("cancellation snapshot");
                    assert_eq!(snapshot.phase(), OperationSessionPhase::Completing);
                    assert_eq!(
                        snapshot.status(),
                        OperationSessionStatus::CancellationRequested
                    );
                    observed_cancellation_status = true;
                }
                _ => {}
            },
            &cancellation,
        );

        assert!(observed_cancellation_status);
        assert_eq!(result.state(), JobState::Cancelled);
        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::Cancelled)
        );
        assert!(!destination.exists());
    }

    #[test]
    fn promoting_covers_only_atomic_publication_then_completion_checks() {
        let (_root, source, destination, workspace) = fixture();
        let session = OperationSession::new();
        let mut promotion_started = false;
        let mut promotion_completed = false;

        let result = execute_with_producer_and_checkpoint(
            plan(&source, &destination, &workspace),
            &session,
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AtomicPromotionStarted {
                    promotion_started = true;
                    let current = session.current_operation().unwrap();
                    assert_eq!(current.phase(), OperationSessionPhase::Promoting);
                    assert_eq!(current.status(), OperationSessionStatus::Running);
                    assert!(!session.cancel());
                }
                if checkpoint == ExecutionCheckpoint::AfterPromotion {
                    promotion_completed = true;
                    assert_eq!(
                        session.current_operation().unwrap().phase(),
                        OperationSessionPhase::Completing
                    );
                }
            },
        );

        assert!(promotion_started && promotion_completed);
        assert_eq!(result.state(), JobState::Succeeded);
        assert_eq!(fs::read(destination).unwrap(), fs::read(source).unwrap());
    }

    #[test]
    fn cancellation_before_atomic_promotion_is_accepted_without_publication() {
        let (_root, source, destination, workspace) = fixture();
        let session = OperationSession::new();
        let consumer = session.subscribe_events().expect("claim event consumer");

        let result = execute_with_producer_and_checkpoint(
            plan(&source, &destination, &workspace),
            &session,
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforeAtomicPromotion {
                    assert!(session.cancel());
                }
            },
        );

        assert_eq!(result.state(), JobState::Cancelled);
        assert_eq!(
            result.failure().unwrap().code(),
            OperationFailureCode::Cancelled
        );
        assert!(!destination.exists());
        assert_eq!(fs::read(&source).unwrap(), b"operation test source bytes");
        assert!(!result.milestones().contains(&OperationMilestone::Published));

        let events = std::iter::from_fn(|| consumer.try_recv().ok()).collect::<Vec<_>>();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event.event(), OperationEventKind::Completed { .. }))
                .count(),
            1
        );
        assert!(events.iter().any(|event| matches!(
            event.event(),
            OperationEventKind::CancellationRequested { accepted: true }
        )));
    }

    #[test]
    fn cancellation_refused_at_atomic_promotion_is_reported_without_rollback() {
        let (_root, source, destination, workspace) = fixture();
        let session = OperationSession::new();
        let consumer = session.subscribe_events().expect("claim event consumer");
        let mut refusal_observed = false;

        let result = execute_with_producer_and_checkpoint(
            plan(&source, &destination, &workspace),
            &session,
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AtomicPromotionStarted {
                    refusal_observed = true;
                    assert_eq!(
                        session.current_operation().unwrap().phase(),
                        OperationSessionPhase::Promoting
                    );
                    assert!(!session.cancel());
                }
            },
        );

        assert!(refusal_observed);
        assert_eq!(result.state(), JobState::Succeeded);
        assert_eq!(fs::read(&source).unwrap(), b"operation test source bytes");
        assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
        assert!(result.milestones().contains(&OperationMilestone::Published));

        let events = std::iter::from_fn(|| consumer.try_recv().ok()).collect::<Vec<_>>();
        assert!(
            events
                .iter()
                .enumerate()
                .all(|(index, event)| event.sequence() == index as u64),
            "event sequences must be contiguous: {events:?}"
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event.event(), OperationEventKind::Completed { .. }))
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(
                    event.event(),
                    OperationEventKind::CancellationRequested { accepted: false }
                ))
                .count(),
            1
        );
        assert!(!events.iter().any(|event| matches!(
            event.event(),
            OperationEventKind::CancellationRequested { accepted: true }
        )));
        assert!(matches!(
            events.last().map(OperationEvent::event),
            Some(OperationEventKind::Completed { result: terminal }) if terminal == &result
        ));
    }

    #[test]
    fn cancellation_handle_requested_at_atomic_promotion_is_refused() {
        let (_root, source, destination, workspace) = fixture();
        let session = OperationSession::new();
        let consumer = session.subscribe_events().expect("claim event consumer");
        let cancellation = CancellationHandle::new();
        let mut refusal_requested = false;

        let result = execute_with_producer_and_checkpoint_and_cancellation(
            plan(&source, &destination, &workspace),
            &session,
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::AtomicPromotionStarted {
                    refusal_requested = true;
                    cancellation.cancel();
                }
            },
            &cancellation,
        );

        assert!(refusal_requested);
        assert_eq!(result.state(), JobState::Succeeded);
        assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
        let events = std::iter::from_fn(|| consumer.try_recv().ok()).collect::<Vec<_>>();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(
                    event.event(),
                    OperationEventKind::CancellationRequested { accepted: false }
                ))
                .count(),
            1
        );
        assert!(!events.iter().any(|event| matches!(
            event.event(),
            OperationEventKind::CancellationRequested { accepted: true }
        )));
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event.event(), OperationEventKind::Completed { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn progress_reports_staged_source_bytes_when_copy_is_cancelled() {
        let (root, _source, destination, workspace) = fixture();
        let source = root.path().join("large-source.bin");
        let body = vec![0x5a_u8; IO_BUFFER_SIZE * 2 + 37];
        fs::write(&source, &body).expect("write large source");
        let planned = body.len() as u64;
        let session = OperationSession::new();

        let result = execute_with_producer(
            plan(&source, &destination, &workspace),
            &session,
            move |source, stage, session| {
                let mut chunks = 0;
                copy_source_to_stage_with_length_and_checkpoint(
                    source,
                    stage,
                    planned,
                    session,
                    || {
                        chunks += 1;
                        if chunks == 1 {
                            let live = session.current_operation().expect("live progress snapshot");
                            assert_eq!(live.total_bytes(), Some(planned));
                            assert!(
                                live.completed_bytes() > 0 && live.completed_bytes() < planned,
                                "live completed bytes must describe staged bytes: {live:?}"
                            );
                            let _ = session.cancel();
                        }
                    },
                )
            },
        );

        assert_eq!(result.state(), JobState::Cancelled);
        let snapshot = session.current_operation().expect("progress snapshot");
        assert_eq!(snapshot.total_bytes(), Some(planned));
        assert!(
            snapshot.completed_bytes() > 0 && snapshot.completed_bytes() < planned,
            "completed bytes must describe staged bytes: {snapshot:?}"
        );
        assert!(!destination.exists());
        assert_eq!(fs::read(&source).unwrap(), body);
    }

    #[test]
    fn failed_execution_after_full_copy_reports_all_bytes_without_publication() {
        let (_root, source, destination, workspace) = fixture();
        let planned = fs::metadata(&source).expect("source metadata").len();
        let session = OperationSession::new();

        let result = execute_with_producer(
            plan(&source, &destination, &workspace),
            &session,
            |source, stage, session| {
                copy_source_to_stage(source, stage, session)?;
                Err(OperationFailureCode::ValidationFailed)
            },
        );

        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().map(OperationFailure::code),
            Some(OperationFailureCode::ValidationFailed)
        );
        assert!(!destination.exists());
        assert_eq!(fs::read(&source).unwrap(), b"operation test source bytes");
        let snapshot = session.current_operation().expect("progress snapshot");
        assert_eq!(snapshot.total_bytes(), Some(planned));
        assert_eq!(
            snapshot.completed_bytes(),
            planned,
            "copy completion is not a publication or verification claim"
        );
    }

    #[test]
    fn busy_admission_does_not_publish_a_terminal_result() {
        let (root, source, destination, workspace) = fixture();
        let session = OperationSession::new();
        let (paused_sender, paused_receiver) = mpsc::channel();
        let (resume_sender, resume_receiver) = mpsc::channel();
        let active_session = session.clone();
        let active_source = source.clone();
        let active_destination = destination.clone();
        let active_workspace = workspace.clone();

        let worker = std::thread::spawn(move || {
            execute_with_producer_and_checkpoint(
                plan(&active_source, &active_destination, &active_workspace),
                &active_session,
                copy_source_to_stage,
                |checkpoint| {
                    if checkpoint == ExecutionCheckpoint::BeforeAtomicPromotion {
                        paused_sender.send(()).expect("signal paused execution");
                        resume_receiver.recv().expect("wait to resume");
                    }
                },
            )
        });

        paused_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("execution reaches promotion checkpoint");
        let busy_plan = plan(
            &source,
            &root.path().join("busy-destination.bin"),
            &workspace,
        );
        let busy = execute_operation(busy_plan, &session);
        assert_eq!(
            busy.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::Busy)
        );
        assert_eq!(session.last_result().expect("terminal state"), None);

        resume_sender.send(()).expect("resume execution");
        let completed = worker.join().expect("execution thread");
        assert_eq!(completed.state(), JobState::Succeeded);
        assert_eq!(
            session.last_result().expect("terminal result"),
            Some(completed)
        );
    }

    #[test]
    fn dropping_consumer_during_execution_does_not_block_completion() {
        let (_root, source, destination, workspace) = fixture();
        let session = OperationSession::new();
        let consumer = session.subscribe_events().expect("claim event consumer");
        let (paused_sender, paused_receiver) = mpsc::channel();
        let (resume_sender, resume_receiver) = mpsc::channel();
        let worker_session = session.clone();
        let worker_source = source.clone();
        let worker_destination = destination.clone();
        let worker_workspace = workspace.clone();

        let worker = std::thread::spawn(move || {
            execute_with_producer_and_checkpoint(
                plan(&worker_source, &worker_destination, &worker_workspace),
                &worker_session,
                copy_source_to_stage,
                |checkpoint| {
                    if checkpoint == ExecutionCheckpoint::BeforeAtomicPromotion {
                        paused_sender.send(()).expect("signal paused execution");
                        resume_receiver.recv().expect("wait to resume");
                    }
                },
            )
        });

        paused_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("execution reaches promotion checkpoint");
        drop(consumer);
        resume_sender.send(()).expect("resume execution");

        let result = worker.join().expect("execution thread");
        assert_eq!(result.state(), JobState::Succeeded);
        assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
        assert_eq!(
            session.last_result().expect("terminal result"),
            Some(result)
        );
    }

    /// Drains without driving execution, then checks the contracted order and
    /// completion recovery independently of transport consumption.
    fn assert_terminal_transition_events(
        session: &OperationSession,
        consumer: &OperationEventConsumer,
        result: &OperationResult,
        expected: &[OperationMilestone],
    ) -> Vec<OperationEvent> {
        let events = std::iter::from_fn(|| consumer.try_recv().ok()).collect::<Vec<_>>();
        assert!(
            events.len() <= 16,
            "semantic cardinality is input-size independent"
        );
        for (index, event) in events.iter().enumerate() {
            assert_eq!(event.sequence(), index as u64);
        }
        let milestones = events
            .iter()
            .filter_map(|event| match event.event() {
                OperationEventKind::Milestone { milestone } => Some(*milestone),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(milestones, expected);
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event.event(), OperationEventKind::Completed { .. }))
                .count(),
            1
        );
        assert!(
            matches!(events.last().map(OperationEvent::event), Some(OperationEventKind::Completed { result: terminal }) if terminal == result)
        );
        assert_eq!(session.last_result().unwrap(), Some(result.clone()));
        let terminal = events.last().expect("one terminal completion");
        let completion = session
            .last_completion()
            .expect("completion lock")
            .expect("terminal envelope retained");
        assert_eq!(completion.sequence(), terminal.sequence());
        assert_eq!(completion.snapshot(), terminal.snapshot());
        assert_eq!(completion.result(), result);
        assert_eq!(terminal.snapshot().phase(), OperationSessionPhase::Idle);
        assert_eq!(
            terminal.snapshot().status(),
            match result.state() {
                JobState::Succeeded => OperationSessionStatus::Succeeded,
                JobState::Failed => OperationSessionStatus::Failed,
                JobState::Cancelled => OperationSessionStatus::Cancelled,
            }
        );
        for event in &events[..events.len() - 1] {
            let json = serde_json::to_value(event).unwrap();
            assert!(json.get("result").is_none());
            assert!(json.get("artifacts").is_none());
            assert_eq!(
                json["snapshot"]["completed_bytes"],
                event.snapshot().completed_bytes()
            );
        }
        events
    }

    #[test]
    fn failure_emits_typed_transition_before_completion() {
        let (_root, source, destination, workspace) = fixture();
        fs::write(&destination, b"preserve existing destination").unwrap();
        let session = OperationSession::new();
        let consumer = session.subscribe_events().unwrap();
        let result = execute_operation(plan(&source, &destination, &workspace), &session);
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            fs::read(&destination).unwrap(),
            b"preserve existing destination"
        );
        assert_eq!(fs::read(&source).unwrap(), b"operation test source bytes");
        let events = assert_terminal_transition_events(
            &session,
            &consumer,
            &result,
            &[OperationMilestone::Executing, OperationMilestone::Failed],
        );
        let payloads = events
            .iter()
            .map(|e| serde_json::to_value(e.event()).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            payloads[payloads.len() - 2],
            serde_json::json!({"event":"failure","code":"destination_conflict"})
        );
    }

    #[test]
    fn cancellation_emits_ordered_transition_before_completion() {
        let (_root, source, destination, workspace) = fixture();
        let session = OperationSession::new();
        let consumer = session.subscribe_events().unwrap();
        let result = execute_with_producer_and_checkpoint(
            plan(&source, &destination, &workspace),
            &session,
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::SourceLockAcquired {
                    assert!(session.cancel());
                }
            },
        );
        assert_eq!(result.state(), JobState::Cancelled);
        assert!(!destination.exists());
        assert_eq!(fs::read(&source).unwrap(), b"operation test source bytes");
        let events = assert_terminal_transition_events(
            &session,
            &consumer,
            &result,
            &[OperationMilestone::Executing, OperationMilestone::Cancelled],
        );
        let request = events
            .iter()
            .position(|e| {
                matches!(
                    e.event(),
                    OperationEventKind::CancellationRequested { accepted: true }
                )
            })
            .unwrap();
        let cancelled = events
            .iter()
            .position(|e| {
                matches!(
                    e.event(),
                    OperationEventKind::Milestone {
                        milestone: OperationMilestone::Cancelled
                    }
                )
            })
            .unwrap();
        assert!(request < cancelled && cancelled < events.len() - 1);
    }

    #[test]
    fn full_staging_progress_does_not_claim_publication_before_cancel() {
        let (_root, source, destination, workspace) = fixture();
        let total_bytes = fs::metadata(&source).unwrap().len();
        let session = OperationSession::new();
        let consumer = session.subscribe_events().unwrap();
        let result = execute_with_producer_and_checkpoint(
            plan(&source, &destination, &workspace),
            &session,
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforePromotion {
                    let snapshot = session.current_operation().unwrap();
                    assert_eq!(snapshot.completed_bytes(), total_bytes);
                    assert!(
                        session.cancel(),
                        "cancellation is accepted before promotion"
                    );
                }
            },
        );

        assert_eq!(result.state(), JobState::Cancelled);
        assert_eq!(result.outcome(), None);
        assert_eq!(
            result.failure().map(OperationFailure::code),
            Some(OperationFailureCode::Cancelled)
        );
        assert_eq!(
            result.cleanup_warning().map(OperationFailure::code),
            Some(OperationFailureCode::CleanupIncomplete)
        );
        assert!(!destination.exists());
        let events = assert_terminal_transition_events(
            &session,
            &consumer,
            &result,
            &[
                OperationMilestone::Executing,
                OperationMilestone::Validated,
                OperationMilestone::Cancelled,
                OperationMilestone::CleanupIncomplete,
            ],
        );
        let warning = events
            .iter()
            .position(|event| {
                matches!(
                    event.event(),
                    OperationEventKind::Warning {
                        code: OperationFailureCode::CleanupIncomplete
                    }
                )
            })
            .expect("cleanup warning transition before completion");
        assert_eq!(warning + 1, events.len() - 1);
        let terminal = events.last().unwrap();
        assert_eq!(terminal.snapshot().completed_bytes(), total_bytes);
        assert_eq!(terminal.snapshot().total_bytes(), Some(total_bytes));
        assert_eq!(terminal.snapshot().outcome(), None);
        assert_eq!(
            terminal.snapshot().milestone(),
            Some(OperationMilestone::CleanupIncomplete)
        );
        assert_eq!(
            terminal.snapshot().status(),
            OperationSessionStatus::Cancelled
        );
    }

    #[test]
    fn cleanup_warning_emits_typed_transition_after_publication_before_completion() {
        let (_root, source, destination, workspace) = fixture();
        let session = OperationSession::new();
        let consumer = session.subscribe_events().unwrap();
        // An unrelated entry in the private staging directory prevents safe
        // directory cleanup without changing the validated published bytes.
        let result = execute_with_producer_and_checkpoint(
            plan(&source, &destination, &workspace),
            &session,
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforeAtomicPromotion {
                    let stage = stage_file_in(&workspace);
                    fs::write(stage.parent().unwrap().join("foreign-entry"), b"preserve").unwrap();
                }
            },
        );
        assert_eq!(result.state(), JobState::Succeeded);
        assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
        assert_eq!(
            result.cleanup_warning().map(OperationFailure::code),
            Some(OperationFailureCode::CleanupIncomplete)
        );
        let events = assert_terminal_transition_events(
            &session,
            &consumer,
            &result,
            &[
                OperationMilestone::Executing,
                OperationMilestone::Validated,
                OperationMilestone::Published,
                OperationMilestone::CleanupIncomplete,
            ],
        );
        let payloads = events
            .iter()
            .map(|e| serde_json::to_value(e.event()).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            payloads[payloads.len() - 2],
            serde_json::json!({"event":"warning","code":"cleanup_incomplete"})
        );
    }

    #[test]
    fn failure_and_cleanup_warning_emit_in_result_order_before_completion() {
        let (_root, source, destination, workspace) = fixture();
        let session = OperationSession::new();
        let consumer = session.subscribe_events().unwrap();
        let result = execute_with_producer(
            plan(&source, &destination, &workspace),
            &session,
            |source, stage, session| {
                copy_source_to_stage(source, stage, session)?;
                let stage = stage_file_in(&workspace);
                fs::write(stage.parent().unwrap().join("foreign-entry"), b"preserve").unwrap();
                Err(OperationFailureCode::WriteFailed)
            },
        );
        assert_eq!(result.state(), JobState::Failed);
        assert!(!destination.exists());
        let events = assert_terminal_transition_events(
            &session,
            &consumer,
            &result,
            &[
                OperationMilestone::Executing,
                OperationMilestone::Failed,
                OperationMilestone::CleanupIncomplete,
            ],
        );
        let tail = events.iter().rev().take(5).collect::<Vec<_>>();
        assert_eq!(
            serde_json::to_value(tail[3].event()).unwrap(),
            serde_json::json!({"event":"failure","code":"write_failed"})
        );
        assert_eq!(
            serde_json::to_value(tail[1].event()).unwrap(),
            serde_json::json!({"event":"warning","code":"cleanup_incomplete"})
        );
    }

    #[test]
    fn subscription_during_execution_is_refused() {
        let (_root, source, destination, workspace) = fixture();
        let session = OperationSession::new();

        let result = execute_with_producer_and_checkpoint(
            plan(&source, &destination, &workspace),
            &session,
            copy_source_to_stage,
            |checkpoint| {
                if checkpoint == ExecutionCheckpoint::BeforeAtomicPromotion {
                    assert_eq!(
                        session.subscribe_events().unwrap_err(),
                        OperationFailureCode::EventConsumerUnavailable
                    );
                }
            },
        );

        assert_eq!(result.state(), JobState::Succeeded);
    }
}

#[cfg(all(test, target_os = "macos"))]
type CopyPlanningCheckpoint = Box<dyn FnOnce()>;

#[cfg(all(test, target_os = "macos"))]
thread_local! {
    static COPY_PLANNING_CHECKPOINT: std::cell::Cell<Option<CopyPlanningCheckpoint>> = const { std::cell::Cell::new(None) };
}

#[cfg(all(test, target_os = "macos"))]
fn set_copy_planning_checkpoint(checkpoint: impl FnOnce() + 'static) {
    COPY_PLANNING_CHECKPOINT.with(|slot| {
        assert!(slot.replace(Some(Box::new(checkpoint))).is_none());
    });
}

#[cfg(all(test, target_os = "macos"))]
mod copy_planning_signal_tests {
    use super::{
        CopyThroughRequest, OperationError, OperationFailureCode, OperationPlan, plan_copy_through,
        set_copy_planning_checkpoint,
    };
    use crate::engine::Engine;
    use crate::inspection::CancellationHandle;
    use crate::operation::OperationSession;
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, mpsc};
    use std::thread;

    fn plan_while_delivering_signal(
        request: CopyThroughRequest,
        signal: i32,
    ) -> (
        Result<OperationPlan, OperationError>,
        CancellationHandle,
        Vec<signal_hook::SigId>,
    ) {
        let flag = Arc::new(AtomicBool::new(false));
        let interrupt = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&flag))
            .expect("register isolated interrupt flag");
        let terminate =
            signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&flag))
                .expect("register isolated terminate flag");
        let cancellation = CancellationHandle::from_flag(flag.clone());
        let (entered_sender, entered_receiver) = mpsc::channel();
        let (resume_sender, resume_receiver) = mpsc::channel();
        set_copy_planning_checkpoint(move || {
            entered_sender
                .send(())
                .expect("signal thread waits for planner entry");
            resume_receiver
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("signal thread releases the planner");
        });
        let signal_thread = thread::spawn(move || {
            entered_receiver
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("copy planning reaches the synchronized checkpoint");
            signal_hook::low_level::raise(signal).expect("deliver signal during copy planning");
            resume_sender
                .send(())
                .expect("copy planner waits for signal delivery");
        });

        let plan = Engine::new().plan_copy_through(request);
        signal_thread
            .join()
            .expect("signal delivery thread completes");
        assert!(
            cancellation.is_cancelled(),
            "the signal is latched before synchronous planning returns"
        );
        (plan, cancellation, vec![interrupt, terminate])
    }

    fn unregister_signal_actions(actions: Vec<signal_hook::SigId>) {
        for action in actions {
            signal_hook::low_level::unregister(action);
        }
    }

    fn run_case(root: &Path, signal: i32) {
        let source = root.join("source.bin");
        let destination = root.join("destination.bin");
        let workspace = root.join("workspace");
        let source_bytes = b"signal during synchronous copy planning";
        fs::write(&source, source_bytes).expect("write source fixture");

        let (plan, cancellation, actions) = plan_while_delivering_signal(
            CopyThroughRequest::new(&source, &destination, &workspace),
            signal,
        );
        let session = OperationSession::new();
        let result = Engine::new().execute_operation_with_cancellation(
            plan.expect("successful planning preserves its plan"),
            &session,
            cancellation,
        );
        assert_eq!(result.state(), crate::operation::JobState::Cancelled);
        assert_eq!(
            session.last_result().unwrap(),
            Some(result),
            "cancellation before staging still produces the authoritative result"
        );
        assert_eq!(fs::read(&source).unwrap(), source_bytes);
        assert!(!destination.exists());
        assert!(!workspace.exists());
        unregister_signal_actions(actions);

        let later_source = root.join("later-source.bin");
        let later_destination = root.join("later-destination.bin");
        let later_workspace = root.join("later-workspace");
        let later_bytes = b"unrelated later invocation";
        fs::write(&later_source, later_bytes).expect("write later source");
        let later_plan = plan_copy_through(CopyThroughRequest::new(
            &later_source,
            &later_destination,
            &later_workspace,
        ))
        .expect("later planning is independent");
        let later_result = Engine::new().execute_operation_with_cancellation(
            later_plan,
            &OperationSession::new(),
            CancellationHandle::new(),
        );
        assert_eq!(later_result.state(), crate::operation::JobState::Succeeded);
        assert_eq!(fs::read(later_destination).unwrap(), later_bytes);
    }

    fn run_failure_case(root: &Path, signal: i32) {
        let missing = root.join("missing-source.bin");
        let destination = root.join("failed-destination.bin");
        let workspace = root.join("failed-workspace");
        let (plan, cancellation, actions) = plan_while_delivering_signal(
            CopyThroughRequest::new(&missing, &destination, &workspace),
            signal,
        );
        let error = match plan {
            Ok(_) => panic!("planning failure remains authoritative"),
            Err(error) => error,
        };
        assert_eq!(error.code(), OperationFailureCode::SourceUnavailable);
        assert!(cancellation.is_cancelled());
        assert!(!destination.exists());
        assert!(!workspace.exists());
        unregister_signal_actions(actions);
    }

    #[test]
    fn signals_during_synchronous_planning_are_latched_before_the_result_handoff() {
        const CHILD_SIGNAL: &str = "NSCB_TEST_SIGNAL_DURING_COPY_PLANNING";
        if let Some(signal) = std::env::var_os(CHILD_SIGNAL) {
            let signal = signal
                .to_string_lossy()
                .parse::<i32>()
                .expect("test signal number");
            let root = tempfile::tempdir().expect("copy planning signal fixture");
            run_case(root.path(), signal);
            run_failure_case(root.path(), signal);
            return;
        }

        for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "operation::copy_planning_signal_tests::signals_during_synchronous_planning_are_latched_before_the_result_handoff",
                    "--nocapture",
                ])
                .env(CHILD_SIGNAL, signal.to_string())
                .output()
                .expect("run planning signal case in an isolated subprocess");
            assert!(
                output.status.success(),
                "signal {signal}: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
        }
    }
}
