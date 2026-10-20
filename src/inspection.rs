//! Typed, read-only content Inspection requests and normalized results.
//!
//! Inspection is distinct from Container Probe and Content Recognition. It
//! requires a key source, may invoke a qualified managed provider, and reports
//! only facts that NSCB has normalized and independently validated. It does
//! not establish authenticity, integrity, Verification success, or the
//! correctness of decrypted content.
use crate::partition_fs::{PartitionFsValidation, PartitionFsValidationError};
use serde::{Serialize, Serializer};
use std::fmt;
use std::io::{Read, Seek, SeekFrom};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Stable inspection capabilities exposed by the Engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InspectionCapability {
    /// Standalone NCA3 structural Inspection that requires an NCA header key.
    Nca,
}

/// One explicit read-only Inspection request.
///
/// The request names an existing input and an existing key source. Provider
/// selection, helper identity, arguments, cache layout, and provisioning are
/// host policy and private implementation details of the Engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectionRequest {
    input: PathBuf,
    key_file: PathBuf,
    capability: InspectionCapability,
}

impl InspectionRequest {
    /// Creates a standalone NCA Inspection request.
    ///
    /// No content is read and no helper is launched by this constructor.
    pub fn nca(input: impl Into<PathBuf>, key_file: impl Into<PathBuf>) -> Self {
        Self {
            input: input.into(),
            key_file: key_file.into(),
            capability: InspectionCapability::Nca,
        }
    }

    /// Returns the requested capability.
    pub const fn capability(&self) -> InspectionCapability {
        self.capability
    }

    pub(crate) fn input(&self) -> &Path {
        &self.input
    }

    pub(crate) fn key_file(&self) -> &Path {
        &self.key_file
    }
}

/// Host-owned cache and network policy for Inspection.
///
/// The Engine never chooses a cache location, downloads implicitly, or accepts
/// an executable path from a caller.
#[derive(Clone, Debug)]
pub struct InspectionHost {
    cache_dir: PathBuf,
    provisioning: ProvisioningPolicy,
    memory_monitoring: MemoryMonitoringPolicy,
    cancellation: Option<CancellationHandle>,
    inspection_active: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProvisioningPolicy {
    CacheOnly,
    ManagedDownload,
}

/// Host policy for optional physical-footprint monitoring of a provider.
///
/// Monitoring is disabled by default. Selecting a threshold requests optional
/// sampling and enforcement where a supported sampler is available. When no
/// sampler is available, Inspection proceeds and
/// [`InspectionHost::memory_monitoring_status`] reports that the threshold is
/// not enforced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryMonitoringPolicy {
    /// Run with no physical-footprint sampling claim.
    Disabled,
    /// Request a physical-footprint threshold where supported.
    ///
    /// This policy does not make unavailable optional telemetry a prerequisite
    /// for Inspection. Check [`InspectionHost::memory_monitoring_status`] to
    /// determine whether the threshold is active.
    RequirePhysicalFootprintThreshold { threshold_bytes: NonZeroU64 },
}

/// Reports whether optional physical-footprint monitoring is active.
///
/// The status is host capability information and is not included in serialized
/// Inspection results. `Unavailable` means that the requested threshold is
/// preserved as policy but cannot be sampled or enforced on this host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MemoryMonitoringStatus {
    /// No physical-footprint threshold was requested.
    Disabled,
    /// A threshold was requested, but no supported sampler is available.
    Unavailable { threshold_bytes: NonZeroU64 },
}

impl InspectionHost {
    /// Uses an existing host-owned provider cache without network access.
    pub fn cache_only(cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            cache_dir: cache_dir.into(),
            provisioning: ProvisioningPolicy::CacheOnly,
            memory_monitoring: MemoryMonitoringPolicy::Disabled,
            cancellation: None,
            inspection_active: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Allows explicit, digest-pinned provider provisioning from the manifest URL.
    ///
    /// Network access occurs only when an Inspection or provisioning request
    /// reaches a missing artifact. Preflight never downloads.
    pub fn managed_download(cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            cache_dir: cache_dir.into(),
            provisioning: ProvisioningPolicy::ManagedDownload,
            memory_monitoring: MemoryMonitoringPolicy::Disabled,
            cancellation: None,
            inspection_active: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Associates cancellation with this host policy.
    pub fn with_cancellation(mut self, cancellation: CancellationHandle) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    /// Sets the host-owned physical-footprint monitoring policy.
    pub fn with_memory_monitoring_policy(mut self, policy: MemoryMonitoringPolicy) -> Self {
        self.memory_monitoring = policy;
        self
    }

    /// Returns the configured memory-monitoring policy.
    pub const fn memory_monitoring_policy(&self) -> MemoryMonitoringPolicy {
        self.memory_monitoring
    }

    /// Reports whether physical-footprint sampling can enforce the configured
    /// threshold on this host.
    pub const fn memory_monitoring_status(&self) -> MemoryMonitoringStatus {
        match self.memory_monitoring {
            MemoryMonitoringPolicy::Disabled => MemoryMonitoringStatus::Disabled,
            MemoryMonitoringPolicy::RequirePhysicalFootprintThreshold { threshold_bytes } => {
                MemoryMonitoringStatus::Unavailable { threshold_bytes }
            }
        }
    }

    pub(crate) fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    pub(crate) const fn provisioning(&self) -> ProvisioningPolicy {
        self.provisioning
    }

    pub(crate) fn cancellation(&self) -> Option<&CancellationHandle> {
        self.cancellation.as_ref()
    }

    pub(crate) fn begin_inspection(&self) -> Result<InspectionAdmissionGuard, InspectionErrorCode> {
        self.inspection_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| InspectionErrorCode::ProviderExecutionBusy)?;
        Ok(InspectionAdmissionGuard(self.inspection_active.clone()))
    }
}

/// Releases a host-session admission slot on every inspection return path.
pub(crate) struct InspectionAdmissionGuard(Arc<AtomicBool>);

impl Drop for InspectionAdmissionGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// A cancellation signal shared with a host or command-line adapter.
#[derive(Clone, Debug)]
pub struct CancellationHandle {
    cancelled: Arc<AtomicBool>,
}

impl CancellationHandle {
    /// Creates a handle in the running state.
    pub fn new() -> Self {
        Self::from_flag(Arc::new(AtomicBool::new(false)))
    }

    /// Creates a handle backed by a host-owned atomic flag.
    ///
    /// This constructor exists so an adapter such as a signal handler can share
    /// its flag without exposing provider execution controls.
    pub fn from_flag(cancelled: Arc<AtomicBool>) -> Self {
        Self { cancelled }
    }

    /// Requests cancellation. Repeated requests are harmless.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Returns whether cancellation was requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

impl Default for CancellationHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of validating prerequisites without launching a provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InspectionPreflightStatus {
    /// The qualified artifact and all request prerequisites are ready.
    Ready,
    /// Explicit managed provisioning is required before Inspection can run.
    ProvisioningRequired,
}

/// Normalized Inspection result. New capabilities may be added additively.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "capability", content = "inspection", rename_all = "snake_case")]
#[non_exhaustive]
pub enum InspectionResult {
    /// Standalone NCA3 Inspection facts.
    Nca(NcaInspection),
}

/// Normalized facts from one supported standalone NCA3 file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NcaInspection {
    /// NCA header format version. The initial profile supports version 3.
    pub format_version: u8,
    /// Content distribution type.
    pub distribution: NcaDistribution,
    /// Content type. The initial profile supports program content.
    pub content_type: NcaContentType,
    /// NCA key generation.
    pub key_generation: u8,
    /// NCA signature-key generation.
    pub signature_generation: u8,
    /// Program identifier reported by the NCA header.
    pub program_id: ProgramId,
    /// Content index reported by the NCA header.
    pub content_index: u32,
    /// Declared NCA size, independently checked against the observed file size.
    pub declared_size: u64,
    /// Supported filesystem partitions in header-index order.
    pub partitions: Vec<NcaPartition>,
}

/// Supported NCA distribution values.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NcaDistribution {
    /// Game Card distribution.
    GameCard,
    /// Download distribution.
    Download,
}

/// Supported NCA content values.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NcaContentType {
    /// Program content.
    Program,
}

/// One validated NCA filesystem partition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NcaPartition {
    /// Header partition index.
    pub index: u8,
    /// Absolute partition offset in the NCA file.
    pub offset: u64,
    /// Declared partition size.
    pub size: u64,
    /// Qualified filesystem profile.
    pub filesystem: NcaFilesystem,
    /// Declared partition hash type.
    pub hash_type: NcaHashType,
    /// Declared partition encryption type.
    pub encryption: NcaEncryptionType,
    /// Files in the partition, ordered by normalized path.
    pub entries: Vec<InspectionEntry>,
}

/// Filesystem profiles supported by this Inspection slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NcaFilesystem {
    /// Nintendo PartitionFs (PFS0).
    PartitionFs,
}

/// NCA partition hash types supported by this Inspection slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NcaHashType {
    /// No partition hash layer. Its presence is not an integrity claim.
    None,
}

/// NCA partition encryption types supported by this Inspection slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NcaEncryptionType {
    /// Clear partition content. The encrypted NCA header is a separate prerequisite.
    None,
}

/// One normalized file in a validated PartitionFs partition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InspectionEntry {
    /// Slash-separated path relative to the partition root.
    pub path: String,
    /// Declared file size in bytes.
    pub size: u64,
}

/// A Nintendo program identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ProgramId(u64);

impl ProgramId {
    /// Creates an identifier from its unsigned 64-bit representation.
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// Returns the unsigned 64-bit representation.
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns exactly 16 lowercase hexadecimal characters.
    pub fn to_hex(self) -> String {
        format!("{:016x}", self.0)
    }
}

impl Serialize for ProgramId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

/// Numeric process exit classes fixed by ADR 0023.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum InspectionExitClass {
    /// Successful operation.
    Success = 0,
    /// Usage or host configuration error.
    Configuration = 2,
    /// Missing, invalid, unsupported, or unqualified prerequisite.
    Prerequisite = 3,
    /// Input or cache changed concurrently.
    Conflict = 4,
    /// The qualified provider executed but failed to produce a valid result.
    Provider = 5,
    /// The operation was cancelled.
    Cancelled = 6,
    /// An internal invariant, I/O, or allocation failure occurred.
    Internal = 7,
}

impl InspectionExitClass {
    /// Returns the stable process exit number.
    pub const fn code(self) -> i32 {
        self as i32
    }
}

/// Stable, sanitized Inspection error codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InspectionErrorCode {
    /// The host supplied an unusable cache directory configuration.
    InvalidCacheDirectory,
    /// The host supplied an unusable key-path configuration.
    InvalidKeyPath,
    /// The content input could not be opened or read.
    InputUnavailable,
    /// The input is not a supported NCA3 file.
    UnsupportedFormat,
    /// The NCA uses a filesystem, encryption, hash, or content profile not qualified here.
    UnsupportedInspectionProfile,
    /// The input ends before a declared structure.
    TruncatedInput,
    /// A declared structure is internally inconsistent.
    MalformedInput,
    /// The input exceeds an explicit Inspection limit.
    InputLimitExceeded,
    /// The key source could not be read.
    KeyFileUnavailable,
    /// The key source does not have the accepted grammar.
    KeyFileMalformed,
    /// The key source exceeds its explicit size limit.
    KeyFileLimitExceeded,
    /// No accepted NCA header-key alias is present.
    MissingHeaderKey,
    /// No qualified provider artifact exists in the host cache.
    ProviderCacheMissing,
    /// A cached provider artifact does not match the immutable manifest digest.
    ProviderArtifactMismatch,
    /// A cached provider installation is missing required files.
    ProviderArtifactIncomplete,
    /// A downloaded provider archive is not the exact qualified archive.
    ProviderArchiveInvalid,
    /// The build target has no official qualified provider artifact.
    ProviderUnsupportedTarget,
    /// An official artifact exists but has no native qualification for this operation.
    ProviderUnqualifiedTarget,
    /// This host cannot enforce the resource limits required for provider execution.
    ProviderContainmentUnsupported,
    /// This host has no supported physical-footprint sampler for a requested threshold.
    PhysicalFootprintMonitoringUnsupported,
    /// Host policy denied required provider provisioning.
    ProvisioningDenied,
    /// Explicit managed provisioning failed before producing a usable artifact.
    ProvisioningFailed,
    /// The content input changed while the provider was executing.
    InputChangedDuringInspection,
    /// The key source changed while the provider was executing.
    KeyFileChangedDuringInspection,
    /// Another process is mutating or repairing the provider cache.
    ProviderCacheBusy,
    /// The explicitly constructed host session already has an active provider execution.
    ProviderExecutionBusy,
    /// The qualified provider process could not be started.
    ProviderLaunchFailed,
    /// The qualified provider returned a nonzero exit status.
    ProviderExitedUnsuccessfully,
    /// The qualified provider terminated without an exit code.
    ProviderCrashed,
    /// The qualified provider exceeded the operation deadline.
    ProviderTimedOut,
    /// The qualified provider exceeded an output-stream bound.
    ProviderOutputExceeded,
    /// The qualified provider output did not match the pinned grammar.
    ProviderOutputMalformed,
    /// A declared clear partition could not be listed or read.
    ProviderContentUnreadable,
    /// NSCB's independent postcondition checks disagreed with provider output.
    ProviderPostconditionMismatch,
    /// Provider output and independent parsing were internally inconsistent.
    ProviderInconsistent,
    /// The operation was cancelled.
    Cancelled,
    /// The immutable provider manifest failed validation.
    ProviderManifestInvalid,
    /// A required cache lock could not be acquired or released safely.
    CacheLockFailed,
    /// Provider-cache cleanup could not complete safely.
    CacheCleanupFailed,
    /// A bounded allocation could not be reserved.
    AllocationFailed,
    /// An internal filesystem or synchronization operation failed.
    InternalIo,
    /// The CLI signal handler could not be installed.
    SignalHandlerFailed,
}

impl InspectionErrorCode {
    /// Returns the stable machine-readable spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCacheDirectory => "invalid_cache_directory",
            Self::InvalidKeyPath => "invalid_key_path",
            Self::InputUnavailable => "input_unavailable",
            Self::UnsupportedFormat => "unsupported_format",
            Self::UnsupportedInspectionProfile => "unsupported_inspection_profile",
            Self::TruncatedInput => "truncated_input",
            Self::MalformedInput => "malformed_input",
            Self::InputLimitExceeded => "input_limit_exceeded",
            Self::KeyFileUnavailable => "key_file_unavailable",
            Self::KeyFileMalformed => "key_file_malformed",
            Self::KeyFileLimitExceeded => "key_file_limit_exceeded",
            Self::MissingHeaderKey => "missing_header_key",
            Self::ProviderCacheMissing => "provider_cache_missing",
            Self::ProviderArtifactMismatch => "provider_artifact_mismatch",
            Self::ProviderArtifactIncomplete => "provider_artifact_incomplete",
            Self::ProviderArchiveInvalid => "provider_archive_invalid",
            Self::ProviderUnsupportedTarget => "provider_unsupported_target",
            Self::ProviderUnqualifiedTarget => "provider_unqualified_target",
            Self::ProviderContainmentUnsupported => "provider_containment_unsupported",
            Self::PhysicalFootprintMonitoringUnsupported => {
                "physical_footprint_monitoring_unsupported"
            }
            Self::ProvisioningDenied => "provisioning_denied",
            Self::ProvisioningFailed => "provisioning_failed",
            Self::InputChangedDuringInspection => "input_changed_during_inspection",
            Self::KeyFileChangedDuringInspection => "key_file_changed_during_inspection",
            Self::ProviderCacheBusy => "provider_cache_busy",
            Self::ProviderExecutionBusy => "provider_execution_busy",
            Self::ProviderLaunchFailed => "provider_launch_failed",
            Self::ProviderExitedUnsuccessfully => "provider_exited_unsuccessfully",
            Self::ProviderCrashed => "provider_crashed",
            Self::ProviderTimedOut => "provider_timed_out",
            Self::ProviderOutputExceeded => "provider_output_exceeded",
            Self::ProviderOutputMalformed => "provider_output_malformed",
            Self::ProviderContentUnreadable => "provider_content_unreadable",
            Self::ProviderPostconditionMismatch => "provider_postcondition_mismatch",
            Self::ProviderInconsistent => "provider_inconsistent",
            Self::Cancelled => "cancelled",
            Self::ProviderManifestInvalid => "provider_manifest_invalid",
            Self::CacheLockFailed => "cache_lock_failed",
            Self::CacheCleanupFailed => "cache_cleanup_failed",
            Self::AllocationFailed => "allocation_failed",
            Self::InternalIo => "internal_io",
            Self::SignalHandlerFailed => "signal_handler_failed",
        }
    }

    /// Returns the ADR 0023 exit class for this stable code.
    pub const fn exit_class(self) -> InspectionExitClass {
        match self {
            Self::InvalidCacheDirectory | Self::InvalidKeyPath => {
                InspectionExitClass::Configuration
            }
            Self::InputUnavailable
            | Self::UnsupportedFormat
            | Self::UnsupportedInspectionProfile
            | Self::TruncatedInput
            | Self::MalformedInput
            | Self::InputLimitExceeded
            | Self::KeyFileUnavailable
            | Self::KeyFileMalformed
            | Self::KeyFileLimitExceeded
            | Self::MissingHeaderKey
            | Self::ProviderCacheMissing
            | Self::ProviderArtifactMismatch
            | Self::ProviderArtifactIncomplete
            | Self::ProviderArchiveInvalid
            | Self::ProviderUnsupportedTarget
            | Self::ProviderUnqualifiedTarget
            | Self::ProviderContainmentUnsupported
            | Self::PhysicalFootprintMonitoringUnsupported
            | Self::ProvisioningDenied
            | Self::ProvisioningFailed => InspectionExitClass::Prerequisite,
            Self::InputChangedDuringInspection
            | Self::KeyFileChangedDuringInspection
            | Self::ProviderCacheBusy
            | Self::ProviderExecutionBusy => InspectionExitClass::Conflict,
            Self::ProviderLaunchFailed
            | Self::ProviderExitedUnsuccessfully
            | Self::ProviderCrashed
            | Self::ProviderTimedOut
            | Self::ProviderOutputExceeded
            | Self::ProviderOutputMalformed
            | Self::ProviderContentUnreadable
            | Self::ProviderPostconditionMismatch
            | Self::ProviderInconsistent => InspectionExitClass::Provider,
            Self::Cancelled => InspectionExitClass::Cancelled,
            Self::ProviderManifestInvalid
            | Self::CacheLockFailed
            | Self::CacheCleanupFailed
            | Self::AllocationFailed
            | Self::InternalIo
            | Self::SignalHandlerFailed => InspectionExitClass::Internal,
        }
    }
}

/// A sanitized Inspection failure containing no provider text, paths, or keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InspectionError {
    code: InspectionErrorCode,
}

impl InspectionError {
    pub(crate) const fn new(code: InspectionErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable error code.
    pub const fn code(self) -> InspectionErrorCode {
        self.code
    }

    /// Returns the stable process exit class.
    pub const fn exit_class(self) -> InspectionExitClass {
        self.code.exit_class()
    }
}

impl fmt::Display for InspectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.code {
            InspectionErrorCode::InvalidCacheDirectory => "the provider cache location is invalid",
            InspectionErrorCode::InvalidKeyPath => "the key source path is invalid",
            InspectionErrorCode::InputUnavailable => "the input could not be read",
            InspectionErrorCode::UnsupportedFormat => "the input is not a supported NCA3 file",
            InspectionErrorCode::UnsupportedInspectionProfile => {
                "the input uses an inspection profile that is not supported"
            }
            InspectionErrorCode::TruncatedInput => "the input is incomplete",
            InspectionErrorCode::MalformedInput => "the input structure is invalid",
            InspectionErrorCode::InputLimitExceeded => "the input exceeds a supported limit",
            InspectionErrorCode::KeyFileUnavailable => "the key source could not be read",
            InspectionErrorCode::KeyFileMalformed => "the key source is malformed",
            InspectionErrorCode::KeyFileLimitExceeded => "the key source exceeds a supported limit",
            InspectionErrorCode::MissingHeaderKey => "the key source has no NCA header key",
            InspectionErrorCode::ProviderCacheMissing => "the provider artifact is not cached",
            InspectionErrorCode::ProviderArtifactMismatch => {
                "the cached provider artifact does not match its manifest"
            }
            InspectionErrorCode::ProviderArtifactIncomplete => {
                "the cached provider installation is incomplete"
            }
            InspectionErrorCode::ProviderArchiveInvalid => {
                "the provider release archive is invalid"
            }
            InspectionErrorCode::ProviderUnsupportedTarget => {
                "the provider does not support this target"
            }
            InspectionErrorCode::ProviderUnqualifiedTarget => {
                "the provider is not qualified for this target and operation"
            }
            InspectionErrorCode::ProviderContainmentUnsupported => {
                "this host cannot enforce the required provider resource limits"
            }
            InspectionErrorCode::PhysicalFootprintMonitoringUnsupported => {
                "this host cannot provide physical-footprint monitoring"
            }
            InspectionErrorCode::ProvisioningDenied => "provider provisioning is not allowed",
            InspectionErrorCode::ProvisioningFailed => "provider provisioning failed",
            InspectionErrorCode::InputChangedDuringInspection => {
                "the input changed during inspection"
            }
            InspectionErrorCode::KeyFileChangedDuringInspection => {
                "the key source changed during inspection"
            }
            InspectionErrorCode::ProviderCacheBusy => "the provider cache is busy",
            InspectionErrorCode::ProviderExecutionBusy => {
                "this inspection host session already has an active provider execution"
            }
            InspectionErrorCode::ProviderLaunchFailed => "the provider could not be started",
            InspectionErrorCode::ProviderExitedUnsuccessfully => {
                "the provider exited unsuccessfully"
            }
            InspectionErrorCode::ProviderCrashed => "the provider terminated abnormally",
            InspectionErrorCode::ProviderTimedOut => "the provider exceeded its deadline",
            InspectionErrorCode::ProviderOutputExceeded => "the provider exceeded an output limit",
            InspectionErrorCode::ProviderOutputMalformed => {
                "the provider output is not in the pinned format"
            }
            InspectionErrorCode::ProviderContentUnreadable => {
                "a declared readable partition could not be read"
            }
            InspectionErrorCode::ProviderPostconditionMismatch => {
                "the provider result failed independent validation"
            }
            InspectionErrorCode::ProviderInconsistent => {
                "the provider output is internally inconsistent"
            }
            InspectionErrorCode::Cancelled => "the operation was cancelled",
            InspectionErrorCode::ProviderManifestInvalid => {
                "the immutable provider manifest is invalid"
            }
            InspectionErrorCode::CacheLockFailed => "the provider cache lock failed",
            InspectionErrorCode::CacheCleanupFailed => "provider cache cleanup failed",
            InspectionErrorCode::AllocationFailed => "a bounded allocation failed",
            InspectionErrorCode::InternalIo => "an internal filesystem operation failed",
            InspectionErrorCode::SignalHandlerFailed => {
                "the command-line signal handler could not be installed"
            }
        })
    }
}

impl std::error::Error for InspectionError {}

const MAX_PARTITIONS: usize = 4;
const MIN_PARTITION_OFFSET: u64 = 0xc00;
const PARTITION_ALIGNMENT: u64 = 0x200;

pub(crate) fn inspect(
    request: &InspectionRequest,
    host: &InspectionHost,
) -> Result<InspectionResult, InspectionErrorCode> {
    if request.capability() != InspectionCapability::Nca {
        return Err(InspectionErrorCode::UnsupportedInspectionProfile);
    }
    let report = crate::provider::inspect(request, host)?;
    validate_provider_report(report)
}

/// Applies the independent Rust profile, filesystem, path, and provider
/// postcondition checks to a prepared provider report.
pub(crate) fn validate_provider_report(
    mut report: crate::provider::ProviderReport,
) -> Result<InspectionResult, InspectionErrorCode> {
    let facts = &report.facts;
    let header = &report.header;
    validate_nca_profile(header)?;
    corroborate_header(facts, header)?;

    let mut validation = PartitionFsValidation::default();
    let mut partitions = Vec::new();
    for partition in &header.partitions {
        let mut span = SpanReader::new(report.input.file(), partition.offset, partition.size);
        let probe = crate::pfs0::probe(&mut span, partition.size).map_err(map_pfs_error)?;
        let entries = validation
            .validate_partition(
                partition.index,
                probe
                    .entries
                    .iter()
                    .map(|entry| (entry.name.as_str(), entry.size)),
            )
            .map_err(map_partition_fs_error)?;
        partitions.push(NcaPartition {
            index: partition.index,
            offset: partition.offset,
            size: partition.size,
            filesystem: NcaFilesystem::PartitionFs,
            hash_type: NcaHashType::None,
            encryption: NcaEncryptionType::None,
            entries: entries
                .into_iter()
                .map(|(path, size)| InspectionEntry { path, size })
                .collect(),
        });
    }
    if validation.total_entries() == 0 {
        return Err(InspectionErrorCode::ProviderContentUnreadable);
    }
    if validation.expected_directories() != &facts.tree_directories
        || validation.expected_files() != &facts.tree_files
    {
        return Err(InspectionErrorCode::ProviderPostconditionMismatch);
    }
    if !report.input.unchanged() {
        return Err(InspectionErrorCode::InputChangedDuringInspection);
    }

    Ok(InspectionResult::Nca(NcaInspection {
        format_version: header.format_version,
        distribution: match header.distribution {
            crate::nca::Distribution::GameCard => NcaDistribution::GameCard,
            crate::nca::Distribution::Download => NcaDistribution::Download,
        },
        content_type: NcaContentType::Program,
        key_generation: header.key_generation,
        signature_generation: header.signature_generation,
        program_id: ProgramId::from_u64(header.program_id),
        content_index: header.content_index,
        declared_size: header.declared_size,
        partitions,
    }))
}

pub(crate) fn validate_nca_profile(header: &crate::nca::Header) -> Result<(), InspectionErrorCode> {
    if header.content_type != crate::nca::ContentType::Program
        || header.key_generation > 0x20
        || header.partitions.is_empty()
        || header.partitions.len() > MAX_PARTITIONS
        || header.partitions.iter().any(|partition| {
            partition.filesystem != 1
                || partition.hash_type != 1
                || partition.encryption != 1
                || partition.extended
                || partition.offset < MIN_PARTITION_OFFSET
                || !partition.size.is_multiple_of(PARTITION_ALIGNMENT)
        })
    {
        return Err(InspectionErrorCode::UnsupportedInspectionProfile);
    }
    Ok(())
}

fn corroborate_header(
    facts: &crate::provider::ProviderFacts,
    header: &crate::nca::Header,
) -> Result<(), InspectionErrorCode> {
    let distribution_matches = matches!(
        (facts.distribution, header.distribution),
        (
            crate::provider::Distribution::GameCard,
            crate::nca::Distribution::GameCard
        ) | (
            crate::provider::Distribution::Download,
            crate::nca::Distribution::Download
        )
    );
    if facts.format_version != header.format_version
        || !distribution_matches
        || facts.content_type != crate::provider::ContentType::Program
        || header.content_type != crate::nca::ContentType::Program
        || facts.key_generation != header.key_generation
        || facts.signature_generation != header.signature_generation
        || facts.kaek_index != header.kaek_index
        || facts.program_id != header.program_id
        || facts.content_index != header.content_index
        || facts.declared_size != header.declared_size
        || facts.partitions.len() != header.partitions.len()
    {
        return Err(InspectionErrorCode::ProviderPostconditionMismatch);
    }
    for (provider, independent) in facts.partitions.iter().zip(&header.partitions) {
        if provider.index != independent.index
            || provider.offset != independent.offset
            || provider.size != independent.size
            || provider.format != "PartitionFs"
            || provider.hash_type != "None"
            || provider.encryption != "None"
        {
            return Err(InspectionErrorCode::ProviderPostconditionMismatch);
        }
    }
    Ok(())
}

fn map_pfs_error(error: crate::ContainerProbeError) -> InspectionErrorCode {
    use crate::ContainerProbeErrorCode as Code;
    match error.code() {
        Code::UnsupportedFormat => InspectionErrorCode::ProviderPostconditionMismatch,
        Code::TruncatedInput => InspectionErrorCode::TruncatedInput,
        Code::InvalidHeader | Code::InvalidStringTable | Code::InvalidEntry => {
            InspectionErrorCode::MalformedInput
        }
        Code::LimitExceeded | Code::NameTooLong => InspectionErrorCode::InputLimitExceeded,
        Code::InputUnavailable => InspectionErrorCode::InternalIo,
        Code::ResourceLimitExceeded => InspectionErrorCode::AllocationFailed,
    }
}

fn map_partition_fs_error(error: PartitionFsValidationError) -> InspectionErrorCode {
    match error {
        PartitionFsValidationError::UnsupportedProfile => {
            InspectionErrorCode::UnsupportedInspectionProfile
        }
        PartitionFsValidationError::MalformedInput => InspectionErrorCode::MalformedInput,
        PartitionFsValidationError::InputLimitExceeded => InspectionErrorCode::InputLimitExceeded,
        PartitionFsValidationError::AllocationFailed => InspectionErrorCode::AllocationFailed,
    }
}

/// A bounded read and seek view over one byte span of an open file.
///
/// Inspection and Verification both use this reader so a nested container can
/// be parsed with offsets relative to its own partition and no read can escape
/// the declared span.
pub(crate) struct SpanReader<'a> {
    file: &'a mut std::fs::File,
    start: u64,
    length: u64,
    position: u64,
}

impl<'a> SpanReader<'a> {
    pub(crate) fn new(file: &'a mut std::fs::File, start: u64, length: u64) -> Self {
        Self {
            file,
            start,
            length,
            position: 0,
        }
    }
}

impl Read for SpanReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.position >= self.length || buffer.is_empty() {
            return Ok(0);
        }
        let remaining = self.length - self.position;
        let maximum = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        self.file
            .seek(SeekFrom::Start(self.start + self.position))?;
        let read = self.file.read(&mut buffer[..maximum])?;
        self.position = self
            .position
            .checked_add(read as u64)
            .ok_or_else(|| std::io::Error::other("span position overflow"))?;
        Ok(read)
    }
}

impl Seek for SpanReader<'_> {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        let next = match position {
            SeekFrom::Start(value) => value,
            SeekFrom::End(value) => self
                .length
                .checked_add_signed(value)
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek"))?,
            SeekFrom::Current(value) => self
                .position
                .checked_add_signed(value)
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek"))?,
        };
        if next > self.length {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek beyond span",
            ));
        }
        self.position = next;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InspectionError, InspectionErrorCode, InspectionExitClass, InspectionHost,
        MemoryMonitoringPolicy, MemoryMonitoringStatus,
    };
    use std::num::NonZeroU64;

    #[test]
    fn memory_monitoring_status_reports_disabled_and_unavailable_thresholds() {
        let disabled = InspectionHost::cache_only("cache");
        assert_eq!(
            disabled.memory_monitoring_status(),
            MemoryMonitoringStatus::Disabled
        );

        let threshold_bytes = NonZeroU64::new(1024).unwrap();
        let requested = InspectionHost::cache_only("cache").with_memory_monitoring_policy(
            MemoryMonitoringPolicy::RequirePhysicalFootprintThreshold { threshold_bytes },
        );
        assert_eq!(
            requested.memory_monitoring_status(),
            MemoryMonitoringStatus::Unavailable { threshold_bytes }
        );
    }

    const CODES: &[InspectionErrorCode] = &[
        InspectionErrorCode::InvalidCacheDirectory,
        InspectionErrorCode::InvalidKeyPath,
        InspectionErrorCode::InputUnavailable,
        InspectionErrorCode::UnsupportedFormat,
        InspectionErrorCode::UnsupportedInspectionProfile,
        InspectionErrorCode::TruncatedInput,
        InspectionErrorCode::MalformedInput,
        InspectionErrorCode::InputLimitExceeded,
        InspectionErrorCode::KeyFileUnavailable,
        InspectionErrorCode::KeyFileMalformed,
        InspectionErrorCode::KeyFileLimitExceeded,
        InspectionErrorCode::MissingHeaderKey,
        InspectionErrorCode::ProviderCacheMissing,
        InspectionErrorCode::ProviderArtifactMismatch,
        InspectionErrorCode::ProviderArtifactIncomplete,
        InspectionErrorCode::ProviderArchiveInvalid,
        InspectionErrorCode::ProviderUnsupportedTarget,
        InspectionErrorCode::ProviderUnqualifiedTarget,
        InspectionErrorCode::ProviderContainmentUnsupported,
        InspectionErrorCode::PhysicalFootprintMonitoringUnsupported,
        InspectionErrorCode::ProvisioningDenied,
        InspectionErrorCode::ProvisioningFailed,
        InspectionErrorCode::InputChangedDuringInspection,
        InspectionErrorCode::KeyFileChangedDuringInspection,
        InspectionErrorCode::ProviderCacheBusy,
        InspectionErrorCode::ProviderExecutionBusy,
        InspectionErrorCode::ProviderLaunchFailed,
        InspectionErrorCode::ProviderExitedUnsuccessfully,
        InspectionErrorCode::ProviderCrashed,
        InspectionErrorCode::ProviderTimedOut,
        InspectionErrorCode::ProviderOutputExceeded,
        InspectionErrorCode::ProviderOutputMalformed,
        InspectionErrorCode::ProviderContentUnreadable,
        InspectionErrorCode::ProviderPostconditionMismatch,
        InspectionErrorCode::ProviderInconsistent,
        InspectionErrorCode::Cancelled,
        InspectionErrorCode::ProviderManifestInvalid,
        InspectionErrorCode::CacheLockFailed,
        InspectionErrorCode::CacheCleanupFailed,
        InspectionErrorCode::AllocationFailed,
        InspectionErrorCode::InternalIo,
        InspectionErrorCode::SignalHandlerFailed,
    ];

    #[test]
    fn every_code_has_a_unique_wire_name_and_consistent_class() {
        let mut names = std::collections::BTreeSet::new();
        for code in CODES {
            assert!(names.insert(code.as_str()), "duplicate code {code:?}");
            assert!(!InspectionError::new(*code).to_string().is_empty());
        }
        assert_eq!(InspectionExitClass::Success.code(), 0);
        assert_eq!(InspectionExitClass::Configuration.code(), 2);
        assert_eq!(InspectionExitClass::Prerequisite.code(), 3);
        assert_eq!(InspectionExitClass::Conflict.code(), 4);
        assert_eq!(InspectionExitClass::Provider.code(), 5);
        assert_eq!(InspectionExitClass::Cancelled.code(), 6);
        assert_eq!(InspectionExitClass::Internal.code(), 7);
    }

    #[test]
    fn unsupported_prerequisites_are_not_provider_execution_failures() {
        for code in [
            InspectionErrorCode::ProviderCacheMissing,
            InspectionErrorCode::ProviderArtifactMismatch,
            InspectionErrorCode::ProviderUnqualifiedTarget,
            InspectionErrorCode::ProviderContainmentUnsupported,
            InspectionErrorCode::UnsupportedInspectionProfile,
            InspectionErrorCode::MissingHeaderKey,
        ] {
            assert_eq!(code.exit_class(), InspectionExitClass::Prerequisite);
        }
        for code in [
            InspectionErrorCode::ProviderExitedUnsuccessfully,
            InspectionErrorCode::ProviderTimedOut,
            InspectionErrorCode::ProviderOutputMalformed,
        ] {
            assert_eq!(code.exit_class(), InspectionExitClass::Provider);
        }
    }

    #[test]
    fn every_stable_error_has_the_documented_exit_class() {
        use InspectionErrorCode::*;
        use InspectionExitClass::*;
        let expected = [
            (InvalidCacheDirectory, Configuration),
            (InvalidKeyPath, Configuration),
            (InputUnavailable, Prerequisite),
            (UnsupportedFormat, Prerequisite),
            (UnsupportedInspectionProfile, Prerequisite),
            (TruncatedInput, Prerequisite),
            (MalformedInput, Prerequisite),
            (InputLimitExceeded, Prerequisite),
            (KeyFileUnavailable, Prerequisite),
            (KeyFileMalformed, Prerequisite),
            (KeyFileLimitExceeded, Prerequisite),
            (MissingHeaderKey, Prerequisite),
            (ProviderCacheMissing, Prerequisite),
            (ProviderArtifactMismatch, Prerequisite),
            (ProviderArtifactIncomplete, Prerequisite),
            (ProviderArchiveInvalid, Prerequisite),
            (ProviderUnsupportedTarget, Prerequisite),
            (ProviderUnqualifiedTarget, Prerequisite),
            (ProviderContainmentUnsupported, Prerequisite),
            (PhysicalFootprintMonitoringUnsupported, Prerequisite),
            (ProvisioningDenied, Prerequisite),
            (ProvisioningFailed, Prerequisite),
            (InputChangedDuringInspection, Conflict),
            (KeyFileChangedDuringInspection, Conflict),
            (ProviderCacheBusy, Conflict),
            (ProviderExecutionBusy, Conflict),
            (ProviderLaunchFailed, Provider),
            (ProviderExitedUnsuccessfully, Provider),
            (ProviderCrashed, Provider),
            (ProviderTimedOut, Provider),
            (ProviderOutputExceeded, Provider),
            (ProviderOutputMalformed, Provider),
            (ProviderContentUnreadable, Provider),
            (ProviderPostconditionMismatch, Provider),
            (ProviderInconsistent, Provider),
            (
                InspectionErrorCode::Cancelled,
                InspectionExitClass::Cancelled,
            ),
            (ProviderManifestInvalid, Internal),
            (CacheLockFailed, Internal),
            (CacheCleanupFailed, Internal),
            (AllocationFailed, Internal),
            (InternalIo, Internal),
            (SignalHandlerFailed, Internal),
        ];
        assert_eq!(expected.len(), CODES.len());
        for (code, class) in expected {
            assert_eq!(code.exit_class(), class, "wrong class for {code:?}");
        }
        assert_eq!(
            InspectionError::new(ProviderExecutionBusy).to_string(),
            "this inspection host session already has an active provider execution"
        );
    }

    #[test]
    fn nca_profile_enumerates_each_supported_dimension() {
        use crate::nca::{ContentType, Distribution, Header, Partition};

        fn base() -> Header {
            Header {
                format_version: 3,
                distribution: Distribution::GameCard,
                content_type: ContentType::Program,
                key_generation: 0,
                signature_generation: 0,
                kaek_index: 0,
                declared_size: 0xe00,
                program_id: 0x0102_0304_0506_0708,
                content_index: 0,
                partitions: vec![Partition {
                    index: 0,
                    offset: 0xc00,
                    size: 0x200,
                    filesystem: 1,
                    hash_type: 1,
                    encryption: 1,
                    extended: false,
                }],
            }
        }

        assert!(super::validate_nca_profile(&base()).is_ok());
        let mut cases = Vec::new();
        let mut header = base();
        header.content_type = ContentType::Meta;
        cases.push(header);
        let mut header = base();
        header.key_generation = 0x21;
        cases.push(header);
        let mut header = base();
        header.partitions.clear();
        cases.push(header);
        let mut header = base();
        header.partitions = vec![header.partitions[0].clone(); 5];
        cases.push(header);
        for mutate in [
            |partition: &mut Partition| partition.filesystem = 0,
            |partition: &mut Partition| partition.hash_type = 2,
            |partition: &mut Partition| partition.encryption = 2,
            |partition: &mut Partition| partition.extended = true,
            |partition: &mut Partition| partition.offset = 0x800,
            |partition: &mut Partition| partition.size = 0x100,
        ] {
            let mut header = base();
            mutate(&mut header.partitions[0]);
            cases.push(header);
        }
        for header in cases {
            assert_eq!(
                super::validate_nca_profile(&header),
                Err(InspectionErrorCode::UnsupportedInspectionProfile)
            );
        }
    }

    #[test]
    fn program_ids_serialize_as_sixteen_lowercase_hex_digits() {
        assert_eq!(
            super::ProgramId::from_u64(0x0102_0304_0506_0708).to_hex(),
            "0102030405060708"
        );
        assert_eq!(
            serde_json::to_string(&super::ProgramId::from_u64(0x0102_0304_0506_0708)).unwrap(),
            "\"0102030405060708\""
        );
    }
}
