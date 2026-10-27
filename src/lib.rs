//! Runtime-neutral Rust facade for bounded Probe, Recognition,
//! input-resolution, qualified Inspection, and safe copy-through operations.
//!
//! Container Probe validates outer PFS0 framing without reading payloads.
//! Recognition examines bounded structural metadata and reports positive families,
//! uncertainty, and package/card structural eligibility without execution authority.
//! Neither operation establishes title identity, authenticity, or Verification.
//! Copy-through plans are immutable in-memory capabilities and publish only
//! independently validated bytes through the host filesystem's atomic rename
//! or link operations.

mod engine;
mod error;
mod file_identity;
mod input_resolution;
mod inspection;
mod nca;
mod operation;
mod partition_fs;
mod pfs0;
mod provider;
mod recognition;
mod sha256;
mod split_manifest;
mod split_reader;
mod split_resolution;
mod split_trust;
mod strict_json;
mod verification;

#[cfg(test)]
#[path = "../tests/support/synthetic_verification.rs"]
#[allow(dead_code)]
mod test_synthetic_verification;

pub use recognition::{
    CompressionVariant, ContentRecognitionError, ContentRecognitionErrorCode,
    ContentRecognitionRequest, ContentRecognitionResult, ExtensionObservation, RecognitionOutcome,
    RecognizedFamily, StructuralEligibility, TicketNameObservation,
};

pub use engine::{
    ContainerFormat, ContainerProbeEntry, ContainerProbeRequest, ContainerProbeResult, Engine,
};
pub use error::{ContainerProbeError, ContainerProbeErrorCode};
pub use operation::{
    ConflictPolicy, CopyThroughRequest, DestinationBaseline, JobState, OperationArtifact,
    OperationArtifactRole, OperationCompletion, OperationError, OperationEvent,
    OperationEventConsumer, OperationEventKind, OperationFailure, OperationFailureCode,
    OperationMilestone, OperationOutcome, OperationPlan, OperationPlanSnapshot, OperationResult,
    OperationSession, OperationSessionPhase, OperationSessionSnapshot, OperationSessionStatus,
    PlannedArtifact, PlannedEffect, PlannedSource, StagingStrategy,
};

pub use input_resolution::{
    DEFAULT_MAX_SPLIT_VALIDATION_BYTES, InputProvenance, InputResolutionCapabilities,
    InputResolutionControl, InputResolutionError, InputResolutionErrorCode,
    InputResolutionProgress, InputResolutionRequest, InputResolutionResult, InputSegment,
    InputSelection, InputSelectionSource, ResolvedInput, SplitQualification,
    SplitQualificationKind,
};
pub use inspection::{
    CancellationHandle, InspectionCapability, InspectionEntry, InspectionError,
    InspectionErrorCode, InspectionExitClass, InspectionHost, InspectionPreflightStatus,
    InspectionRequest, InspectionResult, MemoryMonitoringPolicy, MemoryMonitoringStatus,
    NcaContentType, NcaDistribution, NcaEncryptionType, NcaFilesystem, NcaHashType, NcaInspection,
    NcaPartition, ProgramId,
};
pub use sha256::{InvalidSha256Digest, SHA256_HEX_LENGTH, Sha256Digest};
pub use split_trust::{
    LocalSplitTrustStore, SplitTrustReceipt, SplitTrustRestore, SplitTrustStore,
    SplitTrustStoreError, SplitTrustWriter,
};

pub use verification::{
    CheckApplicability, CheckExecution, CheckOutcome, PublicKeyEncoding, TrustProvenance,
    TrustProvenanceKind, VerificationCheck, VerificationCheckId, VerificationError,
    VerificationErrorCode, VerificationLimitation, VerificationOutcome, VerificationProfile,
    VerificationReason, VerificationRequest, VerificationResult,
};
