//! Runtime-neutral Rust facade for bounded Probe, Recognition,
//! input-resolution, qualified Inspection, safe copy-through, and the supported
//! structural multi-content Build/Split profile.
//!
//! Container Probe validates outer PFS0 framing without reading payloads.
//! Recognition examines bounded structural metadata and reports positive families,
//! uncertainty, and package/card structural eligibility without execution authority.
//! Neither operation establishes title identity, authenticity, or Verification.
//! Copy-through and multi-content operations plan immutable in-memory
//! capabilities. They publish only independently checked output bytes through
//! the host filesystem's qualified atomic rename or link operations.

mod engine;
mod error;
mod file_identity;
mod input_resolution;
mod inspection;
mod key_file;
#[cfg(any(target_os = "macos", test))]
mod multi_content_format;
mod nca;
mod nsp_semantic_qualification;
mod operation;
mod partition_fs;
mod pfs0;
mod provider;
mod recognition;
mod sha256;
mod split_manifest;
mod split_operation;
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
pub use nsp_semantic_qualification::{
    NspSemanticQualificationError, NspSemanticQualificationErrorCode,
    NspSemanticQualificationFacts, NspSemanticQualificationMember, NspSemanticQualificationOutcome,
    NspSemanticQualificationProfile, NspSemanticQualificationReason,
    NspSemanticQualificationRequest, NspSemanticQualificationResult, NspSemanticQualificationRole,
};
pub use operation::{
    ConflictPolicy, CopyBatchCheckpointError, CopyBatchCompletion, CopyBatchEvent,
    CopyBatchEventConsumer, CopyBatchEventKind, CopyBatchExecution, CopyBatchItemCheckpoint,
    CopyBatchItemPlanSnapshot, CopyBatchItemPlanState, CopyBatchItemRequest, CopyBatchItemResult,
    CopyBatchItemState, CopyBatchPlan, CopyBatchPlanSnapshot, CopyBatchProgress, CopyBatchRequest,
    CopyBatchResult, CopyBatchSession, CopyBatchSessionPhase, CopyBatchSessionSnapshot,
    CopyBatchSessionStatus, CopyThroughRequest, DestinationBaseline, JobState,
    MultiContentBuildRequest, MultiContentSplitRequest, OperationArtifact, OperationArtifactRole,
    OperationCompletion, OperationError, OperationEvent, OperationEventConsumer,
    OperationEventKind, OperationFailure, OperationFailureCode, OperationKind, OperationMilestone,
    OperationOutcome, OperationPlan, OperationPlanSnapshot, OperationResult, OperationSession,
    OperationSessionPhase, OperationSessionSnapshot, OperationSessionStatus, PlannedArtifact,
    PlannedContentGroup, PlannedContentMember, PlannedEffect, PlannedSource, StagingStrategy,
};
pub use split_operation::{
    SplitBundleBaseline, SplitOutputPaths, SplitPlan, SplitPlanSnapshot, SplitReceiptCommitState,
    SplitRequest,
};

pub use input_resolution::{
    DEFAULT_MAX_SPLIT_VALIDATION_BYTES, InputProvenance, InputResolutionBatchEntry,
    InputResolutionBatchRequest, InputResolutionBatchResult, InputResolutionCapabilities,
    InputResolutionControl, InputResolutionError, InputResolutionErrorCode, InputResolutionFailure,
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
    LocalSplitTrustStore, SplitTrustCleanupLease, SplitTrustCommitAction, SplitTrustReceipt,
    SplitTrustRestore, SplitTrustStore, SplitTrustStoreError, SplitTrustWriter,
};

pub use verification::{
    CheckApplicability, CheckExecution, CheckOutcome, PublicKeyEncoding, TrustProvenance,
    TrustProvenanceKind, VerificationCheck, VerificationCheckId, VerificationError,
    VerificationErrorCode, VerificationLimitation, VerificationOutcome, VerificationProfile,
    VerificationReason, VerificationRequest, VerificationResult,
};
