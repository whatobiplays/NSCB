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

mod allocation;
#[expect(
    dead_code,
    reason = "The qualifier remains outside the existing NSP, Verification, and conversion flows."
)]
mod control_nca_qualification;
mod engine;
mod error;
mod extraction;
mod file_identity;
mod input_resolution;
mod inspection;
mod key_file;
#[cfg(any(target_os = "macos", test))]
mod multi_content_format;
mod nca;
mod nca_crypto;
#[cfg(target_os = "macos")]
mod ncz;
mod nsp_nsz;
mod nsp_semantic_qualification;
mod operation;
mod partition_fs;
mod pfs0;
#[cfg(any(target_os = "macos", test))]
mod program_repack;
mod provider;
mod recognition;
mod sha256;
pub mod split_finalization;
mod split_manifest;
mod split_operation;
mod split_reader;
mod split_resolution;
mod split_trust;
mod strict_json;
mod verification;
#[cfg(target_os = "macos")]
mod xci_format;
mod xci_to_nsp;
mod xci_to_xcz;
mod xcz_to_xci;

#[cfg(test)]
mod test_allocator;

#[cfg(test)]
#[global_allocator]
static QUALIFICATION_TEST_ALLOCATOR: test_allocator::TestAllocator = test_allocator::TestAllocator;

#[cfg(test)]
#[path = "../tests/support/synthetic_verification.rs"]
#[allow(dead_code)]
mod test_synthetic_verification;

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) mod support {
    pub(crate) use crate::test_synthetic_verification as synthetic_verification;
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
#[path = "../tests/support/synthetic_extraction.rs"]
#[allow(dead_code)]
mod test_synthetic_extraction;

#[cfg(test)]
#[path = "../tests/support/synthetic_nsp_qualification.rs"]
#[allow(dead_code)]
mod test_synthetic_nsp_qualification;

#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use test_synthetic_nsp_qualification as synthetic_nsp_qualification;

#[cfg(test)]
#[path = "../tests/support/synthetic_xci.rs"]
#[allow(dead_code)]
mod test_synthetic_xci;

pub use recognition::{
    CompressionVariant, ContentRecognitionError, ContentRecognitionErrorCode,
    ContentRecognitionRequest, ContentRecognitionResult, ExtensionObservation, RecognitionOutcome,
    RecognizedFamily, StructuralEligibility, TicketNameObservation,
};

pub use engine::{
    ContainerFormat, ContainerProbeEntry, ContainerProbeRequest, ContainerProbeResult, Engine,
};
pub use error::{ContainerProbeError, ContainerProbeErrorCode};
pub use extraction::{
    ExtractionCompleteness, ExtractionManifest, ExtractionManifestFile,
    ExtractionManifestPartition, ExtractionManifestSource, ExtractionRequest, ExtractionSelection,
    ExtractionSelectionMode, ExtractionSelectors, NcaContentId, NcaContentIdParseError,
    is_portable_bundle_leaf,
};
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
    MultiContentBuildRequest, MultiContentProfile, MultiContentSplitRequest, OperationArtifact,
    OperationArtifactRole, OperationCompletion, OperationError, OperationEvent,
    OperationEventConsumer, OperationEventKind, OperationFailure, OperationFailureCode,
    OperationKind, OperationMilestone, OperationOutcome, OperationPlan, OperationPlanSnapshot,
    OperationResult, OperationSession, OperationSessionPhase, OperationSessionSnapshot,
    OperationSessionStatus, PlannedArtifact, PlannedContentGroup, PlannedContentMember,
    PlannedEffect, PlannedSource, RepackRequest, StagingStrategy,
};
pub use split_manifest::SplitLayout;
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
    NcaPartition, ProgramId, ProgramIdParseError,
};
pub use sha256::{InvalidSha256Digest, SHA256_HEX_LENGTH, Sha256Digest};
pub use split_trust::{
    LocalSplitTrustStore, SplitTrustCleanupLease, SplitTrustCommitAction, SplitTrustReceipt,
    SplitTrustRestore, SplitTrustStore, SplitTrustStoreError, SplitTrustWriter,
};

pub use nsp_nsz::{NspToNszRequest, NszCompression, NszToNspRequest};
pub use verification::{
    CheckApplicability, CheckExecution, CheckOutcome, PublicKeyEncoding, TrustProvenance,
    TrustProvenanceKind, VerificationCheck, VerificationCheckId, VerificationError,
    VerificationErrorCode, VerificationLimitation, VerificationOutcome, VerificationProfile,
    VerificationReason, VerificationRequest, VerificationResult,
};
pub use xci_to_nsp::XciToNspRequest;
pub use xci_to_xcz::XciToXczRequest;
pub use xcz_to_xci::XczToXciRequest;
