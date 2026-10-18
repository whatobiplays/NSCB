//! Runtime-neutral Rust facade for bounded, read-only Probe, Recognition,
//! input-resolution, and qualified Inspection operations.
//!
//! Container Probe validates outer PFS0 framing without reading payloads.
//! Recognition examines bounded structural metadata and reports positive families,
//! uncertainty, and package/card structural eligibility without execution authority.
//! Neither operation establishes title identity, authenticity, or Verification.

mod engine;
mod error;
mod file_identity;
mod input_resolution;
mod inspection;
mod nca;
mod pfs0;
mod provider;
mod recognition;
mod sha256;
mod split_manifest;
mod split_reader;
mod split_resolution;
mod split_trust;
mod strict_json;

pub use recognition::{
    CompressionVariant, ContentRecognitionError, ContentRecognitionErrorCode,
    ContentRecognitionRequest, ContentRecognitionResult, ExtensionObservation, RecognitionOutcome,
    RecognizedFamily, StructuralEligibility, TicketNameObservation,
};

pub use engine::{
    ContainerFormat, ContainerProbeEntry, ContainerProbeRequest, ContainerProbeResult, Engine,
};
pub use error::{ContainerProbeError, ContainerProbeErrorCode};

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
