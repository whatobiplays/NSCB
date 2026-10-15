//! Runtime-neutral Rust facade for separate read-only Container Probe and recognition operations.
//!
//! Container Probe validates outer PFS0 framing without reading payloads.
//! Recognition examines bounded structural metadata and reports positive families,
//! uncertainty, and package/card structural eligibility without execution authority.
//! Neither operation establishes title identity, authenticity, or Verification.

mod engine;
mod error;
mod input_resolution;
mod pfs0;
mod recognition;

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
    InputProvenance, InputResolutionError, InputResolutionErrorCode, InputResolutionRequest,
    InputResolutionResult, InputSegment, InputSelection, InputSelectionSource, ResolvedInput,
};
