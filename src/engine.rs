use crate::error::{ContainerProbeError, ContainerProbeErrorCode};
use crate::inspection::{
    CancellationHandle, InspectionError, InspectionErrorCode, InspectionHost,
    InspectionPreflightStatus, InspectionRequest, InspectionResult,
};
use crate::operation::{
    CopyBatchCheckpointError, CopyBatchExecution, CopyBatchItemCheckpoint, CopyBatchPlan,
    CopyBatchRequest, CopyBatchResult, CopyBatchSession, CopyThroughRequest,
    MultiContentBuildRequest, MultiContentSplitRequest, OperationError, OperationFailureCode,
    OperationPlan, OperationResult, OperationSession,
};
use crate::pfs0;
use crate::split_operation::{SplitPlan, SplitRequest};
use crate::split_trust::SplitTrustWriter;
use crate::xci_to_nsp::XciToNspRequest;
use serde::Serialize;
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// A request to validate and summarize one local outer-container file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerProbeRequest {
    path: PathBuf,
}

impl ContainerProbeRequest {
    /// Creates a request for the file at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

/// A runtime-neutral facade for container probing, recognition, resolution,
/// inspection, verification, source-backed Split, and copy-through operations.
/// Copy-through and Split planning are read-only; executing a plan performs
/// filesystem publication.
pub struct Engine;

impl Engine {
    /// Creates an engine without global state, persistent storage, or a runtime requirement.
    pub const fn new() -> Self {
        Self
    }

    /// Resolves a copy-through request into an immutable, inspectable plan.
    ///
    /// Planning reads the source and destination state but does not modify
    /// either path. The returned plan is an in-memory capability consumed by
    /// `execute_operation`.
    pub fn plan_copy_through(
        &self,
        request: CopyThroughRequest,
    ) -> Result<OperationPlan, OperationError> {
        crate::operation::plan_copy_through(request)
    }

    /// Resolves a typed multi-content Build request into an immutable plan.
    ///
    /// Planning validates supported PFS0 and plaintext Program NCA structures,
    /// derives exact ProgramId groups from member bytes, and records source
    /// evidence without changing any path.
    pub fn plan_multi_content_build(
        &self,
        request: MultiContentBuildRequest,
    ) -> Result<OperationPlan, OperationError> {
        crate::operation::plan_multi_content_build(request)
    }

    /// Resolves a typed multi-content Split request into an immutable plan.
    ///
    /// The resulting directory contains one deterministic PFS0 package per
    /// validated ProgramId group and is published as a single operation unit.
    pub fn plan_multi_content_split(
        &self,
        request: MultiContentSplitRequest,
    ) -> Result<OperationPlan, OperationError> {
        crate::operation::plan_multi_content_split(request)
    }

    /// Resolves a rights-free base Application XCI into a planned NSP output.
    ///
    /// The XCI partitions, HFS0 prefix hashes, and secure members are checked
    /// before the existing NSP semantic qualifier assigns member roles. The
    /// operation preserves source NCA bytes and is available only on macOS.
    pub fn plan_xci_to_nsp(
        &self,
        request: XciToNspRequest,
    ) -> Result<OperationPlan, OperationError> {
        crate::operation::plan_xci_to_nsp(request)
    }

    /// Resolves an explicit regular source and outer bundle destination into a
    /// non-replayable canonical Split plan.
    pub fn plan_split<'a>(
        &self,
        request: SplitRequest,
        trust_store: &'a dyn SplitTrustWriter,
    ) -> Result<SplitPlan<'a>, OperationError> {
        crate::split_operation::plan_split(request, trust_store)
    }

    /// Checks whether the nearest existing parent supports Split publication.
    ///
    /// The method does not create directories. Unsupported or unverifiable
    /// filesystem capabilities return an error.
    pub fn validate_split_output_parent(&self, path: &Path) -> Result<(), OperationFailureCode> {
        crate::split_operation::validate_split_output_parent(path)
    }

    /// Resolves a Split plan while honoring cancellation during source hashing.
    ///
    /// The returned plan remains non-replayable and execution still uses the
    /// caller's operation session for progress and cancellation after planning.
    pub fn plan_split_with_cancellation<'a>(
        &self,
        request: SplitRequest,
        trust_store: &'a dyn SplitTrustWriter,
        cancellation: CancellationHandle,
    ) -> Result<SplitPlan<'a>, OperationError> {
        crate::split_operation::plan_split_with_cancellation(request, trust_store, cancellation)
    }

    /// Executes one canonical Split plan using host-owned session state.
    pub fn execute_split(
        &self,
        plan: SplitPlan<'_>,
        session: &OperationSession,
    ) -> OperationResult {
        crate::split_operation::execute_split(plan, session, None)
    }

    /// Executes one canonical Split plan with caller-owned cancellation.
    pub fn execute_split_with_cancellation(
        &self,
        plan: SplitPlan<'_>,
        session: &OperationSession,
        cancellation: CancellationHandle,
    ) -> OperationResult {
        crate::split_operation::execute_split(plan, session, Some(cancellation))
    }
    /// Resolves independent regular files into one immutable sequential copy plan.
    ///
    /// The output directory must already exist. Planning performs no filesystem
    /// mutation. Item-local preflight failures are retained only when at least
    /// one other item is viable; duplicate identities, destination collisions,
    /// unsafe paths, and shared capability failures reject the whole request.
    pub fn plan_copy_batch(
        &self,
        request: CopyBatchRequest,
    ) -> Result<CopyBatchPlan, OperationError> {
        crate::operation::plan_copy_batch(request)
    }

    /// Executes one plan using admission and cancellation state from `session`.
    ///
    /// Clones of a session share operation admission. Separate sessions remain
    /// independent; destination publication is coordinated by the planned
    /// parent-directory lock.
    pub fn execute_operation(
        &self,
        plan: OperationPlan,
        session: &OperationSession,
    ) -> OperationResult {
        crate::operation::execute_operation(plan, session)
    }

    /// Executes one plan with cancellation bound to this invocation.
    ///
    /// The handle is observed while this execution holds admission and lets a
    /// caller request cancellation before execution starts. A request made
    /// before execution is reported as a cancelled result before any
    /// operation-owned workspace or staging entry is created. NSCB does not
    /// clear or reset the caller-owned handle after execution. A host must pass
    /// a fresh handle to each invocation that should remain independently
    /// cancellable; deliberately passing an already-cancelled handle requests
    /// cancellation of that later invocation.
    pub fn execute_operation_with_cancellation(
        &self,
        plan: OperationPlan,
        session: &OperationSession,
        cancellation: CancellationHandle,
    ) -> OperationResult {
        crate::operation::execute_operation_with_cancellation(plan, session, &cancellation)
    }
    /// Executes one immutable copy batch without caller-supplied cancellation.
    pub fn execute_copy_batch(
        &self,
        plan: CopyBatchPlan,
        session: &CopyBatchSession,
    ) -> CopyBatchResult {
        let cancellation = CancellationHandle::new();
        self.execute_copy_batch_with_checkpoint(plan, session, cancellation, |_| Ok(()))
            .into_result()
    }
    /// Executes one immutable copy batch with caller-owned cancellation.
    ///
    /// Cancellation is latched on the caller-owned handle. Once cancellation
    /// has been accepted, a later independent batch using the same handle is
    /// also cancelled. Pass a fresh `CancellationHandle` for each independent
    /// batch that should remain separately cancellable.
    pub fn execute_copy_batch_with_cancellation(
        &self,
        plan: CopyBatchPlan,
        session: &CopyBatchSession,
        cancellation: CancellationHandle,
    ) -> CopyBatchResult {
        self.execute_copy_batch_with_checkpoint(plan, session, cancellation, |_| Ok(()))
            .into_result()
    }
    /// Executes items sequentially and checkpoints each result before advancing.
    ///
    /// A checkpoint error stops execution before the next item. Completed item
    /// evidence remains in the returned aggregate and session completion.
    ///
    /// Cancellation is latched on the caller-owned handle. An already-cancelled
    /// handle remains cancelled for later calls. Pass a fresh
    /// `CancellationHandle` for each independent batch that should remain
    /// separately cancellable.
    pub fn execute_copy_batch_with_checkpoint(
        &self,
        plan: CopyBatchPlan,
        session: &CopyBatchSession,
        cancellation: CancellationHandle,
        checkpoint: impl FnMut(CopyBatchItemCheckpoint) -> Result<(), CopyBatchCheckpointError>,
    ) -> CopyBatchExecution {
        crate::operation::execute_copy_batch_with_checkpoint_and_cancellation(
            plan,
            session,
            cancellation,
            checkpoint,
        )
    }

    /// Validates request and provider prerequisites without launching a helper.
    pub fn preflight_inspection(
        &self,
        request: &InspectionRequest,
        host: &InspectionHost,
    ) -> Result<InspectionPreflightStatus, InspectionError> {
        crate::provider::preflight(request, host).map_err(InspectionError::new)
    }

    /// Runs one keyed, provider-backed, read-only Inspection.
    ///
    /// At most one helper execution is active per explicitly constructed host
    /// session. Admission is shared by clones of that host and releases on all
    /// return paths.
    pub fn inspect(
        &self,
        request: InspectionRequest,
        host: &InspectionHost,
    ) -> Result<InspectionResult, InspectionError> {
        let _admission = host.begin_inspection().map_err(InspectionError::new)?;
        if request.capability() != crate::InspectionCapability::Nca {
            return Err(InspectionError::new(
                InspectionErrorCode::UnsupportedInspectionProfile,
            ));
        }
        crate::inspection::inspect(&request, host).map_err(InspectionError::new)
    }

    /// Runs one native, read-only Verification of a supported standalone NCA3
    /// file.
    ///
    /// Verification never launches a provider and never modifies the content,
    /// key source, or trust anchor. The returned evidence distinguishes checks
    /// that completed from checks that did not apply to the selected profile or
    /// could not run.
    pub fn verify(
        &self,
        request: crate::VerificationRequest,
    ) -> Result<crate::VerificationResult, crate::VerificationError> {
        crate::verification::verify(request)
    }

    /// Checks byte-derived consistency for the supported two-member NSP profile.
    ///
    /// The result does not establish authenticity, installability, Full
    /// Verification, or compatibility with other package profiles.
    pub fn qualify_nsp_semantics(
        &self,
        request: crate::NspSemanticQualificationRequest,
    ) -> Result<crate::NspSemanticQualificationResult, crate::NspSemanticQualificationError> {
        crate::nsp_semantic_qualification::qualify(request)
    }

    /// Recognizes byte-supported structure without keys, execution authority, or content identity.
    pub fn recognize_content(
        &self,
        request: crate::ContentRecognitionRequest,
    ) -> Result<crate::ContentRecognitionResult, crate::ContentRecognitionError> {
        let (mut file, size) =
            open_regular_file(request.path()).map_err(crate::recognition::from_probe_error)?;
        crate::recognition::recognize(&mut file, size, request.path())
    }

    /// Validates supported outer-container framing and returns structural facts.
    ///
    /// The operation reads the container header and metadata tables only. It
    /// does not read payload bytes or interpret embedded content.
    pub fn probe_container(
        &self,
        request: ContainerProbeRequest,
    ) -> Result<ContainerProbeResult, ContainerProbeError> {
        let (mut file, file_size) = open_regular_file(&request.path)?;
        pfs0::probe(&mut file, file_size)
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

/// Opens a read-only regular file and obtains size from the opened handle.
fn open_regular_file(path: &Path) -> Result<(File, u64), ContainerProbeError> {
    #[cfg(unix)]
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| ContainerProbeError::new(ContainerProbeErrorCode::InputUnavailable))?;

    #[cfg(not(unix))]
    let file = {
        let path_metadata = std::fs::metadata(path)
            .map_err(|_| ContainerProbeError::new(ContainerProbeErrorCode::InputUnavailable))?;
        if !path_metadata.file_type().is_file() {
            return Err(ContainerProbeError::new(
                ContainerProbeErrorCode::InputUnavailable,
            ));
        }
        OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|_| ContainerProbeError::new(ContainerProbeErrorCode::InputUnavailable))?
    };

    let metadata = file
        .metadata()
        .map_err(|_| ContainerProbeError::new(ContainerProbeErrorCode::InputUnavailable))?;
    if !metadata.file_type().is_file() {
        return Err(ContainerProbeError::new(
            ContainerProbeErrorCode::InputUnavailable,
        ));
    }

    Ok((file, metadata.len()))
}

/// An outer-container format recognized by the probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerFormat {
    /// The PFS0 outer-container framing format.
    Pfs0,
}

/// Validated structural facts for one PFS0 file entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ContainerProbeEntry {
    /// The UTF-8 name stored in the PFS0 string table.
    pub name: String,
    /// The byte offset from the beginning of the PFS0 payload region.
    pub offset: u64,
    /// The declared byte length of this entry.
    pub size: u64,
    /// The checked absolute file position, equal to payload offset plus `offset`.
    pub file_offset: u64,
}

/// Validated outer-container framing and structural facts for one file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ContainerProbeResult {
    /// The recognized outer-container framing format.
    pub format: ContainerFormat,
    /// The file size observed before reading container metadata.
    pub file_size: u64,
    /// The absolute file position at which payload-relative entry offsets begin.
    pub payload_offset: u64,
    /// The number of bytes from `payload_offset` to the end of the file.
    pub payload_size: u64,
    /// Entries in the order declared by the PFS0 entry table.
    pub entries: Vec<ContainerProbeEntry>,
}

#[cfg(test)]
mod tests {
    use super::Engine;
    use crate::{InspectionErrorCode, InspectionHost, InspectionRequest};

    #[test]
    fn helper_execution_limit_is_shared_by_an_explicit_host_session() {
        let host = InspectionHost::cache_only("/missing/cache");
        let admission = host.begin_inspection().unwrap();
        let request = InspectionRequest::nca("/missing/input.nca", "/missing/prod.keys");
        assert_eq!(
            Engine::new().inspect(request, &host).unwrap_err().code(),
            InspectionErrorCode::ProviderExecutionBusy
        );

        let request = InspectionRequest::nca("/missing/input.nca", "/missing/prod.keys");
        let cloned_host = host.clone();
        assert_eq!(
            Engine.inspect(request, &cloned_host).unwrap_err().code(),
            InspectionErrorCode::ProviderExecutionBusy
        );

        drop(admission);
        let request = InspectionRequest::nca("/missing/input.nca", "/missing/prod.keys");
        let error = Engine::inspect(&Engine, request, &host).unwrap_err();
        assert_ne!(error.code(), InspectionErrorCode::ProviderExecutionBusy);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn copy_batch_capabilities_fail_closed_on_unqualified_platforms() {
        use crate::{
            CancellationHandle, CopyBatchRequest, CopyBatchSession, JobState, OperationFailureCode,
        };

        let planning_error = match Engine::new().plan_copy_batch(
            CopyBatchRequest::new("/missing-output", "/missing-workspace")
                .with_source("/missing-source"),
        ) {
            Ok(_) => panic!("batch copy planning is qualified only on macOS"),
            Err(error) => error,
        };
        assert_eq!(
            planning_error.code(),
            OperationFailureCode::UnsupportedCapability
        );

        let session = CopyBatchSession::new();
        let execution = Engine::new().execute_copy_batch_with_checkpoint(
            crate::operation::unsupported_copy_batch_plan_for_test(),
            &session,
            CancellationHandle::new(),
            |_| Ok(()),
        );
        assert_eq!(execution.result().state(), JobState::Failed);
        assert_eq!(
            execution.result().failure().map(|failure| failure.code()),
            Some(OperationFailureCode::UnsupportedCapability)
        );
        assert!(!session.is_busy());
    }
}
