use crate::error::{ContainerProbeError, ContainerProbeErrorCode};
use crate::inspection::{
    InspectionError, InspectionErrorCode, InspectionHost, InspectionPreflightStatus,
    InspectionRequest, InspectionResult,
};
use crate::pfs0;
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

/// A runtime-neutral facade for supported read-only Engine operations.
pub struct Engine;

impl Engine {
    /// Creates an engine without global state, persistent storage, or a runtime requirement.
    pub const fn new() -> Self {
        Self
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
}
