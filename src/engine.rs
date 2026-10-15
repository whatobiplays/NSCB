use crate::error::{ContainerProbeError, ContainerProbeErrorCode};
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

/// A runtime-neutral facade for the supported read-only container probe.
#[derive(Default)]
pub struct Engine;

impl Engine {
    /// Recognizes byte-supported structure without keys, execution authority, or content identity.
    pub fn recognize_content(
        &self,
        request: crate::ContentRecognitionRequest,
    ) -> Result<crate::ContentRecognitionResult, crate::ContentRecognitionError> {
        let (mut file, size) =
            open_regular_file(request.path()).map_err(crate::recognition::from_probe_error)?;
        crate::recognition::recognize(&mut file, size, request.path())
    }

    /// Creates an engine without global state, persistent storage, or a runtime requirement.
    pub const fn new() -> Self {
        Self
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
