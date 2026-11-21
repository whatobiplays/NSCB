//! Read-only integrity qualification for one bounded, rights-free Control NCA profile.
//!
//! The qualifier accepts one NCA3 RomFS profile and returns private structural facts. It does
//! not establish signatures, authenticity, full Verification, or conversion readiness. The
//! profile limits and format decisions are documented in
//! `docs/testing/control-nca-qualification.md`.

use crate::allocation::{AllocationSite, reserve_exact};
use crate::file_identity::{FileIdentity, FileSnapshot};
use crate::key_file::{NspKeyFileError, NspQualificationKeys};
use crate::nca::{self, ContentType, Distribution, HeaderError, Partition};
use crate::nca_crypto::{NcaCtrReader, decrypt_key_area_slot2};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_ROMFS_METADATA_BYTES: u64 = 1024 * 1024;
const MAX_ROMFS_RECORDS: usize = 32_768;
const IVFC_LEVEL_COUNT: usize = 6;
const IVFC_HEADER_SIZE: usize = 0xe0;
const IVFC_HEADER_IN_FS: usize = 8;
const IVFC_DESCRIPTOR_OFFSET: usize = 0x10;
const IVFC_DESCRIPTOR_SIZE: usize = 0x18;
const IVFC_BLOCK_EXPONENT: u32 = 14;
const IVFC_BLOCK_SIZE: usize = 1 << IVFC_BLOCK_EXPONENT;
/// Maximum SHA-256 operations for a section within the 64 GiB NCA input limit.
///
/// The five child levels occupy disjoint spans within the section. Their combined block count
/// is at most `ceil(64 GiB / 16 KiB) + 4`; one master digest adds the final operation.
/// See `docs/testing/control-nca-qualification.md` for the complete derivation.
const MAX_IVFC_HASH_OPERATIONS: u64 = 4_194_309;
const IVFC_HASH_BUFFER_BYTES: usize = 64 * 1024;
const ROMFS_HEADER_SIZE: usize = 0x50;
const ROMFS_DIRECTORY_RECORD_SIZE: usize = 0x18;
const ROMFS_FILE_RECORD_SIZE: usize = 0x20;
const ROMFS_EMPTY: u32 = u32::MAX;

/// The one Control NCA profile this qualifier can establish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlNcaQualificationProfile {
    /// Rights-free base Control NCA3 with one AES-CTR RomFS section.
    RightsFreeControlRomFsV1,
}

/// A sanitized reason that the source does not match the supported profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlNcaQualificationReason {
    InvalidNcaHeader,
    UnsupportedNcaProfile,
    RightsBearingContent,
    InvalidIvfcLayout,
    InvalidIvfcPadding,
    IvfcIntegrityFailure { level: u8 },
    InvalidRomFsLayout,
    InvalidRomFsGraph,
    InvalidRomFsExtent,
}

/// The result of checking the supported Control NCA profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ControlNcaQualificationOutcome {
    Qualified(ControlNcaQualificationFacts),
    NotQualified(ControlNcaQualificationReason),
}

/// Facts established by the integrity and RomFS structure checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControlNcaQualificationFacts {
    pub(crate) profile: ControlNcaQualificationProfile,
    pub(crate) program_id: u64,
    pub(crate) section_size: u64,
    pub(crate) romfs_size: u64,
    pub(crate) directory_count: usize,
    pub(crate) file_count: usize,
    pub(crate) hash_operations: u64,
}

/// Validated RomFS names and byte spans used only by standalone extraction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControlNcaExtractionInventory {
    pub(crate) metadata: ControlNcaExtractionMetadata,
    pub(crate) directories: Vec<String>,
    pub(crate) files: Vec<crate::inspection::NativeNcaFileSpan>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControlNcaExtractionMetadata {
    pub(crate) program_id: u64,
    pub(crate) content_index: u32,
    pub(crate) partition_index: u8,
    pub(crate) partition_offset: u64,
    pub(crate) partition_size: u64,
    pub(crate) section_ctr: [u8; 8],
}

/// A path-backed request for bounded Control NCA integrity qualification.
#[derive(Clone)]
pub(crate) struct ControlNcaQualificationRequest {
    input: PathBuf,
    key_file: PathBuf,
    cancellation: Option<crate::CancellationHandle>,
    expected_key_snapshot: Option<FileSnapshot>,
}

#[derive(Clone, Copy)]
struct QualificationControl<'a> {
    cancellation: Option<&'a crate::CancellationHandle>,
}

#[derive(Clone, Copy)]
enum ControlQualificationOutput {
    Facts,
    ExtractionInventory,
}

enum QualifiedProfileOutcome {
    Qualified {
        facts: ControlNcaQualificationFacts,
    },
    QualifiedForExtraction {
        inventory: ControlNcaExtractionInventory,
    },
    NotQualified(ControlNcaQualificationReason),
}

impl ControlNcaQualificationRequest {
    /// Creates a request using explicit source and key-file paths.
    pub(crate) fn new(input: impl Into<PathBuf>, key_file: impl Into<PathBuf>) -> Self {
        Self {
            input: input.into(),
            key_file: key_file.into(),
            cancellation: None,
            expected_key_snapshot: None,
        }
    }

    /// Binds qualification to the key-file snapshot captured by its operation plan.
    pub(crate) fn with_expected_key_snapshot(mut self, snapshot: FileSnapshot) -> Self {
        self.expected_key_snapshot = Some(snapshot);
        self
    }

    /// Attaches host-owned cancellation state to the request.
    pub(crate) fn with_cancellation(mut self, cancellation: crate::CancellationHandle) -> Self {
        self.cancellation = Some(cancellation);
        self
    }
}

impl fmt::Debug for ControlNcaQualificationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlNcaQualificationRequest")
            .field("input", &"[REDACTED]")
            .field("key_file", &"[REDACTED]")
            .field("cancellation", &self.cancellation.is_some())
            .field(
                "expected_key_snapshot",
                &self.expected_key_snapshot.is_some(),
            )
            .finish()
    }
}

/// Stable private error categories for source, key, cancellation, and resources.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlNcaQualificationErrorCode {
    InputUnavailable,
    InputChangedDuringQualification,
    KeyFileUnavailable,
    KeyFileChangedDuringQualification,
    KeyFileMalformed,
    MissingHeaderKey,
    MissingApplicationKeyAreaKey,
    KeyFileLimitExceeded,
    InputLimitExceeded,
    ResourceLimitExceeded,
    AllocationFailed,
    Cancelled,
    InternalIo,
}

/// A sanitized failure that never includes paths or key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControlNcaQualificationError {
    code: ControlNcaQualificationErrorCode,
}

impl ControlNcaQualificationError {
    const fn new(code: ControlNcaQualificationErrorCode) -> Self {
        Self { code }
    }

    pub(crate) const fn code(self) -> ControlNcaQualificationErrorCode {
        self.code
    }
}

impl fmt::Display for ControlNcaQualificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.code {
            ControlNcaQualificationErrorCode::InputUnavailable => {
                "the qualification input could not be read"
            }
            ControlNcaQualificationErrorCode::InputChangedDuringQualification => {
                "the qualification input changed during the read"
            }
            ControlNcaQualificationErrorCode::KeyFileUnavailable => {
                "the qualification key file could not be read"
            }
            ControlNcaQualificationErrorCode::KeyFileChangedDuringQualification => {
                "the qualification key file changed during the read"
            }
            ControlNcaQualificationErrorCode::KeyFileMalformed => {
                "the qualification key file is malformed"
            }
            ControlNcaQualificationErrorCode::MissingHeaderKey => {
                "the qualification key file lacks the NCA header key"
            }
            ControlNcaQualificationErrorCode::MissingApplicationKeyAreaKey => {
                "the qualification key file lacks the Application key-area key"
            }
            ControlNcaQualificationErrorCode::KeyFileLimitExceeded => {
                "the qualification key file exceeds its supported size"
            }
            ControlNcaQualificationErrorCode::InputLimitExceeded => {
                "the qualification input exceeds its supported size"
            }
            ControlNcaQualificationErrorCode::ResourceLimitExceeded => {
                "the qualification input exceeds a supported resource limit"
            }
            ControlNcaQualificationErrorCode::AllocationFailed => {
                "qualification could not reserve bounded memory"
            }
            ControlNcaQualificationErrorCode::Cancelled => "qualification was cancelled",
            ControlNcaQualificationErrorCode::InternalIo => {
                "an internal qualification file operation failed"
            }
        })
    }
}

impl std::error::Error for ControlNcaQualificationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Checkpoint {
    InputOpened,
    KeysRead,
    HeaderRead,
    IvfcBlock,
    RomFsMetadata,
    BeforeFinalRevalidation,
}

struct OpenedFile {
    file: File,
    canonical_path: PathBuf,
    requested_path: PathBuf,
    identity: FileIdentity,
    snapshot: FileSnapshot,
    size: u64,
}

impl OpenedFile {
    fn revalidate(
        &self,
        changed: ControlNcaQualificationErrorCode,
        unavailable: ControlNcaQualificationErrorCode,
    ) -> Result<(), ControlNcaQualificationError> {
        let metadata = self
            .file
            .metadata()
            .map_err(|_| ControlNcaQualificationError::new(unavailable))?;
        let identity = crate::file_identity::handle_identity(&self.file);
        let snapshot = crate::file_identity::file_snapshot(&metadata, identity);
        if identity != Some(self.identity)
            || crate::file_identity::path_identity(&self.canonical_path) != Some(self.identity)
            || crate::file_identity::followed_path_identity(&self.requested_path)
                != Some(self.identity)
            || snapshot != self.snapshot
        {
            return Err(ControlNcaQualificationError::new(changed));
        }
        Ok(())
    }
}

fn open_file(
    path: &Path,
    unavailable: ControlNcaQualificationErrorCode,
    changed: ControlNcaQualificationErrorCode,
) -> Result<OpenedFile, ControlNcaQualificationError> {
    let canonical_path =
        std::fs::canonicalize(path).map_err(|_| ControlNcaQualificationError::new(unavailable))?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options
        .open(&canonical_path)
        .map_err(|_| ControlNcaQualificationError::new(unavailable))?;
    let metadata = file
        .metadata()
        .map_err(|_| ControlNcaQualificationError::new(unavailable))?;
    if !metadata.file_type().is_file() {
        return Err(ControlNcaQualificationError::new(unavailable));
    }
    let identity = crate::file_identity::handle_identity(&file).ok_or_else(|| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
    })?;
    if crate::file_identity::path_identity(&canonical_path) != Some(identity)
        || crate::file_identity::followed_path_identity(path) != Some(identity)
    {
        return Err(ControlNcaQualificationError::new(changed));
    }
    let size = metadata.len();
    let snapshot = crate::file_identity::file_snapshot(&metadata, Some(identity));
    Ok(OpenedFile {
        file,
        canonical_path,
        requested_path: path.to_path_buf(),
        identity,
        snapshot,
        size,
    })
}

fn check_cancelled(control: &QualificationControl<'_>) -> Result<(), ControlNcaQualificationError> {
    if control
        .cancellation
        .as_ref()
        .is_some_and(|cancellation| cancellation.is_cancelled())
    {
        return Err(ControlNcaQualificationError::new(
            ControlNcaQualificationErrorCode::Cancelled,
        ));
    }
    Ok(())
}

fn check_input_size(size: u64) -> Result<(), ControlNcaQualificationError> {
    if size > MAX_INPUT_BYTES {
        return Err(ControlNcaQualificationError::new(
            ControlNcaQualificationErrorCode::InputLimitExceeded,
        ));
    }
    Ok(())
}

fn map_key_file_error(error: NspKeyFileError) -> ControlNcaQualificationError {
    use NspKeyFileError as KeyError;
    let code = match error {
        KeyError::Unavailable => ControlNcaQualificationErrorCode::KeyFileUnavailable,
        KeyError::LimitExceeded => ControlNcaQualificationErrorCode::KeyFileLimitExceeded,
        KeyError::AllocationFailed => ControlNcaQualificationErrorCode::AllocationFailed,
        KeyError::Malformed => ControlNcaQualificationErrorCode::KeyFileMalformed,
        KeyError::MissingHeaderKey => ControlNcaQualificationErrorCode::MissingHeaderKey,
        KeyError::MissingApplicationKeyAreaKey => {
            ControlNcaQualificationErrorCode::MissingApplicationKeyAreaKey
        }
    };
    ControlNcaQualificationError::new(code)
}

/// Qualifies a bounded rights-free Control NCA using its explicit key file.
pub(crate) fn qualify(
    request: ControlNcaQualificationRequest,
) -> Result<ControlNcaQualificationOutcome, ControlNcaQualificationError> {
    let mut checkpoint = |_| {};
    qualify_inner(request, None, &mut checkpoint)
}

/// Qualifies one NCA inside a larger file through an exact bounded span.
///
/// The NCA parser sees the start of this span as offset zero. The reader cannot
/// seek or read into bytes before or after the member.
pub(crate) fn qualify_bounded_path(
    request: ControlNcaQualificationRequest,
    offset: u64,
    length: u64,
    expected_source_snapshot: Option<crate::file_identity::FileSnapshot>,
) -> Result<ControlNcaQualificationOutcome, ControlNcaQualificationError> {
    let mut checkpoint = |_| {};
    qualify_inner(
        request,
        Some((offset, length, expected_source_snapshot)),
        &mut checkpoint,
    )
}

/// Qualifies a bounded NCA while polling the enclosing operation for cancellation.
pub(crate) fn qualify_bounded_path_with_cancellation_probe<F>(
    request: ControlNcaQualificationRequest,
    offset: u64,
    length: u64,
    expected_source_snapshot: Option<crate::file_identity::FileSnapshot>,
    mut is_cancelled: F,
) -> Result<ControlNcaQualificationOutcome, ControlNcaQualificationError>
where
    F: FnMut() -> bool,
{
    let cancellation = crate::CancellationHandle::new();
    let request = request.with_cancellation(cancellation.clone());
    let mut checkpoint = |_| {
        if is_cancelled() {
            cancellation.cancel();
        }
    };
    qualify_inner(
        request,
        Some((offset, length, expected_source_snapshot)),
        &mut checkpoint,
    )
}

#[cfg(test)]
fn qualify_with_checkpoint<F>(
    request: ControlNcaQualificationRequest,
    mut checkpoint: F,
) -> Result<ControlNcaQualificationOutcome, ControlNcaQualificationError>
where
    F: FnMut(Checkpoint),
{
    qualify_inner(request, None, &mut checkpoint)
}

fn qualify_inner<F>(
    request: ControlNcaQualificationRequest,
    input_span: Option<(u64, u64, Option<crate::file_identity::FileSnapshot>)>,
    checkpoint: &mut F,
) -> Result<ControlNcaQualificationOutcome, ControlNcaQualificationError>
where
    F: FnMut(Checkpoint),
{
    let control = QualificationControl {
        cancellation: request.cancellation.as_ref(),
    };
    check_cancelled(&control)?;
    let mut input = open_file(
        &request.input,
        ControlNcaQualificationErrorCode::InputUnavailable,
        ControlNcaQualificationErrorCode::InputChangedDuringQualification,
    )?;
    checkpoint(Checkpoint::InputOpened);
    check_cancelled(&control)?;
    let qualification_size = input_span
        .as_ref()
        .map_or(input.size, |(_, length, _)| *length);
    check_input_size(qualification_size)?;
    if input_span.as_ref().is_some_and(|(_, length, expected)| {
        *length == 0
            || expected
                .as_ref()
                .is_some_and(|snapshot| snapshot != &input.snapshot)
    }) {
        return Err(ControlNcaQualificationError::new(
            ControlNcaQualificationErrorCode::InputChangedDuringQualification,
        ));
    }
    let mut key_file = open_file(
        &request.key_file,
        ControlNcaQualificationErrorCode::KeyFileUnavailable,
        ControlNcaQualificationErrorCode::KeyFileChangedDuringQualification,
    )?;
    if key_file.size > crate::key_file::MAX_KEY_FILE_BYTES {
        return Err(ControlNcaQualificationError::new(
            ControlNcaQualificationErrorCode::KeyFileLimitExceeded,
        ));
    }
    if request
        .expected_key_snapshot
        .as_ref()
        .is_some_and(|expected| expected != &key_file.snapshot)
    {
        return Err(ControlNcaQualificationError::new(
            ControlNcaQualificationErrorCode::KeyFileChangedDuringQualification,
        ));
    }
    let keys = crate::key_file::read_nsp_qualification_keys(&mut key_file.file, key_file.size)
        .map_err(map_key_file_error)?;
    key_file.revalidate(
        ControlNcaQualificationErrorCode::KeyFileChangedDuringQualification,
        ControlNcaQualificationErrorCode::KeyFileUnavailable,
    )?;
    checkpoint(Checkpoint::KeysRead);
    check_cancelled(&control)?;

    let result = match input_span {
        Some((offset, length, _)) => {
            let mut bounded = crate::nsp_semantic_qualification::BoundedReader::new(
                &mut input.file,
                offset,
                length,
                input.size,
            )
            .ok_or_else(|| {
                ControlNcaQualificationError::new(
                    ControlNcaQualificationErrorCode::InputChangedDuringQualification,
                )
            })?;
            qualify_opened(&mut bounded, length, &keys, &control, checkpoint)
        }
        None => qualify_opened(&mut input.file, input.size, &keys, &control, checkpoint),
    };
    if result.is_ok() {
        checkpoint(Checkpoint::BeforeFinalRevalidation);
        check_cancelled(&control)?;
        input.revalidate(
            ControlNcaQualificationErrorCode::InputChangedDuringQualification,
            ControlNcaQualificationErrorCode::InputUnavailable,
        )?;
        key_file.revalidate(
            ControlNcaQualificationErrorCode::KeyFileChangedDuringQualification,
            ControlNcaQualificationErrorCode::KeyFileUnavailable,
        )?;
        check_cancelled(&control)?;
    }
    result
}

fn qualify_opened<R, F>(
    input: &mut R,
    input_size: u64,
    keys: &NspQualificationKeys,
    control: &QualificationControl<'_>,
    checkpoint: &mut F,
) -> Result<ControlNcaQualificationOutcome, ControlNcaQualificationError>
where
    R: Read + Seek,
    F: FnMut(Checkpoint),
{
    match qualify_opened_profile(
        input,
        input_size,
        keys,
        control,
        ControlQualificationOutput::Facts,
        checkpoint,
    )? {
        QualifiedProfileOutcome::Qualified { facts, .. } => {
            Ok(ControlNcaQualificationOutcome::Qualified(facts))
        }
        QualifiedProfileOutcome::QualifiedForExtraction { .. } => Err(
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo),
        ),
        QualifiedProfileOutcome::NotQualified(reason) => {
            Ok(ControlNcaQualificationOutcome::NotQualified(reason))
        }
    }
}

/// Qualifies one open source handle and returns its private extraction inventory.
pub(crate) fn qualify_for_extraction_opened<R>(
    input: &mut R,
    input_size: u64,
    keys: &NspQualificationKeys,
    cancellation: &crate::CancellationHandle,
) -> Result<
    Result<ControlNcaExtractionInventory, ControlNcaQualificationReason>,
    ControlNcaQualificationError,
>
where
    R: Read + Seek,
{
    let control = QualificationControl {
        cancellation: Some(cancellation),
    };
    let mut checkpoint = |_| {};
    match qualify_opened_profile(
        input,
        input_size,
        keys,
        &control,
        ControlQualificationOutput::ExtractionInventory,
        &mut checkpoint,
    )? {
        QualifiedProfileOutcome::QualifiedForExtraction { inventory, .. } => Ok(Ok(inventory)),
        QualifiedProfileOutcome::Qualified { .. } => Err(ControlNcaQualificationError::new(
            ControlNcaQualificationErrorCode::InternalIo,
        )),
        QualifiedProfileOutcome::NotQualified(reason) => Ok(Err(reason)),
    }
}

pub(crate) fn derive_control_extraction_key<R: Read + Seek>(
    input: &mut R,
    input_size: u64,
    keys: &NspQualificationKeys,
    expected: &ControlNcaExtractionMetadata,
) -> Result<Zeroizing<[u8; 16]>, ControlNcaQualificationError> {
    check_input_size(input_size)?;
    let block =
        nca::read_header_block(input, input_size, keys.header_key.as_bytes()).map_err(|error| {
            ControlNcaQualificationError::new(match error {
                HeaderError::AllocationFailed => ControlNcaQualificationErrorCode::AllocationFailed,
                HeaderError::InputUnavailable => ControlNcaQualificationErrorCode::InputUnavailable,
                _ => ControlNcaQualificationErrorCode::InputChangedDuringQualification,
            })
        })?;
    let block = Zeroizing::new(block);
    let header = nca::parse_header_block(&block, input_size).map_err(|error| {
        ControlNcaQualificationError::new(match error {
            HeaderError::AllocationFailed => ControlNcaQualificationErrorCode::AllocationFailed,
            HeaderError::InputUnavailable => ControlNcaQualificationErrorCode::InputUnavailable,
            _ => ControlNcaQualificationErrorCode::InputChangedDuringQualification,
        })
    })?;
    let partition = supported_partition(&block, &header).map_err(|_| {
        ControlNcaQualificationError::new(
            ControlNcaQualificationErrorCode::InputChangedDuringQualification,
        )
    })?;
    let fs = &block[0x400..0x600];
    let _layout = parse_ivfc_layout(
        &fs[IVFC_HEADER_IN_FS..IVFC_HEADER_IN_FS + IVFC_HEADER_SIZE],
        partition.size,
    )
    .map_err(|_| {
        ControlNcaQualificationError::new(
            ControlNcaQualificationErrorCode::InputChangedDuringQualification,
        )
    })?;
    if block[0x230..0x240].iter().any(|byte| *byte != 0)
        || !crate::verification::fs_header_hash_matches(&block, usize::from(partition.index))
        || header.program_id != expected.program_id
        || header.content_index != expected.content_index
        || partition.index != expected.partition_index
        || partition.offset != expected.partition_offset
        || partition.size != expected.partition_size
    {
        return Err(ControlNcaQualificationError::new(
            ControlNcaQualificationErrorCode::InputChangedDuringQualification,
        ));
    }
    let mut section_ctr = [0_u8; 8];
    section_ctr.copy_from_slice(&fs[0x140..0x148]);
    if section_ctr != expected.section_ctr {
        return Err(ControlNcaQualificationError::new(
            ControlNcaQualificationErrorCode::InputChangedDuringQualification,
        ));
    }
    decrypt_key_area_slot2(&block[0x300..0x340], keys.application_kaek.as_bytes()).ok_or_else(
        || ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo),
    )
}

fn qualify_opened_profile<R, F>(
    input: &mut R,
    input_size: u64,
    keys: &NspQualificationKeys,
    control: &QualificationControl<'_>,
    output: ControlQualificationOutput,
    checkpoint: &mut F,
) -> Result<QualifiedProfileOutcome, ControlNcaQualificationError>
where
    R: Read + Seek,
    F: FnMut(Checkpoint),
{
    check_input_size(input_size)?;
    let block = match nca::read_header_block(input, input_size, keys.header_key.as_bytes()) {
        Ok(block) => block,
        Err(
            HeaderError::UnsupportedFormat
            | HeaderError::TruncatedInput
            | HeaderError::MalformedInput,
        ) => {
            return Ok(QualifiedProfileOutcome::NotQualified(
                ControlNcaQualificationReason::InvalidNcaHeader,
            ));
        }
        Err(HeaderError::InputUnavailable) => {
            return Err(ControlNcaQualificationError::new(
                ControlNcaQualificationErrorCode::InputUnavailable,
            ));
        }
        Err(HeaderError::AllocationFailed) => {
            return Err(ControlNcaQualificationError::new(
                ControlNcaQualificationErrorCode::AllocationFailed,
            ));
        }
    };
    let block = Zeroizing::new(block);
    checkpoint(Checkpoint::HeaderRead);
    check_cancelled(control)?;
    let header = match nca::parse_header_block(&block, input_size) {
        Ok(header) => header,
        Err(HeaderError::InputUnavailable) => {
            return Err(ControlNcaQualificationError::new(
                ControlNcaQualificationErrorCode::InputUnavailable,
            ));
        }
        Err(HeaderError::AllocationFailed) => {
            return Err(ControlNcaQualificationError::new(
                ControlNcaQualificationErrorCode::AllocationFailed,
            ));
        }
        Err(_) => {
            return Ok(QualifiedProfileOutcome::NotQualified(
                ControlNcaQualificationReason::InvalidNcaHeader,
            ));
        }
    };
    if block[0x230..0x240].iter().any(|byte| *byte != 0) {
        return Ok(QualifiedProfileOutcome::NotQualified(
            ControlNcaQualificationReason::RightsBearingContent,
        ));
    }
    let partition = match supported_partition(&block, &header) {
        Ok(partition) => partition,
        Err(reason) => return Ok(QualifiedProfileOutcome::NotQualified(reason)),
    };
    let fs = &block[0x400..0x600];
    let ivfc_bytes = &fs[IVFC_HEADER_IN_FS..IVFC_HEADER_IN_FS + IVFC_HEADER_SIZE];
    let layout = match parse_ivfc_layout(ivfc_bytes, partition.size) {
        Ok(layout) => layout,
        Err(reason) => return Ok(QualifiedProfileOutcome::NotQualified(reason)),
    };
    if !crate::verification::fs_header_hash_matches(&block, usize::from(partition.index)) {
        return Ok(QualifiedProfileOutcome::NotQualified(
            ControlNcaQualificationReason::InvalidNcaHeader,
        ));
    }
    let section_key =
        decrypt_key_area_slot2(&block[0x300..0x340], keys.application_kaek.as_bytes()).ok_or_else(
            || ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo),
        )?;
    let mut section_ctr = [0_u8; 8];
    section_ctr.copy_from_slice(&fs[0x140..0x148]);
    let mut section = NcaCtrReader::new(
        input,
        partition.offset,
        partition.size,
        &section_key,
        section_ctr,
    );
    let hash_operations = match verify_ivfc(
        &mut section,
        &layout,
        &ivfc_bytes[0xc0..0xe0],
        control,
        checkpoint,
    )? {
        Ok(count) => count,
        Err(reason) => return Ok(QualifiedProfileOutcome::NotQualified(reason)),
    };
    let romfs = match validate_romfs(
        &mut section,
        layout.levels[5],
        partition.offset,
        partition.size,
        output,
        control,
        checkpoint,
    )? {
        Ok(stats) => stats,
        Err(reason) => return Ok(QualifiedProfileOutcome::NotQualified(reason)),
    };
    match (output, romfs) {
        (
            ControlQualificationOutput::Facts,
            RomFsStats::Facts {
                directory_count,
                file_count,
            },
        ) => Ok(QualifiedProfileOutcome::Qualified {
            facts: ControlNcaQualificationFacts {
                profile: ControlNcaQualificationProfile::RightsFreeControlRomFsV1,
                program_id: header.program_id,
                section_size: partition.size,
                romfs_size: layout.levels[5].size,
                directory_count,
                file_count,
                hash_operations,
            },
        }),
        (ControlQualificationOutput::ExtractionInventory, RomFsStats::Extraction { tree }) => {
            Ok(QualifiedProfileOutcome::QualifiedForExtraction {
                inventory: ControlNcaExtractionInventory {
                    metadata: ControlNcaExtractionMetadata {
                        program_id: header.program_id,
                        content_index: header.content_index,
                        partition_index: partition.index,
                        partition_offset: partition.offset,
                        partition_size: partition.size,
                        section_ctr,
                    },
                    directories: tree.directories,
                    files: tree.files,
                },
            })
        }
        _ => Err(ControlNcaQualificationError::new(
            ControlNcaQualificationErrorCode::InternalIo,
        )),
    }
}

fn supported_partition<'a>(
    block: &[u8; nca::HEADER_SIZE],
    header: &'a nca::Header,
) -> Result<&'a Partition, ControlNcaQualificationReason> {
    if header.format_version != 3
        || header.distribution != Distribution::Download
        || header.content_type != ContentType::Control
        || header.key_generation > 1
        || header.kaek_index != 0
        || header.partitions.len() != 1
    {
        return Err(ControlNcaQualificationReason::UnsupportedNcaProfile);
    }
    let partition = &header.partitions[0];
    if partition.index != 0
        || partition.filesystem != 0
        || partition.hash_type != 3
        || partition.encryption != 3
        || partition.extended
    {
        return Err(ControlNcaQualificationReason::UnsupportedNcaProfile);
    }
    let fs = &block[0x400..0x600];
    if fs[0xE8..0x140].iter().any(|byte| *byte != 0) || fs[0x148..].iter().any(|byte| *byte != 0) {
        return Err(ControlNcaQualificationReason::UnsupportedNcaProfile);
    }
    Ok(partition)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IvfcLevel {
    offset: u64,
    size: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IvfcLayout {
    levels: [IvfcLevel; IVFC_LEVEL_COUNT],
    trailing_padding: u64,
}

fn parse_ivfc_layout(
    bytes: &[u8],
    section_size: u64,
) -> Result<IvfcLayout, ControlNcaQualificationReason> {
    if bytes.len() != IVFC_HEADER_SIZE
        || &bytes[..4] != b"IVFC"
        || read_u32(bytes, 4) != 0x20000
        || read_u32(bytes, 8) != 0x20
        || read_u32(bytes, 12) != 7
        || bytes[0xA0..0xC0].iter().any(|byte| *byte != 0)
    {
        return Err(ControlNcaQualificationReason::InvalidIvfcLayout);
    }
    let mut levels = [IvfcLevel { offset: 0, size: 0 }; IVFC_LEVEL_COUNT];
    let mut next_offset = 0_u64;
    for (index, level) in levels.iter_mut().enumerate() {
        let descriptor_offset = IVFC_DESCRIPTOR_OFFSET + index * IVFC_DESCRIPTOR_SIZE;
        let offset = read_u64(bytes, descriptor_offset);
        let size = read_u64(bytes, descriptor_offset + 8);
        let exponent = read_u32(bytes, descriptor_offset + 16);
        let reserved = read_u32(bytes, descriptor_offset + 20);
        if !offset.is_multiple_of(IVFC_BLOCK_SIZE as u64)
            || offset != next_offset
            || size == 0
            || exponent != IVFC_BLOCK_EXPONENT
            || reserved != 0
        {
            return Err(ControlNcaQualificationReason::InvalidIvfcLayout);
        }
        next_offset = offset
            .checked_add(size)
            .ok_or(ControlNcaQualificationReason::InvalidIvfcLayout)?;
        if next_offset > section_size {
            return Err(ControlNcaQualificationReason::InvalidIvfcLayout);
        }
        *level = IvfcLevel { offset, size };
    }
    if levels[0].size != IVFC_BLOCK_SIZE as u64 || levels[5].size < ROMFS_HEADER_SIZE as u64 {
        return Err(ControlNcaQualificationReason::InvalidIvfcLayout);
    }
    for index in 1..5 {
        let required = hash_table_bytes(levels[index + 1].size)
            .ok_or(ControlNcaQualificationReason::InvalidIvfcLayout)?;
        if !is_supported_table_size(levels[index].size, required) {
            return Err(ControlNcaQualificationReason::InvalidIvfcLayout);
        }
    }
    let level_one_hash_bytes =
        hash_table_bytes(levels[1].size).ok_or(ControlNcaQualificationReason::InvalidIvfcLayout)?;
    if level_one_hash_bytes > levels[0].size {
        return Err(ControlNcaQualificationReason::InvalidIvfcLayout);
    }
    let trailing_padding = section_size
        .checked_sub(next_offset)
        .ok_or(ControlNcaQualificationReason::InvalidIvfcLayout)?;
    if trailing_padding > IVFC_BLOCK_SIZE as u64
        || (levels[5].size % IVFC_BLOCK_SIZE as u64 != 0
            && trailing_padding == IVFC_BLOCK_SIZE as u64)
    {
        return Err(ControlNcaQualificationReason::InvalidIvfcLayout);
    }
    hash_operation_count(levels.map(|level| level.size))
        .ok_or(ControlNcaQualificationReason::InvalidIvfcLayout)?;
    Ok(IvfcLayout {
        levels,
        trailing_padding,
    })
}

fn hash_table_bytes(child_size: u64) -> Option<u64> {
    let block_size = IVFC_BLOCK_SIZE as u64;
    let block_count = child_size / block_size + u64::from(!child_size.is_multiple_of(block_size));
    block_count.checked_mul(32)
}

fn is_supported_table_size(declared: u64, required: u64) -> bool {
    let block_size = IVFC_BLOCK_SIZE as u64;
    let Some(rounded) = required
        .checked_add(block_size - 1)
        .map(|value| value / block_size * block_size)
    else {
        return false;
    };
    declared == rounded
        || (required.is_multiple_of(block_size)
            && rounded.checked_add(block_size) == Some(declared))
}

/// Counts the root master digest and each 16 KiB block in child levels one through five.
fn hash_operation_count(level_sizes: [u64; IVFC_LEVEL_COUNT]) -> Option<u64> {
    let block_size = IVFC_BLOCK_SIZE as u64;
    let mut operations = 1_u64;
    for size in &level_sizes[1..] {
        let count = size / block_size + u64::from(size % block_size != 0);
        operations = operations.checked_add(count)?;
    }
    Some(operations)
}

fn verify_ivfc<S, F>(
    section: &mut S,
    layout: &IvfcLayout,
    master_hash: &[u8],
    control: &QualificationControl<'_>,
    checkpoint: &mut F,
) -> Result<Result<u64, ControlNcaQualificationReason>, ControlNcaQualificationError>
where
    S: Read + Seek,
    F: FnMut(Checkpoint),
{
    if master_hash.len() != 32 {
        return Ok(Err(ControlNcaQualificationReason::InvalidIvfcLayout));
    }
    let operations =
        hash_operation_count(layout.levels.map(|level| level.size)).ok_or_else(|| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
        })?;
    if operations > MAX_IVFC_HASH_OPERATIONS {
        return Err(ControlNcaQualificationError::new(
            ControlNcaQualificationErrorCode::ResourceLimitExceeded,
        ));
    }

    let mut hash_buffer = Zeroizing::new(Vec::new());
    reserve_exact(
        &mut hash_buffer,
        IVFC_HASH_BUFFER_BYTES,
        AllocationSite::ControlIvfcHashBuffer,
    )
    .map_err(|_| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::AllocationFailed)
    })?;
    hash_buffer.resize(IVFC_HASH_BUFFER_BYTES, 0);

    let root_level = layout.levels[0];
    let root_table_bytes = hash_table_bytes(layout.levels[1].size).ok_or_else(|| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
    })?;
    let root_padding_offset = root_level
        .offset
        .checked_add(root_table_bytes)
        .ok_or_else(|| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
        })?;
    let root_padding_size = root_level
        .size
        .checked_sub(root_table_bytes)
        .ok_or_else(|| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
        })?;
    match verify_zero_range(
        section,
        root_padding_offset,
        root_padding_size,
        &mut hash_buffer,
        control,
    )? {
        Ok(()) => {}
        Err(reason) => return Ok(Err(reason)),
    }
    let mut root_block = Zeroizing::new([0_u8; IVFC_BLOCK_SIZE]);
    read_exact_at(section, root_level.offset, &mut root_block[..])?;
    let actual_master_hash = Sha256::digest(&root_block[..]);
    if actual_master_hash.as_slice() != master_hash {
        return Ok(Err(ControlNcaQualificationReason::IvfcIntegrityFailure {
            level: 0,
        }));
    }

    for level_index in 1..IVFC_LEVEL_COUNT {
        let parent = layout.levels[level_index - 1];
        let child = layout.levels[level_index];
        let expected_bytes = hash_table_bytes(child.size).ok_or_else(|| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
        })?;
        let parent_padding_offset = parent.offset.checked_add(expected_bytes).ok_or_else(|| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
        })?;
        let parent_padding_size = parent.size.checked_sub(expected_bytes).ok_or_else(|| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
        })?;
        match verify_zero_range(
            section,
            parent_padding_offset,
            parent_padding_size,
            &mut hash_buffer,
            control,
        )? {
            Ok(()) => {}
            Err(reason) => return Ok(Err(reason)),
        }

        let block_count = child.size / IVFC_BLOCK_SIZE as u64
            + u64::from(!child.size.is_multiple_of(IVFC_BLOCK_SIZE as u64));
        let hashes_per_chunk = (hash_buffer.len() / 32) as u64;
        let mut first_block = 0_u64;
        while first_block < block_count {
            check_cancelled(control)?;
            let count = (block_count - first_block).min(hashes_per_chunk);
            let hash_bytes = usize::try_from(count.checked_mul(32).ok_or_else(|| {
                ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
            })?)
            .map_err(|_| {
                ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
            })?;
            let table_offset = parent
                .offset
                .checked_add(first_block.checked_mul(32).ok_or_else(|| {
                    ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
                })?)
                .ok_or_else(|| {
                    ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
                })?;
            read_exact_at(section, table_offset, &mut hash_buffer[..hash_bytes])?;

            for local_index in 0..count {
                check_cancelled(control)?;
                let block_index = first_block.checked_add(local_index).ok_or_else(|| {
                    ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
                })?;
                let relative =
                    block_index
                        .checked_mul(IVFC_BLOCK_SIZE as u64)
                        .ok_or_else(|| {
                            ControlNcaQualificationError::new(
                                ControlNcaQualificationErrorCode::InternalIo,
                            )
                        })?;
                let actual_bytes = usize::try_from(
                    (child.size - relative).min(IVFC_BLOCK_SIZE as u64),
                )
                .map_err(|_| {
                    ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
                })?;
                let child_offset = child.offset.checked_add(relative).ok_or_else(|| {
                    ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
                })?;
                let mut block = Zeroizing::new([0_u8; IVFC_BLOCK_SIZE]);
                read_exact_at(section, child_offset, &mut block[..actual_bytes])?;
                let actual_hash = Sha256::digest(&block[..]);
                let hash_offset =
                    usize::try_from(local_index.checked_mul(32).ok_or_else(|| {
                        ControlNcaQualificationError::new(
                            ControlNcaQualificationErrorCode::InternalIo,
                        )
                    })?)
                    .map_err(|_| {
                        ControlNcaQualificationError::new(
                            ControlNcaQualificationErrorCode::InternalIo,
                        )
                    })?;
                if actual_hash.as_slice() != &hash_buffer[hash_offset..hash_offset + 32] {
                    return Ok(Err(ControlNcaQualificationReason::IvfcIntegrityFailure {
                        level: level_index as u8,
                    }));
                }
                checkpoint(Checkpoint::IvfcBlock);
            }
            first_block = first_block.checked_add(count).ok_or_else(|| {
                ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
            })?;
        }
    }

    let trailing_offset = layout.levels[5]
        .offset
        .checked_add(layout.levels[5].size)
        .ok_or_else(|| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
        })?;
    match verify_zero_range(
        section,
        trailing_offset,
        layout.trailing_padding,
        &mut hash_buffer,
        control,
    )? {
        Ok(()) => Ok(Ok(operations)),
        Err(reason) => Ok(Err(reason)),
    }
}

fn verify_zero_range<S: Read + Seek>(
    section: &mut S,
    offset: u64,
    length: u64,
    buffer: &mut [u8],
    control: &QualificationControl<'_>,
) -> Result<Result<(), ControlNcaQualificationReason>, ControlNcaQualificationError> {
    let mut consumed = 0_u64;
    while consumed < length {
        check_cancelled(control)?;
        let count =
            usize::try_from((length - consumed).min(buffer.len() as u64)).map_err(|_| {
                ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
            })?;
        let absolute = offset.checked_add(consumed).ok_or_else(|| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
        })?;
        read_exact_at(section, absolute, &mut buffer[..count])?;
        if buffer[..count].iter().any(|byte| *byte != 0) {
            return Ok(Err(ControlNcaQualificationReason::InvalidIvfcPadding));
        }
        consumed = consumed.checked_add(count as u64).ok_or_else(|| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
        })?;
    }
    Ok(Ok(()))
}

fn read_exact_at<S: Read + Seek>(
    section: &mut S,
    offset: u64,
    output: &mut [u8],
) -> Result<(), ControlNcaQualificationError> {
    section
        .seek(SeekFrom::Start(offset))
        .and_then(|_| section.read_exact(output))
        .map_err(|_| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InputUnavailable)
        })
}

struct RomFsExtractionTree {
    directories: Vec<String>,
    files: Vec<crate::inspection::NativeNcaFileSpan>,
}

enum RomFsStats {
    Facts {
        directory_count: usize,
        file_count: usize,
    },
    Extraction {
        tree: RomFsExtractionTree,
    },
}

#[derive(Clone, Copy)]
struct RomFsHeader {
    directory_hash_offset: u64,
    directory_hash_size: u64,
    directory_meta_offset: u64,
    directory_meta_size: u64,
    file_hash_offset: u64,
    file_hash_size: u64,
    file_meta_offset: u64,
    file_meta_size: u64,
    data_offset: u64,
}

impl RomFsHeader {
    fn parse(bytes: &[u8; ROMFS_HEADER_SIZE]) -> Self {
        Self {
            directory_hash_offset: read_u64(bytes, 8),
            directory_hash_size: read_u64(bytes, 16),
            directory_meta_offset: read_u64(bytes, 24),
            directory_meta_size: read_u64(bytes, 32),
            file_hash_offset: read_u64(bytes, 40),
            file_hash_size: read_u64(bytes, 48),
            file_meta_offset: read_u64(bytes, 56),
            file_meta_size: read_u64(bytes, 64),
            data_offset: read_u64(bytes, 72),
        }
    }
}

#[derive(Clone, Copy)]
struct NameHashRecord {
    offset: u32,
    parent: u32,
    hash_next: u32,
    name_start: usize,
    name_size: usize,
}

#[derive(Clone, Copy)]
struct DirectoryRecord {
    name: NameHashRecord,
    sibling: u32,
    child_directory: u32,
    child_file: u32,
}

#[derive(Clone, Copy)]
struct FileRecord {
    name: NameHashRecord,
    sibling: u32,
    data_offset: u64,
    size: u64,
}

/// Validated RomFS records and offsets needed to produce file spans.
struct RomFsExtractionInput<'a> {
    metadata: &'a [u8],
    directories: &'a [DirectoryRecord],
    files: &'a [FileRecord],
    data_offset: u64,
    level_offset: u64,
    partition_offset: u64,
    partition_size: u64,
}

trait HashedRecord {
    fn name_hash_record(&self) -> &NameHashRecord;
}

impl HashedRecord for NameHashRecord {
    fn name_hash_record(&self) -> &NameHashRecord {
        self
    }
}

impl HashedRecord for DirectoryRecord {
    fn name_hash_record(&self) -> &NameHashRecord {
        &self.name
    }
}

impl HashedRecord for FileRecord {
    fn name_hash_record(&self) -> &NameHashRecord {
        &self.name
    }
}

fn validate_romfs<S, F>(
    section: &mut S,
    romfs: IvfcLevel,
    partition_offset: u64,
    partition_size: u64,
    output: ControlQualificationOutput,
    control: &QualificationControl<'_>,
    checkpoint: &mut F,
) -> Result<Result<RomFsStats, ControlNcaQualificationReason>, ControlNcaQualificationError>
where
    S: Read + Seek,
    F: FnMut(Checkpoint),
{
    check_cancelled(control)?;
    let mut header_bytes = Zeroizing::new([0_u8; ROMFS_HEADER_SIZE]);
    read_exact_at(section, romfs.offset, &mut header_bytes[..])?;
    let header_size = read_u64(&header_bytes[..], 0);
    if header_size != ROMFS_HEADER_SIZE as u64 {
        return Ok(Err(ControlNcaQualificationReason::InvalidRomFsLayout));
    }
    let header = RomFsHeader::parse(&header_bytes);
    let directory_hash_end = header
        .directory_hash_offset
        .checked_add(header.directory_hash_size);
    let directory_meta_end = header
        .directory_meta_offset
        .checked_add(header.directory_meta_size);
    let file_hash_end = header.file_hash_offset.checked_add(header.file_hash_size);
    let file_meta_end = header.file_meta_offset.checked_add(header.file_meta_size);
    let Some((directory_hash_end, directory_meta_end, file_hash_end, file_meta_end)) =
        directory_hash_end
            .zip(directory_meta_end)
            .zip(file_hash_end)
            .zip(file_meta_end)
            .map(|(((dir_hash, dir_meta), file_hash), file_meta)| {
                (dir_hash, dir_meta, file_hash, file_meta)
            })
    else {
        return Ok(Err(ControlNcaQualificationReason::InvalidRomFsLayout));
    };
    if header.data_offset < ROMFS_HEADER_SIZE as u64
        || header.directory_hash_offset < header.data_offset
        || directory_hash_end != header.directory_meta_offset
        || directory_meta_end != header.file_hash_offset
        || file_hash_end != header.file_meta_offset
        || file_meta_end != romfs.size
        || header.directory_hash_size < 4
        || header.directory_meta_size < ROMFS_DIRECTORY_RECORD_SIZE as u64
        || header.file_hash_size < 4
        || !header.directory_hash_size.is_multiple_of(4)
        || !header.file_hash_size.is_multiple_of(4)
        || !header.directory_hash_offset.is_multiple_of(4)
        || !header.directory_meta_offset.is_multiple_of(4)
        || !header.file_hash_offset.is_multiple_of(4)
        || !header.file_meta_offset.is_multiple_of(4)
    {
        return Ok(Err(ControlNcaQualificationReason::InvalidRomFsLayout));
    }
    let metadata_total = (ROMFS_HEADER_SIZE as u64)
        .checked_add(header.directory_hash_size)
        .and_then(|value| value.checked_add(header.directory_meta_size))
        .and_then(|value| value.checked_add(header.file_hash_size))
        .and_then(|value| value.checked_add(header.file_meta_size))
        .ok_or_else(|| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
        })?;
    if metadata_total > MAX_ROMFS_METADATA_BYTES {
        return Err(ControlNcaQualificationError::new(
            ControlNcaQualificationErrorCode::ResourceLimitExceeded,
        ));
    }
    let table_bytes = header
        .directory_hash_size
        .checked_add(header.directory_meta_size)
        .and_then(|value| value.checked_add(header.file_hash_size))
        .and_then(|value| value.checked_add(header.file_meta_size))
        .ok_or_else(|| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
        })?;
    let table_bytes = usize::try_from(table_bytes).map_err(|_| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::ResourceLimitExceeded)
    })?;
    let directory_hash_size = usize::try_from(header.directory_hash_size).map_err(|_| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
    })?;
    let directory_meta_size = usize::try_from(header.directory_meta_size).map_err(|_| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
    })?;
    let file_hash_size = usize::try_from(header.file_hash_size).map_err(|_| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
    })?;
    let file_meta_size = usize::try_from(header.file_meta_size).map_err(|_| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
    })?;

    let mut tables = Zeroizing::new(Vec::new());
    reserve_exact(
        &mut tables,
        table_bytes,
        AllocationSite::ControlRomfsMetadata,
    )
    .map_err(|_| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::AllocationFailed)
    })?;
    tables.resize(table_bytes, 0);
    let directory_hash_range = 0..directory_hash_size;
    let directory_meta_range = directory_hash_range.end
        ..directory_hash_range
            .end
            .checked_add(directory_meta_size)
            .ok_or_else(|| {
                ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
            })?;
    let file_hash_range = directory_meta_range.end
        ..directory_meta_range
            .end
            .checked_add(file_hash_size)
            .ok_or_else(|| {
                ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
            })?;
    let file_meta_range = file_hash_range.end
        ..file_hash_range
            .end
            .checked_add(file_meta_size)
            .ok_or_else(|| {
                ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
            })?;
    for (source_offset, destination) in [
        (header.directory_hash_offset, directory_hash_range.clone()),
        (header.directory_meta_offset, directory_meta_range.clone()),
        (header.file_hash_offset, file_hash_range.clone()),
        (header.file_meta_offset, file_meta_range.clone()),
    ] {
        check_cancelled(control)?;
        let absolute = romfs.offset.checked_add(source_offset).ok_or_else(|| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
        })?;
        read_exact_at(section, absolute, &mut tables[destination])?;
    }
    checkpoint(Checkpoint::RomFsMetadata);
    check_cancelled(control)?;

    let directory_meta = &tables[directory_meta_range.clone()];
    let file_meta = &tables[file_meta_range.clone()];
    let Some(directory_count) = scan_record_count(
        directory_meta,
        ROMFS_DIRECTORY_RECORD_SIZE,
        20,
        true,
        control,
    )?
    else {
        return Ok(Err(ControlNcaQualificationReason::InvalidRomFsGraph));
    };
    let Some(file_count) =
        scan_record_count(file_meta, ROMFS_FILE_RECORD_SIZE, 28, false, control)?
    else {
        return Ok(Err(ControlNcaQualificationReason::InvalidRomFsGraph));
    };
    if directory_count
        .checked_add(file_count)
        .is_none_or(|count| count > MAX_ROMFS_RECORDS)
    {
        return Err(ControlNcaQualificationError::new(
            ControlNcaQualificationErrorCode::ResourceLimitExceeded,
        ));
    }
    let directories = match parse_directory_records(
        directory_meta,
        directory_meta_range.start,
        directory_count,
        control,
    )? {
        Some(records) => records,
        None => return Ok(Err(ControlNcaQualificationReason::InvalidRomFsGraph)),
    };
    let files = match parse_file_records(file_meta, file_meta_range.start, file_count, control)? {
        Some(records) => records,
        None => return Ok(Err(ControlNcaQualificationReason::InvalidRomFsGraph)),
    };
    let combined_count = directory_count.checked_add(file_count).ok_or_else(|| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
    })?;
    let mut visited = allocate_zeroed_bytes(combined_count, AllocationSite::ControlRomfsTraversal)?;
    let directory_buckets = &tables[directory_hash_range];
    if !validate_hash_chains(
        directory_buckets,
        &directories,
        &tables,
        &mut visited[..directory_count],
        control,
    )? {
        return Ok(Err(ControlNcaQualificationReason::InvalidRomFsGraph));
    }
    visited.fill(0);
    let file_buckets = &tables[file_hash_range];
    if !validate_hash_chains(
        file_buckets,
        &files,
        &tables,
        &mut visited[..file_count],
        control,
    )? {
        return Ok(Err(ControlNcaQualificationReason::InvalidRomFsGraph));
    }
    visited.fill(0);
    if !validate_graph(&directories, &files, &mut visited, control)? {
        return Ok(Err(ControlNcaQualificationReason::InvalidRomFsGraph));
    }
    if !validate_unique_names(&directories, &files, &tables, combined_count, control)? {
        return Ok(Err(ControlNcaQualificationReason::InvalidRomFsGraph));
    }
    // File data ends at the directory hash table, which follows the file partition.
    if !validate_file_extents(
        &files,
        header.data_offset,
        header.directory_hash_offset,
        control,
    )? {
        return Ok(Err(ControlNcaQualificationReason::InvalidRomFsExtent));
    }
    match output {
        ControlQualificationOutput::Facts => Ok(Ok(RomFsStats::Facts {
            directory_count,
            file_count,
        })),
        ControlQualificationOutput::ExtractionInventory => match normalize_romfs_tree(
            RomFsExtractionInput {
                metadata: &tables,
                directories: &directories,
                files: &files,
                data_offset: header.data_offset,
                level_offset: romfs.offset,
                partition_offset,
                partition_size,
            },
            control,
        )? {
            Ok(tree) => Ok(Ok(RomFsStats::Extraction { tree })),
            Err(reason) => Ok(Err(reason)),
        },
    }
}

fn scan_record_count(
    bytes: &[u8],
    fixed_size: usize,
    name_size_offset: usize,
    directory_table: bool,
    control: &QualificationControl<'_>,
) -> Result<Option<usize>, ControlNcaQualificationError> {
    let mut position = 0_usize;
    let mut count = 0_usize;
    while position < bytes.len() {
        check_cancelled(control)?;
        let Some(remaining) = bytes.len().checked_sub(position) else {
            return Ok(None);
        };
        if remaining < fixed_size {
            return Ok(None);
        }
        let Some(size_offset) = position.checked_add(name_size_offset) else {
            return Ok(None);
        };
        let Ok(name_size) = usize::try_from(read_u32(bytes, size_offset)) else {
            return Ok(None);
        };
        if (directory_table && count == 0 && name_size != 0)
            || ((directory_table && count > 0 || !directory_table) && name_size == 0)
        {
            return Ok(None);
        }
        let Some(record_size) = fixed_size.checked_add(name_size) else {
            return Ok(None);
        };
        let Some(aligned_size) = record_size.checked_add(3).map(|value| value & !3) else {
            return Ok(None);
        };
        if aligned_size > remaining {
            return Ok(None);
        }
        let Some(name_start) = position.checked_add(fixed_size) else {
            return Ok(None);
        };
        let Some(name_end) = name_start.checked_add(name_size) else {
            return Ok(None);
        };
        if !valid_romfs_name(&bytes[name_start..name_end], directory_table && count == 0)
            || bytes[name_end..position + aligned_size]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Ok(None);
        }
        let Some(next_position) = position.checked_add(aligned_size) else {
            return Ok(None);
        };
        position = next_position;
        let Some(next_count) = count.checked_add(1) else {
            return Ok(None);
        };
        count = next_count;
        if count > MAX_ROMFS_RECORDS {
            return Ok(Some(count));
        }
    }
    Ok(Some(count))
}

fn valid_romfs_name(name: &[u8], root: bool) -> bool {
    if root {
        return name.is_empty();
    }
    !name.is_empty()
        && name != b"."
        && name != b".."
        && !name.iter().any(|byte| matches!(*byte, 0 | b'/' | b'\\'))
}

fn parse_directory_records(
    bytes: &[u8],
    table_start: usize,
    record_count: usize,
    control: &QualificationControl<'_>,
) -> Result<Option<Vec<DirectoryRecord>>, ControlNcaQualificationError> {
    let mut records = Vec::new();
    reserve_exact(
        &mut records,
        record_count,
        AllocationSite::ControlRomfsRecords,
    )
    .map_err(|_| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::AllocationFailed)
    })?;
    let mut position = 0_usize;
    while position < bytes.len() {
        check_cancelled(control)?;
        let record_size = usize::try_from(read_u32(bytes, position + 20)).map_err(|_| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
        })?;
        let name_start = table_start
            .checked_add(position)
            .and_then(|value| value.checked_add(ROMFS_DIRECTORY_RECORD_SIZE))
            .ok_or_else(|| {
                ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
            })?;
        let offset = u32::try_from(position).map_err(|_| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
        })?;
        records.push(DirectoryRecord {
            name: NameHashRecord {
                offset,
                parent: read_u32(bytes, position),
                hash_next: read_u32(bytes, position + 16),
                name_start,
                name_size: record_size,
            },
            sibling: read_u32(bytes, position + 4),
            child_directory: read_u32(bytes, position + 8),
            child_file: read_u32(bytes, position + 12),
        });
        position = position
            .checked_add(ROMFS_DIRECTORY_RECORD_SIZE)
            .and_then(|value| value.checked_add(record_size))
            .and_then(|value| value.checked_add(3))
            .map(|value| value & !3)
            .ok_or_else(|| {
                ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
            })?;
    }
    Ok((records.len() == record_count).then_some(records))
}

fn parse_file_records(
    bytes: &[u8],
    table_start: usize,
    record_count: usize,
    control: &QualificationControl<'_>,
) -> Result<Option<Vec<FileRecord>>, ControlNcaQualificationError> {
    let mut records = Vec::new();
    reserve_exact(
        &mut records,
        record_count,
        AllocationSite::ControlRomfsRecords,
    )
    .map_err(|_| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::AllocationFailed)
    })?;
    let mut position = 0_usize;
    while position < bytes.len() {
        check_cancelled(control)?;
        let name_size = usize::try_from(read_u32(bytes, position + 28)).map_err(|_| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
        })?;
        let name_start = table_start
            .checked_add(position)
            .and_then(|value| value.checked_add(ROMFS_FILE_RECORD_SIZE))
            .ok_or_else(|| {
                ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
            })?;
        let offset = u32::try_from(position).map_err(|_| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
        })?;
        records.push(FileRecord {
            name: NameHashRecord {
                offset,
                parent: read_u32(bytes, position),
                hash_next: read_u32(bytes, position + 24),
                name_start,
                name_size,
            },
            sibling: read_u32(bytes, position + 4),
            data_offset: read_u64(bytes, position + 8),
            size: read_u64(bytes, position + 16),
        });
        position = position
            .checked_add(ROMFS_FILE_RECORD_SIZE)
            .and_then(|value| value.checked_add(name_size))
            .and_then(|value| value.checked_add(3))
            .map(|value| value & !3)
            .ok_or_else(|| {
                ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
            })?;
    }
    Ok((records.len() == record_count).then_some(records))
}

fn validate_hash_chains<T: HashedRecord>(
    table: &[u8],
    records: &[T],
    metadata: &[u8],
    visited: &mut [u8],
    control: &QualificationControl<'_>,
) -> Result<bool, ControlNcaQualificationError> {
    if table.len() < 4 || !table.len().is_multiple_of(4) || visited.len() < records.len() {
        return Ok(false);
    }
    visited[..records.len()].fill(0);
    let bucket_count = table.len() / 4;
    for bucket in 0..bucket_count {
        check_cancelled(control)?;
        let mut current = read_u32(table, bucket * 4);
        let mut traversed = 0_usize;
        while current != ROMFS_EMPTY {
            check_cancelled(control)?;
            let Ok(index) =
                records.binary_search_by_key(&current, |record| record.name_hash_record().offset)
            else {
                return Ok(false);
            };
            if visited[index] != 0 || traversed >= records.len() {
                return Ok(false);
            }
            let record = records[index].name_hash_record();
            let Some(name_end) = record.name_start.checked_add(record.name_size) else {
                return Ok(false);
            };
            let Some(name) = metadata.get(record.name_start..name_end) else {
                return Ok(false);
            };
            if path_hash(record.parent, name) as usize % bucket_count != bucket {
                return Ok(false);
            }
            visited[index] = 1;
            current = record.hash_next;
            traversed += 1;
        }
    }
    Ok(visited[..records.len()].iter().all(|value| *value == 1))
}

fn path_hash(parent: u32, name: &[u8]) -> u32 {
    let mut hash = parent ^ 123_456_789;
    for byte in name {
        hash = hash.rotate_right(5) ^ u32::from(*byte);
    }
    hash
}

fn validate_graph(
    directories: &[DirectoryRecord],
    files: &[FileRecord],
    visited: &mut [u8],
    control: &QualificationControl<'_>,
) -> Result<bool, ControlNcaQualificationError> {
    let Some(root) = directories.first() else {
        return Ok(false);
    };
    if root.name.offset != 0
        || root.name.parent != 0
        || root.sibling != ROMFS_EMPTY
        || root.name.name_size != 0
        || visited.len() != directories.len() + files.len()
    {
        return Ok(false);
    }
    visited.fill(0);
    visited[0] = 1;
    let mut stack = Vec::new();
    reserve_exact(
        &mut stack,
        directories.len(),
        AllocationSite::ControlRomfsTraversal,
    )
    .map_err(|_| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::AllocationFailed)
    })?;
    stack.push(0_usize);
    while let Some(parent_index) = stack.pop() {
        check_cancelled(control)?;
        let parent = &directories[parent_index];
        let mut current = parent.child_directory;
        let mut steps = 0_usize;
        while current != ROMFS_EMPTY {
            check_cancelled(control)?;
            let Ok(index) = directories.binary_search_by_key(&current, |record| record.name.offset)
            else {
                return Ok(false);
            };
            if index == 0 || visited[index] != 0 || steps >= directories.len() {
                return Ok(false);
            }
            let child = &directories[index];
            if child.name.parent != parent.name.offset {
                return Ok(false);
            }
            visited[index] = 1;
            stack.push(index);
            current = child.sibling;
            steps += 1;
        }

        current = parent.child_file;
        steps = 0;
        while current != ROMFS_EMPTY {
            check_cancelled(control)?;
            let Ok(index) = files.binary_search_by_key(&current, |record| record.name.offset)
            else {
                return Ok(false);
            };
            let seen_index = directories.len() + index;
            if visited[seen_index] != 0 || steps >= files.len() {
                return Ok(false);
            }
            let child = &files[index];
            if child.name.parent != parent.name.offset {
                return Ok(false);
            }
            visited[seen_index] = 1;
            current = child.sibling;
            steps += 1;
        }
    }
    Ok(visited.iter().all(|value| *value == 1))
}

#[derive(Clone, Copy)]
struct NameReference {
    is_directory: bool,
    index: usize,
    parent: u32,
}

fn validate_unique_names(
    directories: &[DirectoryRecord],
    files: &[FileRecord],
    metadata: &[u8],
    record_count: usize,
    control: &QualificationControl<'_>,
) -> Result<bool, ControlNcaQualificationError> {
    let mut names = Vec::new();
    reserve_exact(
        &mut names,
        record_count.saturating_sub(1),
        AllocationSite::ControlRomfsNames,
    )
    .map_err(|_| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::AllocationFailed)
    })?;
    for (index, record) in directories.iter().enumerate().skip(1) {
        check_cancelled(control)?;
        names.push(NameReference {
            is_directory: true,
            index,
            parent: record.name.parent,
        });
    }
    for (index, record) in files.iter().enumerate() {
        check_cancelled(control)?;
        names.push(NameReference {
            is_directory: false,
            index,
            parent: record.name.parent,
        });
    }
    check_cancelled(control)?;
    names.sort_unstable_by(|left, right| {
        left.parent.cmp(&right.parent).then_with(|| {
            name_for_reference(*left, directories, files, metadata).cmp(name_for_reference(
                *right,
                directories,
                files,
                metadata,
            ))
        })
    });
    for pair in names.windows(2) {
        check_cancelled(control)?;
        if pair[0].parent == pair[1].parent
            && name_for_reference(pair[0], directories, files, metadata)
                == name_for_reference(pair[1], directories, files, metadata)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn name_for_reference<'a>(
    reference: NameReference,
    directories: &[DirectoryRecord],
    files: &[FileRecord],
    metadata: &'a [u8],
) -> &'a [u8] {
    let record = if reference.is_directory {
        &directories[reference.index].name
    } else {
        &files[reference.index].name
    };
    &metadata[record.name_start..record.name_start + record.name_size]
}

#[derive(Clone, Copy)]
struct FileExtent {
    start: u64,
    end: u64,
}

fn validate_file_extents(
    files: &[FileRecord],
    data_offset: u64,
    file_data_end: u64,
    control: &QualificationControl<'_>,
) -> Result<bool, ControlNcaQualificationError> {
    if file_data_end < data_offset {
        return Ok(false);
    }
    let available = file_data_end - data_offset;
    let mut extents = Vec::new();
    reserve_exact(
        &mut extents,
        files.len(),
        AllocationSite::ControlRomfsExtents,
    )
    .map_err(|_| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::AllocationFailed)
    })?;
    for file in files {
        check_cancelled(control)?;
        if file.data_offset % 16 != 0
            || file.data_offset > available
            || file.size > available - file.data_offset
        {
            return Ok(false);
        }
        let start = data_offset.checked_add(file.data_offset).ok_or_else(|| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
        })?;
        let end = start.checked_add(file.size).ok_or_else(|| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
        })?;
        if file.size > 0 {
            extents.push(FileExtent { start, end });
        }
    }
    check_cancelled(control)?;
    extents.sort_unstable_by_key(|extent| (extent.start, extent.end));
    let mut previous_end = data_offset;
    for extent in extents {
        check_cancelled(control)?;
        if extent.start < previous_end {
            return Ok(false);
        }
        previous_end = extent.end;
    }
    Ok(true)
}

fn normalize_romfs_tree(
    input: RomFsExtractionInput<'_>,
    control: &QualificationControl<'_>,
) -> Result<Result<RomFsExtractionTree, ControlNcaQualificationReason>, ControlNcaQualificationError>
{
    let RomFsExtractionInput {
        metadata,
        directories,
        files,
        data_offset,
        level_offset,
        partition_offset,
        partition_size,
    } = input;

    let mut paths = Vec::new();
    reserve_exact(
        &mut paths,
        directories.len(),
        AllocationSite::ControlRomfsExtractionDirectoryPaths,
    )
    .map_err(|_| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::AllocationFailed)
    })?;
    paths.resize_with(directories.len(), String::new);
    let Some(root_path) = paths.first_mut() else {
        return Ok(Err(ControlNcaQualificationReason::InvalidRomFsGraph));
    };
    crate::allocation::reserve_string_exact(
        root_path,
        1,
        AllocationSite::ControlRomfsExtractionDirectoryPathBytes,
    )
    .map_err(|_| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::AllocationFailed)
    })?;
    root_path.push('0');

    let mut stack = Vec::new();
    reserve_exact(
        &mut stack,
        directories.len(),
        AllocationSite::ControlRomfsExtractionTraversal,
    )
    .map_err(|_| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::AllocationFailed)
    })?;
    stack.push(0_usize);
    let mut traversal_path_bytes = 1_usize;
    let mut visited_directories = 1_usize;
    while let Some(parent_index) = stack.pop() {
        check_cancelled(control)?;
        let parent = directories[parent_index];
        let mut current = parent.child_directory;
        let mut steps = 0_usize;
        while current != ROMFS_EMPTY {
            check_cancelled(control)?;
            let Ok(index) = directories.binary_search_by_key(&current, |record| record.name.offset)
            else {
                return Ok(Err(ControlNcaQualificationReason::InvalidRomFsGraph));
            };
            if index == 0 || !paths[index].is_empty() || steps >= directories.len() {
                return Ok(Err(ControlNcaQualificationReason::InvalidRomFsGraph));
            }
            let record = directories[index];
            let name_end = record.name.name_start.checked_add(record.name.name_size);
            let Some(name_bytes) =
                name_end.and_then(|end| metadata.get(record.name.name_start..end))
            else {
                return Ok(Err(ControlNcaQualificationReason::InvalidRomFsGraph));
            };
            let Ok(name) = std::str::from_utf8(name_bytes) else {
                return Ok(Err(ControlNcaQualificationReason::InvalidRomFsGraph));
            };
            let child_path = {
                let Some(parent_path) = paths
                    .get(parent_index)
                    .filter(|path| !path.is_empty())
                    .map(String::as_str)
                else {
                    return Ok(Err(ControlNcaQualificationReason::InvalidRomFsGraph));
                };
                join_romfs_path(
                    parent_path,
                    name,
                    AllocationSite::ControlRomfsExtractionTraversalPathBytes,
                )?
            };
            traversal_path_bytes = traversal_path_bytes
                .checked_add(child_path.len())
                .ok_or_else(|| {
                    ControlNcaQualificationError::new(
                        ControlNcaQualificationErrorCode::ResourceLimitExceeded,
                    )
                })?;
            if traversal_path_bytes > crate::partition_fs::MAX_TOTAL_PATH_BYTES {
                return Err(ControlNcaQualificationError::new(
                    ControlNcaQualificationErrorCode::ResourceLimitExceeded,
                ));
            }
            paths[index] = child_path;
            visited_directories = visited_directories.checked_add(1).ok_or_else(|| {
                ControlNcaQualificationError::new(
                    ControlNcaQualificationErrorCode::ResourceLimitExceeded,
                )
            })?;
            stack.push(index);
            current = record.sibling;
            steps += 1;
        }
    }
    if visited_directories != directories.len() {
        return Ok(Err(ControlNcaQualificationReason::InvalidRomFsGraph));
    }

    let mut normalized_path_bytes = traversal_path_bytes;
    let mut normalized_files = Vec::new();
    reserve_exact(
        &mut normalized_files,
        files.len(),
        AllocationSite::ControlRomfsExtractionFiles,
    )
    .map_err(|_| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::AllocationFailed)
    })?;
    let partition_end = partition_offset
        .checked_add(partition_size)
        .ok_or_else(|| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
        })?;
    for file in files {
        check_cancelled(control)?;
        let Ok(parent_index) =
            directories.binary_search_by_key(&file.name.parent, |record| record.name.offset)
        else {
            return Ok(Err(ControlNcaQualificationReason::InvalidRomFsGraph));
        };
        let name_end = file.name.name_start.checked_add(file.name.name_size);
        let Some(name_bytes) = name_end.and_then(|end| metadata.get(file.name.name_start..end))
        else {
            return Ok(Err(ControlNcaQualificationReason::InvalidRomFsGraph));
        };
        let Ok(name) = std::str::from_utf8(name_bytes) else {
            return Ok(Err(ControlNcaQualificationReason::InvalidRomFsGraph));
        };
        let Some(parent_path) = paths
            .get(parent_index)
            .and_then(|path| relative_romfs_directory_path(path))
        else {
            return Ok(Err(ControlNcaQualificationReason::InvalidRomFsGraph));
        };
        let file_path = join_romfs_path(
            parent_path,
            name,
            AllocationSite::ControlRomfsExtractionFilePathBytes,
        )?;
        let manifest_path_size = file_path.len().checked_add(2).ok_or_else(|| {
            ControlNcaQualificationError::new(
                ControlNcaQualificationErrorCode::ResourceLimitExceeded,
            )
        })?;
        normalized_path_bytes = normalized_path_bytes
            .checked_add(manifest_path_size)
            .ok_or_else(|| {
                ControlNcaQualificationError::new(
                    ControlNcaQualificationErrorCode::ResourceLimitExceeded,
                )
            })?;
        if normalized_path_bytes > crate::partition_fs::MAX_TOTAL_PATH_BYTES {
            return Err(ControlNcaQualificationError::new(
                ControlNcaQualificationErrorCode::ResourceLimitExceeded,
            ));
        }
        let section_offset = level_offset
            .checked_add(data_offset)
            .and_then(|offset| offset.checked_add(file.data_offset))
            .ok_or_else(|| {
                ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
            })?;
        let absolute_offset = partition_offset
            .checked_add(section_offset)
            .ok_or_else(|| {
                ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
            })?;
        let absolute_end = absolute_offset.checked_add(file.size).ok_or_else(|| {
            ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::InternalIo)
        })?;
        if absolute_offset < partition_offset || absolute_end > partition_end {
            return Ok(Err(ControlNcaQualificationReason::InvalidRomFsExtent));
        }
        normalized_files.push(crate::inspection::NativeNcaFileSpan {
            partition_index: 0,
            path: file_path,
            offset: absolute_offset,
            size: file.size,
        });
    }
    Ok(Ok(RomFsExtractionTree {
        directories: paths,
        files: normalized_files,
    }))
}

fn join_romfs_path(
    parent: &str,
    name: &str,
    site: AllocationSite,
) -> Result<String, ControlNcaQualificationError> {
    let separator_size = usize::from(!parent.is_empty());
    let capacity = parent
        .len()
        .checked_add(separator_size)
        .and_then(|size| size.checked_add(name.len()))
        .ok_or_else(|| {
            ControlNcaQualificationError::new(
                ControlNcaQualificationErrorCode::ResourceLimitExceeded,
            )
        })?;
    let mut path = String::new();
    crate::allocation::reserve_string_exact(&mut path, capacity, site).map_err(|_| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::AllocationFailed)
    })?;
    path.push_str(parent);
    if separator_size != 0 {
        path.push('/');
    }
    path.push_str(name);
    Ok(path)
}

fn relative_romfs_directory_path(path: &str) -> Option<&str> {
    path.strip_prefix("0/")
        .or_else(|| (path == "0").then_some(""))
}

fn allocate_zeroed_bytes(
    length: usize,
    site: AllocationSite,
) -> Result<Vec<u8>, ControlNcaQualificationError> {
    let mut bytes = Vec::new();
    reserve_exact(&mut bytes, length, site).map_err(|_| {
        ControlNcaQualificationError::new(ControlNcaQualificationErrorCode::AllocationFailed)
    })?;
    bytes.resize(length, 0);
    Ok(bytes)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed-width field"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed-width field"),
    )
}

#[cfg(test)]
#[path = "control_nca_test_fixture.rs"]
#[allow(dead_code)]
pub(crate) mod synthetic_fixture;
#[cfg(test)]
#[path = "control_nca_qualification_tests.rs"]
mod tests;
