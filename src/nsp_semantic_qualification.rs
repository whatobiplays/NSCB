//! Read-only semantic checks for one bounded, rights-free Application NSP profile.
//!
//! A successful result records internal consistency for one Meta NCA, one
//! Program NCA, and one Application CNMT. It does not establish authenticity,
//! installability, full verification, or broad package compatibility.

use crate::allocation::{AllocationSite, reserve_exact};
use crate::engine::{ContainerProbeEntry, ContainerProbeResult};
use crate::file_identity::{FileIdentity, FileSnapshot};
use crate::key_file::{NspKeyFileError, NspQualificationKeys};
use crate::nca::{self, ContentType, Distribution, HeaderError};
use crate::sha256::Sha256Digest;
use aes::Aes128;
use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_PFS0_METADATA_BYTES: usize = 1024 * 1024;
const MAX_PROGRAM_PFS0_ENTRIES: usize = 4096;
const MAX_WORKING_BUFFER_BYTES: usize = 1024 * 1024;
const MIN_HASH_BLOCK_BYTES: u32 = 0x200;
const MAX_HASH_BLOCK_BYTES: u32 = 0x100000;
// Application CNMT: 0x20-byte header, 0x10-byte extended header, one 0x38-byte
// content row, and the format's trailing 0x20-byte digest.
const SUPPORTED_CNMT_BYTES: usize = 0x88;
const OUTER_PFS0_MAX_ENTRIES: usize = 65_536;

/// A request to check the supported semantic profile of one NSP-like file.
///
/// The key file must contain `header_key` (or `nca_header_key`) and the
/// pre-derived `key_area_key_application_00` value. Key contents are never
/// included in request diagnostics or results.
#[derive(Clone)]
pub struct NspSemanticQualificationRequest {
    input: PathBuf,
    key_file: PathBuf,
    cancellation: Option<crate::CancellationHandle>,
}

impl NspSemanticQualificationRequest {
    /// Creates a request using explicit input and key-file paths.
    pub fn new(input: impl Into<PathBuf>, key_file: impl Into<PathBuf>) -> Self {
        Self {
            input: input.into(),
            key_file: key_file.into(),
            cancellation: None,
        }
    }

    /// Attaches host-owned cancellation state to the request.
    pub fn with_cancellation(mut self, cancellation: crate::CancellationHandle) -> Self {
        self.cancellation = Some(cancellation);
        self
    }
}

impl fmt::Debug for NspSemanticQualificationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NspSemanticQualificationRequest")
            .field("input", &"[REDACTED]")
            .field("key_file", &"[REDACTED]")
            .field("cancellation", &self.cancellation.is_some())
            .finish()
    }
}

/// Stable categories for prerequisite, cancellation, resource, and I/O failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NspSemanticQualificationErrorCode {
    /// The source could not be opened or read as a regular file.
    InputUnavailable,
    /// The source path or observable source metadata changed during the read.
    InputChangedDuringQualification,
    /// The key file could not be opened or read as a regular file.
    KeyFileUnavailable,
    /// The key file changed while its key material was being read.
    KeyFileChangedDuringQualification,
    /// The key file is malformed or contains conflicting recognized keys.
    KeyFileMalformed,
    /// The required NCA header key is absent.
    MissingHeaderKey,
    /// The required pre-derived Application key-area key is absent.
    MissingApplicationKeyAreaKey,
    /// The key file exceeds the existing one-megabyte key-file limit.
    KeyFileLimitExceeded,
    /// The source exceeds the supported 64-GiB profile limit.
    InputLimitExceeded,
    /// A PFS0 metadata or entry-count ceiling was exceeded.
    Pfs0ResourceLimitExceeded,
    /// A bounded allocation could not be reserved.
    AllocationFailed,
    /// A supplied key and damaged encrypted section data cannot be separated reliably.
    KeyOrSectionIntegrityFailure,
    /// The caller cancelled qualification.
    Cancelled,
    /// An unexpected internal file operation failed.
    InternalIo,
}

impl NspSemanticQualificationErrorCode {
    /// Returns the stable machine-readable spelling of this error.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InputUnavailable => "input_unavailable",
            Self::InputChangedDuringQualification => "input_changed_during_qualification",
            Self::KeyFileUnavailable => "key_file_unavailable",
            Self::KeyFileChangedDuringQualification => "key_file_changed_during_qualification",
            Self::KeyFileMalformed => "key_file_malformed",
            Self::MissingHeaderKey => "missing_header_key",
            Self::MissingApplicationKeyAreaKey => "missing_application_key_area_key",
            Self::KeyFileLimitExceeded => "key_file_limit_exceeded",
            Self::InputLimitExceeded => "input_limit_exceeded",
            Self::Pfs0ResourceLimitExceeded => "pfs0_resource_limit_exceeded",
            Self::AllocationFailed => "allocation_failed",
            Self::KeyOrSectionIntegrityFailure => "key_or_section_integrity_failure",
            Self::Cancelled => "cancelled",
            Self::InternalIo => "internal_io",
        }
    }
}

/// A sanitized qualification error with no paths, key lines, or input bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NspSemanticQualificationError {
    code: NspSemanticQualificationErrorCode,
}

impl NspSemanticQualificationError {
    const fn new(code: NspSemanticQualificationErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable error category.
    pub const fn code(self) -> NspSemanticQualificationErrorCode {
        self.code
    }
}

impl fmt::Display for NspSemanticQualificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.code {
            NspSemanticQualificationErrorCode::InputUnavailable => {
                "the qualification input could not be read"
            }
            NspSemanticQualificationErrorCode::InputChangedDuringQualification => {
                "the qualification input changed during the read"
            }
            NspSemanticQualificationErrorCode::KeyFileUnavailable => {
                "the qualification key file could not be read"
            }
            NspSemanticQualificationErrorCode::KeyFileChangedDuringQualification => {
                "the qualification key file changed during the read"
            }
            NspSemanticQualificationErrorCode::KeyFileMalformed => {
                "the qualification key file is malformed"
            }
            NspSemanticQualificationErrorCode::MissingHeaderKey => {
                "the qualification key file lacks the NCA header key"
            }
            NspSemanticQualificationErrorCode::MissingApplicationKeyAreaKey => {
                "the qualification key file lacks the Application key-area key"
            }
            NspSemanticQualificationErrorCode::KeyFileLimitExceeded => {
                "the qualification key file exceeds its supported size"
            }
            NspSemanticQualificationErrorCode::InputLimitExceeded => {
                "the qualification input exceeds its supported size"
            }
            NspSemanticQualificationErrorCode::Pfs0ResourceLimitExceeded => {
                "the qualification input exceeds a PFS0 resource limit"
            }
            NspSemanticQualificationErrorCode::AllocationFailed => {
                "qualification could not reserve bounded memory"
            }
            NspSemanticQualificationErrorCode::KeyOrSectionIntegrityFailure => {
                "the supplied key or encrypted section integrity check failed"
            }
            NspSemanticQualificationErrorCode::Cancelled => "qualification was cancelled",
            NspSemanticQualificationErrorCode::InternalIo => {
                "an internal qualification file operation failed"
            }
        })
    }
}

impl std::error::Error for NspSemanticQualificationError {}

/// A stable reason why content did not match the supported semantic profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NspSemanticQualificationReason {
    /// The source does not contain valid bounded PFS0 framing.
    InvalidContainerStructure,
    /// The outer package does not contain exactly the supported two members.
    UnsupportedMemberSet,
    /// A PFS0 payload contains bytes outside its nonempty member spans.
    UnaccountedPfs0Payload,
    /// An embedded member is not a valid supported NCA3 header.
    InvalidNcaHeader,
    /// An NCA role, distribution, key generation, or section profile is unsupported.
    UnsupportedNcaProfile,
    /// At least one NCA has a nonzero RightsId.
    RightsBearingContent,
    /// The NCA section layout or PFS0 structure is malformed or unsupported.
    InvalidSectionStructure,
    /// The Meta section does not contain the supported single Application CNMT.
    UnsupportedCnmtProfile,
    /// CNMT and NCA title IDs or Program content details do not match.
    ProgramRelationshipMismatch,
}

/// The qualified state of the source after bounded semantic checks.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "details")]
pub enum NspSemanticQualificationOutcome {
    /// The source matches the one supported synthetic semantic profile.
    Qualified(NspSemanticQualificationFacts),
    /// The source is readable but does not match the supported profile.
    NotQualified(NspSemanticQualificationReason),
}

/// The exact narrow semantic profile evaluated by this capability.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NspSemanticQualificationProfile {
    /// Rights-free base Application with one Meta and one Program NCA.
    RightsFreeBaseApplicationV1,
}

/// Byte-derived facts for a qualified two-member base Application package.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NspSemanticQualificationFacts {
    /// The exact semantic profile that was qualified.
    pub profile: NspSemanticQualificationProfile,
    /// Application title ID shared by both NCA headers and the CNMT.
    pub title_id: u64,
    /// CNMT title version.
    pub cnmt_version: u32,
    /// Required download system version recorded in the CNMT.
    pub required_download_system_version: u32,
    /// Required system version recorded in the Application extended header.
    pub required_system_version: u32,
    /// Required application version recorded in the Application extended header.
    pub required_application_version: u32,
    /// Exact CNMT ContentId matched to the Program NCA digest.
    pub cnmt_program_content_id: [u8; 16],
    /// Complete accounting in deterministic Meta-then-Program role order.
    pub members: Vec<NspSemanticQualificationMember>,
}

/// One accounted outer PFS0 member.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NspSemanticQualificationMember {
    /// Role derived from the decrypted NCA content-type field.
    pub role: NspSemanticQualificationRole,
    /// Raw NCA member length in bytes.
    pub size: u64,
    /// SHA-256 over the complete raw NCA member bytes.
    pub sha256: Sha256Digest,
}

/// A supported member role derived from NCA bytes.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NspSemanticQualificationRole {
    /// The NCA carrying the one supported CNMT.
    Meta,
    /// The NCA matched to the one Program row in that CNMT.
    Program,
}

/// Result of one source hash and semantic-profile evaluation.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NspSemanticQualificationResult {
    /// SHA-256 over every byte of the source observed through the opened handle.
    pub source_sha256: Sha256Digest,
    /// Qualification outcome and, when qualified, byte-derived profile facts.
    pub outcome: NspSemanticQualificationOutcome,
}

impl NspSemanticQualificationResult {
    fn not_qualified(source_sha256: Sha256Digest, reason: NspSemanticQualificationReason) -> Self {
        Self {
            source_sha256,
            outcome: NspSemanticQualificationOutcome::NotQualified(reason),
        }
    }
}

#[derive(Clone, Copy)]
enum Checkpoint {
    SourceHashChunk,
    SourceHashed,
    MemberStarted,
    MemberFinished,
    QualificationFinished,
}

struct OpenedInput {
    file: File,
    canonical_path: PathBuf,
    requested_path: PathBuf,
    identity: FileIdentity,
    snapshot: FileSnapshot,
    size: u64,
}

impl OpenedInput {
    fn revalidate(
        &self,
        code: NspSemanticQualificationErrorCode,
    ) -> Result<(), NspSemanticQualificationError> {
        let unavailable =
            if code == NspSemanticQualificationErrorCode::KeyFileChangedDuringQualification {
                NspSemanticQualificationErrorCode::KeyFileUnavailable
            } else {
                NspSemanticQualificationErrorCode::InputUnavailable
            };
        let metadata = self
            .file
            .metadata()
            .map_err(|_| NspSemanticQualificationError::new(unavailable))?;
        let identity = crate::file_identity::handle_identity(&self.file);
        let current = crate::file_identity::file_snapshot(&metadata, identity);
        if identity != Some(self.identity)
            || crate::file_identity::path_identity(&self.canonical_path) != Some(self.identity)
            || crate::file_identity::followed_path_identity(&self.requested_path)
                != Some(self.identity)
            || current != self.snapshot
        {
            return Err(NspSemanticQualificationError::new(code));
        }
        Ok(())
    }
}

struct SourceDigests {
    source: Sha256Digest,
    members: [Sha256Digest; 2],
}

struct NcaRecord {
    role: NspSemanticQualificationRole,
    title_id: u64,
    member_size: u64,
    member_sha256: Sha256Digest,
    cnmt: Option<CnmtProgramRow>,
}

#[derive(Clone, Copy)]
struct CnmtProgramRow {
    title_id: u64,
    version: u32,
    required_download_system_version: u32,
    required_system_version: u32,
    required_application_version: u32,
    content_sha256: [u8; 32],
    content_id: [u8; 16],
    content_size: u64,
    content_type: u8,
    id_offset: u8,
}

struct SectionRegions {
    master_hash: [u8; 32],
    hash_table_offset: u64,
    hash_table_size: u64,
    pfs0_offset: u64,
    pfs0_size: u64,
    block_size: u32,
}

/// Performs qualification without adding a CLI or a provider dependency.
pub(crate) fn qualify(
    request: NspSemanticQualificationRequest,
) -> Result<NspSemanticQualificationResult, NspSemanticQualificationError> {
    let mut checkpoint = |_| {};
    qualify_inner(request, &mut checkpoint)
}

#[cfg(test)]
fn qualify_with_checkpoint<F>(
    request: NspSemanticQualificationRequest,
    mut checkpoint: F,
) -> Result<NspSemanticQualificationResult, NspSemanticQualificationError>
where
    F: FnMut(Checkpoint),
{
    qualify_inner(request, &mut checkpoint)
}

fn qualify_inner<F>(
    request: NspSemanticQualificationRequest,
    checkpoint: &mut F,
) -> Result<NspSemanticQualificationResult, NspSemanticQualificationError>
where
    F: FnMut(Checkpoint),
{
    check_cancelled(&request)?;
    let mut input = open_snapshot_file(
        &request.input,
        NspSemanticQualificationErrorCode::InputUnavailable,
        NspSemanticQualificationErrorCode::InputChangedDuringQualification,
    )?;
    validate_input_size(input.size)?;
    input.file.seek(SeekFrom::Start(0)).map_err(|_| {
        NspSemanticQualificationError::new(NspSemanticQualificationErrorCode::InputUnavailable)
    })?;
    let outer = match crate::pfs0::probe_with_limits(
        &mut input.file,
        input.size,
        OUTER_PFS0_MAX_ENTRIES,
        MAX_PFS0_METADATA_BYTES,
    ) {
        Ok(probe) => probe,
        Err(error) => {
            let code = error.code();
            if code == crate::ContainerProbeErrorCode::InputUnavailable {
                return Err(NspSemanticQualificationError::new(
                    NspSemanticQualificationErrorCode::InputUnavailable,
                ));
            }
            if matches!(
                code,
                crate::ContainerProbeErrorCode::LimitExceeded
                    | crate::ContainerProbeErrorCode::ResourceLimitExceeded
            ) {
                return Err(NspSemanticQualificationError::new(
                    if code == crate::ContainerProbeErrorCode::ResourceLimitExceeded {
                        NspSemanticQualificationErrorCode::AllocationFailed
                    } else {
                        NspSemanticQualificationErrorCode::Pfs0ResourceLimitExceeded
                    },
                ));
            }
            input.revalidate(NspSemanticQualificationErrorCode::InputChangedDuringQualification)?;
            let digests = hash_source(&mut input, None, &request, checkpoint)?;
            input.revalidate(NspSemanticQualificationErrorCode::InputChangedDuringQualification)?;
            return Ok(NspSemanticQualificationResult::not_qualified(
                digests.source,
                NspSemanticQualificationReason::InvalidContainerStructure,
            ));
        }
    };
    input.revalidate(NspSemanticQualificationErrorCode::InputChangedDuringQualification)?;
    if outer.entries.len() != 2 {
        let digests = hash_source(&mut input, None, &request, checkpoint)?;
        input.revalidate(NspSemanticQualificationErrorCode::InputChangedDuringQualification)?;
        return Ok(NspSemanticQualificationResult::not_qualified(
            digests.source,
            NspSemanticQualificationReason::UnsupportedMemberSet,
        ));
    }
    if !pfs0_payload_is_fully_accounted(&outer)? {
        let digests = hash_source(&mut input, None, &request, checkpoint)?;
        input.revalidate(NspSemanticQualificationErrorCode::InputChangedDuringQualification)?;
        return Ok(NspSemanticQualificationResult::not_qualified(
            digests.source,
            NspSemanticQualificationReason::UnaccountedPfs0Payload,
        ));
    }

    let mut key_file = open_snapshot_file(
        &request.key_file,
        NspSemanticQualificationErrorCode::KeyFileUnavailable,
        NspSemanticQualificationErrorCode::KeyFileChangedDuringQualification,
    )?;
    if key_file.size > crate::key_file::MAX_KEY_FILE_BYTES {
        return Err(NspSemanticQualificationError::new(
            NspSemanticQualificationErrorCode::KeyFileLimitExceeded,
        ));
    }
    let keys = crate::key_file::read_nsp_qualification_keys(&mut key_file.file, key_file.size)
        .map_err(map_key_file_error)?;
    key_file.revalidate(NspSemanticQualificationErrorCode::KeyFileChangedDuringQualification)?;
    check_cancelled(&request)?;

    let digests = hash_source(&mut input, Some(&outer.entries), &request, checkpoint)?;
    input.revalidate(NspSemanticQualificationErrorCode::InputChangedDuringQualification)?;
    checkpoint(Checkpoint::SourceHashed);
    check_cancelled(&request)?;

    let mut records = try_reserve_vec(2, AllocationSite::NspRecords)?;
    for (index, entry) in outer.entries.iter().enumerate() {
        checkpoint(Checkpoint::MemberStarted);
        check_cancelled(&request)?;
        let record = match read_nca_member(
            &mut input.file,
            input.size,
            entry,
            digests.members[index],
            &keys,
            &request,
            checkpoint,
        )? {
            ReadDecision::Supported(record) => record,
            ReadDecision::NotQualified(reason) => {
                input.revalidate(
                    NspSemanticQualificationErrorCode::InputChangedDuringQualification,
                )?;
                return Ok(NspSemanticQualificationResult::not_qualified(
                    digests.source,
                    reason,
                ));
            }
        };
        records.push(record);
        input.revalidate(NspSemanticQualificationErrorCode::InputChangedDuringQualification)?;
        checkpoint(Checkpoint::MemberFinished);
        check_cancelled(&request)?;
    }
    input.revalidate(NspSemanticQualificationErrorCode::InputChangedDuringQualification)?;

    let Some(meta_index) = records
        .iter()
        .position(|record| record.role == NspSemanticQualificationRole::Meta)
    else {
        return Ok(NspSemanticQualificationResult::not_qualified(
            digests.source,
            NspSemanticQualificationReason::UnsupportedMemberSet,
        ));
    };
    let Some(program_index) = records
        .iter()
        .position(|record| record.role == NspSemanticQualificationRole::Program)
    else {
        return Ok(NspSemanticQualificationResult::not_qualified(
            digests.source,
            NspSemanticQualificationReason::UnsupportedMemberSet,
        ));
    };
    if meta_index == program_index {
        return Ok(NspSemanticQualificationResult::not_qualified(
            digests.source,
            NspSemanticQualificationReason::UnsupportedMemberSet,
        ));
    }
    let meta = &records[meta_index];
    let program = &records[program_index];
    let Some(cnmt) = meta.cnmt else {
        return Ok(NspSemanticQualificationResult::not_qualified(
            digests.source,
            NspSemanticQualificationReason::UnsupportedCnmtProfile,
        ));
    };
    if meta.title_id != program.title_id
        || meta.title_id != cnmt.title_id
        || program.title_id != cnmt.title_id
        || cnmt.content_type != 1
        || cnmt.id_offset != 0
        || cnmt.content_size != program.member_size
        || cnmt.content_sha256 != *program.member_sha256.as_bytes()
        || cnmt.content_id != program.member_sha256.as_bytes()[..16]
    {
        return Ok(NspSemanticQualificationResult::not_qualified(
            digests.source,
            NspSemanticQualificationReason::ProgramRelationshipMismatch,
        ));
    }

    let mut members = try_reserve_vec(2, AllocationSite::NspMembers)?;
    members.extend([
        NspSemanticQualificationMember {
            role: NspSemanticQualificationRole::Meta,
            size: meta.member_size,
            sha256: meta.member_sha256,
        },
        NspSemanticQualificationMember {
            role: NspSemanticQualificationRole::Program,
            size: program.member_size,
            sha256: program.member_sha256,
        },
    ]);
    checkpoint(Checkpoint::QualificationFinished);
    check_cancelled(&request)?;
    input.revalidate(NspSemanticQualificationErrorCode::InputChangedDuringQualification)?;
    Ok(NspSemanticQualificationResult {
        source_sha256: digests.source,
        outcome: NspSemanticQualificationOutcome::Qualified(NspSemanticQualificationFacts {
            profile: NspSemanticQualificationProfile::RightsFreeBaseApplicationV1,
            title_id: cnmt.title_id,
            cnmt_version: cnmt.version,
            required_download_system_version: cnmt.required_download_system_version,
            required_system_version: cnmt.required_system_version,
            required_application_version: cnmt.required_application_version,
            cnmt_program_content_id: cnmt.content_id,
            members,
        }),
    })
}

fn open_snapshot_file(
    path: &Path,
    unavailable: NspSemanticQualificationErrorCode,
    changed: NspSemanticQualificationErrorCode,
) -> Result<OpenedInput, NspSemanticQualificationError> {
    let canonical_path =
        std::fs::canonicalize(path).map_err(|_| NspSemanticQualificationError::new(unavailable))?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options
        .open(&canonical_path)
        .map_err(|_| NspSemanticQualificationError::new(unavailable))?;
    let metadata = file
        .metadata()
        .map_err(|_| NspSemanticQualificationError::new(unavailable))?;
    if !metadata.file_type().is_file() {
        return Err(NspSemanticQualificationError::new(unavailable));
    }
    let identity = crate::file_identity::handle_identity(&file).ok_or_else(|| {
        NspSemanticQualificationError::new(NspSemanticQualificationErrorCode::InternalIo)
    })?;
    if crate::file_identity::path_identity(&canonical_path) != Some(identity)
        || crate::file_identity::followed_path_identity(path) != Some(identity)
    {
        return Err(NspSemanticQualificationError::new(changed));
    }
    let size = metadata.len();
    let snapshot = crate::file_identity::file_snapshot(&metadata, Some(identity));
    Ok(OpenedInput {
        file,
        canonical_path,
        requested_path: path.to_path_buf(),
        identity,
        snapshot,
        size,
    })
}

fn check_cancelled(
    request: &NspSemanticQualificationRequest,
) -> Result<(), NspSemanticQualificationError> {
    if request
        .cancellation
        .as_ref()
        .is_some_and(crate::CancellationHandle::is_cancelled)
    {
        return Err(NspSemanticQualificationError::new(
            NspSemanticQualificationErrorCode::Cancelled,
        ));
    }
    Ok(())
}

fn validate_input_size(size: u64) -> Result<(), NspSemanticQualificationError> {
    if size > MAX_INPUT_BYTES {
        return Err(NspSemanticQualificationError::new(
            NspSemanticQualificationErrorCode::InputLimitExceeded,
        ));
    }
    Ok(())
}

fn try_reserve_vec<T>(
    capacity: usize,
    site: AllocationSite,
) -> Result<Vec<T>, NspSemanticQualificationError> {
    let mut values = Vec::new();
    reserve_exact(&mut values, capacity, site).map_err(|_| {
        NspSemanticQualificationError::new(NspSemanticQualificationErrorCode::AllocationFailed)
    })?;
    Ok(values)
}

fn allocate_zeroizing_buffer(
    size: usize,
    site: AllocationSite,
) -> Result<Zeroizing<Vec<u8>>, NspSemanticQualificationError> {
    let mut buffer = Zeroizing::new(try_reserve_vec(size, site)?);
    buffer.resize(size, 0);
    Ok(buffer)
}

fn map_key_file_error(error: NspKeyFileError) -> NspSemanticQualificationError {
    use NspKeyFileError as KeyError;
    let code = match error {
        KeyError::Unavailable => NspSemanticQualificationErrorCode::KeyFileUnavailable,
        KeyError::LimitExceeded => NspSemanticQualificationErrorCode::KeyFileLimitExceeded,
        KeyError::AllocationFailed => NspSemanticQualificationErrorCode::AllocationFailed,
        KeyError::Malformed => NspSemanticQualificationErrorCode::KeyFileMalformed,
        KeyError::MissingHeaderKey => NspSemanticQualificationErrorCode::MissingHeaderKey,
        KeyError::MissingApplicationKeyAreaKey => {
            NspSemanticQualificationErrorCode::MissingApplicationKeyAreaKey
        }
    };
    NspSemanticQualificationError::new(code)
}

/// Checks the qualification profile's stricter PFS0 payload accounting.
///
/// The general PFS0 probe permits gaps for unrelated callers. This profile
/// requires every payload byte to belong to exactly one nonempty entry, while
/// allowing entry-table records in any order.
fn pfs0_payload_is_fully_accounted(
    probe: &ContainerProbeResult,
) -> Result<bool, NspSemanticQualificationError> {
    if probe.entries.is_empty() || probe.payload_size == 0 {
        return Ok(false);
    }

    let mut spans = try_reserve_vec(probe.entries.len(), AllocationSite::NspSpans)?;
    for entry in &probe.entries {
        if entry.size == 0 {
            return Ok(false);
        }
        let Some(end) = entry.offset.checked_add(entry.size) else {
            return Ok(false);
        };
        if end > probe.payload_size {
            return Ok(false);
        }
        spans.push((entry.offset, end));
    }

    spans.sort_unstable_by_key(|(start, _)| *start);
    let mut next_offset = 0_u64;
    for (start, end) in spans {
        if start != next_offset {
            return Ok(false);
        }
        next_offset = end;
    }
    Ok(next_offset == probe.payload_size)
}

fn hash_source<F>(
    input: &mut OpenedInput,
    members: Option<&[ContainerProbeEntry]>,
    request: &NspSemanticQualificationRequest,
    checkpoint: &mut F,
) -> Result<SourceDigests, NspSemanticQualificationError>
where
    F: FnMut(Checkpoint),
{
    input.file.seek(SeekFrom::Start(0)).map_err(|_| {
        NspSemanticQualificationError::new(NspSemanticQualificationErrorCode::InputUnavailable)
    })?;
    let mut source = Sha256::new();
    let mut member_hashers = [Sha256::new(), Sha256::new()];
    let mut buffer = allocate_zeroizing_buffer(
        MAX_WORKING_BUFFER_BYTES,
        AllocationSite::NspSourceHashBuffer,
    )?;
    let mut offset = 0_u64;
    while offset < input.size {
        check_cancelled(request)?;
        let wanted =
            usize::try_from((input.size - offset).min(buffer.len() as u64)).map_err(|_| {
                NspSemanticQualificationError::new(NspSemanticQualificationErrorCode::InternalIo)
            })?;
        let read = input.file.read(&mut buffer[..wanted]).map_err(|_| {
            NspSemanticQualificationError::new(NspSemanticQualificationErrorCode::InputUnavailable)
        })?;
        if read == 0 {
            return Err(NspSemanticQualificationError::new(
                NspSemanticQualificationErrorCode::InputChangedDuringQualification,
            ));
        }
        source.update(&buffer[..read]);
        if let Some(members) = members {
            let chunk_end = offset.checked_add(read as u64).ok_or_else(|| {
                NspSemanticQualificationError::new(NspSemanticQualificationErrorCode::InternalIo)
            })?;
            for index in 0..2 {
                let member = &members[index];
                let member_end = member.file_offset.checked_add(member.size).ok_or_else(|| {
                    NspSemanticQualificationError::new(
                        NspSemanticQualificationErrorCode::InputChangedDuringQualification,
                    )
                })?;
                let overlap_start = offset.max(member.file_offset);
                let overlap_end = chunk_end.min(member_end);
                if overlap_start < overlap_end {
                    let start = usize::try_from(overlap_start - offset).map_err(|_| {
                        NspSemanticQualificationError::new(
                            NspSemanticQualificationErrorCode::InternalIo,
                        )
                    })?;
                    let end = usize::try_from(overlap_end - offset).map_err(|_| {
                        NspSemanticQualificationError::new(
                            NspSemanticQualificationErrorCode::InternalIo,
                        )
                    })?;
                    member_hashers[index].update(&buffer[start..end]);
                }
            }
        }
        offset = offset.checked_add(read as u64).ok_or_else(|| {
            NspSemanticQualificationError::new(NspSemanticQualificationErrorCode::InternalIo)
        })?;
        checkpoint(Checkpoint::SourceHashChunk);
        check_cancelled(request)?;
    }
    let source = Sha256Digest::from_bytes(source.finalize().into());
    let members = member_hashers.map(|hasher| Sha256Digest::from_bytes(hasher.finalize().into()));
    Ok(SourceDigests { source, members })
}

enum ReadDecision<T> {
    Supported(T),
    NotQualified(NspSemanticQualificationReason),
}

fn read_nca_member<R, F>(
    source: &mut R,
    source_size: u64,
    entry: &ContainerProbeEntry,
    member_sha256: Sha256Digest,
    keys: &NspQualificationKeys,
    request: &NspSemanticQualificationRequest,
    checkpoint: &mut F,
) -> Result<ReadDecision<NcaRecord>, NspSemanticQualificationError>
where
    R: Read + Seek,
    F: FnMut(Checkpoint),
{
    let mut member = BoundedReader::new(source, entry.file_offset, entry.size, source_size)
        .ok_or_else(|| {
            NspSemanticQualificationError::new(
                NspSemanticQualificationErrorCode::InputChangedDuringQualification,
            )
        })?;
    let block = match nca::read_header_block(&mut member, entry.size, keys.header_key.as_bytes()) {
        Ok(block) => block,
        Err(HeaderError::InputUnavailable) => {
            return Err(NspSemanticQualificationError::new(
                NspSemanticQualificationErrorCode::InputUnavailable,
            ));
        }
        Err(HeaderError::AllocationFailed) => {
            return Err(NspSemanticQualificationError::new(
                NspSemanticQualificationErrorCode::AllocationFailed,
            ));
        }
        Err(_) => {
            return Ok(ReadDecision::NotQualified(
                NspSemanticQualificationReason::InvalidNcaHeader,
            ));
        }
    };
    let header = match nca::parse_header_block(&block, entry.size) {
        Ok(header) => header,
        Err(HeaderError::InputUnavailable) => {
            return Err(NspSemanticQualificationError::new(
                NspSemanticQualificationErrorCode::InputUnavailable,
            ));
        }
        Err(HeaderError::AllocationFailed) => {
            return Err(NspSemanticQualificationError::new(
                NspSemanticQualificationErrorCode::AllocationFailed,
            ));
        }
        Err(_) => {
            return Ok(ReadDecision::NotQualified(
                NspSemanticQualificationReason::InvalidNcaHeader,
            ));
        }
    };
    let role = match header.content_type {
        ContentType::Meta => NspSemanticQualificationRole::Meta,
        ContentType::Program => NspSemanticQualificationRole::Program,
        _ => {
            return Ok(ReadDecision::NotQualified(
                NspSemanticQualificationReason::UnsupportedNcaProfile,
            ));
        }
    };
    if header.distribution != Distribution::Download
        || header.key_generation > 1
        || header.kaek_index != 0
        || block[0x230..0x240].iter().any(|byte| *byte != 0)
    {
        if block[0x230..0x240].iter().any(|byte| *byte != 0) {
            return Ok(ReadDecision::NotQualified(
                NspSemanticQualificationReason::RightsBearingContent,
            ));
        }
        return Ok(ReadDecision::NotQualified(
            NspSemanticQualificationReason::UnsupportedNcaProfile,
        ));
    }
    if header.partitions.len() != 1
        || header.partitions[0].index != 0
        || header.partitions[0].filesystem != 1
        || header.partitions[0].hash_type != 2
        || header.partitions[0].encryption != 3
        || header.partitions[0].extended
    {
        return Ok(ReadDecision::NotQualified(
            NspSemanticQualificationReason::UnsupportedNcaProfile,
        ));
    }
    if !crate::verification::fs_header_hash_matches(&block, 0) {
        return Ok(ReadDecision::NotQualified(
            NspSemanticQualificationReason::InvalidSectionStructure,
        ));
    }
    let partition = &header.partitions[0];
    let fs = &block[0x400..0x600];
    let regions = match parse_section_regions(fs, partition.size) {
        Some(regions) => regions,
        None => {
            return Ok(ReadDecision::NotQualified(
                NspSemanticQualificationReason::InvalidSectionStructure,
            ));
        }
    };
    let section_key = decrypt_section_key(&block[0x300..0x340], keys)?;
    let mut section_ctr = [0_u8; 8];
    section_ctr.copy_from_slice(&fs[0x140..0x148]);
    let mut section = CtrSectionReader::new(
        &mut member,
        partition.offset,
        partition.size,
        &section_key,
        section_ctr,
    );
    verify_section_hash_tree(&mut section, &regions, request, checkpoint)?;
    check_cancelled(request)?;

    let probe = {
        let mut pfs0 = BoundedReader::new(
            &mut section,
            regions.pfs0_offset,
            regions.pfs0_size,
            partition.size,
        )
        .ok_or_else(|| {
            NspSemanticQualificationError::new(NspSemanticQualificationErrorCode::InternalIo)
        })?;
        match crate::pfs0::probe_with_limits(
            &mut pfs0,
            regions.pfs0_size,
            MAX_PROGRAM_PFS0_ENTRIES,
            MAX_PFS0_METADATA_BYTES,
        ) {
            Ok(probe) => probe,
            Err(error) => match map_pfs0_error(error.code()) {
                Err(code) => return Err(NspSemanticQualificationError::new(code)),
                Ok(()) => {
                    return Ok(ReadDecision::NotQualified(
                        NspSemanticQualificationReason::InvalidSectionStructure,
                    ));
                }
            },
        }
    };
    if !pfs0_payload_is_fully_accounted(&probe)? {
        return Ok(ReadDecision::NotQualified(
            NspSemanticQualificationReason::UnaccountedPfs0Payload,
        ));
    }
    let cnmt = if role == NspSemanticQualificationRole::Meta {
        if probe.entries.len() != 1 || probe.entries[0].size != SUPPORTED_CNMT_BYTES as u64 {
            return Ok(ReadDecision::NotQualified(
                NspSemanticQualificationReason::UnsupportedCnmtProfile,
            ));
        }
        let entry = &probe.entries[0];
        let mut pfs0 = BoundedReader::new(
            &mut section,
            regions.pfs0_offset,
            regions.pfs0_size,
            partition.size,
        )
        .ok_or_else(|| {
            NspSemanticQualificationError::new(NspSemanticQualificationErrorCode::InternalIo)
        })?;
        let mut cnmt_reader =
            BoundedReader::new(&mut pfs0, entry.file_offset, entry.size, regions.pfs0_size)
                .ok_or_else(|| {
                    NspSemanticQualificationError::new(
                        NspSemanticQualificationErrorCode::InternalIo,
                    )
                })?;
        let mut bytes = Zeroizing::new([0_u8; SUPPORTED_CNMT_BYTES]);
        cnmt_reader.read_exact(&mut bytes[..]).map_err(|_| {
            NspSemanticQualificationError::new(NspSemanticQualificationErrorCode::InputUnavailable)
        })?;
        match parse_cnmt(&bytes) {
            Some(cnmt) => Some(cnmt),
            None => {
                return Ok(ReadDecision::NotQualified(
                    NspSemanticQualificationReason::UnsupportedCnmtProfile,
                ));
            }
        }
    } else {
        if probe.entries.len() > MAX_PROGRAM_PFS0_ENTRIES {
            return Err(NspSemanticQualificationError::new(
                NspSemanticQualificationErrorCode::Pfs0ResourceLimitExceeded,
            ));
        }
        None
    };
    Ok(ReadDecision::Supported(NcaRecord {
        role,
        title_id: header.program_id,
        member_size: entry.size,
        member_sha256,
        cnmt,
    }))
}

fn parse_section_regions(fs: &[u8], section_size: u64) -> Option<SectionRegions> {
    if fs.len() != 0x200
        || fs[0..2] != [2, 0]
        || fs[2] != 1
        || fs[3] != 2
        || fs[4] != 3
        || fs[5] != 0
        || fs[6..8].iter().any(|byte| *byte != 0)
        || fs[0x50..0x140].iter().any(|byte| *byte != 0)
        || fs[0x148..0x200].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    let master_hash: [u8; 32] = fs[0x08..0x28].try_into().ok()?;
    let block_size = u32::from_le_bytes(fs[0x28..0x2c].try_into().ok()?);
    let layer_count = u32::from_le_bytes(fs[0x2c..0x30].try_into().ok()?);
    if layer_count != 2
        || !(MIN_HASH_BLOCK_BYTES..=MAX_HASH_BLOCK_BYTES).contains(&block_size)
        || !block_size.is_power_of_two()
    {
        return None;
    }
    if fs[0x50..0x80].iter().any(|byte| *byte != 0) {
        return None;
    }
    let hash_table_offset = u64::from_le_bytes(fs[0x30..0x38].try_into().ok()?);
    let hash_table_size = u64::from_le_bytes(fs[0x38..0x40].try_into().ok()?);
    let pfs0_offset = u64::from_le_bytes(fs[0x40..0x48].try_into().ok()?);
    let pfs0_size = u64::from_le_bytes(fs[0x48..0x50].try_into().ok()?);
    let expected_hash_count = pfs0_size
        .checked_add(u64::from(block_size) - 1)?
        .checked_div(u64::from(block_size))?;
    let expected_hash_table_size = expected_hash_count.checked_mul(32)?;
    let hash_table_end = hash_table_offset.checked_add(hash_table_size)?;
    let pfs0_end = pfs0_offset.checked_add(pfs0_size)?;
    if pfs0_size < 16
        || hash_table_size != expected_hash_table_size
        || hash_table_size == 0
        || hash_table_end > section_size
        || pfs0_end > section_size
        || (hash_table_offset < pfs0_end && pfs0_offset < hash_table_end)
    {
        return None;
    }
    Some(SectionRegions {
        master_hash,
        hash_table_offset,
        hash_table_size,
        pfs0_offset,
        pfs0_size,
        block_size,
    })
}

fn decrypt_section_key(
    encrypted_key_area: &[u8],
    keys: &NspQualificationKeys,
) -> Result<Zeroizing<[u8; 16]>, NspSemanticQualificationError> {
    if encrypted_key_area.len() != 0x40 {
        return Err(NspSemanticQualificationError::new(
            NspSemanticQualificationErrorCode::InternalIo,
        ));
    }
    let cipher = Aes128::new(GenericArray::from_slice(keys.application_kaek.as_bytes()));
    let mut decrypted = Zeroizing::new([0_u8; 0x40]);
    decrypted.copy_from_slice(encrypted_key_area);
    for block in decrypted.chunks_mut(16) {
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
    }
    let mut section_key = Zeroizing::new([0_u8; 16]);
    section_key.copy_from_slice(&decrypted[0x20..0x30]);
    Ok(section_key)
}

fn verify_section_hash_tree<F>(
    section: &mut CtrSectionReader<'_, impl Read + Seek>,
    regions: &SectionRegions,
    request: &NspSemanticQualificationRequest,
    checkpoint: &mut F,
) -> Result<(), NspSemanticQualificationError>
where
    F: FnMut(Checkpoint),
{
    let mut buffer = allocate_zeroizing_buffer(
        MAX_WORKING_BUFFER_BYTES,
        AllocationSite::NspSectionHashBuffer,
    )?;
    let mut hasher = Sha256::new();
    section
        .seek(SeekFrom::Start(regions.hash_table_offset))
        .map_err(|_| {
            NspSemanticQualificationError::new(NspSemanticQualificationErrorCode::InputUnavailable)
        })?;
    let mut remaining = regions.hash_table_size;
    while remaining > 0 {
        check_cancelled(request)?;
        let count = usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| {
            NspSemanticQualificationError::new(NspSemanticQualificationErrorCode::InternalIo)
        })?;
        section.read_exact(&mut buffer[..count]).map_err(|_| {
            NspSemanticQualificationError::new(NspSemanticQualificationErrorCode::InputUnavailable)
        })?;
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
        checkpoint(Checkpoint::SourceHashChunk);
    }
    let actual_master_hash: [u8; 32] = hasher.finalize().into();
    if actual_master_hash != regions.master_hash {
        return Err(NspSemanticQualificationError::new(
            NspSemanticQualificationErrorCode::KeyOrSectionIntegrityFailure,
        ));
    }

    let block_size = u64::from(regions.block_size);
    let mut data_offset = 0_u64;
    let mut table_offset = regions.hash_table_offset;
    while data_offset < regions.pfs0_size {
        check_cancelled(request)?;
        let count =
            usize::try_from((regions.pfs0_size - data_offset).min(block_size)).map_err(|_| {
                NspSemanticQualificationError::new(NspSemanticQualificationErrorCode::InternalIo)
            })?;
        let mut expected = [0_u8; 32];
        section
            .seek(SeekFrom::Start(table_offset))
            .and_then(|_| section.read_exact(&mut expected))
            .map_err(|_| {
                NspSemanticQualificationError::new(
                    NspSemanticQualificationErrorCode::InputUnavailable,
                )
            })?;
        section
            .seek(SeekFrom::Start(
                regions
                    .pfs0_offset
                    .checked_add(data_offset)
                    .ok_or_else(|| {
                        NspSemanticQualificationError::new(
                            NspSemanticQualificationErrorCode::InternalIo,
                        )
                    })?,
            ))
            .and_then(|_| section.read_exact(&mut buffer[..count]))
            .map_err(|_| {
                NspSemanticQualificationError::new(
                    NspSemanticQualificationErrorCode::InputUnavailable,
                )
            })?;
        let actual: [u8; 32] = Sha256::digest(&buffer[..count]).into();
        if actual != expected {
            return Err(NspSemanticQualificationError::new(
                NspSemanticQualificationErrorCode::KeyOrSectionIntegrityFailure,
            ));
        }
        data_offset += count as u64;
        table_offset = table_offset.checked_add(32).ok_or_else(|| {
            NspSemanticQualificationError::new(NspSemanticQualificationErrorCode::InternalIo)
        })?;
    }
    Ok(())
}

fn parse_cnmt(bytes: &[u8; SUPPORTED_CNMT_BYTES]) -> Option<CnmtProgramRow> {
    if bytes[0x0c] != 0x80
        || bytes[0x0d] != 0
        || u16::from_le_bytes(bytes[0x0e..0x10].try_into().ok()?) != 0x10
        || u16::from_le_bytes(bytes[0x10..0x12].try_into().ok()?) != 1
        || u16::from_le_bytes(bytes[0x12..0x14].try_into().ok()?) != 0
        || bytes[0x14] != 0
        || bytes[0x15..0x18].iter().any(|byte| *byte != 0)
        || bytes[0x1c..0x20].iter().any(|byte| *byte != 0)
        || bytes[0x20..0x28].iter().any(|byte| *byte != 0)
        || bytes[0x65] != 0
    {
        return None;
    }
    let title_id = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
    let version = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
    let required_download_system_version = u32::from_le_bytes(bytes[0x18..0x1c].try_into().ok()?);
    let required_system_version = u32::from_le_bytes(bytes[0x28..0x2c].try_into().ok()?);
    let required_application_version = u32::from_le_bytes(bytes[0x2c..0x30].try_into().ok()?);
    let content_sha256 = bytes[0x30..0x50].try_into().ok()?;
    let content_id = bytes[0x50..0x60].try_into().ok()?;
    let content_size = u64::from(u32::from_le_bytes(bytes[0x60..0x64].try_into().ok()?))
        | (u64::from(bytes[0x64]) << 32);
    Some(CnmtProgramRow {
        title_id,
        version,
        required_download_system_version,
        required_system_version,
        required_application_version,
        content_sha256,
        content_id,
        content_size,
        content_type: bytes[0x66],
        id_offset: bytes[0x67],
    })
}

fn map_pfs0_error(
    code: crate::ContainerProbeErrorCode,
) -> Result<(), NspSemanticQualificationErrorCode> {
    match code {
        crate::ContainerProbeErrorCode::InputUnavailable => {
            Err(NspSemanticQualificationErrorCode::InputUnavailable)
        }
        crate::ContainerProbeErrorCode::ResourceLimitExceeded => {
            Err(NspSemanticQualificationErrorCode::AllocationFailed)
        }
        crate::ContainerProbeErrorCode::LimitExceeded => {
            Err(NspSemanticQualificationErrorCode::Pfs0ResourceLimitExceeded)
        }
        _ => Ok(()),
    }
}

struct BoundedReader<'a, R> {
    inner: &'a mut R,
    start: u64,
    length: u64,
    position: u64,
}

impl<'a, R: Read + Seek> BoundedReader<'a, R> {
    fn new(inner: &'a mut R, start: u64, length: u64, parent_length: u64) -> Option<Self> {
        let end = start.checked_add(length)?;
        if end > parent_length {
            return None;
        }
        Some(Self {
            inner,
            start,
            length,
            position: 0,
        })
    }
}

impl<R: Read + Seek> Read for BoundedReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || self.position >= self.length {
            return Ok(0);
        }
        let count = usize::try_from((self.length - self.position).min(buffer.len() as u64))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bounded read length"))?;
        let absolute = self
            .start
            .checked_add(self.position)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bounded read offset"))?;
        self.inner.seek(SeekFrom::Start(absolute))?;
        let read = self.inner.read(&mut buffer[..count])?;
        self.position = self
            .position
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bounded position"))?;
        Ok(read)
    }
}

impl<R: Read + Seek> Seek for BoundedReader<'_, R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = match position {
            SeekFrom::Start(value) => value,
            SeekFrom::End(value) => self
                .length
                .checked_add_signed(value)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bounded seek"))?,
            SeekFrom::Current(value) => self
                .position
                .checked_add_signed(value)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bounded seek"))?,
        };
        if next > self.length {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bounded seek"));
        }
        self.position = next;
        Ok(next)
    }
}

struct CtrSectionReader<'a, R> {
    inner: &'a mut R,
    section_start: u64,
    length: u64,
    position: u64,
    key: &'a [u8; 16],
    section_ctr: [u8; 8],
}

impl<'a, R: Read + Seek> CtrSectionReader<'a, R> {
    fn new(
        inner: &'a mut R,
        section_start: u64,
        length: u64,
        key: &'a [u8; 16],
        section_ctr: [u8; 8],
    ) -> Self {
        Self {
            inner,
            section_start,
            length,
            position: 0,
            key,
            section_ctr,
        }
    }

    fn counter_at(&self, relative_offset: u64) -> io::Result<([u8; 16], usize)> {
        let block_index = relative_offset / 16;
        let base = self
            .section_start
            .checked_div(16)
            .and_then(|value| value.checked_add(block_index))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "CTR offset"))?;
        let mut counter = [0_u8; 16];
        for (dst, src) in counter[..8].iter_mut().zip(self.section_ctr.iter().rev()) {
            *dst = *src;
        }
        counter[8..].copy_from_slice(&base.to_be_bytes());
        Ok((counter, usize::try_from(relative_offset % 16).unwrap_or(0)))
    }
}

impl<R: Read + Seek> Read for CtrSectionReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || self.position >= self.length {
            return Ok(0);
        }
        let count = usize::try_from((self.length - self.position).min(buffer.len() as u64))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "section read length"))?;
        let relative_offset = self.position;
        let absolute = self
            .section_start
            .checked_add(relative_offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "section read offset"))?;
        self.inner.seek(SeekFrom::Start(absolute))?;
        let read = self.inner.read(&mut buffer[..count])?;
        if read > 0 {
            let (counter, skip) = self.counter_at(relative_offset)?;
            let mut cipher = Ctr128BE::<Aes128>::new_from_slices(self.key, &counter)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "CTR key"))?;
            if skip > 0 {
                let mut skipped = Zeroizing::new([0_u8; 16]);
                cipher.apply_keystream(&mut skipped[..skip]);
            }
            cipher.apply_keystream(&mut buffer[..read]);
            self.position = self
                .position
                .checked_add(read as u64)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "section position"))?;
        }
        Ok(read)
    }
}

impl<R: Read + Seek> Seek for CtrSectionReader<'_, R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = match position {
            SeekFrom::Start(value) => value,
            SeekFrom::End(value) => self
                .length
                .checked_add_signed(value)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "section seek"))?,
            SeekFrom::Current(value) => self
                .position
                .checked_add_signed(value)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "section seek"))?,
        };
        if next > self.length {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "section seek"));
        }
        self.position = next;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BoundedReader, Checkpoint, CtrSectionReader, MAX_INPUT_BYTES,
        NspSemanticQualificationErrorCode, NspSemanticQualificationRequest, parse_section_regions,
        qualify_with_checkpoint, read_nca_member, try_reserve_vec, validate_input_size,
    };
    use crate::CancellationHandle;
    use crate::engine::ContainerProbeEntry;
    use crate::key_file::read_nsp_qualification_keys;
    use crate::sha256::Sha256Digest;
    use std::fs::OpenOptions;
    use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

    struct TempFile(PathBuf);

    impl TempFile {
        fn new(bytes: &[u8]) -> Self {
            let id = NEXT_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("nscb-nsp-unit-{}-{id}.bin", std::process::id()));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .expect("create unique test input");
            file.write_all(bytes).expect("write test input");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn assert_qualifier_reservation_refusal(
        site: crate::allocation::AllocationSite,
        occurrence: u32,
    ) {
        let fixture = crate::test_synthetic_nsp_qualification::valid();
        let input = TempFile::new(&fixture.package);
        let key_file = TempFile::new(&fixture.key_file);
        let input_before = fixture.package;
        let key_file_before = fixture.key_file;
        let request = NspSemanticQualificationRequest::new(input.path(), key_file.path());

        let (result, observation) = crate::test_allocator::with_refusal(site, occurrence, || {
            qualify_with_checkpoint(request, |_| {})
        });

        let error = result.expect_err("the selected bounded reservation was refused");
        assert_eq!(
            error.code(),
            NspSemanticQualificationErrorCode::AllocationFailed
        );
        assert_eq!(
            error.to_string(),
            "qualification could not reserve bounded memory"
        );
        assert!(
            !error
                .to_string()
                .contains(input.path().to_string_lossy().as_ref())
        );
        assert!(
            !error
                .to_string()
                .contains(key_file.path().to_string_lossy().as_ref())
        );
        assert!(
            observation.is_exact_refusal(site, occurrence),
            "{observation:?}"
        );
        assert_eq!(observation.site_calls, occurrence);
        assert!(observation.requested_layout.is_some_and(|(size, align)| {
            size <= super::MAX_WORKING_BUFFER_BYTES && align.is_power_of_two()
        }));
        assert_eq!(
            std::fs::read(input.path()).expect("read input after refusal"),
            input_before
        );
        assert_eq!(
            std::fs::read(key_file.path()).expect("read key file after refusal"),
            key_file_before
        );
        release_file_handle(&input);
        release_file_handle(&key_file);
    }

    fn release_file_handle(file: &TempFile) {
        let moved = file.path().with_extension("moved");
        std::fs::rename(file.path(), &moved).expect("qualification released the file handle");
        std::fs::rename(moved, file.path()).expect("restore the synthetic test input");
    }

    fn two_member_pfs0() -> Vec<u8> {
        let strings = b"a\0b\0";
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PFS0");
        bytes.extend_from_slice(&2_u32.to_le_bytes());
        bytes.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        for (offset, name_offset) in [(0_u64, 0_u32), (16, 2)] {
            bytes.extend_from_slice(&offset.to_le_bytes());
            bytes.extend_from_slice(&16_u64.to_le_bytes());
            bytes.extend_from_slice(&name_offset.to_le_bytes());
            bytes.extend_from_slice(&0_u32.to_le_bytes());
        }
        bytes.extend_from_slice(strings);
        bytes.extend_from_slice(&[0x5a; 32]);
        bytes
    }

    fn key_file() -> Vec<u8> {
        format!(
            "header_key = {}\nkey_area_key_application_00 = {}\n",
            "42".repeat(32),
            "24".repeat(16)
        )
        .into_bytes()
    }

    #[test]
    fn bounded_reader_checks_parent_ranges_and_limits_reads_and_seeks() {
        let mut source = Cursor::new(b"0123456789".to_vec());
        assert!(BoundedReader::new(&mut source, u64::MAX, 2, u64::MAX).is_none());
        assert!(BoundedReader::new(&mut source, 9, 2, 10).is_none());

        let mut reader = BoundedReader::new(&mut source, 2, 4, 10).expect("bounded span");
        let mut bytes = [0; 8];
        assert_eq!(reader.read(&mut bytes).expect("bounded read"), 4);
        assert_eq!(&bytes[..4], b"2345");
        assert_eq!(reader.read(&mut bytes).expect("bounded EOF"), 0);
        assert_eq!(reader.seek(SeekFrom::End(-1)).expect("seek from end"), 3);
        assert_eq!(reader.read(&mut bytes).expect("last byte"), 1);
        assert_eq!(bytes[0], b'5');
        assert_eq!(reader.seek(SeekFrom::Start(4)).expect("seek to end"), 4);
        assert!(reader.seek(SeekFrom::Start(5)).is_err());
        assert!(reader.seek(SeekFrom::Current(-5)).is_err());
    }

    #[test]
    fn bounded_reader_propagates_parent_io_errors() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private marker",
                ))
            }
        }
        impl Seek for FailingReader {
            fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
                Ok(0)
            }
        }

        let mut parent = FailingReader;
        let mut reader = BoundedReader::new(&mut parent, 0, 1, 1).expect("bounded span");
        assert_eq!(
            reader.read(&mut [0]).expect_err("parent failure").kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn nca_member_source_read_failure_is_sanitized_and_typed() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private-source-read-marker",
                ))
            }
        }
        impl Seek for FailingReader {
            fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
                Ok(0)
            }
        }

        let key_bytes = key_file();
        let keys =
            read_nsp_qualification_keys(&mut Cursor::new(&key_bytes), key_bytes.len() as u64)
                .expect("parse test-only keys");
        let request = NspSemanticQualificationRequest::new(
            "/private/source-path.nsp",
            "/private/key-path.txt",
        );
        let entry = ContainerProbeEntry {
            name: "member.nca".to_owned(),
            offset: 0,
            size: 0xc00,
            file_offset: 0,
        };
        let mut reader = FailingReader;
        let mut checkpoint = |_| {};
        let result = read_nca_member(
            &mut reader,
            0xc00,
            &entry,
            Sha256Digest::digest(b"synthetic member"),
            &keys,
            &request,
            &mut checkpoint,
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("injected source read error must remain an operational failure"),
        };

        assert_eq!(
            error.code(),
            NspSemanticQualificationErrorCode::InputUnavailable
        );
        assert_eq!(
            error.to_string(),
            "the qualification input could not be read"
        );
        assert!(!format!("{error:?}").contains("private-source-read-marker"));
        assert!(!format!("{error}").contains("/private/source-path.nsp"));
        assert!(!format!("{error}").contains("/private/key-path.txt"));
    }

    #[test]
    fn section_regions_accept_only_checked_nonoverlapping_ranges() {
        fn valid_header() -> [u8; 0x200] {
            let mut fs = [0; 0x200];
            fs[0..2].copy_from_slice(&[2, 0]);
            fs[2] = 1;
            fs[3] = 2;
            fs[4] = 3;
            fs[0x28..0x2c].copy_from_slice(&0x200_u32.to_le_bytes());
            fs[0x2c..0x30].copy_from_slice(&2_u32.to_le_bytes());
            fs[0x38..0x40].copy_from_slice(&32_u64.to_le_bytes());
            fs[0x40..0x48].copy_from_slice(&0x200_u64.to_le_bytes());
            fs[0x48..0x50].copy_from_slice(&0x200_u64.to_le_bytes());
            fs
        }

        let good = valid_header();
        let parsed = parse_section_regions(&good, 0x400).expect("supported regions");
        assert_eq!(parsed.hash_table_offset, 0);
        assert_eq!(parsed.hash_table_size, 32);
        assert_eq!(parsed.pfs0_offset, 0x200);
        assert_eq!(parsed.pfs0_size, 0x200);

        let mut overflow = good;
        overflow[0x30..0x38].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse_section_regions(&overflow, 0x400).is_none());

        let mut overlap = good;
        overlap[0x30..0x38].copy_from_slice(&0x200_u64.to_le_bytes());
        assert!(parse_section_regions(&overlap, 0x400).is_none());

        assert!(parse_section_regions(&good, 0x3ff).is_none());

        let mut wrong_table_size = good;
        wrong_table_size[0x38..0x40].copy_from_slice(&31_u64.to_le_bytes());
        assert!(parse_section_regions(&wrong_table_size, 0x400).is_none());
    }

    #[test]
    fn ctr_counter_uses_reversed_section_ctr_and_absolute_section_block() {
        let mut parent = Cursor::new(vec![0; 0x1000]);
        let key = [0x24; 16];
        let section_ctr = [1, 2, 3, 4, 5, 6, 7, 8];
        let reader = CtrSectionReader::new(&mut parent, 0xc00, 0x100, &key, section_ctr);
        let (counter, skipped) = reader.counter_at(31).expect("CTR counter");
        assert_eq!(counter[..8], [8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(counter[8..], 0xc1_u64.to_be_bytes());
        assert_eq!(skipped, 15);
    }

    #[test]
    fn input_size_limit_accepts_its_boundary_and_rejects_the_next_byte() {
        assert!(validate_input_size(MAX_INPUT_BYTES).is_ok());
        assert_eq!(
            validate_input_size(MAX_INPUT_BYTES + 1)
                .expect_err("one byte over the configured limit")
                .code(),
            NspSemanticQualificationErrorCode::InputLimitExceeded
        );
    }

    #[test]
    fn allocation_reservation_failure_maps_to_a_typed_error() {
        let site = crate::allocation::AllocationSite::NspRecords;
        let (error, observation) = crate::test_allocator::with_refusal(site, 1, || {
            try_reserve_vec::<u8>(usize::MAX, site)
        });
        let error = error.expect_err("a capacity larger than Rust's allocation limit must fail");
        assert_eq!(
            error.code(),
            NspSemanticQualificationErrorCode::AllocationFailed
        );
        assert_eq!(observation.site_calls, 1);
        assert_eq!(observation.refusal_count, 0);
        assert_eq!(observation.expected_layout, None);
        assert!(observation.armed_on_finish);
    }

    #[test]
    fn key_byte_reservation_refusal_is_typed_and_site_attributed() {
        let bytes = b"bounded key fixture";
        let site = crate::allocation::AllocationSite::KeyFileBytes;
        let (result, observation) = crate::test_allocator::with_refusal(site, 1, || {
            read_nsp_qualification_keys(&mut Cursor::new(bytes), bytes.len() as u64)
        });

        assert_eq!(
            result.err(),
            Some(crate::key_file::NspKeyFileError::AllocationFailed)
        );
        assert!(observation.is_exact_refusal(site, 1));
        assert_eq!(observation.site_calls, 1);
        assert!(
            observation
                .requested_layout
                .is_some_and(|(size, _)| size <= crate::key_file::MAX_KEY_FILE_BYTES as usize)
        );
    }

    #[test]
    fn actual_bounded_qualifier_reservations_refuse_with_sanitized_errors() {
        for (site, occurrence) in [
            (crate::allocation::AllocationSite::KeyFileBytes, 1),
            (crate::allocation::AllocationSite::Pfs0Metadata, 1),
            (crate::allocation::AllocationSite::Pfs0Entries, 1),
            (crate::allocation::AllocationSite::Pfs0Spans, 1),
            (crate::allocation::AllocationSite::Pfs0NameBytes, 1),
            (crate::allocation::AllocationSite::NspSourceHashBuffer, 1),
            (crate::allocation::AllocationSite::NspSpans, 1),
            (crate::allocation::AllocationSite::NspRecords, 1),
            (crate::allocation::AllocationSite::NspSectionHashBuffer, 1),
            (crate::allocation::AllocationSite::NspMembers, 1),
            (crate::allocation::AllocationSite::NcaHeaderSpans, 1),
            (crate::allocation::AllocationSite::NcaHeaderPartitions, 1),
        ] {
            assert_qualifier_reservation_refusal(site, occurrence);
        }
    }

    #[test]
    fn cancellation_after_the_final_source_hash_chunk_is_reported() {
        let cancellation = CancellationHandle::new();
        let input = TempFile::new(b"not a PFS0 container");
        let request = NspSemanticQualificationRequest::new(
            input.path(),
            "/key-file-is-not-opened-for-invalid-container",
        )
        .with_cancellation(cancellation.clone());
        let error = qualify_with_checkpoint(request, |checkpoint| {
            if matches!(checkpoint, Checkpoint::SourceHashChunk) {
                cancellation.cancel();
            }
        })
        .expect_err("cancellation at the last chunk must not become a result");
        assert_eq!(error.code(), NspSemanticQualificationErrorCode::Cancelled);
    }

    #[test]
    fn source_mutation_after_hashing_returns_changed_input_error() {
        let input = TempFile::new(&two_member_pfs0());
        let keys = TempFile::new(&key_file());
        let input_path = input.path().to_path_buf();
        let request = NspSemanticQualificationRequest::new(input.path(), keys.path());
        let mut changed = false;
        let error = qualify_with_checkpoint(request, |checkpoint| {
            if matches!(checkpoint, Checkpoint::SourceHashed) && !changed {
                changed = true;
                let mut writer = OpenOptions::new()
                    .write(true)
                    .open(&input_path)
                    .expect("open fixture for deterministic mutation");
                writer.seek(SeekFrom::Start(0)).expect("seek to first byte");
                writer.write_all(b"X").expect("change the package magic");
            }
        })
        .expect_err("a same-handle source mutation must be detected");
        assert!(changed);
        assert_eq!(
            error.code(),
            NspSemanticQualificationErrorCode::InputChangedDuringQualification
        );
    }
}
