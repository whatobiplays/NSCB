//! Native, read-only Verification for supported standalone NCA3 content.
//!
//! Verification is a separate Engine operation from Inspection. It reads the
//! caller's content, key source, and trust anchor without modifying them,
//! performs bounded structural and cryptographic checks in Rust, and reports a
//! stable result for every check the selected profile covers.
//!
//! The qualified input profile is an encrypted NCA3 Program content archive
//! whose partitions are clear PartitionFs filesystems with partition hash type
//! `None` and no extended metadata. The Full profile executes every applicable
//! structural, filesystem-header hash, fixed-key signature, NPDM metadata, and
//! embedded-key signature consistency check. The Structural profile executes
//! only the structural checks and explicitly reports that signatures and hashes
//! were not checked.
//!
//! A passing result has deliberate limits. Partition hash type `None` stores no
//! payload hash, so neither profile can prove the partition payload bytes are
//! unchanged. The NPDM and its ACID are not authenticated: the ACID signature
//! is not verified, and the RSA key stored in the ACID is used only to check
//! consistency with the header's second signature. A passing result is not a
//! statement of Nintendo authenticity and is not device-write authorization.

use crate::inspection::{CancellationHandle, InspectionErrorCode, SpanReader};
use crate::nca::{self, ContentType, Header, HeaderError};
use crate::partition_fs::{PartitionFsValidation, PartitionFsValidationError};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::pss::Pss;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const MAX_TRUST_ANCHOR_BYTES: u64 = 16 * 1024;
const MAX_NPDM_BYTES: u64 = 4 * 1024 * 1024;
const RSA_MODULUS_BYTES: usize = 256;
const RSA_EXPONENT: u32 = 65_537;
const RSA_SALT_BYTES: usize = 32;
const MIN_PARTITION_OFFSET: u64 = 0xc00;
const PARTITION_ALIGNMENT: u64 = 0x200;
const MAX_KEY_GENERATION: u8 = 0x20;

const META_HEADER_SIZE: usize = 0x80;
const ACI0_HEADER_SIZE: usize = 0x40;
const ACID_HEADER_SIZE: usize = 0x240;
const ACID_MODULUS_START: usize = 0x100;
const ACID_MODULUS_END: usize = 0x200;
const ACID_MAGIC_OFFSET: usize = 0x200;
const ACID_SIZE_OFFSET: usize = 0x204;
const ACID_SIGNATURE_BYTES: usize = 0x100;

/// Selected depth of Verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VerificationProfile {
    /// Structural checks plus filesystem-header hashes, both signature
    /// relationships, NPDM metadata, NPDM/ACID key-signature consistency, and
    /// payload integrity. See the module documentation for the complete check
    /// list.
    Full,
    /// Structural checks only. No signature or hash check is implied.
    Structural,
}

impl VerificationProfile {
    /// Returns the stable machine-readable spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Structural => "structural",
        }
    }
}

/// Aggregate outcome of one completed Verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VerificationOutcome {
    /// Every applicable check completed and passed.
    Passed,
    /// At least one applicable check failed or could not run.
    Failed,
}

/// Whether the selected profile requires a check for this input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CheckApplicability {
    /// The selected profile requires the check.
    Required,
    /// The check does not apply to this input or profile.
    NotApplicable,
}

/// Whether the check body actually executed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CheckExecution {
    /// The check ran to completion.
    Completed,
    /// The check did not run, so it cannot contribute to success.
    NotRun,
}

/// Result of one check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CheckOutcome {
    /// The executed check passed.
    Passed,
    /// The executed check failed, or a required check could not run.
    Failed,
    /// The check does not apply, so no verdict was produced.
    NotApplicable,
}

/// Stable identifier for one Verification check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum VerificationCheckId {
    /// Decrypted NCA3 header fields are inside the qualified Program profile.
    #[serde(rename = "nca3.header_profile")]
    HeaderProfile,
    /// Partition descriptors are ordered, inside the file, and non-overlapping.
    #[serde(rename = "nca3.partition_layout")]
    PartitionLayout,
    /// One partition declares a supported clear PartitionFs filesystem.
    #[serde(rename = "nca3.partition_filesystem")]
    PartitionFilesystem,
    /// One partition's PFS0 entry table and names are structurally valid.
    #[serde(rename = "nca3.partition_entries")]
    PartitionEntries,
    /// One filesystem-header SHA-256 matches its stored hash.
    #[serde(rename = "nca3.fs_header_hash")]
    FsHeaderHash,
    /// The header's fixed-key RSA-PSS signature verifies with the caller's key.
    #[serde(rename = "nca3.fixed_key_signature")]
    FixedKeySignature,
    /// The Program partition contains a bounded canonical `main.npdm`.
    #[serde(rename = "nca3.npdm_metadata")]
    NpdmMetadata,
    /// The header's second signature verifies with the NPDM ACID modulus.
    #[serde(rename = "nca3.npdm_key_signature_consistency")]
    NpdmKeySignatureConsistency,
    /// Partition payload bytes are protected by a supported hash layer.
    #[serde(rename = "nca3.payload_integrity")]
    PayloadIntegrity,
}

impl VerificationCheckId {
    /// Returns the stable machine-readable spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HeaderProfile => "nca3.header_profile",
            Self::PartitionLayout => "nca3.partition_layout",
            Self::PartitionFilesystem => "nca3.partition_filesystem",
            Self::PartitionEntries => "nca3.partition_entries",
            Self::FsHeaderHash => "nca3.fs_header_hash",
            Self::FixedKeySignature => "nca3.fixed_key_signature",
            Self::NpdmMetadata => "nca3.npdm_metadata",
            Self::NpdmKeySignatureConsistency => "nca3.npdm_key_signature_consistency",
            Self::PayloadIntegrity => "nca3.payload_integrity",
        }
    }
}

/// Stable explanation attached to a non-passing check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VerificationReason {
    /// The header is outside the qualified Program profile.
    UnsupportedProfile,
    /// Partition descriptors disagree about ordering, bounds, or overlap.
    PartitionLayoutInvalid,
    /// A partition declares an unsupported filesystem, hash, or encryption profile.
    PartitionFilesystemUnsupported,
    /// A partition's PFS0 table or names are structurally invalid.
    PartitionEntriesInvalid,
    /// A filesystem header hash does not match the stored SHA-256.
    FsHeaderHashMismatch,
    /// An executed RSA-PSS signature verification did not match.
    SignatureMismatch,
    /// The trust anchor cannot verify the input's signature generation.
    TrustAnchorGenerationMismatch,
    /// The Program partition has no top-level `main.npdm`.
    NpdmMissing,
    /// The Program partition has more than one top-level `main.npdm`.
    NpdmDuplicate,
    /// The NPDM metadata, ACID, or ACI0 ranges are invalid.
    NpdmMalformed,
    /// The header's second signature does not match the embedded ACID modulus.
    NpdmKeySignatureMismatch,
    /// A required check could not run because an earlier required check failed.
    PrerequisiteCheckFailed,
    /// Partition hash type `None` stores no payload integrity information.
    HashTypeNone,
    /// A partition declares a hash type this profile cannot verify.
    HashTypeUnsupported,
}

impl VerificationReason {
    /// Returns the stable machine-readable spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedProfile => "unsupported_profile",
            Self::PartitionLayoutInvalid => "partition_layout_invalid",
            Self::PartitionFilesystemUnsupported => "partition_filesystem_unsupported",
            Self::PartitionEntriesInvalid => "partition_entries_invalid",
            Self::FsHeaderHashMismatch => "fs_header_hash_mismatch",
            Self::SignatureMismatch => "signature_mismatch",
            Self::TrustAnchorGenerationMismatch => "trust_anchor_generation_mismatch",
            Self::NpdmMissing => "npdm_missing",
            Self::NpdmDuplicate => "npdm_duplicate",
            Self::NpdmMalformed => "npdm_malformed",
            Self::NpdmKeySignatureMismatch => "npdm_key_signature_mismatch",
            Self::PrerequisiteCheckFailed => "prerequisite_check_failed",
            Self::HashTypeNone => "hash_type_none",
            Self::HashTypeUnsupported => "hash_type_unsupported",
        }
    }
}

/// Stable statement of what a completed Verification did not establish.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VerificationLimitation {
    /// The selected profile did not execute signature checks.
    SignaturesNotChecked,
    /// The selected profile did not execute filesystem-header hash checks.
    HashChecksNotRun,
    /// Partition payload bytes have no supported integrity protection.
    PayloadIntegrityNotAvailable,
    /// The NPDM and its ACID are not authenticated by this operation.
    NpdmAcidAuthenticityUnverified,
    /// A passing result does not establish Nintendo content authenticity.
    AuthenticityNotEstablished,
    /// A passing result does not authorize writing content to a device.
    DeviceWriteAuthorizationNotEvaluated,
}

/// Where a verification key came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TrustProvenanceKind {
    /// A public key supplied by the caller for one anchor generation.
    CallerSuppliedPublicKey,
    /// The RSA modulus stored in the input's NPDM ACID.
    EmbeddedNpdmAcidKey,
}

/// Accepted encodings for a caller-supplied RSA public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PublicKeyEncoding {
    /// PKCS#1 `RSAPublicKey` in PEM armor.
    Pkcs1Pem,
    /// SubjectPublicKeyInfo in PEM armor.
    SpkiPem,
    /// PKCS#1 `RSAPublicKey` in DER.
    Pkcs1Der,
    /// SubjectPublicKeyInfo in DER.
    SpkiDer,
}

/// Evidence about the key used by one signature check.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TrustProvenance {
    /// Source of the key material.
    pub kind: TrustProvenanceKind,
    /// Encoding, when the caller supplied the key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<PublicKeyEncoding>,
    /// Generation the caller associated with the key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_generation: Option<u8>,
}

/// Evidence for one check of a completed Verification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerificationCheck {
    /// Stable check identifier.
    pub id: VerificationCheckId,
    /// Whether the selected profile requires this check.
    pub applicability: CheckApplicability,
    /// Whether the check body executed.
    pub execution: CheckExecution,
    /// Check verdict.
    pub outcome: CheckOutcome,
    /// Stable explanation for a non-passing check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<VerificationReason>,
    /// Header partition index for a per-partition check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<u8>,
    /// Key provenance for a signature check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_provenance: Option<TrustProvenance>,
}

/// Completed, stable Verification evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerificationResult {
    /// Selected profile.
    pub profile: VerificationProfile,
    /// Aggregate outcome.
    pub outcome: VerificationOutcome,
    /// Per-check evidence in stable order.
    pub checks: Vec<VerificationCheck>,
    /// Statements of what the result does not establish.
    pub limitations: Vec<VerificationLimitation>,
}

/// Stable, sanitized Verification failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VerificationErrorCode {
    /// The host supplied no usable key-source path.
    InvalidKeyPath,
    /// Content input could not be opened or read.
    InputUnavailable,
    /// Input is not a supported plaintext or key-decryptable NCA3 file.
    UnsupportedFormat,
    /// Input ends before its declared structure.
    TruncatedInput,
    /// Declared structural metadata is internally inconsistent.
    MalformedInput,
    /// Input exceeds an explicit Verification limit.
    InputLimitExceeded,
    /// Key source could not be read.
    KeyFileUnavailable,
    /// Key source does not contain an accepted header-key entry.
    KeyFileMalformed,
    /// Key source exceeds its explicit size limit.
    KeyFileLimitExceeded,
    /// No accepted NCA header-key alias is present.
    MissingHeaderKey,
    /// The Full profile requires a caller-supplied trust anchor.
    MissingTrustAnchor,
    /// The Full profile requires an anchor generation for the trust anchor.
    MissingAnchorGeneration,
    /// Trust anchor path could not be read.
    TrustAnchorUnavailable,
    /// Trust anchor bytes are not an accepted RSA public key.
    TrustAnchorMalformed,
    /// Trust anchor exceeds its explicit size limit.
    TrustAnchorLimitExceeded,
    /// A trust anchor was supplied for a profile that does not use one.
    AnchorNotApplicable,
    /// Content input changed while Verification was reading it.
    InputChangedDuringVerification,
    /// Key source changed while Verification was reading it.
    KeyFileChangedDuringVerification,
    /// Trust anchor changed while Verification was reading it.
    TrustAnchorChangedDuringVerification,
    /// Cancellation was observed before the operation completed.
    Cancelled,
    /// A bounded allocation could not be reserved.
    AllocationFailed,
    /// An internal filesystem or synchronization operation failed.
    InternalIo,
    /// The command-line cancellation handler could not be installed.
    SignalHandlerFailed,
}

impl VerificationErrorCode {
    /// Returns the stable machine-readable spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidKeyPath => "invalid_key_path",
            Self::InputUnavailable => "input_unavailable",
            Self::UnsupportedFormat => "unsupported_format",
            Self::TruncatedInput => "truncated_input",
            Self::MalformedInput => "malformed_input",
            Self::InputLimitExceeded => "input_limit_exceeded",
            Self::KeyFileUnavailable => "key_file_unavailable",
            Self::KeyFileMalformed => "key_file_malformed",
            Self::KeyFileLimitExceeded => "key_file_limit_exceeded",
            Self::MissingHeaderKey => "missing_header_key",
            Self::MissingTrustAnchor => "missing_trust_anchor",
            Self::MissingAnchorGeneration => "missing_anchor_generation",
            Self::TrustAnchorUnavailable => "trust_anchor_unavailable",
            Self::TrustAnchorMalformed => "trust_anchor_malformed",
            Self::TrustAnchorLimitExceeded => "trust_anchor_limit_exceeded",
            Self::AnchorNotApplicable => "anchor_not_applicable",
            Self::InputChangedDuringVerification => "input_changed_during_verification",
            Self::KeyFileChangedDuringVerification => "key_file_changed_during_verification",
            Self::TrustAnchorChangedDuringVerification => {
                "trust_anchor_changed_during_verification"
            }
            Self::Cancelled => "cancelled",
            Self::AllocationFailed => "allocation_failed",
            Self::InternalIo => "internal_io",
            Self::SignalHandlerFailed => "signal_handler_failed",
        }
    }

    /// Returns the frozen process exit class from ADR 0023.
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::InvalidKeyPath | Self::AnchorNotApplicable => 2,
            Self::InputUnavailable
            | Self::UnsupportedFormat
            | Self::TruncatedInput
            | Self::MalformedInput
            | Self::InputLimitExceeded
            | Self::KeyFileUnavailable
            | Self::KeyFileMalformed
            | Self::KeyFileLimitExceeded
            | Self::MissingHeaderKey
            | Self::MissingTrustAnchor
            | Self::MissingAnchorGeneration
            | Self::TrustAnchorUnavailable
            | Self::TrustAnchorMalformed
            | Self::TrustAnchorLimitExceeded => 3,
            Self::InputChangedDuringVerification
            | Self::KeyFileChangedDuringVerification
            | Self::TrustAnchorChangedDuringVerification => 4,
            Self::Cancelled => 6,
            Self::AllocationFailed | Self::InternalIo | Self::SignalHandlerFailed => 7,
        }
    }
}

/// A sanitized Verification failure without paths, key bytes, or input bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationError {
    code: VerificationErrorCode,
}

impl VerificationError {
    pub(crate) const fn new(code: VerificationErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    pub const fn code(self) -> VerificationErrorCode {
        self.code
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.code {
            VerificationErrorCode::InvalidKeyPath => "the key source path is invalid",
            VerificationErrorCode::InputUnavailable => "the content input could not be read",
            VerificationErrorCode::UnsupportedFormat => {
                "the content input is not a supported encrypted NCA3 file"
            }
            VerificationErrorCode::TruncatedInput => "the content input is incomplete",
            VerificationErrorCode::MalformedInput => {
                "the content input has inconsistent structural metadata"
            }
            VerificationErrorCode::InputLimitExceeded => {
                "the content input exceeds a supported verification limit"
            }
            VerificationErrorCode::KeyFileUnavailable => "the key source could not be read",
            VerificationErrorCode::KeyFileMalformed => {
                "the key source does not contain a valid NCA header key entry"
            }
            VerificationErrorCode::KeyFileLimitExceeded => {
                "the key source exceeds the supported size limit"
            }
            VerificationErrorCode::MissingHeaderKey => {
                "the key source does not contain a header_key or nca_header_key entry"
            }
            VerificationErrorCode::MissingTrustAnchor => "the full profile requires a trust anchor",
            VerificationErrorCode::MissingAnchorGeneration => {
                "the full profile requires an anchor generation"
            }
            VerificationErrorCode::TrustAnchorUnavailable => "the trust anchor could not be read",
            VerificationErrorCode::TrustAnchorMalformed => {
                "the trust anchor is not a supported RSA public key"
            }
            VerificationErrorCode::TrustAnchorLimitExceeded => {
                "the trust anchor exceeds the supported size limit"
            }
            VerificationErrorCode::AnchorNotApplicable => {
                "the selected profile does not use a trust anchor"
            }
            VerificationErrorCode::InputChangedDuringVerification => {
                "the content input changed during verification"
            }
            VerificationErrorCode::KeyFileChangedDuringVerification => {
                "the key source changed during verification"
            }
            VerificationErrorCode::TrustAnchorChangedDuringVerification => {
                "the trust anchor changed during verification"
            }
            VerificationErrorCode::Cancelled => "the verification was cancelled",
            VerificationErrorCode::AllocationFailed => "a bounded memory allocation failed",
            VerificationErrorCode::InternalIo => "an internal filesystem operation failed",
            VerificationErrorCode::SignalHandlerFailed => {
                "the command-line cancellation handler could not be installed"
            }
        })
    }
}

impl std::error::Error for VerificationError {}

/// A read-only Verification request for one supported standalone NCA3 file.
#[derive(Clone, Debug)]
pub struct VerificationRequest {
    input: PathBuf,
    key_file: PathBuf,
    profile: VerificationProfile,
    trust_anchor: Option<PathBuf>,
    anchor_generation: Option<u8>,
    cancellation: Option<CancellationHandle>,
}

impl VerificationRequest {
    /// Creates a Structural request for `input` using `key_file`.
    ///
    /// Structural verification never checks a signature, so it has no trust
    /// anchor prerequisite and never implies authenticity.
    pub fn structural_nca(input: impl Into<PathBuf>, key_file: impl Into<PathBuf>) -> Self {
        Self {
            input: input.into(),
            key_file: key_file.into(),
            profile: VerificationProfile::Structural,
            trust_anchor: None,
            anchor_generation: None,
            cancellation: None,
        }
    }

    /// Creates a Full request for `input` using `key_file` and one RSA public
    /// key valid for `anchor_generation`.
    ///
    /// The generation must equal the input's signature-key-generation byte
    /// (`0x221`). A mismatched generation is a prerequisite failure, not a
    /// cryptographic signature failure.
    pub fn full_nca(
        input: impl Into<PathBuf>,
        key_file: impl Into<PathBuf>,
        trust_anchor: impl Into<PathBuf>,
        anchor_generation: u8,
    ) -> Self {
        Self {
            input: input.into(),
            key_file: key_file.into(),
            profile: VerificationProfile::Full,
            trust_anchor: Some(trust_anchor.into()),
            anchor_generation: Some(anchor_generation),
            cancellation: None,
        }
    }

    /// Shares a cancellation signal with the operation.
    pub fn with_cancellation(mut self, cancellation: CancellationHandle) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    /// Returns the selected profile.
    pub const fn profile(&self) -> VerificationProfile {
        self.profile
    }

    /// Returns the content input path.
    pub fn input(&self) -> &Path {
        &self.input
    }

    /// Returns the key source path.
    pub fn key_file(&self) -> &Path {
        &self.key_file
    }
}

struct TrustAnchor {
    key: RsaPublicKey,
    encoding: PublicKeyEncoding,
    generation: u8,
    opened: OpenedFile,
}

struct OpenedFile {
    file: File,
    /// Canonical target path whose final directory entry must stay unchanged.
    path: PathBuf,
    /// Caller-supplied path whose resolution must still reach the opened file.
    requested_path: PathBuf,
    size: u64,
    identity: crate::file_identity::FileIdentity,
    snapshot: crate::file_identity::FileSnapshot,
}

fn cancelled(request: &VerificationRequest) -> bool {
    request
        .cancellation
        .as_ref()
        .is_some_and(CancellationHandle::is_cancelled)
}

fn check_cancelled(request: &VerificationRequest) -> Result<(), VerificationError> {
    if cancelled(request) {
        return Err(VerificationError::new(VerificationErrorCode::Cancelled));
    }
    Ok(())
}

fn map_header_error(error: HeaderError) -> VerificationErrorCode {
    match error {
        HeaderError::UnsupportedFormat => VerificationErrorCode::UnsupportedFormat,
        HeaderError::TruncatedInput => VerificationErrorCode::TruncatedInput,
        HeaderError::MalformedInput => VerificationErrorCode::MalformedInput,
        HeaderError::InputUnavailable => VerificationErrorCode::InputUnavailable,
    }
}

fn map_key_error(error: InspectionErrorCode) -> VerificationErrorCode {
    match error {
        InspectionErrorCode::KeyFileUnavailable => VerificationErrorCode::KeyFileUnavailable,
        InspectionErrorCode::KeyFileMalformed => VerificationErrorCode::KeyFileMalformed,
        InspectionErrorCode::KeyFileLimitExceeded => VerificationErrorCode::KeyFileLimitExceeded,
        InspectionErrorCode::MissingHeaderKey => VerificationErrorCode::MissingHeaderKey,
        InspectionErrorCode::AllocationFailed => VerificationErrorCode::AllocationFailed,
        _ => VerificationErrorCode::InternalIo,
    }
}

fn opened(
    path: &Path,
    unavailable: VerificationErrorCode,
    changed: VerificationErrorCode,
) -> Result<OpenedFile, VerificationError> {
    let canonical = std::fs::canonicalize(path).map_err(|_| VerificationError::new(unavailable))?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NONBLOCK);
    let file = options
        .open(&canonical)
        .map_err(|_| VerificationError::new(unavailable))?;
    let metadata = file
        .metadata()
        .map_err(|_| VerificationError::new(unavailable))?;
    if !metadata.file_type().is_file() {
        return Err(VerificationError::new(unavailable));
    }
    let identity = crate::file_identity::handle_identity(&file)
        .ok_or_else(|| VerificationError::new(VerificationErrorCode::InternalIo))?;
    if crate::file_identity::path_identity(&canonical) != Some(identity) {
        return Err(VerificationError::new(changed));
    }
    let snapshot = crate::file_identity::file_snapshot(&metadata, Some(identity));
    Ok(OpenedFile {
        file,
        path: canonical,
        requested_path: path.to_path_buf(),
        size: metadata.len(),
        identity,
        snapshot,
    })
}

fn completed(
    id: VerificationCheckId,
    outcome: CheckOutcome,
    reason: Option<VerificationReason>,
    partition: Option<u8>,
) -> VerificationCheck {
    VerificationCheck {
        id,
        applicability: if outcome == CheckOutcome::NotApplicable {
            CheckApplicability::NotApplicable
        } else {
            CheckApplicability::Required
        },
        execution: if outcome == CheckOutcome::NotApplicable {
            CheckExecution::NotRun
        } else {
            CheckExecution::Completed
        },
        outcome,
        reason,
        partition,
        trust_provenance: None,
    }
}

fn not_run(
    id: VerificationCheckId,
    reason: VerificationReason,
    partition: Option<u8>,
) -> VerificationCheck {
    VerificationCheck {
        id,
        applicability: CheckApplicability::Required,
        execution: CheckExecution::NotRun,
        outcome: CheckOutcome::Failed,
        reason: Some(reason),
        partition,
        trust_provenance: None,
    }
}

/// Confirms that an opened source still has the same handle identity, canonical
/// target, caller-path resolution, and metadata snapshot after verification.
fn revalidate(opened: &OpenedFile, code: VerificationErrorCode) -> Result<(), VerificationError> {
    let metadata = opened
        .file
        .metadata()
        .map_err(|_| VerificationError::new(VerificationErrorCode::InternalIo))?;
    let current = crate::file_identity::file_snapshot(
        &metadata,
        crate::file_identity::handle_identity(&opened.file),
    );
    if crate::file_identity::handle_identity(&opened.file) != Some(opened.identity)
        || crate::file_identity::path_identity(&opened.path) != Some(opened.identity)
        || crate::file_identity::followed_path_identity(&opened.requested_path)
            != Some(opened.identity)
        || current != opened.snapshot
    {
        return Err(VerificationError::new(code));
    }
    Ok(())
}

/// Runs one Verification and returns stable per-check evidence or one sanitized
/// failure that prevented a result from being produced.
pub(crate) fn verify(
    request: VerificationRequest,
) -> Result<VerificationResult, VerificationError> {
    verify_inner(request, || {})
}

#[cfg(test)]
fn verify_with_checkpoint<F: FnOnce()>(
    request: VerificationRequest,
    checkpoint: F,
) -> Result<VerificationResult, VerificationError> {
    verify_inner(request, checkpoint)
}

fn verify_inner<F: FnOnce()>(
    request: VerificationRequest,
    checkpoint: F,
) -> Result<VerificationResult, VerificationError> {
    check_cancelled(&request)?;

    if request.profile == VerificationProfile::Structural
        && (request.trust_anchor.is_some() || request.anchor_generation.is_some())
    {
        return Err(VerificationError::new(
            VerificationErrorCode::AnchorNotApplicable,
        ));
    }
    let anchor_requirement = match request.profile {
        VerificationProfile::Structural => None,
        VerificationProfile::Full => {
            let path = request
                .trust_anchor
                .clone()
                .ok_or_else(|| VerificationError::new(VerificationErrorCode::MissingTrustAnchor))?;
            let generation = request.anchor_generation.ok_or_else(|| {
                VerificationError::new(VerificationErrorCode::MissingAnchorGeneration)
            })?;
            Some((path, generation))
        }
    };

    let mut input = opened(
        &request.input,
        VerificationErrorCode::InputUnavailable,
        VerificationErrorCode::InputChangedDuringVerification,
    )?;
    let mut key_file = opened(
        &request.key_file,
        VerificationErrorCode::KeyFileUnavailable,
        VerificationErrorCode::KeyFileChangedDuringVerification,
    )?;
    let header_key = crate::provider::keys::read_header_key(&mut key_file.file, key_file.size)
        .map_err(|error| VerificationError::new(map_key_error(error)))?;
    let mut anchor = match anchor_requirement {
        Some((path, generation)) => Some(read_trust_anchor(&path, generation)?),
        None => None,
    };
    checkpoint();
    check_cancelled(&request)?;

    let block = nca::read_header_block(&mut input.file, input.size, header_key.as_bytes())
        .map_err(|error| VerificationError::new(map_header_error(error)))?;
    let syntax = nca::parse_header_syntax(&block, input.size)
        .map_err(|error| VerificationError::new(map_header_error(error)))?;
    let indices = syntax.present_partition_indices();
    let mut checks = Vec::new();

    let profile_supported =
        syntax.content_type == ContentType::Program && syntax.key_generation <= MAX_KEY_GENERATION;
    checks.push(completed(
        VerificationCheckId::HeaderProfile,
        if profile_supported {
            CheckOutcome::Passed
        } else {
            CheckOutcome::Failed
        },
        (!profile_supported).then_some(VerificationReason::UnsupportedProfile),
        None,
    ));

    if !profile_supported {
        push_not_run_structural(&mut checks, &indices, true);
        if request.profile == VerificationProfile::Full {
            push_not_run_full(&mut checks, &indices);
        }
    } else {
        match nca::complete_header(syntax, input.size) {
            Ok(header) => {
                checks.push(completed(
                    VerificationCheckId::PartitionLayout,
                    CheckOutcome::Passed,
                    None,
                    None,
                ));
                check_cancelled(&request)?;
                let probes = evaluate_partitions(&mut input.file, &header, &mut checks)?;
                check_cancelled(&request)?;
                if request.profile == VerificationProfile::Full {
                    evaluate_full(
                        &mut input.file,
                        &block,
                        &header,
                        &probes,
                        anchor.as_ref(),
                        &mut checks,
                    )?;
                }
            }
            Err(_) => {
                checks.push(completed(
                    VerificationCheckId::PartitionLayout,
                    CheckOutcome::Failed,
                    Some(VerificationReason::PartitionLayoutInvalid),
                    None,
                ));
                push_not_run_structural(&mut checks, &indices, false);
                if request.profile == VerificationProfile::Full {
                    push_not_run_full(&mut checks, &indices);
                }
            }
        }
    }

    check_cancelled(&request)?;
    revalidate(
        &input,
        VerificationErrorCode::InputChangedDuringVerification,
    )?;
    revalidate(
        &key_file,
        VerificationErrorCode::KeyFileChangedDuringVerification,
    )?;
    if let Some(anchor) = anchor.as_mut() {
        revalidate(
            &anchor.opened,
            VerificationErrorCode::TrustAnchorChangedDuringVerification,
        )?;
    }

    let outcome = if checks.iter().all(|check| {
        matches!(
            check.outcome,
            CheckOutcome::Passed | CheckOutcome::NotApplicable
        )
    }) {
        VerificationOutcome::Passed
    } else {
        VerificationOutcome::Failed
    };
    let limitations = limitations(request.profile, &checks);
    Ok(VerificationResult {
        profile: request.profile,
        outcome,
        checks,
        limitations,
    })
}

fn push_not_run_structural(
    checks: &mut Vec<VerificationCheck>,
    indices: &[u8],
    include_layout: bool,
) {
    if include_layout {
        checks.push(not_run(
            VerificationCheckId::PartitionLayout,
            VerificationReason::PrerequisiteCheckFailed,
            None,
        ));
    }
    for index in indices {
        checks.push(not_run(
            VerificationCheckId::PartitionFilesystem,
            VerificationReason::PrerequisiteCheckFailed,
            Some(*index),
        ));
        checks.push(not_run(
            VerificationCheckId::PartitionEntries,
            VerificationReason::PrerequisiteCheckFailed,
            Some(*index),
        ));
    }
}

fn push_not_run_full(checks: &mut Vec<VerificationCheck>, indices: &[u8]) {
    for index in indices {
        checks.push(not_run(
            VerificationCheckId::FsHeaderHash,
            VerificationReason::PrerequisiteCheckFailed,
            Some(*index),
        ));
    }
    for id in [
        VerificationCheckId::FixedKeySignature,
        VerificationCheckId::NpdmMetadata,
        VerificationCheckId::NpdmKeySignatureConsistency,
        VerificationCheckId::PayloadIntegrity,
    ] {
        checks.push(not_run(
            id,
            VerificationReason::PrerequisiteCheckFailed,
            None,
        ));
    }
}

fn evaluate_partitions(
    file: &mut File,
    header: &Header,
    checks: &mut Vec<VerificationCheck>,
) -> Result<Vec<Option<crate::ContainerProbeResult>>, VerificationError> {
    let mut probes = Vec::new();
    probes
        .try_reserve_exact(header.partitions.len())
        .map_err(|_| VerificationError::new(VerificationErrorCode::AllocationFailed))?;
    let mut validation = PartitionFsValidation::default();
    for partition in &header.partitions {
        let index = partition.index;
        let filesystem_supported = partition.filesystem == 1
            && partition.hash_type == 1
            && partition.encryption == 1
            && !partition.extended
            && partition.offset >= MIN_PARTITION_OFFSET
            && partition.size.is_multiple_of(PARTITION_ALIGNMENT)
            && partition.size > 0;
        checks.push(completed(
            VerificationCheckId::PartitionFilesystem,
            if filesystem_supported {
                CheckOutcome::Passed
            } else {
                CheckOutcome::Failed
            },
            (!filesystem_supported).then_some(VerificationReason::PartitionFilesystemUnsupported),
            Some(index),
        ));
        if !filesystem_supported {
            checks.push(not_run(
                VerificationCheckId::PartitionEntries,
                VerificationReason::PrerequisiteCheckFailed,
                Some(index),
            ));
            probes.push(None);
            continue;
        }
        let mut span = SpanReader::new(&mut *file, partition.offset, partition.size);
        match crate::pfs0::probe(&mut span, partition.size) {
            Ok(probe) => {
                let entries_valid = match validation.validate_partition(
                    index,
                    probe
                        .entries
                        .iter()
                        .map(|entry| (entry.name.as_str(), entry.size)),
                ) {
                    Ok(_) => true,
                    Err(PartitionFsValidationError::AllocationFailed) => {
                        return Err(VerificationError::new(
                            VerificationErrorCode::AllocationFailed,
                        ));
                    }
                    Err(_) => false,
                };
                checks.push(completed(
                    VerificationCheckId::PartitionEntries,
                    if entries_valid {
                        CheckOutcome::Passed
                    } else {
                        CheckOutcome::Failed
                    },
                    (!entries_valid).then_some(VerificationReason::PartitionEntriesInvalid),
                    Some(index),
                ));
                probes.push(Some(probe));
            }
            Err(_) => {
                checks.push(completed(
                    VerificationCheckId::PartitionEntries,
                    CheckOutcome::Failed,
                    Some(VerificationReason::PartitionEntriesInvalid),
                    Some(index),
                ));
                probes.push(None);
            }
        }
    }
    Ok(probes)
}

fn evaluate_full(
    file: &mut File,
    block: &[u8; nca::HEADER_SIZE],
    header: &Header,
    probes: &[Option<crate::ContainerProbeResult>],
    anchor: Option<&TrustAnchor>,
    checks: &mut Vec<VerificationCheck>,
) -> Result<(), VerificationError> {
    for partition in &header.partitions {
        let index = usize::from(partition.index);
        let fs_start = 0x400 + index * 0x200;
        let hash_start = 0x280 + index * 0x20;
        let actual = Sha256::digest(&block[fs_start..fs_start + 0x200]);
        let matches = actual.as_slice() == &block[hash_start..hash_start + 0x20];
        checks.push(completed(
            VerificationCheckId::FsHeaderHash,
            if matches {
                CheckOutcome::Passed
            } else {
                CheckOutcome::Failed
            },
            (!matches).then_some(VerificationReason::FsHeaderHashMismatch),
            Some(partition.index),
        ));
    }

    let anchor =
        anchor.ok_or_else(|| VerificationError::new(VerificationErrorCode::MissingTrustAnchor))?;
    let provenance = TrustProvenance {
        kind: TrustProvenanceKind::CallerSuppliedPublicKey,
        encoding: Some(anchor.encoding),
        anchor_generation: Some(anchor.generation),
    };
    let mut signature = if anchor.generation != header.signature_generation {
        not_run(
            VerificationCheckId::FixedKeySignature,
            VerificationReason::TrustAnchorGenerationMismatch,
            None,
        )
    } else {
        let matched = verify_pss(&anchor.key, &block[0x200..0x400], &block[..0x100]);
        completed(
            VerificationCheckId::FixedKeySignature,
            if matched {
                CheckOutcome::Passed
            } else {
                CheckOutcome::Failed
            },
            (!matched).then_some(VerificationReason::SignatureMismatch),
            None,
        )
    };
    signature.trust_provenance = Some(provenance);
    checks.push(signature);

    match locate_and_parse_npdm(file, header, probes) {
        NpdmOutcome::Ok(facts) => {
            checks.push(completed(
                VerificationCheckId::NpdmMetadata,
                CheckOutcome::Passed,
                None,
                Some(0),
            ));
            match acid_public_key(&facts.acid_modulus) {
                Some(key) => {
                    let matched = verify_pss(&key, &block[0x200..0x400], &block[0x100..0x200]);
                    let mut consistency = completed(
                        VerificationCheckId::NpdmKeySignatureConsistency,
                        if matched {
                            CheckOutcome::Passed
                        } else {
                            CheckOutcome::Failed
                        },
                        (!matched).then_some(VerificationReason::NpdmKeySignatureMismatch),
                        Some(0),
                    );
                    consistency.trust_provenance = Some(TrustProvenance {
                        kind: TrustProvenanceKind::EmbeddedNpdmAcidKey,
                        encoding: None,
                        anchor_generation: None,
                    });
                    checks.push(consistency);
                }
                None => checks.push(not_run(
                    VerificationCheckId::NpdmKeySignatureConsistency,
                    VerificationReason::NpdmMalformed,
                    Some(0),
                )),
            }
        }
        NpdmOutcome::Missing => {
            checks.push(completed(
                VerificationCheckId::NpdmMetadata,
                CheckOutcome::Failed,
                Some(VerificationReason::NpdmMissing),
                Some(0),
            ));
            checks.push(not_run(
                VerificationCheckId::NpdmKeySignatureConsistency,
                VerificationReason::PrerequisiteCheckFailed,
                Some(0),
            ));
        }
        NpdmOutcome::Duplicate => {
            checks.push(completed(
                VerificationCheckId::NpdmMetadata,
                CheckOutcome::Failed,
                Some(VerificationReason::NpdmDuplicate),
                Some(0),
            ));
            checks.push(not_run(
                VerificationCheckId::NpdmKeySignatureConsistency,
                VerificationReason::PrerequisiteCheckFailed,
                Some(0),
            ));
        }
        NpdmOutcome::Malformed => {
            checks.push(completed(
                VerificationCheckId::NpdmMetadata,
                CheckOutcome::Failed,
                Some(VerificationReason::NpdmMalformed),
                Some(0),
            ));
            checks.push(not_run(
                VerificationCheckId::NpdmKeySignatureConsistency,
                VerificationReason::PrerequisiteCheckFailed,
                Some(0),
            ));
        }
        NpdmOutcome::Unavailable => {
            checks.push(not_run(
                VerificationCheckId::NpdmMetadata,
                VerificationReason::PrerequisiteCheckFailed,
                Some(0),
            ));
            checks.push(not_run(
                VerificationCheckId::NpdmKeySignatureConsistency,
                VerificationReason::PrerequisiteCheckFailed,
                Some(0),
            ));
        }
    }

    if header
        .partitions
        .iter()
        .all(|partition| partition.hash_type == 1)
    {
        checks.push(completed(
            VerificationCheckId::PayloadIntegrity,
            CheckOutcome::NotApplicable,
            Some(VerificationReason::HashTypeNone),
            None,
        ));
    } else {
        checks.push(not_run(
            VerificationCheckId::PayloadIntegrity,
            VerificationReason::HashTypeUnsupported,
            None,
        ));
    }
    Ok(())
}

fn limitations(
    profile: VerificationProfile,
    checks: &[VerificationCheck],
) -> Vec<VerificationLimitation> {
    let mut limitations = Vec::new();
    if profile == VerificationProfile::Structural {
        limitations.push(VerificationLimitation::SignaturesNotChecked);
        limitations.push(VerificationLimitation::HashChecksNotRun);
    }
    if !checks.iter().any(|check| {
        check.id == VerificationCheckId::PayloadIntegrity && check.outcome == CheckOutcome::Passed
    }) {
        limitations.push(VerificationLimitation::PayloadIntegrityNotAvailable);
    }
    if profile == VerificationProfile::Full {
        limitations.push(VerificationLimitation::NpdmAcidAuthenticityUnverified);
    }
    limitations.push(VerificationLimitation::AuthenticityNotEstablished);
    limitations.push(VerificationLimitation::DeviceWriteAuthorizationNotEvaluated);
    limitations
}

enum NpdmOutcome {
    Ok(Box<NpdmFacts>),
    Missing,
    Duplicate,
    Malformed,
    Unavailable,
}

struct NpdmFacts {
    acid_modulus: [u8; RSA_MODULUS_BYTES],
}

fn locate_and_parse_npdm(
    file: &mut File,
    header: &Header,
    probes: &[Option<crate::ContainerProbeResult>],
) -> NpdmOutcome {
    let Some(partition) = header.partitions.first() else {
        return NpdmOutcome::Unavailable;
    };
    if partition.index != 0 {
        return NpdmOutcome::Unavailable;
    }
    let Some(Some(probe)) = probes.first() else {
        return NpdmOutcome::Unavailable;
    };
    let mut matches = probe
        .entries
        .iter()
        .filter(|entry| entry.name == "main.npdm");
    let Some(entry) = matches.next() else {
        return NpdmOutcome::Missing;
    };
    if matches.next().is_some() {
        return NpdmOutcome::Duplicate;
    }
    if entry.size < META_HEADER_SIZE as u64 || entry.size > MAX_NPDM_BYTES {
        return NpdmOutcome::Malformed;
    }
    let Some(start) = partition.offset.checked_add(entry.file_offset) else {
        return NpdmOutcome::Malformed;
    };
    let mut span = SpanReader::new(file, start, entry.size);
    match parse_npdm(&mut span, entry.size) {
        Ok(facts) => NpdmOutcome::Ok(Box::new(facts)),
        Err(()) => NpdmOutcome::Malformed,
    }
}

fn read_exact_at(
    reader: &mut (impl Read + Seek),
    offset: u64,
    buffer: &mut [u8],
) -> Result<(), ()> {
    reader.seek(SeekFrom::Start(offset)).map_err(|_| ())?;
    reader.read_exact(buffer).map_err(|_| ())
}

fn region(floor: u64, limit: u64, offset: u32, size: u32, minimum: u64) -> Result<(u64, u64), ()> {
    let start = u64::from(offset);
    let size = u64::from(size);
    if size < minimum {
        return Err(());
    }
    let end = start.checked_add(size).ok_or(())?;
    if start < floor || end > limit {
        return Err(());
    }
    Ok((start, size))
}

fn validate_subranges(header: &[u8], region_size: u64, floor: u64) -> Result<(), ()> {
    let mut ranges = Vec::new();
    for chunk in header.as_chunks::<8>().0 {
        let offset = u64::from(u32::from_le_bytes(
            chunk[0..4].try_into().expect("four bytes"),
        ));
        let size = u64::from(u32::from_le_bytes(
            chunk[4..8].try_into().expect("four bytes"),
        ));
        if size == 0 {
            continue;
        }
        let end = offset.checked_add(size).ok_or(())?;
        if offset < floor || end > region_size {
            return Err(());
        }
        ranges.push((offset, end));
    }
    ranges.sort_unstable();
    for pair in ranges.windows(2) {
        if pair[1].0 < pair[0].1 {
            return Err(());
        }
    }
    Ok(())
}

/// Parses the canonical NPDM member from the Program partition.
///
/// Every offset is validated against the member buffer before it is read, so a
/// malformed NPDM cannot cause an out-of-bounds read or an unbounded
/// allocation. The returned ACID modulus is untrusted key material taken from
/// the input; it is only used to check the header's second signature.
fn parse_npdm(reader: &mut (impl Read + Seek), length: u64) -> Result<NpdmFacts, ()> {
    if length < META_HEADER_SIZE as u64 || length > MAX_NPDM_BYTES {
        return Err(());
    }
    let mut meta = [0_u8; META_HEADER_SIZE];
    read_exact_at(reader, 0, &mut meta)?;
    if &meta[0..4] != b"META" {
        return Err(());
    }
    let aci0_offset = u32::from_le_bytes(meta[0x70..0x74].try_into().expect("four bytes"));
    let aci0_size = u32::from_le_bytes(meta[0x74..0x78].try_into().expect("four bytes"));
    let acid_offset = u32::from_le_bytes(meta[0x78..0x7c].try_into().expect("four bytes"));
    let acid_size = u32::from_le_bytes(meta[0x7c..0x80].try_into().expect("four bytes"));

    let (aci0_start, aci0_length) = region(
        META_HEADER_SIZE as u64,
        length,
        aci0_offset,
        aci0_size,
        ACI0_HEADER_SIZE as u64,
    )?;
    let (acid_start, acid_length) = region(
        META_HEADER_SIZE as u64,
        length,
        acid_offset,
        acid_size,
        ACID_HEADER_SIZE as u64,
    )?;
    let aci0_end = aci0_start.checked_add(aci0_length).ok_or(())?;
    let acid_end = acid_start.checked_add(acid_length).ok_or(())?;
    if aci0_start < acid_end && acid_start < aci0_end {
        return Err(());
    }

    let mut aci0 = [0_u8; ACI0_HEADER_SIZE];
    read_exact_at(reader, aci0_start, &mut aci0)?;
    if &aci0[0..4] != b"ACI0" {
        return Err(());
    }
    validate_subranges(&aci0[0x20..0x38], aci0_length, ACI0_HEADER_SIZE as u64)?;

    let mut acid = [0_u8; ACID_HEADER_SIZE];
    read_exact_at(reader, acid_start, &mut acid)?;
    if &acid[ACID_MAGIC_OFFSET..ACID_MAGIC_OFFSET + 4] != b"ACID" {
        return Err(());
    }
    let declared = u64::from(u32::from_le_bytes(
        acid[ACID_SIZE_OFFSET..ACID_SIZE_OFFSET + 4]
            .try_into()
            .expect("four bytes"),
    ));
    if declared
        .checked_add(ACID_SIGNATURE_BYTES as u64)
        .is_none_or(|total| total != acid_length)
    {
        return Err(());
    }
    validate_subranges(&acid[0x220..0x238], acid_length, ACID_HEADER_SIZE as u64)?;

    let mut modulus = [0_u8; RSA_MODULUS_BYTES];
    modulus.copy_from_slice(&acid[ACID_MODULUS_START..ACID_MODULUS_END]);
    Ok(NpdmFacts {
        acid_modulus: modulus,
    })
}

fn acid_public_key(modulus: &[u8; RSA_MODULUS_BYTES]) -> Option<RsaPublicKey> {
    let key =
        RsaPublicKey::new(BigUint::from_bytes_be(modulus), BigUint::from(RSA_EXPONENT)).ok()?;
    (key.size() == RSA_MODULUS_BYTES && key.n().bits() == RSA_MODULUS_BYTES * 8).then_some(key)
}

fn verify_pss(key: &RsaPublicKey, message: &[u8], signature: &[u8]) -> bool {
    let digest = Sha256::digest(message);
    key.verify(
        Pss::new_with_salt::<Sha256>(RSA_SALT_BYTES),
        &digest,
        signature,
    )
    .is_ok()
}

fn parse_public_key(bytes: &[u8]) -> Result<(RsaPublicKey, PublicKeyEncoding), VerificationError> {
    if let Ok(text) = std::str::from_utf8(bytes)
        && text.contains("-----BEGIN ")
    {
        if let Ok(key) = RsaPublicKey::from_public_key_pem(text) {
            return Ok((key, PublicKeyEncoding::SpkiPem));
        }
        if let Ok(key) = RsaPublicKey::from_pkcs1_pem(text) {
            return Ok((key, PublicKeyEncoding::Pkcs1Pem));
        }
        return Err(VerificationError::new(
            VerificationErrorCode::TrustAnchorMalformed,
        ));
    }
    if let Ok(key) = RsaPublicKey::from_public_key_der(bytes) {
        return Ok((key, PublicKeyEncoding::SpkiDer));
    }
    if let Ok(key) = RsaPublicKey::from_pkcs1_der(bytes) {
        return Ok((key, PublicKeyEncoding::Pkcs1Der));
    }
    Err(VerificationError::new(
        VerificationErrorCode::TrustAnchorMalformed,
    ))
}

fn read_trust_anchor(path: &Path, generation: u8) -> Result<TrustAnchor, VerificationError> {
    let mut opened = opened(
        path,
        VerificationErrorCode::TrustAnchorUnavailable,
        VerificationErrorCode::TrustAnchorChangedDuringVerification,
    )?;
    if opened.size > MAX_TRUST_ANCHOR_BYTES {
        return Err(VerificationError::new(
            VerificationErrorCode::TrustAnchorLimitExceeded,
        ));
    }
    let size = usize::try_from(opened.size)
        .map_err(|_| VerificationError::new(VerificationErrorCode::TrustAnchorLimitExceeded))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| VerificationError::new(VerificationErrorCode::AllocationFailed))?;
    bytes.resize(size, 0);
    opened
        .file
        .read_exact(&mut bytes)
        .map_err(|_| VerificationError::new(VerificationErrorCode::TrustAnchorUnavailable))?;
    let (key, encoding) = parse_public_key(&bytes)?;
    if key.size() != RSA_MODULUS_BYTES
        || key.n().bits() != RSA_MODULUS_BYTES * 8
        || key.e() != &BigUint::from(RSA_EXPONENT)
    {
        return Err(VerificationError::new(
            VerificationErrorCode::TrustAnchorMalformed,
        ));
    }
    Ok(TrustAnchor {
        key,
        encoding,
        generation,
        opened,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_synthetic_verification as synthetic_verification;
    use std::io::Cursor;

    const NPDM_LENGTH: u64 = (META_HEADER_SIZE + ACI0_HEADER_SIZE + ACID_HEADER_SIZE) as u64;

    fn canonical_npdm(modulus: [u8; RSA_MODULUS_BYTES]) -> Vec<u8> {
        let mut meta = vec![0_u8; META_HEADER_SIZE];
        meta[0..4].copy_from_slice(b"META");
        meta[0x70..0x74].copy_from_slice(&0x80_u32.to_le_bytes());
        meta[0x74..0x78].copy_from_slice(&0x40_u32.to_le_bytes());
        meta[0x78..0x7c].copy_from_slice(&0xc0_u32.to_le_bytes());
        meta[0x7c..0x80].copy_from_slice(&0x240_u32.to_le_bytes());

        let mut aci0 = vec![0_u8; ACI0_HEADER_SIZE];
        aci0[0..4].copy_from_slice(b"ACI0");

        let mut acid = vec![0_u8; ACID_HEADER_SIZE];
        acid[ACID_MODULUS_START..ACID_MODULUS_END].copy_from_slice(&modulus);
        acid[ACID_MAGIC_OFFSET..ACID_MAGIC_OFFSET + 4].copy_from_slice(b"ACID");
        acid[ACID_SIZE_OFFSET..ACID_SIZE_OFFSET + 4].copy_from_slice(
            &u32::try_from(ACID_HEADER_SIZE - ACID_SIGNATURE_BYTES)
                .unwrap()
                .to_le_bytes(),
        );

        let mut bytes = meta;
        bytes.extend_from_slice(&aci0);
        bytes.extend_from_slice(&acid);
        bytes
    }

    #[test]
    fn npdm_parser_accepts_canonical_layout_and_exposes_the_untrusted_modulus() {
        let modulus = [7_u8; RSA_MODULUS_BYTES];
        let facts = parse_npdm(&mut Cursor::new(canonical_npdm(modulus)), NPDM_LENGTH).unwrap();
        assert_eq!(facts.acid_modulus, modulus);
    }

    #[test]
    fn npdm_parser_rejects_oversized_lengths_and_malformed_layouts() {
        let modulus = [7_u8; RSA_MODULUS_BYTES];
        let mut empty = Cursor::new(Vec::new());
        assert!(parse_npdm(&mut empty, MAX_NPDM_BYTES + 1).is_err());
        assert!(parse_npdm(&mut empty, (META_HEADER_SIZE - 1) as u64).is_err());

        let mut wrong_magic = canonical_npdm(modulus);
        wrong_magic[0] = b'X';
        assert!(parse_npdm(&mut Cursor::new(wrong_magic), NPDM_LENGTH).is_err());

        let mut aci0_out_of_bounds = canonical_npdm(modulus);
        aci0_out_of_bounds[0x74..0x78].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_npdm(&mut Cursor::new(aci0_out_of_bounds), NPDM_LENGTH).is_err());

        let mut overlapping = canonical_npdm(modulus);
        overlapping[0x78..0x7c].copy_from_slice(&0x90_u32.to_le_bytes());
        assert!(parse_npdm(&mut Cursor::new(overlapping), NPDM_LENGTH).is_err());

        let mut acid_size_mismatch = canonical_npdm(modulus);
        let acid_size = 0x80 + ACI0_HEADER_SIZE + ACID_SIZE_OFFSET;
        acid_size_mismatch[acid_size..acid_size + 4].copy_from_slice(&0_u32.to_le_bytes());
        assert!(parse_npdm(&mut Cursor::new(acid_size_mismatch), NPDM_LENGTH).is_err());

        let mut subrange_out_of_bounds = canonical_npdm(modulus);
        let aci0_subrange = 0x80 + 0x20;
        subrange_out_of_bounds[aci0_subrange..aci0_subrange + 4]
            .copy_from_slice(&0x80_u32.to_le_bytes());
        subrange_out_of_bounds[aci0_subrange + 4..aci0_subrange + 8]
            .copy_from_slice(&0x100_u32.to_le_bytes());
        assert!(parse_npdm(&mut Cursor::new(subrange_out_of_bounds), NPDM_LENGTH).is_err());
    }

    #[test]
    fn verification_detects_path_replacement_for_every_source() {
        #[derive(Clone, Copy)]
        enum Source {
            Input,
            KeyFile,
            TrustAnchor,
        }

        for source in [Source::Input, Source::KeyFile, Source::TrustAnchor] {
            for replace_with_symlink in [false, true] {
                if replace_with_symlink && cfg!(not(unix)) {
                    continue;
                }
                let directory = tempfile::tempdir().unwrap();
                let built = synthetic_verification::build(synthetic_verification::Spec::default());
                let paths = built.write(directory.path());
                let (path, request, expected) = match source {
                    Source::Input => (
                        paths.input.clone(),
                        VerificationRequest::structural_nca(&paths.input, &paths.keys),
                        VerificationErrorCode::InputChangedDuringVerification,
                    ),
                    Source::KeyFile => (
                        paths.keys.clone(),
                        VerificationRequest::structural_nca(&paths.input, &paths.keys),
                        VerificationErrorCode::KeyFileChangedDuringVerification,
                    ),
                    Source::TrustAnchor => (
                        paths.anchor.clone(),
                        VerificationRequest::full_nca(&paths.input, &paths.keys, &paths.anchor, 5),
                        VerificationErrorCode::TrustAnchorChangedDuringVerification,
                    ),
                };
                let moved = directory.path().join("moved-source");
                let checkpoint_path = path.clone();
                let checkpoint_moved = moved.clone();
                let error = verify_with_checkpoint(request, move || {
                    std::fs::rename(&checkpoint_path, &checkpoint_moved).unwrap();
                    if replace_with_symlink {
                        #[cfg(unix)]
                        std::os::unix::fs::symlink(&checkpoint_moved, &checkpoint_path).unwrap();
                    } else {
                        std::fs::write(&checkpoint_path, b"replacement").unwrap();
                    }
                })
                .unwrap_err();
                assert_eq!(error.code(), expected);
                assert_eq!(error.code().exit_code(), 4);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn verification_detects_retargeted_source_symlinks() {
        #[derive(Clone, Copy)]
        enum Source {
            Input,
            KeyFile,
            TrustAnchor,
        }

        for source in [Source::Input, Source::KeyFile, Source::TrustAnchor] {
            let directory = tempfile::tempdir().unwrap();
            let built = synthetic_verification::build(synthetic_verification::Spec::default());
            let paths = built.write(directory.path());
            let (target, link) = match source {
                Source::Input => (paths.input.clone(), directory.path().join("input-link.nca")),
                Source::KeyFile => (paths.keys.clone(), directory.path().join("keys-link")),
                Source::TrustAnchor => (
                    paths.anchor.clone(),
                    directory.path().join("anchor-link.der"),
                ),
            };
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let (request, expected) = match source {
                Source::Input => (
                    VerificationRequest::structural_nca(&link, &paths.keys),
                    VerificationErrorCode::InputChangedDuringVerification,
                ),
                Source::KeyFile => (
                    VerificationRequest::structural_nca(&paths.input, &link),
                    VerificationErrorCode::KeyFileChangedDuringVerification,
                ),
                Source::TrustAnchor => (
                    VerificationRequest::full_nca(&paths.input, &paths.keys, &link, 5),
                    VerificationErrorCode::TrustAnchorChangedDuringVerification,
                ),
            };
            let replacement = directory.path().join("replacement");
            std::fs::write(&replacement, b"retargeted").unwrap();
            let checkpoint_link = link.clone();
            let checkpoint_replacement = replacement.clone();
            let error = verify_with_checkpoint(request, move || {
                std::fs::remove_file(&checkpoint_link).unwrap();
                std::os::unix::fs::symlink(&checkpoint_replacement, &checkpoint_link).unwrap();
            })
            .unwrap_err();
            assert_eq!(error.code(), expected);
            assert_eq!(error.code().exit_code(), 4);
        }
    }

    #[cfg(unix)]
    #[test]
    fn verification_accepts_stable_source_symlinks() {
        #[derive(Clone, Copy)]
        enum Source {
            Input,
            KeyFile,
            TrustAnchor,
        }

        for source in [Source::Input, Source::KeyFile, Source::TrustAnchor] {
            let directory = tempfile::tempdir().unwrap();
            let built = synthetic_verification::build(synthetic_verification::Spec::default());
            let paths = built.write(directory.path());
            let (target, link) = match source {
                Source::Input => (paths.input.clone(), directory.path().join("input-link.nca")),
                Source::KeyFile => (paths.keys.clone(), directory.path().join("keys-link")),
                Source::TrustAnchor => (
                    paths.anchor.clone(),
                    directory.path().join("anchor-link.der"),
                ),
            };
            std::os::unix::fs::symlink(&target, &link).unwrap();

            let request = match source {
                Source::Input => VerificationRequest::structural_nca(&link, &paths.keys),
                Source::KeyFile => VerificationRequest::structural_nca(&paths.input, &link),
                Source::TrustAnchor => {
                    VerificationRequest::full_nca(&paths.input, &paths.keys, &link, 5)
                }
            };
            verify(request).unwrap();
        }
    }

    #[test]
    fn cancellation_after_opening_inputs_returns_no_result() {
        let directory = tempfile::tempdir().unwrap();
        let built = synthetic_verification::build(synthetic_verification::Spec::default());
        let paths = built.write(directory.path());
        let cancellation = CancellationHandle::new();
        let request = VerificationRequest::structural_nca(&paths.input, &paths.keys)
            .with_cancellation(cancellation.clone());
        let checkpoint = cancellation.clone();
        let error = verify_with_checkpoint(request, move || checkpoint.cancel()).unwrap_err();
        assert_eq!(error.code(), VerificationErrorCode::Cancelled);
        assert_eq!(error.code().exit_code(), 6);
    }

    #[test]
    fn revalidate_detects_mutation_and_path_replacement_conflicts() {
        for code in [
            VerificationErrorCode::InputChangedDuringVerification,
            VerificationErrorCode::KeyFileChangedDuringVerification,
            VerificationErrorCode::TrustAnchorChangedDuringVerification,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let mutated_path = directory.path().join("mutated");
            std::fs::write(&mutated_path, b"initial bytes").unwrap();
            let mutated = opened(&mutated_path, code, code).unwrap();
            assert!(revalidate(&mutated, code).is_ok());
            std::fs::write(&mutated_path, b"changed").unwrap();
            let error = revalidate(&mutated, code).unwrap_err();
            assert_eq!(error.code(), code);
            assert_eq!(error.code().exit_code(), 4);

            let replaced_path = directory.path().join("replaced");
            let moved_path = directory.path().join("moved");
            std::fs::write(&replaced_path, b"opened bytes").unwrap();
            let replaced = opened(&replaced_path, code, code).unwrap();
            std::fs::rename(&replaced_path, &moved_path).unwrap();
            std::fs::write(&replaced_path, b"replacement").unwrap();
            assert_eq!(revalidate(&replaced, code).unwrap_err().code(), code);

            #[cfg(unix)]
            {
                let link_path = directory.path().join("linked");
                let target_path = directory.path().join("linked-target");
                std::fs::write(&link_path, b"opened bytes").unwrap();
                let linked = opened(&link_path, code, code).unwrap();
                std::fs::rename(&link_path, &target_path).unwrap();
                std::os::unix::fs::symlink(&target_path, &link_path).unwrap();
                assert_eq!(revalidate(&linked, code).unwrap_err().code(), code);
            }
        }
    }

    #[test]
    fn every_verification_error_uses_a_documented_exit_class() {
        use VerificationErrorCode::*;
        let codes = [
            InvalidKeyPath,
            InputUnavailable,
            UnsupportedFormat,
            TruncatedInput,
            MalformedInput,
            InputLimitExceeded,
            KeyFileUnavailable,
            KeyFileMalformed,
            KeyFileLimitExceeded,
            MissingHeaderKey,
            MissingTrustAnchor,
            MissingAnchorGeneration,
            TrustAnchorUnavailable,
            TrustAnchorMalformed,
            TrustAnchorLimitExceeded,
            AnchorNotApplicable,
            InputChangedDuringVerification,
            KeyFileChangedDuringVerification,
            TrustAnchorChangedDuringVerification,
            Cancelled,
            AllocationFailed,
            InternalIo,
            SignalHandlerFailed,
        ];
        for code in codes {
            let exit = code.exit_code();
            assert!(
                matches!(exit, 2 | 3 | 4 | 6 | 7),
                "{} mapped to undocumented exit {exit}",
                code.as_str()
            );
            assert_ne!(
                exit,
                8,
                "{} must not use the batch exit class",
                code.as_str()
            );
        }
        assert_eq!(InvalidKeyPath.exit_code(), 2);
        assert_eq!(AnchorNotApplicable.exit_code(), 2);
        assert_eq!(MissingTrustAnchor.exit_code(), 3);
        assert_eq!(MissingAnchorGeneration.exit_code(), 3);
        assert_eq!(InputChangedDuringVerification.exit_code(), 4);
        assert_eq!(Cancelled.exit_code(), 6);
        assert_eq!(InternalIo.exit_code(), 7);
    }
}
