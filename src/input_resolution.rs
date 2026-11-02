//! Deterministic, read-only resolution of ordered local content selections.
//!
//! Ordinary files and directory candidates are identified from metadata and keep
//! the original v1 behavior. Canonical Split representations additionally require
//! an adjacent manifest, a host-owned local receipt, complete physical membership,
//! and matching per-segment and whole-stream SHA-256 evidence. Resolution never
//! treats a manifest or a plausible numeric layout as completeness evidence, and
//! it never issues or repairs trust itself.

use crate::file_identity::{FileIdentity, path_identity};
use crate::inspection::CancellationHandle;
use crate::sha256::Sha256Digest;
use crate::split_resolution::{
    SplitResolutionContext, canonical_member_index, directory_has_canonical_member,
    has_adjacent_sidecar, qualify_directory,
};
use crate::split_trust::SplitTrustStore;
use crate::strict_json::{self, StrictJsonValue};
use serde::Serialize;
use std::collections::HashSet;
use std::fmt;
use std::fs::{self, Metadata, OpenOptions, ReadDir};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use unicode_normalization::UnicodeNormalization;

const MAX_INPUT_LIST_BYTES: u64 = 1_048_576;
const MAX_INPUT_LIST_BYTES_PER_REQUEST: u64 = 4_194_304;
const MAX_INPUT_LIST_ENTRIES: usize = 100_000;
const MAX_TRAVERSAL_ENTRIES: usize = 100_000;
const MAX_TRAVERSAL_DEPTH: usize = 64;
const MAX_RESOLVED_SEGMENTS: usize = 100_000;
/// Cumulative Split bytes one request may hash when the host does not override
/// the budget. This covers the largest canonical FAT32 Split set (100 parts of
/// 0xFFFF0000 bytes) without limiting ordinary single-file resolution.
pub const DEFAULT_MAX_SPLIT_VALIDATION_BYTES: u64 = 429_490_176_000;
const PROGRESS_TOTAL_UNSET: u64 = u64::MAX;
const DISCOVERABLE_EXTENSIONS: &[&str] = &["nsp", "nsz", "nsx", "xci", "xcz", "nca", "ncz"];

/// Ordered selections and traversal controls for a read-only input resolution.
///
/// `base_directory` must be an absolute directory. Relative direct selections are
/// resolved against this base. Entries in a JSON input list are resolved against
/// the directory containing that list. Embedding hosts must provide the base
/// explicitly; the Engine never consults the process working directory.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct InputResolutionRequest {
    base_directory: PathBuf,
    selections: Vec<InputSelection>,
    recursive: bool,
    follow_symlinks: bool,
}

impl InputResolutionRequest {
    /// Creates a request with an explicit path base and no selections.
    pub fn new(base_directory: impl Into<PathBuf>) -> Self {
        Self {
            base_directory: base_directory.into(),
            selections: Vec::new(),
            recursive: false,
            follow_symlinks: false,
        }
    }

    /// Appends an explicit path selection, preserving its position in the request.
    #[must_use]
    pub fn with_path(self, path: impl Into<PathBuf>) -> Self {
        self.with_selection(InputSelection::Path(path.into()))
    }

    /// Appends a typed selection in request order.
    #[must_use]
    pub fn with_selection(mut self, selection: InputSelection) -> Self {
        self.selections.push(selection);
        self
    }

    /// Appends a versioned JSON input-list selection in request order.
    #[must_use]
    pub fn with_input_list(self, path: impl Into<PathBuf>) -> Self {
        self.with_selection(InputSelection::InputList(path.into()))
    }

    /// Enables bounded recursive directory discovery.
    #[must_use]
    pub fn with_recursive(mut self, recursive: bool) -> Self {
        self.recursive = recursive;
        self
    }

    /// Enables traversal through symbolic links encountered during discovery.
    ///
    /// Symlink targets must remain within the selected directory tree. Cycles are
    /// detected and skipped. Explicitly selected regular-file symlinks are allowed.
    #[must_use]
    pub fn with_follow_symlinks(mut self, follow_symlinks: bool) -> Self {
        self.follow_symlinks = follow_symlinks;
        self
    }
}

/// Ordered selections with a separate resolution base for each batch entry.
///
/// All entries share one resolver, so duplicate detection and aggregate resource
/// limits apply across the complete batch. The traversal settings apply to every
/// entry. Each base must be an absolute directory.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct InputResolutionBatchRequest {
    selections: Vec<InputResolutionBatchSelection>,
    recursive: bool,
    follow_symlinks: bool,
}

#[derive(Clone, Debug)]
struct InputResolutionBatchSelection {
    base_directory: PathBuf,
    selection: InputSelection,
}

impl InputResolutionBatchRequest {
    /// Creates an empty batch request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends one typed selection and its path base in request order.
    #[must_use]
    pub fn with_selection(
        mut self,
        base_directory: impl Into<PathBuf>,
        selection: InputSelection,
    ) -> Self {
        self.selections.push(InputResolutionBatchSelection {
            base_directory: base_directory.into(),
            selection,
        });
        self
    }

    /// Appends a direct path selection and its path base.
    #[must_use]
    pub fn with_path(self, base_directory: impl Into<PathBuf>, path: impl Into<PathBuf>) -> Self {
        self.with_selection(base_directory, InputSelection::Path(path.into()))
    }

    /// Appends a versioned JSON input-list selection and its path base.
    #[must_use]
    pub fn with_input_list(
        self,
        base_directory: impl Into<PathBuf>,
        path: impl Into<PathBuf>,
    ) -> Self {
        self.with_selection(base_directory, InputSelection::InputList(path.into()))
    }

    /// Enables bounded recursive directory discovery for every entry.
    #[must_use]
    pub fn with_recursive(mut self, recursive: bool) -> Self {
        self.recursive = recursive;
        self
    }

    /// Enables traversal through symbolic links for every entry.
    #[must_use]
    pub fn with_follow_symlinks(mut self, follow_symlinks: bool) -> Self {
        self.follow_symlinks = follow_symlinks;
        self
    }
}

impl From<InputResolutionRequest> for InputResolutionBatchRequest {
    fn from(request: InputResolutionRequest) -> Self {
        let InputResolutionRequest {
            base_directory,
            selections,
            recursive,
            follow_symlinks,
        } = request;
        Self {
            selections: selections
                .into_iter()
                .map(|selection| InputResolutionBatchSelection {
                    base_directory: base_directory.clone(),
                    selection,
                })
                .collect(),
            recursive,
            follow_symlinks,
        }
    }
}

/// A caller selection in the order it was supplied.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum InputSelection {
    /// A regular file or directory path. Regular files do not require a recognized extension.
    Path(PathBuf),
    /// A strict, versioned JSON input-list file.
    InputList(PathBuf),
}

/// A resolved batch in caller-selection order and normalized directory order.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct InputResolutionResult {
    /// Resolved logical inputs in stable selection order.
    pub inputs: Vec<ResolvedInput>,
}

/// One request-order entry from independent batch resolution.
///
/// A resolved entry is ready for planning. A failed entry records a selection-
/// local failure whose exact identity is known. An unavailable ordinary direct
/// path is item-local, as is an unavailable path inside a readable input list
/// and a broken discoverable symlink found without recursive traversal. A
/// split-shaped broken symlink, a broken symlink found during recursion, a
/// missing, unreadable, or malformed input-list file, a Split resolution
/// failure, duplicate inputs, unsafe filesystem layout, cancellation, and a
/// resource limit reject the whole batch. External callers must include a
/// wildcard match arm to handle entries added in future releases.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum InputResolutionBatchEntry {
    /// A logical input that resolved successfully.
    Resolved(ResolvedInput),
    /// A selection-local failure retained for its batch item.
    Failed(InputResolutionFailure),
}

/// Sanitized failure for one independently selectable batch item.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct InputResolutionFailure {
    selection_index: usize,
    source: InputSelectionSource,
    selection_path: PathBuf,
    base_directory: PathBuf,
    input_list_entry_index: Option<usize>,
    input_list_entry_path: Option<PathBuf>,
    discovered_directory: Option<PathBuf>,
    discovered_relative_path: Option<PathBuf>,
    requested_path: PathBuf,
    code: InputResolutionErrorCode,
}

impl InputResolutionFailure {
    /// Returns the caller selection index that produced this item.
    pub const fn selection_index(&self) -> usize {
        self.selection_index
    }

    /// Returns whether the caller supplied a direct path or an input list.
    pub const fn source(&self) -> InputSelectionSource {
        self.source
    }

    /// Returns the original caller-side selection path.
    pub fn selection_path(&self) -> &Path {
        &self.selection_path
    }

    /// Returns the absolute request base used for relative path resolution.
    pub fn base_directory(&self) -> &Path {
        &self.base_directory
    }

    /// Returns the input-list entry index, when the item came from a list.
    pub const fn input_list_entry_index(&self) -> Option<usize> {
        self.input_list_entry_index
    }

    /// Returns the input-list entry path, when the item came from a list.
    pub fn input_list_entry_path(&self) -> Option<&Path> {
        self.input_list_entry_path.as_deref()
    }

    /// Returns the selected directory that produced a discovered failure.
    pub fn discovered_directory(&self) -> Option<&Path> {
        self.discovered_directory.as_deref()
    }

    /// Returns the failed child's path relative to its selected directory.
    pub fn discovered_relative_path(&self) -> Option<&Path> {
        self.discovered_relative_path.as_deref()
    }

    /// Returns the exact path selected for this item before failure.
    pub fn requested_path(&self) -> &Path {
        &self.requested_path
    }

    /// Returns the stable failure category.
    pub const fn code(&self) -> InputResolutionErrorCode {
        self.code
    }
}

/// Ordered partial resolution result for an independent copy batch.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct InputResolutionBatchResult {
    /// Resolved inputs and item-local failures in request order.
    pub entries: Vec<InputResolutionBatchEntry>,
}

/// Additive host capabilities used for one read-only resolution request.
///
/// Omitting a trust store preserves ordinary non-Split resolution. A canonical
/// Split candidate then fails as untrusted instead of silently accepting an
/// unsigned manifest. The control handle is host-owned and optional; it never
/// creates a background Job or hidden engine state.
#[non_exhaustive]
pub struct InputResolutionCapabilities<'a> {
    /// Host-owned local evidence store used only for Split qualification.
    pub split_trust_store: Option<&'a dyn SplitTrustStore>,
    /// Optional latest-value progress and cancellation control.
    pub control: Option<&'a InputResolutionControl>,
    /// Cumulative byte budget for Split validation in this request.
    pub max_split_validation_bytes: u64,
}

impl Default for InputResolutionCapabilities<'_> {
    fn default() -> Self {
        Self {
            split_trust_store: None,
            control: None,
            max_split_validation_bytes: DEFAULT_MAX_SPLIT_VALIDATION_BYTES,
        }
    }
}

impl<'a> InputResolutionCapabilities<'a> {
    /// Creates capabilities without a trust store or progress control.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a host-owned Split trust store.
    #[must_use]
    pub fn with_split_trust_store(mut self, store: &'a dyn SplitTrustStore) -> Self {
        self.split_trust_store = Some(store);
        self
    }

    /// Adds a host-owned progress and cancellation control.
    #[must_use]
    pub fn with_control(mut self, control: &'a InputResolutionControl) -> Self {
        self.control = Some(control);
        self
    }

    /// Replaces the cumulative Split validation byte budget.
    #[must_use]
    pub const fn with_max_split_validation_bytes(mut self, bytes: u64) -> Self {
        self.max_split_validation_bytes = bytes;
        self
    }
}

/// Latest-value progress for the Split input currently being validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct InputResolutionProgress {
    /// Zero-based logical input index in the eventual result.
    pub input_index: usize,
    /// Bytes hashed for the current Split input.
    pub completed_bytes: u64,
    /// Expected logical byte length of the current Split input.
    pub total_bytes: Option<u64>,
}

/// Host-owned cancellation and progress state for one resolution request.
///
/// The resolver updates this atomically while hashing Split segments. Hosts may
/// poll [`progress`](Self::progress) from another thread and call
/// [`cancel`](Self::cancel) at any time. Progress is not a queued event stream
/// and never backpressures the resolver.
#[derive(Debug)]
pub struct InputResolutionControl {
    input_index: AtomicUsize,
    completed_bytes: AtomicU64,
    total_bytes: AtomicU64,
    cancelled: AtomicBool,
    external_cancellation: Option<CancellationHandle>,
}

impl Default for InputResolutionControl {
    fn default() -> Self {
        Self {
            input_index: AtomicUsize::new(0),
            completed_bytes: AtomicU64::new(0),
            total_bytes: AtomicU64::new(PROGRESS_TOTAL_UNSET),
            cancelled: AtomicBool::new(false),
            external_cancellation: None,
        }
    }
}

impl InputResolutionControl {
    /// Creates an uncancelled control with no active Split input.
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cooperative cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Binds an existing invocation cancellation handle to this control.
    ///
    /// Resolution checks the control and the bound handle before filesystem
    /// work and between directory entries. Split validation also checks while
    /// hashing. The caller retains ownership of the handle.
    #[must_use]
    pub fn with_cancellation(mut self, cancellation: CancellationHandle) -> Self {
        self.external_cancellation = Some(cancellation);
        self
    }

    /// Reports whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
            || self
                .external_cancellation
                .as_ref()
                .is_some_and(CancellationHandle::is_cancelled)
    }

    /// Returns the latest progress snapshot without blocking.
    pub fn progress(&self) -> InputResolutionProgress {
        let total_bytes = self.total_bytes.load(Ordering::Acquire);
        InputResolutionProgress {
            input_index: self.input_index.load(Ordering::Acquire),
            completed_bytes: self.completed_bytes.load(Ordering::Acquire),
            total_bytes: (total_bytes != PROGRESS_TOTAL_UNSET).then_some(total_bytes),
        }
    }

    pub(crate) fn begin_split_input(&self, input_index: usize, total_bytes: u64) {
        self.input_index.store(input_index, Ordering::Release);
        self.completed_bytes.store(0, Ordering::Release);
        self.total_bytes.store(total_bytes, Ordering::Release);
    }

    pub(crate) fn add_completed(&self, bytes: u64) -> Result<(), InputResolutionError> {
        let completed = self
            .completed_bytes
            .fetch_add(bytes, Ordering::AcqRel)
            .checked_add(bytes)
            .ok_or_else(|| {
                InputResolutionError::new(InputResolutionErrorCode::SplitIntegrityMismatch)
            })?;
        let total = self.total_bytes.load(Ordering::Acquire);
        if total != PROGRESS_TOTAL_UNSET && completed > total {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::SplitIntegrityMismatch,
            ));
        }
        Ok(())
    }

    pub(crate) fn check_cancelled(&self) -> Result<(), InputResolutionError> {
        if self.is_cancelled() {
            Err(InputResolutionError::new(
                InputResolutionErrorCode::SplitResolutionCancelled,
            ))
        } else {
            Ok(())
        }
    }
}

/// Additive completeness evidence attached only to a qualified Split input.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SplitQualification {
    /// Evidence family that established completeness.
    pub kind: SplitQualificationKind,
    /// Manifest schema version bound to the receipt.
    pub manifest_schema_version: u16,
    /// Independently observed source byte length.
    pub original_size_bytes: u64,
    /// Independently observed source SHA-256 digest.
    pub original_sha256: Sha256Digest,
}

impl SplitQualification {
    /// Creates qualification evidence from a validated local Split receipt.
    pub const fn local_receipt(
        manifest_schema_version: u16,
        original_size_bytes: u64,
        original_sha256: Sha256Digest,
    ) -> Self {
        Self {
            kind: SplitQualificationKind::LocalSplitReceipt,
            manifest_schema_version,
            original_size_bytes,
            original_sha256,
        }
    }
}

/// Kind of completeness evidence attached to a resolved Split input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SplitQualificationKind {
    /// A host-local receipt binds exact manifest bytes to source evidence.
    LocalSplitReceipt,
}

/// One logical input with an ordered physical segment representation.
///
/// Version 1 non-Split inputs contain exactly one segment. The vector preserves
/// segment order for future additive support, but its presence is not evidence that
/// a Split set is complete.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ResolvedInput {
    /// Physical segments in their logical order.
    pub segments: Vec<InputSegment>,
    /// The caller selection and directory/list entry that produced this input.
    pub provenance: InputProvenance,
    /// Split completeness evidence, present only for qualified Split inputs.
    pub qualification: Option<SplitQualification>,
    /// Hash of the exact manifest bytes used to qualify a Split input.
    pub(crate) split_manifest_sha256: Option<Sha256Digest>,
}

impl ResolvedInput {
    /// Returns the logical caller-selected path represented by this input.
    ///
    /// For a Split directory this is the directory itself, rather than any
    /// physical member file.
    pub fn logical_selection_path(&self) -> PathBuf {
        self.provenance.logical_selection_path()
    }

    /// Returns the digest of the exact manifest bytes used to qualify a Split.
    ///
    /// Ordinary inputs do not have a Split manifest.
    pub fn split_manifest_sha256(&self) -> Option<&Sha256Digest> {
        self.split_manifest_sha256.as_ref()
    }
}

/// One physical file segment and its observed byte length.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct InputSegment {
    /// Canonical absolute path to the regular file.
    pub path: PathBuf,
    /// File length observed during resolution.
    pub size: u64,
}

/// Provenance connecting a resolved input to the caller's ordered selection.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct InputProvenance {
    /// Zero-based position in the request's ordered selections.
    pub selection_index: usize,
    /// Whether the top-level selection was a path or a JSON input list.
    pub source: InputSelectionSource,
    /// Path supplied for the top-level selection, kept as supplied.
    pub selection_path: PathBuf,
    /// Absolute request base used to resolve relative selections.
    pub base_directory: PathBuf,
    /// Zero-based entry position when the input came from a JSON input list.
    pub input_list_entry_index: Option<usize>,
    /// Path string supplied by that JSON entry, when applicable.
    pub input_list_entry_path: Option<PathBuf>,
    /// Canonical selected directory when discovery produced the input.
    pub discovered_directory: Option<PathBuf>,
    /// Relative path within the selected directory, when discovery produced the input.
    pub discovered_relative_path: Option<PathBuf>,
}

impl InputProvenance {
    /// Returns the logical selected path represented by this provenance.
    ///
    /// Directory discovery uses its recorded root and relative path. Input-list
    /// entries are resolved against the directory containing the list, anchored
    /// to the request's stored base. Direct selections retain the caller-supplied path.
    pub fn logical_selection_path(&self) -> PathBuf {
        if let (Some(directory), Some(relative)) = (
            self.discovered_directory.as_deref(),
            self.discovered_relative_path.as_deref(),
        ) {
            return directory.join(relative);
        }
        if let Some(entry) = self.input_list_entry_path.as_deref() {
            let selected = if entry.is_absolute() {
                entry.to_path_buf()
            } else {
                let list_path = absolute_path(&self.base_directory, &self.selection_path);
                match list_path.parent() {
                    Some(parent) => parent.join(entry),
                    None => return self.selection_path.clone(),
                }
            };
            return fs::canonicalize(&selected).unwrap_or(selected);
        }
        self.selection_path.clone()
    }
}

/// Kind of top-level selection that produced a resolved input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InputSelectionSource {
    /// A directly supplied filesystem path.
    Path,
    /// An entry read from a versioned JSON input list.
    InputList,
}

/// Stable typed failures produced by input resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InputResolutionErrorCode {
    /// No selection produced any usable regular file.
    EmptySelection,
    /// A path could not be read or does not identify a regular file or directory.
    InputUnavailable,
    /// A special filesystem entry or unsafe symlink target was encountered.
    UnsupportedFilesystemEntry,
    /// A suspected Split representation has no qualified v1 resolver.
    UnsupportedSplitLayout,
    /// An input-list document is malformed or violates the v1 schema.
    InvalidInputList,
    /// An input-list schema version is not supported.
    UnsupportedInputListVersion,
    /// An input list requires semantics this resolver does not implement.
    UnsupportedRequiredFeature,
    /// Two selections resolve to the same logical file identity.
    DuplicateSelection,
    /// A configured safety bound was exceeded.
    ResourceLimitExceeded,
    /// The caller supplied a base that is not an absolute directory.
    InvalidBaseDirectory,
    /// A filesystem path cannot be represented losslessly in the JSON result format.
    UnrepresentablePath,
    /// A canonical Split candidate has no adjacent manifest.
    SplitManifestMissing,
    /// A Split receipt is absent, revoked, or does not bind this manifest.
    SplitEvidenceUntrusted,
    /// A Split manifest is malformed, unsafe, or internally inconsistent.
    SplitManifestInvalid,
    /// A Split manifest version or required feature is unsupported.
    SplitManifestVersionUnsupported,
    /// Declared members are missing or the representation is ambiguous.
    SplitSetIncomplete,
    /// A member or reconstructed stream does not match its declared digest.
    SplitIntegrityMismatch,
    /// A Split input changed while it was being validated.
    SplitInputChanged,
    /// The configured host evidence store is unreadable or corrupt.
    SplitStateUnavailable,
    /// The explicitly configured trust-store location is invalid.
    SplitTrustStoreConfigurationInvalid,
    /// Cooperative cancellation stopped Split validation.
    SplitResolutionCancelled,
}

impl InputResolutionErrorCode {
    /// Returns the stable machine-readable code used in JSON error documents.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmptySelection => "empty_selection",
            Self::InputUnavailable => "input_unavailable",
            Self::UnsupportedFilesystemEntry => "unsupported_filesystem_entry",
            Self::UnsupportedSplitLayout => "unsupported_split_layout",
            Self::InvalidInputList => "invalid_input_list",
            Self::UnsupportedInputListVersion => "unsupported_input_list_version",
            Self::UnsupportedRequiredFeature => "unsupported_required_feature",
            Self::DuplicateSelection => "duplicate_selection",
            Self::ResourceLimitExceeded => "resource_limit_exceeded",
            Self::InvalidBaseDirectory => "invalid_base_directory",
            Self::UnrepresentablePath => "unrepresentable_path",
            Self::SplitManifestMissing => "split_manifest_missing",
            Self::SplitEvidenceUntrusted => "split_evidence_untrusted",
            Self::SplitManifestInvalid => "split_manifest_invalid",
            Self::SplitManifestVersionUnsupported => "split_manifest_version_unsupported",
            Self::SplitSetIncomplete => "split_set_incomplete",
            Self::SplitIntegrityMismatch => "split_integrity_mismatch",
            Self::SplitInputChanged => "split_input_changed",
            Self::SplitStateUnavailable => "split_state_unavailable",
            Self::SplitTrustStoreConfigurationInvalid => "split_trust_store_configuration_invalid",
            Self::SplitResolutionCancelled => "split_resolution_cancelled",
        }
    }
}

/// Sanitized input-resolution failure suitable for public Rust and CLI boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputResolutionError {
    code: InputResolutionErrorCode,
}

impl InputResolutionError {
    pub(crate) fn new(code: InputResolutionErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable typed failure category.
    pub const fn code(&self) -> InputResolutionErrorCode {
        self.code
    }
}

impl fmt::Display for InputResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.code {
            InputResolutionErrorCode::EmptySelection => "no usable input was selected",
            InputResolutionErrorCode::InputUnavailable => "the input could not be read",
            InputResolutionErrorCode::UnsupportedFilesystemEntry => {
                "the filesystem entry is not supported"
            }
            InputResolutionErrorCode::UnsupportedSplitLayout => {
                "the selected path appears to use an unsupported Split layout"
            }
            InputResolutionErrorCode::InvalidInputList => "the input list is invalid",
            InputResolutionErrorCode::UnsupportedInputListVersion => {
                "the input-list schema version is not supported"
            }
            InputResolutionErrorCode::UnsupportedRequiredFeature => {
                "the input list requires unsupported features"
            }
            InputResolutionErrorCode::DuplicateSelection => {
                "the selection contains a duplicate logical input"
            }
            InputResolutionErrorCode::ResourceLimitExceeded => {
                "input resolution exceeded a safety limit"
            }
            InputResolutionErrorCode::InvalidBaseDirectory => {
                "the relative path base is not an absolute directory"
            }
            InputResolutionErrorCode::UnrepresentablePath => {
                "a filesystem path cannot be represented losslessly in JSON"
            }
            InputResolutionErrorCode::SplitManifestMissing => "the Split candidate has no manifest",
            InputResolutionErrorCode::SplitEvidenceUntrusted => {
                "the Split manifest has no usable local trust receipt"
            }
            InputResolutionErrorCode::SplitManifestInvalid => "the Split manifest is invalid",
            InputResolutionErrorCode::SplitManifestVersionUnsupported => {
                "the Split manifest version or required feature is unsupported"
            }
            InputResolutionErrorCode::SplitSetIncomplete => {
                "the Split set is incomplete or ambiguous"
            }
            InputResolutionErrorCode::SplitIntegrityMismatch => {
                "the Split set does not match its declared integrity evidence"
            }
            InputResolutionErrorCode::SplitInputChanged => {
                "a Split input changed during validation"
            }
            InputResolutionErrorCode::SplitStateUnavailable => {
                "the Split trust store is unavailable or corrupt"
            }
            InputResolutionErrorCode::SplitTrustStoreConfigurationInvalid => {
                "the Split trust store location is invalid"
            }
            InputResolutionErrorCode::SplitResolutionCancelled => {
                "Split input resolution was cancelled"
            }
        })
    }
}

impl std::error::Error for InputResolutionError {}

/// Resolves files, directories, and JSON input lists through the public Engine.
///
/// Explicit file selections accept regular files regardless of extension. Directory
/// discovery uses the documented candidate extensions and is nonrecursive by
/// default. Ordinary outputs contain one physical segment. Canonical Split
/// directories additionally require a host-owned receipt and complete byte
/// validation; unsupported numeric layouts remain typed failures.
impl crate::Engine {
    /// Resolves ordered local selections without a Split trust-store capability.
    ///
    /// Ordinary non-Split inputs retain their metadata-only behavior. Canonical
    /// Split candidates fail as untrusted because no host evidence was supplied.
    pub fn resolve_inputs(
        &self,
        request: InputResolutionRequest,
    ) -> Result<InputResolutionResult, InputResolutionError> {
        resolve_inputs_impl(request, InputResolutionCapabilities::default())
    }

    /// Resolves ordered local selections with explicit host capabilities.
    ///
    /// The capability boundary is evaluated per call and introduces no engine
    /// state. A configured trust store is consulted only when a canonical Split
    /// candidate is selected or discovered.
    pub fn resolve_inputs_with(
        &self,
        request: InputResolutionRequest,
        capabilities: InputResolutionCapabilities<'_>,
    ) -> Result<InputResolutionResult, InputResolutionError> {
        resolve_inputs_impl(request, capabilities)
    }

    /// Resolves independent batch selections while retaining item-local failures.
    ///
    /// The resolver keeps one shared duplicate set, traversal counter, input-list
    /// budget, segment budget, Split byte budget, and cancellation state across
    /// the whole request. A contract, duplicate, resource, Split, or safety
    /// failure still rejects the request globally. An unavailable ordinary
    /// path, empty input list, or empty selected directory remains a failed
    /// entry when its identity is known, so viable siblings can proceed. An
    /// item-local failure discovered inside a directory remains in sorted path
    /// order and does not suppress later discovered siblings. An unavailable
    /// input-list file rejects the request because its selections
    /// cannot be known. Split qualification failures always reject globally.
    pub fn resolve_inputs_batch(
        &self,
        request: InputResolutionRequest,
    ) -> Result<InputResolutionBatchResult, InputResolutionError> {
        self.resolve_inputs_batch_request(request.into())
    }

    /// Resolves independent batch selections with explicit host capabilities.
    pub fn resolve_inputs_batch_with(
        &self,
        request: InputResolutionRequest,
        capabilities: InputResolutionCapabilities<'_>,
    ) -> Result<InputResolutionBatchResult, InputResolutionError> {
        self.resolve_inputs_batch_request_with(request.into(), capabilities)
    }

    /// Resolves ordered batch entries with a separate path base for each entry.
    ///
    /// One resolver tracks duplicate identities and aggregate resource use across
    /// all entries. Item-local ordinary selection failures remain in the result.
    pub fn resolve_inputs_batch_request(
        &self,
        request: InputResolutionBatchRequest,
    ) -> Result<InputResolutionBatchResult, InputResolutionError> {
        resolve_inputs_batch_impl(request, InputResolutionCapabilities::default())
    }

    /// Resolves batch entries with per-entry path bases and explicit capabilities.
    pub fn resolve_inputs_batch_request_with(
        &self,
        request: InputResolutionBatchRequest,
        capabilities: InputResolutionCapabilities<'_>,
    ) -> Result<InputResolutionBatchResult, InputResolutionError> {
        resolve_inputs_batch_impl(request, capabilities)
    }
}

fn resolve_inputs_impl(
    request: InputResolutionRequest,
    capabilities: InputResolutionCapabilities<'_>,
) -> Result<InputResolutionResult, InputResolutionError> {
    if request.selections.is_empty() {
        return Err(InputResolutionError::new(
            InputResolutionErrorCode::EmptySelection,
        ));
    }
    if !request.base_directory.is_absolute() {
        return Err(InputResolutionError::new(
            InputResolutionErrorCode::InvalidBaseDirectory,
        ));
    }
    let base_directory = fs::canonicalize(&request.base_directory)
        .map_err(|_| InputResolutionError::new(InputResolutionErrorCode::InvalidBaseDirectory))?;
    if !fs::metadata(&base_directory)
        .map_err(|_| InputResolutionError::new(InputResolutionErrorCode::InvalidBaseDirectory))?
        .is_dir()
    {
        return Err(InputResolutionError::new(
            InputResolutionErrorCode::InvalidBaseDirectory,
        ));
    }

    if request.selections.len() > MAX_INPUT_LIST_ENTRIES {
        return Err(InputResolutionError::new(
            InputResolutionErrorCode::ResourceLimitExceeded,
        ));
    }
    if let Some(control) = capabilities.control {
        control.check_cancelled()?;
    }

    let mut resolver = Resolver::new(
        request.recursive,
        request.follow_symlinks,
        capabilities.split_trust_store,
        capabilities.control,
        capabilities.max_split_validation_bytes,
    );
    for (selection_index, selection) in request.selections.iter().enumerate() {
        resolver.check_cancelled()?;
        match selection {
            InputSelection::Path(path) => {
                let before = resolver.inputs.len();
                let selection = SelectionContext {
                    selection_index,
                    source: InputSelectionSource::Path,
                    selection_path: path.clone(),
                    base_directory: base_directory.clone(),
                    input_list_entry_index: None,
                    input_list_entry_path: None,
                };
                let expanded = resolver.expand_path(path, &base_directory, &selection)?;
                reject_failed_expansion_entries(&expanded)?;
                if resolver.inputs.len() == before {
                    return Err(InputResolutionError::new(
                        InputResolutionErrorCode::EmptySelection,
                    ));
                }
            }
            InputSelection::InputList(path) => {
                let selected_list_path = absolute_path(&base_directory, path);
                let list_parent = selected_list_path
                    .parent()
                    .ok_or_else(|| {
                        InputResolutionError::new(InputResolutionErrorCode::InputUnavailable)
                    })?
                    .to_path_buf();
                let bytes = read_bounded_regular_file(&selected_list_path)?;
                let entries = parse_input_list(&bytes)?;
                resolver.record_input_list(bytes.len(), entries.len())?;
                resolver.check_cancelled()?;
                if entries.is_empty() {
                    return Err(InputResolutionError::new(
                        InputResolutionErrorCode::EmptySelection,
                    ));
                }
                let before_list = resolver.inputs.len();
                for (entry_index, entry_path) in entries.into_iter().enumerate() {
                    resolver.check_cancelled()?;
                    let before_entry = resolver.inputs.len();
                    let selection = SelectionContext {
                        selection_index,
                        source: InputSelectionSource::InputList,
                        selection_path: path.clone(),
                        base_directory: base_directory.clone(),
                        input_list_entry_index: Some(entry_index),
                        input_list_entry_path: Some(entry_path.clone()),
                    };
                    let expanded = resolver.expand_path(&entry_path, &list_parent, &selection)?;
                    reject_failed_expansion_entries(&expanded)?;
                    if resolver.inputs.len() == before_entry {
                        return Err(InputResolutionError::new(
                            InputResolutionErrorCode::EmptySelection,
                        ));
                    }
                }
                if resolver.inputs.len() == before_list {
                    return Err(InputResolutionError::new(
                        InputResolutionErrorCode::EmptySelection,
                    ));
                }
            }
        }
    }

    if resolver.inputs.is_empty() {
        return Err(InputResolutionError::new(
            InputResolutionErrorCode::EmptySelection,
        ));
    }
    Ok(InputResolutionResult {
        inputs: resolver.inputs,
    })
}

fn resolve_inputs_batch_impl(
    request: InputResolutionBatchRequest,
    capabilities: InputResolutionCapabilities<'_>,
) -> Result<InputResolutionBatchResult, InputResolutionError> {
    if request.selections.is_empty() {
        return Err(InputResolutionError::new(
            InputResolutionErrorCode::EmptySelection,
        ));
    }
    if request.selections.len() > MAX_INPUT_LIST_ENTRIES {
        return Err(InputResolutionError::new(
            InputResolutionErrorCode::ResourceLimitExceeded,
        ));
    }
    if let Some(control) = capabilities.control {
        control.check_cancelled()?;
    }
    let base_directories = request
        .selections
        .iter()
        .map(|selection| {
            if let Some(control) = capabilities.control {
                control.check_cancelled()?;
            }
            if !selection.base_directory.is_absolute() {
                return Err(InputResolutionError::new(
                    InputResolutionErrorCode::InvalidBaseDirectory,
                ));
            }
            let base_directory = fs::canonicalize(&selection.base_directory).map_err(|_| {
                InputResolutionError::new(InputResolutionErrorCode::InvalidBaseDirectory)
            })?;
            if !fs::metadata(&base_directory)
                .map_err(|_| {
                    InputResolutionError::new(InputResolutionErrorCode::InvalidBaseDirectory)
                })?
                .is_dir()
            {
                return Err(InputResolutionError::new(
                    InputResolutionErrorCode::InvalidBaseDirectory,
                ));
            }
            #[cfg(test)]
            BASE_DIRECTORY_VALIDATION_CHECKPOINT.with(|checkpoint| {
                if let Some(checkpoint) = checkpoint.borrow_mut().take() {
                    checkpoint();
                }
            });
            if let Some(control) = capabilities.control {
                control.check_cancelled()?;
            }
            Ok(base_directory)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut resolver = Resolver::new(
        request.recursive,
        request.follow_symlinks,
        capabilities.split_trust_store,
        capabilities.control,
        capabilities.max_split_validation_bytes,
    );
    let mut entries = Vec::new();
    for (selection_index, selection) in request.selections.iter().enumerate() {
        resolver.check_cancelled()?;
        let base_directory = &base_directories[selection_index];
        match &selection.selection {
            InputSelection::Path(path) => {
                let context = SelectionContext {
                    selection_index,
                    source: InputSelectionSource::Path,
                    selection_path: path.clone(),
                    base_directory: base_directory.clone(),
                    input_list_entry_index: None,
                    input_list_entry_path: None,
                };
                match resolver.expand_path_for_batch(path, base_directory, &context) {
                    Ok(expanded) if expanded.is_empty() => {
                        entries.push(InputResolutionBatchEntry::Failed(batch_failure(
                            &context,
                            absolute_path(base_directory, path),
                            InputResolutionErrorCode::EmptySelection,
                            None,
                            None,
                        )))
                    }
                    Ok(expanded) => append_expansion_entries(expanded, &context, &mut entries),
                    Err(error) => match error.class() {
                        ExpansionFailureClass::ItemLocal => {
                            entries.push(InputResolutionBatchEntry::Failed(batch_failure(
                                &context,
                                error.requested_path().to_path_buf(),
                                error.code(),
                                None,
                                None,
                            )));
                        }
                        ExpansionFailureClass::Global => return Err(error.into()),
                    },
                }
            }
            InputSelection::InputList(path) => {
                let selected_list_path = absolute_path(base_directory, path);
                let context = SelectionContext {
                    selection_index,
                    source: InputSelectionSource::InputList,
                    selection_path: path.clone(),
                    base_directory: base_directory.clone(),
                    input_list_entry_index: None,
                    input_list_entry_path: None,
                };
                let list_parent = selected_list_path
                    .parent()
                    .ok_or_else(|| {
                        InputResolutionError::new(InputResolutionErrorCode::InputUnavailable)
                    })?
                    .to_path_buf();
                let bytes = read_bounded_regular_file(&selected_list_path)?;
                let listed_entries = parse_input_list(&bytes)?;
                resolver.record_input_list(bytes.len(), listed_entries.len())?;
                resolver.check_cancelled()?;
                if listed_entries.is_empty() {
                    entries.push(InputResolutionBatchEntry::Failed(batch_failure(
                        &context,
                        selected_list_path,
                        InputResolutionErrorCode::EmptySelection,
                        None,
                        None,
                    )));
                    continue;
                }
                for (entry_index, entry_path) in listed_entries.into_iter().enumerate() {
                    resolver.check_cancelled()?;
                    let context = SelectionContext {
                        selection_index,
                        source: InputSelectionSource::InputList,
                        selection_path: path.clone(),
                        base_directory: base_directory.clone(),
                        input_list_entry_index: Some(entry_index),
                        input_list_entry_path: Some(entry_path.clone()),
                    };
                    match resolver.expand_path_for_batch(&entry_path, &list_parent, &context) {
                        Ok(expanded) if expanded.is_empty() => {
                            entries.push(InputResolutionBatchEntry::Failed(batch_failure(
                                &context,
                                absolute_path(&list_parent, &entry_path),
                                InputResolutionErrorCode::EmptySelection,
                                None,
                                None,
                            )))
                        }
                        Ok(expanded) => append_expansion_entries(expanded, &context, &mut entries),
                        Err(error) => match error.class() {
                            ExpansionFailureClass::ItemLocal => {
                                entries.push(InputResolutionBatchEntry::Failed(batch_failure(
                                    &context,
                                    error.requested_path().to_path_buf(),
                                    error.code(),
                                    None,
                                    None,
                                )));
                            }
                            ExpansionFailureClass::Global => return Err(error.into()),
                        },
                    }
                }
            }
        }
    }
    Ok(InputResolutionBatchResult { entries })
}

fn append_expansion_entries(
    expanded: Vec<ExpansionEntry>,
    context: &SelectionContext,
    entries: &mut Vec<InputResolutionBatchEntry>,
) {
    for entry in expanded {
        entries.push(match entry {
            ExpansionEntry::Resolved(input) => InputResolutionBatchEntry::Resolved(*input),
            ExpansionEntry::Failed {
                requested_path,
                code,
                discovered_directory,
                discovered_relative_path,
            } => InputResolutionBatchEntry::Failed(batch_failure(
                context,
                requested_path,
                code,
                discovered_directory,
                discovered_relative_path,
            )),
        });
    }
}

fn reject_failed_expansion_entries(
    expanded: &[ExpansionEntry],
) -> Result<(), InputResolutionError> {
    if let Some(code) = expanded.iter().find_map(|entry| match entry {
        ExpansionEntry::Failed { code, .. } => Some(*code),
        ExpansionEntry::Resolved(_) => None,
    }) {
        return Err(InputResolutionError::new(code));
    }
    Ok(())
}

fn batch_failure(
    context: &SelectionContext,
    requested_path: PathBuf,
    code: InputResolutionErrorCode,
    discovered_directory: Option<PathBuf>,
    discovered_relative_path: Option<PathBuf>,
) -> InputResolutionFailure {
    InputResolutionFailure {
        selection_index: context.selection_index,
        source: context.source,
        selection_path: context.selection_path.clone(),
        base_directory: context.base_directory.clone(),
        input_list_entry_index: context.input_list_entry_index,
        input_list_entry_path: context.input_list_entry_path.clone(),
        discovered_directory,
        discovered_relative_path,
        requested_path,
        code,
    }
}

fn is_item_local_resolution_failure(code: InputResolutionErrorCode, path: &Path) -> bool {
    matches!(
        code,
        InputResolutionErrorCode::EmptySelection | InputResolutionErrorCode::InputUnavailable
    ) && !path
        .file_name()
        .is_some_and(|name| looks_like_split_segment(Path::new(name)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpansionFailureClass {
    ItemLocal,
    Global,
}

#[derive(Debug)]
enum ExpansionEntry {
    Resolved(Box<ResolvedInput>),
    Failed {
        requested_path: PathBuf,
        code: InputResolutionErrorCode,
        discovered_directory: Option<PathBuf>,
        discovered_relative_path: Option<PathBuf>,
    },
}

struct ExpansionError {
    error: InputResolutionError,
    requested_path: PathBuf,
    class: ExpansionFailureClass,
}

impl ExpansionError {
    fn ordinary(error: InputResolutionError, requested_path: PathBuf) -> Self {
        let class = if is_item_local_resolution_failure(error.code(), &requested_path) {
            ExpansionFailureClass::ItemLocal
        } else {
            ExpansionFailureClass::Global
        };
        Self {
            error,
            requested_path,
            class,
        }
    }

    fn split_related(error: InputResolutionError, requested_path: PathBuf) -> Self {
        Self {
            error,
            requested_path,
            class: ExpansionFailureClass::Global,
        }
    }

    fn global(error: InputResolutionError, requested_path: PathBuf) -> Self {
        Self {
            error,
            requested_path,
            class: ExpansionFailureClass::Global,
        }
    }

    fn code(&self) -> InputResolutionErrorCode {
        self.error.code()
    }

    fn class(&self) -> ExpansionFailureClass {
        self.class
    }

    fn requested_path(&self) -> &Path {
        &self.requested_path
    }
}

impl From<ExpansionError> for InputResolutionError {
    fn from(error: ExpansionError) -> Self {
        error.error
    }
}

struct Resolver<'a> {
    recursive: bool,
    follow_symlinks: bool,
    trust_store: Option<&'a dyn SplitTrustStore>,
    control: Option<&'a InputResolutionControl>,
    visited_entries: usize,
    input_list_bytes: u64,
    input_list_entries: usize,
    resolved_segments: usize,
    validated_split_bytes: u64,
    max_split_validation_bytes: u64,
    path_keys: HashSet<String>,
    file_identities: HashSet<FileIdentity>,
    inputs: Vec<ResolvedInput>,
}

struct SelectionContext {
    selection_index: usize,
    source: InputSelectionSource,
    selection_path: PathBuf,
    base_directory: PathBuf,
    input_list_entry_index: Option<usize>,
    input_list_entry_path: Option<PathBuf>,
}

impl<'a> Resolver<'a> {
    fn new(
        recursive: bool,
        follow_symlinks: bool,
        trust_store: Option<&'a dyn SplitTrustStore>,
        control: Option<&'a InputResolutionControl>,
        max_split_validation_bytes: u64,
    ) -> Self {
        Self {
            recursive,
            follow_symlinks,
            trust_store,
            control,
            visited_entries: 0,
            input_list_bytes: 0,
            input_list_entries: 0,
            resolved_segments: 0,
            validated_split_bytes: 0,
            max_split_validation_bytes,
            path_keys: HashSet::new(),
            file_identities: HashSet::new(),
            inputs: Vec::new(),
        }
    }

    fn record_input_list(
        &mut self,
        byte_count: usize,
        entry_count: usize,
    ) -> Result<(), InputResolutionError> {
        self.input_list_bytes = self
            .input_list_bytes
            .checked_add(byte_count as u64)
            .ok_or_else(|| {
                InputResolutionError::new(InputResolutionErrorCode::ResourceLimitExceeded)
            })?;
        self.input_list_entries = self
            .input_list_entries
            .checked_add(entry_count)
            .ok_or_else(|| {
                InputResolutionError::new(InputResolutionErrorCode::ResourceLimitExceeded)
            })?;
        if self.input_list_bytes > MAX_INPUT_LIST_BYTES_PER_REQUEST
            || self.input_list_entries > MAX_INPUT_LIST_ENTRIES
        {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::ResourceLimitExceeded,
            ));
        }
        Ok(())
    }

    fn check_cancelled(&self) -> Result<(), InputResolutionError> {
        if let Some(control) = self.control {
            control.check_cancelled()?;
        }
        Ok(())
    }

    fn record_resolved_segments(&mut self, count: usize) -> Result<(), InputResolutionError> {
        self.resolved_segments = self.resolved_segments.checked_add(count).ok_or_else(|| {
            InputResolutionError::new(InputResolutionErrorCode::ResourceLimitExceeded)
        })?;
        if self.resolved_segments > MAX_RESOLVED_SEGMENTS {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::ResourceLimitExceeded,
            ));
        }
        Ok(())
    }

    fn expand_path_for_batch(
        &mut self,
        path: &Path,
        path_base: &Path,
        selection: &SelectionContext,
    ) -> Result<Vec<ExpansionEntry>, ExpansionError> {
        self.expand_path(path, path_base, selection)
    }

    fn expand_path(
        &mut self,
        path: &Path,
        path_base: &Path,
        selection: &SelectionContext,
    ) -> Result<Vec<ExpansionEntry>, ExpansionError> {
        let selected_path = absolute_path(path_base, path);
        self.check_cancelled()
            .map_err(|error| ExpansionError::ordinary(error, selected_path.clone()))?;
        let link_metadata = fs::symlink_metadata(&selected_path).map_err(|_| {
            ExpansionError::ordinary(
                InputResolutionError::new(InputResolutionErrorCode::InputUnavailable),
                selected_path.clone(),
            )
        })?;
        let is_symlink = link_metadata.file_type().is_symlink();
        let target_metadata = fs::metadata(&selected_path).map_err(|_| {
            ExpansionError::ordinary(
                InputResolutionError::new(InputResolutionErrorCode::InputUnavailable),
                selected_path.clone(),
            )
        })?;

        if target_metadata.is_file() {
            if selected_path
                .file_name()
                .and_then(canonical_member_index)
                .is_some()
            {
                let before = self.inputs.len();
                (|| {
                    if is_symlink {
                        return Err(InputResolutionError::new(
                            InputResolutionErrorCode::SplitSetIncomplete,
                        ));
                    }
                    if !self.follow_symlinks
                        && traverses_intermediate_symlink(&selected_path, path_base)?
                    {
                        return Err(InputResolutionError::new(
                            InputResolutionErrorCode::UnsupportedFilesystemEntry,
                        ));
                    }
                    self.append_split_member(&selected_path, selection)
                })()
                .map_err(|error| ExpansionError::split_related(error, selected_path))?;
                return Ok(vec![ExpansionEntry::Resolved(Box::new(
                    self.inputs[before].clone(),
                ))]);
            }
            let before = self.inputs.len();
            self.append_file(&selected_path, selection, None, None)
                .map_err(|error| ExpansionError::ordinary(error, selected_path))?;
            Ok(vec![ExpansionEntry::Resolved(Box::new(
                self.inputs[before].clone(),
            ))])
        } else if target_metadata.is_dir() {
            if is_symlink && !self.follow_symlinks {
                return Err(ExpansionError::ordinary(
                    InputResolutionError::new(InputResolutionErrorCode::UnsupportedFilesystemEntry),
                    selected_path,
                ));
            }
            let canonical = fs::canonicalize(&selected_path).map_err(|_| {
                ExpansionError::ordinary(
                    InputResolutionError::new(InputResolutionErrorCode::InputUnavailable),
                    selected_path.clone(),
                )
            })?;
            let (has_sidecar, has_canonical_member) = (|| {
                #[cfg(test)]
                ADJACENT_SIDECAR_PROBE_CHECKPOINT.with(|checkpoint| {
                    if let Some(checkpoint) = checkpoint.borrow_mut().take() {
                        checkpoint(&canonical)?;
                    }
                    Ok::<(), InputResolutionError>(())
                })?;
                let has_sidecar = has_adjacent_sidecar(&canonical)?;
                let has_canonical_member = if has_sidecar {
                    false
                } else {
                    #[cfg(test)]
                    CANONICAL_MEMBER_PROBE_CHECKPOINT.with(|checkpoint| {
                        if let Some(checkpoint) = checkpoint.borrow_mut().take() {
                            checkpoint(&canonical)?;
                        }
                        Ok::<(), InputResolutionError>(())
                    })?;
                    directory_has_canonical_member(&canonical)?
                };
                Ok::<_, InputResolutionError>((has_sidecar, has_canonical_member))
            })()
            .map_err(|error| ExpansionError::split_related(error, selected_path.clone()))?;
            if (has_sidecar || has_canonical_member)
                && !self.follow_symlinks
                && traverses_intermediate_symlink(&selected_path, path_base)
                    .map_err(|error| ExpansionError::split_related(error, selected_path.clone()))?
            {
                return Err(ExpansionError::split_related(
                    InputResolutionError::new(InputResolutionErrorCode::UnsupportedFilesystemEntry),
                    selected_path,
                ));
            }
            if has_sidecar {
                let before = self.inputs.len();
                self.append_split_directory(&canonical, selection, None, None)
                    .map_err(|error| ExpansionError::split_related(error, selected_path))?;
                Ok(vec![ExpansionEntry::Resolved(Box::new(
                    self.inputs[before].clone(),
                ))])
            } else if has_canonical_member {
                Err(ExpansionError::split_related(
                    InputResolutionError::new(InputResolutionErrorCode::SplitManifestMissing),
                    selected_path,
                ))
            } else {
                self.expand_directory(&selected_path, selection)
            }
        } else {
            Err(ExpansionError::ordinary(
                InputResolutionError::new(InputResolutionErrorCode::InputUnavailable),
                selected_path,
            ))
        }
    }

    fn expand_directory(
        &mut self,
        selected_path: &Path,
        selection: &SelectionContext,
    ) -> Result<Vec<ExpansionEntry>, ExpansionError> {
        self.check_cancelled()
            .map_err(|error| ExpansionError::ordinary(error, selected_path.to_path_buf()))?;
        let canonical_root = fs::canonicalize(selected_path).map_err(|_| {
            ExpansionError::ordinary(
                InputResolutionError::new(InputResolutionErrorCode::InputUnavailable),
                selected_path.to_path_buf(),
            )
        })?;
        let root_metadata = fs::metadata(&canonical_root).map_err(|_| {
            ExpansionError::ordinary(
                InputResolutionError::new(InputResolutionErrorCode::InputUnavailable),
                canonical_root.clone(),
            )
        })?;
        if !root_metadata.is_dir() {
            return Err(ExpansionError::ordinary(
                InputResolutionError::new(InputResolutionErrorCode::InputUnavailable),
                canonical_root,
            ));
        }

        let mut found = Vec::new();
        let mut visited_directories = HashSet::new();
        let mut active_directories = HashSet::new();
        self.scan_directory(
            &canonical_root,
            &canonical_root,
            Path::new(""),
            0,
            &mut visited_directories,
            &mut active_directories,
            &mut found,
        )?;
        found.sort_by(|left, right| {
            normalized_path_key(left.relative_path())
                .cmp(&normalized_path_key(right.relative_path()))
                .then_with(|| {
                    raw_path_key(left.relative_path()).cmp(&raw_path_key(right.relative_path()))
                })
        });
        self.check_cancelled()
            .map_err(|error| ExpansionError::ordinary(error, selected_path.to_path_buf()))?;

        if found.is_empty() {
            return Err(ExpansionError::ordinary(
                InputResolutionError::new(InputResolutionErrorCode::EmptySelection),
                canonical_root,
            ));
        }
        let mut outcomes = Vec::with_capacity(found.len());
        for candidate in found {
            self.check_cancelled()
                .map_err(|error| ExpansionError::ordinary(error, canonical_root.clone()))?;
            match candidate {
                FoundInput::File(candidate) => {
                    let before = self.inputs.len();
                    let failure_path = candidate.canonical_path.clone();
                    let failure_relative_path = candidate.relative_path.clone();
                    let append =
                        observe_append_file_fault(&candidate.canonical_path).and_then(|()| {
                            self.append_known_file(
                                candidate.canonical_path,
                                candidate.size,
                                candidate.file_identity,
                                selection,
                                Some(canonical_root.clone()),
                                Some(candidate.relative_path),
                            )
                        });
                    match append {
                        Ok(()) => outcomes.push(ExpansionEntry::Resolved(Box::new(
                            self.inputs[before].clone(),
                        ))),
                        Err(error) => {
                            let error = ExpansionError::ordinary(error, failure_path);
                            match error.class() {
                                ExpansionFailureClass::ItemLocal => {
                                    outcomes.push(ExpansionEntry::Failed {
                                        requested_path: error.requested_path().to_path_buf(),
                                        code: error.code(),
                                        discovered_directory: Some(canonical_root.clone()),
                                        discovered_relative_path: Some(failure_relative_path),
                                    });
                                }
                                ExpansionFailureClass::Global => return Err(error),
                            }
                        }
                    }
                }
                FoundInput::Split {
                    canonical_directory,
                    relative_path,
                } => {
                    let before = self.inputs.len();
                    self.append_split_directory(
                        &canonical_directory,
                        selection,
                        Some(canonical_root.clone()),
                        Some(relative_path),
                    )
                    .map_err(|error| ExpansionError::split_related(error, canonical_directory))?;
                    outcomes.push(ExpansionEntry::Resolved(Box::new(
                        self.inputs[before].clone(),
                    )));
                }
                FoundInput::Failed(failure) => outcomes.push(ExpansionEntry::Failed {
                    requested_path: failure.requested_path,
                    code: failure.code,
                    discovered_directory: Some(canonical_root.clone()),
                    discovered_relative_path: Some(failure.relative_path),
                }),
            }
        }
        Ok(outcomes)
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_directory(
        &mut self,
        root: &Path,
        directory: &Path,
        relative_directory: &Path,
        depth: usize,
        visited_directories: &mut HashSet<DirectoryIdentity>,
        active_directories: &mut HashSet<DirectoryIdentity>,
        found: &mut Vec<FoundInput>,
    ) -> Result<(), ExpansionError> {
        self.check_cancelled()
            .map_err(|error| ExpansionError::ordinary(error, directory.to_path_buf()))?;
        if depth > MAX_TRAVERSAL_DEPTH {
            return Err(ExpansionError::ordinary(
                InputResolutionError::new(InputResolutionErrorCode::ResourceLimitExceeded),
                directory.to_path_buf(),
            ));
        }
        let metadata = fs::metadata(directory).map_err(|_| {
            ExpansionError::global(
                InputResolutionError::new(InputResolutionErrorCode::InputUnavailable),
                directory.to_path_buf(),
            )
        })?;
        let identity = directory_identity(directory, &metadata);
        if active_directories.contains(&identity) {
            return Ok(());
        }
        if !visited_directories.insert(identity.clone()) {
            return Err(ExpansionError::ordinary(
                InputResolutionError::new(InputResolutionErrorCode::DuplicateSelection),
                directory.to_path_buf(),
            ));
        }
        active_directories.insert(identity.clone());

        let mut entries = read_directory(directory, &mut self.visited_entries)
            .map_err(|error| ExpansionError::global(error, directory.to_path_buf()))?;
        entries.sort_by(|left, right| {
            let left_name = left.file_name();
            let right_name = right.file_name();
            normalized_os_component_key(&left_name)
                .cmp(&normalized_os_component_key(&right_name))
                .then_with(|| raw_os_key(&left_name).cmp(&raw_os_key(&right_name)))
        });

        for entry in entries {
            let name = entry.file_name();
            let encountered_path = directory.join(&name);
            #[cfg(test)]
            SCAN_DIRECTORY_ENTRY_CHECKPOINT.with(|checkpoint| {
                let mut checkpoint = checkpoint.borrow_mut();
                let completed = checkpoint
                    .as_mut()
                    .is_some_and(|checkpoint| checkpoint(&encountered_path));
                if completed {
                    checkpoint.take();
                }
            });
            self.check_cancelled()
                .map_err(|error| ExpansionError::ordinary(error, encountered_path.clone()))?;
            let relative_path = relative_directory.join(&name);
            let failure_relative_path = relative_path.clone();
            let scan_result = (|| {
                let file_type = entry.file_type().map_err(|_| {
                    ExpansionError::global(
                        InputResolutionError::new(InputResolutionErrorCode::InputUnavailable),
                        encountered_path.clone(),
                    )
                })?;

                if file_type.is_symlink() {
                    if !self.follow_symlinks {
                        return Ok(());
                    }
                    let suspected_split = looks_like_split_segment(&encountered_path);
                    let discovery_candidate = is_discovery_candidate(&encountered_path);
                    if !self.recursive && !discovery_candidate && !suspected_split {
                        return Ok(());
                    }
                    let target = fs::canonicalize(&encountered_path).map_err(|_| {
                        let error =
                            InputResolutionError::new(InputResolutionErrorCode::InputUnavailable);
                        if suspected_split {
                            ExpansionError::split_related(error, encountered_path.clone())
                        } else if !self.recursive && discovery_candidate {
                            ExpansionError::ordinary(error, encountered_path.clone())
                        } else {
                            ExpansionError::global(error, encountered_path.clone())
                        }
                    })?;
                    let target_metadata = fs::metadata(&target).map_err(|_| {
                        let error =
                            InputResolutionError::new(InputResolutionErrorCode::InputUnavailable);
                        ExpansionError::global(error, encountered_path.clone())
                    })?;
                    if target_metadata.is_dir() {
                        if self.recursive {
                            if !target.starts_with(root) {
                                return Err(ExpansionError::ordinary(
                                    InputResolutionError::new(
                                        InputResolutionErrorCode::UnsupportedFilesystemEntry,
                                    ),
                                    target,
                                ));
                            }
                            if has_adjacent_sidecar(&target).map_err(|error| {
                                ExpansionError::split_related(error, target.clone())
                            })? {
                                found.push(FoundInput::Split {
                                    canonical_directory: target,
                                    relative_path,
                                });
                            } else {
                                self.scan_directory(
                                    root,
                                    &target,
                                    &relative_path,
                                    depth + 1,
                                    visited_directories,
                                    active_directories,
                                    found,
                                )?;
                            }
                        }
                    } else if target_metadata.is_file() {
                        if suspected_split || looks_like_split_segment(&target) {
                            return Err(ExpansionError::split_related(
                                InputResolutionError::new(
                                    InputResolutionErrorCode::UnsupportedSplitLayout,
                                ),
                                target,
                            ));
                        }
                        if discovery_candidate {
                            if !target.starts_with(root) {
                                return Err(ExpansionError::ordinary(
                                    InputResolutionError::new(
                                        InputResolutionErrorCode::UnsupportedFilesystemEntry,
                                    ),
                                    target,
                                ));
                            }
                            found.push(FoundInput::File(
                                found_file(&target, &target_metadata, relative_path).map_err(
                                    |error| ExpansionError::global(error, target.clone()),
                                )?,
                            ));
                        }
                    } else if discovery_candidate || suspected_split {
                        return Err(ExpansionError::ordinary(
                            InputResolutionError::new(
                                InputResolutionErrorCode::UnsupportedFilesystemEntry,
                            ),
                            target,
                        ));
                    }
                    return Ok(());
                }

                if file_type.is_dir() {
                    if has_adjacent_sidecar(&encountered_path).map_err(|error| {
                        ExpansionError::split_related(error, encountered_path.clone())
                    })? {
                        let canonical = fs::canonicalize(&encountered_path).map_err(|_| {
                            ExpansionError::split_related(
                                InputResolutionError::new(
                                    InputResolutionErrorCode::InputUnavailable,
                                ),
                                encountered_path.clone(),
                            )
                        })?;
                        if !canonical.starts_with(root) {
                            return Err(ExpansionError::split_related(
                                InputResolutionError::new(
                                    InputResolutionErrorCode::UnsupportedFilesystemEntry,
                                ),
                                canonical,
                            ));
                        }
                        found.push(FoundInput::Split {
                            canonical_directory: canonical,
                            relative_path,
                        });
                    } else if self.recursive {
                        let canonical = fs::canonicalize(&encountered_path).map_err(|_| {
                            ExpansionError::global(
                                InputResolutionError::new(
                                    InputResolutionErrorCode::InputUnavailable,
                                ),
                                encountered_path.clone(),
                            )
                        })?;
                        if !canonical.starts_with(root) {
                            return Err(ExpansionError::ordinary(
                                InputResolutionError::new(
                                    InputResolutionErrorCode::UnsupportedFilesystemEntry,
                                ),
                                canonical,
                            ));
                        }
                        self.scan_directory(
                            root,
                            &canonical,
                            &relative_path,
                            depth + 1,
                            visited_directories,
                            active_directories,
                            found,
                        )?;
                    }
                } else if file_type.is_file() {
                    if looks_like_split_segment(&encountered_path) {
                        return Err(ExpansionError::split_related(
                            InputResolutionError::new(
                                InputResolutionErrorCode::UnsupportedSplitLayout,
                            ),
                            encountered_path,
                        ));
                    }
                    if is_discovery_candidate(&encountered_path) {
                        let canonical = fs::canonicalize(&encountered_path).map_err(|_| {
                            ExpansionError::ordinary(
                                InputResolutionError::new(
                                    InputResolutionErrorCode::InputUnavailable,
                                ),
                                encountered_path.clone(),
                            )
                        })?;
                        if !canonical.starts_with(root) {
                            return Err(ExpansionError::ordinary(
                                InputResolutionError::new(
                                    InputResolutionErrorCode::UnsupportedFilesystemEntry,
                                ),
                                canonical,
                            ));
                        }
                        let metadata = fs::metadata(&canonical).map_err(|_| {
                            ExpansionError::ordinary(
                                InputResolutionError::new(
                                    InputResolutionErrorCode::InputUnavailable,
                                ),
                                canonical.clone(),
                            )
                        })?;
                        if looks_like_split_segment(&canonical) {
                            return Err(ExpansionError::split_related(
                                InputResolutionError::new(
                                    InputResolutionErrorCode::UnsupportedSplitLayout,
                                ),
                                canonical,
                            ));
                        }
                        found.push(FoundInput::File(
                            found_file(&canonical, &metadata, relative_path).map_err(|error| {
                                ExpansionError::ordinary(error, canonical.clone())
                            })?,
                        ));
                    }
                } else if is_discovery_candidate(&encountered_path) {
                    return Err(ExpansionError::ordinary(
                        InputResolutionError::new(
                            InputResolutionErrorCode::UnsupportedFilesystemEntry,
                        ),
                        encountered_path,
                    ));
                }
                Ok(())
            })();
            match scan_result {
                Ok(()) => {}
                Err(error) if error.class() == ExpansionFailureClass::ItemLocal => {
                    found.push(FoundInput::Failed(FoundFailure {
                        relative_path: failure_relative_path,
                        requested_path: error.requested_path().to_path_buf(),
                        code: error.code(),
                    }));
                }
                Err(error) => return Err(error),
            }
        }

        active_directories.remove(&identity);
        Ok(())
    }

    fn append_split_member(
        &mut self,
        member: &Path,
        selection: &SelectionContext,
    ) -> Result<(), InputResolutionError> {
        let canonical_member = fs::canonicalize(member)
            .map_err(|_| InputResolutionError::new(InputResolutionErrorCode::InputUnavailable))?;
        let metadata = fs::metadata(&canonical_member)
            .map_err(|_| InputResolutionError::new(InputResolutionErrorCode::InputUnavailable))?;
        if !metadata.is_file() {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::SplitSetIncomplete,
            ));
        }
        let directory = canonical_member.parent().ok_or_else(|| {
            InputResolutionError::new(InputResolutionErrorCode::SplitSetIncomplete)
        })?;
        self.append_split_directory(directory, selection, None, None)
    }

    fn append_split_directory(
        &mut self,
        directory: &Path,
        selection: &SelectionContext,
        discovered_directory: Option<PathBuf>,
        discovered_relative_path: Option<PathBuf>,
    ) -> Result<(), InputResolutionError> {
        #[cfg(test)]
        if let Some(checkpoint) =
            SPLIT_QUALIFICATION_CHECKPOINT.with(|checkpoint| checkpoint.borrow_mut().take())
        {
            checkpoint(directory, selection)?;
        }

        let input_index = self.inputs.len();
        let qualified = {
            let mut context = SplitResolutionContext {
                trust_store: self.trust_store,
                control: self.control,
                visited_entries: &mut self.visited_entries,
                validated_bytes: &mut self.validated_split_bytes,
                max_validated_bytes: self.max_split_validation_bytes,
                input_index,
            };
            qualify_directory(directory, &mut context)?
        };
        self.record_resolved_segments(qualified.segments.len())?;
        let split_manifest_sha256 = qualified.manifest_sha256;

        let mut segments = Vec::with_capacity(qualified.segments.len());
        for segment in qualified.segments {
            let path_key = normalized_path_key(&segment.path);
            if !self.path_keys.insert(path_key) {
                return Err(InputResolutionError::new(
                    InputResolutionErrorCode::DuplicateSelection,
                ));
            }
            let identity = segment.identity.ok_or_else(|| {
                InputResolutionError::new(InputResolutionErrorCode::SplitSetIncomplete)
            })?;
            if !self.file_identities.insert(identity) {
                return Err(InputResolutionError::new(
                    InputResolutionErrorCode::DuplicateSelection,
                ));
            }
            segments.push(InputSegment {
                path: segment.path,
                size: segment.size,
            });
        }

        self.inputs.push(ResolvedInput {
            segments,
            provenance: InputProvenance {
                selection_index: selection.selection_index,
                source: selection.source,
                selection_path: selection.selection_path.clone(),
                base_directory: selection.base_directory.clone(),
                input_list_entry_index: selection.input_list_entry_index,
                input_list_entry_path: selection.input_list_entry_path.clone(),
                discovered_directory,
                discovered_relative_path,
            },
            qualification: Some(qualified.qualification),
            split_manifest_sha256: Some(split_manifest_sha256),
        });
        Ok(())
    }

    fn append_file(
        &mut self,
        path: &Path,
        selection: &SelectionContext,
        discovered_directory: Option<PathBuf>,
        discovered_relative_path: Option<PathBuf>,
    ) -> Result<(), InputResolutionError> {
        let metadata = fs::metadata(path)
            .map_err(|_| InputResolutionError::new(InputResolutionErrorCode::InputUnavailable))?;
        if !metadata.is_file() {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::InputUnavailable,
            ));
        }
        if looks_like_split_segment(path) {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::UnsupportedSplitLayout,
            ));
        }
        let canonical_path = fs::canonicalize(path)
            .map_err(|_| InputResolutionError::new(InputResolutionErrorCode::InputUnavailable))?;
        let metadata = fs::metadata(&canonical_path)
            .map_err(|_| InputResolutionError::new(InputResolutionErrorCode::InputUnavailable))?;
        if !metadata.is_file() {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::InputUnavailable,
            ));
        }
        if looks_like_split_segment(&canonical_path) {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::UnsupportedSplitLayout,
            ));
        }
        let file_identity = path_identity(&canonical_path);
        self.append_known_file(
            canonical_path,
            metadata.len(),
            file_identity,
            selection,
            discovered_directory,
            discovered_relative_path,
        )
    }

    fn append_known_file(
        &mut self,
        canonical_path: PathBuf,
        size: u64,
        file_identity: Option<FileIdentity>,
        selection: &SelectionContext,
        discovered_directory: Option<PathBuf>,
        discovered_relative_path: Option<PathBuf>,
    ) -> Result<(), InputResolutionError> {
        let path_key = normalized_path_key(&canonical_path);
        if !self.path_keys.insert(path_key) {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::DuplicateSelection,
            ));
        }
        if let Some(identity) = file_identity
            && !self.file_identities.insert(identity)
        {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::DuplicateSelection,
            ));
        }
        self.record_resolved_segments(1)?;
        self.inputs.push(ResolvedInput {
            segments: vec![InputSegment {
                path: canonical_path,
                size,
            }],
            provenance: InputProvenance {
                selection_index: selection.selection_index,
                source: selection.source,
                selection_path: selection.selection_path.clone(),
                base_directory: selection.base_directory.clone(),
                input_list_entry_index: selection.input_list_entry_index,
                input_list_entry_path: selection.input_list_entry_path.clone(),
                discovered_directory,
                discovered_relative_path,
            },
            qualification: None,
            split_manifest_sha256: None,
        });
        Ok(())
    }
}

enum FoundInput {
    File(FoundFile),
    Split {
        canonical_directory: PathBuf,
        relative_path: PathBuf,
    },
    Failed(FoundFailure),
}

struct FoundFailure {
    relative_path: PathBuf,
    requested_path: PathBuf,
    code: InputResolutionErrorCode,
}

impl FoundInput {
    fn relative_path(&self) -> &Path {
        match self {
            Self::File(file) => &file.relative_path,
            Self::Split { relative_path, .. } => relative_path,
            Self::Failed(failure) => &failure.relative_path,
        }
    }
}

struct FoundFile {
    canonical_path: PathBuf,
    size: u64,
    file_identity: Option<FileIdentity>,
    relative_path: PathBuf,
}

fn found_file(
    path: &Path,
    metadata: &Metadata,
    relative_path: PathBuf,
) -> Result<FoundFile, InputResolutionError> {
    if !metadata.is_file() {
        return Err(InputResolutionError::new(
            InputResolutionErrorCode::InputUnavailable,
        ));
    }
    Ok(FoundFile {
        canonical_path: path.to_path_buf(),
        size: metadata.len(),
        file_identity: path_identity(path),
        relative_path,
    })
}

pub(crate) fn read_directory(
    path: &Path,
    visited_entries: &mut usize,
) -> Result<Vec<fs::DirEntry>, InputResolutionError> {
    let iterator = fs::read_dir(path)
        .map_err(|_| InputResolutionError::new(InputResolutionErrorCode::InputUnavailable))?;
    collect_bounded_entries(iterator, visited_entries)
}

fn collect_bounded_entries(
    iterator: ReadDir,
    visited_entries: &mut usize,
) -> Result<Vec<fs::DirEntry>, InputResolutionError> {
    let mut entries = Vec::new();
    for entry in iterator {
        *visited_entries = visited_entries.checked_add(1).ok_or_else(|| {
            InputResolutionError::new(InputResolutionErrorCode::ResourceLimitExceeded)
        })?;
        if *visited_entries > MAX_TRAVERSAL_ENTRIES {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::ResourceLimitExceeded,
            ));
        }
        entries.push(
            entry.map_err(|_| {
                InputResolutionError::new(InputResolutionErrorCode::InputUnavailable)
            })?,
        );
    }
    Ok(entries)
}

fn read_bounded_regular_file(path: &Path) -> Result<Vec<u8>, InputResolutionError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NONBLOCK);
    let file = options
        .open(path)
        .map_err(|_| InputResolutionError::new(InputResolutionErrorCode::InputUnavailable))?;
    let metadata = file
        .metadata()
        .map_err(|_| InputResolutionError::new(InputResolutionErrorCode::InputUnavailable))?;
    if !metadata.is_file() {
        return Err(InputResolutionError::new(
            InputResolutionErrorCode::InputUnavailable,
        ));
    }
    if metadata.len() > MAX_INPUT_LIST_BYTES {
        return Err(InputResolutionError::new(
            InputResolutionErrorCode::ResourceLimitExceeded,
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let read_result = file.take(MAX_INPUT_LIST_BYTES + 1).read_to_end(&mut bytes);
    read_result
        .map_err(|_| InputResolutionError::new(InputResolutionErrorCode::InputUnavailable))?;
    if bytes.len() as u64 > MAX_INPUT_LIST_BYTES {
        return Err(InputResolutionError::new(
            InputResolutionErrorCode::ResourceLimitExceeded,
        ));
    }
    Ok(bytes)
}

fn parse_input_list(bytes: &[u8]) -> Result<Vec<PathBuf>, InputResolutionError> {
    let document = strict_json::parse(bytes)
        .map_err(|_| InputResolutionError::new(InputResolutionErrorCode::InvalidInputList))?;
    let fields = match document {
        StrictJsonValue::Object(fields) => fields,
        _ => {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::InvalidInputList,
            ));
        }
    };

    let version = required_field(&fields, "schema_version")?;
    match version {
        StrictJsonValue::Number(number) if number.as_u64() == Some(1) => {}
        StrictJsonValue::Number(number) if number.as_u64().is_some() => {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::UnsupportedInputListVersion,
            ));
        }
        _ => {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::InvalidInputList,
            ));
        }
    }
    match required_field(&fields, "kind")? {
        StrictJsonValue::String(kind) if kind == "nscb.input_list" => {}
        _ => {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::InvalidInputList,
            ));
        }
    }
    let required_features = match required_field(&fields, "required_features")? {
        StrictJsonValue::Array(features) => features,
        _ => {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::InvalidInputList,
            ));
        }
    };
    let mut unique_features = HashSet::new();
    let mut has_unsupported_feature = false;
    for feature in required_features {
        let StrictJsonValue::String(feature) = feature else {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::InvalidInputList,
            ));
        };
        if !unique_features.insert(feature.as_str()) {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::InvalidInputList,
            ));
        }
        has_unsupported_feature = true;
    }
    if has_unsupported_feature {
        return Err(InputResolutionError::new(
            InputResolutionErrorCode::UnsupportedRequiredFeature,
        ));
    }

    let entries = match required_field(&fields, "entries")? {
        StrictJsonValue::Array(entries) => entries,
        _ => {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::InvalidInputList,
            ));
        }
    };
    if entries.len() > MAX_INPUT_LIST_ENTRIES {
        return Err(InputResolutionError::new(
            InputResolutionErrorCode::ResourceLimitExceeded,
        ));
    }
    let mut paths = Vec::with_capacity(entries.len());
    for entry in entries {
        let StrictJsonValue::Object(entry_fields) = entry else {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::InvalidInputList,
            ));
        };
        let StrictJsonValue::String(path) = required_field(entry_fields, "path")? else {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::InvalidInputList,
            ));
        };
        if path.is_empty() {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::InvalidInputList,
            ));
        }
        paths.push(PathBuf::from(path));
    }
    Ok(paths)
}

fn required_field<'a>(
    fields: &'a [(String, StrictJsonValue)],
    name: &str,
) -> Result<&'a StrictJsonValue, InputResolutionError> {
    strict_json::required_field(fields, name)
        .ok_or_else(|| InputResolutionError::new(InputResolutionErrorCode::InvalidInputList))
}

fn absolute_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

/// Reports whether an intermediate component of an explicit Split candidate
/// traverses a symlink.
///
/// The final component is handled separately because a symlinked member has
/// different semantics from a member reached through a symlinked parent.
/// Every intermediate component is inspected, including components above an
/// absolute path outside the request base. Known macOS filesystem aliases
/// (`/tmp`, `/var`, and `/etc`) are ignored so platform path normalization
/// does not require traversal permission.
fn traverses_intermediate_symlink(path: &Path, base: &Path) -> Result<bool, InputResolutionError> {
    let mut ancestors = Vec::new();
    let mut current = path.parent();
    while let Some(parent) = current {
        if parent == base {
            break;
        }
        ancestors.push(parent.to_path_buf());
        current = parent.parent();
    }
    for ancestor in ancestors.iter().rev() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata)
                if metadata.file_type().is_symlink() && !is_platform_directory_alias(ancestor) =>
            {
                return Ok(true);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                return Err(InputResolutionError::new(
                    InputResolutionErrorCode::InputUnavailable,
                ));
            }
        }
    }
    Ok(false)
}

fn is_platform_directory_alias(path: &Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        matches!(path.to_str(), Some("/tmp" | "/var" | "/etc"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        false
    }
}

fn is_discovery_candidate(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            DISCOVERABLE_EXTENSIONS
                .iter()
                .any(|candidate| extension.eq_ignore_ascii_case(candidate))
        })
}

pub(crate) fn looks_like_split_segment(path: &Path) -> bool {
    let Some(name) = path.file_name().map(|name| name.to_string_lossy()) else {
        return false;
    };
    if !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit()) {
        return true;
    }
    let Some((stem, extension)) = name.rsplit_once('.') else {
        return false;
    };
    if !extension.is_empty() && extension.bytes().all(|byte| byte.is_ascii_digit()) {
        return true;
    }
    let extension = extension.to_ascii_lowercase();
    let legacy_numbered = ["xc", "ns"].iter().any(|prefix| {
        extension.strip_prefix(prefix).is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
    });
    if legacy_numbered {
        return true;
    }
    let ordinary_extension = DISCOVERABLE_EXTENSIONS
        .iter()
        .any(|candidate| extension.eq_ignore_ascii_case(candidate));
    ordinary_extension
        && stem.rsplit_once('.').is_some_and(|(prefix, number)| {
            !prefix.is_empty()
                && !number.is_empty()
                && number.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn directory_identity(path: &Path, _metadata: &Metadata) -> DirectoryIdentity {
    DirectoryIdentity {
        path_key: normalized_path_key(path),
        file_identity: path_identity(path),
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DirectoryIdentity {
    path_key: String,
    file_identity: Option<FileIdentity>,
}

fn normalized_path_key(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Prefix(prefix) => Some(format!(
                "prefix:{}",
                normalized_os_component_key(prefix.as_os_str())
            )),
            Component::RootDir => Some("root".to_owned()),
            Component::CurDir => None,
            Component::ParentDir => Some("parent".to_owned()),
            Component::Normal(name) => Some(normalized_os_component_key(name)),
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn normalized_os_component_key(value: &std::ffi::OsStr) -> String {
    if let Some(value) = value.to_str() {
        let lower: String = value.nfc().flat_map(char::to_lowercase).collect();
        format!("unicode:{}", lower.nfc().collect::<String>())
    } else {
        format!("bytes:{}", raw_os_key(value))
    }
}

fn raw_path_key(path: &Path) -> String {
    raw_os_key(path.as_os_str())
}

#[cfg(unix)]
fn raw_os_key(value: &std::ffi::OsStr) -> String {
    use std::os::unix::ffi::OsStrExt;
    hex_key(value.as_bytes())
}

#[cfg(windows)]
fn raw_os_key(value: &std::ffi::OsStr) -> String {
    use std::os::windows::ffi::OsStrExt;
    let bytes = value
        .encode_wide()
        .flat_map(u16::to_be_bytes)
        .collect::<Vec<_>>();
    hex_key(&bytes)
}

#[cfg(not(any(unix, windows)))]
fn raw_os_key(value: &std::ffi::OsStr) -> String {
    hex_key(value.to_string_lossy().as_bytes())
}

fn hex_key(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[usize::from(byte >> 4)] as char);
        result.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    result
}

#[cfg(test)]
type SplitQualificationCheckpoint =
    dyn FnOnce(&Path, &SelectionContext) -> Result<(), InputResolutionError>;

#[cfg(test)]
type SplitProbeCheckpoint = dyn FnOnce(&Path) -> Result<(), InputResolutionError>;

#[cfg(test)]
type AppendFileFaultCheckpoint = dyn FnMut(&Path) -> Result<bool, InputResolutionError>;

#[cfg(test)]
type ScanDirectoryEntryCheckpoint = dyn FnMut(&Path) -> bool;

#[cfg(test)]
thread_local! {
    static SCAN_DIRECTORY_ENTRY_CHECKPOINT:
        std::cell::RefCell<Option<Box<ScanDirectoryEntryCheckpoint>>> = const {
            std::cell::RefCell::new(None)
        };
    static BASE_DIRECTORY_VALIDATION_CHECKPOINT:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const {
            std::cell::RefCell::new(None)
        };
    static SPLIT_QUALIFICATION_CHECKPOINT:
        std::cell::RefCell<Option<Box<SplitQualificationCheckpoint>>> = const {
            std::cell::RefCell::new(None)
        };
static ADJACENT_SIDECAR_PROBE_CHECKPOINT: std::cell::RefCell<Option<Box<SplitProbeCheckpoint>>> =
    const { std::cell::RefCell::new(None) };
static CANONICAL_MEMBER_PROBE_CHECKPOINT: std::cell::RefCell<Option<Box<SplitProbeCheckpoint>>> =
    const { std::cell::RefCell::new(None) };
static APPEND_FILE_FAULT_CHECKPOINT: std::cell::RefCell<Option<Box<AppendFileFaultCheckpoint>>> =
    const { std::cell::RefCell::new(None) };
}

fn observe_append_file_fault(path: &Path) -> Result<(), InputResolutionError> {
    #[cfg(test)]
    APPEND_FILE_FAULT_CHECKPOINT.with(|checkpoint| {
        let mut checkpoint = checkpoint.borrow_mut();
        let result = match checkpoint.as_mut() {
            Some(checkpoint) => checkpoint(path),
            None => Ok(false),
        };
        match result {
            Ok(true) => {
                checkpoint.take();
                Ok(())
            }
            Err(error) => {
                checkpoint.take();
                Err(error)
            }
            Ok(false) => Ok(()),
        }
    })?;
    #[cfg(not(test))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_MAX_SPLIT_VALIDATION_BYTES, InputResolutionCapabilities, InputResolutionControl,
        MAX_INPUT_LIST_BYTES_PER_REQUEST, MAX_INPUT_LIST_ENTRIES, MAX_TRAVERSAL_DEPTH,
        MAX_TRAVERSAL_ENTRIES, Resolver, parse_input_list,
    };
    use crate::input_resolution::{
        ADJACENT_SIDECAR_PROBE_CHECKPOINT, APPEND_FILE_FAULT_CHECKPOINT,
        BASE_DIRECTORY_VALIDATION_CHECKPOINT, CANONICAL_MEMBER_PROBE_CHECKPOINT,
        InputResolutionError, InputResolutionErrorCode, SCAN_DIRECTORY_ENTRY_CHECKPOINT,
        SPLIT_QUALIFICATION_CHECKPOINT,
    };
    use crate::inspection::CancellationHandle;
    use crate::{LocalSplitTrustStore, Sha256Digest, SplitTrustReceipt, SplitTrustWriter};
    use std::collections::HashSet;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn resolver() -> Resolver<'static> {
        Resolver::new(
            false,
            false,
            InputResolutionCapabilities::default().split_trust_store,
            None,
            DEFAULT_MAX_SPLIT_VALIDATION_BYTES,
        )
    }

    fn queue_split_qualification_failure(
        expected_source: super::InputSelectionSource,
        expected_entry_index: Option<usize>,
        expected_entry_path: Option<&'static str>,
    ) {
        let expected_entry_path = expected_entry_path.map(std::path::PathBuf::from);
        SPLIT_QUALIFICATION_CHECKPOINT.with(|checkpoint| {
            let previous =
                checkpoint
                    .borrow_mut()
                    .replace(Box::new(move |directory, selection| {
                        assert_eq!(
                            directory.file_name().and_then(|name| name.to_str()),
                            Some("Game.nsp")
                        );
                        assert_eq!(selection.source, expected_source);
                        assert_eq!(selection.input_list_entry_index, expected_entry_index);
                        assert_eq!(selection.input_list_entry_path, expected_entry_path);
                        Err(InputResolutionError::new(
                            InputResolutionErrorCode::InputUnavailable,
                        ))
                    }));
            assert!(previous.is_none(), "checkpoint was already queued");
        });
    }

    fn write_recognized_split_candidate(root: &Path) -> std::path::PathBuf {
        let directory = root.join("Game.nsp");
        std::fs::create_dir_all(&directory).expect("create recognized Split directory");
        std::fs::write(directory.join("00"), b"member").expect("write Split member");
        std::fs::write(root.join("Game.nsp.nscb-split.json"), b"fixture")
            .expect("write adjacent Split sidecar");
        directory
    }

    fn write_unqualified_split_candidate(root: &Path) -> PathBuf {
        let directory = root.join("Game.nsp");
        std::fs::create_dir_all(&directory).expect("create canonical member directory");
        std::fs::write(directory.join("00"), b"member").expect("write canonical member");
        directory
    }

    fn write_qualified_split_fixture(root: &Path) -> (PathBuf, LocalSplitTrustStore) {
        let directory = root.join("Game.nsp");
        let source = b"qualified batch source";
        let parts: [&[u8]; 2] = [&source[..8], &source[8..]];
        std::fs::create_dir_all(&directory).expect("create qualified Split directory");
        for (index, part) in parts.iter().enumerate() {
            std::fs::write(directory.join(format!("{index:02}")), part)
                .expect("write qualified Split part");
        }
        let manifest = serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": 1,
            "kind": "nscb.split_manifest",
            "required_features": [],
            "source": {
                "size_bytes": source.len(),
                "sha256": Sha256Digest::digest(source).to_hex(),
            },
            "segments": parts
                .iter()
                .enumerate()
                .map(|(index, part)| serde_json::json!({
                    "name": format!("{index:02}"),
                    "size_bytes": part.len(),
                    "sha256": Sha256Digest::digest(part).to_hex(),
                }))
                .collect::<Vec<_>>(),
        }))
        .expect("serialize qualified Split manifest");
        std::fs::write(root.join("Game.nsp.nscb-split.json"), &manifest)
            .expect("write qualified Split sidecar");

        let store = LocalSplitTrustStore::new(root.join("state").join("split-trust"));
        store
            .issue(SplitTrustReceipt::new(
                Sha256Digest::digest(&manifest),
                source.len() as u64,
                Sha256Digest::digest(source),
            ))
            .expect("issue qualified Split receipt");
        (directory, store)
    }

    fn queue_adjacent_sidecar_probe_failure(expected_path: PathBuf) {
        ADJACENT_SIDECAR_PROBE_CHECKPOINT.with(|checkpoint| {
            let previous = checkpoint.borrow_mut().replace(Box::new(move |path| {
                assert_eq!(path, expected_path);
                Err(InputResolutionError::new(
                    InputResolutionErrorCode::InputUnavailable,
                ))
            }));
            assert!(previous.is_none(), "checkpoint was already queued");
        });
    }

    fn queue_canonical_member_probe_failure(expected_path: PathBuf) {
        CANONICAL_MEMBER_PROBE_CHECKPOINT.with(|checkpoint| {
            let previous = checkpoint.borrow_mut().replace(Box::new(move |path| {
                assert_eq!(path, expected_path);
                Err(InputResolutionError::new(
                    InputResolutionErrorCode::InputUnavailable,
                ))
            }));
            assert!(previous.is_none(), "checkpoint was already queued");
        });
    }

    fn queue_append_file_failure(expected_path: PathBuf) {
        APPEND_FILE_FAULT_CHECKPOINT.with(|checkpoint| {
            let previous = checkpoint.borrow_mut().replace(Box::new(move |path| {
                if path != expected_path {
                    return Ok(false);
                }
                Err(InputResolutionError::new(
                    InputResolutionErrorCode::InputUnavailable,
                ))
            }));
            assert!(previous.is_none(), "checkpoint was already queued");
        });
    }

    #[test]
    fn batch_resolution_rejects_an_adjacent_sidecar_probe_error_for_a_direct_directory() {
        let tree = tempfile::tempdir().expect("create direct sidecar probe fixture");
        std::fs::write(tree.path().join("ordinary.bin"), b"ordinary")
            .expect("write viable batch item");
        let split_directory = write_recognized_split_candidate(tree.path());
        queue_adjacent_sidecar_probe_failure(
            std::fs::canonicalize(split_directory).expect("canonical Split directory"),
        );

        let error = crate::Engine::new()
            .resolve_inputs_batch(
                super::InputResolutionRequest::new(tree.path().to_path_buf())
                    .with_path("ordinary.bin")
                    .with_path("Game.nsp"),
            )
            .expect_err("sidecar probe uncertainty must reject a direct selection globally");

        assert_eq!(error.code(), InputResolutionErrorCode::InputUnavailable);
    }

    #[test]
    fn batch_resolution_rejects_a_canonical_member_probe_error_for_a_direct_directory() {
        let tree = tempfile::tempdir().expect("create direct member probe fixture");
        std::fs::write(tree.path().join("ordinary.bin"), b"ordinary")
            .expect("write viable batch item");
        let split_directory = write_unqualified_split_candidate(tree.path());
        queue_canonical_member_probe_failure(
            std::fs::canonicalize(split_directory).expect("canonical Split directory"),
        );

        let error = crate::Engine::new()
            .resolve_inputs_batch(
                super::InputResolutionRequest::new(tree.path().to_path_buf())
                    .with_path("ordinary.bin")
                    .with_path("Game.nsp"),
            )
            .expect_err("member probe uncertainty must reject a direct selection globally");

        assert_eq!(error.code(), InputResolutionErrorCode::InputUnavailable);
    }

    #[test]
    fn batch_resolution_rejects_an_adjacent_sidecar_probe_error_for_an_input_list() {
        let tree = tempfile::tempdir().expect("create input-list sidecar probe fixture");
        std::fs::write(tree.path().join("ordinary.bin"), b"ordinary")
            .expect("write viable batch item");
        let split_directory = write_recognized_split_candidate(tree.path());
        std::fs::write(
            tree.path().join("selection.json"),
            br#"{"schema_version":1,"kind":"nscb.input_list","required_features":[],"entries":[{"path":"ordinary.bin"},{"path":"Game.nsp"}]}"#,
        )
        .expect("write input list");
        queue_adjacent_sidecar_probe_failure(
            std::fs::canonicalize(split_directory).expect("canonical Split directory"),
        );

        let error = crate::Engine::new()
            .resolve_inputs_batch(
                super::InputResolutionRequest::new(tree.path().to_path_buf())
                    .with_input_list("selection.json"),
            )
            .expect_err("sidecar probe uncertainty must reject an input-list selection globally");

        assert_eq!(error.code(), InputResolutionErrorCode::InputUnavailable);
    }

    #[test]
    fn batch_resolution_rejects_a_canonical_member_probe_error_for_an_input_list() {
        let tree = tempfile::tempdir().expect("create input-list member probe fixture");
        std::fs::write(tree.path().join("ordinary.bin"), b"ordinary")
            .expect("write viable batch item");
        let split_directory = write_unqualified_split_candidate(tree.path());
        std::fs::write(
            tree.path().join("selection.json"),
            br#"{"schema_version":1,"kind":"nscb.input_list","required_features":[],"entries":[{"path":"ordinary.bin"},{"path":"Game.nsp"}]}"#,
        )
        .expect("write input list");
        queue_canonical_member_probe_failure(
            std::fs::canonicalize(split_directory).expect("canonical Split directory"),
        );

        let error = crate::Engine::new()
            .resolve_inputs_batch(
                super::InputResolutionRequest::new(tree.path().to_path_buf())
                    .with_input_list("selection.json"),
            )
            .expect_err("member probe uncertainty must reject an input-list selection globally");

        assert_eq!(error.code(), InputResolutionErrorCode::InputUnavailable);
    }

    #[test]
    fn qualified_split_does_not_make_a_later_ordinary_append_failure_global() {
        let tree = tempfile::tempdir().expect("create qualified Split batch fixture");
        let batch = tree.path().join("batch");
        std::fs::create_dir_all(&batch).expect("create mixed batch directory");
        let (_split, store) = write_qualified_split_fixture(&batch);
        let ordinary = batch.join("ordinary.nsp");
        std::fs::write(&ordinary, b"ordinary").expect("write ordinary batch child");
        let canonical_ordinary =
            std::fs::canonicalize(&ordinary).expect("canonical ordinary child");
        queue_append_file_failure(canonical_ordinary.clone());

        let result = crate::Engine::new()
            .resolve_inputs_batch_with(
                super::InputResolutionRequest::new(tree.path().to_path_buf()).with_path("batch"),
                InputResolutionCapabilities::new().with_split_trust_store(&store),
            )
            .expect("a qualified Split must survive a later ordinary append failure");

        assert_eq!(result.entries.len(), 2);
        let super::InputResolutionBatchEntry::Resolved(split) = &result.entries[0] else {
            panic!("the qualified Split must remain a successful batch entry");
        };
        assert!(split.qualification.is_some());
        let super::InputResolutionBatchEntry::Failed(failure) = &result.entries[1] else {
            panic!("the later ordinary child failure must remain item-local");
        };
        assert_eq!(failure.code(), InputResolutionErrorCode::InputUnavailable);
        assert_eq!(failure.requested_path(), canonical_ordinary);
        assert_eq!(
            failure.discovered_directory(),
            Some(std::fs::canonicalize(&batch).unwrap().as_path())
        );
        assert_eq!(
            failure.discovered_relative_path(),
            Some(Path::new("ordinary.nsp"))
        );
    }

    #[test]
    fn directory_append_failure_preserves_later_ordered_sibling() {
        let tree = tempfile::tempdir().expect("create ordered append fixture");
        let batch = tree.path().join("batch");
        std::fs::create_dir_all(&batch).expect("create ordered append directory");
        let (_split, store) = write_qualified_split_fixture(&batch);
        let middle = batch.join("middle.nsp");
        let final_item = batch.join("z.nsp");
        std::fs::write(&middle, b"middle").expect("write middle batch child");
        std::fs::write(&final_item, b"final").expect("write final batch child");
        let canonical_middle = std::fs::canonicalize(&middle).expect("canonical middle child");
        let canonical_final = std::fs::canonicalize(&final_item).expect("canonical final child");
        queue_append_file_failure(canonical_middle.clone());

        let result = crate::Engine::new()
            .resolve_inputs_batch_with(
                super::InputResolutionRequest::new(tree.path().to_path_buf()).with_path("batch"),
                InputResolutionCapabilities::new().with_split_trust_store(&store),
            )
            .expect("an item-local append failure must not abort directory expansion");

        assert_eq!(result.entries.len(), 3);
        let super::InputResolutionBatchEntry::Resolved(split) = &result.entries[0] else {
            panic!("the qualified Split must remain the first ordered batch entry");
        };
        assert!(split.qualification.is_some());
        assert_eq!(
            split.logical_selection_path(),
            std::fs::canonicalize(batch.join("Game.nsp")).expect("canonical Split child")
        );
        let super::InputResolutionBatchEntry::Failed(failure) = &result.entries[1] else {
            panic!("the middle ordinary append failure must remain in order");
        };
        assert_eq!(failure.code(), InputResolutionErrorCode::InputUnavailable);
        assert_eq!(failure.requested_path(), canonical_middle);
        assert_eq!(
            failure.discovered_directory(),
            Some(std::fs::canonicalize(&batch).unwrap().as_path())
        );
        assert_eq!(
            failure.discovered_relative_path(),
            Some(Path::new("middle.nsp"))
        );
        let super::InputResolutionBatchEntry::Resolved(final_resolved) = &result.entries[2] else {
            panic!("the viable sibling after the failure must remain in order");
        };
        assert_eq!(final_resolved.logical_selection_path(), canonical_final);
    }

    #[test]
    fn single_resolution_rejects_an_item_local_directory_failure() {
        let tree = tempfile::tempdir().expect("create single-resolution fixture");
        let batch = tree.path().join("batch");
        std::fs::create_dir_all(&batch).expect("create single-resolution directory");
        let middle = batch.join("middle.nsp");
        std::fs::write(batch.join("a.nsp"), b"first").expect("write first single child");
        std::fs::write(&middle, b"middle").expect("write middle single child");
        std::fs::write(batch.join("z.nsp"), b"final").expect("write final single child");
        queue_append_file_failure(std::fs::canonicalize(&middle).expect("canonical middle child"));

        let error = crate::Engine::new()
            .resolve_inputs(
                super::InputResolutionRequest::new(tree.path().to_path_buf()).with_path("batch"),
            )
            .expect_err("single resolution must reject an incomplete directory selection");

        assert_eq!(error.code(), InputResolutionErrorCode::InputUnavailable);
    }

    #[test]
    fn later_ordinary_scan_failure_stays_item_local_after_a_split_candidate() {
        let tree = tempfile::tempdir().expect("create mixed scan fixture");
        std::fs::write(tree.path().join("present.bin"), b"present")
            .expect("write viable top-level item");
        let batch = tree.path().join("batch");
        std::fs::create_dir_all(&batch).expect("create mixed scan directory");
        let (_split, store) = write_qualified_split_fixture(&batch);
        let ordinary = batch.join("ordinary.nsp");
        std::fs::write(&ordinary, b"ordinary").expect("write ordinary scan child");
        let canonical_ordinary =
            std::fs::canonicalize(&ordinary).expect("canonical ordinary child");
        let fault_triggered = Arc::new(AtomicBool::new(false));
        let checkpoint_fault_triggered = Arc::clone(&fault_triggered);
        let expected_ordinary = canonical_ordinary.clone();
        SCAN_DIRECTORY_ENTRY_CHECKPOINT.with(|checkpoint| {
            let previous = checkpoint.borrow_mut().replace(Box::new(move |path| {
                if path != expected_ordinary {
                    return false;
                }
                std::fs::remove_file(&ordinary).expect("remove ordinary child during scan");
                checkpoint_fault_triggered.store(true, Ordering::SeqCst);
                true
            }));
            assert!(previous.is_none(), "checkpoint was already queued");
        });

        let result = crate::Engine::new()
            .resolve_inputs_batch_with(
                super::InputResolutionRequest::new(tree.path().to_path_buf())
                    .with_path("present.bin")
                    .with_path("batch"),
                InputResolutionCapabilities::new().with_split_trust_store(&store),
            )
            .expect("a later ordinary scan failure must not reject the batch");

        assert!(
            fault_triggered.load(Ordering::SeqCst),
            "the ordinary-child scan fault must fire"
        );
        assert_eq!(result.entries.len(), 3);
        assert!(matches!(
            &result.entries[0],
            super::InputResolutionBatchEntry::Resolved(_)
        ));
        let super::InputResolutionBatchEntry::Resolved(split) = &result.entries[1] else {
            panic!("the qualified Split must remain successful");
        };
        assert!(split.qualification.is_some());
        let super::InputResolutionBatchEntry::Failed(failure) = &result.entries[2] else {
            panic!("the ordinary scan failure must remain item-local");
        };
        assert_eq!(failure.code(), InputResolutionErrorCode::InputUnavailable);
        assert_eq!(failure.requested_path(), canonical_ordinary);
        assert_eq!(
            failure.discovered_directory(),
            Some(std::fs::canonicalize(&batch).unwrap().as_path())
        );
        assert_eq!(
            failure.discovered_relative_path(),
            Some(Path::new("ordinary.nsp"))
        );
    }

    #[test]
    fn directory_scan_failure_preserves_later_ordered_sibling() {
        let tree = tempfile::tempdir().expect("create ordered scan fixture");
        let batch = tree.path().join("batch");
        std::fs::create_dir_all(&batch).expect("create ordered scan directory");
        let first = batch.join("a.nsp");
        let middle = batch.join("middle.nsp");
        let final_item = batch.join("z.nsp");
        std::fs::write(&first, b"first").expect("write first scan child");
        std::fs::write(&middle, b"middle").expect("write middle scan child");
        std::fs::write(&final_item, b"final").expect("write final scan child");
        let canonical_first = std::fs::canonicalize(&first).expect("canonical first child");
        let canonical_middle = std::fs::canonicalize(&middle).expect("canonical middle child");
        let canonical_final = std::fs::canonicalize(&final_item).expect("canonical final child");
        let fault_triggered = Arc::new(AtomicBool::new(false));
        let checkpoint_fault_triggered = Arc::clone(&fault_triggered);
        let expected_middle = canonical_middle.clone();
        SCAN_DIRECTORY_ENTRY_CHECKPOINT.with(|checkpoint| {
            let previous = checkpoint.borrow_mut().replace(Box::new(move |path| {
                if path != expected_middle {
                    return false;
                }
                std::fs::remove_file(&middle).expect("remove middle child during scan");
                checkpoint_fault_triggered.store(true, Ordering::SeqCst);
                true
            }));
            assert!(previous.is_none(), "checkpoint was already queued");
        });

        let result = crate::Engine::new()
            .resolve_inputs_batch(
                super::InputResolutionRequest::new(tree.path().to_path_buf()).with_path("batch"),
            )
            .expect("an item-local scan failure must not abort directory expansion");

        assert!(
            fault_triggered.load(Ordering::SeqCst),
            "the middle-child scan fault must fire"
        );
        assert_eq!(result.entries.len(), 3);
        let super::InputResolutionBatchEntry::Resolved(first_resolved) = &result.entries[0] else {
            panic!("the first viable child must remain first");
        };
        assert_eq!(first_resolved.logical_selection_path(), canonical_first);
        let super::InputResolutionBatchEntry::Failed(failure) = &result.entries[1] else {
            panic!("the middle scan failure must remain in order");
        };
        assert_eq!(failure.code(), InputResolutionErrorCode::InputUnavailable);
        assert_eq!(failure.requested_path(), canonical_middle);
        assert_eq!(
            failure.discovered_directory(),
            Some(std::fs::canonicalize(&batch).unwrap().as_path())
        );
        assert_eq!(
            failure.discovered_relative_path(),
            Some(Path::new("middle.nsp"))
        );
        let super::InputResolutionBatchEntry::Resolved(final_resolved) = &result.entries[2] else {
            panic!("the viable sibling after the scan failure must remain in order");
        };
        assert_eq!(final_resolved.logical_selection_path(), canonical_final);
    }

    #[test]
    fn batch_resolution_rejects_unavailable_direct_split_qualification() {
        let tree = tempfile::tempdir().expect("create direct Split fixture");
        std::fs::write(tree.path().join("ordinary.bin"), b"ordinary")
            .expect("write viable batch item");
        write_recognized_split_candidate(tree.path());
        queue_split_qualification_failure(super::InputSelectionSource::Path, None, None);

        let error = crate::Engine::new()
            .resolve_inputs_batch(
                super::InputResolutionRequest::new(tree.path().to_path_buf())
                    .with_path("ordinary.bin")
                    .with_path("Game.nsp"),
            )
            .expect_err("a recognized Split qualification failure must reject the batch");

        assert_eq!(error.code(), InputResolutionErrorCode::InputUnavailable);
    }

    #[test]
    fn batch_resolution_rejects_unavailable_input_list_split_qualification() {
        let tree = tempfile::tempdir().expect("create input-list Split fixture");
        std::fs::write(tree.path().join("ordinary.bin"), b"ordinary")
            .expect("write viable batch item");
        write_recognized_split_candidate(tree.path());
        std::fs::write(
            tree.path().join("selection.json"),
            br#"{"schema_version":1,"kind":"nscb.input_list","required_features":[],"entries":[{"path":"Game.nsp"},{"path":"ordinary.bin"}]}"#,
        )
        .expect("write input list");
        queue_split_qualification_failure(
            super::InputSelectionSource::InputList,
            Some(0),
            Some("Game.nsp"),
        );

        let error = crate::Engine::new()
            .resolve_inputs_batch(
                super::InputResolutionRequest::new(tree.path().to_path_buf())
                    .with_input_list("selection.json"),
            )
            .expect_err("an input-list Split qualification failure must reject the batch");

        assert_eq!(error.code(), InputResolutionErrorCode::InputUnavailable);
    }

    #[test]
    fn batch_resolution_checks_cancellation_between_base_directory_validations() {
        let tree = tempfile::tempdir().expect("create base validation fixture");
        let control = Arc::new(InputResolutionControl::new());
        let checkpoint_control = Arc::clone(&control);
        BASE_DIRECTORY_VALIDATION_CHECKPOINT.with(|checkpoint| {
            *checkpoint.borrow_mut() = Some(Box::new(move || checkpoint_control.cancel()));
        });

        let error = crate::Engine::new()
            .resolve_inputs_batch_request_with(
                super::InputResolutionBatchRequest::new()
                    .with_path(tree.path().to_path_buf(), "present.bin")
                    .with_path(std::path::PathBuf::from("relative-base"), "second.bin"),
                InputResolutionCapabilities::new().with_control(control.as_ref()),
            )
            .expect_err("cancellation after the first base must precede the second base check");

        assert_eq!(
            error.code(),
            InputResolutionErrorCode::SplitResolutionCancelled
        );
    }

    #[test]
    fn schema_parser_tolerates_unknown_optional_fields_but_requires_v1_semantics() {
        let paths = parse_input_list(
            br#"{"schema_version":1,"kind":"nscb.input_list","required_features":[],"future":{"x":true},"entries":[{"path":"a.bin","note":null}]}"#,
        )
        .unwrap();
        assert_eq!(paths, [std::path::PathBuf::from("a.bin")]);
    }

    #[cfg(unix)]
    #[test]
    fn split_suffix_detection_handles_non_unicode_os_paths() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path = std::path::PathBuf::from(OsString::from_vec(b"bad-\xff.xc0".to_vec()));
        assert!(super::looks_like_split_segment(&path));
    }

    #[test]
    fn aggregate_input_list_entry_and_byte_budgets_are_enforced() {
        let mut entry_budget = resolver();
        entry_budget.record_input_list(10, 60_000).unwrap();
        let entry_error = entry_budget.record_input_list(10, 40_001).unwrap_err();
        assert_eq!(
            entry_error.code(),
            InputResolutionErrorCode::ResourceLimitExceeded
        );

        let mut byte_budget = resolver();
        byte_budget.record_input_list(3_000_000, 1).unwrap();
        let byte_error = byte_budget.record_input_list(1_200_000, 1).unwrap_err();
        assert_eq!(
            byte_error.code(),
            InputResolutionErrorCode::ResourceLimitExceeded
        );
    }

    #[cfg(unix)]
    #[test]
    fn missing_non_unicode_split_suffix_is_not_a_regular_split_file() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let split_path = std::path::PathBuf::from(OsString::from_vec(b"bad-\xff.xc0".to_vec()));
        let selection = super::SelectionContext {
            selection_index: 0,
            source: super::InputSelectionSource::Path,
            selection_path: split_path.clone(),
            base_directory: std::path::PathBuf::from("/"),
            input_list_entry_index: None,
            input_list_entry_path: None,
        };
        let error = resolver()
            .expand_path(&split_path, std::path::Path::new("/"), &selection)
            .unwrap_err();
        assert_eq!(error.code(), InputResolutionErrorCode::InputUnavailable);
    }

    #[test]
    fn traversal_limits_are_finite_and_documented_constants() {
        assert_eq!(MAX_TRAVERSAL_DEPTH, 64);
        assert_eq!(MAX_TRAVERSAL_ENTRIES, 100_000);
        assert_eq!(MAX_INPUT_LIST_ENTRIES, 100_000);
        assert_eq!(MAX_INPUT_LIST_BYTES_PER_REQUEST, 4_194_304);
    }

    #[test]
    fn fresh_control_reports_no_active_split_input() {
        let control = InputResolutionControl::new();
        let progress = control.progress();
        assert_eq!(progress.input_index, 0);
        assert_eq!(progress.completed_bytes, 0);
        assert_eq!(progress.total_bytes, None);
        assert!(!control.is_cancelled());
    }

    #[test]
    fn control_observes_a_bound_invocation_cancellation_handle() {
        let cancellation = CancellationHandle::new();
        let control = InputResolutionControl::new().with_cancellation(cancellation.clone());

        assert!(!control.is_cancelled());
        cancellation.cancel();
        assert!(control.is_cancelled());
    }

    #[test]
    fn directory_scan_observes_cancellation_between_entries() {
        let tree = tempfile::tempdir().expect("create traversal cancellation fixture");
        std::fs::write(tree.path().join("present.nsp"), b"present")
            .expect("write traversal candidate");
        let root = std::fs::canonicalize(tree.path()).expect("canonical traversal root");
        let control = Arc::new(InputResolutionControl::new());
        let checkpoint_control = Arc::clone(&control);
        SCAN_DIRECTORY_ENTRY_CHECKPOINT.with(|checkpoint| {
            *checkpoint.borrow_mut() = Some(Box::new(move |_| {
                checkpoint_control.cancel();
                true
            }));
        });
        let mut resolver = Resolver::new(
            false,
            false,
            None,
            Some(control.as_ref()),
            DEFAULT_MAX_SPLIT_VALIDATION_BYTES,
        );
        let mut visited = HashSet::new();
        let mut active = HashSet::new();
        let mut found = Vec::new();

        let error = resolver
            .scan_directory(
                &root,
                &root,
                Path::new(""),
                0,
                &mut visited,
                &mut active,
                &mut found,
            )
            .expect_err("cancellation between traversal entries must stop the scan");

        assert_eq!(
            error.code(),
            InputResolutionErrorCode::SplitResolutionCancelled
        );
        assert!(found.is_empty());
    }
}
