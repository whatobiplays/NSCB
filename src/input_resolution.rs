//! Deterministic, read-only resolution of ordered local content selections.
//!
//! Resolution identifies regular filesystem inputs and records their paths, sizes,
//! and selection provenance. It does not inspect content bytes, establish a content
//! family, verify identity, or decide that a Split set is complete. Suspected Split
//! representations fail closed until their physical layout has qualified support.

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::fs::{self, Metadata, OpenOptions, ReadDir};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use unicode_normalization::UnicodeNormalization;

const MAX_INPUT_LIST_BYTES: u64 = 1_048_576;
const MAX_INPUT_LIST_BYTES_PER_REQUEST: u64 = 4_194_304;
const MAX_INPUT_LIST_ENTRIES: usize = 100_000;
const MAX_TRAVERSAL_ENTRIES: usize = 100_000;
const MAX_TRAVERSAL_DEPTH: usize = 64;
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
    /// Zero-based entry position when the input came from a JSON input list.
    pub input_list_entry_index: Option<usize>,
    /// Path string supplied by that JSON entry, when applicable.
    pub input_list_entry_path: Option<PathBuf>,
    /// Canonical selected directory when discovery produced the input.
    pub discovered_directory: Option<PathBuf>,
    /// Relative path within the selected directory, when discovery produced the input.
    pub discovered_relative_path: Option<PathBuf>,
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
        }
    }
}

/// Sanitized input-resolution failure suitable for public Rust and CLI boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputResolutionError {
    code: InputResolutionErrorCode,
}

impl InputResolutionError {
    fn new(code: InputResolutionErrorCode) -> Self {
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
        })
    }
}

impl std::error::Error for InputResolutionError {}

/// Resolves files, directories, and JSON input lists through the public Engine.
///
/// Explicit file selections accept regular files regardless of extension. Directory
/// discovery uses the documented candidate extensions and is nonrecursive by
/// default. Every output contains one physical segment; suspected Split layouts
/// return a typed error until positive completeness evidence and a stable grammar
/// qualify their support.
impl crate::Engine {
    /// Resolves ordered local selections without reading or changing content bytes.
    pub fn resolve_inputs(
        &self,
        request: InputResolutionRequest,
    ) -> Result<InputResolutionResult, InputResolutionError> {
        resolve_inputs(request)
    }
}

fn resolve_inputs(
    request: InputResolutionRequest,
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

    let mut resolver = Resolver::new(request.recursive, request.follow_symlinks);
    for (selection_index, selection) in request.selections.iter().enumerate() {
        match selection {
            InputSelection::Path(path) => {
                let before = resolver.inputs.len();
                let selection = SelectionContext {
                    selection_index,
                    source: InputSelectionSource::Path,
                    selection_path: path.clone(),
                    input_list_entry_index: None,
                    input_list_entry_path: None,
                };
                resolver.expand_path(path, &base_directory, &selection)?;
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
                if entries.is_empty() {
                    return Err(InputResolutionError::new(
                        InputResolutionErrorCode::EmptySelection,
                    ));
                }
                let before_list = resolver.inputs.len();
                for (entry_index, entry_path) in entries.into_iter().enumerate() {
                    let before_entry = resolver.inputs.len();
                    let selection = SelectionContext {
                        selection_index,
                        source: InputSelectionSource::InputList,
                        selection_path: path.clone(),
                        input_list_entry_index: Some(entry_index),
                        input_list_entry_path: Some(entry_path.clone()),
                    };
                    resolver.expand_path(&entry_path, &list_parent, &selection)?;
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

struct Resolver {
    recursive: bool,
    follow_symlinks: bool,
    visited_entries: usize,
    input_list_bytes: u64,
    input_list_entries: usize,
    path_keys: HashSet<String>,
    file_identities: HashSet<FileIdentity>,
    inputs: Vec<ResolvedInput>,
}

struct SelectionContext {
    selection_index: usize,
    source: InputSelectionSource,
    selection_path: PathBuf,
    input_list_entry_index: Option<usize>,
    input_list_entry_path: Option<PathBuf>,
}

impl Resolver {
    fn new(recursive: bool, follow_symlinks: bool) -> Self {
        Self {
            recursive,
            follow_symlinks,
            visited_entries: 0,
            input_list_bytes: 0,
            input_list_entries: 0,
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

    fn expand_path(
        &mut self,
        path: &Path,
        path_base: &Path,
        selection: &SelectionContext,
    ) -> Result<(), InputResolutionError> {
        let selected_path = absolute_path(path_base, path);
        let link_metadata = fs::symlink_metadata(&selected_path)
            .map_err(|_| InputResolutionError::new(InputResolutionErrorCode::InputUnavailable))?;
        let is_symlink = link_metadata.file_type().is_symlink();
        let target_metadata = fs::metadata(&selected_path)
            .map_err(|_| InputResolutionError::new(InputResolutionErrorCode::InputUnavailable))?;

        if target_metadata.is_file() {
            self.append_file(&selected_path, selection, None, None)
        } else if target_metadata.is_dir() {
            if is_symlink && !self.follow_symlinks {
                return Err(InputResolutionError::new(
                    InputResolutionErrorCode::UnsupportedFilesystemEntry,
                ));
            }
            self.expand_directory(&selected_path, selection)
        } else {
            Err(InputResolutionError::new(
                InputResolutionErrorCode::InputUnavailable,
            ))
        }
    }

    fn expand_directory(
        &mut self,
        selected_path: &Path,
        selection: &SelectionContext,
    ) -> Result<(), InputResolutionError> {
        let canonical_root = fs::canonicalize(selected_path)
            .map_err(|_| InputResolutionError::new(InputResolutionErrorCode::InputUnavailable))?;
        let root_metadata = fs::metadata(&canonical_root)
            .map_err(|_| InputResolutionError::new(InputResolutionErrorCode::InputUnavailable))?;
        if !root_metadata.is_dir() {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::InputUnavailable,
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
            normalized_path_key(&left.relative_path)
                .cmp(&normalized_path_key(&right.relative_path))
                .then_with(|| {
                    raw_path_key(&left.relative_path).cmp(&raw_path_key(&right.relative_path))
                })
        });

        if found.is_empty() {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::EmptySelection,
            ));
        }
        for candidate in found {
            self.append_known_file(
                candidate.canonical_path,
                candidate.size,
                candidate.file_identity,
                selection,
                Some(canonical_root.clone()),
                Some(candidate.relative_path),
            )?;
        }
        Ok(())
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
        found: &mut Vec<FoundFile>,
    ) -> Result<(), InputResolutionError> {
        if depth > MAX_TRAVERSAL_DEPTH {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::ResourceLimitExceeded,
            ));
        }
        let metadata = fs::metadata(directory)
            .map_err(|_| InputResolutionError::new(InputResolutionErrorCode::InputUnavailable))?;
        let identity = directory_identity(directory, &metadata);
        if active_directories.contains(&identity) {
            return Ok(());
        }
        if !visited_directories.insert(identity.clone()) {
            return Err(InputResolutionError::new(
                InputResolutionErrorCode::DuplicateSelection,
            ));
        }
        active_directories.insert(identity.clone());

        let mut entries = read_directory(directory, &mut self.visited_entries)?;
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
            let relative_path = relative_directory.join(&name);
            let file_type = entry.file_type().map_err(|_| {
                InputResolutionError::new(InputResolutionErrorCode::InputUnavailable)
            })?;

            if file_type.is_symlink() {
                if !self.follow_symlinks {
                    continue;
                }
                let suspected_split = looks_like_split_segment(&encountered_path);
                let discovery_candidate = is_discovery_candidate(&encountered_path);
                if !self.recursive && !discovery_candidate && !suspected_split {
                    continue;
                }
                let target = fs::canonicalize(&encountered_path).map_err(|_| {
                    InputResolutionError::new(InputResolutionErrorCode::InputUnavailable)
                })?;
                let target_metadata = fs::metadata(&target).map_err(|_| {
                    InputResolutionError::new(InputResolutionErrorCode::InputUnavailable)
                })?;
                if target_metadata.is_dir() {
                    if self.recursive {
                        if !target.starts_with(root) {
                            return Err(InputResolutionError::new(
                                InputResolutionErrorCode::UnsupportedFilesystemEntry,
                            ));
                        }
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
                } else if target_metadata.is_file() {
                    if suspected_split || looks_like_split_segment(&target) {
                        return Err(InputResolutionError::new(
                            InputResolutionErrorCode::UnsupportedSplitLayout,
                        ));
                    }
                    if discovery_candidate {
                        if !target.starts_with(root) {
                            return Err(InputResolutionError::new(
                                InputResolutionErrorCode::UnsupportedFilesystemEntry,
                            ));
                        }
                        found.push(found_file(&target, &target_metadata, relative_path)?);
                    }
                } else if discovery_candidate || suspected_split {
                    return Err(InputResolutionError::new(
                        InputResolutionErrorCode::UnsupportedFilesystemEntry,
                    ));
                }
                continue;
            }

            if file_type.is_dir() {
                if self.recursive {
                    let canonical = fs::canonicalize(&encountered_path).map_err(|_| {
                        InputResolutionError::new(InputResolutionErrorCode::InputUnavailable)
                    })?;
                    if !canonical.starts_with(root) {
                        return Err(InputResolutionError::new(
                            InputResolutionErrorCode::UnsupportedFilesystemEntry,
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
                    return Err(InputResolutionError::new(
                        InputResolutionErrorCode::UnsupportedSplitLayout,
                    ));
                }
                if is_discovery_candidate(&encountered_path) {
                    let canonical = fs::canonicalize(&encountered_path).map_err(|_| {
                        InputResolutionError::new(InputResolutionErrorCode::InputUnavailable)
                    })?;
                    if !canonical.starts_with(root) {
                        return Err(InputResolutionError::new(
                            InputResolutionErrorCode::UnsupportedFilesystemEntry,
                        ));
                    }
                    let metadata = fs::metadata(&canonical).map_err(|_| {
                        InputResolutionError::new(InputResolutionErrorCode::InputUnavailable)
                    })?;
                    if looks_like_split_segment(&canonical) {
                        return Err(InputResolutionError::new(
                            InputResolutionErrorCode::UnsupportedSplitLayout,
                        ));
                    }
                    found.push(found_file(&canonical, &metadata, relative_path)?);
                }
            } else if is_discovery_candidate(&encountered_path) {
                return Err(InputResolutionError::new(
                    InputResolutionErrorCode::UnsupportedFilesystemEntry,
                ));
            }
        }

        active_directories.remove(&identity);
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
        let file_identity = file_identity(&metadata);
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
        self.inputs.push(ResolvedInput {
            segments: vec![InputSegment {
                path: canonical_path,
                size,
            }],
            provenance: InputProvenance {
                selection_index: selection.selection_index,
                source: selection.source,
                selection_path: selection.selection_path.clone(),
                input_list_entry_index: selection.input_list_entry_index,
                input_list_entry_path: selection.input_list_entry_path.clone(),
                discovered_directory,
                discovered_relative_path,
            },
        });
        Ok(())
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
        file_identity: file_identity(metadata),
        relative_path,
    })
}

fn read_directory(
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
    let document: StrictJsonValue = serde_json::from_slice(bytes)
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
    fields
        .iter()
        .find(|(field_name, _)| field_name == name)
        .map(|(_, value)| value)
        .ok_or_else(|| InputResolutionError::new(InputResolutionErrorCode::InvalidInputList))
}

enum StrictJsonValue {
    Object(Vec<(String, StrictJsonValue)>),
    Array(Vec<StrictJsonValue>),
    String(String),
    Number(serde_json::Number),
    Bool,
    Null,
}

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonValueVisitor)
    }
}

struct StrictJsonValueVisitor;

impl<'de> Visitor<'de> for StrictJsonValueVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value with unique object keys")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::Bool)
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(StrictJsonValue::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictJsonValue::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut fields = Vec::new();
        let mut keys = HashSet::new();
        while let Some((key, value)) = map.next_entry::<String, StrictJsonValue>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            fields.push((key, value));
        }
        Ok(StrictJsonValue::Object(fields))
    }
}

fn absolute_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
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

fn looks_like_split_segment(path: &Path) -> bool {
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

fn directory_identity(path: &Path, metadata: &Metadata) -> DirectoryIdentity {
    DirectoryIdentity {
        path_key: normalized_path_key(path),
        file_identity: file_identity(metadata),
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DirectoryIdentity {
    path_key: String,
    file_identity: Option<FileIdentity>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FileIdentity {
    first: u64,
    second: u64,
}

fn file_identity(metadata: &Metadata) -> Option<FileIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        return Some(FileIdentity {
            first: metadata.dev(),
            second: metadata.ino(),
        });
    }
    #[allow(unreachable_code)]
    None
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
mod tests {
    use super::{
        MAX_INPUT_LIST_BYTES_PER_REQUEST, MAX_INPUT_LIST_ENTRIES, MAX_TRAVERSAL_DEPTH,
        MAX_TRAVERSAL_ENTRIES, Resolver, parse_input_list,
    };
    use crate::input_resolution::{InputResolutionErrorCode, StrictJsonValue};
    use serde::Deserialize;

    #[test]
    fn strict_json_parser_rejects_duplicate_keys_before_schema_projection() {
        let parsed = StrictJsonValue::deserialize(&mut serde_json::Deserializer::from_str(
            r#"{"x":{"y":1,"y":2}}"#,
        ));
        assert!(parsed.is_err());
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
        let mut entry_budget = Resolver::new(false, false);
        entry_budget.record_input_list(10, 60_000).unwrap();
        let entry_error = entry_budget.record_input_list(10, 40_001).unwrap_err();
        assert_eq!(
            entry_error.code(),
            InputResolutionErrorCode::ResourceLimitExceeded
        );

        let mut byte_budget = Resolver::new(false, false);
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
            input_list_entry_index: None,
            input_list_entry_path: None,
        };
        let error = Resolver::new(false, false)
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
}
