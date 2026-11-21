//! Typed requests and stable manifests for Program and Control extraction.

#[cfg(any(all(target_os = "macos", target_arch = "aarch64"), test))]
use crate::inspection::{NativeNcaFileSpan, NativeNcaInventory};
use crate::inspection::{NcaContentType, ProgramId};
use serde::{Serialize, Serializer};
#[cfg(any(all(target_os = "macos", target_arch = "aarch64"), test))]
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::{fmt, str::FromStr};

const MAX_COMPONENT_BYTES: usize = 255;

/// The canonical 128-bit identifier recorded in an Application CNMT row.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NcaContentId([u8; 16]);

impl NcaContentId {
    /// Creates an identifier from its verified 16-byte representation.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Parses exactly 32 ASCII hexadecimal digits.
    pub fn from_hex(value: &str) -> Result<Self, NcaContentIdParseError> {
        if value.len() != 32 || !value.is_ascii() {
            return Err(NcaContentIdParseError);
        }
        let mut bytes = [0_u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let start = index * 2;
            *byte = u8::from_str_radix(&value[start..start + 2], 16)
                .map_err(|_| NcaContentIdParseError)?;
        }
        Ok(Self(bytes))
    }

    /// Returns the identifier's bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Returns 32 lowercase hexadecimal digits.
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut value = String::with_capacity(32);
        for byte in self.0 {
            value.push(HEX[(byte >> 4) as usize] as char);
            value.push(HEX[(byte & 0x0f) as usize] as char);
        }
        value
    }
}

/// Error returned when an NCA ContentId is not 32 ASCII hexadecimal digits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NcaContentIdParseError;

impl fmt::Display for NcaContentIdParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NCA ContentId must contain exactly 32 ASCII hexadecimal digits")
    }
}

impl std::error::Error for NcaContentIdParseError {}

impl FromStr for NcaContentId {
    type Err = NcaContentIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_hex(value)
    }
}

impl fmt::Display for NcaContentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl Serialize for NcaContentId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

/// One Program or Control extraction request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractionRequest {
    source: PathBuf,
    destination: PathBuf,
    key_file: PathBuf,
    selection: ExtractionSelection,
}

impl ExtractionRequest {
    /// Creates an extraction request for an NCA or qualified NSP, destination bundle, key file, and selection.
    pub fn new(
        source: impl Into<PathBuf>,
        destination: impl Into<PathBuf>,
        key_file: impl Into<PathBuf>,
        selection: ExtractionSelection,
    ) -> Self {
        Self {
            source: source.into(),
            destination: destination.into(),
            key_file: key_file.into(),
            selection,
        }
    }

    /// Returns the NCA or NSP source path.
    pub fn source(&self) -> &std::path::Path {
        &self.source
    }

    /// Returns the new bundle directory path.
    pub fn destination(&self) -> &std::path::Path {
        &self.destination
    }

    /// Returns the header-key file path.
    pub fn key_file(&self) -> &std::path::Path {
        &self.key_file
    }

    /// Returns the requested full-tree or explicit selection.
    pub const fn selection(&self) -> &ExtractionSelection {
        &self.selection
    }
}

/// Chooses the complete validated tree or a set of explicit selectors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtractionSelection {
    /// Select every regular file and retain every validated partition directory.
    All,
    /// Select files matching every populated selector dimension.
    Selectors(ExtractionSelectors),
}

impl ExtractionSelection {
    /// Selects the complete supported logical filesystem tree.
    pub const fn all() -> Self {
        Self::All
    }

    /// Selects files using the supplied typed selector dimensions.
    pub const fn selectors(selectors: ExtractionSelectors) -> Self {
        Self::Selectors(selectors)
    }
}

/// Selector values combined with AND across dimensions and OR within a dimension.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExtractionSelectors {
    program_id: Option<ProgramId>,
    title_id: Option<ProgramId>,
    nca_content_id: Option<NcaContentId>,
    nca_type: Option<NcaContentType>,
    partitions: Vec<u8>,
    paths: Vec<String>,
}

impl ExtractionSelectors {
    /// Creates an empty selector set. At least one selector must be added before planning.
    pub const fn new() -> Self {
        Self {
            program_id: None,
            title_id: None,
            nca_content_id: None,
            nca_type: None,
            partitions: Vec::new(),
            paths: Vec::new(),
        }
    }

    /// Adds a Program ID predicate.
    pub fn with_program_id(mut self, program_id: ProgramId) -> Self {
        self.program_id = Some(program_id);
        self
    }

    /// Adds a verified NSP title identity predicate.
    pub fn with_title_id(mut self, title_id: ProgramId) -> Self {
        self.title_id = Some(title_id);
        self
    }

    /// Adds a verified NCA ContentId predicate.
    pub fn with_nca_content_id(mut self, content_id: NcaContentId) -> Self {
        self.nca_content_id = Some(content_id);
        self
    }

    /// Adds an NCA content-type predicate.
    pub fn with_nca_type(mut self, nca_type: NcaContentType) -> Self {
        self.nca_type = Some(nca_type);
        self
    }

    /// Adds a partition index to the OR-combined partition dimension.
    pub fn with_partition(mut self, partition: u8) -> Self {
        self.partitions.push(partition);
        self
    }

    /// Adds an exact, case-sensitive partition-relative path predicate.
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.paths.push(path.into());
        self
    }

    /// Returns the optional Program ID predicate.
    pub const fn program_id(&self) -> Option<ProgramId> {
        self.program_id
    }

    /// Returns the optional qualified NSP title identity predicate.
    pub const fn title_id(&self) -> Option<ProgramId> {
        self.title_id
    }

    /// Returns the optional qualified NCA ContentId predicate.
    pub const fn nca_content_id(&self) -> Option<NcaContentId> {
        self.nca_content_id
    }

    /// Returns the optional NCA content-type predicate.
    pub const fn nca_type(&self) -> Option<NcaContentType> {
        self.nca_type
    }

    /// Returns the partition indices in the OR-combined dimension.
    pub fn partitions(&self) -> &[u8] {
        &self.partitions
    }

    /// Returns the exact paths in the OR-combined dimension.
    pub fn paths(&self) -> &[String] {
        &self.paths
    }

    #[cfg(any(all(target_os = "macos", target_arch = "aarch64"), test))]
    pub(crate) fn is_empty(&self) -> bool {
        self.program_id.is_none()
            && self.title_id.is_none()
            && self.nca_content_id.is_none()
            && self.nca_type.is_none()
            && self.partitions.is_empty()
            && self.paths.is_empty()
    }
}

/// Selection mode recorded in a manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExtractionSelectionMode {
    /// The request selected every file in the validated tree.
    All,
    /// The request used one or more explicit selector dimensions.
    Selectors,
}

/// Completeness of the supported logical filesystem tree in a bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExtractionCompleteness {
    /// Every validated file, partition record, and directory is represented.
    Complete,
    /// The bundle contains a selected subset of the validated tree.
    Incomplete,
}

/// Versioned description of an extracted content tree.
///
/// The manifest records structural paths and profile identity. It deliberately
/// omits execution hashes so later payload edits remain compatible with its
/// declared format.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExtractionManifest {
    /// Manifest schema version.
    pub schema_version: u8,
    /// Stable format identifier.
    pub kind: &'static str,
    /// Whether the request selected all files or used explicit selectors.
    pub selection_mode: ExtractionSelectionMode,
    /// Directory containing the extracted payload.
    pub content_root: &'static str,
    /// Required profile features understood by this manifest version.
    pub required_features: Vec<&'static str>,
    /// Whether all validated logical filesystem structure is represented.
    pub completeness: ExtractionCompleteness,
    /// Structural identity reported by the NCA header and selected profile.
    pub source: ExtractionManifestSource,
    /// Partition records in ascending index order.
    pub partitions: Vec<ExtractionManifestPartition>,
}

impl ExtractionManifest {
    /// Serializes the manifest as deterministic UTF-8 JSON with a final newline.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut bytes = serde_json::to_vec(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// NCA identity and supported extraction role recorded in the manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExtractionManifestSource {
    /// Qualified native extraction profile.
    pub profile: &'static str,
    /// Logical content role.
    pub role: &'static str,
    /// NCA header content type.
    pub nca_type: &'static str,
    /// Canonical lowercase 16-digit Program ID.
    pub program_id: String,
    /// NCA header content index.
    pub content_index: u32,
    /// Verified container identity when the source is a qualified package.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<ExtractionManifestContainer>,
}

/// Verified identity of the containing application package.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExtractionManifestContainer {
    /// Semantic package profile.
    pub profile: &'static str,
    /// Canonical lowercase 16-digit title identity.
    pub title_id: String,
    /// Canonical lowercase 32-digit Program ContentId.
    pub program_content_id: String,
}

/// Supported filesystem metadata for one NCA partition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExtractionManifestPartition {
    /// Header partition index.
    pub index: u8,
    /// Filesystem type in the qualified profile.
    pub filesystem: &'static str,
    /// Directories relative to `content_root`, including the partition root.
    pub directories: Vec<String>,
    /// Regular files relative to `content_root`.
    pub files: Vec<ExtractionManifestFile>,
}

/// One regular-file path relative to the manifest's content root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExtractionManifestFile {
    /// Slash-separated path relative to `content_root`.
    pub path: String,
}

/// Selected source spans and their stable, validated manifest representation.
#[cfg(any(all(target_os = "macos", target_arch = "aarch64"), test))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedExtraction {
    /// Files to copy from the checked NCA source.
    pub(crate) selected_files: Vec<NativeNcaFileSpan>,
    /// Content-root-relative directories to create in the bundle.
    pub(crate) directories: Vec<String>,
    /// Manifest matching the selected files and directories.
    pub(crate) manifest: ExtractionManifest,
}

/// Errors found while resolving selectors or validating the published tree names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExtractionValidationError {
    /// Selectors were requested without any selector values.
    #[cfg(any(all(target_os = "macos", target_arch = "aarch64"), test))]
    EmptySelectors,
    /// No file matched the combined selector dimensions.
    #[cfg(any(all(target_os = "macos", target_arch = "aarch64"), test))]
    EmptySelection,
    /// At least one supplied selector value matched no file in the final selection.
    #[cfg(any(all(target_os = "macos", target_arch = "aarch64"), test))]
    SelectorMiss,
    /// A selected path or bundle component violates the portable naming policy.
    UnsupportedPath,
    /// A selected path aliases another source file or directory.
    #[cfg(any(all(target_os = "macos", target_arch = "aarch64"), test))]
    PathCollision,
    /// A published tree exceeds an existing inspection resource limit.
    #[cfg(any(all(target_os = "macos", target_arch = "aarch64"), test))]
    ResourceLimitExceeded,
}

/// Resolves a request against the native, validated NCA inventory.
///
/// Selector dimensions are conjunctive; values within partition and path
/// dimensions are disjunctive. Every supplied value must match at least one
/// file in the final selection.
#[cfg(any(all(target_os = "macos", target_arch = "aarch64"), test))]
struct ExtractionInventoryView<'a> {
    program_id: u64,
    title_id: Option<ProgramId>,
    nca_content_id: Option<NcaContentId>,
    content_index: u32,
    nca_type: NcaContentType,
    nca_type_name: &'static str,
    profile: &'static str,
    role: &'static str,
    filesystem: &'static str,
    required_feature: &'static str,
    additional_required_features: &'static [&'static str],
    container: Option<ExtractionManifestContainer>,
    partition_indices: Vec<u8>,
    directories: &'a [String],
    files: &'a [NativeNcaFileSpan],
    allow_empty_all: bool,
}

#[cfg(any(all(target_os = "macos", target_arch = "aarch64"), test))]
pub(crate) fn resolve_extraction(
    selection: &ExtractionSelection,
    inventory: &NativeNcaInventory,
) -> Result<ResolvedExtraction, ExtractionValidationError> {
    let mut partition_indices = Vec::new();
    partition_indices
        .try_reserve_exact(inventory.partitions.len())
        .map_err(|_| ExtractionValidationError::ResourceLimitExceeded)?;
    partition_indices.extend(inventory.partitions.iter().map(|partition| partition.index));
    resolve_extraction_from_inventory(
        selection,
        ExtractionInventoryView {
            program_id: inventory.header.program_id,
            title_id: None,
            nca_content_id: None,
            content_index: inventory.header.content_index,
            nca_type: NcaContentType::Program,
            nca_type_name: "program",
            profile: "nca3_program_partition_fs",
            role: "program",
            filesystem: "partition_fs",
            required_feature: "nca3_program_partition_fs",
            additional_required_features: &[],
            container: None,
            partition_indices,
            directories: &inventory.directories,
            files: &inventory.files,
            allow_empty_all: false,
        },
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn resolve_control_extraction(
    selection: &ExtractionSelection,
    inventory: &crate::control_nca_qualification::ControlNcaExtractionInventory,
) -> Result<ResolvedExtraction, ExtractionValidationError> {
    let mut partition_indices = Vec::new();
    partition_indices
        .try_reserve_exact(1)
        .map_err(|_| ExtractionValidationError::ResourceLimitExceeded)?;
    partition_indices.push(inventory.metadata.partition_index);
    resolve_extraction_from_inventory(
        selection,
        ExtractionInventoryView {
            program_id: inventory.metadata.program_id,
            title_id: None,
            nca_content_id: None,
            content_index: inventory.metadata.content_index,
            nca_type: NcaContentType::Control,
            nca_type_name: "control",
            profile: "nca3_control_romfs_ivfc_sha256_aes_ctr",
            role: "control",
            filesystem: "romfs",
            required_feature: "nca3_control_romfs_ivfc_sha256_aes_ctr",
            additional_required_features: &[],
            container: None,
            partition_indices,
            directories: &inventory.directories,
            files: &inventory.files,
            allow_empty_all: true,
        },
    )
}

#[cfg(any(all(target_os = "macos", target_arch = "aarch64"), test))]
/// Resolves selectors against Program spans from a qualified NSP identity.
pub(crate) fn resolve_nsp_program_extraction(
    selection: &ExtractionSelection,
    evidence: &crate::nsp_semantic_qualification::NspProgramExtractionEvidence,
    directories: &[String],
    files: &[NativeNcaFileSpan],
) -> Result<ResolvedExtraction, ExtractionValidationError> {
    let title_id = ProgramId::from_u64(evidence.title_id);
    resolve_extraction_from_inventory(
        selection,
        ExtractionInventoryView {
            program_id: evidence.title_id,
            title_id: Some(title_id),
            nca_content_id: Some(NcaContentId::from_bytes(evidence.program_content_id)),
            content_index: evidence.content_index,
            nca_type: NcaContentType::Program,
            nca_type_name: "program",
            profile: "nca3_program_partition_fs_hierarchical_sha256_aes_ctr",
            role: "program",
            filesystem: "partition_fs",
            required_feature: "nca3_program_partition_fs_hierarchical_sha256_aes_ctr",
            additional_required_features: &["rights_free_base_application_v1"],
            container: Some(ExtractionManifestContainer {
                profile: "rights_free_base_application_v1",
                title_id: title_id.to_hex(),
                program_content_id: NcaContentId::from_bytes(evidence.program_content_id).to_hex(),
            }),
            partition_indices: vec![0],
            directories,
            files,
            allow_empty_all: false,
        },
    )
}

#[cfg(any(all(target_os = "macos", target_arch = "aarch64"), test))]
fn resolve_extraction_from_inventory(
    selection: &ExtractionSelection,
    inventory: ExtractionInventoryView<'_>,
) -> Result<ResolvedExtraction, ExtractionValidationError> {
    let (selection_mode, selectors) = match selection {
        ExtractionSelection::All => (ExtractionSelectionMode::All, None),
        ExtractionSelection::Selectors(selectors) => {
            if selectors.is_empty() {
                return Err(ExtractionValidationError::EmptySelectors);
            }
            (ExtractionSelectionMode::Selectors, Some(selectors))
        }
    };

    let mut requested_partitions = [false; 256];
    let mut selected_partitions = [false; 256];
    let mut path_matches = HashMap::new();
    if let Some(selectors) = selectors {
        let selector_count = selectors
            .partitions()
            .len()
            .checked_add(selectors.paths().len())
            .ok_or(ExtractionValidationError::ResourceLimitExceeded)?;
        if selector_count > crate::partition_fs::MAX_TOTAL_ENTRIES {
            return Err(ExtractionValidationError::ResourceLimitExceeded);
        }
        let selector_path_bytes = selectors
            .paths()
            .iter()
            .try_fold(0_usize, |total, path| total.checked_add(path.len()));
        if selector_path_bytes.is_none_or(|bytes| bytes > crate::partition_fs::MAX_TOTAL_NAME_BYTES)
        {
            return Err(ExtractionValidationError::ResourceLimitExceeded);
        }
        path_matches
            .try_reserve(selectors.paths().len())
            .map_err(|_| ExtractionValidationError::ResourceLimitExceeded)?;
        for partition in selectors.partitions() {
            requested_partitions[*partition as usize] = true;
        }
        for path in selectors.paths() {
            path_matches.entry(path.as_str()).or_insert(false);
        }
    }

    let source_program_id = ProgramId::from_u64(inventory.program_id);
    let scalar_selectors_match = selectors.is_none_or(|selectors| {
        selectors
            .program_id()
            .is_none_or(|program_id| program_id == source_program_id)
            && selectors
                .nca_type()
                .is_none_or(|nca_type| nca_type == inventory.nca_type)
            && selectors
                .title_id()
                .is_none_or(|title_id| inventory.title_id == Some(title_id))
            && selectors
                .nca_content_id()
                .is_none_or(|content_id| inventory.nca_content_id == Some(content_id))
    });

    let mut selected_files = Vec::new();
    selected_files
        .try_reserve(inventory.files.len())
        .map_err(|_| ExtractionValidationError::ResourceLimitExceeded)?;
    if scalar_selectors_match {
        for file in inventory.files {
            let selected = selectors.is_none_or(|selectors| {
                (selectors.partitions().is_empty()
                    || requested_partitions[file.partition_index as usize])
                    && (selectors.paths().is_empty()
                        || path_matches.contains_key(file.path.as_str()))
            });
            if selected {
                selected_files.push(file.clone());
                selected_partitions[file.partition_index as usize] = true;
                if let Some(matched) = path_matches.get_mut(file.path.as_str()) {
                    *matched = true;
                }
            }
        }
    }

    if selectors.is_some() {
        if selected_files.is_empty()
            || (0..requested_partitions.len())
                .any(|index| requested_partitions[index] && !selected_partitions[index])
            || path_matches.values().any(|matched| !matched)
        {
            return Err(ExtractionValidationError::SelectorMiss);
        }
    } else if selected_files.is_empty() && !inventory.allow_empty_all {
        return Err(ExtractionValidationError::EmptySelection);
    }

    selected_files.sort_unstable_by(|left, right| {
        left.partition_index
            .cmp(&right.partition_index)
            .then_with(|| left.path.as_bytes().cmp(right.path.as_bytes()))
    });

    // Selection filters the validated file inventory once, so matching its
    // length means every source file is selected. The full-tree branches below
    // also retain all validated directories and partition records.
    let all_files_selected = selected_files.len() == inventory.files.len();
    let mut selected_file_paths = Vec::new();
    selected_file_paths
        .try_reserve_exact(selected_files.len())
        .map_err(|_| ExtractionValidationError::ResourceLimitExceeded)?;
    for file in &selected_files {
        validate_selected_relative_path(&file.path)?;
        selected_file_paths.push(content_path(file.partition_index, &file.path)?);
    }

    let mut required_directories = HashSet::new();
    if !all_files_selected {
        required_directories
            .try_reserve(inventory.directories.len())
            .map_err(|_| ExtractionValidationError::ResourceLimitExceeded)?;
        for file in &selected_files {
            let mut current = file.partition_index.to_string();
            insert_directory(&mut required_directories, &current)?;
            let mut components = file.path.split('/').peekable();
            while let Some(component) = components.next() {
                if components.peek().is_none() {
                    break;
                }
                current
                    .try_reserve(component.len().saturating_add(1))
                    .map_err(|_| ExtractionValidationError::ResourceLimitExceeded)?;
                current.push('/');
                current.push_str(component);
                insert_directory(&mut required_directories, &current)?;
            }
        }
    }

    let mut directories = Vec::new();
    let selected_directory_count = if all_files_selected {
        inventory.directories.len()
    } else {
        required_directories.len()
    };
    directories
        .try_reserve_exact(selected_directory_count)
        .map_err(|_| ExtractionValidationError::ResourceLimitExceeded)?;
    for directory in inventory.directories {
        if all_files_selected || required_directories.contains(directory) {
            validate_selected_relative_path(directory)?;
            directories.push(copy_string(directory)?);
        }
    }
    directories.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

    let mut source_file_paths = Vec::new();
    source_file_paths
        .try_reserve_exact(inventory.files.len())
        .map_err(|_| ExtractionValidationError::ResourceLimitExceeded)?;
    for file in inventory.files {
        source_file_paths.push(content_path(file.partition_index, &file.path)?);
    }
    validate_selected_path_aliases(
        &selected_file_paths,
        &directories,
        &source_file_paths,
        inventory.directories,
    )?;

    let mut manifest_partitions = Vec::new();
    manifest_partitions
        .try_reserve_exact(inventory.partition_indices.len())
        .map_err(|_| ExtractionValidationError::ResourceLimitExceeded)?;
    let mut ordered_partitions = Vec::new();
    ordered_partitions
        .try_reserve_exact(inventory.partition_indices.len())
        .map_err(|_| ExtractionValidationError::ResourceLimitExceeded)?;
    ordered_partitions.extend(inventory.partition_indices.iter().copied());
    ordered_partitions.sort_unstable();
    for partition_index in ordered_partitions {
        let prefix = format!("{partition_index}/");
        let represented = all_files_selected
            || selected_files
                .iter()
                .any(|file| file.partition_index == partition_index);
        if !represented {
            continue;
        }

        let mut partition_directories = Vec::new();
        for directory in &directories {
            if directory == &partition_index.to_string() || directory.starts_with(&prefix) {
                partition_directories.push(copy_string(directory)?);
            }
        }
        let mut partition_files = Vec::new();
        for file in selected_files
            .iter()
            .filter(|file| file.partition_index == partition_index)
        {
            partition_files.push(ExtractionManifestFile {
                path: content_path(partition_index, &file.path)?,
            });
        }
        manifest_partitions.push(ExtractionManifestPartition {
            index: partition_index,
            filesystem: inventory.filesystem,
            directories: partition_directories,
            files: partition_files,
        });
    }

    let mut required_features = Vec::new();
    required_features
        .try_reserve_exact(1 + inventory.additional_required_features.len())
        .map_err(|_| ExtractionValidationError::ResourceLimitExceeded)?;
    required_features.push(inventory.required_feature);
    required_features.extend_from_slice(inventory.additional_required_features);

    Ok(ResolvedExtraction {
        selected_files,
        directories,
        manifest: ExtractionManifest {
            schema_version: 1,
            kind: "extracted_content_manifest",
            selection_mode,
            content_root: "content",
            required_features,
            // A full-file candidate includes every inventory directory and
            // partition record above, including roots with no files. Publication
            // validates the planned payload paths before reporting success.
            completeness: if all_files_selected {
                ExtractionCompleteness::Complete
            } else {
                ExtractionCompleteness::Incomplete
            },
            source: ExtractionManifestSource {
                profile: inventory.profile,
                role: inventory.role,
                nca_type: inventory.nca_type_name,
                program_id: source_program_id.to_hex(),
                content_index: inventory.content_index,
                container: inventory.container,
            },
            partitions: manifest_partitions,
        },
    })
}

#[cfg(any(all(target_os = "macos", target_arch = "aarch64"), test))]
fn content_path(partition_index: u8, path: &str) -> Result<String, ExtractionValidationError> {
    let partition = partition_index.to_string();
    let capacity = partition
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(path.len()))
        .ok_or(ExtractionValidationError::ResourceLimitExceeded)?;
    let mut full_path = String::new();
    full_path
        .try_reserve_exact(capacity)
        .map_err(|_| ExtractionValidationError::ResourceLimitExceeded)?;
    full_path.push_str(&partition);
    full_path.push('/');
    full_path.push_str(path);
    Ok(full_path)
}

#[cfg(any(all(target_os = "macos", target_arch = "aarch64"), test))]
fn insert_directory(
    directories: &mut HashSet<String>,
    path: &str,
) -> Result<(), ExtractionValidationError> {
    if !directories.contains(path) {
        let mut copy = copy_string(path)?;
        copy.shrink_to_fit();
        directories.insert(copy);
    }
    Ok(())
}

#[cfg(any(all(target_os = "macos", target_arch = "aarch64"), test))]
fn copy_string(value: &str) -> Result<String, ExtractionValidationError> {
    let mut copy = String::new();
    copy.try_reserve_exact(value.len())
        .map_err(|_| ExtractionValidationError::ResourceLimitExceeded)?;
    copy.push_str(value);
    Ok(copy)
}

/// Validates one selected relative path using the portable published-name policy.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn validate_selected_relative_path(path: &str) -> Result<(), ExtractionValidationError> {
    if path.is_empty() {
        return Err(ExtractionValidationError::UnsupportedPath);
    }
    for component in path.split('/') {
        validate_portable_component(component)?;
    }
    Ok(())
}

/// Validates the final bundle directory name using the portable name policy.
pub(crate) fn validate_bundle_leaf(name: &str) -> Result<(), ExtractionValidationError> {
    validate_portable_component(name)
}

/// Reports whether `name` can be used as a portable extraction bundle directory name.
#[doc(hidden)]
pub fn is_portable_bundle_leaf(name: &str) -> bool {
    validate_bundle_leaf(name).is_ok()
}

fn validate_portable_component(component: &str) -> Result<(), ExtractionValidationError> {
    if component.is_empty()
        || component.len() > MAX_COMPONENT_BYTES
        || component == "."
        || component == ".."
        || component.ends_with('.')
        || component.ends_with(' ')
        || !component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || is_reserved_device_name(component)
    {
        return Err(ExtractionValidationError::UnsupportedPath);
    }
    Ok(())
}

fn is_reserved_device_name(component: &str) -> bool {
    let basename = component
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(
        basename.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        basename.strip_prefix(prefix).is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
    })
}

/// Rejects source aliases that could change the meaning of selected paths on a
/// case-insensitive filesystem or after Windows trailing-dot/space handling.
#[cfg(any(all(target_os = "macos", target_arch = "aarch64"), test))]
pub(crate) fn validate_selected_path_aliases(
    selected_files: &[String],
    selected_directories: &[String],
    source_files: &[String],
    source_directories: &[String],
) -> Result<(), ExtractionValidationError> {
    let selected_file_keys = selected_paths_by_key(selected_files, false)?;
    let selected_directory_keys = selected_paths_by_key(selected_directories, true)?;
    let source_file_keys = source_paths_by_key(source_files)?;
    let source_directory_keys = source_paths_by_key(source_directories)?;

    for (key, selected_path) in &selected_file_keys {
        if source_file_keys.get(key) != Some(&Some(*selected_path))
            || source_directory_keys.contains_key(key)
            || selected_directory_keys.contains_key(key)
        {
            return Err(ExtractionValidationError::PathCollision);
        }
    }

    for (key, selected_path) in &selected_directory_keys {
        if source_file_keys.contains_key(key)
            || source_directory_keys.get(key) != Some(&Some(*selected_path))
            || selected_file_keys.contains_key(key)
        {
            return Err(ExtractionValidationError::PathCollision);
        }
    }
    Ok(())
}

#[cfg(any(all(target_os = "macos", target_arch = "aarch64"), test))]
fn selected_paths_by_key(
    paths: &[String],
    allow_exact_duplicates: bool,
) -> Result<HashMap<String, &str>, ExtractionValidationError> {
    let mut canonical = HashMap::new();
    canonical
        .try_reserve(paths.len())
        .map_err(|_| ExtractionValidationError::ResourceLimitExceeded)?;
    for path in paths {
        let key = comparison_key(path)?;
        if let Some(previous) = canonical.get(&key) {
            if !allow_exact_duplicates || *previous != path.as_str() {
                return Err(ExtractionValidationError::PathCollision);
            }
        } else {
            canonical.insert(key, path.as_str());
        }
    }
    Ok(canonical)
}

#[cfg(any(all(target_os = "macos", target_arch = "aarch64"), test))]
fn source_paths_by_key(
    paths: &[String],
) -> Result<HashMap<String, Option<&str>>, ExtractionValidationError> {
    let mut canonical = HashMap::new();
    canonical
        .try_reserve(paths.len())
        .map_err(|_| ExtractionValidationError::ResourceLimitExceeded)?;
    for path in paths {
        let key = comparison_key(path)?;
        match canonical.entry(key) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Some(path.as_str()));
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if entry
                    .get()
                    .is_some_and(|previous| previous != path.as_str())
                {
                    entry.insert(None);
                }
            }
        }
    }
    Ok(canonical)
}

#[cfg(any(all(target_os = "macos", target_arch = "aarch64"), test))]
fn comparison_key(path: &str) -> Result<String, ExtractionValidationError> {
    let mut key = String::new();
    key.try_reserve(path.len())
        .map_err(|_| ExtractionValidationError::ResourceLimitExceeded)?;
    for (index, component) in path.split('/').enumerate() {
        if index > 0 {
            key.push('/');
        }
        let component = component.trim_end_matches(['.', ' ']);
        for character in component.chars() {
            key.push(character.to_ascii_lowercase());
        }
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::{
        ExtractionValidationError, is_portable_bundle_leaf, validate_bundle_leaf,
        validate_selected_path_aliases, validate_selected_relative_path,
    };

    #[test]
    fn selected_paths_and_bundle_names_use_the_portable_ascii_policy() {
        for path in [
            "",
            ".",
            "..",
            "dir//file",
            "dir/../file",
            "bad:name",
            "has space",
        ] {
            assert_eq!(
                validate_selected_relative_path(path),
                Err(ExtractionValidationError::UnsupportedPath),
                "{path:?}"
            );
        }
        for path in ["CON", "con.txt", "PRN.log", "COM1", "lpt9.bin", "trailing."] {
            assert_eq!(
                validate_selected_relative_path(path),
                Err(ExtractionValidationError::UnsupportedPath),
                "{path:?}"
            );
        }
        assert_eq!(
            validate_selected_relative_path(&format!("{}.bin", "a".repeat(253))),
            Err(ExtractionValidationError::UnsupportedPath)
        );

        assert_eq!(validate_selected_relative_path("assets/main_2.nca"), Ok(()));
        assert_eq!(validate_bundle_leaf("game-1.extracted"), Ok(()));
        assert!(is_portable_bundle_leaf("game-1.extracted"));
        assert!(!is_portable_bundle_leaf("game name.extracted"));
        assert_eq!(
            validate_bundle_leaf("game name.extracted"),
            Err(ExtractionValidationError::UnsupportedPath)
        );
    }

    #[test]
    fn unrelated_nonportable_unselected_names_do_not_block_a_safe_selection() {
        assert_eq!(
            validate_selected_path_aliases(
                &["0/main".to_owned()],
                &["0".to_owned()],
                &["0/main".to_owned(), "0/other;file".to_owned()],
                &["0".to_owned()],
            ),
            Ok(())
        );
    }

    #[test]
    fn case_and_trailing_character_aliases_of_selected_paths_are_rejected() {
        for alias in ["0/MAIN", "0/main.", "0/main "] {
            assert_eq!(
                validate_selected_path_aliases(
                    &["0/main".to_owned()],
                    &["0".to_owned()],
                    &["0/main".to_owned(), alias.to_owned()],
                    &["0".to_owned()],
                ),
                Err(ExtractionValidationError::PathCollision),
                "{alias:?}"
            );
        }
    }

    #[test]
    fn file_directory_and_directory_case_aliases_are_rejected() {
        assert_eq!(
            validate_selected_path_aliases(
                &["0/node/child".to_owned()],
                &["0".to_owned(), "0/node".to_owned()],
                &["0/node".to_owned(), "0/node/child".to_owned()],
                &["0".to_owned(), "0/node".to_owned()],
            ),
            Err(ExtractionValidationError::PathCollision)
        );
        assert_eq!(
            validate_selected_path_aliases(
                &["0/dir/file".to_owned()],
                &["0".to_owned(), "0/dir".to_owned()],
                &["0/dir/file".to_owned()],
                &["0".to_owned(), "0/Dir".to_owned()],
            ),
            Err(ExtractionValidationError::PathCollision)
        );
    }
}

#[cfg(test)]
mod planning_tests {
    use super::{
        ExtractionCompleteness, ExtractionManifest, ExtractionManifestContainer,
        ExtractionManifestFile, ExtractionManifestPartition, ExtractionManifestSource,
        ExtractionSelection, ExtractionSelectionMode, ExtractionSelectors,
        ExtractionValidationError, NcaContentId, resolve_extraction,
        resolve_nsp_program_extraction,
    };
    use crate::inspection::{
        InspectionEntry, NcaEncryptionType, NcaFilesystem, NcaHashType, NcaPartition, ProgramId,
    };
    use crate::inspection::{NativeNcaFileSpan, NativeNcaInventory};
    use crate::nca::{ContentType, Distribution, Header, Partition};

    fn inventory() -> NativeNcaInventory {
        let definitions = [
            (0_u8, "same.bin", 0x2200_u64, 4_u64),
            (0, "nested/a.bin", 0x2100, 5),
            (1, "same.bin", 0x3200, 6),
        ];
        let partitions = (0_u8..3)
            .map(|index| {
                let offset = 0x2000 + u64::from(index) * 0x1000;
                NcaPartition {
                    index,
                    offset,
                    size: 0x800,
                    filesystem: NcaFilesystem::PartitionFs,
                    hash_type: NcaHashType::None,
                    encryption: NcaEncryptionType::None,
                    entries: definitions
                        .iter()
                        .filter(|(partition, _, _, _)| *partition == index)
                        .map(|(_, path, _, size)| InspectionEntry {
                            path: (*path).to_owned(),
                            size: *size,
                        })
                        .collect(),
                }
            })
            .collect();
        let header_partitions = (0_u8..3)
            .map(|index| Partition {
                index,
                offset: 0x2000 + u64::from(index) * 0x1000,
                size: 0x800,
                filesystem: 1,
                hash_type: 1,
                encryption: 1,
                extended: false,
            })
            .collect();
        NativeNcaInventory {
            header: Header {
                format_version: 3,
                distribution: Distribution::GameCard,
                content_type: ContentType::Program,
                key_generation: 0,
                signature_generation: 0,
                kaek_index: 0,
                declared_size: 0x8000,
                program_id: 0x0102_0304_0506_0708,
                content_index: 9,
                partitions: header_partitions,
            },
            partitions,
            directories: vec![
                "0".to_owned(),
                "0/nested".to_owned(),
                "1".to_owned(),
                "2".to_owned(),
            ],
            files: definitions
                .iter()
                .map(|(partition_index, path, offset, size)| NativeNcaFileSpan {
                    partition_index: *partition_index,
                    path: (*path).to_owned(),
                    offset: *offset,
                    size: *size,
                })
                .collect(),
        }
    }

    #[test]
    fn all_selection_includes_empty_partition_directories() {
        let resolved = resolve_extraction(&ExtractionSelection::All, &inventory()).unwrap();
        assert_eq!(
            resolved.manifest.selection_mode,
            ExtractionSelectionMode::All
        );
        assert_eq!(
            resolved.manifest.completeness,
            ExtractionCompleteness::Complete
        );
        assert_eq!(resolved.manifest.partitions.len(), 3);
        assert_eq!(resolved.directories, ["0", "0/nested", "1", "2"]);
        assert_eq!(
            resolved.manifest.partitions[0].directories,
            ["0", "0/nested"]
        );
        assert_eq!(resolved.manifest.partitions[1].directories, ["1"]);
        assert_eq!(resolved.manifest.partitions[2].index, 2);
        assert_eq!(resolved.manifest.partitions[2].directories, ["2"]);
        assert!(resolved.manifest.partitions[2].files.is_empty());
        assert_eq!(
            resolved
                .manifest
                .partitions
                .iter()
                .map(|partition| partition.files.len())
                .collect::<Vec<_>>(),
            [2, 1, 0]
        );
        assert_eq!(
            resolved
                .manifest
                .partitions
                .iter()
                .flat_map(|partition| partition.files.iter().map(|file| file.path.as_str()))
                .collect::<Vec<_>>(),
            ["0/nested/a.bin", "0/same.bin", "1/same.bin"]
        );
        let bytes = resolved.manifest.to_json_bytes().unwrap();
        assert!(bytes.ends_with(b"\n"));
        assert!(
            String::from_utf8_lossy(&bytes).contains("\"kind\":\"extracted_content_manifest\"")
        );
    }

    #[test]
    fn selectors_can_be_complete_and_path_matches_span_partitions() {
        let selection = ExtractionSelection::Selectors(
            ExtractionSelectors::new()
                .with_program_id(ProgramId::from_u64(0x0102_0304_0506_0708))
                .with_nca_type(crate::inspection::NcaContentType::Program)
                .with_path("same.bin")
                .with_path("nested/a.bin"),
        );
        let resolved = resolve_extraction(&selection, &inventory()).unwrap();
        assert_eq!(
            resolved.manifest.selection_mode,
            ExtractionSelectionMode::Selectors
        );
        assert_eq!(
            resolved.manifest.completeness,
            ExtractionCompleteness::Complete
        );
        assert_eq!(resolved.manifest.partitions.len(), 3);
        assert_eq!(resolved.directories, ["0", "0/nested", "1", "2"]);
        assert_eq!(
            resolved
                .manifest
                .partitions
                .iter()
                .map(|partition| partition.index)
                .collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert_eq!(resolved.manifest.partitions[2].directories, ["2"]);
        assert_eq!(
            resolved
                .manifest
                .partitions
                .iter()
                .map(|partition| partition.files.len())
                .collect::<Vec<_>>(),
            [2, 1, 0]
        );
        assert_eq!(
            resolved.selected_files[0].path, "nested/a.bin",
            "selected spans are sorted bytewise by partition and path"
        );
        assert_eq!(
            resolved.manifest.to_json_bytes().unwrap(),
            resolved.manifest.to_json_bytes().unwrap()
        );
    }

    #[test]
    fn partial_selection_emits_only_required_directories_and_content_relative_paths() {
        let selection = ExtractionSelection::Selectors(
            ExtractionSelectors::new()
                .with_partition(0)
                .with_path("nested/a.bin"),
        );
        let resolved = resolve_extraction(&selection, &inventory()).unwrap();
        assert_eq!(
            resolved.manifest.completeness,
            ExtractionCompleteness::Incomplete
        );
        assert_eq!(resolved.directories, ["0", "0/nested"]);
        assert_eq!(resolved.manifest.partitions.len(), 1);
        assert_eq!(
            resolved.manifest.partitions[0].directories,
            ["0", "0/nested"]
        );
        assert_eq!(
            resolved.manifest.partitions[0].files[0].path,
            "0/nested/a.bin"
        );
    }

    #[test]
    fn every_selector_value_must_match_the_final_file_selection() {
        for selectors in [
            ExtractionSelectors::new().with_partition(2),
            ExtractionSelectors::new().with_path("Nested/a.bin"),
            ExtractionSelectors::new()
                .with_partition(2)
                .with_path("same.bin"),
        ] {
            assert_eq!(
                resolve_extraction(&ExtractionSelection::Selectors(selectors), &inventory()),
                Err(ExtractionValidationError::SelectorMiss)
            );
        }
        assert_eq!(
            resolve_extraction(
                &ExtractionSelection::Selectors(ExtractionSelectors::new()),
                &inventory()
            ),
            Err(ExtractionValidationError::EmptySelectors)
        );
    }

    #[test]
    fn selector_count_uses_the_existing_entry_budget() {
        let mut selectors = ExtractionSelectors::new();
        selectors
            .partitions
            .resize(crate::partition_fs::MAX_TOTAL_ENTRIES + 1, 0);
        assert_eq!(
            resolve_extraction(&ExtractionSelection::Selectors(selectors), &inventory()),
            Err(ExtractionValidationError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn qualified_nsp_selectors_require_and_record_container_identity() {
        let evidence = crate::nsp_semantic_qualification::NspProgramExtractionEvidence {
            source_sha256: crate::sha256::Sha256Digest::from_bytes([0x11; 32]),
            source_size: 0x8000,
            title_id: 0x0100_1234_5678_9abc,
            content_index: 4,
            program_content_id: [0x22; 16],
            member_offset: 0x400,
            member_size: 0x4000,
            member_sha256: crate::sha256::Sha256Digest::from_bytes([0x22; 32]),
            partition_offset: 0x400,
            partition_size: 0x3000,
            pfs0_offset: 0x1000,
            pfs0_size: 0x1000,
            section_ctr: [0; 8],
            files: Vec::new(),
        };
        let directories = vec!["0".to_owned(), "0/nested".to_owned()];
        let files = vec![NativeNcaFileSpan {
            partition_index: 0,
            path: "nested/data.bin".to_owned(),
            offset: 0x1200,
            size: 4,
        }];
        let title_id = ProgramId::from_u64(evidence.title_id);
        let content_id = NcaContentId::from_bytes(evidence.program_content_id);
        let selectors = ExtractionSelectors::new()
            .with_program_id(title_id)
            .with_title_id(title_id)
            .with_nca_content_id(content_id)
            .with_nca_type(crate::inspection::NcaContentType::Program)
            .with_partition(0)
            .with_path("nested/data.bin");
        let resolved = resolve_nsp_program_extraction(
            &ExtractionSelection::Selectors(selectors),
            &evidence,
            &directories,
            &files,
        )
        .unwrap();

        assert_eq!(resolved.manifest.content_root, "content");
        assert_eq!(
            resolved.manifest.required_features,
            [
                "nca3_program_partition_fs_hierarchical_sha256_aes_ctr",
                "rights_free_base_application_v1",
            ]
        );
        assert_eq!(
            resolved.manifest.source.profile,
            "nca3_program_partition_fs_hierarchical_sha256_aes_ctr"
        );
        assert_eq!(
            resolved.manifest.source.container,
            Some(ExtractionManifestContainer {
                profile: "rights_free_base_application_v1",
                title_id: "0100123456789abc".to_owned(),
                program_content_id: "22222222222222222222222222222222".to_owned(),
            })
        );
        assert_eq!(
            resolved.manifest.partitions[0].files[0].path,
            "0/nested/data.bin"
        );

        let standalone = inventory();
        for selectors in [
            ExtractionSelectors::new().with_title_id(title_id),
            ExtractionSelectors::new().with_nca_content_id(content_id),
        ] {
            assert_eq!(
                resolve_extraction(&ExtractionSelection::Selectors(selectors), &standalone),
                Err(ExtractionValidationError::SelectorMiss)
            );
        }
    }

    #[test]
    fn standalone_manifest_bytes_omit_optional_container_metadata() {
        let manifest = ExtractionManifest {
            schema_version: 1,
            kind: "extracted_content_manifest",
            selection_mode: ExtractionSelectionMode::All,
            content_root: "content",
            required_features: vec!["nca3_program_partition_fs"],
            completeness: ExtractionCompleteness::Complete,
            source: ExtractionManifestSource {
                profile: "nca3_program_partition_fs",
                role: "program",
                nca_type: "program",
                program_id: "0102030405060708".to_owned(),
                content_index: 0,
                container: None,
            },
            partitions: vec![ExtractionManifestPartition {
                index: 0,
                filesystem: "partition_fs",
                directories: vec!["0".to_owned()],
                files: vec![ExtractionManifestFile {
                    path: "0/main.nro".to_owned(),
                }],
            }],
        };
        assert_eq!(
            manifest.to_json_bytes().unwrap(),
            b"{\"schema_version\":1,\"kind\":\"extracted_content_manifest\",\"selection_mode\":\"all\",\"content_root\":\"content\",\"required_features\":[\"nca3_program_partition_fs\"],\"completeness\":\"complete\",\"source\":{\"profile\":\"nca3_program_partition_fs\",\"role\":\"program\",\"nca_type\":\"program\",\"program_id\":\"0102030405060708\",\"content_index\":0},\"partitions\":[{\"index\":0,\"filesystem\":\"partition_fs\",\"directories\":[\"0\"],\"files\":[{\"path\":\"0/main.nro\"}]}]}\n"
        );

        let mut control = manifest;
        control.required_features = vec!["nca3_control_romfs_ivfc_sha256_aes_ctr"];
        control.source.profile = "nca3_control_romfs_ivfc_sha256_aes_ctr";
        control.source.role = "control";
        control.source.nca_type = "control";
        control.partitions[0].filesystem = "romfs";
        assert_eq!(
            control.to_json_bytes().unwrap(),
            b"{\"schema_version\":1,\"kind\":\"extracted_content_manifest\",\"selection_mode\":\"all\",\"content_root\":\"content\",\"required_features\":[\"nca3_control_romfs_ivfc_sha256_aes_ctr\"],\"completeness\":\"complete\",\"source\":{\"profile\":\"nca3_control_romfs_ivfc_sha256_aes_ctr\",\"role\":\"control\",\"nca_type\":\"control\",\"program_id\":\"0102030405060708\",\"content_index\":0},\"partitions\":[{\"index\":0,\"filesystem\":\"romfs\",\"directories\":[\"0\"],\"files\":[{\"path\":\"0/main.nro\"}]}]}\n"
        );
    }

    #[test]
    fn nca_content_id_uses_canonical_lowercase_hex() {
        let canonical = "00112233445566778899aabbccddeeff";
        let id = NcaContentId::from_hex("00112233445566778899AABBCCDDEEFF").unwrap();
        assert_eq!(
            id.as_bytes(),
            &[
                0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );
        assert_eq!(id.to_hex(), canonical);
        assert_eq!(id.to_string(), canonical);
        assert_eq!(canonical.parse::<NcaContentId>().unwrap(), id);
        assert_eq!(
            serde_json::to_string(&id).unwrap(),
            format!("\"{canonical}\"")
        );
        assert_eq!(
            NcaContentId::from_hex("bad").unwrap_err().to_string(),
            "NCA ContentId must contain exactly 32 ASCII hexadecimal digits"
        );
        assert!(NcaContentId::from_hex("00112233445566778899aabbccddeef").is_err());
        assert!(NcaContentId::from_hex("00112233445566778899aabbccddeefg").is_err());
    }
}
