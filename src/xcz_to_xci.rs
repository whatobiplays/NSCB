//! Bounded reconstruction of a rights-free Application XCZ as an XCI image.

#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]

use crate::operation::ConflictPolicy;
use std::path::PathBuf;

const ROOT_PLACEMENT: u64 = 0xF000;
const HFS_HEADER_SIZE: u64 = 0x8000;
const CARD_HEADER_SIZE: u64 = 0x200;
const HFS_HASH_PREFIX_LIMIT: u64 = 0x200;
const IO_BUFFER_SIZE: usize = 64 * 1024;

/// Describes a request to reconstruct an XCZ gamecard image as an XCI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XczToXciRequest {
    source: PathBuf,
    destination: PathBuf,
    workspace: PathBuf,
    key_file: PathBuf,
    conflict_policy: ConflictPolicy,
}

impl XczToXciRequest {
    /// Creates a conversion request with explicit input, output, workspace,
    /// and NCA qualification key paths.
    pub fn new(
        source: impl Into<PathBuf>,
        destination: impl Into<PathBuf>,
        workspace: impl Into<PathBuf>,
        key_file: impl Into<PathBuf>,
    ) -> Self {
        Self {
            source: source.into(),
            destination: destination.into(),
            workspace: workspace.into(),
            key_file: key_file.into(),
            conflict_policy: ConflictPolicy::Fail,
        }
    }

    /// Selects how execution handles an existing destination.
    #[must_use]
    pub fn with_conflict_policy(mut self, policy: ConflictPolicy) -> Self {
        self.conflict_policy = policy;
        self
    }

    pub(crate) fn into_parts(self) -> XczToXciRequestParts {
        XczToXciRequestParts {
            source: self.source,
            destination: self.destination,
            workspace: self.workspace,
            key_file: self.key_file,
            conflict_policy: self.conflict_policy,
        }
    }
}

pub(crate) struct XczToXciRequestParts {
    pub(crate) source: PathBuf,
    pub(crate) destination: PathBuf,
    pub(crate) workspace: PathBuf,
    pub(crate) key_file: PathBuf,
    pub(crate) conflict_policy: ConflictPolicy,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XczToXciPackagePlan {
    pub(crate) input: crate::recognition::XciConversionSource,
    pub(crate) meta: crate::recognition::XciSecureMember,
    pub(crate) program: crate::recognition::XciSecureMember,
    pub(crate) program_nca_size: u64,
    pub(crate) program_section_offset: u64,
    pub(crate) program_section_size: u64,
    pub(crate) semantic_facts: crate::nsp_semantic_qualification::NspSemanticQualificationFacts,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct XczQualificationContext<'a> {
    pub(crate) source_file: &'a mut std::fs::File,
    pub(crate) source_path: &'a std::path::Path,
    pub(crate) source_length: u64,
    pub(crate) source_identity: crate::file_identity::FileIdentity,
    pub(crate) source_snapshot: crate::file_identity::FileSnapshot,
    pub(crate) key_path: &'a std::path::Path,
    pub(crate) key_snapshot: crate::file_identity::FileSnapshot,
    pub(crate) keys: &'a crate::key_file::NspQualificationKeys,
    pub(crate) program_spool: &'a mut std::fs::File,
}

/// Returns the bounded SHA-256 span required for one output HFS0 member.
fn hfs_hash_size(member_length: u64) -> Option<u32> {
    let prefix = member_length.min(HFS_HASH_PREFIX_LIMIT);
    if prefix == 0 {
        return None;
    }
    u32::try_from(prefix).ok()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn qualify_source(
    context: XczQualificationContext<'_>,
) -> Result<XczToXciPackagePlan, crate::operation::OperationFailureCode> {
    use std::io::{Seek, SeekFrom};

    let XczQualificationContext {
        source_file,
        source_path,
        source_length,
        source_identity,
        source_snapshot,
        key_path,
        key_snapshot,
        keys,
        program_spool,
    } = context;

    if source_length > crate::nsp_nsz::MAX_PACKAGE_BYTES {
        return Err(crate::operation::OperationFailureCode::ResourceLimitExceeded);
    }
    let input = crate::recognition::inspect_xcz_for_conversion(source_file, source_length)
        .map_err(crate::xci_to_nsp::map_recognition_error)?;
    if input.secure_members.len() != 2 {
        return Err(crate::operation::OperationFailureCode::UnsupportedContentProfile);
    }

    let mut meta = None;
    let mut program = None;
    let mut program_record = None;
    let mut program_section = None;
    for member in &input.secure_members {
        let record = read_member_record(source_file, member)?;
        let nca_size = match &record {
            Some(record) => record.nca_size,
            None => member.length,
        };
        if nca_size > crate::nsp_nsz::MAX_PACKAGE_BYTES {
            return Err(crate::operation::OperationFailureCode::ResourceLimitExceeded);
        }
        let block = read_member_header(
            source_file,
            member,
            nca_size,
            record.is_some(),
            keys.header_key.as_bytes(),
        )?;
        let header = crate::nca::parse_header_block(&block, nca_size)
            .map_err(crate::nsp_nsz::map_nca_header_error)
            .map_err(crate::operation::map_nsp_nsz_format_error)?;
        crate::nsp_nsz::validate_supported_header(&block, &header, nca_size)
            .map_err(crate::operation::map_nsp_nsz_format_error)?;

        match (record, header.content_type) {
            (None, crate::nca::ContentType::Meta) if meta.is_none() => meta = Some(member.clone()),
            (Some(record), crate::nca::ContentType::Program) if program.is_none() => {
                let partition = header
                    .partitions
                    .first()
                    .ok_or(crate::operation::OperationFailureCode::UnsupportedContentProfile)?;
                program_section = Some((partition.offset, partition.size));
                program = Some(member.clone());
                program_record = Some(record);
            }
            _ => return Err(crate::operation::OperationFailureCode::UnsupportedContentProfile),
        }
    }
    let meta = meta.ok_or(crate::operation::OperationFailureCode::UnsupportedContentProfile)?;
    let program =
        program.ok_or(crate::operation::OperationFailureCode::UnsupportedContentProfile)?;
    let program_record =
        program_record.ok_or(crate::operation::OperationFailureCode::UnsupportedContentProfile)?;
    let (program_section_offset, program_section_size) =
        program_section.ok_or(crate::operation::OperationFailureCode::UnsupportedContentProfile)?;
    if program_record.nca_size <= crate::ncz::NCZ_PREFIX_SIZE {
        return Err(crate::operation::OperationFailureCode::UnsupportedContentProfile);
    }

    program_spool
        .set_len(0)
        .map_err(|_| crate::operation::OperationFailureCode::WriteFailed)?;
    program_spool
        .seek(SeekFrom::Start(0))
        .map_err(|_| crate::operation::OperationFailureCode::WriteFailed)?;
    crate::ncz::decode_member(
        source_file,
        crate::ncz::NczDecodeSpec {
            source_offset: program.offset,
            source_size: program.length,
            expected_nca_size: program_record.nca_size,
            section_offset: program_section_offset,
            section_size: program_section_size,
        },
        program_spool,
        |_| Ok(()),
    )
    .map_err(crate::operation::map_nsp_nsz_runtime_error)?;
    program_spool
        .sync_all()
        .map_err(|_| crate::operation::OperationFailureCode::WriteFailed)?;
    let program_spool_size = program_spool
        .metadata()
        .map_err(|_| crate::operation::OperationFailureCode::WriteFailed)?
        .len();
    if program_spool_size != program_record.nca_size {
        return Err(crate::operation::OperationFailureCode::ValidationFailed);
    }

    let layout_members = vec![
        (String::from("meta.nca"), meta.length),
        (String::from("program.nca"), program_record.nca_size),
    ];
    let layout = crate::multi_content_format::build_pfs0_layout(&layout_members)
        .map_err(crate::operation::map_content_format_error)?;
    let program_identity = crate::file_identity::handle_identity(program_spool)
        .ok_or(crate::operation::OperationFailureCode::UnsupportedCapability)?;
    let program_metadata = program_spool
        .metadata()
        .map_err(|_| crate::operation::OperationFailureCode::WriteFailed)?;
    let program_snapshot =
        crate::file_identity::file_snapshot(&program_metadata, Some(program_identity));
    let virtual_input = XczSemanticInput {
        source_file: source_file
            .try_clone()
            .map_err(|_| crate::operation::OperationFailureCode::SourceUnavailable)?,
        program_file: program_spool
            .try_clone()
            .map_err(|_| crate::operation::OperationFailureCode::SourceUnavailable)?,
        source_path: source_path.to_path_buf(),
        source_identity,
        source_snapshot: source_snapshot.clone(),
        program_identity,
        program_snapshot,
        layout,
        source_members: [
            SemanticSourceMember {
                file: SemanticFile::Source,
                offset: meta.offset,
            },
            SemanticSourceMember {
                file: SemanticFile::Program,
                offset: 0,
            },
        ],
        position: 0,
    };
    let request = crate::nsp_semantic_qualification::NspSemanticQualificationRequest::new(
        source_path,
        key_path,
    )
    .with_expected_key_snapshot(key_snapshot);
    let result = crate::nsp_semantic_qualification::qualify_with_input(request, virtual_input)
        .map_err(|error| crate::xci_to_nsp::map_qualification_error(error.code()))?;
    let semantic_facts = match result.outcome {
        crate::nsp_semantic_qualification::NspSemanticQualificationOutcome::Qualified(facts) => {
            facts
        }
        crate::nsp_semantic_qualification::NspSemanticQualificationOutcome::NotQualified(_) => {
            return Err(crate::operation::OperationFailureCode::UnsupportedContentProfile);
        }
    };
    let [semantic_meta, semantic_program] = semantic_facts.members.as_slice() else {
        return Err(crate::operation::OperationFailureCode::UnsupportedContentProfile);
    };
    if semantic_facts.profile
        != crate::nsp_semantic_qualification::NspSemanticQualificationProfile::RightsFreeBaseApplicationV1
        || semantic_meta.role
            != crate::nsp_semantic_qualification::NspSemanticQualificationRole::Meta
        || semantic_meta.size != meta.length
        || semantic_program.role
            != crate::nsp_semantic_qualification::NspSemanticQualificationRole::Program
        || semantic_program.size != program_record.nca_size
    {
        return Err(crate::operation::OperationFailureCode::UnsupportedContentProfile);
    }
    source_file
        .seek(SeekFrom::Start(0))
        .map_err(|_| crate::operation::OperationFailureCode::SourceChanged)?;

    Ok(XczToXciPackagePlan {
        input,
        meta,
        program,
        program_nca_size: program_record.nca_size,
        program_section_offset,
        program_section_size,
        semantic_facts,
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn read_member_record(
    source_file: &mut std::fs::File,
    member: &crate::recognition::XciSecureMember,
) -> Result<Option<crate::ncz::NczRecord>, crate::operation::OperationFailureCode> {
    use std::io::{Read, Seek, SeekFrom};

    if member.length <= crate::ncz::NCZ_PREFIX_SIZE + 8 {
        return Ok(None);
    }
    let marker_offset = member
        .offset
        .checked_add(crate::ncz::NCZ_PREFIX_SIZE)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    source_file
        .seek(SeekFrom::Start(marker_offset))
        .map_err(|_| crate::operation::OperationFailureCode::SourceUnavailable)?;
    let mut marker = [0_u8; 8];
    source_file
        .read_exact(&mut marker)
        .map_err(|_| crate::operation::OperationFailureCode::SourceChanged)?;
    if &marker != b"NCZSECTN" {
        return Ok(None);
    }
    let mut bounded = crate::ncz::SpanReader::new(source_file, member.offset, member.length);
    crate::ncz::read_ncz_record(&mut bounded, member.length)
        .map(Some)
        .map_err(crate::operation::map_nsp_nsz_format_error)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn read_member_header(
    source_file: &mut std::fs::File,
    member: &crate::recognition::XciSecureMember,
    nca_size: u64,
    compressed: bool,
    header_key: &[u8; 32],
) -> Result<[u8; crate::nca::HEADER_SIZE], crate::operation::OperationFailureCode> {
    let read_size = if compressed {
        member.length.min(crate::ncz::NCZ_PREFIX_SIZE)
    } else {
        member.length
    };
    let mut bounded = crate::ncz::SpanReader::new(source_file, member.offset, read_size);
    crate::nca::read_header_block(&mut bounded, nca_size, header_key)
        .map_err(crate::nsp_nsz::map_nca_header_error)
        .map_err(crate::operation::map_nsp_nsz_format_error)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy)]
enum SemanticFile {
    Source,
    Program,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy)]
struct SemanticSourceMember {
    file: SemanticFile,
    offset: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct XczSemanticInput {
    source_file: std::fs::File,
    program_file: std::fs::File,
    source_path: PathBuf,
    source_identity: crate::file_identity::FileIdentity,
    source_snapshot: crate::file_identity::FileSnapshot,
    program_identity: crate::file_identity::FileIdentity,
    program_snapshot: crate::file_identity::FileSnapshot,
    layout: crate::multi_content_format::Pfs0WriteLayout,
    source_members: [SemanticSourceMember; 2],
    position: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl std::io::Read for XczSemanticInput {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        use std::io::{Seek, SeekFrom};

        if buffer.is_empty() || self.position >= self.layout.length {
            return Ok(0);
        }
        if self.position < self.layout.payload_offset {
            let metadata_start = usize::try_from(self.position)
                .map_err(|_| std::io::Error::other("virtual PFS0 offset is too large"))?;
            let count = buffer
                .len()
                .min(self.layout.metadata.len().saturating_sub(metadata_start));
            if count == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "virtual PFS0 metadata range is incomplete",
                ));
            }
            buffer[..count]
                .copy_from_slice(&self.layout.metadata[metadata_start..metadata_start + count]);
            self.position =
                self.position
                    .checked_add(u64::try_from(count).map_err(|_| {
                        std::io::Error::other("virtual PFS0 read length is too large")
                    })?)
                    .ok_or_else(|| std::io::Error::other("virtual PFS0 offset overflow"))?;
            return Ok(count);
        }

        let payload_position = self.position - self.layout.payload_offset;
        let Some((layout_member, source_member)) = self
            .layout
            .members
            .iter()
            .zip(&self.source_members)
            .find(|(layout, _)| {
                layout.data_offset <= payload_position
                    && layout
                        .data_offset
                        .checked_add(layout.size)
                        .is_some_and(|end| payload_position < end)
            })
        else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "virtual PFS0 payload has an unaccounted range",
            ));
        };
        let member_offset = payload_position - layout_member.data_offset;
        let count = usize::try_from((layout_member.size - member_offset).min(buffer.len() as u64))
            .map_err(|_| std::io::Error::other("virtual PFS0 read length is too large"))?;
        let source_offset = source_member
            .offset
            .checked_add(member_offset)
            .ok_or_else(|| std::io::Error::other("source member offset overflow"))?;
        let file = match source_member.file {
            SemanticFile::Source => &mut self.source_file,
            SemanticFile::Program => &mut self.program_file,
        };
        file.seek(SeekFrom::Start(source_offset))?;
        let read = file.read(&mut buffer[..count])?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "virtual PFS0 source member ended early",
            ));
        }
        self.position = self
            .position
            .checked_add(
                u64::try_from(read)
                    .map_err(|_| std::io::Error::other("virtual PFS0 read length is too large"))?,
            )
            .ok_or_else(|| std::io::Error::other("virtual PFS0 offset overflow"))?;
        Ok(read)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl std::io::Seek for XczSemanticInput {
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        let requested = match position {
            std::io::SeekFrom::Start(offset) => i128::from(offset),
            std::io::SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
            std::io::SeekFrom::End(delta) => i128::from(self.layout.length) + i128::from(delta),
        };
        if requested < 0 || requested > i128::from(self.layout.length) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek is outside the virtual PFS0 package",
            ));
        }
        self.position = u64::try_from(requested)
            .map_err(|_| std::io::Error::other("virtual PFS0 offset is too large"))?;
        Ok(self.position)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl crate::nsp_semantic_qualification::NspSemanticInput for XczSemanticInput {
    fn input_size(&self) -> u64 {
        self.layout.length
    }

    fn revalidate(
        &self,
        code: crate::nsp_semantic_qualification::NspSemanticQualificationErrorCode,
    ) -> Result<(), crate::nsp_semantic_qualification::NspSemanticQualificationError> {
        use crate::nsp_semantic_qualification::NspSemanticQualificationError;

        let changed = || Err(NspSemanticQualificationError::new(code));
        let Ok(source_metadata) = self.source_file.metadata() else {
            return changed();
        };
        let Ok(program_metadata) = self.program_file.metadata() else {
            return changed();
        };
        if !source_metadata.file_type().is_file()
            || crate::file_identity::handle_identity(&self.source_file)
                != Some(self.source_identity)
            || crate::file_identity::path_identity(&self.source_path) != Some(self.source_identity)
            || crate::file_identity::followed_path_identity(&self.source_path)
                != Some(self.source_identity)
            || crate::file_identity::file_snapshot(&source_metadata, Some(self.source_identity))
                != self.source_snapshot
            || !program_metadata.file_type().is_file()
            || crate::file_identity::handle_identity(&self.program_file)
                != Some(self.program_identity)
            || crate::file_identity::file_snapshot(&program_metadata, Some(self.program_identity))
                != self.program_snapshot
        {
            return changed();
        }
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OutputGeometry {
    root_offset: u64,
    root_header_size: u64,
    secure_offset: u64,
    secure_length: u64,
    meta_offset: u64,
    program_offset: u64,
    output_length: u64,
    rom_area_start_page: u32,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone)]
struct HfsEntry {
    name: &'static str,
    relative_data_offset: u64,
    length: u64,
    digest: [u8; 32],
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn output_geometry(
    meta_length: u64,
    program_length: u64,
    has_logo: bool,
    rom_size: u8,
    valid_data_end: u32,
) -> Result<OutputGeometry, crate::operation::OperationFailureCode> {
    if meta_length == 0 || program_length == 0 {
        return Err(crate::operation::OperationFailureCode::UnsupportedContentProfile);
    }
    let secure_offset = ROOT_PLACEMENT
        .checked_add(HFS_HEADER_SIZE)
        .and_then(|offset| offset.checked_add(CARD_HEADER_SIZE * 2))
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let secure_data_start = secure_offset
        .checked_add(HFS_HEADER_SIZE)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let meta_offset = secure_data_start;
    let meta_end = meta_offset
        .checked_add(meta_length)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let program_offset = align_card_page(meta_end)?;
    let program_end = program_offset
        .checked_add(program_length)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let secure_end = align_card_page(program_end)?;
    let secure_length = secure_end
        .checked_sub(secure_offset)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let output_length = if has_logo {
        secure_end
            .checked_add(CARD_HEADER_SIZE)
            .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?
    } else {
        secure_end
    };
    if output_length > crate::nsp_nsz::MAX_PACKAGE_BYTES {
        return Err(crate::operation::OperationFailureCode::ResourceLimitExceeded);
    }

    let physical_end = output_length
        .checked_add(0x1000)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let physical_end_pages = div_ceil(physical_end, CARD_HEADER_SIZE)?;
    let capacity_pages = crate::recognition::rom_size_pages(u64::from(rom_size))
        .ok_or(crate::operation::OperationFailureCode::UnsupportedXciProfile)?;
    if physical_end_pages > capacity_pages || physical_end_pages > u64::from(valid_data_end) {
        return Err(crate::operation::OperationFailureCode::UnsupportedXciProfile);
    }
    let physical_secure_page = secure_offset
        .checked_add(0x1000)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?
        / CARD_HEADER_SIZE;
    let rom_area_start_page = u32::try_from(physical_secure_page)
        .map_err(|_| crate::operation::OperationFailureCode::UnsupportedXciProfile)?;
    Ok(OutputGeometry {
        root_offset: ROOT_PLACEMENT,
        root_header_size: HFS_HEADER_SIZE,
        secure_offset,
        secure_length,
        meta_offset,
        program_offset,
        output_length,
        rom_area_start_page,
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn align_card_page(value: u64) -> Result<u64, crate::operation::OperationFailureCode> {
    let remainder = value % CARD_HEADER_SIZE;
    if remainder == 0 {
        Ok(value)
    } else {
        value
            .checked_add(CARD_HEADER_SIZE - remainder)
            .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn div_ceil(value: u64, divisor: u64) -> Result<u64, crate::operation::OperationFailureCode> {
    value
        .checked_add(divisor - 1)
        .map(|rounded| rounded / divisor)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hfs_table_size(names: &[&str]) -> Result<u64, crate::operation::OperationFailureCode> {
    let entries = u64::try_from(names.len())
        .map_err(|_| crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let records = entries
        .checked_mul(64)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let strings = names.iter().try_fold(0_u64, |size, name| {
        size.checked_add(u64::try_from(name.len()).ok()?)
            .and_then(|size| size.checked_add(1))
    });
    16_u64
        .checked_add(records)
        .and_then(|size| size.checked_add(strings?))
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn build_hfs_header(
    entries: &[HfsEntry],
    declared_data_start: u64,
) -> Result<Vec<u8>, crate::operation::OperationFailureCode> {
    let names = entries.iter().map(|entry| entry.name).collect::<Vec<_>>();
    let raw_size = hfs_table_size(&names)?;
    if raw_size > declared_data_start {
        return Err(crate::operation::OperationFailureCode::UnsupportedXciProfile);
    }
    let capacity = usize::try_from(declared_data_start)
        .map_err(|_| crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let raw_capacity = usize::try_from(raw_size)
        .map_err(|_| crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let record_bytes = u64::try_from(entries.len())
        .map_err(|_| crate::operation::OperationFailureCode::ResourceLimitExceeded)?
        .checked_mul(64)
        .and_then(|size| size.checked_add(16))
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let record_capacity = usize::try_from(record_bytes)
        .map_err(|_| crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    bytes.resize(record_capacity, 0);
    bytes[..4].copy_from_slice(b"HFS0");
    let count = u32::try_from(entries.len())
        .map_err(|_| crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    bytes[4..8].copy_from_slice(&count.to_le_bytes());
    let names_size = names.iter().try_fold(0_u32, |size, name| {
        let length = u32::try_from(name.len()).ok()?.checked_add(1)?;
        size.checked_add(length)
    });
    let names_size =
        names_size.ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    bytes[8..12].copy_from_slice(&names_size.to_le_bytes());

    let header_data_base = declared_data_start
        .checked_sub(raw_size)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let mut name_offset = 0_u32;
    for (index, entry) in entries.iter().enumerate() {
        let hashed_size = hfs_hash_size(entry.length)
            .ok_or(crate::operation::OperationFailureCode::UnsupportedXciProfile)?;
        let record_start = 16_usize
            .checked_add(
                index
                    .checked_mul(64)
                    .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?,
            )
            .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
        let relative_offset = header_data_base
            .checked_add(entry.relative_data_offset)
            .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
        bytes[record_start..record_start + 8].copy_from_slice(&relative_offset.to_le_bytes());
        bytes[record_start + 8..record_start + 16].copy_from_slice(&entry.length.to_le_bytes());
        bytes[record_start + 16..record_start + 20].copy_from_slice(&name_offset.to_le_bytes());
        bytes[record_start + 20..record_start + 24].copy_from_slice(&hashed_size.to_le_bytes());
        bytes[record_start + 32..record_start + 64].copy_from_slice(&entry.digest);
        name_offset = name_offset
            .checked_add(
                u32::try_from(entry.name.len())
                    .map_err(|_| crate::operation::OperationFailureCode::ResourceLimitExceeded)?,
            )
            .and_then(|offset| offset.checked_add(1))
            .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    }
    for entry in entries {
        bytes.extend_from_slice(entry.name.as_bytes());
        bytes.push(0);
    }
    if bytes.len() != raw_capacity {
        return Err(crate::operation::OperationFailureCode::ValidationFailed);
    }
    bytes.resize(capacity, 0);
    Ok(bytes)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    Sha256::digest(bytes).into()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hash_file_prefix(
    source: &mut std::fs::File,
    offset: u64,
    member_length: u64,
) -> Result<[u8; 32], crate::operation::OperationFailureCode> {
    let hashed_size = hfs_hash_size(member_length)
        .ok_or(crate::operation::OperationFailureCode::UnsupportedXciProfile)?;
    hash_file_range(source, offset, u64::from(hashed_size), |_| Ok(()))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hash_file_range(
    source: &mut std::fs::File,
    offset: u64,
    length: u64,
    mut on_chunk: impl FnMut(u64) -> Result<(), crate::operation::OperationFailureCode>,
) -> Result<[u8; 32], crate::operation::OperationFailureCode> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom};

    source
        .seek(SeekFrom::Start(offset))
        .map_err(|_| crate::operation::OperationFailureCode::SourceUnavailable)?;
    let mut remaining = length;
    let mut buffer = [0_u8; IO_BUFFER_SIZE];
    let mut hasher = Sha256::new();
    while remaining > 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
        let read = source
            .read(&mut buffer[..count])
            .map_err(|_| crate::operation::OperationFailureCode::SourceUnavailable)?;
        if read == 0 {
            return Err(crate::operation::OperationFailureCode::SourceChanged);
        }
        hasher.update(&buffer[..read]);
        let read_length = u64::try_from(read)
            .map_err(|_| crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
        on_chunk(read_length)?;
        remaining -= read_length;
    }
    Ok(hasher.finalize().into())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn write_bytes<W: std::io::Write>(
    writer: &mut W,
    bytes: &[u8],
    on_chunk: &mut impl FnMut(u64) -> Result<(), crate::operation::OperationFailureCode>,
) -> Result<(), crate::operation::OperationFailureCode> {
    writer
        .write_all(bytes)
        .map_err(|_| crate::operation::OperationFailureCode::WriteFailed)?;
    on_chunk(
        u64::try_from(bytes.len())
            .map_err(|_| crate::operation::OperationFailureCode::ResourceLimitExceeded)?,
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn write_zero_padding<W: std::io::Write>(
    writer: &mut W,
    length: u64,
    on_chunk: &mut impl FnMut(u64) -> Result<(), crate::operation::OperationFailureCode>,
) -> Result<(), crate::operation::OperationFailureCode> {
    let zeros = [0_u8; IO_BUFFER_SIZE];
    let mut remaining = length;
    while remaining > 0 {
        let count = usize::try_from(remaining.min(zeros.len() as u64))
            .map_err(|_| crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
        writer
            .write_all(&zeros[..count])
            .map_err(|_| crate::operation::OperationFailureCode::WriteFailed)?;
        on_chunk(
            u64::try_from(count)
                .map_err(|_| crate::operation::OperationFailureCode::ResourceLimitExceeded)?,
        )?;
        remaining -= u64::try_from(count)
            .map_err(|_| crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn copy_file_span<W: std::io::Write>(
    source: &mut std::fs::File,
    source_offset: u64,
    length: u64,
    writer: &mut W,
    on_chunk: &mut impl FnMut(u64) -> Result<(), crate::operation::OperationFailureCode>,
) -> Result<(), crate::operation::OperationFailureCode> {
    use std::io::{Read, Seek, SeekFrom};

    source
        .seek(SeekFrom::Start(source_offset))
        .map_err(|_| crate::operation::OperationFailureCode::SourceUnavailable)?;
    let mut remaining = length;
    let mut buffer = [0_u8; IO_BUFFER_SIZE];
    while remaining > 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
        let read = source
            .read(&mut buffer[..wanted])
            .map_err(|_| crate::operation::OperationFailureCode::SourceUnavailable)?;
        if read == 0 {
            return Err(crate::operation::OperationFailureCode::SourceChanged);
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|_| crate::operation::OperationFailureCode::WriteFailed)?;
        let read_u64 = u64::try_from(read)
            .map_err(|_| crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
        on_chunk(read_u64)?;
        remaining -= read_u64;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn write_xci<W: std::io::Write>(
    source_file: &mut std::fs::File,
    program_spool: &mut std::fs::File,
    package: &XczToXciPackagePlan,
    writer: &mut W,
    mut on_chunk: impl FnMut(u64) -> Result<(), crate::operation::OperationFailureCode>,
) -> Result<u64, crate::operation::OperationFailureCode> {
    use std::io::{Read, Seek, SeekFrom};

    let mut source_header = [0_u8; CARD_HEADER_SIZE as usize];
    source_file
        .seek(SeekFrom::Start(0))
        .and_then(|_| source_file.read_exact(&mut source_header))
        .map_err(|_| crate::operation::OperationFailureCode::SourceUnavailable)?;
    let geometry = output_geometry(
        package.meta.length,
        package.program_nca_size,
        package.input.has_logo_partition,
        source_header[0x10D],
        u32::from_le_bytes(source_header[0x118..0x11C].try_into().expect("fixed field")),
    )?;
    let empty_partition = build_hfs_header(&[], CARD_HEADER_SIZE)?;
    let meta_hash = hash_file_prefix(source_file, package.meta.offset, package.meta.length)?;
    let program_hash = hash_file_prefix(program_spool, 0, package.program_nca_size)?;
    let secure_data_start = geometry
        .secure_offset
        .checked_add(HFS_HEADER_SIZE)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let program_relative_offset = geometry
        .program_offset
        .checked_sub(secure_data_start)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let secure_header = build_hfs_header(
        &[
            HfsEntry {
                name: "meta.nca",
                relative_data_offset: 0,
                length: package.meta.length,
                digest: meta_hash,
            },
            HfsEntry {
                name: "program.nca",
                relative_data_offset: program_relative_offset,
                length: package.program_nca_size,
                digest: program_hash,
            },
        ],
        HFS_HEADER_SIZE,
    )?;
    let root_count = if package.input.has_logo_partition {
        4
    } else {
        3
    };
    let root_names = if package.input.has_logo_partition {
        vec!["update", "normal", "secure", "logo"]
    } else {
        vec!["update", "normal", "secure"]
    };
    let root_raw_size = hfs_table_size(&root_names)?;
    let _ = HFS_HEADER_SIZE
        .checked_sub(root_raw_size)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let secure_relative_offset = CARD_HEADER_SIZE
        .checked_mul(2)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let mut root_entries = vec![
        HfsEntry {
            name: "update",
            relative_data_offset: 0,
            length: CARD_HEADER_SIZE,
            digest: hash_bytes(&empty_partition),
        },
        HfsEntry {
            name: "normal",
            relative_data_offset: CARD_HEADER_SIZE,
            length: CARD_HEADER_SIZE,
            digest: hash_bytes(&empty_partition),
        },
        HfsEntry {
            name: "secure",
            relative_data_offset: secure_relative_offset,
            length: geometry.secure_length,
            digest: hash_bytes(&secure_header[..CARD_HEADER_SIZE as usize]),
        },
    ];
    if package.input.has_logo_partition {
        root_entries.push(HfsEntry {
            name: "logo",
            relative_data_offset: secure_relative_offset
                .checked_add(geometry.secure_length)
                .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?,
            length: CARD_HEADER_SIZE,
            digest: hash_bytes(&empty_partition),
        });
    }
    if root_entries.len() != root_count {
        return Err(crate::operation::OperationFailureCode::ValidationFailed);
    }
    let root_header = build_hfs_header(&root_entries, geometry.root_header_size)?;
    let root_digest = hash_bytes(&root_header);
    let mut card_header = source_header;
    card_header[0x104..0x108].copy_from_slice(&geometry.rom_area_start_page.to_le_bytes());
    card_header[0x130..0x138].copy_from_slice(&geometry.root_offset.to_le_bytes());
    card_header[0x138..0x140].copy_from_slice(&geometry.root_header_size.to_le_bytes());
    card_header[0x140..0x160].copy_from_slice(&root_digest);

    let mut written = 0_u64;
    write_bytes(writer, &card_header, &mut |amount| {
        written = written
            .checked_add(amount)
            .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
        on_chunk(amount)
    })?;
    let root_gap = geometry
        .root_offset
        .checked_sub(CARD_HEADER_SIZE)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    write_zero_padding(writer, root_gap, &mut |amount| {
        written = written
            .checked_add(amount)
            .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
        on_chunk(amount)
    })?;
    write_bytes(writer, &root_header, &mut |amount| {
        written = written
            .checked_add(amount)
            .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
        on_chunk(amount)
    })?;
    write_bytes(writer, &empty_partition, &mut |amount| {
        written = written
            .checked_add(amount)
            .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
        on_chunk(amount)
    })?;
    write_bytes(writer, &empty_partition, &mut |amount| {
        written = written
            .checked_add(amount)
            .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
        on_chunk(amount)
    })?;
    write_bytes(writer, &secure_header, &mut |amount| {
        written = written
            .checked_add(amount)
            .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
        on_chunk(amount)
    })?;
    copy_file_span(
        source_file,
        package.meta.offset,
        package.meta.length,
        writer,
        &mut |amount| {
            written = written
                .checked_add(amount)
                .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
            on_chunk(amount)
        },
    )?;
    let meta_end = geometry
        .meta_offset
        .checked_add(package.meta.length)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let program_gap = geometry
        .program_offset
        .checked_sub(meta_end)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    write_zero_padding(writer, program_gap, &mut |amount| {
        written = written
            .checked_add(amount)
            .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
        on_chunk(amount)
    })?;
    copy_file_span(
        program_spool,
        0,
        package.program_nca_size,
        writer,
        &mut |amount| {
            written = written
                .checked_add(amount)
                .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
            on_chunk(amount)
        },
    )?;
    let secure_content_end = geometry
        .program_offset
        .checked_add(package.program_nca_size)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let secure_end = geometry
        .secure_offset
        .checked_add(geometry.secure_length)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let secure_padding = secure_end
        .checked_sub(secure_content_end)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    write_zero_padding(writer, secure_padding, &mut |amount| {
        written = written
            .checked_add(amount)
            .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
        on_chunk(amount)
    })?;
    if package.input.has_logo_partition {
        write_bytes(writer, &empty_partition, &mut |amount| {
            written = written
                .checked_add(amount)
                .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
            on_chunk(amount)
        })?;
    }
    if written != geometry.output_length
        || u64::try_from(root_header.len())
            .map_err(|_| crate::operation::OperationFailureCode::ResourceLimitExceeded)?
            != geometry.root_header_size
    {
        return Err(crate::operation::OperationFailureCode::ValidationFailed);
    }
    Ok(written)
}

/// Verifies card geometry, HFS0 fields, and HFS0 prefix hashes directly from
/// staged bytes. Full NCA digests and CNMT relationships are checked separately
/// by the NCA semantic qualifier. The XCI signature remains opaque: changing
/// signed header fields while retaining its original bytes does not prove that
/// the signature remains valid or authentic.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn verify_staged_output(
    source_file: &mut std::fs::File,
    staged_file: &mut std::fs::File,
    staged_length: u64,
    package: &XczToXciPackagePlan,
    mut on_chunk: impl FnMut(u64) -> Result<(), crate::operation::OperationFailureCode>,
) -> Result<(), crate::operation::OperationFailureCode> {
    use std::io::{Read, Seek, SeekFrom};

    let inspected = crate::recognition::inspect_xci_for_conversion(staged_file, staged_length)
        .map_err(crate::xci_to_nsp::map_recognition_error)?;
    if inspected.secure_members.len() != 2 || inspected.all_hfs_entry_hashes_absent {
        return Err(crate::operation::OperationFailureCode::ValidationFailed);
    }
    let file_length = staged_file
        .metadata()
        .map_err(|_| crate::operation::OperationFailureCode::ValidationFailed)?
        .len();
    if file_length != staged_length {
        return Err(crate::operation::OperationFailureCode::ValidationFailed);
    }

    let mut source_header = [0_u8; CARD_HEADER_SIZE as usize];
    source_file
        .seek(SeekFrom::Start(0))
        .and_then(|_| source_file.read_exact(&mut source_header))
        .map_err(|_| crate::operation::OperationFailureCode::SourceUnavailable)?;
    let mut output_header = [0_u8; CARD_HEADER_SIZE as usize];
    staged_file
        .seek(SeekFrom::Start(0))
        .and_then(|_| staged_file.read_exact(&mut output_header))
        .map_err(|_| crate::operation::OperationFailureCode::ValidationFailed)?;

    let rom_size = source_header[0x10D];
    let valid_data_end = u32::from_le_bytes(
        source_header[0x118..0x11C]
            .try_into()
            .expect("fixed card-header field"),
    );
    let geometry = output_geometry(
        package.meta.length,
        package.program_nca_size,
        package.input.has_logo_partition,
        rom_size,
        valid_data_end,
    )?;
    if staged_length != geometry.output_length {
        return Err(crate::operation::OperationFailureCode::ValidationFailed);
    }

    if output_header[..0x104] != source_header[..0x104]
        || output_header[0x108..0x138] != source_header[0x108..0x138]
        || output_header[0x160..0x200] != source_header[0x160..0x200]
        || output_header[0x10D] != rom_size
        || u32::from_le_bytes(
            output_header[0x118..0x11C]
                .try_into()
                .expect("fixed card-header field"),
        ) != valid_data_end
    {
        return Err(crate::operation::OperationFailureCode::ValidationFailed);
    }
    let root_offset = u64::from_le_bytes(
        output_header[0x130..0x138]
            .try_into()
            .expect("fixed card-header field"),
    );
    let root_header_size = u64::from_le_bytes(
        output_header[0x138..0x140]
            .try_into()
            .expect("fixed card-header field"),
    );
    let page = u32::from_le_bytes(
        output_header[0x104..0x108]
            .try_into()
            .expect("fixed card-header field"),
    );
    let physical_secure_offset = geometry
        .secure_offset
        .checked_add(0x1000)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    if root_offset != ROOT_PLACEMENT
        || root_offset != geometry.root_offset
        || root_header_size != HFS_HEADER_SIZE
        || root_header_size != geometry.root_header_size
        || page != geometry.rom_area_start_page
        || u64::from(page) != physical_secure_offset / CARD_HEADER_SIZE
    {
        return Err(crate::operation::OperationFailureCode::ValidationFailed);
    }

    let root_names = if package.input.has_logo_partition {
        vec!["update", "normal", "secure", "logo"]
    } else {
        vec!["update", "normal", "secure"]
    };
    let secure_names = ["meta.nca", "program.nca"];
    if inspected.root_hfs0_table_size != hfs_table_size(&root_names)?
        || inspected.secure_hfs0_table_size != hfs_table_size(&secure_names)?
        || inspected.root_hfs0_table_size > root_header_size
        || inspected.root_hfs0_header_size != root_header_size
        || inspected.secure_partition_offset != geometry.secure_offset
        || inspected.secure_partition_length != geometry.secure_length
    {
        return Err(crate::operation::OperationFailureCode::ValidationFailed);
    }

    let root_data_start = geometry
        .root_offset
        .checked_add(geometry.root_header_size)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let normal_offset = root_data_start
        .checked_add(CARD_HEADER_SIZE)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let secure_offset = normal_offset
        .checked_add(CARD_HEADER_SIZE)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let mut expected_root = vec![
        ("update", root_data_start, CARD_HEADER_SIZE),
        ("normal", normal_offset, CARD_HEADER_SIZE),
        ("secure", secure_offset, geometry.secure_length),
    ];
    if package.input.has_logo_partition {
        expected_root.push((
            "logo",
            secure_offset
                .checked_add(geometry.secure_length)
                .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?,
            CARD_HEADER_SIZE,
        ));
    }
    verify_hfs_entries(
        staged_file,
        &inspected.root_entries,
        &expected_root,
        staged_length,
        &mut on_chunk,
    )?;

    let expected_secure = [
        ("meta.nca", geometry.meta_offset, package.meta.length),
        (
            "program.nca",
            geometry.program_offset,
            package.program_nca_size,
        ),
    ];
    verify_hfs_entries(
        staged_file,
        &inspected.secure_entries,
        &expected_secure,
        staged_length,
        &mut on_chunk,
    )?;
    if expected_secure
        .iter()
        .any(|(_, offset, _)| !offset.is_multiple_of(CARD_HEADER_SIZE))
        || expected_root
            .iter()
            .any(|(_, offset, _)| !offset.is_multiple_of(CARD_HEADER_SIZE))
    {
        return Err(crate::operation::OperationFailureCode::ValidationFailed);
    }

    let root_digest = hash_file_range(staged_file, root_offset, root_header_size, &mut on_chunk)?;
    if output_header[0x140..0x160] != root_digest {
        return Err(crate::operation::OperationFailureCode::ValidationFailed);
    }

    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn verify_hfs_entries(
    file: &mut std::fs::File,
    entries: &[crate::recognition::XciConversionEntry],
    expected: &[(&str, u64, u64)],
    file_length: u64,
    on_chunk: &mut impl FnMut(u64) -> Result<(), crate::operation::OperationFailureCode>,
) -> Result<(), crate::operation::OperationFailureCode> {
    if entries.len() != expected.len() {
        return Err(crate::operation::OperationFailureCode::ValidationFailed);
    }
    for (entry, (name, offset, length)) in entries.iter().zip(expected) {
        let expected_hash_size = hfs_hash_size(*length)
            .ok_or(crate::operation::OperationFailureCode::ValidationFailed)?;
        let end = entry
            .offset
            .checked_add(entry.length)
            .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
        if entry.name != *name
            || entry.offset != *offset
            || entry.length != *length
            || entry.hashed_size != expected_hash_size
            || entry.reserved_offset != [0; 8]
            || !entry.offset.is_multiple_of(CARD_HEADER_SIZE)
            || end > file_length
            || hash_file_range(
                file,
                entry.offset,
                u64::from(entry.hashed_size),
                &mut *on_chunk,
            )? != entry.digest
        {
            return Err(crate::operation::OperationFailureCode::ValidationFailed);
        }
    }
    Ok(())
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod tests {
    use super::*;
    use crate::nsp_nsz::NspNszDirection;
    use sha2::Digest;
    use std::io::{Read, Seek, SeekFrom, Write};

    fn encoded_xcz_fixture() -> (
        crate::test_synthetic_xci::Fixture,
        crate::test_synthetic_nsp_qualification::Fixture,
    ) {
        encoded_xcz_fixture_with_payload(0x9000)
    }

    fn encoded_xcz_fixture_with_payload(
        payload_size: usize,
    ) -> (
        crate::test_synthetic_xci::Fixture,
        crate::test_synthetic_nsp_qualification::Fixture,
    ) {
        let payload = vec![0xA5; payload_size];
        let nsp_fixture =
            crate::test_synthetic_nsp_qualification::build_with_program_payload(&payload, |_| {});
        let mut nsp_file = tempfile::tempfile().expect("synthetic NSP source");
        nsp_file
            .write_all(&nsp_fixture.package)
            .expect("write synthetic NSP");
        nsp_file
            .seek(SeekFrom::Start(0))
            .expect("rewind synthetic NSP");

        let key_length = u64::try_from(nsp_fixture.key_file.len()).expect("key length fits u64");
        let keys = crate::key_file::read_nsp_qualification_keys(
            &mut std::io::Cursor::new(&nsp_fixture.key_file),
            key_length,
        )
        .expect("synthetic qualification keys");
        let package = crate::nsp_nsz::inspect_package(
            &mut nsp_file,
            u64::try_from(nsp_fixture.package.len()).expect("package length fits u64"),
            NspNszDirection::NspToNsz,
            &keys,
        )
        .expect("synthetic NSP profile");
        let program = &package.members[package.program_index];
        let crypto = crate::nsp_nsz::read_program_crypto(&mut nsp_file, program, &keys)
            .expect("synthetic Program section crypto");
        let suffix_size = program
            .nca_size
            .checked_sub(crate::ncz::NCZ_PREFIX_SIZE)
            .expect("Program is larger than the NCZ prefix");
        let settings = crate::nsp_nsz::NczCompressionSettings::for_plan(3, suffix_size)
            .expect("qualified synthetic Zstandard settings");
        let mut ncz_file = tempfile::tempfile().expect("synthetic NCZ output");
        crate::nsp_nsz::encode_ncz_member(
            &mut nsp_file,
            program,
            &crypto,
            &settings,
            &mut ncz_file,
            |_| Ok(()),
        )
        .expect("encode synthetic Program as NCZ");
        ncz_file
            .seek(SeekFrom::Start(0))
            .expect("rewind synthetic NCZ");
        let mut program_ncz = Vec::new();
        ncz_file
            .read_to_end(&mut program_ncz)
            .expect("read synthetic NCZ");

        let xcz_fixture = crate::test_synthetic_xci::xcz(
            &nsp_fixture.meta_nca,
            &program_ncz,
            &nsp_fixture.package,
            &nsp_fixture.key_file,
        );
        (xcz_fixture, nsp_fixture)
    }

    struct XczTestPaths {
        _root: tempfile::TempDir,
        source: PathBuf,
        destination: PathBuf,
        key_file: PathBuf,
        workspace: PathBuf,
    }

    fn xcz_test_paths(image: &[u8], key_bytes: Option<&[u8]>) -> XczTestPaths {
        let root = tempfile::tempdir().expect("temporary XCZ operation directory");
        let source = root.path().join("source.xcz");
        let destination = root.path().join("output.xci");
        let key_file = root.path().join("keys.dat");
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace).expect("operation workspace");
        std::fs::write(&source, image).expect("write synthetic XCZ");
        if let Some(key_bytes) = key_bytes {
            std::fs::write(&key_file, key_bytes).expect("write synthetic keys");
        }
        XczTestPaths {
            _root: root,
            source,
            destination,
            key_file,
            workspace,
        }
    }

    fn assert_output_hfs_hashes(
        file: &mut std::fs::File,
        source: &crate::recognition::XciConversionSource,
    ) {
        for entry in source.root_entries.iter().chain(&source.secure_entries) {
            let expected_size = hfs_hash_size(entry.length).expect("nonempty output member");
            assert_eq!(entry.hashed_size, expected_size);
            let digest = hash_file_range(file, entry.offset, u64::from(expected_size), |_| Ok(()))
                .expect("hash declared HFS0 prefix");
            assert_eq!(
                entry.digest, digest,
                "HFS0 prefix digest for {}",
                entry.name
            );
        }
    }

    fn qualify_source_for_test(
        source_path: &std::path::Path,
        key_path: &std::path::Path,
    ) -> XczToXciPackagePlan {
        let mut source = std::fs::File::open(source_path).expect("open test XCZ");
        let source_metadata = source.metadata().expect("test XCZ metadata");
        let source_identity =
            crate::file_identity::handle_identity(&source).expect("test XCZ identity");
        let source_snapshot =
            crate::file_identity::file_snapshot(&source_metadata, Some(source_identity));
        let mut key_file = std::fs::File::open(key_path).expect("open test keys");
        let key_metadata = key_file.metadata().expect("test key metadata");
        let key_identity =
            crate::file_identity::handle_identity(&key_file).expect("test key identity");
        let key_snapshot = crate::file_identity::file_snapshot(&key_metadata, Some(key_identity));
        let keys = crate::key_file::read_nsp_qualification_keys(&mut key_file, key_metadata.len())
            .expect("read test qualification keys");
        let mut program_spool = tempfile::tempfile().expect("test Program spool");
        qualify_source(XczQualificationContext {
            source_file: &mut source,
            source_path,
            source_length: source_metadata.len(),
            source_identity,
            source_snapshot,
            key_path,
            key_snapshot,
            keys: &keys,
            program_spool: &mut program_spool,
        })
        .expect("qualify test XCZ source")
    }

    #[test]
    fn engine_reconstructs_xci_with_bounded_prefix_hashes_and_exact_ncas() {
        let directory = tempfile::tempdir().expect("temporary XCZ directory");
        let (fixture, nsp_fixture) = encoded_xcz_fixture();
        let source = directory.path().join("source.xcz");
        let destination = directory.path().join("output.xci");
        let key_file = directory.path().join("keys.dat");
        let workspace = directory.path().join("workspace");
        std::fs::create_dir(&workspace).expect("operation workspace");
        std::fs::write(&source, &fixture.image).expect("write synthetic XCZ");
        std::fs::write(&key_file, &fixture.key_file).expect("write synthetic keys");
        let package = qualify_source_for_test(&source, &key_file);

        let engine = crate::Engine::new();
        let plan = engine
            .plan_xcz_to_xci(XczToXciRequest::new(
                &source,
                &destination,
                &workspace,
                &key_file,
            ))
            .expect("qualified XCZ-to-XCI plan");
        assert_eq!(
            plan.snapshot().operation_kind(),
            crate::OperationKind::XczToXci
        );
        let result = engine.execute_operation(plan, &crate::OperationSession::new());
        assert_eq!(
            result.state(),
            crate::JobState::Succeeded,
            "conversion failed: {:?}",
            result.failure().map(|failure| failure.code())
        );
        assert_eq!(
            result.outcome(),
            Some(crate::OperationOutcome::Decompressed)
        );

        let source_header = &fixture.image[..CARD_HEADER_SIZE as usize];
        let mut output = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&destination)
            .expect("published XCI");
        let output_length = output.metadata().expect("output metadata").len();
        let output_source =
            crate::recognition::inspect_xci_for_conversion(&mut output, output_length)
                .expect("strict output HFS0 hashes validate");
        assert!(!output_source.all_hfs_entry_hashes_absent);
        assert_output_hfs_hashes(&mut output, &output_source);

        let mut output_header = [0_u8; CARD_HEADER_SIZE as usize];
        output
            .seek(SeekFrom::Start(0))
            .expect("rewind output header");
        output
            .read_exact(&mut output_header)
            .expect("read output header");
        assert_eq!(&output_header[..0x100], &source_header[..0x100]);
        assert_eq!(&output_header[0x108..0x130], &source_header[0x108..0x130]);
        assert_eq!(&output_header[0x160..0x180], &source_header[0x160..0x180]);
        assert_eq!(output_header[0x10D], source_header[0x10D]);
        assert_eq!(&output_header[0x118..0x11C], &source_header[0x118..0x11C]);
        assert_eq!(
            u64::from_le_bytes(output_header[0x130..0x138].try_into().expect("root offset")),
            ROOT_PLACEMENT
        );
        assert_eq!(
            u64::from_le_bytes(output_header[0x138..0x140].try_into().expect("root size")),
            HFS_HEADER_SIZE
        );
        let physical_secure_page = output_source
            .secure_partition_offset
            .checked_add(0x1000)
            .expect("physical secure offset fits")
            / CARD_HEADER_SIZE;
        assert_eq!(
            u32::from_le_bytes(
                output_header[0x104..0x108]
                    .try_into()
                    .expect("RomArea page")
            ),
            u32::try_from(physical_secure_page).expect("page fits u32")
        );
        let root_hash = hash_file_range(&mut output, ROOT_PLACEMENT, HFS_HEADER_SIZE, |_| Ok(()))
            .expect("recompute padded root HFS0 hash");
        assert_eq!(&output_header[0x140..0x160], &root_hash);

        for member in &output_source.secure_members {
            let expected = match member.name.as_str() {
                "meta.nca" => &nsp_fixture.meta_nca,
                "program.nca" => &nsp_fixture.program_nca,
                name => panic!("unexpected reconstructed member {name}"),
            };
            assert_eq!(member.length, expected.len() as u64);
            let mut bytes = vec![0_u8; expected.len()];
            output
                .seek(SeekFrom::Start(member.offset))
                .expect("seek reconstructed NCA");
            output
                .read_exact(&mut bytes)
                .expect("read reconstructed NCA");
            assert_eq!(
                bytes, *expected,
                "full reconstructed bytes for {}",
                member.name
            );
            let full_digest: [u8; 32] = sha2::Sha256::digest(&bytes).into();
            let expected_digest: [u8; 32] = sha2::Sha256::digest(expected).into();
            assert_eq!(full_digest, expected_digest);
        }

        let mut source_file = std::fs::File::open(&source).expect("source for postconditions");
        verify_staged_output(
            &mut source_file,
            &mut output,
            output_length,
            &package,
            |_| Ok(()),
        )
        .expect("independent staged-byte postcondition verification");

        output
            .seek(SeekFrom::Start(0x140))
            .expect("seek card-header root digest");
        output
            .write_all(&[output_header[0x140] ^ 0x80])
            .expect("corrupt card-header root digest");
        assert_eq!(
            verify_staged_output(
                &mut source_file,
                &mut output,
                output_length,
                &package,
                |_| Ok(()),
            ),
            Err(crate::OperationFailureCode::ValidationFailed),
            "the strict HFS parser does not substitute for root-header hash verification"
        );
    }

    #[test]
    fn malformed_ncz_and_invalid_keys_fail_before_publication() {
        let (mut fixture, _) = encoded_xcz_fixture();
        let program_entry = fixture.secure_entries[1];
        let frame_marker = program_entry.data_offset
            + usize::try_from(crate::ncz::NCZ_FRAME_OFFSET).expect("frame offset fits usize");
        fixture.image[frame_marker] ^= 0x80;
        let files = xcz_test_paths(&fixture.image, Some(&fixture.key_file));
        let engine = crate::Engine::new();
        assert!(
            engine
                .plan_xcz_to_xci(XczToXciRequest::new(
                    &files.source,
                    &files.destination,
                    &files.workspace,
                    &files.key_file,
                ))
                .is_err(),
            "a damaged NCZ frame must fail qualification"
        );
        assert!(!files.destination.exists());

        let (fixture, _) = encoded_xcz_fixture();
        let files = xcz_test_paths(&fixture.image, None);
        assert!(
            engine
                .plan_xcz_to_xci(XczToXciRequest::new(
                    &files.source,
                    &files.destination,
                    &files.workspace,
                    &files.key_file,
                ))
                .is_err(),
            "missing NCA qualification keys must fail planning"
        );
        assert!(!files.destination.exists());

        let files = xcz_test_paths(&fixture.image, Some(b"invalid synthetic key file"));
        assert!(
            engine
                .plan_xcz_to_xci(XczToXciRequest::new(
                    &files.source,
                    &files.destination,
                    &files.workspace,
                    &files.key_file,
                ))
                .is_err(),
            "malformed NCA qualification keys must fail planning"
        );
        assert!(!files.destination.exists());
    }

    #[test]
    fn source_key_changes_conflicts_and_cancellation_preserve_outputs() {
        let engine = crate::Engine::new();

        let (fixture, _) = encoded_xcz_fixture();
        let files = xcz_test_paths(&fixture.image, Some(&fixture.key_file));
        let plan = engine
            .plan_xcz_to_xci(XczToXciRequest::new(
                &files.source,
                &files.destination,
                &files.workspace,
                &files.key_file,
            ))
            .expect("plan before source mutation");
        std::fs::write(&files.source, b"changed source").expect("mutate source after planning");
        let result = engine.execute_operation(plan, &crate::OperationSession::new());
        assert_eq!(result.state(), crate::JobState::Failed);
        assert!(!files.destination.exists());

        let (fixture, _) = encoded_xcz_fixture();
        let files = xcz_test_paths(&fixture.image, Some(&fixture.key_file));
        let plan = engine
            .plan_xcz_to_xci(XczToXciRequest::new(
                &files.source,
                &files.destination,
                &files.workspace,
                &files.key_file,
            ))
            .expect("plan before key mutation");
        std::fs::write(&files.key_file, b"changed key file").expect("mutate keys after planning");
        let result = engine.execute_operation(plan, &crate::OperationSession::new());
        assert_eq!(result.state(), crate::JobState::Failed);
        assert!(!files.destination.exists());

        let (fixture, _) = encoded_xcz_fixture();
        let files = xcz_test_paths(&fixture.image, Some(&fixture.key_file));
        let plan = engine
            .plan_xcz_to_xci(XczToXciRequest::new(
                &files.source,
                &files.destination,
                &files.workspace,
                &files.key_file,
            ))
            .expect("plan before destination race");
        let sentinel = b"existing destination must survive";
        std::fs::write(&files.destination, sentinel).expect("create competing destination");
        let result = engine.execute_operation(plan, &crate::OperationSession::new());
        assert_ne!(result.state(), crate::JobState::Succeeded);
        assert_eq!(
            std::fs::read(&files.destination).expect("destination after conflict"),
            sentinel
        );

        let (fixture, _) = encoded_xcz_fixture_with_payload(8 * 1024 * 1024);
        let files = xcz_test_paths(&fixture.image, Some(&fixture.key_file));
        let plan = engine
            .plan_xcz_to_xci(XczToXciRequest::new(
                &files.source,
                &files.destination,
                &files.workspace,
                &files.key_file,
            ))
            .expect("plan before cancellation");
        let session = crate::OperationSession::new();
        let cancel_session = session.clone();
        let cancellation = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let Ok(snapshot) = cancel_session.current_operation() else {
                    return false;
                };
                if snapshot.phase() == crate::OperationSessionPhase::Executing {
                    return cancel_session.cancel();
                }
                if std::time::Instant::now() >= deadline {
                    return false;
                }
                std::thread::yield_now();
            }
        });
        let result = engine.execute_operation(plan, &session);
        assert!(cancellation.join().expect("join cancellation observer"));
        assert_eq!(result.state(), crate::JobState::Cancelled);
        assert!(!files.destination.exists());
    }

    #[test]
    fn hfs_prefix_sizing_handles_short_and_u64_sized_members_without_truncation() {
        assert_eq!(hfs_hash_size(0), None);
        let short_member = [0x51_u8, 0x72, 0x93];
        assert_eq!(hfs_hash_size(short_member.len() as u64), Some(3));
        let short_digest = hash_bytes(&short_member);
        let short_header = build_hfs_header(
            &[HfsEntry {
                name: "short.bin",
                relative_data_offset: 0,
                length: u64::try_from(short_member.len()).expect("short length fits u64"),
                digest: short_digest,
            }],
            HFS_HEADER_SIZE,
        )
        .expect("short-member HFS0 header");
        assert_eq!(
            u32::from_le_bytes(
                short_header[16 + 20..16 + 24]
                    .try_into()
                    .expect("hash size")
            ),
            3
        );
        assert_eq!(&short_header[16 + 32..16 + 64], &short_digest);

        let large_length = u64::MAX;
        assert_eq!(hfs_hash_size(large_length), Some(0x200));
        assert_eq!(
            output_geometry(large_length, 1, false, 0xFA, u32::MAX),
            Err(crate::OperationFailureCode::ResourceLimitExceeded)
        );
        let large_header = build_hfs_header(
            &[HfsEntry {
                name: "large.nca",
                relative_data_offset: 0,
                length: large_length,
                digest: [0xA5; 32],
            }],
            HFS_HEADER_SIZE,
        )
        .expect("bounded HFS0 prefix remains representable");
        assert_eq!(
            u64::from_le_bytes(
                large_header[16 + 8..16 + 16]
                    .try_into()
                    .expect("member length")
            ),
            u64::MAX
        );
        assert_eq!(
            u32::from_le_bytes(
                large_header[16 + 20..16 + 24]
                    .try_into()
                    .expect("hash size")
            ),
            0x200
        );
    }

    #[test]
    fn output_prefix_hashes_and_full_content_digests_have_distinct_spans() {
        let short = 0x100_u64;
        let large = 150 * 1024 * 1024_u64;
        assert_eq!(hfs_hash_size(short), Some(0x100));
        assert_eq!(hfs_hash_size(large), Some(0x200));
        assert_ne!(hfs_hash_size(large), u32::try_from(large).ok());
    }
}
