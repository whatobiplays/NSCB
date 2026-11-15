//! Bounded NSP/NSZ conversion for one rights-free Application profile.

#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]

use crate::operation::ConflictPolicy;
use std::path::PathBuf;

/// Describes a request to compress the Program member of a qualified NSP.
///
/// Standard NCZ metadata contains the Program section key and counter in
/// plaintext. The resulting NSZ therefore exposes reusable decryption
/// material to anyone who obtains the artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NspToNszRequest {
    source: PathBuf,
    destination: PathBuf,
    workspace: PathBuf,
    key_file: PathBuf,
    conflict_policy: ConflictPolicy,
}

impl NspToNszRequest {
    /// Creates a compression request with explicit source, destination,
    /// workspace, and semantic-qualification key file paths.
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

    pub(crate) fn into_parts(self) -> NspNszRequestParts {
        NspNszRequestParts {
            source: self.source,
            destination: self.destination,
            workspace: self.workspace,
            key_file: self.key_file,
            conflict_policy: self.conflict_policy,
        }
    }
}

/// Describes a request to reconstruct a qualified NSP from an NSZ.
///
/// Execution requires the external NCA header and Application key-area keys
/// used by the existing semantic qualifier. Keys from NCZ metadata alone do
/// not establish the package's CNMT relationships.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NszToNspRequest {
    source: PathBuf,
    destination: PathBuf,
    workspace: PathBuf,
    key_file: PathBuf,
    conflict_policy: ConflictPolicy,
}

impl NszToNspRequest {
    /// Creates a decompression request with explicit source, destination,
    /// workspace, and semantic-qualification key file paths.
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

    pub(crate) fn into_parts(self) -> NspNszRequestParts {
        NspNszRequestParts {
            source: self.source,
            destination: self.destination,
            workspace: self.workspace,
            key_file: self.key_file,
            conflict_policy: self.conflict_policy,
        }
    }
}

pub(crate) struct NspNszRequestParts {
    pub(crate) source: PathBuf,
    pub(crate) destination: PathBuf,
    pub(crate) workspace: PathBuf,
    pub(crate) key_file: PathBuf,
    pub(crate) conflict_policy: ConflictPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NspNszDirection {
    NspToNsz,
    NszToNsp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NspNszMemberRole {
    Meta,
    Program,
}

/// PFS0 member evidence retained by an immutable conversion plan.
///
/// This structure contains paths, spans, names, and content digests. It never
/// stores section keys or counters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NspNszMember {
    pub(crate) input_name: String,
    pub(crate) output_name: String,
    pub(crate) source_offset: u64,
    pub(crate) source_size: u64,
    pub(crate) source_sha256: crate::sha256::Sha256Digest,
    pub(crate) role: NspNszMemberRole,
    pub(crate) nca_size: u64,
    pub(crate) section_offset: Option<u64>,
    pub(crate) section_size: Option<u64>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct ProgramCrypto {
    pub(crate) section_key: zeroize::Zeroizing<[u8; 16]>,
    pub(crate) section_counter: zeroize::Zeroizing<[u8; 8]>,
}

/// Source member order and content-derived roles captured during planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NspNszPackage {
    pub(crate) direction: NspNszDirection,
    pub(crate) members: Vec<NspNszMember>,
    pub(crate) meta_index: usize,
    pub(crate) program_index: usize,
    pub(crate) program_nca_size: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NspNszFormatError {
    InvalidPackage,
    UnsupportedProfile,
    ResourceLimit,
    KeyOrSectionIntegrityFailure,
    Cancelled,
    SourceIo,
    OutputIo,
}

#[cfg(target_os = "macos")]
pub(crate) const NCZ_PREFIX_SIZE: u64 = 0x4000;
#[cfg(target_os = "macos")]
const NCZ_TABLE_OFFSET: u64 = 0x4010;
#[cfg(target_os = "macos")]
const NCZ_RECORD_SIZE: u64 = 64;
#[cfg(target_os = "macos")]
const NCZ_FRAME_OFFSET: u64 = NCZ_TABLE_OFFSET + NCZ_RECORD_SIZE;
#[cfg(target_os = "macos")]
pub(crate) const MAX_PACKAGE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
#[cfg(target_os = "macos")]
const MAX_PFS0_METADATA_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "macos")]
const ZSTD_WINDOW_LOG: u32 = 27;
#[cfg(target_os = "macos")]
const ZSTD_COMPRESSION_LEVEL: i32 = 9;
#[cfg(target_os = "macos")]
const IO_BUFFER_SIZE: usize = 64 * 1024;

#[cfg(target_os = "macos")]
pub(crate) fn inspect_package(
    source: &mut std::fs::File,
    file_size: u64,
    direction: NspNszDirection,
    keys: &crate::key_file::NspQualificationKeys,
) -> Result<NspNszPackage, NspNszFormatError> {
    use crate::engine::ContainerFormat;
    use std::io::{Seek, SeekFrom};

    if file_size > MAX_PACKAGE_BYTES {
        return Err(NspNszFormatError::ResourceLimit);
    }
    let probe = crate::pfs0::probe_with_limits(source, file_size, 2, MAX_PFS0_METADATA_BYTES)
        .map_err(|error| match error.code() {
            crate::ContainerProbeErrorCode::LimitExceeded
            | crate::ContainerProbeErrorCode::ResourceLimitExceeded => {
                NspNszFormatError::ResourceLimit
            }
            crate::ContainerProbeErrorCode::InputUnavailable => NspNszFormatError::SourceIo,
            _ => NspNszFormatError::InvalidPackage,
        })?;
    if probe.format != ContainerFormat::Pfs0 || probe.entries.len() != 2 {
        return Err(NspNszFormatError::InvalidPackage);
    }
    if !pfs0_payload_is_accounted(&probe) {
        return Err(NspNszFormatError::InvalidPackage);
    }

    let mut members = Vec::new();
    members
        .try_reserve_exact(2)
        .map_err(|_| NspNszFormatError::ResourceLimit)?;
    let mut meta_index = None;
    let mut program_index = None;
    for entry in &probe.entries {
        let (nca_size, is_compressed, ncz_geometry) = match direction {
            NspNszDirection::NspToNsz => {
                if !entry.name.ends_with(".nca") {
                    return Err(NspNszFormatError::UnsupportedProfile);
                }
                (entry.size, false, None)
            }
            NspNszDirection::NszToNsp if entry.name.ends_with(".ncz") => {
                let mut ncz = SpanReader::new(&mut *source, entry.file_offset, entry.size);
                let record = read_ncz_record(&mut ncz, entry.size)?;
                (
                    record.nca_size,
                    true,
                    Some((record.section_offset, record.section_size)),
                )
            }
            NspNszDirection::NszToNsp if entry.name.ends_with(".nca") => (entry.size, false, None),
            NspNszDirection::NszToNsp => {
                return Err(NspNszFormatError::UnsupportedProfile);
            }
        };
        if entry.size == 0 || nca_size > MAX_PACKAGE_BYTES {
            return Err(NspNszFormatError::ResourceLimit);
        }

        let mut nca = SpanReader::new(&mut *source, entry.file_offset, entry.size);
        let block = crate::nca::read_header_block(&mut nca, nca_size, keys.header_key.as_bytes())
            .map_err(map_nca_header_error)?;
        let header =
            crate::nca::parse_header_block(&block, nca_size).map_err(map_nca_header_error)?;
        validate_supported_header(&block, &header, nca_size)?;

        let (role, output_name) = match header.content_type {
            crate::nca::ContentType::Meta => {
                if is_compressed || !entry.name.ends_with(".nca") {
                    return Err(NspNszFormatError::UnsupportedProfile);
                }
                if meta_index.is_some() {
                    return Err(NspNszFormatError::InvalidPackage);
                }
                meta_index = Some(members.len());
                (NspNszMemberRole::Meta, entry.name.clone())
            }
            crate::nca::ContentType::Program => {
                let (from, to) = match direction {
                    NspNszDirection::NspToNsz => {
                        if is_compressed {
                            return Err(NspNszFormatError::UnsupportedProfile);
                        }
                        (".nca", ".ncz")
                    }
                    NspNszDirection::NszToNsp => {
                        if !is_compressed {
                            return Err(NspNszFormatError::UnsupportedProfile);
                        }
                        (".ncz", ".nca")
                    }
                };
                if program_index.is_some() {
                    return Err(NspNszFormatError::InvalidPackage);
                }
                program_index = Some(members.len());
                (
                    NspNszMemberRole::Program,
                    replace_terminal_suffix(&entry.name, from, to)?,
                )
            }
            _ => return Err(NspNszFormatError::UnsupportedProfile),
        };

        let partition = header
            .partitions
            .first()
            .ok_or(NspNszFormatError::UnsupportedProfile)?;
        let section_end = partition
            .offset
            .checked_add(partition.size)
            .ok_or(NspNszFormatError::ResourceLimit)?;
        if section_end != nca_size {
            return Err(NspNszFormatError::UnsupportedProfile);
        }
        if let Some((record_offset, record_size)) = ncz_geometry {
            let standard_record =
                record_offset == partition.offset && record_size == nca_size - partition.offset;
            let clipped_record =
                record_offset == NCZ_PREFIX_SIZE && record_size == nca_size - NCZ_PREFIX_SIZE;
            if !standard_record && !clipped_record {
                return Err(NspNszFormatError::UnsupportedProfile);
            }
        }
        if role == NspNszMemberRole::Program
            && (nca_size <= NCZ_PREFIX_SIZE || partition.offset > NCZ_PREFIX_SIZE)
        {
            return Err(NspNszFormatError::UnsupportedProfile);
        }

        let source_sha256 = hash_span(source, entry.file_offset, entry.size)?;
        members.push(NspNszMember {
            input_name: entry.name.clone(),
            output_name,
            source_offset: entry.file_offset,
            source_size: entry.size,
            source_sha256,
            role,
            nca_size,
            section_offset: (role == NspNszMemberRole::Program).then_some(partition.offset),
            section_size: (role == NspNszMemberRole::Program).then_some(partition.size),
        });
    }

    let meta_index = meta_index.ok_or(NspNszFormatError::InvalidPackage)?;
    let program_index = program_index.ok_or(NspNszFormatError::InvalidPackage)?;
    let program_nca_size = members[program_index].nca_size;
    let names = members
        .iter()
        .map(|member| member.output_name.clone())
        .collect::<Vec<_>>();
    ensure_distinct_names(&names)?;
    let layout_members = members
        .iter()
        .map(|member| (member.output_name.clone(), member.source_size))
        .collect::<Vec<_>>();
    crate::multi_content_format::build_pfs0_layout(&layout_members).map_err(map_format_error)?;

    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| NspNszFormatError::SourceIo)?;
    Ok(NspNszPackage {
        direction,
        members,
        meta_index,
        program_index,
        program_nca_size,
    })
}

#[cfg(target_os = "macos")]
fn pfs0_payload_is_accounted(probe: &crate::engine::ContainerProbeResult) -> bool {
    let mut spans = probe
        .entries
        .iter()
        .map(|entry| (entry.offset, entry.size))
        .collect::<Vec<_>>();
    spans.sort_unstable();
    let mut expected = 0_u64;
    for (offset, size) in spans {
        if offset != expected {
            return false;
        }
        let Some(end) = offset.checked_add(size) else {
            return false;
        };
        expected = end;
    }
    expected == probe.payload_size
}

#[cfg(target_os = "macos")]
fn validate_supported_header(
    block: &[u8; crate::nca::HEADER_SIZE],
    header: &crate::nca::Header,
    nca_size: u64,
) -> Result<(), NspNszFormatError> {
    if header.distribution != crate::nca::Distribution::Download
        || header.key_generation > 1
        || header.kaek_index != 0
        || block[0x230..0x240].iter().any(|byte| *byte != 0)
        || header.partitions.len() != 1
        || header.partitions[0].index != 0
        || header.partitions[0].filesystem != 1
        || header.partitions[0].hash_type != 2
        || header.partitions[0].encryption != 3
        || header.partitions[0].extended
        || !crate::verification::fs_header_hash_matches(block, 0)
    {
        return Err(NspNszFormatError::UnsupportedProfile);
    }
    let partition = &header.partitions[0];
    if partition
        .offset
        .checked_add(partition.size)
        .filter(|end| *end == nca_size)
        .is_none()
    {
        return Err(NspNszFormatError::UnsupportedProfile);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn replace_terminal_suffix(name: &str, from: &str, to: &str) -> Result<String, NspNszFormatError> {
    let basename = name
        .strip_suffix(from)
        .filter(|basename| !basename.is_empty())
        .ok_or(NspNszFormatError::UnsupportedProfile)?;
    let mut result = String::new();
    result
        .try_reserve_exact(basename.len() + to.len())
        .map_err(|_| NspNszFormatError::ResourceLimit)?;
    result.push_str(basename);
    result.push_str(to);
    Ok(result)
}

#[cfg(target_os = "macos")]
fn ensure_distinct_names(names: &[String]) -> Result<(), NspNszFormatError> {
    use std::collections::HashSet;
    use unicode_normalization::UnicodeNormalization;

    let mut seen = HashSet::new();
    seen.try_reserve(names.len())
        .map_err(|_| NspNszFormatError::ResourceLimit)?;
    for name in names {
        let normalized = name.nfkc().flat_map(char::to_lowercase).collect::<String>();
        if !seen.insert(normalized) {
            return Err(NspNszFormatError::InvalidPackage);
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn hash_span(
    source: &mut std::fs::File,
    offset: u64,
    length: u64,
) -> Result<crate::sha256::Sha256Digest, NspNszFormatError> {
    use sha2::{Digest as _, Sha256};
    use std::io::{Read, Seek, SeekFrom};

    source
        .seek(SeekFrom::Start(offset))
        .map_err(|_| NspNszFormatError::SourceIo)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; IO_BUFFER_SIZE];
    let mut remaining = length;
    while remaining > 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| NspNszFormatError::ResourceLimit)?;
        let read = source
            .read(&mut buffer[..wanted])
            .map_err(|_| NspNszFormatError::SourceIo)?;
        if read == 0 {
            return Err(NspNszFormatError::InvalidPackage);
        }
        hasher.update(&buffer[..read]);
        remaining -= u64::try_from(read).map_err(|_| NspNszFormatError::ResourceLimit)?;
    }
    Ok(crate::sha256::Sha256Digest::from_bytes(
        hasher.finalize().into(),
    ))
}

#[cfg(target_os = "macos")]
struct NczRecord {
    nca_size: u64,
    section_offset: u64,
    section_size: u64,
    frame_offset: u64,
    frame_size: u64,
    key: zeroize::Zeroizing<[u8; 16]>,
    counter: zeroize::Zeroizing<[u8; 16]>,
}

#[cfg(target_os = "macos")]
fn read_ncz_record<R: std::io::Read + std::io::Seek>(
    member: &mut SpanReader<R>,
    member_size: u64,
) -> Result<NczRecord, NspNszFormatError> {
    use std::io::{Read, Seek, SeekFrom};

    if member_size <= NCZ_FRAME_OFFSET {
        return Err(NspNszFormatError::InvalidPackage);
    }
    member
        .seek(SeekFrom::Start(NCZ_PREFIX_SIZE))
        .map_err(|_| NspNszFormatError::SourceIo)?;
    let mut marker = [0_u8; 8];
    member.read_exact(&mut marker).map_err(map_ncz_read_error)?;
    if &marker != b"NCZSECTN" {
        return Err(NspNszFormatError::InvalidPackage);
    }
    let mut count = [0_u8; 8];
    member.read_exact(&mut count).map_err(map_ncz_read_error)?;
    if u64::from_le_bytes(count) != 1 {
        return Err(NspNszFormatError::UnsupportedProfile);
    }

    let mut record = zeroize::Zeroizing::new([0_u8; NCZ_RECORD_SIZE as usize]);
    member
        .read_exact(&mut record[..])
        .map_err(map_ncz_read_error)?;
    let offset = u64::from_le_bytes(record[0..8].try_into().expect("fixed NCZ field"));
    let section_size = u64::from_le_bytes(record[8..16].try_into().expect("fixed NCZ field"));
    let crypto_type = u64::from_le_bytes(record[16..24].try_into().expect("fixed NCZ field"));
    if offset > NCZ_PREFIX_SIZE
        || section_size == 0
        || crypto_type != 3
        || record[24..32].iter().any(|byte| *byte != 0)
        || record[56..64].iter().any(|byte| *byte != 0)
    {
        return Err(NspNszFormatError::UnsupportedProfile);
    }
    let nca_size = offset
        .checked_add(section_size)
        .ok_or(NspNszFormatError::ResourceLimit)?;
    if nca_size <= NCZ_PREFIX_SIZE {
        return Err(NspNszFormatError::UnsupportedProfile);
    }
    let frame_size = member_size
        .checked_sub(NCZ_FRAME_OFFSET)
        .filter(|size| *size > 0)
        .ok_or(NspNszFormatError::InvalidPackage)?;
    member
        .seek(SeekFrom::Start(NCZ_FRAME_OFFSET))
        .map_err(|_| NspNszFormatError::SourceIo)?;
    let mut frame_marker = [0_u8; 8];
    member
        .read_exact(&mut frame_marker)
        .map_err(map_ncz_read_error)?;
    if &frame_marker == b"NCZBLOCK" {
        return Err(NspNszFormatError::UnsupportedProfile);
    }

    let mut key = zeroize::Zeroizing::new([0_u8; 16]);
    key.copy_from_slice(&record[32..48]);
    let mut counter = zeroize::Zeroizing::new([0_u8; 16]);
    counter.copy_from_slice(&record[48..64]);
    Ok(NczRecord {
        nca_size,
        section_offset: offset,
        section_size,
        frame_offset: NCZ_FRAME_OFFSET,
        frame_size,
        key,
        counter,
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn read_program_crypto(
    source: &mut std::fs::File,
    member: &NspNszMember,
    keys: &crate::key_file::NspQualificationKeys,
) -> Result<ProgramCrypto, NspNszFormatError> {
    if member.role != NspNszMemberRole::Program {
        return Err(NspNszFormatError::UnsupportedProfile);
    }
    let mut span = SpanReader::new(&mut *source, member.source_offset, member.source_size);
    let block =
        crate::nca::read_header_block(&mut span, member.nca_size, keys.header_key.as_bytes())
            .map_err(map_nca_header_error)?;
    let header =
        crate::nca::parse_header_block(&block, member.nca_size).map_err(map_nca_header_error)?;
    validate_supported_header(&block, &header, member.nca_size)?;
    if header.content_type != crate::nca::ContentType::Program {
        return Err(NspNszFormatError::UnsupportedProfile);
    }
    let partition = header
        .partitions
        .first()
        .ok_or(NspNszFormatError::UnsupportedProfile)?;
    if Some(partition.offset) != member.section_offset
        || Some(partition.size) != member.section_size
    {
        return Err(NspNszFormatError::InvalidPackage);
    }
    let key = crate::nca_crypto::decrypt_key_area_slot2(
        &block[0x300..0x340],
        keys.application_kaek.as_bytes(),
    )
    .ok_or(NspNszFormatError::KeyOrSectionIntegrityFailure)?;
    let mut counter = zeroize::Zeroizing::new([0_u8; 8]);
    counter.copy_from_slice(&block[0x400 + 0x140..0x400 + 0x148]);
    Ok(ProgramCrypto {
        section_key: key,
        section_counter: counter,
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn ncz_member_bound(nca_size: u64) -> Result<u64, NspNszFormatError> {
    if nca_size <= NCZ_PREFIX_SIZE {
        return Err(NspNszFormatError::UnsupportedProfile);
    }
    let suffix_size = nca_size
        .checked_sub(NCZ_PREFIX_SIZE)
        .ok_or(NspNszFormatError::ResourceLimit)?;
    let suffix_size = usize::try_from(suffix_size).map_err(|_| NspNszFormatError::ResourceLimit)?;
    let frame_bound = u64::try_from(zstd::compress_bound(suffix_size))
        .map_err(|_| NspNszFormatError::ResourceLimit)?;
    NCZ_FRAME_OFFSET
        .checked_add(frame_bound)
        .ok_or(NspNszFormatError::ResourceLimit)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn encode_ncz_member(
    source: &mut std::fs::File,
    member: &NspNszMember,
    crypto: &ProgramCrypto,
    output: &mut std::fs::File,
    mut on_chunk: impl FnMut(u64) -> Result<(), NspNszFormatError>,
) -> Result<(), NspNszFormatError> {
    use std::io::{Read, Seek, SeekFrom, Write};

    if member.role != NspNszMemberRole::Program {
        return Err(NspNszFormatError::UnsupportedProfile);
    }
    let source_offset = member.source_offset;
    let nca_size = member.nca_size;
    let section_offset = member
        .section_offset
        .ok_or(NspNszFormatError::UnsupportedProfile)?;
    let section_size = member
        .section_size
        .ok_or(NspNszFormatError::UnsupportedProfile)?;
    let suffix_size = nca_size
        .checked_sub(NCZ_PREFIX_SIZE)
        .filter(|size| *size > 0)
        .ok_or(NspNszFormatError::UnsupportedProfile)?;
    if section_offset > NCZ_PREFIX_SIZE
        || section_offset
            .checked_add(section_size)
            .filter(|end| *end == nca_size)
            .is_none()
        || NCZ_PREFIX_SIZE < section_offset
    {
        return Err(NspNszFormatError::UnsupportedProfile);
    }
    let bound = ncz_member_bound(nca_size)?;
    let mut limited = LimitedWriter::new(output, bound);
    copy_file_span(
        source,
        source_offset,
        NCZ_PREFIX_SIZE,
        &mut limited,
        &mut on_chunk,
    )?;

    limited
        .write_all(b"NCZSECTN")
        .map_err(|_| NspNszFormatError::OutputIo)?;
    limited
        .write_all(&1_u64.to_le_bytes())
        .map_err(|_| NspNszFormatError::OutputIo)?;
    limited
        .write_all(&NCZ_PREFIX_SIZE.to_le_bytes())
        .map_err(|_| NspNszFormatError::OutputIo)?;
    limited
        .write_all(&suffix_size.to_le_bytes())
        .map_err(|_| NspNszFormatError::OutputIo)?;
    limited
        .write_all(&3_u64.to_le_bytes())
        .map_err(|_| NspNszFormatError::OutputIo)?;
    limited
        .write_all(&[0_u8; 8])
        .map_err(|_| NspNszFormatError::OutputIo)?;
    limited
        .write_all(&crypto.section_key[..])
        .map_err(|_| NspNszFormatError::OutputIo)?;
    let mut serialized_counter = zeroize::Zeroizing::new([0_u8; 16]);
    for (destination, source) in serialized_counter[..8]
        .iter_mut()
        .zip(crypto.section_counter.iter().rev())
    {
        *destination = *source;
    }
    limited
        .write_all(&serialized_counter[..])
        .map_err(|_| NspNszFormatError::OutputIo)?;

    let mut member = SpanReader::new(&mut *source, source_offset, nca_size);
    let mut section = crate::nca_crypto::NcaCtrReader::new(
        &mut member,
        section_offset,
        section_size,
        &crypto.section_key,
        *crypto.section_counter,
    );
    let start = NCZ_PREFIX_SIZE
        .checked_sub(section_offset)
        .ok_or(NspNszFormatError::UnsupportedProfile)?;
    section
        .seek(SeekFrom::Start(start))
        .map_err(|_| NspNszFormatError::InvalidPackage)?;

    let mut encoder = zstd::stream::write::Encoder::new(&mut limited, ZSTD_COMPRESSION_LEVEL)
        .map_err(|_| NspNszFormatError::OutputIo)?;
    encoder
        .window_log(ZSTD_WINDOW_LOG)
        .map_err(|_| NspNszFormatError::UnsupportedProfile)?;
    encoder
        .include_checksum(true)
        .map_err(|_| NspNszFormatError::UnsupportedProfile)?;
    encoder
        .include_contentsize(true)
        .map_err(|_| NspNszFormatError::UnsupportedProfile)?;
    encoder
        .set_pledged_src_size(Some(suffix_size))
        .map_err(|_| NspNszFormatError::ResourceLimit)?;

    let mut buffer = [0_u8; IO_BUFFER_SIZE];
    let mut remaining = suffix_size;
    while remaining > 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| NspNszFormatError::ResourceLimit)?;
        let read = section
            .read(&mut buffer[..wanted])
            .map_err(|_| NspNszFormatError::SourceIo)?;
        if read == 0 {
            return Err(NspNszFormatError::InvalidPackage);
        }
        encoder
            .write_all(&buffer[..read])
            .map_err(|_| NspNszFormatError::OutputIo)?;
        remaining -= u64::try_from(read).map_err(|_| NspNszFormatError::ResourceLimit)?;
        on_chunk(u64::try_from(read).map_err(|_| NspNszFormatError::ResourceLimit)?)?;
    }
    encoder.finish().map_err(|_| NspNszFormatError::OutputIo)?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| NspNszFormatError::SourceIo)?;
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn decode_ncz_member(
    source: &mut std::fs::File,
    member: &NspNszMember,
    output: &mut std::fs::File,
    mut on_chunk: impl FnMut(u64) -> Result<(), NspNszFormatError>,
) -> Result<(), NspNszFormatError> {
    use std::io::{Read, Seek, SeekFrom, Write};
    use zeroize::Zeroizing;

    if member.role != NspNszMemberRole::Program {
        return Err(NspNszFormatError::UnsupportedProfile);
    }
    let source_offset = member.source_offset;
    let source_size = member.source_size;
    let expected_nca_size = member.nca_size;
    let section_offset = member
        .section_offset
        .ok_or(NspNszFormatError::UnsupportedProfile)?;
    let section_size = member
        .section_size
        .ok_or(NspNszFormatError::UnsupportedProfile)?;
    let mut member = SpanReader::new(&mut *source, source_offset, source_size);
    let record = read_ncz_record(&mut member, source_size)?;
    let encoded_suffix_size = expected_nca_size
        .checked_sub(NCZ_PREFIX_SIZE)
        .filter(|size| *size > 0)
        .ok_or(NspNszFormatError::UnsupportedProfile)?;
    let standard_record =
        record.section_offset == section_offset && record.section_size == section_size;
    let clipped_record =
        record.section_offset == NCZ_PREFIX_SIZE && record.section_size == encoded_suffix_size;
    if record.nca_size != expected_nca_size
        || section_offset > NCZ_PREFIX_SIZE
        || section_offset
            .checked_add(section_size)
            .filter(|end| *end == expected_nca_size)
            .is_none()
        || (!standard_record && !clipped_record)
    {
        return Err(NspNszFormatError::UnsupportedProfile);
    }

    copy_file_span(
        source,
        source_offset,
        NCZ_PREFIX_SIZE,
        output,
        &mut on_chunk,
    )?;
    let frame_source_offset = source_offset
        .checked_add(record.frame_offset)
        .ok_or(NspNszFormatError::ResourceLimit)?;
    let frame_reader = SpanReader::new(&mut *source, frame_source_offset, record.frame_size);
    let source_io_tracker = SourceIoTracker::default();
    let frame_reader = source_io_tracker.track(frame_reader);
    let mut decoder = zstd::stream::read::Decoder::new(frame_reader)
        .map_err(|_| source_io_tracker.zstd_error())?
        .single_frame();
    decoder
        .window_log_max(ZSTD_WINDOW_LOG)
        .map_err(|_| NspNszFormatError::UnsupportedProfile)?;

    let mut raw_counter = Zeroizing::new([0_u8; 8]);
    for (destination, source) in raw_counter.iter_mut().zip(record.counter[..8].iter().rev()) {
        *destination = *source;
    }
    let mut decoded = 0_u64;
    let mut buffer = Zeroizing::new([0_u8; IO_BUFFER_SIZE]);
    loop {
        let read = decoder
            .read(&mut buffer[..])
            .map_err(|_| source_io_tracker.zstd_error())?;
        if read == 0 {
            break;
        }
        let next = decoded
            .checked_add(u64::try_from(read).map_err(|_| NspNszFormatError::ResourceLimit)?)
            .ok_or(NspNszFormatError::ResourceLimit)?;
        if next > encoded_suffix_size {
            return Err(NspNszFormatError::InvalidPackage);
        }
        apply_ctr_at_nca_offset(
            &record.key,
            &raw_counter,
            section_offset,
            NCZ_PREFIX_SIZE - section_offset + decoded,
            &mut buffer[..read],
        )?;
        output
            .write_all(&buffer[..read])
            .map_err(|_| NspNszFormatError::OutputIo)?;
        decoded = next;
        on_chunk(u64::try_from(read).map_err(|_| NspNszFormatError::ResourceLimit)?)?;
    }
    if decoded != encoded_suffix_size {
        return Err(NspNszFormatError::InvalidPackage);
    }
    let mut frame_reader = decoder.finish();
    let consumed = frame_reader
        .stream_position()
        .map_err(|_| NspNszFormatError::SourceIo)?;
    if consumed != record.frame_size {
        return Err(NspNszFormatError::InvalidPackage);
    }
    output
        .seek(SeekFrom::Start(0))
        .map_err(|_| NspNszFormatError::OutputIo)?;
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn apply_ctr_at_nca_offset(
    key: &[u8; 16],
    raw_counter: &[u8; 8],
    section_offset: u64,
    section_relative_offset: u64,
    bytes: &mut [u8],
) -> Result<(), NspNszFormatError> {
    use aes::Aes128;
    use aes::cipher::{KeyIvInit, StreamCipher};
    use ctr::Ctr128BE;
    use zeroize::Zeroizing;

    let block = (section_offset / 16)
        .checked_add(section_relative_offset / 16)
        .ok_or(NspNszFormatError::ResourceLimit)?;
    let mut counter = [0_u8; 16];
    for (destination, source) in counter[..8].iter_mut().zip(raw_counter.iter().rev()) {
        *destination = *source;
    }
    counter[8..].copy_from_slice(&block.to_be_bytes());
    let mut cipher = Ctr128BE::<Aes128>::new_from_slices(key, &counter)
        .map_err(|_| NspNszFormatError::UnsupportedProfile)?;
    let skip = usize::try_from(section_relative_offset % 16)
        .map_err(|_| NspNszFormatError::ResourceLimit)?;
    if skip > 0 {
        let mut skipped = Zeroizing::new([0_u8; 16]);
        cipher.apply_keystream(&mut skipped[..skip]);
    }
    cipher.apply_keystream(bytes);
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn copy_file_span<W: std::io::Write>(
    source: &mut std::fs::File,
    offset: u64,
    length: u64,
    output: &mut W,
    on_chunk: &mut impl FnMut(u64) -> Result<(), NspNszFormatError>,
) -> Result<(), NspNszFormatError> {
    use std::io::{Read, Seek, SeekFrom};

    source
        .seek(SeekFrom::Start(offset))
        .map_err(|_| NspNszFormatError::SourceIo)?;
    let mut remaining = length;
    let mut buffer = ZeroizingBuffer::new();
    while remaining > 0 {
        let wanted = usize::try_from(remaining.min(IO_BUFFER_SIZE as u64))
            .map_err(|_| NspNszFormatError::ResourceLimit)?;
        let read = source
            .read(&mut buffer.0[..wanted])
            .map_err(|_| NspNszFormatError::SourceIo)?;
        if read == 0 {
            return Err(NspNszFormatError::InvalidPackage);
        }
        output
            .write_all(&buffer.0[..read])
            .map_err(|_| NspNszFormatError::OutputIo)?;
        remaining -= u64::try_from(read).map_err(|_| NspNszFormatError::ResourceLimit)?;
        on_chunk(u64::try_from(read).map_err(|_| NspNszFormatError::ResourceLimit)?)?;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct ZeroizingBuffer(zeroize::Zeroizing<[u8; IO_BUFFER_SIZE]>);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ZeroizingBuffer {
    fn new() -> Self {
        Self(zeroize::Zeroizing::new([0_u8; IO_BUFFER_SIZE]))
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct LimitedWriter<W> {
    inner: W,
    remaining: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl<W> LimitedWriter<W> {
    fn new(inner: W, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl<W: std::io::Write> std::io::Write for LimitedWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
        }
        let allowed = usize::try_from(self.remaining.min(buffer.len() as u64))
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let written = self.inner.write(&buffer[..allowed])?;
        self.remaining -= u64::try_from(written)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(target_os = "macos")]
struct SpanReader<R> {
    inner: R,
    base: u64,
    length: u64,
    position: u64,
}

#[cfg(target_os = "macos")]
impl<R> SpanReader<R> {
    fn new(inner: R, base: u64, length: u64) -> Self {
        Self {
            inner,
            base,
            length,
            position: 0,
        }
    }
}

#[cfg(target_os = "macos")]
impl<R: std::io::Read + std::io::Seek> std::io::Read for SpanReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        use std::io::SeekFrom;

        if buffer.is_empty() || self.position >= self.length {
            return Ok(0);
        }
        let count = usize::try_from((self.length - self.position).min(buffer.len() as u64))
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let absolute = self
            .base
            .checked_add(self.position)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        self.inner.seek(SeekFrom::Start(absolute))?;
        let read = self.inner.read(&mut buffer[..count])?;
        self.position = self
            .position
            .checked_add(read as u64)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        Ok(read)
    }
}

#[cfg(target_os = "macos")]
impl<R: std::io::Read + std::io::Seek> std::io::Seek for SpanReader<R> {
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        let next = match position {
            std::io::SeekFrom::Start(value) => value,
            std::io::SeekFrom::End(value) => self
                .length
                .checked_add_signed(value)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?,
            std::io::SeekFrom::Current(value) => self
                .position
                .checked_add_signed(value)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?,
        };
        if next > self.length {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        }
        self.position = next;
        Ok(next)
    }
}

#[cfg(target_os = "macos")]
fn map_ncz_read_error(error: std::io::Error) -> NspNszFormatError {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        NspNszFormatError::InvalidPackage
    } else {
        NspNszFormatError::SourceIo
    }
}

#[cfg(target_os = "macos")]
fn map_nca_header_error(error: crate::nca::HeaderError) -> NspNszFormatError {
    match error {
        crate::nca::HeaderError::UnsupportedFormat => NspNszFormatError::UnsupportedProfile,
        crate::nca::HeaderError::TruncatedInput | crate::nca::HeaderError::MalformedInput => {
            NspNszFormatError::InvalidPackage
        }
        crate::nca::HeaderError::InputUnavailable => NspNszFormatError::SourceIo,
        crate::nca::HeaderError::AllocationFailed => NspNszFormatError::ResourceLimit,
    }
}

#[cfg(target_os = "macos")]
#[derive(Clone, Default)]
struct SourceIoTracker(std::rc::Rc<std::cell::Cell<bool>>);

#[cfg(target_os = "macos")]
impl SourceIoTracker {
    fn track<R: std::io::Read + std::io::Seek>(&self, inner: R) -> TrackedSourceReader<R> {
        TrackedSourceReader {
            inner,
            tracker: self.clone(),
        }
    }

    fn zstd_error(&self) -> NspNszFormatError {
        if self.0.get() {
            NspNszFormatError::SourceIo
        } else {
            NspNszFormatError::InvalidPackage
        }
    }
}

#[cfg(target_os = "macos")]
struct TrackedSourceReader<R> {
    inner: R,
    tracker: SourceIoTracker,
}

#[cfg(target_os = "macos")]
impl<R: std::io::Read> std::io::Read for TrackedSourceReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self.inner.read(buffer) {
            Err(error) => {
                self.tracker.0.set(true);
                Err(error)
            }
            result => result,
        }
    }
}

#[cfg(target_os = "macos")]
impl<R: std::io::Seek> std::io::Seek for TrackedSourceReader<R> {
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        match self.inner.seek(position) {
            Err(error) => {
                self.tracker.0.set(true);
                Err(error)
            }
            result => result,
        }
    }
}

#[cfg(target_os = "macos")]
fn map_format_error(error: crate::multi_content_format::FormatError) -> NspNszFormatError {
    match error {
        crate::multi_content_format::FormatError::ResourceLimit => NspNszFormatError::ResourceLimit,
        crate::multi_content_format::FormatError::InvalidPackage
        | crate::multi_content_format::FormatError::DuplicateMember => {
            NspNszFormatError::InvalidPackage
        }
        _ => NspNszFormatError::UnsupportedProfile,
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::{
        MAX_PACKAGE_BYTES, NspNszDirection, NspNszFormatError, SourceIoTracker,
        ensure_distinct_names, inspect_package, map_nca_header_error, replace_terminal_suffix,
    };
    use std::io::Read as _;

    #[test]
    fn nca_header_errors_preserve_io_and_allocation_classification() {
        use crate::nca::HeaderError;

        for (header_error, expected) in [
            (
                HeaderError::UnsupportedFormat,
                NspNszFormatError::UnsupportedProfile,
            ),
            (
                HeaderError::TruncatedInput,
                NspNszFormatError::InvalidPackage,
            ),
            (
                HeaderError::MalformedInput,
                NspNszFormatError::InvalidPackage,
            ),
            (HeaderError::InputUnavailable, NspNszFormatError::SourceIo),
            (
                HeaderError::AllocationFailed,
                NspNszFormatError::ResourceLimit,
            ),
        ] {
            assert_eq!(map_nca_header_error(header_error), expected);
        }
    }

    #[test]
    fn decoder_read_errors_distinguish_source_io_from_invalid_frames() {
        struct FailingReader;

        impl std::io::Read for FailingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            }
        }

        impl std::io::Seek for FailingReader {
            fn seek(&mut self, _position: std::io::SeekFrom) -> std::io::Result<u64> {
                Ok(0)
            }
        }

        let tracker = SourceIoTracker::default();
        assert_eq!(tracker.zstd_error(), NspNszFormatError::InvalidPackage);

        let mut reader = tracker.track(FailingReader);
        assert_eq!(
            reader.read(&mut [0_u8; 1]).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(tracker.zstd_error(), NspNszFormatError::SourceIo);
    }

    #[test]
    fn member_suffix_conversion_requires_the_exact_supported_casing() {
        assert_eq!(
            replace_terminal_suffix("content.nca", ".nca", ".ncz").unwrap(),
            "content.ncz"
        );
        assert_eq!(
            replace_terminal_suffix("content.NCA", ".nca", ".ncz"),
            Err(NspNszFormatError::UnsupportedProfile)
        );
        assert_eq!(
            replace_terminal_suffix("content", ".nca", ".ncz"),
            Err(NspNszFormatError::UnsupportedProfile)
        );
    }

    #[test]
    fn output_member_names_collide_without_case_or_compatibility_aliases() {
        let names = [String::from("Program.nca"), String::from("program.nca")];
        assert_eq!(
            ensure_distinct_names(&names),
            Err(NspNszFormatError::InvalidPackage)
        );
    }

    #[test]
    fn package_size_limit_fails_before_reading_package_bytes() {
        let mut source = tempfile::tempfile().expect("temporary package file");
        let key_file = format!(
            "header_key = {}\nkey_area_key_application_00 = {}\n",
            "42".repeat(32),
            "24".repeat(16)
        );
        let keys = crate::key_file::read_nsp_qualification_keys(
            &mut std::io::Cursor::new(key_file.as_bytes()),
            key_file.len() as u64,
        )
        .expect("synthetic qualification keys");

        for direction in [NspNszDirection::NspToNsz, NspNszDirection::NszToNsp] {
            assert_eq!(
                inspect_package(&mut source, MAX_PACKAGE_BYTES + 1, direction, &keys),
                Err(NspNszFormatError::ResourceLimit)
            );
        }
    }
}
