//! Parses and writes the bounded PFS0 and plaintext Program NCA profile.
//!
//! Member bytes are hashed while they are read or copied in fixed-size chunks.
//! Structural parsing does not authenticate the NCA header or the source
//! container.

use crate::nca::{self, ContentType};
use crate::sha256::Sha256Digest;
use sha2::{Digest as _, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const PFS0_HEADER_SIZE: usize = 16;
const PFS0_ENTRY_SIZE: usize = 24;
const MAX_PFS0_ENTRIES: usize = 65_536;
const MAX_STRING_TABLE_SIZE: usize = 16 * 1024 * 1024;
const MAX_NAME_SIZE: usize = 4 * 1024;
const MAX_TOTAL_NAME_SIZE: usize = 16 * 1024 * 1024;
const COPY_CHUNK_SIZE: usize = 64 * 1024;
const NCA_PARTITION_FS: u8 = 1;
const NCA_HASH_NONE: u8 = 1;
const NCA_CRYPT_NONE: u8 = 1;

/// One NCA member's source span, header identity, and SHA-256 digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProgramMember {
    /// Path of the package or file containing this NCA.
    pub(crate) source_path: PathBuf,
    /// Absolute byte offset of the NCA in its source path.
    pub(crate) source_file_offset: u64,
    /// Number of bytes in the NCA.
    pub(crate) size: u64,
    /// Program ID read from the NCA header.
    pub(crate) program_id: u64,
    /// Content index read from the NCA header.
    pub(crate) content_index: u32,
    /// SHA-256 digest of the complete NCA member.
    pub(crate) sha256: Sha256Digest,
}

/// Members that share one Program ID, ordered by content index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ComponentGroup {
    /// Program ID shared by every member in this group.
    pub(crate) program_id: u64,
    /// Members in ascending content-index order.
    pub(crate) members: Vec<ProgramMember>,
}

/// Parsed package members in deterministic group and member order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProgramPackage {
    /// Groups in ascending Program ID order.
    pub(crate) groups: Vec<ComponentGroup>,
    /// All members in ascending program ID and content-index order.
    pub(crate) members: Vec<ProgramMember>,
}

/// Failure categories for package parsing and deterministic PFS0 writing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FormatError {
    /// A source file could not be opened, read, or matched to its recorded digest.
    SourceUnavailable,
    /// Package framing, a member span, or member structure is invalid.
    InvalidPackage,
    /// A member does not match the supported plaintext Program NCA profile.
    UnsupportedProfile,
    /// Two package members or member identities collide.
    DuplicateMember,
    /// A member does not have an unambiguous Program ID.
    AmbiguousGrouping,
    /// A package or output exceeds a fixed metadata bound or allocation failed.
    ResourceLimit,
    /// The output writer rejected a write.
    OutputUnavailable,
}

impl fmt::Display for FormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SourceUnavailable => "a source member could not be read or verified",
            Self::InvalidPackage => "the package or one of its members is invalid",
            Self::UnsupportedProfile => "the package uses an unsupported content profile",
            Self::DuplicateMember => "the package contains duplicate member identities",
            Self::AmbiguousGrouping => "a member does not identify one Program group",
            Self::ResourceLimit => "the package exceeds a supported resource limit",
            Self::OutputUnavailable => "the PFS0 output could not be written",
        })
    }
}

impl std::error::Error for FormatError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Pfs0Entry {
    name: String,
    offset: u64,
    size: u64,
}

struct Pfs0Layout {
    payload_offset: u64,
    entries: Vec<Pfs0Entry>,
}

/// Parses and hashes each member in a structurally valid PFS0 package.
///
/// Every member must be a nonempty plaintext NCA3 Program with exactly one
/// clear, un-hashed PartitionFS partition containing valid PFS0 framing.
/// Returned identities come from NCA header bytes, not package filenames.
pub(crate) fn inspect_package(path: &Path) -> Result<ProgramPackage, FormatError> {
    let mut file = File::open(path).map_err(|_| FormatError::SourceUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| FormatError::SourceUnavailable)?;
    if !metadata.is_file() {
        return Err(FormatError::SourceUnavailable);
    }

    let package_size = metadata.len();
    let outer = parse_pfs0(&mut file, package_size)?;
    let mut identities = HashSet::new();
    identities
        .try_reserve(outer.entries.len())
        .map_err(|_| FormatError::ResourceLimit)?;
    let mut members = Vec::new();
    members
        .try_reserve_exact(outer.entries.len())
        .map_err(|_| FormatError::ResourceLimit)?;

    for entry in outer.entries {
        if entry.size == 0 {
            return Err(FormatError::InvalidPackage);
        }

        let source_file_offset = outer
            .payload_offset
            .checked_add(entry.offset)
            .ok_or(FormatError::InvalidPackage)?;
        let member_end = source_file_offset
            .checked_add(entry.size)
            .ok_or(FormatError::InvalidPackage)?;
        if member_end > package_size || entry.size < nca::HEADER_SIZE as u64 {
            return Err(FormatError::InvalidPackage);
        }

        file.seek(SeekFrom::Start(source_file_offset))
            .map_err(|_| FormatError::SourceUnavailable)?;
        let mut header_bytes = [0_u8; nca::HEADER_SIZE];
        read_exact(&mut file, &mut header_bytes)?;
        if &header_bytes[0x200..0x204] != b"NCA3" {
            return Err(FormatError::UnsupportedProfile);
        }
        let header =
            nca::parse_header_block(&header_bytes, entry.size).map_err(map_header_error)?;
        if header.content_type != ContentType::Program {
            return Err(FormatError::UnsupportedProfile);
        }
        if header.program_id == 0 || header.program_id == u64::MAX {
            return Err(FormatError::AmbiguousGrouping);
        }
        if header.partitions.len() != 1 {
            return Err(FormatError::UnsupportedProfile);
        }
        let partition = &header.partitions[0];
        if partition.filesystem != NCA_PARTITION_FS
            || partition.hash_type != NCA_HASH_NONE
            || partition.extended
            || partition.encryption != NCA_CRYPT_NONE
        {
            return Err(FormatError::UnsupportedProfile);
        }

        let partition_start = source_file_offset
            .checked_add(partition.offset)
            .ok_or(FormatError::InvalidPackage)?;
        let mut partition_reader = FileSpan::new(&mut file, partition_start, partition.size);
        parse_pfs0(&mut partition_reader, partition.size)?;

        if !identities.insert((header.program_id, header.content_index)) {
            return Err(FormatError::DuplicateMember);
        }
        let sha256 = hash_file_range(&mut file, source_file_offset, entry.size)?;
        members.push(ProgramMember {
            source_path: path.to_path_buf(),
            source_file_offset,
            size: entry.size,
            program_id: header.program_id,
            content_index: header.content_index,
            sha256,
        });
    }

    members.sort_by_key(|member| (member.program_id, member.content_index));
    let mut groups: Vec<ComponentGroup> = Vec::new();
    groups
        .try_reserve_exact(members.len())
        .map_err(|_| FormatError::ResourceLimit)?;
    for member in &members {
        if let Some(group) = groups
            .last_mut()
            .filter(|group| group.program_id == member.program_id)
        {
            group
                .members
                .try_reserve(1)
                .map_err(|_| FormatError::ResourceLimit)?;
            group.members.push(member.clone());
        } else {
            let mut group_members = Vec::new();
            group_members
                .try_reserve_exact(1)
                .map_err(|_| FormatError::ResourceLimit)?;
            group_members.push(member.clone());
            groups.push(ComponentGroup {
                program_id: member.program_id,
                members: group_members,
            });
        }
    }

    Ok(ProgramPackage { groups, members })
}

/// Writes a new PFS0 with members ordered by identity and names derived from IDs.
///
/// The callback receives the number of payload bytes written in each chunk.
/// The writer streams source bytes and checks each member's recorded digest.
/// The result is a new container; it does not authenticate or reconstruct the
/// original package.
pub(crate) fn write_pfs0<W: Write>(
    writer: &mut W,
    members: &[ProgramMember],
    mut on_chunk: impl FnMut(u64) -> Result<(), FormatError>,
) -> Result<(), FormatError> {
    if members.len() > MAX_PFS0_ENTRIES {
        return Err(FormatError::ResourceLimit);
    }
    let mut ordered: Vec<&ProgramMember> = Vec::new();
    ordered
        .try_reserve_exact(members.len())
        .map_err(|_| FormatError::ResourceLimit)?;
    ordered.extend(members.iter());
    ordered.sort_by_key(|member| (member.program_id, member.content_index));

    let mut identities = HashSet::new();
    identities
        .try_reserve(ordered.len())
        .map_err(|_| FormatError::ResourceLimit)?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(ordered.len())
        .map_err(|_| FormatError::ResourceLimit)?;
    let mut string_table = Vec::new();
    let mut payload_size = 0_u64;

    for member in ordered {
        if member.size == 0 {
            return Err(FormatError::InvalidPackage);
        }
        if member.program_id == 0 || member.program_id == u64::MAX {
            return Err(FormatError::AmbiguousGrouping);
        }
        if !identities.insert((member.program_id, member.content_index)) {
            return Err(FormatError::DuplicateMember);
        }
        member
            .source_file_offset
            .checked_add(member.size)
            .ok_or(FormatError::InvalidPackage)?;

        let name = output_name(member.program_id, member.content_index)?;
        let name_offset =
            u32::try_from(string_table.len()).map_err(|_| FormatError::ResourceLimit)?;
        let added_name_size = name
            .len()
            .checked_add(1)
            .ok_or(FormatError::ResourceLimit)?;
        let new_table_size = string_table
            .len()
            .checked_add(added_name_size)
            .ok_or(FormatError::ResourceLimit)?;
        if new_table_size > MAX_STRING_TABLE_SIZE {
            return Err(FormatError::ResourceLimit);
        }
        string_table
            .try_reserve(added_name_size)
            .map_err(|_| FormatError::ResourceLimit)?;
        string_table.extend_from_slice(name.as_bytes());
        string_table.push(0);

        entries.push(OutputEntry {
            member,
            name_offset,
            data_offset: payload_size,
        });
        payload_size = payload_size
            .checked_add(member.size)
            .ok_or(FormatError::ResourceLimit)?;
    }

    let entry_count = u32::try_from(entries.len()).map_err(|_| FormatError::ResourceLimit)?;
    let table_size = u32::try_from(string_table.len()).map_err(|_| FormatError::ResourceLimit)?;
    let mut header = [0_u8; PFS0_HEADER_SIZE];
    header[..4].copy_from_slice(b"PFS0");
    header[4..8].copy_from_slice(&entry_count.to_le_bytes());
    header[8..12].copy_from_slice(&table_size.to_le_bytes());
    writer
        .write_all(&header)
        .map_err(|_| FormatError::OutputUnavailable)?;

    for entry in &entries {
        let mut raw = [0_u8; PFS0_ENTRY_SIZE];
        raw[..8].copy_from_slice(&entry.data_offset.to_le_bytes());
        raw[8..16].copy_from_slice(&entry.member.size.to_le_bytes());
        raw[16..20].copy_from_slice(&entry.name_offset.to_le_bytes());
        writer
            .write_all(&raw)
            .map_err(|_| FormatError::OutputUnavailable)?;
    }
    writer
        .write_all(&string_table)
        .map_err(|_| FormatError::OutputUnavailable)?;

    for entry in entries {
        copy_member(writer, entry.member, &mut on_chunk)?;
    }
    Ok(())
}

struct OutputEntry<'a> {
    member: &'a ProgramMember,
    name_offset: u32,
    data_offset: u64,
}

fn output_name(program_id: u64, content_index: u32) -> Result<String, FormatError> {
    let mut name = String::new();
    name.try_reserve_exact(29)
        .map_err(|_| FormatError::ResourceLimit)?;
    use fmt::Write as _;
    write!(&mut name, "{program_id:016X}_{content_index:08X}.nca")
        .map_err(|_| FormatError::ResourceLimit)?;
    Ok(name)
}

fn copy_member<W: Write>(
    writer: &mut W,
    member: &ProgramMember,
    on_chunk: &mut impl FnMut(u64) -> Result<(), FormatError>,
) -> Result<(), FormatError> {
    let mut source = File::open(&member.source_path).map_err(|_| FormatError::SourceUnavailable)?;
    let metadata = source
        .metadata()
        .map_err(|_| FormatError::SourceUnavailable)?;
    let end = member
        .source_file_offset
        .checked_add(member.size)
        .ok_or(FormatError::InvalidPackage)?;
    if !metadata.is_file() || end > metadata.len() {
        return Err(FormatError::SourceUnavailable);
    }
    source
        .seek(SeekFrom::Start(member.source_file_offset))
        .map_err(|_| FormatError::SourceUnavailable)?;

    let mut remaining = member.size;
    let mut buffer = [0_u8; COPY_CHUNK_SIZE];
    let mut digest = Sha256::new();
    while remaining > 0 {
        let amount =
            usize::try_from(remaining.min(COPY_CHUNK_SIZE as u64)).expect("copy chunk fits usize");
        let read = source
            .read(&mut buffer[..amount])
            .map_err(|_| FormatError::SourceUnavailable)?;
        if read == 0 {
            return Err(FormatError::SourceUnavailable);
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|_| FormatError::OutputUnavailable)?;
        digest.update(&buffer[..read]);
        remaining -= u64::try_from(read).expect("read length fits u64");
        on_chunk(u64::try_from(read).expect("read length fits u64"))?;
    }
    let actual = Sha256Digest::from_bytes(digest.finalize().into());
    if actual != member.sha256 {
        return Err(FormatError::SourceUnavailable);
    }
    Ok(())
}

fn hash_file_range(file: &mut File, offset: u64, size: u64) -> Result<Sha256Digest, FormatError> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| FormatError::SourceUnavailable)?;
    let mut remaining = size;
    let mut buffer = [0_u8; COPY_CHUNK_SIZE];
    let mut digest = Sha256::new();
    while remaining > 0 {
        let amount =
            usize::try_from(remaining.min(COPY_CHUNK_SIZE as u64)).expect("hash chunk fits usize");
        let read = file
            .read(&mut buffer[..amount])
            .map_err(|_| FormatError::SourceUnavailable)?;
        if read == 0 {
            return Err(FormatError::SourceUnavailable);
        }
        digest.update(&buffer[..read]);
        remaining -= u64::try_from(read).expect("read length fits u64");
    }
    Ok(Sha256Digest::from_bytes(digest.finalize().into()))
}

fn parse_pfs0<R: Read + Seek>(reader: &mut R, file_size: u64) -> Result<Pfs0Layout, FormatError> {
    if file_size < PFS0_HEADER_SIZE as u64 {
        return Err(FormatError::InvalidPackage);
    }
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| FormatError::SourceUnavailable)?;

    let mut header = [0_u8; PFS0_HEADER_SIZE];
    read_exact(reader, &mut header)?;
    if &header[..4] != b"PFS0" {
        return Err(FormatError::InvalidPackage);
    }
    let entry_count = read_u32(&header[4..8]) as usize;
    let string_table_size = read_u32(&header[8..12]) as usize;
    if read_u32(&header[12..16]) != 0 {
        return Err(FormatError::InvalidPackage);
    }
    if entry_count > MAX_PFS0_ENTRIES || string_table_size > MAX_STRING_TABLE_SIZE {
        return Err(FormatError::ResourceLimit);
    }
    if (entry_count == 0) != (string_table_size == 0) {
        return Err(FormatError::InvalidPackage);
    }

    let entry_table_size = entry_count
        .checked_mul(PFS0_ENTRY_SIZE)
        .ok_or(FormatError::ResourceLimit)?;
    let payload_offset = (PFS0_HEADER_SIZE as u64)
        .checked_add(u64::try_from(entry_table_size).map_err(|_| FormatError::ResourceLimit)?)
        .and_then(|offset| offset.checked_add(string_table_size as u64))
        .ok_or(FormatError::ResourceLimit)?;
    if payload_offset > file_size {
        return Err(FormatError::InvalidPackage);
    }
    let metadata_size = entry_table_size
        .checked_add(string_table_size)
        .ok_or(FormatError::ResourceLimit)?;
    let mut metadata = Vec::new();
    metadata
        .try_reserve_exact(metadata_size)
        .map_err(|_| FormatError::ResourceLimit)?;
    metadata.resize(metadata_size, 0);
    read_exact(reader, &mut metadata)?;
    let (entry_table, string_table) = metadata.split_at(entry_table_size);
    if !string_table.is_empty()
        && (string_table.last() != Some(&0) || std::str::from_utf8(string_table).is_err())
    {
        return Err(FormatError::InvalidPackage);
    }

    let payload_size = file_size - payload_offset;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(entry_count)
        .map_err(|_| FormatError::ResourceLimit)?;
    let mut names = HashSet::new();
    names
        .try_reserve(entry_count)
        .map_err(|_| FormatError::ResourceLimit)?;
    let mut folded_names = HashSet::new();
    folded_names
        .try_reserve(entry_count)
        .map_err(|_| FormatError::ResourceLimit)?;
    let mut total_name_size = 0_usize;
    let mut previous_end = 0_u64;
    for record in entry_table.as_chunks::<PFS0_ENTRY_SIZE>().0 {
        let offset = read_u64(&record[..8]);
        let size = read_u64(&record[8..16]);
        let name_offset = read_u32(&record[16..20]);
        if read_u32(&record[20..24]) != 0 {
            return Err(FormatError::InvalidPackage);
        }
        let name = read_name(string_table, name_offset)?;
        if !names.insert(name.clone()) || !folded_names.insert(name.to_ascii_lowercase()) {
            return Err(FormatError::DuplicateMember);
        }
        total_name_size = total_name_size
            .checked_add(name.len())
            .ok_or(FormatError::ResourceLimit)?;
        if total_name_size > MAX_TOTAL_NAME_SIZE {
            return Err(FormatError::ResourceLimit);
        }

        let end = offset
            .checked_add(size)
            .ok_or(FormatError::InvalidPackage)?;
        if offset < previous_end {
            return Err(FormatError::InvalidPackage);
        }
        if end > payload_size {
            return Err(FormatError::InvalidPackage);
        }
        previous_end = end;
        entries.push(Pfs0Entry { name, offset, size });
    }
    Ok(Pfs0Layout {
        payload_offset,
        entries,
    })
}

fn read_name(string_table: &[u8], name_offset: u32) -> Result<String, FormatError> {
    let start = usize::try_from(name_offset).map_err(|_| FormatError::InvalidPackage)?;
    if start >= string_table.len() || (start > 0 && string_table[start - 1] != 0) {
        return Err(FormatError::InvalidPackage);
    }
    let remaining = &string_table[start..];
    let length = remaining
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(FormatError::InvalidPackage)?;
    if length == 0 {
        return Err(FormatError::InvalidPackage);
    }
    if length > MAX_NAME_SIZE {
        return Err(FormatError::ResourceLimit);
    }
    let name =
        std::str::from_utf8(&remaining[..length]).map_err(|_| FormatError::InvalidPackage)?;
    if !name.is_ascii()
        || name == "."
        || name == ".."
        || name.ends_with('.')
        || name.ends_with(' ')
        || name
            .bytes()
            .any(|byte| byte < b' ' || byte == b'/' || byte == b'\\' || byte == b':')
    {
        return Err(FormatError::InvalidPackage);
    }
    let mut result = String::new();
    result
        .try_reserve_exact(name.len())
        .map_err(|_| FormatError::ResourceLimit)?;
    result.push_str(name);
    Ok(result)
}

fn read_exact<R: Read>(reader: &mut R, bytes: &mut [u8]) -> Result<(), FormatError> {
    reader
        .read_exact(bytes)
        .map_err(|error| match error.kind() {
            io::ErrorKind::UnexpectedEof => FormatError::InvalidPackage,
            _ => FormatError::SourceUnavailable,
        })
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("four-byte field"))
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("eight-byte field"))
}

fn map_header_error(error: nca::HeaderError) -> FormatError {
    match error {
        nca::HeaderError::UnsupportedFormat => FormatError::UnsupportedProfile,
        nca::HeaderError::TruncatedInput => FormatError::InvalidPackage,
        nca::HeaderError::MalformedInput => FormatError::InvalidPackage,
        nca::HeaderError::InputUnavailable => FormatError::SourceUnavailable,
        nca::HeaderError::AllocationFailed => FormatError::ResourceLimit,
    }
}

struct FileSpan<'a> {
    file: &'a mut File,
    start: u64,
    size: u64,
    position: u64,
}

impl<'a> FileSpan<'a> {
    fn new(file: &'a mut File, start: u64, size: u64) -> Self {
        Self {
            file,
            start,
            size,
            position: 0,
        }
    }
}

impl Read for FileSpan<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || self.position == self.size {
            return Ok(0);
        }
        let count = usize::try_from((buffer.len() as u64).min(self.size - self.position))
            .expect("read span fits usize");
        let offset = self
            .start
            .checked_add(self.position)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "span offset overflow"))?;
        self.file.seek(SeekFrom::Start(offset))?;
        let read = self.file.read(&mut buffer[..count])?;
        self.position += u64::try_from(read).expect("read length fits u64");
        Ok(read)
    }
}

impl Seek for FileSpan<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let requested = match position {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
            SeekFrom::End(delta) => i128::from(self.size) + i128::from(delta),
        };
        if requested < 0 || requested > i128::from(self.size) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek is outside the partition span",
            ));
        }
        self.position = u64::try_from(requested).expect("validated span position fits u64");
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn nca_allocation_failure_maps_to_multi_content_resource_limit() {
        assert_eq!(
            super::map_header_error(crate::nca::HeaderError::AllocationFailed),
            super::FormatError::ResourceLimit
        );
    }

    use super::{FormatError, ProgramMember, ProgramPackage, inspect_package, write_pfs0};
    use crate::sha256::Sha256Digest;
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    const NCA_HEADER_SIZE: usize = 0xc00;
    const PARTITION_SIZE: usize = 0x200;

    fn pfs0(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut strings = Vec::new();
        let mut entries = Vec::new();
        let mut payload = Vec::new();

        for (name, bytes) in files {
            let name_offset = u32::try_from(strings.len()).expect("small synthetic name table");
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
            entries.push((
                u64::try_from(payload.len()).expect("small synthetic payload"),
                u64::try_from(bytes.len()).expect("small synthetic file"),
                name_offset,
            ));
            payload.extend_from_slice(bytes);
        }

        let mut output = Vec::new();
        output.extend_from_slice(b"PFS0");
        output.extend_from_slice(
            &u32::try_from(entries.len())
                .expect("small synthetic entry count")
                .to_le_bytes(),
        );
        output.extend_from_slice(
            &u32::try_from(strings.len())
                .expect("small synthetic string table")
                .to_le_bytes(),
        );
        output.extend_from_slice(&0_u32.to_le_bytes());
        for (offset, size, name_offset) in entries {
            output.extend_from_slice(&offset.to_le_bytes());
            output.extend_from_slice(&size.to_le_bytes());
            output.extend_from_slice(&name_offset.to_le_bytes());
            output.extend_from_slice(&0_u32.to_le_bytes());
        }
        output.extend_from_slice(&strings);
        output.extend_from_slice(&payload);
        output
    }

    fn nca(
        program_id: u64,
        content_index: u32,
        content_type: u8,
        partition_type: u8,
        hash_type: u8,
        encryption_type: u8,
        inner_payload: Vec<u8>,
    ) -> Vec<u8> {
        let inner = pfs0(&[("inside.bin", inner_payload)]);
        let partition_size = inner.len().div_ceil(PARTITION_SIZE) * PARTITION_SIZE;
        let file_size = NCA_HEADER_SIZE + partition_size;
        let mut bytes = vec![0; file_size];
        bytes[0x200..0x204].copy_from_slice(b"NCA3");
        bytes[0x204] = 0;
        bytes[0x205] = content_type;
        bytes[0x208..0x210].copy_from_slice(&(file_size as u64).to_le_bytes());
        bytes[0x210..0x218].copy_from_slice(&program_id.to_le_bytes());
        bytes[0x218..0x21c].copy_from_slice(&content_index.to_le_bytes());

        let start_page =
            u32::try_from(NCA_HEADER_SIZE / PARTITION_SIZE).expect("header page count fits");
        let end_page = start_page
            + u32::try_from(partition_size / PARTITION_SIZE).expect("partition page count fits");
        bytes[0x240..0x244].copy_from_slice(&start_page.to_le_bytes());
        bytes[0x244..0x248].copy_from_slice(&end_page.to_le_bytes());
        bytes[0x400..0x408].copy_from_slice(&[
            2,
            0,
            partition_type,
            hash_type,
            encryption_type,
            0,
            0,
            0,
        ]);
        bytes[NCA_HEADER_SIZE..NCA_HEADER_SIZE + inner.len()].copy_from_slice(&inner);
        bytes
    }

    fn write_package(path: &Path, files: &[(&str, Vec<u8>)]) {
        fs::write(path, pfs0(files)).expect("write synthetic package");
    }

    fn member(path: &Path, program_id: u64, content_index: u32, bytes: &[u8]) -> ProgramMember {
        ProgramMember {
            source_path: path.to_path_buf(),
            source_file_offset: 0,
            size: u64::try_from(bytes.len()).expect("small synthetic NCA"),
            program_id,
            content_index,
            sha256: Sha256Digest::digest(bytes),
        }
    }

    fn package_members(package: &ProgramPackage) -> Vec<(u64, u32)> {
        package
            .members
            .iter()
            .map(|member| (member.program_id, member.content_index))
            .collect()
    }

    fn output_names(bytes: &[u8]) -> Vec<String> {
        assert_eq!(&bytes[0..4], b"PFS0");
        let count = u32::from_le_bytes(bytes[4..8].try_into().expect("PFS0 count")) as usize;
        let string_size =
            u32::from_le_bytes(bytes[8..12].try_into().expect("PFS0 string size")) as usize;
        let names_start = 16 + count * 24;
        let names_end = names_start + string_size;
        let names = &bytes[names_start..names_end];
        let mut result = Vec::new();

        for index in 0..count {
            let entry = &bytes[16 + index * 24..16 + (index + 1) * 24];
            let name_offset =
                u32::from_le_bytes(entry[16..20].try_into().expect("PFS0 name offset")) as usize;
            let remaining = &names[name_offset..];
            let end = remaining
                .iter()
                .position(|byte| *byte == 0)
                .expect("terminated PFS0 name");
            result.push(
                std::str::from_utf8(&remaining[..end])
                    .expect("UTF-8 PFS0 name")
                    .to_owned(),
            );
        }
        result
    }

    #[test]
    fn parses_and_sorts_exact_program_groups_and_hashes_members() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("input.nsp");
        let first = nca(0x20, 2, 0, 1, 1, 1, vec![0x22; 8]);
        let second = nca(0x10, 0, 0, 1, 1, 1, vec![0x10; 5]);
        let third = nca(0x20, 1, 0, 1, 1, 1, vec![0x21; 13]);
        write_package(
            &path,
            &[
                ("misleading-a.bin", first.clone()),
                ("not-the-id.nca", second.clone()),
                ("arbitrary-name", third.clone()),
            ],
        );

        let parsed = inspect_package(&path).expect("supported synthetic package");

        assert_eq!(package_members(&parsed), [(0x10, 0), (0x20, 1), (0x20, 2)]);
        assert_eq!(
            parsed
                .groups
                .iter()
                .map(|group| group.program_id)
                .collect::<Vec<_>>(),
            [0x10, 0x20]
        );
        assert_eq!(
            parsed.groups[1]
                .members
                .iter()
                .map(|member| member.content_index)
                .collect::<Vec<_>>(),
            [1, 2]
        );
        assert_eq!(parsed.members[0].sha256, Sha256Digest::digest(&second));
        assert_eq!(parsed.members[1].sha256, Sha256Digest::digest(&third));
        assert_eq!(parsed.members[2].sha256, Sha256Digest::digest(&first));
    }

    #[test]
    fn rejects_duplicate_outer_member_names() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("duplicate-names.nsp");
        write_package(
            &path,
            &[
                ("same.nca", nca(1, 0, 0, 1, 1, 1, vec![1])),
                ("same.nca", nca(2, 0, 0, 1, 1, 1, vec![2])),
            ],
        );

        assert_eq!(inspect_package(&path), Err(FormatError::DuplicateMember));
    }

    #[test]
    fn rejects_case_aliases_and_path_like_outer_member_names() {
        let directory = tempdir().expect("temporary directory");
        let alias_path = directory.path().join("case-alias.nsp");
        write_package(
            &alias_path,
            &[
                ("Member.nca", nca(1, 0, 0, 1, 1, 1, vec![1])),
                ("member.nca", nca(2, 0, 0, 1, 1, 1, vec![2])),
            ],
        );
        assert_eq!(
            inspect_package(&alias_path),
            Err(FormatError::DuplicateMember)
        );

        for unsafe_name in ["../member.nca", "folder\\member.nca", "member.nca."] {
            let path = directory.path().join("unsafe-name.nsp");
            write_package(&path, &[(unsafe_name, nca(1, 0, 0, 1, 1, 1, vec![1]))]);
            assert_eq!(inspect_package(&path), Err(FormatError::InvalidPackage));
        }
    }

    #[test]
    fn rejects_duplicate_program_and_content_index_pairs() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("duplicate-identities.nsp");
        write_package(
            &path,
            &[
                ("first.nca", nca(0x1234, 7, 0, 1, 1, 1, vec![1])),
                ("second.nca", nca(0x1234, 7, 0, 1, 1, 1, vec![2])),
            ],
        );

        assert_eq!(inspect_package(&path), Err(FormatError::DuplicateMember));
    }

    #[test]
    fn rejects_reserved_ids_and_zero_size_members_as_ambiguous_or_empty() {
        let directory = tempdir().expect("temporary directory");
        let zero_id_path = directory.path().join("zero-id.nsp");
        write_package(
            &zero_id_path,
            &[("zero.nca", nca(0, 0, 0, 1, 1, 1, vec![1]))],
        );
        assert_eq!(
            inspect_package(&zero_id_path),
            Err(FormatError::AmbiguousGrouping)
        );

        let reserved_id_path = directory.path().join("reserved-id.nsp");
        write_package(
            &reserved_id_path,
            &[("reserved.nca", nca(u64::MAX, 0, 0, 1, 1, 1, vec![1]))],
        );
        assert_eq!(
            inspect_package(&reserved_id_path),
            Err(FormatError::AmbiguousGrouping)
        );

        let empty_path = directory.path().join("empty-member.nsp");
        write_package(&empty_path, &[("empty.nca", Vec::new())]);
        assert_eq!(
            inspect_package(&empty_path),
            Err(FormatError::InvalidPackage)
        );
    }

    #[test]
    fn rejects_truncated_outer_and_nca_inputs() {
        let directory = tempdir().expect("temporary directory");
        let outer_path = directory.path().join("truncated-outer.nsp");
        fs::write(&outer_path, b"PFS0").expect("write truncated PFS0 header");
        assert_eq!(
            inspect_package(&outer_path),
            Err(FormatError::InvalidPackage)
        );

        let member_path = directory.path().join("truncated-member.nsp");
        write_package(&member_path, &[("short.nca", vec![0; 0x400])]);
        assert_eq!(
            inspect_package(&member_path),
            Err(FormatError::InvalidPackage)
        );

        let malformed_path = directory.path().join("malformed-member.nsp");
        let mut malformed = nca(0x33, 4, 0, 1, 1, 1, vec![1]);
        malformed[0x249] = 1; // Reserved partition descriptor byte.
        write_package(&malformed_path, &[("broken.nca", malformed)]);
        assert_eq!(
            inspect_package(&malformed_path),
            Err(FormatError::InvalidPackage)
        );
    }

    #[test]
    fn rejects_malformed_inner_partition_pfs0_framing() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("malformed-inner.nsp");
        let mut malformed = nca(0x33, 4, 0, 1, 1, 1, vec![1]);
        malformed[NCA_HEADER_SIZE..NCA_HEADER_SIZE + 4].copy_from_slice(b"NOPE");
        write_package(&path, &[("member.nca", malformed)]);

        assert_eq!(inspect_package(&path), Err(FormatError::InvalidPackage));
    }

    #[test]
    fn rejects_non_program_and_encrypted_nca_headers() {
        let directory = tempdir().expect("temporary directory");
        let non_program_path = directory.path().join("non-program.nsp");
        write_package(
            &non_program_path,
            &[("member.nca", nca(1, 0, 1, 1, 1, 1, vec![1]))],
        );
        assert_eq!(
            inspect_package(&non_program_path),
            Err(FormatError::UnsupportedProfile)
        );

        let encrypted_path = directory.path().join("encrypted.nsp");
        let encrypted = crate::nca::synthetic_nca_with_header_fields(1, 1, 1, 1);
        write_package(&encrypted_path, &[("opaque.nca", encrypted)]);
        assert_eq!(
            inspect_package(&encrypted_path),
            Err(FormatError::UnsupportedProfile)
        );
    }

    #[test]
    fn rejects_unsupported_partition_layout_and_crypto() {
        let directory = tempdir().expect("temporary directory");
        let layout_path = directory.path().join("unsupported-layout.nsp");
        write_package(
            &layout_path,
            &[("member.nca", nca(1, 0, 0, 0, 1, 1, vec![1]))],
        );
        assert_eq!(
            inspect_package(&layout_path),
            Err(FormatError::UnsupportedProfile)
        );

        let crypto_path = directory.path().join("encrypted-partition.nsp");
        write_package(
            &crypto_path,
            &[("member.nca", nca(1, 0, 0, 1, 1, 2, vec![1]))],
        );
        assert_eq!(
            inspect_package(&crypto_path),
            Err(FormatError::UnsupportedProfile)
        );
    }

    #[test]
    fn writes_sorted_deterministic_pfs0_and_round_trips_member_evidence() {
        let directory = tempdir().expect("temporary directory");
        let source_path = directory.path().join("sources.bin");
        let first = nca(0x20, 2, 0, 1, 1, 1, vec![0x22; 8]);
        let second = nca(0x10, 0, 0, 1, 1, 1, vec![0x10; 5]);
        let third = nca(0x20, 1, 0, 1, 1, 1, vec![0x21; 13]);
        let mut source_bytes = Vec::new();
        let mut members = Vec::new();
        for (program_id, index, bytes) in [(0x20, 2, &first), (0x10, 0, &second), (0x20, 1, &third)]
        {
            let offset = u64::try_from(source_bytes.len()).expect("small source bundle");
            members.push(ProgramMember {
                source_path: source_path.clone(),
                source_file_offset: offset,
                size: u64::try_from(bytes.len()).expect("small NCA"),
                program_id,
                content_index: index,
                sha256: Sha256Digest::digest(bytes),
            });
            source_bytes.extend_from_slice(bytes);
        }
        fs::write(&source_path, source_bytes).expect("write source bundle");

        let mut first_output = Vec::new();
        let mut copied = Vec::new();
        write_pfs0(&mut first_output, &members, |chunk| {
            copied.push(chunk);
            Ok(())
        })
        .expect("write deterministic PFS0");
        let mut reversed = members.clone();
        reversed.reverse();
        let mut second_output = Vec::new();
        write_pfs0(&mut second_output, &reversed, |_| Ok(()))
            .expect("write sorted deterministic PFS0");

        assert_eq!(first_output, second_output);
        assert_eq!(
            output_names(&first_output),
            [
                "0000000000000010_00000000.nca",
                "0000000000000020_00000001.nca",
                "0000000000000020_00000002.nca",
            ]
        );
        assert_eq!(
            copied.iter().sum::<u64>(),
            members.iter().map(|member| member.size).sum::<u64>()
        );

        let expected = pfs0(&[
            ("0000000000000010_00000000.nca", second.clone()),
            ("0000000000000020_00000001.nca", third.clone()),
            ("0000000000000020_00000002.nca", first.clone()),
        ]);
        assert_eq!(first_output, expected);

        let output_path = directory.path().join("round-trip.nsp");
        fs::write(&output_path, first_output).expect("write generated package");
        let reparsed = inspect_package(&output_path).expect("reparse generated package");
        assert_eq!(
            package_members(&reparsed),
            [(0x10, 0), (0x20, 1), (0x20, 2)]
        );
        assert_eq!(reparsed.members[0].sha256, Sha256Digest::digest(&second));
        assert_eq!(reparsed.members[1].sha256, Sha256Digest::digest(&third));
        assert_eq!(reparsed.members[2].sha256, Sha256Digest::digest(&first));
    }

    #[test]
    fn streams_large_member_in_bounded_chunks_and_propagates_callback_errors() {
        let directory = tempdir().expect("temporary directory");
        let source_path = directory.path().join("large.nca");
        let bytes = nca(0x42, 9, 0, 1, 1, 1, vec![0x5a; 256 * 1024]);
        fs::write(&source_path, &bytes).expect("write large synthetic NCA");
        let large_member = member(&source_path, 0x42, 9, &bytes);
        let mut output = Vec::new();
        let mut chunks = Vec::new();

        write_pfs0(&mut output, &[large_member], |chunk| {
            chunks.push(chunk);
            Ok(())
        })
        .expect("stream large member");

        assert!(chunks.len() > 1);
        assert!(chunks.iter().all(|chunk| *chunk <= 64 * 1024));
        assert_eq!(chunks.iter().sum::<u64>(), bytes.len() as u64);

        let mut callback_output = Vec::new();
        let error = write_pfs0(
            &mut callback_output,
            &[member(&source_path, 0x42, 9, &bytes)],
            |_| Err(FormatError::OutputUnavailable),
        )
        .expect_err("callback error propagates");
        assert_eq!(error, FormatError::OutputUnavailable);
    }

    #[test]
    fn writer_rejects_a_member_whose_digest_no_longer_matches() {
        let directory = tempdir().expect("temporary directory");
        let source_path = directory.path().join("changed.nca");
        let bytes = nca(0x55, 3, 0, 1, 1, 1, vec![0x33; 4]);
        fs::write(&source_path, &bytes).expect("write synthetic NCA");
        let mut described = member(&source_path, 0x55, 3, &bytes);
        described.sha256 = Sha256Digest::digest(b"different bytes");
        let mut output = Vec::new();

        assert_eq!(
            write_pfs0(&mut output, &[described], |_| Ok(())),
            Err(FormatError::SourceUnavailable)
        );
    }
}
