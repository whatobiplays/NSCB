//! Compression of a narrowly qualified rights-free Application XCI into XCZ.

#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]

use crate::operation::ConflictPolicy;
use std::fmt;
use std::path::PathBuf;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use crate::xci_format::{
    CARD_HEADER_SIZE, HFS_HEADER_SIZE, HfsEntry, ROOT_PLACEMENT, build_hfs_header, copy_file_span,
    hash_bytes, hash_file_prefix, hash_file_range, hfs_table_size, output_geometry,
    verify_hfs_entries, write_bytes, write_zero_padding,
};

/// Describes a request to compress a qualified base Application XCI as XCZ.
#[derive(Clone)]
pub struct XciToXczRequest {
    source: PathBuf,
    destination: PathBuf,
    workspace: PathBuf,
    key_file: PathBuf,
    conflict_policy: ConflictPolicy,
    compression: crate::nsp_nsz::NszCompression,
}

impl XciToXczRequest {
    /// Creates a request with explicit input, output, workspace, and key paths.
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
            compression: crate::nsp_nsz::NszCompression::default(),
        }
    }

    /// Selects how execution handles an existing destination.
    #[must_use]
    pub fn with_conflict_policy(mut self, policy: ConflictPolicy) -> Self {
        self.conflict_policy = policy;
        self
    }

    /// Selects the Zstandard level resolved into the immutable operation plan.
    #[must_use]
    pub fn with_compression(mut self, compression: crate::nsp_nsz::NszCompression) -> Self {
        self.compression = compression;
        self
    }

    pub(crate) fn into_parts(self) -> XciToXczRequestParts {
        XciToXczRequestParts {
            source: self.source,
            destination: self.destination,
            workspace: self.workspace,
            key_file: self.key_file,
            conflict_policy: self.conflict_policy,
            compression: self.compression,
        }
    }
}

impl fmt::Debug for XciToXczRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XciToXczRequest")
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("workspace", &self.workspace)
            .field("key_file", &"[REDACTED]")
            .field("conflict_policy", &self.conflict_policy)
            .field("compression", &self.compression)
            .finish()
    }
}

pub(crate) struct XciToXczRequestParts {
    pub(crate) source: PathBuf,
    pub(crate) destination: PathBuf,
    pub(crate) workspace: PathBuf,
    pub(crate) key_file: PathBuf,
    pub(crate) conflict_policy: ConflictPolicy,
    pub(crate) compression: crate::nsp_nsz::NszCompression,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XciToXczPackagePlan {
    pub(crate) input: crate::recognition::XciConversionSource,
    pub(crate) meta: crate::nsp_nsz::NspNszMember,
    pub(crate) program: crate::nsp_nsz::NspNszMember,
    pub(crate) semantic_facts: crate::nsp_semantic_qualification::NspSemanticQualificationFacts,
}

/// Enforces the exact empty auxiliary blocks accepted by the XCI-to-XCZ writer.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn validate_empty_auxiliary_partitions(
    source_file: &mut std::fs::File,
    source_length: u64,
    input: &crate::recognition::XciConversionSource,
) -> Result<(), crate::operation::OperationFailureCode> {
    use std::io::{Read, Seek, SeekFrom};

    let unsupported = crate::operation::OperationFailureCode::UnsupportedContentProfile;
    let mut card_header = [0_u8; crate::xci_format::CARD_HEADER_SIZE as usize];
    source_file
        .seek(SeekFrom::Start(0))
        .and_then(|_| source_file.read_exact(&mut card_header))
        .map_err(|_| crate::operation::OperationFailureCode::SourceUnavailable)?;
    let root_offset = u64::from_le_bytes(
        card_header[0x130..0x138]
            .try_into()
            .expect("fixed card-header field"),
    );
    let root_end = crate::xci_format::ROOT_PLACEMENT
        .checked_add(input.root_hfs0_table_size)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let declared_root_end = root_offset
        .checked_add(input.root_hfs0_header_size)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    if root_offset != crate::xci_format::ROOT_PLACEMENT
        || input.root_hfs0_table_size > input.root_hfs0_header_size
        || declared_root_end > source_length
    {
        return Err(unsupported);
    }
    validate_zero_range(
        source_file,
        crate::xci_format::CARD_HEADER_SIZE,
        root_offset
            .checked_sub(crate::xci_format::CARD_HEADER_SIZE)
            .ok_or(unsupported)?,
    )?;
    validate_zero_range(
        source_file,
        root_end,
        declared_root_end
            .checked_sub(root_end)
            .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?,
    )?;

    let mut unreferenced_start = declared_root_end;
    for entry in &input.root_entries {
        if entry.offset < unreferenced_start {
            return Err(unsupported);
        }
        validate_zero_range(
            source_file,
            unreferenced_start,
            entry
                .offset
                .checked_sub(unreferenced_start)
                .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?,
        )?;
        unreferenced_start = entry
            .offset
            .checked_add(entry.length)
            .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    }
    validate_zero_range(
        source_file,
        unreferenced_start,
        source_length
            .checked_sub(unreferenced_start)
            .ok_or(unsupported)?,
    )?;
    validate_zero_range(source_file, root_end, declared_root_end - root_end)?;

    let mut auxiliary_count = 0_u8;
    for entry in &input.root_entries {
        if !matches!(entry.name.as_str(), "update" | "normal" | "logo") {
            continue;
        }
        auxiliary_count = auxiliary_count
            .checked_add(1)
            .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
        if entry.length != crate::xci_format::CARD_HEADER_SIZE
            || u64::from(entry.hashed_size) != crate::xci_format::CARD_HEADER_SIZE
            || entry.reserved_offset != [0; 8]
            || !entry
                .offset
                .is_multiple_of(crate::xci_format::CARD_HEADER_SIZE)
            || entry
                .offset
                .checked_add(crate::xci_format::CARD_HEADER_SIZE)
                .filter(|end| *end <= source_length)
                .is_none()
        {
            return Err(unsupported);
        }

        let mut block = [0_u8; crate::xci_format::CARD_HEADER_SIZE as usize];
        source_file
            .seek(SeekFrom::Start(entry.offset))
            .and_then(|_| source_file.read_exact(&mut block))
            .map_err(|_| crate::operation::OperationFailureCode::SourceChanged)?;
        if &block[..4] != b"HFS0"
            || block[4..16].iter().any(|byte| *byte != 0)
            || block[16..].iter().any(|byte| *byte != 0)
        {
            return Err(unsupported);
        }
    }
    if !matches!(auxiliary_count, 2 | 3) {
        return Err(unsupported);
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn validate_zero_range(
    file: &mut std::fs::File,
    offset: u64,
    length: u64,
) -> Result<(), crate::operation::OperationFailureCode> {
    use std::io::{Read, Seek, SeekFrom};

    let mut remaining = length;
    let mut buffer = [0_u8; 64 * 1024];
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| crate::operation::OperationFailureCode::SourceUnavailable)?;
    while remaining > 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
        let read = file
            .read(&mut buffer[..count])
            .map_err(|_| crate::operation::OperationFailureCode::SourceUnavailable)?;
        if read == 0 {
            return Err(crate::operation::OperationFailureCode::SourceChanged);
        }
        if buffer[..read].iter().any(|byte| *byte != 0) {
            return Err(crate::operation::OperationFailureCode::UnsupportedContentProfile);
        }
        remaining -= u64::try_from(read)
            .map_err(|_| crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    }
    Ok(())
}

/// Builds the XCZ gamecard layout from a measured NCZ member spool.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn write_xcz<W: std::io::Write>(
    source_file: &mut std::fs::File,
    program_spool: &mut std::fs::File,
    package: &XciToXczPackagePlan,
    writer: &mut W,
    mut on_chunk: impl FnMut(u64) -> Result<(), crate::operation::OperationFailureCode>,
) -> Result<u64, crate::operation::OperationFailureCode> {
    use std::io::{Read, Seek, SeekFrom};

    let program_length = program_spool
        .metadata()
        .map_err(|_| crate::operation::OperationFailureCode::ValidationFailed)?
        .len();
    let mut source_header = [0_u8; CARD_HEADER_SIZE as usize];
    source_file
        .seek(SeekFrom::Start(0))
        .and_then(|_| source_file.read_exact(&mut source_header))
        .map_err(|_| crate::operation::OperationFailureCode::SourceUnavailable)?;
    let geometry = output_geometry(
        package.meta.source_size,
        program_length,
        package.input.has_logo_partition,
        source_header[0x10D],
        u32::from_le_bytes(source_header[0x118..0x11C].try_into().expect("fixed field")),
    )?;
    let empty_partition = build_hfs_header(&[], CARD_HEADER_SIZE)?;
    let meta_hash = hash_file_prefix(
        source_file,
        package.meta.source_offset,
        package.meta.source_size,
    )?;
    let program_hash = hash_file_prefix(program_spool, 0, program_length)?;
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
                name: &package.meta.output_name,
                relative_data_offset: 0,
                length: package.meta.source_size,
                digest: meta_hash,
            },
            HfsEntry {
                name: &package.program.output_name,
                relative_data_offset: program_relative_offset,
                length: program_length,
                digest: program_hash,
            },
        ],
        HFS_HEADER_SIZE,
    )?;
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
        package.meta.source_offset,
        package.meta.source_size,
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
        .checked_add(package.meta.source_size)
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
    copy_file_span(program_spool, 0, program_length, writer, &mut |amount| {
        written = written
            .checked_add(amount)
            .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
        on_chunk(amount)
    })?;
    let secure_content_end = geometry
        .program_offset
        .checked_add(program_length)
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

/// Checks the staged XCZ card fields, exact HFS0 layout, and preserved Meta NCA.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn verify_staged_output(
    source_file: &mut std::fs::File,
    staged_file: &mut std::fs::File,
    staged_length: u64,
    package: &XciToXczPackagePlan,
    mut on_chunk: impl FnMut(u64) -> Result<(), crate::operation::OperationFailureCode>,
) -> Result<(), crate::operation::OperationFailureCode> {
    use std::io::{Read, Seek, SeekFrom};

    let inspected = crate::recognition::inspect_xcz_for_conversion(staged_file, staged_length)
        .map_err(crate::xci_to_nsp::map_recognition_error)?;
    if inspected.secure_members.len() != 2 || inspected.all_hfs_entry_hashes_absent {
        return Err(crate::operation::OperationFailureCode::ValidationFailed);
    }
    validate_empty_auxiliary_partitions(staged_file, staged_length, &inspected)
        .map_err(|_| crate::operation::OperationFailureCode::ValidationFailed)?;
    if staged_file
        .metadata()
        .map_err(|_| crate::operation::OperationFailureCode::ValidationFailed)?
        .len()
        != staged_length
    {
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
    if output_header[..0x104] != source_header[..0x104]
        || output_header[0x108..0x138] != source_header[0x108..0x138]
        || output_header[0x160..0x200] != source_header[0x160..0x200]
    {
        return Err(crate::operation::OperationFailureCode::ValidationFailed);
    }

    let rom_size = source_header[0x10D];
    let valid_data_end = u32::from_le_bytes(
        source_header[0x118..0x11C]
            .try_into()
            .expect("fixed card-header field"),
    );
    let program_length = inspected
        .secure_members
        .iter()
        .find(|member| member.name == package.program.output_name)
        .map(|member| member.length)
        .ok_or(crate::operation::OperationFailureCode::ValidationFailed)?;
    let geometry = output_geometry(
        package.meta.source_size,
        program_length,
        package.input.has_logo_partition,
        rom_size,
        valid_data_end,
    )?;
    if staged_length != geometry.output_length {
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
        || u64::from(page) != physical_secure_offset / CARD_HEADER_SIZE
    {
        return Err(crate::operation::OperationFailureCode::ValidationFailed);
    }

    let root_names = if package.input.has_logo_partition {
        vec!["update", "normal", "secure", "logo"]
    } else {
        vec!["update", "normal", "secure"]
    };
    let secure_names = [
        package.meta.output_name.as_str(),
        package.program.output_name.as_str(),
    ];
    if inspected.root_hfs0_table_size != hfs_table_size(&root_names)?
        || inspected.secure_hfs0_table_size != hfs_table_size(&secure_names)?
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
        (
            package.meta.output_name.as_str(),
            geometry.meta_offset,
            package.meta.source_size,
        ),
        (
            package.program.output_name.as_str(),
            geometry.program_offset,
            program_length,
        ),
    ];
    verify_hfs_entries(
        staged_file,
        &inspected.secure_entries,
        &expected_secure,
        staged_length,
        &mut on_chunk,
    )?;
    let root_digest = hash_file_range(staged_file, root_offset, root_header_size, &mut on_chunk)?;
    if output_header[0x140..0x160] != root_digest {
        return Err(crate::operation::OperationFailureCode::ValidationFailed);
    }

    let source_meta_digest = hash_file_range(
        source_file,
        package.meta.source_offset,
        package.meta.source_size,
        &mut on_chunk,
    )?;
    let staged_meta_digest = hash_file_range(
        staged_file,
        geometry.meta_offset,
        package.meta.source_size,
        &mut on_chunk,
    )?;
    if source_meta_digest != *package.meta.source_sha256.as_bytes()
        || staged_meta_digest != *package.meta.source_sha256.as_bytes()
    {
        return Err(crate::operation::OperationFailureCode::ValidationFailed);
    }
    Ok(())
}
