//! Shared card geometry, HFS0 serialization, and bounded span helpers for XCI conversion.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) const ROOT_PLACEMENT: u64 = 0xF000;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) const HFS_HEADER_SIZE: u64 = 0x8000;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) const CARD_HEADER_SIZE: u64 = 0x200;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const HFS_HASH_PREFIX_LIMIT: u64 = 0x200;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const IO_BUFFER_SIZE: usize = 64 * 1024;

/// Returns the bounded SHA-256 span required for one output HFS0 member.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hfs_hash_size(member_length: u64) -> Option<u32> {
    let prefix = member_length.min(HFS_HASH_PREFIX_LIMIT);
    if prefix == 0 {
        return None;
    }
    u32::try_from(prefix).ok()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OutputGeometry {
    pub(crate) root_offset: u64,
    pub(crate) root_header_size: u64,
    pub(crate) secure_offset: u64,
    pub(crate) secure_length: u64,
    pub(crate) meta_offset: u64,
    pub(crate) program_offset: u64,
    pub(crate) output_length: u64,
    pub(crate) rom_area_start_page: u32,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OutputLayout {
    secure_offset: u64,
    secure_length: u64,
    meta_offset: u64,
    program_offset: u64,
    output_length: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone)]
pub(crate) struct HfsEntry<'a> {
    pub(crate) name: &'a str,
    pub(crate) relative_data_offset: u64,
    pub(crate) length: u64,
    pub(crate) digest: [u8; 32],
}

/// Computes the checked offsets and serialized length shared by XCI layout paths.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn checked_output_layout(
    meta_length: u64,
    program_length: u64,
    has_logo: bool,
) -> Result<OutputLayout, crate::operation::OperationFailureCode> {
    if meta_length == 0 || program_length == 0 {
        return Err(crate::operation::OperationFailureCode::UnsupportedContentProfile);
    }
    let secure_offset = ROOT_PLACEMENT
        .checked_add(HFS_HEADER_SIZE)
        .and_then(|offset| offset.checked_add(CARD_HEADER_SIZE * 2))
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let meta_offset = secure_offset
        .checked_add(HFS_HEADER_SIZE)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
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

    Ok(OutputLayout {
        secure_offset,
        secure_length,
        meta_offset,
        program_offset,
        output_length,
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn output_geometry(
    meta_length: u64,
    program_length: u64,
    has_logo: bool,
    rom_size: u8,
    valid_data_end: u32,
) -> Result<OutputGeometry, crate::operation::OperationFailureCode> {
    let layout = checked_output_layout(meta_length, program_length, has_logo)?;

    let physical_end = layout
        .output_length
        .checked_add(0x1000)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?;
    let physical_end_pages = div_ceil(physical_end, CARD_HEADER_SIZE)?;
    let capacity_pages = crate::recognition::rom_size_pages(u64::from(rom_size))
        .ok_or(crate::operation::OperationFailureCode::UnsupportedXciProfile)?;
    if physical_end_pages > capacity_pages || physical_end_pages > u64::from(valid_data_end) {
        return Err(crate::operation::OperationFailureCode::UnsupportedXciProfile);
    }
    let physical_secure_page = layout
        .secure_offset
        .checked_add(0x1000)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)?
        / CARD_HEADER_SIZE;
    let rom_area_start_page = u32::try_from(physical_secure_page)
        .map_err(|_| crate::operation::OperationFailureCode::UnsupportedXciProfile)?;
    Ok(OutputGeometry {
        root_offset: ROOT_PLACEMENT,
        root_header_size: HFS_HEADER_SIZE,
        secure_offset: layout.secure_offset,
        secure_length: layout.secure_length,
        meta_offset: layout.meta_offset,
        program_offset: layout.program_offset,
        output_length: layout.output_length,
        rom_area_start_page,
    })
}

/// Returns the maximum serialized size before applying card-header capacity limits.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn output_length_bound(
    meta_length: u64,
    program_length: u64,
    has_logo: bool,
) -> Result<u64, crate::operation::OperationFailureCode> {
    checked_output_layout(meta_length, program_length, has_logo).map(|layout| layout.output_length)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn align_card_page(value: u64) -> Result<u64, crate::operation::OperationFailureCode> {
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
pub(crate) fn div_ceil(
    value: u64,
    divisor: u64,
) -> Result<u64, crate::operation::OperationFailureCode> {
    value
        .checked_add(divisor - 1)
        .map(|rounded| rounded / divisor)
        .ok_or(crate::operation::OperationFailureCode::ResourceLimitExceeded)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hfs_table_size(
    names: &[&str],
) -> Result<u64, crate::operation::OperationFailureCode> {
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
pub(crate) fn build_hfs_header(
    entries: &[HfsEntry<'_>],
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
pub(crate) fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    Sha256::digest(bytes).into()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hash_file_prefix(
    source: &mut std::fs::File,
    offset: u64,
    member_length: u64,
) -> Result<[u8; 32], crate::operation::OperationFailureCode> {
    let hashed_size = hfs_hash_size(member_length)
        .ok_or(crate::operation::OperationFailureCode::UnsupportedXciProfile)?;
    hash_file_range(source, offset, u64::from(hashed_size), |_| Ok(()))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hash_file_range(
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
pub(crate) fn write_bytes<W: std::io::Write>(
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
pub(crate) fn write_zero_padding<W: std::io::Write>(
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
pub(crate) fn copy_file_span<W: std::io::Write>(
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
pub(crate) fn verify_hfs_entries(
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
mod output_layout_tests {
    use super::{
        CARD_HEADER_SIZE, HFS_HEADER_SIZE, ROOT_PLACEMENT, checked_output_layout, output_geometry,
        output_length_bound,
    };
    use crate::{OperationFailureCode, nsp_nsz::MAX_PACKAGE_BYTES};

    fn geometry(meta_length: u64, program_length: u64, has_logo: bool) -> super::OutputGeometry {
        output_geometry(meta_length, program_length, has_logo, 0xE2, u32::MAX)
            .expect("synthetic member lengths fit the supported card")
    }

    #[test]
    fn checked_layout_places_aligned_members_and_includes_optional_logo() {
        let layout = checked_output_layout(0x400, 0x800, false).expect("aligned layout");
        let layout_with_logo =
            checked_output_layout(0x400, 0x800, true).expect("aligned layout with logo");
        let expected_secure_offset = ROOT_PLACEMENT + HFS_HEADER_SIZE + CARD_HEADER_SIZE * 2;
        let expected_meta_offset = expected_secure_offset + HFS_HEADER_SIZE;

        assert_eq!(layout.secure_offset, expected_secure_offset);
        assert_eq!(layout.meta_offset, expected_meta_offset);
        assert_eq!(layout.program_offset, expected_meta_offset + 0x400);
        assert_eq!(layout.output_length, 0x20_000);
        assert_eq!(
            layout_with_logo.output_length,
            layout.output_length + CARD_HEADER_SIZE
        );
        assert_eq!(
            geometry(0x400, 0x800, true).output_length,
            layout_with_logo.output_length
        );
        assert_eq!(
            output_length_bound(0x400, 0x800, false),
            Ok(layout.output_length)
        );
        assert_eq!(
            output_length_bound(0x400, 0x800, true),
            Ok(layout.output_length + CARD_HEADER_SIZE)
        );
    }

    #[test]
    fn checked_layout_rounds_unaligned_member_ends_to_card_pages() {
        let layout = checked_output_layout(0x401, 0x801, false).expect("unaligned layout");
        let expected_meta_offset = ROOT_PLACEMENT + HFS_HEADER_SIZE * 2 + CARD_HEADER_SIZE * 2;

        assert_eq!(layout.meta_offset, expected_meta_offset);
        assert_eq!(layout.program_offset, expected_meta_offset + 0x600);
        assert_eq!(layout.output_length, 0x20_400);
        assert_eq!(layout.output_length % CARD_HEADER_SIZE, 0);
    }

    #[test]
    fn geometry_and_preflight_bound_share_the_same_measured_layout() {
        for has_logo in [false, true] {
            let measured = geometry(0x401, 0x801, has_logo);
            let exact_bound =
                output_length_bound(0x401, 0x801, has_logo).expect("exact preflight bound");
            let larger_bound =
                output_length_bound(0x401, 0x1_001, has_logo).expect("upper-bound preflight size");
            let smaller_measured = geometry(0x401, 0x601, has_logo);

            assert_eq!(measured.output_length, exact_bound);
            assert!(smaller_measured.output_length <= exact_bound);
            assert!(exact_bound <= larger_bound);
        }
    }

    #[test]
    fn checked_layout_rejects_maximum_size_and_arithmetic_overflow() {
        assert_eq!(
            output_length_bound(MAX_PACKAGE_BYTES, 1, false),
            Err(OperationFailureCode::ResourceLimitExceeded)
        );
        assert_eq!(
            output_geometry(MAX_PACKAGE_BYTES, 1, false, 0xE2, u32::MAX),
            Err(OperationFailureCode::ResourceLimitExceeded)
        );

        let meta_offset = ROOT_PLACEMENT + HFS_HEADER_SIZE * 2 + CARD_HEADER_SIZE * 2;
        assert_eq!(
            output_length_bound(u64::MAX - meta_offset, 1, false),
            Err(OperationFailureCode::ResourceLimitExceeded)
        );
        assert_eq!(
            output_length_bound(u64::MAX, 1, false),
            Err(OperationFailureCode::ResourceLimitExceeded)
        );
    }

    #[test]
    fn checked_geometry_retains_rom_size_and_valid_data_end_constraints() {
        assert_eq!(
            output_geometry(1, 1, false, 0xFF, u32::MAX),
            Err(OperationFailureCode::UnsupportedXciProfile)
        );

        let layout = checked_output_layout(0x400, 0x800, false).expect("small layout");
        let physical_end = layout.output_length + 0x1000;
        let physical_end_pages = physical_end.div_ceil(CARD_HEADER_SIZE);
        assert_eq!(
            output_geometry(0x400, 0x800, false, 0xE2, physical_end_pages as u32 - 1),
            Err(OperationFailureCode::UnsupportedXciProfile)
        );
        assert_eq!(
            output_geometry(1 << 30, 1, false, 0xFA, u32::MAX),
            Err(OperationFailureCode::UnsupportedXciProfile)
        );
    }
}
