//! Shared bounded reader and decoder for the supported NCZ member profile.
//!
//! Container adapters validate their own member tables and NCA roles. This
//! module checks the NCZ record and reconstructs the encoded NCA section.

use crate::nsp_nsz::NspNszFormatError;
#[cfg(target_arch = "aarch64")]
use std::fs::File;
#[cfg(target_arch = "aarch64")]
use std::io::Write;
use std::io::{Read, Seek, SeekFrom};

pub(crate) const NCZ_PREFIX_SIZE: u64 = 0x4000;
pub(crate) const NCZ_TABLE_OFFSET: u64 = 0x4010;
pub(crate) const NCZ_RECORD_SIZE: u64 = 64;
pub(crate) const NCZ_FRAME_OFFSET: u64 = NCZ_TABLE_OFFSET + NCZ_RECORD_SIZE;
pub(crate) const DEFAULT_ZSTD_WINDOW_LOG: u32 = 27;
const IO_BUFFER_SIZE: usize = 64 * 1024;

pub(crate) struct NczRecord {
    pub(crate) nca_size: u64,
    pub(crate) section_offset: u64,
    pub(crate) section_size: u64,
    frame_offset: u64,
    frame_size: u64,
    key: zeroize::Zeroizing<[u8; 16]>,
    counter: zeroize::Zeroizing<[u8; 16]>,
}

pub(crate) struct NczDecodeSpec {
    pub(crate) source_offset: u64,
    pub(crate) source_size: u64,
    pub(crate) expected_nca_size: u64,
    pub(crate) section_offset: u64,
    pub(crate) section_size: u64,
}

/// Reads the supported single-section NCZ record inside a bounded member.
pub(crate) fn read_ncz_record<R: Read + Seek>(
    member: &mut R,
    member_size: u64,
) -> Result<NczRecord, NspNszFormatError> {
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

/// Reconstructs one NCZ member after its container has qualified the NCA role.
#[cfg(target_arch = "aarch64")]
pub(crate) fn decode_member(
    source: &mut File,
    spec: NczDecodeSpec,
    output: &mut File,
    mut on_chunk: impl FnMut(u64) -> Result<(), NspNszFormatError>,
) -> Result<(), NspNszFormatError> {
    let mut member = SpanReader::new(&mut *source, spec.source_offset, spec.source_size);
    let record = read_ncz_record(&mut member, spec.source_size)?;
    let encoded_suffix_size = spec
        .expected_nca_size
        .checked_sub(NCZ_PREFIX_SIZE)
        .filter(|size| *size > 0)
        .ok_or(NspNszFormatError::UnsupportedProfile)?;
    let standard_record =
        record.section_offset == spec.section_offset && record.section_size == spec.section_size;
    let clipped_record =
        record.section_offset == NCZ_PREFIX_SIZE && record.section_size == encoded_suffix_size;
    if record.nca_size != spec.expected_nca_size
        || spec.section_offset > NCZ_PREFIX_SIZE
        || spec
            .section_offset
            .checked_add(spec.section_size)
            .filter(|end| *end == spec.expected_nca_size)
            .is_none()
        || (!standard_record && !clipped_record)
    {
        return Err(NspNszFormatError::UnsupportedProfile);
    }

    copy_file_span(
        source,
        spec.source_offset,
        NCZ_PREFIX_SIZE,
        output,
        &mut on_chunk,
    )?;
    let frame_source_offset = spec
        .source_offset
        .checked_add(record.frame_offset)
        .ok_or(NspNszFormatError::ResourceLimit)?;
    let frame_reader = SpanReader::new(&mut *source, frame_source_offset, record.frame_size);
    let source_io_tracker = SourceIoTracker::default();
    let frame_reader = source_io_tracker.track(frame_reader);
    let mut decoder = zstd::stream::read::Decoder::new(frame_reader)
        .map_err(|_| source_io_tracker.zstd_error())?
        .single_frame();
    decoder
        .window_log_max(DEFAULT_ZSTD_WINDOW_LOG)
        .map_err(|_| NspNszFormatError::UnsupportedProfile)?;

    let mut raw_counter = zeroize::Zeroizing::new([0_u8; 8]);
    for (destination, source) in raw_counter.iter_mut().zip(record.counter[..8].iter().rev()) {
        *destination = *source;
    }
    let mut decoded = 0_u64;
    let mut buffer = ZeroizingBuffer::new();
    loop {
        let read = decoder
            .read(&mut buffer.0[..])
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
            spec.section_offset,
            NCZ_PREFIX_SIZE - spec.section_offset + decoded,
            &mut buffer.0[..read],
        )?;
        output
            .write_all(&buffer.0[..read])
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

#[cfg(target_arch = "aarch64")]
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

    let block = (section_offset / 16)
        .checked_add(section_relative_offset / 16)
        .ok_or(NspNszFormatError::ResourceLimit)?;
    let mut counter = zeroize::Zeroizing::new([0_u8; 16]);
    for (destination, source) in counter[..8].iter_mut().zip(raw_counter.iter().rev()) {
        *destination = *source;
    }
    counter[8..].copy_from_slice(&block.to_be_bytes());
    let mut cipher = Ctr128BE::<Aes128>::new_from_slices(key, &counter[..])
        .map_err(|_| NspNszFormatError::UnsupportedProfile)?;
    let skip = usize::try_from(section_relative_offset % 16)
        .map_err(|_| NspNszFormatError::ResourceLimit)?;
    if skip > 0 {
        let mut skipped = zeroize::Zeroizing::new([0_u8; 16]);
        cipher.apply_keystream(&mut skipped[..skip]);
    }
    cipher.apply_keystream(bytes);
    Ok(())
}

#[cfg(target_arch = "aarch64")]
fn copy_file_span(
    source: &mut File,
    offset: u64,
    length: u64,
    output: &mut File,
    on_chunk: &mut impl FnMut(u64) -> Result<(), NspNszFormatError>,
) -> Result<(), NspNszFormatError> {
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

#[cfg(target_arch = "aarch64")]
pub(crate) struct ZeroizingBuffer(pub(crate) zeroize::Zeroizing<[u8; IO_BUFFER_SIZE]>);

#[cfg(target_arch = "aarch64")]
impl ZeroizingBuffer {
    pub(crate) fn new() -> Self {
        Self(zeroize::Zeroizing::new([0_u8; IO_BUFFER_SIZE]))
    }
}

pub(crate) struct SpanReader<R> {
    inner: R,
    base: u64,
    length: u64,
    position: u64,
}

impl<R> SpanReader<R> {
    pub(crate) fn new(inner: R, base: u64, length: u64) -> Self {
        Self {
            inner,
            base,
            length,
            position: 0,
        }
    }
}

impl<R: Read + Seek> Read for SpanReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
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

impl<R: Read + Seek> Seek for SpanReader<R> {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        let next = match position {
            SeekFrom::Start(value) => value,
            SeekFrom::End(value) => self
                .length
                .checked_add_signed(value)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?,
            SeekFrom::Current(value) => self
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

#[cfg(target_arch = "aarch64")]
#[derive(Clone, Default)]
pub(crate) struct SourceIoTracker(std::rc::Rc<std::cell::Cell<bool>>);

#[cfg(target_arch = "aarch64")]
impl SourceIoTracker {
    pub(crate) fn track<R: Read + Seek>(&self, inner: R) -> TrackedSourceReader<R> {
        TrackedSourceReader {
            inner,
            tracker: self.clone(),
        }
    }

    pub(crate) fn zstd_error(&self) -> NspNszFormatError {
        if self.0.get() {
            NspNszFormatError::SourceIo
        } else {
            NspNszFormatError::InvalidPackage
        }
    }
}

#[cfg(target_arch = "aarch64")]
pub(crate) struct TrackedSourceReader<R> {
    inner: R,
    tracker: SourceIoTracker,
}

#[cfg(target_arch = "aarch64")]
impl<R: Read> Read for TrackedSourceReader<R> {
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

#[cfg(target_arch = "aarch64")]
impl<R: Seek> Seek for TrackedSourceReader<R> {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        match self.inner.seek(position) {
            Err(error) => {
                self.tracker.0.set(true);
                Err(error)
            }
            result => result,
        }
    }
}

fn map_ncz_read_error(error: std::io::Error) -> NspNszFormatError {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        NspNszFormatError::InvalidPackage
    } else {
        NspNszFormatError::SourceIo
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn synthetic_member() -> Vec<u8> {
        let mut bytes = vec![0_u8; (NCZ_FRAME_OFFSET + 8) as usize];
        bytes[NCZ_PREFIX_SIZE as usize..NCZ_PREFIX_SIZE as usize + 8].copy_from_slice(b"NCZSECTN");
        bytes[NCZ_PREFIX_SIZE as usize + 8..NCZ_PREFIX_SIZE as usize + 16]
            .copy_from_slice(&1_u64.to_le_bytes());
        let record = NCZ_TABLE_OFFSET as usize;
        bytes[record..record + 8].copy_from_slice(&NCZ_PREFIX_SIZE.to_le_bytes());
        bytes[record + 8..record + 16].copy_from_slice(&0x1000_u64.to_le_bytes());
        bytes[record + 16..record + 24].copy_from_slice(&3_u64.to_le_bytes());
        bytes[NCZ_FRAME_OFFSET as usize..NCZ_FRAME_OFFSET as usize + 8]
            .copy_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0, 0, 0, 0]);
        bytes
    }

    fn read(bytes: Vec<u8>) -> Result<NczRecord, NspNszFormatError> {
        let size = u64::try_from(bytes.len()).expect("synthetic member length fits u64");
        read_ncz_record(&mut Cursor::new(bytes), size)
    }

    #[test]
    fn reads_the_supported_single_section_record() {
        let record = read(synthetic_member()).expect("valid NCZ record");
        assert_eq!(record.nca_size, NCZ_PREFIX_SIZE + 0x1000);
        assert_eq!(record.section_offset, NCZ_PREFIX_SIZE);
        assert_eq!(record.section_size, 0x1000);
        assert_eq!(record.frame_offset, NCZ_FRAME_OFFSET);
        assert_eq!(record.frame_size, 8);
    }

    #[test]
    fn rejects_short_members_and_truncated_fields() {
        assert!(matches!(
            read(vec![0; NCZ_FRAME_OFFSET as usize]),
            Err(NspNszFormatError::InvalidPackage)
        ));

        let mut valid = synthetic_member();
        let expected_size = valid.len();
        for length in [
            NCZ_PREFIX_SIZE as usize + 4,
            NCZ_PREFIX_SIZE as usize + 12,
            NCZ_TABLE_OFFSET as usize + 63,
            NCZ_FRAME_OFFSET as usize + 7,
        ] {
            let mut truncated = valid.clone();
            truncated.truncate(length);
            let size = u64::try_from(expected_size).expect("fixture length fits u64");
            assert!(matches!(
                read_ncz_record(&mut Cursor::new(truncated), size),
                Err(NspNszFormatError::InvalidPackage)
            ));
        }

        valid[NCZ_PREFIX_SIZE as usize] = b'X';
        assert!(matches!(
            read(valid),
            Err(NspNszFormatError::InvalidPackage)
        ));
    }

    #[test]
    fn rejects_unsupported_record_counts_and_fields() {
        let mut bytes = synthetic_member();
        bytes[NCZ_PREFIX_SIZE as usize + 8..NCZ_PREFIX_SIZE as usize + 16]
            .copy_from_slice(&2_u64.to_le_bytes());
        assert!(matches!(
            read(bytes),
            Err(NspNszFormatError::UnsupportedProfile)
        ));

        for (field_offset, value) in [(0, u64::MAX), (8, 0), (16, 2), (24, 1), (56, 1)] {
            let mut bytes = synthetic_member();
            let offset = NCZ_TABLE_OFFSET as usize + field_offset;
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            assert!(matches!(
                read(bytes),
                Err(NspNszFormatError::UnsupportedProfile)
            ));
        }

        let mut overflow = synthetic_member();
        let record = NCZ_TABLE_OFFSET as usize;
        overflow[record..record + 8].copy_from_slice(&NCZ_PREFIX_SIZE.to_le_bytes());
        overflow[record + 8..record + 16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            read(overflow),
            Err(NspNszFormatError::ResourceLimit)
        ));

        let mut too_small_nca = synthetic_member();
        too_small_nca[NCZ_TABLE_OFFSET as usize..NCZ_TABLE_OFFSET as usize + 8]
            .copy_from_slice(&0_u64.to_le_bytes());
        too_small_nca[NCZ_TABLE_OFFSET as usize + 8..NCZ_TABLE_OFFSET as usize + 16]
            .copy_from_slice(&NCZ_PREFIX_SIZE.to_le_bytes());
        assert!(matches!(
            read(too_small_nca),
            Err(NspNszFormatError::UnsupportedProfile)
        ));

        let mut blocked = synthetic_member();
        blocked[NCZ_FRAME_OFFSET as usize..NCZ_FRAME_OFFSET as usize + 8]
            .copy_from_slice(b"NCZBLOCK");
        assert!(matches!(
            read(blocked),
            Err(NspNszFormatError::UnsupportedProfile)
        ));
    }
}
