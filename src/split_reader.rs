//! Bounded logical reader over an ordered set of physical Split segments.
//!
//! The reader presents already-qualified regular files as one byte stream for
//! internal parsers. It never concatenates segments into a temporary file and
//! never claims that an open handle is an immutable snapshot. Every read
//! revalidates the path and handle identity so replacement, truncation, and
//! same-size mutation fail closed. Future effectful operations must repeat
//! this revalidation before producing externally visible results.
//!
//! A physical file may satisfy a read request with fewer bytes than asked for.
//! That is a valid short read, not corruption: the reader keeps reading until
//! the requested logical range or the declared segment extent is reached. A
//! segment that reports end-of-file before its declared length fails with
//! [`std::io::ErrorKind::UnexpectedEof`] instead of silently shortening the
//! logical stream.

use crate::file_identity::{FileSnapshot, file_snapshot, handle_identity, path_identity};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// A validated regular-file segment with an opened read-only handle.
pub(crate) struct OpenedSegment {
    pub(crate) path: PathBuf,
    pub(crate) file: File,
    pub(crate) len: u64,
    snapshot: FileSnapshot,
}

impl OpenedSegment {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    pub(crate) fn identity(&self) -> Option<crate::file_identity::FileIdentity> {
        self.snapshot.identity
    }

    pub(crate) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
}

impl Read for OpenedSegment {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

impl Seek for OpenedSegment {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

/// Internal source used by the virtual reader. The production implementation
/// validates a real opened handle; tests can provide a deterministic short-read
/// source without exposing a new public abstraction.
trait SegmentSource: Read + Seek {
    fn logical_len(&self) -> u64;
    fn revalidate_source(&mut self) -> io::Result<()>;
}

impl SegmentSource for OpenedSegment {
    fn logical_len(&self) -> u64 {
        self.len
    }

    fn revalidate_source(&mut self) -> io::Result<()> {
        revalidate_segment(self).map_err(revalidation_error)
    }
}

/// Why an opened segment could not be accepted or remained unstable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SegmentOpenError {
    /// The path could not be inspected or opened.
    Unavailable,
    /// The entry is a symlink, directory, device, FIFO, or other special file.
    NotRegular,
    /// The platform cannot prove a unique stable file identity.
    IdentityUnavailable,
    /// The observed byte length differs from the manifest declaration.
    SizeMismatch,
    /// The path or opened handle changed during inspection.
    Changed,
}

/// Opens and validates one physical regular-file segment without following a
/// final-component symlink.
pub(crate) fn open_segment_file(
    path: &Path,
    expected_size: u64,
) -> Result<OpenedSegment, SegmentOpenError> {
    let path_metadata =
        std::fs::symlink_metadata(path).map_err(|_| SegmentOpenError::Unavailable)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(SegmentOpenError::NotRegular);
    }
    let before = file_snapshot(&path_metadata, path_identity(path));

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: inspect the link itself instead of following it.
        options.custom_flags(0x0020_0000);
    }
    let file = options
        .open(path)
        .map_err(|_| SegmentOpenError::Unavailable)?;
    let handle_metadata = file.metadata().map_err(|_| SegmentOpenError::Unavailable)?;
    if !handle_metadata.file_type().is_file() {
        return Err(SegmentOpenError::NotRegular);
    }
    let Some(identity) = handle_identity(&file) else {
        return Err(SegmentOpenError::IdentityUnavailable);
    };
    if handle_metadata.len() != expected_size {
        return Err(SegmentOpenError::SizeMismatch);
    }
    let snapshot = file_snapshot(&handle_metadata, Some(identity));
    if before.identity != Some(identity) || before.len != expected_size {
        return Err(SegmentOpenError::Changed);
    }

    let after_path = std::fs::symlink_metadata(path).map_err(|_| SegmentOpenError::Unavailable)?;
    if after_path.file_type().is_symlink() || !after_path.file_type().is_file() {
        return Err(SegmentOpenError::NotRegular);
    }
    if path_identity(path) != Some(identity) || after_path.len() != expected_size {
        return Err(SegmentOpenError::Changed);
    }

    Ok(OpenedSegment {
        path: path.to_path_buf(),
        file,
        len: expected_size,
        snapshot,
    })
}

/// Revalidates both the path and the opened handle against the stored snapshot.
pub(crate) fn revalidate_segment(segment: &OpenedSegment) -> Result<(), SegmentOpenError> {
    let handle_metadata = segment
        .file
        .metadata()
        .map_err(|_| SegmentOpenError::Changed)?;
    let Some(identity) = handle_identity(&segment.file) else {
        return Err(SegmentOpenError::Changed);
    };
    if !handle_metadata.file_type().is_file()
        || file_snapshot(&handle_metadata, Some(identity)) != segment.snapshot
    {
        return Err(SegmentOpenError::Changed);
    }
    let path_metadata =
        std::fs::symlink_metadata(&segment.path).map_err(|_| SegmentOpenError::Changed)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(SegmentOpenError::Changed);
    }
    if file_snapshot(&path_metadata, path_identity(&segment.path)) != segment.snapshot {
        return Err(SegmentOpenError::Changed);
    }
    Ok(())
}

/// A bounded multi-segment `Read + Seek` adapter over opened regular files.
#[allow(dead_code)] // Exercised by internal parser integration tests until execution uses it.
pub(crate) struct SegmentedFileReader {
    segments: Vec<Box<dyn SegmentSource>>,
    starts: Vec<u64>,
    total_len: u64,
    position: u64,
}

#[allow(dead_code)]
impl SegmentedFileReader {
    /// Builds a reader from validated opened segments in logical order.
    pub(crate) fn from_segments(segments: Vec<OpenedSegment>) -> io::Result<Self> {
        if segments.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "no segments"));
        }
        let mut starts = Vec::with_capacity(segments.len());
        let mut total_len = 0_u64;
        for segment in &segments {
            starts.push(total_len);
            total_len = total_len
                .checked_add(segment.logical_len())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "logical length overflow")
                })?;
        }
        Ok(Self {
            segments: segments
                .into_iter()
                .map(|segment| Box::new(segment) as Box<dyn SegmentSource>)
                .collect(),
            starts,
            total_len,
            position: 0,
        })
    }

    #[cfg(test)]
    fn from_test_segments(segments: Vec<Box<dyn SegmentSource>>) -> io::Result<Self> {
        if segments.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "no segments"));
        }
        let mut starts = Vec::with_capacity(segments.len());
        let mut total_len = 0_u64;
        for segment in &segments {
            starts.push(total_len);
            total_len = total_len
                .checked_add(segment.logical_len())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "logical length overflow")
                })?;
        }
        Ok(Self {
            segments,
            starts,
            total_len,
            position: 0,
        })
    }

    /// Returns the exact logical byte length of all segments.
    pub(crate) fn len(&self) -> u64 {
        self.total_len
    }

    fn segment_index(&self, position: u64) -> io::Result<usize> {
        let index = match self.starts.binary_search(&position) {
            Ok(index) => index,
            Err(index) => index.checked_sub(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "position outside reader")
            })?,
        };
        if index >= self.segments.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "position outside reader",
            ));
        }
        Ok(index)
    }

    fn revalidate_all(&mut self) -> io::Result<()> {
        for segment in &mut self.segments {
            segment.revalidate_source()?;
        }
        Ok(())
    }
}

impl Read for SegmentedFileReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.position == self.total_len {
            self.revalidate_all()?;
            return Ok(0);
        }
        let mut written = 0;
        while written < buffer.len() && self.position < self.total_len {
            let index = self.segment_index(self.position)?;
            let segment = &mut self.segments[index];
            let within = self.position - self.starts[index];
            let available = segment.logical_len() - within;
            let count = usize::try_from(available)
                .unwrap_or(usize::MAX)
                .min(buffer.len() - written);
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "segment has no readable bytes",
                ));
            }
            segment
                .seek(SeekFrom::Start(within))
                .map_err(map_io_error)?;
            segment.revalidate_source()?;
            let mut filled = 0;
            while filled < count {
                if filled != 0 {
                    segment.revalidate_source()?;
                }
                let read = segment
                    .read(&mut buffer[written + filled..written + count])
                    .map_err(map_io_error)?;
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "segment ended before its declared length",
                    ));
                }
                filled += read;
            }
            written += count;
            self.position = self
                .position
                .checked_add(count as u64)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
        }
        if self.position == self.total_len {
            self.revalidate_all()?;
        }
        Ok(written)
    }
}

impl Seek for SegmentedFileReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = match position {
            SeekFrom::Start(offset) => offset,
            SeekFrom::Current(delta) => checked_offset(self.position, delta)?,
            SeekFrom::End(delta) => checked_offset(self.total_len, delta)?,
        };
        if next > self.total_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek past logical end",
            ));
        }
        self.position = next;
        Ok(next)
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        Ok(self.position)
    }
}

#[allow(dead_code)] // The reader is exercised by internal integration tests.
fn checked_offset(base: u64, delta: i64) -> io::Result<u64> {
    if delta >= 0 {
        base.checked_add(delta as u64)
    } else {
        base.checked_sub(delta.unsigned_abs())
    }
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek offset overflow"))
}

#[allow(dead_code)]
fn revalidation_error(_: SegmentOpenError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "segment identity or metadata changed",
    )
}

#[allow(dead_code)]
fn map_io_error(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), "segment read failed")
}

#[cfg(test)]
mod tests {
    use super::{SegmentSource, SegmentedFileReader, open_segment_file};
    use std::fs;
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn temp_directory() -> PathBuf {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("nscb-split-reader-{}-{id}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn write_parts(directory: &Path, parts: &[&[u8]]) -> Vec<PathBuf> {
        parts
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                let path = directory.join(format!("{index:02}"));
                fs::write(&path, bytes).unwrap();
                path
            })
            .collect()
    }

    fn opened_reader(paths: &[PathBuf], sizes: &[u64]) -> SegmentedFileReader {
        let segments = paths
            .iter()
            .zip(sizes)
            .map(|(path, size)| open_segment_file(path, *size).unwrap())
            .collect();
        SegmentedFileReader::from_segments(segments).unwrap()
    }

    struct ShortReadSegment {
        cursor: Cursor<Vec<u8>>,
        declared_len: u64,
        max_chunk: usize,
    }

    impl ShortReadSegment {
        fn new(bytes: &[u8], declared_len: u64, max_chunk: usize) -> Self {
            Self {
                cursor: Cursor::new(bytes.to_vec()),
                declared_len,
                max_chunk,
            }
        }
    }

    impl Read for ShortReadSegment {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let remaining = self.declared_len.saturating_sub(self.cursor.position());
            if remaining == 0 || buffer.is_empty() {
                return Ok(0);
            }
            let limit = usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(self.max_chunk)
                .min(buffer.len());
            self.cursor.read(&mut buffer[..limit])
        }
    }

    impl Seek for ShortReadSegment {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            self.cursor.seek(position)
        }
    }

    impl SegmentSource for ShortReadSegment {
        fn logical_len(&self) -> u64 {
            self.declared_len
        }

        fn revalidate_source(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn test_reader(segments: Vec<ShortReadSegment>) -> SegmentedFileReader {
        SegmentedFileReader::from_test_segments(
            segments
                .into_iter()
                .map(|segment| Box::new(segment) as Box<dyn SegmentSource>)
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn short_underlying_reads_are_completed_without_exposing_partial_output() {
        let mut reader = test_reader(vec![
            ShortReadSegment::new(b"abcdef", 6, 2),
            ShortReadSegment::new(b"gh", 2, 1),
        ]);
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output, b"abcdefgh");
        assert_eq!(reader.stream_position().unwrap(), 8);
    }

    #[test]
    fn short_reads_crossing_a_segment_boundary_preserve_exact_bytes() {
        let mut reader = test_reader(vec![
            ShortReadSegment::new(b"abc", 3, 1),
            ShortReadSegment::new(b"defg", 4, 2),
        ]);
        assert_eq!(reader.seek(SeekFrom::Start(2)).unwrap(), 2);
        let mut output = [0_u8; 4];
        reader.read_exact(&mut output).unwrap();
        assert_eq!(&output, b"cdef");
        assert_eq!(reader.stream_position().unwrap(), 6);
    }

    #[test]
    fn premature_eof_before_the_declared_extent_is_rejected() {
        let mut reader = test_reader(vec![ShortReadSegment::new(b"abcd", 6, 2)]);
        let mut output = [0_u8; 6];
        let error = reader.read(&mut output).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn reads_across_boundaries_and_seeks_to_valid_offsets() {
        let directory = temp_directory();
        let paths = write_parts(&directory, &[b"abcd", b"ef", b"ghij"]);
        let mut reader = opened_reader(&paths, &[4, 2, 4]);
        assert_eq!(reader.len(), 10);

        let mut first = [0_u8; 5];
        reader.read_exact(&mut first).unwrap();
        assert_eq!(&first, b"abcde");
        assert_eq!(reader.stream_position().unwrap(), 5);
        assert_eq!(reader.seek(SeekFrom::Start(0)).unwrap(), 0);
        let mut all = [0_u8; 10];
        reader.read_exact(&mut all).unwrap();
        assert_eq!(&all, b"abcdefghij");
        assert_eq!(reader.read(&mut [0_u8; 1]).unwrap(), 0);
        assert_eq!(reader.seek(SeekFrom::End(0)).unwrap(), 10);
        assert_eq!(reader.seek(SeekFrom::End(-3)).unwrap(), 7);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_symlinks_special_files_and_size_mismatch() {
        let directory = temp_directory();
        let path = directory.join("00");
        fs::write(&path, b"data").unwrap();
        assert!(open_segment_file(&path, 3).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = directory.join("link");
            symlink(&path, &link).unwrap();
            assert!(open_segment_file(&link, 4).is_err());
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_invalid_and_overflowing_seeks() {
        let directory = temp_directory();
        let paths = write_parts(&directory, &[b"abcd"]);
        let mut reader = opened_reader(&paths, &[4]);
        assert!(reader.seek(SeekFrom::Start(5)).is_err());
        assert!(reader.seek(SeekFrom::Start(u64::MAX)).is_err());
        assert!(reader.seek(SeekFrom::Start(0)).is_ok());
        assert!(reader.seek(SeekFrom::Current(-1)).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn detects_replacement_and_same_size_mutation() {
        let directory = temp_directory();
        let paths = write_parts(&directory, &[b"abcd", b"efgh"]);
        let mut reader = opened_reader(&paths, &[4, 4]);
        let mut buffer = [0_u8; 2];
        reader.read_exact(&mut buffer).unwrap();
        let replacement = directory.join("replacement");
        fs::write(&replacement, b"WXYZ").unwrap();
        fs::rename(&replacement, &paths[0]).unwrap();
        assert!(reader.read(&mut [0_u8; 1]).is_err());

        let mutation_paths = write_parts(&directory, &[b"1234", b"5678"]);
        let mut reader = opened_reader(&mutation_paths, &[4, 4]);
        std::thread::sleep(std::time::Duration::from_millis(20));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&mutation_paths[0])
            .unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"9").unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(reader.read(&mut [0_u8; 1]).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn truncation_after_open_fails_before_exposing_short_logical_bytes() {
        let directory = temp_directory();
        let paths = write_parts(&directory, &[b"abcdef", b"gh"]);
        let mut reader = opened_reader(&paths, &[6, 2]);
        let mut first = [0_u8; 2];
        reader.read_exact(&mut first).unwrap();
        let truncated = fs::OpenOptions::new().write(true).open(&paths[0]).unwrap();
        truncated.set_len(4).unwrap();
        truncated.sync_all().unwrap();
        drop(truncated);
        let mut buffer = [0_u8; 8];
        let error = reader.read(&mut buffer).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn every_offset_returns_the_same_logical_bytes() {
        let expected = b"abcdefgh".to_vec();
        for offset in 0..=expected.len() {
            let mut reader = test_reader(vec![
                ShortReadSegment::new(b"abcdef", 6, 1),
                ShortReadSegment::new(b"gh", 2, 1),
            ]);
            assert_eq!(
                reader.seek(SeekFrom::Start(offset as u64)).unwrap(),
                offset as u64
            );
            let mut buffer = [0_u8; 3];
            let read = reader.read(&mut buffer).unwrap();
            let available = expected.len() - offset;
            assert_eq!(read, available.min(buffer.len()), "offset {offset}");
            assert_eq!(
                &buffer[..read],
                &expected[offset..offset + read],
                "offset {offset}"
            );
        }
    }

    #[test]
    fn empty_reads_and_eof_are_exact() {
        let directory = temp_directory();
        let paths = write_parts(&directory, &[b"ab", b"cd"]);
        let mut reader = opened_reader(&paths, &[2, 2]);
        assert_eq!(reader.read(&mut []).unwrap(), 0);
        reader.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(reader.read(&mut []).unwrap(), 0);
        assert_eq!(reader.read(&mut [0_u8; 4]).unwrap(), 0);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pfs0_probe_reads_metadata_across_physical_segments() {
        let directory = temp_directory();
        let name = b"member";
        let payload = b"DATA";
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PFS0");
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&(name.len() as u32 + 1).to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(name);
        bytes.push(0);
        bytes.extend_from_slice(payload);

        let first = 8;
        let second = 16 + 12 + 1;
        let third = 16 + 24 + name.len() + 1;
        let slices = [
            &bytes[..first],
            &bytes[first..second],
            &bytes[second..third],
            &bytes[third..],
        ];
        let paths = write_parts(&directory, &slices);
        let sizes = slices.map(|slice| slice.len() as u64);
        let mut reader = opened_reader(&paths, &sizes);
        let result = crate::pfs0::probe(&mut reader, bytes.len() as u64).unwrap();
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].name, "member");
        fs::remove_dir_all(directory).unwrap();
    }
}
