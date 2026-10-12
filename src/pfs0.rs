use crate::engine::{ContainerFormat, ContainerProbeEntry, ContainerProbeResult};
use crate::error::{ContainerProbeError, ContainerProbeErrorCode};
use std::io::{Read, Seek, SeekFrom};

const HEADER_SIZE: usize = 16;
const ENTRY_SIZE: usize = 24;
const MAX_ENTRIES: usize = 65_536;
const MAX_STRING_TABLE: usize = 16 * 1024 * 1024;
const MAX_NAME: usize = 4 * 1024;
const MAX_TOTAL_NAME_BYTES: usize = 16 * 1024 * 1024;

/// Reads and validates PFS0 metadata without reading any payload bytes.
pub(crate) fn probe<R: Read + Seek>(
    reader: &mut R,
    file_size: u64,
) -> Result<ContainerProbeResult, ContainerProbeError> {
    if file_size < HEADER_SIZE as u64 {
        return Err(error(ContainerProbeErrorCode::TruncatedInput));
    }

    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| error(ContainerProbeErrorCode::InputUnavailable))?;
    let mut header = [0_u8; HEADER_SIZE];
    reader.read_exact(&mut header).map_err(map_read_error)?;

    if &header[0..4] != b"PFS0" {
        return Err(error(ContainerProbeErrorCode::UnsupportedFormat));
    }

    let entry_count = u32::from_le_bytes(header[4..8].try_into().expect("fixed header field"));
    let string_table_size =
        u32::from_le_bytes(header[8..12].try_into().expect("fixed header field"));
    let reserved = u32::from_le_bytes(header[12..16].try_into().expect("fixed header field"));

    if reserved != 0 {
        return Err(error(ContainerProbeErrorCode::InvalidHeader));
    }

    let entry_count =
        usize::try_from(entry_count).map_err(|_| error(ContainerProbeErrorCode::LimitExceeded))?;
    if entry_count > MAX_ENTRIES {
        return Err(error(ContainerProbeErrorCode::LimitExceeded));
    }

    let string_table_size = usize::try_from(string_table_size)
        .map_err(|_| error(ContainerProbeErrorCode::LimitExceeded))?;
    if string_table_size > MAX_STRING_TABLE {
        return Err(error(ContainerProbeErrorCode::LimitExceeded));
    }
    if (entry_count == 0) != (string_table_size == 0) {
        return Err(error(ContainerProbeErrorCode::InvalidStringTable));
    }

    let entry_table_size = entry_count
        .checked_mul(ENTRY_SIZE)
        .ok_or_else(|| error(ContainerProbeErrorCode::InvalidHeader))?;
    let payload_offset = (HEADER_SIZE as u64)
        .checked_add(
            u64::try_from(entry_table_size)
                .map_err(|_| error(ContainerProbeErrorCode::InvalidHeader))?,
        )
        .and_then(|position| position.checked_add(string_table_size as u64))
        .ok_or_else(|| error(ContainerProbeErrorCode::InvalidHeader))?;
    if payload_offset > file_size {
        return Err(error(ContainerProbeErrorCode::TruncatedInput));
    }

    let metadata_size = entry_table_size
        .checked_add(string_table_size)
        .ok_or_else(|| error(ContainerProbeErrorCode::InvalidHeader))?;
    let mut metadata = Vec::new();
    metadata
        .try_reserve_exact(metadata_size)
        .map_err(|_| error(ContainerProbeErrorCode::ResourceLimitExceeded))?;
    metadata.resize(metadata_size, 0);
    reader.read_exact(&mut metadata).map_err(map_read_error)?;

    let (entry_table, string_table) = metadata.split_at(entry_table_size);
    validate_string_table(string_table)?;

    let payload_size = file_size - payload_offset;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(entry_count)
        .map_err(|_| error(ContainerProbeErrorCode::ResourceLimitExceeded))?;
    let mut spans = Vec::new();
    spans
        .try_reserve_exact(entry_count)
        .map_err(|_| error(ContainerProbeErrorCode::ResourceLimitExceeded))?;
    let mut total_name_bytes = 0_usize;

    let (records, remainder) = entry_table.as_chunks::<ENTRY_SIZE>();
    if !remainder.is_empty() {
        return Err(error(ContainerProbeErrorCode::InvalidHeader));
    }
    for record in records {
        let offset = u64::from_le_bytes(record[0..8].try_into().expect("fixed entry field"));
        let size = u64::from_le_bytes(record[8..16].try_into().expect("fixed entry field"));
        let name_offset = u32::from_le_bytes(record[16..20].try_into().expect("fixed entry field"));
        let reserved = u32::from_le_bytes(record[20..24].try_into().expect("fixed entry field"));
        if reserved != 0 {
            return Err(error(ContainerProbeErrorCode::InvalidEntry));
        }

        let name = read_name(string_table, name_offset)?;
        total_name_bytes = total_name_bytes
            .checked_add(name.len())
            .ok_or_else(|| error(ContainerProbeErrorCode::LimitExceeded))?;
        if total_name_bytes > MAX_TOTAL_NAME_BYTES {
            return Err(error(ContainerProbeErrorCode::LimitExceeded));
        }
        let mut owned_name = String::new();
        owned_name
            .try_reserve_exact(name.len())
            .map_err(|_| error(ContainerProbeErrorCode::ResourceLimitExceeded))?;
        owned_name.push_str(name);
        let relative_end = offset
            .checked_add(size)
            .ok_or_else(|| error(ContainerProbeErrorCode::InvalidEntry))?;
        if relative_end > payload_size {
            return Err(error(ContainerProbeErrorCode::TruncatedInput));
        }
        let file_offset = payload_offset
            .checked_add(offset)
            .ok_or_else(|| error(ContainerProbeErrorCode::InvalidEntry))?;
        let file_end = file_offset
            .checked_add(size)
            .ok_or_else(|| error(ContainerProbeErrorCode::InvalidEntry))?;
        if file_end > file_size {
            return Err(error(ContainerProbeErrorCode::TruncatedInput));
        }
        if size != 0 {
            spans.push((offset, relative_end));
        }
        entries.push(ContainerProbeEntry {
            name: owned_name,
            offset,
            size,
            file_offset,
        });
    }

    spans.sort_unstable();
    let mut previous_end = 0;
    for (start, end) in spans {
        if start < previous_end {
            return Err(error(ContainerProbeErrorCode::InvalidEntry));
        }
        previous_end = end;
    }

    Ok(ContainerProbeResult {
        format: ContainerFormat::Pfs0,
        file_size,
        payload_offset,
        payload_size,
        entries,
    })
}

fn validate_string_table(string_table: &[u8]) -> Result<(), ContainerProbeError> {
    if !string_table.is_empty()
        && (string_table.last() != Some(&0) || std::str::from_utf8(string_table).is_err())
    {
        return Err(error(ContainerProbeErrorCode::InvalidStringTable));
    }
    Ok(())
}

fn read_name(string_table: &[u8], name_offset: u32) -> Result<&str, ContainerProbeError> {
    let start = usize::try_from(name_offset)
        .map_err(|_| error(ContainerProbeErrorCode::InvalidStringTable))?;
    if start >= string_table.len() || (start > 0 && string_table[start - 1] != 0) {
        return Err(error(ContainerProbeErrorCode::InvalidStringTable));
    }

    let remaining = &string_table[start..];
    let length = remaining
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| error(ContainerProbeErrorCode::InvalidStringTable))?;
    if length == 0 {
        return Err(error(ContainerProbeErrorCode::InvalidStringTable));
    }
    if length > MAX_NAME {
        return Err(error(ContainerProbeErrorCode::NameTooLong));
    }
    let name = std::str::from_utf8(&remaining[..length])
        .map_err(|_| error(ContainerProbeErrorCode::InvalidStringTable))?;
    Ok(name)
}

fn map_read_error(cause: std::io::Error) -> ContainerProbeError {
    match cause.kind() {
        std::io::ErrorKind::UnexpectedEof => error(ContainerProbeErrorCode::TruncatedInput),
        _ => error(ContainerProbeErrorCode::InputUnavailable),
    }
}

fn error(code: ContainerProbeErrorCode) -> ContainerProbeError {
    ContainerProbeError::new(code)
}

#[cfg(test)]
mod tests {
    use super::{HEADER_SIZE, probe};
    use crate::ContainerProbeErrorCode;
    use std::io::{Cursor, Read, Seek, SeekFrom};

    const MAX_ENTRIES: usize = 65_536;
    const MAX_STRING_TABLE: usize = 16 * 1024 * 1024;
    const MAX_NAME: usize = 4 * 1024;
    const MAX_TOTAL_NAME_BYTES: usize = 16 * 1024 * 1024;

    struct CountingReader {
        inner: Cursor<Vec<u8>>,
        bytes_read: usize,
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "synthetic read failure",
            ))
        }
    }

    impl Seek for FailingReader {
        fn seek(&mut self, _: SeekFrom) -> std::io::Result<u64> {
            Ok(0)
        }
    }

    impl CountingReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                inner: Cursor::new(bytes),
                bytes_read: 0,
            }
        }
    }

    impl Read for CountingReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let read = self.inner.read(buffer)?;
            self.bytes_read += read;
            Ok(read)
        }
    }

    impl Seek for CountingReader {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(position)
        }
    }

    fn parse(bytes: Vec<u8>) -> Result<crate::ContainerProbeResult, crate::ContainerProbeError> {
        let length = bytes.len() as u64;
        probe(&mut Cursor::new(bytes), length)
    }

    fn entry(offset: u64, size: u64, name_offset: u32, reserved: u32) -> [u8; 24] {
        let mut bytes = [0; 24];
        bytes[0..8].copy_from_slice(&offset.to_le_bytes());
        bytes[8..16].copy_from_slice(&size.to_le_bytes());
        bytes[16..20].copy_from_slice(&name_offset.to_le_bytes());
        bytes[20..24].copy_from_slice(&reserved.to_le_bytes());
        bytes
    }

    fn raw_pfs0(entries: &[[u8; 24]], strings: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PFS0");
        bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        for entry in entries {
            bytes.extend_from_slice(entry);
        }
        bytes.extend_from_slice(strings);
        bytes.extend_from_slice(payload);
        bytes
    }

    fn header_with(count: u32, string_size: u32) -> Vec<u8> {
        let mut bytes = Vec::from(&b"PFS0"[..]);
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes.extend_from_slice(&string_size.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes
    }

    fn assert_code(
        result: Result<crate::ContainerProbeResult, crate::ContainerProbeError>,
        want: ContainerProbeErrorCode,
    ) {
        match result {
            Err(error) => assert_eq!(error.code(), want),
            Ok(_) => panic!("input was accepted when rejection was expected"),
        }
    }

    #[test]
    fn parses_payload_relative_spans_without_reading_payload_bytes() {
        let strings = b"sample\0";
        let payload = b"prefixDATA-and-unread-tail";
        let bytes = raw_pfs0(&[entry(6, 4, 0, 0)], strings, payload);
        let expected_payload_offset = 16 + 24 + strings.len();
        let mut reader = CountingReader::new(bytes.clone());

        let probed = probe(&mut reader, bytes.len() as u64).expect("valid synthetic PFS0");

        assert_eq!(probed.file_size, bytes.len() as u64);
        assert_eq!(probed.payload_offset, expected_payload_offset as u64);
        assert_eq!(probed.payload_size, payload.len() as u64);
        assert_eq!(probed.entries[0].offset, 6);
        assert_eq!(probed.entries[0].size, 4);
        assert_eq!(
            probed.entries[0].file_offset,
            (expected_payload_offset + 6) as u64
        );
        assert_eq!(reader.bytes_read, expected_payload_offset);
    }

    #[test]
    fn maps_non_eof_reader_failures_to_sanitized_input_errors() {
        let mut reader = FailingReader;
        let error = probe(&mut reader, HEADER_SIZE as u64)
            .expect_err("reader failure should become a typed input error");

        assert_eq!(error.code(), ContainerProbeErrorCode::InputUnavailable);
        assert_eq!(error.to_string(), "the input could not be read");
    }

    #[test]
    fn accepts_an_empty_container_and_zero_length_entry_at_payload_end() {
        let empty = raw_pfs0(&[], &[], &[]);
        assert!(
            parse(empty)
                .expect("empty PFS0 has no malformed relationships")
                .entries
                .is_empty()
        );

        let bytes = raw_pfs0(&[entry(0, 0, 0, 0)], b"x\0", &[]);
        let probed = parse(bytes).expect("zero-length span at the payload boundary is valid");
        assert_eq!(probed.entries[0].offset, 0);
        assert_eq!(probed.entries[0].size, 0);
    }

    #[test]
    fn rejects_short_headers_and_unrecognized_magic() {
        assert_code(
            parse(b"PFS0".to_vec()),
            ContainerProbeErrorCode::TruncatedInput,
        );

        let mut wrong_magic = header_with(0, 0);
        wrong_magic[0..4].copy_from_slice(b"NOPE");
        assert_code(
            parse(wrong_magic),
            ContainerProbeErrorCode::UnsupportedFormat,
        );
    }

    #[test]
    fn rejects_reserved_header_and_entry_bits() {
        let mut header = header_with(0, 0);
        header[12] = 1;
        assert_code(parse(header), ContainerProbeErrorCode::InvalidHeader);

        let bytes = raw_pfs0(&[entry(0, 0, 0, 1)], b"x\0", &[]);
        assert_code(parse(bytes), ContainerProbeErrorCode::InvalidEntry);
    }

    #[test]
    fn enforces_entry_and_string_table_limits_before_reading_declared_tables() {
        assert_code(
            parse(header_with((MAX_ENTRIES + 1) as u32, 0)),
            ContainerProbeErrorCode::LimitExceeded,
        );
        assert_code(
            parse(header_with(0, (MAX_STRING_TABLE + 1) as u32)),
            ContainerProbeErrorCode::LimitExceeded,
        );
    }

    #[test]
    fn accepts_the_entry_and_string_table_limits() {
        let mut records = Vec::with_capacity(MAX_ENTRIES);
        for _ in 0..MAX_ENTRIES {
            records.push(entry(0, 0, 0, 0));
        }
        let strings = b"x\0";
        let probed =
            parse(raw_pfs0(&records, strings, &[])).expect("maximum supported entry count");
        assert_eq!(probed.entries.len(), MAX_ENTRIES);

        let mut strings = vec![0; MAX_STRING_TABLE];
        strings[0] = b'x';
        let probed = parse(raw_pfs0(&[entry(0, 0, 0, 0)], &strings, &[]))
            .expect("maximum supported string-table size");
        assert_eq!(probed.entries[0].name, "x");
    }

    #[test]
    fn accepts_the_maximum_name_length_and_rejects_a_longer_name() {
        let mut maximum = vec![b'a'; MAX_NAME];
        maximum.push(0);
        let probed = parse(raw_pfs0(&[entry(0, 0, 0, 0)], &maximum, &[]))
            .expect("maximum supported name length");
        assert_eq!(probed.entries[0].name.len(), MAX_NAME);

        let mut too_long = vec![b'a'; MAX_NAME + 1];
        too_long.push(0);
        assert_code(
            parse(raw_pfs0(&[entry(0, 0, 0, 0)], &too_long, &[])),
            ContainerProbeErrorCode::NameTooLong,
        );
    }

    #[test]
    fn bounds_total_copied_filename_bytes_across_repeated_entries() {
        let name = vec![b'a'; MAX_NAME];
        let mut strings = name;
        strings.push(0);
        let entry_count = (MAX_TOTAL_NAME_BYTES / MAX_NAME) + 1;
        let records = vec![entry(0, 0, 0, 0); entry_count];

        assert_code(
            parse(raw_pfs0(&records, &strings, &[])),
            ContainerProbeErrorCode::LimitExceeded,
        );
    }

    #[test]
    fn rejects_invalid_string_table_termination_utf8_offsets_and_boundaries() {
        assert_code(
            parse(raw_pfs0(&[entry(0, 0, 0, 0)], b"name", &[])),
            ContainerProbeErrorCode::InvalidStringTable,
        );
        assert_code(
            parse(raw_pfs0(&[entry(0, 0, 0, 0)], &[0xff, 0], &[])),
            ContainerProbeErrorCode::InvalidStringTable,
        );
        assert_code(
            parse(raw_pfs0(&[entry(0, 0, 2, 0)], b"x\0", &[])),
            ContainerProbeErrorCode::InvalidStringTable,
        );
        assert_code(
            parse(raw_pfs0(&[entry(0, 0, 1, 0)], b"xy\0", &[])),
            ContainerProbeErrorCode::InvalidStringTable,
        );
        assert_code(
            parse(raw_pfs0(&[], b"unused\0", &[])),
            ContainerProbeErrorCode::InvalidStringTable,
        );
    }

    #[test]
    fn rejects_empty_names() {
        assert_code(
            parse(raw_pfs0(&[entry(0, 0, 0, 0)], b"\0", &[])),
            ContainerProbeErrorCode::InvalidStringTable,
        );
    }

    #[test]
    fn rejects_entry_arithmetic_overflow_out_of_bounds_and_overlap() {
        assert_code(
            parse(raw_pfs0(&[entry(u64::MAX, 1, 0, 0)], b"x\0", &[])),
            ContainerProbeErrorCode::InvalidEntry,
        );
        assert_code(
            parse(raw_pfs0(&[entry(0, 4, 0, 0)], b"x\0", b"abc")),
            ContainerProbeErrorCode::TruncatedInput,
        );
        assert_code(
            parse(raw_pfs0(
                &[entry(0, 4, 0, 0), entry(2, 4, 2, 0)],
                b"a\0b\0",
                b"abcdef",
            )),
            ContainerProbeErrorCode::InvalidEntry,
        );
    }

    #[test]
    fn rejects_incomplete_entry_tables_and_string_tables() {
        let mut missing_entry = header_with(1, 2);
        missing_entry.extend_from_slice(b"x\0");
        assert_code(
            parse(missing_entry),
            ContainerProbeErrorCode::TruncatedInput,
        );

        let mut missing_strings = header_with(1, 2);
        missing_strings.extend_from_slice(&entry(0, 0, 0, 0));
        missing_strings.push(b'x');
        assert_code(
            parse(missing_strings),
            ContainerProbeErrorCode::TruncatedInput,
        );
    }
}
