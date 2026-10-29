//! Bounded parsing of the NCA header-key aliases needed by the provider.
//!
//! Other entries in a conventional key file remain opaque and are deliberately
//! ignored. Only a sanitized key file containing the normalized header key is
//! presented to the helper.
use crate::inspection::InspectionErrorCode;
pub(crate) use crate::key_file::HeaderKey;
use crate::key_file::{KeyFileParseError, parse_header_key_bytes};
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub(crate) use crate::key_file::MAX_KEY_FILE_BYTES;

pub(crate) fn read_header_key(
    reader: &mut impl Read,
    file_size: u64,
) -> Result<HeaderKey, InspectionErrorCode> {
    if file_size > MAX_KEY_FILE_BYTES {
        return Err(InspectionErrorCode::KeyFileLimitExceeded);
    }
    let size = usize::try_from(file_size).map_err(|_| InspectionErrorCode::KeyFileLimitExceeded)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| InspectionErrorCode::AllocationFailed)?;
    bytes.resize(size, 0);
    if read_exact_or_clear(reader, &mut bytes).is_err() {
        return Err(InspectionErrorCode::KeyFileUnavailable);
    }

    let parsed = parse_header_key_bytes(&bytes).map_err(|error| match error {
        KeyFileParseError::Malformed => InspectionErrorCode::KeyFileMalformed,
        KeyFileParseError::MissingHeaderKey => InspectionErrorCode::MissingHeaderKey,
    });
    bytes.fill(0);
    parsed
}

fn read_exact_or_clear(reader: &mut impl Read, bytes: &mut [u8]) -> std::io::Result<()> {
    if let Err(error) = reader.read_exact(bytes) {
        bytes.fill(0);
        return Err(error);
    }
    Ok(())
}

pub(crate) fn write_sanitized(path: &Path, key: &HeaderKey) -> Result<(), InspectionErrorCode> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|_| InspectionErrorCode::InternalIo)?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = [0_u8; 64];
    for (index, byte) in key.as_bytes().iter().enumerate() {
        encoded[index * 2] = HEX[usize::from(byte >> 4)];
        encoded[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    write_sanitized_bytes(&mut file, &mut encoded).map_err(|_| InspectionErrorCode::InternalIo)
}

fn write_sanitized_bytes(writer: &mut impl Write, encoded: &mut [u8; 64]) -> io::Result<()> {
    let result = writer
        .write_all(b"header_key = ")
        .and_then(|_| writer.write_all(encoded))
        .and_then(|_| writer.write_all(b"\n"));
    encoded.fill(0);
    result
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_KEY_FILE_BYTES, read_exact_or_clear, read_header_key, write_sanitized,
        write_sanitized_bytes,
    };
    use crate::inspection::InspectionErrorCode;
    use std::fs;
    use std::io::{self, Cursor, Read, Write};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct PartialThenError(bool);

    impl Read for PartialThenError {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.0 {
                return Err(io::Error::other("injected read failure"));
            }
            self.0 = true;
            buffer[..3].copy_from_slice(b"key");
            Ok(3)
        }
    }

    #[test]
    fn partially_read_key_buffer_is_cleared_on_io_failure() {
        let mut buffer = [0x5a; 8];
        let error = read_exact_or_clear(&mut PartialThenError(false), &mut buffer).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(buffer, [0; 8]);
    }

    struct FailAfter(usize);

    impl Write for FailAfter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0 == 0 {
                return Err(io::Error::other("injected write failure"));
            }
            let written = self.0.min(bytes.len());
            self.0 -= written;
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn sanitized_key_encoding_is_cleared_for_prefix_key_and_newline_write_failures() {
        for bytes_before_failure in [5, 20, 77] {
            let mut encoded = [b'7'; 64];
            let error = write_sanitized_bytes(&mut FailAfter(bytes_before_failure), &mut encoded)
                .unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::Other);
            assert_eq!(
                encoded, [0; 64],
                "failure after {bytes_before_failure} bytes"
            );
        }
    }

    #[test]
    fn both_recognized_aliases_produce_the_same_key() {
        let one = read_header_key(&mut Cursor::new(b"header_key = 11".to_vec()), 15).unwrap_err();
        assert_eq!(one, InspectionErrorCode::KeyFileMalformed);

        let value = "42".repeat(32);
        let first = format!("header_key = {value}\n");
        let second = format!("nca_header_key = {value}\n");
        let first_key = read_header_key(
            &mut Cursor::new(first.clone().into_bytes()),
            first.len() as u64,
        )
        .expect("header_key alias");
        let second_key = read_header_key(
            &mut Cursor::new(second.clone().into_bytes()),
            second.len() as u64,
        )
        .expect("nca_header_key alias");
        assert_eq!(first_key.as_bytes(), second_key.as_bytes());
        let text = format!("header_key = {value}\nnca_header_key = {value}\n");
        let key = read_header_key(
            &mut Cursor::new(text.clone().into_bytes()),
            text.len() as u64,
        )
        .expect("matching aliases");
        assert_eq!(key.as_bytes(), &[0x42; 32]);
        assert!(!format!("{key:?}").contains(&value));
        assert!(second.contains(&value));
    }

    #[test]
    fn header_key_alias_accepts_an_all_zero_key() {
        let text = format!("header_key = {}\n", "00".repeat(32));
        let key = read_header_key(
            &mut Cursor::new(text.clone().into_bytes()),
            text.len() as u64,
        )
        .expect("all-zero header_key alias");

        assert_eq!(key.as_bytes(), &[0; 32]);
        assert_eq!(format!("{key:?}"), "HeaderKey([REDACTED])");
    }

    #[test]
    fn nca_header_key_alias_accepts_an_all_zero_key() {
        let text = format!("nca_header_key = {}\n", "00".repeat(32));
        let key = read_header_key(
            &mut Cursor::new(text.clone().into_bytes()),
            text.len() as u64,
        )
        .expect("all-zero nca_header_key alias");

        assert_eq!(key.as_bytes(), &[0; 32]);
        assert_eq!(format!("{key:?}"), "HeaderKey([REDACTED])");
    }

    #[test]
    fn matching_all_zero_alias_definitions_follow_the_duplicate_policy() {
        let text = format!(
            "header_key = {}\nnca_header_key = {}\n",
            "00".repeat(32),
            "00".repeat(32)
        );
        let key = read_header_key(
            &mut Cursor::new(text.clone().into_bytes()),
            text.len() as u64,
        )
        .expect("matching all-zero aliases");

        assert_eq!(key.as_bytes(), &[0; 32]);
        assert_eq!(format!("{key:?}"), "HeaderKey([REDACTED])");
    }

    #[test]
    fn zero_and_nonzero_alias_definitions_conflict_in_either_order() {
        let zero = "00".repeat(32);
        let nonzero = "01".repeat(32);
        for text in [
            format!("header_key = {zero}\nnca_header_key = {nonzero}\n"),
            format!("nca_header_key = {nonzero}\nheader_key = {zero}\n"),
        ] {
            assert_eq!(
                read_header_key(
                    &mut Cursor::new(text.clone().into_bytes()),
                    text.len() as u64,
                )
                .unwrap_err(),
                InspectionErrorCode::KeyFileMalformed
            );
        }
    }

    #[test]
    fn conflicting_aliases_fail_without_repeating_the_values() {
        let one = "11".repeat(32);
        let two = "22".repeat(32);
        let text = format!("header_key = {one}\nnca_header_key = {two}\n");
        let error = read_header_key(
            &mut Cursor::new(text.clone().into_bytes()),
            text.len() as u64,
        )
        .unwrap_err();
        assert_eq!(error, InspectionErrorCode::KeyFileMalformed);
        let message = crate::inspection::InspectionError::new(error).to_string();
        assert!(!message.contains(&one));
        assert!(!message.contains(&two));
    }

    #[test]
    fn unrelated_keys_comments_and_case_are_accepted() {
        let value = "AbCdEf".repeat(10) + "AbCd";
        let text = format!(
            "# generated by a user\nprod_key = {}\r\n nca_header_key = {value} \n",
            "00".repeat(16)
        );
        let key = read_header_key(
            &mut Cursor::new(text.clone().into_bytes()),
            text.len() as u64,
        )
        .expect("valid key");
        assert_eq!(key.as_bytes()[0], 0xab);
    }

    #[test]
    fn absent_or_malformed_aliases_are_typed_prerequisites() {
        for (bytes, expected) in [
            (
                b"prod_key = abcd\n".as_slice(),
                InspectionErrorCode::MissingHeaderKey,
            ),
            (
                b"header_key = abcd\n".as_slice(),
                InspectionErrorCode::KeyFileMalformed,
            ),
            (
                b"header_key\n".as_slice(),
                InspectionErrorCode::KeyFileMalformed,
            ),
        ] {
            assert_eq!(
                read_header_key(&mut Cursor::new(bytes.to_vec()), bytes.len() as u64).unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn key_file_size_is_bounded() {
        assert_eq!(
            read_header_key(&mut Cursor::new(Vec::new()), MAX_KEY_FILE_BYTES + 1).unwrap_err(),
            InspectionErrorCode::KeyFileLimitExceeded
        );
    }

    #[test]
    fn sanitized_file_contains_only_the_header_key() {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("nscb-key-test-{}-{id}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("nstool.keys");
        let text = format!(
            "header_key = {}\nprod_key = {}\n",
            "42".repeat(32),
            "11".repeat(16)
        );
        let key = read_header_key(
            &mut Cursor::new(text.clone().into_bytes()),
            text.len() as u64,
        )
        .unwrap();
        write_sanitized(&path, &key).unwrap();
        let written = fs::read_to_string(&path).unwrap();
        assert_eq!(written, format!("header_key = {}\n", "42".repeat(32)));
        assert!(!written.contains(&"11".repeat(16)));
        drop(key);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn sanitized_all_zero_keyset_is_exact_and_debug_output_is_redacted() {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("nscb-zero-key-test-{}-{id}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("nstool.keys");
        let text = format!("nca_header_key = {}\n", "00".repeat(32));
        let key = read_header_key(
            &mut Cursor::new(text.clone().into_bytes()),
            text.len() as u64,
        )
        .expect("all-zero key");

        assert_eq!(format!("{key:?}"), "HeaderKey([REDACTED])");
        write_sanitized(&path, &key).unwrap();

        let written = fs::read(&path).unwrap();
        assert_eq!(
            written,
            format!("header_key = {}\n", "00".repeat(32)).as_bytes()
        );
        assert_eq!(written.iter().filter(|byte| **byte == b'0').count(), 64);
        let _ = fs::remove_dir_all(directory);
    }
}
