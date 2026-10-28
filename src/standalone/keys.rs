//! Validation and atomic installation of complete user-selected key files.

use super::config::{atomic_replace_io, create_private_directory_io};
use super::paths;
use crate::key_file::{KeyFileParseError, MAX_KEY_FILE_BYTES, parse_header_key_bytes};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{Ordering, compiler_fence};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeySetError {
    KeyFileUnavailable,
    KeyFileLimitExceeded,
    KeyFileMalformed,
    MissingHeaderKey,
    HomeDirectoryUnavailable,
    DestinationWriteFailed,
}

impl KeySetError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::KeyFileUnavailable => "key_file_unavailable",
            Self::KeyFileLimitExceeded => "key_file_limit_exceeded",
            Self::KeyFileMalformed => "key_file_malformed",
            Self::MissingHeaderKey => "missing_header_key",
            Self::HomeDirectoryUnavailable => "home_directory_unavailable",
            Self::DestinationWriteFailed => "key_destination_write_failed",
        }
    }
}

pub(crate) fn set_complete_key_file(source: &Path) -> Result<String, KeySetError> {
    // Resolve every destination prerequisite that can fail before reading the
    // complete secret. Once bytes are read, the owner below guarantees cleanup
    // on every subsequent return and unwind.
    let destination =
        paths::conventional_key_file_path().map_err(|_| KeySetError::HomeDirectoryUnavailable)?;
    let destination_text = destination
        .to_str()
        .ok_or(KeySetError::DestinationWriteFailed)?
        .to_owned();
    let parent = destination
        .parent()
        .ok_or(KeySetError::HomeDirectoryUnavailable)?;
    let metadata = fs::symlink_metadata(source).map_err(|_| KeySetError::KeyFileUnavailable)?;
    if !metadata.file_type().is_file() {
        return Err(KeySetError::KeyFileUnavailable);
    }
    if metadata.len() > MAX_KEY_FILE_BYTES {
        return Err(KeySetError::KeyFileLimitExceeded);
    }

    let file = File::open(source).map_err(|_| KeySetError::KeyFileUnavailable)?;
    let mut bytes = SensitiveKeyFileBytes(Vec::with_capacity((MAX_KEY_FILE_BYTES + 1) as usize));
    file.take(MAX_KEY_FILE_BYTES + 1)
        .read_to_end(&mut bytes.0)
        .map_err(|_| KeySetError::KeyFileUnavailable)?;
    if bytes.len() as u64 > MAX_KEY_FILE_BYTES {
        return Err(KeySetError::KeyFileLimitExceeded);
    }
    validate_header_key(bytes.as_ref())?;
    let result = create_private_directory_io(parent)
        .and_then(|()| atomic_replace_io(&destination, bytes.as_ref()))
        .map_err(|_| KeySetError::DestinationWriteFailed);
    result.map(|()| destination_text)
}

/// Owns the complete key-file bytes after reading succeeds.
///
/// Partial copies may participate in validation and installation, so all
/// bytes must remain unchanged until validation and atomic replacement have
/// used them. Dropping the owner zeroes the entire allocation, including the
/// extra byte read to detect oversized files, before the vector is freed.
struct SensitiveKeyFileBytes(Vec<u8>);

impl SensitiveKeyFileBytes {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn clear(&mut self) {
        for byte in &mut self.0 {
            // Volatile writes prevent a release build from treating the final
            // stores as dead before the backing allocation is deallocated.
            // SAFETY: `byte` is a live, uniquely borrowed `u8` for this loop
            // iteration, and zero is a valid bit pattern for `u8`.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl AsRef<[u8]> for SensitiveKeyFileBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SensitiveKeyFileBytes {
    fn drop(&mut self) {
        self.clear();
        #[cfg(test)]
        SENSITIVE_KEY_DROP.with(|observation| {
            *observation.borrow_mut() = Some(SensitiveKeyDropObservation {
                byte_count: self.0.len(),
                all_zero: self.0.iter().all(|byte| *byte == 0),
            });
        });
    }
}

#[cfg(test)]
#[derive(Debug, Eq, PartialEq)]
struct SensitiveKeyDropObservation {
    byte_count: usize,
    all_zero: bool,
}

#[cfg(test)]
thread_local! {
    static SENSITIVE_KEY_DROP: std::cell::RefCell<Option<SensitiveKeyDropObservation>> =
        const { std::cell::RefCell::new(None) };
}

fn validate_header_key(bytes: &[u8]) -> Result<(), KeySetError> {
    parse_header_key_bytes(bytes)
        .map(|_| ())
        .map_err(|error| match error {
            KeyFileParseError::Malformed => KeySetError::KeyFileMalformed,
            KeyFileParseError::MissingHeaderKey => KeySetError::MissingHeaderKey,
        })
}

#[cfg(test)]
mod tests {
    use super::{SENSITIVE_KEY_DROP, SensitiveKeyDropObservation, SensitiveKeyFileBytes};

    #[test]
    fn sensitive_key_owner_zeroes_the_complete_buffer_on_drop() {
        let owner = SensitiveKeyFileBytes(b"header_key = secret\n".to_vec());
        let byte_count = owner.len();

        drop(owner);

        let observation = SENSITIVE_KEY_DROP.with(|slot| slot.borrow_mut().take());
        assert_eq!(
            observation,
            Some(SensitiveKeyDropObservation {
                byte_count,
                all_zero: true,
            })
        );
    }

    #[test]
    fn sensitive_key_owner_zeroes_a_read_limit_sentinel_too() {
        let owner = SensitiveKeyFileBytes(vec![b'x'; super::MAX_KEY_FILE_BYTES as usize + 1]);
        let byte_count = owner.len();

        drop(owner);

        let observation = SENSITIVE_KEY_DROP.with(|slot| slot.borrow_mut().take());
        assert_eq!(
            observation,
            Some(SensitiveKeyDropObservation {
                byte_count,
                all_zero: true,
            })
        );
    }
}
