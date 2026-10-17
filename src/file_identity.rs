//! Stable filesystem identity and metadata snapshots.
//!
//! Split segments must be unique physical regular files. A path alone is not a
//! stable identity because it can be replaced between inspection and use, so
//! callers compare the identity reported by an opened handle with the identity
//! of the path before and after reading. Platforms that cannot report a stable
//! file identity fail Split qualification closed.

use std::fs::{File, Metadata};
use std::path::Path;
use std::time::SystemTime;

/// A stable file identity reported by the host filesystem.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct FileIdentity {
    first: u64,
    second: u64,
}

/// Metadata that must remain stable while a file is inspected or read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FileSnapshot {
    /// File byte length.
    pub(crate) len: u64,
    /// Stable filesystem identity, when the platform exposes one.
    pub(crate) identity: Option<FileIdentity>,
    /// Last modification time, when the platform reports one.
    pub(crate) modified: Option<SystemTime>,
    /// Change time in seconds on Unix, detecting metadata rewrites.
    #[cfg(unix)]
    pub(crate) change_seconds: i64,
    /// Nanosecond component of the Unix change time.
    #[cfg(unix)]
    pub(crate) change_nanoseconds: i64,
}

/// Returns the stable identity described by Unix metadata.
///
/// Windows path metadata does not expose a stable file index through a stable
/// standard-library API. Callers on Windows use handle_identity or
/// path_identity instead.
#[cfg(unix)]
pub(crate) fn file_identity(metadata: &Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    Some(FileIdentity {
        first: metadata.dev(),
        second: metadata.ino(),
    })
}

/// Returns the stable identity for an opened file handle.
#[cfg(unix)]
pub(crate) fn handle_identity(file: &File) -> Option<FileIdentity> {
    file.metadata()
        .ok()
        .and_then(|metadata| file_identity(&metadata))
}

/// Returns the stable identity for an opened Windows file handle.
#[cfg(windows)]
pub(crate) fn handle_identity(file: &File) -> Option<FileIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    // SAFETY: `BY_HANDLE_FILE_INFORMATION` is a plain-old-data Windows
    // structure for which an all-zero bit pattern is a valid initial value.
    let mut information = unsafe { std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    // SAFETY: `file` owns a valid open handle for the duration of this call,
    // and `information` is a live, properly aligned local output buffer.
    let succeeded =
        unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut information) };
    if succeeded == 0 {
        return None;
    }
    Some(FileIdentity {
        first: u64::from(information.dwVolumeSerialNumber),
        second: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn handle_identity(_file: &File) -> Option<FileIdentity> {
    None
}

/// Returns the stable identity of the directory entry at the path without
/// following a final symlink or reparse point.
#[cfg(unix)]
pub(crate) fn path_identity(path: &Path) -> Option<FileIdentity> {
    std::fs::symlink_metadata(path)
        .ok()
        .and_then(|metadata| file_identity(&metadata))
}

#[cfg(windows)]
pub(crate) fn path_identity(path: &Path) -> Option<FileIdentity> {
    use std::os::windows::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    // FILE_FLAG_OPEN_REPARSE_POINT inspects the entry itself instead of
    // following a reparse point. FILE_FLAG_BACKUP_SEMANTICS permits directories.
    options.custom_flags(0x0020_0000 | 0x0200_0000);
    let file = options.open(path).ok()?;
    handle_identity(&file)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn path_identity(_path: &Path) -> Option<FileIdentity> {
    None
}

/// Returns the stable identity reached by following the path.
///
/// This mirrors path_identity while resolving a final symlink or reparse point,
/// allowing callers to detect a link that replaced a regular entry.
#[cfg(unix)]
pub(crate) fn followed_path_identity(path: &Path) -> Option<FileIdentity> {
    std::fs::metadata(path)
        .ok()
        .and_then(|metadata| file_identity(&metadata))
}

#[cfg(windows)]
pub(crate) fn followed_path_identity(path: &Path) -> Option<FileIdentity> {
    use std::os::windows::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    // FILE_FLAG_BACKUP_SEMANTICS permits opening directories.
    options.custom_flags(0x0200_0000);
    let file = options.open(path).ok()?;
    handle_identity(&file)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn followed_path_identity(_path: &Path) -> Option<FileIdentity> {
    None
}

/// Captures the metadata compared before and after a read.
pub(crate) fn file_snapshot(metadata: &Metadata, identity: Option<FileIdentity>) -> FileSnapshot {
    FileSnapshot {
        len: metadata.len(),
        identity,
        modified: metadata.modified().ok(),
        #[cfg(unix)]
        change_seconds: {
            use std::os::unix::fs::MetadataExt;
            metadata.ctime()
        },
        #[cfg(unix)]
        change_nanoseconds: {
            use std::os::unix::fs::MetadataExt;
            metadata.ctime_nsec()
        },
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::file_identity;
    use super::{file_snapshot, path_identity};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn temp_file() -> PathBuf {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("nscb-file-identity-{}-{id}", std::process::id()));
        fs::write(&path, b"content").unwrap();
        path
    }

    #[test]
    fn reports_identity_and_length() {
        let path = temp_file();
        let metadata = fs::metadata(&path).unwrap();
        let identity = path_identity(&path);
        let snapshot = file_snapshot(&metadata, identity);
        assert_eq!(snapshot.len, 7);
        assert!(snapshot.identity.is_some());
        #[cfg(unix)]
        assert_eq!(snapshot.identity, file_identity(&metadata));
        fs::remove_file(path).unwrap();
    }
}
