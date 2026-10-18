//! Crash-consistent, content-addressed storage for the qualified helper.
//!
//! Every generation is immutable. Pointer files are published under new
//! sequence names, so an interrupted install or pointer publication leaves the
//! previously valid generation selectable. No pointer, object path, or
//! executable name is accepted from a production caller.
use crate::inspection::InspectionErrorCode;
use crate::provider::manifest::TargetArtifact;
use crate::sha256::Sha256Digest;
use fs2::FileExt;
#[cfg(not(unix))]
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(any(not(unix), test))]
use std::path::PathBuf;
use std::path::{Component, Path};

const PROVIDER_DIRECTORY: &str = "nstool";
const VERSION_DIRECTORY: &str = "v1.9.2";
const OBJECTS_DIRECTORY: &str = "objects";
const POINTERS_DIRECTORY: &str = "pointers";
const LOCKS_DIRECTORY: &str = ".locks";
const LOCK_FILE: &str = "provider.lock";
const MAX_POINTER_BYTES: u64 = 256;
const MAX_CACHE_DIRECTORY_ENTRIES: usize = 1024;
const MAX_POINTER_CANDIDATES: usize = 256;
const KEEP_GENERATIONS: usize = 3;
const POINTER_MAGIC: &str = "nstool 1.9.2";

#[derive(Debug)]
pub(crate) struct CachedArtifact {
    executable: File,
    executable_sha256: Sha256Digest,
    #[cfg(test)]
    sequence: u64,
}

impl CachedArtifact {
    pub(crate) fn executable_sha256(&self) -> Sha256Digest {
        self.executable_sha256
    }

    #[cfg(test)]
    pub(crate) fn sequence(&self) -> u64 {
        self.sequence
    }
}

pub(crate) fn snapshot_executable(
    artifact: &CachedArtifact,
    target: &TargetArtifact,
    destination: &Path,
) -> Result<(), InspectionErrorCode> {
    let mut source = artifact
        .executable
        .try_clone()
        .map_err(|_| InspectionErrorCode::ProviderArtifactIncomplete)?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| InspectionErrorCode::ProviderArtifactIncomplete)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o500);
    let mut output = options
        .open(destination)
        .map_err(|_| InspectionErrorCode::InternalIo)?;
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|_| InspectionErrorCode::ProviderArtifactIncomplete)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .ok_or(InspectionErrorCode::ProviderArtifactMismatch)?;
        if copied > target.executable_bytes() {
            return Err(InspectionErrorCode::ProviderArtifactMismatch);
        }
        hasher.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .map_err(|_| InspectionErrorCode::InternalIo)?;
    }
    output
        .sync_all()
        .map_err(|_| InspectionErrorCode::InternalIo)?;
    if copied != target.executable_bytes()
        || Sha256Digest::from_bytes(hasher.finalize().into()) != target.executable_sha256()
        || artifact.executable_sha256() != target.executable_sha256()
    {
        return Err(InspectionErrorCode::ProviderArtifactMismatch);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CacheProblem {
    Missing,
    ArtifactMismatch,
    ArtifactIncomplete,
    ArchiveInvalid,
}

impl CacheProblem {
    pub(crate) const fn code(self) -> InspectionErrorCode {
        match self {
            Self::Missing => InspectionErrorCode::ProviderCacheMissing,
            Self::ArtifactMismatch => InspectionErrorCode::ProviderArtifactMismatch,
            Self::ArtifactIncomplete => InspectionErrorCode::ProviderArtifactIncomplete,
            Self::ArchiveInvalid => InspectionErrorCode::ProviderArchiveInvalid,
        }
    }
}

#[derive(Debug)]
pub(crate) enum CacheLookup {
    Ready(CachedArtifact),
    Missing(CacheProblem),
}

#[derive(Clone, Debug)]
struct Pointer {
    sequence: u64,
    archive_sha256: Sha256Digest,
    executable_sha256: Sha256Digest,
}

#[cfg(not(unix))]
pub(crate) fn lookup(
    cache_dir: &Path,
    target: &TargetArtifact,
) -> Result<CacheLookup, InspectionErrorCode> {
    let root = provider_root(cache_dir)?;
    if !root.exists() {
        return Ok(CacheLookup::Missing(CacheProblem::Missing));
    }
    validate_directory_chain(cache_dir, &root)?;

    let pointers = root.join(POINTERS_DIRECTORY);
    if !pointers.exists() {
        return Ok(CacheLookup::Missing(CacheProblem::Missing));
    }
    validate_directory_chain(&root, &pointers)?;

    let entries = bounded_directory_entries(
        &pointers,
        InspectionErrorCode::InternalIo,
        InspectionErrorCode::ProviderArtifactIncomplete,
    )?;
    let mut parsed = Vec::new();
    parsed
        .try_reserve(MAX_POINTER_CANDIDATES)
        .map_err(|_| InspectionErrorCode::AllocationFailed)?;
    let mut problem = CacheProblem::Missing;
    for entry in entries {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        let Some(sequence) = parse_sequence(name) else {
            continue;
        };
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|_| InspectionErrorCode::InternalIo)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            problem = worst(problem, CacheProblem::ArtifactIncomplete);
            continue;
        }
        match read_pointer(&entry.path(), sequence) {
            Ok(pointer) => {
                if parsed.len() == MAX_POINTER_CANDIDATES {
                    return Err(InspectionErrorCode::ProviderArtifactIncomplete);
                }
                parsed.push(pointer);
            }
            Err(CacheProblem::Missing) => {
                problem = worst(problem, CacheProblem::ArtifactIncomplete)
            }
            Err(other) => problem = worst(problem, other),
        }
    }
    parsed.sort_unstable_by_key(|left| std::cmp::Reverse(left.sequence));
    if parsed.is_empty() {
        return Ok(CacheLookup::Missing(problem));
    }

    for pointer in parsed {
        if pointer.archive_sha256 != target.archive_sha256()
            || pointer.executable_sha256 != target.executable_sha256()
        {
            problem = worst(problem, CacheProblem::ArtifactMismatch);
            continue;
        }
        let object = root
            .join(OBJECTS_DIRECTORY)
            .join(pointer.archive_sha256.to_hex());
        match validate_object(&root, &object, target) {
            Ok(executable) => {
                return Ok(CacheLookup::Ready(CachedArtifact {
                    executable,
                    executable_sha256: pointer.executable_sha256,
                    #[cfg(test)]
                    sequence: pointer.sequence,
                }));
            }
            Err(object_problem) => problem = worst(problem, object_problem),
        }
    }
    Ok(CacheLookup::Missing(problem))
}

#[cfg(not(unix))]
pub(crate) fn install_archive(
    cache_dir: &Path,
    target: &TargetArtifact,
    archive: &[u8],
) -> Result<CachedArtifact, InspectionErrorCode> {
    let root = provider_root(cache_dir)?;
    if let CacheLookup::Ready(artifact) = lookup(cache_dir, target)? {
        return Ok(artifact);
    }
    if archive.len() as u64 != target.archive_bytes()
        || Sha256Digest::digest(archive) != target.archive_sha256()
    {
        return Err(InspectionErrorCode::ProviderArchiveInvalid);
    }
    fs::create_dir_all(cache_dir).map_err(|_| InspectionErrorCode::InvalidCacheDirectory)?;
    let metadata =
        fs::symlink_metadata(cache_dir).map_err(|_| InspectionErrorCode::InvalidCacheDirectory)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(InspectionErrorCode::InvalidCacheDirectory);
    }
    ensure_provider_directories(&root)?;
    validate_directory_chain(cache_dir, &root)?;
    let _lock = acquire_lock(&root)?;
    if let CacheLookup::Ready(artifact) = lookup(cache_dir, target)? {
        return Ok(artifact);
    }
    let executable_bytes = extract_executable(archive, target)?;
    let _object = install_object(&root, target, &executable_bytes)?;
    drop(executable_bytes);

    let sequence = next_sequence(&root.join(POINTERS_DIRECTORY))?;
    publish_pointer(&root.join(POINTERS_DIRECTORY), sequence, target)?;
    cleanup(&root, target)?;
    match lookup(cache_dir, target)? {
        CacheLookup::Ready(artifact) => Ok(artifact),
        CacheLookup::Missing(problem) => Err(problem.code()),
    }
}

#[cfg(unix)]
pub(crate) fn lookup(
    cache_dir: &Path,
    target: &TargetArtifact,
) -> Result<CacheLookup, InspectionErrorCode> {
    unix_cache::lookup(cache_dir, target)
}

#[cfg(unix)]
pub(crate) fn install_archive(
    cache_dir: &Path,
    target: &TargetArtifact,
    archive: &[u8],
) -> Result<CachedArtifact, InspectionErrorCode> {
    unix_cache::install_archive(cache_dir, target, archive)
}

fn extract_executable(
    archive: &[u8],
    target: &TargetArtifact,
) -> Result<Vec<u8>, InspectionErrorCode> {
    let cursor = std::io::Cursor::new(archive);
    let mut zip =
        zip::ZipArchive::new(cursor).map_err(|_| InspectionErrorCode::ProviderArchiveInvalid)?;
    if zip.len() != 1 {
        return Err(InspectionErrorCode::ProviderArchiveInvalid);
    }
    let member_name = {
        let member = zip
            .by_index(0)
            .map_err(|_| InspectionErrorCode::ProviderArchiveInvalid)?;
        let unix_mode = member.unix_mode();
        let file_type = unix_mode.map(|mode| mode & 0o170000);
        if member.is_dir()
            || member.name() != target.executable()
            || file_type.is_some_and(|kind| kind != 0 && kind != 0o100000)
        {
            return Err(InspectionErrorCode::ProviderArchiveInvalid);
        }
        member.name().to_owned()
    };
    let mut member = zip
        .by_name(&member_name)
        .map_err(|_| InspectionErrorCode::ProviderArchiveInvalid)?;
    if member.size() != target.executable_bytes() {
        return Err(InspectionErrorCode::ProviderArchiveInvalid);
    }
    let size =
        usize::try_from(member.size()).map_err(|_| InspectionErrorCode::ProviderArchiveInvalid)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| InspectionErrorCode::AllocationFailed)?;
    member
        .read_to_end(&mut bytes)
        .map_err(|_| InspectionErrorCode::ProviderArchiveInvalid)?;
    if bytes.len() != size || Sha256Digest::digest(&bytes) != target.executable_sha256() {
        bytes.fill(0);
        return Err(InspectionErrorCode::ProviderArchiveInvalid);
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn install_object(
    root: &Path,
    target: &TargetArtifact,
    executable_bytes: &[u8],
) -> Result<PathBuf, InspectionErrorCode> {
    let objects = root.join(OBJECTS_DIRECTORY);
    let final_object = objects.join(target.archive_sha256().to_hex());
    if final_object.exists() {
        if validate_object(root, &final_object, target).is_ok() {
            return Ok(final_object);
        }
        let quarantine = objects.join(format!(
            ".tmp-invalid-{}-{}",
            target.archive_sha256().to_hex(),
            std::process::id()
        ));
        fs::rename(&final_object, &quarantine)
            .map_err(|_| InspectionErrorCode::ProviderArtifactMismatch)?;
        fs::remove_dir_all(&quarantine).map_err(|_| InspectionErrorCode::CacheCleanupFailed)?;
        sync_directory(&objects)?;
    }

    let temporary = tempfile::Builder::new()
        .prefix(".tmp-object-")
        .tempdir_in(&objects)
        .map_err(|_| InspectionErrorCode::InternalIo)?;
    let executable = temporary.path().join(target.executable());
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o500);
    let mut file = options
        .open(&executable)
        .map_err(|_| InspectionErrorCode::InternalIo)?;
    file.write_all(executable_bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| InspectionErrorCode::InternalIo)?;
    sync_directory(temporary.path())?;
    let temporary_path = temporary.keep();
    match fs::rename(&temporary_path, &final_object) {
        Ok(()) => {
            sync_directory(&objects)?;
            Ok(final_object)
        }
        Err(_) => {
            let _ = fs::remove_dir_all(&temporary_path);
            Err(InspectionErrorCode::InternalIo)
        }
    }
}

#[cfg(not(unix))]
fn publish_pointer(
    pointers: &Path,
    sequence: u64,
    target: &TargetArtifact,
) -> Result<(), InspectionErrorCode> {
    let destination = pointers.join(format!("{sequence:020}"));
    if destination.exists() {
        return Err(InspectionErrorCode::ProviderArtifactIncomplete);
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".tmp-pointer-")
        .tempfile_in(pointers)
        .map_err(|_| InspectionErrorCode::InternalIo)?;
    let contents = format!(
        "{POINTER_MAGIC}\n{}\n{}\n",
        target.archive_sha256(),
        target.executable_sha256()
    );
    temporary
        .write_all(contents.as_bytes())
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|_| InspectionErrorCode::InternalIo)?;
    temporary
        .into_temp_path()
        .persist(&destination)
        .map_err(|_| InspectionErrorCode::InternalIo)?;
    sync_directory(pointers)
}

#[cfg(not(unix))]
fn cleanup(root: &Path, target: &TargetArtifact) -> Result<(), InspectionErrorCode> {
    let pointers = root.join(POINTERS_DIRECTORY);
    let mut sequences = Vec::new();
    sequences
        .try_reserve(MAX_CACHE_DIRECTORY_ENTRIES)
        .map_err(|_| InspectionErrorCode::AllocationFailed)?;
    for entry in bounded_directory_entries(
        &pointers,
        InspectionErrorCode::CacheCleanupFailed,
        InspectionErrorCode::CacheCleanupFailed,
    )? {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(sequence) = parse_sequence(name) {
            sequences.push(sequence);
        } else if name.starts_with(".tmp-") {
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|_| InspectionErrorCode::CacheCleanupFailed)?;
            if metadata.file_type().is_dir() {
                fs::remove_dir_all(entry.path())
                    .map_err(|_| InspectionErrorCode::CacheCleanupFailed)?;
            } else {
                fs::remove_file(entry.path())
                    .map_err(|_| InspectionErrorCode::CacheCleanupFailed)?;
            }
        }
    }
    sequences.sort_unstable_by(|left, right| right.cmp(left));
    sequences.dedup();
    for sequence in sequences.iter().skip(KEEP_GENERATIONS) {
        let path = pointers.join(format!("{sequence:020}"));
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| InspectionErrorCode::CacheCleanupFailed)?;
        if metadata.file_type().is_symlink() {
            return Err(InspectionErrorCode::CacheCleanupFailed);
        }
        fs::remove_file(path).map_err(|_| InspectionErrorCode::CacheCleanupFailed)?;
    }

    let mut referenced = Vec::new();
    referenced
        .try_reserve(KEEP_GENERATIONS + 1)
        .map_err(|_| InspectionErrorCode::AllocationFailed)?;
    for sequence in sequences.iter().take(KEEP_GENERATIONS) {
        let path = pointers.join(format!("{sequence:020}"));
        if let Ok(pointer) = read_pointer(&path, *sequence) {
            referenced.push(pointer.archive_sha256);
        }
    }
    if !referenced.contains(&target.archive_sha256()) {
        referenced.push(target.archive_sha256());
    }

    let objects = root.join(OBJECTS_DIRECTORY);
    for entry in bounded_directory_entries(
        &objects,
        InspectionErrorCode::CacheCleanupFailed,
        InspectionErrorCode::CacheCleanupFailed,
    )? {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| InspectionErrorCode::CacheCleanupFailed)?;
        if name.starts_with(".tmp-") {
            if metadata.file_type().is_dir() {
                fs::remove_dir_all(entry.path())
                    .map_err(|_| InspectionErrorCode::CacheCleanupFailed)?;
            }
            continue;
        }
        let Ok(digest) = Sha256Digest::parse_hex(name) else {
            continue;
        };
        if referenced.contains(&digest) {
            continue;
        }
        if metadata.file_type().is_symlink() {
            return Err(InspectionErrorCode::CacheCleanupFailed);
        }
        if metadata.file_type().is_dir() {
            fs::remove_dir_all(entry.path())
                .map_err(|_| InspectionErrorCode::CacheCleanupFailed)?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_object(
    root: &Path,
    object: &Path,
    target: &TargetArtifact,
) -> Result<File, CacheProblem> {
    validate_directory_chain(root, object).map_err(|_| CacheProblem::ArtifactIncomplete)?;
    let executable = object.join(target.executable());
    let relative = executable
        .strip_prefix(root)
        .map_err(|_| CacheProblem::ArtifactIncomplete)?;
    let mut file =
        open_beneath_nofollow(root, relative).map_err(|_| CacheProblem::ArtifactIncomplete)?;
    let metadata = file
        .metadata()
        .map_err(|_| CacheProblem::ArtifactIncomplete)?;
    if !metadata.is_file() {
        return Err(CacheProblem::ArtifactIncomplete);
    }
    if metadata.len() != target.executable_bytes() {
        return Err(CacheProblem::ArtifactMismatch);
    }
    let digest = digest_reader(&mut file, target.executable_bytes())
        .map_err(|_| CacheProblem::ArtifactIncomplete)?;
    if digest != target.executable_sha256() {
        return Err(CacheProblem::ArtifactMismatch);
    }
    Ok(file)
}

fn digest_reader(
    reader: &mut impl Read,
    expected: u64,
) -> Result<Sha256Digest, InspectionErrorCode> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| InspectionErrorCode::InternalIo)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(InspectionErrorCode::ProviderArtifactMismatch)?;
        if total > expected {
            return Err(InspectionErrorCode::ProviderArtifactMismatch);
        }
        hasher.update(&buffer[..read]);
    }
    if total != expected {
        return Err(InspectionErrorCode::ProviderArtifactMismatch);
    }
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

#[cfg(not(unix))]
fn read_pointer(path: &Path, sequence: u64) -> Result<Pointer, CacheProblem> {
    let metadata = fs::symlink_metadata(path).map_err(|_| CacheProblem::ArtifactIncomplete)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.len() > MAX_POINTER_BYTES
    {
        return Err(CacheProblem::ArtifactIncomplete);
    }
    let file = open_nofollow(path).map_err(|_| CacheProblem::ArtifactIncomplete)?;
    let mut contents = String::new();
    file.take(MAX_POINTER_BYTES + 1)
        .read_to_string(&mut contents)
        .map_err(|_| CacheProblem::ArtifactIncomplete)?;
    if contents.len() as u64 > MAX_POINTER_BYTES {
        return Err(CacheProblem::ArtifactIncomplete);
    }
    let mut lines = contents.lines();
    if lines.next() != Some(POINTER_MAGIC) {
        return Err(CacheProblem::ArtifactIncomplete);
    }
    let archive = lines
        .next()
        .and_then(|value| Sha256Digest::parse_hex(value).ok())
        .ok_or(CacheProblem::ArtifactIncomplete)?;
    let executable = lines
        .next()
        .and_then(|value| Sha256Digest::parse_hex(value).ok())
        .ok_or(CacheProblem::ArtifactIncomplete)?;
    if lines.next().is_some() {
        return Err(CacheProblem::ArtifactIncomplete);
    }
    Ok(Pointer {
        sequence,
        archive_sha256: archive,
        executable_sha256: executable,
    })
}

#[cfg(not(unix))]
fn provider_root(cache_dir: &Path) -> Result<PathBuf, InspectionErrorCode> {
    if !cache_dir.is_absolute()
        || cache_dir.as_os_str().is_empty()
        || cache_dir
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(InspectionErrorCode::InvalidCacheDirectory);
    }
    match fs::symlink_metadata(cache_dir) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() => {
            return Err(InspectionErrorCode::InvalidCacheDirectory);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(InspectionErrorCode::InvalidCacheDirectory),
    }
    Ok(cache_dir.join(PROVIDER_DIRECTORY).join(VERSION_DIRECTORY))
}

#[cfg(not(unix))]
fn ensure_provider_directories(root: &Path) -> Result<(), InspectionErrorCode> {
    let provider = root
        .parent()
        .ok_or(InspectionErrorCode::InvalidCacheDirectory)?;
    ensure_directory(provider)?;
    ensure_directory(root)?;
    ensure_directory(&root.join(OBJECTS_DIRECTORY))?;
    ensure_directory(&root.join(POINTERS_DIRECTORY))?;
    ensure_directory(&root.join(LOCKS_DIRECTORY))?;
    Ok(())
}

#[cfg(not(unix))]
fn ensure_directory(path: &Path) -> Result<(), InspectionErrorCode> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(InspectionErrorCode::InvalidCacheDirectory);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|_| InspectionErrorCode::InvalidCacheDirectory)?;
            let metadata = fs::symlink_metadata(path)
                .map_err(|_| InspectionErrorCode::InvalidCacheDirectory)?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(InspectionErrorCode::InvalidCacheDirectory);
            }
        }
        Err(_) => return Err(InspectionErrorCode::InvalidCacheDirectory),
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_directory_chain(root: &Path, path: &Path) -> Result<(), InspectionErrorCode> {
    let metadata = fs::symlink_metadata(path).map_err(|_| InspectionErrorCode::InternalIo)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(InspectionErrorCode::InvalidCacheDirectory);
    }
    let relative = path
        .strip_prefix(root)
        .map_err(|_| InspectionErrorCode::InvalidCacheDirectory)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| InspectionErrorCode::InternalIo)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(InspectionErrorCode::InvalidCacheDirectory);
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn acquire_lock(root: &Path) -> Result<CacheLock, InspectionErrorCode> {
    ensure_provider_directories(root)?;
    let path = root.join(LOCKS_DIRECTORY).join(LOCK_FILE);
    let metadata = fs::symlink_metadata(&path);
    if metadata.is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(InspectionErrorCode::CacheLockFailed);
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    #[cfg(windows)]
    options.custom_flags(0x0020_0000);
    let file = options
        .open(path)
        .map_err(|_| InspectionErrorCode::CacheLockFailed)?;
    let metadata = file
        .metadata()
        .map_err(|_| InspectionErrorCode::CacheLockFailed)?;
    if !metadata.file_type().is_file() {
        return Err(InspectionErrorCode::CacheLockFailed);
    }
    match file.try_lock_exclusive() {
        Ok(()) => Ok(CacheLock { file }),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            Err(InspectionErrorCode::ProviderCacheBusy)
        }
        Err(_) => Err(InspectionErrorCode::CacheLockFailed),
    }
}

#[cfg(not(unix))]
struct CacheLock {
    file: File,
}

#[cfg(not(unix))]
impl Drop for CacheLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[cfg(not(unix))]
fn next_sequence(pointers: &Path) -> Result<u64, InspectionErrorCode> {
    let mut maximum = 0;
    for entry in bounded_directory_entries(
        pointers,
        InspectionErrorCode::InternalIo,
        InspectionErrorCode::ProviderArtifactIncomplete,
    )? {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Some(sequence) = parse_sequence(&name) {
            maximum = maximum.max(sequence);
        }
    }
    maximum
        .checked_add(1)
        .ok_or(InspectionErrorCode::ProviderArtifactIncomplete)
}

#[cfg(not(unix))]
fn bounded_directory_entries(
    path: &Path,
    read_error: InspectionErrorCode,
    limit_error: InspectionErrorCode,
) -> Result<Vec<fs::DirEntry>, InspectionErrorCode> {
    let entries = fs::read_dir(path).map_err(|_| read_error)?;
    let mut retained = Vec::new();
    retained
        .try_reserve(MAX_CACHE_DIRECTORY_ENTRIES)
        .map_err(|_| InspectionErrorCode::AllocationFailed)?;
    for entry in entries {
        let entry = entry.map_err(|_| read_error)?;
        if retained.len() == MAX_CACHE_DIRECTORY_ENTRIES {
            return Err(limit_error);
        }
        retained.push(entry);
    }
    Ok(retained)
}

fn parse_sequence(name: &str) -> Option<u64> {
    if name.len() != 20 || !name.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let sequence = name.parse::<u64>().ok()?;
    (sequence != 0).then_some(sequence)
}

fn worst(left: CacheProblem, right: CacheProblem) -> CacheProblem {
    use CacheProblem::*;
    match (left, right) {
        (ArtifactMismatch, _) | (_, ArtifactMismatch) => ArtifactMismatch,
        (ArchiveInvalid, _) | (_, ArchiveInvalid) => ArchiveInvalid,
        (ArtifactIncomplete, _) | (_, ArtifactIncomplete) => ArtifactIncomplete,
        _ => Missing,
    }
}

/// Opens cache entries through directory descriptors rooted at the filesystem
/// root. Holding each descriptor keeps the verified ancestry fixed while
/// lookup, installation, publication, and cleanup operate on child names.
#[cfg(unix)]
mod unix_cache {
    use super::*;
    use std::ffi::{CStr, CString, OsStr, OsString};
    use std::io::{self, ErrorKind};
    use std::mem::MaybeUninit;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_NAME: AtomicU64 = AtomicU64::new(1);

    pub(super) struct CacheDirectories {
        pub(super) root: File,
        pub(super) pointers: Option<File>,
        pub(super) objects: Option<File>,
        pub(super) locks: Option<File>,
    }

    pub(super) fn lookup(
        cache_dir: &Path,
        target: &TargetArtifact,
    ) -> Result<CacheLookup, InspectionErrorCode> {
        let Some(directories) = open_cache_directories(cache_dir, false)? else {
            return Ok(CacheLookup::Missing(CacheProblem::Missing));
        };
        lookup_in_directories(&directories, target)
    }

    pub(super) fn install_archive(
        cache_dir: &Path,
        target: &TargetArtifact,
        archive: &[u8],
    ) -> Result<CachedArtifact, InspectionErrorCode> {
        let mut directories = open_cache_directories(cache_dir, false)?;
        if let Some(directories) = directories.as_ref()
            && let CacheLookup::Ready(artifact) = lookup_in_directories(directories, target)?
        {
            return Ok(artifact);
        }
        if archive.len() as u64 != target.archive_bytes()
            || Sha256Digest::digest(archive) != target.archive_sha256()
        {
            return Err(InspectionErrorCode::ProviderArchiveInvalid);
        }

        let mut directories = match directories.take() {
            Some(mut directories) => {
                ensure_child_directories(&mut directories)?;
                directories
            }
            None => open_cache_directories(cache_dir, true)?
                .ok_or(InspectionErrorCode::InvalidCacheDirectory)?,
        };
        ensure_child_directories(&mut directories)?;
        install_in_directories(&directories, target, archive)
    }

    pub(super) fn open_cache_directories(
        cache_dir: &Path,
        create: bool,
    ) -> Result<Option<CacheDirectories>, InspectionErrorCode> {
        if !cache_dir.is_absolute()
            || cache_dir.as_os_str().is_empty()
            || cache_dir
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(InspectionErrorCode::InvalidCacheDirectory);
        }
        let Some(cache) = open_absolute_directory(cache_dir, create)? else {
            return Ok(None);
        };
        let Some(provider) =
            open_or_create_directory_at(&cache, OsStr::new(PROVIDER_DIRECTORY), create)
                .map_err(|_| InspectionErrorCode::InvalidCacheDirectory)?
        else {
            return Ok(None);
        };
        let Some(root) =
            open_or_create_directory_at(&provider, OsStr::new(VERSION_DIRECTORY), create)
                .map_err(|_| InspectionErrorCode::InvalidCacheDirectory)?
        else {
            return Ok(None);
        };
        let pointers = open_or_create_directory_at(&root, OsStr::new(POINTERS_DIRECTORY), create)
            .map_err(|_| InspectionErrorCode::InvalidCacheDirectory)?;
        let objects = open_lookup_directory_at(&root, OsStr::new(OBJECTS_DIRECTORY), create)
            .map_err(|_| InspectionErrorCode::InvalidCacheDirectory)?;
        let locks = open_lookup_directory_at(&root, OsStr::new(LOCKS_DIRECTORY), create)
            .map_err(|_| InspectionErrorCode::InvalidCacheDirectory)?;
        Ok(Some(CacheDirectories {
            root,
            pointers,
            objects,
            locks,
        }))
    }

    fn ensure_child_directories(
        directories: &mut CacheDirectories,
    ) -> Result<(), InspectionErrorCode> {
        directories.pointers = Some(
            open_or_create_directory_at(&directories.root, OsStr::new(POINTERS_DIRECTORY), true)
                .map_err(|_| InspectionErrorCode::InvalidCacheDirectory)?
                .ok_or(InspectionErrorCode::InvalidCacheDirectory)?,
        );
        directories.objects = Some(
            open_or_create_directory_at(&directories.root, OsStr::new(OBJECTS_DIRECTORY), true)
                .map_err(|_| InspectionErrorCode::InvalidCacheDirectory)?
                .ok_or(InspectionErrorCode::InvalidCacheDirectory)?,
        );
        directories.locks = Some(
            open_or_create_directory_at(&directories.root, OsStr::new(LOCKS_DIRECTORY), true)
                .map_err(|_| InspectionErrorCode::InvalidCacheDirectory)?
                .ok_or(InspectionErrorCode::InvalidCacheDirectory)?,
        );
        Ok(())
    }

    fn open_absolute_directory(
        path: &Path,
        create: bool,
    ) -> Result<Option<File>, InspectionErrorCode> {
        let mut current =
            open_filesystem_root().map_err(|_| InspectionErrorCode::InvalidCacheDirectory)?;
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => {
                    let Some(next) = open_or_create_directory_at(&current, name, create)
                        .map_err(|_| InspectionErrorCode::InvalidCacheDirectory)?
                    else {
                        return Ok(None);
                    };
                    current = next;
                }
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(InspectionErrorCode::InvalidCacheDirectory);
                }
            }
        }
        Ok(Some(current))
    }

    fn open_filesystem_root() -> io::Result<File> {
        let path = b"/\0";
        // SAFETY: `path` is a NUL-terminated absolute path and the resulting
        // descriptor is immediately transferred to an owning `File`.
        let descriptor = unsafe {
            libc::open(
                path.as_ptr().cast(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        file_from_descriptor(descriptor)
    }

    fn open_or_create_directory_at(
        parent: &File,
        name: &OsStr,
        create: bool,
    ) -> io::Result<Option<File>> {
        match open_directory_at(parent, name) {
            Ok(directory) => Ok(Some(directory)),
            Err(error) if error.kind() == ErrorKind::NotFound && create => {
                let name = c_name(name)?;
                // SAFETY: `parent` is an open directory and `name` is one
                // NUL-terminated child name, never a slash-separated path.
                let result = unsafe {
                    libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700 as libc::mode_t)
                };
                if result == 0 {
                    parent.sync_all()?;
                } else {
                    let error = io::Error::last_os_error();
                    if error.kind() != ErrorKind::AlreadyExists {
                        return Err(error);
                    }
                }
                open_directory_at(parent, OsStr::from_bytes(name.as_bytes())).map(Some)
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn open_lookup_directory_at(
        parent: &File,
        name: &OsStr,
        create: bool,
    ) -> io::Result<Option<File>> {
        match open_or_create_directory_at(parent, name, create) {
            Err(error)
                if !create
                    && matches!(
                        error.raw_os_error(),
                        Some(libc::ELOOP) | Some(libc::ENOTDIR)
                    ) =>
            {
                // A symlink or non-directory child cannot provide an object
                // or lock directory. Lookup treats that state as unavailable;
                // installation retries with strict directory validation.
                Ok(None)
            }
            result => result,
        }
    }

    fn open_directory_at(parent: &File, name: &OsStr) -> io::Result<File> {
        open_at(
            parent,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
    }

    fn open_at(
        parent: &File,
        name: &OsStr,
        flags: libc::c_int,
        mode: libc::mode_t,
    ) -> io::Result<File> {
        let name = c_name(name)?;
        // SAFETY: `parent` is an open directory; `name` is a single
        // NUL-terminated component; and a successful descriptor is owned by
        // the `File` returned below.
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                flags,
                mode as libc::c_uint,
            )
        };
        file_from_descriptor(descriptor)
    }

    fn file_from_descriptor(descriptor: libc::c_int) -> io::Result<File> {
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the caller transfers ownership of a successful descriptor.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }

    fn c_name(name: &OsStr) -> io::Result<CString> {
        CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "NUL in cache name"))
    }

    pub(super) fn lookup_in_directories(
        directories: &CacheDirectories,
        target: &TargetArtifact,
    ) -> Result<CacheLookup, InspectionErrorCode> {
        let Some(pointers) = directories.pointers.as_ref() else {
            return Ok(CacheLookup::Missing(CacheProblem::Missing));
        };
        let entries = bounded_directory_names(
            pointers,
            InspectionErrorCode::InternalIo,
            InspectionErrorCode::ProviderArtifactIncomplete,
        )?;
        let mut parsed = Vec::new();
        parsed
            .try_reserve(MAX_POINTER_CANDIDATES)
            .map_err(|_| InspectionErrorCode::AllocationFailed)?;
        let mut problem = CacheProblem::Missing;
        for name in entries {
            let Some(name_string) = name.to_str() else {
                continue;
            };
            if name_string.starts_with('.') {
                continue;
            }
            let Some(sequence) = parse_sequence(name_string) else {
                continue;
            };
            match read_pointer_at(pointers, &name, sequence) {
                Ok(pointer) => {
                    if parsed.len() == MAX_POINTER_CANDIDATES {
                        return Err(InspectionErrorCode::ProviderArtifactIncomplete);
                    }
                    parsed.push(pointer);
                }
                Err(CacheProblem::Missing) => {
                    problem = worst(problem, CacheProblem::ArtifactIncomplete)
                }
                Err(other) => problem = worst(problem, other),
            }
        }
        parsed.sort_unstable_by_key(|pointer| std::cmp::Reverse(pointer.sequence));
        if parsed.is_empty() {
            return Ok(CacheLookup::Missing(problem));
        }
        for pointer in parsed {
            if pointer.archive_sha256 != target.archive_sha256()
                || pointer.executable_sha256 != target.executable_sha256()
            {
                problem = worst(problem, CacheProblem::ArtifactMismatch);
                continue;
            }
            match validate_object_at(directories.objects.as_ref(), pointer.archive_sha256, target) {
                Ok(executable) => {
                    return Ok(CacheLookup::Ready(CachedArtifact {
                        executable,
                        executable_sha256: pointer.executable_sha256,
                        #[cfg(test)]
                        sequence: pointer.sequence,
                    }));
                }
                Err(object_problem) => problem = worst(problem, object_problem),
            }
        }
        Ok(CacheLookup::Missing(problem))
    }

    fn read_pointer_at(
        pointers: &File,
        name: &OsStr,
        sequence: u64,
    ) -> Result<Pointer, CacheProblem> {
        let file = open_at(
            pointers,
            name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0,
        )
        .map_err(|_| CacheProblem::ArtifactIncomplete)?;
        let metadata = file
            .metadata()
            .map_err(|_| CacheProblem::ArtifactIncomplete)?;
        if !metadata.is_file() || metadata.len() > MAX_POINTER_BYTES {
            return Err(CacheProblem::ArtifactIncomplete);
        }
        let mut contents = String::new();
        file.take(MAX_POINTER_BYTES + 1)
            .read_to_string(&mut contents)
            .map_err(|_| CacheProblem::ArtifactIncomplete)?;
        if contents.len() as u64 > MAX_POINTER_BYTES {
            return Err(CacheProblem::ArtifactIncomplete);
        }
        let mut lines = contents.lines();
        if lines.next() != Some(POINTER_MAGIC) {
            return Err(CacheProblem::ArtifactIncomplete);
        }
        let archive_sha256 = lines
            .next()
            .and_then(|value| Sha256Digest::parse_hex(value).ok())
            .ok_or(CacheProblem::ArtifactIncomplete)?;
        let executable_sha256 = lines
            .next()
            .and_then(|value| Sha256Digest::parse_hex(value).ok())
            .ok_or(CacheProblem::ArtifactIncomplete)?;
        if lines.next().is_some() {
            return Err(CacheProblem::ArtifactIncomplete);
        }
        Ok(Pointer {
            sequence,
            archive_sha256,
            executable_sha256,
        })
    }

    fn validate_object_at(
        objects: Option<&File>,
        archive_sha256: Sha256Digest,
        target: &TargetArtifact,
    ) -> Result<File, CacheProblem> {
        let objects = objects.ok_or(CacheProblem::ArtifactIncomplete)?;
        let object_name = archive_sha256.to_hex();
        let object = open_directory_at(objects, OsStr::new(&object_name))
            .map_err(|_| CacheProblem::ArtifactIncomplete)?;
        let mut executable = open_at(
            &object,
            OsStr::new(target.executable()),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0,
        )
        .map_err(|_| CacheProblem::ArtifactIncomplete)?;
        let metadata = executable
            .metadata()
            .map_err(|_| CacheProblem::ArtifactIncomplete)?;
        if !metadata.is_file() {
            return Err(CacheProblem::ArtifactIncomplete);
        }
        if metadata.len() != target.executable_bytes() {
            return Err(CacheProblem::ArtifactMismatch);
        }
        let digest = digest_reader(&mut executable, target.executable_bytes())
            .map_err(|_| CacheProblem::ArtifactIncomplete)?;
        if digest != target.executable_sha256() {
            return Err(CacheProblem::ArtifactMismatch);
        }
        Ok(executable)
    }

    pub(super) fn install_in_directories(
        directories: &CacheDirectories,
        target: &TargetArtifact,
        archive: &[u8],
    ) -> Result<CachedArtifact, InspectionErrorCode> {
        let pointers = directories
            .pointers
            .as_ref()
            .ok_or(InspectionErrorCode::InvalidCacheDirectory)?;
        let objects = directories
            .objects
            .as_ref()
            .ok_or(InspectionErrorCode::InvalidCacheDirectory)?;
        let locks = directories
            .locks
            .as_ref()
            .ok_or(InspectionErrorCode::InvalidCacheDirectory)?;
        let _lock = acquire_lock(locks)?;
        if let CacheLookup::Ready(artifact) = lookup_in_directories(directories, target)? {
            return Ok(artifact);
        }
        let executable_bytes = extract_executable(archive, target)?;
        install_object_at(objects, target, &executable_bytes)?;
        let sequence = next_sequence(pointers)?;
        publish_pointer(pointers, sequence, target)?;
        cleanup(directories, target)?;
        match lookup_in_directories(directories, target)? {
            CacheLookup::Ready(artifact) => Ok(artifact),
            CacheLookup::Missing(problem) => Err(problem.code()),
        }
    }

    fn install_object_at(
        objects: &File,
        target: &TargetArtifact,
        executable_bytes: &[u8],
    ) -> Result<(), InspectionErrorCode> {
        let object_name = target.archive_sha256().to_hex();
        if validate_object_at(Some(objects), target.archive_sha256(), target).is_ok() {
            return Ok(());
        }
        if metadata_at(objects, OsStr::new(&object_name))
            .map_err(|_| InspectionErrorCode::ProviderArtifactMismatch)?
            .is_some()
        {
            remove_entry_at(objects, OsStr::new(&object_name))
                .map_err(|_| InspectionErrorCode::ProviderArtifactMismatch)?;
            objects
                .sync_all()
                .map_err(|_| InspectionErrorCode::InternalIo)?;
        }
        let name = c_name(OsStr::new(&object_name)).map_err(|_| InspectionErrorCode::InternalIo)?;
        // SAFETY: `objects` is an open directory and `name` is one child
        // component. mkdirat creates the object only if its name is unused.
        let result =
            unsafe { libc::mkdirat(objects.as_raw_fd(), name.as_ptr(), 0o700 as libc::mode_t) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == ErrorKind::AlreadyExists
                && validate_object_at(Some(objects), target.archive_sha256(), target).is_ok()
            {
                return Ok(());
            }
            return Err(InspectionErrorCode::ProviderArtifactMismatch);
        }
        let object = open_directory_at(objects, OsStr::new(&object_name))
            .map_err(|_| InspectionErrorCode::InternalIo)?;
        let mut executable = open_at(
            &object,
            OsStr::new(target.executable()),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o500 as libc::mode_t,
        )
        .map_err(|_| InspectionErrorCode::InternalIo)?;
        executable
            .write_all(executable_bytes)
            .and_then(|()| executable.sync_all())
            .map_err(|_| InspectionErrorCode::InternalIo)?;
        object
            .sync_all()
            .and_then(|()| objects.sync_all())
            .map_err(|_| InspectionErrorCode::InternalIo)?;
        Ok(())
    }

    fn publish_pointer(
        pointers: &File,
        sequence: u64,
        target: &TargetArtifact,
    ) -> Result<(), InspectionErrorCode> {
        let contents = format!(
            "{POINTER_MAGIC}\n{}\n{}\n",
            target.archive_sha256(),
            target.executable_sha256()
        );
        let (temporary_name, mut temporary) = create_temp_file(pointers, "pointer")?;
        temporary
            .write_all(contents.as_bytes())
            .and_then(|()| temporary.sync_all())
            .map_err(|_| InspectionErrorCode::InternalIo)?;

        let destination = format!("{sequence:020}");
        let temporary_c = c_name(&temporary_name).map_err(|_| InspectionErrorCode::InternalIo)?;
        let destination_c =
            c_name(OsStr::new(&destination)).map_err(|_| InspectionErrorCode::InternalIo)?;
        // SAFETY: both names are single components in the same open directory.
        // linkat publishes the complete pointer without replacing a sequence.
        let linked = unsafe {
            libc::linkat(
                pointers.as_raw_fd(),
                temporary_c.as_ptr(),
                pointers.as_raw_fd(),
                destination_c.as_ptr(),
                0,
            )
        };
        if linked < 0 {
            let error = io::Error::last_os_error();
            let _ = unlink_at(pointers, &temporary_name, 0);
            return Err(if error.kind() == ErrorKind::AlreadyExists {
                InspectionErrorCode::ProviderArtifactIncomplete
            } else {
                InspectionErrorCode::InternalIo
            });
        }
        unlink_at(pointers, &temporary_name, 0).map_err(|_| InspectionErrorCode::InternalIo)?;
        pointers
            .sync_all()
            .map_err(|_| InspectionErrorCode::InternalIo)
    }

    fn create_temp_file(
        directory: &File,
        label: &str,
    ) -> Result<(OsString, File), InspectionErrorCode> {
        for _ in 0..32 {
            let id = NEXT_TEMP_NAME.fetch_add(1, Ordering::Relaxed);
            let name = OsString::from(format!(".tmp-{label}-{}-{id}", std::process::id()));
            match open_at(
                directory,
                &name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::mode_t,
            ) {
                Ok(file) => return Ok((name, file)),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(InspectionErrorCode::InternalIo),
            }
        }
        Err(InspectionErrorCode::InternalIo)
    }

    pub(super) fn cleanup(
        directories: &CacheDirectories,
        target: &TargetArtifact,
    ) -> Result<(), InspectionErrorCode> {
        let pointers = directories
            .pointers
            .as_ref()
            .ok_or(InspectionErrorCode::CacheCleanupFailed)?;
        let objects = directories
            .objects
            .as_ref()
            .ok_or(InspectionErrorCode::CacheCleanupFailed)?;

        let pointer_names = bounded_directory_names(
            pointers,
            InspectionErrorCode::CacheCleanupFailed,
            InspectionErrorCode::CacheCleanupFailed,
        )?;
        let mut sequences = Vec::new();
        sequences
            .try_reserve(MAX_CACHE_DIRECTORY_ENTRIES)
            .map_err(|_| InspectionErrorCode::AllocationFailed)?;
        let mut temporary_pointers = Vec::new();
        temporary_pointers
            .try_reserve(MAX_CACHE_DIRECTORY_ENTRIES)
            .map_err(|_| InspectionErrorCode::AllocationFailed)?;
        for name in &pointer_names {
            if let Some(sequence) = name.to_str().and_then(parse_sequence) {
                sequences.push(sequence);
            } else if name.to_string_lossy().starts_with(".tmp-") {
                temporary_pointers.push(name.clone());
            }
        }
        sequences.sort_unstable_by(|left, right| right.cmp(left));
        sequences.dedup();

        let mut old_pointers = Vec::new();
        old_pointers
            .try_reserve(sequences.len().saturating_sub(KEEP_GENERATIONS))
            .map_err(|_| InspectionErrorCode::AllocationFailed)?;
        for sequence in sequences.iter().skip(KEEP_GENERATIONS) {
            let name = OsString::from(format!("{sequence:020}"));
            if let Some(metadata) =
                metadata_at(pointers, &name).map_err(|_| InspectionErrorCode::CacheCleanupFailed)?
            {
                if is_symlink(&metadata) {
                    return Err(InspectionErrorCode::CacheCleanupFailed);
                }
                old_pointers.push(name);
            }
        }

        let mut referenced = Vec::new();
        referenced
            .try_reserve(KEEP_GENERATIONS + 1)
            .map_err(|_| InspectionErrorCode::AllocationFailed)?;
        for sequence in sequences.iter().take(KEEP_GENERATIONS) {
            let name = OsString::from(format!("{sequence:020}"));
            if let Ok(pointer) = read_pointer_at(pointers, &name, *sequence) {
                referenced.push(pointer.archive_sha256);
            }
        }
        if !referenced.contains(&target.archive_sha256()) {
            referenced.push(target.archive_sha256());
        }

        let object_names = bounded_directory_names(
            objects,
            InspectionErrorCode::CacheCleanupFailed,
            InspectionErrorCode::CacheCleanupFailed,
        )?;
        let mut remove_objects = Vec::new();
        remove_objects
            .try_reserve(MAX_CACHE_DIRECTORY_ENTRIES)
            .map_err(|_| InspectionErrorCode::AllocationFailed)?;
        for name in object_names {
            let metadata =
                metadata_at(objects, &name).map_err(|_| InspectionErrorCode::CacheCleanupFailed)?;
            let Some(metadata) = metadata else {
                continue;
            };
            let name_string = name.to_string_lossy();
            if name_string.starts_with(".tmp-") {
                if is_directory(&metadata) {
                    remove_objects.push(name);
                }
                continue;
            }
            let Ok(digest) = Sha256Digest::parse_hex(&name_string) else {
                continue;
            };
            if referenced.contains(&digest) {
                continue;
            }
            if is_symlink(&metadata) {
                return Err(InspectionErrorCode::CacheCleanupFailed);
            }
            if is_directory(&metadata) {
                remove_objects.push(name);
            }
        }

        for name in temporary_pointers {
            remove_entry_at(pointers, &name)
                .map_err(|_| InspectionErrorCode::CacheCleanupFailed)?;
        }
        for name in old_pointers {
            unlink_at(pointers, &name, 0).map_err(|_| InspectionErrorCode::CacheCleanupFailed)?;
        }
        for name in remove_objects {
            remove_entry_at(objects, &name).map_err(|_| InspectionErrorCode::CacheCleanupFailed)?;
        }
        pointers
            .sync_all()
            .and_then(|()| objects.sync_all())
            .map_err(|_| InspectionErrorCode::CacheCleanupFailed)
    }

    fn next_sequence(pointers: &File) -> Result<u64, InspectionErrorCode> {
        let mut maximum = 0;
        for name in bounded_directory_names(
            pointers,
            InspectionErrorCode::InternalIo,
            InspectionErrorCode::ProviderArtifactIncomplete,
        )? {
            if let Some(sequence) = name.to_str().and_then(parse_sequence) {
                maximum = maximum.max(sequence);
            }
        }
        maximum
            .checked_add(1)
            .ok_or(InspectionErrorCode::ProviderArtifactIncomplete)
    }

    fn bounded_directory_names(
        directory: &File,
        read_error: InspectionErrorCode,
        limit_error: InspectionErrorCode,
    ) -> Result<Vec<OsString>, InspectionErrorCode> {
        let duplicate = open_directory_at(directory, OsStr::new("."))
            .map_err(|_| read_error)?
            .into_raw_fd();
        // SAFETY: fdopendir takes ownership of a separately opened directory
        // descriptor, so enumeration does not share an offset with another
        // operation on the pinned directory handle.
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            unsafe { libc::close(duplicate) };
            return Err(read_error);
        }
        let stream = DirectoryStream(stream);
        let mut names = Vec::new();
        names
            .try_reserve(MAX_CACHE_DIRECTORY_ENTRIES)
            .map_err(|_| InspectionErrorCode::AllocationFailed)?;
        loop {
            clear_errno();
            // SAFETY: stream remains open and exclusively owned by this call.
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                if last_errno() != 0 {
                    return Err(read_error);
                }
                break;
            }
            // SAFETY: readdir returns a live dirent with NUL-terminated d_name.
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            if names.len() == MAX_CACHE_DIRECTORY_ENTRIES {
                return Err(limit_error);
            }
            let mut owned_name = Vec::new();
            owned_name
                .try_reserve(bytes.len())
                .map_err(|_| InspectionErrorCode::AllocationFailed)?;
            owned_name.extend_from_slice(bytes);
            names.push(OsString::from_vec(owned_name));
        }
        Ok(names)
    }

    struct DirectoryStream(*mut libc::DIR);

    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            // SAFETY: this stream was returned by fdopendir and is closed once.
            unsafe { libc::closedir(self.0) };
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn clear_errno() {
        unsafe { *libc::__errno_location() = 0 };
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    fn clear_errno() {
        unsafe { *libc::__error() = 0 };
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    fn clear_errno() {}

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn last_errno() -> i32 {
        unsafe { *libc::__errno_location() }
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    fn last_errno() -> i32 {
        unsafe { *libc::__error() }
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    fn last_errno() -> i32 {
        0
    }

    fn metadata_at(parent: &File, name: &OsStr) -> io::Result<Option<libc::stat>> {
        let name = c_name(name)?;
        let mut metadata = MaybeUninit::<libc::stat>::zeroed();
        // SAFETY: parent is an open directory and metadata points to writable
        // storage for fstatat's result.
        let result = unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(error)
            };
        }
        // SAFETY: fstatat initialized metadata after returning success.
        Ok(Some(unsafe { metadata.assume_init() }))
    }

    fn is_directory(metadata: &libc::stat) -> bool {
        metadata.st_mode & libc::S_IFMT == libc::S_IFDIR
    }

    fn is_symlink(metadata: &libc::stat) -> bool {
        metadata.st_mode & libc::S_IFMT == libc::S_IFLNK
    }

    fn unlink_at(parent: &File, name: &OsStr, flags: libc::c_int) -> io::Result<()> {
        let name = c_name(name)?;
        // SAFETY: parent is an open directory; unlinkat removes this child
        // entry without following a symbolic link.
        let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == ErrorKind::NotFound {
            Ok(())
        } else {
            Err(error)
        }
    }

    fn remove_entry_at(parent: &File, name: &OsStr) -> Result<(), InspectionErrorCode> {
        let mut visited = 0;
        remove_entry_at_inner(parent, name, 0, &mut visited)
    }

    fn remove_entry_at_inner(
        parent: &File,
        name: &OsStr,
        depth: usize,
        visited: &mut usize,
    ) -> Result<(), InspectionErrorCode> {
        if depth >= MAX_CACHE_DIRECTORY_ENTRIES || *visited >= MAX_CACHE_DIRECTORY_ENTRIES {
            return Err(InspectionErrorCode::CacheCleanupFailed);
        }
        match open_directory_at(parent, name) {
            Ok(directory) => {
                let names = bounded_directory_names(
                    &directory,
                    InspectionErrorCode::CacheCleanupFailed,
                    InspectionErrorCode::CacheCleanupFailed,
                )?;
                for child in names {
                    *visited = visited
                        .checked_add(1)
                        .ok_or(InspectionErrorCode::CacheCleanupFailed)?;
                    if *visited > MAX_CACHE_DIRECTORY_ENTRIES {
                        return Err(InspectionErrorCode::CacheCleanupFailed);
                    }
                    remove_entry_at_inner(&directory, &child, depth + 1, visited)?;
                }
                let name_c = c_name(name).map_err(|_| InspectionErrorCode::CacheCleanupFailed)?;
                // SAFETY: AT_REMOVEDIR can remove only a directory entry under
                // the pinned parent; it cannot traverse a replacement symlink.
                let result = unsafe {
                    libc::unlinkat(parent.as_raw_fd(), name_c.as_ptr(), libc::AT_REMOVEDIR)
                };
                if result == 0 || io::Error::last_os_error().kind() == ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(InspectionErrorCode::CacheCleanupFailed)
                }
            }
            Err(error)
                if error.kind() == ErrorKind::NotFound
                    || error.kind() == ErrorKind::NotADirectory
                    || error.raw_os_error() == Some(libc::ELOOP) =>
            {
                unlink_at(parent, name, 0).map_err(|_| InspectionErrorCode::CacheCleanupFailed)
            }
            Err(_) => Err(InspectionErrorCode::CacheCleanupFailed),
        }
    }

    pub(super) struct CacheLock {
        file: File,
    }

    impl Drop for CacheLock {
        fn drop(&mut self) {
            let _ = self.file.unlock();
        }
    }

    pub(super) fn acquire_lock(locks: &File) -> Result<CacheLock, InspectionErrorCode> {
        let file = open_at(
            locks,
            OsStr::new(LOCK_FILE),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::mode_t,
        )
        .map_err(|_| InspectionErrorCode::CacheLockFailed)?;
        let metadata = file
            .metadata()
            .map_err(|_| InspectionErrorCode::CacheLockFailed)?;
        if !metadata.is_file() {
            return Err(InspectionErrorCode::CacheLockFailed);
        }
        match file.try_lock_exclusive() {
            Ok(()) => Ok(CacheLock { file }),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                Err(InspectionErrorCode::ProviderCacheBusy)
            }
            Err(_) => Err(InspectionErrorCode::CacheLockFailed),
        }
    }
}

#[cfg(not(unix))]
fn open_beneath_nofollow(root: &Path, relative: &Path) -> std::io::Result<File> {
    open_nofollow(&root.join(relative))
}

#[cfg(not(unix))]
fn open_nofollow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    #[cfg(windows)]
    options.custom_flags(0x0020_0000 | 0x0200_0000);
    options.open(path)
}

#[cfg(not(unix))]
fn sync_directory(path: &Path) -> Result<(), InspectionErrorCode> {
    let _ = path;
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_pointer_name(sequence: u64) -> String {
    format!("{sequence:020}")
}

#[cfg(test)]
pub(crate) fn test_provider_root(cache_dir: &Path) -> PathBuf {
    cache_dir.join(PROVIDER_DIRECTORY).join(VERSION_DIRECTORY)
}

#[cfg(test)]
mod tests {
    use super::unix_cache;
    use super::{
        CacheLookup, CacheProblem, MAX_CACHE_DIRECTORY_ENTRIES, MAX_POINTER_CANDIDATES,
        extract_executable, install_archive, lookup, test_pointer_name, test_provider_root,
    };
    use crate::provider::manifest::{TargetArtifact, manifest, synthetic_target};
    use std::fs;
    use std::io::{Cursor, Write};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn temp_cache() -> PathBuf {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let temporary_directory = fs::canonicalize(std::env::temp_dir()).expect("temp directory");
        temporary_directory.join(format!("nscb-cache-test-{}-{id}", std::process::id()))
    }

    fn native_target() -> &'static crate::provider::manifest::TargetArtifact {
        manifest()
            .unwrap()
            .find("macos", "aarch64")
            .expect("test target")
    }

    fn synthetic_release() -> (TargetArtifact, Vec<u8>, Vec<u8>) {
        synthetic_release_for(b"synthetic nstool executable")
    }

    fn synthetic_release_with_suffix(suffix: &[u8]) -> (TargetArtifact, Vec<u8>, Vec<u8>) {
        synthetic_release_for(suffix)
    }

    fn synthetic_release_for(executable: &[u8]) -> (TargetArtifact, Vec<u8>, Vec<u8>) {
        let executable = executable.to_vec();
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(
                "nstool",
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        writer.write_all(&executable).unwrap();
        let archive = writer.finish().unwrap().into_inner();
        let target = synthetic_target(&executable, &archive);
        (target, archive, executable)
    }

    fn pointer_contents(target: &TargetArtifact) -> String {
        format!(
            "nstool 1.9.2\n{}\n{}\n",
            target.archive_sha256(),
            target.executable_sha256()
        )
    }

    fn ready_sequence(cache: &Path, target: &TargetArtifact) -> u64 {
        match lookup(cache, target).unwrap() {
            CacheLookup::Ready(artifact) => artifact.sequence(),
            CacheLookup::Missing(problem) => panic!("unexpected cache miss: {problem:?}"),
        }
    }

    #[test]
    fn missing_cache_is_a_prerequisite() {
        let cache = temp_cache();
        let found = lookup(&cache, native_target()).unwrap();
        assert!(matches!(found, CacheLookup::Missing(CacheProblem::Missing)));
    }

    #[test]
    fn cache_root_must_be_absolute() {
        assert_eq!(
            lookup(Path::new("relative-cache"), native_target()).unwrap_err(),
            crate::inspection::InspectionErrorCode::InvalidCacheDirectory
        );
    }

    #[test]
    fn lookup_rejects_more_than_the_pointer_candidate_cap() {
        let cache = temp_cache();
        let target = native_target();
        let pointers = test_provider_root(&cache).join("pointers");
        fs::create_dir_all(&pointers).unwrap();
        let contents = pointer_contents(target);
        for sequence in 1..=(MAX_POINTER_CANDIDATES + 1) {
            fs::write(pointers.join(test_pointer_name(sequence as u64)), &contents).unwrap();
        }
        assert_eq!(
            lookup(&cache, target).unwrap_err(),
            crate::inspection::InspectionErrorCode::ProviderArtifactIncomplete
        );
        let _ = fs::remove_dir_all(cache);
    }

    #[test]
    fn lookup_rejects_directory_enumeration_over_the_cap() {
        let cache = temp_cache();
        let pointers = test_provider_root(&cache).join("pointers");
        fs::create_dir_all(&pointers).unwrap();
        for entry in 0..=MAX_CACHE_DIRECTORY_ENTRIES {
            fs::write(pointers.join(format!("unrecognized-{entry}")), b"").unwrap();
        }
        assert_eq!(
            lookup(&cache, native_target()).unwrap_err(),
            crate::inspection::InspectionErrorCode::ProviderArtifactIncomplete
        );
        let _ = fs::remove_dir_all(cache);
    }

    #[test]
    fn cleanup_bounds_pointer_enumeration_before_removing_entries() {
        let cache = temp_cache();
        let target = native_target();
        let root = test_provider_root(&cache);
        let pointers = root.join("pointers");
        fs::create_dir_all(&pointers).unwrap();
        let temporary = pointers.join(".tmp-preserve-on-limit");
        fs::write(&temporary, b"keep until bounded scan completes").unwrap();
        for entry in 0..MAX_CACHE_DIRECTORY_ENTRIES {
            fs::write(pointers.join(format!("unrecognized-{entry}")), b"").unwrap();
        }
        assert_eq!(
            unix_cache::cleanup(
                &unix_cache::open_cache_directories(&cache, true)
                    .unwrap()
                    .unwrap(),
                target,
            )
            .unwrap_err(),
            crate::inspection::InspectionErrorCode::CacheCleanupFailed
        );
        assert!(temporary.exists());
        let _ = fs::remove_dir_all(cache);
    }

    #[test]
    fn cleanup_bounds_object_enumeration() {
        let cache = temp_cache();
        let target = native_target();
        let root = test_provider_root(&cache);
        let pointers = root.join("pointers");
        let objects = root.join("objects");
        fs::create_dir_all(&pointers).unwrap();
        fs::create_dir_all(&objects).unwrap();
        let last = objects.join(format!("orphan-{}", MAX_CACHE_DIRECTORY_ENTRIES));
        for entry in 0..=MAX_CACHE_DIRECTORY_ENTRIES {
            fs::write(objects.join(format!("orphan-{entry}")), b"").unwrap();
        }
        assert_eq!(
            unix_cache::cleanup(
                &unix_cache::open_cache_directories(&cache, true)
                    .unwrap()
                    .unwrap(),
                target,
            )
            .unwrap_err(),
            crate::inspection::InspectionErrorCode::CacheCleanupFailed
        );
        assert!(last.exists());
        let _ = fs::remove_dir_all(cache);
    }

    #[test]
    fn unsafe_parent_indirection_is_rejected() {
        let cache = temp_cache();
        fs::create_dir_all(&cache).unwrap();
        let root = test_provider_root(&cache);
        fs::create_dir_all(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(std::env::temp_dir(), root.join("pointers")).unwrap();
            assert_eq!(
                lookup(&cache, native_target()).unwrap_err(),
                crate::inspection::InspectionErrorCode::InvalidCacheDirectory
            );
        }
        let _ = fs::remove_dir_all(cache);
    }

    #[cfg(unix)]
    #[test]
    fn lookup_rejects_symlinked_ancestor_above_cache_directory() {
        use std::os::unix::fs::symlink;

        let base = temp_cache();
        let real_parent = base.join("real-parent");
        fs::create_dir_all(&real_parent).unwrap();
        let linked_parent = base.join("linked-parent");
        symlink(&real_parent, &linked_parent).unwrap();
        let cache = linked_parent.join("cache");

        assert_eq!(
            lookup(&cache, native_target()).unwrap_err(),
            crate::inspection::InspectionErrorCode::InvalidCacheDirectory
        );
        let _ = fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[test]
    fn install_stays_on_open_directories_after_ancestor_and_child_replacement() {
        use std::os::unix::fs::symlink;

        let base = temp_cache();
        let cache = base.join("cache");
        fs::create_dir_all(&cache).unwrap();
        let (first, first_archive, _) = synthetic_release();
        install_archive(&cache, &first, &first_archive).unwrap();

        let root = test_provider_root(&cache);
        let original_pointers = root.join("pointers");
        let original_objects = root.join("objects");
        fs::write(original_pointers.join(".tmp-pointer-race"), b"partial").unwrap();
        let temporary_object = original_objects.join(".tmp-object-race");
        fs::create_dir(&temporary_object).unwrap();
        fs::write(temporary_object.join("partial"), b"partial").unwrap();

        let directories = unix_cache::open_cache_directories(&cache, false)
            .unwrap()
            .unwrap();
        let moved_base = base.with_extension("opened");
        let decoy_base = base.with_extension("decoy");
        fs::rename(&base, &moved_base).unwrap();
        fs::create_dir(&decoy_base).unwrap();
        symlink(&decoy_base, &base).unwrap();

        let moved_root = test_provider_root(&moved_base.join("cache"));
        let held_pointers = moved_root.join("pointers-opened");
        let held_objects = moved_root.join("objects-opened");
        fs::rename(moved_root.join("pointers"), &held_pointers).unwrap();
        fs::rename(moved_root.join("objects"), &held_objects).unwrap();
        let decoy_pointers = moved_root.join("pointers-decoy");
        let decoy_objects = moved_root.join("objects-decoy");
        fs::create_dir(&decoy_pointers).unwrap();
        fs::create_dir(&decoy_objects).unwrap();
        symlink(&decoy_pointers, moved_root.join("pointers")).unwrap();
        symlink(&decoy_objects, moved_root.join("objects")).unwrap();

        let (second, second_archive, _) = synthetic_release_with_suffix(b"replacement race");
        let installed =
            unix_cache::install_in_directories(&directories, &second, &second_archive).unwrap();
        assert_eq!(installed.executable_sha256(), second.executable_sha256());
        assert!(matches!(
            unix_cache::lookup_in_directories(&directories, &first).unwrap(),
            CacheLookup::Ready(artifact) if artifact.sequence() == 1
        ));
        assert!(matches!(
            unix_cache::lookup_in_directories(&directories, &second).unwrap(),
            CacheLookup::Ready(artifact) if artifact.sequence() == 2
        ));
        assert!(!held_pointers.join(".tmp-pointer-race").exists());
        assert!(!held_objects.join(".tmp-object-race").exists());
        assert_eq!(fs::read_dir(&decoy_pointers).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&decoy_objects).unwrap().count(), 0);
        assert_eq!(
            lookup(&cache, &second).unwrap_err(),
            crate::inspection::InspectionErrorCode::InvalidCacheDirectory
        );

        drop(directories);
        fs::remove_file(&base).unwrap();
        let _ = fs::remove_dir_all(moved_base);
        let _ = fs::remove_dir_all(decoy_base);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_object_parent_is_never_selected() {
        use std::os::unix::fs::symlink;

        let cache = temp_cache();
        let (target, archive, _executable) = synthetic_release();
        install_archive(&cache, &target, &archive).unwrap();
        let root = test_provider_root(&cache);
        fs::rename(root.join("objects"), root.join("objects-real")).unwrap();
        symlink("objects-real", root.join("objects")).unwrap();

        assert!(matches!(
            lookup(&cache, &target).unwrap(),
            CacheLookup::Missing(CacheProblem::ArtifactIncomplete)
        ));
        let _ = fs::remove_dir_all(cache);
    }

    #[test]
    fn new_pointer_with_missing_object_falls_back_to_previous_valid_artifact() {
        let cache = temp_cache();
        fs::create_dir_all(&cache).unwrap();
        let root = test_provider_root(&cache);
        let (target, archive, _executable) = synthetic_release();
        install_archive(&cache, &target, &archive).unwrap();
        let pointers = root.join("pointers");
        let (other, _other_archive, _other_executable) = synthetic_release_with_suffix(b"other");
        fs::write(
            pointers.join(test_pointer_name(2)),
            pointer_contents(&other),
        )
        .unwrap();
        assert_eq!(ready_sequence(&cache, &target), 1);
        let _ = fs::remove_dir_all(cache);
    }

    #[test]
    fn malformed_pointer_is_not_selected() {
        let cache = temp_cache();
        let root = test_provider_root(&cache);
        fs::create_dir_all(root.join("objects")).unwrap();
        fs::create_dir_all(root.join("pointers")).unwrap();
        fs::write(root.join("pointers").join(test_pointer_name(1)), b"broken").unwrap();
        assert!(matches!(
            lookup(&cache, native_target()).unwrap(),
            CacheLookup::Missing(CacheProblem::ArtifactIncomplete)
        ));
        let _ = fs::remove_dir_all(cache);
    }

    #[test]
    fn archive_digest_is_checked_before_installation() {
        let cache = temp_cache();
        let error = install_archive(&cache, native_target(), b"not the release").unwrap_err();
        assert_eq!(
            error,
            crate::inspection::InspectionErrorCode::ProviderArchiveInvalid
        );
        assert!(!Path::new(&cache).exists());
    }

    #[test]
    fn exact_single_regular_member_is_accepted_by_the_pinned_layout_parser() {
        let (target, archive, executable) = synthetic_release();
        assert_eq!(extract_executable(&archive, &target).unwrap(), executable);
    }

    #[test]
    fn archive_symlink_metadata_is_rejected_without_publishing_cache_entries() {
        let executable = b"synthetic executable";
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(
                "nstool",
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored)
                    .unix_permissions(0o120777),
            )
            .unwrap();
        writer.write_all(executable).unwrap();
        let mut archive = writer.finish().unwrap().into_inner();
        let central_directory = archive
            .windows(4)
            .position(|signature| signature == b"PK\x01\x02")
            .expect("central directory entry");
        // Mark the central-directory entry as a Unix symlink. The archive
        // reader uses the creator OS and external attributes to report this.
        archive[central_directory + 5] = 3;
        archive[central_directory + 38..central_directory + 42]
            .copy_from_slice(&(0o120777_u32 << 16).to_le_bytes());
        let target = synthetic_target(executable, &archive);
        let cache = temp_cache();

        assert_eq!(
            install_archive(&cache, &target, &archive).unwrap_err(),
            crate::inspection::InspectionErrorCode::ProviderArchiveInvalid
        );
        let root = test_provider_root(&cache);
        assert_eq!(fs::read_dir(root.join("pointers")).unwrap().count(), 0);
        assert_eq!(fs::read_dir(root.join("objects")).unwrap().count(), 0);
        let _ = fs::remove_dir_all(cache);
    }

    #[test]
    fn pinned_archive_from_explicit_path_installs_exact_verified_bytes() {
        let Some(archive_path) = std::env::var_os("NSCB_PINNED_ARCHIVE_PATH") else {
            return;
        };
        let archive = fs::read(archive_path).expect("read provided pinned archive");
        let target = native_target();
        eprintln!(
            "archive_install_input=bytes:{} sha256:{}",
            archive.len(),
            crate::sha256::Sha256Digest::digest(&archive)
        );
        assert_eq!(archive.len() as u64, target.archive_bytes());
        assert_eq!(
            crate::sha256::Sha256Digest::digest(&archive),
            target.archive_sha256()
        );
        let cache = temp_cache();
        let installed = install_archive(&cache, target, &archive).expect("install exact bytes");
        assert_eq!(installed.executable_sha256(), target.executable_sha256());
        assert!(matches!(
            lookup(&cache, target).unwrap(),
            CacheLookup::Ready(_)
        ));
        let _ = fs::remove_dir_all(cache);
    }

    #[test]
    fn malformed_newest_pointer_falls_back_to_last_valid_artifact() {
        let cache = temp_cache();
        let root = test_provider_root(&cache);
        let (target, archive, executable) = synthetic_release();
        install_archive(&cache, &target, &archive).unwrap();
        fs::write(root.join("pointers").join(test_pointer_name(2)), b"broken").unwrap();
        assert_eq!(ready_sequence(&cache, &target), 1);
        let object = root
            .join("objects")
            .join(target.archive_sha256().to_hex())
            .join(target.executable());
        assert_eq!(fs::read(object).unwrap(), executable);
        let _ = fs::remove_dir_all(cache);
    }

    #[test]
    fn corrupt_orphan_object_is_repaired_without_losing_the_archive_identity() {
        let cache = temp_cache();
        let root = test_provider_root(&cache);
        let (target, archive, executable) = synthetic_release();
        install_archive(&cache, &target, &archive).unwrap();
        fs::remove_dir_all(root.join("pointers")).unwrap();
        let object = root.join("objects").join(target.archive_sha256().to_hex());
        let executable_path = object.join(target.executable());
        fs::remove_file(&executable_path).unwrap();
        fs::write(&executable_path, b"tampered").unwrap();
        install_archive(&cache, &target, &archive).unwrap();
        assert_eq!(
            fs::read(object.join(target.executable())).unwrap(),
            executable
        );
        assert_eq!(ready_sequence(&cache, &target), 1);
        let _ = fs::remove_dir_all(cache);
    }

    #[test]
    fn interrupted_temporary_entries_are_cleaned_without_removing_valid_generations() {
        let cache = temp_cache();
        let root = test_provider_root(&cache);
        let (first, first_archive, _) = synthetic_release();
        install_archive(&cache, &first, &first_archive).unwrap();
        let pointers = root.join("pointers");
        let objects = root.join("objects");
        fs::write(pointers.join(".tmp-pointer-interrupted"), b"partial").unwrap();
        let object_temp = objects.join(".tmp-object-interrupted");
        fs::create_dir_all(&object_temp).unwrap();
        fs::write(object_temp.join("partial"), b"partial").unwrap();
        let (second, second_archive, _) = synthetic_release_with_suffix(b"second helper");
        install_archive(&cache, &second, &second_archive).unwrap();
        assert!(!pointers.join(".tmp-pointer-interrupted").exists());
        assert!(!object_temp.exists());
        assert_eq!(ready_sequence(&cache, &first), 1);
        assert_eq!(ready_sequence(&cache, &second), 2);
        let _ = fs::remove_dir_all(cache);
    }

    #[test]
    fn active_cache_lock_prevents_a_concurrent_repair() {
        let cache = temp_cache();
        fs::create_dir_all(&cache).unwrap();
        let directories = unix_cache::open_cache_directories(&cache, true)
            .unwrap()
            .unwrap();
        let locks = directories.locks.as_ref().unwrap();
        let lock = unix_cache::acquire_lock(locks).unwrap();
        assert!(matches!(
            unix_cache::acquire_lock(locks),
            Err(crate::inspection::InspectionErrorCode::ProviderCacheBusy)
        ));
        drop(lock);
        assert!(unix_cache::acquire_lock(locks).is_ok());
        let _ = fs::remove_dir_all(cache);
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_pointer_type_is_ignored_and_last_valid_artifact_remains_selectable() {
        use std::os::unix::fs::symlink;

        let cache = temp_cache();
        let root = test_provider_root(&cache);
        let (target, archive, _) = synthetic_release();
        install_archive(&cache, &target, &archive).unwrap();
        let external = cache.join("external-pointer");
        fs::write(&external, pointer_contents(&target)).unwrap();
        symlink(&external, root.join("pointers").join(test_pointer_name(2))).unwrap();
        assert_eq!(ready_sequence(&cache, &target), 1);
        let _ = fs::remove_dir_all(cache);
    }

    #[test]
    fn tampered_cached_executable_is_not_reported_ready() {
        let cache = temp_cache();
        let root = test_provider_root(&cache);
        let (target, archive, _) = synthetic_release();
        install_archive(&cache, &target, &archive).unwrap();
        let executable = root
            .join("objects")
            .join(target.archive_sha256().to_hex())
            .join(target.executable());
        fs::remove_file(&executable).unwrap();
        fs::write(executable, b"wrong length").unwrap();
        assert!(matches!(
            lookup(&cache, &target).unwrap(),
            CacheLookup::Missing(CacheProblem::ArtifactMismatch)
        ));
        let _ = fs::remove_dir_all(cache);
    }
}
