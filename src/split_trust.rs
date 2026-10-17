//! Host-owned local trust receipts for qualified Split sets.
//!
//! A receipt binds the exact bytes of an unsigned manifest to source evidence
//! that was observed during an NSCB-controlled Split operation. Receipts are
//! intentionally host-local: copying an unsigned manifest, moving a directory,
//! or presenting byte-identical parts cannot create trust. The resolver only
//! reads receipts; production issuance belongs to the future source-backed
//! Split producer, while the Issue #6 tests use a test-only source-backed
//! fixture issuer.
//!
//! # Store layout
//!
//! A store has three kinds of state:
//!
//! - `receipts/<manifest>.json` records the source evidence bound to one exact
//!   manifest. Receipt files are replaceable data; a receipt alone never
//!   authorizes trust.
//! - `authority.json` inside the store root is the authoritative index of
//!   manifests and their revision states. It carries a random authority
//!   identifier that is created the first time the store writes state.
//! - `<store-name>-continuity.json` is a sibling of the store root, outside
//!   the directory a backup or copy usually replaces. It mirrors the authority
//!   index and must agree with it exactly. A store root copied to another
//!   location therefore has no continuity evidence and is rejected, and a
//!   partially rolled-back store root disagrees with the continuity anchor.
//!
//! Each mutation advances a store generation and appends a monotonic per
//! manifest revision. Issuance supplies the revision it supersedes, so a stale
//! issuance cannot erase a concurrent revocation. Revocations are recorded even
//! for manifests that were never issued, and a revocation is never replaced by
//! a lower or equal revision.
//!
//! # Durability and recovery
//!
//! Every mutation is serialized across processes with an advisory lock. The
//! complete target state, including any replacement receipt, is written to a
//! `commit.pending` journal first, then the receipt and both indexes are
//! replaced, and finally the journal is removed. A process that starts after a
//! crash replays the journal before reading or writing state, so a committed
//! revocation is never lost to a partially written index. A fresh store creates
//! each missing directory separately and synchronizes it and its parent on
//! Unix, so a commit cannot outlive the directory entries it depends on.
//!
//! Directory synchronization is a no-op on Windows. Write-through replacement
//! makes individual file replacements durable there, but ordering of newly
//! created directories and their parent entries is not qualified on Windows.
//!
//! Missing state directories behave as empty stores; malformed or unreadable
//! state fails closed instead of being treated as untrusted evidence.

use crate::file_identity::{followed_path_identity, handle_identity, path_identity};
use crate::input_resolution::{InputResolutionError, InputResolutionErrorCode};
use crate::sha256::Sha256Digest;
use crate::strict_json::{self, StrictJsonValue};
use fs2::FileExt as _;
use serde::Serialize;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const RECEIPT_SCHEMA_VERSION: u8 = 1;
const RECEIPT_KIND: &str = "nscb.split_trust_receipt";
const MAX_RECEIPT_BYTES: u64 = 16_384;
const AUTHORITY_SCHEMA_VERSION: u8 = 1;
const AUTHORITY_KIND: &str = "nscb.split_trust_authority";
const CONTINUITY_KIND: &str = "nscb.split_trust_continuity";
const COMMIT_SCHEMA_VERSION: u8 = 1;
const COMMIT_KIND: &str = "nscb.split_trust_commit";
const AUTHORITY_FILE: &str = "authority.json";
const COMMIT_PENDING_FILE: &str = "commit.pending";
const MAX_INDEX_BYTES: u64 = 4 * 1024 * 1024;
const MAX_COMMIT_BYTES: u64 = MAX_INDEX_BYTES + 4 * MAX_RECEIPT_BYTES;
const MAX_INDEX_ENTRIES: usize = 100_000;
const STATE_DIRECTORY_ENV: &str = "NSCB_STATE_DIR";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// A host-owned read capability for Split trust receipts.
///
/// Resolution receives only this trait, so it cannot issue or revoke trust.
/// Implementations must return a receipt only when the exact manifest bytes are
/// bound to the recorded source evidence, and must report store failures rather
/// than converting them into an untrusted result.
pub trait SplitTrustStore: Send + Sync {
    /// Looks up a receipt bound to the exact manifest bytes.
    fn lookup(
        &self,
        manifest_sha256: &Sha256Digest,
    ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError>;
}

/// A host-owned write capability for source-backed Split evidence.
///
/// Only a producer that independently observed the original source and
/// validated the complete published representation may call these methods.
/// The read-only resolver never receives this capability. Implementations must
/// make each mutation atomic and durable across processes that share the same
/// host state.
pub trait SplitTrustWriter: SplitTrustStore {
    /// Durably commits a complete, source-backed receipt.
    fn issue(&self, receipt: SplitTrustReceipt) -> Result<(), SplitTrustStoreError>;

    /// Explicitly revokes every byte-identical copy of a manifest.
    fn revoke(&self, manifest_sha256: &Sha256Digest) -> Result<(), SplitTrustStoreError>;
}

/// A host-local record binding exact manifest bytes to source evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SplitTrustReceipt {
    manifest_sha256: Sha256Digest,
    source_size_bytes: u64,
    source_sha256: Sha256Digest,
    revoked: bool,
    predecessor_revision: u64,
}

impl SplitTrustReceipt {
    /// Creates an issued receipt from independently observed source evidence.
    ///
    /// Production callers must construct this only after observing the original
    /// source bytes and validating the completed published Split output against
    /// them. Resolution never calls this constructor or the writer capability.
    pub const fn new(
        manifest_sha256: Sha256Digest,
        source_size_bytes: u64,
        source_sha256: Sha256Digest,
    ) -> Self {
        Self {
            manifest_sha256,
            source_size_bytes,
            source_sha256,
            revoked: false,
            predecessor_revision: 0,
        }
    }

    /// Returns the store revision this record supersedes.
    ///
    /// A receipt returned by [`SplitTrustStore::lookup`] reports the revision
    /// that produced it. Pass that value to [`Self::with_predecessor_revision`]
    /// before issuing a replacement so a concurrent revocation cannot be
    /// overwritten by stale evidence.
    pub const fn predecessor_revision(&self) -> u64 {
        self.predecessor_revision
    }

    /// Returns the same receipt with an explicit predecessor revision.
    pub const fn with_predecessor_revision(mut self, revision: u64) -> Self {
        self.predecessor_revision = revision;
        self
    }

    /// Returns the SHA-256 digest of the exact manifest bytes.
    pub const fn manifest_sha256(&self) -> &Sha256Digest {
        &self.manifest_sha256
    }

    /// Returns the independently observed source byte length.
    pub const fn source_size_bytes(&self) -> u64 {
        self.source_size_bytes
    }

    /// Returns the independently observed source SHA-256 digest.
    pub const fn source_sha256(&self) -> &Sha256Digest {
        &self.source_sha256
    }

    /// Reports whether this receipt has been explicitly revoked.
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// Returns the same receipt with the requested revocation state.
    pub const fn with_revoked(mut self, revoked: bool) -> Self {
        self.revoked = revoked;
        self
    }

    pub(crate) fn binds(&self, manifest_sha256: &Sha256Digest, source: &SourceEvidence) -> bool {
        self.manifest_sha256 == *manifest_sha256
            && self.source_size_bytes == source.size
            && self.source_sha256 == source.sha256
    }
}

/// Independent source evidence recorded during a completed Split operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SourceEvidence {
    pub(crate) size: u64,
    pub(crate) sha256: Sha256Digest,
}

/// A stable failure from a host trust store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SplitTrustStoreError {
    /// The store cannot currently be read or committed.
    Unavailable,
    /// Stored evidence is malformed or internally inconsistent.
    Corrupt,
    /// The caller tried to issue evidence that a newer store revision superseded.
    StaleEvidence,
    /// The host explicitly configured an invalid state location.
    ConfigurationInvalid,
}

impl fmt::Display for SplitTrustStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "the Split trust store is unavailable",
            Self::Corrupt => "the Split trust store contains invalid evidence",
            Self::StaleEvidence => "the Split trust store revision changed before issuance",
            Self::ConfigurationInvalid => "the Split trust store configuration is invalid",
        })
    }
}

impl std::error::Error for SplitTrustStoreError {}

/// A durable per-user trust store stored under a host-controlled state root.
///
/// The store keeps its authoritative index inside the configured root and its
/// continuity anchor next to that root, in the same parent directory. Hosts
/// that create a store with [`LocalSplitTrustStore::new`] should treat the
/// root and its sibling continuity file as one unit when backing up, and use
/// [`LocalSplitTrustStore::restore_from_snapshot`] rather than replacing the
/// root directory in place.
#[derive(Clone, Debug)]
pub struct LocalSplitTrustStore {
    root: StateRoot,
}

#[derive(Clone, Debug)]
enum StateRoot {
    Configured(PathBuf),
    Missing,
    InvalidConfiguration,
}

struct StorePaths {
    root: PathBuf,
    receipts: PathBuf,
    authority: PathBuf,
    continuity: PathBuf,
    pending: PathBuf,
}

impl StorePaths {
    fn for_root(root: &Path) -> Result<Self, SplitTrustStoreError> {
        Ok(Self {
            root: root.to_path_buf(),
            receipts: root.join("receipts"),
            authority: root.join(AUTHORITY_FILE),
            continuity: continuity_file(root)?,
            pending: root.join(COMMIT_PENDING_FILE),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum IndexState {
    Issued,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct IndexEntry {
    revision: u64,
    state: IndexState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct IndexDocument {
    schema_version: u8,
    kind: &'static str,
    authority_id: Sha256Digest,
    generation: u64,
    receipts: BTreeMap<String, IndexEntry>,
}

impl IndexDocument {
    fn new(kind: &'static str, authority_id: Sha256Digest) -> Self {
        Self {
            schema_version: AUTHORITY_SCHEMA_VERSION,
            kind,
            authority_id,
            generation: 0,
            receipts: BTreeMap::new(),
        }
    }

    const fn with_generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }

    fn entry(&self, manifest_sha256: &Sha256Digest) -> Option<&IndexEntry> {
        self.receipts.get(&manifest_sha256.to_hex())
    }

    fn upsert(&mut self, manifest_sha256: &Sha256Digest, revision: u64, state: IndexState) {
        self.receipts
            .insert(manifest_sha256.to_hex(), IndexEntry { revision, state });
    }

    fn advance_generation(&mut self) -> Result<(), SplitTrustStoreError> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(SplitTrustStoreError::Corrupt)?;
        Ok(())
    }

    fn same_authority_and_contents(&self, other: &Self) -> bool {
        self.authority_id == other.authority_id
            && self.generation == other.generation
            && self.receipts == other.receipts
    }
}

/// Index state observed on disk before any interpretation.
enum LoadedIndexes {
    /// Neither index file exists. The store has never committed state.
    Empty,
    /// Both indexes exist and agree.
    Ready {
        authority: IndexDocument,
        continuity: IndexDocument,
    },
    /// Only the continuity anchor exists. The store root was removed or
    /// replaced; reads fail closed and only restoration can rebuild the root.
    AnchorOnly { continuity: IndexDocument },
}

/// Summary of one explicit same-host restoration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SplitTrustRestore {
    /// Snapshot entries that were absent locally or newer than local state.
    pub restored_entries: usize,
    /// Local revocations that the snapshot asked to replace.
    pub preserved_revocations: usize,
}

impl LocalSplitTrustStore {
    /// Creates a store rooted at `root`. Tests and embedded hosts normally use
    /// this constructor with an isolated, absolute directory. The path is used
    /// as supplied; the standalone CLI instead rejects a relative
    /// `NSCB_STATE_DIR` override before constructing a store.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: StateRoot::Configured(root.into()),
        }
    }

    /// Creates the standalone CLI store from the host environment.
    ///
    /// An explicitly configured `NSCB_STATE_DIR` must be an absolute path. A
    /// relative or empty override is retained as a configuration failure so
    /// ordinary non-Split resolution does not depend on trust-store startup.
    pub fn from_environment() -> Self {
        Self {
            root: state_root_from_environment(),
        }
    }

    fn configured_root(&self) -> Result<&Path, SplitTrustStoreError> {
        match &self.root {
            StateRoot::Configured(root) => Ok(root),
            StateRoot::Missing => Err(SplitTrustStoreError::Unavailable),
            StateRoot::InvalidConfiguration => Err(SplitTrustStoreError::ConfigurationInvalid),
        }
    }

    fn existing_store_paths(&self) -> Result<Option<StorePaths>, SplitTrustStoreError> {
        let root = self.configured_root()?;
        let paths = StorePaths::for_root(root)?;
        if !validate_store_directory(root)? {
            return match fs::symlink_metadata(&paths.continuity) {
                Ok(_) => Err(SplitTrustStoreError::Corrupt),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(_) => Err(SplitTrustStoreError::Unavailable),
            };
        }
        Ok(Some(paths))
    }

    fn ensure_store_directories(&self) -> Result<StorePaths, SplitTrustStoreError> {
        let root = self.configured_root()?;
        create_dir_all_durable(root)?;
        let receipts = root.join("receipts");
        create_dir_all_durable(&receipts)?;
        StorePaths::for_root(root)
    }

    fn with_store_lock<T>(
        &self,
        operation: impl FnOnce(&StorePaths) -> Result<T, SplitTrustStoreError>,
    ) -> Result<T, SplitTrustStoreError> {
        let paths = self.ensure_store_directories()?;
        self.with_locked_store(&paths, operation)
    }

    fn with_locked_store<T>(
        &self,
        paths: &StorePaths,
        operation: impl FnOnce(&StorePaths) -> Result<T, SplitTrustStoreError>,
    ) -> Result<T, SplitTrustStoreError> {
        let lock_path = paths.root.join(".lock");
        let lock = open_lock_file(&lock_path)?;
        lock.lock_exclusive()
            .map_err(|_| SplitTrustStoreError::Unavailable)?;
        let root_valid = validate_store_directory(&paths.root)?;
        let receipts_valid = validate_store_directory(&paths.receipts)?;
        let indexes_present =
            state_file_exists(&paths.authority)? || state_file_exists(&paths.continuity)?;
        let result = if !root_valid
            || !lock_matches_path(&lock, &lock_path)?
            || (!receipts_valid && indexes_present)
        {
            Err(SplitTrustStoreError::Corrupt)
        } else {
            recover_pending_commit(paths).and_then(|()| operation(paths))
        };
        let _ = lock.unlock();
        result
    }

    fn lookup_receipt(
        &self,
        manifest_sha256: &Sha256Digest,
    ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
        let Some(paths) = self.existing_store_paths()? else {
            return Ok(None);
        };
        self.with_locked_store(&paths, |paths| {
            let path = receipt_path(&paths.receipts, manifest_sha256);
            let (authority, continuity) = match load_indexes(paths)? {
                LoadedIndexes::Empty => {
                    // No authority exists yet, so a receipt cannot be bound to
                    // this store. A malformed file is dangling corrupt state;
                    // a well-formed one is inert.
                    read_receipt_file(&path, manifest_sha256, None)?;
                    return Ok(None);
                }
                LoadedIndexes::AnchorOnly { .. } => return Err(SplitTrustStoreError::Corrupt),
                LoadedIndexes::Ready {
                    authority,
                    continuity,
                } => (authority, continuity),
            };
            let Some(entry) = continuity.entry(manifest_sha256).copied() else {
                // A well-formed receipt that no index names is inert, because
                // trust is established by the index pair, not by receipt files.
                // Malformed or non-regular files still fail closed.
                read_receipt_file(&path, manifest_sha256, Some(&authority.authority_id))?;
                return Ok(None);
            };
            let authority_entry = authority
                .entry(manifest_sha256)
                .copied()
                .ok_or(SplitTrustStoreError::Corrupt)?;
            if authority_entry != entry {
                return Err(SplitTrustStoreError::Corrupt);
            }
            if entry.state == IndexState::Revoked {
                return Ok(Some(revoked_tombstone(manifest_sha256, entry.revision)));
            }
            let receipt = read_receipt_file(&path, manifest_sha256, Some(&authority.authority_id))?
                .ok_or(SplitTrustStoreError::Corrupt)?;
            if receipt.predecessor_revision() != entry.revision || receipt.is_revoked() {
                return Err(SplitTrustStoreError::Corrupt);
            }
            Ok(Some(receipt))
        })
    }

    fn read_receipt(
        &self,
        manifest_sha256: &Sha256Digest,
    ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
        self.lookup_receipt(manifest_sha256)
    }

    /// Explicitly merges a same-host store snapshot into this store.
    ///
    /// A snapshot is a directory that contains an `authority.json` written by an
    /// earlier copy of this store. Restoration is the supported way to recover
    /// receipts after the store root is lost: it runs under the store lock,
    /// requires the snapshot to carry the same host authority identifier as the
    /// local continuity anchor, rejects a snapshot generation newer than the
    /// anchor, and never replaces a local revocation with an issued record.
    /// Receipt files named by restored issued entries are copied from the
    /// snapshot after their authority binding and revision are validated.
    ///
    /// Replacing `authority.json` or a receipt file by hand is not a
    /// restoration. A copied store root has no continuity anchor, and a
    /// partially rolled-back root disagrees with the anchor, so both fail
    /// closed instead of silently reviving trust.
    pub fn restore_from_snapshot(
        &self,
        snapshot_root: impl AsRef<Path>,
    ) -> Result<SplitTrustRestore, SplitTrustStoreError> {
        let snapshot_root = snapshot_root.as_ref();
        let snapshot_bytes =
            read_bounded_state_file(&snapshot_root.join(AUTHORITY_FILE), MAX_INDEX_BYTES)?
                .ok_or(SplitTrustStoreError::Unavailable)?;
        let snapshot = decode_index(&snapshot_bytes, AUTHORITY_KIND)?;
        let snapshot_receipts = snapshot_root.join("receipts");
        self.with_store_lock(|paths| {
            let (mut authority, continuity) = match load_indexes(paths)? {
                LoadedIndexes::Empty => return Err(SplitTrustStoreError::Corrupt),
                LoadedIndexes::AnchorOnly { continuity } => (
                    IndexDocument::new(AUTHORITY_KIND, continuity.authority_id)
                        .with_generation(continuity.generation),
                    continuity,
                ),
                LoadedIndexes::Ready {
                    authority,
                    continuity,
                } => (authority, continuity),
            };
            if snapshot.authority_id != continuity.authority_id
                || snapshot.authority_id != authority.authority_id
            {
                return Err(SplitTrustStoreError::Corrupt);
            }
            if snapshot.generation > authority.generation {
                return Err(SplitTrustStoreError::Corrupt);
            }
            let mut restore = SplitTrustRestore {
                restored_entries: 0,
                preserved_revocations: 0,
            };
            let mut pending_receipts = Vec::new();
            for (key, entry) in &snapshot.receipts {
                let manifest =
                    Sha256Digest::parse_hex(key).map_err(|_| SplitTrustStoreError::Corrupt)?;
                let replace = match authority.receipts.get(key).copied() {
                    None => true,
                    Some(current) => {
                        if current.state == IndexState::Revoked
                            && entry.state != IndexState::Revoked
                        {
                            restore.preserved_revocations += 1;
                            false
                        } else {
                            entry.revision > current.revision
                                || (entry.revision == current.revision
                                    && entry.state == IndexState::Revoked)
                        }
                    }
                };
                if !replace {
                    continue;
                }
                if entry.revision > snapshot.generation {
                    return Err(SplitTrustStoreError::Corrupt);
                }
                let source = read_bounded_state_file(
                    &receipt_path(&snapshot_receipts, &manifest),
                    MAX_RECEIPT_BYTES,
                )?;
                let bytes = match (entry.state, source) {
                    (IndexState::Issued, Some(bytes)) => {
                        let receipt =
                            decode_receipt(&bytes, &manifest, Some(&authority.authority_id))?
                                .ok_or(SplitTrustStoreError::Corrupt)?;
                        if receipt.predecessor_revision() != entry.revision || receipt.is_revoked()
                        {
                            return Err(SplitTrustStoreError::Corrupt);
                        }
                        bytes
                    }
                    (IndexState::Issued, None) => return Err(SplitTrustStoreError::Corrupt),
                    (IndexState::Revoked, Some(bytes)) => {
                        let receipt =
                            decode_receipt(&bytes, &manifest, Some(&authority.authority_id))?
                                .ok_or(SplitTrustStoreError::Corrupt)?;
                        if receipt.predecessor_revision() != entry.revision || !receipt.is_revoked()
                        {
                            return Err(SplitTrustStoreError::Corrupt);
                        }
                        bytes
                    }
                    (IndexState::Revoked, None) => encode_receipt(
                        &revoked_tombstone(&manifest, entry.revision),
                        entry.revision,
                        &authority.authority_id,
                    )?,
                };
                pending_receipts.push((
                    key.clone(),
                    *entry,
                    receipt_path(&paths.receipts, &manifest),
                    bytes,
                ));
            }
            if pending_receipts.is_empty() && restore.preserved_revocations == 0 {
                return Ok(restore);
            }
            if pending_receipts.is_empty() {
                authority.advance_generation()?;
                commit_indexes(paths, &authority, None)?;
                return Ok(restore);
            }
            // Commit each restored receipt with its matching index update. A
            // crash between entries leaves the store consistent and lets a
            // later restoration resume the remaining receipts.
            for (key, entry, path, bytes) in &pending_receipts {
                authority.receipts.insert(key.clone(), *entry);
                authority.advance_generation()?;
                commit_indexes(paths, &authority, Some((path.as_path(), bytes.as_slice())))?;
                restore.restored_entries += 1;
            }
            Ok(restore)
        })
    }
}

impl SplitTrustStore for LocalSplitTrustStore {
    fn lookup(
        &self,
        manifest_sha256: &Sha256Digest,
    ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
        self.read_receipt(manifest_sha256)
    }
}

impl SplitTrustWriter for LocalSplitTrustStore {
    fn issue(&self, receipt: SplitTrustReceipt) -> Result<(), SplitTrustStoreError> {
        self.with_store_lock(|paths| {
            let (mut authority, continuity) = load_or_initialize_indexes(paths)?;
            let manifest = *receipt.manifest_sha256();
            let current = continuity.entry(&manifest).copied().unwrap_or(IndexEntry {
                revision: 0,
                state: IndexState::Issued,
            });
            if receipt.predecessor_revision() != current.revision {
                return Err(SplitTrustStoreError::StaleEvidence);
            }
            let revision = current
                .revision
                .checked_add(1)
                .ok_or(SplitTrustStoreError::Corrupt)?;
            let path = receipt_path(&paths.receipts, &manifest);
            let bytes = encode_receipt(&receipt, revision, &authority.authority_id)?;
            let state = if receipt.is_revoked() {
                IndexState::Revoked
            } else {
                IndexState::Issued
            };
            authority.upsert(&manifest, revision, state);
            authority.advance_generation()?;
            commit_indexes(paths, &authority, Some((&path, &bytes)))
        })
    }

    fn revoke(&self, manifest_sha256: &Sha256Digest) -> Result<(), SplitTrustStoreError> {
        self.with_store_lock(|paths| {
            let (mut authority, continuity) = load_or_initialize_indexes(paths)?;
            let current = continuity
                .entry(manifest_sha256)
                .copied()
                .unwrap_or(IndexEntry {
                    revision: 0,
                    state: IndexState::Issued,
                });
            if current.state == IndexState::Revoked {
                return Ok(());
            }
            let revision = current
                .revision
                .checked_add(1)
                .ok_or(SplitTrustStoreError::Corrupt)?;
            let path = receipt_path(&paths.receipts, manifest_sha256);
            let existing =
                read_receipt_file(&path, manifest_sha256, Some(&authority.authority_id))?;
            if let Some(existing) = &existing
                && (existing.predecessor_revision() != current.revision || existing.is_revoked())
            {
                return Err(SplitTrustStoreError::Corrupt);
            }
            let receipt = existing
                .unwrap_or_else(|| {
                    SplitTrustReceipt::new(
                        *manifest_sha256,
                        0,
                        Sha256Digest::from_bytes([0_u8; 32]),
                    )
                })
                .with_revoked(true);
            let bytes = encode_receipt(&receipt, revision, &authority.authority_id)?;
            authority.upsert(manifest_sha256, revision, IndexState::Revoked);
            authority.advance_generation()?;
            commit_indexes(paths, &authority, Some((&path, &bytes)))
        })
    }
}

fn load_indexes(paths: &StorePaths) -> Result<LoadedIndexes, SplitTrustStoreError> {
    let (authority, continuity) = read_index_pair(paths)?;
    match (authority, continuity) {
        (None, None) => Ok(LoadedIndexes::Empty),
        (Some(authority), Some(continuity)) => {
            if !authority.same_authority_and_contents(&continuity) {
                return Err(SplitTrustStoreError::Corrupt);
            }
            Ok(LoadedIndexes::Ready {
                authority,
                continuity,
            })
        }
        (None, Some(continuity)) => Ok(LoadedIndexes::AnchorOnly { continuity }),
        (Some(_), None) => Err(SplitTrustStoreError::Corrupt),
    }
}

fn read_index_pair(
    paths: &StorePaths,
) -> Result<(Option<IndexDocument>, Option<IndexDocument>), SplitTrustStoreError> {
    Ok((
        read_index_file(&paths.authority, AUTHORITY_KIND)?,
        read_index_file(&paths.continuity, CONTINUITY_KIND)?,
    ))
}

fn load_or_initialize_indexes(
    paths: &StorePaths,
) -> Result<(IndexDocument, IndexDocument), SplitTrustStoreError> {
    match load_indexes(paths)? {
        LoadedIndexes::Ready {
            authority,
            continuity,
        } => Ok((authority, continuity)),
        LoadedIndexes::AnchorOnly { .. } => Err(SplitTrustStoreError::Corrupt),
        LoadedIndexes::Empty => {
            let authority = IndexDocument::new(AUTHORITY_KIND, new_authority_id());
            commit_indexes(paths, &authority, None)?;
            let mut continuity = authority.clone();
            continuity.kind = CONTINUITY_KIND;
            Ok((authority, continuity))
        }
    }
}

fn read_index_file(
    path: &Path,
    expected_kind: &'static str,
) -> Result<Option<IndexDocument>, SplitTrustStoreError> {
    match read_bounded_state_file(path, MAX_INDEX_BYTES)? {
        Some(bytes) => decode_index(&bytes, expected_kind).map(Some),
        None => Ok(None),
    }
}

fn write_index_pair(
    paths: &StorePaths,
    authority: &IndexDocument,
) -> Result<(), SplitTrustStoreError> {
    let mut continuity = authority.clone();
    continuity.kind = CONTINUITY_KIND;
    atomic_write(&paths.authority, &encode_index(authority)?)?;
    atomic_write(&paths.continuity, &encode_index(&continuity)?)
}

fn commit_indexes(
    paths: &StorePaths,
    authority: &IndexDocument,
    receipt: Option<(&Path, &[u8])>,
) -> Result<(), SplitTrustStoreError> {
    let journal = encode_commit(authority, receipt)?;
    atomic_write(&paths.pending, &journal)?;
    if let Some((path, bytes)) = receipt {
        atomic_write(path, bytes)?;
    }
    write_index_pair(paths, authority)?;
    remove_pending(paths)
}

fn remove_pending(paths: &StorePaths) -> Result<(), SplitTrustStoreError> {
    match fs::remove_file(&paths.pending) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(SplitTrustStoreError::Unavailable),
    }
    sync_directory(&paths.root).map_err(|_| SplitTrustStoreError::Unavailable)
}

fn recover_pending_commit(paths: &StorePaths) -> Result<(), SplitTrustStoreError> {
    let Some(bytes) = read_bounded_state_file(&paths.pending, MAX_COMMIT_BYTES)? else {
        return Ok(());
    };
    let (authority, receipt) = decode_commit(&bytes)?;
    let (existing, _) = read_index_pair(paths)?;
    if let Some(existing) = existing {
        if existing.authority_id != authority.authority_id {
            return Err(SplitTrustStoreError::Corrupt);
        }
        if existing.generation > authority.generation {
            return remove_pending(paths);
        }
    }
    if let Some((file_name, contents)) = receipt {
        let manifest = manifest_from_file_name(&file_name)?;
        let path = receipt_path(&paths.receipts, &manifest);
        if path.file_name().and_then(OsStr::to_str) != Some(file_name.as_str()) {
            return Err(SplitTrustStoreError::Corrupt);
        }
        let receipt = decode_receipt(&contents, &manifest, Some(&authority.authority_id))?
            .ok_or(SplitTrustStoreError::Corrupt)?;
        let entry = authority
            .entry(&manifest)
            .copied()
            .ok_or(SplitTrustStoreError::Corrupt)?;
        if receipt.predecessor_revision() != entry.revision
            || receipt.is_revoked() != (entry.state == IndexState::Revoked)
        {
            return Err(SplitTrustStoreError::Corrupt);
        }
        atomic_write(&path, &contents)?;
    }
    write_index_pair(paths, &authority)?;
    remove_pending(paths)
}

fn revoked_tombstone(manifest_sha256: &Sha256Digest, revision: u64) -> SplitTrustReceipt {
    SplitTrustReceipt::new(*manifest_sha256, 0, Sha256Digest::from_bytes([0_u8; 32]))
        .with_revoked(true)
        .with_predecessor_revision(revision)
}

fn manifest_from_file_name(name: &str) -> Result<Sha256Digest, SplitTrustStoreError> {
    let stem = name
        .strip_suffix(".json")
        .ok_or(SplitTrustStoreError::Corrupt)?;
    Sha256Digest::parse_hex(stem).map_err(|_| SplitTrustStoreError::Corrupt)
}

fn state_file_exists(path: &Path) -> Result<bool, SplitTrustStoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(SplitTrustStoreError::Unavailable),
    }
}

fn lock_matches_path(lock: &File, path: &Path) -> Result<bool, SplitTrustStoreError> {
    let Some(identity) = handle_identity(lock) else {
        return Err(SplitTrustStoreError::Corrupt);
    };
    Ok(path_identity(path) == Some(identity))
}

fn continuity_file(root: &Path) -> Result<PathBuf, SplitTrustStoreError> {
    let name = root
        .file_name()
        .ok_or(SplitTrustStoreError::ConfigurationInvalid)?;
    let parent = root
        .parent()
        .ok_or(SplitTrustStoreError::ConfigurationInvalid)?;
    let mut file_name = name.to_os_string();
    file_name.push("-continuity.json");
    Ok(parent.join(file_name))
}

fn new_authority_id() -> Sha256Digest {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let mut material = Vec::with_capacity(64);
    for _ in 0..2 {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u32(std::process::id());
        hasher.write_u128(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos()),
        );
        hasher.write_u64(NEXT_TEMP.fetch_add(1, Ordering::Relaxed));
        material.extend_from_slice(&hasher.finish().to_le_bytes());
    }
    material.extend_from_slice(b"nscb split trust authority");
    Sha256Digest::digest(&material)
}

fn create_dir_all_durable(path: &Path) -> Result<(), SplitTrustStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(SplitTrustStoreError::Corrupt);
            }
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(SplitTrustStoreError::Unavailable),
    }

    let mut missing = Vec::new();
    let mut current = Some(path);
    while let Some(candidate) = current {
        match fs::symlink_metadata(candidate) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                    return Err(SplitTrustStoreError::Corrupt);
                }
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(candidate.to_path_buf());
                current = candidate.parent();
            }
            Err(_) => return Err(SplitTrustStoreError::Unavailable),
        }
    }

    for directory in missing.iter().rev() {
        match fs::create_dir(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(directory)
                    .map_err(|_| SplitTrustStoreError::Unavailable)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(SplitTrustStoreError::Corrupt);
                }
                continue;
            }
            Err(_) => return Err(SplitTrustStoreError::Unavailable),
        }
        sync_directory(directory).map_err(|_| SplitTrustStoreError::Unavailable)?;
        if let Some(parent) = directory.parent() {
            sync_directory(parent).map_err(|_| SplitTrustStoreError::Unavailable)?;
        }
    }
    Ok(())
}

fn receipt_path(directory: &Path, manifest_sha256: &Sha256Digest) -> PathBuf {
    directory.join(format!("{}.json", manifest_sha256.to_hex()))
}

fn validate_store_directory(path: &Path) -> Result<bool, SplitTrustStoreError> {
    let link_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(SplitTrustStoreError::Unavailable),
    };
    if link_metadata.file_type().is_symlink() || !link_metadata.file_type().is_dir() {
        return Err(SplitTrustStoreError::Corrupt);
    }
    let expected_identity = path_identity(path).ok_or(SplitTrustStoreError::Corrupt)?;
    if followed_path_identity(path) != Some(expected_identity) {
        return Err(SplitTrustStoreError::Corrupt);
    }
    Ok(true)
}

fn open_lock_file(path: &Path) -> Result<File, SplitTrustStoreError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000);
    }
    let file = options
        .open(path)
        .map_err(|_| SplitTrustStoreError::Unavailable)?;
    if !file
        .metadata()
        .map_err(|_| SplitTrustStoreError::Unavailable)?
        .is_file()
    {
        return Err(SplitTrustStoreError::Unavailable);
    }
    Ok(file)
}

fn read_receipt_file(
    path: &Path,
    manifest_sha256: &Sha256Digest,
    expected_authority: Option<&Sha256Digest>,
) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
    match read_bounded_state_file(path, MAX_RECEIPT_BYTES)? {
        Some(bytes) => decode_receipt(&bytes, manifest_sha256, expected_authority),
        None => Ok(None),
    }
}

/// Reads one bounded regular state file without following a final symlink.
///
/// Returns `Ok(None)` when the path does not exist. The opened handle must
/// describe the same file as the path before opening and after reading, so a
/// replacement between inspection and reading, or while the file is being
/// read, fails closed.
fn read_bounded_state_file(
    path: &Path,
    max_bytes: u64,
) -> Result<Option<Vec<u8>>, SplitTrustStoreError> {
    let link_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(SplitTrustStoreError::Unavailable),
    };
    if link_metadata.file_type().is_symlink() || !link_metadata.file_type().is_file() {
        return Err(SplitTrustStoreError::Corrupt);
    }
    if link_metadata.len() > max_bytes {
        return Err(SplitTrustStoreError::Corrupt);
    }
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
        options.custom_flags(0x0020_0000);
    }
    let file = options
        .open(path)
        .map_err(|_| SplitTrustStoreError::Unavailable)?;
    let handle_metadata = file
        .metadata()
        .map_err(|_| SplitTrustStoreError::Unavailable)?;
    let Some(identity) = handle_identity(&file) else {
        return Err(SplitTrustStoreError::Corrupt);
    };
    if !handle_metadata.file_type().is_file() || path_identity(path) != Some(identity) {
        return Err(SplitTrustStoreError::Corrupt);
    }
    let mut bytes = Vec::with_capacity(link_metadata.len() as usize);
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SplitTrustStoreError::Unavailable)?;
    if bytes.len() as u64 > max_bytes {
        return Err(SplitTrustStoreError::Corrupt);
    }
    if path_identity(path) != Some(identity) {
        return Err(SplitTrustStoreError::Corrupt);
    }
    Ok(Some(bytes))
}

#[derive(Serialize)]
struct ReceiptDocument<'a> {
    schema_version: u8,
    kind: &'static str,
    manifest_sha256: &'a Sha256Digest,
    authority_id: &'a Sha256Digest,
    source: ReceiptSource<'a>,
    state: &'static str,
    revision: u64,
}

#[derive(Serialize)]
struct ReceiptSource<'a> {
    size_bytes: u64,
    sha256: &'a Sha256Digest,
}

fn encode_receipt(
    receipt: &SplitTrustReceipt,
    revision: u64,
    authority_id: &Sha256Digest,
) -> Result<Vec<u8>, SplitTrustStoreError> {
    let document = ReceiptDocument {
        schema_version: RECEIPT_SCHEMA_VERSION,
        kind: RECEIPT_KIND,
        manifest_sha256: receipt.manifest_sha256(),
        authority_id,
        source: ReceiptSource {
            size_bytes: receipt.source_size_bytes(),
            sha256: receipt.source_sha256(),
        },
        state: if receipt.is_revoked() {
            "revoked"
        } else {
            "issued"
        },
        revision,
    };
    let mut bytes = serde_json::to_vec(&document).map_err(|_| SplitTrustStoreError::Corrupt)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn decode_receipt(
    bytes: &[u8],
    expected_manifest: &Sha256Digest,
    expected_authority: Option<&Sha256Digest>,
) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
    let document = strict_json::parse(bytes).map_err(|_| SplitTrustStoreError::Corrupt)?;
    let StrictJsonValue::Object(fields) = document else {
        return Err(SplitTrustStoreError::Corrupt);
    };
    reject_unknown_fields(
        &fields,
        &[
            "schema_version",
            "kind",
            "manifest_sha256",
            "authority_id",
            "source",
            "state",
            "revision",
        ],
    )?;
    match strict_json::required_field(&fields, "schema_version") {
        Some(StrictJsonValue::Number(number)) if number.as_u64() == Some(1) => {}
        _ => return Err(SplitTrustStoreError::Corrupt),
    }
    match strict_json::required_field(&fields, "kind") {
        Some(StrictJsonValue::String(kind)) if kind == RECEIPT_KIND => {}
        _ => return Err(SplitTrustStoreError::Corrupt),
    }
    let manifest_sha256 = required_digest(&fields, "manifest_sha256")?;
    if manifest_sha256 != *expected_manifest {
        return Err(SplitTrustStoreError::Corrupt);
    }
    let authority_id = required_digest(&fields, "authority_id")?;
    if let Some(expected) = expected_authority
        && authority_id != *expected
    {
        return Err(SplitTrustStoreError::Corrupt);
    }
    let StrictJsonValue::Object(source_fields) =
        strict_json::required_field(&fields, "source").ok_or(SplitTrustStoreError::Corrupt)?
    else {
        return Err(SplitTrustStoreError::Corrupt);
    };
    reject_unknown_fields(source_fields, &["size_bytes", "sha256"])?;
    let source_size_bytes = match strict_json::required_field(source_fields, "size_bytes") {
        Some(StrictJsonValue::Number(number)) => {
            number.as_u64().ok_or(SplitTrustStoreError::Corrupt)?
        }
        _ => return Err(SplitTrustStoreError::Corrupt),
    };
    let source_sha256 = required_digest(source_fields, "sha256")?;
    let revoked = match strict_json::required_field(&fields, "state") {
        Some(StrictJsonValue::String(state)) if state == "issued" => false,
        Some(StrictJsonValue::String(state)) if state == "revoked" => true,
        _ => return Err(SplitTrustStoreError::Corrupt),
    };
    let revision = match strict_json::required_field(&fields, "revision") {
        Some(StrictJsonValue::Number(number)) => number
            .as_u64()
            .filter(|revision| *revision >= 1)
            .ok_or(SplitTrustStoreError::Corrupt)?,
        _ => return Err(SplitTrustStoreError::Corrupt),
    };
    Ok(Some(
        SplitTrustReceipt::new(manifest_sha256, source_size_bytes, source_sha256)
            .with_revoked(revoked)
            .with_predecessor_revision(revision),
    ))
}

/// Rejects fields that are not part of the decoded schema version.
fn reject_unknown_fields(
    fields: &[(String, StrictJsonValue)],
    allowed: &[&str],
) -> Result<(), SplitTrustStoreError> {
    if fields
        .iter()
        .any(|(name, _)| !allowed.contains(&name.as_str()))
    {
        return Err(SplitTrustStoreError::Corrupt);
    }
    Ok(())
}

fn required_digest(
    fields: &[(String, StrictJsonValue)],
    name: &str,
) -> Result<Sha256Digest, SplitTrustStoreError> {
    match strict_json::required_field(fields, name) {
        Some(StrictJsonValue::String(value)) => {
            Sha256Digest::parse_hex(value).map_err(|_| SplitTrustStoreError::Corrupt)
        }
        _ => Err(SplitTrustStoreError::Corrupt),
    }
}

fn encode_index(document: &IndexDocument) -> Result<Vec<u8>, SplitTrustStoreError> {
    if document.schema_version != AUTHORITY_SCHEMA_VERSION
        || (document.kind != AUTHORITY_KIND && document.kind != CONTINUITY_KIND)
        || document.receipts.len() > MAX_INDEX_ENTRIES
    {
        return Err(SplitTrustStoreError::Corrupt);
    }
    let mut bytes = serde_json::to_vec(document).map_err(|_| SplitTrustStoreError::Corrupt)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_INDEX_BYTES {
        return Err(SplitTrustStoreError::Corrupt);
    }
    Ok(bytes)
}

fn decode_index(
    bytes: &[u8],
    expected_kind: &'static str,
) -> Result<IndexDocument, SplitTrustStoreError> {
    let document = strict_json::parse(bytes).map_err(|_| SplitTrustStoreError::Corrupt)?;
    decode_index_value(&document, expected_kind)
}

fn decode_index_value(
    document: &StrictJsonValue,
    expected_kind: &'static str,
) -> Result<IndexDocument, SplitTrustStoreError> {
    let StrictJsonValue::Object(fields) = document else {
        return Err(SplitTrustStoreError::Corrupt);
    };
    reject_unknown_fields(
        fields,
        &[
            "schema_version",
            "kind",
            "authority_id",
            "generation",
            "receipts",
        ],
    )?;
    match strict_json::required_field(fields, "schema_version") {
        Some(StrictJsonValue::Number(number))
            if number.as_u64() == Some(u64::from(AUTHORITY_SCHEMA_VERSION)) => {}
        _ => return Err(SplitTrustStoreError::Corrupt),
    }
    match strict_json::required_field(fields, "kind") {
        Some(StrictJsonValue::String(kind)) if kind == expected_kind => {}
        _ => return Err(SplitTrustStoreError::Corrupt),
    }
    let authority_id = required_digest(fields, "authority_id")?;
    let generation = match strict_json::required_field(fields, "generation") {
        Some(StrictJsonValue::Number(number)) => {
            number.as_u64().ok_or(SplitTrustStoreError::Corrupt)?
        }
        _ => return Err(SplitTrustStoreError::Corrupt),
    };
    let StrictJsonValue::Object(entry_fields) =
        strict_json::required_field(fields, "receipts").ok_or(SplitTrustStoreError::Corrupt)?
    else {
        return Err(SplitTrustStoreError::Corrupt);
    };
    if entry_fields.len() > MAX_INDEX_ENTRIES {
        return Err(SplitTrustStoreError::Corrupt);
    }
    let mut receipts = BTreeMap::new();
    for (key, value) in entry_fields {
        let manifest = Sha256Digest::parse_hex(key).map_err(|_| SplitTrustStoreError::Corrupt)?;
        if manifest.to_hex() != *key {
            return Err(SplitTrustStoreError::Corrupt);
        }
        let StrictJsonValue::Object(fields) = value else {
            return Err(SplitTrustStoreError::Corrupt);
        };
        reject_unknown_fields(fields, &["revision", "state"])?;
        let revision = match strict_json::required_field(fields, "revision") {
            Some(StrictJsonValue::Number(number)) => number
                .as_u64()
                .filter(|revision| *revision >= 1 && *revision <= generation)
                .ok_or(SplitTrustStoreError::Corrupt)?,
            _ => return Err(SplitTrustStoreError::Corrupt),
        };
        let state = match strict_json::required_field(fields, "state") {
            Some(StrictJsonValue::String(state)) if state == "issued" => IndexState::Issued,
            Some(StrictJsonValue::String(state)) if state == "revoked" => IndexState::Revoked,
            _ => return Err(SplitTrustStoreError::Corrupt),
        };
        receipts.insert(key.clone(), IndexEntry { revision, state });
    }
    Ok(IndexDocument {
        schema_version: AUTHORITY_SCHEMA_VERSION,
        kind: expected_kind,
        authority_id,
        generation,
        receipts,
    })
}

#[derive(Serialize)]
struct CommitDocument<'a> {
    schema_version: u8,
    kind: &'static str,
    authority: &'a IndexDocument,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt: Option<CommitReceipt<'a>>,
}

#[derive(Serialize)]
struct CommitReceipt<'a> {
    file_name: &'a str,
    contents: &'a str,
}

fn encode_commit(
    authority: &IndexDocument,
    receipt: Option<(&Path, &[u8])>,
) -> Result<Vec<u8>, SplitTrustStoreError> {
    let receipt = match receipt {
        Some((path, bytes)) => {
            let file_name = path
                .file_name()
                .and_then(OsStr::to_str)
                .ok_or(SplitTrustStoreError::Corrupt)?;
            let contents = std::str::from_utf8(bytes).map_err(|_| SplitTrustStoreError::Corrupt)?;
            Some(CommitReceipt {
                file_name,
                contents,
            })
        }
        None => None,
    };
    let document = CommitDocument {
        schema_version: COMMIT_SCHEMA_VERSION,
        kind: COMMIT_KIND,
        authority,
        receipt,
    };
    let mut bytes = serde_json::to_vec(&document).map_err(|_| SplitTrustStoreError::Corrupt)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_COMMIT_BYTES {
        return Err(SplitTrustStoreError::Corrupt);
    }
    Ok(bytes)
}

type DecodedCommit = (IndexDocument, Option<(String, Vec<u8>)>);

fn decode_commit(bytes: &[u8]) -> Result<DecodedCommit, SplitTrustStoreError> {
    let document = strict_json::parse(bytes).map_err(|_| SplitTrustStoreError::Corrupt)?;
    let StrictJsonValue::Object(fields) = document else {
        return Err(SplitTrustStoreError::Corrupt);
    };
    reject_unknown_fields(&fields, &["schema_version", "kind", "authority", "receipt"])?;
    match strict_json::required_field(&fields, "schema_version") {
        Some(StrictJsonValue::Number(number))
            if number.as_u64() == Some(u64::from(COMMIT_SCHEMA_VERSION)) => {}
        _ => return Err(SplitTrustStoreError::Corrupt),
    }
    match strict_json::required_field(&fields, "kind") {
        Some(StrictJsonValue::String(kind)) if kind == COMMIT_KIND => {}
        _ => return Err(SplitTrustStoreError::Corrupt),
    }
    let authority = decode_index_value(
        strict_json::required_field(&fields, "authority").ok_or(SplitTrustStoreError::Corrupt)?,
        AUTHORITY_KIND,
    )?;
    let receipt = match strict_json::required_field(&fields, "receipt") {
        None | Some(StrictJsonValue::Null) => None,
        Some(StrictJsonValue::Object(receipt_fields)) => {
            reject_unknown_fields(receipt_fields, &["file_name", "contents"])?;
            let file_name = match strict_json::required_field(receipt_fields, "file_name") {
                Some(StrictJsonValue::String(name)) => name.clone(),
                _ => return Err(SplitTrustStoreError::Corrupt),
            };
            let contents = match strict_json::required_field(receipt_fields, "contents") {
                Some(StrictJsonValue::String(contents)) => contents.clone().into_bytes(),
                _ => return Err(SplitTrustStoreError::Corrupt),
            };
            Some((file_name, contents))
        }
        _ => return Err(SplitTrustStoreError::Corrupt),
    };
    Ok((authority, receipt))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), SplitTrustStoreError> {
    let parent = path.parent().ok_or(SplitTrustStoreError::Corrupt)?;
    let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let temp = parent.join(format!(
        ".{}.{}.{}.{}.tmp",
        path.file_name()
            .and_then(OsStr::to_str)
            .unwrap_or("receipt"),
        std::process::id(),
        nonce,
        sequence
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options
            .open(&temp)
            .map_err(|_| SplitTrustStoreError::Unavailable)?;
        file.write_all(bytes)
            .map_err(|_| SplitTrustStoreError::Unavailable)?;
        file.sync_all()
            .map_err(|_| SplitTrustStoreError::Unavailable)?;
        drop(file);
        replace_file(&temp, path).map_err(|_| SplitTrustStoreError::Unavailable)?;
        sync_directory(parent).map_err(|_| SplitTrustStoreError::Unavailable)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

/// Atomically replaces an existing receipt on Windows.
///
/// `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING` keeps replacement atomic, and
/// `MOVEFILE_WRITE_THROUGH` requests durability before the call returns so a
/// committed revocation survives a subsequent crash.
#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: both paths are NUL-terminated UTF-16 buffers that outlive the call.
    let replaced = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if replaced == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn state_root_from_environment() -> StateRoot {
    state_root_from(
        std::env::var_os(STATE_DIRECTORY_ENV).as_deref(),
        std::env::var_os("XDG_STATE_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
        std::env::var_os("LOCALAPPDATA").as_deref(),
    )
}

fn state_root_from(
    explicit: Option<&OsStr>,
    xdg_state_home: Option<&OsStr>,
    home: Option<&OsStr>,
    _local_app_data: Option<&OsStr>,
) -> StateRoot {
    if let Some(explicit) = explicit {
        let path = Path::new(explicit);
        if explicit.is_empty() || !path.is_absolute() {
            return StateRoot::InvalidConfiguration;
        }
        return StateRoot::Configured(path.join("split-trust"));
    }

    #[cfg(unix)]
    if let Some(xdg_state_home) = xdg_state_home.map(Path::new)
        && xdg_state_home.is_absolute()
    {
        return StateRoot::Configured(xdg_state_home.join("nscb").join("split-trust"));
    }

    #[cfg(windows)]
    {
        let _ = (xdg_state_home, home);
        let Some(local_app_data) = _local_app_data.map(Path::new) else {
            return StateRoot::Missing;
        };
        if !local_app_data.is_absolute() {
            return StateRoot::Missing;
        }
        return StateRoot::Configured(local_app_data.join("nscb").join("split-trust"));
    }

    #[cfg(target_os = "macos")]
    {
        let Some(home) = home.map(Path::new) else {
            return StateRoot::Missing;
        };
        if !home.is_absolute() {
            return StateRoot::Missing;
        }
        return StateRoot::Configured(
            home.join("Library")
                .join("Application Support")
                .join("nscb")
                .join("split-trust"),
        );
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let Some(home) = home.map(Path::new) else {
            return StateRoot::Missing;
        };
        if !home.is_absolute() {
            return StateRoot::Missing;
        }
        return StateRoot::Configured(
            home.join(".local")
                .join("state")
                .join("nscb")
                .join("split-trust"),
        );
    }

    #[allow(unreachable_code)]
    StateRoot::Missing
}

pub(crate) fn trust_store_error(error: SplitTrustStoreError) -> InputResolutionError {
    let code = match error {
        SplitTrustStoreError::ConfigurationInvalid => {
            InputResolutionErrorCode::SplitTrustStoreConfigurationInvalid
        }
        SplitTrustStoreError::Unavailable
        | SplitTrustStoreError::Corrupt
        | SplitTrustStoreError::StaleEvidence => InputResolutionErrorCode::SplitStateUnavailable,
    };
    InputResolutionError::new(code)
}

#[cfg(test)]
mod tests {
    use super::{
        LocalSplitTrustStore, SplitTrustReceipt, SplitTrustStore, SplitTrustStoreError,
        SplitTrustWriter, StateRoot, state_root_from,
    };
    use crate::sha256::Sha256Digest;
    use std::ffi::OsStr;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn temp_root() -> PathBuf {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("nscb-trust-test-{}-{id}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        let _ = fs::remove_file(super::continuity_file(&path).unwrap());
        path
    }

    fn remove_store(root: &Path) {
        let continuity = super::continuity_file(root).unwrap();
        fs::remove_dir_all(root).unwrap();
        let _ = fs::remove_file(continuity);
    }

    fn copy_tree(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    #[test]
    fn issue_lookup_revoke_and_missing_store_are_distinct() {
        let root = temp_root();
        let store = LocalSplitTrustStore::new(&root);
        let manifest = Sha256Digest::digest(b"manifest");
        let source = Sha256Digest::digest(b"source");
        assert_eq!(store.lookup(&manifest).unwrap(), None);
        let receipt = SplitTrustReceipt::new(manifest, 6, source);
        store.issue(receipt).unwrap();
        let issued = store.lookup(&manifest).unwrap().unwrap();
        assert!(!issued.is_revoked());
        assert_eq!(issued.predecessor_revision(), 1);

        store.revoke(&manifest).unwrap();
        let revoked = store.lookup(&manifest).unwrap().unwrap();
        assert!(revoked.is_revoked());
        assert_eq!(revoked.predecessor_revision(), 2);

        let stale = SplitTrustReceipt::new(manifest, 6, source);
        assert_eq!(
            store.issue(stale).unwrap_err(),
            SplitTrustStoreError::StaleEvidence
        );
        assert!(store.lookup(&manifest).unwrap().unwrap().is_revoked());

        let requalified = SplitTrustReceipt::new(manifest, 6, source)
            .with_predecessor_revision(revoked.predecessor_revision());
        store.issue(requalified).unwrap();
        assert!(!store.lookup(&manifest).unwrap().unwrap().is_revoked());
        remove_store(&root);
    }

    #[test]
    fn revoking_an_unknown_manifest_records_a_durable_tombstone() {
        let root = temp_root();
        let store = LocalSplitTrustStore::new(&root);
        let manifest = Sha256Digest::digest(b"unknown manifest");
        store.revoke(&manifest).unwrap();
        let tombstone = store.lookup(&manifest).unwrap().unwrap();
        assert!(tombstone.is_revoked());
        assert_eq!(tombstone.predecessor_revision(), 1);
        assert_eq!(
            store
                .issue(SplitTrustReceipt::new(
                    manifest,
                    0,
                    Sha256Digest::digest(b"source"),
                ))
                .unwrap_err(),
            SplitTrustStoreError::StaleEvidence
        );
        assert!(store.lookup(&manifest).unwrap().unwrap().is_revoked());
        remove_store(&root);
    }

    #[test]
    fn concurrent_issuance_and_revocation_leave_a_decodable_revision() {
        let root = temp_root();
        let store = Arc::new(LocalSplitTrustStore::new(&root));
        let manifest = Sha256Digest::digest(b"concurrent manifest");
        let source = Sha256Digest::digest(b"concurrent source");
        store
            .issue(SplitTrustReceipt::new(manifest, 17, source))
            .unwrap();

        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for worker in 0..8 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..20 {
                    let current = store.lookup(&manifest).unwrap().unwrap();
                    let candidate = SplitTrustReceipt::new(manifest, 17, source)
                        .with_predecessor_revision(current.predecessor_revision());
                    // Concurrent writers win or lose the revision check; both
                    // outcomes must leave a complete, decodable record.
                    match store.issue(candidate) {
                        Ok(()) | Err(SplitTrustStoreError::StaleEvidence) => {}
                        Err(error) => panic!("unexpected concurrent issuance result: {error:?}"),
                    }
                    if worker % 2 == 0 {
                        store.revoke(&manifest).unwrap();
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        let final_receipt = store.lookup(&manifest).unwrap().unwrap();
        assert!(final_receipt.predecessor_revision() >= 1);
        remove_store(&root);
    }

    #[test]
    fn cross_process_stale_issuance_cannot_overwrite_revocation() {
        let root = temp_root();
        let store = LocalSplitTrustStore::new(&root);
        let manifest = Sha256Digest::digest(b"cross-process manifest");
        let source = Sha256Digest::digest(b"cross-process source");
        store
            .issue(SplitTrustReceipt::new(manifest, 23, source))
            .unwrap();

        let ready = root.join("worker-ready");
        let proceed = root.join("worker-proceed");
        let executable = std::env::current_exe().unwrap();
        let mut child = Command::new(executable)
            .args([
                "--ignored",
                "--exact",
                "split_trust::tests::cross_process_issuance_worker",
                "--test-threads=1",
            ])
            .env("NSCB_TRUST_PROCESS_ROOT", &root)
            .env("NSCB_TRUST_PROCESS_MANIFEST", manifest.to_hex())
            .env("NSCB_TRUST_PROCESS_READY", &ready)
            .env("NSCB_TRUST_PROCESS_PROCEED", &proceed)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        wait_for_path(&ready);
        store.revoke(&manifest).unwrap();
        fs::write(&proceed, b"go").unwrap();

        let status = wait_for_child(&mut child);
        assert!(status.success(), "cross-process issuance worker failed");

        let revoked = store.lookup(&manifest).unwrap().unwrap();
        assert!(revoked.is_revoked());
        assert_eq!(revoked.predecessor_revision(), 2);
        remove_store(&root);
    }

    #[test]
    #[ignore = "launched by cross_process_stale_issuance_cannot_overwrite_revocation"]
    fn cross_process_issuance_worker() {
        let Some(root) = std::env::var_os("NSCB_TRUST_PROCESS_ROOT") else {
            return;
        };
        let manifest = std::env::var("NSCB_TRUST_PROCESS_MANIFEST").unwrap();
        let manifest = Sha256Digest::parse_hex(&manifest).unwrap();
        let ready = PathBuf::from(std::env::var_os("NSCB_TRUST_PROCESS_READY").unwrap());
        let proceed = PathBuf::from(std::env::var_os("NSCB_TRUST_PROCESS_PROCEED").unwrap());
        fs::write(&ready, b"ready").unwrap();
        wait_for_path(&proceed);

        let store = LocalSplitTrustStore::new(root);
        let error = store
            .issue(
                SplitTrustReceipt::new(manifest, 23, Sha256Digest::digest(b"cross-process source"))
                    .with_predecessor_revision(1),
            )
            .unwrap_err();
        assert_eq!(error, SplitTrustStoreError::StaleEvidence);
    }

    #[test]
    fn cross_process_issue_and_revoke_contention_preserves_revocation() {
        for round in 0..8 {
            let base = temp_root();
            let root = base.join("store");
            let manifest = Sha256Digest::digest(format!("contended manifest {round}").as_bytes());
            let issue_ready = base.join("issue-ready");
            let issue_proceed = base.join("issue-proceed");
            let revoke_ready = base.join("revoke-ready");
            let revoke_proceed = base.join("revoke-proceed");

            let mut issue =
                spawn_contention_worker("issue", &root, manifest, &issue_ready, &issue_proceed);
            let mut revoke =
                spawn_contention_worker("revoke", &root, manifest, &revoke_ready, &revoke_proceed);
            wait_for_path(&issue_ready);
            wait_for_path(&revoke_ready);
            fs::write(&issue_proceed, b"go").unwrap();
            fs::write(&revoke_proceed, b"go").unwrap();

            assert!(wait_for_child(&mut issue).success(), "issue worker {round}");
            assert!(
                wait_for_child(&mut revoke).success(),
                "revoke worker {round}"
            );
            let receipt = LocalSplitTrustStore::new(&root)
                .lookup(&manifest)
                .unwrap()
                .expect("contended receipt");
            assert!(receipt.is_revoked(), "revocation lost in round {round}");
            assert!(receipt.predecessor_revision() >= 1);
            fs::remove_dir_all(base).unwrap();
        }
    }

    #[test]
    #[ignore = "launched by cross_process_issue_and_revoke_contention_preserves_revocation"]
    fn cross_process_contention_worker() {
        let Some(root) = std::env::var_os("NSCB_TRUST_PROCESS_ROOT") else {
            return;
        };
        let mode = std::env::var("NSCB_TRUST_PROCESS_MODE").unwrap();
        let manifest = std::env::var("NSCB_TRUST_PROCESS_MANIFEST").unwrap();
        let manifest = Sha256Digest::parse_hex(&manifest).unwrap();
        let ready = PathBuf::from(std::env::var_os("NSCB_TRUST_PROCESS_READY").unwrap());
        let proceed = PathBuf::from(std::env::var_os("NSCB_TRUST_PROCESS_PROCEED").unwrap());
        fs::write(&ready, b"ready").unwrap();
        wait_for_path(&proceed);

        let store = LocalSplitTrustStore::new(root);
        match mode.as_str() {
            "issue" => match store.issue(
                SplitTrustReceipt::new(manifest, 16, Sha256Digest::digest(b"contended source"))
                    .with_predecessor_revision(0),
            ) {
                Ok(()) | Err(SplitTrustStoreError::StaleEvidence) => {}
                Err(error) => panic!("unexpected issuance result: {error:?}"),
            },
            "revoke" => store.revoke(&manifest).unwrap(),
            other => panic!("unexpected worker mode: {other}"),
        }
    }

    #[test]
    fn dangling_and_indexed_corruption_fail_closed_but_valid_orphans_are_inert() {
        let root = temp_root();
        let store = LocalSplitTrustStore::new(&root);
        let manifest = Sha256Digest::digest(b"manifest");
        let path = root
            .join("receipts")
            .join(format!("{}.json", manifest.to_hex()));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"not json").unwrap();
        // An empty store cannot bind a receipt to an authority, so malformed
        // dangling state fails closed instead of being treated as untrusted.
        assert_eq!(
            store.lookup(&manifest).unwrap_err(),
            SplitTrustStoreError::Corrupt
        );
        store
            .issue(SplitTrustReceipt::new(
                manifest,
                5,
                Sha256Digest::digest(b"source"),
            ))
            .unwrap();

        // A well-formed receipt that no index names is inert.
        let orphan = Sha256Digest::digest(b"orphan manifest");
        let authority =
            super::read_index_file(&root.join(super::AUTHORITY_FILE), super::AUTHORITY_KIND)
                .unwrap()
                .unwrap();
        let orphan_bytes = super::encode_receipt(
            &SplitTrustReceipt::new(orphan, 3, Sha256Digest::digest(b"orphan source")),
            1,
            &authority.authority_id,
        )
        .unwrap();
        fs::write(
            root.join("receipts")
                .join(format!("{}.json", orphan.to_hex())),
            orphan_bytes,
        )
        .unwrap();
        assert_eq!(store.lookup(&orphan).unwrap(), None);

        fs::write(&path, b"not json").unwrap();
        assert_eq!(
            store.lookup(&manifest).unwrap_err(),
            SplitTrustStoreError::Corrupt
        );
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert_eq!(
            store.lookup(&manifest).unwrap_err(),
            SplitTrustStoreError::Corrupt
        );
        remove_store(&root);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_store_directories_fail_closed() {
        let base = temp_root();
        let outside = base.join("outside");
        fs::create_dir_all(&outside).unwrap();
        let configured = base.join("configured");
        std::os::unix::fs::symlink(&outside, &configured).unwrap();
        let manifest = Sha256Digest::digest(b"symlinked store manifest");
        let source = Sha256Digest::digest(b"symlinked store source");
        let store = LocalSplitTrustStore::new(&configured);

        assert_eq!(
            store.lookup(&manifest).unwrap_err(),
            SplitTrustStoreError::Corrupt
        );
        assert_eq!(
            store
                .issue(SplitTrustReceipt::new(manifest, 5, source))
                .unwrap_err(),
            SplitTrustStoreError::Corrupt
        );
        assert_eq!(
            store.revoke(&manifest).unwrap_err(),
            SplitTrustStoreError::Corrupt
        );

        fs::remove_file(&configured).unwrap();
        fs::create_dir(&configured).unwrap();
        std::os::unix::fs::symlink(&outside, configured.join("receipts")).unwrap();
        assert_eq!(
            store.lookup(&manifest).unwrap_err(),
            SplitTrustStoreError::Corrupt
        );
        assert_eq!(
            store
                .issue(SplitTrustReceipt::new(manifest, 5, source))
                .unwrap_err(),
            SplitTrustStoreError::Corrupt
        );
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn explicit_state_root_must_be_absolute() {
        assert!(matches!(
            state_root_from(Some(OsStr::new("relative")), None, None, None),
            StateRoot::InvalidConfiguration
        ));
        assert!(matches!(
            state_root_from(Some(OsStr::new("")), None, None, None),
            StateRoot::InvalidConfiguration
        ));
        let root = temp_root();
        let StateRoot::Configured(resolved) = state_root_from(
            Some(root.as_os_str()),
            None,
            Some(Path::new("/home/test").as_os_str()),
            None,
        ) else {
            panic!("configured");
        };
        assert_eq!(resolved, root.join("split-trust"));
        remove_store(&root);
    }

    #[cfg(unix)]
    #[test]
    fn absolute_xdg_state_home_wins_over_home() {
        let xdg = temp_root();
        let StateRoot::Configured(resolved) = state_root_from(
            None,
            Some(xdg.as_os_str()),
            Some(Path::new("/home/test").as_os_str()),
            None,
        ) else {
            panic!("configured");
        };
        assert_eq!(resolved, xdg.join("nscb").join("split-trust"));
        fs::remove_dir_all(xdg).unwrap();
    }

    #[test]
    fn missing_native_environment_is_unavailable_not_invalid_configuration() {
        assert!(matches!(
            state_root_from(None, None, None, None),
            StateRoot::Missing
        ));
    }

    #[test]
    fn copied_store_root_without_continuity_fails_closed() {
        let source_base = temp_root();
        let root = source_base.join("store");
        let store = LocalSplitTrustStore::new(&root);
        let manifest = Sha256Digest::digest(b"copied manifest");
        store
            .issue(SplitTrustReceipt::new(
                manifest,
                11,
                Sha256Digest::digest(b"copied source"),
            ))
            .unwrap();
        assert!(store.lookup(&manifest).unwrap().is_some());

        let copied_base = temp_root();
        let copied = copied_base.join("store");
        copy_tree(&root, &copied);
        let copied_store = LocalSplitTrustStore::new(&copied);
        assert_eq!(
            copied_store.lookup(&manifest).unwrap_err(),
            SplitTrustStoreError::Corrupt
        );
        assert_eq!(
            copied_store
                .issue(SplitTrustReceipt::new(
                    manifest,
                    11,
                    Sha256Digest::digest(b"copied source"),
                ))
                .unwrap_err(),
            SplitTrustStoreError::Corrupt
        );
        fs::remove_dir_all(source_base).unwrap();
        fs::remove_dir_all(copied_base).unwrap();
    }

    #[test]
    fn rolled_back_authority_file_disagrees_with_continuity() {
        let root = temp_root();
        let store = LocalSplitTrustStore::new(&root);
        let manifest = Sha256Digest::digest(b"rollback manifest");
        let source = Sha256Digest::digest(b"rollback source");
        store
            .issue(SplitTrustReceipt::new(manifest, 4, source))
            .unwrap();
        let authority = root.join(super::AUTHORITY_FILE);
        let old = fs::read(&authority).unwrap();
        store.revoke(&manifest).unwrap();

        fs::write(&authority, &old).unwrap();
        assert_eq!(
            store.lookup(&manifest).unwrap_err(),
            SplitTrustStoreError::Corrupt
        );
        assert_eq!(
            store
                .issue(SplitTrustReceipt::new(manifest, 4, source))
                .unwrap_err(),
            SplitTrustStoreError::Corrupt
        );
        remove_store(&root);
    }

    #[test]
    fn explicit_restoration_preserves_a_later_local_revocation() {
        let base = temp_root();
        let root = base.join("store");
        let store = LocalSplitTrustStore::new(&root);
        let manifest = Sha256Digest::digest(b"restored manifest");
        store
            .issue(SplitTrustReceipt::new(
                manifest,
                9,
                Sha256Digest::digest(b"restored source"),
            ))
            .unwrap();
        let snapshot_base = temp_root();
        let snapshot = snapshot_base.join("store");
        copy_tree(&root, &snapshot);

        store.revoke(&manifest).unwrap();
        let restore = store.restore_from_snapshot(&snapshot).unwrap();
        assert_eq!(restore.restored_entries, 0);
        assert_eq!(restore.preserved_revocations, 1);
        let receipt = store.lookup(&manifest).unwrap().unwrap();
        assert!(receipt.is_revoked());
        assert_eq!(receipt.predecessor_revision(), 2);

        let requalified =
            SplitTrustReceipt::new(manifest, 9, Sha256Digest::digest(b"restored source"))
                .with_predecessor_revision(2);
        store.issue(requalified).unwrap();
        assert!(!store.lookup(&manifest).unwrap().unwrap().is_revoked());
        fs::remove_dir_all(base).unwrap();
        fs::remove_dir_all(snapshot_base).unwrap();
    }

    #[test]
    fn restoration_rebuilds_a_lost_store_root_from_its_snapshot() {
        let base = temp_root();
        let root = base.join("store");
        let store = LocalSplitTrustStore::new(&root);
        let manifest = Sha256Digest::digest(b"lost root manifest");
        store
            .issue(SplitTrustReceipt::new(
                manifest,
                7,
                Sha256Digest::digest(b"lost root source"),
            ))
            .unwrap();
        let snapshot_base = temp_root();
        let snapshot = snapshot_base.join("store");
        copy_tree(&root, &snapshot);

        fs::remove_dir_all(&root).unwrap();
        assert_eq!(
            store.lookup(&manifest).unwrap_err(),
            SplitTrustStoreError::Corrupt
        );
        let restore = store.restore_from_snapshot(&snapshot).unwrap();
        assert_eq!(restore.restored_entries, 1);
        let receipt = store.lookup(&manifest).unwrap().unwrap();
        assert!(!receipt.is_revoked());
        assert_eq!(receipt.predecessor_revision(), 1);
        fs::remove_dir_all(base).unwrap();
        fs::remove_dir_all(snapshot_base).unwrap();
    }

    #[test]
    fn interrupted_restoration_completes_through_the_commit_journal() {
        let base = temp_root();
        let root = base.join("store");
        let store = LocalSplitTrustStore::new(&root);
        let first = Sha256Digest::digest(b"restore first");
        let second = Sha256Digest::digest(b"restore second");
        for manifest in [first, second] {
            store
                .issue(SplitTrustReceipt::new(
                    manifest,
                    5,
                    Sha256Digest::digest(b"restore source"),
                ))
                .unwrap();
        }

        let copied_base = temp_root();
        copy_tree(&base, &copied_base);
        let copied_root = copied_base.join("store");
        let copied = LocalSplitTrustStore::new(&copied_root);
        for filler in [&b"restore filler one"[..], &b"restore filler two"[..]] {
            copied
                .issue(SplitTrustReceipt::new(
                    Sha256Digest::digest(filler),
                    5,
                    Sha256Digest::digest(b"filler source"),
                ))
                .unwrap();
        }

        for manifest in [first, second] {
            store
                .issue(
                    SplitTrustReceipt::new(manifest, 5, Sha256Digest::digest(b"restore source"))
                        .with_predecessor_revision(1),
                )
                .unwrap();
        }

        let snapshot_base = temp_root();
        let snapshot = snapshot_base.join("store");
        copy_tree(&root, &snapshot);

        let mut order = [first, second];
        order.sort_by_key(|manifest| manifest.to_hex());
        let blocked = order[1];
        let completed = order[0];
        let blocked_path = super::receipt_path(&copied_root.join("receipts"), &blocked);
        fs::remove_file(&blocked_path).unwrap();
        fs::create_dir(&blocked_path).unwrap();

        assert_eq!(
            copied.restore_from_snapshot(&snapshot).unwrap_err(),
            SplitTrustStoreError::Unavailable
        );
        fs::remove_dir(&blocked_path).unwrap();

        let receipt = copied.lookup(&completed).unwrap().unwrap();
        assert_eq!(receipt.predecessor_revision(), 2);
        let receipt = copied.lookup(&blocked).unwrap().unwrap();
        assert_eq!(receipt.predecessor_revision(), 2);

        fs::remove_dir_all(base).unwrap();
        fs::remove_dir_all(copied_base).unwrap();
        fs::remove_dir_all(snapshot_base).unwrap();
    }

    #[test]
    fn restoration_rejects_foreign_or_newer_snapshots() {
        let base = temp_root();
        let root = base.join("store");
        let store = LocalSplitTrustStore::new(&root);
        store
            .issue(SplitTrustReceipt::new(
                Sha256Digest::digest(b"local manifest"),
                3,
                Sha256Digest::digest(b"local source"),
            ))
            .unwrap();
        let empty_store = LocalSplitTrustStore::new(base.join("empty"));
        assert_eq!(
            empty_store
                .restore_from_snapshot(base.join("missing"))
                .unwrap_err(),
            SplitTrustStoreError::Unavailable
        );
        assert_eq!(
            empty_store.restore_from_snapshot(&root).unwrap_err(),
            SplitTrustStoreError::Corrupt
        );

        let other_base = temp_root();
        let other = other_base.join("store");
        LocalSplitTrustStore::new(&other)
            .issue(SplitTrustReceipt::new(
                Sha256Digest::digest(b"other manifest"),
                3,
                Sha256Digest::digest(b"other source"),
            ))
            .unwrap();
        assert_eq!(
            store.restore_from_snapshot(&other).unwrap_err(),
            SplitTrustStoreError::Corrupt
        );

        let snapshot_base = temp_root();
        let snapshot = snapshot_base.join("store");
        copy_tree(&root, &snapshot);
        let authority = snapshot.join(super::AUTHORITY_FILE);
        let text = fs::read_to_string(&authority).unwrap();
        let text = text.replacen("\"generation\":1", "\"generation\":900", 1);
        fs::write(&authority, text).unwrap();
        assert_eq!(
            store.restore_from_snapshot(&snapshot).unwrap_err(),
            SplitTrustStoreError::Corrupt
        );
        fs::remove_dir_all(base).unwrap();
        fs::remove_dir_all(other_base).unwrap();
        fs::remove_dir_all(snapshot_base).unwrap();
    }

    #[test]
    fn first_use_creates_missing_ancestor_directories() {
        let base = temp_root();
        let root = base.join("one").join("two").join("store");
        let store = LocalSplitTrustStore::new(&root);
        let manifest = Sha256Digest::digest(b"nested manifest");
        store
            .issue(SplitTrustReceipt::new(
                manifest,
                2,
                Sha256Digest::digest(b"nested source"),
            ))
            .unwrap();
        assert!(root.is_dir());
        assert!(root.join("receipts").is_dir());
        assert!(super::continuity_file(&root).unwrap().is_file());
        assert!(store.lookup(&manifest).unwrap().is_some());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn interrupted_commit_journal_is_replayed_before_reading() {
        let root = temp_root();
        let store = LocalSplitTrustStore::new(&root);
        let manifest = Sha256Digest::digest(b"journal manifest");
        store
            .issue(SplitTrustReceipt::new(
                manifest,
                13,
                Sha256Digest::digest(b"journal source"),
            ))
            .unwrap();

        let paths = store.ensure_store_directories().unwrap();
        let mut authority = super::read_index_file(&paths.authority, super::AUTHORITY_KIND)
            .unwrap()
            .unwrap();
        let revision = authority.entry(&manifest).unwrap().revision + 1;
        let receipt = super::revoked_tombstone(&manifest, revision);
        let receipt_bytes =
            super::encode_receipt(&receipt, revision, &authority.authority_id).unwrap();
        let receipt_path = super::receipt_path(&paths.receipts, &manifest);
        authority.upsert(&manifest, revision, super::IndexState::Revoked);
        authority.advance_generation().unwrap();
        let journal =
            super::encode_commit(&authority, Some((&receipt_path, receipt_bytes.as_slice())))
                .unwrap();
        super::atomic_write(&paths.pending, &journal).unwrap();
        assert!(paths.pending.is_file());

        let recovered = store.lookup(&manifest).unwrap().unwrap();
        assert!(recovered.is_revoked());
        assert_eq!(recovered.predecessor_revision(), revision);
        assert!(!paths.pending.exists());
        remove_store(&root);
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_index_state_is_unavailable() {
        use std::os::unix::fs::PermissionsExt;

        // Permission checks do not apply to the superuser, so skip there.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let root = temp_root();
        let store = LocalSplitTrustStore::new(&root);
        let manifest = Sha256Digest::digest(b"permission manifest");
        store
            .issue(SplitTrustReceipt::new(
                manifest,
                6,
                Sha256Digest::digest(b"permission source"),
            ))
            .unwrap();
        let authority = root.join(super::AUTHORITY_FILE);
        let original = fs::metadata(&authority).unwrap().permissions();
        let mut locked = original.clone();
        locked.set_mode(0o000);
        fs::set_permissions(&authority, locked).unwrap();
        let result = store.lookup(&manifest);
        fs::set_permissions(&authority, original).unwrap();
        assert_eq!(result.unwrap_err(), SplitTrustStoreError::Unavailable);
        remove_store(&root);
    }

    fn wait_for_path(path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !path.exists() {
            assert!(Instant::now() < deadline, "timed out waiting for {path:?}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn spawn_contention_worker(
        mode: &str,
        root: &Path,
        manifest: Sha256Digest,
        ready: &Path,
        proceed: &Path,
    ) -> std::process::Child {
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "split_trust::tests::cross_process_contention_worker",
                "--test-threads=1",
            ])
            .env("NSCB_TRUST_PROCESS_MODE", mode)
            .env("NSCB_TRUST_PROCESS_ROOT", root)
            .env("NSCB_TRUST_PROCESS_MANIFEST", manifest.to_hex())
            .env("NSCB_TRUST_PROCESS_READY", ready)
            .env("NSCB_TRUST_PROCESS_PROCEED", proceed)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    fn wait_for_child(child: &mut std::process::Child) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("cross-process worker timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
