//! Process-lifetime OS advisory leases tied to durable SQLite slot identities.
//!
//! The registry contains a fixed set of slot files. Files are created once and
//! are never unlinked or replaced, which prevents two processes from owning
//! different inodes for the same logical slot. Each file contains only its
//! immutable opaque slot ID. SQLite records each Job claim so releasing an OS
//! lock alone cannot authorize reuse while the publication outcome is unresolved.

use super::model::HistoryError;
use super::storage::{ensure_private_directory, open_private_lock_file};
use fs2::FileExt;
use rusqlite::Connection;
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const SLOT_PREFIX: &str = "lease-slot-";
const SLOT_SUFFIX: &str = ".lock";
const OWNER_RECORD_MAGIC: &str = "NSCB-LEASE-SLOT-V3";
const LEGACY_OWNER_RECORD_MAGIC: &str = "NSCB-LEASE-SLOT-V2";
const MAX_OWNER_RECORD_BYTES: u64 = 256;

/// Maximum number of slots and simultaneous standalone Job leases.
pub(crate) const LEASE_SLOT_COUNT: usize = 64;

/// A live claim on one durable Job and one persistent slot.
///
/// Clones share one open slot file handle. The operating-system lock therefore
/// remains continuously held from before admission through Job completion.
#[derive(Clone, Debug)]
pub(crate) struct JobLease {
    _file: Arc<File>,
    job_id: String,
    _slot_id: String,
    _claim_token: String,
}

impl JobLease {
    pub(crate) fn job_id(&self) -> &str {
        &self.job_id
    }

    #[cfg(test)]
    pub(crate) fn slot_id(&self) -> &str {
        &self._slot_id
    }

    #[cfg(test)]
    pub(crate) fn claim_token(&self) -> &str {
        &self._claim_token
    }
}

/// A temporarily locked slot that has not yet been linked to a Job.
pub(crate) struct SlotReservation {
    file: File,
    slot_id: String,
    slot_key: String,
    record_to_normalize: Option<SlotRecord>,
}

impl SlotReservation {
    pub(crate) fn slot_id(&self) -> &str {
        &self.slot_id
    }

    pub(crate) fn slot_key(&self) -> &str {
        &self.slot_key
    }

    /// Removes legacy owner fields after SQLite confirms that the slot has no
    /// outstanding or unresolved claim. The exclusive file lock remains held.
    pub(crate) fn transition_legacy_slot_record(mut self) -> Result<Self, HistoryError> {
        if let Some(record) = self.record_to_normalize.take() {
            transition_legacy_slot_identity(&self.file, &record)?;
        }
        Ok(self)
    }

    /// Binds the already locked slot to the durable admission claim.
    pub(crate) fn bind(self, job_id: &str, claim_token: &str) -> Result<JobLease, HistoryError> {
        validate_token(job_id)?;
        validate_token(claim_token)?;
        Ok(JobLease {
            _file: Arc::new(self.file),
            job_id: job_id.to_owned(),
            _slot_id: self.slot_id,
            _claim_token: claim_token.to_owned(),
        })
    }
}

/// Ensures every SQLite slot identity has one stable, matching file.
pub(crate) fn initialize_slot_files(
    connection: &Connection,
    database_path: &Path,
    allow_empty_initialization: bool,
) -> Result<usize, HistoryError> {
    let lock_directory = slot_directory(database_path)?;
    ensure_private_directory(&lock_directory)?;
    let mut statement = connection
        .prepare("SELECT slot_id, slot_key, ordinal FROM lease_slots ORDER BY ordinal")
        .map_err(|_| HistoryError::LockFailed)?;
    let slots = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|_| HistoryError::LockFailed)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| HistoryError::LockFailed)?;
    if slots.len() != LEASE_SLOT_COUNT {
        return Err(HistoryError::LockFailed);
    }

    let mut healthy = 0;
    for (slot_id, slot_key, ordinal) in slots {
        validate_token(&slot_id)?;
        let expected_key = canonical_slot_key(ordinal)?;
        if slot_key != expected_key {
            return Err(HistoryError::LockFailed);
        }
        let file = match open_private_lock_file(&lock_directory.join(&slot_key)) {
            Ok(file) => file,
            Err(_) => continue,
        };
        match read_owner_record(&file) {
            Ok(Some(record)) if record.slot_id == slot_id => healthy += 1,
            Ok(None) => {
                if !allow_empty_initialization {
                    continue;
                }
                if file.try_lock_exclusive().is_err() {
                    continue;
                }
                if write_slot_identity(&file, &slot_id).is_ok() {
                    healthy += 1;
                }
            }
            Ok(Some(_)) | Err(_) if allow_empty_initialization => {
                // A pending registry cannot be marked ready with an uncertain slot owner.
                return Err(HistoryError::LockFailed);
            }
            Ok(Some(_)) | Err(_) => continue,
        }
    }
    sync_directory_if_supported(&lock_directory)?;
    if healthy == 0 {
        return Err(HistoryError::LockFailed);
    }
    Ok(healthy)
}

/// Locks the first fixed slot that is not actively owned by another process.
///
/// The caller must check durable SQLite claim eligibility after obtaining this
/// reservation. A released slot file stays in place, so no waiters can split
/// ownership across an old and replacement inode.
pub(crate) fn acquire_available_slot(
    database_path: &Path,
    excluded_slot_ids: &HashSet<String>,
) -> Result<SlotReservation, HistoryError> {
    let lock_directory = slot_directory(database_path)?;
    for index in 0..LEASE_SLOT_COUNT {
        let slot_key = canonical_slot_key(index as i64)?;
        let file = match open_private_lock_file(&lock_directory.join(&slot_key)) {
            Ok(file) => file,
            Err(_) => continue,
        };
        if file.try_lock_exclusive().is_err() {
            continue;
        }
        let record = match read_owner_record(&file) {
            Ok(Some(record)) => record,
            Ok(None) | Err(_) => continue,
        };
        if excluded_slot_ids.contains(&record.slot_id) {
            continue;
        }
        let record_to_normalize = (record.format != SlotRecordFormat::V3).then(|| record.clone());
        return Ok(SlotReservation {
            file,
            slot_id: record.slot_id,
            slot_key,
            record_to_normalize,
        });
    }
    Err(HistoryError::LockFailed)
}

/// Coordinates schema initialization and slot-file validation across processes.
pub(crate) fn acquire_initialization_lock(database_path: &Path) -> Result<File, HistoryError> {
    let lock_directory = slot_directory(database_path)?;
    ensure_private_directory(&lock_directory)?;
    let lock_path = lock_directory.join("history-schema.lock");
    let file = open_private_lock_file(&lock_path)?;
    file.lock_exclusive()
        .map_err(|_| HistoryError::LockFailed)?;
    Ok(file)
}

/// Locks and verifies the durable slot/token claim for a Job under recovery.
///
/// The caller must re-read and verify the same claim in its SQLite recovery
/// transaction while this lease remains held. Any mismatch or live owner keeps
/// the Job unresolved.
pub(crate) fn try_acquire_existing_claim(
    database_path: &Path,
    slot_key: &str,
    expected_slot_id: &str,
    job_id: &str,
    expected_claim_token: &str,
) -> Result<JobLease, HistoryError> {
    validate_token(expected_slot_id)?;
    validate_token(job_id)?;
    validate_token(expected_claim_token)?;
    if canonical_key_is_valid(slot_key).is_none() {
        return Err(HistoryError::LockFailed);
    }
    let lock_directory = slot_directory(database_path)?;
    let file = open_private_lock_file(&lock_directory.join(slot_key))?;
    if file.try_lock_exclusive().is_err() {
        return Err(HistoryError::LockFailed);
    }
    // Read only after acquiring the lock. A different owner may bind this slot
    // between an earlier read and the lock attempt; that record must not be
    // accepted as evidence for the claim being recovered.
    let record = read_owner_record(&file)?.ok_or(HistoryError::LockFailed)?;
    let legacy_owner_mismatch = match &record.format {
        SlotRecordFormat::V2 {
            job_id: owner_job_id,
            claim_token: owner_token,
        } => {
            owner_job_id
                .as_deref()
                .is_some_and(|owner_job_id| owner_job_id != job_id)
                || owner_token
                    .as_deref()
                    .is_some_and(|owner_token| owner_token != expected_claim_token)
        }
        SlotRecordFormat::TransitionalV3 | SlotRecordFormat::V3 => false,
    };
    if record.slot_id != expected_slot_id || legacy_owner_mismatch {
        return Err(HistoryError::LockFailed);
    }
    Ok(JobLease {
        _file: Arc::new(file),
        job_id: job_id.to_owned(),
        _slot_id: expected_slot_id.to_owned(),
        _claim_token: expected_claim_token.to_owned(),
    })
}

fn slot_directory(database_path: &Path) -> Result<PathBuf, HistoryError> {
    database_path
        .parent()
        .map(|parent| parent.join("job-locks"))
        .ok_or(HistoryError::DirectoryUnavailable)
}

fn canonical_slot_key(ordinal: i64) -> Result<String, HistoryError> {
    if !(0..LEASE_SLOT_COUNT as i64).contains(&ordinal) {
        return Err(HistoryError::LockFailed);
    }
    Ok(format!("{SLOT_PREFIX}{ordinal:03}{SLOT_SUFFIX}"))
}

fn canonical_key_is_valid(slot_key: &str) -> Option<i64> {
    let ordinal = slot_key
        .strip_prefix(SLOT_PREFIX)?
        .strip_suffix(SLOT_SUFFIX)?;
    if ordinal.len() != 3 {
        return None;
    }
    let ordinal = ordinal.parse::<i64>().ok()?;
    canonical_slot_key(ordinal).ok().map(|_| ordinal)
}

fn validate_token(token: &str) -> Result<(), HistoryError> {
    if token.len() == 32
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(HistoryError::LockFailed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SlotRecord {
    slot_id: String,
    format: SlotRecordFormat,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SlotRecordFormat {
    V2 {
        job_id: Option<String>,
        claim_token: Option<String>,
    },
    TransitionalV3,
    V3,
}

fn owner_record(slot_id: &str) -> String {
    format!("{OWNER_RECORD_MAGIC}\nslot={slot_id}\n")
}

fn parse_owner_record(bytes: &[u8]) -> Result<Option<SlotRecord>, HistoryError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| HistoryError::LockFailed)?;
    let mut lines = text.lines();
    let magic = lines.next().ok_or(HistoryError::LockFailed)?;
    let slot_id = lines
        .next()
        .and_then(|line| line.strip_prefix("slot="))
        .ok_or(HistoryError::LockFailed)?;
    validate_token(slot_id)?;
    if magic == OWNER_RECORD_MAGIC {
        let format = match lines.next() {
            None => SlotRecordFormat::V3,
            Some(job_line) => {
                parse_legacy_owner_fields(job_line, &mut lines)?;
                if lines.next().is_some() {
                    return Err(HistoryError::LockFailed);
                }
                SlotRecordFormat::TransitionalV3
            }
        };
        return Ok(Some(SlotRecord {
            slot_id: slot_id.to_owned(),
            format,
        }));
    }
    if magic != LEGACY_OWNER_RECORD_MAGIC {
        return Err(HistoryError::LockFailed);
    }
    let (job_id, claim_token) =
        parse_legacy_owner_fields(lines.next().ok_or(HistoryError::LockFailed)?, &mut lines)?;
    if lines.next().is_some() {
        return Err(HistoryError::LockFailed);
    }
    Ok(Some(SlotRecord {
        slot_id: slot_id.to_owned(),
        format: SlotRecordFormat::V2 {
            job_id,
            claim_token,
        },
    }))
}

/// Parses complete legacy owner tokens and rejects blank placeholders.
fn parse_legacy_owner_fields(
    job_line: &str,
    lines: &mut std::str::Lines<'_>,
) -> Result<(Option<String>, Option<String>), HistoryError> {
    let job_id = job_line
        .strip_prefix("job=")
        .ok_or(HistoryError::LockFailed)?;
    let claim_token = lines
        .next()
        .and_then(|line| line.strip_prefix("claim="))
        .ok_or(HistoryError::LockFailed)?;
    validate_token(job_id)?;
    validate_token(claim_token)?;
    Ok((Some(job_id.to_owned()), Some(claim_token.to_owned())))
}

fn read_owner_record(file: &File) -> Result<Option<SlotRecord>, HistoryError> {
    let mut cursor = file;
    cursor
        .seek(SeekFrom::Start(0))
        .map_err(|_| HistoryError::LockFailed)?;
    let mut bytes = Vec::new();
    cursor
        .take(MAX_OWNER_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| HistoryError::LockFailed)?;
    if bytes.len() as u64 > MAX_OWNER_RECORD_BYTES {
        return Err(HistoryError::LockFailed);
    }
    parse_owner_record(&bytes)
}

fn write_slot_identity(file: &File, slot_id: &str) -> Result<(), HistoryError> {
    if file.metadata().map_err(|_| HistoryError::LockFailed)?.len() != 0 {
        return Err(HistoryError::LockFailed);
    }
    let record = owner_record(slot_id);
    let mut cursor = file;
    cursor
        .seek(SeekFrom::Start(0))
        .map_err(|_| HistoryError::LockFailed)?;
    cursor
        .write_all(record.as_bytes())
        .map_err(|_| HistoryError::LockFailed)?;
    file.sync_all().map_err(|_| HistoryError::LockFailed)
}

/// Converts a reusable legacy record while retaining the slot file inode.
/// The V2 and V3 magic differ in one byte; changing that byte before truncation
/// leaves a parseable V2 or transitional V3 record if the process stops. The
/// caller must hold the exclusive OS lock and confirm SQLite has no blocking
/// claim before invoking this function.
fn transition_legacy_slot_identity(file: &File, expected: &SlotRecord) -> Result<(), HistoryError> {
    if expected.format == SlotRecordFormat::V3 {
        return Err(HistoryError::LockFailed);
    }
    let current = read_owner_record(file)?.ok_or(HistoryError::LockFailed)?;
    if current != *expected {
        return Err(HistoryError::LockFailed);
    }

    let record = owner_record(&expected.slot_id);
    if matches!(&expected.format, SlotRecordFormat::V2 { .. }) {
        let mut cursor = file;
        cursor
            .seek(SeekFrom::Start(
                (LEGACY_OWNER_RECORD_MAGIC.len() - 1) as u64,
            ))
            .map_err(|_| HistoryError::LockFailed)?;
        cursor
            .write_all(b"3")
            .map_err(|_| HistoryError::LockFailed)?;
        file.sync_all().map_err(|_| HistoryError::LockFailed)?;
    }

    match read_owner_record(file)? {
        Some(record)
            if record.slot_id == expected.slot_id
                && !matches!(record.format, SlotRecordFormat::V2 { .. }) => {}
        _ => return Err(HistoryError::LockFailed),
    }
    file.set_len(record.len() as u64)
        .map_err(|_| HistoryError::LockFailed)?;
    file.sync_all().map_err(|_| HistoryError::LockFailed)?;

    match read_owner_record(file)? {
        Some(record)
            if record.slot_id == expected.slot_id && record.format == SlotRecordFormat::V3 =>
        {
            Ok(())
        }
        _ => Err(HistoryError::LockFailed),
    }
}

#[cfg(unix)]
fn sync_directory_if_supported(directory: &Path) -> Result<(), HistoryError> {
    File::open(directory)
        .and_then(|directory_file| directory_file.sync_all())
        .map_err(|_| HistoryError::LockFailed)
}

#[cfg(not(unix))]
fn sync_directory_if_supported(_directory: &Path) -> Result<(), HistoryError> {
    Ok(())
}

#[cfg(test)]
pub(crate) fn slot_paths_for_test(database_path: &Path) -> Result<Vec<PathBuf>, HistoryError> {
    let directory = slot_directory(database_path)?;
    Ok((0..LEASE_SLOT_COUNT)
        .map(|index| directory.join(canonical_slot_key(index as i64).unwrap()))
        .collect())
}
