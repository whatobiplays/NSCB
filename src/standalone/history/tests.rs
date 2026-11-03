//! Unit coverage for schema recovery, admission, leases, retention, and clearing.

use super::storage::create_recovery_backup;
use super::store::{classify_publication, completion_entry_is_pruneable};
use super::*;
#[cfg(unix)]
use fs2::FileExt;
#[cfg(target_os = "macos")]
use nscb::JobState;
use nscb::OperationArtifactRole;
use rusqlite::{Connection, OpenFlags, params, types::Value};
#[cfg(target_os = "macos")]
use serde_json::Value as JsonValue;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(unix)]
use std::process::Stdio;
use std::sync::{
    Arc, Barrier, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

#[cfg(unix)]
const CHILD_OWNER_DATABASE: &str = "NSCB_TEST_CHILD_OWNER_DATABASE";
#[cfg(unix)]
const CHILD_OWNER_JOB_ID: &str = "NSCB_TEST_CHILD_OWNER_JOB_ID";
#[cfg(unix)]
const CHILD_OWNER_READY: &str = "NSCB_TEST_CHILD_OWNER_READY";
#[cfg(unix)]
const CHILD_OWNER_RELEASE: &str = "NSCB_TEST_CHILD_OWNER_RELEASE";

const CHILD_V1_MIGRATION_DATABASE: &str = "NSCB_TEST_V1_MIGRATION_DATABASE";
const CHILD_V1_MIGRATION_DDL_REACHED: &str = "NSCB_TEST_V1_MIGRATION_DDL_REACHED";
const CHILD_V3_MIGRATION_DATABASE: &str = "NSCB_TEST_V3_MIGRATION_DATABASE";
const CHILD_V3_MIGRATION_DDL_REACHED: &str = "NSCB_TEST_V3_MIGRATION_DDL_REACHED";

static V1_MIGRATION_WRITER_RELEASE: OnceLock<Barrier> = OnceLock::new();
static V1_MIGRATION_RELEASE_ON_BUSY: AtomicBool = AtomicBool::new(false);

fn release_v1_migration_writer_on_busy(_retry_count: i32) -> bool {
    if V1_MIGRATION_RELEASE_ON_BUSY.swap(false, Ordering::SeqCst) {
        V1_MIGRATION_WRITER_RELEASE
            .get()
            .expect("migration race barrier is initialized")
            .wait();
    }
    std::thread::sleep(std::time::Duration::from_millis(1));
    true
}

fn admission() -> AdmissionInput {
    AdmissionInput {
        kind: JobKind::CopyThrough,
        submission_kind: SubmissionKind::Single,
        invocation_cwd: PathBuf::from("/fixture"),
        source: AdmissionSource::Single(PathBuf::from("/fixture/source.bin")),
        destination: PathBuf::from("/fixture/output.bin"),
        destination_selection: DestinationSelection::Explicit,
        workspace: PathBuf::from("/fixture/workspace"),
        workspace_selection: WorkspaceSelection::Explicit,
        conflict_policy: ConflictPolicyRecord::Fail,
        conflict_policy_provenance: ConflictPolicyProvenance::Default,
        parent_conflict_policy: None,
        parent_conflict_policy_provenance: None,
        parent_job_id: None,
        retry_scope: RetryScope::All,
        required_providers: Vec::new(),
        required_keys: Vec::new(),
        batch_intent: None,
        items: vec![AdmissionItem {
            item_key: "copy-through-0".to_owned(),
            source: PathBuf::from("/fixture/source.bin"),
            destination: Some(PathBuf::from("/fixture/output.bin")),
            provenance: None,
            split_qualification: None,
            split_manifest_sha256: None,
        }],
    }
}

fn claim_coordinates(path: &Path, job_id: &str) -> (String, String, String) {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    connection
        .query_row(
            "SELECT s.slot_key, s.slot_id, c.claim_token
             FROM job_lease_claims c
             JOIN lease_slots s ON s.slot_id = c.slot_id
             WHERE c.job_id = ?1",
            [job_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

fn query_rows_for_test(connection: &Connection, query: &str) -> Vec<Vec<Value>> {
    let mut statement = connection.prepare(query).unwrap();
    let column_count = statement.column_count();
    statement
        .query_map([], |row| {
            (0..column_count)
                .map(|index| row.get::<_, Value>(index))
                .collect::<Result<Vec<_>, _>>()
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn create_v1_database(path: &Path) -> Connection {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(&format!(
            "PRAGMA application_id = {APPLICATION_ID};\n\
                 PRAGMA user_version = 1;\n\
                 CREATE TABLE jobs (\n\
                     job_id TEXT PRIMARY KEY,\n\
                     parent_job_id TEXT,\n\
                     kind TEXT NOT NULL,\n\
                     submission_kind TEXT NOT NULL,\n\
                     source TEXT NOT NULL,\n\
                     source_provenance TEXT NOT NULL,\n\
                     destination TEXT NOT NULL,\n\
                     workspace TEXT NOT NULL,\n\
                     state TEXT NOT NULL,\n\
                     admitted_at TEXT NOT NULL,\n\
                     started_at TEXT,\n\
                     terminal_at TEXT,\n\
                     outcome TEXT,\n\
                     failure_code TEXT,\n\
                     cleanup_warning_code TEXT\n\
                 );\n\
                 INSERT INTO jobs VALUES (\n\
                     'legacy-job', NULL, 'copy_through', 'single',\n\
                     '/fixture/source.bin', 'cli_argument', '/fixture/output.bin',\n\
                     '/fixture/workspace', 'succeeded', '2026-01-01T00:00:00Z',\n\
                     '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z',\n\
                     'copied', NULL, NULL\n\
                 );"
        ))
        .unwrap();
    connection
}

fn create_v2_database(path: &Path, job_id: &str, state: &str) -> Connection {
    let mut connection = create_v1_database(path);
    connection
        .execute(
            "UPDATE jobs
             SET job_id = ?1, state = ?2,
                 started_at = CASE WHEN ?2 = 'running' THEN admitted_at ELSE NULL END,
                 terminal_at = NULL, outcome = NULL, failure_code = NULL",
            params![job_id, state],
        )
        .unwrap();
    super::storage::migrate_v1_to_v2(&mut connection, path).unwrap();
    connection
}

#[test]
fn fresh_store_initializes_current_schema_and_private_state() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("state").join("jobs.sqlite3");
    let store = HistoryStore::open_at(&path).unwrap();
    assert_eq!(store.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    assert!(store.list().unwrap().is_empty());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn canonical_current_schema_is_valid_after_reopen() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    drop(HistoryStore::open_at(&path).unwrap());

    let reopened = HistoryStore::open_at(&path)
        .expect("a freshly initialized canonical database must pass health validation");
    assert_eq!(reopened.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
}

#[test]
fn fresh_pending_schema_finishes_slot_initialization_after_restart() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let mut connection = Connection::open(&path).unwrap();
    super::storage::create_schema(&mut connection).unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row("SELECT ready FROM history_registry", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    drop(connection);

    let store = HistoryStore::open_at(&path).unwrap();
    assert_eq!(store.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    assert_eq!(
        store
            .connection
            .query_row("SELECT ready FROM history_registry", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
    assert!(
        super::lease::slot_paths_for_test(&path)
            .unwrap()
            .iter()
            .all(|slot| fs::read(slot).is_ok())
    );
}

#[test]
fn pending_registry_rejects_partial_slot_identity_without_resolving_claim() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let admitted = HistoryStore::open_at(&path)
        .unwrap()
        .begin_admission(admission())
        .unwrap()
        .commit()
        .unwrap();
    let job_id = admitted.job_id.clone();
    let running_store = HistoryStore::open_at(&path).unwrap();
    running_store.begin_running(&job_id).unwrap();
    let (slot_key, _, claim_token) = claim_coordinates(&path, &job_id);
    let slot_path = root.path().join("job-locks").join(slot_key);
    let complete_identity = fs::read(&slot_path).unwrap();
    assert!(complete_identity.len() > 1);
    let partial_identity = complete_identity[..complete_identity.len() / 2].to_vec();
    assert!(!partial_identity.is_empty());
    drop(admitted);
    drop(running_store);

    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("UPDATE history_registry SET ready = 0; PRAGMA user_version = 0;")
        .unwrap();
    drop(connection);
    fs::write(&slot_path, partial_identity).unwrap();

    assert!(matches!(
        HistoryStore::open_at(&path),
        Err(HistoryError::LockFailed)
    ));

    let connection = Connection::open(&path).unwrap();
    let ready: i64 = connection
        .query_row("SELECT ready FROM history_registry", [], |row| row.get(0))
        .unwrap();
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(ready, 0);
    assert_eq!(version, 0);

    let (job_state, item_state): (String, String) = connection
        .query_row(
            "SELECT j.state, i.state
             FROM jobs j JOIN job_items i ON i.job_id = j.job_id
             WHERE j.job_id = ?1",
            [&job_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (job_state.as_str(), item_state.as_str()),
        ("running", "running")
    );

    let (claim_state, resolved_at, recorded_token): (String, Option<String>, String) = connection
        .query_row(
            "SELECT state, resolved_at, claim_token
             FROM job_lease_claims WHERE job_id = ?1",
            [&job_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(claim_state, "outstanding");
    assert_eq!(resolved_at, None);
    assert_eq!(recorded_token, claim_token);
}

#[cfg(unix)]
#[test]
fn private_database_symlink_is_rejected_without_opening_its_target() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target.sqlite3");
    drop(HistoryStore::open_at(&target).unwrap());
    let before = fs::read(&target).unwrap();
    let alias = root.path().join("alias.sqlite3");
    symlink(&target, &alias).unwrap();

    assert_eq!(
        HistoryStore::open_at(&alias).unwrap_err(),
        HistoryError::OpenFailed
    );
    assert_eq!(fs::read(&target).unwrap(), before);
    assert!(
        fs::symlink_metadata(alias)
            .unwrap()
            .file_type()
            .is_symlink()
    );

    let pinned_path = root.path().join("pinned-directory");
    let displaced_path = root.path().join("displaced-directory");
    let replacement_path = root.path().join("replacement-directory");
    fs::create_dir(&pinned_path).unwrap();
    fs::create_dir(&replacement_path).unwrap();
    let pinned_directory =
        super::storage::open_directory_components(&fs::canonicalize(&pinned_path).unwrap())
            .unwrap();
    fs::rename(&pinned_path, &displaced_path).unwrap();
    symlink(&replacement_path, &pinned_path).unwrap();

    let lock_file = super::storage::open_private_lock_file_at(
        &pinned_directory,
        std::ffi::OsStr::new("history-schema.lock"),
        true,
    )
    .unwrap();
    drop(lock_file);
    assert!(displaced_path.join("history-schema.lock").is_file());
    assert!(!replacement_path.join("history-schema.lock").exists());
    assert!(super::storage::open_directory_components(&pinned_path).is_err());
}

#[cfg(unix)]
#[test]
fn symlinked_slot_does_not_redirect_admission_from_healthy_slots() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    drop(HistoryStore::open_at(&path).unwrap());
    let slots = super::lease::slot_paths_for_test(&path).unwrap();
    let target = root.path().join("outside.lock");
    fs::write(&target, b"untouched target").unwrap();
    fs::remove_file(&slots[0]).unwrap();
    symlink(&target, &slots[0]).unwrap();

    let pending = HistoryStore::open_at(&path)
        .unwrap()
        .begin_admission(admission())
        .unwrap();
    let admitted = pending.commit().unwrap();
    let (slot_key, _, _) = claim_coordinates(&path, &admitted.job_id);

    assert_ne!(slot_key, "lease-slot-000.lock");
    assert_eq!(fs::read(target).unwrap(), b"untouched target");
    assert!(
        fs::symlink_metadata(&slots[0])
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[cfg(unix)]
#[test]
fn existing_history_parent_permissions_are_preserved() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("caller-owned");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();

    HistoryStore::open_at(parent.join("jobs.sqlite3")).unwrap();

    assert_eq!(
        fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[cfg(unix)]
#[test]
fn newly_created_history_leaf_is_private() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("history");

    HistoryStore::open_at(parent.join("jobs.sqlite3")).unwrap();

    assert_eq!(
        fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn dropping_uncommitted_admission_leaves_no_job() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let store = HistoryStore::open_at(&path).unwrap();
    let pending = store.begin_admission(admission()).unwrap();
    assert_eq!(pending.job_id().len(), 32);
    drop(pending);
    let reopened = HistoryStore::open_at(&path).unwrap();
    assert!(reopened.list().unwrap().is_empty());
}

#[test]
fn admitted_job_owns_lease_until_the_owner_drops_it() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let pending = HistoryStore::open_at(&path)
        .unwrap()
        .begin_admission(admission())
        .unwrap();
    let admitted = pending.commit().unwrap();
    let job_id = admitted.job_id.clone();
    let reopened = HistoryStore::open_at(&path).unwrap();

    assert_eq!(reopened.reconcile_interrupted().unwrap(), 0);
    assert_eq!(reopened.load(&job_id).unwrap().state, "admitted");

    drop(admitted);
    assert_eq!(reopened.reconcile_interrupted().unwrap(), 1);
    assert_eq!(reopened.load(&job_id).unwrap().state, "interrupted");
}

#[test]
fn missing_owner_lease_preserves_unresolved_job_state() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let admitted = HistoryStore::open_at(&path)
        .unwrap()
        .begin_admission(admission())
        .unwrap()
        .commit()
        .unwrap();
    let job_id = admitted.job_id.clone();
    drop(admitted);
    let (slot_key, _, _) = claim_coordinates(&path, &job_id);
    fs::remove_file(root.path().join("job-locks").join(slot_key)).unwrap();

    let store = HistoryStore::open_at(&path).unwrap();
    assert_eq!(store.reconcile_interrupted().unwrap(), 0);
    assert_eq!(store.load(&job_id).unwrap().state, "admitted");
}

fn lease_token(seed: u8) -> String {
    format!("{seed:02x}").repeat(16)
}

#[cfg(unix)]
#[test]
fn slot_registry_is_bounded_stable_and_leaves_legacy_locks_untouched() {
    use std::os::unix::fs::MetadataExt;

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    drop(HistoryStore::open_at(&path).unwrap());
    let legacy = root.path().join("job-locks").join("legacy-owner.lock");
    fs::write(&legacy, b"preserve this historical owner record").unwrap();
    let slots = super::lease::slot_paths_for_test(&path).unwrap();
    let inodes_before = slots
        .iter()
        .map(|slot| fs::metadata(slot).unwrap().ino())
        .collect::<Vec<_>>();

    let admitted = HistoryStore::open_at(&path)
        .unwrap()
        .begin_admission(admission())
        .unwrap()
        .commit()
        .unwrap();
    drop(admitted);
    let inodes_after = slots
        .iter()
        .map(|slot| fs::metadata(slot).unwrap().ino())
        .collect::<Vec<_>>();

    assert_eq!(slots.len(), super::lease::LEASE_SLOT_COUNT);
    assert_eq!(inodes_before, inodes_after);
    assert_eq!(
        fs::read(&legacy).unwrap(),
        b"preserve this historical owner record"
    );
    let entries = fs::read_dir(root.path().join("job-locks"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), super::lease::LEASE_SLOT_COUNT + 2);
}

#[cfg(unix)]
#[test]
fn slot_exhaustion_fails_closed_and_releases_only_owned_capacity() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    drop(HistoryStore::open_at(&path).unwrap());
    let excluded = std::collections::HashSet::new();
    let mut leases = Vec::new();
    for seed in 0..super::lease::LEASE_SLOT_COUNT {
        let reservation = super::lease::acquire_available_slot(&path, &excluded).unwrap();
        leases.push(
            reservation
                .bind(&lease_token(seed as u8), &lease_token(seed as u8))
                .unwrap(),
        );
    }
    assert_eq!(
        super::lease::acquire_available_slot(&path, &excluded).err(),
        Some(HistoryError::LockFailed)
    );
    leases.pop();
    assert!(super::lease::acquire_available_slot(&path, &excluded).is_ok());
}

#[cfg(unix)]
#[test]
fn durable_outstanding_claims_prevent_a_sixty_fifth_job() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let mut owners = Vec::new();
    for _ in 0..64 {
        let pending = HistoryStore::open_at(&path)
            .unwrap()
            .begin_admission(admission())
            .unwrap();
        owners.push(pending.commit().unwrap());
    }

    // Release process locks so only the durable SQLite claims can block admission.
    drop(owners);
    let store = HistoryStore::open_at(&path).unwrap();
    let (job_count, outstanding_claim_count, distinct_slot_count): (i64, i64, i64) = store
        .connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM jobs),
                    (SELECT COUNT(*) FROM job_lease_claims WHERE state = 'outstanding'),
                    (SELECT COUNT(DISTINCT slot_id) FROM job_lease_claims
                     WHERE state = 'outstanding')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (job_count, outstanding_claim_count, distinct_slot_count),
        (64, 64, 64)
    );

    for slot_path in super::lease::slot_paths_for_test(&path).unwrap() {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(slot_path)
            .unwrap();
        file.try_lock_exclusive().unwrap();
        FileExt::unlock(&file).unwrap();
    }

    assert!(matches!(
        store.begin_admission(admission()),
        Err(HistoryError::LockFailed)
    ));

    let connection = Connection::open(&path).unwrap();
    let (job_count, outstanding_claim_count): (i64, i64) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM jobs),
                    (SELECT COUNT(*) FROM job_lease_claims WHERE state = 'outstanding')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((job_count, outstanding_claim_count), (64, 64));
}

#[test]
fn slot_claim_token_mismatch_never_authorizes_recovery() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let store = HistoryStore::open_at(&path).unwrap();
    let pending = store.begin_admission(admission()).unwrap();
    let lease = pending.acquire_lease().unwrap();
    let admitted = pending.commit().unwrap();
    let job_id = admitted.job_id.clone();
    let (slot_key, slot_id, claim_token) = claim_coordinates(&path, &job_id);
    fs::write(
        root.path().join("job-locks").join(&slot_key),
        format!("NSCB-LEASE-SLOT-V2\nslot={slot_id}\njob={job_id}\nclaim={claim_token}\n"),
    )
    .unwrap();
    assert_eq!(lease.slot_id(), slot_id);
    assert_eq!(lease.claim_token(), claim_token);
    assert_eq!(
        super::lease::try_acquire_existing_claim(
            &path,
            &slot_key,
            &slot_id,
            &job_id,
            &lease_token(99),
        )
        .err(),
        Some(HistoryError::LockFailed)
    );
    drop(lease);
    drop(admitted);
    assert_eq!(
        super::lease::try_acquire_existing_claim(
            &path,
            &slot_key,
            &slot_id,
            &job_id,
            &lease_token(99),
        )
        .err(),
        Some(HistoryError::LockFailed)
    );
    assert!(
        super::lease::try_acquire_existing_claim(&path, &slot_key, &slot_id, &job_id, &claim_token)
            .is_ok()
    );
}

#[cfg(unix)]
#[test]
fn replaced_active_lease_slot_with_blank_v2_owner_is_rejected() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let admitted = HistoryStore::open_at(&path)
        .unwrap()
        .begin_admission(admission())
        .unwrap()
        .commit()
        .unwrap();
    let job_id = admitted.job_id.clone();
    let (slot_key, slot_id, claim_token) = claim_coordinates(&path, &job_id);
    let slot_path = root.path().join("job-locks").join(&slot_key);
    let original_inode = fs::metadata(&slot_path).unwrap().ino();

    fs::remove_file(&slot_path).unwrap();
    fs::write(
        &slot_path,
        format!("NSCB-LEASE-SLOT-V2\nslot={slot_id}\njob=-\nclaim=-\n"),
    )
    .unwrap();
    fs::set_permissions(&slot_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_ne!(fs::metadata(&slot_path).unwrap().ino(), original_inode);

    assert_eq!(
        super::lease::try_acquire_existing_claim(
            &path,
            &slot_key,
            &slot_id,
            &job_id,
            &claim_token,
        )
        .err(),
        Some(HistoryError::LockFailed)
    );
    drop(admitted);
}

#[test]
fn slot_identity_is_unchanged_by_admission_and_survives_owner_exit() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let store = HistoryStore::open_at(&path).unwrap();
    let slot_paths = super::lease::slot_paths_for_test(&path).unwrap();
    let identities_before = slot_paths
        .iter()
        .map(fs::read)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let pending = store.begin_admission(admission()).unwrap();
    let lease = pending.acquire_lease().unwrap();
    let admitted = pending.commit().unwrap();
    let job_id = admitted.job_id.clone();
    let (slot_key, slot_id, _) = claim_coordinates(&path, &job_id);
    let slot = root.path().join("job-locks").join(slot_key);
    let index = slot_paths.iter().position(|path| path == &slot).unwrap();
    let recorded = fs::read(&slot).unwrap();
    assert_eq!(recorded, identities_before[index]);
    let recorded = String::from_utf8(recorded).unwrap();
    assert!(recorded.contains(&format!("slot={slot_id}")));
    assert!(!recorded.contains(&format!("job={job_id}")));
    assert!(!recorded.contains("claim="));
    drop(lease);
    drop(admitted);
    assert_eq!(fs::read(&slot).unwrap(), identities_before[index]);
}

#[test]
fn damaged_slot_does_not_prevent_admission_through_another_healthy_slot() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    drop(HistoryStore::open_at(&path).unwrap());
    let slots = super::lease::slot_paths_for_test(&path).unwrap();
    fs::write(&slots[0], b"damaged slot identity").unwrap();

    let store = HistoryStore::open_at(&path).unwrap();
    let pending = store.begin_admission(admission()).unwrap();
    let admitted = pending.commit().unwrap();
    let (slot_key, _, _) = claim_coordinates(&path, &admitted.job_id);
    assert_ne!(slot_key, "lease-slot-000.lock");
}

#[test]
fn all_unavailable_slots_fail_closed_without_admitting_a_job() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    drop(HistoryStore::open_at(&path).unwrap());
    for slot in super::lease::slot_paths_for_test(&path).unwrap() {
        fs::write(slot, b"damaged slot identity").unwrap();
    }

    assert!(matches!(
        HistoryStore::open_at(&path),
        Err(HistoryError::LockFailed)
    ));
    let connection = Connection::open(path).unwrap();
    let jobs: i64 = connection
        .query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get(0))
        .unwrap();
    assert_eq!(jobs, 0);
}

#[test]
fn recovering_one_stale_claim_does_not_interrupt_a_live_peer() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let live = HistoryStore::open_at(&path)
        .unwrap()
        .begin_admission(admission())
        .unwrap()
        .commit()
        .unwrap();
    let abandoned = HistoryStore::open_at(&path)
        .unwrap()
        .begin_admission(admission())
        .unwrap()
        .commit()
        .unwrap();
    let live_id = live.job_id.clone();
    let abandoned_id = abandoned.job_id.clone();
    let (abandoned_slot_key, abandoned_slot_id, abandoned_claim_token) =
        claim_coordinates(&path, &abandoned_id);
    let abandoned_slot_path = root.path().join("job-locks").join(&abandoned_slot_key);
    let abandoned_legacy_record = format!(
        "NSCB-LEASE-SLOT-V2\nslot={abandoned_slot_id}\njob={abandoned_id}\nclaim={abandoned_claim_token}\n"
    );
    fs::write(&abandoned_slot_path, &abandoned_legacy_record).unwrap();
    drop(abandoned);

    let store = HistoryStore::open_at(&path).unwrap();
    assert_eq!(store.reconcile_interrupted().unwrap(), 1);
    assert_eq!(store.load(&live_id).unwrap().state, "admitted");
    assert_eq!(store.load(&abandoned_id).unwrap().state, "interrupted");
    let claim_state = store
        .connection
        .query_row(
            "SELECT state FROM job_lease_claims WHERE job_id = ?1",
            [&abandoned_id],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    assert_eq!(claim_state, "unresolved");
    let next = store
        .begin_admission(admission())
        .unwrap()
        .commit()
        .unwrap();
    let (next_slot_key, _, _) = claim_coordinates(&path, &next.job_id);
    assert_ne!(next_slot_key, abandoned_slot_key);
    assert_eq!(
        fs::read(&abandoned_slot_path).unwrap(),
        abandoned_legacy_record.as_bytes()
    );
    drop(next);
    drop(live);
}

#[test]
fn committed_admission_is_durable_and_deterministically_listed() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let store = HistoryStore::open_at(&path).unwrap();
    let pending = store.begin_admission(admission()).unwrap();
    let lease = pending.acquire_lease().unwrap();
    let admitted = pending.commit().unwrap();
    assert_eq!(lease.job_id(), admitted.job_id);
    drop(lease);

    let reopened = HistoryStore::open_at(&path).unwrap();
    let jobs = reopened.list().unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].job_id, admitted.job_id);
    assert_eq!(jobs[0].state, "admitted");
    assert_eq!(jobs[0].kind, "copy_through");
}

#[test]
fn future_schema_and_non_database_files_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let future = root.path().join("future.sqlite3");
    let connection = Connection::open(&future).unwrap();
    connection
        .execute_batch(&format!(
            "PRAGMA application_id = {APPLICATION_ID}; PRAGMA user_version = {};",
            CURRENT_SCHEMA_VERSION + 1
        ))
        .unwrap();
    drop(connection);
    assert_eq!(
        HistoryStore::open_at(&future).unwrap_err(),
        HistoryError::VersionUnsupported
    );

    let corrupt = root.path().join("corrupt.sqlite3");
    fs::write(&corrupt, b"not sqlite").unwrap();
    assert_eq!(
        HistoryStore::open_at(&corrupt).unwrap_err(),
        HistoryError::Corrupt
    );
}

#[test]
fn current_schema_validation_rejects_missing_required_tables_and_child_columns() {
    let mutations = [
        "DROP TABLE job_items",
        "DROP TABLE job_artifacts",
        "ALTER TABLE job_items DROP COLUMN evidence_json",
        "ALTER TABLE job_artifacts DROP COLUMN evidence_json",
    ];
    for mutation in mutations {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("jobs.sqlite3");
        drop(HistoryStore::open_at(&path).unwrap());
        let slots = super::lease::slot_paths_for_test(&path).unwrap();
        let identity_files = slots
            .iter()
            .map(fs::read)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        Connection::open(&path)
            .unwrap()
            .execute_batch(mutation)
            .unwrap_or_else(|error| {
                panic!("could not apply schema corruption fixture {mutation}: {error}")
            });

        assert!(
            matches!(HistoryStore::open_at(&path), Err(HistoryError::Corrupt)),
            "accepted damaged schema after {mutation}"
        );
        assert_eq!(
            slots
                .iter()
                .map(fs::read)
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            identity_files,
            "schema validation changed durable slot files after {mutation}"
        );
    }
}

#[test]
fn current_schema_validation_rejects_missing_v4_objects_and_contracts() {
    let mutations = [
        "DROP TRIGGER independent_batch_source_intent_on_terminal",
        "DROP TRIGGER batch_artifact_owner_on_insert;
         CREATE TRIGGER batch_artifact_owner_on_insert BEFORE INSERT ON job_artifacts
         BEGIN SELECT 1; END;",
        "DROP TRIGGER job_batch_intent_owner_on_update;
         CREATE TRIGGER job_batch_intent_owner_on_update
         BEFORE UPDATE OF submission_kind ON jobs
         WHEN NEW.submission_kind = 'single'
           AND EXISTS (SELECT 1 FROM batch_intents WHERE job_id = NEW.job_id)
         BEGIN SELECT RAISE(ABORT, 'single job cannot own a batch intent'); END;",
        "DROP TRIGGER independent_batch_source_intent_on_terminal;
         CREATE TRIGGER independent_batch_source_intent_on_terminal
         BEFORE UPDATE OF state ON jobs
         BEGIN SELECT 1; END;",
        "DROP INDEX job_lease_claims_blocking_slot;
         CREATE INDEX job_lease_claims_blocking_slot
         ON job_lease_claims(slot_id) WHERE state != 'released';",
        "DROP TRIGGER batch_artifact_owner_on_insert",
        "DROP INDEX job_artifacts_item_owner",
        "ALTER TABLE batch_source_intents DROP COLUMN intent_json",
        "PRAGMA foreign_keys = OFF; DROP TABLE batch_source_intents;",
        "PRAGMA foreign_keys = OFF; ALTER TABLE job_artifacts RENAME TO damaged_artifacts;
         CREATE TABLE job_artifacts (
             job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
             item_key TEXT, ordinal INTEGER NOT NULL, role TEXT NOT NULL,
             path TEXT NOT NULL, retained INTEGER NOT NULL, identity_known INTEGER NOT NULL,
             content_known INTEGER NOT NULL, evidence_json TEXT NOT NULL,
             PRIMARY KEY (job_id, ordinal)
         );
         DROP TABLE damaged_artifacts;",
        "PRAGMA foreign_keys = OFF; ALTER TABLE batch_item_checkpoints RENAME TO damaged_checkpoints;
         CREATE TABLE batch_item_checkpoints (
             job_id TEXT NOT NULL, item_key TEXT NOT NULL, sequence INTEGER NOT NULL,
             item_state TEXT NOT NULL, outcome TEXT, failure_code TEXT,
             publication_state TEXT NOT NULL, evidence_json TEXT NOT NULL,
             recorded_at TEXT NOT NULL, PRIMARY KEY (job_id, item_key),
             UNIQUE (job_id, sequence),
             FOREIGN KEY (job_id, item_key) REFERENCES job_items(job_id, item_key)
         );
         DROP TABLE damaged_checkpoints;",
        "PRAGMA foreign_keys = OFF; ALTER TABLE jobs RENAME TO damaged_jobs;
         CREATE TABLE jobs (
             job_id TEXT PRIMARY KEY, parent_job_id TEXT, kind TEXT NOT NULL,
             submission_kind TEXT NOT NULL, source TEXT, invocation_cwd TEXT NOT NULL,
             source_provenance TEXT NOT NULL, destination TEXT NOT NULL,
             destination_selection TEXT NOT NULL, workspace TEXT NOT NULL,
             workspace_selection TEXT NOT NULL, conflict_policy TEXT NOT NULL,
             conflict_policy_provenance TEXT NOT NULL, parent_conflict_policy TEXT,
             parent_conflict_policy_provenance TEXT, retry_scope TEXT NOT NULL,
             state TEXT NOT NULL, admitted_at TEXT NOT NULL, started_at TEXT,
             terminal_at TEXT, outcome TEXT, failure_code TEXT,
             cleanup_warning_code TEXT, publication_state TEXT NOT NULL,
             pruneable INTEGER NOT NULL DEFAULT 0,
             required_providers_json TEXT NOT NULL DEFAULT '[]',
             required_keys_json TEXT NOT NULL DEFAULT '[]', result_json TEXT,
             snapshot_json TEXT, lease_slot_id TEXT REFERENCES lease_slots(slot_id)
         );
         INSERT INTO jobs SELECT * FROM damaged_jobs;
         DROP TABLE damaged_jobs;
         CREATE INDEX jobs_history_order ON jobs(state, terminal_at DESC, admitted_at DESC, job_id DESC);
         CREATE INDEX jobs_parent ON jobs(parent_job_id);
         CREATE INDEX jobs_lease_slot ON jobs(lease_slot_id);",
        "PRAGMA foreign_keys = OFF;
         PRAGMA legacy_alter_table = ON;
         ALTER TABLE job_items RENAME TO damaged_job_items;
         CREATE TABLE job_items (
             job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
             ordinal INTEGER NOT NULL, item_key TEXT NOT NULL, kind TEXT NOT NULL,
             source TEXT NOT NULL, destination TEXT NOT NULL, state TEXT NOT NULL,
             outcome TEXT, failure_code TEXT, evidence_json TEXT, provenance_json TEXT,
             PRIMARY KEY (job_id, ordinal), UNIQUE (job_id, item_key)
         );
         DROP TABLE damaged_job_items;",
        "PRAGMA foreign_keys = OFF;
         PRAGMA legacy_alter_table = ON;
         ALTER TABLE job_items RENAME TO damaged_job_items;
         CREATE TABLE job_items (
             job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
             ordinal INTEGER NOT NULL, item_key TEXT NOT NULL, kind TEXT NOT NULL,
             source TEXT NOT NULL, destination TEXT NOT NULL,
             destination_assigned INTEGER NOT NULL DEFAULT 1,
             state TEXT NOT NULL, outcome TEXT, failure_code TEXT,
             evidence_json TEXT, provenance_json TEXT,
             PRIMARY KEY (job_id, ordinal), UNIQUE (job_id, item_key)
         );
         DROP TABLE damaged_job_items;",
        "PRAGMA foreign_keys = OFF;
         PRAGMA legacy_alter_table = ON;
         ALTER TABLE job_items RENAME TO damaged_job_items;
         CREATE TABLE job_items (
             job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
             ordinal INTEGER NOT NULL, item_key TEXT NOT NULL, kind TEXT NOT NULL,
             source TEXT NOT NULL, destination TEXT NOT NULL,
             destination_assigned INTEGER NOT NULL DEFAULT 1
                 CHECK (destination_assigned IN (0, 1)),
             state TEXT NOT NULL, outcome TEXT, failure_code TEXT,
             evidence_json TEXT, provenance_json TEXT,
             PRIMARY KEY (job_id, ordinal), UNIQUE (job_id, item_key)
         );
         DROP TABLE damaged_job_items;",
"PRAGMA foreign_keys = OFF;
PRAGMA legacy_alter_table = ON;
ALTER TABLE job_items RENAME TO damaged_job_items;
CREATE TABLE job_items (
    job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL, item_key TEXT NOT NULL, kind TEXT NOT NULL,
    source TEXT NOT NULL, destination TEXT NOT NULL,
    destination_assigned INTEGER DEFAULT 1,
    state TEXT NOT NULL, outcome TEXT, failure_code TEXT,
    evidence_json TEXT, provenance_json TEXT,
    PRIMARY KEY (job_id, ordinal), UNIQUE (job_id, item_key),
    CONSTRAINT job_items_destination_representation CHECK (
        (destination_assigned = 1 AND length(destination) > 0)
        OR (destination_assigned = 0 AND destination = '')
    )
);
DROP TABLE damaged_job_items;",
    ];

    let rebuild_job_items = |destination: &str, destination_assigned: &str, constraint: &str| {
        format!(
            "PRAGMA foreign_keys = OFF;
             PRAGMA legacy_alter_table = ON;
             ALTER TABLE job_items RENAME TO damaged_job_items;
             CREATE TABLE job_items (
                 job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
                 ordinal INTEGER NOT NULL, item_key TEXT NOT NULL, kind TEXT NOT NULL,
                 source TEXT NOT NULL, destination {destination},
                 destination_assigned {destination_assigned},
                 state TEXT NOT NULL, outcome TEXT, failure_code TEXT,
                 evidence_json TEXT, provenance_json TEXT,
                 PRIMARY KEY (job_id, ordinal), UNIQUE (job_id, item_key){constraint}
             );
             DROP TABLE damaged_job_items;"
        )
    };
    let expected_destination_check = ",
        CONSTRAINT job_items_destination_representation CHECK (
            (destination_assigned = 1 AND length(destination) > 0)
            OR (destination_assigned = 0 AND destination = '')
        )";
    let spoofed_destination_check = "( (destination_assigned = 1 AND length(destination) > 0) OR (destination_assigned = 0 AND destination = '') )";
    let spoofed_single_quoted_literal =
        format!("'CHECK {}'", spoofed_destination_check.replace('\'', "''"));
    let metadata_mutations = [
        (
            "destination wrong declared type",
            rebuild_job_items(
                "INTEGER NOT NULL",
                "INTEGER NOT NULL DEFAULT 1",
                expected_destination_check,
            ),
        ),
        (
            "destination_assigned wrong declared type",
            rebuild_job_items(
                "TEXT NOT NULL",
                "TEXT NOT NULL DEFAULT 1",
                expected_destination_check,
            ),
        ),
        (
            "destination wrong default",
            rebuild_job_items(
                "TEXT NOT NULL DEFAULT ''",
                "INTEGER NOT NULL DEFAULT 1",
                expected_destination_check,
            ),
        ),
        (
            "destination_assigned missing default",
            rebuild_job_items(
                "TEXT NOT NULL",
                "INTEGER NOT NULL",
                expected_destination_check,
            ),
        ),
        (
            "destination_assigned wrong default",
            rebuild_job_items(
                "TEXT NOT NULL",
                "INTEGER NOT NULL DEFAULT 0",
                expected_destination_check,
            ),
        ),
        (
            "destination nullable",
            rebuild_job_items(
                "TEXT",
                "INTEGER NOT NULL DEFAULT 1",
                expected_destination_check,
            ),
        ),
        (
            "expected check text only in double-quoted constraint name",
            rebuild_job_items(
                "TEXT NOT NULL",
                "INTEGER NOT NULL DEFAULT 1",
                ",
                 CONSTRAINT \"CHECK ((destination_assigned = 1 AND length(destination) > 0) OR (destination_assigned = 0 AND destination = ''))\"
                 CHECK (destination_assigned IN (0, 1))",
            ),
        ),
        (
            "expected check text only in a line comment",
            rebuild_job_items(
                "TEXT NOT NULL",
                "INTEGER NOT NULL DEFAULT 1",
                &format!(
                    ",
                     CONSTRAINT job_items_destination_representation CHECK (
                         destination_assigned IN (0, 1) -- CHECK {spoofed_destination_check}
                     )"
                ),
            ),
        ),
        (
            "expected check text only in a block comment",
            rebuild_job_items(
                "TEXT NOT NULL",
                "INTEGER NOT NULL DEFAULT 1",
                &format!(
                    ",
                     CONSTRAINT job_items_destination_representation CHECK (
                         destination_assigned IN (0, 1) /* CHECK {spoofed_destination_check} */
                     )"
                ),
            ),
        ),
        (
            "expected check text only in a single-quoted literal",
            rebuild_job_items(
                "TEXT NOT NULL",
                "INTEGER NOT NULL DEFAULT 1",
                &format!(
                    ",
                     CONSTRAINT job_items_destination_representation CHECK (
                         destination_assigned IN (0, 1)
                         AND {spoofed_single_quoted_literal} IS NOT NULL
                     )"
                ),
            ),
        ),
        (
            "expected check text only in a backtick-quoted constraint name",
            rebuild_job_items(
                "TEXT NOT NULL",
                "INTEGER NOT NULL DEFAULT 1",
                &format!(
                    ",
                     CONSTRAINT `CHECK {spoofed_destination_check}`
                     CHECK (destination_assigned IN (0, 1))"
                ),
            ),
        ),
        (
            "expected check text only in a bracket-quoted constraint name",
            rebuild_job_items(
                "TEXT NOT NULL",
                "INTEGER NOT NULL DEFAULT 1",
                &format!(
                    ",
                     CONSTRAINT [CHECK {spoofed_destination_check}]
                     CHECK (destination_assigned IN (0, 1))"
                ),
            ),
        ),
    ];
    for (case, mutation) in mutations
        .into_iter()
        .map(|mutation| ("existing fixture", mutation.to_owned()))
        .chain(metadata_mutations)
    {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("jobs.sqlite3");
        drop(HistoryStore::open_at(&path).unwrap());
        Connection::open(&path)
            .unwrap()
            .execute_batch(&mutation)
            .unwrap();
        assert!(
            matches!(HistoryStore::open_at(&path), Err(HistoryError::Corrupt)),
            "accepted damaged current schema after {case}: {mutation}"
        );
    }

    let commented_destination_check = ",
        CONSTRAINT job_items_destination_representation CHECK (
            -- Comments do not change the required expression.
            (destination_assigned = 1 AND length(destination) > 0)
            /* Block comments are also inert. */
            OR (destination_assigned = 0 AND destination = '')
        )";
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    drop(HistoryStore::open_at(&path).unwrap());
    Connection::open(&path)
        .unwrap()
        .execute_batch(&rebuild_job_items(
            "TEXT NOT NULL",
            "INTEGER NOT NULL DEFAULT 1",
            commented_destination_check,
        ))
        .unwrap();
    assert!(
        HistoryStore::open_at(&path).is_ok(),
        "rejected canonical destination constraint with internal comments"
    );
}

#[test]
fn batch_intent_ownership_is_enforced_and_checked_when_loading_jobs() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let store = HistoryStore::open_at(&path).unwrap();
    let admitted = store
        .begin_admission(admission())
        .unwrap()
        .commit()
        .unwrap();
    let store = HistoryStore::open_at(&path).unwrap();
    let insert = "INSERT INTO batch_intents (job_id, schema_version, kind, intent_json)
                  VALUES (?1, 1, 'nscb.copy_batch_intent', '{}')";

    assert!(
        store
            .connection
            .execute(insert, [&admitted.job_id])
            .is_err()
    );
    store
        .connection
        .execute("DROP TRIGGER batch_intent_owner_on_insert", [])
        .unwrap();
    store
        .connection
        .execute(insert, [&admitted.job_id])
        .unwrap();
    assert!(
        store
            .connection
            .execute(
                "UPDATE jobs SET submission_kind = 'single', source = '/fixture/source.bin'
             WHERE job_id = ?1",
                [&admitted.job_id],
            )
            .is_err()
    );
    store
        .connection
        .execute("DROP TRIGGER job_batch_intent_owner_on_update", [])
        .unwrap();
    store
        .connection
        .execute(
            "UPDATE jobs SET submission_kind = 'single', source = '/fixture/source.bin'
             WHERE job_id = ?1",
            [&admitted.job_id],
        )
        .unwrap();

    assert_eq!(store.load(&admitted.job_id), Err(HistoryError::QueryFailed));
}

#[test]
fn batch_source_intent_ownership_is_enforced_when_submission_kind_changes() {
    let store = valid_failed_batch_store();
    let update = "UPDATE jobs SET submission_kind = 'single', source = '/fixture/first.bin'
                  WHERE job_id = 'batch'";

    store
        .connection
        .execute("DELETE FROM batch_intents WHERE job_id = 'batch'", [])
        .unwrap();
    assert!(store.connection.execute(update, []).is_err());

    store
        .connection
        .execute("DROP TRIGGER job_batch_intent_owner_on_update", [])
        .unwrap();
    store.connection.execute(update, []).unwrap();
    assert_eq!(store.load("batch"), Err(HistoryError::QueryFailed));
}

#[test]
fn begin_running_rolls_back_job_when_the_item_update_fails() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let store = HistoryStore::open_at(&path).unwrap();
    let pending = store.begin_admission(admission()).unwrap();
    let admitted = pending.commit().unwrap();
    let store = HistoryStore::open_at(&path).unwrap();
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_running_item
             BEFORE UPDATE ON job_items
             WHEN NEW.state = 'running'
             BEGIN SELECT RAISE(ABORT, 'injected item transition failure'); END;",
        )
        .unwrap();

    assert!(store.begin_running(&admitted.job_id).is_err());
    let connection = Connection::open(&path).unwrap();
    let job_state: String = connection
        .query_row(
            "SELECT state FROM jobs WHERE job_id = ?1",
            [&admitted.job_id],
            |row| row.get(0),
        )
        .unwrap();
    let item_state: String = connection
        .query_row(
            "SELECT state FROM job_items WHERE job_id = ?1",
            [&admitted.job_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(job_state, "admitted");
    assert_eq!(item_state, "planned");
}

#[test]
fn recovery_backup_rejects_child_item_and_artifact_row_mismatches() {
    for table in ["job_items", "job_artifacts"] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("jobs.sqlite3");
        let connection = create_v2_database(&path, "legacy-job", "succeeded");
        if table == "job_items" {
            connection
                .execute(
                    "INSERT INTO job_items
                     (job_id, ordinal, item_key, kind, source, destination, state,
                      outcome, failure_code, evidence_json)
                     VALUES ('legacy-job', 0, 'item-0', 'copy', '/source', '/destination',
                             'succeeded', 'copied', NULL, NULL)",
                    [],
                )
                .unwrap();
        } else {
            connection
                .execute(
                    "INSERT INTO job_artifacts
                     (job_id, ordinal, role, path, retained, identity_known,
                      content_known, evidence_json)
                     VALUES ('legacy-job', 0, 'workspace', '/workspace', 1, 1, 1, '{}')",
                    [],
                )
                .unwrap();
        }
        let backup = create_recovery_backup(&connection, &path, 2).unwrap();
        drop(connection);

        let backup_connection = Connection::open(backup).unwrap();
        backup_connection
            .execute(
                &format!(
                    "UPDATE {table} SET {} = '{}' WHERE job_id = 'legacy-job'",
                    if table == "job_items" {
                        "outcome"
                    } else {
                        "path"
                    },
                    "changed"
                ),
                [],
            )
            .unwrap();
        drop(backup_connection);

        assert!(
            matches!(
                HistoryStore::open_at(&path),
                Err(HistoryError::BackupFailed)
            ),
            "accepted changed {table} rows in the recovery backup"
        );
        let connection = Connection::open(path).unwrap();
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 2);
    }
}
#[test]
fn nontrivial_migration_preserves_rows_and_creates_recovery_backup() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    drop(create_v1_database(&path));

    let store = HistoryStore::open_at(&path).unwrap();
    assert_eq!(store.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    let jobs = store.list().unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].job_id, "legacy-job");

    let backup = path.with_extension("sqlite3.v1.bak");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let backup_connection =
        Connection::open_with_flags(backup, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(
        backup_connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn v1_migration_backup_includes_a_writer_waiting_to_commit() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let connection = create_v1_database(&path);
    connection
        .execute_batch("PRAGMA journal_mode = WAL;")
        .unwrap();
    drop(connection);

    let writer_ready = Arc::new(Barrier::new(2));
    let release_writer = V1_MIGRATION_WRITER_RELEASE.get_or_init(|| Barrier::new(2));
    let writer_path = path.clone();
    let writer_ready_for_thread = Arc::clone(&writer_ready);
    let writer = std::thread::spawn(move || {
        let writer = Connection::open(writer_path).unwrap();
        writer.execute_batch("BEGIN IMMEDIATE;").unwrap();
        writer
            .execute(
                "UPDATE jobs SET outcome = 'writer-committed' WHERE job_id = 'legacy-job'",
                [],
            )
            .unwrap();
        writer_ready_for_thread.wait();
        release_writer.wait();
        writer.execute_batch("COMMIT;").unwrap();
    });
    writer_ready.wait();

    let mut migration = Connection::open(&path).unwrap();
    V1_MIGRATION_RELEASE_ON_BUSY.store(true, Ordering::SeqCst);
    migration
        .busy_handler(Some(release_v1_migration_writer_on_busy))
        .unwrap();

    super::storage::migrate_v1_to_v2(&mut migration, &path).unwrap();
    writer.join().unwrap();

    let backup_path = path.with_extension("sqlite3.v1.bak");
    let backup =
        Connection::open_with_flags(backup_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let backup_outcome: String = backup
        .query_row(
            "SELECT outcome FROM jobs WHERE job_id = 'legacy-job'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(backup_outcome, "writer-committed");

    let migrated_outcome: String = migration
        .query_row(
            "SELECT outcome FROM jobs WHERE job_id = 'legacy-job'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(migrated_outcome, "writer-committed");
}

#[test]
fn version_one_upgrades_through_version_two_before_adding_lease_slots() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let mut connection = create_v1_database(&path);
    super::storage::migrate_v1_to_v2(&mut connection, &path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'lease_slots'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    drop(connection);

    let store = HistoryStore::open_at(&path).unwrap();
    assert_eq!(store.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    assert_eq!(store.list().unwrap()[0].job_id, "legacy-job");
    assert!(path.with_extension("sqlite3.v1.bak").is_file());
    assert!(path.with_extension("sqlite3.v2.bak").is_file());
}

#[test]
fn v2_migration_rolls_back_when_backup_parent_sync_fails() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    drop(create_v2_database(&path, "sync-failure-job", "succeeded"));
    let mut connection = Connection::open(&path).unwrap();
    let sync_called = std::cell::Cell::new(false);

    let result = super::storage::migrate_v2_to_v3_with_parent_sync(&mut connection, &path, |_| {
        sync_called.set(true);
        Err(std::io::Error::other(
            "injected parent directory sync failure",
        ))
    });

    assert!(
        path.with_extension("sqlite3.v2.bak").exists(),
        "the recovery backup must be published before its parent is synced"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'lease_slots'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0,
        "schema changes must roll back when backup parent sync fails",
    );
    assert_eq!(result.unwrap_err(), HistoryError::BackupFailed);
    assert!(sync_called.get(), "backup parent sync must be attempted");
}

#[test]
fn v2_migration_succeeds_when_parent_directory_sync_is_unsupported() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    drop(create_v2_database(
        &path,
        "unsupported-sync-job",
        "succeeded",
    ));
    let original = Connection::open(&path).unwrap();
    let old_schema = query_rows_for_test(
        &original,
        "SELECT type, name, tbl_name, sql FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    );
    let old_jobs = query_rows_for_test(&original, "SELECT * FROM jobs ORDER BY rowid");
    drop(original);

    let mut connection = Connection::open(&path).unwrap();
    let result = super::storage::migrate_v2_to_v3_with_parent_sync(&mut connection, &path, |_| {
        Ok(super::storage::ParentDirectorySyncOutcome::Unsupported)
    });

    assert_eq!(result, Ok(()));
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        2
    );
    let backup_path = path.with_extension("sqlite3.v2.bak");
    assert!(backup_path.is_file());
    let backup =
        Connection::open_with_flags(&backup_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(
        query_rows_for_test(
            &backup,
            "SELECT type, name, tbl_name, sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        ),
        old_schema
    );
    assert_eq!(
        query_rows_for_test(&backup, "SELECT * FROM jobs ORDER BY rowid"),
        old_jobs
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT state FROM jobs WHERE job_id = 'unsupported-sync-job'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "succeeded"
    );
    drop(backup);
    drop(connection);

    let store = HistoryStore::open_at(&path).unwrap();
    assert_eq!(store.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    assert_eq!(
        store.load("unsupported-sync-job").unwrap().state,
        "succeeded"
    );
}

#[test]
fn version_two_backup_failure_preserves_the_complete_version_two_database() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let mut connection = create_v1_database(&path);
    super::storage::migrate_v1_to_v2(&mut connection, &path).unwrap();
    drop(connection);
    fs::create_dir(path.with_extension("sqlite3.v2.bak")).unwrap();

    assert_eq!(
        HistoryStore::open_at(&path).unwrap_err(),
        HistoryError::BackupFailed
    );
    let connection = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[cfg(unix)]
#[test]
fn v2_migration_never_interrupts_a_job_with_a_live_legacy_lock() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let job_id = lease_token(1);
    drop(create_v2_database(&path, &job_id, "running"));
    let lock_directory = root.path().join("job-locks");
    fs::create_dir_all(&lock_directory).unwrap();
    let lock_path = lock_directory.join(format!("{job_id}.lock"));
    let lock_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(lock_path)
        .unwrap();
    lock_file.lock_exclusive().unwrap();

    assert!(matches!(
        HistoryStore::open_at(&path),
        Err(HistoryError::LockFailed | HistoryError::MigrationFailed)
    ));
    let connection = Connection::open(&path).unwrap();
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    let state: String = connection
        .query_row(
            "SELECT state FROM jobs WHERE job_id = ?1",
            [&job_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(version, 2);
    assert_eq!(state, "running");
    assert!(!path.with_extension("sqlite3.v2.bak").exists());
}

#[test]
fn v2_migration_fails_closed_when_an_active_job_has_no_legacy_lock_file() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let job_id = lease_token(3);
    drop(create_v2_database(&path, &job_id, "admitted"));

    assert!(matches!(
        HistoryStore::open_at(&path),
        Err(HistoryError::LockFailed)
    ));
    let connection = Connection::open(&path).unwrap();
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    let state: String = connection
        .query_row(
            "SELECT state FROM jobs WHERE job_id = ?1",
            [&job_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(version, 2);
    assert_eq!(state, "admitted");
    assert!(!path.with_extension("sqlite3.v2.bak").exists());
}

#[test]
fn v2_migration_marks_abandoned_active_jobs_interrupted_and_unresolved() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let job_id = lease_token(2);
    let connection = create_v2_database(&path, &job_id, "running");
    connection
        .execute(
            "INSERT INTO job_items
             (job_id, ordinal, item_key, kind, source, destination, state,
              outcome, failure_code, evidence_json)
             VALUES (?1, 0, 'item-0', 'copy', '/source', '/destination',
                     'running', NULL, NULL, NULL)",
            [&job_id],
        )
        .unwrap();
    drop(connection);
    let lock_directory = root.path().join("job-locks");
    fs::create_dir_all(&lock_directory).unwrap();
    fs::write(lock_directory.join(format!("{job_id}.lock")), b"").unwrap();

    let store = HistoryStore::open_at(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    let state: String = connection
        .query_row(
            "SELECT state FROM jobs WHERE job_id = ?1",
            [&job_id],
            |row| row.get(0),
        )
        .unwrap();
    let item_state: String = connection
        .query_row(
            "SELECT state FROM job_items WHERE job_id = ?1",
            [&job_id],
            |row| row.get(0),
        )
        .unwrap();
    let claim_state: String = connection
        .query_row(
            "SELECT state FROM job_lease_claims WHERE job_id = ?1",
            [&job_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "interrupted");
    assert_eq!(item_state, "interrupted");
    assert_eq!(claim_state, "unresolved");
    assert_eq!(store.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
}

#[test]
fn pending_v2_schema_finishes_slot_initialization_after_restart() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let mut connection = create_v2_database(&path, "legacy-job", "succeeded");
    super::storage::migrate_v2_to_v3(&mut connection, &path).unwrap();
    let pending_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    drop(connection);

    assert_eq!(pending_version, 2);
    let store = HistoryStore::open_at(&path).unwrap();
    assert_eq!(store.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    let pending = store.begin_admission(admission()).unwrap();
    assert!(pending.commit().is_ok());
}

#[test]
fn migration_backup_failure_leaves_old_database_unchanged() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    drop(create_v1_database(&path));
    fs::create_dir(path.with_extension("sqlite3.v1.bak")).unwrap();

    assert_eq!(
        HistoryStore::open_at(&path).unwrap_err(),
        HistoryError::BackupFailed
    );
    let connection = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[cfg(unix)]
#[test]
fn recovery_backup_rejects_public_backup_left_by_interrupted_creation() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let source = create_v1_database(&path);
    let backup = path.with_extension("sqlite3.v1.bak");
    source
        .execute("VACUUM INTO ?1", [backup.to_str().unwrap()])
        .unwrap();
    fs::set_permissions(&backup, fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(
        create_recovery_backup(&source, &path, 1),
        Err(HistoryError::BackupFailed)
    );
    assert_eq!(
        fs::metadata(backup).unwrap().permissions().mode() & 0o777,
        0o644
    );
}

#[test]
fn migration_rolls_back_after_a_recovery_backup_when_schema_change_fails() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let connection = create_v1_database(&path);
    connection
        // This conflicts after the migration has added columns, tables, and an index.
        .execute_batch("CREATE INDEX jobs_parent ON jobs(parent_job_id);")
        .unwrap();
    let old_schema = query_rows_for_test(
        &connection,
        "SELECT type, name, tbl_name, sql FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    );
    let old_jobs = query_rows_for_test(&connection, "SELECT * FROM jobs ORDER BY rowid");
    drop(connection);

    assert_eq!(
        HistoryStore::open_at(&path).unwrap_err(),
        HistoryError::MigrationFailed
    );
    let connection = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        query_rows_for_test(
            &connection,
            "SELECT type, name, tbl_name, sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        ),
        old_schema
    );
    assert_eq!(
        query_rows_for_test(&connection, "SELECT * FROM jobs ORDER BY rowid"),
        old_jobs
    );

    let backup_path = path.with_extension("sqlite3.v1.bak");
    assert!(backup_path.is_file());
    let backup =
        Connection::open_with_flags(&backup_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(
        query_rows_for_test(
            &backup,
            "SELECT type, name, tbl_name, sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        ),
        old_schema
    );
    assert_eq!(
        query_rows_for_test(&backup, "SELECT * FROM jobs ORDER BY rowid"),
        old_jobs
    );
}

#[test]
fn v1_migration_process_crash_before_commit_preserves_backup_and_retries() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let original = create_v1_database(&path);
    let old_schema = query_rows_for_test(
        &original,
        "SELECT type, name, tbl_name, sql FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    );
    let old_jobs = query_rows_for_test(&original, "SELECT * FROM jobs ORDER BY rowid");
    drop(original);

    let crash_marker = root.path().join("migration-ddl-reached");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "standalone::history::tests::child_v1_migration_crash_injection",
            "--nocapture",
        ])
        .env(CHILD_V1_MIGRATION_DATABASE, &path)
        .env(CHILD_V1_MIGRATION_DDL_REACHED, &crash_marker)
        .current_dir(root.path())
        .spawn()
        .unwrap();
    await_migration_crash_marker(&mut child, &crash_marker);
    child
        .kill()
        .expect("migration child could not be killed at DDL marker");
    let child_status = child.wait().expect("migration child could not be reaped");
    assert!(
        !child_status.success(),
        "migration child unexpectedly exited successfully after being killed"
    );

    let backup_path = path.with_extension("sqlite3.v1.bak");
    assert!(backup_path.is_file());
    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        query_rows_for_test(
            &connection,
            "SELECT type, name, tbl_name, sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        ),
        old_schema
    );
    assert_eq!(
        query_rows_for_test(&connection, "SELECT * FROM jobs ORDER BY rowid"),
        old_jobs
    );
    let backup =
        Connection::open_with_flags(&backup_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(
        query_rows_for_test(
            &backup,
            "SELECT type, name, tbl_name, sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        ),
        old_schema
    );
    assert_eq!(
        query_rows_for_test(&backup, "SELECT * FROM jobs ORDER BY rowid"),
        old_jobs
    );
    drop(backup);
    drop(connection);

    let retried = HistoryStore::open_at(&path).unwrap();
    assert_eq!(retried.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    assert_eq!(retried.load("legacy-job").unwrap().state, "succeeded");
    let migrated_job: (String, String, String, String, String, Option<String>) = retried
        .connection
        .query_row(
            "SELECT job_id, source, destination, workspace, state, outcome
             FROM jobs WHERE job_id = 'legacy-job'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        migrated_job,
        (
            "legacy-job".to_owned(),
            "/fixture/source.bin".to_owned(),
            "/fixture/output.bin".to_owned(),
            "/fixture/workspace".to_owned(),
            "succeeded".to_owned(),
            Some("copied".to_owned()),
        )
    );
}

/// Waits until the child publishes the complete migration DDL marker payload.
///
/// The marker path can exist before its contents become visible, so file existence alone does not
/// establish that the child reached the crash boundary. This helper also stops and reaps the child
/// when waiting fails.
fn await_migration_crash_marker(child: &mut std::process::Child, path: &Path) {
    const EXPECTED_CONTENT: &[u8] = b"ddl-applied";
    let deadline = Instant::now() + Duration::from_secs(10);

    loop {
        match fs::read(path) {
            Ok(contents) if contents == EXPECTED_CONTENT => return,
            Ok(contents) if EXPECTED_CONTENT.starts_with(&contents) => {}
            Ok(contents) => {
                let cleanup = stop_migration_child(child);
                panic!(
                    "migration DDL marker {} had unexpected content: {:?}{cleanup}",
                    path.display(),
                    String::from_utf8_lossy(&contents),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                let cleanup = stop_migration_child(child);
                panic!(
                    "could not read migration DDL marker {}: {error}{cleanup}",
                    path.display(),
                );
            }
        }

        match child.try_wait() {
            Ok(Some(status)) => panic!("migration child exited before DDL marker: {status}"),
            Ok(None) => {}
            Err(error) => {
                let cleanup = stop_migration_child(child);
                panic!("could not check migration child status: {error}{cleanup}");
            }
        }

        if Instant::now() >= deadline {
            let cleanup = stop_migration_child(child);
            panic!("timed out waiting for complete migration DDL marker{cleanup}");
        }
        std::thread::yield_now();
    }
}

fn stop_migration_child(child: &mut std::process::Child) -> String {
    let kill_error = child.kill().err();
    let wait_error = child.wait().err();
    match (kill_error, wait_error) {
        (None, None) => String::new(),
        (Some(error), None) => {
            format!("; additionally could not kill migration child: {error}")
        }
        (None, Some(error)) => {
            format!("; additionally could not reap migration child: {error}")
        }
        (Some(kill_error), Some(wait_error)) => format!(
            "; additionally could not kill migration child: {kill_error}; \
             could not reap migration child: {wait_error}"
        ),
    }
}

#[test]
fn child_v1_migration_crash_injection() {
    let Some(path) = std::env::var_os(CHILD_V1_MIGRATION_DATABASE) else {
        return;
    };
    drop(HistoryStore::open_at(path).unwrap());
}

#[test]
fn v3_migration_process_crash_rolls_back_and_reopens_safely() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let original = v3_database_for_migration(&path);
    original
        .execute(
            "INSERT INTO job_items
             (job_id, ordinal, item_key, kind, source, destination, state, evidence_json)
             VALUES ('migration-job', 0, 'legacy-item', 'copy_through', '/source',
                     '/destination', 'succeeded', '{}')",
            [],
        )
        .unwrap();
    original
        .execute(
            "INSERT INTO job_artifacts
             (job_id, ordinal, role, path, retained, identity_known, content_known, evidence_json)
             VALUES ('migration-job', 0, 'workspace', '/workspace', 1, 1, 1, '{}')",
            [],
        )
        .unwrap();
    let slot_id = original
        .query_row(
            "SELECT slot_id FROM lease_slots ORDER BY ordinal LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    original
        .execute(
            "UPDATE jobs SET lease_slot_id = ?1 WHERE job_id = 'migration-job'",
            [&slot_id],
        )
        .unwrap();
    original
        .execute(
            "INSERT INTO job_lease_claims
             (claim_id, job_id, slot_id, claim_token, state, created_at, resolved_at)
             VALUES ('legacy-claim', 'migration-job', ?1, 'legacy-token',
                     'released', '2026-01-01T00:00:00Z',
                     '2026-01-01T00:00:01Z')",
            [&slot_id],
        )
        .unwrap();
    let old_schema = query_rows_for_test(
        &original,
        "SELECT type, name, tbl_name, sql FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    );
    let old_jobs = query_rows_for_test(&original, "SELECT * FROM jobs ORDER BY rowid");
    let old_items = query_rows_for_test(&original, "SELECT * FROM job_items ORDER BY rowid");
    let old_artifacts =
        query_rows_for_test(&original, "SELECT * FROM job_artifacts ORDER BY rowid");
    let old_claims =
        query_rows_for_test(&original, "SELECT * FROM job_lease_claims ORDER BY rowid");
    let old_registry =
        query_rows_for_test(&original, "SELECT * FROM history_registry ORDER BY rowid");
    drop(original);

    let crash_marker = root.path().join("v3-migration-ddl-reached");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "standalone::history::tests::child_v3_migration_crash_injection",
            "--nocapture",
        ])
        .env(CHILD_V3_MIGRATION_DATABASE, &path)
        .env(CHILD_V3_MIGRATION_DDL_REACHED, &crash_marker)
        .current_dir(root.path())
        .spawn()
        .unwrap();
    await_migration_crash_marker(&mut child, &crash_marker);
    child
        .kill()
        .expect("v3 migration child could not be killed at DDL marker");
    assert!(
        !child
            .wait()
            .expect("v3 migration child could not be reaped")
            .success(),
        "v3 migration child unexpectedly exited after DDL marker"
    );

    let rolled_back = Connection::open(&path).unwrap();
    assert_eq!(
        rolled_back
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        query_rows_for_test(
            &rolled_back,
            "SELECT type, name, tbl_name, sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        ),
        old_schema
    );
    assert_eq!(
        query_rows_for_test(&rolled_back, "SELECT * FROM jobs ORDER BY rowid"),
        old_jobs
    );
    assert_eq!(
        query_rows_for_test(&rolled_back, "SELECT * FROM job_items ORDER BY rowid"),
        old_items
    );
    assert_eq!(
        query_rows_for_test(&rolled_back, "SELECT * FROM job_artifacts ORDER BY rowid"),
        old_artifacts
    );
    assert_eq!(
        query_rows_for_test(
            &rolled_back,
            "SELECT * FROM job_lease_claims ORDER BY rowid"
        ),
        old_claims
    );
    assert_eq!(
        query_rows_for_test(
            &rolled_back,
            "SELECT * FROM history_registry ORDER BY rowid"
        ),
        old_registry
    );
    assert!(path.with_extension("sqlite3.v3.bak").is_file());
    drop(rolled_back);

    let reopened = HistoryStore::open_at(&path).unwrap();
    assert_eq!(reopened.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    assert_eq!(
        reopened
            .connection
            .query_row(
                "SELECT path FROM job_artifacts WHERE job_id = 'migration-job'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "/workspace"
    );
    assert_eq!(
        reopened
            .connection
            .query_row(
                "SELECT state FROM job_lease_claims WHERE job_id = 'migration-job'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "released"
    );
}

#[test]
fn child_v3_migration_crash_injection() {
    let Some(path) = std::env::var_os(CHILD_V3_MIGRATION_DATABASE) else {
        return;
    };
    drop(HistoryStore::open_at(path).unwrap());
}

#[test]
fn migration_rejects_a_different_existing_recovery_backup() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    drop(create_v1_database(&path));
    let backup = path.with_extension("sqlite3.v1.bak");
    let backup_connection = create_v1_database(&backup);
    backup_connection.execute("DELETE FROM jobs", []).unwrap();
    drop(backup_connection);

    assert_eq!(
        HistoryStore::open_at(&path).unwrap_err(),
        HistoryError::BackupFailed
    );
    let connection = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn migration_rejects_a_recovery_backup_with_different_job_content() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    drop(create_v1_database(&path));
    let backup = path.with_extension("sqlite3.v1.bak");
    let backup_connection = create_v1_database(&backup);
    backup_connection
        .execute("UPDATE jobs SET destination = '/different/output.bin'", [])
        .unwrap();
    drop(backup_connection);
    assert_eq!(
        HistoryStore::open_at(&path).unwrap_err(),
        HistoryError::BackupFailed
    );
    let connection = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT destination FROM jobs", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
        "/fixture/output.bin"
    );
}

#[test]
fn recovery_backup_comparison_covers_every_job_column() {
    let column_probe = tempfile::tempdir().unwrap();
    let column_path = column_probe.path().join("jobs.sqlite3");
    let store = HistoryStore::open_at(&column_path).unwrap();
    store
        .begin_admission(admission())
        .unwrap()
        .commit()
        .unwrap();
    let connection = Connection::open(&column_path).unwrap();
    let mut statement = connection.prepare("PRAGMA table_info(jobs)").unwrap();
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(columns.len() > 15, "regression must cover post-v1 columns");
    drop(statement);
    drop(connection);

    for column in columns {
        // The source contract makes `submission_kind` inseparable from `source`.
        // Its recovery comparison is covered as a coupled row update below.
        if column == "submission_kind" {
            continue;
        }
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("jobs.sqlite3");
        let store = HistoryStore::open_at(&path).unwrap();
        store
            .begin_admission(admission())
            .unwrap()
            .commit()
            .unwrap();
        let source = Connection::open(&path).unwrap();
        let backup = create_recovery_backup(&source, &path, CURRENT_SCHEMA_VERSION).unwrap();
        let backup_connection = Connection::open(&backup).unwrap();
        backup_connection
            .execute_batch("PRAGMA foreign_keys = OFF;")
            .unwrap();
        backup_connection
            .execute(
                &format!("UPDATE jobs SET \"{column}\" = 'different-value'"),
                [],
            )
            .unwrap();
        drop(backup_connection);
        assert_eq!(
            create_recovery_backup(&source, &path, CURRENT_SCHEMA_VERSION),
            Err(HistoryError::BackupFailed),
            "column {column} was omitted from recovery comparison"
        );
    }
}

#[test]
fn recovery_backup_comparison_covers_source_submission_contract_as_a_pair() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let store = HistoryStore::open_at(&path).unwrap();
    store
        .begin_admission(admission())
        .unwrap()
        .commit()
        .unwrap();
    let source = Connection::open(&path).unwrap();
    create_recovery_backup(&source, &path, CURRENT_SCHEMA_VERSION).unwrap();

    let backup = path.with_extension("sqlite3.v4.bak");
    let backup_connection = Connection::open(&backup).unwrap();
    backup_connection
        .execute_batch("PRAGMA foreign_keys = OFF;")
        .unwrap();
    backup_connection
        .execute(
            "UPDATE jobs SET submission_kind = 'independent_batch', source = NULL",
            [],
        )
        .unwrap();
    drop(backup_connection);

    assert_eq!(
        create_recovery_backup(&source, &path, CURRENT_SCHEMA_VERSION),
        Err(HistoryError::BackupFailed)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn completion_persists_authoritative_result_items_and_recovery_evidence() {
    use nscb::{CopyThroughRequest, Engine, OperationSession};

    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source.bin");
    let destination = root.path().join("destination.bin");
    let workspace = root.path().join("workspace");
    fs::write(&source, b"durable history source").unwrap();
    fs::create_dir(&workspace).unwrap();
    let plan = Engine::new()
        .plan_copy_through(CopyThroughRequest::new(&source, &destination, &workspace))
        .unwrap();
    let database = root.path().join("jobs.sqlite3");
    let mut input = admission();
    input.source = AdmissionSource::Single(source.clone());
    input.destination = destination.clone();
    input.workspace = workspace.clone();
    input.items[0].source = source;
    input.items[0].destination = Some(destination);
    let pending = HistoryStore::open_at(&database)
        .unwrap()
        .begin_admission(input)
        .unwrap();
    let lease = pending.acquire_lease().unwrap();
    let admitted = pending.commit().unwrap();
    let mut store = HistoryStore::open_at(&database).unwrap();
    store.begin_running(&admitted.job_id).unwrap();
    let session = OperationSession::new();
    let result = Engine::new().execute_operation(plan, &session);
    assert_eq!(result.state(), JobState::Succeeded);
    let completion = session.last_completion().unwrap().unwrap();
    store.complete(&admitted.job_id, &completion).unwrap();
    drop(lease);

    let detail = store.load(&admitted.job_id).unwrap();
    assert_eq!(detail.state, "succeeded");
    assert_eq!(detail.outcome.as_deref(), Some("copied"));
    assert_eq!(detail.publication_state, "completed");
    assert_eq!(detail.items.len(), 1);
    assert_eq!(detail.items[0].state, "succeeded");
    assert!(detail.items[0].evidence.is_some());
    assert!(detail.result.is_some());
    assert!(detail.snapshot.is_some());
    let artifacts: i64 = store
        .connection
        .query_row(
            "SELECT COUNT(*) FROM job_artifacts WHERE job_id = ?1",
            [&admitted.job_id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(artifacts > 0);
}

#[test]
fn publication_classification_preserves_published_artifacts_without_an_outcome() {
    assert_eq!(
        classify_publication(false, None, [OperationArtifactRole::PublishedDestination]),
        "published_unresolved"
    );
    assert_eq!(classify_publication(false, None, []), "not_completed");
    assert_eq!(
        classify_publication(true, None, [OperationArtifactRole::PublishedDestination]),
        "completed"
    );
    assert_eq!(
        classify_publication(
            false,
            Some(nscb::OperationFailureCode::PublicationUncertain),
            [OperationArtifactRole::PublishedDestination]
        ),
        "uncertain"
    );
}

#[test]
fn completion_pruneability_preserves_uncertain_and_unknown_publication_evidence() {
    for publication_state in [
        "published_unresolved",
        "uncertain",
        "unknown",
        "future_publication",
    ] {
        assert!(
            !completion_entry_is_pruneable("failed", publication_state, false),
            "completion entry with {publication_state} publication state was pruneable"
        );
    }

    assert!(!completion_entry_is_pruneable(
        "interrupted",
        "not_started",
        false
    ));
    assert!(!completion_entry_is_pruneable(
        "failed",
        "not_completed",
        true
    ));
    assert!(completion_entry_is_pruneable(
        "failed",
        "not_completed",
        false
    ));
    assert!(completion_entry_is_pruneable(
        "succeeded",
        "completed",
        false
    ));
}

#[test]
fn live_lease_prevents_interruption_and_released_lease_proves_abandonment() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let store = HistoryStore::open_at(&path).unwrap();
    let pending = store.begin_admission(admission()).unwrap();
    let lease = pending.acquire_lease().unwrap();
    let admitted = pending.commit().unwrap();
    let job_id = admitted.job_id.clone();
    let reopened = HistoryStore::open_at(&path).unwrap();
    reopened.begin_running(&job_id).unwrap();

    assert_eq!(reopened.reconcile_interrupted().unwrap(), 0);
    assert_eq!(reopened.load(&job_id).unwrap().state, "running");
    drop(lease);
    drop(admitted);
    assert_eq!(reopened.reconcile_interrupted().unwrap(), 1);
    let detail = reopened.load(&job_id).unwrap();
    assert_eq!(detail.state, "interrupted");
    assert_eq!(detail.failure_code.as_deref(), Some("interrupted"));
    assert_eq!(detail.publication_state, "unknown");
    assert_eq!(detail.items[0].state, "interrupted");
}

#[test]
fn item_interruption_failure_rolls_back_job_recovery() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let store = HistoryStore::open_at(&path).unwrap();
    let pending = store.begin_admission(admission()).unwrap();
    let lease = pending.acquire_lease().unwrap();
    let admitted = pending.commit().unwrap();
    let job_id = admitted.job_id.clone();
    drop(lease);
    drop(admitted);

    let reopened = HistoryStore::open_at(&path).unwrap();
    reopened.begin_running(&job_id).unwrap();
    reopened
        .connection
        .execute_batch(
            "CREATE TRIGGER reject_item_interruption
             BEFORE UPDATE OF state ON job_items
             WHEN OLD.state = 'running' AND NEW.state = 'interrupted'
             BEGIN SELECT RAISE(ABORT, 'injected item interruption failure'); END;",
        )
        .unwrap();

    assert_eq!(
        reopened.reconcile_interrupted(),
        Err(HistoryError::CompletionFailed)
    );

    let detail = reopened.load(&job_id).unwrap();
    assert_eq!(detail.state, "running");
    assert_eq!(detail.failure_code, None);
    assert_eq!(detail.terminal_at, None);
    assert_eq!(detail.publication_state, "not_started");
    assert_eq!(detail.items[0].state, "running");
    assert_eq!(detail.items[0].failure_code, None);

    let (claim_state, resolved_at): (String, Option<String>) = reopened
        .connection
        .query_row(
            "SELECT state, resolved_at
             FROM job_lease_claims WHERE job_id = ?1",
            [&job_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(claim_state, "outstanding");
    assert_eq!(resolved_at, None);
}

#[cfg(unix)]
#[test]
fn cross_process_owner_lease_prevents_interruption() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let admitted = HistoryStore::open_at(&path)
        .unwrap()
        .begin_admission(admission())
        .unwrap()
        .commit()
        .unwrap();
    let job_id = admitted.job_id.clone();
    drop(admitted);
    let (slot_key, slot_id, claim_token) = claim_coordinates(&path, &job_id);
    let slot_path = root.path().join("job-locks").join(slot_key);
    let legacy_record =
        format!("NSCB-LEASE-SLOT-V2\nslot={slot_id}\njob={job_id}\nclaim={claim_token}\n");
    fs::write(&slot_path, legacy_record.as_bytes()).unwrap();
    use std::os::unix::fs::MetadataExt;
    let slot_inode = fs::metadata(&slot_path).unwrap().ino();

    let ready = root.path().join("child-ready");
    let release = root.path().join("child-release");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "standalone::history::tests::child_process_lease_holder",
            "--nocapture",
        ])
        .env(CHILD_OWNER_DATABASE, &path)
        .env(CHILD_OWNER_JOB_ID, &job_id)
        .env(CHILD_OWNER_READY, &ready)
        .env(CHILD_OWNER_RELEASE, &release)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    await_file(&mut child, &ready);

    let store = HistoryStore::open_at(&path).unwrap();
    assert_eq!(store.reconcile_interrupted().unwrap(), 0);
    assert_eq!(store.load(&job_id).unwrap().state, "admitted");
    assert_eq!(fs::read(&slot_path).unwrap(), legacy_record.as_bytes());
    assert_eq!(fs::metadata(&slot_path).unwrap().ino(), slot_inode);

    fs::write(&release, b"release").unwrap();
    assert!(child.wait().unwrap().success());
    assert_eq!(store.reconcile_interrupted().unwrap(), 1);
    assert_eq!(store.load(&job_id).unwrap().state, "interrupted");
}

#[cfg(unix)]
#[test]
fn legacy_slot_reuse_transitions_in_place_and_crash_recovery_uses_sqlite_claim() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let old_admitted = HistoryStore::open_at(&path)
        .unwrap()
        .begin_admission(admission())
        .unwrap()
        .commit()
        .unwrap();
    let old_job_id = old_admitted.job_id.clone();
    drop(old_admitted);

    let (slot_key, slot_id, old_claim_token) = claim_coordinates(&path, &old_job_id);
    let slot_path = root.path().join("job-locks").join(&slot_key);
    use std::os::unix::fs::MetadataExt;
    let slot_inode = fs::metadata(&slot_path).unwrap().ino();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE jobs
             SET state = 'succeeded', terminal_at = '2026-01-01T00:00:01Z',
                 outcome = 'copied', publication_state = 'completed', pruneable = 1
             WHERE job_id = ?1",
            [&old_job_id],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE job_lease_claims
             SET state = 'released', resolved_at = '2026-01-01T00:00:01Z'
             WHERE job_id = ?1",
            [&old_job_id],
        )
        .unwrap();
    drop(connection);
    let legacy_record =
        format!("NSCB-LEASE-SLOT-V2\nslot={slot_id}\njob={old_job_id}\nclaim={old_claim_token}\n");
    fs::write(&slot_path, legacy_record).unwrap();

    let new_admitted = HistoryStore::open_at(&path)
        .unwrap()
        .begin_admission(admission())
        .unwrap()
        .commit()
        .unwrap();
    let job_id = new_admitted.job_id.clone();
    drop(new_admitted);
    let (reused_slot_key, reused_slot_id, claim_token) = claim_coordinates(&path, &job_id);
    assert_eq!(reused_slot_key, slot_key);
    assert_eq!(reused_slot_id, slot_id);
    assert_eq!(
        fs::read(&slot_path).unwrap(),
        format!("NSCB-LEASE-SLOT-V3\nslot={slot_id}\n").as_bytes()
    );
    assert_eq!(fs::metadata(&slot_path).unwrap().ino(), slot_inode);

    let ready = root.path().join("recovery-ready");
    let release = root.path().join("recovery-release");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "standalone::history::tests::child_process_lease_holder",
            "--nocapture",
        ])
        .env(CHILD_OWNER_DATABASE, &path)
        .env(CHILD_OWNER_JOB_ID, &job_id)
        .env(CHILD_OWNER_READY, &ready)
        .env(CHILD_OWNER_RELEASE, &release)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    await_file(&mut child, &ready);
    assert_eq!(
        super::lease::try_acquire_existing_claim(
            &path,
            &reused_slot_key,
            &reused_slot_id,
            &job_id,
            &claim_token
        )
        .err(),
        Some(HistoryError::LockFailed)
    );
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());

    let recovered = HistoryStore::open_at(&path).unwrap();
    assert_eq!(recovered.reconcile_interrupted().unwrap(), 1);
    assert_eq!(recovered.load(&job_id).unwrap().state, "interrupted");
    assert_eq!(
        recovered
            .connection
            .query_row(
                "SELECT state FROM job_lease_claims WHERE job_id = ?1",
                [&job_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "unresolved"
    );

    let interrupted_root = root.path().join("interrupted-transition");
    fs::create_dir(&interrupted_root).unwrap();
    let interrupted_database = interrupted_root.join("jobs.sqlite3");
    let old_job = HistoryStore::open_at(&interrupted_database)
        .unwrap()
        .begin_admission(admission())
        .unwrap()
        .commit()
        .unwrap();
    let old_job_id = old_job.job_id.clone();
    drop(old_job);
    let (old_slot_key, old_slot_id, old_claim_token) =
        claim_coordinates(&interrupted_database, &old_job_id);
    let old_slot_path = interrupted_root.join("job-locks").join(&old_slot_key);
    let old_connection = Connection::open(&interrupted_database).unwrap();
    old_connection
        .execute(
            "UPDATE jobs
             SET state = 'succeeded', terminal_at = '2026-01-01T00:00:01Z',
                 outcome = 'copied', publication_state = 'completed', pruneable = 1
             WHERE job_id = ?1",
            [&old_job_id],
        )
        .unwrap();
    old_connection
        .execute(
            "UPDATE job_lease_claims
             SET state = 'released', resolved_at = '2026-01-01T00:00:01Z'
             WHERE job_id = ?1",
            [&old_job_id],
        )
        .unwrap();
    drop(old_connection);
    fs::write(
        &old_slot_path,
        format!(
            "NSCB-LEASE-SLOT-V2\nslot={old_slot_id}\njob={old_job_id}\nclaim={old_claim_token}\n"
        ),
    )
    .unwrap();
    let old_slot_inode = fs::metadata(&old_slot_path).unwrap().ino();
    let mut interrupted_conversion = fs::OpenOptions::new()
        .write(true)
        .open(&old_slot_path)
        .unwrap();
    use std::io::{Seek, SeekFrom, Write};
    interrupted_conversion
        .seek(SeekFrom::Start("NSCB-LEASE-SLOT-V2".len() as u64 - 1))
        .unwrap();
    interrupted_conversion.write_all(b"3").unwrap();
    interrupted_conversion.sync_all().unwrap();
    drop(interrupted_conversion);

    let replacement = HistoryStore::open_at(&interrupted_database)
        .unwrap()
        .begin_admission(admission())
        .unwrap()
        .commit()
        .unwrap();
    let (replacement_slot_key, replacement_slot_id, _) =
        claim_coordinates(&interrupted_database, &replacement.job_id);
    assert_eq!(replacement_slot_key, old_slot_key);
    assert_eq!(replacement_slot_id, old_slot_id);
    assert_eq!(
        fs::read(&old_slot_path).unwrap(),
        format!("NSCB-LEASE-SLOT-V3\nslot={old_slot_id}\n").as_bytes()
    );
    assert_eq!(fs::metadata(&old_slot_path).unwrap().ino(), old_slot_inode);
}

#[cfg(unix)]
#[test]
fn child_process_lease_holder() {
    let Some(database) = std::env::var_os(CHILD_OWNER_DATABASE) else {
        return;
    };
    let job_id = std::env::var(CHILD_OWNER_JOB_ID).unwrap();
    let ready = PathBuf::from(std::env::var_os(CHILD_OWNER_READY).unwrap());
    let release = PathBuf::from(std::env::var_os(CHILD_OWNER_RELEASE).unwrap());
    let database = Path::new(&database);
    let (slot_key, slot_id, claim_token) = claim_coordinates(database, &job_id);
    let _lease = super::lease::try_acquire_existing_claim(
        database,
        &slot_key,
        &slot_id,
        &job_id,
        &claim_token,
    )
    .unwrap();
    fs::write(ready, b"ready").unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    while !release.exists() {
        assert!(
            Instant::now() < deadline,
            "parent did not release child lease"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn await_file(child: &mut std::process::Child, path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("child owner exited before becoming ready: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "child owner did not become ready"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn valid_failed_batch_intent() -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "kind": "nscb.copy_batch_intent",
        "parent_job_id": "parent",
        "retry_scope": "failed_items",
        "plan": {
            "kind": "copy_batch_plan",
            "nscb_version": env!("CARGO_PKG_VERSION"),
            "destination_directory": "/output",
            "workspace": "/work",
            "conflict_policy": "fail",
            "items": [
                {
                    "item_key": "failed-item",
                    "source": "/fixture/first.bin",
                    "destination": "/output/first.bin",
                    "state": "preflight_failed",
                    "failure_code": "source_unavailable"
                },
                {
                    "item_key": "successful-item",
                    "source": "/fixture/second.bin",
                    "destination": "/output/second.bin",
                    "state": "viable",
                    "failure_code": null
                }
            ]
        },
        "selections": [
            {
                "schema_version": 1,
                "kind": "nscb.copy_batch_item_provenance",
                "selection_index": 0,
                "source": "path",
                "selection_path": "first.bin",
                "base_directory": "/fixture",
                "input_list_entry_index": null,
                "input_list_entry_path": null,
                "discovered_directory": null,
                "discovered_relative_path": null,
                "requested_path": "/fixture/first.bin",
                "failure_code": "input_unavailable",
                "phase": "resolution"
            },
            {
                "schema_version": 1,
                "kind": "nscb.copy_batch_item_provenance",
                "selection_index": 1,
                "source": "path",
                "selection_path": "second.bin",
                "base_directory": "/fixture",
                "input_list_entry_index": null,
                "input_list_entry_path": null,
                "discovered_directory": null,
                "discovered_relative_path": null
            }
        ]
    })
}

fn batch_source_intent_for_retry(intent: &serde_json::Value) -> serde_json::Value {
    let selections = intent["selections"].as_array().unwrap();
    let items = intent["plan"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .zip(selections)
        .map(|(item, provenance)| {
            serde_json::json!({
                "item_key": item["item_key"],
                "source": item["source"],
                "provenance": provenance,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "schema_version": 1,
        "kind": "nscb.copy_batch_sources",
        "items": items,
    })
}

fn failed_batch_checkpoint_evidence(
    sequence: u64,
    item_key: &str,
    source: &str,
    destination: &str,
    state: &str,
    outcome: Option<&str>,
    failure_code: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "sequence": sequence,
        "item": {
            "item_key": item_key,
            "source": source,
            "destination": destination,
            "state": state,
            "outcome": outcome,
            "failure": failure_code.map(|code| serde_json::json!({ "code": code })),
            "artifacts": []
        }
    })
}

fn valid_failed_batch_store() -> HistoryStore {
    let root = tempfile::tempdir().unwrap();
    let path = root.keep().join("jobs.sqlite3");
    let store = HistoryStore::open_at(&path).unwrap();
    store
        .connection
        .execute(
            "INSERT INTO jobs
             (job_id, parent_job_id, kind, submission_kind, invocation_cwd, source,
              source_provenance, destination, destination_selection, workspace,
              workspace_selection, conflict_policy, conflict_policy_provenance,
              retry_scope, state, admitted_at, terminal_at, publication_state, pruneable)
             VALUES ('batch', 'parent', 'copy_through', 'independent_batch', '/fixture', NULL,
                     'cli_argument', '/output', 'explicit', '/work', 'explicit',
                     'fail', 'retry_default', 'failed_items', 'completed_with_issues',
                     '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z', 'completed', 0)",
            [],
        )
        .unwrap();
    let slot_id = store
        .connection
        .query_row(
            "SELECT slot_id FROM lease_slots ORDER BY ordinal LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    store
        .connection
        .execute(
            "UPDATE jobs SET lease_slot_id = ?1 WHERE job_id = 'batch'",
            [&slot_id],
        )
        .unwrap();
    store
        .connection
        .execute(
            "INSERT INTO job_lease_claims
             (claim_id, job_id, slot_id, claim_token, state, created_at, resolved_at)
             VALUES ('batch-claim', 'batch', ?1, 'batch-token', 'released',
                     '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z')",
            [&slot_id],
        )
        .unwrap();
    let intent = valid_failed_batch_intent();
    store
        .connection
        .execute(
            "INSERT INTO batch_intents (job_id, schema_version, kind, intent_json)
             VALUES ('batch', 1, 'nscb.copy_batch_intent', ?1)",
            [intent.to_string()],
        )
        .unwrap();
    for (ordinal, key, source, destination, state, outcome, failure_code, provenance) in [
        (
            0,
            "failed-item",
            "/fixture/first.bin",
            "/output/first.bin",
            "failed",
            None,
            Some("source_unavailable"),
            intent["selections"][0].clone(),
        ),
        (
            1,
            "successful-item",
            "/fixture/second.bin",
            "/output/second.bin",
            "succeeded",
            Some("copied"),
            None,
            intent["selections"][1].clone(),
        ),
    ] {
        let evidence = failed_batch_checkpoint_evidence(
            ordinal as u64,
            key,
            source,
            destination,
            state,
            outcome,
            failure_code,
        );
        store
            .connection
            .execute(
                "INSERT INTO job_items
                 (job_id, ordinal, item_key, kind, source, destination, state,
                  outcome, failure_code, evidence_json, provenance_json)
                 VALUES ('batch', ?1, ?2, 'copy_through', ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    ordinal,
                    key,
                    source,
                    destination,
                    state,
                    outcome,
                    failure_code,
                    evidence.to_string(),
                    provenance.to_string()
                ],
            )
            .unwrap();
    }
    for (sequence, key, source, destination, state, outcome, failure_code, publication_state) in [
        (
            0,
            "failed-item",
            "/fixture/first.bin",
            "/output/first.bin",
            "failed",
            None,
            Some("source_unavailable"),
            "not_completed",
        ),
        (
            1,
            "successful-item",
            "/fixture/second.bin",
            "/output/second.bin",
            "succeeded",
            Some("copied"),
            None,
            "completed",
        ),
    ] {
        let evidence = failed_batch_checkpoint_evidence(
            sequence,
            key,
            source,
            destination,
            state,
            outcome,
            failure_code,
        );
        store
            .connection
            .execute(
                "INSERT INTO batch_item_checkpoints
                 (job_id, item_key, sequence, item_state, outcome, failure_code,
                  publication_state, evidence_json, recorded_at)
                 VALUES ('batch', ?1, ?2, ?3, ?4, ?5, ?6, ?7,
                         '2026-01-01T00:00:02Z')",
                params![
                    key,
                    sequence,
                    state,
                    outcome,
                    failure_code,
                    publication_state,
                    evidence.to_string()
                ],
            )
            .unwrap();
    }
    let source_intent = batch_source_intent_for_retry(&intent);
    store
        .connection
        .execute(
            "INSERT INTO batch_source_intents
             (job_id, schema_version, kind, intent_json)
             VALUES ('batch', 1, 'nscb.copy_batch_sources', ?1)",
            [source_intent.to_string()],
        )
        .unwrap();
    store
}

fn parent_v4_unversioned_batch_store() -> HistoryStore {
    let store = valid_failed_batch_store();
    let mut batch_intent = valid_failed_batch_intent();
    for provenance in batch_intent["selections"].as_array_mut().unwrap() {
        let provenance = provenance.as_object_mut().unwrap();
        provenance.remove("schema_version");
        provenance.remove("kind");
    }
    batch_intent["selections"][0]
        .as_object_mut()
        .unwrap()
        .remove("discovered_directory");
    batch_intent["selections"][0]
        .as_object_mut()
        .unwrap()
        .remove("discovered_relative_path");
    store
        .connection
        .execute(
            "UPDATE jobs SET source_provenance = 'independent_batch_items'
             WHERE job_id = 'batch'",
            [],
        )
        .unwrap();
    store
        .connection
        .execute(
            "UPDATE batch_intents SET intent_json = ?1 WHERE job_id = 'batch'",
            [batch_intent.to_string()],
        )
        .unwrap();
    let source_intent = batch_source_intent_for_retry(&batch_intent);
    store
        .connection
        .execute(
            "UPDATE batch_source_intents SET intent_json = ?1 WHERE job_id = 'batch'",
            [source_intent.to_string()],
        )
        .unwrap();
    for (ordinal, provenance) in batch_intent["selections"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        store
            .connection
            .execute(
                "UPDATE job_items SET provenance_json = ?1
                 WHERE job_id = 'batch' AND ordinal = ?2",
                params![provenance.to_string(), ordinal],
            )
            .unwrap();
    }
    store
}

fn replace_parent_v4_batch_provenance(store: &HistoryStore, replacement: &serde_json::Value) {
    store
        .connection
        .execute(
            "UPDATE job_items SET provenance_json = ?1
             WHERE job_id = 'batch' AND ordinal = 0",
            [replacement.to_string()],
        )
        .unwrap();

    let source_intent = store
        .connection
        .query_row(
            "SELECT intent_json FROM batch_source_intents WHERE job_id = 'batch'",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    let mut source_intent: serde_json::Value = serde_json::from_str(&source_intent).unwrap();
    source_intent["items"][0]["provenance"] = replacement.clone();
    store
        .connection
        .execute(
            "UPDATE batch_source_intents SET intent_json = ?1 WHERE job_id = 'batch'",
            [source_intent.to_string()],
        )
        .unwrap();

    let batch_intent = store
        .connection
        .query_row(
            "SELECT intent_json FROM batch_intents WHERE job_id = 'batch'",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    let mut batch_intent: serde_json::Value = serde_json::from_str(&batch_intent).unwrap();
    batch_intent["selections"][0] = replacement.clone();
    store
        .connection
        .execute(
            "UPDATE batch_intents SET intent_json = ?1 WHERE job_id = 'batch'",
            [batch_intent.to_string()],
        )
        .unwrap();
}

fn replace_batch_intent(store: &HistoryStore, intent: &serde_json::Value) {
    store
        .connection
        .execute(
            "UPDATE batch_intents SET intent_json = ?1 WHERE job_id = 'batch'",
            [intent.to_string()],
        )
        .unwrap();
}

fn replace_batch_source_intent(store: &HistoryStore, intent: &serde_json::Value) {
    let source_intent = batch_source_intent_for_retry(intent);
    store
        .connection
        .execute(
            "UPDATE batch_source_intents SET intent_json = ?1 WHERE job_id = 'batch'",
            [source_intent.to_string()],
        )
        .unwrap();
}

fn assert_mutated_retry_intent_is_rejected(
    label: &str,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let store = valid_failed_batch_store();
    let mut intent = valid_failed_batch_intent();
    mutate(&mut intent);
    replace_batch_intent(&store, &intent);
    assert_eq!(
        store.failed_items_retry_intent("batch"),
        Err(HistoryError::UnsupportedFailedItems),
        "accepted malformed retry intent: {label}"
    );
}

#[test]
fn failed_items_retry_validation_rejects_destinationless_empty_selection() {
    let store = valid_failed_batch_store();
    let mut job = store.load("batch").unwrap();
    let mut intent = valid_failed_batch_intent();

    job.items[0].destination = None;
    job.items[0].state = "failed".to_owned();
    job.items[0].failure_code = Some("empty_selection".to_owned());
    intent["plan"]["items"][0]["destination"] = serde_json::Value::Null;
    intent["plan"]["items"][0]["state"] = serde_json::Value::String("preflight_failed".to_owned());
    intent["plan"]["items"][0]["failure_code"] =
        serde_json::Value::String("empty_selection".to_owned());
    intent["selections"][0]["failure_code"] =
        serde_json::Value::String("empty_selection".to_owned());
    intent["selections"][0]["phase"] = serde_json::Value::String("resolution".to_owned());
    job.items[0].provenance = Some(intent["selections"][0].clone());

    assert_eq!(
        super::store::validate_failed_items_retry_intent(&job, &intent),
        Err(HistoryError::UnsupportedFailedItems)
    );
}

#[test]
fn failed_items_retry_validation_rejects_destinationful_empty_selection() {
    let store = valid_failed_batch_store();
    let mut job = store.load("batch").unwrap();
    let mut intent = valid_failed_batch_intent();

    assert!(job.items[0].destination.is_some());
    assert!(intent["plan"]["items"][0]["destination"].is_string());
    job.items[0].state = "failed".to_owned();
    job.items[0].failure_code = Some("empty_selection".to_owned());
    intent["plan"]["items"][0]["failure_code"] =
        serde_json::Value::String("empty_selection".to_owned());
    intent["selections"][0]["failure_code"] =
        serde_json::Value::String("empty_selection".to_owned());
    intent["selections"][0]["phase"] = serde_json::Value::String("resolution".to_owned());
    job.items[0].provenance = Some(intent["selections"][0].clone());

    assert_eq!(
        super::store::validate_failed_items_retry_intent(&job, &intent),
        Err(HistoryError::UnsupportedFailedItems)
    );
}

#[test]
fn failed_items_retry_rejects_viable_empty_selection_contradiction_before_admission() {
    let store = valid_failed_batch_store();
    let mut intent = valid_failed_batch_intent();
    intent["plan"]["items"][0]["state"] = serde_json::Value::String("viable".to_owned());
    intent["plan"]["items"][0]["failure_code"] = serde_json::Value::Null;
    intent["selections"][0]
        .as_object_mut()
        .unwrap()
        .retain(|field, _| !matches!(field.as_str(), "requested_path" | "failure_code" | "phase"));
    replace_batch_intent(&store, &intent);
    replace_batch_source_intent(&store, &intent);

    let evidence = failed_batch_checkpoint_evidence(
        0,
        "failed-item",
        "/fixture/first.bin",
        "/output/first.bin",
        "failed",
        None,
        Some("empty_selection"),
    );
    store
        .connection
        .execute(
            "UPDATE job_items
             SET failure_code = 'empty_selection', evidence_json = ?1,
                 provenance_json = ?2
             WHERE job_id = 'batch' AND item_key = 'failed-item'",
            params![evidence.to_string(), intent["selections"][0].to_string()],
        )
        .unwrap();
    store
        .connection
        .execute(
            "UPDATE batch_item_checkpoints
             SET failure_code = 'empty_selection', evidence_json = ?1
             WHERE job_id = 'batch' AND item_key = 'failed-item'",
            [evidence.to_string()],
        )
        .unwrap();
    assert_eq!(
        store.failed_items_retry_intent("batch"),
        Err(HistoryError::UnsupportedFailedItems)
    );
}

#[test]
fn failed_items_retry_accepts_viable_runtime_failure() {
    let store = valid_failed_batch_store();
    let mut intent = valid_failed_batch_intent();
    intent["plan"]["items"][0]["state"] = serde_json::Value::String("viable".to_owned());
    intent["plan"]["items"][0]["failure_code"] = serde_json::Value::Null;
    intent["selections"][0]
        .as_object_mut()
        .unwrap()
        .retain(|field, _| !matches!(field.as_str(), "requested_path" | "failure_code" | "phase"));
    replace_batch_intent(&store, &intent);
    replace_batch_source_intent(&store, &intent);

    let evidence = failed_batch_checkpoint_evidence(
        0,
        "failed-item",
        "/fixture/first.bin",
        "/output/first.bin",
        "failed",
        None,
        Some("write_failed"),
    );
    store
        .connection
        .execute(
            "UPDATE job_items
             SET failure_code = 'write_failed', evidence_json = ?1,
                 provenance_json = ?2
             WHERE job_id = 'batch' AND item_key = 'failed-item'",
            params![evidence.to_string(), intent["selections"][0].to_string()],
        )
        .unwrap();
    store
        .connection
        .execute(
            "UPDATE batch_item_checkpoints
             SET failure_code = 'write_failed', evidence_json = ?1
             WHERE job_id = 'batch' AND item_key = 'failed-item'",
            [evidence.to_string()],
        )
        .unwrap();

    let retry = store.failed_items_retry_intent("batch").unwrap();
    assert_eq!(retry.items.len(), 1);
    assert_eq!(retry.items[0].item_key, "failed-item");
    assert_eq!(
        retry.items[0].destination,
        Some(PathBuf::from("/output/first.bin"))
    );
}

#[test]
fn failed_items_retry_rejects_unsafe_publication_states_and_unreleased_claims() {
    for state in ["published_unresolved", "uncertain", "unknown"] {
        let store = valid_failed_batch_store();
        store
            .connection
            .execute(
                "UPDATE jobs SET publication_state = ?1 WHERE job_id = 'batch'",
                [state],
            )
            .unwrap();
        assert_eq!(
            store.failed_items_retry_intent("batch"),
            Err(HistoryError::UnsupportedFailedItems),
            "accepted batch publication state {state}"
        );

        let store = valid_failed_batch_store();
        store
            .connection
            .execute(
                "UPDATE batch_item_checkpoints SET publication_state = ?1
                 WHERE job_id = 'batch' AND item_key = 'failed-item'",
                [state],
            )
            .unwrap();
        assert_eq!(
            store.failed_items_retry_intent("batch"),
            Err(HistoryError::QueryFailed),
            "accepted item publication state {state}"
        );
    }

    for (state, resolved_at) in [
        ("outstanding", None),
        ("unresolved", Some("2026-01-01T00:00:01Z")),
        ("future_state", Some("2026-01-01T00:00:01Z")),
    ] {
        let store = valid_failed_batch_store();
        if state == "future_state" {
            store
                .connection
                .execute_batch("PRAGMA ignore_check_constraints = ON;")
                .unwrap();
        }
        store
            .connection
            .execute(
                "UPDATE job_lease_claims
                 SET state = ?1, resolved_at = ?2
                 WHERE job_id = 'batch'",
                params![state, resolved_at],
            )
            .unwrap();
        assert_eq!(
            store.failed_items_retry_intent("batch"),
            Err(HistoryError::UnsupportedFailedItems),
            "accepted a {state} lease claim"
        );
    }
}

#[test]
fn failed_items_retry_rejects_checkpoint_result_contradictions_before_admission() {
    for (label, statement) in [
        (
            "item state",
            "UPDATE batch_item_checkpoints SET item_state = 'succeeded'
             WHERE job_id = 'batch' AND item_key = 'failed-item'",
        ),
        (
            "outcome",
            "UPDATE batch_item_checkpoints SET outcome = 'copied'
             WHERE job_id = 'batch' AND item_key = 'failed-item'",
        ),
        (
            "failure code",
            "UPDATE batch_item_checkpoints SET failure_code = 'destination_conflict'
             WHERE job_id = 'batch' AND item_key = 'failed-item'",
        ),
        (
            "publication state",
            "UPDATE batch_item_checkpoints SET publication_state = 'completed'
             WHERE job_id = 'batch' AND item_key = 'failed-item'",
        ),
        (
            "sequence",
            "UPDATE batch_item_checkpoints SET sequence = 2
             WHERE job_id = 'batch' AND item_key = 'successful-item'",
        ),
        (
            "evidence",
            "UPDATE batch_item_checkpoints
                SET evidence_json = replace(evidence_json, '\"sequence\":1', '\"sequence\":2')
              WHERE job_id = 'batch' AND item_key = 'successful-item'",
        ),
    ] {
        let store = valid_failed_batch_store();
        let jobs_before: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get(0))
            .unwrap();
        store.connection.execute(statement, []).unwrap();

        assert_eq!(
            store.failed_items_retry_intent("batch"),
            Err(HistoryError::QueryFailed),
            "accepted contradictory checkpoint {label}"
        );
        let jobs_after: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(jobs_after, jobs_before, "admitted a child for {label}");
    }
}

#[test]
fn failed_items_retry_rejects_missing_extra_and_malformed_intent_fields() {
    assert_mutated_retry_intent_is_rejected("missing parent job id", |intent| {
        intent.as_object_mut().unwrap().remove("parent_job_id");
    });
    assert_mutated_retry_intent_is_rejected("extra top-level field", |intent| {
        intent["future"] = serde_json::Value::Bool(true);
    });
    assert_mutated_retry_intent_is_rejected("malformed schema version", |intent| {
        intent["schema_version"] = serde_json::Value::String("1".to_owned());
    });
    assert_mutated_retry_intent_is_rejected("missing plan workspace", |intent| {
        intent["plan"].as_object_mut().unwrap().remove("workspace");
    });
    assert_mutated_retry_intent_is_rejected("missing plan item state", |intent| {
        intent["plan"]["items"][0]
            .as_object_mut()
            .unwrap()
            .remove("state");
    });
    assert_mutated_retry_intent_is_rejected("extra plan item field", |intent| {
        intent["plan"]["items"][0]["future"] = serde_json::Value::Bool(true);
    });
    assert_mutated_retry_intent_is_rejected("missing selection path", |intent| {
        intent["selections"][0]
            .as_object_mut()
            .unwrap()
            .remove("selection_path");
    });
    assert_mutated_retry_intent_is_rejected("extra selection field", |intent| {
        intent["selections"][0]["future"] = serde_json::Value::Bool(true);
    });
    assert_mutated_retry_intent_is_rejected("missing provenance version", |intent| {
        intent["selections"][0]
            .as_object_mut()
            .unwrap()
            .remove("schema_version");
    });
    assert_mutated_retry_intent_is_rejected("unknown provenance kind", |intent| {
        intent["selections"][0]["kind"] =
            serde_json::Value::String("nscb.future_item_provenance".to_owned());
    });
    assert_mutated_retry_intent_is_rejected("partial discovery evidence", |intent| {
        intent["selections"][0]["discovered_directory"] =
            serde_json::Value::String("/fixture".to_owned());
    });
    assert_mutated_retry_intent_is_rejected("unknown selection source", |intent| {
        intent["selections"][0]["source"] = serde_json::Value::String("future".to_owned());
    });
    assert_mutated_retry_intent_is_rejected("unknown selection failure code", |intent| {
        intent["selections"][0]["failure_code"] =
            serde_json::Value::String("future_failure".to_owned());
    });
    assert_mutated_retry_intent_is_rejected(
        "operation failure used as resolution provenance",
        |intent| {
            intent["selections"][0]["failure_code"] =
                serde_json::Value::String("source_unavailable".to_owned());
        },
    );
}

#[test]
fn failed_items_retry_verifies_intent_against_durable_job_and_item_rows() {
    assert!(
        valid_failed_batch_store()
            .failed_items_retry_intent("batch")
            .is_ok()
    );
    let store = valid_failed_batch_store();
    let mut empty_selection = valid_failed_batch_intent();
    empty_selection["plan"]["items"][0]["failure_code"] =
        serde_json::Value::String("empty_selection".to_owned());
    empty_selection["selections"][0]["failure_code"] =
        serde_json::Value::String("empty_selection".to_owned());
    replace_batch_intent(&store, &empty_selection);
    replace_batch_source_intent(&store, &empty_selection);
    store
        .connection
        .execute(
            "UPDATE job_items
             SET failure_code = 'empty_selection',
                 evidence_json = json_set(
                     evidence_json,
                     '$.item.failure.code',
                     'empty_selection'
                 ),
                 provenance_json = ?1
             WHERE item_key = 'failed-item'",
            [empty_selection["selections"][0].to_string()],
        )
        .unwrap();
    store
        .connection
        .execute(
            "UPDATE batch_item_checkpoints
             SET failure_code = 'empty_selection',
                 evidence_json = json_set(
                     evidence_json,
                     '$.item.failure.code',
                     'empty_selection'
                 )
             WHERE item_key = 'failed-item'",
            [],
        )
        .unwrap();
    assert_eq!(
        store.failed_items_retry_intent("batch"),
        Err(HistoryError::UnsupportedFailedItems),
        "empty selections must never authorize failed-item retry"
    );
    let store = valid_failed_batch_store();
    let mut unavailable_list = valid_failed_batch_intent();
    unavailable_list["selections"][0]["source"] =
        serde_json::Value::String("input_list".to_owned());
    replace_batch_intent(&store, &unavailable_list);
    replace_batch_source_intent(&store, &unavailable_list);
    store
        .connection
        .execute(
            "UPDATE job_items SET provenance_json = ?1 WHERE item_key = 'failed-item'",
            [unavailable_list["selections"][0].to_string()],
        )
        .unwrap();
    assert_eq!(
        store.failed_items_retry_intent("batch"),
        Err(HistoryError::UnsupportedFailedItems),
        "a failed input-list file must not be retried as a concrete copy path"
    );
    assert_mutated_retry_intent_is_rejected("parent job mismatch", |intent| {
        intent["parent_job_id"] = serde_json::Value::String("other-parent".to_owned());
    });
    assert_mutated_retry_intent_is_rejected("retry scope mismatch", |intent| {
        intent["retry_scope"] = serde_json::Value::String("all".to_owned());
    });
    assert_mutated_retry_intent_is_rejected("selection count mismatch", |intent| {
        intent["selections"].as_array_mut().unwrap().pop();
    });
    assert_mutated_retry_intent_is_rejected("item order mismatch", |intent| {
        intent["plan"]["items"].as_array_mut().unwrap().swap(0, 1);
    });
    assert_mutated_retry_intent_is_rejected("plan kind mismatch", |intent| {
        intent["plan"]["kind"] = serde_json::Value::String("future_plan".to_owned());
    });
    assert_mutated_retry_intent_is_rejected("destination directory mismatch", |intent| {
        intent["plan"]["destination_directory"] =
            serde_json::Value::String("/other-output".to_owned());
    });
    assert_mutated_retry_intent_is_rejected("workspace mismatch", |intent| {
        intent["plan"]["workspace"] = serde_json::Value::String("/other-work".to_owned());
    });
    assert_mutated_retry_intent_is_rejected("conflict policy mismatch", |intent| {
        intent["plan"]["conflict_policy"] = serde_json::Value::String("skip".to_owned());
    });
    assert_mutated_retry_intent_is_rejected("plan source mismatch", |intent| {
        intent["plan"]["items"][0]["source"] =
            serde_json::Value::String("/fixture/other.bin".to_owned());
    });
    assert_mutated_retry_intent_is_rejected("plan destination mismatch", |intent| {
        intent["plan"]["items"][0]["destination"] =
            serde_json::Value::String("/output/other.bin".to_owned());
    });
    assert_mutated_retry_intent_is_rejected("plan prior state mismatch", |intent| {
        intent["plan"]["items"][0]["state"] = serde_json::Value::String("viable".to_owned());
        intent["plan"]["items"][0]["failure_code"] = serde_json::Value::Null;
    });
    assert_mutated_retry_intent_is_rejected("failure code mismatch", |intent| {
        intent["plan"]["items"][0]["failure_code"] =
            serde_json::Value::String("destination_conflict".to_owned());
    });
    assert_mutated_retry_intent_is_rejected("selection item source mismatch", |intent| {
        intent["selections"][1]["selection_path"] =
            serde_json::Value::String("other.bin".to_owned());
    });
    assert_mutated_retry_intent_is_rejected("selection path base mismatch", |intent| {
        intent["selections"][0]["requested_path"] =
            serde_json::Value::String("/fixture/first.bin/child".to_owned());
    });
    assert_mutated_retry_intent_is_rejected("persisted provenance mismatch", |intent| {
        intent["selections"][1]["selection_index"] = serde_json::json!(7);
    });

    let store = valid_failed_batch_store();
    store
        .connection
        .execute(
            "UPDATE job_items SET source = '/fixture/other.bin' WHERE item_key = 'failed-item'",
            [],
        )
        .unwrap();
    assert_eq!(
        store.failed_items_retry_intent("batch"),
        Err(HistoryError::QueryFailed)
    );

    let store = valid_failed_batch_store();
    store
        .connection
        .execute(
            "UPDATE job_items SET destination = '/output/other.bin'
             WHERE item_key = 'failed-item'",
            [],
        )
        .unwrap();
    assert_eq!(
        store.failed_items_retry_intent("batch"),
        Err(HistoryError::QueryFailed)
    );

    let store = valid_failed_batch_store();
    store
        .connection
        .execute(
            "UPDATE job_items SET state = 'succeeded' WHERE item_key = 'failed-item'",
            [],
        )
        .unwrap();
    assert_eq!(
        store.failed_items_retry_intent("batch"),
        Err(HistoryError::QueryFailed)
    );
}

#[test]
fn parent_v4_unversioned_batch_provenance_is_inspectable_without_retry_authority() {
    let store = parent_v4_unversioned_batch_store();
    let stored_before = store
        .connection
        .query_row(
            "SELECT source.intent_json, item.provenance_json
             FROM batch_source_intents source
             JOIN job_items item ON item.job_id = source.job_id
             WHERE source.job_id = 'batch' AND item.ordinal = 0",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .unwrap();

    let job = store.load("batch").unwrap();
    assert_eq!(job.job_id, "batch");
    assert_eq!(job.submission_kind, "independent_batch");
    assert_eq!(job.items.len(), 2);
    let source_intent = job.batch_source_intent.as_ref().unwrap();
    assert_eq!(source_intent.items.len(), job.items.len());
    let legacy_provenance = job.items[0].provenance.as_ref().unwrap();
    assert!(legacy_provenance.is_object());
    assert!(legacy_provenance.get("schema_version").is_none());
    assert!(legacy_provenance.get("kind").is_none());
    assert_eq!(source_intent.items[0].provenance, legacy_provenance.clone());
    assert_eq!(
        job.batch_intent.as_ref().unwrap()["selections"][0],
        legacy_provenance.clone()
    );

    let stored_after = store
        .connection
        .query_row(
            "SELECT source.intent_json, item.provenance_json
             FROM batch_source_intents source
             JOIN job_items item ON item.job_id = source.job_id
             WHERE source.job_id = 'batch' AND item.ordinal = 0",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .unwrap();
    assert_eq!(stored_after, stored_before);
    assert_eq!(
        store.failed_items_retry_intent("batch"),
        Err(HistoryError::UnsupportedFailedItems),
        "legacy provenance must remain inspectable without granting retry authority"
    );
}

#[test]
fn parent_v4_legacy_batch_provenance_rejects_mixed_and_malformed_records() {
    let replacements = [
        (
            "mixed versioned and unversioned provenance",
            valid_failed_batch_intent()["selections"][0].clone(),
        ),
        (
            "partial provenance version",
            serde_json::json!({ "schema_version": 1, "selection_index": 0 }),
        ),
        (
            "non-object provenance",
            serde_json::Value::String("not provenance".to_owned()),
        ),
    ];

    for (case, replacement) in replacements {
        let store = parent_v4_unversioned_batch_store();
        assert!(
            store.load("batch").is_ok(),
            "parent-v4 fixture did not load before applying {case}"
        );
        replace_parent_v4_batch_provenance(&store, &replacement);
        assert_eq!(
            store.load("batch"),
            Err(HistoryError::QueryFailed),
            "accepted {case}"
        );
    }
}

#[test]
fn failed_items_retry_accepts_directory_discovered_resolution_failure() {
    let store = valid_failed_batch_store();
    let mut intent = valid_failed_batch_intent();
    intent["plan"]["items"][0]["source"] =
        serde_json::Value::String("/fixture/inputs/first.bin".to_owned());
    intent["selections"][0]["schema_version"] = serde_json::json!(1);
    intent["selections"][0]["kind"] =
        serde_json::Value::String("nscb.copy_batch_item_provenance".to_owned());
    intent["selections"][0]["selection_path"] = serde_json::Value::String("inputs".to_owned());
    intent["selections"][0]["base_directory"] = serde_json::Value::String("/fixture".to_owned());
    intent["selections"][0]["discovered_directory"] =
        serde_json::Value::String("/fixture/inputs".to_owned());
    intent["selections"][0]["discovered_relative_path"] =
        serde_json::Value::String("first.bin".to_owned());
    intent["selections"][0]["requested_path"] =
        serde_json::Value::String("/fixture/inputs/first.bin".to_owned());
    replace_batch_intent(&store, &intent);
    replace_batch_source_intent(&store, &intent);
    store
        .connection
        .execute(
            "UPDATE job_items
             SET source = '/fixture/inputs/first.bin', provenance_json = ?1,
                 evidence_json = json_set(
                     evidence_json, '$.item.source', '/fixture/inputs/first.bin'
                 )
             WHERE job_id = 'batch' AND item_key = 'failed-item'",
            [intent["selections"][0].to_string()],
        )
        .unwrap();
    store
        .connection
        .execute(
            "UPDATE batch_item_checkpoints
             SET evidence_json = json_set(
                 evidence_json, '$.item.source', '/fixture/inputs/first.bin'
             )
             WHERE job_id = 'batch' AND item_key = 'failed-item'",
            [],
        )
        .unwrap();

    let retry = store.failed_items_retry_intent("batch").unwrap();
    assert_eq!(retry.items.len(), 1);
    assert_eq!(retry.items[0].item_key, "failed-item");
    assert_eq!(
        retry.items[0].source,
        PathBuf::from("/fixture/inputs/first.bin")
    );
    assert_eq!(
        retry.items[0].destination,
        Some(PathBuf::from("/output/first.bin"))
    );
    assert_eq!(
        retry.items[0].provenance.as_ref().unwrap()["discovered_relative_path"],
        "first.bin"
    );
}

#[test]
fn failed_items_retry_accepts_an_item_local_qualified_split_failure() {
    let store = valid_failed_batch_store();
    let split_selection = serde_json::json!({
        "schema_version": 1,
        "kind": "nscb.copy_batch_item_provenance",
        "selection_index": 0,
        "source": "path",
        "selection_path": "first.bin",
        "base_directory": "/fixture",
        "input_list_entry_index": null,
        "input_list_entry_path": null,
        "discovered_directory": null,
        "discovered_relative_path": null,
        "split_qualification": {
            "kind": "local_split_receipt",
            "manifest_schema_version": 1,
            "original_size_bytes": 512,
            "original_sha256": format!("{:064x}", 0),
            "manifest_sha256": format!("{:064x}", 1),
        }
    });
    let mut intent = valid_failed_batch_intent();
    intent["plan"]["items"][0]["failure_code"] =
        serde_json::Value::String("split_input_unsupported".to_owned());
    intent["selections"][0] = split_selection.clone();
    replace_batch_intent(&store, &intent);
    replace_batch_source_intent(&store, &intent);
    store
        .connection
        .execute(
            "UPDATE job_items
             SET failure_code = 'split_input_unsupported', provenance_json = ?1,
                 evidence_json = ?2
             WHERE item_key = 'failed-item'",
            params![
                split_selection.to_string(),
                failed_batch_checkpoint_evidence(
                    0,
                    "failed-item",
                    "/fixture/first.bin",
                    "/output/first.bin",
                    "failed",
                    None,
                    Some("split_input_unsupported"),
                )
                .to_string()
            ],
        )
        .unwrap();
    store
        .connection
        .execute(
            "UPDATE batch_item_checkpoints
                SET failure_code = 'split_input_unsupported', evidence_json = ?1
              WHERE job_id = 'batch' AND item_key = 'failed-item'",
            [failed_batch_checkpoint_evidence(
                0,
                "failed-item",
                "/fixture/first.bin",
                "/output/first.bin",
                "failed",
                None,
                Some("split_input_unsupported"),
            )
            .to_string()],
        )
        .unwrap();

    assert!(store.failed_items_retry_intent("batch").is_ok());
}

#[test]
fn retry_intent_rejects_unreleased_and_unknown_claims_before_planning() {
    for (state, resolved_at) in [
        ("outstanding", None),
        ("unresolved", Some("2026-01-01T00:00:01Z")),
        ("future_state", Some("2026-01-01T00:00:01Z")),
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("jobs.sqlite3");
        let admitted = HistoryStore::open_at(&path)
            .unwrap()
            .begin_admission(admission())
            .unwrap()
            .commit()
            .unwrap();
        let store = HistoryStore::open_at(&path).unwrap();
        if state == "future_state" {
            store
                .connection
                .execute_batch("PRAGMA ignore_check_constraints = ON;")
                .unwrap();
        }
        store
            .connection
            .execute(
                "UPDATE jobs SET state = 'succeeded' WHERE job_id = ?1",
                [&admitted.job_id],
            )
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE job_lease_claims SET state = ?2, resolved_at = ?3
                 WHERE job_id = ?1",
                params![&admitted.job_id, state, resolved_at],
            )
            .unwrap();

        assert_eq!(
            store.retry_intent(&admitted.job_id),
            Err(HistoryError::IneligibleJob),
            "accepted a {state} lease claim"
        );
    }
}

#[test]
fn retry_intent_rejects_future_and_malformed_job_contracts_before_copy_planning() {
    for (column, value) in [
        ("kind", "future_job"),
        ("retry_scope", "failed_items"),
        ("destination_selection", "future_destination"),
        ("workspace_selection", "future_workspace"),
        ("conflict_policy", "future_conflict"),
        ("invocation_cwd", "relative-cwd"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("jobs.sqlite3");
        let admitted = HistoryStore::open_at(&path)
            .unwrap()
            .begin_admission(admission())
            .unwrap()
            .commit()
            .unwrap();
        let store = HistoryStore::open_at(&path).unwrap();
        store
            .connection
            .execute(
                &format!("UPDATE jobs SET {column} = ?1, state = 'succeeded' WHERE job_id = ?2"),
                params![value, admitted.job_id],
            )
            .unwrap();
        assert_eq!(
            store.retry_intent(&admitted.job_id),
            Err(HistoryError::IneligibleJob),
            "accepted malformed {column}={value}"
        );
    }
}

#[test]
fn clear_deletes_terminal_history_but_preserves_active_jobs_and_outputs() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let output = root.path().join("published.bin");
    fs::write(&output, b"published bytes survive history clear").unwrap();
    let configuration = root.path().join("config.toml");
    let key_file = root.path().join("prod.keys");
    let cache = root.path().join("cache.bin");
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let modified = workspace.join("modified.bin");
    let foreign = workspace.join("foreign.bin");
    let displaced = workspace.join("displaced.bin");
    let unproven = workspace.join("unproven.bin");
    fs::write(&configuration, b"unchanged configuration").unwrap();
    fs::write(&key_file, b"unchanged key fixture").unwrap();
    fs::write(&cache, b"unchanged cache fixture").unwrap();
    fs::write(&modified, b"locally modified").unwrap();
    fs::write(&foreign, b"foreign content").unwrap();
    fs::write(&displaced, b"displaced content").unwrap();
    fs::write(&unproven, b"unproven content").unwrap();
    #[cfg(unix)]
    let symlink_path = workspace.join("symlink.bin");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&foreign, &symlink_path).unwrap();
    let store = HistoryStore::open_at(&path).unwrap();
    let active = store
        .begin_admission(admission())
        .unwrap()
        .commit()
        .unwrap();
    let mut store = HistoryStore::open_at(&path).unwrap();
    for (job_id, state) in [("terminal", "succeeded"), ("future-state", "future_state")] {
        store
            .connection
            .execute(
                "INSERT INTO jobs
                (job_id, kind, submission_kind, invocation_cwd, source, source_provenance,
                destination, destination_selection, workspace,
                workspace_selection, conflict_policy,
                conflict_policy_provenance, retry_scope, state, admitted_at,
                terminal_at, publication_state, pruneable)
                VALUES (?1, 'copy_through', 'single', '/fixture', '/s',
                'cli_argument', '/d', 'explicit', '/w', 'explicit',
                'fail', 'default', 'all', ?2,
                '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z',
                'completed', 1)",
                rusqlite::params![job_id, state],
            )
            .unwrap();
    }
    let mut artifacts = vec![
        ("staged_output", &modified),
        ("uncertain_entry", &foreign),
        ("displaced_destination", &displaced),
        ("uncertain_entry", &unproven),
    ];
    #[cfg(unix)]
    artifacts.push(("uncertain_entry", &symlink_path));
    for (ordinal, (role, path)) in artifacts.into_iter().enumerate() {
        store
            .connection
            .execute(
                "INSERT INTO job_artifacts
                 (job_id, ordinal, role, path, retained, identity_known, content_known, evidence_json)
                 VALUES ('terminal', ?1, ?2, ?3, 1, 0, 0, '{}')",
                params![ordinal as i64, role, path.to_str().unwrap()],
            )
            .unwrap();
    }
    assert_eq!(store.clear_terminal().unwrap(), 1);
    let jobs = store.list().unwrap();
    assert_eq!(jobs.len(), 2);
    assert!(jobs.iter().any(|job| job.job_id == active.job_id));
    assert!(jobs.iter().any(|job| job.job_id == "future-state"));
    assert_eq!(
        fs::read(output).unwrap(),
        b"published bytes survive history clear"
    );
    assert_eq!(fs::read(configuration).unwrap(), b"unchanged configuration");
    assert_eq!(fs::read(key_file).unwrap(), b"unchanged key fixture");
    assert_eq!(fs::read(cache).unwrap(), b"unchanged cache fixture");
    assert_eq!(fs::read(modified).unwrap(), b"locally modified");
    assert_eq!(fs::read(&foreign).unwrap(), b"foreign content");
    assert_eq!(fs::read(displaced).unwrap(), b"displaced content");
    assert_eq!(fs::read(unproven).unwrap(), b"unproven content");
    #[cfg(unix)]
    assert_eq!(
        fs::read_link(workspace.join("symlink.bin")).unwrap(),
        foreign
    );
}

#[test]
fn clear_removes_unresolved_interruption_evidence_without_touching_outputs_or_retry_links() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let store = HistoryStore::open_at(&path).unwrap();
    let parent = store.begin_admission(admission()).unwrap();
    let parent_lease = parent.acquire_lease().unwrap();
    let parent = parent.commit().unwrap();
    let parent_id = parent.job_id.clone();
    let (parent_slot_key, _, _) = claim_coordinates(&path, &parent_id);
    let store = HistoryStore::open_at(&path).unwrap();

    let mut retry_input = admission();
    retry_input.parent_job_id = Some(parent_id.clone());
    let retry_pending = store.begin_admission(retry_input).unwrap();
    let retry_lease = retry_pending.acquire_lease().unwrap();
    let retry = retry_pending.commit().unwrap();
    let retry_id = retry.job_id.clone();
    let mut store = HistoryStore::open_at(&path).unwrap();

    drop(parent_lease);
    drop(parent);
    assert_eq!(store.reconcile_interrupted().unwrap(), 1);

    let output = root.path().join("published.bin");
    let config = root.path().join("config.toml");
    let cache = root.path().join("cache.bin");
    fs::write(&output, b"published data").unwrap();
    fs::write(&config, b"configuration").unwrap();
    fs::write(&cache, b"cache data").unwrap();
    Connection::open(&path)
        .unwrap()
        .execute(
            "INSERT INTO job_artifacts
             (job_id, ordinal, role, path, retained, identity_known,
              content_known, evidence_json)
             VALUES (?1, 0, 'published_output', ?2, 1, 1, 1, '{}')",
            params![parent_id, output.to_string_lossy()],
        )
        .unwrap();

    assert_eq!(store.clear_terminal().unwrap(), 1);
    let connection = Connection::open(&path).unwrap();
    let parent_rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM jobs WHERE job_id = ?1",
            [&parent_id],
            |row| row.get(0),
        )
        .unwrap();
    let child_parent: String = connection
        .query_row(
            "SELECT parent_job_id FROM jobs WHERE job_id = ?1",
            [&retry_id],
            |row| row.get(0),
        )
        .unwrap();
    let unresolved_claims: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM job_lease_claims
             WHERE job_id = ?1 AND state = 'unresolved'",
            [&parent_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(parent_rows, 0);
    assert_eq!(child_parent, parent_id);
    assert_eq!(unresolved_claims, 0);
    assert!(output.is_file());
    assert!(config.is_file());
    assert!(cache.is_file());

    let new_pending = store.begin_admission(admission()).unwrap();
    let new_job = new_pending.commit().unwrap();
    let (reused_slot_key, _, _) = claim_coordinates(&path, &new_job.job_id);
    assert_eq!(reused_slot_key, parent_slot_key);
    drop(retry_lease);
    drop(retry);
}

#[test]
fn failed_item_selection_uses_only_failed_independent_batch_items() {
    let store = valid_failed_batch_store();
    assert_eq!(
        store.retry_failed_item_keys("batch").unwrap(),
        vec!["failed-item".to_owned()]
    );
}

#[test]
fn failed_item_retry_requires_a_durable_released_batch_claim() {
    let store = valid_failed_batch_store();
    store
        .connection
        .execute("DELETE FROM job_lease_claims WHERE job_id = 'batch'", [])
        .unwrap();

    assert!(matches!(
        store.failed_items_retry_intent("batch"),
        Err(HistoryError::UnsupportedFailedItems)
    ));
}

#[test]
fn failed_item_selection_rejects_unsupported_future_record_shapes() {
    for (column, value) in [
        ("kind", "future_job"),
        ("submission_kind", "single"),
        ("retry_scope", "all"),
        ("retry_scope", "future_scope"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("jobs.sqlite3");
        let store = HistoryStore::open_at(&path).unwrap();
        store
            .connection
            .execute(
                "INSERT INTO jobs
                 (job_id, kind, submission_kind, invocation_cwd, source, source_provenance,
                  destination, destination_selection, workspace, workspace_selection,
                  conflict_policy, conflict_policy_provenance, retry_scope, state, admitted_at,
                  terminal_at, publication_state, pruneable)
                 VALUES ('batch', 'copy_through', 'independent_batch', '/fixture', NULL,
                 'cli_argument', '/d', 'explicit', '/w', 'explicit', 'fail', 'default',
                 'failed_items', 'completed_with_issues', '2026-01-01T00:00:00Z',
                 '2026-01-01T00:00:01Z', 'completed', 1)",
                [],
            )
            .unwrap();
        let provenance = serde_json::json!({
            "schema_version": 1,
            "kind": "nscb.copy_batch_item_provenance",
            "selection_index": 0,
            "source": "path",
            "selection_path": "/s",
        });
        store
            .connection
            .execute(
                "INSERT INTO job_items
                 (job_id, ordinal, item_key, kind, source, destination, state, provenance_json)
                 VALUES ('batch', 0, 'failed-item', 'copy_through', '/s', '/d', 'failed', ?1)",
                [provenance.to_string()],
            )
            .unwrap();
        let source_intent = serde_json::json!({
            "schema_version": 1,
            "kind": "nscb.copy_batch_sources",
            "items": [{
                "item_key": "failed-item",
                "source": "/s",
                "provenance": provenance,
            }]
        });
        store
            .connection
            .execute(
                "INSERT INTO batch_source_intents (job_id, schema_version, kind, intent_json)
                 VALUES ('batch', 1, 'nscb.copy_batch_sources', ?1)",
                [source_intent.to_string()],
            )
            .unwrap();
        if column == "submission_kind" {
            store
                .connection
                .execute(
                    "DELETE FROM batch_source_intents WHERE job_id = 'batch'",
                    [],
                )
                .unwrap();
            store
                .connection
                .execute(
                    "UPDATE jobs
                     SET submission_kind = 'single', source = '/s'
                     WHERE job_id = 'batch'",
                    [],
                )
                .unwrap();
        } else {
            store
                .connection
                .execute(
                    &format!("UPDATE jobs SET {column} = ?1 WHERE job_id = 'batch'"),
                    [value],
                )
                .unwrap();
        }
        assert_eq!(
            store.retry_failed_item_keys("batch"),
            Err(HistoryError::UnsupportedFailedItems),
            "accepted unsupported failed-item record {column}={value}"
        );
    }
}

#[test]
fn retention_cap_protects_interrupted_evidence_and_keeps_parent_ids() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let retained_artifact = root.path().join("retained-artifact.bin");
    fs::write(&retained_artifact, b"retained evidence").unwrap();
    let store = HistoryStore::open_at(&path).unwrap();
    store.connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    for index in 0..(RETENTION_LIMIT + 2) {
        let parent = (index == RETENTION_LIMIT + 1).then_some("job-0001");
        let state = if index == 0 {
            "interrupted"
        } else {
            "succeeded"
        };
        let pruneable = if index == 0 { 0 } else { 1 };
        store
            .connection
            .execute(
                "INSERT INTO jobs
                (job_id, parent_job_id, kind, submission_kind, invocation_cwd, source,
                      source_provenance, destination, destination_selection,
                      workspace, workspace_selection, conflict_policy,
                      conflict_policy_provenance, retry_scope, state, admitted_at,
                      terminal_at, publication_state, pruneable)
                VALUES (?1, ?2, 'copy_through', 'single', '/fixture', '/s',
                             'cli_argument', '/d', 'explicit', '/w', 'explicit',
                             'fail', 'default', 'all', ?3, ?4, ?4, 'unknown', ?5)",
                params![
                    format!("job-{index:04}"),
                    parent,
                    state,
                    format!("2026-01-01T00:{:02}:{:02}Z", index / 60, index % 60),
                    pruneable,
                ],
            )
            .unwrap();
    }
    store
        .connection
        .execute(
            "INSERT INTO jobs
            (job_id, kind, submission_kind, invocation_cwd, source, source_provenance,
            destination, destination_selection, workspace, workspace_selection,
            conflict_policy, conflict_policy_provenance, retry_scope, state, admitted_at,
            terminal_at, publication_state, pruneable)
            VALUES ('uncertain-artifact', 'copy_through', 'single', '/fixture', '/s',
            'cli_argument', '/d', 'explicit', '/w', 'explicit', 'fail', 'default', 'all',
            'failed', '2020-01-01T00:00:00Z', '2020-01-01T00:00:01Z', 'uncertain', 0)",
            [],
        )
        .unwrap();
    store
        .connection
        .execute(
            "INSERT INTO jobs
             (job_id, kind, submission_kind, invocation_cwd, source, source_provenance,
              destination, destination_selection, workspace, workspace_selection,
              conflict_policy, conflict_policy_provenance, retry_scope, state, admitted_at,
              terminal_at, publication_state, pruneable)
             VALUES ('published-unresolved', 'copy_through', 'single', '/fixture', '/s',
             'cli_argument', '/d', 'explicit', '/w', 'explicit', 'fail', 'default', 'all',
             'failed', '2020-01-01T00:00:00Z', '2020-01-01T00:00:01Z',
             'published_unresolved', 0)",
            [],
        )
        .unwrap();
    store
        .connection
        .execute(
            "INSERT INTO job_artifacts
             (job_id, ordinal, role, path, retained, identity_known, content_known, evidence_json)
             VALUES ('published-unresolved', 0, 'published_destination', ?1, 0, 1, 1, '{}')",
            [retained_artifact.to_str().unwrap()],
        )
        .unwrap();
    store
        .connection
        .execute(
            "INSERT INTO job_artifacts
            (job_id, ordinal, role, path, retained, identity_known, content_known, evidence_json)
            VALUES ('uncertain-artifact', 0, 'uncertain_entry', ?1, 1, 0, 0, '{}')",
            [retained_artifact.to_str().unwrap()],
        )
        .unwrap();
    store.connection.execute_batch("COMMIT").unwrap();
    store.connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    store.prune_in_transaction().unwrap();
    store.connection.execute_batch("COMMIT").unwrap();

    let jobs = store.list().unwrap();
    let ordinary: i64 = store
        .connection
        .query_row("SELECT COUNT(*) FROM jobs WHERE pruneable = 1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(ordinary, RETENTION_LIMIT as i64);
    assert!(jobs.iter().any(|job| job.job_id == "job-0000"));
    assert!(jobs.iter().any(|job| job.job_id == "uncertain-artifact"));
    assert!(jobs.iter().any(|job| job.job_id == "published-unresolved"));
    assert!(jobs.iter().all(|job| job.job_id != "job-0001"));
    let artifact_count: i64 = store
        .connection
        .query_row(
            "SELECT COUNT(*) FROM job_artifacts WHERE job_id = 'uncertain-artifact'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(artifact_count, 1);
    assert_eq!(fs::read(retained_artifact).unwrap(), b"retained evidence");
    assert!(
        jobs.iter()
            .any(|job| job.parent_job_id.as_deref() == Some("job-0001"))
    );
}

#[cfg(target_os = "macos")]
fn admit_copy_batch_for_history(
    root: &Path,
    output: &Path,
    workspace: &Path,
    plan: &nscb::CopyBatchPlan,
) -> (HistoryStore, super::store::AdmittedJob) {
    let snapshot = plan.snapshot();
    let items = snapshot
        .items()
        .iter()
        .enumerate()
        .map(|(index, item)| AdmissionItem {
            item_key: item.item_key().to_owned(),
            source: item.source().to_path_buf(),
            destination: item.destination().map(Path::to_path_buf),
            provenance: Some(serde_json::json!({
                "schema_version": 1,
                "kind": "nscb.copy_batch_item_provenance",
                "selection_index": index,
                "source": "path",
                "selection_path": item.source(),
                "base_directory": root,
                "input_list_entry_index": null,
                "input_list_entry_path": null,
                "discovered_directory": null,
                "discovered_relative_path": null,
            })),
            split_qualification: None,
            split_manifest_sha256: None,
        })
        .collect::<Vec<_>>();
    let batch_intent = serde_json::json!({
        "schema_version": 1,
        "kind": "nscb.copy_batch_intent",
        "plan": snapshot,
    });
    let input = AdmissionInput {
        kind: JobKind::CopyThrough,
        submission_kind: SubmissionKind::IndependentBatch,
        invocation_cwd: root.to_path_buf(),
        source: AdmissionSource::IndependentBatch,
        destination: output.to_path_buf(),
        destination_selection: DestinationSelection::Explicit,
        workspace: workspace.to_path_buf(),
        workspace_selection: WorkspaceSelection::Explicit,
        conflict_policy: ConflictPolicyRecord::Fail,
        conflict_policy_provenance: ConflictPolicyProvenance::Default,
        parent_conflict_policy: None,
        parent_conflict_policy_provenance: None,
        parent_job_id: None,
        retry_scope: RetryScope::FailedItems,
        required_providers: Vec::new(),
        required_keys: Vec::new(),
        items,
        batch_intent: Some(batch_intent),
    };
    let store = HistoryStore::open_at(root.join("jobs.sqlite3")).unwrap();
    let admitted = store.begin_admission(input).unwrap().commit().unwrap();
    let store = HistoryStore::open_at(root.join("jobs.sqlite3")).unwrap();
    store.begin_running(&admitted.job_id).unwrap();
    (store, admitted)
}

#[cfg(target_os = "macos")]
fn two_item_batch(root: &Path, output: &Path, workspace: &Path) -> nscb::CopyBatchPlan {
    let first = root.join("first.bin");
    let second = root.join("second.bin");
    fs::write(&first, b"first durable item").unwrap();
    fs::write(&second, b"second durable item").unwrap();
    nscb::Engine::new()
        .plan_copy_batch(
            nscb::CopyBatchRequest::new(output, workspace)
                .with_item(&first, output.join("first.bin"))
                .with_item(&second, output.join("second.bin")),
        )
        .unwrap()
}

#[cfg(target_os = "macos")]
#[test]
fn checkpoint_sequence_query_failure_rolls_back_item_update() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("output");
    let workspace = root.path().join("workspace");
    fs::create_dir(&output).unwrap();
    fs::create_dir(&workspace).unwrap();
    let plan = two_item_batch(root.path(), &output, &workspace);
    let (mut store, admitted) =
        admit_copy_batch_for_history(root.path(), &output, &workspace, &plan);
    store.fail_checkpoint_sequence_query = true;
    let session = nscb::CopyBatchSession::new();
    let execution = nscb::Engine::new().execute_copy_batch_with_checkpoint(
        plan,
        &session,
        nscb::CancellationHandle::new(),
        |checkpoint| {
            store
                .checkpoint_batch_item(&admitted.job_id, &checkpoint)
                .map_err(|_| nscb::CopyBatchCheckpointError)
        },
    );

    assert!(execution.checkpoint_failed());
    let detail = store.load(&admitted.job_id).unwrap();
    assert_eq!(detail.state, "running");
    assert_eq!(detail.items[0].state, "running");
    assert_eq!(detail.items[0].checkpoint_sequence, None);
    let checkpoint_count: i64 = store
        .connection
        .query_row(
            "SELECT COUNT(*) FROM batch_item_checkpoints WHERE job_id = ?1",
            [&admitted.job_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(checkpoint_count, 0);
}

#[cfg(target_os = "macos")]
#[test]
fn checkpoint_callback_failure_is_durable_after_atomic_batch_completion() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("output");
    let workspace = root.path().join("workspace");
    fs::create_dir(&output).unwrap();
    fs::create_dir(&workspace).unwrap();
    let plan = two_item_batch(root.path(), &output, &workspace);
    let (mut store, admitted) =
        admit_copy_batch_for_history(root.path(), &output, &workspace, &plan);
    let session = nscb::CopyBatchSession::new();
    let execution = nscb::Engine::new().execute_copy_batch_with_checkpoint(
        plan,
        &session,
        nscb::CancellationHandle::new(),
        |_| Err(nscb::CopyBatchCheckpointError),
    );
    assert!(execution.checkpoint_failed());
    let completion = session.last_completion().unwrap().unwrap();
    store
        .complete_batch(&admitted.job_id, &completion, execution.failed_checkpoint())
        .unwrap();

    let (job_state, failure_code): (String, Option<String>) = store
        .connection
        .query_row(
            "SELECT state, failure_code FROM jobs WHERE job_id = ?1",
            [&admitted.job_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(job_state, "failed");
    assert_eq!(failure_code.as_deref(), Some("checkpoint_failed"));
    let checkpoints = query_rows_for_test(
        &store.connection,
        &format!(
            "SELECT item_key, item_state FROM batch_item_checkpoints
             WHERE job_id = '{}' ORDER BY sequence",
            admitted.job_id
        ),
    );
    assert_eq!(checkpoints.len(), 1);
    assert!(matches!(&checkpoints[0][0], Value::Text(value) if value == "batch-item-0001"));
    assert!(matches!(&checkpoints[0][1], Value::Text(value) if value == "succeeded"));
    let item_states = query_rows_for_test(
        &store.connection,
        &format!(
            "SELECT state FROM job_items WHERE job_id = '{}' ORDER BY ordinal",
            admitted.job_id
        ),
    );
    assert!(matches!(&item_states[0][0], Value::Text(value) if value == "succeeded"));
    assert!(matches!(&item_states[1][0], Value::Text(value) if value == "not_started"));
}

#[cfg(target_os = "macos")]
#[test]
fn failed_batch_completion_rolls_back_aggregate_but_preserves_item_checkpoints() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("output");
    let workspace = root.path().join("workspace");
    fs::create_dir(&output).unwrap();
    fs::create_dir(&workspace).unwrap();
    let plan = two_item_batch(root.path(), &output, &workspace);
    let (mut store, admitted) =
        admit_copy_batch_for_history(root.path(), &output, &workspace, &plan);
    let session = nscb::CopyBatchSession::new();
    let execution = nscb::Engine::new().execute_copy_batch_with_checkpoint(
        plan,
        &session,
        nscb::CancellationHandle::new(),
        |checkpoint| {
            store
                .checkpoint_batch_item(&admitted.job_id, &checkpoint)
                .map_err(|_| nscb::CopyBatchCheckpointError)
        },
    );
    assert_eq!(execution.result().state(), JobState::Succeeded);
    store
        .connection
        .execute_batch(
            "CREATE TRIGGER reject_batch_completion
             BEFORE UPDATE OF state ON jobs
             WHEN OLD.state = 'running'
             BEGIN SELECT RAISE(ABORT, 'injected aggregate completion failure'); END;",
        )
        .unwrap();
    let completion = session.last_completion().unwrap().unwrap();
    assert_eq!(
        store.complete_batch(&admitted.job_id, &completion, execution.failed_checkpoint(),),
        Err(HistoryError::CompletionFailed)
    );
    let state: String = store
        .connection
        .query_row(
            "SELECT state FROM jobs WHERE job_id = ?1",
            [&admitted.job_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "running");
    let checkpoint_count: i64 = store
        .connection
        .query_row(
            "SELECT COUNT(*) FROM batch_item_checkpoints WHERE job_id = ?1",
            [&admitted.job_id],
            |row| row.get(0),
        )
        .unwrap();
    let artifact_count: i64 = store
        .connection
        .query_row(
            "SELECT COUNT(*) FROM job_artifacts
             WHERE job_id = ?1 AND item_key IS NULL",
            [&admitted.job_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(checkpoint_count, 2);
    assert_eq!(artifact_count, 0);
    let item_artifact_count: i64 = store
        .connection
        .query_row(
            "SELECT COUNT(*) FROM job_artifacts
             WHERE job_id = ?1 AND item_key IS NOT NULL
               AND role = 'published_destination'",
            [&admitted.job_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(item_artifact_count, 2);
}

#[cfg(target_os = "macos")]
#[test]
fn interrupted_batch_recovery_retains_checkpoint_evidence_and_unresolved_publication() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("output");
    let workspace = root.path().join("workspace");
    fs::create_dir(&output).unwrap();
    fs::create_dir(&workspace).unwrap();
    let source = root.path().join("published.bin");
    fs::write(&source, b"published before the checkpoint").unwrap();
    let plan = nscb::Engine::new()
        .plan_copy_batch(
            nscb::CopyBatchRequest::new(&output, &workspace)
                .with_item(&source, output.join("published.bin")),
        )
        .unwrap();
    let (store, admitted) = admit_copy_batch_for_history(root.path(), &output, &workspace, &plan);
    let job_id = admitted.job_id.clone();
    let session = nscb::CopyBatchSession::new();
    let execution = nscb::Engine::new().execute_copy_batch(plan, &session);
    assert_eq!(execution.state(), JobState::Succeeded);
    // Model a crash after publication but before the planned item was checkpointed.
    let mut evidence = serde_json::json!({
        "sequence": 0,
        "item": execution.items()[0],
    });
    assert!(
        evidence["item"]["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|artifact| artifact["role"] == "published_destination"),
        "the crash fixture must retain destination publication evidence: {evidence}"
    );
    evidence["item"]["state"] = serde_json::json!("failed");
    evidence["item"]["outcome"] = JsonValue::Null;
    evidence["item"]["failure"] = serde_json::json!({"code": "publication_failed"});
    store.connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        store
            .connection
            .execute(
                "UPDATE job_items
                 SET state = 'failed', outcome = NULL, failure_code = 'publication_failed',
                     evidence_json = ?1
                 WHERE job_id = ?2 AND item_key = 'batch-item-0001'
                   AND state IN ('planned', 'running')",
                params![evidence.to_string(), job_id],
            )
            .unwrap(),
        1
    );
    store
        .connection
        .execute(
            "INSERT INTO batch_item_checkpoints
             (job_id, item_key, sequence, item_state, outcome, failure_code,
              publication_state, evidence_json, recorded_at)
             VALUES (?1, 'batch-item-0001', 0, 'failed', NULL, 'publication_failed',
                     'published_unresolved', ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            params![job_id, evidence.to_string()],
        )
        .unwrap();
    for (ordinal, artifact) in evidence["item"]["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let identity_known = artifact["device"].is_number() && artifact["inode"].is_number();
        let content_known =
            artifact["sha256"].is_string() || artifact["recorded_sha256"].is_string();
        store
            .connection
            .execute(
                "INSERT INTO job_artifacts
                 (job_id, item_key, ordinal, role, path, retained, identity_known,
                  content_known, evidence_json)
                 VALUES (?1, 'batch-item-0001', ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    job_id,
                    i64::try_from(ordinal).unwrap(),
                    artifact["role"].as_str().unwrap(),
                    artifact["path"].as_str().unwrap(),
                    artifact["retained"].as_bool().unwrap(),
                    identity_known,
                    content_known,
                    serde_json::to_string(artifact).unwrap(),
                ],
            )
            .unwrap();
    }
    store.connection.execute_batch("COMMIT").unwrap();
    let seeded = store.load(&job_id).unwrap();
    assert_eq!(seeded.items[0].state, "failed");
    assert_eq!(seeded.items[0].publication_state, "published_unresolved");
    let claim_state: String = store
        .connection
        .query_row(
            "SELECT state FROM job_lease_claims WHERE job_id = ?1",
            [&job_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(claim_state, "outstanding");
    drop(admitted);
    let job_state: String = store
        .connection
        .query_row(
            "SELECT state FROM jobs WHERE job_id = ?1",
            [&job_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(job_state, "running");
    assert_eq!(store.reconcile_interrupted().unwrap(), 1);

    let checkpoints = query_rows_for_test(
        &store.connection,
        &format!(
            "SELECT item_key, item_state FROM batch_item_checkpoints
             WHERE job_id = '{}' ORDER BY sequence",
            job_id
        ),
    );
    assert_eq!(checkpoints.len(), 1);
    assert!(matches!(&checkpoints[0][0], Value::Text(value) if value == "batch-item-0001"));
    assert!(matches!(&checkpoints[0][1], Value::Text(value) if value == "failed"));
    let (publication_state, evidence_json): (String, String) = store
        .connection
        .query_row(
            "SELECT publication_state, evidence_json FROM batch_item_checkpoints
             WHERE job_id = ?1 AND item_key = 'batch-item-0001'",
            [&job_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(publication_state, "published_unresolved");
    let evidence: JsonValue = serde_json::from_str(&evidence_json).unwrap();
    assert!(
        evidence["item"]["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|artifact| artifact["role"] == "published_destination"),
        "recovery must retain unresolved destination evidence: {evidence}"
    );
    let (artifact_item_key, artifact_path, artifact_evidence_json): (String, String, String) =
        store
            .connection
            .query_row(
                "SELECT item_key, path, evidence_json FROM job_artifacts
             WHERE job_id = ?1 AND role = 'published_destination'
             ORDER BY ordinal LIMIT 1",
                [&job_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
    assert_eq!(artifact_item_key, "batch-item-0001");
    let projected_artifact: JsonValue = serde_json::from_str(&artifact_evidence_json).unwrap();
    let checkpoint_artifact = evidence["item"]["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|artifact| artifact["role"] == "published_destination")
        .unwrap();
    assert_eq!(artifact_path, checkpoint_artifact["path"].as_str().unwrap());
    assert_eq!(projected_artifact, *checkpoint_artifact);
    let claim_state: String = store
        .connection
        .query_row(
            "SELECT state FROM job_lease_claims WHERE job_id = ?1",
            [&job_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(claim_state, "unresolved");
    let job_state: String = store
        .connection
        .query_row(
            "SELECT state FROM jobs WHERE job_id = ?1",
            [&job_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(job_state, "interrupted");
    let item_states = query_rows_for_test(
        &store.connection,
        &format!(
            "SELECT state FROM job_items WHERE job_id = '{}' ORDER BY ordinal",
            job_id
        ),
    );
    assert_eq!(item_states.len(), 1);
    assert!(matches!(&item_states[0][0], Value::Text(value) if value == "failed"));
    let recovered = store.load(&job_id).unwrap();
    let unresolved_item = &recovered.items[0];
    assert_eq!(unresolved_item.state, "failed");
    assert_eq!(
        unresolved_item.failure_code.as_deref(),
        Some("publication_failed")
    );
    assert_eq!(unresolved_item.publication_state, "published_unresolved");
    assert!(
        unresolved_item.evidence.as_ref().unwrap()["item"]["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|artifact| artifact["role"] == "published_destination")
    );
}

fn v3_database_for_migration(path: &Path) -> Connection {
    drop(create_v2_database(path, "migration-job", "succeeded"));
    let mut connection = Connection::open(path).unwrap();
    super::storage::migrate_v2_to_v3(&mut connection, path).unwrap();
    connection.execute_batch("PRAGMA user_version = 3").unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        3
    );
    connection
}

fn populate_v3_migration_evidence(connection: &Connection) -> (String, String) {
    let (slot_id, slot_key) = connection
        .query_row(
            "SELECT slot_id, slot_key FROM lease_slots ORDER BY ordinal LIMIT 1",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .unwrap();
    connection
        .execute(
            "UPDATE jobs
             SET submission_kind = 'independent_batch', state = 'failed',
                 invocation_cwd = '/fixture',
                 started_at = '2026-01-01T00:00:00Z',
                 terminal_at = '2026-01-01T00:00:01Z', failure_code = 'source_unavailable',
                 publication_state = 'not_completed', retry_scope = 'failed_items',
                 lease_slot_id = ?1
             WHERE job_id = 'migration-job'",
            [&slot_id],
        )
        .unwrap();
    connection
        .execute_batch(
            "INSERT INTO job_items
                 (job_id, ordinal, item_key, kind, source, destination, state,
                  outcome, failure_code, evidence_json)
             VALUES
                 ('migration-job', 0, 'legacy-item', 'copy_through',
'/fixture/inputs/source.bin', '/fixture/output.bin', 'failed',
                  NULL, 'source_unavailable', '{\"legacy_item\":true}');
             INSERT INTO job_artifacts
                 (job_id, ordinal, role, path, retained, identity_known,
                  content_known, evidence_json)
             VALUES
                 ('migration-job', 0, 'workspace', '/fixture/workspace', 1, 1, 1,
                  '{\"legacy_artifact\":true}');",
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO job_lease_claims
                 (claim_id, job_id, slot_id, claim_token, state, created_at, resolved_at)
             VALUES
                 ('legacy-claim', 'migration-job', ?1, 'legacy-token', 'released',
                  '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z')",
            [&slot_id],
        )
        .unwrap();
    (slot_id, slot_key)
}

#[test]
fn finalized_v3_store_migrates_and_preserves_legacy_evidence() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let connection = v3_database_for_migration(&path);
    let (slot_id, slot_key) = populate_v3_migration_evidence(&connection);
    super::lease::initialize_slot_files(&connection, &path, true).unwrap();
    connection
        .execute_batch("UPDATE history_registry SET ready = 1")
        .unwrap();
    let original_schema = query_rows_for_test(
        &connection,
        "SELECT type, name, tbl_name, sql FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    );
    let original_jobs = query_rows_for_test(&connection, "SELECT * FROM jobs ORDER BY rowid");
    let original_items = query_rows_for_test(&connection, "SELECT * FROM job_items ORDER BY rowid");
    let original_artifacts =
        query_rows_for_test(&connection, "SELECT * FROM job_artifacts ORDER BY rowid");
    let original_claims =
        query_rows_for_test(&connection, "SELECT * FROM job_lease_claims ORDER BY rowid");
    let original_slots =
        query_rows_for_test(&connection, "SELECT * FROM lease_slots ORDER BY rowid");
    let original_registry =
        query_rows_for_test(&connection, "SELECT * FROM history_registry ORDER BY rowid");
    drop(connection);

    let store = HistoryStore::open_at(&path).unwrap();
    assert_eq!(store.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    assert_eq!(
        store
            .connection
            .query_row("SELECT ready FROM history_registry", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
    let job = store.load("migration-job").unwrap();
    assert_eq!(job.submission_kind, "independent_batch");
    assert_eq!(job.state, "failed");
    assert_eq!(job.retry_scope, "failed_items");
    assert_eq!(job.items.len(), 1);
    assert_eq!(job.items[0].item_key, "legacy-item");
    assert_eq!(job.items[0].state, "failed");
    assert_eq!(
        job.items[0].provenance.as_ref().unwrap()["kind"],
        "nscb.legacy_unqualified_copy_batch_item_provenance"
    );
    assert_eq!(
        job.batch_source_intent.as_ref().unwrap().kind,
        "nscb.legacy_unqualified_batch_sources"
    );
    assert!(
        matches!(
            &store.failed_items_retry_intent("migration-job"),
            Err(HistoryError::UnsupportedFailedItems)
        ),
        "legacy provenance must not authorize failed item retry"
    );

    assert_eq!(
        store
            .connection
            .query_row("SELECT lease_slot_id FROM jobs", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
        slot_id
    );
    assert_eq!(
        store
            .connection
            .query_row(
                "SELECT role, path, evidence_json FROM job_artifacts",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .unwrap(),
        (
            "workspace".to_owned(),
            "/fixture/workspace".to_owned(),
            "{\"legacy_artifact\":true}".to_owned()
        )
    );
    assert_eq!(
        store
            .connection
            .query_row(
                "SELECT c.claim_token, s.slot_key FROM job_lease_claims c
                 JOIN lease_slots s USING (slot_id) WHERE c.job_id = 'migration-job'",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .unwrap(),
        ("legacy-token".to_owned(), slot_key)
    );

    let backup_path = path.with_extension("sqlite3.v3.bak");
    assert!(backup_path.is_file());
    let backup =
        Connection::open_with_flags(&backup_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(
        backup
            .pragma_query_value(None, "application_id", |row| row.get::<_, i64>(0))
            .unwrap(),
        APPLICATION_ID
    );
    assert_eq!(
        backup
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        backup
            .query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    assert_eq!(
        query_rows_for_test(
            &backup,
            "SELECT type, name, tbl_name, sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        ),
        original_schema
    );
    assert_eq!(
        query_rows_for_test(&backup, "SELECT * FROM jobs ORDER BY rowid"),
        original_jobs
    );
    assert_eq!(
        query_rows_for_test(&backup, "SELECT * FROM job_items ORDER BY rowid"),
        original_items
    );
    assert_eq!(
        query_rows_for_test(&backup, "SELECT * FROM job_artifacts ORDER BY rowid"),
        original_artifacts
    );
    assert_eq!(
        query_rows_for_test(&backup, "SELECT * FROM job_lease_claims ORDER BY rowid"),
        original_claims
    );
    assert_eq!(
        query_rows_for_test(&backup, "SELECT * FROM lease_slots ORDER BY rowid"),
        original_slots
    );
    assert_eq!(
        query_rows_for_test(&backup, "SELECT * FROM history_registry ORDER BY rowid"),
        original_registry
    );
}

#[test]
fn malformed_v3_schema_or_registry_fails_closed_before_migration() {
    for malformation in [
        "DROP TABLE job_artifacts",
        "DROP TABLE history_registry;
         CREATE TABLE history_registry (singleton INTEGER NOT NULL, ready INTEGER NOT NULL);
         INSERT INTO history_registry VALUES (1, 2);",
        "DROP TABLE history_registry;
         CREATE TABLE history_registry (singleton INTEGER NOT NULL, ready INTEGER NOT NULL);
         INSERT INTO history_registry VALUES (1, 1), (2, 1);",
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("jobs.sqlite3");
        let connection = v3_database_for_migration(&path);
        connection.execute_batch(malformation).unwrap();
        drop(connection);

        assert_eq!(
            HistoryStore::open_at(&path).unwrap_err(),
            HistoryError::Corrupt
        );
        let connection = Connection::open(&path).unwrap();
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            3
        );
        assert!(!path.with_extension("sqlite3.v3.bak").exists());
    }
}

#[test]
fn v3_to_v4_migration_preserves_history_and_creates_batch_evidence_schema() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let mut connection = v3_database_for_migration(&path);
    super::storage::migrate_v3_to_v4(&mut connection, &path).unwrap();

    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        4
    );
    assert!(path.with_extension("sqlite3.v3.bak").is_file());
    assert_eq!(
        connection
            .query_row(
                "SELECT state FROM jobs WHERE job_id = 'migration-job'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "succeeded"
    );
    let provenance_column: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('job_items')
             WHERE name = 'provenance_json'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(provenance_column, 1);
    for table in [
        "batch_intents",
        "batch_source_intents",
        "batch_item_checkpoints",
    ] {
        assert!(super::storage::database_has_table(&connection, table).unwrap());
    }
    let source: String = connection
        .query_row(
            "SELECT source FROM jobs WHERE job_id = 'migration-job'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(source, "/fixture/source.bin");
}

#[test]
fn v4_commit_before_registry_finalization_reopens_and_finalizes() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let mut connection = v3_database_for_migration(&path);

    super::storage::migrate_v3_to_v4(&mut connection, &path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        4
    );
    assert_eq!(
        connection
            .query_row("SELECT ready FROM history_registry", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    drop(connection);

    let reopened = HistoryStore::open_at(&path).unwrap();
    assert_eq!(reopened.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    assert_eq!(
        reopened
            .connection
            .query_row("SELECT ready FROM history_registry", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
    assert_eq!(reopened.load("migration-job").unwrap().state, "succeeded");
}

#[test]
fn v4_pending_finalization_still_rejects_incomplete_schema() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let mut connection = v3_database_for_migration(&path);
    super::storage::migrate_v3_to_v4(&mut connection, &path).unwrap();
    connection
        .execute_batch("DROP TRIGGER batch_source_intent_owner_on_insert")
        .unwrap();
    drop(connection);

    assert_eq!(
        HistoryStore::open_at(&path).unwrap_err(),
        HistoryError::Corrupt
    );

    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT ready FROM history_registry", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
}

#[test]
fn pending_v3_batch_history_remains_readable_with_incomplete_nonretryable_provenance() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let connection = v3_database_for_migration(&path);
    assert_eq!(
        connection
            .query_row("SELECT ready FROM history_registry", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    connection
        .execute_batch(
            "UPDATE jobs
             SET submission_kind = 'independent_batch', state = 'failed',
                 retry_scope = 'failed_items'
             WHERE job_id = 'migration-job';
             INSERT INTO job_items
                 (job_id, ordinal, item_key, kind, source, destination, state,
                  outcome, failure_code, evidence_json)
             VALUES
                 ('migration-job', 0, 'legacy-item', 'copy_through',
'/fixture/inputs/source.bin', '/fixture/output.bin', 'failed',
                  NULL, 'source_unavailable', NULL);",
        )
        .unwrap();

    drop(connection);

    let store = HistoryStore::open_at(&path).unwrap();
    assert_eq!(store.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    assert_eq!(
        store
            .connection
            .query_row("SELECT ready FROM history_registry", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
    let job = store.load("migration-job").unwrap();
    assert_eq!(job.submission_kind, "independent_batch");
    assert_eq!(job.items.len(), 1);
    assert_eq!(
        job.items[0].provenance.as_ref().unwrap()["kind"],
        "nscb.legacy_unqualified_copy_batch_item_provenance"
    );
    let source_intent = job.batch_source_intent.as_ref().unwrap();
    assert_eq!(source_intent.kind, "nscb.legacy_unqualified_batch_sources");
    assert!(source_intent.items.is_empty());
    assert!(matches!(
        store.failed_items_retry_intent("migration-job"),
        Err(HistoryError::UnsupportedFailedItems)
    ));
}

#[test]
fn failed_v3_to_v4_migration_rolls_back_schema_and_retains_recovery_copy() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let mut connection = v3_database_for_migration(&path);
    connection
        .execute_batch("CREATE TABLE batch_intents (conflict INTEGER);")
        .unwrap();
    connection
        .execute_batch("UPDATE history_registry SET ready = 1")
        .unwrap();

    assert_eq!(
        super::storage::migrate_v3_to_v4(&mut connection, &path),
        Err(HistoryError::MigrationFailed)
    );
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        connection
            .query_row("SELECT ready FROM history_registry", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
    let provenance_column: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('job_items')
             WHERE name = 'provenance_json'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(provenance_column, 0);
    assert!(!super::storage::database_has_table(&connection, "batch_item_checkpoints").unwrap());
    assert!(path.with_extension("sqlite3.v3.bak").is_file());
    assert_eq!(
        connection
            .query_row(
                "SELECT state FROM jobs WHERE job_id = 'migration-job'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "succeeded"
    );
}

#[test]
fn v4_constraints_reject_malformed_batch_intent_checkpoint_and_terminal_state() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    drop(v3_database_for_migration(&path));
    let store = HistoryStore::open_at(&path).unwrap();
    store
        .connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap();
    assert!(
        store
            .connection
            .execute(
                "INSERT INTO batch_intents (job_id, schema_version, kind, intent_json)
             VALUES ('migration-job', 2, 'nscb.copy_batch_intent', '{}')",
                [],
            )
            .is_err()
    );
    for (ordinal, item_key) in [(0, "item"), (1, "second-item")] {
        store
            .connection
            .execute(
                "INSERT INTO job_items
                 (job_id, ordinal, item_key, kind, source, destination, state,
                  provenance_json)
                 VALUES ('migration-job', ?1, ?2, 'copy_through', '/s', '/d',
                         'planned', '{}')",
                params![ordinal, item_key],
            )
            .unwrap();
    }
    assert!(
        store
            .connection
            .execute(
                "INSERT INTO batch_item_checkpoints
             (job_id, item_key, sequence, item_state, publication_state,
              evidence_json, recorded_at)
             VALUES ('migration-job', 'item', 0, 'future_state', 'unknown',
                     '{}', '2026-01-01T00:00:00Z')",
                [],
            )
            .is_err()
    );
    assert!(
        store
            .connection
            .execute(
                "INSERT INTO batch_item_checkpoints
             (job_id, item_key, sequence, item_state, publication_state,
              evidence_json, recorded_at)
             VALUES ('migration-job', 'missing-item', 0, 'succeeded', 'completed',
                     '{}', '2026-01-01T00:00:00Z')",
                [],
            )
            .is_err()
    );
    store
        .connection
        .execute(
            "INSERT INTO batch_item_checkpoints
             (job_id, item_key, sequence, item_state, publication_state,
              evidence_json, recorded_at)
             VALUES ('migration-job', 'item', 0, 'succeeded', 'completed',
                     '{}', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
    assert!(
        store
            .connection
            .execute(
                "INSERT INTO batch_item_checkpoints
             (job_id, item_key, sequence, item_state, publication_state,
              evidence_json, recorded_at)
             VALUES ('migration-job', 'second-item', 0, 'failed', 'completed',
                     '{}', '2026-01-01T00:00:00Z')",
                [],
            )
            .is_err()
    );
    store
        .connection
        .execute(
            "UPDATE jobs SET submission_kind = 'independent_batch', source = NULL,
         state = 'running'
             WHERE job_id = 'migration-job'",
            [],
        )
        .unwrap();
    assert!(
        store
            .connection
            .execute(
                "UPDATE jobs SET state = 'succeeded'
             WHERE job_id = 'migration-job'",
                [],
            )
            .is_err()
    );
}
