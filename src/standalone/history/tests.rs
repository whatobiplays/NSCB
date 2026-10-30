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
        source: PathBuf::from("/fixture/source.bin"),
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
        items: vec![AdmissionItem {
            item_key: "copy-through-0".to_owned(),
            source: PathBuf::from("/fixture/source.bin"),
            destination: PathBuf::from("/fixture/output.bin"),
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
            .unwrap();

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
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if crash_marker.is_file() {
            break;
        }
        match child.try_wait() {
            Ok(Some(status)) => panic!("migration child exited before DDL marker: {status}"),
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("could not check migration child status: {error}");
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("timed out waiting for migration DDL marker");
        }
        std::thread::yield_now();
    }
    assert_eq!(fs::read(&crash_marker).unwrap(), b"ddl-applied");
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

#[test]
fn child_v1_migration_crash_injection() {
    let Some(path) = std::env::var_os(CHILD_V1_MIGRATION_DATABASE) else {
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
    input.source = source.clone();
    input.destination = destination.clone();
    input.workspace = workspace.clone();
    input.items[0].source = source;
    input.items[0].destination = destination;
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

#[test]
fn retry_intent_rejects_future_and_malformed_job_contracts_before_copy_planning() {
    for (column, value) in [
        ("kind", "future_job"),
        ("submission_kind", "independent_batch"),
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
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("jobs.sqlite3");
    let store = HistoryStore::open_at(&path).unwrap();
    store
        .connection
        .execute(
            "INSERT INTO jobs
                (job_id, kind, submission_kind, invocation_cwd, source, source_provenance,
                  destination, destination_selection, workspace,
                  workspace_selection, conflict_policy,
                  conflict_policy_provenance, retry_scope, state, admitted_at,
                  terminal_at, publication_state, pruneable)
                VALUES ('batch', 'copy_through', 'independent_batch', '/fixture', '/s',
                         'cli_argument', '/d', 'explicit', '/w', 'explicit',
'fail', 'default', 'failed_items', 'completed_with_issues',
                         '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z',
                         'completed', 1)",
            [],
        )
        .unwrap();
    for (ordinal, key, state) in [
        (0, "succeeded-item", "succeeded"),
        (1, "failed-item", "failed"),
        (2, "cancelled-item", "cancelled"),
    ] {
        store
            .connection
            .execute(
                "INSERT INTO job_items
                     (job_id, ordinal, item_key, kind, source, destination, state)
                     VALUES ('batch', ?1, ?2, 'copy_through', '/s', '/d', ?3)",
                params![ordinal, key, state],
            )
            .unwrap();
    }

    assert_eq!(
        store.retry_failed_item_keys("batch").unwrap(),
        vec!["failed-item".to_owned()]
    );
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
                 VALUES ('batch', 'copy_through', 'independent_batch', '/fixture', '/s',
                 'cli_argument', '/d', 'explicit', '/w', 'explicit', 'fail', 'default',
                 'failed_items', 'completed_with_issues', '2026-01-01T00:00:00Z',
                 '2026-01-01T00:00:01Z', 'completed', 1)",
                [],
            )
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO job_items
                 (job_id, ordinal, item_key, kind, source, destination, state)
                 VALUES ('batch', 0, 'failed-item', 'copy_through', '/s', '/d', 'failed')",
                [],
            )
            .unwrap();
        store
            .connection
            .execute(
                &format!("UPDATE jobs SET {column} = ?1 WHERE job_id = 'batch'"),
                [value],
            )
            .unwrap();
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
