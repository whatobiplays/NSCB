//! SQLite schema migration, recovery validation, and private filesystem setup.

use super::lease::LEASE_SLOT_COUNT;
use super::model::HistoryError;
use super::{APPLICATION_ID, CURRENT_SCHEMA_VERSION};
use fs2::FileExt;
use rusqlite::ffi;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use std::collections::HashMap;
#[cfg(unix)]
use std::ffi::CString;
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::path::Component;
use std::path::{Path, PathBuf};

pub(crate) fn create_schema(connection: &mut Connection) -> Result<(), HistoryError> {
    connection
        .execute_batch(&format!(
            r#"BEGIN IMMEDIATE;
PRAGMA application_id = {APPLICATION_ID};
CREATE TABLE jobs (
    job_id TEXT PRIMARY KEY,
    parent_job_id TEXT,
    kind TEXT NOT NULL,
    submission_kind TEXT NOT NULL,
    source TEXT,
    invocation_cwd TEXT NOT NULL,
    source_provenance TEXT NOT NULL,
    destination TEXT NOT NULL,
    destination_selection TEXT NOT NULL,
    workspace TEXT NOT NULL,
    workspace_selection TEXT NOT NULL,
    conflict_policy TEXT NOT NULL,
    conflict_policy_provenance TEXT NOT NULL,
    parent_conflict_policy TEXT,
    parent_conflict_policy_provenance TEXT,
    retry_scope TEXT NOT NULL,
    state TEXT NOT NULL,
    admitted_at TEXT NOT NULL,
    started_at TEXT,
    terminal_at TEXT,
    outcome TEXT,
    failure_code TEXT,
    cleanup_warning_code TEXT,
    publication_state TEXT NOT NULL,
    pruneable INTEGER NOT NULL DEFAULT 0,
    required_providers_json TEXT NOT NULL DEFAULT '[]',
    required_keys_json TEXT NOT NULL DEFAULT '[]',
    result_json TEXT,
    snapshot_json TEXT,
    CONSTRAINT jobs_source_submission_contract CHECK (
        (submission_kind = 'single' AND source IS NOT NULL)
        OR (submission_kind = 'independent_batch' AND source IS NULL)
    )
);
CREATE TABLE job_items (
    job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    item_key TEXT NOT NULL,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    destination TEXT NOT NULL,
    destination_assigned INTEGER NOT NULL DEFAULT 1
        CONSTRAINT job_items_destination_representation CHECK (
            (destination_assigned = 1 AND length(destination) > 0)
            OR (destination_assigned = 0 AND destination = '')
        ),
    state TEXT NOT NULL,
    outcome TEXT,
    failure_code TEXT,
    evidence_json TEXT,
    provenance_json TEXT,
    PRIMARY KEY (job_id, ordinal),
    UNIQUE (job_id, item_key)
);
CREATE TABLE job_artifacts (
    job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    item_key TEXT,
    ordinal INTEGER NOT NULL,
    role TEXT NOT NULL,
    path TEXT NOT NULL,
    retained INTEGER NOT NULL,
    identity_known INTEGER NOT NULL,
    content_known INTEGER NOT NULL,
    evidence_json TEXT NOT NULL,
    PRIMARY KEY (job_id, ordinal),
    FOREIGN KEY (job_id, item_key)
        REFERENCES job_items(job_id, item_key) ON DELETE CASCADE
);
CREATE INDEX job_artifacts_item_owner ON job_artifacts(job_id, item_key);
CREATE TABLE batch_intents (
    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL
        CONSTRAINT batch_intents_schema_version CHECK (schema_version = 1),
    kind TEXT NOT NULL
        CONSTRAINT batch_intents_kind CHECK (kind = 'nscb.copy_batch_intent'),
    intent_json TEXT NOT NULL
        CONSTRAINT batch_intents_payload CHECK (length(intent_json) > 0)
);
CREATE TABLE batch_source_intents (
    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL
        CONSTRAINT batch_source_intents_schema_version CHECK (schema_version = 1),
    kind TEXT NOT NULL
        CONSTRAINT batch_source_intents_kind CHECK (
            kind IN ('nscb.copy_batch_sources', 'nscb.legacy_unqualified_batch_sources')
        ),
    intent_json TEXT NOT NULL
        CONSTRAINT batch_source_intents_payload CHECK (length(intent_json) > 0)
);
CREATE TABLE batch_item_checkpoints (
    job_id TEXT NOT NULL,
    item_key TEXT NOT NULL,
    sequence INTEGER NOT NULL
        CONSTRAINT batch_item_checkpoints_sequence CHECK (sequence >= 0),
    item_state TEXT NOT NULL
        CONSTRAINT batch_item_checkpoints_state CHECK (item_state IN (
            'preflight_failed', 'succeeded', 'skipped', 'failed',
            'uncertain', 'cancelled', 'not_started'
        )),
    outcome TEXT,
    failure_code TEXT,
    publication_state TEXT NOT NULL
        CONSTRAINT batch_item_checkpoints_publication CHECK (publication_state IN (
            'not_completed', 'completed', 'published_unresolved', 'uncertain', 'unknown'
        )),
    evidence_json TEXT NOT NULL
        CONSTRAINT batch_item_checkpoints_payload CHECK (length(evidence_json) > 0),
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (job_id, item_key),
    UNIQUE (job_id, sequence),
    FOREIGN KEY (job_id, item_key)
        REFERENCES job_items(job_id, item_key) ON DELETE CASCADE
);
CREATE TRIGGER independent_batch_intent_on_terminal
BEFORE UPDATE OF state ON jobs
WHEN NEW.submission_kind = 'independent_batch'
  AND NEW.state IN ('succeeded', 'completed_with_issues', 'failed', 'cancelled')
  AND NOT EXISTS (SELECT 1 FROM batch_intents WHERE job_id = NEW.job_id)
BEGIN
    SELECT RAISE(ABORT, 'independent batch intent missing');
END;
CREATE TRIGGER batch_intent_owner_on_insert
BEFORE INSERT ON batch_intents
WHEN NOT EXISTS (
    SELECT 1 FROM jobs
    WHERE job_id = NEW.job_id AND submission_kind = 'independent_batch'
)
BEGIN
    SELECT RAISE(ABORT, 'batch intent owner is not an independent batch');
END;
CREATE TRIGGER batch_intent_owner_on_update
BEFORE UPDATE OF job_id ON batch_intents
WHEN NOT EXISTS (
    SELECT 1 FROM jobs
    WHERE job_id = NEW.job_id AND submission_kind = 'independent_batch'
)
BEGIN
    SELECT RAISE(ABORT, 'batch intent owner is not an independent batch');
END;
CREATE TRIGGER job_batch_intent_owner_on_update
BEFORE UPDATE OF submission_kind ON jobs
WHEN NEW.submission_kind = 'single'
  AND (
      EXISTS (SELECT 1 FROM batch_intents WHERE job_id = NEW.job_id)
      OR EXISTS (SELECT 1 FROM batch_source_intents WHERE job_id = NEW.job_id)
  )
BEGIN
    SELECT RAISE(ABORT, 'single job cannot own a batch intent');
END;
CREATE TRIGGER independent_batch_source_intent_on_terminal
BEFORE UPDATE OF state ON jobs
WHEN NEW.submission_kind = 'independent_batch'
  AND NEW.state IN ('succeeded', 'completed_with_issues', 'failed', 'cancelled')
  AND NOT EXISTS (SELECT 1 FROM batch_source_intents WHERE job_id = NEW.job_id)
BEGIN
    SELECT RAISE(ABORT, 'independent batch source intent missing');
END;
CREATE TRIGGER batch_source_intent_owner_on_insert
BEFORE INSERT ON batch_source_intents
WHEN NOT EXISTS (
    SELECT 1 FROM jobs
    WHERE job_id = NEW.job_id AND submission_kind = 'independent_batch'
)
BEGIN
    SELECT RAISE(ABORT, 'batch source intent owner is not an independent batch');
END;
CREATE TRIGGER batch_source_intent_owner_on_update
BEFORE UPDATE OF job_id ON batch_source_intents
WHEN NOT EXISTS (
    SELECT 1 FROM jobs
    WHERE job_id = NEW.job_id AND submission_kind = 'independent_batch'
)
BEGIN
    SELECT RAISE(ABORT, 'batch source intent owner is not an independent batch');
END;
CREATE TRIGGER batch_artifact_owner_on_insert
BEFORE INSERT ON job_artifacts
WHEN (
    NEW.item_key IS NULL
    AND COALESCE((SELECT submission_kind FROM jobs WHERE job_id = NEW.job_id), '')
        = 'independent_batch'
) OR (
    NEW.item_key IS NOT NULL
    AND COALESCE((SELECT submission_kind FROM jobs WHERE job_id = NEW.job_id), '')
        != 'independent_batch'
)
BEGIN
    SELECT RAISE(ABORT, 'artifact owner does not match the Job submission kind');
END;
CREATE TRIGGER batch_artifact_owner_on_update
BEFORE UPDATE OF job_id, item_key ON job_artifacts
WHEN (
    NEW.item_key IS NULL
    AND COALESCE((SELECT submission_kind FROM jobs WHERE job_id = NEW.job_id), '')
        = 'independent_batch'
) OR (
    NEW.item_key IS NOT NULL
    AND COALESCE((SELECT submission_kind FROM jobs WHERE job_id = NEW.job_id), '')
        != 'independent_batch'
)
BEGIN
    SELECT RAISE(ABORT, 'artifact owner does not match the Job submission kind');
END;
CREATE INDEX jobs_history_order
    ON jobs(state, terminal_at DESC, admitted_at DESC, job_id DESC);
CREATE INDEX jobs_parent ON jobs(parent_job_id);
CREATE TABLE lease_slots (
    slot_id TEXT PRIMARY KEY,
    slot_key TEXT NOT NULL UNIQUE,
    ordinal INTEGER NOT NULL UNIQUE
);
CREATE TABLE job_lease_claims (
    claim_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL UNIQUE REFERENCES jobs(job_id) ON DELETE CASCADE,
    slot_id TEXT NOT NULL REFERENCES lease_slots(slot_id),
    claim_token TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL
        CONSTRAINT job_lease_claims_state CHECK (state IN ('outstanding', 'released', 'unresolved')),
    created_at TEXT NOT NULL,
    resolved_at TEXT,
    CONSTRAINT job_lease_claims_resolution CHECK (
        (state = 'outstanding' AND resolved_at IS NULL)
        OR (state IN ('released', 'unresolved') AND resolved_at IS NOT NULL)
    )
);
CREATE UNIQUE INDEX job_lease_claims_blocking_slot
    ON job_lease_claims(slot_id) WHERE state != 'released';
ALTER TABLE jobs ADD COLUMN lease_slot_id TEXT REFERENCES lease_slots(slot_id);
CREATE INDEX jobs_lease_slot ON jobs(lease_slot_id);
CREATE TABLE history_registry (
    singleton INTEGER PRIMARY KEY
        CONSTRAINT history_registry_singleton CHECK (singleton = 1),
    ready INTEGER NOT NULL
        CONSTRAINT history_registry_ready CHECK (ready IN (0, 1))
);
INSERT INTO history_registry(singleton, ready) VALUES (1, 0);
WITH RECURSIVE slot_ord(ordinal) AS (
    SELECT 0 UNION ALL
    SELECT ordinal + 1 FROM slot_ord WHERE ordinal + 1 < {LEASE_SLOT_COUNT}
)
INSERT INTO lease_slots(slot_id, slot_key, ordinal)
SELECT lower(hex(randomblob(16))),
       printf('lease-slot-%03d.lock', ordinal), ordinal
FROM slot_ord;
COMMIT;"#
        ))
        .map_err(|error| {
            #[cfg(test)]
            eprintln!("history schema initialization failed: {error}");
            #[cfg(not(test))]
            let _ = error;
            HistoryError::MigrationFailed
        })
}

/// Describes whether a recovery backup's containing directory was flushed.
///
/// `Unsupported` omits only the containing-directory/device power-loss barrier.
/// Backup contents are still synced and checked, and SQLite transactions still
/// protect migration rollback after a process crash.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ParentDirectorySyncOutcome {
    #[cfg(any(unix, test))]
    Synced,
    #[cfg(any(not(unix), test))]
    Unsupported,
}

/// Migrates version 1 records after acquiring SQLite writer exclusion.
///
/// The recovery backup and schema upgrade share this exclusion so a version 1
/// writer cannot commit between the recovery snapshot and the migration.
pub(crate) fn migrate_v1_to_v2(
    connection: &mut Connection,
    path: &Path,
) -> Result<(), HistoryError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| HistoryError::MigrationFailed)?;
    create_recovery_backup(&transaction, path, 1)?;
    transaction
            .execute_batch(
            "ALTER TABLE jobs ADD COLUMN destination_selection TEXT NOT NULL DEFAULT 'explicit';\n\
             ALTER TABLE jobs ADD COLUMN workspace_selection TEXT NOT NULL DEFAULT 'explicit';\n\
ALTER TABLE jobs ADD COLUMN invocation_cwd TEXT;\n\
             ALTER TABLE jobs ADD COLUMN conflict_policy TEXT NOT NULL DEFAULT 'fail';\n\
             ALTER TABLE jobs ADD COLUMN conflict_policy_provenance TEXT NOT NULL DEFAULT 'default';\n\
             ALTER TABLE jobs ADD COLUMN parent_conflict_policy TEXT;\n\
             ALTER TABLE jobs ADD COLUMN parent_conflict_policy_provenance TEXT;\n\
             ALTER TABLE jobs ADD COLUMN retry_scope TEXT NOT NULL DEFAULT 'all';\n\
             ALTER TABLE jobs ADD COLUMN publication_state TEXT NOT NULL DEFAULT 'unknown';\n\
             ALTER TABLE jobs ADD COLUMN pruneable INTEGER NOT NULL DEFAULT 0;\n\
             ALTER TABLE jobs ADD COLUMN required_providers_json TEXT NOT NULL DEFAULT '[]';\n\
             ALTER TABLE jobs ADD COLUMN required_keys_json TEXT NOT NULL DEFAULT '[]';\n\
             ALTER TABLE jobs ADD COLUMN result_json TEXT;\n\
             ALTER TABLE jobs ADD COLUMN snapshot_json TEXT;\n\
             CREATE TABLE job_items (\n                job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,\n                ordinal INTEGER NOT NULL,\n                item_key TEXT NOT NULL,\n                kind TEXT NOT NULL,\n                source TEXT NOT NULL,\n                destination TEXT NOT NULL,\n                state TEXT NOT NULL,\n                outcome TEXT,\n                failure_code TEXT,\n                evidence_json TEXT,\n                PRIMARY KEY (job_id, ordinal),\n                UNIQUE (job_id, item_key)\n            );\n\
             CREATE TABLE job_artifacts (\n                job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,\n                ordinal INTEGER NOT NULL,\n                role TEXT NOT NULL,\n                path TEXT NOT NULL,\n                retained INTEGER NOT NULL,\n                identity_known INTEGER NOT NULL,\n                content_known INTEGER NOT NULL,\n                evidence_json TEXT NOT NULL,\n                PRIMARY KEY (job_id, ordinal)\n            );\n\
             CREATE INDEX jobs_history_order\n                ON jobs(state, terminal_at DESC, admitted_at DESC, job_id DESC);\n\
             CREATE INDEX jobs_parent ON jobs(parent_job_id);\n\
            PRAGMA user_version = 2;"
        )
        .map_err(|error| {
            #[cfg(test)]
            eprintln!("history v1 migration failed: {error}");
            #[cfg(not(test))]
            let _ = error;
            HistoryError::MigrationFailed
        })?;
    #[cfg(test)]
    if let Some(marker) = std::env::var_os("NSCB_TEST_V1_MIGRATION_DDL_REACHED") {
        std::fs::write(marker, b"ddl-applied")
            .expect("test migration crash marker could not be written");
        loop {
            std::thread::park();
        }
    }
    transaction
        .commit()
        .map_err(|_| HistoryError::MigrationFailed)
}

/// Adds durable slot identities and Job claims to a version 2 database.
///
/// Version 1 upgrades pass through version 2 first, so this function always
/// starts from the exact schema version named by its recovery backup.
pub(crate) fn migrate_v2_to_v3(
    connection: &mut Connection,
    path: &Path,
) -> Result<(), HistoryError> {
    migrate_v2_to_v3_with_parent_sync(connection, path, sync_parent_directory_durably)
}

/// Applies the version 2 migration with a caller-supplied backup directory sync.
///
/// The sync completes before schema changes can commit. Keeping it injectable
/// lets tests prove that a sync error leaves the version 2 transaction intact.
pub(super) fn migrate_v2_to_v3_with_parent_sync(
    connection: &mut Connection,
    path: &Path,
    sync_parent: impl Fn(&Path) -> io::Result<ParentDirectorySyncOutcome>,
) -> Result<(), HistoryError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| HistoryError::MigrationFailed)?;
    let legacy_activity = acquire_legacy_active_job_locks(path, &transaction)?;
    if legacy_activity.jobs.len() > LEASE_SLOT_COUNT {
        return Err(HistoryError::LockFailed);
    }
    let database_path = canonical_file_path(path)?;
    let backup_source = Connection::open_with_flags(
        &database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| HistoryError::BackupFailed)?;
    create_recovery_backup_with_parent_sync(&backup_source, path, 2, &sync_parent)?;
    transaction
        .execute_batch(&format!(
            "CREATE TABLE lease_slots (
                slot_id TEXT PRIMARY KEY,
                slot_key TEXT NOT NULL UNIQUE,
                ordinal INTEGER NOT NULL UNIQUE
            );
            CREATE TABLE job_lease_claims (
                claim_id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL UNIQUE REFERENCES jobs(job_id) ON DELETE CASCADE,
                slot_id TEXT NOT NULL REFERENCES lease_slots(slot_id),
                claim_token TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL CHECK (state IN ('outstanding', 'released', 'unresolved')),
                created_at TEXT NOT NULL,
                resolved_at TEXT,
                CHECK ((state = 'outstanding' AND resolved_at IS NULL)
                    OR (state IN ('released', 'unresolved') AND resolved_at IS NOT NULL))
            );
            CREATE UNIQUE INDEX job_lease_claims_blocking_slot
                ON job_lease_claims(slot_id) WHERE state != 'released';
            ALTER TABLE jobs ADD COLUMN lease_slot_id TEXT REFERENCES lease_slots(slot_id);
            CREATE INDEX jobs_lease_slot ON jobs(lease_slot_id);
            CREATE TABLE history_registry (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                ready INTEGER NOT NULL CHECK (ready IN (0, 1))
            );
            INSERT INTO history_registry(singleton, ready) VALUES (1, 0);
            WITH RECURSIVE slot_ord(ordinal) AS (
                SELECT 0 UNION ALL
                SELECT ordinal + 1 FROM slot_ord WHERE ordinal + 1 < {LEASE_SLOT_COUNT}
            )
            INSERT INTO lease_slots(slot_id, slot_key, ordinal)
                SELECT lower(hex(randomblob(16))),
                    printf('lease-slot-%03d.lock', ordinal), ordinal
                FROM slot_ord;"
        ))
        .map_err(|_| HistoryError::MigrationFailed)?;

    let slots = {
        let mut statement = transaction
            .prepare("SELECT slot_id FROM lease_slots ORDER BY ordinal")
            .map_err(|_| HistoryError::MigrationFailed)?;
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| HistoryError::MigrationFailed)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| HistoryError::MigrationFailed)?
    };
    for (ordinal, (job_id, admitted_at)) in legacy_activity.jobs.iter().enumerate() {
        let slot_id = slots.get(ordinal).ok_or(HistoryError::MigrationFailed)?;
        let changed = transaction
            .execute(
                "UPDATE jobs
                 SET state = 'interrupted',
                     terminal_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                     failure_code = 'interrupted',
                     publication_state = 'unknown',
                     pruneable = 0,
                     lease_slot_id = ?1
                 WHERE job_id = ?2 AND state IN ('admitted', 'running')",
                rusqlite::params![slot_id, job_id],
            )
            .map_err(|_| HistoryError::MigrationFailed)?;
        if changed != 1 {
            return Err(HistoryError::MigrationFailed);
        }
        transaction
            .execute(
                "UPDATE job_items
                 SET state = 'interrupted',
                     failure_code = COALESCE(failure_code, 'interrupted')
                 WHERE job_id = ?1 AND state IN ('planned', 'running')",
                [job_id],
            )
            .map_err(|_| HistoryError::MigrationFailed)?;
        transaction
            .execute(
                "INSERT INTO job_lease_claims
                 (claim_id, job_id, slot_id, claim_token, state, created_at, resolved_at)
                 VALUES (?1, ?1, ?2, lower(hex(randomblob(16))), 'unresolved', ?3,
                         strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                rusqlite::params![job_id, slot_id, admitted_at],
            )
            .map_err(|_| HistoryError::MigrationFailed)?;
    }
    transaction
        .commit()
        .map_err(|_| HistoryError::MigrationFailed)
}

/// Adds independently admitted batch intent, source intent, and item-owned
/// artifact evidence to a version 3 database.
///
/// The rebuild runs in one transaction after foreign-key enforcement is
/// disabled outside that transaction. Every required relationship is checked
/// before commit, and the prior enforcement state is restored on both success
/// and failure. A recovery backup is created before schema changes commit.
pub(crate) fn migrate_v3_to_v4(
    connection: &mut Connection,
    path: &Path,
) -> Result<(), HistoryError> {
    let foreign_keys_enabled = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))
        .map_err(|_| HistoryError::MigrationFailed)?;
    if foreign_keys_enabled {
        connection
            .execute_batch("PRAGMA foreign_keys = OFF")
            .map_err(|_| HistoryError::MigrationFailed)?;
        let disabled = connection
            .pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))
            .map_err(|_| HistoryError::MigrationFailed)?;
        if disabled {
            return Err(HistoryError::MigrationFailed);
        }
    }

    let migration = (|| {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| HistoryError::MigrationFailed)?;
        create_recovery_backup(&transaction, path, 3)?;
        transaction
            .execute_batch(
                r#"ALTER TABLE job_items ADD COLUMN provenance_json TEXT;
ALTER TABLE job_items ADD COLUMN destination_assigned INTEGER NOT NULL DEFAULT 1
    CONSTRAINT job_items_destination_representation CHECK (
        (destination_assigned = 1 AND length(destination) > 0)
        OR (destination_assigned = 0 AND destination = '')
    );
CREATE TABLE jobs_v4 (
    job_id TEXT PRIMARY KEY,
    parent_job_id TEXT,
    kind TEXT NOT NULL,
    submission_kind TEXT NOT NULL,
    source TEXT,
    invocation_cwd TEXT,
    source_provenance TEXT NOT NULL,
    destination TEXT NOT NULL,
    destination_selection TEXT NOT NULL,
    workspace TEXT NOT NULL,
    workspace_selection TEXT NOT NULL,
    conflict_policy TEXT NOT NULL,
    conflict_policy_provenance TEXT NOT NULL,
    parent_conflict_policy TEXT,
    parent_conflict_policy_provenance TEXT,
    retry_scope TEXT NOT NULL,
    state TEXT NOT NULL,
    admitted_at TEXT NOT NULL,
    started_at TEXT,
    terminal_at TEXT,
    outcome TEXT,
    failure_code TEXT,
    cleanup_warning_code TEXT,
    publication_state TEXT NOT NULL,
    pruneable INTEGER NOT NULL DEFAULT 0,
    required_providers_json TEXT NOT NULL DEFAULT '[]',
    required_keys_json TEXT NOT NULL DEFAULT '[]',
    result_json TEXT,
    snapshot_json TEXT,
    lease_slot_id TEXT REFERENCES lease_slots(slot_id),
    CONSTRAINT jobs_source_submission_contract CHECK (
        (submission_kind = 'single' AND source IS NOT NULL)
        OR (submission_kind = 'independent_batch' AND source IS NULL)
    )
);
INSERT INTO jobs_v4 (
    job_id, parent_job_id, kind, submission_kind, source, invocation_cwd,
    source_provenance, destination, destination_selection, workspace,
    workspace_selection, conflict_policy, conflict_policy_provenance,
    parent_conflict_policy, parent_conflict_policy_provenance, retry_scope,
    state, admitted_at, started_at, terminal_at, outcome, failure_code,
    cleanup_warning_code, publication_state, pruneable,
    required_providers_json, required_keys_json, result_json, snapshot_json,
    lease_slot_id
)
SELECT
    job_id, parent_job_id, kind, submission_kind,
    CASE WHEN submission_kind = 'independent_batch' THEN NULL ELSE source END,
    invocation_cwd, source_provenance, destination, destination_selection,
    workspace, workspace_selection, conflict_policy,
    conflict_policy_provenance, parent_conflict_policy,
    parent_conflict_policy_provenance, retry_scope, state, admitted_at,
    started_at, terminal_at, outcome, failure_code, cleanup_warning_code,
    publication_state, pruneable, required_providers_json,
    required_keys_json, result_json, snapshot_json, lease_slot_id
FROM jobs;
DROP TABLE jobs;
ALTER TABLE jobs_v4 RENAME TO jobs;
CREATE INDEX jobs_history_order
    ON jobs(state, terminal_at DESC, admitted_at DESC, job_id DESC);
CREATE INDEX jobs_parent ON jobs(parent_job_id);
CREATE INDEX jobs_lease_slot ON jobs(lease_slot_id);
CREATE TABLE job_artifacts_v4 (
    job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    item_key TEXT,
    ordinal INTEGER NOT NULL,
    role TEXT NOT NULL,
    path TEXT NOT NULL,
    retained INTEGER NOT NULL,
    identity_known INTEGER NOT NULL,
    content_known INTEGER NOT NULL,
    evidence_json TEXT NOT NULL,
    PRIMARY KEY (job_id, ordinal),
    FOREIGN KEY (job_id, item_key)
        REFERENCES job_items(job_id, item_key) ON DELETE CASCADE
);
CREATE TABLE batch_intents (
    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL
        CONSTRAINT batch_intents_schema_version CHECK (schema_version = 1),
    kind TEXT NOT NULL
        CONSTRAINT batch_intents_kind CHECK (kind = 'nscb.copy_batch_intent'),
    intent_json TEXT NOT NULL
        CONSTRAINT batch_intents_payload CHECK (length(intent_json) > 0)
);
INSERT INTO job_artifacts_v4 (
    job_id, item_key, ordinal, role, path, retained, identity_known,
    content_known, evidence_json
)
SELECT
    job_id, NULL, ordinal, role, path, retained, identity_known,
    content_known, evidence_json
FROM job_artifacts;
DROP TABLE job_artifacts;
ALTER TABLE job_artifacts_v4 RENAME TO job_artifacts;
CREATE INDEX job_artifacts_item_owner ON job_artifacts(job_id, item_key);
CREATE TABLE batch_source_intents (
    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL
        CONSTRAINT batch_source_intents_schema_version CHECK (schema_version = 1),
    kind TEXT NOT NULL
        CONSTRAINT batch_source_intents_kind CHECK (
            kind IN ('nscb.copy_batch_sources', 'nscb.legacy_unqualified_batch_sources')
        ),
    intent_json TEXT NOT NULL
        CONSTRAINT batch_source_intents_payload CHECK (length(intent_json) > 0)
);
CREATE TABLE batch_item_checkpoints (
    job_id TEXT NOT NULL,
    item_key TEXT NOT NULL,
    sequence INTEGER NOT NULL
        CONSTRAINT batch_item_checkpoints_sequence CHECK (sequence >= 0),
    item_state TEXT NOT NULL
        CONSTRAINT batch_item_checkpoints_state CHECK (item_state IN (
            'preflight_failed', 'succeeded', 'skipped', 'failed',
            'uncertain', 'cancelled', 'not_started'
        )),
    outcome TEXT,
    failure_code TEXT,
    publication_state TEXT NOT NULL
        CONSTRAINT batch_item_checkpoints_publication CHECK (publication_state IN (
            'not_completed', 'completed', 'published_unresolved', 'uncertain', 'unknown'
        )),
    evidence_json TEXT NOT NULL
        CONSTRAINT batch_item_checkpoints_payload CHECK (length(evidence_json) > 0),
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (job_id, item_key),
    UNIQUE (job_id, sequence),
    FOREIGN KEY (job_id, item_key)
        REFERENCES job_items(job_id, item_key) ON DELETE CASCADE
);
CREATE TRIGGER independent_batch_intent_on_terminal
BEFORE UPDATE OF state ON jobs
WHEN NEW.submission_kind = 'independent_batch'
  AND NEW.state IN ('succeeded', 'completed_with_issues', 'failed', 'cancelled')
  AND NOT EXISTS (SELECT 1 FROM batch_intents WHERE job_id = NEW.job_id)
BEGIN
    SELECT RAISE(ABORT, 'independent batch intent missing');
END;
CREATE TRIGGER batch_intent_owner_on_insert
BEFORE INSERT ON batch_intents
WHEN NOT EXISTS (
    SELECT 1 FROM jobs
    WHERE job_id = NEW.job_id AND submission_kind = 'independent_batch'
)
BEGIN
    SELECT RAISE(ABORT, 'batch intent owner is not an independent batch');
END;
CREATE TRIGGER batch_intent_owner_on_update
BEFORE UPDATE OF job_id ON batch_intents
WHEN NOT EXISTS (
    SELECT 1 FROM jobs
    WHERE job_id = NEW.job_id AND submission_kind = 'independent_batch'
)
BEGIN
    SELECT RAISE(ABORT, 'batch intent owner is not an independent batch');
END;
CREATE TRIGGER job_batch_intent_owner_on_update
BEFORE UPDATE OF submission_kind ON jobs
WHEN NEW.submission_kind = 'single'
  AND (
      EXISTS (SELECT 1 FROM batch_intents WHERE job_id = NEW.job_id)
      OR EXISTS (SELECT 1 FROM batch_source_intents WHERE job_id = NEW.job_id)
  )
BEGIN
    SELECT RAISE(ABORT, 'single job cannot own a batch intent');
END;
CREATE TRIGGER independent_batch_source_intent_on_terminal
BEFORE UPDATE OF state ON jobs
WHEN NEW.submission_kind = 'independent_batch'
  AND NEW.state IN ('succeeded', 'completed_with_issues', 'failed', 'cancelled')
  AND NOT EXISTS (SELECT 1 FROM batch_source_intents WHERE job_id = NEW.job_id)
BEGIN
    SELECT RAISE(ABORT, 'independent batch source intent missing');
END;
CREATE TRIGGER batch_source_intent_owner_on_insert
BEFORE INSERT ON batch_source_intents
WHEN NOT EXISTS (
    SELECT 1 FROM jobs
    WHERE job_id = NEW.job_id AND submission_kind = 'independent_batch'
)
BEGIN
    SELECT RAISE(ABORT, 'batch source intent owner is not an independent batch');
END;
CREATE TRIGGER batch_source_intent_owner_on_update
BEFORE UPDATE OF job_id ON batch_source_intents
WHEN NOT EXISTS (
    SELECT 1 FROM jobs
    WHERE job_id = NEW.job_id AND submission_kind = 'independent_batch'
)
BEGIN
    SELECT RAISE(ABORT, 'batch source intent owner is not an independent batch');
END;
CREATE TRIGGER batch_artifact_owner_on_insert
BEFORE INSERT ON job_artifacts
WHEN (
    NEW.item_key IS NULL
    AND COALESCE((SELECT submission_kind FROM jobs WHERE job_id = NEW.job_id), '')
        = 'independent_batch'
) OR (
    NEW.item_key IS NOT NULL
    AND COALESCE((SELECT submission_kind FROM jobs WHERE job_id = NEW.job_id), '')
        != 'independent_batch'
)
BEGIN
    SELECT RAISE(ABORT, 'artifact owner does not match the Job submission kind');
END;
CREATE TRIGGER batch_artifact_owner_on_update
BEFORE UPDATE OF job_id, item_key ON job_artifacts
WHEN (
    NEW.item_key IS NULL
    AND COALESCE((SELECT submission_kind FROM jobs WHERE job_id = NEW.job_id), '')
        = 'independent_batch'
) OR (
    NEW.item_key IS NOT NULL
    AND COALESCE((SELECT submission_kind FROM jobs WHERE job_id = NEW.job_id), '')
        != 'independent_batch'
)
BEGIN
    SELECT RAISE(ABORT, 'artifact owner does not match the Job submission kind');
END;
PRAGMA user_version = 4;"#,
            )
            .map_err(|error| {
                #[cfg(test)]
                eprintln!("history v3 migration failed: {error}");
                #[cfg(not(test))]
                let _ = error;
                HistoryError::MigrationFailed
            })?;
        let legacy_intent = super::model::BatchSourceIntent::legacy_incomplete();
        let legacy_intent_json =
            serde_json::to_string(&legacy_intent).map_err(|_| HistoryError::MigrationFailed)?;
        let legacy_intent_schema_version = i64::try_from(legacy_intent.schema_version)
            .map_err(|_| HistoryError::MigrationFailed)?;
        let legacy_item_provenance =
            serde_json::to_string(&super::model::legacy_unqualified_item_provenance())
                .map_err(|_| HistoryError::MigrationFailed)?;
        transaction
            .execute(
                "UPDATE job_items SET provenance_json = ?1
                 WHERE job_id IN (
                     SELECT job_id FROM jobs WHERE submission_kind = 'independent_batch'
                 )",
                [&legacy_item_provenance],
            )
            .map_err(|_| HistoryError::MigrationFailed)?;
        transaction
            .execute(
                "INSERT INTO batch_source_intents
                     (job_id, schema_version, kind, intent_json)
                 SELECT job_id, ?1, ?2, ?3 FROM jobs
                 WHERE submission_kind = 'independent_batch'",
                rusqlite::params![
                    legacy_intent_schema_version,
                    legacy_intent.kind,
                    legacy_intent_json
                ],
            )
            .map_err(|_| HistoryError::MigrationFailed)?;
        validate_foreign_key_integrity(&transaction).map_err(|_| HistoryError::MigrationFailed)?;
        #[cfg(test)]
        if let Some(marker) = std::env::var_os("NSCB_TEST_V3_MIGRATION_DDL_REACHED") {
            std::fs::write(marker, b"ddl-applied")
                .expect("test migration crash marker could not be written");
            loop {
                std::thread::park();
            }
        }
        transaction
            .commit()
            .map_err(|_| HistoryError::MigrationFailed)
    })();

    if foreign_keys_enabled
        && connection
            .execute_batch("PRAGMA foreign_keys = ON")
            .is_err()
    {
        return Err(HistoryError::MigrationFailed);
    }
    migration
}

fn acquire_legacy_active_job_locks(
    database_path: &Path,
    connection: &Connection,
) -> Result<LegacyActivity, HistoryError> {
    let active_jobs = {
        let mut statement = connection
            .prepare(
                "SELECT job_id, admitted_at FROM jobs
                 WHERE state IN ('admitted', 'running') ORDER BY job_id",
            )
            .map_err(|_| HistoryError::MigrationFailed)?;
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| HistoryError::MigrationFailed)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| HistoryError::MigrationFailed)?
    };
    let parent = database_path
        .parent()
        .ok_or(HistoryError::DirectoryUnavailable)?;
    let lock_directory = parent.join("job-locks");
    let mut guards = Vec::with_capacity(active_jobs.len());
    let mut jobs = Vec::with_capacity(active_jobs.len());
    let mut locked_names = std::collections::HashSet::new();
    for (job_id, admitted_at) in active_jobs {
        if !legacy_job_id_is_valid(&job_id) {
            return Err(HistoryError::LockFailed);
        }
        let mut candidate_paths = vec![lock_directory.join(format!("{job_id}.lock"))];
        let prefixed = lock_directory.join(format!("job-{job_id}.lock"));
        if fs::symlink_metadata(&prefixed).is_ok() {
            candidate_paths.push(prefixed);
        }
        let mut owner_found = false;
        for candidate in candidate_paths {
            if fs::symlink_metadata(&candidate).is_err() {
                continue;
            }
            let file = open_existing_private_lock_file(&candidate)
                .map_err(|_| HistoryError::LockFailed)?;
            file.try_lock_exclusive()
                .map_err(|_| HistoryError::LockFailed)?;
            if let Some(name) = candidate.file_name() {
                locked_names.insert(name.to_owned());
            }
            owner_found = true;
            guards.push(file);
        }
        if !owner_found {
            return Err(HistoryError::LockFailed);
        }
        jobs.push((job_id, admitted_at));
    }

    match fs::read_dir(&lock_directory) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|_| HistoryError::LockFailed)?;
                let name = entry.file_name();
                let Some(name_text) = name.to_str() else {
                    if entry
                        .path()
                        .extension()
                        .is_some_and(|extension| extension == "lock")
                    {
                        return Err(HistoryError::LockFailed);
                    }
                    continue;
                };
                if name_text == "history-schema.lock"
                    || !name_text.ends_with(".lock")
                    || locked_names.contains(std::ffi::OsStr::new(name_text))
                {
                    continue;
                }
                let file = open_existing_private_lock_file(&entry.path())
                    .map_err(|_| HistoryError::LockFailed)?;
                file.try_lock_exclusive()
                    .map_err(|_| HistoryError::LockFailed)?;
                guards.push(file);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && jobs.is_empty() => {}
        Err(_) => return Err(HistoryError::LockFailed),
    }
    Ok(LegacyActivity {
        jobs,
        _guards: guards,
    })
}

struct LegacyActivity {
    jobs: Vec<(String, String)>,
    _guards: Vec<File>,
}

fn legacy_job_id_is_valid(job_id: &str) -> bool {
    job_id.len() == 32
        && job_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Creates or validates a private recovery backup for a schema version.
///
/// New backups are written to a securely created staging file, validated
/// against the source database, and published without replacing an existing
/// backup. The backup contents and parent directory are synced before success
/// is returned. A backup left at the final path with non-private permissions
/// is rejected so an interrupted legacy creation cannot be reused.
pub(crate) fn create_recovery_backup(
    connection: &Connection,
    path: &Path,
    source_version: i64,
) -> Result<PathBuf, HistoryError> {
    create_recovery_backup_with_parent_sync(
        connection,
        path,
        source_version,
        &sync_parent_directory_durably,
    )
}

/// Creates or verifies a recovery backup using the supplied parent-sync operation.
///
/// Keeping the sync operation injectable lets migration tests verify that a
/// sync error prevents the schema transaction from committing.
fn create_recovery_backup_with_parent_sync(
    connection: &Connection,
    path: &Path,
    source_version: i64,
    sync_parent: &dyn Fn(&Path) -> io::Result<ParentDirectorySyncOutcome>,
) -> Result<PathBuf, HistoryError> {
    let database_path = canonical_file_path(path).map_err(|_| HistoryError::BackupFailed)?;
    let backup = database_path.with_extension(format!("sqlite3.v{source_version}.bak"));
    #[cfg(unix)]
    let existing_backup = match open_existing_regular_file(&backup) {
        Ok(file) => {
            use std::os::unix::fs::PermissionsExt;
            if file
                .metadata()
                .map_err(|_| HistoryError::BackupFailed)?
                .permissions()
                .mode()
                & 0o777
                != 0o600
            {
                return Err(HistoryError::BackupFailed);
            }
            Some(file)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => return Err(HistoryError::BackupFailed),
    };
    #[cfg(not(unix))]
    let existing_backup = match fs::symlink_metadata(&backup) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(HistoryError::BackupFailed);
        }
        Ok(_) => Some(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => return Err(HistoryError::BackupFailed),
    };
    if let Some(_verified_backup_file) = existing_backup {
        let backup_connection = Connection::open_with_flags(
            &backup,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| HistoryError::BackupFailed)?;
        let backup_snapshot = recovery_snapshot(&backup_connection, source_version)?;
        let source_snapshot = recovery_snapshot(connection, source_version)?;
        if backup_snapshot != source_snapshot {
            return Err(HistoryError::BackupFailed);
        }
        drop(backup_connection);
        sync_existing_backup_contents(&backup).map_err(|_| HistoryError::BackupFailed)?;
        sync_recovery_backup_parent(sync_parent, &backup)?;
        return Ok(backup);
    }

    let parent = backup.parent().ok_or(HistoryError::BackupFailed)?;
    let staging_file = tempfile::Builder::new()
        .prefix(".nscb-history-backup-")
        .tempfile_in(parent)
        .map_err(|_| HistoryError::BackupFailed)?;
    let staging_connection = Connection::open_with_flags(
        staging_file.path(),
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| HistoryError::BackupFailed)?;
    // The caller holds writer exclusion while this separate connection reads
    // the same committed database state as the migration transaction.
    let backup_source = Connection::open_with_flags(
        &database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| HistoryError::BackupFailed)?;
    copy_database(&backup_source, &staging_connection)?;
    let backup_connection = Connection::open_with_flags(
        staging_file.path(),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| HistoryError::BackupFailed)?;
    if recovery_snapshot(&backup_connection, source_version)?
        != recovery_snapshot(connection, source_version)?
    {
        return Err(HistoryError::BackupFailed);
    }
    drop(backup_connection);
    drop(staging_connection);
    staging_file
        .as_file()
        .sync_all()
        .map_err(|_| HistoryError::BackupFailed)?;
    let published_file = staging_file
        .persist_noclobber(&backup)
        .map_err(|_| HistoryError::BackupFailed)?;
    drop(published_file);
    sync_recovery_backup_parent(sync_parent, &backup)?;
    Ok(backup)
}

fn sync_recovery_backup_parent(
    sync_parent: &dyn Fn(&Path) -> io::Result<ParentDirectorySyncOutcome>,
    backup: &Path,
) -> Result<(), HistoryError> {
    match sync_parent(backup).map_err(|_| HistoryError::BackupFailed)? {
        #[cfg(any(unix, test))]
        ParentDirectorySyncOutcome::Synced => Ok(()),
        #[cfg(any(not(unix), test))]
        ParentDirectorySyncOutcome::Unsupported => Ok(()),
    }
}

/// Copies the main database into an already-open, distinct SQLite database.
///
/// The caller creates the destination file with private permissions before
/// SQLite opens it. The online backup API populates that same file, avoiding a
/// second file creation whose permissions would be controlled by the VFS.
fn copy_database(source: &Connection, destination: &Connection) -> Result<(), HistoryError> {
    let main_database = c"main";
    // SAFETY: Both handles remain alive for the whole backup; the destination
    // is a distinct, exclusively used staging connection, and both database
    // names point to a valid static C string.
    let backup = unsafe {
        ffi::sqlite3_backup_init(
            destination.handle(),
            main_database.as_ptr(),
            source.handle(),
            main_database.as_ptr(),
        )
    };
    if backup.is_null() {
        return Err(HistoryError::BackupFailed);
    }

    let step_result = loop {
        // SAFETY: `backup` is a live handle returned by `sqlite3_backup_init`
        // and is finalized below before this function returns.
        let result = unsafe { ffi::sqlite3_backup_step(backup, -1) };
        if result != ffi::SQLITE_OK {
            break result;
        }
    };
    // SAFETY: This finalizes the handle created above exactly once.
    let finish_result = unsafe { ffi::sqlite3_backup_finish(backup) };
    if step_result == ffi::SQLITE_DONE && finish_result == ffi::SQLITE_OK {
        Ok(())
    } else {
        Err(HistoryError::BackupFailed)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct RecoverySnapshot {
    schema: Vec<String>,
    tables: Vec<(String, Vec<Vec<String>>)>,
}

fn recovery_snapshot(
    connection: &Connection,
    expected_version: i64,
) -> Result<RecoverySnapshot, HistoryError> {
    verify_database_health(connection).map_err(|_| HistoryError::BackupFailed)?;
    let application_id = connection
        .pragma_query_value(None, "application_id", |row| row.get::<_, i64>(0))
        .map_err(|_| HistoryError::BackupFailed)?;
    let version = connection
        .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
        .map_err(|_| HistoryError::BackupFailed)?;
    if application_id != APPLICATION_ID || version != expected_version {
        return Err(HistoryError::BackupFailed);
    }
    let mut schema_statement = connection
        .prepare(
            "SELECT type || ':' || name || ':' || tbl_name || ':' ||
                    COALESCE(sql, '')
             FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%'
             ORDER BY type, name",
        )
        .map_err(|_| HistoryError::BackupFailed)?;
    let schema = schema_statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| HistoryError::BackupFailed)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| HistoryError::BackupFailed)?;
    let table_names = {
        let mut statement = connection
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .map_err(|_| HistoryError::BackupFailed)?;
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| HistoryError::BackupFailed)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| HistoryError::BackupFailed)?
    };
    let mut tables = Vec::with_capacity(table_names.len());
    for table_name in table_names {
        let identifier = table_name.replace('"', "\"\"");
        let columns =
            table_columns(connection, &table_name).map_err(|_| HistoryError::BackupFailed)?;
        if columns.is_empty() {
            return Err(HistoryError::BackupFailed);
        }
        let projection = columns
            .iter()
            .map(|column| format!("\"{}\"", column.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(", ");
        let mut statement = connection
            .prepare(&format!("SELECT {projection} FROM \"{identifier}\""))
            .map_err(|_| HistoryError::BackupFailed)?;
        let mut rows = statement
            .query([])
            .map_err(|_| HistoryError::BackupFailed)?;
        let mut table_rows = Vec::new();
        while let Some(row) = rows.next().map_err(|_| HistoryError::BackupFailed)? {
            let mut values = Vec::with_capacity(columns.len());
            for index in 0..columns.len() {
                let value = match row.get_ref(index).map_err(|_| HistoryError::BackupFailed)? {
                    ValueRef::Null => "N".to_owned(),
                    ValueRef::Integer(value) => format!("I{value}"),
                    ValueRef::Real(value) => format!("R{:016x}", value.to_bits()),
                    ValueRef::Text(value) => format!("T{}", encode_hex(value)),
                    ValueRef::Blob(value) => format!("B{}", encode_hex(value)),
                };
                values.push(value);
            }
            table_rows.push(values);
        }
        table_rows.sort();
        tables.push((table_name, table_rows));
    }
    Ok(RecoverySnapshot { schema, tables })
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

/// Validates a database before opening it through `HistoryStore`.
///
/// Version 3 databases may have registry `ready = 0` while pending or
/// `ready = 1` after finalization. Both states must contain the complete v3
/// schema and exactly one registry row.
///
/// A version 4 database with registry `ready = 0` is the durable state after
/// the final migration transaction commits and before finalization. Accepting
/// only the complete current schema in that state lets the store resume the
/// interrupted finalization without admitting partially migrated databases.
pub(crate) fn verify_database_health_for_open(connection: &Connection) -> Result<(), HistoryError> {
    verify_database_health_state(connection, true)
}

pub(crate) fn verify_database_health(connection: &Connection) -> Result<(), HistoryError> {
    verify_database_health_state(connection, false)
}

fn verify_database_health_state(
    connection: &Connection,
    allow_pending_finalization: bool,
) -> Result<(), HistoryError> {
    let result = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0))
        .map_err(|_| HistoryError::Corrupt)?;
    if result != "ok" {
        return Err(HistoryError::Corrupt);
    }
    let version = connection
        .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
        .map_err(|_| HistoryError::Corrupt)?;
    let application_id = connection
        .pragma_query_value(None, "application_id", |row| row.get::<_, i64>(0))
        .map_err(|_| HistoryError::Corrupt)?;
    match version {
        0 => {
            if !database_has_tables(connection)? {
                return Ok(());
            }
            if application_id != APPLICATION_ID
                || !database_has_table(connection, "history_registry")?
            {
                return Err(HistoryError::Corrupt);
            }
            validate_current_schema(connection, false)
        }
        1 => {
            if application_id != APPLICATION_ID {
                return Err(HistoryError::Corrupt);
            }
            validate_required_columns(connection, &["jobs"], V1_REQUIRED_COLUMNS)
        }
        2 => {
            if application_id != APPLICATION_ID {
                return Err(HistoryError::Corrupt);
            }
            if database_has_table(connection, "history_registry")? {
                validate_v3_schema(connection, false)
            } else {
                validate_required_columns(connection, V2_REQUIRED_TABLES, V2_REQUIRED_COLUMNS)
            }
        }
        3 => {
            if application_id != APPLICATION_ID {
                return Err(HistoryError::Corrupt);
            }
            validate_v3_schema(connection, true)
        }
        4 => {
            if application_id != APPLICATION_ID {
                return Err(HistoryError::Corrupt);
            }
            if allow_pending_finalization
                && connection
                    .query_row(
                        "SELECT ready FROM history_registry WHERE singleton = 1",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .map_err(|_| HistoryError::Corrupt)?
                    == 0
            {
                return validate_current_schema(connection, false);
            }
            validate_current_schema(connection, true)
        }
        _ => Ok(()),
    }
}

const V1_REQUIRED_COLUMNS: &[(&str, &[&str])] = &[(
    "jobs",
    &[
        "job_id",
        "parent_job_id",
        "kind",
        "submission_kind",
        "source",
        "source_provenance",
        "destination",
        "workspace",
        "state",
        "admitted_at",
        "started_at",
        "terminal_at",
        "outcome",
        "failure_code",
        "cleanup_warning_code",
    ],
)];

const V2_REQUIRED_TABLES: &[&str] = &["jobs", "job_items", "job_artifacts"];
const V2_REQUIRED_COLUMNS: &[(&str, &[&str])] = &[
    (
        "jobs",
        &[
            "job_id",
            "parent_job_id",
            "kind",
            "submission_kind",
            "source",
            "invocation_cwd",
            "source_provenance",
            "destination",
            "destination_selection",
            "workspace",
            "workspace_selection",
            "conflict_policy",
            "conflict_policy_provenance",
            "parent_conflict_policy",
            "parent_conflict_policy_provenance",
            "retry_scope",
            "state",
            "admitted_at",
            "started_at",
            "terminal_at",
            "outcome",
            "failure_code",
            "cleanup_warning_code",
            "publication_state",
            "pruneable",
            "required_providers_json",
            "required_keys_json",
            "result_json",
            "snapshot_json",
        ],
    ),
    (
        "job_items",
        &[
            "job_id",
            "ordinal",
            "item_key",
            "kind",
            "source",
            "destination",
            "state",
            "outcome",
            "failure_code",
            "evidence_json",
        ],
    ),
    (
        "job_artifacts",
        &[
            "job_id",
            "ordinal",
            "role",
            "path",
            "retained",
            "identity_known",
            "content_known",
            "evidence_json",
        ],
    ),
];

const V3_REQUIRED_COLUMNS: &[(&str, &[&str])] = &[
    (
        "jobs",
        &[
            "job_id",
            "parent_job_id",
            "kind",
            "submission_kind",
            "source",
            "invocation_cwd",
            "source_provenance",
            "destination",
            "destination_selection",
            "workspace",
            "workspace_selection",
            "conflict_policy",
            "conflict_policy_provenance",
            "parent_conflict_policy",
            "parent_conflict_policy_provenance",
            "retry_scope",
            "state",
            "admitted_at",
            "started_at",
            "terminal_at",
            "outcome",
            "failure_code",
            "cleanup_warning_code",
            "publication_state",
            "pruneable",
            "required_providers_json",
            "required_keys_json",
            "result_json",
            "snapshot_json",
            "lease_slot_id",
        ],
    ),
    V2_REQUIRED_COLUMNS[1],
    V2_REQUIRED_COLUMNS[2],
    ("lease_slots", &["slot_id", "slot_key", "ordinal"]),
    (
        "job_lease_claims",
        &[
            "claim_id",
            "job_id",
            "slot_id",
            "claim_token",
            "state",
            "created_at",
            "resolved_at",
        ],
    ),
    ("history_registry", &["singleton", "ready"]),
];

const V3_REQUIRED_TABLES: &[&str] = &[
    "jobs",
    "job_items",
    "job_artifacts",
    "lease_slots",
    "job_lease_claims",
    "history_registry",
];

const V4_REQUIRED_COLUMNS: &[(&str, &[&str])] = &[
    V3_REQUIRED_COLUMNS[0],
    (
        "job_items",
        &[
            "job_id",
            "ordinal",
            "item_key",
            "kind",
            "source",
            "destination",
            "destination_assigned",
            "state",
            "outcome",
            "failure_code",
            "evidence_json",
            "provenance_json",
        ],
    ),
    (
        "job_artifacts",
        &[
            "job_id",
            "item_key",
            "ordinal",
            "role",
            "path",
            "retained",
            "identity_known",
            "content_known",
            "evidence_json",
        ],
    ),
    V3_REQUIRED_COLUMNS[3],
    V3_REQUIRED_COLUMNS[4],
    V3_REQUIRED_COLUMNS[5],
    (
        "batch_intents",
        &["job_id", "schema_version", "kind", "intent_json"],
    ),
    (
        "batch_source_intents",
        &["job_id", "schema_version", "kind", "intent_json"],
    ),
    (
        "batch_item_checkpoints",
        &[
            "job_id",
            "item_key",
            "sequence",
            "item_state",
            "outcome",
            "failure_code",
            "publication_state",
            "evidence_json",
            "recorded_at",
        ],
    ),
];

#[derive(Clone, Copy)]
struct RequiredColumnDefinition {
    table: &'static str,
    column: &'static str,
    declared_type: &'static str,
    not_null: bool,
    default_value: Option<&'static str>,
}

const V4_REQUIRED_COLUMN_DEFINITIONS: &[RequiredColumnDefinition] = &[
    RequiredColumnDefinition {
        table: "job_items",
        column: "destination",
        declared_type: "TEXT",
        not_null: true,
        default_value: None,
    },
    RequiredColumnDefinition {
        table: "job_items",
        column: "destination_assigned",
        declared_type: "INTEGER",
        not_null: true,
        default_value: Some("1"),
    },
];

const V4_REQUIRED_TABLES: &[&str] = &[
    "jobs",
    "job_items",
    "job_artifacts",
    "lease_slots",
    "job_lease_claims",
    "history_registry",
    "batch_intents",
    "batch_source_intents",
    "batch_item_checkpoints",
];

fn validate_v3_schema(connection: &Connection, allow_finalized: bool) -> Result<(), HistoryError> {
    validate_required_columns(connection, V3_REQUIRED_TABLES, V3_REQUIRED_COLUMNS)?;
    if allow_finalized {
        validate_registry_row(connection).map(|_| ())
    } else {
        validate_registry_ready(connection, false)
    }
}

fn validate_current_schema(
    connection: &Connection,
    require_ready: bool,
) -> Result<(), HistoryError> {
    validate_required_columns(connection, V4_REQUIRED_TABLES, V4_REQUIRED_COLUMNS)?;
    validate_registry_ready(connection, require_ready)?;
    validate_v4_integrity(connection)
}

fn validate_registry_ready(
    connection: &Connection,
    require_ready: bool,
) -> Result<(), HistoryError> {
    let registry_state = validate_registry_row(connection)?;
    if (require_ready && registry_state != 1) || (!require_ready && registry_state != 0) {
        return Err(HistoryError::Corrupt);
    }
    Ok(())
}

fn validate_registry_row(connection: &Connection) -> Result<i64, HistoryError> {
    let registry_state = connection
        .query_row(
            "SELECT ready FROM history_registry WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| HistoryError::Corrupt)?;
    let registry_rows = connection
        .query_row("SELECT COUNT(*) FROM history_registry", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|_| HistoryError::Corrupt)?;
    if registry_rows != 1 || !matches!(registry_state, 0 | 1) {
        return Err(HistoryError::Corrupt);
    }
    Ok(registry_state)
}

fn validate_required_columns(
    connection: &Connection,
    required_tables: &[&str],
    required_columns: &[(&str, &[&str])],
) -> Result<(), HistoryError> {
    for table in required_tables {
        if !database_has_table(connection, table)? {
            return Err(HistoryError::Corrupt);
        }
    }
    for (table, required) in required_columns {
        let columns = table_columns(connection, table)?;
        if required
            .iter()
            .any(|column| !columns.iter().any(|found| found == column))
        {
            return Err(HistoryError::Corrupt);
        }
    }
    Ok(())
}

const V4_REQUIRED_INDEXES: &[(&str, &str)] = &[
    (
        "job_artifacts_item_owner",
        "CREATE INDEX job_artifacts_item_owner ON job_artifacts(job_id, item_key)",
    ),
    (
        "jobs_history_order",
        "CREATE INDEX jobs_history_order ON jobs(state, terminal_at DESC, admitted_at DESC, job_id DESC)",
    ),
    (
        "jobs_parent",
        "CREATE INDEX jobs_parent ON jobs(parent_job_id)",
    ),
    (
        "job_lease_claims_blocking_slot",
        "CREATE UNIQUE INDEX job_lease_claims_blocking_slot ON job_lease_claims(slot_id) WHERE state != 'released'",
    ),
    (
        "jobs_lease_slot",
        "CREATE INDEX jobs_lease_slot ON jobs(lease_slot_id)",
    ),
];

const V4_REQUIRED_TRIGGERS: &[(&str, &str)] = &[
    (
        "independent_batch_intent_on_terminal",
        "CREATE TRIGGER independent_batch_intent_on_terminal BEFORE UPDATE OF state ON jobs WHEN NEW.submission_kind = 'independent_batch' AND NEW.state IN ('succeeded', 'completed_with_issues', 'failed', 'cancelled') AND NOT EXISTS (SELECT 1 FROM batch_intents WHERE job_id = NEW.job_id) BEGIN SELECT RAISE(ABORT, 'independent batch intent missing'); END",
    ),
    (
        "batch_intent_owner_on_insert",
        "CREATE TRIGGER batch_intent_owner_on_insert BEFORE INSERT ON batch_intents WHEN NOT EXISTS (SELECT 1 FROM jobs WHERE job_id = NEW.job_id AND submission_kind = 'independent_batch') BEGIN SELECT RAISE(ABORT, 'batch intent owner is not an independent batch'); END",
    ),
    (
        "batch_intent_owner_on_update",
        "CREATE TRIGGER batch_intent_owner_on_update BEFORE UPDATE OF job_id ON batch_intents WHEN NOT EXISTS (SELECT 1 FROM jobs WHERE job_id = NEW.job_id AND submission_kind = 'independent_batch') BEGIN SELECT RAISE(ABORT, 'batch intent owner is not an independent batch'); END",
    ),
    (
        "job_batch_intent_owner_on_update",
        "CREATE TRIGGER job_batch_intent_owner_on_update BEFORE UPDATE OF submission_kind ON jobs WHEN NEW.submission_kind = 'single' AND (EXISTS (SELECT 1 FROM batch_intents WHERE job_id = NEW.job_id) OR EXISTS (SELECT 1 FROM batch_source_intents WHERE job_id = NEW.job_id)) BEGIN SELECT RAISE(ABORT, 'single job cannot own a batch intent'); END",
    ),
    (
        "independent_batch_source_intent_on_terminal",
        "CREATE TRIGGER independent_batch_source_intent_on_terminal BEFORE UPDATE OF state ON jobs WHEN NEW.submission_kind = 'independent_batch' AND NEW.state IN ('succeeded', 'completed_with_issues', 'failed', 'cancelled') AND NOT EXISTS (SELECT 1 FROM batch_source_intents WHERE job_id = NEW.job_id) BEGIN SELECT RAISE(ABORT, 'independent batch source intent missing'); END",
    ),
    (
        "batch_source_intent_owner_on_insert",
        "CREATE TRIGGER batch_source_intent_owner_on_insert BEFORE INSERT ON batch_source_intents WHEN NOT EXISTS (SELECT 1 FROM jobs WHERE job_id = NEW.job_id AND submission_kind = 'independent_batch') BEGIN SELECT RAISE(ABORT, 'batch source intent owner is not an independent batch'); END",
    ),
    (
        "batch_source_intent_owner_on_update",
        "CREATE TRIGGER batch_source_intent_owner_on_update BEFORE UPDATE OF job_id ON batch_source_intents WHEN NOT EXISTS (SELECT 1 FROM jobs WHERE job_id = NEW.job_id AND submission_kind = 'independent_batch') BEGIN SELECT RAISE(ABORT, 'batch source intent owner is not an independent batch'); END",
    ),
    (
        "batch_artifact_owner_on_insert",
        "CREATE TRIGGER batch_artifact_owner_on_insert BEFORE INSERT ON job_artifacts WHEN (NEW.item_key IS NULL AND COALESCE((SELECT submission_kind FROM jobs WHERE job_id = NEW.job_id), '') = 'independent_batch') OR (NEW.item_key IS NOT NULL AND COALESCE((SELECT submission_kind FROM jobs WHERE job_id = NEW.job_id), '') != 'independent_batch') BEGIN SELECT RAISE(ABORT, 'artifact owner does not match the Job submission kind'); END",
    ),
    (
        "batch_artifact_owner_on_update",
        "CREATE TRIGGER batch_artifact_owner_on_update BEFORE UPDATE OF job_id, item_key ON job_artifacts WHEN (NEW.item_key IS NULL AND COALESCE((SELECT submission_kind FROM jobs WHERE job_id = NEW.job_id), '') = 'independent_batch') OR (NEW.item_key IS NOT NULL AND COALESCE((SELECT submission_kind FROM jobs WHERE job_id = NEW.job_id), '') != 'independent_batch') BEGIN SELECT RAISE(ABORT, 'artifact owner does not match the Job submission kind'); END",
    ),
];

const V4_REQUIRED_CHECKS: &[(&str, &str)] = &[
    (
        "jobs",
        "( (submission_kind = 'single' and source is not null) or (submission_kind = 'independent_batch' and source is null) )",
    ),
    (
        "job_items",
        "( (destination_assigned = 1 AND length(destination) > 0) OR (destination_assigned = 0 AND destination = '') )",
    ),
    ("batch_intents", "(schema_version = 1)"),
    ("batch_intents", "(kind = 'nscb.copy_batch_intent')"),
    ("batch_intents", "(length(intent_json) > 0)"),
    ("batch_source_intents", "(schema_version = 1)"),
    (
        "batch_source_intents",
        "(kind IN ('nscb.copy_batch_sources', 'nscb.legacy_unqualified_batch_sources'))",
    ),
    ("batch_source_intents", "(length(intent_json) > 0)"),
    ("batch_item_checkpoints", "(sequence >= 0)"),
    (
        "batch_item_checkpoints",
        "(item_state in ('preflight_failed', 'succeeded', 'skipped', 'failed', 'uncertain', 'cancelled', 'not_started'))",
    ),
    (
        "batch_item_checkpoints",
        "(publication_state in ('not_completed', 'completed', 'published_unresolved', 'uncertain', 'unknown'))",
    ),
    ("batch_item_checkpoints", "(length(evidence_json) > 0)"),
    (
        "job_lease_claims",
        "(state in ('outstanding', 'released', 'unresolved'))",
    ),
    (
        "job_lease_claims",
        "( (state = 'outstanding' and resolved_at is null) or (state in ('released', 'unresolved') and resolved_at is not null) )",
    ),
    ("history_registry", "(singleton = 1)"),
    ("history_registry", "(ready in (0, 1))"),
];

struct ForeignKeyRequirement {
    child: &'static str,
    parent: &'static str,
    columns: &'static [&'static str],
    parent_columns: &'static [&'static str],
    on_delete: &'static str,
}

const V4_REQUIRED_FOREIGN_KEYS: &[ForeignKeyRequirement] = &[
    ForeignKeyRequirement {
        child: "job_items",
        parent: "jobs",
        columns: &["job_id"],
        parent_columns: &["job_id"],
        on_delete: "CASCADE",
    },
    ForeignKeyRequirement {
        child: "job_artifacts",
        parent: "jobs",
        columns: &["job_id"],
        parent_columns: &["job_id"],
        on_delete: "CASCADE",
    },
    ForeignKeyRequirement {
        child: "job_artifacts",
        parent: "job_items",
        columns: &["job_id", "item_key"],
        parent_columns: &["job_id", "item_key"],
        on_delete: "CASCADE",
    },
    ForeignKeyRequirement {
        child: "batch_intents",
        parent: "jobs",
        columns: &["job_id"],
        parent_columns: &["job_id"],
        on_delete: "CASCADE",
    },
    ForeignKeyRequirement {
        child: "batch_source_intents",
        parent: "jobs",
        columns: &["job_id"],
        parent_columns: &["job_id"],
        on_delete: "CASCADE",
    },
    ForeignKeyRequirement {
        child: "batch_item_checkpoints",
        parent: "job_items",
        columns: &["job_id", "item_key"],
        parent_columns: &["job_id", "item_key"],
        on_delete: "CASCADE",
    },
    ForeignKeyRequirement {
        child: "job_lease_claims",
        parent: "jobs",
        columns: &["job_id"],
        parent_columns: &["job_id"],
        on_delete: "CASCADE",
    },
    ForeignKeyRequirement {
        child: "job_lease_claims",
        parent: "lease_slots",
        columns: &["slot_id"],
        parent_columns: &["slot_id"],
        on_delete: "NO ACTION",
    },
    ForeignKeyRequirement {
        child: "jobs",
        parent: "lease_slots",
        columns: &["lease_slot_id"],
        parent_columns: &["slot_id"],
        on_delete: "NO ACTION",
    },
];

fn validate_v4_integrity(connection: &Connection) -> Result<(), HistoryError> {
    validate_required_column_definitions(connection, V4_REQUIRED_COLUMN_DEFINITIONS)?;
    validate_required_sqlite_definitions(connection, "index", V4_REQUIRED_INDEXES)?;
    validate_required_sqlite_definitions(connection, "trigger", V4_REQUIRED_TRIGGERS)?;
    validate_required_constraints(connection)?;
    validate_required_foreign_keys(connection)?;
    validate_foreign_key_integrity(connection)
}

fn validate_required_column_definitions(
    connection: &Connection,
    required: &[RequiredColumnDefinition],
) -> Result<(), HistoryError> {
    for requirement in required {
        let mut statement = connection
            .prepare(&format!(
                "PRAGMA table_info(\"{}\")",
                requirement.table.replace('"', "\"\"")
            ))
            .map_err(|_| HistoryError::Corrupt)?;
        let columns = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })
            .map_err(|_| HistoryError::Corrupt)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| HistoryError::Corrupt)?;
        let Some((_, declared_type, not_null, default_value)) = columns
            .into_iter()
            .find(|(column, _, _, _)| column == requirement.column)
        else {
            return Err(HistoryError::Corrupt);
        };
        if !declared_type.eq_ignore_ascii_case(requirement.declared_type)
            || (not_null != 0) != requirement.not_null
            || default_value.as_deref() != requirement.default_value
        {
            return Err(HistoryError::Corrupt);
        }
    }
    Ok(())
}

fn validate_required_sqlite_definitions(
    connection: &Connection,
    object_type: &str,
    required: &[(&str, &str)],
) -> Result<(), HistoryError> {
    for (name, expected) in required {
        let definition = connection
            .query_row(
                "SELECT COALESCE(sql, '') FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                rusqlite::params![object_type, name],
                |row| row.get::<_, String>(0),
            )
            .map_err(|_| HistoryError::Corrupt)?;
        if normalize_sql_definition(&definition) != normalize_sql_definition(expected) {
            return Err(HistoryError::Corrupt);
        }
    }
    Ok(())
}

fn validate_required_constraints(connection: &Connection) -> Result<(), HistoryError> {
    for (table, expression) in V4_REQUIRED_CHECKS {
        let sql = connection
            .query_row(
                "SELECT COALESCE(sql, '') FROM sqlite_schema
                 WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get::<_, String>(0),
            )
            .map_err(|_| HistoryError::Corrupt)?;
        let expected = tokenize_sql_expression(expression).ok_or(HistoryError::Corrupt)?;
        let checks = table_check_expressions(&sql).ok_or(HistoryError::Corrupt)?;
        if !checks.iter().any(|actual| actual == &expected) {
            return Err(HistoryError::Corrupt);
        }
    }
    Ok(())
}

fn normalize_sql_definition(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
        .replace("( ", "(")
        .replace(" )", ")")
        .replace(", ", ",")
        .trim_end_matches(';')
        .to_owned()
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SqlToken {
    Word(String),
    QuotedIdentifier(String),
    StringLiteral(String),
    Symbol(char),
}

fn tokenize_sql_expression(sql: &str) -> Option<Vec<SqlToken>> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            byte if byte.is_ascii_whitespace() => index += 1,
            b'-' if bytes.get(index + 1) == Some(&b'-') => {
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                loop {
                    if index + 1 >= bytes.len() {
                        return None;
                    }
                    if bytes[index] == b'*' && bytes[index + 1] == b'/' {
                        index += 2;
                        break;
                    }
                    index += 1;
                }
            }
            quote @ (b'\'' | b'"' | b'`' | b'[') => {
                let closing = if quote == b'[' { b']' } else { quote };
                let start = index + 1;
                index = start;
                loop {
                    if index >= bytes.len() {
                        return None;
                    }
                    if bytes[index] == closing {
                        if bytes.get(index + 1) == Some(&closing) {
                            index += 2;
                            continue;
                        }
                        break;
                    }
                    index += 1;
                }
                let raw = String::from_utf8_lossy(&bytes[start..index]).into_owned();
                tokens.push(if quote == b'\'' {
                    SqlToken::StringLiteral(raw)
                } else {
                    SqlToken::QuotedIdentifier(raw.to_ascii_lowercase())
                });
                index += 1;
            }
            byte if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$') => {
                let start = index;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'$'))
                {
                    index += 1;
                }
                tokens.push(SqlToken::Word(
                    String::from_utf8_lossy(&bytes[start..index]).to_ascii_lowercase(),
                ));
            }
            byte => {
                tokens.push(SqlToken::Symbol(char::from(byte)));
                index += 1;
            }
        }
    }
    Some(tokens)
}

fn table_check_expressions(sql: &str) -> Option<Vec<Vec<SqlToken>>> {
    let tokens = tokenize_sql_expression(sql)?;
    let mut checks = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if tokens[index] == SqlToken::Word("check".to_owned())
            && matches!(tokens.get(index + 1), Some(SqlToken::Symbol('(')))
        {
            let start = index + 1;
            let mut depth = 0usize;
            let mut end = None;
            for (offset, token) in tokens[start..].iter().enumerate() {
                match token {
                    SqlToken::Symbol('(') => depth += 1,
                    SqlToken::Symbol(')') => {
                        depth = depth.checked_sub(1)?;
                        if depth == 0 {
                            end = Some(start + offset);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let end = end?;
            checks.push(tokens[start..=end].to_vec());
            index = end + 1;
        } else {
            index += 1;
        }
    }
    Some(checks)
}

fn validate_required_foreign_keys(connection: &Connection) -> Result<(), HistoryError> {
    type ForeignKeyColumn = (i64, String, Option<String>);
    type GroupedForeignKey = (String, Vec<ForeignKeyColumn>, String);

    for requirement in V4_REQUIRED_FOREIGN_KEYS {
        let mut statement = connection
            .prepare(&format!(
                "PRAGMA foreign_key_list(\"{}\")",
                requirement.child.replace('"', "\"\"")
            ))
            .map_err(|_| HistoryError::Corrupt)?;
        let definitions = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(6)?,
                ))
            })
            .map_err(|_| HistoryError::Corrupt)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| HistoryError::Corrupt)?;
        let mut grouped: HashMap<i64, GroupedForeignKey> = HashMap::new();
        for (id, sequence, parent, child_column, parent_column, on_delete) in definitions {
            grouped
                .entry(id)
                .or_insert_with(|| (parent, Vec::new(), on_delete))
                .1
                .push((sequence, child_column, parent_column));
        }
        let found = grouped.values().any(|(parent, columns, on_delete)| {
            let mut columns = columns.clone();
            columns.sort_by_key(|(sequence, _, _)| *sequence);
            parent == requirement.parent
                && on_delete.eq_ignore_ascii_case(requirement.on_delete)
                && columns.len() == requirement.columns.len()
                && columns
                    .iter()
                    .zip(requirement.columns)
                    .all(|((_, child, _), expected)| child == expected)
                && columns.iter().zip(requirement.parent_columns).all(
                    |((_, _, parent_column), expected)| parent_column.as_deref() == Some(*expected),
                )
        });
        if !found {
            return Err(HistoryError::Corrupt);
        }
    }
    Ok(())
}

fn validate_foreign_key_integrity(connection: &Connection) -> Result<(), HistoryError> {
    let mut statement = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|_| HistoryError::Corrupt)?;
    let mut rows = statement.query([]).map_err(|_| HistoryError::Corrupt)?;
    if rows.next().map_err(|_| HistoryError::Corrupt)?.is_some() {
        return Err(HistoryError::Corrupt);
    }
    Ok(())
}

fn table_columns(connection: &Connection, table: &str) -> Result<Vec<String>, HistoryError> {
    let mut statement = connection
        .prepare(&format!(
            "PRAGMA table_info(\"{}\")",
            table.replace('"', "\"\"")
        ))
        .map_err(|_| HistoryError::Corrupt)?;
    statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|_| HistoryError::Corrupt)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| HistoryError::Corrupt)
}

pub(crate) fn database_has_table(
    connection: &Connection,
    table: &str,
) -> Result<bool, HistoryError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            [table],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| HistoryError::Corrupt)
}

pub(crate) fn mark_registry_ready(connection: &mut Connection) -> Result<(), HistoryError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| HistoryError::MigrationFailed)?;
    if transaction
        .execute(
            "UPDATE history_registry SET ready = 1 WHERE singleton = 1",
            [],
        )
        .map_err(|_| HistoryError::MigrationFailed)?
        != 1
    {
        return Err(HistoryError::Corrupt);
    }
    transaction
        .execute_batch(&format!("PRAGMA user_version = {CURRENT_SCHEMA_VERSION}"))
        .map_err(|_| HistoryError::MigrationFailed)?;
    transaction
        .commit()
        .map_err(|_| HistoryError::MigrationFailed)
}

pub(crate) fn map_open_error(error: rusqlite::Error) -> HistoryError {
    if error.sqlite_error_code().is_some_and(|code| {
        matches!(
            code,
            rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase
        )
    }) {
        HistoryError::Corrupt
    } else {
        HistoryError::OpenFailed
    }
}

pub(crate) fn database_has_tables(connection: &Connection) -> Result<bool, HistoryError> {
    let count = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| HistoryError::Corrupt)?;
    Ok(count != 0)
}

pub(crate) fn path_text(path: &Path) -> Result<&str, HistoryError> {
    path.to_str().ok_or(HistoryError::PathUnrepresentable)
}

/// Resolves directory aliases before SQLite opens the database by pathname.
/// Unix preflight and lock operations use descriptor-relative no-follow opens,
/// but SQLite's pathname-based open does not pin the parent directory; its
/// no-follow flag protects the database file component only.
pub(crate) fn canonical_file_path(path: &Path) -> Result<PathBuf, HistoryError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or(HistoryError::DirectoryUnavailable)?;
    Ok(fs::canonicalize(parent)
        .map_err(|_| HistoryError::DirectoryUnavailable)?
        .join(file_name))
}

#[cfg(all(unix, test))]
pub(super) fn open_directory_components(path: &Path) -> Result<File, HistoryError> {
    open_directory_components_io(path).map_err(|_| HistoryError::DirectoryUnavailable)
}

#[cfg(unix)]
fn open_directory_components_io(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory path must be absolute",
        ));
    }

    let mut directory = File::open("/")?;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                directory = open_directory_at(&directory, std::ffi::OsStr::new(".."))?;
            }
            Component::Normal(name) => {
                directory = open_directory_at(&directory, name)?;
            }
            Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "directory path has an unsupported prefix",
                ));
            }
        }
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_directory_at(parent: &File, name: &std::ffi::OsStr) -> io::Result<File> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn open_file_at(
    parent: &File,
    name: &std::ffi::OsStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> io::Result<File> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode as libc::c_uint,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn open_parent_directory(path: &Path) -> io::Result<File> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    open_existing_directory(parent)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "unsafe parent directory"))
}

#[cfg(unix)]
fn open_private_path_file(path: &Path, flags: libc::c_int, mode: libc::mode_t) -> io::Result<File> {
    let parent = open_parent_directory(path)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing file name"))?;
    open_file_at(&parent, file_name, flags, mode)
}

#[cfg(unix)]
fn open_existing_regular_file(path: &Path) -> io::Result<File> {
    let file = open_private_path_file(path, libc::O_RDONLY, 0)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "history path is not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(unix)]
pub(super) fn open_private_lock_file_at(
    parent: &File,
    file_name: &std::ffi::OsStr,
    create: bool,
) -> Result<File, HistoryError> {
    let flags = libc::O_RDWR | if create { libc::O_CREAT } else { 0 };
    let file =
        open_file_at(parent, file_name, flags, 0o600).map_err(|_| HistoryError::LockFailed)?;
    let metadata = file.metadata().map_err(|_| HistoryError::LockFailed)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(HistoryError::LockFailed);
    }
    set_private_open_file_permissions(&file).map_err(|_| HistoryError::LockFailed)?;
    Ok(file)
}

/// Creates a history directory when absent and secures directories created by
/// this function.
///
/// Existing directories belong to the caller and are validated without having
/// their permissions changed. This distinction prevents NSCB from tightening a
/// data root or other parent selected by the operating system, an embedding
/// host, or a user even though NSCB creates its own leaf beneath that parent.
pub(crate) fn ensure_private_directory(path: &Path) -> Result<(), HistoryError> {
    #[cfg(unix)]
    {
        ensure_private_directory_unix(path)
    }
    #[cfg(not(unix))]
    {
        ensure_private_directory_portable(path)
    }
}

#[cfg(unix)]
fn ensure_private_directory_unix(path: &Path) -> Result<(), HistoryError> {
    let _directory = open_or_create_private_directory(path)?;
    Ok(())
}

#[cfg(unix)]
fn open_or_create_private_directory(path: &Path) -> Result<File, HistoryError> {
    if path.file_name().is_none() {
        let canonical = fs::canonicalize(path).map_err(|_| HistoryError::DirectoryUnavailable)?;
        let directory = open_directory_components_io(&canonical)
            .map_err(|_| HistoryError::DirectoryUnavailable)?;
        validate_directory_metadata(
            &directory
                .metadata()
                .map_err(|_| HistoryError::DirectoryUnavailable)?,
        )?;
        return Ok(directory);
    }

    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_directory_metadata(&metadata)?;
            return open_existing_directory(path);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(HistoryError::DirectoryUnavailable),
    }

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_directory = open_or_create_private_directory(parent)?;
    let file_name = path.file_name().ok_or(HistoryError::DirectoryUnavailable)?;
    let name =
        CString::new(file_name.as_bytes()).map_err(|_| HistoryError::DirectoryUnavailable)?;
    let created = unsafe { libc::mkdirat(parent_directory.as_raw_fd(), name.as_ptr(), 0o700) };
    let created = if created == 0 {
        true
    } else if io::Error::last_os_error().kind() == io::ErrorKind::AlreadyExists {
        false
    } else {
        return Err(HistoryError::DirectoryUnavailable);
    };

    let directory = open_directory_at(&parent_directory, file_name)
        .map_err(|_| HistoryError::DirectoryUnavailable)?;
    validate_directory_metadata(
        &directory
            .metadata()
            .map_err(|_| HistoryError::DirectoryUnavailable)?,
    )?;
    if created {
        use std::os::unix::fs::PermissionsExt;
        directory
            .set_permissions(fs::Permissions::from_mode(0o700))
            .map_err(|_| HistoryError::DirectoryUnavailable)?;
        parent_directory
            .sync_all()
            .map_err(|_| HistoryError::DirectoryUnavailable)?;
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_existing_directory(path: &Path) -> Result<File, HistoryError> {
    if path.file_name().is_none() {
        let canonical = fs::canonicalize(path).map_err(|_| HistoryError::DirectoryUnavailable)?;
        let directory = open_directory_components_io(&canonical)
            .map_err(|_| HistoryError::DirectoryUnavailable)?;
        validate_directory_metadata(
            &directory
                .metadata()
                .map_err(|_| HistoryError::DirectoryUnavailable)?,
        )?;
        return Ok(directory);
    }

    let metadata = fs::symlink_metadata(path).map_err(|_| HistoryError::DirectoryUnavailable)?;
    validate_directory_metadata(&metadata)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_parent =
        fs::canonicalize(parent).map_err(|_| HistoryError::DirectoryUnavailable)?;
    let parent_directory = open_directory_components_io(&canonical_parent)
        .map_err(|_| HistoryError::DirectoryUnavailable)?;
    let file_name = path.file_name().ok_or(HistoryError::DirectoryUnavailable)?;
    let directory = open_directory_at(&parent_directory, file_name)
        .map_err(|_| HistoryError::DirectoryUnavailable)?;
    validate_directory_metadata(
        &directory
            .metadata()
            .map_err(|_| HistoryError::DirectoryUnavailable)?,
    )?;
    Ok(directory)
}

#[cfg(not(unix))]
fn ensure_private_directory_portable(path: &Path) -> Result<(), HistoryError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => return validate_directory_metadata(&metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(HistoryError::DirectoryUnavailable),
    }

    let parent = path.parent().ok_or(HistoryError::DirectoryUnavailable)?;
    if parent != path {
        ensure_private_directory(parent)?;
    }
    match fs::create_dir(path) {
        Ok(()) => match set_private_directory_permissions(path) {
            Ok(()) => sync_parent_directory_after_directory_creation(path)
                .map_err(|_| HistoryError::DirectoryUnavailable),
            Err(_) => {
                let _ = fs::remove_dir(path);
                Err(HistoryError::DirectoryUnavailable)
            }
        },
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata =
                fs::symlink_metadata(path).map_err(|_| HistoryError::DirectoryUnavailable)?;
            validate_directory_metadata(&metadata)
        }
        Err(_) => Err(HistoryError::DirectoryUnavailable),
    }
}

#[cfg(not(unix))]
/// Preserves portable directory creation behavior outside Unix targets.
fn sync_parent_directory_after_directory_creation(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Flushes an existing recovery backup file before it is reused.
#[cfg(unix)]
fn sync_existing_backup_contents(path: &Path) -> io::Result<()> {
    open_existing_regular_file(path)?.sync_all()
}

/// Flushes an existing recovery backup file before it is reused.
#[cfg(not(unix))]
fn sync_existing_backup_contents(path: &Path) -> io::Result<()> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?
        .sync_all()
}

/// Flushes the directory entry that publishes a recovery backup on Unix.
#[cfg(unix)]
fn sync_parent_directory_durably(path: &Path) -> io::Result<ParentDirectorySyncOutcome> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing parent"))?;
    File::open(parent)?.sync_all()?;
    Ok(ParentDirectorySyncOutcome::Synced)
}

/// Reports the unavailable power-loss barrier on targets without portable directory syncing.
///
/// The backup file itself is synced before this result is handled. Process-crash
/// recovery remains transactional; containing-directory/device power-loss
/// durability is unqualified on these targets.
#[cfg(not(unix))]
fn sync_parent_directory_durably(_path: &Path) -> io::Result<ParentDirectorySyncOutcome> {
    Ok(ParentDirectorySyncOutcome::Unsupported)
}

fn validate_directory_metadata(metadata: &fs::Metadata) -> Result<(), HistoryError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(HistoryError::DirectoryUnavailable);
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory_permissions(path: &Path) -> io::Result<()> {
    let _ = path;
    Ok(())
}

pub(crate) fn prepare_private_database_file(path: &Path) -> Result<(), HistoryError> {
    #[cfg(unix)]
    let file = open_private_path_file(path, libc::O_RDWR | libc::O_CREAT, 0o600)
        .map_err(|_| HistoryError::OpenFailed)?;
    #[cfg(not(unix))]
    let file = {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(
                windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
            );
        }
        options.open(path).map_err(|_| HistoryError::OpenFailed)?
    };
    let metadata = file.metadata().map_err(|_| HistoryError::OpenFailed)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(HistoryError::OpenFailed);
    }
    set_private_open_file_permissions(&file).map_err(|_| HistoryError::OpenFailed)?;
    file.sync_all().map_err(|_| HistoryError::OpenFailed)?;
    Ok(())
}

pub(crate) fn open_private_lock_file(path: &Path) -> Result<File, HistoryError> {
    open_private_lock_file_inner(path, true)
}

fn open_existing_private_lock_file(path: &Path) -> Result<File, HistoryError> {
    open_private_lock_file_inner(path, false)
}

fn open_private_lock_file_inner(path: &Path, create: bool) -> Result<File, HistoryError> {
    #[cfg(unix)]
    let file = {
        let parent = open_parent_directory(path).map_err(|_| HistoryError::LockFailed)?;
        let file_name = path.file_name().ok_or(HistoryError::LockFailed)?;
        open_private_lock_file_at(&parent, file_name, create)?
    };
    #[cfg(not(unix))]
    let file = {
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        if create {
            options.create(true);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(
                windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
            );
        }
        let file = options.open(path).map_err(|_| HistoryError::LockFailed)?;
        let metadata = file.metadata().map_err(|_| HistoryError::LockFailed)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(HistoryError::LockFailed);
        }
        set_private_open_file_permissions(&file).map_err(|_| HistoryError::LockFailed)?;
        file
    };
    Ok(file)
}

fn set_private_open_file_permissions(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    let _ = file;
    Ok(())
}
