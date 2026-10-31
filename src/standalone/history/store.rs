//! Durable Job admission, query, completion, retention, and recovery operations.

use super::lease::{
    JobLease, SlotReservation, acquire_available_slot, acquire_initialization_lock,
    initialize_slot_files, try_acquire_existing_claim,
};
use super::model::*;
use super::storage::{
    canonical_file_path, create_schema, database_has_table, database_has_tables,
    ensure_private_directory, map_open_error, mark_registry_ready, migrate_v1_to_v2,
    migrate_v2_to_v3, path_text, prepare_private_database_file, verify_database_health,
};
use super::{APPLICATION_ID, BUSY_TIMEOUT_MILLIS, CURRENT_SCHEMA_VERSION, RETENTION_LIMIT};
use crate::standalone::paths;
use nscb::{OperationArtifactRole, OperationCompletion, OperationFailureCode};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) struct HistoryStore {
    path: PathBuf,
    pub(crate) connection: Connection,
}

impl HistoryStore {
    pub(crate) fn open_default() -> Result<Self, HistoryError> {
        let path = paths::history_database_path().map_err(|error| match error {
            paths::StandalonePathError::DataRoot => HistoryError::DirectoryUnavailable,
            _ => HistoryError::DirectoryUnavailable,
        })?;
        Self::open_path(&path)
    }

    #[cfg(test)]
    pub(crate) fn open_at(path: impl AsRef<Path>) -> Result<Self, HistoryError> {
        Self::open_path(path.as_ref())
    }

    fn open_path(path: &Path) -> Result<Self, HistoryError> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        ensure_private_directory(parent)?;
        let resolved_path = canonical_file_path(path)?;
        let _initialization_lock = acquire_initialization_lock(&resolved_path)?;
        prepare_private_database_file(&resolved_path)?;
        let connection = Connection::open_with_flags(
            &resolved_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| HistoryError::OpenFailed)?;
        connection
            .busy_timeout(std::time::Duration::from_millis(BUSY_TIMEOUT_MILLIS))
            .map_err(|_| HistoryError::OpenFailed)?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;\n\
                 PRAGMA journal_mode = WAL;\n\
                 PRAGMA synchronous = FULL;\n\
                 PRAGMA trusted_schema = OFF;",
            )
            .map_err(map_open_error)?;
        verify_database_health(&connection)?;
        let mut store = Self {
            path: resolved_path,
            connection,
        };
        store.initialize_or_migrate()?;
        Ok(store)
    }

    pub(crate) fn schema_version(&self) -> Result<i64, HistoryError> {
        self.connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|_| HistoryError::QueryFailed)
    }

    fn generate_token(&self) -> Result<String, HistoryError> {
        self.connection
            .query_row("SELECT lower(hex(randomblob(16)))", [], |row| row.get(0))
            .map_err(|_| HistoryError::AdmissionFailed)
    }

    /// Locks an available slot and confirms that SQLite has no blocking claim.
    ///
    /// The slot lock is acquired before any SQLite writer transaction starts.
    /// Because every claim writer and recovery transition holds that same slot
    /// lock, the eligibility result remains stable while this reservation is
    /// held. A durable `released` claim may be reused; `outstanding` and
    /// `unresolved` claims may not.
    fn reserve_admission_slot(&self) -> Result<SlotReservation, HistoryError> {
        let mut excluded = HashSet::new();
        loop {
            let reservation = acquire_available_slot(&self.path, &excluded)?;
            let mapping_count = self
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM lease_slots
                     WHERE slot_id = ?1 AND slot_key = ?2",
                    params![reservation.slot_id(), reservation.slot_key()],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|_| HistoryError::AdmissionFailed)?;
            if mapping_count != 1 {
                excluded.insert(reservation.slot_id().to_owned());
                continue;
            }
            let blocking_claims = self
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM job_lease_claims
                     WHERE slot_id = ?1 AND state != 'released'",
                    [reservation.slot_id()],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|_| HistoryError::AdmissionFailed)?;
            if blocking_claims == 0 {
                let slot_id = reservation.slot_id().to_owned();
                match reservation.transition_legacy_slot_record() {
                    Ok(reservation) => return Ok(reservation),
                    Err(_) => {
                        excluded.insert(slot_id);
                    }
                }
                continue;
            }
            excluded.insert(reservation.slot_id().to_owned());
        }
    }

    pub(crate) fn begin_admission(
        self,
        input: AdmissionInput,
    ) -> Result<PendingAdmission, HistoryError> {
        verify_database_health(&self.connection)?;
        if input.items.is_empty() || !input.invocation_cwd.is_absolute() {
            return Err(HistoryError::AdmissionFailed);
        }
        // Slot acquisition is deliberately outside the SQLite writer
        // transaction. A process can wait for an operating-system slot without
        // holding SQLite's single writer lock.
        let reservation = self.reserve_admission_slot()?;
        let job_id = self.generate_token()?;
        let claim_token = self.generate_token()?;
        self.connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|_| HistoryError::AdmissionFailed)?;
        let kind = input.kind.as_str();
        let submission_kind = input.submission_kind.as_str();
        let destination_selection = input.destination_selection.as_str();
        let workspace_selection = input.workspace_selection.as_str();
        let conflict_policy = input.conflict_policy.as_str();
        let conflict_policy_provenance = input.conflict_policy_provenance.as_str();
        let parent_conflict_policy = input
            .parent_conflict_policy
            .map(ConflictPolicyRecord::as_str);
        let parent_conflict_policy_provenance = input
            .parent_conflict_policy_provenance
            .map(ConflictPolicyProvenance::as_str);
        let retry_scope = input.retry_scope.as_str();
        let required_providers = serde_json::to_string(&input.required_providers)
            .map_err(|_| HistoryError::AdmissionFailed)?;
        let required_keys = serde_json::to_string(&input.required_keys)
            .map_err(|_| HistoryError::AdmissionFailed)?;
        let source = path_text(&input.source)?;
        let invocation_cwd = path_text(&input.invocation_cwd)?;
        let destination = path_text(&input.destination)?;
        let workspace = path_text(&input.workspace)?;
        let insert_result = self.connection.execute(
                "INSERT INTO jobs (\n job_id, parent_job_id, kind, submission_kind, source,\n invocation_cwd, source_provenance, destination, destination_selection,\n workspace, workspace_selection, conflict_policy, conflict_policy_provenance,\n parent_conflict_policy, parent_conflict_policy_provenance, retry_scope,\n state, admitted_at, publication_state, pruneable, required_providers_json,\n required_keys_json, lease_slot_id\n ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'cli_argument', ?7, ?8,\n ?9, ?10, ?11, ?12, ?13, ?14, ?15, 'admitted',\n strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'not_started', 0,\n ?16, ?17, ?18)",
            params![
                job_id,
                input.parent_job_id,
                kind,
                submission_kind,
                source,
                invocation_cwd,
                destination,
                destination_selection,
                workspace,
                workspace_selection,
                conflict_policy,
                conflict_policy_provenance,
                parent_conflict_policy,
                parent_conflict_policy_provenance,
                retry_scope,
                required_providers,
                required_keys,
                reservation.slot_id(),
            ],
        );
        if insert_result.is_err() {
            let _ = self.connection.execute_batch("ROLLBACK");
            return Err(HistoryError::AdmissionFailed);
        }
        for (ordinal, item) in input.items.iter().enumerate() {
            let item_source = match path_text(&item.source) {
                Ok(value) => value,
                Err(error) => {
                    let _ = self.connection.execute_batch("ROLLBACK");
                    return Err(error);
                }
            };
            let item_destination = match path_text(&item.destination) {
                Ok(value) => value,
                Err(error) => {
                    let _ = self.connection.execute_batch("ROLLBACK");
                    return Err(error);
                }
            };
            let result = self.connection.execute(
                "INSERT INTO job_items (\n                    job_id, ordinal, item_key, kind, source, destination, state\n                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'planned')",
                params![
                    job_id,
                    ordinal as i64,
                    item.item_key,
                    kind,
                    item_source,
                    item_destination,
                ],
            );
            if result.is_err() {
                let _ = self.connection.execute_batch("ROLLBACK");
                return Err(HistoryError::AdmissionFailed);
            }
        }
        let claim = self.connection.execute(
            "INSERT INTO job_lease_claims
             (claim_id, job_id, slot_id, claim_token, state, created_at, resolved_at)
             VALUES (?1, ?2, ?3, ?4, 'outstanding',
                     strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), NULL)",
            params![claim_token, job_id, reservation.slot_id(), claim_token],
        );
        if claim.is_err() {
            let _ = self.connection.execute_batch("ROLLBACK");
            return Err(HistoryError::AdmissionFailed);
        }
        let lease = match reservation.bind(&job_id, &claim_token) {
            Ok(lease) => lease,
            Err(error) => {
                let _ = self.connection.execute_batch("ROLLBACK");
                return Err(error);
            }
        };
        Ok(PendingAdmission {
            store: self,
            job_id,
            lease,
        })
    }

    pub(crate) fn list(&self) -> Result<Vec<JobSummary>, HistoryError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT job_id, parent_job_id, kind, state, admitted_at, terminal_at,\n                       outcome, failure_code, publication_state\n                FROM jobs\n                ORDER BY admitted_at DESC, job_id DESC",
            )
            .map_err(|_| HistoryError::QueryFailed)?;
        let rows = statement
            .query_map([], |row| {
                Ok(JobSummary {
                    job_id: row.get(0)?,
                    parent_job_id: row.get(1)?,
                    kind: row.get(2)?,
                    state: row.get(3)?,
                    admitted_at: row.get(4)?,
                    terminal_at: row.get(5)?,
                    outcome: row.get(6)?,
                    failure_code: row.get(7)?,
                    publication_state: row.get(8)?,
                })
            })
            .map_err(|_| HistoryError::QueryFailed)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| HistoryError::QueryFailed)
    }

    pub(crate) fn load(&self, job_id: &str) -> Result<JobDetail, HistoryError> {
        let mut detail = self
            .connection
            .query_row(
                "SELECT job_id, parent_job_id, kind, submission_kind, state, source,\n                       invocation_cwd, destination, destination_selection, workspace,\n                       workspace_selection, conflict_policy,\n                       conflict_policy_provenance, parent_conflict_policy,\n                       parent_conflict_policy_provenance, retry_scope, admitted_at,\n                       started_at, terminal_at, outcome, failure_code,\n                       cleanup_warning_code, publication_state, required_providers_json,\n                       required_keys_json, snapshot_json, result_json\n                FROM jobs WHERE job_id = ?1",
                [job_id],
                |row| {
                    let required_providers: String = row.get(23)?;
                    let required_keys: String = row.get(24)?;
                    let snapshot_text: Option<String> = row.get(25)?;
                    let result_text: Option<String> = row.get(26)?;
                    Ok(JobDetail {
                        job_id: row.get(0)?,
                        parent_job_id: row.get(1)?,
                        kind: row.get(2)?,
                        submission_kind: row.get(3)?,
                        state: row.get(4)?,
                        source: row.get(5)?,
                        invocation_cwd: row.get(6)?,
                        destination: row.get(7)?,
                        destination_selection: row.get(8)?,
                        workspace: row.get(9)?,
                        workspace_selection: row.get(10)?,
                        conflict_policy: row.get(11)?,
                        conflict_policy_provenance: row.get(12)?,
                        parent_conflict_policy: row.get(13)?,
                        parent_conflict_policy_provenance: row.get(14)?,
                        retry_scope: row.get(15)?,
                        admitted_at: row.get(16)?,
                        started_at: row.get(17)?,
                        terminal_at: row.get(18)?,
                        outcome: row.get(19)?,
                        failure_code: row.get(20)?,
                        cleanup_warning_code: row.get(21)?,
                        publication_state: row.get(22)?,
                        required_providers: serde_json::from_str(&required_providers)
                            .map_err(|error| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    21,
                                    rusqlite::types::Type::Text,
                                    Box::new(error),
                                )
                            })?,
                        required_keys: serde_json::from_str(&required_keys).map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                22,
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        })?,
                        snapshot: decode_json_column(snapshot_text, 23)?,
                        result: decode_json_column(result_text, 24)?,
                        items: Vec::new(),
                    })
                },
            )
            .optional()
            .map_err(|error| {
                #[cfg(test)]
                eprintln!("history load failed: {error}");
                #[cfg(not(test))]
                let _ = error;
                HistoryError::QueryFailed
            })?
            .ok_or(HistoryError::UnknownJob)?;
        detail.items = self.load_items(job_id)?;
        Ok(detail)
    }

    pub(crate) fn retry_intent(&self, job_id: &str) -> Result<RetryIntent, HistoryError> {
        let job = self.load(job_id)?;
        if matches!(job.state.as_str(), "admitted" | "running") {
            return Err(HistoryError::ActiveJob);
        }
        if !matches!(
            job.state.as_str(),
            "succeeded" | "completed_with_issues" | "failed" | "cancelled" | "interrupted"
        ) || job.kind != "copy_through"
            || job.submission_kind != "single"
            || job.retry_scope != "all"
        {
            return Err(HistoryError::IneligibleJob);
        }
        let invocation_cwd = job
            .invocation_cwd
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or(HistoryError::IneligibleJob)?;
        let destination_selection = match job.destination_selection.as_str() {
            "explicit" => DestinationSelection::Explicit,
            "configured_output_dir" => DestinationSelection::ConfiguredOutputDirectory,
            "native_documents_output" => DestinationSelection::NativeDocumentsOutput,
            _ => return Err(HistoryError::IneligibleJob),
        };
        let workspace_selection = match job.workspace_selection.as_str() {
            "explicit" => WorkspaceSelection::Explicit,
            "host_default" => WorkspaceSelection::HostDefault,
            _ => return Err(HistoryError::IneligibleJob),
        };
        let conflict_policy = match job.conflict_policy.as_str() {
            "fail" => ConflictPolicyRecord::Fail,
            "replace" => ConflictPolicyRecord::Replace,
            _ => return Err(HistoryError::IneligibleJob),
        };
        let conflict_policy_provenance = match job.conflict_policy_provenance.as_str() {
            "default" => ConflictPolicyProvenance::Default,
            "cli_replace" => ConflictPolicyProvenance::CliReplace,
            "retry_default" => ConflictPolicyProvenance::RetryDefault,
            "retry_explicit_replace" => ConflictPolicyProvenance::RetryExplicitReplace,
            _ => return Err(HistoryError::IneligibleJob),
        };
        Ok(RetryIntent {
            job_id: job.job_id,
            invocation_cwd,
            source: PathBuf::from(job.source),
            destination: PathBuf::from(job.destination),
            destination_selection,
            workspace: PathBuf::from(job.workspace),
            workspace_selection,
            conflict_policy,
            conflict_policy_provenance,
        })
    }

    pub(crate) fn begin_running(&self, job_id: &str) -> Result<(), HistoryError> {
        verify_database_health(&self.connection)?;
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(|_| HistoryError::AdmissionFailed)?;
        let changed = transaction
            .execute(
                "UPDATE jobs
                 SET state = 'running',
                     started_at = COALESCE(started_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                 WHERE job_id = ?1 AND state = 'admitted'",
                [job_id],
            )
            .map_err(|_| HistoryError::AdmissionFailed)?;
        if changed == 1 {
            transaction
                .execute(
                    "UPDATE job_items SET state = 'running'
                     WHERE job_id = ?1 AND state = 'planned'",
                    [job_id],
                )
                .map_err(|_| HistoryError::AdmissionFailed)?;
            transaction
                .commit()
                .map_err(|_| HistoryError::AdmissionFailed)?;
            return Ok(());
        }
        let state = transaction
            .query_row(
                "SELECT state FROM jobs WHERE job_id = ?1",
                [job_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| HistoryError::QueryFailed)?;
        transaction
            .commit()
            .map_err(|_| HistoryError::AdmissionFailed)?;
        match state.as_deref() {
            Some("running") => Ok(()),
            Some(_) => Err(HistoryError::IneligibleJob),
            None => Err(HistoryError::UnknownJob),
        }
    }

    pub(crate) fn complete(
        &mut self,
        job_id: &str,
        completion: &OperationCompletion,
    ) -> Result<(), HistoryError> {
        let result = completion.result();
        let state = history_state(result.state());
        let outcome = result.outcome().map(operation_outcome);
        let failure_code = result.failure().map(|failure| failure.code().as_str());
        let cleanup_warning_code = result
            .cleanup_warning()
            .map(|failure| failure.code().as_str());
        let publication_state = classify_publication(
            result.outcome().is_some(),
            result.failure().map(|failure| failure.code()),
            result.artifacts().iter().map(|artifact| artifact.role()),
        );
        let artifact_retained = result.cleanup_artifact_retained()
            || result
                .artifacts()
                .iter()
                .any(|artifact| artifact.retained());
        let pruneable =
            if completion_entry_is_pruneable(state, publication_state, artifact_retained) {
                1_i64
            } else {
                0_i64
            };
        let result_json =
            serde_json::to_string(result).map_err(|_| HistoryError::CompletionFailed)?;
        let snapshot_json = serde_json::to_string(&completion.snapshot())
            .map_err(|_| HistoryError::CompletionFailed)?;
        let evidence_json = serde_json::json!({
            "sequence": completion.sequence(),
            "snapshot": completion.snapshot(),
        })
        .to_string();

        self.connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|_| HistoryError::CompletionFailed)?;
        let update = self.connection.execute(
            "UPDATE jobs
             SET state = ?2, terminal_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                 outcome = ?3, failure_code = ?4, cleanup_warning_code = ?5,
                 publication_state = ?6, pruneable = ?7, result_json = ?8,
                 snapshot_json = ?9
             WHERE job_id = ?1 AND state IN ('admitted', 'running')",
            params![
                job_id,
                state,
                outcome,
                failure_code,
                cleanup_warning_code,
                publication_state,
                pruneable,
                result_json,
                snapshot_json,
            ],
        );
        if !matches!(update, Ok(1)) {
            let _ = self.connection.execute_batch("ROLLBACK");
            return Err(HistoryError::CompletionFailed);
        }
        if self
            .connection
            .execute(
                "UPDATE job_items
                 SET state = ?2, outcome = ?3, failure_code = ?4, evidence_json = ?5
                 WHERE job_id = ?1 AND state IN ('planned', 'running')",
                params![
                    job_id,
                    item_state(state),
                    outcome,
                    failure_code,
                    evidence_json
                ],
            )
            .is_err()
        {
            let _ = self.connection.execute_batch("ROLLBACK");
            return Err(HistoryError::CompletionFailed);
        }
        for (ordinal, artifact) in result.artifacts().iter().enumerate() {
            let role = serde_json::to_value(artifact.role())
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "uncertain_entry".to_owned());
            let path = match artifact.path().to_str() {
                Some(path) => path,
                None => {
                    let _ = self.connection.execute_batch("ROLLBACK");
                    return Err(HistoryError::CompletionFailed);
                }
            };
            let evidence = match serde_json::to_string(artifact) {
                Ok(evidence) => evidence,
                Err(_) => {
                    let _ = self.connection.execute_batch("ROLLBACK");
                    return Err(HistoryError::CompletionFailed);
                }
            };
            let identity_known = artifact.device().is_some() && artifact.inode().is_some();
            let content_known = artifact.sha256().is_some() || artifact.recorded_sha256().is_some();
            if self
                .connection
                .execute(
                    "INSERT INTO job_artifacts
                     (job_id, ordinal, role, path, retained, identity_known,
                      content_known, evidence_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        job_id,
                        ordinal as i64,
                        role,
                        path,
                        artifact.retained(),
                        identity_known,
                        content_known,
                        evidence,
                    ],
                )
                .is_err()
            {
                let _ = self.connection.execute_batch("ROLLBACK");
                return Err(HistoryError::CompletionFailed);
            }
        }
        let claim_state = if matches!(publication_state, "completed" | "not_completed") {
            "released"
        } else {
            "unresolved"
        };
        let claim_update = self.connection.execute(
            "UPDATE job_lease_claims
             SET state = ?2, resolved_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE job_id = ?1 AND state = 'outstanding'",
            params![job_id, claim_state],
        );
        if !matches!(claim_update, Ok(1))
            || self.prune_in_transaction().is_err()
            || self.connection.execute_batch("COMMIT").is_err()
        {
            let _ = self.connection.execute_batch("ROLLBACK");
            return Err(HistoryError::CompletionFailed);
        }
        Ok(())
    }

    /// Marks abandoned Jobs and their active items as interrupted.
    ///
    /// A Job is abandoned only when its owner's filesystem lease can be
    /// acquired. The Job and item transitions share one immediate SQLite
    /// transaction so a storage failure cannot publish a partially recovered
    /// history record.
    pub(crate) fn reconcile_interrupted(&self) -> Result<usize, HistoryError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT j.job_id, s.slot_key, s.slot_id, c.claim_token
                 FROM jobs j
                 JOIN job_lease_claims c ON c.job_id = j.job_id
                 JOIN lease_slots s ON s.slot_id = c.slot_id
                 WHERE j.state IN ('admitted', 'running')
                   AND c.state = 'outstanding'",
            )
            .map_err(|_| HistoryError::QueryFailed)?;
        let claims = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|_| HistoryError::QueryFailed)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| HistoryError::QueryFailed)?;
        drop(statement);
        let mut reconciled = 0;
        for (job_id, slot_key, slot_id, claim_token) in claims {
            let Ok(lease) =
                try_acquire_existing_claim(&self.path, &slot_key, &slot_id, &job_id, &claim_token)
            else {
                continue;
            };
            if self.connection.execute_batch("BEGIN IMMEDIATE").is_err() {
                return Err(HistoryError::CompletionFailed);
            }
            let verified = match self
                .connection
                .query_row(
                    "SELECT j.state, c.slot_id, c.claim_token
                     FROM jobs j
                     JOIN job_lease_claims c ON c.job_id = j.job_id
                     WHERE j.job_id = ?1 AND c.state = 'outstanding'",
                    [&job_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()
            {
                Ok(verified) => verified,
                Err(_) => {
                    let _ = self.connection.execute_batch("ROLLBACK");
                    return Err(HistoryError::CompletionFailed);
                }
            };
            if verified != Some(("admitted".to_owned(), slot_id.clone(), claim_token.clone()))
                && verified != Some(("running".to_owned(), slot_id.clone(), claim_token.clone()))
            {
                let _ = self.connection.execute_batch("ROLLBACK");
                continue;
            }
            let changed = self.connection.execute(
                "UPDATE jobs
                 SET state = 'interrupted',
                     terminal_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                     failure_code = 'interrupted', publication_state = 'unknown',
                     pruneable = 0
                 WHERE job_id = ?1 AND state IN ('admitted', 'running')",
                [&job_id],
            );
            match changed {
                Ok(1) => {}
                Ok(_) => {
                    let _ = self.connection.execute_batch("ROLLBACK");
                    continue;
                }
                Err(_) => {
                    let _ = self.connection.execute_batch("ROLLBACK");
                    return Err(HistoryError::CompletionFailed);
                }
            }
            if self
                .connection
                .execute(
                    "UPDATE job_items
                     SET state = 'interrupted', failure_code = 'interrupted'
                     WHERE job_id = ?1 AND state IN ('planned', 'running')",
                    [&job_id],
                )
                .is_err()
            {
                let _ = self.connection.execute_batch("ROLLBACK");
                return Err(HistoryError::CompletionFailed);
            }
            if !matches!(
                self.connection.execute(
                    "UPDATE job_lease_claims
                     SET state = 'unresolved',
                         resolved_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                     WHERE job_id = ?1 AND slot_id = ?2
                       AND claim_token = ?3 AND state = 'outstanding'",
                    params![job_id, slot_id, claim_token],
                ),
                Ok(1)
            ) {
                let _ = self.connection.execute_batch("ROLLBACK");
                return Err(HistoryError::CompletionFailed);
            }
            if self.connection.execute_batch("COMMIT").is_err() {
                let _ = self.connection.execute_batch("ROLLBACK");
                return Err(HistoryError::CompletionFailed);
            }
            reconciled += 1;
            drop(lease);
        }
        Ok(reconciled)
    }

    pub(crate) fn clear_terminal(&mut self) -> Result<usize, HistoryError> {
        self.connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|_| HistoryError::CompletionFailed)?;
        let deleted = self.connection.execute(
            "DELETE FROM jobs
             WHERE state IN (
                 'succeeded', 'completed_with_issues', 'failed', 'cancelled', 'interrupted'
             )",
            [],
        );
        let Ok(deleted) = deleted else {
            let _ = self.connection.execute_batch("ROLLBACK");
            return Err(HistoryError::CompletionFailed);
        };
        if self.connection.execute_batch("COMMIT").is_err() {
            let _ = self.connection.execute_batch("ROLLBACK");
            return Err(HistoryError::CompletionFailed);
        }
        Ok(deleted)
    }

    pub(crate) fn retry_failed_item_keys(&self, job_id: &str) -> Result<Vec<String>, HistoryError> {
        let detail = self.load(job_id)?;
        if matches!(detail.state.as_str(), "admitted" | "running") {
            return Err(HistoryError::ActiveJob);
        }
        if detail.kind != "copy_through"
            || detail.submission_kind != "independent_batch"
            || detail.retry_scope != "failed_items"
            || !matches!(
                detail.state.as_str(),
                "succeeded" | "completed_with_issues" | "failed" | "cancelled" | "interrupted"
            )
        {
            return Err(HistoryError::UnsupportedFailedItems);
        }
        let failed = detail
            .items
            .into_iter()
            .filter(|item| item.state == "failed")
            .map(|item| item.item_key)
            .collect::<Vec<_>>();
        if failed.is_empty() {
            Err(HistoryError::NoFailedItems)
        } else {
            Ok(failed)
        }
    }

    pub(crate) fn discard_unstarted_admission(&self, job_id: &str) -> Result<(), HistoryError> {
        self.connection
            .execute(
                "DELETE FROM jobs WHERE job_id = ?1 AND state = 'admitted'",
                [job_id],
            )
            .map(|_| ())
            .map_err(|_| HistoryError::AdmissionFailed)
    }

    fn load_items(&self, job_id: &str) -> Result<Vec<JobItem>, HistoryError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT item_key, kind, source, destination, state, outcome,\n                       failure_code, evidence_json\n                FROM job_items WHERE job_id = ?1 ORDER BY ordinal",
            )
            .map_err(|_| HistoryError::QueryFailed)?;
        let rows = statement
            .query_map([job_id], |row| {
                let evidence_text: Option<String> = row.get(7)?;
                Ok(JobItem {
                    item_key: row.get(0)?,
                    kind: row.get(1)?,
                    source: row.get(2)?,
                    destination: row.get(3)?,
                    state: row.get(4)?,
                    outcome: row.get(5)?,
                    failure_code: row.get(6)?,
                    evidence: decode_json_column(evidence_text, 7)?,
                })
            })
            .map_err(|_| HistoryError::QueryFailed)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| HistoryError::QueryFailed)
    }

    pub(crate) fn prune_in_transaction(&self) -> Result<usize, HistoryError> {
        self.connection
            .execute(
                "DELETE FROM jobs
                 WHERE job_id IN (
                     SELECT job_id FROM jobs
                     WHERE state IN ('succeeded', 'completed_with_issues',
                                     'failed', 'cancelled')
                       AND pruneable = 1
                       AND NOT EXISTS (
                           SELECT 1 FROM job_lease_claims c
                           WHERE c.job_id = jobs.job_id AND c.state = 'unresolved'
                       )
                     ORDER BY terminal_at DESC, job_id DESC
                     LIMIT -1 OFFSET ?1
                 )",
                [RETENTION_LIMIT as i64],
            )
            .map_err(|_| HistoryError::CompletionFailed)
    }

    fn initialize_or_migrate(&mut self) -> Result<(), HistoryError> {
        let mut version = self.schema_version()?;
        let mut application_id = self
            .connection
            .pragma_query_value(None, "application_id", |row| row.get::<_, i64>(0))
            .map_err(|_| HistoryError::Corrupt)?;
        if version == 0 {
            if application_id == 0 && !database_has_tables(&self.connection)? {
                create_schema(&mut self.connection)?;
                application_id = self
                    .connection
                    .pragma_query_value(None, "application_id", |row| row.get::<_, i64>(0))
                    .map_err(|_| HistoryError::Corrupt)?;
            } else if application_id != APPLICATION_ID
                || !database_has_table(&self.connection, "history_registry")?
            {
                return Err(HistoryError::Corrupt);
            }
        }
        if application_id != APPLICATION_ID {
            return Err(HistoryError::Corrupt);
        }
        if version > CURRENT_SCHEMA_VERSION {
            return Err(HistoryError::VersionUnsupported);
        }
        if version == 1 {
            migrate_v1_to_v2(&mut self.connection, &self.path)?;
            version = self.schema_version()?;
        }
        if version == 2 && !database_has_table(&self.connection, "history_registry")? {
            migrate_v2_to_v3(&mut self.connection, &self.path)?;
            version = self.schema_version()?;
        }
        if version == 0 || version == 2 {
            verify_database_health(&self.connection)?;
            initialize_slot_files(&self.connection, &self.path, true)?;
            mark_registry_ready(&mut self.connection)?;
        } else if version == CURRENT_SCHEMA_VERSION {
            verify_database_health(&self.connection)?;
            initialize_slot_files(&self.connection, &self.path, false)?;
        } else {
            return Err(HistoryError::Corrupt);
        }
        verify_database_health(&self.connection)?;
        Ok(())
    }
}

pub(super) fn classify_publication(
    has_outcome: bool,
    failure: Option<OperationFailureCode>,
    artifacts: impl IntoIterator<Item = OperationArtifactRole>,
) -> &'static str {
    if failure == Some(OperationFailureCode::PublicationUncertain) {
        "uncertain"
    } else if has_outcome {
        "completed"
    } else if artifacts
        .into_iter()
        .any(|role| role == OperationArtifactRole::PublishedDestination)
    {
        "published_unresolved"
    } else {
        "not_completed"
    }
}

pub(super) fn completion_entry_is_pruneable(
    state: &str,
    publication_state: &str,
    artifact_retained: bool,
) -> bool {
    state != "interrupted"
        && !artifact_retained
        && matches!(publication_state, "completed" | "not_completed")
}

#[derive(Debug)]
pub(crate) struct PendingAdmission {
    store: HistoryStore,
    job_id: String,
    lease: JobLease,
}

impl PendingAdmission {
    pub(crate) fn job_id(&self) -> &str {
        &self.job_id
    }

    pub(crate) fn acquire_lease(&self) -> Result<JobLease, HistoryError> {
        Ok(self.lease.clone())
    }

    /// Commits a uniquely identified admission while its ownership lease is
    /// still held.
    ///
    /// The lease is created before this value is returned and moved into the
    /// admitted Job, so there is no committed state in which recovery can
    /// mistake an owner that has not yet taken its lock for a dead owner.
    pub(crate) fn commit(self) -> Result<AdmittedJob, HistoryError> {
        self.store
            .connection
            .execute_batch("COMMIT")
            .map_err(|_| HistoryError::AdmissionFailed)?;
        Ok(AdmittedJob {
            job_id: self.job_id,
            _lease: self.lease,
        })
    }
}

#[derive(Debug)]
pub(crate) struct AdmittedJob {
    pub(crate) job_id: String,
    _lease: JobLease,
}
