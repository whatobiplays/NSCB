//! Durable Job admission, query, completion, retention, and recovery operations.

use super::lease::{
    JobLease, SlotReservation, acquire_available_slot, acquire_initialization_lock,
    initialize_slot_files, try_acquire_existing_claim,
};
use super::model::*;
use super::storage::{
    canonical_file_path, create_schema, database_has_table, database_has_tables,
    ensure_private_directory, map_open_error, mark_registry_ready, migrate_v1_to_v2,
    migrate_v2_to_v3, migrate_v3_to_v4, path_text, prepare_private_database_file,
    verify_database_health, verify_database_health_for_open,
};
use super::{APPLICATION_ID, BUSY_TIMEOUT_MILLIS, CURRENT_SCHEMA_VERSION, RETENTION_LIMIT};
use crate::standalone::paths;
use nscb::{
    CopyBatchCompletion, CopyBatchItemCheckpoint, CopyBatchItemState, CopyBatchResult,
    OperationArtifact, OperationArtifactRole, OperationCompletion, OperationFailureCode,
    Sha256Digest, SplitQualification,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArtifactProjectionRow {
    role: String,
    path: String,
    retained: bool,
    identity_known: bool,
    content_known: bool,
    evidence: String,
}

fn artifact_projection_rows<'a>(
    artifacts: impl IntoIterator<Item = &'a OperationArtifact>,
) -> Result<Vec<ArtifactProjectionRow>, HistoryError> {
    artifacts
        .into_iter()
        .map(|artifact| {
            let role = serde_json::to_value(artifact.role())
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "uncertain_entry".to_owned());
            let path = artifact
                .path()
                .to_str()
                .ok_or(HistoryError::CompletionFailed)?
                .to_owned();
            let evidence =
                serde_json::to_string(artifact).map_err(|_| HistoryError::CompletionFailed)?;
            Ok(ArtifactProjectionRow {
                role,
                path,
                retained: artifact.retained(),
                identity_known: artifact.device().is_some() && artifact.inode().is_some(),
                content_known: artifact.sha256().is_some() || artifact.recorded_sha256().is_some(),
                evidence,
            })
        })
        .collect()
}

fn insert_artifact_projection(
    connection: &Connection,
    job_id: &str,
    item_key: Option<&str>,
    rows: &[ArtifactProjectionRow],
) -> Result<(), HistoryError> {
    if rows.is_empty() {
        return Ok(());
    }
    let first_ordinal = connection
        .query_row(
            "SELECT COALESCE(MAX(ordinal), -1) + 1 FROM job_artifacts WHERE job_id = ?1",
            [job_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| HistoryError::CompletionFailed)?;
    for (ordinal, row) in (first_ordinal..).zip(rows) {
        connection
            .execute(
                "INSERT INTO job_artifacts
                 (job_id, item_key, ordinal, role, path, retained, identity_known,
                  content_known, evidence_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    job_id,
                    item_key,
                    ordinal,
                    row.role,
                    row.path,
                    row.retained,
                    row.identity_known,
                    row.content_known,
                    row.evidence,
                ],
            )
            .map_err(|_| HistoryError::CompletionFailed)?;
    }
    Ok(())
}

fn load_artifact_projection(
    connection: &Connection,
    job_id: &str,
    item_key: Option<&str>,
) -> Result<Vec<ArtifactProjectionRow>, HistoryError> {
    let item_key = item_key.map(str::to_owned);
    let mut statement = connection
        .prepare(
            "SELECT role, path, retained, identity_known, content_known, evidence_json
             FROM job_artifacts
             WHERE job_id = ?1 AND item_key IS ?2
             ORDER BY ordinal",
        )
        .map_err(|_| HistoryError::CompletionFailed)?;
    statement
        .query_map(params![job_id, item_key], |row| {
            Ok(ArtifactProjectionRow {
                role: row.get(0)?,
                path: row.get(1)?,
                retained: row.get(2)?,
                identity_known: row.get(3)?,
                content_known: row.get(4)?,
                evidence: row.get(5)?,
            })
        })
        .map_err(|_| HistoryError::CompletionFailed)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| HistoryError::CompletionFailed)
}

#[derive(Debug)]
pub(crate) struct HistoryStore {
    path: PathBuf,
    pub(crate) connection: Connection,
    #[cfg(test)]
    pub(crate) fail_checkpoint_sequence_query: bool,
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
        let health = verify_database_health_for_open(&connection);
        #[cfg(test)]
        if let Err(error) = &health {
            eprintln!("initial history health validation failed: {error:?}");
        }
        health?;
        let mut store = Self {
            path: resolved_path,
            connection,
            #[cfg(test)]
            fail_checkpoint_sequence_query: false,
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
        let is_independent_batch = input.submission_kind == SubmissionKind::IndependentBatch;
        if input.items.is_empty()
            || !input.invocation_cwd.is_absolute()
            || (is_independent_batch != input.batch_intent.is_some())
        {
            return Err(HistoryError::AdmissionFailed);
        }
        let (source, source_provenance, batch_source_intent) =
            match (&input.source, input.submission_kind) {
                (AdmissionSource::Single(source), SubmissionKind::Single) => {
                    let source = path_text(source)
                        .map_err(|_| HistoryError::AdmissionFailed)?
                        .to_owned();
                    (Some(source), "cli_argument", None)
                }
                (AdmissionSource::IndependentBatch, SubmissionKind::IndependentBatch) => {
                    let intent = BatchSourceIntent::from_items(&input.items)?;
                    let intent_json = serde_json::to_string(&intent)
                        .map_err(|_| HistoryError::AdmissionFailed)?;
                    (None, "independent_batch_items", Some(intent_json))
                }
                _ => return Err(HistoryError::AdmissionFailed),
            };
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
        let batch_intent = input
            .batch_intent
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| HistoryError::AdmissionFailed)?;
        let invocation_cwd = path_text(&input.invocation_cwd)?;
        let destination = path_text(&input.destination)?;
        let workspace = path_text(&input.workspace)?;
        let insert_result = self.connection.execute(
                "INSERT INTO jobs (\n job_id, parent_job_id, kind, submission_kind, source,\n invocation_cwd, source_provenance, destination, destination_selection,\n workspace, workspace_selection, conflict_policy, conflict_policy_provenance,\n parent_conflict_policy, parent_conflict_policy_provenance, retry_scope,\n state, admitted_at, publication_state, pruneable, required_providers_json,\n required_keys_json, lease_slot_id\n ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,\n ?10, ?11, ?12, ?13, ?14, ?15, ?16, 'admitted',\n strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'not_started', 0,\n ?17, ?18, ?19)",
            params![
                job_id,
                input.parent_job_id,
                kind,
                submission_kind,
                source,
                invocation_cwd,
                source_provenance,
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
        if let Some(batch_intent) = batch_intent.as_deref() {
            let inserted = self.connection.execute(
                "INSERT INTO batch_intents (job_id, schema_version, kind, intent_json)
                 VALUES (?1, 1, 'nscb.copy_batch_intent', ?2)",
                params![job_id, batch_intent],
            );
            if inserted.is_err() {
                let _ = self.connection.execute_batch("ROLLBACK");
                return Err(HistoryError::AdmissionFailed);
            }
        }
        if let Some(source_intent) = batch_source_intent.as_deref() {
            let inserted = self.connection.execute(
                "INSERT INTO batch_source_intents (job_id, schema_version, kind, intent_json)
                 VALUES (?1, 1, 'nscb.copy_batch_sources', ?2)",
                params![job_id, source_intent],
            );
            if inserted.is_err() {
                let _ = self.connection.execute_batch("ROLLBACK");
                return Err(HistoryError::AdmissionFailed);
            }
        }
        for (ordinal, item) in input.items.iter().enumerate() {
            if is_independent_batch && item.provenance.is_none() {
                let _ = self.connection.execute_batch("ROLLBACK");
                return Err(HistoryError::AdmissionFailed);
            }
            let item_source = match path_text(&item.source) {
                Ok(value) => value,
                Err(error) => {
                    let _ = self.connection.execute_batch("ROLLBACK");
                    return Err(error);
                }
            };
            let (item_destination, destination_assigned) = match item.destination.as_ref() {
                Some(destination) => match path_text(destination) {
                    Ok(value) => (value.to_owned(), 1_i64),
                    Err(error) => {
                        let _ = self.connection.execute_batch("ROLLBACK");
                        return Err(error);
                    }
                },
                None => (String::new(), 0_i64),
            };
            let provenance = item
                .provenance
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .map_err(|_| HistoryError::AdmissionFailed)?;
            let result = self.connection.execute(
                "INSERT INTO job_items (\n                    job_id, ordinal, item_key, kind, source, destination,\n                    destination_assigned, state, provenance_json\n                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'planned', ?8)",
                params![
                    job_id,
                    ordinal as i64,
                    item.item_key,
                    kind,
                    item_source,
                    item_destination,
                    destination_assigned,
                    provenance,
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
                        batch_source_intent: None,
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
                        batch_intent: None,
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
        detail.batch_source_intent = self.load_batch_source_intent(job_id)?;
        match (
            detail.submission_kind.as_str(),
            detail.source.as_deref(),
            detail.batch_source_intent.as_ref(),
        ) {
            ("single", Some(_), None) => {}
            ("independent_batch", None, Some(intent))
                if intent.is_legacy_incomplete()
                    || intent.matches_items(&detail.items)
                    || intent.matches_legacy_unversioned_items(&detail.items) => {}
            _ => return Err(HistoryError::QueryFailed),
        }
        detail.batch_intent = self.load_batch_intent(job_id)?;
        if detail.submission_kind == "single" && detail.batch_intent.is_some() {
            return Err(HistoryError::QueryFailed);
        }
        Ok(detail)
    }

    /// Allows retry only when every persisted claim is explicitly released.
    ///
    /// Legacy single-copy history may predate durable claims. Batch retries
    /// require a persisted released claim before planning can begin.
    fn retry_claim_states_are_released(
        &self,
        job_id: &str,
        require_claim: bool,
    ) -> Result<bool, HistoryError> {
        let mut statement = self
            .connection
            .prepare("SELECT state FROM job_lease_claims WHERE job_id = ?1")
            .map_err(|_| HistoryError::QueryFailed)?;
        let states = statement
            .query_map([job_id], |row| row.get::<_, String>(0))
            .map_err(|_| HistoryError::QueryFailed)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| HistoryError::QueryFailed)?;
        Ok(
            (!require_claim || !states.is_empty())
                && states.iter().all(|state| state == "released"),
        )
    }

    pub(crate) fn retry_intent(&self, job_id: &str) -> Result<RetryIntent, HistoryError> {
        let job = self.load(job_id).map_err(|error| match error {
            HistoryError::QueryFailed => HistoryError::IneligibleJob,
            error => error,
        })?;
        if matches!(job.state.as_str(), "admitted" | "running") {
            return Err(HistoryError::ActiveJob);
        }
        if !self.retry_claim_states_are_released(job_id, false)? {
            return Err(HistoryError::IneligibleJob);
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
            .as_ref()
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
            "skip" => ConflictPolicyRecord::Skip,
            _ => return Err(HistoryError::IneligibleJob),
        };
        let conflict_policy_provenance = match job.conflict_policy_provenance.as_str() {
            "default" => ConflictPolicyProvenance::Default,
            "cli_replace" => ConflictPolicyProvenance::CliReplace,
            "cli_skip" => ConflictPolicyProvenance::CliSkip,
            "retry_default" => ConflictPolicyProvenance::RetryDefault,
            "retry_explicit_replace" => ConflictPolicyProvenance::RetryExplicitReplace,
            "retry_explicit_skip" => ConflictPolicyProvenance::RetryExplicitSkip,
            _ => return Err(HistoryError::IneligibleJob),
        };
        Ok(RetryIntent {
            job_id: job.job_id,
            invocation_cwd,
            source: PathBuf::from(job.source.ok_or(HistoryError::IneligibleJob)?),
            destination: PathBuf::from(job.destination),
            destination_selection,
            workspace: PathBuf::from(job.workspace),
            workspace_selection,
            conflict_policy,
            conflict_policy_provenance,
        })
    }

    /// Loads exact failed-item retry intent from one durable independent batch.
    ///
    /// Only stored `failed` item rows are eligible. Successful, skipped,
    /// planned, running, cancelled, uncertain, interrupted, and not-started rows
    /// remain untouched and cannot be selected by re-expanding prior inputs.
    pub(crate) fn failed_items_retry_intent(
        &self,
        job_id: &str,
    ) -> Result<BatchFailedItemsRetryIntent, HistoryError> {
        let job = self.load(job_id)?;
        if matches!(job.state.as_str(), "admitted" | "running") {
            return Err(HistoryError::ActiveJob);
        }
        if !self.retry_claim_states_are_released(job_id, true)? {
            return Err(HistoryError::UnsupportedFailedItems);
        }
        if !matches!(
            job.state.as_str(),
            "succeeded" | "completed_with_issues" | "failed" | "cancelled" | "interrupted"
        ) || job.kind != "copy_through"
            || job.submission_kind != "independent_batch"
            || job.retry_scope != "failed_items"
        {
            return Err(HistoryError::UnsupportedFailedItems);
        }
        let invocation_cwd = job
            .invocation_cwd
            .as_ref()
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or(HistoryError::IneligibleJob)?;
        let destination = PathBuf::from(&job.destination);
        let workspace = PathBuf::from(&job.workspace);
        if !destination.is_absolute() || !workspace.is_absolute() {
            return Err(HistoryError::IneligibleJob);
        }
        let destination_selection = match job.destination_selection.as_str() {
            "explicit" => DestinationSelection::Explicit,
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
            "skip" => ConflictPolicyRecord::Skip,
            _ => return Err(HistoryError::IneligibleJob),
        };
        let conflict_policy_provenance = match job.conflict_policy_provenance.as_str() {
            "default" => ConflictPolicyProvenance::Default,
            "cli_replace" => ConflictPolicyProvenance::CliReplace,
            "cli_skip" => ConflictPolicyProvenance::CliSkip,
            "retry_default" => ConflictPolicyProvenance::RetryDefault,
            "retry_explicit_replace" => ConflictPolicyProvenance::RetryExplicitReplace,
            "retry_explicit_skip" => ConflictPolicyProvenance::RetryExplicitSkip,
            _ => return Err(HistoryError::IneligibleJob),
        };
        if !matches!(
            job.publication_state.as_str(),
            "completed" | "not_completed"
        ) {
            return Err(HistoryError::UnsupportedFailedItems);
        }
        if !job
            .batch_source_intent
            .as_ref()
            .is_some_and(|intent| intent.matches_items(&job.items))
        {
            return Err(HistoryError::UnsupportedFailedItems);
        }
        let batch_intent = job
            .batch_intent
            .clone()
            .ok_or(HistoryError::UnsupportedFailedItems)?;
        validate_failed_items_retry_intent(&job, &batch_intent)?;
        let items = job
            .items
            .into_iter()
            .filter(|item| item.state == "failed")
            .map(|item| {
                let source = PathBuf::from(item.source);
                let destination = PathBuf::from(
                    item.destination
                        .ok_or(HistoryError::UnsupportedFailedItems)?,
                );
                let provenance = item.provenance.ok_or(HistoryError::IneligibleJob)?;
                if !source.is_absolute() || !destination.is_absolute() {
                    return Err(HistoryError::IneligibleJob);
                }
                let selection = parse_retry_selection(&provenance)?;
                let split_evidence = selection
                    .split_qualification
                    .as_ref()
                    .map(FailedItemsRetrySplitQualificationRecord::to_runtime)
                    .transpose()?;
                let (split_qualification, split_manifest_sha256) = match split_evidence {
                    Some((qualification, manifest_sha256)) => {
                        (Some(qualification), Some(manifest_sha256))
                    }
                    None => (None, None),
                };
                Ok(AdmissionItem {
                    item_key: item.item_key,
                    source,
                    destination: Some(destination),
                    provenance: Some(provenance),
                    split_qualification,
                    split_manifest_sha256,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if items.is_empty() {
            return Err(HistoryError::NoFailedItems);
        }
        Ok(BatchFailedItemsRetryIntent {
            job_id: job.job_id,
            invocation_cwd,
            destination,
            destination_selection,
            workspace,
            workspace_selection,
            conflict_policy,
            conflict_policy_provenance,
            items,
            batch_intent,
        })
    }

    fn load_batch_intent(&self, job_id: &str) -> Result<Option<serde_json::Value>, HistoryError> {
        let value = self
            .connection
            .query_row(
                "SELECT intent_json FROM batch_intents WHERE job_id = ?1",
                [job_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| HistoryError::QueryFailed)?;
        decode_json_column(value, 0).map_err(|_| HistoryError::QueryFailed)
    }

    fn load_batch_source_intent(
        &self,
        job_id: &str,
    ) -> Result<Option<BatchSourceIntent>, HistoryError> {
        let value = self
            .connection
            .query_row(
                "SELECT intent_json FROM batch_source_intents WHERE job_id = ?1",
                [job_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| HistoryError::QueryFailed)?;
        value
            .map(|intent| serde_json::from_str(&intent).map_err(|_| HistoryError::QueryFailed))
            .transpose()
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
              WHERE job_id = ?1 AND submission_kind = 'single'
                AND state IN ('admitted', 'running')",
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
        let artifact_rows = match artifact_projection_rows(result.artifacts()) {
            Ok(rows) => rows,
            Err(error) => {
                let _ = self.connection.execute_batch("ROLLBACK");
                return Err(error);
            }
        };
        if insert_artifact_projection(&self.connection, job_id, None, &artifact_rows).is_err() {
            let _ = self.connection.execute_batch("ROLLBACK");
            return Err(HistoryError::CompletionFailed);
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

    /// Commits one authoritative item result and its publication evidence for
    /// an independently admitted batch.
    ///
    /// The caller must checkpoint an item before execution advances to the next
    /// item. The sequence must increase within the admitted Job, and the item
    /// must still be planned or running in this same transaction.
    pub(crate) fn checkpoint_batch_item(
        &self,
        job_id: &str,
        checkpoint: &CopyBatchItemCheckpoint,
    ) -> Result<(), HistoryError> {
        verify_database_health(&self.connection)?;
        let job_state = self
            .connection
            .query_row(
                "SELECT submission_kind, state FROM jobs WHERE job_id = ?1",
                [job_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|_| HistoryError::CompletionFailed)?;
        if job_state != Some(("independent_batch".to_owned(), "running".to_owned())) {
            return Err(HistoryError::CompletionFailed);
        }
        let item = checkpoint.item();
        let state = batch_item_history_state(item.state());
        let outcome = item.outcome().map(operation_outcome);
        let failure_code = item.failure().map(|failure| failure.code().as_str());
        let publication_state = classify_publication(
            item.outcome().is_some(),
            item.failure().map(|failure| failure.code()),
            item.artifacts().iter().map(|artifact| artifact.role()),
        );
        let evidence_json = serde_json::json!({
            "sequence": checkpoint.sequence(),
            "item": item,
        })
        .to_string();
        let checkpoint_sequence =
            i64::try_from(checkpoint.sequence()).map_err(|_| HistoryError::CompletionFailed)?;

        self.connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|_| HistoryError::CompletionFailed)?;
        #[cfg(test)]
        let previous_sequence = if self.fail_checkpoint_sequence_query {
            Err(rusqlite::Error::InvalidQuery)
        } else {
            self.connection.query_row(
                "SELECT MAX(sequence) FROM batch_item_checkpoints WHERE job_id = ?1",
                [job_id],
                |row| row.get::<_, Option<i64>>(0),
            )
        };
        #[cfg(not(test))]
        let previous_sequence = self.connection.query_row(
            "SELECT MAX(sequence) FROM batch_item_checkpoints WHERE job_id = ?1",
            [job_id],
            |row| row.get::<_, Option<i64>>(0),
        );
        match previous_sequence {
            Ok(Some(previous)) if checkpoint.sequence() <= previous as u64 => {
                let _ = self.connection.execute_batch("ROLLBACK");
                return Err(HistoryError::CompletionFailed);
            }
            Ok(_) => {}
            Err(_) => {
                let _ = self.connection.execute_batch("ROLLBACK");
                return Err(HistoryError::CompletionFailed);
            }
        }
        let updated = self.connection.execute(
            "UPDATE job_items
                SET state = ?3, outcome = ?4, failure_code = ?5, evidence_json = ?6
              WHERE job_id = ?1 AND item_key = ?2
                AND state IN ('planned', 'running')",
            params![
                job_id,
                item.item_key(),
                state,
                outcome,
                failure_code,
                evidence_json,
            ],
        );
        if !matches!(updated, Ok(1)) {
            let _ = self.connection.execute_batch("ROLLBACK");
            return Err(HistoryError::CompletionFailed);
        }
        let inserted = self.connection.execute(
            "INSERT INTO batch_item_checkpoints
                (job_id, item_key, sequence, item_state, outcome, failure_code,
                 publication_state, evidence_json, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
                     strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            params![
                job_id,
                item.item_key(),
                checkpoint_sequence,
                state,
                outcome,
                failure_code,
                publication_state,
                evidence_json,
            ],
        );
        if inserted.is_err() {
            let _ = self.connection.execute_batch("ROLLBACK");
            return Err(HistoryError::CompletionFailed);
        }
        let artifact_rows = match artifact_projection_rows(item.artifacts()) {
            Ok(rows) => rows,
            Err(error) => {
                let _ = self.connection.execute_batch("ROLLBACK");
                return Err(error);
            }
        };
        if insert_artifact_projection(
            &self.connection,
            job_id,
            Some(item.item_key()),
            &artifact_rows,
        )
        .is_err()
            || self.connection.execute_batch("COMMIT").is_err()
        {
            let _ = self.connection.execute_batch("ROLLBACK");
            return Err(HistoryError::CompletionFailed);
        }
        Ok(())
    }

    /// Atomically commits the aggregate result after every executable item has
    /// supplied its own checkpoint.
    pub(crate) fn complete_batch(
        &mut self,
        job_id: &str,
        completion: &CopyBatchCompletion,
        failed_checkpoint: Option<&CopyBatchItemCheckpoint>,
    ) -> Result<(), HistoryError> {
        let result = completion.result();
        let state = history_state(result.state());
        let failure_code = result.failure().map(|failure| failure.code().as_str());
        let cleanup_warning_code = result.items().iter().find_map(|item| {
            item.cleanup_warning()
                .map(|failure| failure.code().as_str())
        });
        let publication_state = classify_batch_publication(result);
        let artifact_retained = result.items().iter().any(|item| {
            item.cleanup_artifact_retained()
                || item.artifacts().iter().any(|artifact| artifact.retained())
        });
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
        let item_evidence = result
            .items()
            .iter()
            .map(|item| {
                Ok((
                    item.item_key().to_owned(),
                    serde_json::to_string(item).map_err(|_| HistoryError::CompletionFailed)?,
                ))
            })
            .collect::<Result<Vec<_>, HistoryError>>()?;
        let artifact_rows = result
            .items()
            .iter()
            .map(|item| {
                Ok((
                    item.item_key().to_owned(),
                    artifact_projection_rows(item.artifacts())?,
                ))
            })
            .collect::<Result<Vec<_>, HistoryError>>()?;
        let checkpoint_failed = result
            .failure()
            .is_some_and(|failure| failure.code() == OperationFailureCode::CheckpointFailed);
        let failed_checkpoint_row = match failed_checkpoint {
            Some(checkpoint)
                if checkpoint_failed
                    && checkpoint.item().state() != CopyBatchItemState::NotStarted
                    && result.items().iter().any(|item| {
                        item.item_key() == checkpoint.item().item_key()
                            && item.state() == checkpoint.item().state()
                    }) =>
            {
                let item = checkpoint.item();
                Some((
                    item.item_key().to_owned(),
                    i64::try_from(checkpoint.sequence())
                        .map_err(|_| HistoryError::CompletionFailed)?,
                    batch_item_history_state(item.state()).to_owned(),
                    item.outcome().map(operation_outcome).map(str::to_owned),
                    item.failure()
                        .map(|failure| failure.code().as_str().to_owned()),
                    classify_publication(
                        item.outcome().is_some(),
                        item.failure().map(|failure| failure.code()),
                        item.artifacts().iter().map(|artifact| artifact.role()),
                    )
                    .to_owned(),
                    serde_json::json!({
                        "sequence": checkpoint.sequence(),
                        "item": item,
                    })
                    .to_string(),
                ))
            }
            None => None,
            Some(_) => return Err(HistoryError::CompletionFailed),
        };

        self.connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|_| HistoryError::CompletionFailed)?;
        let mut failed_checkpoint_used = false;
        for item in result.items() {
            let checkpoint_state = self
                .connection
                .query_row(
                    "SELECT item_state FROM batch_item_checkpoints
                 WHERE job_id = ?1 AND item_key = ?2",
                    params![job_id, item.item_key()],
                    |row| row.get::<_, String>(0),
                )
                .optional();
            let had_checkpoint = matches!(&checkpoint_state, Ok(Some(_)));
            match checkpoint_state {
                Ok(Some(found)) if found == batch_item_history_state(item.state()) => {}
                Ok(None) if item.state() == CopyBatchItemState::NotStarted => {
                    let evidence = item_evidence
                        .iter()
                        .find(|(key, _)| key == item.item_key())
                        .map(|(_, evidence)| evidence.as_str())
                        .ok_or(HistoryError::CompletionFailed)?;
                    let changed = self.connection.execute(
                        "UPDATE job_items
                         SET state = 'not_started', failure_code = NULL, evidence_json = ?3
                         WHERE job_id = ?1 AND item_key = ?2
                         AND state IN ('planned', 'running')",
                        params![job_id, item.item_key(), evidence],
                    );
                    if !matches!(changed, Ok(1)) {
                        let _ = self.connection.execute_batch("ROLLBACK");
                        return Err(HistoryError::CompletionFailed);
                    }
                }
                Ok(None)
                    if failed_checkpoint_row
                        .as_ref()
                        .is_some_and(|row| row.0 == item.item_key() && !failed_checkpoint_used) =>
                {
                    let row = failed_checkpoint_row
                        .as_ref()
                        .ok_or(HistoryError::CompletionFailed)?;
                    let changed = self.connection.execute(
                        "UPDATE job_items
                         SET state = ?3, outcome = ?4, failure_code = ?5, evidence_json = ?6
                         WHERE job_id = ?1 AND item_key = ?2
                         AND state IN ('planned', 'running')",
                        params![job_id, item.item_key(), row.2, row.3, row.4, row.6],
                    );
                    if !matches!(changed, Ok(1)) {
                        let _ = self.connection.execute_batch("ROLLBACK");
                        return Err(HistoryError::CompletionFailed);
                    }
                    let inserted = self.connection.execute(
                        "INSERT INTO batch_item_checkpoints
                         (job_id, item_key, sequence, item_state, outcome, failure_code,
                          publication_state, evidence_json, recorded_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
                          strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                        params![job_id, row.0, row.1, row.2, row.3, row.4, row.5, row.6],
                    );
                    if inserted.is_err() {
                        let _ = self.connection.execute_batch("ROLLBACK");
                        return Err(HistoryError::CompletionFailed);
                    }
                    failed_checkpoint_used = true;
                }
                _ => {
                    let _ = self.connection.execute_batch("ROLLBACK");
                    return Err(HistoryError::CompletionFailed);
                }
            }
            let expected_artifacts = artifact_rows
                .iter()
                .find(|(item_key, _)| item_key == item.item_key())
                .map(|(_, rows)| rows)
                .ok_or(HistoryError::CompletionFailed)?;
            let existing_artifacts =
                match load_artifact_projection(&self.connection, job_id, Some(item.item_key())) {
                    Ok(rows) => rows,
                    Err(_) => {
                        let _ = self.connection.execute_batch("ROLLBACK");
                        return Err(HistoryError::CompletionFailed);
                    }
                };
            if had_checkpoint {
                if existing_artifacts != *expected_artifacts {
                    let _ = self.connection.execute_batch("ROLLBACK");
                    return Err(HistoryError::CompletionFailed);
                }
            } else if insert_artifact_projection(
                &self.connection,
                job_id,
                Some(item.item_key()),
                expected_artifacts,
            )
            .is_err()
            {
                let _ = self.connection.execute_batch("ROLLBACK");
                return Err(HistoryError::CompletionFailed);
            }
        }
        if failed_checkpoint_row.is_some() && !failed_checkpoint_used {
            let _ = self.connection.execute_batch("ROLLBACK");
            return Err(HistoryError::CompletionFailed);
        }
        let update = self.connection.execute(
            "UPDATE jobs
             SET state = ?2, terminal_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
             outcome = NULL, failure_code = ?3, cleanup_warning_code = ?4,
             publication_state = ?5, pruneable = ?6, result_json = ?7,
             snapshot_json = ?8
             WHERE job_id = ?1 AND submission_kind = 'independent_batch'
             AND state = 'running'",
            params![
                job_id,
                state,
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

    #[cfg(test)]
    pub(crate) fn retry_failed_item_keys(&self, job_id: &str) -> Result<Vec<String>, HistoryError> {
        self.failed_items_retry_intent(job_id)
            .map(|intent| intent.items.into_iter().map(|item| item.item_key).collect())
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
                "SELECT items.item_key, items.kind, items.source, items.destination,\n                       items.destination_assigned, items.state, items.outcome,\n                       items.failure_code, items.evidence_json, items.provenance_json,\n                       checkpoints.item_state, checkpoints.outcome,\n                       checkpoints.failure_code, checkpoints.publication_state,\n                       checkpoints.evidence_json, checkpoints.sequence\n                 FROM job_items items\n                LEFT JOIN batch_item_checkpoints checkpoints\n                  ON checkpoints.job_id = items.job_id\n                 AND checkpoints.item_key = items.item_key\n                WHERE items.job_id = ?1 ORDER BY items.ordinal",
            )
            .map_err(|_| HistoryError::QueryFailed)?;
        let rows = statement
            .query_map([job_id], |row| {
                let item_key: String = row.get(0)?;
                let source: String = row.get(2)?;
                let stored_destination: String = row.get(3)?;
                let destination_assigned: i64 = row.get(4)?;
                let destination = match (destination_assigned, stored_destination.is_empty()) {
                    (1, false) => Some(stored_destination),
                    (0, true) => None,
                    _ => return Err(rusqlite::Error::InvalidQuery),
                };
                let state: String = row.get(5)?;
                let outcome: Option<String> = row.get(6)?;
                let failure_code: Option<String> = row.get(7)?;
                let evidence_text: Option<String> = row.get(8)?;
                let provenance_text: Option<String> = row.get(9)?;
                let checkpoint_state: Option<String> = row.get(10)?;
                let checkpoint_outcome: Option<String> = row.get(11)?;
                let checkpoint_failure_code: Option<String> = row.get(12)?;
                let checkpoint_publication_state: Option<String> = row.get(13)?;
                let checkpoint_evidence_text: Option<String> = row.get(14)?;
                let checkpoint_sequence = row.get::<_, Option<i64>>(15)?;
                let checkpoint_sequence = checkpoint_sequence
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| {
                        rusqlite::Error::IntegralValueOutOfRange(
                            15,
                            checkpoint_sequence.unwrap_or_default(),
                        )
                    })?;
                if destination.is_none()
                    && !matches!(
                        (state.as_str(), failure_code.as_deref()),
                        ("planned", None)
                            | ("failed", Some("empty_selection"))
                            | ("cancelled", Some("cancelled"))
                            | ("not_started", None)
                    )
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                let evidence = decode_json_column(evidence_text.clone(), 8)?;
                let checkpoint_evidence = decode_json_column(checkpoint_evidence_text, 14)?;
                let durable = DurableCheckpointResult {
                    item_key: &item_key,
                    source: &source,
                    destination: destination.as_deref(),
                    state: &state,
                    outcome: outcome.as_deref(),
                    failure_code: failure_code.as_deref(),
                    evidence: evidence.as_ref(),
                };
                let checkpoint = StoredCheckpointResult {
                    item_state: checkpoint_state.as_deref(),
                    outcome: checkpoint_outcome.as_deref(),
                    failure_code: checkpoint_failure_code.as_deref(),
                    publication_state: checkpoint_publication_state.as_deref(),
                    sequence: checkpoint_sequence,
                    evidence: checkpoint_evidence.as_ref(),
                };
                if checkpoint_state.is_some()
                    && !checkpoint_result_is_consistent(&durable, &checkpoint)
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                let (publication_state, checkpoint_sequence) = if checkpoint_state.is_some() {
                    (
                        checkpoint_publication_state
                            .clone()
                            .ok_or(rusqlite::Error::InvalidQuery)?,
                        checkpoint.sequence,
                    )
                } else {
                    ("unknown".to_owned(), None)
                };
                Ok(JobItem {
                    item_key,
                    kind: row.get(1)?,
                    source,
                    destination,
                    state,
                    outcome,
                    failure_code,
                    evidence,
                    provenance: decode_json_column(provenance_text, 9)?,
                    publication_state,
                    checkpoint_sequence,
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
        let needs_registry_finalize = matches!(version, 0..=2)
            || (matches!(version, 3 | 4)
                && database_has_table(&self.connection, "history_registry")?
                && self
                    .connection
                    .query_row(
                        "SELECT ready FROM history_registry WHERE singleton = 1",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .map_err(|_| HistoryError::Corrupt)?
                    == 0);
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
        if version == 2 {
            if !database_has_table(&self.connection, "history_registry")? {
                migrate_v2_to_v3(&mut self.connection, &self.path)?;
            }
            self.connection
                .execute_batch("PRAGMA user_version = 3")
                .map_err(|_| HistoryError::MigrationFailed)?;
            version = self.schema_version()?;
        }
        if version == 3 {
            migrate_v3_to_v4(&mut self.connection, &self.path)?;
            version = self.schema_version()?;
        }
        if needs_registry_finalize {
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FailedItemsRetryIntentRecord {
    schema_version: u64,
    kind: String,
    parent_job_id: Option<String>,
    retry_scope: Option<String>,
    plan: FailedItemsRetryPlanRecord,
    selections: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FailedItemsRetryPlanRecord {
    kind: String,
    nscb_version: String,
    destination_directory: PathBuf,
    workspace: PathBuf,
    conflict_policy: String,
    items: Vec<FailedItemsRetryPlanItemRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FailedItemsRetryPlanItemRecord {
    item_key: String,
    source: PathBuf,
    destination: Option<PathBuf>,
    state: FailedItemsRetryPlanState,
    failure_code: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum FailedItemsRetryPlanState {
    Viable,
    PreflightFailed,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FailedItemsRetrySelectionRecord {
    schema_version: u64,
    kind: String,
    selection_index: usize,
    source: FailedItemsRetrySelectionSource,
    selection_path: PathBuf,
    #[serde(default)]
    base_directory: Option<PathBuf>,
    input_list_entry_index: Option<usize>,
    input_list_entry_path: Option<PathBuf>,
    discovered_directory: Option<PathBuf>,
    discovered_relative_path: Option<PathBuf>,
    requested_path: Option<PathBuf>,
    failure_code: Option<String>,
    phase: Option<String>,
    #[serde(default)]
    split_qualification: Option<FailedItemsRetrySplitQualificationRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FailedItemsRetrySplitQualificationRecord {
    kind: FailedItemsRetrySplitQualificationKind,
    manifest_schema_version: u16,
    original_size_bytes: u64,
    original_sha256: String,
    manifest_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum FailedItemsRetrySplitQualificationKind {
    LocalSplitReceipt,
}

impl FailedItemsRetrySplitQualificationRecord {
    fn to_runtime(&self) -> Result<(SplitQualification, Sha256Digest), HistoryError> {
        if self.kind != FailedItemsRetrySplitQualificationKind::LocalSplitReceipt
            || self.manifest_schema_version != 1
            || self.original_size_bytes == 0
        {
            return Err(HistoryError::UnsupportedFailedItems);
        }
        let original_sha256 = Sha256Digest::parse_hex(&self.original_sha256)
            .map_err(|_| HistoryError::UnsupportedFailedItems)?;
        let manifest_sha256 = Sha256Digest::parse_hex(&self.manifest_sha256)
            .map_err(|_| HistoryError::UnsupportedFailedItems)?;
        Ok((
            SplitQualification::local_receipt(
                self.manifest_schema_version,
                self.original_size_bytes,
                original_sha256,
            ),
            manifest_sha256,
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum FailedItemsRetrySelectionSource {
    Path,
    InputList,
}

pub(super) fn validate_failed_items_retry_intent(
    job: &JobDetail,
    intent: &serde_json::Value,
) -> Result<(), HistoryError> {
    let object = intent
        .as_object()
        .ok_or(HistoryError::UnsupportedFailedItems)?;
    let expected_intent_fields: &[&str] = if job.parent_job_id.is_some() {
        &[
            "schema_version",
            "kind",
            "parent_job_id",
            "retry_scope",
            "plan",
            "selections",
        ]
    } else {
        &["schema_version", "kind", "plan", "selections"]
    };
    if !has_exact_fields(object, expected_intent_fields) {
        return Err(HistoryError::UnsupportedFailedItems);
    }
    let record: FailedItemsRetryIntentRecord =
        serde_json::from_value(intent.clone()).map_err(|_| HistoryError::UnsupportedFailedItems)?;
    if record.schema_version != 1
        || record.kind != "nscb.copy_batch_intent"
        || record.parent_job_id != job.parent_job_id
        || record.retry_scope.as_deref() != job.parent_job_id.as_ref().map(|_| "failed_items")
    {
        return Err(HistoryError::UnsupportedFailedItems);
    }
    let plan_object = intent
        .get("plan")
        .and_then(serde_json::Value::as_object)
        .ok_or(HistoryError::UnsupportedFailedItems)?;
    if !has_exact_fields(
        plan_object,
        &[
            "kind",
            "nscb_version",
            "destination_directory",
            "workspace",
            "conflict_policy",
            "items",
        ],
    ) {
        return Err(HistoryError::UnsupportedFailedItems);
    }
    if record.plan.kind != "copy_batch_plan"
        || record.plan.nscb_version.is_empty()
        || !record.plan.destination_directory.is_absolute()
        || !record.plan.workspace.is_absolute()
        || record.plan.destination_directory != Path::new(&job.destination)
        || record.plan.workspace != Path::new(&job.workspace)
        || record.plan.conflict_policy != job.conflict_policy
        || record.plan.items.len() != job.items.len()
        || record.selections.len() != job.items.len()
    {
        return Err(HistoryError::UnsupportedFailedItems);
    }
    let plan_items = intent
        .get("plan")
        .and_then(|plan| plan.get("items"))
        .and_then(serde_json::Value::as_array)
        .ok_or(HistoryError::UnsupportedFailedItems)?;
    if plan_items.iter().any(|item| {
        !item.as_object().is_some_and(|item| {
            has_exact_fields(
                item,
                &["item_key", "source", "destination", "state", "failure_code"],
            )
        })
    }) {
        return Err(HistoryError::UnsupportedFailedItems);
    }

    let invocation_cwd = job
        .invocation_cwd
        .as_deref()
        .map(Path::new)
        .ok_or(HistoryError::UnsupportedFailedItems)?;
    let mut previous_sequence = None;
    let mut previous_selection_index = None;
    let mut successful_items = 0_usize;
    let mut failed_items = 0_usize;
    let mut cancelled = false;
    for (index, ((plan_item, item), raw_selection)) in plan_items
        .iter()
        .zip(&job.items)
        .zip(&record.selections)
        .enumerate()
    {
        let stored_plan_item = &record.plan.items[index];
        let destination_matches = match (
            stored_plan_item.destination.as_deref(),
            item.destination.as_deref(),
        ) {
            (Some(plan_destination), Some(item_destination)) => {
                same_retry_path(plan_destination, Path::new(item_destination))
            }
            (None, None) => true,
            _ => false,
        };
        if plan_item
            .get("item_key")
            .and_then(serde_json::Value::as_str)
            != Some(item.item_key.as_str())
            || record.plan.items[index].item_key != item.item_key
            || !same_retry_path(&record.plan.items[index].source, Path::new(&item.source))
            || !destination_matches
            || item.kind != "copy_through"
            || !Path::new(&item.source).is_absolute()
            || item.provenance.as_ref() != Some(raw_selection)
        {
            return Err(HistoryError::UnsupportedFailedItems);
        }
        let selection = parse_retry_selection(raw_selection)?;
        // Empty selection is a preflight-only failure. Reject it in every
        // validated authority so a saved destination, viable plan state, or
        // success-looking provenance cannot make the item eligible.
        let empty_selection = OperationFailureCode::EmptySelection.as_str();
        if item.failure_code.as_deref() == Some(empty_selection)
            || stored_plan_item.failure_code.as_deref() == Some(empty_selection)
            || selection.failure_code.as_deref() == Some(empty_selection)
        {
            return Err(HistoryError::UnsupportedFailedItems);
        }
        match item.destination.as_deref() {
            Some(destination)
                if Path::new(destination).is_absolute()
                    && Path::new(destination).parent()
                        == Some(record.plan.destination_directory.as_path()) => {}
            Some(_) | None => return Err(HistoryError::UnsupportedFailedItems),
        }
        if previous_selection_index.is_some_and(|previous| selection.selection_index < previous) {
            return Err(HistoryError::UnsupportedFailedItems);
        }
        previous_selection_index = Some(selection.selection_index);
        validate_retry_selection_paths(&record.plan.items[index], &selection, invocation_cwd)?;
        let sequence = item
            .checkpoint_sequence
            .ok_or(HistoryError::UnsupportedFailedItems)?;
        if previous_sequence.is_some_and(|previous| sequence <= previous) {
            return Err(HistoryError::UnsupportedFailedItems);
        }
        previous_sequence = Some(sequence);
        match item.state.as_str() {
            "succeeded" | "skipped" => {
                if item.state == "succeeded" {
                    successful_items += 1;
                }
                if item.outcome.is_none()
                    || item.failure_code.is_some()
                    || item.publication_state != "completed"
                {
                    return Err(HistoryError::UnsupportedFailedItems);
                }
            }
            "failed" => {
                failed_items += 1;
                if item.outcome.is_some()
                    || item.failure_code.is_none()
                    || item.publication_state != "not_completed"
                {
                    return Err(HistoryError::UnsupportedFailedItems);
                }
            }
            "cancelled" => {
                cancelled = true;
                if item.outcome.is_some()
                    || item.failure_code.is_none()
                    || item.publication_state != "not_completed"
                {
                    return Err(HistoryError::UnsupportedFailedItems);
                }
            }
            _ => return Err(HistoryError::UnsupportedFailedItems),
        }
        match record.plan.items[index].state {
            FailedItemsRetryPlanState::PreflightFailed => {
                if item.state != "failed"
                    || record.plan.items[index].failure_code.as_deref()
                        != item.failure_code.as_deref()
                    || !record.plan.items[index]
                        .failure_code
                        .as_deref()
                        .is_some_and(is_known_operation_failure_code)
                {
                    return Err(HistoryError::UnsupportedFailedItems);
                }
            }
            FailedItemsRetryPlanState::Viable => {
                if record.plan.items[index].failure_code.is_some() {
                    return Err(HistoryError::UnsupportedFailedItems);
                }
            }
        }
    }
    let expected_state = if cancelled {
        "cancelled"
    } else if failed_items == 0 {
        "succeeded"
    } else if successful_items == 0 {
        "failed"
    } else {
        "completed_with_issues"
    };
    if job.state != expected_state {
        return Err(HistoryError::UnsupportedFailedItems);
    }
    Ok(())
}

fn parse_retry_selection(
    value: &serde_json::Value,
) -> Result<FailedItemsRetrySelectionRecord, HistoryError> {
    let object = value
        .as_object()
        .ok_or(HistoryError::UnsupportedFailedItems)?;
    let is_failure = object.contains_key("requested_path");
    let has_split_qualification = object.contains_key("split_qualification");
    let expected_fields = if is_failure {
        &[
            "schema_version",
            "kind",
            "selection_index",
            "source",
            "selection_path",
            "base_directory",
            "input_list_entry_index",
            "input_list_entry_path",
            "discovered_directory",
            "discovered_relative_path",
            "requested_path",
            "failure_code",
            "phase",
        ][..]
    } else {
        &[
            "schema_version",
            "kind",
            "selection_index",
            "source",
            "selection_path",
            "base_directory",
            "input_list_entry_index",
            "input_list_entry_path",
            "discovered_directory",
            "discovered_relative_path",
        ][..]
    };
    if !expected_fields
        .iter()
        .all(|field| object.contains_key(*field))
        || object.len() != expected_fields.len() + usize::from(has_split_qualification)
        || (is_failure && has_split_qualification)
    {
        return Err(HistoryError::UnsupportedFailedItems);
    }
    let selection: FailedItemsRetrySelectionRecord =
        serde_json::from_value(value.clone()).map_err(|_| HistoryError::UnsupportedFailedItems)?;
    if selection.schema_version
        != crate::standalone::history::COPY_BATCH_ITEM_PROVENANCE_SCHEMA_VERSION
        || selection.kind != crate::standalone::history::COPY_BATCH_ITEM_PROVENANCE_KIND
        || selection.selection_path.as_os_str().is_empty()
        || selection.input_list_entry_index.is_some() != selection.input_list_entry_path.is_some()
        || (selection.source == FailedItemsRetrySelectionSource::Path
            && (selection.input_list_entry_index.is_some()
                || selection.input_list_entry_path.is_some()))
        || (is_failure
            && (selection.requested_path.is_none()
                || selection.failure_code.is_none()
                || selection.phase.as_deref() != Some("resolution")
                || selection.split_qualification.is_some()))
        || (!is_failure
            && (selection.requested_path.is_some()
                || selection.failure_code.is_some()
                || selection.phase.is_some()))
    {
        return Err(HistoryError::UnsupportedFailedItems);
    }
    Ok(selection)
}

fn validate_retry_selection_paths(
    plan_item: &FailedItemsRetryPlanItemRecord,
    selection: &FailedItemsRetrySelectionRecord,
    invocation_cwd: &Path,
) -> Result<(), HistoryError> {
    if !invocation_cwd.is_absolute() || !plan_item.source.is_absolute() {
        return Err(HistoryError::UnsupportedFailedItems);
    }
    let base_directory = match selection.base_directory.as_deref() {
        Some(base) if base.is_absolute() => base,
        Some(_) => return Err(HistoryError::UnsupportedFailedItems),
        None => return Err(HistoryError::UnsupportedFailedItems),
    };
    let selected_path = anchored_retry_path(base_directory, &selection.selection_path);
    let list_parent = selected_path
        .parent()
        .ok_or(HistoryError::UnsupportedFailedItems)?;
    let entry_path = selection
        .input_list_entry_path
        .as_ref()
        .map(|entry| anchored_retry_path(list_parent, entry));
    if selection.source == FailedItemsRetrySelectionSource::InputList
        && selection.input_list_entry_path.is_none()
    {
        return Err(HistoryError::UnsupportedFailedItems);
    }
    if let Some(failure_code) = selection.failure_code.as_deref()
        && !is_known_retry_selection_failure_code(failure_code)
    {
        return Err(HistoryError::UnsupportedFailedItems);
    }
    let expected_source = match (
        selection.discovered_directory.as_deref(),
        selection.discovered_relative_path.as_deref(),
    ) {
        (Some(directory), Some(relative))
            if directory.is_absolute() && is_relative_path(relative) =>
        {
            Some(directory.join(relative))
        }
        (None, None) => Some(entry_path.clone().unwrap_or(selected_path.clone())),
        _ => None,
    }
    .ok_or(HistoryError::UnsupportedFailedItems)?;
    match plan_item.state {
        FailedItemsRetryPlanState::PreflightFailed => match selection.failure_code.as_deref() {
            Some(selection_failure) => {
                let requested = selection
                    .requested_path
                    .as_deref()
                    .ok_or(HistoryError::UnsupportedFailedItems)?;
                let expected_plan_failure = match selection_failure {
                    "input_unavailable" => "source_unavailable",
                    "empty_selection" => "empty_selection",
                    _ => return Err(HistoryError::UnsupportedFailedItems),
                };
                if !requested.is_absolute()
                    || !same_retry_path(requested, &plan_item.source)
                    || !same_retry_path(requested, &expected_source)
                    || plan_item.failure_code.as_deref() != Some(expected_plan_failure)
                {
                    return Err(HistoryError::UnsupportedFailedItems);
                }
            }
            None => {
                if selection.requested_path.is_some()
                    || !same_retry_path(&plan_item.source, &expected_source)
                    || plan_item
                        .destination
                        .as_ref()
                        .and_then(|destination| destination.file_name())
                        != expected_source.file_name()
                {
                    return Err(HistoryError::UnsupportedFailedItems);
                }
                match plan_item.failure_code.as_deref() {
                    Some("split_input_unsupported") => {
                        let qualification = selection
                            .split_qualification
                            .as_ref()
                            .ok_or(HistoryError::UnsupportedFailedItems)?;
                        qualification.to_runtime()?;
                    }
                    Some(code) if is_retryable_operation_preflight_failure_code(code) => {
                        if selection.split_qualification.is_some() {
                            return Err(HistoryError::UnsupportedFailedItems);
                        }
                    }
                    _ => return Err(HistoryError::UnsupportedFailedItems),
                }
            }
        },
        FailedItemsRetryPlanState::Viable => {
            if selection.requested_path.is_some()
                || selection.failure_code.is_some()
                || selection.split_qualification.is_some()
                || plan_item.failure_code.is_some()
                || !same_retry_path(&plan_item.source, &expected_source)
            {
                return Err(HistoryError::UnsupportedFailedItems);
            }
        }
    }
    Ok(())
}

fn has_exact_fields(object: &serde_json::Map<String, serde_json::Value>, fields: &[&str]) -> bool {
    object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
}

fn anchored_retry_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn same_retry_path(left: &Path, right: &Path) -> bool {
    left == right
        || resolve_retry_path(left)
            .zip(resolve_retry_path(right))
            .is_some_and(|(left, right)| left == right)
}

fn resolve_retry_path(path: &Path) -> Option<PathBuf> {
    let mut existing_ancestor = path;
    let mut missing_components = Vec::<PathBuf>::new();
    loop {
        if let Ok(canonical_ancestor) = existing_ancestor.canonicalize() {
            let mut resolved = canonical_ancestor;
            for component in missing_components.iter().rev() {
                resolved.push(component);
            }
            return Some(resolved);
        }
        missing_components.push(PathBuf::from(existing_ancestor.file_name()?));
        existing_ancestor = existing_ancestor.parent()?;
    }
}

fn is_relative_path(path: &Path) -> bool {
    !path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
}

fn is_known_operation_failure_code(value: &str) -> bool {
    matches!(
        value,
        "empty_batch"
            | "empty_selection"
            | "duplicate_input"
            | "destination_collision"
            | "source_unavailable"
            | "split_input_unsupported"
            | "source_changed"
            | "stale_plan"
            | "workspace_unavailable"
            | "destination_unavailable"
            | "destination_conflict"
            | "destination_changed"
            | "unsafe_path"
            | "unsupported_capability"
            | "insufficient_storage"
            | "operation_session_busy"
            | "event_consumer_unavailable"
            | "operation_session_unavailable"
            | "cancelled"
            | "write_failed"
            | "staged_output_invalid"
            | "publication_failed"
            | "publication_uncertain"
            | "cleanup_incomplete"
            | "checkpoint_failed"
    )
}

fn is_retryable_operation_preflight_failure_code(value: &str) -> bool {
    matches!(
        value,
        "source_unavailable"
            | "source_changed"
            | "destination_unavailable"
            | "destination_conflict"
            | "destination_changed"
    )
}

fn is_known_retry_selection_failure_code(value: &str) -> bool {
    matches!(value, "input_unavailable" | "empty_selection")
}

struct DurableCheckpointResult<'a> {
    item_key: &'a str,
    source: &'a str,
    destination: Option<&'a str>,
    state: &'a str,
    outcome: Option<&'a str>,
    failure_code: Option<&'a str>,
    evidence: Option<&'a serde_json::Value>,
}

struct StoredCheckpointResult<'a> {
    item_state: Option<&'a str>,
    outcome: Option<&'a str>,
    failure_code: Option<&'a str>,
    publication_state: Option<&'a str>,
    sequence: Option<u64>,
    evidence: Option<&'a serde_json::Value>,
}

fn checkpoint_result_is_consistent(
    durable: &DurableCheckpointResult<'_>,
    checkpoint: &StoredCheckpointResult<'_>,
) -> bool {
    if checkpoint.item_state != Some(durable.state)
        || checkpoint.outcome != durable.outcome
        || checkpoint.failure_code != durable.failure_code
    {
        return false;
    }
    let (Some(durable_evidence), Some(checkpoint_evidence), Some(sequence)) =
        (durable.evidence, checkpoint.evidence, checkpoint.sequence)
    else {
        return false;
    };
    if durable_evidence != checkpoint_evidence
        || durable_evidence
            .get("sequence")
            .and_then(serde_json::Value::as_u64)
            != Some(sequence)
    {
        return false;
    }
    let Some(item) = durable_evidence
        .get("item")
        .and_then(serde_json::Value::as_object)
    else {
        return false;
    };
    let item_destination = match item.get("destination") {
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value)) => Some(value.as_str()),
        _ => return false,
    };
    if item.get("item_key").and_then(serde_json::Value::as_str) != Some(durable.item_key)
        || item.get("source").and_then(serde_json::Value::as_str) != Some(durable.source)
        || item_destination != durable.destination
        || item
            .get("state")
            .and_then(serde_json::Value::as_str)
            .and_then(checkpoint_history_state)
            != Some(durable.state)
    {
        return false;
    }
    let evidence_outcome = match item.get("outcome") {
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value)) => Some(value.as_str()),
        _ => return false,
    };
    if evidence_outcome != durable.outcome {
        return false;
    }
    let evidence_failure_code = match item.get("failure") {
        Some(serde_json::Value::Null) => None,
        Some(failure) => match failure.get("code").and_then(serde_json::Value::as_str) {
            Some(code) => Some(code),
            None => return false,
        },
        None => return false,
    };
    if evidence_failure_code != durable.failure_code {
        return false;
    }
    let Some(artifacts) = item.get("artifacts").and_then(serde_json::Value::as_array) else {
        return false;
    };
    let mut has_published_artifact = false;
    for artifact in artifacts {
        let Some(role) = artifact.get("role").and_then(serde_json::Value::as_str) else {
            return false;
        };
        has_published_artifact |= role == "published_destination";
    }
    let evidence_publication_state =
        if evidence_failure_code == Some(OperationFailureCode::PublicationUncertain.as_str()) {
            "uncertain"
        } else if evidence_outcome.is_some() {
            "completed"
        } else if has_published_artifact {
            "published_unresolved"
        } else {
            "not_completed"
        };
    checkpoint.publication_state == Some(evidence_publication_state)
}

fn checkpoint_history_state(value: &str) -> Option<&'static str> {
    match value {
        "preflight_failed" | "failed" => Some("failed"),
        "succeeded" => Some("succeeded"),
        "skipped" => Some("skipped"),
        "uncertain" => Some("uncertain"),
        "cancelled" => Some("cancelled"),
        "not_started" => Some("not_started"),
        _ => None,
    }
}

fn batch_item_history_state(state: CopyBatchItemState) -> &'static str {
    match state {
        CopyBatchItemState::PreflightFailed | CopyBatchItemState::Failed => "failed",
        CopyBatchItemState::Succeeded => "succeeded",
        CopyBatchItemState::Skipped => "skipped",
        CopyBatchItemState::Uncertain => "uncertain",
        CopyBatchItemState::Cancelled => "cancelled",
        CopyBatchItemState::NotStarted => "not_started",
        _ => "failed",
    }
}

fn classify_batch_publication(result: &CopyBatchResult) -> &'static str {
    let mut completed = false;
    let mut unresolved = false;
    for item in result.items() {
        if item
            .failure()
            .is_some_and(|failure| failure.code() == OperationFailureCode::PublicationUncertain)
            || item.state() == CopyBatchItemState::Uncertain
        {
            return "uncertain";
        }
        if item.outcome().is_some() {
            completed = true;
        }
        if item
            .artifacts()
            .iter()
            .any(|artifact| artifact.role() == OperationArtifactRole::PublishedDestination)
            && item.outcome().is_none()
        {
            unresolved = true;
        }
    }
    if unresolved {
        "published_unresolved"
    } else if completed {
        "completed"
    } else {
        "not_completed"
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
