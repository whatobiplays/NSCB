//! Typed Job-history records and their stable serialized representations.

use nscb::{JobState, OperationOutcome, Sha256Digest, SplitQualification};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HistoryError {
    DirectoryUnavailable,
    OpenFailed,
    Corrupt,
    VersionUnsupported,
    MigrationFailed,
    BackupFailed,
    LockFailed,
    AdmissionFailed,
    CompletionFailed,
    QueryFailed,
    PathUnrepresentable,
    UnknownJob,
    ActiveJob,
    IneligibleJob,
    UnsupportedFailedItems,
    NoFailedItems,
}

impl HistoryError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::DirectoryUnavailable => "job_history_directory_unavailable",
            Self::OpenFailed => "job_history_unavailable",
            Self::Corrupt => "job_history_corrupt",
            Self::VersionUnsupported => "job_history_version_unsupported",
            Self::MigrationFailed => "job_history_migration_failed",
            Self::BackupFailed => "job_history_backup_failed",
            Self::LockFailed => "job_history_lock_failed",
            Self::AdmissionFailed => "job_history_admission_failed",
            Self::CompletionFailed => "job_history_completion_failed",
            Self::QueryFailed => "job_history_query_failed",
            Self::PathUnrepresentable => "job_history_path_unrepresentable",
            Self::UnknownJob => "job_not_found",
            Self::ActiveJob => "job_active",
            Self::IneligibleJob => "job_retry_ineligible",
            Self::UnsupportedFailedItems => "job_failed_items_unsupported",
            Self::NoFailedItems => "job_failed_items_empty",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum JobKind {
    CopyThrough,
}

impl JobKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::CopyThrough => "copy_through",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SubmissionKind {
    Single,
    /// A batch admitted as one Job with independently reported item results.
    IndependentBatch,
}

impl SubmissionKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::IndependentBatch => "independent_batch",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DestinationSelection {
    Explicit,
    ConfiguredOutputDirectory,
    NativeDocumentsOutput,
}

impl DestinationSelection {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::ConfiguredOutputDirectory => "configured_output_dir",
            Self::NativeDocumentsOutput => "native_documents_output",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WorkspaceSelection {
    Explicit,
    HostDefault,
}

impl WorkspaceSelection {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::HostDefault => "host_default",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConflictPolicyRecord {
    Fail,
    Replace,
    Skip,
}

impl ConflictPolicyRecord {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Fail => "fail",
            Self::Replace => "replace",
            Self::Skip => "skip",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConflictPolicyProvenance {
    Default,
    CliReplace,
    CliSkip,
    RetryDefault,
    RetryExplicitReplace,
    RetryExplicitSkip,
}

impl ConflictPolicyProvenance {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::CliReplace => "cli_replace",
            Self::CliSkip => "cli_skip",
            Self::RetryDefault => "retry_default",
            Self::RetryExplicitReplace => "retry_explicit_replace",
            Self::RetryExplicitSkip => "retry_explicit_skip",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RetryScope {
    All,
    /// A retry containing only eligible failed items from one independent batch.
    FailedItems,
}

impl RetryScope {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::FailedItems => "failed_items",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionItem {
    pub(crate) item_key: String,
    pub(crate) source: PathBuf,
    pub(crate) destination: Option<PathBuf>,
    pub(crate) provenance: Option<serde_json::Value>,
    pub(crate) split_qualification: Option<SplitQualification>,
    pub(crate) split_manifest_sha256: Option<Sha256Digest>,
}

/// Source intent for an independently admitted batch.
///
/// A batch has no single filesystem source. This tagged representation keeps
/// each logical item's source and resolver provenance together while leaving
/// `jobs.source` reserved for the single-copy contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BatchSourceIntent {
    pub(crate) schema_version: u64,
    pub(crate) kind: String,
    pub(crate) items: Vec<BatchSourceItemIntent>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BatchSourceItemIntent {
    pub(crate) item_key: String,
    pub(crate) source: String,
    pub(crate) provenance: serde_json::Value,
}

/// Version tag for the per-item resolver evidence stored with a batch Job.
pub(crate) const COPY_BATCH_ITEM_PROVENANCE_SCHEMA_VERSION: u64 = 1;
pub(crate) const COPY_BATCH_ITEM_PROVENANCE_KIND: &str = "nscb.copy_batch_item_provenance";
pub(crate) const LEGACY_UNQUALIFIED_ITEM_PROVENANCE_KIND: &str =
    "nscb.legacy_unqualified_copy_batch_item_provenance";

/// Marks pre-v4 batch items that lack enough evidence for exact retry.
pub(crate) fn legacy_unqualified_item_provenance() -> serde_json::Value {
    serde_json::json!({
        "schema_version": COPY_BATCH_ITEM_PROVENANCE_SCHEMA_VERSION,
        "kind": LEGACY_UNQUALIFIED_ITEM_PROVENANCE_KIND,
    })
}

impl BatchSourceIntent {
    const SCHEMA_VERSION: u64 = 1;
    const KIND: &'static str = "nscb.copy_batch_sources";
    const LEGACY_INCOMPLETE_KIND: &'static str = "nscb.legacy_unqualified_batch_sources";

    pub(crate) fn legacy_incomplete() -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            kind: Self::LEGACY_INCOMPLETE_KIND.to_owned(),
            items: Vec::new(),
        }
    }

    pub(crate) fn is_legacy_incomplete(&self) -> bool {
        self.schema_version == Self::SCHEMA_VERSION
            && self.kind == Self::LEGACY_INCOMPLETE_KIND
            && self.items.is_empty()
    }

    pub(crate) fn from_items(items: &[AdmissionItem]) -> Result<Self, HistoryError> {
        let items = items
            .iter()
            .map(|item| {
                if item.item_key.is_empty()
                    || !item.source.is_absolute()
                    || !item
                        .provenance
                        .as_ref()
                        .is_some_and(is_versioned_item_provenance)
                {
                    return Err(HistoryError::AdmissionFailed);
                }
                Ok(BatchSourceItemIntent {
                    item_key: item.item_key.clone(),
                    source: item
                        .source
                        .to_str()
                        .ok_or(HistoryError::PathUnrepresentable)?
                        .to_owned(),
                    provenance: item
                        .provenance
                        .clone()
                        .ok_or(HistoryError::AdmissionFailed)?,
                })
            })
            .collect::<Result<Vec<_>, HistoryError>>()?;
        let intent = Self {
            schema_version: Self::SCHEMA_VERSION,
            kind: Self::KIND.to_owned(),
            items,
        };
        intent
            .is_valid()
            .then_some(intent)
            .ok_or(HistoryError::AdmissionFailed)
    }

    /// Checks the tagged source-intent shape without consulting filesystem state.
    pub(crate) fn is_valid(&self) -> bool {
        if self.schema_version != Self::SCHEMA_VERSION
            || self.kind != Self::KIND
            || self.items.is_empty()
        {
            return false;
        }
        let mut item_keys = HashSet::with_capacity(self.items.len());
        self.items.iter().all(|item| {
            !item.item_key.is_empty()
                && PathBuf::from(&item.source).is_absolute()
                && is_versioned_item_provenance(&item.provenance)
                && item_keys.insert(item.item_key.as_str())
        })
    }

    /// Verifies that persisted item rows are the exact items named by this intent.
    pub(crate) fn matches_items(&self, items: &[JobItem]) -> bool {
        self.is_valid()
            && self.items.len() == items.len()
            && self.items.iter().zip(items).all(|(source_item, item)| {
                item.item_key == source_item.item_key
                    && item.source == source_item.source
                    && item.provenance.as_ref() == Some(&source_item.provenance)
            })
    }

    /// Verifies the parent-v4 batch source shape for read-only inspection.
    ///
    /// Schema v4 originally required each item's provenance to be a JSON
    /// object without requiring version tags. This compatibility check keeps
    /// those records inspectable while leaving [`Self::matches_items`] as the
    /// strict gate for retry and newly admitted batches.
    pub(crate) fn matches_legacy_unversioned_items(&self, items: &[JobItem]) -> bool {
        if self.schema_version != Self::SCHEMA_VERSION
            || self.kind != Self::KIND
            || self.items.is_empty()
            || self.items.len() != items.len()
        {
            return false;
        }

        let mut item_keys = HashSet::with_capacity(self.items.len());
        self.items.iter().zip(items).all(|(source_item, item)| {
            !source_item.item_key.is_empty()
                && PathBuf::from(&source_item.source).is_absolute()
                && is_legacy_unversioned_item_provenance(&source_item.provenance)
                && item_keys.insert(source_item.item_key.as_str())
                && item.item_key == source_item.item_key
                && item.source == source_item.source
                && item.provenance.as_ref() == Some(&source_item.provenance)
        })
    }
}

fn is_versioned_item_provenance(value: &serde_json::Value) -> bool {
    value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        == Some(COPY_BATCH_ITEM_PROVENANCE_SCHEMA_VERSION)
        && value.get("kind").and_then(serde_json::Value::as_str)
            == Some(COPY_BATCH_ITEM_PROVENANCE_KIND)
}

fn is_legacy_unversioned_item_provenance(value: &serde_json::Value) -> bool {
    value.as_object().is_some_and(|provenance| {
        !provenance.contains_key("schema_version") && !provenance.contains_key("kind")
    })
}

/// Compile-time distinction between a single filesystem source and an
/// independent batch's per-item source intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionSource {
    Single(PathBuf),
    IndependentBatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionInput {
    pub(crate) kind: JobKind,
    pub(crate) submission_kind: SubmissionKind,
    pub(crate) invocation_cwd: PathBuf,
    pub(crate) source: AdmissionSource,
    pub(crate) destination: PathBuf,
    pub(crate) destination_selection: DestinationSelection,
    pub(crate) workspace: PathBuf,
    pub(crate) workspace_selection: WorkspaceSelection,
    pub(crate) conflict_policy: ConflictPolicyRecord,
    pub(crate) conflict_policy_provenance: ConflictPolicyProvenance,
    pub(crate) parent_conflict_policy: Option<ConflictPolicyRecord>,
    pub(crate) parent_conflict_policy_provenance: Option<ConflictPolicyProvenance>,
    pub(crate) parent_job_id: Option<String>,
    pub(crate) retry_scope: RetryScope,
    pub(crate) required_providers: Vec<String>,
    pub(crate) required_keys: Vec<String>,
    pub(crate) items: Vec<AdmissionItem>,
    pub(crate) batch_intent: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct JobSummary {
    pub(crate) job_id: String,
    pub(crate) parent_job_id: Option<String>,
    pub(crate) kind: String,
    pub(crate) state: String,
    pub(crate) admitted_at: String,
    pub(crate) terminal_at: Option<String>,
    pub(crate) outcome: Option<String>,
    pub(crate) failure_code: Option<String>,
    pub(crate) publication_state: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct JobItem {
    pub(crate) item_key: String,
    pub(crate) kind: String,
    pub(crate) source: String,
    pub(crate) destination: Option<String>,
    pub(crate) state: String,
    pub(crate) outcome: Option<String>,
    pub(crate) failure_code: Option<String>,
    pub(crate) evidence: Option<serde_json::Value>,
    pub(crate) provenance: Option<serde_json::Value>,
    pub(crate) publication_state: String,
    pub(crate) checkpoint_sequence: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct JobDetail {
    pub(crate) job_id: String,
    pub(crate) parent_job_id: Option<String>,
    pub(crate) kind: String,
    pub(crate) submission_kind: String,
    pub(crate) state: String,
    pub(crate) invocation_cwd: Option<String>,
    pub(crate) source: Option<String>,
    pub(crate) batch_source_intent: Option<BatchSourceIntent>,
    pub(crate) destination: String,
    pub(crate) destination_selection: String,
    pub(crate) workspace: String,
    pub(crate) workspace_selection: String,
    pub(crate) conflict_policy: String,
    pub(crate) conflict_policy_provenance: String,
    pub(crate) parent_conflict_policy: Option<String>,
    pub(crate) parent_conflict_policy_provenance: Option<String>,
    pub(crate) retry_scope: String,
    pub(crate) admitted_at: String,
    pub(crate) started_at: Option<String>,
    pub(crate) terminal_at: Option<String>,
    pub(crate) outcome: Option<String>,
    pub(crate) failure_code: Option<String>,
    pub(crate) cleanup_warning_code: Option<String>,
    pub(crate) publication_state: String,
    pub(crate) required_providers: Vec<String>,
    pub(crate) required_keys: Vec<String>,
    pub(crate) snapshot: Option<serde_json::Value>,
    pub(crate) result: Option<serde_json::Value>,
    pub(crate) batch_intent: Option<serde_json::Value>,
    pub(crate) items: Vec<JobItem>,
}

/// Validated intent needed to create a new Copy Job from a terminal Job.
///
/// Raw persisted strings never flow directly into retry planning. The history
/// boundary rejects unsupported Job kinds, batch submission, unsafe retry
/// scopes, invalid enum values, and missing invocation context before the CLI
/// resolves current destination configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetryIntent {
    pub(crate) job_id: String,
    pub(crate) invocation_cwd: PathBuf,
    pub(crate) source: PathBuf,
    pub(crate) destination: PathBuf,
    pub(crate) destination_selection: DestinationSelection,
    pub(crate) workspace: PathBuf,
    pub(crate) workspace_selection: WorkspaceSelection,
    pub(crate) conflict_policy: ConflictPolicyRecord,
    pub(crate) conflict_policy_provenance: ConflictPolicyProvenance,
}

/// Validated exact failed-item retry intent for an independently admitted batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BatchFailedItemsRetryIntent {
    pub(crate) job_id: String,
    pub(crate) invocation_cwd: PathBuf,
    pub(crate) destination: PathBuf,
    pub(crate) destination_selection: DestinationSelection,
    pub(crate) workspace: PathBuf,
    pub(crate) workspace_selection: WorkspaceSelection,
    pub(crate) conflict_policy: ConflictPolicyRecord,
    pub(crate) conflict_policy_provenance: ConflictPolicyProvenance,
    pub(crate) items: Vec<AdmissionItem>,
    pub(crate) batch_intent: serde_json::Value,
}

pub(crate) fn history_state(state: JobState) -> &'static str {
    match state {
        JobState::Succeeded => "succeeded",
        JobState::CompletedWithIssues => "completed_with_issues",
        JobState::Failed => "failed",
        JobState::Cancelled => "cancelled",
        _ => "failed",
    }
}

pub(crate) fn item_state(job_state: &str) -> &'static str {
    match job_state {
        "succeeded" => "succeeded",
        "completed_with_issues" => "completed_with_issues",
        "cancelled" => "cancelled",
        "interrupted" => "interrupted",
        _ => "failed",
    }
}

pub(crate) fn operation_outcome(outcome: OperationOutcome) -> &'static str {
    match outcome {
        OperationOutcome::Copied => "copied",
        OperationOutcome::AlreadyUpToDate => "already_up_to_date",
        OperationOutcome::Skipped => "skipped",
        _ => "unknown",
    }
}

pub(crate) fn decode_json_column(
    value: Option<String>,
    column: usize,
) -> Result<Option<serde_json::Value>, rusqlite::Error> {
    value
        .map(|value| {
            serde_json::from_str(&value).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    column,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })
        .transpose()
}
