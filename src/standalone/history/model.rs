//! Typed Job-history records and their stable serialized representations.

use nscb::{JobState, OperationOutcome};
use serde::Serialize;
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
    /// Reserved for Issue #13 independent-item execution. Stored records may
    /// use this value even though the current CLI cannot execute a batch.
    #[allow(dead_code)]
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
}

impl ConflictPolicyRecord {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Fail => "fail",
            Self::Replace => "replace",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConflictPolicyProvenance {
    Default,
    CliReplace,
    RetryDefault,
    RetryExplicitReplace,
}

impl ConflictPolicyProvenance {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::CliReplace => "cli_replace",
            Self::RetryDefault => "retry_default",
            Self::RetryExplicitReplace => "retry_explicit_replace",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RetryScope {
    All,
    /// Reserved for the future batch retry contract. Current copy Jobs reject
    /// this selection before admission.
    #[allow(dead_code)]
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
    pub(crate) destination: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionInput {
    pub(crate) kind: JobKind,
    pub(crate) submission_kind: SubmissionKind,
    pub(crate) invocation_cwd: PathBuf,
    pub(crate) source: PathBuf,
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
    pub(crate) destination: String,
    pub(crate) state: String,
    pub(crate) outcome: Option<String>,
    pub(crate) failure_code: Option<String>,
    pub(crate) evidence: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct JobDetail {
    pub(crate) job_id: String,
    pub(crate) parent_job_id: Option<String>,
    pub(crate) kind: String,
    pub(crate) submission_kind: String,
    pub(crate) state: String,
    pub(crate) invocation_cwd: Option<String>,
    pub(crate) source: String,
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

pub(crate) fn history_state(state: JobState) -> &'static str {
    match state {
        JobState::Succeeded => "succeeded",
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
