//! English presentation strings for the standalone command-line adapter.

use nscb::{
    ContainerProbeErrorCode, InputResolutionErrorCode, InputResolutionResult, InspectionErrorCode,
    JobState, NcaContentType, NcaDistribution, NcaInspection, OperationFailureCode,
    OperationOutcome, OperationResult, VerificationErrorCode, VerificationLimitation,
    VerificationProfile, VerificationResult,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Deserialize)]
struct Messages {
    usage: String,
    recognition: String,
    recognition_usage: String,
    input_resolution_usage: String,
    input_resolution_success: String,
    input_resolution_errors: HashMap<String, String>,
    recognition_errors: HashMap<String, String>,
    success: SuccessMessages,
    output_failure: String,
    errors: HashMap<String, String>,
}

#[derive(Deserialize)]
struct SuccessMessages {
    one: String,
    other: String,
}

#[derive(Deserialize)]
struct InspectionMessages {
    usage: String,
    preflight_ready: String,
    preflight_provisioning_required: String,
    preflight_unknown: String,
    unsupported_result: String,
    result: String,
    partition: String,
    entry: String,
    content_program: String,
    distribution_game_card: String,
    distribution_download: String,
    errors: HashMap<String, String>,
}

fn messages() -> &'static Messages {
    static MESSAGES: OnceLock<Messages> = OnceLock::new();
    MESSAGES.get_or_init(|| {
        serde_json::from_str(include_str!("../../locales/en.json"))
            .expect("bundled English CLI localization resource must be valid")
    })
}

fn inspection_messages() -> &'static InspectionMessages {
    static MESSAGES: OnceLock<InspectionMessages> = OnceLock::new();
    MESSAGES.get_or_init(|| {
        serde_json::from_str(include_str!("inspection.en.json"))
            .expect("bundled English Inspection localization resource must be valid")
    })
}

#[derive(Deserialize)]
struct VerificationMessages {
    usage: String,
    passed: String,
    failed: String,
    limitations: String,
    profile_full: String,
    profile_structural: String,
    signatures_not_checked: String,
    hash_checks_not_run: String,
    payload_integrity_not_available: String,
    npdm_acid_authenticity_unverified: String,
    authenticity_not_established: String,
    device_write_authorization_not_evaluated: String,
    errors: HashMap<String, String>,
}

fn verification_messages() -> &'static VerificationMessages {
    static MESSAGES: OnceLock<VerificationMessages> = OnceLock::new();
    MESSAGES.get_or_init(|| {
        serde_json::from_str(include_str!("verification.en.json"))
            .expect("bundled English Verification localization resource must be valid")
    })
}

#[derive(Deserialize)]
struct CopyMessages {
    usage: String,
    succeeded_copied: String,
    succeeded_already_up_to_date: String,
    cancelled: String,
    failed: String,
    cleanup_warning: String,
    cleanup_artifacts_heading: String,
    signal_failure: String,
    internal_failure: String,
    unknown_error: String,
    errors: HashMap<String, String>,
}

fn copy_messages() -> &'static CopyMessages {
    static MESSAGES: OnceLock<CopyMessages> = OnceLock::new();
    MESSAGES.get_or_init(|| {
        serde_json::from_str(include_str!("copy.en.json"))
            .expect("bundled English copy-through localization resource must be valid")
    })
}

pub(crate) fn copy_usage() -> &'static str {
    &copy_messages().usage
}

pub(crate) fn copy_error_message(code: &str) -> &'static str {
    let messages = copy_messages();
    messages
        .errors
        .get(code)
        .map(String::as_str)
        .unwrap_or(&messages.unknown_error)
}

pub(crate) fn copy_error(code: OperationFailureCode) -> &'static str {
    copy_error_message(code.as_str())
}

pub(crate) fn copy_signal_failure() -> &'static str {
    &copy_messages().signal_failure
}

pub(crate) fn copy_internal_failure() -> &'static str {
    &copy_messages().internal_failure
}

/// Formats a human copy result and, when cleanup evidence is retained, lists
/// complete artifact records so a user can reconcile their paths and identities.
pub(crate) fn copy_result(result: &OperationResult) -> String {
    let messages = copy_messages();
    let mut message = match result.state() {
        JobState::Succeeded => match result.outcome() {
            Some(OperationOutcome::AlreadyUpToDate) => {
                messages.succeeded_already_up_to_date.clone()
            }
            _ => messages.succeeded_copied.clone(),
        },
        JobState::Cancelled => messages.cancelled.clone(),
        JobState::Failed => messages.failed.replace(
            "{code}",
            result
                .failure()
                .map(|failure| copy_error(failure.code()))
                .unwrap_or(&messages.internal_failure),
        ),
        _ => messages.unknown_error.clone(),
    };
    if result.cleanup_artifact_retained() {
        message.push(' ');
        message.push_str(&messages.cleanup_warning);
        message.push('\n');
        message.push_str(&messages.cleanup_artifacts_heading);
        for artifact in result.artifacts() {
            message.push_str("\n  artifact: ");
            match serde_json::to_string(artifact) {
                Ok(record) => message.push_str(&record),
                Err(_) => message.push_str(&format!("{artifact:?}")),
            }
        }
    }
    message
}

pub(crate) fn inspection_usage() -> &'static str {
    &inspection_messages().usage
}

pub(crate) fn inspection_preflight_ready() -> &'static str {
    &inspection_messages().preflight_ready
}

pub(crate) fn inspection_preflight_provisioning_required() -> &'static str {
    &inspection_messages().preflight_provisioning_required
}

pub(crate) fn inspection_preflight_unknown() -> &'static str {
    &inspection_messages().preflight_unknown
}

pub(crate) fn inspection_unsupported_result() -> &'static str {
    &inspection_messages().unsupported_result
}

pub(crate) fn inspection_error(code: InspectionErrorCode) -> &'static str {
    inspection_messages()
        .errors
        .get(code.as_str())
        .expect("every Inspection error code must have an English CLI message")
}

pub(crate) fn inspection_result(result: &NcaInspection) -> String {
    let messages = inspection_messages();
    let content_type = match result.content_type {
        NcaContentType::Program => &messages.content_program,
        _ => &messages.content_program,
    };
    let distribution = match result.distribution {
        NcaDistribution::GameCard => &messages.distribution_game_card,
        NcaDistribution::Download => &messages.distribution_download,
        _ => &messages.distribution_download,
    };
    let mut output = messages
        .result
        .replace("{content_type}", content_type)
        .replace("{distribution}", distribution)
        .replace("{program_id}", &result.program_id.to_hex())
        .replace("{key_generation}", &result.key_generation.to_string())
        .replace(
            "{signature_generation}",
            &result.signature_generation.to_string(),
        )
        .replace("{size}", &result.declared_size.to_string());
    for partition in &result.partitions {
        output.push('\n');
        output.push_str(
            &messages
                .partition
                .replace("{index}", &partition.index.to_string())
                .replace("{size}", &partition.size.to_string())
                .replace("{offset}", &format!("{:x}", partition.offset))
                .replace("{entry_count}", &partition.entries.len().to_string()),
        );
        for entry in &partition.entries {
            output.push('\n');
            output.push_str(
                &messages
                    .entry
                    .replace("{path}", &entry.path)
                    .replace("{size}", &entry.size.to_string()),
            );
        }
    }
    output
}

pub(crate) fn usage() -> &'static str {
    &messages().usage
}

pub(crate) fn success(entry_count: usize, payload_offset: u64) -> String {
    let template = if entry_count == 1 {
        &messages().success.one
    } else {
        &messages().success.other
    };
    template
        .replace("{entry_count}", &entry_count.to_string())
        .replace("{payload_offset}", &payload_offset.to_string())
}

pub(crate) fn error_message(code: ContainerProbeErrorCode) -> &'static str {
    messages()
        .errors
        .get(code.as_str())
        .expect("every Container Probe error code must have an English CLI message")
}

pub(crate) fn output_failure() -> &'static str {
    &messages().output_failure
}

/// Renders sanitized recognition facts with bundled presentation text.
pub(crate) fn recognition(result: &nscb::ContentRecognitionResult) -> String {
    let value = serde_json::to_value(result).expect("recognition facts serialize");
    messages()
        .recognition
        .replace(
            "{outcome}",
            value["recognition"]["outcome"]
                .as_str()
                .unwrap_or("unknown"),
        )
        .replace(
            "{family}",
            value["recognition"]["family"]
                .as_str()
                .unwrap_or("not_established"),
        )
        .replace(
            "{compression}",
            value["recognition"]["compression_variant"]
                .as_str()
                .unwrap_or("not_established"),
        )
        .replace(
            "{eligibility}",
            value["package_structure_eligibility"]
                .as_str()
                .unwrap_or("not_established"),
        )
        .replace(
            "{extension}",
            value["extension_observation"]
                .as_str()
                .unwrap_or("unrecognized"),
        )
}
/// Returns a localized sanitized recognition error.
pub(crate) fn recognition_error(code: nscb::ContentRecognitionErrorCode) -> &'static str {
    messages()
        .recognition_errors
        .get(code.as_str())
        .expect("recognition error message")
}

/// Renders the number of logical inputs and physical segments resolved.
pub(crate) fn input_resolution_success(result: &InputResolutionResult) -> String {
    let segment_count: usize = result.inputs.iter().map(|input| input.segments.len()).sum();
    messages()
        .input_resolution_success
        .replace("{input_count}", &result.inputs.len().to_string())
        .replace("{segment_count}", &segment_count.to_string())
}

/// Returns a sanitized English message for an input-resolution error.
pub(crate) fn input_resolution_error(code: InputResolutionErrorCode) -> &'static str {
    messages()
        .input_resolution_errors
        .get(code.as_str())
        .expect("every input-resolution error code must have an English CLI message")
}

/// Returns the input-resolution command syntax.
pub(crate) fn input_resolution_usage() -> &'static str {
    &messages().input_resolution_usage
}

pub(crate) fn recognition_usage() -> &'static str {
    &messages().recognition_usage
}

/// Returns the Verification command syntax.
pub(crate) fn verification_usage() -> &'static str {
    &verification_messages().usage
}

/// Returns the localized message for one Verification failure category.
pub(crate) fn verification_error(code: VerificationErrorCode) -> &'static str {
    verification_messages()
        .errors
        .get(code.as_str())
        .expect("every Verification error code must have an English CLI message")
}

/// Formats one completed Verification for human readers.
///
/// The limitations line is always present so a passing Full result cannot be
/// read as proof of payload integrity, authenticity, or device-write
/// authorization.
pub(crate) fn verification_result(result: &VerificationResult) -> String {
    let messages = verification_messages();
    let profile = match result.profile {
        VerificationProfile::Full => &messages.profile_full,
        VerificationProfile::Structural => &messages.profile_structural,
        _ => &messages.profile_full,
    };
    let required = result
        .checks
        .iter()
        .filter(|check| check.outcome == nscb::CheckOutcome::Passed)
        .count();
    let not_applicable = result
        .checks
        .iter()
        .filter(|check| check.outcome == nscb::CheckOutcome::NotApplicable)
        .count();
    let failures = result
        .checks
        .iter()
        .filter(|check| check.outcome == nscb::CheckOutcome::Failed)
        .map(|check| match check.partition {
            Some(partition) => format!("{} (partition {partition})", check.id.as_str()),
            None => check.id.as_str().to_owned(),
        })
        .collect::<Vec<_>>()
        .join(", ");
    let message = if failures.is_empty() {
        messages
            .passed
            .replace("{profile}", profile)
            .replace("{required}", &required.to_string())
            .replace("{not_applicable}", &not_applicable.to_string())
    } else {
        messages
            .failed
            .replace("{profile}", profile)
            .replace("{failures}", &failures)
    };
    let limitations = result
        .limitations
        .iter()
        .map(|limitation| {
            let text = match limitation {
                VerificationLimitation::SignaturesNotChecked => &messages.signatures_not_checked,
                VerificationLimitation::HashChecksNotRun => &messages.hash_checks_not_run,
                VerificationLimitation::PayloadIntegrityNotAvailable => {
                    &messages.payload_integrity_not_available
                }
                VerificationLimitation::NpdmAcidAuthenticityUnverified => {
                    &messages.npdm_acid_authenticity_unverified
                }
                VerificationLimitation::AuthenticityNotEstablished => {
                    &messages.authenticity_not_established
                }
                VerificationLimitation::DeviceWriteAuthorizationNotEvaluated => {
                    &messages.device_write_authorization_not_evaluated
                }
                _ => &messages.authenticity_not_established,
            };
            text.as_str()
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "{message}\n{}",
        messages.limitations.replace("{limitations}", &limitations)
    )
}

#[derive(Deserialize)]
struct StandaloneConfigMessages {
    global_help: String,
    global_version: String,
    config_usage: String,
    config_path: String,
    config_show_header: String,
    config_show_value: String,
    config_updated: String,
    config_reset: String,
    keys_usage: String,
    keys_set: String,
    keys_errors: HashMap<String, String>,
    config_errors: HashMap<String, String>,
}

fn standalone_config_messages() -> &'static StandaloneConfigMessages {
    static MESSAGES: OnceLock<StandaloneConfigMessages> = OnceLock::new();
    MESSAGES.get_or_init(|| {
        serde_json::from_str(include_str!("config.en.json"))
            .expect("bundled English standalone-configuration resource must be valid")
    })
}

pub(crate) fn global_help() -> &'static str {
    &standalone_config_messages().global_help
}

pub(crate) fn global_version(version: &str) -> String {
    standalone_config_messages()
        .global_version
        .replace("{version}", version)
}

pub(crate) fn config_usage() -> &'static str {
    &standalone_config_messages().config_usage
}

pub(crate) fn config_path(path: &str) -> String {
    standalone_config_messages()
        .config_path
        .replace("{path}", path)
}

pub(crate) fn config_show_header(path: &str, schema_version: i64) -> String {
    let schema_version = schema_version.to_string();
    interpolate(
        &standalone_config_messages().config_show_header,
        &[("path", path), ("schema_version", &schema_version)],
    )
}

/// Replaces named placeholders while scanning only the original template.
///
/// Each value is copied directly into the output, so braces or placeholder-like
/// text in a substituted value remain literal instead of being interpreted by
/// a later replacement pass.
fn interpolate(template: &str, replacements: &[(&str, &str)]) -> String {
    let mut rendered = String::with_capacity(template.len());
    let mut cursor = 0;

    while cursor < template.len() {
        let Some(relative_open) = template[cursor..].find('{') else {
            rendered.push_str(&template[cursor..]);
            break;
        };
        let open = cursor + relative_open;
        rendered.push_str(&template[cursor..open]);

        let Some(relative_close) = template[open + 1..].find('}') else {
            rendered.push_str(&template[open..]);
            break;
        };
        let close = open + 1 + relative_close;
        let key = &template[open + 1..close];
        if let Some((_, value)) = replacements
            .iter()
            .find(|(placeholder, _)| *placeholder == key)
        {
            rendered.push_str(value);
        } else {
            rendered.push_str(&template[open..=close]);
        }
        cursor = close + 1;
    }

    rendered
}

pub(crate) fn config_show_value(name: &str, value: &str, source: &str) -> String {
    interpolate(
        &standalone_config_messages().config_show_value,
        &[("name", name), ("value", value), ("source", source)],
    )
}

pub(crate) fn config_updated(path: &str, name: &str, value: &str) -> String {
    interpolate(
        &standalone_config_messages().config_updated,
        &[("path", path), ("name", name), ("value", value)],
    )
}

pub(crate) fn config_reset(path: &str) -> String {
    standalone_config_messages()
        .config_reset
        .replace("{path}", path)
}

pub(crate) fn keys_usage() -> &'static str {
    &standalone_config_messages().keys_usage
}

pub(crate) fn keys_set(path: &str) -> String {
    standalone_config_messages()
        .keys_set
        .replace("{path}", path)
}

pub(crate) fn keys_error(code: &str) -> &str {
    standalone_config_messages()
        .keys_errors
        .get(code)
        .map(String::as_str)
        .unwrap_or("The key-file update failed.")
}

pub(crate) fn config_error(code: &str) -> &str {
    standalone_config_messages()
        .config_errors
        .get(code)
        .map(String::as_str)
        .unwrap_or("The standalone configuration operation failed.")
}

#[cfg(test)]
mod tests {
    use super::{error_message, success, usage};
    use nscb::{ContainerProbeErrorCode as Code, InputResolutionErrorCode as InputCode};

    #[test]
    fn interpolation_scans_only_the_original_template() {
        assert_eq!(
            super::interpolate(
                " {name} = {value} ({source})",
                &[
                    ("name", "translation.note"),
                    ("value", "{source}"),
                    ("source", "file"),
                ],
            ),
            " translation.note = {source} (file)"
        );
        assert_eq!(
            super::interpolate("{known} {unknown} {unclosed", &[("known", "value")]),
            "value {unknown} {unclosed"
        );
        assert_eq!(super::interpolate("plain", &[]), "plain");
    }

    #[test]
    fn copy_error_uses_localized_fallback_for_an_unknown_code() {
        assert_eq!(
            super::copy_error_message("future_unknown_code"),
            "An unrecognized operation failure occurred."
        );
    }

    #[test]
    fn resource_contains_a_message_for_every_stable_error_code() {
        let codes = [
            Code::UnsupportedFormat,
            Code::TruncatedInput,
            Code::InvalidHeader,
            Code::InvalidStringTable,
            Code::InvalidEntry,
            Code::LimitExceeded,
            Code::NameTooLong,
            Code::InputUnavailable,
            Code::ResourceLimitExceeded,
        ];

        for code in codes {
            assert!(
                !error_message(code).is_empty(),
                "missing message for {code:?}"
            );
        }
    }

    #[test]
    fn resource_formats_singular_and_plural_success_messages() {
        assert_eq!(
            success(1, 46),
            "PFS0 container probe found one entry; payload begins at byte 46."
        );
        assert_eq!(
            success(2, 64),
            "PFS0 container probe found 2 entries; payload begins at byte 64."
        );
    }

    #[test]
    fn resource_contains_a_message_for_every_input_resolution_error_code() {
        let codes = [
            InputCode::EmptySelection,
            InputCode::InputUnavailable,
            InputCode::UnsupportedFilesystemEntry,
            InputCode::UnsupportedSplitLayout,
            InputCode::InvalidInputList,
            InputCode::UnsupportedInputListVersion,
            InputCode::UnsupportedRequiredFeature,
            InputCode::DuplicateSelection,
            InputCode::ResourceLimitExceeded,
            InputCode::InvalidBaseDirectory,
            InputCode::UnrepresentablePath,
            InputCode::SplitManifestMissing,
            InputCode::SplitEvidenceUntrusted,
            InputCode::SplitManifestInvalid,
            InputCode::SplitManifestVersionUnsupported,
            InputCode::SplitSetIncomplete,
            InputCode::SplitIntegrityMismatch,
            InputCode::SplitInputChanged,
            InputCode::SplitStateUnavailable,
            InputCode::SplitTrustStoreConfigurationInvalid,
            InputCode::SplitResolutionCancelled,
        ];

        for code in codes {
            assert!(
                !super::input_resolution_error(code).is_empty(),
                "missing message for {code:?}"
            );
        }
    }

    #[test]
    fn input_resolution_success_formats_counts_and_usage_documents_the_command() {
        use nscb::{Engine, InputResolutionRequest};
        use std::time::{SystemTime, UNIX_EPOCH};

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "nscb-input-message-{}-{suffix}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("item.bin"), b"x").unwrap();
        let result = Engine::new()
            .resolve_inputs(InputResolutionRequest::new(directory.clone()).with_path("item.bin"))
            .unwrap();
        let _ = std::fs::remove_dir_all(directory);

        assert_eq!(
            super::input_resolution_success(&result),
            "Resolved 1 logical input(s) across 1 physical segment(s)."
        );
        assert!(super::input_resolution_usage().contains("--input-list"));
    }

    #[test]
    fn resource_provides_cli_usage() {
        assert_eq!(usage(), "Usage: nscb probe <path> [--json]");
    }

    #[test]
    fn inspection_resource_has_a_message_for_every_stable_error_code() {
        use nscb::InspectionErrorCode as InspectionCode;
        let codes = [
            InspectionCode::InvalidCacheDirectory,
            InspectionCode::InvalidKeyPath,
            InspectionCode::InputUnavailable,
            InspectionCode::UnsupportedFormat,
            InspectionCode::UnsupportedInspectionProfile,
            InspectionCode::TruncatedInput,
            InspectionCode::MalformedInput,
            InspectionCode::InputLimitExceeded,
            InspectionCode::KeyFileUnavailable,
            InspectionCode::KeyFileMalformed,
            InspectionCode::KeyFileLimitExceeded,
            InspectionCode::MissingHeaderKey,
            InspectionCode::ProviderCacheMissing,
            InspectionCode::ProviderArtifactMismatch,
            InspectionCode::ProviderArtifactIncomplete,
            InspectionCode::ProviderArchiveInvalid,
            InspectionCode::ProviderUnsupportedTarget,
            InspectionCode::ProviderUnqualifiedTarget,
            InspectionCode::ProviderContainmentUnsupported,
            InspectionCode::PhysicalFootprintMonitoringUnsupported,
            InspectionCode::ProvisioningDenied,
            InspectionCode::ProvisioningFailed,
            InspectionCode::InputChangedDuringInspection,
            InspectionCode::KeyFileChangedDuringInspection,
            InspectionCode::ProviderCacheBusy,
            InspectionCode::ProviderExecutionBusy,
            InspectionCode::ProviderLaunchFailed,
            InspectionCode::ProviderExitedUnsuccessfully,
            InspectionCode::ProviderCrashed,
            InspectionCode::ProviderTimedOut,
            InspectionCode::ProviderOutputExceeded,
            InspectionCode::ProviderOutputMalformed,
            InspectionCode::ProviderContentUnreadable,
            InspectionCode::ProviderPostconditionMismatch,
            InspectionCode::ProviderInconsistent,
            InspectionCode::Cancelled,
            InspectionCode::ProviderManifestInvalid,
            InspectionCode::CacheLockFailed,
            InspectionCode::CacheCleanupFailed,
            InspectionCode::AllocationFailed,
            InspectionCode::InternalIo,
            InspectionCode::SignalHandlerFailed,
        ];
        for code in codes {
            assert!(
                !super::inspection_error(code).is_empty(),
                "missing message for {code:?}"
            );
        }
        assert_eq!(
            super::inspection_error(InspectionCode::ProviderExecutionBusy),
            "This inspection host session already has an active provider execution."
        );
    }

    #[test]
    fn inspection_human_output_is_localized_and_contains_only_normalized_facts() {
        use nscb::{InspectionEntry, NcaPartition, ProgramId};
        let result = nscb::NcaInspection {
            format_version: 3,
            distribution: nscb::NcaDistribution::GameCard,
            content_type: nscb::NcaContentType::Program,
            key_generation: 0,
            signature_generation: 5,
            program_id: ProgramId::from_u64(0x0102_0304_0506_0708),
            content_index: 0,
            declared_size: 0xe00,
            partitions: vec![NcaPartition {
                index: 0,
                offset: 0xc00,
                size: 0x200,
                filesystem: nscb::NcaFilesystem::PartitionFs,
                hash_type: nscb::NcaHashType::None,
                encryption: nscb::NcaEncryptionType::None,
                entries: vec![InspectionEntry {
                    path: "0/hello.nca".to_owned(),
                    size: 4,
                }],
            }],
        };
        let output = super::inspection_result(&result);
        assert!(output.contains("program ID 0102030405060708"));
        assert!(output.contains("signature generation 5"));
        assert!(output.contains("Partition 0: PartitionFs"));
        assert!(output.contains("0/hello.nca (4 bytes)"));
        assert!(!output.contains("NSTool"));
    }

    #[test]
    fn inspection_usage_documents_human_and_json_invocation() {
        let usage = super::inspection_usage();
        assert!(usage.contains("nscb inspect <path> [--keys <path>]"));
        assert!(usage.contains("[--preflight]"));
        assert!(usage.contains("[--json]"));
    }

    #[test]
    fn resource_contains_a_message_for_every_verification_error_code() {
        use nscb::VerificationErrorCode as VerificationCode;
        let codes = [
            VerificationCode::InvalidKeyPath,
            VerificationCode::InputUnavailable,
            VerificationCode::UnsupportedFormat,
            VerificationCode::TruncatedInput,
            VerificationCode::MalformedInput,
            VerificationCode::InputLimitExceeded,
            VerificationCode::KeyFileUnavailable,
            VerificationCode::KeyFileMalformed,
            VerificationCode::KeyFileLimitExceeded,
            VerificationCode::MissingHeaderKey,
            VerificationCode::MissingTrustAnchor,
            VerificationCode::MissingAnchorGeneration,
            VerificationCode::TrustAnchorUnavailable,
            VerificationCode::TrustAnchorMalformed,
            VerificationCode::TrustAnchorLimitExceeded,
            VerificationCode::AnchorNotApplicable,
            VerificationCode::InputChangedDuringVerification,
            VerificationCode::KeyFileChangedDuringVerification,
            VerificationCode::TrustAnchorChangedDuringVerification,
            VerificationCode::Cancelled,
            VerificationCode::AllocationFailed,
            VerificationCode::InternalIo,
            VerificationCode::SignalHandlerFailed,
        ];
        for code in codes {
            assert!(
                !super::verification_error(code).is_empty(),
                "missing message {code:?}"
            );
        }
        let usage = super::verification_usage();
        assert!(usage.contains("nscb verify <input>"));
        assert!(usage.contains("[--profile full|structural]"));
        assert!(usage.contains("[--trust-anchor <path> --anchor-generation <n>]"));
    }

    #[test]
    fn verification_human_output_states_every_required_limitation() {
        let result = nscb::VerificationResult {
            profile: nscb::VerificationProfile::Full,
            outcome: nscb::VerificationOutcome::Passed,
            checks: Vec::new(),
            limitations: vec![
                nscb::VerificationLimitation::PayloadIntegrityNotAvailable,
                nscb::VerificationLimitation::NpdmAcidAuthenticityUnverified,
                nscb::VerificationLimitation::AuthenticityNotEstablished,
                nscb::VerificationLimitation::DeviceWriteAuthorizationNotEvaluated,
            ],
        };
        let output = super::verification_result(&result);
        assert!(output.contains("Verification (full) passed"));
        assert!(output.contains("partition payload integrity is not available"));
        assert!(output.contains("the NPDM and ACID are not authenticated"));
        assert!(output.contains("content authenticity is not established"));
        assert!(output.contains("device-write authorization was not evaluated"));
    }
}
