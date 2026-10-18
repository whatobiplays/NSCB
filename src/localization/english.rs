//! English presentation strings for the standalone command-line adapter.

use nscb::{
    ContainerProbeErrorCode, InputResolutionErrorCode, InputResolutionResult, InspectionErrorCode,
    NcaContentType, NcaDistribution, NcaInspection,
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

#[cfg(test)]
mod tests {
    use super::{error_message, success, usage};
    use nscb::{ContainerProbeErrorCode as Code, InputResolutionErrorCode as InputCode};

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
}
