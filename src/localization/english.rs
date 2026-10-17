//! English presentation strings for the standalone command-line adapter.

use nscb::{ContainerProbeErrorCode, InputResolutionErrorCode, InputResolutionResult};
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

fn messages() -> &'static Messages {
    static MESSAGES: OnceLock<Messages> = OnceLock::new();
    MESSAGES.get_or_init(|| {
        serde_json::from_str(include_str!("../../locales/en.json"))
            .expect("bundled English CLI localization resource must be valid")
    })
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
}
