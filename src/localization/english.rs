//! English presentation strings for the standalone command-line adapter.

use nscb::ContainerProbeErrorCode;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Deserialize)]
struct Messages {
    usage: String,
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

#[cfg(test)]
mod tests {
    use super::{error_message, success, usage};
    use nscb::ContainerProbeErrorCode as Code;

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
    fn resource_provides_cli_usage() {
        assert_eq!(usage(), "Usage: nscb probe <path> [--json]");
    }
}
