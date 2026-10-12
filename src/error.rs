use serde::Serialize;
use std::fmt;

/// Stable error categories returned by the PFS0 Container Probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerProbeErrorCode {
    /// The input does not begin with the supported PFS0 signature.
    UnsupportedFormat,
    /// The file ended before a declared header, table, or payload span ended.
    TruncatedInput,
    /// A header field violates the PFS0 structural contract.
    InvalidHeader,
    /// A filename table or filename reference is malformed.
    InvalidStringTable,
    /// An entry span or entry reserved field is structurally invalid.
    InvalidEntry,
    /// A supported input-size limit was exceeded.
    LimitExceeded,
    /// A filename exceeds the supported byte length.
    NameTooLong,
    /// The file could not be opened or read.
    InputUnavailable,
    /// A bounded metadata allocation could not be made.
    ResourceLimitExceeded,
}

impl ContainerProbeErrorCode {
    /// Returns the stable machine-readable spelling of this category.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedFormat => "unsupported_format",
            Self::TruncatedInput => "truncated_input",
            Self::InvalidHeader => "invalid_header",
            Self::InvalidStringTable => "invalid_string_table",
            Self::InvalidEntry => "invalid_entry",
            Self::LimitExceeded => "limit_exceeded",
            Self::NameTooLong => "name_too_long",
            Self::InputUnavailable => "input_unavailable",
            Self::ResourceLimitExceeded => "resource_limit_exceeded",
        }
    }
}

/// A sanitized Container Probe error without paths, parser details, or input bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainerProbeError {
    code: ContainerProbeErrorCode,
}

impl ContainerProbeError {
    pub(crate) const fn new(code: ContainerProbeErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable category used by Rust callers and machine output.
    pub const fn code(self) -> ContainerProbeErrorCode {
        self.code
    }
}

impl fmt::Display for ContainerProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.code {
            ContainerProbeErrorCode::UnsupportedFormat => {
                "the outer-container format is not supported"
            }
            ContainerProbeErrorCode::TruncatedInput => "the input is incomplete",
            ContainerProbeErrorCode::InvalidHeader => "the container header is invalid",
            ContainerProbeErrorCode::InvalidStringTable => {
                "the container filename table is invalid"
            }
            ContainerProbeErrorCode::InvalidEntry => "a container entry is invalid",
            ContainerProbeErrorCode::LimitExceeded => "the input exceeds a supported limit",
            ContainerProbeErrorCode::NameTooLong => {
                "a container filename exceeds the supported limit"
            }
            ContainerProbeErrorCode::InputUnavailable => "the input could not be read",
            ContainerProbeErrorCode::ResourceLimitExceeded => {
                "container probe could not reserve bounded resources"
            }
        })
    }
}

impl std::error::Error for ContainerProbeError {}

#[cfg(test)]
mod tests {
    use super::{ContainerProbeError, ContainerProbeErrorCode};

    #[test]
    fn error_codes_have_stable_json_names_and_sanitized_messages() {
        let cases = [
            (
                ContainerProbeErrorCode::UnsupportedFormat,
                "unsupported_format",
                "the outer-container format is not supported",
            ),
            (
                ContainerProbeErrorCode::TruncatedInput,
                "truncated_input",
                "the input is incomplete",
            ),
            (
                ContainerProbeErrorCode::InvalidHeader,
                "invalid_header",
                "the container header is invalid",
            ),
            (
                ContainerProbeErrorCode::InvalidStringTable,
                "invalid_string_table",
                "the container filename table is invalid",
            ),
            (
                ContainerProbeErrorCode::InvalidEntry,
                "invalid_entry",
                "a container entry is invalid",
            ),
            (
                ContainerProbeErrorCode::LimitExceeded,
                "limit_exceeded",
                "the input exceeds a supported limit",
            ),
            (
                ContainerProbeErrorCode::NameTooLong,
                "name_too_long",
                "a container filename exceeds the supported limit",
            ),
            (
                ContainerProbeErrorCode::InputUnavailable,
                "input_unavailable",
                "the input could not be read",
            ),
            (
                ContainerProbeErrorCode::ResourceLimitExceeded,
                "resource_limit_exceeded",
                "container probe could not reserve bounded resources",
            ),
        ];

        for (code, wire_name, message) in cases {
            assert_eq!(code.as_str(), wire_name);
            assert_eq!(
                serde_json::to_value(code).expect("serialize error code"),
                wire_name
            );
            assert_eq!(ContainerProbeError::new(code).to_string(), message);
            assert!(!message.contains("path"));
        }
    }
}
