//! Standalone-only configuration, key, and output policy.
//!
//! Embedded Engine hosts do not compile or consume this module. It resolves
//! operating-system directories and owns persistent user state for the NSCB
//! executable.

mod config;
pub(crate) mod history;
mod keys;
mod paths;

pub(crate) use config::{
    ConfigField, ConfigSnapshot, CopyDestinationSelection, StandaloneConfig, StandaloneConfigError,
};

use serde::Serialize;
use std::ffi::{OsStr, OsString};
use std::io::Write;

const EXIT_SUCCESS: i32 = 0;
const EXIT_USAGE: i32 = 2;
const EXIT_INPUT: i32 = 3;
const EXIT_INTERNAL: i32 = 7;

#[derive(Serialize)]
struct SuccessDocument<'a, T> {
    schema_version: u8,
    kind: &'static str,
    nscb_version: &'static str,
    result: &'a T,
}

#[derive(Serialize)]
struct ErrorDocument {
    schema_version: u8,
    kind: &'static str,
    nscb_version: &'static str,
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
}

#[derive(Serialize)]
struct ConfigPathResult<'a> {
    path: &'a str,
}

#[derive(Serialize)]
struct ConfigSetResult<'a> {
    path: &'a str,
    name: &'static str,
    value: &'a str,
}

#[derive(Serialize)]
struct ConfigResetResult<'a> {
    path: &'a str,
}

#[derive(Serialize)]
struct KeysSetResult<'a> {
    path: &'a str,
}

pub(crate) fn run_global_information(args: &[OsString]) -> Option<i32> {
    let first = args.first()?;
    if first == OsStr::new("--help") || first == OsStr::new("-h") {
        let mut stdout = std::io::stdout().lock();
        return Some(
            if writeln!(stdout, "{}", crate::localization::english::global_help()).is_ok() {
                EXIT_SUCCESS
            } else {
                EXIT_INTERNAL
            },
        );
    }
    if first == OsStr::new("--version") || first == OsStr::new("-V") {
        let mut stdout = std::io::stdout().lock();
        return Some(
            if writeln!(
                stdout,
                "{}",
                crate::localization::english::global_version(env!("CARGO_PKG_VERSION"))
            )
            .is_ok()
            {
                EXIT_SUCCESS
            } else {
                EXIT_INTERNAL
            },
        );
    }
    None
}

pub(crate) fn run_pre_engine_command(
    args: &[OsString],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Option<i32> {
    if args
        .first()
        .is_some_and(|argument| argument == OsStr::new("config"))
    {
        Some(run_config_command(args, stdout, stderr))
    } else if args
        .first()
        .is_some_and(|argument| argument == OsStr::new("keys"))
    {
        Some(run_keys_command(args, stdout, stderr))
    } else {
        None
    }
}

fn run_keys_command(args: &[OsString], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let json = args.iter().any(|argument| argument == OsStr::new("--json"));
    let mut positional = Vec::new();
    let mut json_seen = false;
    for argument in args.iter().skip(1) {
        if argument == OsStr::new("--json") {
            if json_seen {
                return emit_keys_usage_error(json, stdout, stderr);
            }
            json_seen = true;
        } else if argument
            .to_str()
            .is_some_and(|value| value.starts_with("--"))
        {
            return emit_keys_usage_error(json, stdout, stderr);
        } else {
            positional.push(argument);
        }
    }
    let [action, source] = positional.as_slice() else {
        return emit_keys_usage_error(json, stdout, stderr);
    };
    if action.as_os_str() != OsStr::new("set") {
        return emit_keys_usage_error(json, stdout, stderr);
    }

    if let Err(error) = StandaloneConfig::load_or_initialize() {
        return emit_config_error(error, json, stdout, stderr);
    }
    let destination = match keys::set_complete_key_file(std::path::Path::new(source)) {
        Ok(destination) => destination,
        Err(error) => return emit_keys_error(error, json, stdout, stderr),
    };
    if json {
        let result = KeysSetResult { path: &destination };
        let document = SuccessDocument {
            schema_version: 1,
            kind: "keys.set",
            nscb_version: env!("CARGO_PKG_VERSION"),
            result: &result,
        };
        if write_json_document(&document, stdout) {
            EXIT_SUCCESS
        } else {
            EXIT_INTERNAL
        }
    } else if writeln!(
        stdout,
        "{}",
        crate::localization::english::keys_set(&destination)
    )
    .is_ok()
    {
        EXIT_SUCCESS
    } else {
        EXIT_INTERNAL
    }
}

fn emit_keys_usage_error(json: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    if json {
        return emit_json_error(stdout, "usage_error", EXIT_USAGE);
    }
    if writeln!(stderr, "{}", crate::localization::english::keys_usage()).is_ok() {
        EXIT_USAGE
    } else {
        EXIT_INTERNAL
    }
}

fn emit_keys_error(
    error: keys::KeySetError,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    if json {
        return emit_json_error(stdout, error.code(), EXIT_INPUT);
    }
    if writeln!(
        stderr,
        "{}",
        crate::localization::english::keys_error(error.code())
    )
    .is_ok()
    {
        EXIT_INPUT
    } else {
        EXIT_INTERNAL
    }
}

fn run_config_command(args: &[OsString], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let json = args.iter().any(|argument| argument == OsStr::new("--json"));
    let mut positional = Vec::new();
    let mut json_seen = false;
    for argument in args.iter().skip(1) {
        if argument == OsStr::new("--json") {
            if json_seen {
                return emit_usage_error(json, stdout, stderr);
            }
            json_seen = true;
        } else if argument
            .to_str()
            .is_some_and(|value| value.starts_with("--"))
        {
            return emit_usage_error(json, stdout, stderr);
        } else {
            positional.push(argument);
        }
    }
    match positional.as_slice() {
        [action] if action.as_os_str() == OsStr::new("path") => {
            let config = match StandaloneConfig::load_or_initialize() {
                Ok(config) => config,
                Err(error) => return emit_config_error(error, json, stdout, stderr),
            };
            let Some(path) = config.path().to_str() else {
                return emit_config_error(
                    StandaloneConfigError::PathUnrepresentable,
                    json,
                    stdout,
                    stderr,
                );
            };
            if json {
                return emit_config_path_success(path, stdout);
            }
            emit_human_config_path(path, stdout)
        }
        [action] if action.as_os_str() == OsStr::new("show") => {
            let config = match StandaloneConfig::load_or_initialize() {
                Ok(config) => config,
                Err(error) => return emit_config_error(error, json, stdout, stderr),
            };
            let snapshot = match config.snapshot() {
                Ok(snapshot) => snapshot,
                Err(error) => return emit_config_error(error, json, stdout, stderr),
            };
            if json {
                emit_config_show_success(&snapshot, stdout)
            } else {
                emit_human_config_show(&snapshot, stdout)
            }
        }
        [action, field, value] if action.as_os_str() == OsStr::new("set") => {
            let Some(field_name) = field.to_str() else {
                return emit_usage_error(json, stdout, stderr);
            };
            let Some(field) = ConfigField::parse(field_name) else {
                return emit_usage_error(json, stdout, stderr);
            };
            let Some(value_text) = value.to_str() else {
                return emit_config_error(
                    StandaloneConfigError::PathUnrepresentable,
                    json,
                    stdout,
                    stderr,
                );
            };
            let path = match StandaloneConfig::set(field, value_text) {
                Ok(path) => path,
                Err(error) => return emit_config_error(error, json, stdout, stderr),
            };
            let Some(path) = path.to_str() else {
                return emit_config_error(
                    StandaloneConfigError::PathUnrepresentable,
                    json,
                    stdout,
                    stderr,
                );
            };
            if json {
                emit_config_set_success(path, field.name(), value_text, stdout)
            } else {
                emit_human_config_update(path, field.name(), value_text, stdout)
            }
        }
        [action] if action.as_os_str() == OsStr::new("reset") => {
            let path = match StandaloneConfig::reset() {
                Ok(path) => path,
                Err(error) => return emit_config_error(error, json, stdout, stderr),
            };
            let Some(path) = path.to_str() else {
                return emit_config_error(
                    StandaloneConfigError::PathUnrepresentable,
                    json,
                    stdout,
                    stderr,
                );
            };
            if json {
                emit_config_reset_success(path, stdout)
            } else {
                emit_human_config_reset(path, stdout)
            }
        }
        _ => emit_usage_error(json, stdout, stderr),
    }
}

fn emit_config_path_success(path: &str, stdout: &mut dyn Write) -> i32 {
    let result = ConfigPathResult { path };
    let document = SuccessDocument {
        schema_version: 1,
        kind: "config.path",
        nscb_version: env!("CARGO_PKG_VERSION"),
        result: &result,
    };
    if write_json_document(&document, stdout) {
        EXIT_SUCCESS
    } else {
        EXIT_INTERNAL
    }
}

fn emit_human_config_path(path: &str, stdout: &mut dyn Write) -> i32 {
    let message = crate::localization::english::config_path(path);
    if writeln!(stdout, "{message}").is_ok() {
        EXIT_SUCCESS
    } else {
        EXIT_INTERNAL
    }
}

fn emit_config_show_success(snapshot: &ConfigSnapshot, stdout: &mut dyn Write) -> i32 {
    let document = SuccessDocument {
        schema_version: 1,
        kind: "config.show",
        nscb_version: env!("CARGO_PKG_VERSION"),
        result: snapshot,
    };
    if write_json_document(&document, stdout) {
        EXIT_SUCCESS
    } else {
        EXIT_INTERNAL
    }
}

fn emit_human_config_show(snapshot: &ConfigSnapshot, stdout: &mut dyn Write) -> i32 {
    let mut output =
        crate::localization::english::config_show_header(&snapshot.path, snapshot.schema_version);
    for entry in &snapshot.values {
        output.push('\n');
        output.push_str(&crate::localization::english::config_show_value(
            &entry.name,
            &entry.value,
            entry.source,
        ));
    }
    if writeln!(stdout, "{output}").is_ok() {
        EXIT_SUCCESS
    } else {
        EXIT_INTERNAL
    }
}

fn emit_config_set_success(
    path: &str,
    name: &'static str,
    value: &str,
    stdout: &mut dyn Write,
) -> i32 {
    let result = ConfigSetResult { path, name, value };
    let document = SuccessDocument {
        schema_version: 1,
        kind: "config.set",
        nscb_version: env!("CARGO_PKG_VERSION"),
        result: &result,
    };
    if write_json_document(&document, stdout) {
        EXIT_SUCCESS
    } else {
        EXIT_INTERNAL
    }
}

fn emit_human_config_update(path: &str, name: &str, value: &str, stdout: &mut dyn Write) -> i32 {
    if writeln!(
        stdout,
        "{}",
        crate::localization::english::config_updated(path, name, value)
    )
    .is_ok()
    {
        EXIT_SUCCESS
    } else {
        EXIT_INTERNAL
    }
}

fn emit_config_reset_success(path: &str, stdout: &mut dyn Write) -> i32 {
    let result = ConfigResetResult { path };
    let document = SuccessDocument {
        schema_version: 1,
        kind: "config.reset",
        nscb_version: env!("CARGO_PKG_VERSION"),
        result: &result,
    };
    if write_json_document(&document, stdout) {
        EXIT_SUCCESS
    } else {
        EXIT_INTERNAL
    }
}

fn emit_human_config_reset(path: &str, stdout: &mut dyn Write) -> i32 {
    if writeln!(
        stdout,
        "{}",
        crate::localization::english::config_reset(path)
    )
    .is_ok()
    {
        EXIT_SUCCESS
    } else {
        EXIT_INTERNAL
    }
}

fn emit_usage_error(json: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    if json {
        return emit_json_error(stdout, "usage_error", EXIT_USAGE);
    }
    if writeln!(stderr, "{}", crate::localization::english::config_usage()).is_ok() {
        EXIT_USAGE
    } else {
        EXIT_INTERNAL
    }
}

fn emit_config_error(
    error: StandaloneConfigError,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let exit = config_error_exit(error);
    if json {
        return emit_json_error(stdout, error.code(), exit);
    }
    if writeln!(
        stderr,
        "{}",
        crate::localization::english::config_error(error.code())
    )
    .is_ok()
    {
        exit
    } else {
        EXIT_INTERNAL
    }
}

const fn config_error_exit(error: StandaloneConfigError) -> i32 {
    match error {
        StandaloneConfigError::PathUnrepresentable => EXIT_INPUT,
        _ => EXIT_USAGE,
    }
}

pub(crate) fn emit_startup_error(
    args: &[OsString],
    error: StandaloneConfigError,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let exit = config_error_exit(error);
    if args
        .iter()
        .any(|argument| argument == OsStr::new("--json") || argument == OsStr::new("--jsonl"))
    {
        emit_json_error(stdout, error.code(), exit)
    } else if writeln!(
        stderr,
        "{}",
        crate::localization::english::config_error(error.code())
    )
    .is_ok()
    {
        exit
    } else {
        EXIT_INTERNAL
    }
}

fn emit_json_error(stdout: &mut dyn Write, code: &'static str, exit: i32) -> i32 {
    let document = ErrorDocument {
        schema_version: 1,
        kind: "error",
        nscb_version: env!("CARGO_PKG_VERSION"),
        error: ErrorDetail { code },
    };
    if write_json_document(&document, stdout) {
        exit
    } else {
        EXIT_INTERNAL
    }
}

fn write_json_document<T: Serialize>(document: &T, writer: &mut dyn Write) -> bool {
    serde_json::to_writer(&mut *writer, document).is_ok() && writer.write_all(b"\n").is_ok()
}
