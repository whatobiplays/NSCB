use nscb::{
    ContainerProbeError, ContainerProbeErrorCode, Engine, InputResolutionRequest,
    InputSelectionSource,
};
use serde::Serialize;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};

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

/// A validated command line invocation shared by the `probe` and `recognize`
/// subcommands: the target path, whether JSON output was requested, and which
/// subcommand selects the operation.
struct CliInvocation {
    path: PathBuf,
    json: bool,
    recognize: bool,
}

/// Adapts typed Container Probe requests and errors to the stable CLI contract.
pub(crate) fn run(
    args: &[OsString],
    engine: &Engine,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    if args
        .first()
        .is_some_and(|argument| argument == OsStr::new("resolve"))
    {
        return run_input_resolution(args, engine, stdout, stderr);
    }

    let json_requested = args.iter().any(|argument| argument == OsStr::new("--json"));
    let parsed = match parse(args) {
        Ok(parsed) => parsed,
        Err(()) => {
            if json_requested {
                return emit_error(stdout, "usage_error", EXIT_USAGE);
            }
            return if writeln!(
                stderr,
                "{}",
                if args
                    .first()
                    .is_some_and(|arg| arg == OsStr::new("recognize"))
                {
                    crate::localization::english::recognition_usage()
                } else {
                    crate::localization::english::usage()
                }
            )
            .is_ok()
            {
                EXIT_USAGE
            } else {
                EXIT_INTERNAL
            };
        }
    };

    if parsed.recognize {
        return run_recognition(parsed, engine, stdout, stderr);
    }
    match engine.probe_container(nscb::ContainerProbeRequest::new(parsed.path)) {
        Ok(result) if parsed.json => {
            let document = SuccessDocument {
                schema_version: 1,
                kind: "container_probe.result",
                nscb_version: env!("CARGO_PKG_VERSION"),
                result: &result,
            };
            if write_json(&document, stdout) {
                EXIT_SUCCESS
            } else {
                report_output_failure(stderr)
            }
        }
        Ok(result) => {
            let message =
                crate::localization::english::success(result.entries.len(), result.payload_offset);
            if writeln!(stdout, "{message}").is_ok() {
                EXIT_SUCCESS
            } else {
                report_output_failure(stderr)
            }
        }
        Err(error) if parsed.json => emit_error(stdout, error.code().as_str(), exit_for(&error)),
        Err(error) => {
            let code = exit_for(&error);
            if writeln!(
                stderr,
                "{}",
                crate::localization::english::error_message(error.code())
            )
            .is_err()
            {
                EXIT_INTERNAL
            } else {
                code
            }
        }
    }
}

struct ResolveInvocation {
    selections: Vec<ResolveSelection>,
    json: bool,
    recursive: bool,
    follow_symlinks: bool,
}

enum ResolveSelection {
    Path(PathBuf),
    InputList(PathBuf),
}

#[derive(Serialize)]
struct InputResolutionJsonResult {
    inputs: Vec<InputResolutionJsonInput>,
}

#[derive(Serialize)]
struct InputResolutionJsonInput {
    segments: Vec<InputResolutionJsonSegment>,
    provenance: InputResolutionJsonProvenance,
}

#[derive(Serialize)]
struct InputResolutionJsonSegment {
    path: String,
    size_bytes: u64,
}

#[derive(Serialize)]
struct InputResolutionJsonProvenance {
    selection_index: usize,
    source: InputSelectionSource,
    selection_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    input_list_entry_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    input_list_entry_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    discovered_directory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    discovered_relative_path: Option<String>,
}

fn input_resolution_json(
    result: &nscb::InputResolutionResult,
) -> Result<InputResolutionJsonResult, nscb::InputResolutionErrorCode> {
    let inputs = result
        .inputs
        .iter()
        .map(|input| {
            let segments = input
                .segments
                .iter()
                .map(|segment| {
                    Ok(InputResolutionJsonSegment {
                        path: json_path(&segment.path)?,
                        size_bytes: segment.size,
                    })
                })
                .collect::<Result<Vec<_>, nscb::InputResolutionErrorCode>>()?;
            Ok(InputResolutionJsonInput {
                segments,
                provenance: InputResolutionJsonProvenance {
                    selection_index: input.provenance.selection_index,
                    source: input.provenance.source,
                    selection_path: json_path(&input.provenance.selection_path)?,
                    input_list_entry_index: input.provenance.input_list_entry_index,
                    input_list_entry_path: input
                        .provenance
                        .input_list_entry_path
                        .as_deref()
                        .map(json_path)
                        .transpose()?,
                    discovered_directory: input
                        .provenance
                        .discovered_directory
                        .as_deref()
                        .map(json_path)
                        .transpose()?,
                    discovered_relative_path: input
                        .provenance
                        .discovered_relative_path
                        .as_deref()
                        .map(json_path)
                        .transpose()?,
                },
            })
        })
        .collect::<Result<Vec<_>, nscb::InputResolutionErrorCode>>()?;
    Ok(InputResolutionJsonResult { inputs })
}

fn json_path(path: &Path) -> Result<String, nscb::InputResolutionErrorCode> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(nscb::InputResolutionErrorCode::UnrepresentablePath)
}

fn run_input_resolution(
    args: &[OsString],
    engine: &Engine,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let json_requested = args.iter().any(|argument| argument == OsStr::new("--json"));
    let parsed = match parse_input_resolution(args) {
        Ok(parsed) => parsed,
        Err(()) => {
            if json_requested {
                return emit_error(stdout, "usage_error", EXIT_USAGE);
            }
            return if writeln!(
                stderr,
                "{}",
                crate::localization::english::input_resolution_usage()
            )
            .is_ok()
            {
                EXIT_USAGE
            } else {
                EXIT_INTERNAL
            };
        }
    };
    let base = match std::env::current_dir() {
        Ok(base) => base,
        Err(_) if parsed.json => {
            return emit_error(
                stdout,
                nscb::InputResolutionErrorCode::InvalidBaseDirectory.as_str(),
                EXIT_INPUT,
            );
        }
        Err(_) => {
            return if writeln!(
                stderr,
                "{}",
                crate::localization::english::input_resolution_error(
                    nscb::InputResolutionErrorCode::InvalidBaseDirectory
                )
            )
            .is_ok()
            {
                EXIT_INPUT
            } else {
                EXIT_INTERNAL
            };
        }
    };
    let mut request = InputResolutionRequest::new(base)
        .with_recursive(parsed.recursive)
        .with_follow_symlinks(parsed.follow_symlinks);
    for selection in parsed.selections {
        request = match selection {
            ResolveSelection::Path(path) => request.with_path(path),
            ResolveSelection::InputList(path) => request.with_input_list(path),
        };
    }

    match engine.resolve_inputs(request) {
        Ok(result) if parsed.json => {
            let result = match input_resolution_json(&result) {
                Ok(result) => result,
                Err(code) => return emit_error(stdout, code.as_str(), EXIT_INPUT),
            };
            if write_json(
                &SuccessDocument {
                    schema_version: 1,
                    kind: "input_resolution.result",
                    nscb_version: env!("CARGO_PKG_VERSION"),
                    result: &result,
                },
                stdout,
            ) {
                EXIT_SUCCESS
            } else {
                report_output_failure(stderr)
            }
        }
        Ok(result) => {
            let message = crate::localization::english::input_resolution_success(&result);
            if writeln!(stdout, "{message}").is_ok() {
                EXIT_SUCCESS
            } else {
                report_output_failure(stderr)
            }
        }
        Err(error) if parsed.json => emit_error(stdout, error.code().as_str(), EXIT_INPUT),
        Err(error) => {
            if writeln!(
                stderr,
                "{}",
                crate::localization::english::input_resolution_error(error.code())
            )
            .is_ok()
            {
                EXIT_INPUT
            } else {
                EXIT_INTERNAL
            }
        }
    }
}

fn parse_input_resolution(args: &[OsString]) -> Result<ResolveInvocation, ()> {
    if args
        .first()
        .is_none_or(|command| command != OsStr::new("resolve"))
    {
        return Err(());
    }

    let mut selections = Vec::new();
    let mut json = false;
    let mut recursive = false;
    let mut follow_symlinks = false;
    let mut positional_only = false;
    let mut index = 1;
    while index < args.len() {
        let argument = &args[index];
        if !positional_only && argument == OsStr::new("--") {
            positional_only = true;
            index += 1;
        } else if !positional_only && argument == OsStr::new("--json") {
            if json {
                return Err(());
            }
            json = true;
            index += 1;
        } else if !positional_only && argument == OsStr::new("--recursive") {
            if recursive {
                return Err(());
            }
            recursive = true;
            index += 1;
        } else if !positional_only && argument == OsStr::new("--follow-symlinks") {
            if follow_symlinks {
                return Err(());
            }
            follow_symlinks = true;
            index += 1;
        } else if !positional_only && argument == OsStr::new("--input-list") {
            let Some(path) = args
                .get(index + 1)
                .filter(|path| !path.to_str().is_some_and(|value| value.starts_with("--")))
            else {
                return Err(());
            };
            selections.push(ResolveSelection::InputList(PathBuf::from(path)));
            index += 2;
        } else if !positional_only
            && argument
                .to_str()
                .is_some_and(|value| value.starts_with("--"))
        {
            return Err(());
        } else {
            selections.push(ResolveSelection::Path(PathBuf::from(argument)));
            index += 1;
        }
    }

    Ok(ResolveInvocation {
        selections,
        json,
        recursive,
        follow_symlinks,
    })
}

fn parse(args: &[OsString]) -> Result<CliInvocation, ()> {
    if args
        .first()
        .is_none_or(|command| command != OsStr::new("probe") && command != OsStr::new("recognize"))
    {
        return Err(());
    }

    let mut path = None;
    let mut json = false;
    for argument in args.iter().skip(1) {
        if argument == OsStr::new("--json") {
            if json {
                return Err(());
            }
            json = true;
        } else if argument
            .to_str()
            .is_some_and(|value| value.starts_with("--"))
        {
            return Err(());
        } else if path.is_none() {
            path = Some(PathBuf::from(argument));
        } else {
            return Err(());
        }
    }

    Ok(CliInvocation {
        path: path.ok_or(())?,
        json,
        recognize: args[0] == OsStr::new("recognize"),
    })
}

fn run_recognition(
    parsed: CliInvocation,
    engine: &Engine,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    match engine.recognize_content(nscb::ContentRecognitionRequest::new(parsed.path)) {
        Ok(result) => {
            let exit = if matches!(
                result.recognition,
                nscb::RecognitionOutcome::Recognized { .. }
            ) {
                EXIT_SUCCESS
            } else {
                EXIT_INPUT
            };
            let written = if parsed.json {
                write_json(
                    &SuccessDocument {
                        schema_version: 1,
                        kind: "content_recognition.result",
                        nscb_version: env!("CARGO_PKG_VERSION"),
                        result: &result,
                    },
                    stdout,
                )
            } else {
                writeln!(
                    stdout,
                    "{}",
                    crate::localization::english::recognition(&result)
                )
                .is_ok()
            };
            if written {
                exit
            } else {
                report_output_failure(stderr)
            }
        }
        Err(error) => {
            let exit = if error.code() == nscb::ContentRecognitionErrorCode::ResourceLimitExceeded {
                EXIT_INTERNAL
            } else {
                EXIT_INPUT
            };
            if parsed.json {
                emit_error(stdout, error.code().as_str(), exit)
            } else if writeln!(
                stderr,
                "{}",
                crate::localization::english::recognition_error(error.code())
            )
            .is_ok()
            {
                exit
            } else {
                EXIT_INTERNAL
            }
        }
    }
}

fn write_json(document: &impl Serialize, stdout: &mut dyn Write) -> bool {
    serde_json::to_writer(&mut *stdout, document).is_ok() && stdout.write_all(b"\n").is_ok()
}

fn emit_error(stdout: &mut dyn Write, code: &'static str, exit_code: i32) -> i32 {
    let document = ErrorDocument {
        schema_version: 1,
        kind: "error",
        nscb_version: env!("CARGO_PKG_VERSION"),
        error: ErrorDetail { code },
    };
    if write_json(&document, stdout) {
        exit_code
    } else {
        EXIT_INTERNAL
    }
}

fn exit_for(error: &ContainerProbeError) -> i32 {
    match error.code() {
        ContainerProbeErrorCode::ResourceLimitExceeded => EXIT_INTERNAL,
        _ => EXIT_INPUT,
    }
}

fn report_output_failure(stderr: &mut dyn Write) -> i32 {
    let _ = writeln!(stderr, "{}", crate::localization::english::output_failure());
    EXIT_INTERNAL
}

#[cfg(test)]
#[path = "../tests/support/synthetic_pfs0.rs"]
mod synthetic_fixtures;

#[cfg(test)]
mod tests {
    use super::run;
    use super::synthetic_fixtures::{self, TempInput};
    use crate::localization::english;
    use nscb::Engine;
    use serde_json::Value;
    use std::ffi::OsString;
    use std::io::{self, Write};

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "test output failure",
            ))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn json_args(path: &std::path::Path) -> Vec<OsString> {
        vec![
            OsString::from("probe"),
            path.as_os_str().to_owned(),
            OsString::from("--json"),
        ]
    }

    #[test]
    fn json_success_matches_the_facade_for_the_same_synthetic_container() {
        let input = TempInput::new(&synthetic_fixtures::valid_container_probe_fixture());
        let engine = Engine::new();
        let expected = engine
            .probe_container(nscb::ContainerProbeRequest::new(input.path()))
            .expect("facade probes a deterministic container without keys");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit = run(&json_args(input.path()), &engine, &mut stdout, &mut stderr);

        assert_eq!(exit, 0);
        assert!(stderr.is_empty());
        assert_eq!(stdout.iter().filter(|byte| **byte == b'\n').count(), 1);
        let document: Value = serde_json::from_slice(&stdout).expect("one success JSON document");
        assert_eq!(document["schema_version"], 1);
        assert_eq!(document["kind"], "container_probe.result");
        assert_eq!(document["result"]["format"], "pfs0");
        assert_eq!(document["result"]["file_size"], 52);
        assert_eq!(document["result"]["payload_offset"], 46);
        assert_eq!(document["result"]["entries"][0]["offset"], 2);
        assert_eq!(document["result"]["entries"][0]["file_offset"], 48);
        assert_eq!(document["result"]["entries"][0]["name"], "a\"\n\\b");
        assert_eq!(document["result"], serde_json::to_value(expected).unwrap());
        let output = String::from_utf8(stdout).expect("JSON output is UTF-8");
        assert!(output.contains("a\\\"\\n\\\\b"));
    }

    #[test]
    fn json_handled_error_is_one_sanitized_document_with_input_exit_class() {
        let input = TempInput::new(b"not a PFS0 container");
        let engine = Engine::new();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit = run(&json_args(input.path()), &engine, &mut stdout, &mut stderr);

        assert_eq!(exit, 3);
        assert!(stderr.is_empty());
        assert_eq!(stdout.iter().filter(|byte| **byte == b'\n').count(), 1);
        let document: Value = serde_json::from_slice(&stdout).expect("one error JSON document");
        assert_eq!(document["kind"], "error");
        assert_eq!(document["error"]["code"], "unsupported_format");
        assert!(
            !String::from_utf8_lossy(&stdout).contains(input.path().to_string_lossy().as_ref())
        );
        assert!(!String::from_utf8_lossy(&stdout).contains("not a PFS0"));
    }

    #[test]
    fn json_truncated_payload_is_one_handled_error_document() {
        let mut bytes = synthetic_fixtures::valid_container_probe_fixture();
        bytes.pop();
        let input = TempInput::new(&bytes);
        let engine = Engine::new();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit = run(&json_args(input.path()), &engine, &mut stdout, &mut stderr);

        assert_eq!(exit, 3);
        assert!(stderr.is_empty());
        assert_eq!(stdout.iter().filter(|byte| **byte == b'\n').count(), 1);
        let document: Value =
            serde_json::from_slice(&stdout).expect("one truncated-input document");
        assert_eq!(document["error"]["code"], "truncated_input");
    }

    #[test]
    fn json_usage_error_has_the_usage_exit_class() {
        let engine = Engine::new();
        let args = [OsString::from("probe"), OsString::from("--json")];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit = run(&args, &engine, &mut stdout, &mut stderr);

        assert_eq!(exit, 2);
        assert!(stderr.is_empty());
        assert_eq!(stdout.iter().filter(|byte| **byte == b'\n').count(), 1);
        let document: Value = serde_json::from_slice(&stdout).expect("one usage JSON document");
        assert_eq!(document["error"]["code"], "usage_error");
    }

    #[test]
    fn human_success_reports_outer_container_structure() {
        let input = TempInput::new(&synthetic_fixtures::valid_container_probe_fixture());
        let engine = Engine::new();
        let args = [OsString::from("probe"), input.path().as_os_str().to_owned()];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit = run(&args, &engine, &mut stdout, &mut stderr);

        assert_eq!(exit, 0);
        assert_eq!(
            String::from_utf8(stdout).expect("human output is UTF-8"),
            "PFS0 container probe found one entry; payload begins at byte 46.\n"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn human_input_error_uses_stderr_and_the_input_exit_class() {
        let input = TempInput::new(b"not a PFS0 container");
        let engine = Engine::new();
        let args = [OsString::from("probe"), input.path().as_os_str().to_owned()];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit = run(&args, &engine, &mut stdout, &mut stderr);

        assert_eq!(exit, 3);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8(stderr).expect("error output is UTF-8"),
            "The outer-container format is not supported.\n"
        );
    }

    #[test]
    fn human_usage_error_uses_stderr_and_the_usage_exit_class() {
        let engine = Engine::new();
        let args = [OsString::from("probe")];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit = run(&args, &engine, &mut stdout, &mut stderr);

        assert_eq!(exit, 2);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            format!("{}\n", english::usage())
        );
    }

    #[test]
    fn human_usage_error_stderr_failure_uses_the_internal_exit_class() {
        let engine = Engine::new();
        let args = [OsString::from("probe")];
        let mut stdout = Vec::new();

        let exit = run(&args, &engine, &mut stdout, &mut FailingWriter);

        assert_eq!(exit, 7);
        assert!(stdout.is_empty());
    }

    #[test]
    fn stdout_write_failure_uses_the_internal_exit_class() {
        let input = TempInput::new(&synthetic_fixtures::valid_container_probe_fixture());
        let engine = Engine::new();
        let mut stderr = Vec::new();

        let exit = run(
            &json_args(input.path()),
            &engine,
            &mut FailingWriter,
            &mut stderr,
        );

        assert_eq!(exit, 7);
        assert_eq!(
            String::from_utf8(stderr).expect("localized output failure is UTF-8"),
            format!("{}\n", english::output_failure())
        );
    }

    #[test]
    fn handled_error_output_failure_uses_the_internal_exit_class() {
        let engine = Engine::new();
        let args = [OsString::from("probe"), OsString::from("--json")];
        let mut stderr = Vec::new();

        let exit = run(&args, &engine, &mut FailingWriter, &mut stderr);

        assert_eq!(exit, 7);
    }

    #[cfg(unix)]
    #[test]
    fn input_resolution_json_does_not_lossily_encode_non_unicode_paths() {
        use std::os::unix::ffi::OsStringExt;

        let baseline = Engine::new()
            .resolve_inputs(
                nscb::InputResolutionRequest::new(std::env::current_dir().unwrap())
                    .with_path("Cargo.toml"),
            )
            .expect("resolve an existing file for the serialization fixture");
        let path = std::path::PathBuf::from(std::ffi::OsString::from_vec(
            b"non-unicode-\xff.nsp".to_vec(),
        ));

        for path_field in 0..5 {
            let mut result = baseline.clone();
            let input = &mut result.inputs[0];
            match path_field {
                0 => input.segments[0].path = path.clone(),
                1 => input.provenance.selection_path = path.clone(),
                2 => input.provenance.input_list_entry_path = Some(path.clone()),
                3 => input.provenance.discovered_directory = Some(path.clone()),
                _ => input.provenance.discovered_relative_path = Some(path.clone()),
            }

            let error = match super::input_resolution_json(&result) {
                Ok(_) => panic!("path field {path_field} must not be silently replaced"),
                Err(error) => error,
            };
            assert_eq!(error.as_str(), "unrepresentable_path");
        }
    }
}
