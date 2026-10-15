use nscb::{ContainerProbeError, ContainerProbeErrorCode, Engine};
use serde::Serialize;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::PathBuf;

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
}
