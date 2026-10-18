use nscb::{
    CancellationHandle, ContainerProbeError, ContainerProbeErrorCode, Engine,
    InputResolutionCapabilities, InputResolutionRequest, InputSelectionSource, InspectionErrorCode,
    InspectionHost, InspectionPreflightStatus, InspectionRequest, InspectionResult,
    LocalSplitTrustStore, SplitQualificationKind,
};
use serde::Serialize;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

const EXIT_SUCCESS: i32 = 0;
const EXIT_USAGE: i32 = 2;
const EXIT_INPUT: i32 = 3;
const EXIT_CANCELLED: i32 = 6;
const EXIT_INTERNAL: i32 = 7;

#[derive(Serialize)]
struct SuccessDocument<'a, T> {
    schema_version: u8,
    kind: &'static str,
    nscb_version: &'static str,
    result: &'a T,
}

#[cfg(test)]
mod inspection_cli_tests {
    use super::{parse_inspection, run};
    use nscb::Engine;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn inspection_parser_requires_one_input_and_accepts_optional_keys() {
        assert!(parse_inspection(&args(&["inspect"])).is_err());
        let implicit = parse_inspection(&args(&["inspect", "input.nca"])).unwrap();
        assert!(implicit.key_file.is_none());
        assert!(
            parse_inspection(&args(&[
                "inspect",
                "input.nca",
                "--keys",
                "prod.keys",
                "extra.nca"
            ]))
            .is_err()
        );
        let parsed = parse_inspection(&args(&[
            "inspect",
            "input.nca",
            "--keys",
            "prod.keys",
            "--cache-dir",
            "cache",
            "--allow-download",
            "--preflight",
            "--json",
        ]))
        .unwrap();
        assert!(parsed.allow_download);
        assert!(parsed.preflight);
        assert!(parsed.json);
        assert_eq!(parsed.key_file.as_deref(), Some(Path::new("prod.keys")));

        for values in [
            &["inspect", "input.nca", "--keys"][..],
            &["inspect", "input.nca", "--cache-dir"][..],
            &["inspect", "input.nca", "--keys", "--json"][..],
            &["inspect", "input.nca", "--cache-dir", "--json"][..],
        ] {
            assert!(parse_inspection(&args(values)).is_err(), "{values:?}");
        }
    }

    #[test]
    fn inspection_key_resolution_prefers_explicit_then_configured_then_home_default() {
        let home = PathBuf::from("/fixture/home");
        assert_eq!(
            super::resolve_inspection_key_file(
                Some(PathBuf::from("/explicit/prod.keys")),
                Some(PathBuf::from("/configured/prod.keys")),
                Some(home.clone()),
            )
            .unwrap(),
            PathBuf::from("/explicit/prod.keys")
        );
        assert_eq!(
            super::resolve_inspection_key_file(
                None,
                Some(PathBuf::from("/configured/prod.keys")),
                Some(home.clone()),
            )
            .unwrap(),
            PathBuf::from("/configured/prod.keys")
        );
        assert_eq!(
            super::resolve_inspection_key_file(None, None, Some(home)).unwrap(),
            PathBuf::from("/fixture/home/.switch/prod.keys")
        );
        assert_eq!(
            super::resolve_inspection_key_file(None, None, None).unwrap_err(),
            nscb::InspectionErrorCode::InvalidKeyPath
        );
    }

    #[test]
    fn inspection_home_uses_home_on_all_platforms() {
        assert_eq!(
            super::resolve_home_directory(
                Some(PathBuf::from("/Users/tester")),
                Some(PathBuf::from("C:/Users/tester")),
                false,
            ),
            Some(PathBuf::from("/Users/tester"))
        );
    }

    #[test]
    fn inspection_home_uses_userprofile_as_a_windows_fallback() {
        assert_eq!(
            super::resolve_home_directory(None, Some(PathBuf::from("C:/Users/tester")), true,)
                .unwrap(),
            PathBuf::from("C:/Users/tester")
        );
    }

    #[test]
    fn inspection_home_prefers_home_over_windows_userprofile() {
        assert_eq!(
            super::resolve_home_directory(
                Some(PathBuf::from("/Users/tester")),
                Some(PathBuf::from("C:/Users/tester")),
                true,
            )
            .unwrap(),
            PathBuf::from("/Users/tester")
        );
    }

    #[test]
    fn inspection_home_is_missing_on_non_windows_without_home() {
        assert_eq!(
            super::resolve_home_directory(None, Some(PathBuf::from("C:/Users/tester")), false),
            None
        );
    }

    #[test]
    fn inspect_usage_is_human_readable_without_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run(
            &args(&["inspect"]),
            &Engine::new(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, 2);
        assert!(stdout.is_empty());
        assert!(
            String::from_utf8(stderr)
                .unwrap()
                .contains("nscb inspect <path> [--keys <path>]")
        );
    }

    #[test]
    fn inspect_usage_is_sanitized_json_when_requested() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run(
            &args(&["inspect", "--json"]),
            &Engine::new(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, 2);
        assert!(stderr.is_empty());
        let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(document["kind"], "error");
        assert_eq!(document["error"]["code"], "usage_error");
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn missing_input_is_reported_as_a_localized_prerequisite_failure() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run(
            &args(&[
                "inspect",
                "/definitely/missing/input.nca",
                "--keys",
                "/definitely/missing/prod.keys",
                "--cache-dir",
                "/tmp/nscb-inspection-test-cache",
            ]),
            &Engine::new(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, 3);
        assert!(stdout.is_empty());
        let message = String::from_utf8(stderr).unwrap();
        assert!(message.contains("content input could not be read"));
        assert!(!message.contains("/definitely/missing"));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn unqualified_target_is_reported_without_disclosing_input_or_key_paths() {
        let input = "/definitely/missing/input.nca";
        let keys = "/definitely/missing/prod.keys";
        let engine = Engine::new();
        let invocation = [
            "inspect",
            input,
            "--keys",
            keys,
            "--cache-dir",
            "/tmp/nscb-inspection-test-cache",
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit = run(&args(&invocation), &engine, &mut stdout, &mut stderr);

        assert_eq!(exit, 3);
        assert!(stdout.is_empty());
        let message = String::from_utf8(stderr).unwrap();
        assert!(
            message
                .contains("NSTool v1.9.2 is not qualified for NCA inspection on this host target.")
        );
        assert!(!message.contains(input));
        assert!(!message.contains(keys));

        let json_invocation = [
            "inspect",
            input,
            "--keys",
            keys,
            "--cache-dir",
            "/tmp/nscb-inspection-test-cache",
            "--json",
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit = run(&args(&json_invocation), &engine, &mut stdout, &mut stderr);

        assert_eq!(exit, 3);
        assert!(stderr.is_empty());
        let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(document["kind"], "error");
        assert_eq!(document["error"]["code"], "provider_unqualified_target");
        let output = String::from_utf8(stdout).unwrap();
        assert!(!output.contains(input));
        assert!(!output.contains(keys));
    }

    #[test]
    fn input_unavailable_error_uses_localized_prerequisite_exit_class() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit = super::emit_inspection_error(
            &mut stdout,
            &mut stderr,
            nscb::InspectionErrorCode::InputUnavailable,
            false,
        );

        assert_eq!(exit, 3);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "The content input could not be read.\n"
        );
    }
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
        .is_some_and(|argument| argument == OsStr::new("inspect"))
    {
        return run_inspection(args, engine, stdout, stderr);
    }

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
    #[serde(skip_serializing_if = "Option::is_none")]
    qualification: Option<InputResolutionJsonQualification>,
}

#[derive(Serialize)]
struct InputResolutionJsonQualification {
    kind: SplitQualificationKind,
    manifest_schema_version: u16,
    original_size_bytes: u64,
    original_sha256: String,
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
                qualification: input.qualification.as_ref().map(|qualification| {
                    InputResolutionJsonQualification {
                        kind: qualification.kind,
                        manifest_schema_version: qualification.manifest_schema_version,
                        original_size_bytes: qualification.original_size_bytes,
                        original_sha256: qualification.original_sha256.to_hex(),
                    }
                }),
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
    let trust_store = LocalSplitTrustStore::from_environment();
    run_input_resolution_with(args, engine, &trust_store, None, stdout, stderr)
}

/// Runs one input-resolution invocation with explicit host capabilities.
///
/// Production calls supply the environment-derived trust store and no
/// cancellation handle. Tests use this seam to exercise dispatcher behavior
/// with a controlled store and progress handle instead of adding a
/// user-facing flag that exists only for testing.
fn run_input_resolution_with(
    args: &[OsString],
    engine: &Engine,
    trust_store: &dyn nscb::SplitTrustStore,
    control: Option<&nscb::InputResolutionControl>,
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

    let mut capabilities = InputResolutionCapabilities::new().with_split_trust_store(trust_store);
    if let Some(control) = control {
        capabilities = capabilities.with_control(control);
    }
    match engine.resolve_inputs_with(request, capabilities) {
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
        Err(error) if parsed.json => emit_error(
            stdout,
            error.code().as_str(),
            input_resolution_exit_code(error.code()),
        ),
        Err(error) => {
            if writeln!(
                stderr,
                "{}",
                crate::localization::english::input_resolution_error(error.code())
            )
            .is_ok()
            {
                input_resolution_exit_code(error.code())
            } else {
                EXIT_INTERNAL
            }
        }
    }
}

fn input_resolution_exit_code(code: nscb::InputResolutionErrorCode) -> i32 {
    use nscb::InputResolutionErrorCode as Code;
    match code {
        Code::SplitTrustStoreConfigurationInvalid => EXIT_USAGE,
        Code::SplitStateUnavailable => EXIT_INTERNAL,
        Code::SplitResolutionCancelled => EXIT_CANCELLED,
        _ => EXIT_INPUT,
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

struct InspectionInvocation {
    input: PathBuf,
    key_file: Option<PathBuf>,
    cache_dir: Option<PathBuf>,
    allow_download: bool,
    preflight: bool,
    json: bool,
}

fn parse_inspection(args: &[OsString]) -> Result<InspectionInvocation, ()> {
    if args.first().is_none_or(|arg| arg != OsStr::new("inspect")) {
        return Err(());
    }
    let mut input = None;
    let mut key_file = None;
    let mut cache_dir = None;
    let mut allow_download = false;
    let mut preflight = false;
    let mut json = false;
    let mut iter = args.iter().skip(1);
    while let Some(argument) = iter.next() {
        if argument == OsStr::new("--json") {
            if json {
                return Err(());
            }
            json = true;
        } else if argument == OsStr::new("--allow-download") {
            if allow_download {
                return Err(());
            }
            allow_download = true;
        } else if argument == OsStr::new("--preflight") {
            if preflight {
                return Err(());
            }
            preflight = true;
        } else if argument == OsStr::new("--keys") {
            if key_file.is_some() {
                return Err(());
            }
            let value = iter.next().ok_or(())?;
            if value.to_str().is_some_and(|value| value.starts_with("--")) {
                return Err(());
            }
            key_file = Some(PathBuf::from(value));
        } else if argument == OsStr::new("--cache-dir") {
            if cache_dir.is_some() {
                return Err(());
            }
            let value = iter.next().ok_or(())?;
            if value.to_str().is_some_and(|value| value.starts_with("--")) {
                return Err(());
            }
            cache_dir = Some(PathBuf::from(value));
        } else if argument
            .to_str()
            .is_some_and(|value| value.starts_with("--"))
        {
            return Err(());
        } else if input.is_none() {
            input = Some(PathBuf::from(argument));
        } else {
            return Err(());
        }
    }
    Ok(InspectionInvocation {
        input: input.ok_or(())?,
        key_file,
        cache_dir,
        allow_download,
        preflight,
        json,
    })
}

fn run_inspection(
    args: &[OsString],
    engine: &Engine,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let json_requested = args.iter().any(|argument| argument == OsStr::new("--json"));
    let invocation = match parse_inspection(args) {
        Ok(invocation) => invocation,
        Err(()) => {
            if json_requested {
                return emit_error(stdout, "usage_error", EXIT_USAGE);
            }
            return if writeln!(
                stderr,
                "{}",
                crate::localization::english::inspection_usage()
            )
            .is_ok()
            {
                EXIT_USAGE
            } else {
                EXIT_INTERNAL
            };
        }
    };
    let key_file =
        match resolve_inspection_key_file(invocation.key_file, None, inspection_home_directory()) {
            Ok(path) => path,
            Err(code) => return emit_inspection_error(stdout, stderr, code, invocation.json),
        };
    let cache_dir = match invocation.cache_dir {
        Some(cache_dir) => cache_dir,
        None => match default_inspection_cache_dir() {
            Ok(cache_dir) => cache_dir,
            Err(code) => return emit_inspection_error(stdout, stderr, code, invocation.json),
        },
    };
    let cancellation = if invocation.preflight {
        None
    } else {
        match inspection_cancellation() {
            Ok(handle) => Some(handle),
            Err(code) => return emit_inspection_error(stdout, stderr, code, invocation.json),
        }
    };
    let mut host = if invocation.allow_download {
        InspectionHost::managed_download(cache_dir)
    } else {
        InspectionHost::cache_only(cache_dir)
    };
    if let Some(cancellation) = cancellation {
        host = host.with_cancellation(cancellation);
    }
    let request = InspectionRequest::nca(invocation.input, key_file);
    if invocation.preflight {
        return match engine.preflight_inspection(&request, &host) {
            Ok(status) if invocation.json => {
                if write_json(
                    &SuccessDocument {
                        schema_version: 1,
                        kind: "inspection.preflight",
                        nscb_version: env!("CARGO_PKG_VERSION"),
                        result: &status,
                    },
                    stdout,
                ) {
                    EXIT_SUCCESS
                } else {
                    report_output_failure(stderr)
                }
            }
            Ok(status) => {
                let message = match status {
                    InspectionPreflightStatus::Ready => {
                        crate::localization::english::inspection_preflight_ready()
                    }
                    InspectionPreflightStatus::ProvisioningRequired => {
                        crate::localization::english::inspection_preflight_provisioning_required()
                    }
                    _ => crate::localization::english::inspection_preflight_unknown(),
                };
                if writeln!(stdout, "{message}").is_ok() {
                    EXIT_SUCCESS
                } else {
                    report_output_failure(stderr)
                }
            }
            Err(error) => emit_inspection_error(stdout, stderr, error.code(), invocation.json),
        };
    }
    match engine.inspect(request, &host) {
        Ok(result) if invocation.json => {
            if write_json(
                &SuccessDocument {
                    schema_version: 1,
                    kind: "inspection.result",
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
            let message = match result {
                InspectionResult::Nca(inspection) => {
                    crate::localization::english::inspection_result(&inspection)
                }
                _ => crate::localization::english::inspection_unsupported_result().to_owned(),
            };
            if writeln!(stdout, "{message}").is_ok() {
                EXIT_SUCCESS
            } else {
                report_output_failure(stderr)
            }
        }
        Err(error) => emit_inspection_error(stdout, stderr, error.code(), invocation.json),
    }
}

fn resolve_inspection_key_file(
    explicit: Option<PathBuf>,
    configured: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Result<PathBuf, InspectionErrorCode> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    if let Some(path) = configured {
        return Ok(path);
    }
    let home = home.ok_or(InspectionErrorCode::InvalidKeyPath)?;
    Ok(home.join(".switch").join("prod.keys"))
}

fn resolve_home_directory(
    home: Option<PathBuf>,
    user_profile: Option<PathBuf>,
    is_windows: bool,
) -> Option<PathBuf> {
    home.or(if is_windows { user_profile } else { None })
}

fn inspection_home_directory() -> Option<PathBuf> {
    resolve_home_directory(
        std::env::var_os("HOME").map(PathBuf::from),
        std::env::var_os("USERPROFILE").map(PathBuf::from),
        cfg!(windows),
    )
}

fn emit_inspection_error(
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    code: InspectionErrorCode,
    json: bool,
) -> i32 {
    let exit = code.exit_class().code();
    if json {
        return emit_error(stdout, code.as_str(), exit);
    }
    if writeln!(
        stderr,
        "{}",
        crate::localization::english::inspection_error(code)
    )
    .is_ok()
    {
        exit
    } else {
        EXIT_INTERNAL
    }
}

#[cfg(unix)]
fn inspection_cancellation() -> Result<CancellationHandle, InspectionErrorCode> {
    let flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&flag))
        .map_err(|_| InspectionErrorCode::SignalHandlerFailed)?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&flag))
        .map_err(|_| InspectionErrorCode::SignalHandlerFailed)?;
    Ok(CancellationHandle::from_flag(flag))
}

#[cfg(not(unix))]
fn inspection_cancellation() -> Result<CancellationHandle, InspectionErrorCode> {
    Ok(CancellationHandle::new())
}

fn default_inspection_cache_dir() -> Result<PathBuf, InspectionErrorCode> {
    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or(InspectionErrorCode::InvalidCacheDirectory)?
        .join("Library/Caches");
    #[cfg(all(unix, not(target_os = "macos")))]
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .ok_or(InspectionErrorCode::InvalidCacheDirectory)?;
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or(InspectionErrorCode::InvalidCacheDirectory)?;
    Ok(base.join("nscb").join("providers"))
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
    use super::run_input_resolution_with;
    use super::synthetic_fixtures::{self, TempInput};
    use crate::localization::english;
    use nscb::{
        Engine, InputResolutionControl, LocalSplitTrustStore, Sha256Digest, SplitTrustReceipt,
        SplitTrustWriter,
    };
    use serde_json::Value;
    use std::ffi::OsString;
    use std::fs;
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

    #[test]
    fn cancelled_split_resolution_emits_one_json_error_and_exits_six() {
        let base = std::env::temp_dir().join(format!(
            "nscb-cli-cancelled-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        fs::create_dir_all(&base).unwrap();
        let directory = base.join("Game.nsp");
        fs::create_dir_all(&directory).unwrap();
        let parts = [b"abcdef".as_slice(), b"ghijkl".as_slice()];
        let mut segments = Vec::new();
        for (index, part) in parts.iter().enumerate() {
            fs::write(directory.join(format!("{index:02}")), part).unwrap();
            segments.push(serde_json::json!({
                "name": format!("{index:02}"),
                "size_bytes": part.len(),
                "sha256": Sha256Digest::digest(part).to_hex(),
            }));
        }
        let source = parts.concat();
        let manifest = serde_json::json!({
            "schema_version": 1,
            "kind": "nscb.split_manifest",
            "required_features": [],
            "source": {
                "size_bytes": source.len(),
                "sha256": Sha256Digest::digest(&source).to_hex(),
            },
            "segments": segments,
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(
            directory.with_file_name("Game.nsp.nscb-split.json"),
            &manifest_bytes,
        )
        .unwrap();
        let store = LocalSplitTrustStore::new(base.join("state").join("split-trust"));
        store
            .issue(SplitTrustReceipt::new(
                Sha256Digest::digest(&manifest_bytes),
                source.len() as u64,
                Sha256Digest::digest(&source),
            ))
            .unwrap();

        let control = InputResolutionControl::new();
        control.cancel();
        let args = vec![
            OsString::from("resolve"),
            OsString::from("--json"),
            directory.as_os_str().to_owned(),
        ];
        let engine = Engine::new();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run_input_resolution_with(
            &args,
            &engine,
            &store,
            Some(&control),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, 6);
        assert!(stderr.is_empty());
        assert_eq!(stdout.iter().filter(|byte| **byte == b'\n').count(), 1);
        let document: Value = serde_json::from_slice(&stdout).expect("one JSON error document");
        assert_eq!(document["error"]["code"], "split_resolution_cancelled");
        let _ = fs::remove_dir_all(base);
    }
}
