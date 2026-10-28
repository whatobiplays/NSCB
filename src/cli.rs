#[cfg(target_os = "macos")]
use crate::cli_reporting::{ReportingControl, ReportingSession};
use crate::standalone::StandaloneConfig;
use nscb::{
    CancellationHandle, ConflictPolicy, ContainerProbeError, ContainerProbeErrorCode,
    CopyThroughRequest, Engine, InputResolutionCapabilities, InputResolutionRequest,
    InputSelectionSource, InspectionErrorCode, InspectionHost, InspectionPreflightStatus,
    InspectionRequest, InspectionResult, JobState, LocalSplitTrustStore, OperationEventConsumer,
    OperationEventKind, OperationFailureCode, OperationPlan, OperationResult, OperationSession,
    OperationSessionSnapshot, SplitQualificationKind, VerificationErrorCode, VerificationProfile,
    VerificationRequest,
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
const EXIT_CONFLICT: i32 = 4;
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

    #[cfg(unix)]
    #[test]
    fn inspection_signal_guard_reaches_the_execution_boundary() {
        const CHILD_SIGNAL: &str = "NSCB_TEST_INSPECTION_EXECUTION_SIGNAL";
        if let Ok(signal) = std::env::var(CHILD_SIGNAL) {
            let signal = signal.parse::<i32>().expect("test signal number");
            assert!([signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM].contains(&signal));
            super::INSPECTION_EXECUTION_CHECKPOINT.set(Some(Box::new(move |handle| {
                let handle = handle.expect("inspection has an invocation cancellation handle");
                assert!(!handle.is_cancelled());
                signal_hook::low_level::raise(signal).expect("deliver isolated test signal");
                assert!(
                    handle.is_cancelled(),
                    "inspection signal action was unregistered before execution"
                );
            })));
            let root = tempfile::tempdir().expect("inspection signal fixture");
            let invocation = vec![
                OsString::from("inspect"),
                root.path().join("missing-input.nca").into_os_string(),
                OsString::from("--keys"),
                root.path().join("missing-keys").into_os_string(),
                OsString::from("--cache-dir"),
                root.path().join("cache").into_os_string(),
                OsString::from("--json"),
            ];
            // The checkpoint observes the same shared flag passed to the host,
            // before prerequisite validation. No provider or key material is used.
            assert_eq!(
                run(
                    &invocation,
                    &Engine::new(),
                    &mut Vec::new(),
                    &mut Vec::new()
                ),
                3
            );
            assert!(super::INSPECTION_EXECUTION_CHECKPOINT.take().is_none());
            assert!(!root.path().join("cache").exists());
            return;
        }
        for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "cli::inspection_cli_tests::inspection_signal_guard_reaches_the_execution_boundary", "--nocapture"])
                .env(CHILD_SIGNAL, signal.to_string())
                .output()
                .expect("run isolated signal test");
            assert!(
                output.status.success(),
                "signal {signal}: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
        }
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
    fn configured_key_selection_precedes_home_without_requiring_file_existence() {
        let configured = PathBuf::from("/fixture/configured-missing.keys");
        assert_eq!(
            super::resolve_inspection_key_file(
                None,
                Some(configured.clone()),
                Some(PathBuf::from("/fixture/home")),
            )
            .unwrap(),
            configured
        );
    }

    #[test]
    fn shared_cli_key_file_resolver_preserves_explicit_and_home_defaults() {
        let home = PathBuf::from("/fixture/home");
        assert_eq!(
            super::resolve_cli_key_file(
                Some(PathBuf::from("/explicit/prod.keys")),
                None,
                Some(home.clone()),
            )
            .unwrap(),
            PathBuf::from("/explicit/prod.keys")
        );
        assert_eq!(
            super::resolve_cli_key_file(None, None, Some(home.clone())).unwrap(),
            home.join(".switch").join("prod.keys")
        );
        assert!(super::resolve_cli_key_file(None, None, None).is_err());
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

    #[test]
    fn verification_error_renderer_preserves_conflict_cancelled_and_internal_exits() {
        for (code, expected) in [
            (
                nscb::VerificationErrorCode::InputChangedDuringVerification,
                4,
            ),
            (nscb::VerificationErrorCode::Cancelled, 6),
            (nscb::VerificationErrorCode::InternalIo, 7),
        ] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            assert_eq!(
                super::emit_verification_error(&mut stdout, &mut stderr, code, true),
                expected
            );
            assert!(!stdout.is_empty());
            assert!(stderr.is_empty());
        }
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
#[cfg(any(test, not(target_os = "macos")))]
pub(crate) fn run(
    args: &[OsString],
    engine: &Engine,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    #[cfg(target_os = "macos")]
    {
        run_with_control(args, engine, None, stdout, stderr, None)
    }
    #[cfg(not(target_os = "macos"))]
    {
        run_with_control(args, engine, None, stdout, stderr)
    }
}

pub(crate) fn run_with_standalone_config(
    args: &[OsString],
    engine: &Engine,
    config: &StandaloneConfig,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    #[cfg(target_os = "macos")]
    {
        run_with_control(args, engine, Some(config), stdout, stderr, None)
    }
    #[cfg(not(target_os = "macos"))]
    {
        run_with_control(args, engine, Some(config), stdout, stderr)
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn run_with_reporting_and_standalone_config(
    args: &[OsString],
    engine: &Engine,
    config: &StandaloneConfig,
    reporting: &mut ReportingSession,
) -> i32 {
    let control = reporting.control();
    let (stdout, stderr) = reporting.writers();
    run_with_control(args, engine, Some(config), stdout, stderr, Some(&control))
}

pub(crate) fn is_copy_command(args: &[OsString]) -> bool {
    args.first()
        .is_some_and(|argument| argument == OsStr::new("copy"))
}

fn run_with_control(
    args: &[OsString],
    engine: &Engine,
    standalone: Option<&StandaloneConfig>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    #[cfg(target_os = "macos")] reporting: Option<&ReportingControl>,
) -> i32 {
    if is_copy_command(args) {
        #[cfg(target_os = "macos")]
        {
            return run_copy_with_control(args, engine, standalone, stdout, stderr, reporting);
        }
        #[cfg(not(target_os = "macos"))]
        {
            return run_copy_with_standalone_config(args, engine, standalone, stdout, stderr);
        }
    }

    if args
        .first()
        .is_some_and(|argument| argument == OsStr::new("inspect"))
    {
        return run_inspection(args, engine, standalone, stdout, stderr);
    }

    if args
        .first()
        .is_some_and(|argument| argument == OsStr::new("resolve"))
    {
        return run_input_resolution(args, engine, stdout, stderr);
    }

    if args
        .first()
        .is_some_and(|argument| argument == OsStr::new("verify"))
    {
        return run_verification(args, engine, standalone, stdout, stderr);
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

#[cfg(all(test, unix))]
type InspectionExecutionCheckpoint = Box<dyn FnOnce(Option<&CancellationHandle>)>;

#[cfg(all(test, unix))]
thread_local! {
    // A thread-local test seam observes signal delivery at the real CLI handoff.
    // Test processes isolate signal dispositions; ordinary tests install no hook.
    static INSPECTION_EXECUTION_CHECKPOINT: std::cell::Cell<Option<InspectionExecutionCheckpoint>> = const { std::cell::Cell::new(None) };
}

fn run_inspection(
    args: &[OsString],
    engine: &Engine,
    standalone: Option<&StandaloneConfig>,
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
        match resolve_cli_key_file(invocation.key_file, standalone, inspection_home_directory()) {
            Ok(path) => path,
            Err(_) => {
                return emit_inspection_error(
                    stdout,
                    stderr,
                    InspectionErrorCode::InvalidKeyPath,
                    invocation.json,
                );
            }
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
        match scoped_cancellation() {
            Ok(handle) => Some(handle),
            Err(code) => return emit_inspection_error(stdout, stderr, code, invocation.json),
        }
    };
    #[cfg(all(test, unix))]
    let inspection_cancellation = cancellation.as_ref().map(|guard| guard.handle().clone());
    let mut host = if invocation.allow_download {
        InspectionHost::managed_download(cache_dir)
    } else {
        InspectionHost::cache_only(cache_dir)
    };
    if let Some(cancellation) = &cancellation {
        host = host.with_cancellation(cancellation.handle().clone());
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
    #[cfg(all(test, unix))]
    if let Some(checkpoint) = INSPECTION_EXECUTION_CHECKPOINT.take() {
        checkpoint(inspection_cancellation.as_ref());
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CliKeyFileResolutionError {
    InvalidPath,
}

fn resolve_cli_key_file(
    explicit: Option<PathBuf>,
    standalone: Option<&StandaloneConfig>,
    home: Option<PathBuf>,
) -> Result<PathBuf, CliKeyFileResolutionError> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    let configured = standalone
        .map(|config| config.effective_key_file())
        .transpose()
        .map_err(|_| CliKeyFileResolutionError::InvalidPath)?;
    resolve_inspection_key_file(None, configured, home)
        .map_err(|_| CliKeyFileResolutionError::InvalidPath)
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

struct VerificationInvocation {
    input: PathBuf,
    key_file: Option<PathBuf>,
    profile: VerificationProfile,
    trust_anchor: Option<PathBuf>,
    anchor_generation: Option<u8>,
    json: bool,
}

fn parse_verification(args: &[OsString]) -> Result<VerificationInvocation, ()> {
    if args.first().is_none_or(|arg| arg != OsStr::new("verify")) {
        return Err(());
    }
    let mut input = None;
    let mut key_file = None;
    let mut profile = VerificationProfile::Full;
    let mut profile_set = false;
    let mut trust_anchor = None;
    let mut anchor_generation = None;
    let mut json = false;
    let mut iter = args.iter().skip(1);
    while let Some(argument) = iter.next() {
        if argument == OsStr::new("--json") {
            if json {
                return Err(());
            }
            json = true;
        } else if argument == OsStr::new("--profile") {
            if profile_set {
                return Err(());
            }
            let value = iter.next().ok_or(())?;
            profile = match value.to_str() {
                Some("full") => VerificationProfile::Full,
                Some("structural") => VerificationProfile::Structural,
                _ => return Err(()),
            };
            profile_set = true;
        } else if argument == OsStr::new("--keys") {
            if key_file.is_some() {
                return Err(());
            }
            let value = iter.next().ok_or(())?;
            if value.to_str().is_some_and(|value| value.starts_with("--")) {
                return Err(());
            }
            key_file = Some(PathBuf::from(value));
        } else if argument == OsStr::new("--trust-anchor") {
            if trust_anchor.is_some() {
                return Err(());
            }
            let value = iter.next().ok_or(())?;
            if value.to_str().is_some_and(|value| value.starts_with("--")) {
                return Err(());
            }
            trust_anchor = Some(PathBuf::from(value));
        } else if argument == OsStr::new("--anchor-generation") {
            if anchor_generation.is_some() {
                return Err(());
            }
            let value = iter.next().ok_or(())?;
            anchor_generation = Some(value.to_str().ok_or(())?.parse::<u8>().map_err(|_| ())?);
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
    Ok(VerificationInvocation {
        input: input.ok_or(())?,
        key_file,
        profile,
        trust_anchor,
        anchor_generation,
        json,
    })
}

fn run_verification(
    args: &[OsString],
    engine: &Engine,
    standalone: Option<&StandaloneConfig>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let json_requested = args.iter().any(|argument| argument == OsStr::new("--json"));
    let invocation = match parse_verification(args) {
        Ok(invocation) => invocation,
        Err(()) => {
            if json_requested {
                return emit_error(stdout, "usage_error", EXIT_USAGE);
            }
            return if writeln!(
                stderr,
                "{}",
                crate::localization::english::verification_usage()
            )
            .is_ok()
            {
                EXIT_USAGE
            } else {
                EXIT_INTERNAL
            };
        }
    };
    if invocation.profile == VerificationProfile::Structural
        && (invocation.trust_anchor.is_some() || invocation.anchor_generation.is_some())
    {
        if invocation.json {
            return emit_error(stdout, "usage_error", EXIT_USAGE);
        }
        return if writeln!(
            stderr,
            "{}",
            crate::localization::english::verification_usage()
        )
        .is_ok()
        {
            EXIT_USAGE
        } else {
            EXIT_INTERNAL
        };
    }
    let key_file =
        match resolve_cli_key_file(invocation.key_file, standalone, inspection_home_directory()) {
            Ok(path) => path,
            Err(_) => {
                return emit_verification_error(
                    stdout,
                    stderr,
                    VerificationErrorCode::InvalidKeyPath,
                    invocation.json,
                );
            }
        };
    let cancellation = match scoped_cancellation() {
        Ok(handle) => handle,
        Err(_) => {
            return emit_verification_error(
                stdout,
                stderr,
                VerificationErrorCode::SignalHandlerFailed,
                invocation.json,
            );
        }
    };
    let request = match invocation.profile {
        VerificationProfile::Full => {
            let Some(trust_anchor) = invocation.trust_anchor else {
                return emit_verification_error(
                    stdout,
                    stderr,
                    VerificationErrorCode::MissingTrustAnchor,
                    invocation.json,
                );
            };
            let Some(anchor_generation) = invocation.anchor_generation else {
                return emit_verification_error(
                    stdout,
                    stderr,
                    VerificationErrorCode::MissingAnchorGeneration,
                    invocation.json,
                );
            };
            VerificationRequest::full_nca(
                invocation.input,
                key_file,
                trust_anchor,
                anchor_generation,
            )
        }
        _ => VerificationRequest::structural_nca(invocation.input, key_file),
    }
    .with_cancellation(cancellation.handle().clone());
    match engine.verify(request) {
        Ok(result) if invocation.json => {
            let exit = verification_exit(&result);
            if write_json(
                &SuccessDocument {
                    schema_version: 1,
                    kind: "verification.result",
                    nscb_version: env!("CARGO_PKG_VERSION"),
                    result: &result,
                },
                stdout,
            ) {
                exit
            } else {
                report_output_failure(stderr)
            }
        }
        Ok(result) => {
            let exit = verification_exit(&result);
            if writeln!(
                stdout,
                "{}",
                crate::localization::english::verification_result(&result)
            )
            .is_ok()
            {
                exit
            } else {
                report_output_failure(stderr)
            }
        }
        Err(error) => emit_verification_error(stdout, stderr, error.code(), invocation.json),
    }
}

fn verification_exit(result: &nscb::VerificationResult) -> i32 {
    match result.outcome {
        nscb::VerificationOutcome::Passed => EXIT_SUCCESS,
        nscb::VerificationOutcome::Failed => EXIT_INPUT,
        _ => EXIT_INPUT,
    }
}

fn emit_verification_error(
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    code: VerificationErrorCode,
    json: bool,
) -> i32 {
    let exit = code.exit_code();
    if json {
        return emit_error(stdout, code.as_str(), exit);
    }
    if writeln!(
        stderr,
        "{}",
        crate::localization::english::verification_error(code)
    )
    .is_ok()
    {
        exit
    } else {
        EXIT_INTERNAL
    }
}

/// Signal registrations owned by one command invocation.
///
/// Dropping the guard unregisters the signal-hook actions it created.
/// Signal-hook 0.3 does not restore the process's previous signal disposition
/// when its final action is unregistered, so this type deliberately does not
/// claim process-global restoration. Long-lived hosts should run commands in an
/// isolated process and must not rely on a later default-disposition signal.
struct ScopedCancellation {
    handle: CancellationHandle,
    #[cfg(unix)]
    registrations: Vec<signal_hook::SigId>,
}

impl ScopedCancellation {
    fn handle(&self) -> &CancellationHandle {
        &self.handle
    }
}

#[cfg(unix)]
impl Drop for ScopedCancellation {
    fn drop(&mut self) {
        for registration in self.registrations.drain(..) {
            signal_hook::low_level::unregister(registration);
        }
    }
}

#[cfg(unix)]
fn register_cancellation_signal(
    signal: i32,
    flag: &Arc<AtomicBool>,
) -> std::io::Result<signal_hook::SigId> {
    #[cfg(test)]
    if signal == signal_hook::consts::SIGTERM {
        let fail = SIGNAL_REGISTRATION_TEST_STATE.with(|state| {
            let mut state = state.borrow_mut();
            std::mem::take(&mut state.fail_next_sigterm)
        });
        if fail {
            return Err(std::io::Error::other(
                "injected signal registration failure",
            ));
        }
    }

    let registration = signal_hook::flag::register(signal, Arc::clone(flag))?;
    #[cfg(test)]
    SIGNAL_REGISTRATION_TEST_STATE.with(|state| {
        state.borrow_mut().last_registration = Some(registration);
    });
    Ok(registration)
}

#[cfg(all(unix, test))]
#[derive(Default)]
struct SignalRegistrationTestState {
    fail_next_sigterm: bool,
    last_registration: Option<signal_hook::SigId>,
}

#[cfg(all(unix, test))]
thread_local! {
    static SIGNAL_REGISTRATION_TEST_STATE: std::cell::RefCell<SignalRegistrationTestState> =
        std::cell::RefCell::new(SignalRegistrationTestState::default());
}

#[cfg(unix)]
fn scoped_cancellation() -> Result<ScopedCancellation, InspectionErrorCode> {
    let flag = Arc::new(AtomicBool::new(false));
    let mut registrations = Vec::new();
    let interrupt = register_cancellation_signal(signal_hook::consts::SIGINT, &flag)
        .map_err(|_| InspectionErrorCode::SignalHandlerFailed)?;
    registrations.push(interrupt);
    match register_cancellation_signal(signal_hook::consts::SIGTERM, &flag) {
        Ok(registration) => registrations.push(registration),
        Err(_) => {
            signal_hook::low_level::unregister(interrupt);
            return Err(InspectionErrorCode::SignalHandlerFailed);
        }
    }
    Ok(ScopedCancellation {
        handle: CancellationHandle::from_flag(flag),
        registrations,
    })
}

#[cfg(not(unix))]
fn scoped_cancellation() -> Result<ScopedCancellation, InspectionErrorCode> {
    Ok(ScopedCancellation {
        handle: CancellationHandle::new(),
    })
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
    let Ok(mut document) = serde_json::to_vec(document) else {
        return false;
    };
    document.push(b'\n');
    stdout.write_all(&document).is_ok()
}

struct CopyInvocation {
    source: PathBuf,
    destination: Option<PathBuf>,
    workspace: Option<PathBuf>,
    replace: bool,
    json: bool,
    jsonl: bool,
}

fn parse_copy(args: &[OsString]) -> Result<CopyInvocation, ()> {
    if args
        .first()
        .is_none_or(|argument| argument != OsStr::new("copy"))
    {
        return Err(());
    }
    let mut positionals = Vec::new();
    let mut workspace = None;
    let mut replace = false;
    let mut json = false;
    let mut jsonl = false;
    let mut index = 1;
    while index < args.len() {
        let argument = &args[index];
        if argument == OsStr::new("--workspace") {
            if workspace.is_some() {
                return Err(());
            }
            index += 1;
            let value = args.get(index).ok_or(())?;
            if value
                .to_str()
                .is_some_and(|argument| argument.starts_with("--"))
            {
                return Err(());
            }
            workspace = Some(PathBuf::from(value));
        } else if argument == OsStr::new("--replace") {
            if replace {
                return Err(());
            }
            replace = true;
        } else if argument == OsStr::new("--json") {
            if json {
                return Err(());
            }
            json = true;
        } else if argument == OsStr::new("--jsonl") {
            if jsonl {
                return Err(());
            }
            jsonl = true;
        } else if argument
            .to_str()
            .is_some_and(|value| value.starts_with("--"))
        {
            return Err(());
        } else {
            positionals.push(PathBuf::from(argument));
        }
        index += 1;
    }
    if json && jsonl {
        return Err(());
    }
    if !(1..=2).contains(&positionals.len()) {
        return Err(());
    }
    let destination = if positionals.len() == 2 {
        Some(positionals.pop().ok_or(())?)
    } else {
        None
    };
    let source = positionals.pop().ok_or(())?;
    Ok(CopyInvocation {
        source,
        destination,
        workspace,
        replace,
        json,
        jsonl,
    })
}

fn default_copy_workspace() -> PathBuf {
    std::env::temp_dir().join("nscb-copy-through")
}

fn copy_plan_paths_are_json_representable(plan: &OperationPlan) -> bool {
    let snapshot = plan.snapshot();
    paths_are_json_representable(
        std::iter::once(snapshot.source().path())
            .chain(std::iter::once(snapshot.destination()))
            .chain(std::iter::once(snapshot.workspace()))
            .chain(std::iter::once(snapshot.destination_lock_path()))
            .chain(
                snapshot
                    .planned_artifacts()
                    .iter()
                    .map(|artifact| artifact.path()),
            ),
    )
}

fn paths_are_json_representable<'a>(paths: impl IntoIterator<Item = &'a Path>) -> bool {
    paths.into_iter().all(|path| path.to_str().is_some())
}

fn exit_for_operation_failure(code: OperationFailureCode) -> i32 {
    match code {
        OperationFailureCode::DestinationConflict | OperationFailureCode::DestinationChanged => {
            EXIT_CONFLICT
        }
        OperationFailureCode::SourceUnavailable
        | OperationFailureCode::SplitInputUnsupported
        | OperationFailureCode::SourceChanged
        | OperationFailureCode::StalePlan
        | OperationFailureCode::WorkspaceUnavailable
        | OperationFailureCode::DestinationUnavailable
        | OperationFailureCode::UnsafePath
        | OperationFailureCode::UnsupportedCapability
        | OperationFailureCode::InsufficientStorage => EXIT_INPUT,
        OperationFailureCode::Cancelled => EXIT_CANCELLED,
        _ => EXIT_INTERNAL,
    }
}

fn exit_for_operation_result(result: &OperationResult) -> i32 {
    match result.state() {
        JobState::Succeeded => EXIT_SUCCESS,
        JobState::Cancelled => EXIT_CANCELLED,
        JobState::Failed => result
            .failure()
            .map(|failure| exit_for_operation_failure(failure.code()))
            .unwrap_or(EXIT_INTERNAL),
        _ => EXIT_INTERNAL,
    }
}

#[derive(Serialize)]
struct JobEventDocument<'a> {
    schema_version: u8,
    kind: &'static str,
    nscb_version: &'static str,
    sequence: u64,
    snapshot: OperationSessionSnapshot,
    #[serde(flatten)]
    event: &'a OperationEventKind,
}

#[derive(Serialize)]
struct JobResultDocument<'a> {
    schema_version: u8,
    kind: &'static str,
    nscb_version: &'static str,
    sequence: u64,
    snapshot: OperationSessionSnapshot,
    result: &'a OperationResult,
}

fn stream_job_events(
    consumer: &OperationEventConsumer,
    stdout: &mut dyn Write,
    worker: &std::thread::JoinHandle<OperationResult>,
) -> (bool, bool) {
    let mut output_ok = true;
    let mut terminal_written = false;
    loop {
        let event = match consumer.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(event) => event,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if !worker.is_finished() {
                    continue;
                }
                match consumer.try_recv() {
                    Ok(event) => event,
                    Err(_) => break,
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        };
        let wrote = match event.event() {
            OperationEventKind::Completed { result } => {
                terminal_written = true;
                write_json(
                    &JobResultDocument {
                        schema_version: 1,
                        kind: "job.result",
                        nscb_version: env!("CARGO_PKG_VERSION"),
                        sequence: event.sequence(),
                        snapshot: event.snapshot(),
                        result,
                    },
                    stdout,
                )
            }
            _ => write_json(
                &JobEventDocument {
                    schema_version: 1,
                    kind: "job.event",
                    nscb_version: env!("CARGO_PKG_VERSION"),
                    sequence: event.sequence(),
                    snapshot: event.snapshot(),
                    event: event.event(),
                },
                stdout,
            ),
        };
        output_ok &= wrote && stdout.flush().is_ok();
    }
    (output_ok, terminal_written)
}

fn write_last_job_completion(session: &OperationSession, stdout: &mut dyn Write) -> bool {
    let Ok(Some(completion)) = session.last_completion() else {
        return false;
    };
    write_json(
        &JobResultDocument {
            schema_version: 1,
            kind: "job.result",
            nscb_version: env!("CARGO_PKG_VERSION"),
            sequence: completion.sequence(),
            snapshot: completion.snapshot(),
            result: completion.result(),
        },
        stdout,
    )
}

#[cfg(any(test, not(target_os = "macos")))]
fn run_copy(
    args: &[OsString],
    engine: &Engine,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    #[cfg(target_os = "macos")]
    {
        run_copy_with_control(args, engine, None, stdout, stderr, None)
    }
    #[cfg(not(target_os = "macos"))]
    {
        run_copy_impl(args, engine, None, stdout, stderr)
    }
}

#[cfg(not(target_os = "macos"))]
fn run_copy_with_standalone_config(
    args: &[OsString],
    engine: &Engine,
    standalone: Option<&StandaloneConfig>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    run_copy_impl(args, engine, standalone, stdout, stderr)
}

#[cfg(target_os = "macos")]
fn run_copy_with_control(
    args: &[OsString],
    engine: &Engine,
    standalone: Option<&StandaloneConfig>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    reporting: Option<&ReportingControl>,
) -> i32 {
    run_copy_impl(args, engine, standalone, stdout, stderr, reporting)
}

fn run_copy_impl(
    args: &[OsString],
    engine: &Engine,
    standalone: Option<&StandaloneConfig>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    #[cfg(target_os = "macos")] reporting: Option<&ReportingControl>,
) -> i32 {
    let machine_requested = args
        .iter()
        .any(|argument| argument == OsStr::new("--json") || argument == OsStr::new("--jsonl"));
    let invocation = match parse_copy(args) {
        Ok(invocation) => invocation,
        Err(()) => {
            #[cfg(target_os = "macos")]
            if let Some(reporting) = reporting {
                reporting.pre_admission_complete();
            }
            if machine_requested {
                return emit_error(stdout, "usage_error", EXIT_USAGE);
            }
            return if write_copy_record(stderr, crate::localization::english::copy_usage()) {
                EXIT_USAGE
            } else {
                EXIT_INTERNAL
            };
        }
    };
    let destination = match invocation.destination {
        Some(destination) => destination,
        None => {
            let Some(config) = standalone else {
                #[cfg(target_os = "macos")]
                if let Some(reporting) = reporting {
                    reporting.pre_admission_complete();
                }
                if machine_requested {
                    return emit_error(stdout, "usage_error", EXIT_USAGE);
                }
                return if write_copy_record(stderr, crate::localization::english::copy_usage()) {
                    EXIT_USAGE
                } else {
                    EXIT_INTERNAL
                };
            };
            match config.copy_destination(&invocation.source) {
                Ok(destination) => destination,
                Err(error) => {
                    #[cfg(target_os = "macos")]
                    if let Some(reporting) = reporting {
                        reporting.pre_admission_complete();
                    }
                    if machine_requested {
                        return emit_error(stdout, error.code(), EXIT_INPUT);
                    }
                    return if write_copy_record(
                        stderr,
                        crate::localization::english::copy_error_message(error.code()),
                    ) {
                        EXIT_INPUT
                    } else {
                        EXIT_INTERNAL
                    };
                }
            }
        }
    };
    if machine_requested
        && !paths_are_json_representable(
            std::iter::once(invocation.source.as_path())
                .chain(std::iter::once(destination.as_path()))
                .chain(invocation.workspace.as_deref()),
        )
    {
        #[cfg(target_os = "macos")]
        if let Some(reporting) = reporting {
            reporting.pre_admission_complete();
        }
        return emit_error(stdout, "unrepresentable_path", EXIT_INPUT);
    }

    let request = match invocation.workspace {
        Some(workspace) => CopyThroughRequest::new(&invocation.source, &destination, workspace),
        None => CopyThroughRequest::with_host_default_workspace(
            &invocation.source,
            &destination,
            default_copy_workspace(),
        ),
    };
    let request = if invocation.replace {
        request.with_conflict_policy(ConflictPolicy::Replace)
    } else {
        request
    };
    let cancellation = match scoped_cancellation() {
        Ok(cancellation) => cancellation,
        Err(_) => {
            #[cfg(target_os = "macos")]
            if let Some(reporting) = reporting {
                reporting.pre_admission_complete();
            }
            if machine_requested {
                return emit_error(stdout, "signal_handler_failed", EXIT_INTERNAL);
            }
            let _ = write_copy_record(stderr, crate::localization::english::copy_signal_failure());
            return EXIT_INTERNAL;
        }
    };
    #[cfg(target_os = "macos")]
    if let Some(reporting) = reporting {
        reporting.begin_planning();
    }
    let plan = match plan_copy_through_for_cli(|| engine.plan_copy_through(request)) {
        Ok(plan) => plan,
        Err(error) => {
            #[cfg(target_os = "macos")]
            if let Some(reporting) = reporting {
                reporting.pre_admission_complete();
            }
            if machine_requested {
                return emit_error(
                    stdout,
                    error.code().as_str(),
                    exit_for_operation_failure(error.code()),
                );
            }
            return if write_copy_record(
                stderr,
                crate::localization::english::copy_error(error.code()),
            ) {
                exit_for_operation_failure(error.code())
            } else {
                EXIT_INTERNAL
            };
        }
    };
    if machine_requested && !copy_plan_paths_are_json_representable(&plan) {
        #[cfg(target_os = "macos")]
        if let Some(reporting) = reporting {
            reporting.pre_admission_complete();
        }
        return emit_error(stdout, "unrepresentable_path", EXIT_INPUT);
    }

    let session = OperationSession::new();
    if invocation.jsonl {
        let consumer = match session.subscribe_events() {
            Ok(consumer) => consumer,
            Err(code) => {
                #[cfg(target_os = "macos")]
                if let Some(reporting) = reporting {
                    reporting.pre_admission_complete();
                }
                return emit_error(stdout, code.as_str(), exit_for_operation_failure(code));
            }
        };
        let execution_session = session.clone();
        let execution_cancellation = cancellation.handle().clone();
        #[cfg(target_os = "macos")]
        let execution_reporting = reporting.cloned();
        let worker = match spawn_copy_worker(move || {
            let result = Engine::new().execute_operation_with_cancellation(
                plan,
                &execution_session,
                execution_cancellation,
            );
            #[cfg(target_os = "macos")]
            if let Some(reporting) = execution_reporting {
                reporting.job_complete();
            }
            result
        }) {
            Ok(worker) => worker,
            Err(_) => {
                #[cfg(target_os = "macos")]
                if let Some(reporting) = reporting {
                    reporting.pre_admission_complete();
                }
                drop(consumer);
                drop(session);
                drop(cancellation);
                return emit_error(stdout, "execution_worker_start_failed", EXIT_INTERNAL);
            }
        };
        let (output_ok, terminal_written) = stream_job_events(&consumer, stdout, &worker);
        let result = match worker.join() {
            Ok(result) => result,
            Err(_) => {
                #[cfg(target_os = "macos")]
                if let Some(reporting) = reporting {
                    reporting.job_complete();
                }
                let _ = write_copy_record(
                    stderr,
                    crate::localization::english::copy_internal_failure(),
                );
                return EXIT_INTERNAL;
            }
        };
        drop(cancellation);
        let mut output_ok = output_ok;
        if !terminal_written && output_ok {
            output_ok = write_last_job_completion(&session, stdout);
        }
        if !output_ok {
            #[cfg(target_os = "macos")]
            let managed = reporting.is_some();
            #[cfg(target_os = "macos")]
            if let Some(reporting) = reporting {
                reporting.fail();
            }
            #[cfg(not(target_os = "macos"))]
            let managed = false;
            if !managed {
                let _ = write_copy_record(stderr, crate::localization::english::output_failure());
            }
        }
        return exit_for_operation_result(&result);
    }

    let result =
        engine.execute_operation_with_cancellation(plan, &session, cancellation.handle().clone());
    #[cfg(target_os = "macos")]
    if let Some(reporting) = reporting {
        reporting.job_complete();
    }
    drop(cancellation);
    if invocation.json {
        if !write_last_job_completion(&session, stdout) {
            #[cfg(target_os = "macos")]
            let managed = reporting.is_some();
            #[cfg(target_os = "macos")]
            if let Some(reporting) = reporting {
                reporting.fail();
            }
            #[cfg(not(target_os = "macos"))]
            let managed = false;
            if !managed {
                let _ = write_copy_record(stderr, crate::localization::english::output_failure());
            }
        }
    } else {
        let written = write_human_copy_result(&result, stdout, stderr);
        if !written {
            #[cfg(target_os = "macos")]
            let managed = reporting.is_some();
            #[cfg(not(target_os = "macos"))]
            let managed = false;
            if !managed {
                let _ = write_copy_record(stderr, crate::localization::english::output_failure());
            }
        }
    }
    exit_for_operation_result(&result)
}

#[cfg(all(test, target_os = "macos"))]
type CopyPlanHandoffCheckpoint = Box<dyn FnOnce()>;

#[cfg(all(test, target_os = "macos"))]
type CopyPlanEntryCheckpoint = Box<dyn FnOnce()>;

#[cfg(all(test, target_os = "macos"))]
thread_local! {
    static COPY_PLAN_HANDOFF_CHECKPOINT: std::cell::Cell<Option<CopyPlanHandoffCheckpoint>> = const { std::cell::Cell::new(None) };
    static COPY_PLAN_ENTRY_CHECKPOINT: std::cell::Cell<Option<CopyPlanEntryCheckpoint>> = const { std::cell::Cell::new(None) };
}

/// Runs synchronous copy planning before the CLI admits an operation.
///
/// The macOS-only test checkpoint at entry runs after the invocation's signal
/// guard is installed and immediately before the Engine begins planning. It
/// verifies that the invocation-local guard is live before synchronous
/// planning starts.
/// The macOS-only test checkpoint runs after the Engine planner returns and
/// before the CLI admits the plan. It verifies that an invocation-local signal
/// received at this handoff cancels before staging. A separate operation test
/// pauses inside the Engine planner to verify signal delivery during planning.
fn plan_copy_through_for_cli<T>(planner: impl FnOnce() -> T) -> T {
    #[cfg(all(test, target_os = "macos"))]
    if let Some(checkpoint) = COPY_PLAN_ENTRY_CHECKPOINT.take() {
        checkpoint();
    }
    let plan = planner();
    #[cfg(all(test, target_os = "macos"))]
    if let Some(checkpoint) = COPY_PLAN_HANDOFF_CHECKPOINT.take() {
        checkpoint();
    }
    plan
}

#[cfg(all(test, target_os = "macos"))]
thread_local! {
    static COPY_WORKER_START_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn spawn_copy_worker(
    worker: impl FnOnce() -> OperationResult + Send + 'static,
) -> std::io::Result<std::thread::JoinHandle<OperationResult>> {
    #[cfg(all(test, target_os = "macos"))]
    if COPY_WORKER_START_FAILURE.with(|failure| failure.replace(false)) {
        return Err(std::io::Error::other("injected worker startup failure"));
    }
    std::thread::Builder::new().spawn(worker)
}

fn write_copy_record(writer: &mut dyn Write, message: &str) -> bool {
    let mut record = message.as_bytes().to_vec();
    record.push(b'\n');
    writer.write_all(&record).is_ok()
}

/// Writes successful human results to stdout and failed or cancelled results to stderr.
fn write_human_copy_result(
    result: &OperationResult,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> bool {
    let message = crate::localization::english::copy_result(result);
    if result.state() == JobState::Succeeded {
        write_copy_record(stdout, &message)
    } else {
        write_copy_record(stderr, &message)
    }
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

#[cfg(test)]
mod copy_cli_tests {
    #[cfg(unix)]
    use super::SIGNAL_REGISTRATION_TEST_STATE;
    use super::{
        Engine, exit_for_operation_failure, parse_copy, paths_are_json_representable, run_copy,
        scoped_cancellation, write_json,
    };
    #[cfg(target_os = "macos")]
    use super::{exit_for_operation_result, write_human_copy_result};
    use nscb::OperationFailureCode;
    #[cfg(target_os = "macos")]
    use nscb::{CancellationHandle, CopyThroughRequest, JobState, OperationSession};
    use std::ffi::OsString;
    use std::fs;
    #[cfg(target_os = "macos")]
    use std::io::{self, Write};
    use std::path::{Path, PathBuf};
    #[cfg(target_os = "macos")]
    use std::sync::mpsc;
    #[cfg(target_os = "macos")]
    use std::time::{Duration, Instant};

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[cfg(target_os = "macos")]
    fn signal_at_plan_handoff(signal: i32) -> std::thread::JoinHandle<()> {
        let (entered_sender, entered_receiver) = mpsc::channel();
        let (resume_sender, resume_receiver) = mpsc::channel();
        super::COPY_PLAN_HANDOFF_CHECKPOINT.set(Some(Box::new(move || {
            entered_sender
                .send(())
                .expect("signal thread waits for the plan handoff");
            resume_receiver
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("signal thread releases the plan handoff");
        })));

        std::thread::spawn(move || {
            entered_receiver
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("copy planner reaches the synchronized result handoff");
            signal_hook::low_level::raise(signal).expect("deliver signal during planning");
            resume_sender
                .send(())
                .expect("copy plan handoff waits for signal delivery");
        })
    }

    #[cfg(target_os = "macos")]
    fn signal_at_plan_entry(signal: i32) -> std::thread::JoinHandle<()> {
        let (entered_sender, entered_receiver) = mpsc::channel();
        let (resume_sender, resume_receiver) = mpsc::channel();
        super::COPY_PLAN_ENTRY_CHECKPOINT.set(Some(Box::new(move || {
            entered_sender
                .send(())
                .expect("signal thread waits for CLI planning entry");
            resume_receiver
                .recv_timeout(Duration::from_secs(5))
                .expect("signal thread releases CLI planning");
        })));

        std::thread::spawn(move || {
            entered_receiver
                .recv_timeout(Duration::from_secs(5))
                .expect("CLI reaches the synchronous planning entry");
            signal_hook::low_level::raise(signal).expect("deliver signal while CLI guard is live");
            resume_sender
                .send(())
                .expect("CLI planning waits for signal delivery");
        })
    }

    #[test]
    fn copy_parser_accepts_explicit_destination_and_options_in_any_order() {
        let parsed = parse_copy(&args(&[
            "copy",
            "--replace",
            "source.bin",
            "--workspace",
            "staging",
            "destination.bin",
            "--jsonl",
        ]))
        .expect("valid copy invocation");
        assert_eq!(parsed.source, std::path::Path::new("source.bin"));
        assert_eq!(
            parsed.destination.as_deref(),
            Some(std::path::Path::new("destination.bin"))
        );
        assert_eq!(
            parsed.workspace.as_deref(),
            Some(std::path::Path::new("staging"))
        );
        assert!(parsed.replace);
        assert!(parsed.jsonl);
        assert!(!parsed.json);
    }

    #[test]
    fn copy_parser_allows_an_omitted_destination() {
        let parsed = parse_copy(&args(&["copy", "source.bin", "--json"])).unwrap();
        assert_eq!(parsed.source, std::path::Path::new("source.bin"));
        assert!(parsed.destination.is_none());
        assert!(parsed.json);
    }

    #[test]
    fn copy_parser_rejects_ambiguous_and_incomplete_invocations() {
        for invalid in [
            &["copy"][..],
            &["copy", "source", "destination", "extra"][..],
            &["copy", "source", "destination", "--json", "--jsonl"][..],
            &["copy", "source", "destination", "--json", "--json"][..],
            &["copy", "source", "destination", "--workspace"][..],
            &[
                "copy",
                "source",
                "destination",
                "--workspace",
                "a",
                "--workspace",
                "b",
            ][..],
            &["copy", "source", "destination", "--workspace", "--json"][..],
            &["copy", "source", "destination", "--workspace", "--jsonl"][..],
            &["copy", "source", "destination", "--force"][..],
        ] {
            assert!(parse_copy(&args(invalid)).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn signal_guards_use_independent_cancellation_flags() {
        let first = scoped_cancellation().expect("first signal guard");
        first.handle().cancel();
        drop(first);

        let second = scoped_cancellation().expect("second signal guard");
        assert!(!second.handle().is_cancelled());
    }

    #[cfg(unix)]
    #[test]
    fn signal_guard_unregisters_both_actions_on_drop() {
        let guard = scoped_cancellation().expect("signal guard");
        let registrations = guard.registrations.clone();
        assert_eq!(registrations.len(), 2);

        drop(guard);

        for registration in registrations {
            assert!(
                !signal_hook::low_level::unregister(registration),
                "signal guard left a registered action behind"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn failed_second_signal_registration_unregisters_first_action() {
        SIGNAL_REGISTRATION_TEST_STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.fail_next_sigterm = true;
            state.last_registration = None;
        });

        let result = scoped_cancellation();
        assert!(matches!(
            result,
            Err(super::InspectionErrorCode::SignalHandlerFailed)
        ));

        let first_registration = SIGNAL_REGISTRATION_TEST_STATE
            .with(|state| state.borrow_mut().last_registration.take())
            .expect("first registration");
        assert!(
            !signal_hook::low_level::unregister(first_registration),
            "failed second registration left the first action registered"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn copy_plan_handoff_signals_are_latched_without_leaking_to_the_next_invocation() {
        const CHILD_SIGNAL: &str = "NSCB_TEST_COPY_PLAN_HANDOFF_SIGNAL";
        if let Ok(signal) = std::env::var(CHILD_SIGNAL) {
            let signal = signal.parse::<i32>().expect("test signal number");
            let root = tempfile::tempdir().expect("copy signal fixture");
            let source = root.path().join("source.bin");
            let destination = root.path().join("destination.bin");
            let workspace = root.path().join("workspace");
            fs::write(&source, b"pending signal source").expect("write source");
            let signal_thread = signal_at_plan_handoff(signal);

            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let cancelled = run_copy(
                &args(&[
                    "copy",
                    source.to_str().unwrap(),
                    destination.to_str().unwrap(),
                    "--workspace",
                    workspace.to_str().unwrap(),
                    "--json",
                ]),
                &Engine::new(),
                &mut stdout,
                &mut stderr,
            );
            signal_thread
                .join()
                .expect("deliver signal during planning");
            assert_eq!(cancelled, 6);
            assert!(stderr.is_empty());
            let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
            assert_eq!(document["kind"], "job.result");
            assert_eq!(document["result"]["state"], "cancelled");
            assert!(!destination.exists());
            assert!(!workspace.exists());

            let next_destination = root.path().join("next-destination.bin");
            let next_workspace = root.path().join("next-workspace");
            let next = run_copy(
                &args(&[
                    "copy",
                    source.to_str().unwrap(),
                    next_destination.to_str().unwrap(),
                    "--workspace",
                    next_workspace.to_str().unwrap(),
                    "--json",
                ]),
                &Engine::new(),
                &mut Vec::new(),
                &mut Vec::new(),
            );
            assert_eq!(next, 0, "a prior invocation cannot cancel a later one");
            assert_eq!(
                fs::read(next_destination).unwrap(),
                b"pending signal source"
            );
            return;
        }

        for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "cli::copy_cli_tests::copy_plan_handoff_signals_are_latched_without_leaking_to_the_next_invocation",
                    "--nocapture",
                ])
                .env(CHILD_SIGNAL, signal.to_string())
                .output()
                .expect("run isolated planning-signal test");
            assert!(
                output.status.success(),
                "signal {signal}: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn planning_entry_signals_use_the_invocation_guard_and_preserve_pre_admission_errors() {
        const CHILD_SIGNAL: &str = "NSCB_TEST_COPY_PLAN_ENTRY_SIGNAL";
        if let Ok(signal) = std::env::var(CHILD_SIGNAL) {
            let signal = signal.parse::<i32>().expect("test signal number");
            let root = tempfile::tempdir().expect("copy planning-entry fixture");
            let source = root.path().join("source.bin");
            let destination = root.path().join("destination.bin");
            let workspace = root.path().join("workspace");
            let source_bytes = b"signal at CLI planning entry";
            fs::write(&source, source_bytes).expect("write source fixture");

            let signal_thread = signal_at_plan_entry(signal);
            let mut stdout = Vec::new();
            let code = run_copy(
                &args(&[
                    "copy",
                    source.to_str().unwrap(),
                    destination.to_str().unwrap(),
                    "--workspace",
                    workspace.to_str().unwrap(),
                    "--json",
                ]),
                &Engine::new(),
                &mut stdout,
                &mut Vec::new(),
            );
            signal_thread
                .join()
                .expect("deliver signal at CLI planning entry");
            assert_eq!(code, 6);
            let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
            assert_eq!(document["kind"], "job.result");
            assert_eq!(document["result"]["state"], "cancelled");
            assert_eq!(fs::read(&source).unwrap(), source_bytes);
            assert!(!destination.exists());
            assert!(!workspace.exists());

            let later_destination = root.path().join("later-destination.bin");
            let later_workspace = root.path().join("later-workspace");
            let later = run_copy(
                &args(&[
                    "copy",
                    source.to_str().unwrap(),
                    later_destination.to_str().unwrap(),
                    "--workspace",
                    later_workspace.to_str().unwrap(),
                    "--json",
                ]),
                &Engine::new(),
                &mut Vec::new(),
                &mut Vec::new(),
            );
            assert_eq!(later, 0, "a cancelled invocation cannot cancel a later one");
            assert_eq!(fs::read(later_destination).unwrap(), source_bytes);

            let missing = root.path().join("missing-source.bin");
            let failed_destination = root.path().join("failed-destination.bin");
            let failed_workspace = root.path().join("failed-workspace");
            let signal_thread = signal_at_plan_entry(signal);
            let mut failure_stdout = Vec::new();
            let failed = run_copy(
                &args(&[
                    "copy",
                    missing.to_str().unwrap(),
                    failed_destination.to_str().unwrap(),
                    "--workspace",
                    failed_workspace.to_str().unwrap(),
                    "--json",
                ]),
                &Engine::new(),
                &mut failure_stdout,
                &mut Vec::new(),
            );
            signal_thread
                .join()
                .expect("deliver signal during failed CLI planning");
            assert_eq!(failed, 3);
            let error: serde_json::Value = serde_json::from_slice(&failure_stdout).unwrap();
            assert_eq!(error["kind"], "error");
            assert_eq!(error["error"]["code"], "source_unavailable");
            assert!(!failed_destination.exists());
            assert!(!failed_workspace.exists());

            let after_failure_destination = root.path().join("after-failure-destination.bin");
            let after_failure_workspace = root.path().join("after-failure-workspace");
            let after_failure = run_copy(
                &args(&[
                    "copy",
                    source.to_str().unwrap(),
                    after_failure_destination.to_str().unwrap(),
                    "--workspace",
                    after_failure_workspace.to_str().unwrap(),
                    "--json",
                ]),
                &Engine::new(),
                &mut Vec::new(),
                &mut Vec::new(),
            );
            assert_eq!(
                after_failure, 0,
                "failed planning cannot cancel a later invocation"
            );
            assert_eq!(fs::read(after_failure_destination).unwrap(), source_bytes);
            return;
        }

        for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "cli::copy_cli_tests::planning_entry_signals_use_the_invocation_guard_and_preserve_pre_admission_errors",
                    "--nocapture",
                ])
                .env(CHILD_SIGNAL, signal.to_string())
                .output()
                .expect("run isolated CLI planning-entry signal test");
            assert!(
                output.status.success(),
                "signal {signal}: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn plan_handoff_signal_preserves_the_pre_admission_error() {
        const CHILD_SIGNAL: &str = "NSCB_TEST_COPY_PLAN_HANDOFF_FAILURE_SIGNAL";
        if let Some(signal) = std::env::var_os(CHILD_SIGNAL) {
            let signal = signal
                .to_string_lossy()
                .parse::<i32>()
                .expect("test signal number");
            let root = tempfile::tempdir().expect("copy planning failure fixture");
            let missing = root.path().join("missing-source.bin");
            let destination = root.path().join("destination.bin");
            let workspace = root.path().join("workspace");
            let signal_thread = signal_at_plan_handoff(signal);

            let mut stdout = Vec::new();
            let code = run_copy(
                &args(&[
                    "copy",
                    missing.to_str().unwrap(),
                    destination.to_str().unwrap(),
                    "--workspace",
                    workspace.to_str().unwrap(),
                    "--json",
                ]),
                &Engine::new(),
                &mut stdout,
                &mut Vec::new(),
            );
            signal_thread
                .join()
                .expect("deliver signal during planning");
            assert_eq!(code, 3);
            let error: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
            assert_eq!(error["kind"], "error");
            assert_eq!(error["error"]["code"], "source_unavailable");
            assert!(!workspace.exists());
            let source = root.path().join("later-source.bin");
            let later_destination = root.path().join("later-destination.bin");
            let later_workspace = root.path().join("later-workspace");
            fs::write(&source, b"later invocation source").expect("write later source");
            let later = run_copy(
                &args(&[
                    "copy",
                    source.to_str().unwrap(),
                    later_destination.to_str().unwrap(),
                    "--workspace",
                    later_workspace.to_str().unwrap(),
                    "--json",
                ]),
                &Engine::new(),
                &mut Vec::new(),
                &mut Vec::new(),
            );
            assert_eq!(later, 0, "failed planning cannot cancel a later invocation");
            assert_eq!(
                fs::read(later_destination).unwrap(),
                b"later invocation source"
            );
            return;
        }

        for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "cli::copy_cli_tests::plan_handoff_signal_preserves_the_pre_admission_error",
                    "--nocapture",
                ])
                .env(CHILD_SIGNAL, signal.to_string())
                .output()
                .expect("run isolated planning failure test");
            assert!(
                output.status.success(),
                "signal {signal}: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn jsonl_worker_start_failure_is_a_sanitized_pre_admission_error() {
        let root = tempfile::tempdir().expect("worker startup fixture");
        let source = root.path().join("source.bin");
        let destination = root.path().join("destination.bin");
        let workspace = root.path().join("workspace");
        let bytes = b"worker startup failure preserves filesystem state";
        fs::write(&source, bytes).expect("write source");
        super::COPY_WORKER_START_FAILURE.set(true);

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run_copy(
            &args(&[
                "copy",
                source.to_str().unwrap(),
                destination.to_str().unwrap(),
                "--workspace",
                workspace.to_str().unwrap(),
                "--jsonl",
            ]),
            &Engine::new(),
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit, 7);
        assert!(stderr.is_empty());
        assert_eq!(stdout.iter().filter(|byte| **byte == b'\n').count(), 1);
        let error: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(error["kind"], "error");
        assert_eq!(error["error"]["code"], "execution_worker_start_failed");
        assert!(!String::from_utf8_lossy(&stdout).contains(root.path().to_str().unwrap()));
        assert_eq!(fs::read(&source).unwrap(), bytes);
        assert!(!destination.exists());
        assert!(!workspace.exists());

        let next_destination = root.path().join("next-destination.bin");
        let next_workspace = root.path().join("next-workspace");
        assert_eq!(
            run_copy(
                &args(&[
                    "copy",
                    source.to_str().unwrap(),
                    next_destination.to_str().unwrap(),
                    "--workspace",
                    next_workspace.to_str().unwrap(),
                    "--json",
                ]),
                &Engine::new(),
                &mut Vec::new(),
                &mut Vec::new(),
            ),
            0,
            "a failed worker start releases invocation state"
        );
        assert_eq!(fs::read(next_destination).unwrap(), bytes);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn copy_human_cancelled_result_uses_stderr() {
        let root = tempfile::tempdir().expect("copy fixture");
        let source = root.path().join("source.bin");
        let destination = root.path().join("destination.bin");
        let workspace = root.path().join("workspace");
        let bytes = b"cancelled copy source bytes";
        fs::write(&source, bytes).expect("write source");
        let engine = Engine::new();
        let plan = engine
            .plan_copy_through(CopyThroughRequest::new(&source, &destination, &workspace))
            .expect("plan copy");
        let session = OperationSession::new();
        let cancellation = CancellationHandle::new();
        // Cancellation is bound to the admitted invocation without a signal or scheduling race.
        cancellation.cancel();
        let result = engine.execute_operation_with_cancellation(plan, &session, cancellation);
        assert_eq!(result.state(), JobState::Cancelled);
        assert_eq!(exit_for_operation_result(&result), 6);

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        write_human_copy_result(&result, &mut stdout, &mut stderr);

        assert!(
            stdout.is_empty(),
            "cancelled copy diagnostics must use stderr; stdout: {}",
            String::from_utf8_lossy(&stdout)
        );
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "Copy-through was cancelled before publication. No destination change was made.\n"
        );
        assert_eq!(
            session.last_result().expect("admitted result"),
            Some(result)
        );
        assert!(!destination.exists());
        assert!(!workspace.exists());
        assert_eq!(fs::read(&source).unwrap(), bytes);
    }

    #[test]
    fn operation_failure_exit_classes_are_stable() {
        assert_eq!(
            exit_for_operation_failure(OperationFailureCode::DestinationConflict),
            4
        );
        assert_eq!(
            exit_for_operation_failure(OperationFailureCode::DestinationChanged),
            4
        );
        assert_eq!(
            exit_for_operation_failure(OperationFailureCode::SourceUnavailable),
            3
        );
        assert_eq!(
            exit_for_operation_failure(OperationFailureCode::UnsupportedCapability),
            3
        );
        assert_eq!(
            exit_for_operation_failure(OperationFailureCode::Cancelled),
            6
        );
        assert_eq!(
            exit_for_operation_failure(OperationFailureCode::PublicationUncertain),
            7
        );
    }

    const EXIT_PROVIDER_DEVICE: i32 = 5;
    const EXIT_COMPLETED_WITH_ISSUES: i32 = 8;

    #[test]
    fn reserved_exit_classes_are_not_fabricated() {
        assert_eq!(EXIT_PROVIDER_DEVICE, 5);
        assert_eq!(EXIT_COMPLETED_WITH_ISSUES, 8);
        let codes = [
            OperationFailureCode::SourceUnavailable,
            OperationFailureCode::SplitInputUnsupported,
            OperationFailureCode::SourceChanged,
            OperationFailureCode::StalePlan,
            OperationFailureCode::WorkspaceUnavailable,
            OperationFailureCode::DestinationUnavailable,
            OperationFailureCode::DestinationConflict,
            OperationFailureCode::DestinationChanged,
            OperationFailureCode::UnsafePath,
            OperationFailureCode::UnsupportedCapability,
            OperationFailureCode::InsufficientStorage,
            OperationFailureCode::EventConsumerUnavailable,
            OperationFailureCode::SessionUnavailable,
            OperationFailureCode::Cancelled,
            OperationFailureCode::WriteFailed,
            OperationFailureCode::ValidationFailed,
            OperationFailureCode::PublicationFailed,
            OperationFailureCode::PublicationUncertain,
            OperationFailureCode::CleanupIncomplete,
        ];
        for code in codes {
            let exit = exit_for_operation_failure(code);
            assert_ne!(exit, EXIT_PROVIDER_DEVICE, "{code:?}");
            assert_ne!(exit, EXIT_COMPLETED_WITH_ISSUES, "{code:?}");
        }
    }

    #[cfg(target_os = "macos")]
    struct BlockingWriter {
        started: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
        blocked: bool,
    }

    #[cfg(target_os = "macos")]
    impl Write for BlockingWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if !self.blocked {
                self.blocked = true;
                let _ = self.started.send(());
                let _ = self.release.recv();
            }
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn stalled_jsonl_writer_does_not_block_filesystem_execution() {
        let root = tempfile::tempdir().expect("copy fixture");
        let source = root.path().join("source.bin");
        let destination = root.path().join("destination.bin");
        let workspace = root.path().join("workspace");
        let bytes = vec![0x11_u8; 256 * 1024];
        fs::write(&source, &bytes).expect("write source");
        let args = args(&[
            "copy",
            source.to_str().unwrap(),
            destination.to_str().unwrap(),
            "--workspace",
            workspace.to_str().unwrap(),
            "--jsonl",
        ]);
        let (started_sender, started_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let expected_destination = destination.clone();
        let expected_bytes = bytes.clone();

        let worker = std::thread::spawn(move || {
            let mut writer = BlockingWriter {
                started: started_sender,
                release: release_receiver,
                blocked: false,
            };
            let mut stderr = Vec::new();
            run_copy(&args, &Engine::new(), &mut writer, &mut stderr)
        });

        started_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("writer receives the first record");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !expected_destination.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            expected_destination.exists(),
            "filesystem execution must finish while stdout is stalled"
        );
        assert_eq!(fs::read(&expected_destination).unwrap(), expected_bytes);

        release_sender.send(()).expect("release the stalled writer");
        assert_eq!(worker.join().expect("writer thread"), 0);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn copy_fails_closed_with_one_typed_error_on_unqualified_hosts() {
        let root = tempfile::tempdir().expect("copy fixture");
        let source = root.path().join("source.bin");
        let destination = root.path().join("destination.bin");
        fs::write(&source, b"unqualified host source").expect("write source");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run_copy(
            &args(&[
                "copy",
                source.to_str().unwrap(),
                destination.to_str().unwrap(),
                "--json",
            ]),
            &Engine::new(),
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit, 3);
        assert!(stderr.is_empty());
        assert!(!destination.exists());
        assert_eq!(stdout.iter().filter(|byte| **byte == b'\n').count(), 1);
        let document: serde_json::Value =
            serde_json::from_slice(&stdout).expect("one JSON error document");
        assert_eq!(document["kind"], "error");
        assert_eq!(document["error"]["code"], "unsupported_capability");
    }

    #[cfg(unix)]
    #[test]
    fn machine_copy_rejects_unrepresentable_arguments_before_planning() {
        use std::os::unix::ffi::OsStringExt;

        let source = PathBuf::from(OsString::from_vec(b"source-\xff.bin".to_vec()));
        let destination = PathBuf::from("destination.bin");
        for mode in ["--json", "--jsonl"] {
            let invocation = [
                OsString::from("copy"),
                source.as_os_str().to_owned(),
                destination.as_os_str().to_owned(),
                OsString::from(mode),
            ];
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let exit = run_copy(&invocation, &Engine::new(), &mut stdout, &mut stderr);

            assert_eq!(exit, 3, "{mode}");
            assert!(stderr.is_empty(), "{mode}");
            assert_eq!(
                stdout.iter().filter(|byte| **byte == b'\n').count(),
                1,
                "{mode}"
            );
            let document: serde_json::Value =
                serde_json::from_slice(&stdout).expect("one JSON error document");
            assert_eq!(document["kind"], "error");
            assert_eq!(document["error"]["code"], "unrepresentable_path");
        }
        assert!(!destination.exists());
    }

    #[cfg(unix)]
    #[derive(serde::Serialize)]
    struct PathDocument {
        path: PathBuf,
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_paths_are_rejected_without_truncating_a_json_document() {
        use std::os::unix::ffi::OsStringExt;

        let path = PathBuf::from(OsString::from_vec(b"non-unicode-\xff.bin".to_vec()));
        assert!(!paths_are_json_representable([path.as_path()]));
        assert!(paths_are_json_representable([Path::new(
            "representable.bin"
        )]));

        let mut stdout = Vec::new();
        assert!(!write_json(&PathDocument { path }, &mut stdout));
        assert!(
            stdout.is_empty(),
            "serialization failure must not emit a partial JSON document"
        );
    }
}
