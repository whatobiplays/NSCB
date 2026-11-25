//! Subprocess checks for the standalone repack command.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "support/mod.rs"]
mod support;

#[cfg(all(
    feature = "standalone-job-history",
    target_os = "macos",
    target_arch = "aarch64"
))]
use support::process;

#[cfg(not(all(
    feature = "standalone-job-history",
    target_os = "macos",
    target_arch = "aarch64"
)))]
#[path = "support/process.rs"]
mod process;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(dead_code)]
#[path = "support/synthetic_extraction.rs"]
mod synthetic_extraction;

use nscb::{ConflictPolicy, Engine, OperationSession, RepackRequest};
use serde_json::Value;
use std::ffi::OsString;
use std::path::Path;
use std::process::Output;

fn run(args: &[OsString]) -> Output {
    process::isolated_command()
        .args(args)
        .output()
        .expect("launch nscb executable")
}

fn document(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("one JSON document on stdout")
}

fn path_arg(path: &Path) -> OsString {
    path.as_os_str().to_owned()
}

#[test]
fn repack_help_lists_the_manifest_and_conflict_policies() {
    let output = run(&["repack".into(), "--help".into()]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let help = String::from_utf8_lossy(&output.stderr);
    for entry in [
        "usage: repack",
        "--manifest FILE",
        "--output PFS0",
        "--workspace DIR",
        "--key-file FILE",
        "--conflict-policy fail|replace|skip",
        "--json|--jsonl",
    ] {
        assert!(help.contains(entry), "missing {entry:?} from help: {help}");
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn program_repack_runs_and_preserves_engine_conflict_outcomes() {
    use synthetic_extraction::SyntheticExtractionFixture;

    let fixture = SyntheticExtractionFixture::populated();
    let root = fixture.source.parent().expect("fixture root");
    let bundle = root.join("cli-program-bundle");
    let workspace = root.join("cli-repack-workspace");
    let destination = root.join("cli-program.pfs0");
    std::fs::create_dir(&workspace).expect("create repack workspace");

    let extraction = run(&[
        "extract".into(),
        "--source".into(),
        path_arg(&fixture.source),
        "--keys".into(),
        path_arg(&fixture.key_file),
        "--output-directory".into(),
        path_arg(&bundle),
        "--all".into(),
        "--json".into(),
    ]);
    assert_eq!(
        extraction.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&extraction.stdout),
        String::from_utf8_lossy(&extraction.stderr)
    );

    let args = |policy: &str| {
        vec![
            "repack".into(),
            "--manifest".into(),
            path_arg(&bundle.join("manifest.json")),
            "--output".into(),
            path_arg(&destination),
            "--workspace".into(),
            path_arg(&workspace),
            "--key-file".into(),
            path_arg(&fixture.key_file),
            "--conflict-policy".into(),
            policy.into(),
            "--json".into(),
        ]
    };

    let first = run(&args("fail"));
    assert_eq!(
        first.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    let first_document = document(&first);
    assert_eq!(first_document["kind"], "repack.job_result");
    assert_eq!(first_document["result"]["state"], "succeeded");
    assert_eq!(first_document["result"]["outcome"], "repacked");
    assert!(destination.is_file());
    let original_bytes = std::fs::read(&destination).expect("read repacked PFS0");
    assert_eq!(&original_bytes[..4], b"PFS0");
    assert_eq!(
        u32::from_le_bytes(original_bytes[4..8].try_into().unwrap()),
        1
    );

    std::fs::write(
        bundle.join("content/0/nested/program.bin"),
        b"changed by repack CLI test",
    )
    .expect("edit extracted Program payload");

    let conflict = run(&args("fail"));
    assert_eq!(conflict.status.code(), Some(4));
    let expected_conflict_code = match Engine::new().plan_repack(
        RepackRequest::new(
            bundle.join("manifest.json"),
            &destination,
            &workspace,
            &fixture.key_file,
        )
        .with_conflict_policy(ConflictPolicy::Fail),
    ) {
        Err(error) => error.code().as_str().to_owned(),
        Ok(plan) => {
            let result = Engine::new().execute_operation(plan, &OperationSession::new());
            result
                .failure()
                .expect("fail policy rejects an existing output")
                .code()
                .as_str()
                .to_owned()
        }
    };
    let conflict_document = document(&conflict);
    let reported_conflict_code = conflict_document
        .pointer("/error/code")
        .or_else(|| conflict_document.pointer("/result/failure/code"))
        .and_then(Value::as_str)
        .expect("CLI reports the Engine conflict code");
    assert_eq!(reported_conflict_code, expected_conflict_code);
    assert_eq!(std::fs::read(&destination).unwrap(), original_bytes);

    let skipped = run(&args("skip"));
    assert_eq!(skipped.status.code(), Some(0));
    assert_eq!(document(&skipped)["result"]["outcome"], "skipped");
    assert_eq!(std::fs::read(&destination).unwrap(), original_bytes);

    let replaced = run(&args("replace"));
    assert_eq!(
        replaced.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&replaced.stdout),
        String::from_utf8_lossy(&replaced.stderr)
    );
    assert_eq!(document(&replaced)["result"]["outcome"], "repacked");
    assert_ne!(std::fs::read(&destination).unwrap(), original_bytes);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn repack_cli_uses_the_engine_missing_payload_error_code() {
    use synthetic_extraction::SyntheticExtractionFixture;

    let fixture = SyntheticExtractionFixture::populated();
    let root = fixture.source.parent().expect("fixture root");
    let bundle = root.join("cli-missing-payload-bundle");
    let workspace = root.join("cli-missing-payload-workspace");
    let destination = root.join("cli-missing-payload.pfs0");
    std::fs::create_dir(&workspace).expect("create repack workspace");

    let extraction = run(&[
        "extract".into(),
        "--source".into(),
        path_arg(&fixture.source),
        "--keys".into(),
        path_arg(&fixture.key_file),
        "--output-directory".into(),
        path_arg(&bundle),
        "--all".into(),
        "--json".into(),
    ]);
    assert_eq!(
        extraction.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&extraction.stdout),
        String::from_utf8_lossy(&extraction.stderr)
    );
    std::fs::remove_file(bundle.join("content/0/empty.dat")).expect("remove one declared payload");

    let request = RepackRequest::new(
        bundle.join("manifest.json"),
        &destination,
        &workspace,
        &fixture.key_file,
    );
    let engine_error = match Engine::new().plan_repack(request) {
        Ok(_) => panic!("Engine must reject the missing payload"),
        Err(error) => error,
    };
    let engine_code = engine_error.code().as_str().to_owned();
    let output = run(&[
        "repack".into(),
        "--manifest".into(),
        path_arg(&bundle.join("manifest.json")),
        "--output".into(),
        path_arg(&destination),
        "--workspace".into(),
        path_arg(&workspace),
        "--key-file".into(),
        path_arg(&fixture.key_file),
        "--json".into(),
    ]);

    assert!(!output.status.success());
    let cli_document = document(&output);
    let cli_code = cli_document
        .pointer("/error/code")
        .or_else(|| cli_document.pointer("/result/failure/code"))
        .and_then(Value::as_str)
        .expect("CLI reports a stable missing-payload code");
    assert_eq!(cli_code, engine_code);
    assert_eq!(engine_code, "missing_repack_payload");
    assert!(!destination.exists());
}
