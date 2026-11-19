//! Subprocess checks for the standalone `nscb extract` command.

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
fn extraction_help_lists_the_supported_selector_dimensions() {
    let output = run(&["extract".into(), "--help".into()]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let help = String::from_utf8_lossy(&output.stderr);
    for entry in [
        "Usage: nscb extract",
        "--program-id 16-HEX-DIGITS",
        "--nca-type program|control",
        "--role program|control",
        "--partition 0..3",
        "--path RELATIVE_PATH",
        "combine with AND",
        "combine with OR",
    ] {
        assert!(help.contains(entry), "missing {entry:?} from help: {help}");
    }
}

#[test]
fn missing_selection_is_a_single_json_usage_error() {
    let root = tempfile::tempdir().expect("create extraction CLI fixture");
    let source = root.path().join("missing.nca");

    let output = run(&[
        "extract".into(),
        "--source".into(),
        path_arg(&source),
        "--json".into(),
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    assert!(output.stdout.ends_with(b"\n"));
    assert_eq!(document(&output)["error"]["code"], "usage_error");
}

#[test]
fn json_and_jsonl_cannot_be_combined() {
    let root = tempfile::tempdir().expect("create extraction CLI fixture");
    let source = root.path().join("missing.nca");

    let output = run(&[
        "extract".into(),
        "--source".into(),
        path_arg(&source),
        "--all".into(),
        "--json".into(),
        "--jsonl".into(),
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    assert_eq!(document(&output)["error"]["code"], "usage_error");
}

#[test]
fn jsonl_accepts_repeated_partition_and_path_selectors_and_frames_the_input_error() {
    let root = tempfile::tempdir().expect("create extraction CLI fixture");
    let source = root.path().join("missing.nca");
    let keys = root.path().join("missing.keys");
    let destination = root.path().join("bundle");

    let output = run(&[
        "extract".into(),
        "--source".into(),
        path_arg(&source),
        "--keys".into(),
        path_arg(&keys),
        "--output-directory".into(),
        path_arg(&destination),
        "--program-id".into(),
        "0102030405060708".into(),
        "--role".into(),
        "program".into(),
        "--partition".into(),
        "0".into(),
        "--partition".into(),
        "3".into(),
        "--path".into(),
        "main.npdm".into(),
        "--path".into(),
        "romfs/data.bin".into(),
        "--jsonl".into(),
    ]);

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    assert!(output.stdout.ends_with(b"\n"));
    assert_eq!(document(&output)["kind"], "error");
    assert!(document(&output)["error"]["code"].is_string());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(!text.contains(source.to_str().unwrap()));
    assert!(!text.contains(keys.to_str().unwrap()));
    assert!(!destination.exists());
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn json_success_reports_the_published_extraction_result_and_manifest() {
    use std::fs;
    use synthetic_extraction::SyntheticExtractionFixture;

    let fixture = SyntheticExtractionFixture::populated();
    let destination = fixture.source.parent().unwrap().join("cli-bundle");
    let output = run(&[
        "extract".into(),
        "--source".into(),
        path_arg(&fixture.source),
        "--keys".into(),
        path_arg(&fixture.key_file),
        "--output-directory".into(),
        path_arg(&destination),
        "--all".into(),
        "--json".into(),
    ]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    let result = document(&output);
    assert_eq!(result["kind"], "job.result");
    assert_eq!(result["result"]["state"], "succeeded");
    assert_eq!(result["result"]["outcome"], "extracted");
    assert_eq!(result["snapshot"]["outcome"], "extracted");

    let manifest: Value = serde_json::from_slice(
        &fs::read(destination.join("manifest.json")).expect("published extraction manifest"),
    )
    .expect("manifest JSON");
    assert_eq!(manifest["kind"], "extracted_content_manifest");
    assert_eq!(manifest["content_root"], "content");
    assert_eq!(manifest["completeness"], "complete");
    let program_files = manifest["partitions"][0]["files"].as_array().unwrap();
    assert!(
        program_files
            .iter()
            .any(|file| { file["path"] == "0/nested/program.bin" })
    );
    assert_eq!(
        fs::read(destination.join("content/0/nested/program.bin")).unwrap(),
        b"nested program bytes"
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn jsonl_success_streams_operation_events_and_one_terminal_result() {
    use synthetic_extraction::SyntheticExtractionFixture;

    let fixture = SyntheticExtractionFixture::populated();
    let destination = fixture.source.parent().unwrap().join("cli-jsonl-bundle");
    let output = run(&[
        "extract".into(),
        "--source".into(),
        path_arg(&fixture.source),
        "--keys".into(),
        path_arg(&fixture.key_file),
        "--output-directory".into(),
        path_arg(&destination),
        "--all".into(),
        "--jsonl".into(),
    ]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let records = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(records.len() > 1);
    assert!(
        records
            .iter()
            .all(|record| record["kind"] == "job.event" || record["kind"] == "job.result")
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| record["kind"] == "job.result")
            .count(),
        1
    );
    assert_eq!(records.last().unwrap()["kind"], "job.result");
    assert_eq!(records.last().unwrap()["result"]["state"], "succeeded");
    assert_eq!(records.last().unwrap()["result"]["outcome"], "extracted");
    assert_eq!(records.last().unwrap()["snapshot"]["outcome"], "extracted");
    assert!(destination.join("manifest.json").is_file());
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn unmatched_selected_path_is_reported_by_engine_without_publishing() {
    use synthetic_extraction::SyntheticExtractionFixture;

    let fixture = SyntheticExtractionFixture::populated();
    let destination = fixture.source.parent().unwrap().join("cli-missing-path");
    let output = run(&[
        "extract".into(),
        "--source".into(),
        path_arg(&fixture.source),
        "--keys".into(),
        path_arg(&fixture.key_file),
        "--output-directory".into(),
        path_arg(&destination),
        "--path".into(),
        "does-not-exist.bin".into(),
        "--json".into(),
    ]);

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stderr.is_empty());
    let error = document(&output);
    assert_eq!(error["kind"], "error");
    assert!(error["error"]["code"].is_string());
    assert!(!destination.exists());
}
