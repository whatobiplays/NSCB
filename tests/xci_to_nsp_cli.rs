#[cfg(not(feature = "standalone-job-history"))]
use nscb::XciToNspRequest;
#[cfg(feature = "standalone-job-history")]
use std::fs;
#[cfg(feature = "standalone-job-history")]
use std::path::PathBuf;
#[cfg(feature = "standalone-job-history")]
use std::process::Command;

#[cfg(feature = "standalone-job-history")]
#[allow(dead_code)]
#[path = "support/synthetic_nsp_qualification.rs"]
mod synthetic_nsp_qualification;
#[cfg(feature = "standalone-job-history")]
#[allow(dead_code)]
#[path = "support/synthetic_xci.rs"]
mod synthetic_xci;

#[cfg(feature = "standalone-job-history")]
struct CliFiles {
    root: tempfile::TempDir,
    source: PathBuf,
    output: PathBuf,
    key_file: PathBuf,
    workspace: PathBuf,
}

#[cfg(feature = "standalone-job-history")]
fn files_with_fixture(fixture: &synthetic_xci::Fixture) -> CliFiles {
    let root = tempfile::tempdir().expect("temporary root");
    let source = root.path().join("misleading-name.bin");
    let output = root.path().join("converted-package.bin");
    let key_file = root.path().join("private-key-file-name.dat");
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    fs::write(&source, &fixture.image).expect("synthetic XCI");
    fs::write(&key_file, &fixture.key_file).expect("synthetic keys");
    CliFiles {
        root,
        source,
        output,
        key_file,
        workspace,
    }
}

#[cfg(feature = "standalone-job-history")]
fn command(files: &CliFiles, mode: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nscb"));
    command
        .env("HOME", files.root.path())
        .args(["xci-to-nsp", "--source"])
        .arg(&files.source)
        .args(["--output"])
        .arg(&files.output)
        .arg("--workspace")
        .arg(&files.workspace)
        .arg("--keys")
        .arg(&files.key_file)
        .arg(mode);
    command
}

#[cfg(feature = "standalone-job-history")]
fn combined_output(stdout: &[u8], stderr: &[u8]) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr)
    )
}

#[cfg(all(target_os = "macos", feature = "standalone-job-history"))]
#[test]
fn json_cli_converts_to_the_canonical_output_and_redacts_key_path() {
    let fixture = synthetic_xci::valid();
    let files = files_with_fixture(&fixture);
    let source_before = fs::read(&files.source).expect("source baseline");
    let output = command(&files, "--json").output().expect("run CLI");

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON result");
    assert_eq!(result["kind"], "xci_to_nsp.job_result");
    assert_eq!(result["plan"]["operation_kind"], "xci_to_nsp");
    assert_eq!(result["result"]["state"], "succeeded");
    assert_eq!(result["result"]["outcome"], "converted");
    assert_eq!(
        fs::read(&files.output).expect("NSP output"),
        fixture.package
    );
    assert_eq!(
        fs::read(&files.source).expect("source after conversion"),
        source_before
    );

    let output = combined_output(&output.stdout, &output.stderr);
    assert!(!output.contains(&files.key_file.display().to_string()));
    let key_text = std::str::from_utf8(&fixture.key_file).expect("synthetic key fixture is UTF-8");
    assert!(!output.contains(key_text));
}

#[cfg(all(target_os = "macos", feature = "standalone-job-history"))]
#[test]
fn jsonl_cli_streams_events_and_reports_converted_outcome() {
    let fixture = synthetic_xci::valid();
    let files = files_with_fixture(&fixture);
    let output = command(&files, "--jsonl").output().expect("run JSONL CLI");

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let records = std::str::from_utf8(&output.stdout)
        .expect("JSONL output is UTF-8")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("JSONL record"))
        .collect::<Vec<_>>();
    assert!(records.len() >= 2);
    assert!(
        records[..records.len() - 1]
            .iter()
            .all(|record| record["kind"] == "job.event")
    );
    let result = records.last().expect("terminal result");
    assert_eq!(result["kind"], "xci_to_nsp.job_result");
    assert_eq!(result["result"]["outcome"], "converted");

    let output = combined_output(&output.stdout, &output.stderr);
    assert!(!output.contains(&files.key_file.display().to_string()));
}

#[cfg(all(target_os = "macos", feature = "standalone-job-history"))]
#[test]
fn malformed_key_diagnostic_does_not_disclose_its_path_or_contents() {
    let fixture = synthetic_xci::valid();
    let files = files_with_fixture(&fixture);
    let secret_marker = b"SYNTHETIC-KEY-SECRET-MARKER";
    fs::write(&files.key_file, secret_marker).expect("malformed synthetic key file");
    let output = command(&files, "--json").output().expect("run CLI");

    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert_eq!(result["error"]["code"], "key_file_malformed");
    let output = combined_output(&output.stdout, &output.stderr);
    assert!(!output.contains(&files.key_file.display().to_string()));
    assert!(!output.contains(std::str::from_utf8(secret_marker).expect("marker is UTF-8")));
}

#[cfg(all(not(target_os = "macos"), feature = "standalone-job-history"))]
#[test]
fn valid_cli_shape_reports_unsupported_capability_on_non_macos() {
    let root = tempfile::tempdir().expect("temporary root");
    let output = root.path().join("output.nsp");
    let workspace = root.path().join("workspace");
    let key_file = root.path().join("keys.dat");
    let mut command = Command::new(env!("CARGO_BIN_EXE_nscb"));
    let output = command
        .env("HOME", root.path())
        .args(["xci-to-nsp", "--source", "source.xci", "--output"])
        .arg(output)
        .arg("--workspace")
        .arg(workspace)
        .arg("--keys")
        .arg(key_file)
        .arg("--json")
        .output()
        .expect("run unsupported target CLI");

    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert_eq!(result["error"]["code"], "unsupported_capability");
}

#[cfg(not(feature = "standalone-job-history"))]
#[test]
fn request_debug_redacts_the_key_path_without_standalone_cli_feature() {
    let key_path = "/private/test/key-file-secret-name";
    let request = XciToNspRequest::new("source.xci", "output.nsp", "workspace", key_path);
    let debug = format!("{request:?}");

    assert!(!debug.contains(key_path));
    assert!(debug.contains("[REDACTED]"));
}
