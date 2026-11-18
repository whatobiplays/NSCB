#![cfg(feature = "standalone-job-history")]

use serde_json::Value;
use std::fs;
use std::process::{Command, Output};

#[allow(dead_code)]
#[path = "support/synthetic_nsp_qualification.rs"]
mod synthetic_nsp_qualification;
#[allow(dead_code)]
#[path = "support/synthetic_xci.rs"]
mod synthetic_xci;

fn command(
    source: &std::path::Path,
    output: &std::path::Path,
    workspace: &std::path::Path,
    keys: &std::path::Path,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nscb"));
    command
        .args(["xci-to-xcz", "--source"])
        .arg(source)
        .args(["--output"])
        .arg(output)
        .arg("--workspace")
        .arg(workspace)
        .arg("--keys")
        .arg(keys);
    command
}

fn assert_error(output: &Output, expected_code: &str) {
    assert!(
        !output.status.success(),
        "unexpected CLI success: {output:?}"
    );
    let document: Value = serde_json::from_slice(&output.stdout).expect("JSON error");
    assert_eq!(document["kind"], "error");
    assert_eq!(document["error"]["code"], expected_code);
}

#[test]
fn compression_options_reject_duplicates_and_conflicting_selections() {
    let directory = tempfile::tempdir().expect("temporary CLI directory");
    let source = directory.path().join("input.xci");
    let output = directory.path().join("output.xcz");
    let workspace = directory.path().join("workspace");
    let keys = directory.path().join("keys.dat");
    fs::create_dir(&workspace).expect("workspace");

    for selection in [
        vec!["--preset", "fast", "--level", "9"],
        vec!["--level", "20"],
        vec!["--preset", "unknown"],
    ] {
        let mut invocation = command(&source, &output, &workspace, &keys);
        invocation.args(selection).arg("--json");
        assert_error(
            &invocation.output().expect("run invalid invocation"),
            "usage_error",
        );
        assert!(!output.exists());
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
#[test]
fn parsed_command_reports_unsupported_capability_on_other_targets() {
    let directory = tempfile::tempdir().expect("temporary CLI directory");
    let source = directory.path().join("missing.xci");
    let output = directory.path().join("output.xcz");
    let workspace = directory.path().join("missing-workspace");
    let keys = directory.path().join("missing-keys.dat");
    let mut invocation = command(&source, &output, &workspace, &keys);
    invocation.arg("--json");

    assert_error(
        &invocation.output().expect("run unsupported command"),
        "unsupported_capability",
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn json_cli_compresses_and_reports_the_additive_operation_kind() {
    let payload = vec![0xA5; 0x9000];
    let nsp = synthetic_nsp_qualification::build_with_program_payload(&payload, |_| {});
    let fixture = synthetic_xci::build(
        &nsp.meta_nca,
        &nsp.program_nca,
        &nsp.package,
        &nsp.key_file,
        ["program.nca", "meta.nca"],
        false,
    );
    let directory = tempfile::tempdir().expect("temporary CLI directory");
    let source = directory.path().join("input.xci");
    let output = directory.path().join("output.xcz");
    let workspace = directory.path().join("workspace");
    let keys = directory.path().join("private-keys.dat");
    fs::create_dir(&workspace).expect("workspace");
    fs::write(&source, &fixture.image).expect("write source XCI");
    fs::write(&keys, &fixture.key_file).expect("write synthetic keys");

    let mut invocation = command(&source, &output, &workspace, &keys);
    let result = invocation
        .args(["--preset", "fast", "--json"])
        .output()
        .expect("run CLI compression");
    assert!(result.status.success(), "CLI failed: {result:?}");
    let document: Value = serde_json::from_slice(&result.stdout).expect("JSON result");
    assert_eq!(document["kind"], "xci_to_xcz.job_result");
    assert_eq!(document["plan"]["operation_kind"], "xci_to_xcz");
    assert_eq!(document["result"]["state"], "succeeded");
    assert_eq!(document["result"]["outcome"], "compressed");
    assert!(output.is_file());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!combined.contains(&keys.display().to_string()));
    assert!(!combined.contains(std::str::from_utf8(&fixture.key_file).expect("key fixture text")));
}
