#![cfg(all(feature = "standalone-job-history", target_os = "macos"))]
//! Real-binary contracts for independent copy-batch execution.

#[path = "support/mod.rs"]
mod support;

use nscb::{LocalSplitTrustStore, SplitTrustStore};
use rusqlite::Connection;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use support::process::isolated_command_with_home;
use support::split_fixture::{SplitFixture, sidecar_path};
use tempfile::TempDir;

fn command(root: &TempDir) -> Command {
    isolated_command_with_home(&root.path().join("home"))
}

fn history_database(root: &TempDir) -> PathBuf {
    root.path()
        .join("home")
        .join("Library")
        .join("Application Support")
        .join("NSCB")
        .join("jobs.sqlite3")
}

fn batch(
    root: &TempDir,
    output: &Path,
    workspace: &Path,
    policy_args: &[&str],
    sources: &[&Path],
) -> Output {
    let mut command = command(root);
    command
        .args(["copy-batch", "--output-dir"])
        .arg(output)
        .arg("--workspace")
        .arg(workspace)
        .args(policy_args)
        .arg("--json");
    for source in sources {
        command.arg(source);
    }
    command.output().unwrap()
}

fn fixtures() -> (TempDir, PathBuf, PathBuf, PathBuf, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("output");
    let workspace = root.path().join("workspace");
    let first = root.path().join("first.bin");
    let second = root.path().join("second.bin");
    fs::create_dir(&output).unwrap();
    fs::create_dir(&workspace).unwrap();
    (root, output, workspace, first, second)
}

fn write_input_list(path: &Path, entries: &[&str]) {
    let entries = entries
        .iter()
        .map(|entry| serde_json::json!({ "path": entry }))
        .collect::<Vec<_>>();
    fs::write(
        path,
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "kind": "nscb.input_list",
            "required_features": [],
            "entries": entries,
        }))
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn all_skipped_batch_is_authoritative_success_with_exit_zero() {
    let (root, output, workspace, first, second) = fixtures();
    fs::write(&first, b"new first").unwrap();
    fs::write(&second, b"new second").unwrap();
    fs::write(output.join("first.bin"), b"old first").unwrap();
    fs::write(output.join("second.bin"), b"old second").unwrap();

    let completed = batch(
        &root,
        &output,
        &workspace,
        &["--conflict", "skip"],
        &[&first, &second],
    );

    assert_eq!(completed.status.code(), Some(0), "{completed:?}");
    let document: Value = serde_json::from_slice(&completed.stdout).unwrap();
    assert_eq!(document["kind"], "job.result");
    assert_eq!(document["schema_version"], 2);
    assert_eq!(document["submission_kind"], "independent_batch");
    assert_eq!(document["result"]["state"], "succeeded");
    assert_eq!(document["result"]["items"].as_array().unwrap().len(), 2);
    for item in document["result"]["items"].as_array().unwrap() {
        assert_eq!(item["state"], "skipped");
        assert_eq!(item["outcome"], "skipped");
    }
    assert_eq!(fs::read(output.join("first.bin")).unwrap(), b"old first");
    assert_eq!(fs::read(output.join("second.bin")).unwrap(), b"old second");
}

#[test]
fn copy_batch_jsonl_uses_schema_two_and_has_one_terminal_result() {
    let (root, output, workspace, first, second) = fixtures();
    fs::write(&first, b"first item").unwrap();
    fs::write(&second, b"second item").unwrap();

    let completed = command(&root)
        .args(["copy-batch", "--output-dir"])
        .arg(&output)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--jsonl")
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();

    assert_eq!(completed.status.code(), Some(0), "{completed:?}");
    let stdout = String::from_utf8(completed.stdout).unwrap();
    let documents = stdout
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        documents
            .iter()
            .filter(|document| document["kind"] == "job.result")
            .count(),
        1
    );
    assert_eq!(documents.last().unwrap()["kind"], "job.result");
    for (index, document) in documents.iter().enumerate() {
        assert_eq!(document["schema_version"], 2);
        assert_eq!(document["submission_kind"], "independent_batch");
        assert_eq!(document["sequence"], index as u64);
    }
}

#[test]
fn empty_input_list_does_not_hide_a_viable_batch_item() {
    let (root, output, workspace, first, _) = fixtures();
    let empty_list = root.path().join("empty.json");
    fs::write(
        &empty_list,
        br#"{"schema_version":1,"kind":"nscb.input_list","required_features":[],"entries":[]}"#,
    )
    .unwrap();
    fs::write(&first, b"viable").unwrap();

    let completed = command(&root)
        .args(["copy-batch", "--output-dir"])
        .arg(&output)
        .arg("--workspace")
        .arg(&workspace)
        .args(["--json", "--input-list"])
        .arg(&empty_list)
        .arg(&first)
        .output()
        .unwrap();
    assert_eq!(completed.status.code(), Some(8), "{completed:?}");
    let completed: Value = serde_json::from_slice(&completed.stdout).unwrap();
    assert_eq!(completed["result"]["state"], "completed_with_issues");
    assert_eq!(completed["result"]["items"][0]["state"], "preflight_failed");
    assert_eq!(
        completed["result"]["items"][0]["failure"]["code"],
        "empty_selection"
    );
    assert_eq!(completed["result"]["items"][1]["state"], "succeeded");
    assert_eq!(fs::read(output.join("first.bin")).unwrap(), b"viable");
    assert!(!output.join("empty.json").exists());
}

#[test]
fn empty_parent_directory_selection_does_not_block_valid_sibling() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("output");
    let workspace = root.path().join("workspace");
    let empty_parent = root.path().join("empty-parent");
    let child = empty_parent.join("child");
    fs::create_dir(&output).unwrap();
    fs::create_dir(&workspace).unwrap();
    fs::create_dir_all(&child).unwrap();
    fs::write(child.join("good.nsp"), b"valid sibling").unwrap();

    let completed = command(&root)
        .current_dir(&child)
        .args(["copy-batch", "good.nsp", "..", "--output-dir"])
        .arg(&output)
        .args(["--workspace"])
        .arg(&workspace)
        .args(["--json"])
        .output()
        .unwrap();

    assert_eq!(completed.status.code(), Some(8), "{completed:?}");
    let document: Value = serde_json::from_slice(&completed.stdout).unwrap();
    assert_eq!(document["kind"], "job.result");
    assert_eq!(document["result"]["state"], "completed_with_issues");
    let items = document["result"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["item_key"], "batch-item-0001");
    assert_eq!(items[0]["state"], "succeeded");
    assert_eq!(items[1]["item_key"], "batch-item-0002");
    assert_eq!(items[1]["state"], "preflight_failed");
    assert_eq!(items[1]["failure"]["code"], "empty_selection");
    assert!(items[1]["destination"].is_null());
    assert_eq!(fs::read(output.join("good.nsp")).unwrap(), b"valid sibling");
    assert!(!output.join("empty-parent").exists());
}

#[test]
fn all_empty_directory_batch_fails_before_job_admission() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("output");
    let workspace = root.path().join("workspace");
    let empty_parent = root.path().join("empty-parent");
    let child = empty_parent.join("child");
    fs::create_dir(&output).unwrap();
    fs::create_dir(&workspace).unwrap();
    fs::create_dir_all(&child).unwrap();

    let completed = command(&root)
        .current_dir(&child)
        .args(["copy-batch", "..", "--output-dir"])
        .arg(&output)
        .args(["--workspace"])
        .arg(&workspace)
        .args(["--json"])
        .output()
        .unwrap();

    assert_eq!(completed.status.code(), Some(3), "{completed:?}");
    let document: Value = serde_json::from_slice(&completed.stdout).unwrap();
    assert_eq!(document["kind"], "error");
    assert_eq!(document["error"]["code"], "empty_selection");
    assert!(document.get("job_id").is_none());
    assert!(!output.join("empty-parent").exists());
}

#[test]
fn skipped_and_failed_items_without_a_copy_return_the_input_error_exit() {
    let (root, output, workspace, first, _) = fixtures();
    let empty_list = root.path().join("empty.json");
    write_input_list(&empty_list, &[]);
    fs::write(&first, b"new bytes").unwrap();
    fs::write(output.join("first.bin"), b"existing bytes").unwrap();

    let completed = command(&root)
        .args(["copy-batch", "--output-dir"])
        .arg(&output)
        .arg("--workspace")
        .arg(&workspace)
        .args(["--conflict", "skip", "--input-list"])
        .arg(&empty_list)
        .arg("--json")
        .arg(&first)
        .output()
        .unwrap();

    assert_eq!(completed.status.code(), Some(3), "{completed:?}");
    let document: Value = serde_json::from_slice(&completed.stdout).unwrap();
    assert_eq!(document["result"]["state"], "failed");
    assert_eq!(
        document["result"]["items"][0]["failure"]["code"],
        "empty_selection"
    );
    assert_eq!(document["result"]["items"][1]["state"], "skipped");
    assert_eq!(
        fs::read(output.join("first.bin")).unwrap(),
        b"existing bytes"
    );
}

#[test]
fn empty_input_list_retry_is_ineligible_and_missing_input_list_fails_before_admission() {
    let (root, output, workspace, first, _) = fixtures();
    let empty_list = root.path().join("empty.json");
    fs::write(
        &empty_list,
        br#"{"schema_version":1,"kind":"nscb.input_list","required_features":[],"entries":[]}"#,
    )
    .unwrap();
    fs::write(&first, b"viable item").unwrap();

    let original = command(&root)
        .args(["copy-batch", "--output-dir"])
        .arg(&output)
        .arg("--workspace")
        .arg(&workspace)
        .args(["--json", "--input-list"])
        .arg(&empty_list)
        .arg(&first)
        .output()
        .unwrap();
    assert_eq!(original.status.code(), Some(8), "{original:?}");
    let original: Value = serde_json::from_slice(&original.stdout).unwrap();
    let parent_id = original["job_id"].as_str().unwrap();
    assert_eq!(original["result"]["items"][0]["state"], "preflight_failed");
    assert_eq!(
        original["result"]["items"][0]["failure"]["code"],
        "empty_selection"
    );
    assert_eq!(
        Path::new(original["result"]["items"][0]["source"].as_str().unwrap()),
        empty_list.as_path()
    );

    let before_retry = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    let retry = command(&root)
        .args(["jobs", "retry", parent_id, "--failed-items", "--json"])
        .output()
        .unwrap();
    assert_ne!(retry.status.code(), Some(0), "{retry:?}");
    let retry: Value = serde_json::from_slice(&retry.stdout).unwrap();
    assert_eq!(retry["kind"], "error");
    let after_retry = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(before_retry.stdout, after_retry.stdout);
    assert_eq!(fs::read(output.join("first.bin")).unwrap(), b"viable item");

    let (root, output, workspace, first, _) = fixtures();
    let missing_list = root.path().join("unavailable.json");
    fs::write(&first, b"must not be copied").unwrap();
    let jobs_before = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    let rejected = command(&root)
        .args(["copy-batch", "--output-dir"])
        .arg(&output)
        .arg("--workspace")
        .arg(&workspace)
        .args(["--json", "--input-list"])
        .arg(&missing_list)
        .arg(&first)
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(3), "{rejected:?}");
    let rejected: Value = serde_json::from_slice(&rejected.stdout).unwrap();
    assert_eq!(rejected["kind"], "error");
    assert_eq!(rejected["error"]["code"], "input_unavailable");
    assert!(rejected.get("job_id").is_none());
    let jobs_after = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(jobs_before.stdout, jobs_after.stdout);
    assert!(!output.join("first.bin").exists());
}

#[test]
fn batch_selections_and_input_lists_retain_interleaved_encounter_order() {
    let (root, output, workspace, direct_one, direct_two) = fixtures();
    let list_one = root.path().join("list-one.json");
    let list_two = root.path().join("list-two.json");
    fs::write(&direct_one, b"direct one").unwrap();
    fs::write(&direct_two, b"direct two").unwrap();
    for name in ["list-one-a.bin", "list-one-b.bin", "list-two.bin"] {
        fs::write(root.path().join(name), name.as_bytes()).unwrap();
    }
    write_input_list(&list_one, &["list-one-a.bin", "list-one-b.bin"]);
    write_input_list(&list_two, &["list-two.bin"]);

    let completed = command(&root)
        .args(["copy-batch", "--output-dir"])
        .arg(&output)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--json")
        .arg(&direct_one)
        .arg("--input-list")
        .arg(&list_one)
        .arg(&direct_two)
        .arg("--input-list")
        .arg(&list_two)
        .output()
        .unwrap();

    assert_eq!(completed.status.code(), Some(0), "{completed:?}");
    let document: Value = serde_json::from_slice(&completed.stdout).unwrap();
    let expected = [
        "first.bin",
        "list-one-a.bin",
        "list-one-b.bin",
        "second.bin",
        "list-two.bin",
    ];
    let items = document["result"]["items"].as_array().unwrap();
    assert_eq!(items.len(), expected.len());
    let output = fs::canonicalize(output).unwrap();
    for (item, name) in items.iter().zip(expected) {
        assert_eq!(item["state"], "succeeded");
        assert!(
            Path::new(item["source"].as_str().unwrap()).ends_with(name),
            "unexpected source order for {name}: {item}"
        );
        assert_eq!(item["destination"], output.join(name).to_str().unwrap());
    }
}

#[test]
fn failed_item_retry_skip_selects_only_the_exact_failure_and_preserves_success() {
    let (root, output, workspace, first, second) = fixtures();
    fs::write(&first, b"first original").unwrap();
    fs::write(&second, b"second retry").unwrap();
    fs::write(output.join("second.bin"), b"occupied").unwrap();

    let original = batch(&root, &output, &workspace, &[], &[&first, &second]);
    assert_eq!(original.status.code(), Some(8), "{original:?}");
    let original: Value = serde_json::from_slice(&original.stdout).unwrap();
    let parent_id = original["job_id"].as_str().unwrap();
    assert_eq!(original["result"]["state"], "completed_with_issues");
    assert_eq!(original["result"]["items"][0]["state"], "succeeded");
    assert_eq!(original["result"]["items"][1]["state"], "failed");
    let failed_key = original["result"]["items"][1]["item_key"].clone();
    fs::write(&first, b"changed after original").unwrap();

    let retried = command(&root)
        .args([
            "jobs",
            "retry",
            parent_id,
            "--failed-items",
            "--skip",
            "--json",
        ])
        .output()
        .unwrap();

    assert_eq!(retried.status.code(), Some(0), "{retried:?}");
    let retried: Value = serde_json::from_slice(&retried.stdout).unwrap();
    let retry_id = retried["job_id"].as_str().unwrap();
    assert_ne!(retry_id, parent_id);
    assert_eq!(retried["result"]["state"], "succeeded");
    assert_eq!(retried["result"]["items"].as_array().unwrap().len(), 1);
    assert_eq!(retried["result"]["items"][0]["item_key"], failed_key);
    assert_eq!(retried["result"]["items"][0]["state"], "skipped");
    assert_eq!(retried["result"]["items"][0]["outcome"], "skipped");
    assert_eq!(
        fs::read(output.join("first.bin")).unwrap(),
        b"first original"
    );
    assert_eq!(fs::read(output.join("second.bin")).unwrap(), b"occupied");

    let shown = command(&root)
        .args(["jobs", "show", retry_id, "--json"])
        .output()
        .unwrap();
    assert_eq!(shown.status.code(), Some(0), "{shown:?}");
    let shown: Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(shown["result"]["job"]["parent_job_id"], parent_id);
    assert_eq!(shown["result"]["job"]["conflict_policy"], "skip");
    assert_eq!(
        shown["result"]["job"]["conflict_policy_provenance"],
        "retry_explicit_skip"
    );
    assert_eq!(shown["result"]["job"]["items"].as_array().unwrap().len(), 1);
}

#[test]
fn failed_item_retry_defaults_to_fail_and_requires_unambiguous_fresh_authority() {
    let (root, output, workspace, first, second) = fixtures();
    fs::write(&first, b"first").unwrap();
    fs::write(&second, b"replacement").unwrap();
    fs::write(output.join("second.bin"), b"occupied").unwrap();
    let original = batch(&root, &output, &workspace, &[], &[&first, &second]);
    assert_eq!(original.status.code(), Some(8), "{original:?}");
    let original: Value = serde_json::from_slice(&original.stdout).unwrap();
    let parent_id = original["job_id"].as_str().unwrap();

    let default_retry = command(&root)
        .args(["jobs", "retry", parent_id, "--failed-items", "--json"])
        .output()
        .unwrap();
    assert_eq!(default_retry.status.code(), Some(4), "{default_retry:?}");
    let default_retry: Value = serde_json::from_slice(&default_retry.stdout).unwrap();
    assert_eq!(default_retry["kind"], "job.result");
    assert_eq!(default_retry["result"]["state"], "failed");
    assert_eq!(
        default_retry["result"]["items"][0]["failure"]["code"],
        "destination_conflict"
    );
    let before_contradictory = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();

    let contradictory = command(&root)
        .args([
            "jobs",
            "retry",
            parent_id,
            "--failed-items",
            "--replace",
            "--skip",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(contradictory.status.code(), Some(2), "{contradictory:?}");
    let contradictory: Value = serde_json::from_slice(&contradictory.stdout).unwrap();
    assert_eq!(contradictory["error"]["code"], "usage_error");
    let after_contradictory = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(before_contradictory.stdout, after_contradictory.stdout);

    let replaced = command(&root)
        .args([
            "jobs",
            "retry",
            parent_id,
            "--failed-items",
            "--replace",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(replaced.status.code(), Some(0), "{replaced:?}");
    let replaced: Value = serde_json::from_slice(&replaced.stdout).unwrap();
    assert_eq!(replaced["result"]["state"], "succeeded");
    assert_eq!(replaced["result"]["items"][0]["state"], "succeeded");
    assert_eq!(replaced["result"]["items"][0]["outcome"], "copied");
    assert_eq!(fs::read(output.join("second.bin")).unwrap(), b"replacement");
    assert_eq!(fs::read(output.join("first.bin")).unwrap(), b"first");
}

#[test]
fn failed_item_retry_uses_the_absolute_workspace_anchored_at_original_cwd() {
    let (root, output, _, first, _) = fixtures();
    let initial_cwd = root.path().join("initial-cwd");
    let retry_cwd = root.path().join("retry-cwd");
    let workspace = initial_cwd.join("relative-workspace");
    fs::create_dir(&initial_cwd).unwrap();
    fs::create_dir(&retry_cwd).unwrap();
    fs::create_dir(&workspace).unwrap();
    fs::write(&first, b"retry from another cwd").unwrap();
    fs::write(output.join("first.bin"), b"occupied").unwrap();

    let original = command(&root)
        .current_dir(&initial_cwd)
        .args(["copy-batch", "--output-dir"])
        .arg(&output)
        .args(["--workspace", "relative-workspace", "--json"])
        .arg(&first)
        .output()
        .unwrap();
    assert_eq!(original.status.code(), Some(4), "{original:?}");
    let original: Value = serde_json::from_slice(&original.stdout).unwrap();
    let parent_id = original["job_id"].as_str().unwrap();

    let shown = command(&root)
        .args(["jobs", "show", parent_id, "--json"])
        .output()
        .unwrap();
    assert_eq!(shown.status.code(), Some(0), "{shown:?}");
    let shown: Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(
        shown["result"]["job"]["workspace"],
        workspace.canonicalize().unwrap().to_str().unwrap()
    );

    let retried = command(&root)
        .current_dir(&retry_cwd)
        .args([
            "jobs",
            "retry",
            parent_id,
            "--failed-items",
            "--replace",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(retried.status.code(), Some(0), "{retried:?}");
    let retried: Value = serde_json::from_slice(&retried.stdout).unwrap();
    assert_eq!(retried["result"]["state"], "succeeded");
    assert_eq!(
        fs::read(output.join("first.bin")).unwrap(),
        b"retry from another cwd"
    );
}

#[test]
fn jsonl_skip_batch_has_ordered_events_and_one_terminal_result() {
    let (root, output, workspace, first, second) = fixtures();
    fs::write(&first, b"new first").unwrap();
    fs::write(&second, b"new second").unwrap();
    fs::write(output.join("first.bin"), b"old first").unwrap();
    fs::write(output.join("second.bin"), b"old second").unwrap();
    let completed = command(&root)
        .args(["copy-batch", "--output-dir"])
        .arg(&output)
        .arg("--workspace")
        .arg(&workspace)
        .args(["--skip", "--jsonl"])
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();

    assert_eq!(completed.status.code(), Some(0), "{completed:?}");
    let documents = completed
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        documents
            .iter()
            .filter(|document| document["kind"] == "job.result")
            .count(),
        1
    );
    assert_eq!(documents.last().unwrap()["kind"], "job.result");
    let events = documents
        .iter()
        .filter(|document| document["kind"] == "job.event")
        .collect::<Vec<_>>();
    assert!(
        events
            .iter()
            .all(|event| event["sequence"].as_u64().is_some())
    );
    assert!(events.windows(2).all(|pair| {
        pair[0]["sequence"].as_u64().unwrap() < pair[1]["sequence"].as_u64().unwrap()
    }));
    assert!(events.iter().any(|event| {
        event["event"] == "started"
            && event["snapshot"]["status"] == "running"
            && event["snapshot"]["completed_items"] == 0
    }));
    assert_eq!(documents.last().unwrap()["snapshot"]["status"], "succeeded");
    assert_eq!(documents.last().unwrap()["snapshot"]["completed_items"], 2);
    assert_eq!(documents.last().unwrap()["snapshot"]["skipped_items"], 2);
}

#[test]
fn failed_item_retry_from_skipped_and_failed_batch_retries_only_failure() {
    let (root, output, workspace, skipped_source, missing_source) = fixtures();
    fs::write(&skipped_source, b"skipped source before retry").unwrap();
    fs::write(output.join("first.bin"), b"preserve skipped output").unwrap();

    let original = batch(
        &root,
        &output,
        &workspace,
        &["--conflict", "skip"],
        &[&skipped_source, &missing_source],
    );
    assert_eq!(original.status.code(), Some(3), "{original:?}");
    let original: Value = serde_json::from_slice(&original.stdout).unwrap();
    assert_eq!(original["result"]["state"], "failed");
    let original_items = original["result"]["items"].as_array().unwrap();
    assert_eq!(original_items.len(), 2);
    assert_eq!(original_items[0]["state"], "skipped");
    assert_eq!(original_items[1]["state"], "preflight_failed");
    assert_eq!(original_items[1]["failure"]["code"], "source_unavailable");
    let parent_id = original["job_id"].as_str().unwrap();
    let failed_key = original_items[1]["item_key"].clone();

    fs::write(&skipped_source, b"changed skipped source").unwrap();
    fs::write(&missing_source, b"recovered failed source").unwrap();
    let retried = command(&root)
        .args(["jobs", "retry", parent_id, "--failed-items", "--json"])
        .output()
        .unwrap();

    assert_eq!(retried.status.code(), Some(0), "{retried:?}");
    let retried: Value = serde_json::from_slice(&retried.stdout).unwrap();
    assert_eq!(retried["result"]["state"], "succeeded");
    let retried_items = retried["result"]["items"].as_array().unwrap();
    assert_eq!(retried_items.len(), 1);
    assert_eq!(retried_items[0]["item_key"], failed_key);
    assert_eq!(retried_items[0]["state"], "succeeded");
    assert_eq!(
        fs::read(output.join("first.bin")).unwrap(),
        b"preserve skipped output"
    );
    assert_eq!(
        fs::read(output.join("second.bin")).unwrap(),
        b"recovered failed source"
    );
}

#[test]
fn failed_item_retry_can_execute_a_previously_missing_exact_selection() {
    let (root, output, workspace, present, missing) = fixtures();
    fs::write(&present, b"present original").unwrap();
    let original = batch(&root, &output, &workspace, &[], &[&present, &missing]);
    assert_eq!(original.status.code(), Some(8), "{original:?}");
    let original: Value = serde_json::from_slice(&original.stdout).unwrap();
    let parent_id = original["job_id"].as_str().unwrap();
    assert_eq!(original["result"]["state"], "completed_with_issues");
    assert_eq!(original["result"]["items"][0]["state"], "succeeded");
    assert_eq!(original["result"]["items"][1]["state"], "preflight_failed");
    assert_eq!(
        original["result"]["items"][1]["failure"]["code"],
        "source_unavailable"
    );
    let failed_key = original["result"]["items"][1]["item_key"].clone();

    let still_missing = command(&root)
        .args(["jobs", "retry", parent_id, "--failed-items", "--json"])
        .output()
        .unwrap();
    let still_missing: Value = serde_json::from_slice(&still_missing.stdout).unwrap();
    assert_eq!(still_missing["kind"], "error", "{still_missing:#}");
    assert_eq!(still_missing["error"]["code"], "source_unavailable");
    fs::write(&missing, b"now available").unwrap();
    fs::write(&present, b"changed successful source").unwrap();
    let retried = command(&root)
        .args(["jobs", "retry", parent_id, "--failed-items", "--json"])
        .output()
        .unwrap();
    assert_eq!(retried.status.code(), Some(0), "{retried:?}");
    let retried: Value = serde_json::from_slice(&retried.stdout).unwrap();
    assert_eq!(retried["result"]["state"], "succeeded");
    assert_eq!(retried["result"]["items"].as_array().unwrap().len(), 1);
    assert_eq!(retried["result"]["items"][0]["item_key"], failed_key);
    assert_eq!(retried["result"]["items"][0]["state"], "succeeded");
    assert_eq!(
        fs::read(output.join("second.bin")).unwrap(),
        b"now available"
    );
    assert_eq!(
        fs::read(output.join("first.bin")).unwrap(),
        b"present original"
    );
}

#[test]
fn failed_item_retry_replans_only_a_cleared_operation_preflight_conflict() {
    let (root, output, workspace, first, second) = fixtures();
    fs::write(&first, b"successful original").unwrap();
    fs::write(&second, b"failed item source").unwrap();
    fs::write(output.join("second.bin"), b"conflicting output").unwrap();
    let original = batch(&root, &output, &workspace, &[], &[&first, &second]);
    assert_eq!(original.status.code(), Some(8), "{original:?}");
    let original: Value = serde_json::from_slice(&original.stdout).unwrap();
    let parent_id = original["job_id"].as_str().unwrap();
    let items = original["result"]["items"].as_array().unwrap();
    assert_eq!(items[0]["state"], "succeeded");
    assert_eq!(items[1]["state"], "failed");
    assert_eq!(items[1]["failure"]["code"], "destination_conflict");
    let failed_key = items[1]["item_key"].clone();
    fs::remove_file(output.join("second.bin")).unwrap();
    fs::write(&first, b"successful source changed after admission").unwrap();

    let retry = command(&root)
        .args(["jobs", "retry", parent_id, "--failed-items", "--json"])
        .output()
        .unwrap();
    assert_eq!(retry.status.code(), Some(0), "{retry:?}");
    let retry: Value = serde_json::from_slice(&retry.stdout).unwrap();
    let retried_items = retry["result"]["items"].as_array().unwrap();
    assert_eq!(retried_items.len(), 1);
    assert_eq!(retried_items[0]["item_key"], failed_key);
    assert_eq!(retried_items[0]["state"], "succeeded");
    assert_eq!(
        fs::read(output.join("second.bin")).unwrap(),
        b"failed item source"
    );
    assert_eq!(
        fs::read(output.join("first.bin")).unwrap(),
        b"successful original"
    );
}

#[test]
fn failed_item_retry_rejects_a_missing_durable_batch_claim_before_admission() {
    let (root, output, workspace, first, second) = fixtures();
    fs::write(&first, b"successful original").unwrap();
    fs::write(&second, b"failed item source").unwrap();
    fs::write(output.join("second.bin"), b"conflicting output").unwrap();
    let original = batch(&root, &output, &workspace, &[], &[&first, &second]);
    assert_eq!(original.status.code(), Some(8), "{original:?}");
    let original: Value = serde_json::from_slice(&original.stdout).unwrap();
    let parent_id = original["job_id"].as_str().unwrap();

    let connection = Connection::open(history_database(&root)).unwrap();
    assert_eq!(
        connection
            .execute(
                "DELETE FROM job_lease_claims WHERE job_id = ?1",
                [parent_id],
            )
            .unwrap(),
        1
    );
    fs::remove_file(output.join("second.bin")).unwrap();
    let before = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();

    let retry = command(&root)
        .args(["jobs", "retry", parent_id, "--failed-items", "--json"])
        .output()
        .unwrap();
    assert_ne!(retry.status.code(), Some(0), "{retry:?}");
    let retry: Value = serde_json::from_slice(&retry.stdout).unwrap();
    assert_eq!(retry["kind"], "error");
    let after = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(before.stdout, after.stdout);
    assert!(!output.join("second.bin").exists());
    assert_eq!(
        fs::read(output.join("first.bin")).unwrap(),
        b"successful original"
    );
}

#[test]
fn copy_batch_missing_output_directory_fails_before_creating_workspace() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("missing-output");
    let workspace = root.path().join("missing-workspace");
    let source = root.path().join("source.bin");
    fs::write(&source, b"batch source").unwrap();
    let failed = command(&root)
        .args(["copy-batch", "--output-dir"])
        .arg(&output)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--json")
        .arg(&source)
        .output()
        .unwrap();
    assert_eq!(failed.status.code(), Some(3), "{failed:?}");
    let document: Value = serde_json::from_slice(&failed.stdout).unwrap();
    assert_eq!(document["error"]["code"], "output_directory_unavailable");
    assert!(!output.exists());
    assert!(!workspace.exists());
}

#[test]
fn output_mode_prescan_stops_at_the_positional_delimiter() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("output");
    let workspace = root.path().join("workspace");
    fs::create_dir(&output).unwrap();
    fs::create_dir(&workspace).unwrap();
    fs::write(root.path().join("--json"), b"literal json source").unwrap();
    fs::write(root.path().join("--jsonl"), b"literal jsonl source").unwrap();

    let usage = command(&root)
        .current_dir(root.path())
        .args(["copy-batch", "--", "--json", "--jsonl"])
        .output()
        .unwrap();
    assert_eq!(usage.status.code(), Some(2), "{usage:?}");
    assert!(usage.stdout.is_empty());
    assert!(!usage.stderr.is_empty());

    let human = command(&root)
        .current_dir(root.path())
        .args(["copy-batch", "--output-dir"])
        .arg(&output)
        .arg("--workspace")
        .arg(&workspace)
        .args(["--", "--json", "--jsonl"])
        .output()
        .unwrap();
    assert_eq!(human.status.code(), Some(0), "{human:?}");
    assert!(human.stderr.is_empty());
    assert!(String::from_utf8_lossy(&human.stdout).contains("Copy batch succeeded: 2 items"));
    assert_eq!(
        fs::read(output.join("--json")).unwrap(),
        b"literal json source"
    );
    assert_eq!(
        fs::read(output.join("--jsonl")).unwrap(),
        b"literal jsonl source"
    );

    let json_output = root.path().join("json-output");
    let json_workspace = root.path().join("json-workspace");
    fs::create_dir(&json_output).unwrap();
    fs::create_dir(&json_workspace).unwrap();
    let machine = command(&root)
        .current_dir(root.path())
        .args(["copy-batch", "--output-dir"])
        .arg(&json_output)
        .arg("--workspace")
        .arg(&json_workspace)
        .args(["--json", "--", "--jsonl"])
        .output()
        .unwrap();
    assert_eq!(machine.status.code(), Some(0), "{machine:?}");
    assert!(machine.stderr.is_empty());
    let document: Value = serde_json::from_slice(&machine.stdout).unwrap();
    assert_eq!(document["kind"], "job.result");
    assert_eq!(document["result"]["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        fs::read(json_output.join("--jsonl")).unwrap(),
        b"literal jsonl source"
    );
}

#[test]
fn pre_admission_destination_collision_uses_the_input_exit_class() {
    let (root, output, workspace, _first, _second) = fixtures();
    let present_directory = root.path().join("present");
    let missing_directory = root.path().join("missing");
    fs::create_dir(&present_directory).unwrap();
    fs::create_dir(&missing_directory).unwrap();
    let present = present_directory.join("same.bin");
    let missing = missing_directory.join("same.bin");
    fs::write(&present, b"present").unwrap();

    let failed = batch(&root, &output, &workspace, &[], &[&present, &missing]);

    assert_eq!(failed.status.code(), Some(3), "{failed:?}");
    let document: Value = serde_json::from_slice(&failed.stdout).unwrap();
    assert_eq!(document["error"]["code"], "destination_collision");
}

#[test]
fn single_copy_retry_accepts_explicit_skip_without_becoming_a_batch() {
    let (root, output, workspace, source, _second) = fixtures();
    let destination = output.join("single.bin");
    fs::write(&source, b"single source bytes").unwrap();
    let copied = command(&root)
        .arg("copy")
        .arg(&source)
        .arg(&destination)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(copied.status.code(), Some(0), "{copied:?}");
    let copied: Value = serde_json::from_slice(&copied.stdout).unwrap();
    let job_id = copied["job_id"].as_str().unwrap();
    fs::write(&destination, b"operator owned bytes").unwrap();

    let retried = command(&root)
        .args(["jobs", "retry", job_id, "--skip", "--json"])
        .output()
        .unwrap();
    assert_eq!(retried.status.code(), Some(0), "{retried:?}");
    let retried: Value = serde_json::from_slice(&retried.stdout).unwrap();
    assert!(retried.get("submission_kind").is_none());
    assert_eq!(retried["result"]["state"], "succeeded");
    assert_eq!(retried["result"]["outcome"], "skipped");
    assert_eq!(fs::read(&destination).unwrap(), b"operator owned bytes");
    let shown = command(&root)
        .args([
            "jobs",
            "show",
            retried["job_id"].as_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    let shown: Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(shown["result"]["job"]["conflict_policy"], "skip");
    assert_eq!(
        shown["result"]["job"]["conflict_policy_provenance"],
        "retry_explicit_skip"
    );
}

#[test]
fn single_copy_retry_skip_reports_skipped_in_human_output() {
    let (root, output, workspace, source, _second) = fixtures();
    let destination = output.join("single-human.bin");
    fs::write(&source, b"single source bytes").unwrap();
    let copied = command(&root)
        .arg("copy")
        .arg(&source)
        .arg(&destination)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(copied.status.code(), Some(0), "{copied:?}");
    let copied: Value = serde_json::from_slice(&copied.stdout).unwrap();
    let job_id = copied["job_id"].as_str().unwrap();
    fs::write(&destination, b"operator owned bytes").unwrap();

    let retried = command(&root)
        .args(["jobs", "retry", job_id, "--skip"])
        .output()
        .unwrap();
    assert_eq!(retried.status.code(), Some(0), "{retried:?}");
    let human = String::from_utf8(retried.stdout).unwrap();
    assert!(
        human.contains("Copy-through skipped: the destination was left unchanged."),
        "{human}"
    );
    assert_eq!(fs::read(&destination).unwrap(), b"operator owned bytes");
}

#[test]
fn failed_batch_exit_uses_the_most_severe_item_failure() {
    let (root, output, workspace, missing, conflict) = fixtures();
    fs::write(&conflict, b"replacement").unwrap();
    fs::write(output.join("second.bin"), b"operator owned").unwrap();

    let completed = batch(
        &root,
        &output,
        &workspace,
        &["--conflict", "fail"],
        &[&missing, &conflict],
    );

    assert_eq!(completed.status.code(), Some(4), "{completed:?}");
    let document: Value = serde_json::from_slice(&completed.stdout).unwrap();
    assert_eq!(document["result"]["state"], "failed");
    assert_eq!(
        document["result"]["items"][0]["failure"]["code"],
        "source_unavailable"
    );
    assert_eq!(
        document["result"]["items"][1]["failure"]["code"],
        "destination_conflict"
    );
}

#[test]
fn trusted_split_is_admitted_then_rejected_only_for_its_copy_item() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("output");
    let workspace = root.path().join("workspace");
    let ordinary = root.path().join("ordinary.bin");
    let state_base = root.path().join("state");
    fs::create_dir(&output).unwrap();
    fs::create_dir(&workspace).unwrap();
    fs::write(&ordinary, b"ordinary batch bytes").unwrap();

    let fixture = SplitFixture::new(b"trusted split source", 6);
    fixture.write(root.path(), "qualified.nsp");
    let store = LocalSplitTrustStore::new(state_base.join("split-trust"));
    fixture.issue(&store);

    let mut command = command(&root);
    let completed = command
        .env("NSCB_STATE_DIR", &state_base)
        .args(["copy-batch", "--output-dir"])
        .arg(&output)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--json")
        .arg(&ordinary)
        .arg(root.path().join("qualified.nsp"))
        .output()
        .unwrap();

    assert_eq!(completed.status.code(), Some(8), "{completed:?}");
    let document: Value = serde_json::from_slice(&completed.stdout).unwrap();
    assert_eq!(document["result"]["state"], "completed_with_issues");
    assert_eq!(document["result"]["items"][0]["state"], "succeeded");
    assert_eq!(document["result"]["items"][1]["state"], "preflight_failed");
    assert_eq!(
        document["result"]["items"][1]["failure"]["code"],
        "split_input_unsupported"
    );
    let logical_source = root.path().join("qualified.nsp");
    assert_eq!(
        document["result"]["items"][1]["source"],
        logical_source.to_str().unwrap()
    );
    assert_eq!(
        document["result"]["items"][1]["destination"],
        fs::canonicalize(&output)
            .unwrap()
            .join("qualified.nsp")
            .to_str()
            .unwrap()
    );
    assert_eq!(
        fs::read(output.join("ordinary.bin")).unwrap(),
        b"ordinary batch bytes"
    );
    assert!(!output.join("qualified.nsp").exists());
    fixture.revalidate_source_and_parts();
}

#[test]
fn failed_item_retry_preserves_qualified_split_preflight_without_copying_parts() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("output");
    let workspace = root.path().join("workspace");
    let ordinary = root.path().join("ordinary.bin");
    let recovered = root.path().join("recovered.bin");
    let state_base = root.path().join("state");
    let split_list = root.path().join("split-inputs.json");
    fs::create_dir(&output).unwrap();
    fs::create_dir(&workspace).unwrap();
    fs::write(&ordinary, b"ordinary batch bytes").unwrap();

    let fixture = SplitFixture::new(b"trusted split source", 6);
    fixture.write(root.path(), "qualified.nsp");
    write_input_list(&split_list, &["qualified.nsp"]);
    let store = LocalSplitTrustStore::new(state_base.join("split-trust"));
    fixture.issue(&store);

    let original = command(&root)
        .env("NSCB_STATE_DIR", &state_base)
        .args(["copy-batch", "--output-dir"])
        .arg(&output)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--json")
        .arg(&ordinary)
        .arg(&recovered)
        .args(["--input-list"])
        .arg(&split_list)
        .output()
        .unwrap();
    assert_eq!(original.status.code(), Some(8), "{original:?}");
    let original: Value = serde_json::from_slice(&original.stdout).unwrap();
    let parent_id = original["job_id"].as_str().unwrap();
    let recovered_key = original["result"]["items"][1]["item_key"].clone();
    let split_key = original["result"]["items"][2]["item_key"].clone();
    assert_eq!(original["result"]["items"][1]["state"], "preflight_failed");
    assert_eq!(original["result"]["items"][2]["state"], "preflight_failed");
    assert_eq!(
        original["result"]["items"][2]["failure"]["code"],
        "split_input_unsupported"
    );

    fs::write(&recovered, b"recovered on retry").unwrap();
    write_input_list(&split_list, &["ordinary.bin"]);
    let retried = command(&root)
        .env("NSCB_STATE_DIR", &state_base)
        .args([
            "jobs",
            "retry",
            parent_id,
            "--failed-items",
            "--skip",
            "--json",
        ])
        .output()
        .unwrap();

    assert_eq!(retried.status.code(), Some(8), "{retried:?}");
    let retried: Value = serde_json::from_slice(&retried.stdout).unwrap();
    assert_eq!(retried["result"]["state"], "completed_with_issues");
    let items = retried["result"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["item_key"], recovered_key);
    assert_eq!(items[0]["state"], "succeeded");
    assert_eq!(items[1]["item_key"], split_key);
    assert_eq!(items[1]["state"], "preflight_failed");
    assert_eq!(items[1]["failure"]["code"], "split_input_unsupported");
    let logical_source = root.path().join("qualified.nsp");
    assert_eq!(
        fs::canonicalize(items[1]["source"].as_str().unwrap()).unwrap(),
        fs::canonicalize(&logical_source).unwrap()
    );
    assert_eq!(
        items[1]["destination"],
        fs::canonicalize(&output)
            .unwrap()
            .join("qualified.nsp")
            .to_str()
            .unwrap()
    );
    let retried_job_id = retried["job_id"].as_str().unwrap();
    let split_item_key = split_key.as_str().unwrap();
    let connection = Connection::open(history_database(&root)).unwrap();
    let provenance_json: String = connection
        .query_row(
            "SELECT provenance_json FROM job_items
             WHERE job_id = ?1 AND item_key = ?2",
            [retried_job_id, split_item_key],
            |row| row.get(0),
        )
        .unwrap();
    let provenance: Value = serde_json::from_str(&provenance_json).unwrap();
    assert_eq!(
        provenance["split_qualification"]["kind"],
        "local_split_receipt"
    );
    assert_eq!(
        provenance["split_qualification"]["manifest_schema_version"],
        1
    );
    assert!(
        provenance["split_qualification"]["original_size_bytes"]
            .as_u64()
            .is_some_and(|size| size > 0)
    );
    assert_eq!(
        provenance["split_qualification"]["original_sha256"]
            .as_str()
            .map(str::len),
        Some(64)
    );
    assert_eq!(
        provenance["split_qualification"]["manifest_sha256"]
            .as_str()
            .map(str::len),
        Some(64)
    );
    let intent_json: String = connection
        .query_row(
            "SELECT intent_json FROM batch_intents WHERE job_id = ?1",
            [retried_job_id],
            |row| row.get(0),
        )
        .unwrap();
    let intent: Value = serde_json::from_str(&intent_json).unwrap();
    let split_selection = intent["selections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|selection| selection.get("split_qualification").is_some())
        .unwrap();
    assert_eq!(
        split_selection["selection_path"],
        split_list.to_str().unwrap()
    );
    assert_eq!(split_selection["input_list_entry_path"], "qualified.nsp");
    assert!(Path::new(split_selection["base_directory"].as_str().unwrap()).is_absolute());
    assert_eq!(
        fs::read(output.join("recovered.bin")).unwrap(),
        b"recovered on retry"
    );
    assert!(!output.join("qualified.nsp").exists());
    assert!(!output.join("00").exists());
    fixture.revalidate_source_and_parts();
}

#[test]
fn failed_item_retry_rejects_changed_trusted_split_membership_before_admission() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("output");
    let workspace = root.path().join("workspace");
    let ordinary = root.path().join("ordinary.bin");
    let recovered = root.path().join("recovered.bin");
    let state_base = root.path().join("state");
    let split_list = root.path().join("split-inputs.json");
    fs::create_dir(&output).unwrap();
    fs::create_dir(&workspace).unwrap();
    fs::write(&ordinary, b"ordinary batch bytes").unwrap();

    let original_split = SplitFixture::new(b"trusted split source", 6);
    original_split.write(root.path(), "qualified.nsp");
    write_input_list(&split_list, &["qualified.nsp"]);
    let store = LocalSplitTrustStore::new(state_base.join("split-trust"));
    original_split.issue(&store);

    let original = command(&root)
        .env("NSCB_STATE_DIR", &state_base)
        .args(["copy-batch", "--output-dir"])
        .arg(&output)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--json")
        .arg(&ordinary)
        .arg(&recovered)
        .args(["--input-list"])
        .arg(&split_list)
        .output()
        .unwrap();
    assert_eq!(original.status.code(), Some(8), "{original:?}");
    let original: Value = serde_json::from_slice(&original.stdout).unwrap();
    let parent_id = original["job_id"].as_str().unwrap();
    assert_eq!(original["result"]["items"][1]["state"], "preflight_failed");
    assert_eq!(original["result"]["items"][2]["state"], "preflight_failed");
    assert_eq!(
        original["result"]["items"][2]["failure"]["code"],
        "split_input_unsupported"
    );
    let jobs_before = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();

    fs::write(&recovered, b"recovered on retry").unwrap();
    fs::remove_dir_all(root.path().join("qualified.nsp")).unwrap();
    let changed_split = SplitFixture::new(&original_split.source, 7);
    assert_eq!(changed_split.source.len(), original_split.source.len());
    assert_eq!(changed_split.source_sha256, original_split.source_sha256);
    assert_ne!(
        changed_split.manifest_sha256,
        original_split.manifest_sha256
    );
    changed_split.write(root.path(), "qualified.nsp");
    changed_split.issue(&store);

    let retried = command(&root)
        .env("NSCB_STATE_DIR", &state_base)
        .args([
            "jobs",
            "retry",
            parent_id,
            "--failed-items",
            "--skip",
            "--json",
        ])
        .output()
        .unwrap();

    assert_ne!(retried.status.code(), Some(0), "{retried:?}");
    let retried: Value = serde_json::from_slice(&retried.stdout).unwrap();
    assert_eq!(retried["kind"], "error", "{retried:#}");
    assert_eq!(retried["error"]["code"], "job_failed_items_unsupported");
    let jobs_after = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(jobs_before.stdout, jobs_after.stdout);
    assert!(!output.join("recovered.bin").exists());
    assert!(!output.join("qualified.nsp").exists());
    assert_eq!(
        fs::read(output.join("ordinary.bin")).unwrap(),
        b"ordinary batch bytes"
    );
    changed_split.revalidate_source_and_parts();
}

#[test]
fn failed_item_retry_preserves_split_resolver_error_identity_before_admission() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("output");
    let workspace = root.path().join("workspace");
    let ordinary = root.path().join("ordinary.bin");
    let state_base = root.path().join("state");
    fs::create_dir(&output).unwrap();
    fs::create_dir(&workspace).unwrap();
    fs::write(&ordinary, b"prior successful output").unwrap();
    let split = SplitFixture::new(b"retry resolver error identity", 6);
    split.write(root.path(), "qualified.nsp");
    let store = LocalSplitTrustStore::new(state_base.join("split-trust"));
    split.issue(&store);

    let original = command(&root)
        .env("NSCB_STATE_DIR", &state_base)
        .args(["copy-batch", "--output-dir"])
        .arg(&output)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--json")
        .arg(&ordinary)
        .arg(root.path().join("qualified.nsp"))
        .output()
        .unwrap();
    assert_eq!(original.status.code(), Some(8), "{original:?}");
    let original: Value = serde_json::from_slice(&original.stdout).unwrap();
    let parent_id = original["job_id"].as_str().unwrap();
    assert_eq!(original["result"]["items"][0]["state"], "succeeded");
    assert_eq!(original["result"]["items"][1]["state"], "preflight_failed");

    let jobs_before = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    let receipt = state_base
        .join("split-trust")
        .join("receipts")
        .join(format!("{}.json", split.manifest_sha256.to_hex()));
    fs::write(receipt, b"corrupt receipt").unwrap();

    for (state_directory, expected_code, expected_exit) in [
        (state_base.as_path(), "split_state_unavailable", 7),
        (
            Path::new("relative-state"),
            "split_trust_store_configuration_invalid",
            2,
        ),
    ] {
        let retried = command(&root)
            .env("NSCB_STATE_DIR", state_directory)
            .args([
                "jobs",
                "retry",
                parent_id,
                "--failed-items",
                "--skip",
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(retried.status.code(), Some(expected_exit), "{retried:?}");
        assert!(retried.stderr.is_empty());
        let error: Value = serde_json::from_slice(&retried.stdout).unwrap();
        assert_eq!(error["kind"], "error");
        assert_eq!(error["error"]["code"], expected_code);
        let jobs_after = command(&root)
            .args(["jobs", "list", "--json"])
            .output()
            .unwrap();
        assert_eq!(jobs_before.stdout, jobs_after.stdout);
        assert_eq!(
            fs::read(output.join("ordinary.bin")).unwrap(),
            b"prior successful output"
        );
        assert!(!output.join("qualified.nsp").exists());
    }
    split.revalidate_source_and_parts();
}

#[test]
fn failed_item_retry_preserves_missing_qualified_split_source_error_before_admission() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("output");
    let workspace = root.path().join("workspace");
    let ordinary = root.path().join("ordinary.bin");
    let state_base = root.path().join("state");
    fs::create_dir(&output).unwrap();
    fs::create_dir(&workspace).unwrap();
    fs::write(&ordinary, b"prior successful output").unwrap();

    let split = SplitFixture::new(b"retry deleted qualified split", 6);
    let split_directory = split.write(root.path(), "qualified.nsp");
    let store = LocalSplitTrustStore::new(state_base.join("split-trust"));
    split.issue(&store);

    let original = command(&root)
        .env("NSCB_STATE_DIR", &state_base)
        .args(["copy-batch", "--output-dir"])
        .arg(&output)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--json")
        .arg(&ordinary)
        .arg(&split_directory)
        .output()
        .unwrap();
    assert_eq!(original.status.code(), Some(8), "{original:?}");
    let original: Value = serde_json::from_slice(&original.stdout).unwrap();
    let parent_id = original["job_id"].as_str().unwrap();
    assert_eq!(original["result"]["items"][0]["state"], "succeeded");
    assert_eq!(original["result"]["items"][1]["state"], "preflight_failed");
    assert_eq!(
        original["result"]["items"][1]["failure"]["code"],
        "split_input_unsupported"
    );
    let jobs_before = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();

    fs::remove_dir_all(&split_directory).unwrap();

    let retried = command(&root)
        .env("NSCB_STATE_DIR", &state_base)
        .args([
            "jobs",
            "retry",
            parent_id,
            "--failed-items",
            "--skip",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(retried.status.code(), Some(3), "{retried:?}");
    assert!(retried.stderr.is_empty());
    let error: Value = serde_json::from_slice(&retried.stdout).unwrap();
    assert_eq!(error["kind"], "error");
    assert_eq!(error["error"]["code"], "input_unavailable");

    let jobs_after = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(jobs_before.stdout, jobs_after.stdout);
    assert_eq!(
        fs::read(output.join("ordinary.bin")).unwrap(),
        b"prior successful output"
    );
    assert!(!output.join("qualified.nsp").exists());
}

#[test]
fn failed_item_retry_rejects_shared_split_member_identity_before_admission() {
    use std::os::unix::fs::MetadataExt;

    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("output");
    let workspace = root.path().join("workspace");
    let ordinary = root.path().join("ordinary.bin");
    let state_base = root.path().join("state");
    fs::create_dir(&output).unwrap();
    fs::create_dir(&workspace).unwrap();
    fs::write(&ordinary, b"ordinary batch bytes").unwrap();

    let first_split = SplitFixture::new(b"common-first-split-source", 6);
    let first_directory = first_split.write(root.path(), "first.nsp");
    let second_split = SplitFixture::new(b"common-other-split-source", 6);
    assert_eq!(first_split.parts[0], second_split.parts[0]);
    assert_ne!(first_split.manifest_sha256, second_split.manifest_sha256);
    let second_directory = second_split.write(root.path(), "second.nsp");
    let first_member_before = fs::metadata(first_directory.join("00")).unwrap();
    let second_member_before = fs::metadata(second_directory.join("00")).unwrap();
    assert_ne!(
        (first_member_before.dev(), first_member_before.ino()),
        (second_member_before.dev(), second_member_before.ino())
    );
    let store = LocalSplitTrustStore::new(state_base.join("split-trust"));
    first_split.issue(&store);
    second_split.issue(&store);

    let original = command(&root)
        .env("NSCB_STATE_DIR", &state_base)
        .args(["copy-batch", "--output-dir"])
        .arg(&output)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--json")
        .arg(&ordinary)
        .arg(&first_directory)
        .arg(&second_directory)
        .output()
        .unwrap();
    assert_eq!(original.status.code(), Some(8), "{original:?}");
    let original: Value = serde_json::from_slice(&original.stdout).unwrap();
    let parent_id = original["job_id"].as_str().unwrap();
    assert_eq!(original["result"]["items"][0]["state"], "succeeded");
    assert_eq!(original["result"]["items"][1]["state"], "preflight_failed");
    assert_eq!(original["result"]["items"][2]["state"], "preflight_failed");
    assert_eq!(
        original["result"]["items"][1]["failure"]["code"],
        "split_input_unsupported"
    );
    assert_eq!(
        original["result"]["items"][2]["failure"]["code"],
        "split_input_unsupported"
    );
    let jobs_before = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();

    let first_receipt_before = store.lookup(&first_split.manifest_sha256).unwrap().unwrap();
    let second_receipt_before = store
        .lookup(&second_split.manifest_sha256)
        .unwrap()
        .unwrap();
    let member_bytes = fs::read(second_directory.join("00")).unwrap();
    let first_manifest = fs::read(sidecar_path(&first_directory)).unwrap();
    let second_manifest = fs::read(sidecar_path(&second_directory)).unwrap();
    fs::remove_file(second_directory.join("00")).unwrap();
    fs::hard_link(first_directory.join("00"), second_directory.join("00")).unwrap();
    assert_eq!(fs::read(second_directory.join("00")).unwrap(), member_bytes);
    assert_eq!(
        fs::metadata(second_directory.join("00")).unwrap().len(),
        member_bytes.len() as u64
    );
    let first_member_after = fs::metadata(first_directory.join("00")).unwrap();
    let second_member_after = fs::metadata(second_directory.join("00")).unwrap();
    assert_eq!(
        (first_member_after.dev(), first_member_after.ino()),
        (second_member_after.dev(), second_member_after.ino())
    );
    assert_eq!(
        fs::read(sidecar_path(&first_directory)).unwrap(),
        first_manifest
    );
    assert_eq!(
        fs::read(sidecar_path(&second_directory)).unwrap(),
        second_manifest
    );
    let first_receipt_after = store.lookup(&first_split.manifest_sha256).unwrap().unwrap();
    let second_receipt_after = store
        .lookup(&second_split.manifest_sha256)
        .unwrap()
        .unwrap();
    assert_eq!(
        first_receipt_before.manifest_sha256(),
        first_receipt_after.manifest_sha256()
    );
    assert_eq!(
        first_receipt_before.source_size_bytes(),
        first_receipt_after.source_size_bytes()
    );
    assert_eq!(
        first_receipt_before.source_sha256(),
        first_receipt_after.source_sha256()
    );
    assert_eq!(
        second_receipt_before.manifest_sha256(),
        second_receipt_after.manifest_sha256()
    );
    assert_eq!(
        second_receipt_before.source_size_bytes(),
        second_receipt_after.source_size_bytes()
    );
    assert_eq!(
        second_receipt_before.source_sha256(),
        second_receipt_after.source_sha256()
    );
    second_split.revalidate_source_and_parts();

    let retried = command(&root)
        .env("NSCB_STATE_DIR", &state_base)
        .args([
            "jobs",
            "retry",
            parent_id,
            "--failed-items",
            "--skip",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(retried.status.code(), Some(3), "{retried:?}");
    let retried: Value = serde_json::from_slice(&retried.stdout).unwrap();
    assert_eq!(retried["kind"], "error", "{retried:#}");
    assert_eq!(retried["error"]["code"], "duplicate_selection");
    let jobs_after = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(jobs_before.stdout, jobs_after.stdout);
    assert_eq!(
        fs::read(output.join("ordinary.bin")).unwrap(),
        b"ordinary batch bytes"
    );
    assert!(!output.join("first.nsp").exists());
    assert!(!output.join("second.nsp").exists());
}
