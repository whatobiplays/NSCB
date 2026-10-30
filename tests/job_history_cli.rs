#![cfg(feature = "standalone-job-history")]

//! Real-binary contracts for standalone Job history commands.

#[path = "support/mod.rs"]
mod support;

#[cfg(target_os = "macos")]
use rusqlite::Connection;
use serde_json::Value;
#[cfg(target_os = "macos")]
use std::fs;
#[cfg(target_os = "macos")]
use std::io::{BufRead, BufReader};
#[cfg(target_os = "macos")]
use std::os::fd::FromRawFd;
#[cfg(unix)]
#[cfg(target_os = "macos")]
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
#[cfg(target_os = "macos")]
use std::process::Stdio;
use support::process::isolated_command_with_home;
use tempfile::TempDir;

fn command(root: &TempDir) -> Command {
    isolated_command_with_home(&root.path().join("home"))
}

fn configuration_path(root: &TempDir) -> std::path::PathBuf {
    let home = root.path().join("home");
    #[cfg(target_os = "macos")]
    {
        home.join("Library")
            .join("Application Support")
            .join("NSCB")
            .join("config.toml")
    }
    #[cfg(target_os = "linux")]
    {
        home.join("xdg-config").join("NSCB").join("config.toml")
    }
    #[cfg(target_os = "windows")]
    {
        home.join("AppData")
            .join("Roaming")
            .join("NSCB")
            .join("config.toml")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        home.join("xdg-config").join("NSCB").join("config.toml")
    }
}

#[test]
fn job_history_commands_initialize_missing_configuration() {
    for (args, expected_status) in [
        (&["jobs", "list", "--json"][..], 0),
        (
            &["jobs", "show", "00000000000000000000000000000000", "--json"][..],
            3,
        ),
        (&["jobs", "clear", "--json"][..], 0),
    ] {
        let root = tempfile::tempdir().unwrap();
        let config = configuration_path(&root);
        assert!(!config.exists());

        let output = command(&root).args(args).output().unwrap();

        assert_eq!(output.status.code(), Some(expected_status), "{output:?}");
        assert!(config.is_file(), "startup did not initialize {config:?}");
        let document: Value = serde_json::from_slice(&output.stdout).unwrap();
        if expected_status == 0 {
            assert!(matches!(
                document["kind"].as_str(),
                Some("jobs.list" | "jobs.clear")
            ));
        } else {
            assert_eq!(document["error"]["code"], "job_not_found");
        }
    }
}

#[test]
fn malformed_configuration_blocks_job_history_commands_before_history_actions() {
    for args in [
        &["jobs", "list", "--json"][..],
        &["jobs", "show", "00000000000000000000000000000000", "--json"][..],
        &["jobs", "clear", "--json"][..],
    ] {
        let root = tempfile::tempdir().unwrap();
        let config = configuration_path(&root);
        let malformed = "schema_version = [\n";
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(&config, malformed).unwrap();

        let output = command(&root).args(args).output().unwrap();

        assert_eq!(output.status.code(), Some(2), "{output:?}");
        let document: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(document["kind"], "error");
        assert_eq!(document["error"]["code"], "config_parse_failed");
        assert!(!history_database(&root).exists());
        assert_eq!(std::fs::read_to_string(config).unwrap(), malformed);
    }
}

#[cfg(target_os = "macos")]
fn write_source(root: &TempDir) -> (PathBuf, PathBuf, PathBuf) {
    let source = root.path().join("source.bin");
    let destination = root.path().join("destination.bin");
    let workspace = root.path().join("workspace");
    fs::write(&source, b"durable Job history source").unwrap();
    (source, destination, workspace)
}

fn history_database(root: &TempDir) -> PathBuf {
    let home = root.path().join("home");
    #[cfg(target_os = "macos")]
    {
        home.join("Library")
            .join("Application Support")
            .join("NSCB")
            .join("jobs.sqlite3")
    }
    #[cfg(target_os = "linux")]
    {
        home.join("xdg-data").join("NSCB").join("jobs.sqlite3")
    }
    #[cfg(target_os = "windows")]
    {
        home.join("AppData")
            .join("Local")
            .join("NSCB")
            .join("jobs.sqlite3")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        home.join("xdg-data").join("NSCB").join("jobs.sqlite3")
    }
}

#[cfg(target_os = "macos")]
fn copy_json(root: &TempDir, source: &Path, destination: &Path, workspace: &Path) -> Value {
    let output = command(root)
        .arg("copy")
        .arg(source)
        .arg(destination)
        .arg("--workspace")
        .arg(workspace)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[cfg(target_os = "macos")]
#[test]
fn copy_history_is_inspectable_after_the_copy_process_exits() {
    let root = tempfile::tempdir().unwrap();
    let (source, destination, workspace) = write_source(&root);
    let copied = copy_json(&root, &source, &destination, &workspace);
    let job_id = copied["job_id"]
        .as_str()
        .expect("standalone copy exposes its durable Job ID");

    let shown = command(&root)
        .args(["jobs", "show", job_id, "--json"])
        .output()
        .unwrap();
    assert_eq!(shown.status.code(), Some(0), "{shown:?}");
    let shown: Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(shown["kind"], "jobs.show");
    assert_eq!(shown["result"]["job"]["job_id"], job_id);
    assert_eq!(shown["result"]["job"]["state"], "succeeded");
    assert_eq!(shown["result"]["job"]["result"]["state"], "succeeded");
    assert_eq!(shown["result"]["job"]["items"][0]["state"], "succeeded");

    let listed = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(listed.status.code(), Some(0), "{listed:?}");
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed["kind"], "jobs.list");
    assert_eq!(listed["result"]["retention_limit"], 1000);
    assert_eq!(listed["result"]["jobs"][0]["job_id"], job_id);
}

#[cfg(target_os = "macos")]
#[test]
fn human_job_history_commands_render_localized_records_and_clear_summary() {
    let root = tempfile::tempdir().unwrap();
    let (source, destination, workspace) = write_source(&root);
    let copied = copy_json(&root, &source, &destination, &workspace);
    let job_id = copied["job_id"].as_str().unwrap();

    let listed = command(&root).args(["jobs", "list"]).output().unwrap();
    assert_eq!(listed.status.code(), Some(0), "{listed:?}");
    assert!(listed.stderr.is_empty(), "{listed:?}");
    let listed = String::from_utf8(listed.stdout).unwrap();
    assert!(listed.contains(job_id), "{listed}");
    assert!(listed.contains("Succeeded"), "{listed}");
    assert!(!listed.contains("succeeded"), "{listed}");

    let shown = command(&root)
        .args(["jobs", "show", job_id])
        .output()
        .unwrap();
    assert_eq!(shown.status.code(), Some(0), "{shown:?}");
    assert!(shown.stderr.is_empty(), "{shown:?}");
    let shown = String::from_utf8(shown.stdout).unwrap();
    for label in ["Job: ", "State: Succeeded", "Admitted: ", "Terminal: "] {
        assert!(shown.contains(label), "missing {label:?} in {shown}");
    }
    assert!(shown.contains("Item: "), "{shown}");
    assert!(!shown.contains("State: succeeded"), "{shown}");

    let cleared = command(&root).args(["jobs", "clear"]).output().unwrap();
    assert_eq!(cleared.status.code(), Some(0), "{cleared:?}");
    assert!(cleared.stderr.is_empty(), "{cleared:?}");
    assert_eq!(
        String::from_utf8(cleared.stdout).unwrap(),
        "Deleted 1 terminal Job records. Active Jobs were preserved.\n"
    );

    let empty = command(&root).args(["jobs", "list"]).output().unwrap();
    assert_eq!(empty.status.code(), Some(0), "{empty:?}");
    assert!(empty.stderr.is_empty(), "{empty:?}");
    assert_eq!(
        String::from_utf8(empty.stdout).unwrap(),
        "No historical Jobs.\n"
    );
}

#[test]
fn planning_failure_does_not_create_a_job() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("missing-source.bin");
    let destination = root.path().join("destination.bin");
    let workspace = root.path().join("workspace");

    let output = command(&root)
        .arg("copy")
        .arg(&source)
        .arg(&destination)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--json")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let output: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output["kind"], "error");
    #[cfg(target_os = "macos")]
    let expected_error = "source_unavailable";
    #[cfg(not(target_os = "macos"))]
    let expected_error = "unsupported_capability";
    assert_eq!(output["error"]["code"], expected_error);
    assert!(!destination.exists());

    let listed = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(listed.status.code(), Some(0), "{listed:?}");
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed["result"]["jobs"], serde_json::json!([]));
}

#[cfg(target_os = "macos")]
#[test]
fn jobs_clear_removes_history_but_preserves_published_output() {
    let root = tempfile::tempdir().unwrap();
    let (source, destination, workspace) = write_source(&root);
    let configured_output = root.path().join("configured-output");
    let configured = command(&root)
        .args(["config", "set", "output_dir"])
        .arg(&configured_output)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(configured.status.code(), Some(0), "{configured:?}");
    let config_path_output = command(&root)
        .args(["config", "path", "--json"])
        .output()
        .unwrap();
    assert_eq!(
        config_path_output.status.code(),
        Some(0),
        "{config_path_output:?}"
    );
    let config_path_output: Value = serde_json::from_slice(&config_path_output.stdout).unwrap();
    let config_path = PathBuf::from(config_path_output["result"]["path"].as_str().unwrap());

    let key_source = root.path().join("complete.keys");
    let key_bytes = format!("header_key = {}\n", "00".repeat(32));
    fs::write(&key_source, &key_bytes).unwrap();
    let keys_set = command(&root)
        .arg("keys")
        .arg("set")
        .arg(&key_source)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(keys_set.status.code(), Some(0), "{keys_set:?}");
    let keys_set: Value = serde_json::from_slice(&keys_set.stdout).unwrap();
    let key_path = PathBuf::from(keys_set["result"]["path"].as_str().unwrap());

    let cache_path = root
        .path()
        .join("home")
        .join("Library")
        .join("Caches")
        .join("nscb")
        .join("providers")
        .join("cache.bin");
    fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
    fs::write(&cache_path, b"cache fixture survives clear").unwrap();
    let copied = copy_json(&root, &source, &destination, &workspace);
    assert!(copied["job_id"].is_string());
    assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());

    let modified = workspace.join("modified.bin");
    let foreign = workspace.join("foreign.bin");
    let displaced = workspace.join("displaced.bin");
    let unproven = workspace.join("unproven.bin");
    fs::write(&modified, b"locally modified artifact").unwrap();
    fs::write(&foreign, b"foreign artifact").unwrap();
    fs::write(&displaced, b"displaced artifact").unwrap();
    fs::write(&unproven, b"unproven artifact").unwrap();
    #[cfg(unix)]
    let symlink = workspace.join("symlink.bin");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&foreign, &symlink).unwrap();
    let config_bytes = fs::read(&config_path).unwrap();

    let cleared = command(&root)
        .args(["jobs", "clear", "--json"])
        .output()
        .unwrap();
    assert_eq!(cleared.status.code(), Some(0), "{cleared:?}");
    let cleared: Value = serde_json::from_slice(&cleared.stdout).unwrap();
    assert_eq!(cleared["kind"], "jobs.clear");
    assert_eq!(cleared["result"]["deleted"], 1);
    assert_eq!(fs::read(destination).unwrap(), fs::read(source).unwrap());
    assert_eq!(fs::read(&config_path).unwrap(), config_bytes);
    assert_eq!(fs::read_to_string(&key_path).unwrap(), key_bytes);
    assert_eq!(
        fs::read(&cache_path).unwrap(),
        b"cache fixture survives clear"
    );
    assert_eq!(fs::read(&modified).unwrap(), b"locally modified artifact");
    assert_eq!(fs::read(&foreign).unwrap(), b"foreign artifact");
    assert_eq!(fs::read(&displaced).unwrap(), b"displaced artifact");
    assert_eq!(fs::read(&unproven).unwrap(), b"unproven artifact");
    #[cfg(unix)]
    assert_eq!(fs::read_link(&symlink).unwrap(), foreign);

    let listed = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(listed.status.code(), Some(0), "{listed:?}");
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed["result"]["jobs"], serde_json::json!([]));
}

#[test]
fn missing_job_and_invalid_history_flags_use_typed_exit_classes() {
    let root = tempfile::tempdir().unwrap();
    let missing = command(&root)
        .args(["jobs", "show", "not-a-job", "--json"])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(3), "{missing:?}");
    let missing: Value = serde_json::from_slice(&missing.stdout).unwrap();
    assert_eq!(missing["kind"], "error");
    assert_eq!(missing["error"]["code"], "job_not_found");

    let invalid = command(&root)
        .args(["jobs", "list", "--unknown", "--json"])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2), "{invalid:?}");
    let invalid: Value = serde_json::from_slice(&invalid.stdout).unwrap();
    assert_eq!(invalid["error"]["code"], "usage_error");

    let human_missing = command(&root)
        .args(["jobs", "show", "not-a-job"])
        .output()
        .unwrap();
    assert_eq!(human_missing.status.code(), Some(3), "{human_missing:?}");
    assert!(human_missing.stdout.is_empty(), "{human_missing:?}");
    let human_error = String::from_utf8(human_missing.stderr).unwrap();
    assert_eq!(human_error, "The requested Job was not found in history.\n");
    assert!(!human_error.contains("job_not_found"), "{human_error}");
}

#[cfg(target_os = "macos")]
#[test]
fn retry_replans_implicit_destination_from_current_configuration() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source.bin");
    let first_directory = root.path().join("first-output");
    let second_directory = root.path().join("second-output");
    fs::write(&source, b"retry uses current output configuration").unwrap();

    let configured = command(&root)
        .args(["config", "set", "output_dir"])
        .arg(&first_directory)
        .output()
        .unwrap();
    assert_eq!(configured.status.code(), Some(0), "{configured:?}");
    let first = command(&root)
        .arg("copy")
        .arg(&source)
        .args(["--json"])
        .output()
        .unwrap();
    assert_eq!(first.status.code(), Some(0), "{first:?}");
    let first: Value = serde_json::from_slice(&first.stdout).unwrap();
    let first_id = first["job_id"].as_str().unwrap();
    let first_output = first_directory.join("source.bin");
    assert_eq!(fs::read(&first_output).unwrap(), fs::read(&source).unwrap());
    let first_shown = command(&root)
        .args(["jobs", "show", first_id, "--json"])
        .output()
        .unwrap();
    assert_eq!(first_shown.status.code(), Some(0), "{first_shown:?}");
    let first_shown: Value = serde_json::from_slice(&first_shown.stdout).unwrap();
    let first_job = &first_shown["result"]["job"];
    assert_eq!(first_job["destination_selection"], "configured_output_dir");
    assert_eq!(first_job["workspace_selection"], "host_default");
    assert_eq!(first_job["conflict_policy"], "fail");
    assert_eq!(first_job["conflict_policy_provenance"], "default");

    let reconfigured = command(&root)
        .args(["config", "set", "output_dir"])
        .arg(&second_directory)
        .output()
        .unwrap();
    assert_eq!(reconfigured.status.code(), Some(0), "{reconfigured:?}");
    let retried = command(&root)
        .args(["jobs", "retry", first_id, "--json"])
        .output()
        .unwrap();
    assert_eq!(retried.status.code(), Some(0), "{retried:?}");
    let retried: Value = serde_json::from_slice(&retried.stdout).unwrap();
    let second_id = retried["job_id"].as_str().unwrap();
    assert_ne!(second_id, first_id);
    let second_output = second_directory.join("source.bin");
    assert_eq!(
        fs::read(&second_output).unwrap(),
        fs::read(&source).unwrap()
    );
    assert_eq!(fs::read(&first_output).unwrap(), fs::read(&source).unwrap());

    let shown = command(&root)
        .args(["jobs", "show", second_id, "--json"])
        .output()
        .unwrap();
    assert_eq!(shown.status.code(), Some(0), "{shown:?}");
    let shown: Value = serde_json::from_slice(&shown.stdout).unwrap();
    let retry = &shown["result"]["job"];
    assert_eq!(retry["parent_job_id"], first_id);
    assert_eq!(retry["destination_selection"], "configured_output_dir");
    assert_eq!(retry["workspace_selection"], "host_default");
    assert_eq!(retry["conflict_policy"], "fail");
    assert_eq!(retry["parent_conflict_policy"], "fail");
    assert_eq!(retry["parent_conflict_policy_provenance"], "default");
    assert_eq!(retry["conflict_policy_provenance"], "retry_default");
}

#[cfg(target_os = "macos")]
#[test]
fn retry_anchors_relative_arguments_to_the_original_invocation_cwd() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("source.bin"), b"relative retry fixture").unwrap();
    let first = command(&root)
        .current_dir(root.path())
        .args([
            "copy",
            "source.bin",
            "destination.bin",
            "--workspace",
            "workspace",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(first.status.code(), Some(0), "{first:?}");
    let first: Value = serde_json::from_slice(&first.stdout).unwrap();
    let first_id = first["job_id"].as_str().unwrap();

    let unrelated_cwd = root.path().join("unrelated-cwd");
    fs::create_dir(&unrelated_cwd).unwrap();
    let retried = command(&root)
        .current_dir(&unrelated_cwd)
        .args(["jobs", "retry", first_id, "--json"])
        .output()
        .unwrap();
    assert_eq!(retried.status.code(), Some(0), "{retried:?}");
    let retried: Value = serde_json::from_slice(&retried.stdout).unwrap();
    let retry_id = retried["job_id"].as_str().unwrap();

    let original = command(&root)
        .args(["jobs", "show", first_id, "--json"])
        .output()
        .unwrap();
    assert_eq!(original.status.code(), Some(0), "{original:?}");
    let original: Value = serde_json::from_slice(&original.stdout).unwrap();
    assert_eq!(
        original["result"]["job"]["invocation_cwd"],
        root.path().canonicalize().unwrap().to_str().unwrap()
    );

    let shown = command(&root)
        .args(["jobs", "show", retry_id, "--json"])
        .output()
        .unwrap();
    assert_eq!(shown.status.code(), Some(0), "{shown:?}");
    let shown: Value = serde_json::from_slice(&shown.stdout).unwrap();
    let retry = &shown["result"]["job"];
    assert_eq!(
        retry["invocation_cwd"],
        unrelated_cwd.canonicalize().unwrap().to_str().unwrap()
    );
    let invocation_cwd = root.path().canonicalize().unwrap();
    assert_eq!(
        retry["source"],
        invocation_cwd.join("source.bin").to_str().unwrap()
    );
    assert_eq!(
        retry["destination"],
        invocation_cwd.join("destination.bin").to_str().unwrap()
    );
    assert_eq!(
        fs::read(root.path().join("destination.bin")).unwrap(),
        b"relative retry fixture"
    );
    assert!(root.path().join("workspace").exists());
    assert!(!unrelated_cwd.join("source.bin").exists());
}

#[cfg(target_os = "macos")]
#[test]
fn retry_rejects_future_job_kind_submission_and_scope_contracts() {
    for (column, value) in [
        ("kind", "future_job"),
        ("submission_kind", "independent_batch"),
        ("retry_scope", "failed_items"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let (source, destination, workspace) = write_source(&root);
        let first = copy_json(&root, &source, &destination, &workspace);
        let first_id = first["job_id"].as_str().unwrap();
        let connection = Connection::open(history_database(&root)).unwrap();
        connection
            .execute(
                &format!("UPDATE jobs SET {column} = ?1 WHERE job_id = ?2"),
                rusqlite::params![value, first_id],
            )
            .unwrap();
        drop(connection);

        let retried = command(&root)
            .args(["jobs", "retry", first_id, "--json"])
            .output()
            .unwrap();
        assert_eq!(retried.status.code(), Some(3), "{column}: {retried:?}");
        let retried: Value = serde_json::from_slice(&retried.stdout).unwrap();
        assert_eq!(retried["error"]["code"], "job_retry_ineligible");
        assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
        let listed = command(&root)
            .args(["jobs", "list", "--json"])
            .output()
            .unwrap();
        let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
        assert_eq!(listed["result"]["jobs"].as_array().unwrap().len(), 1);
    }
}

#[cfg(target_os = "macos")]
#[test]
fn retry_does_not_inherit_prior_replacement_without_explicit_reauthorization() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source.bin");
    let destination = root.path().join("destination.bin");
    let workspace = root.path().join("workspace");
    fs::write(&source, b"first replacement bytes").unwrap();
    fs::write(&destination, b"pre-existing destination").unwrap();
    let first = command(&root)
        .arg("copy")
        .arg(&source)
        .arg(&destination)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--replace")
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(first.status.code(), Some(0), "{first:?}");
    let first: Value = serde_json::from_slice(&first.stdout).unwrap();
    let first_id = first["job_id"].as_str().unwrap();
    let first_shown = command(&root)
        .args(["jobs", "show", first_id, "--json"])
        .output()
        .unwrap();
    assert_eq!(first_shown.status.code(), Some(0), "{first_shown:?}");
    let first_shown: Value = serde_json::from_slice(&first_shown.stdout).unwrap();
    let first_job = &first_shown["result"]["job"];
    assert_eq!(first_job["destination_selection"], "explicit");
    assert_eq!(first_job["workspace_selection"], "explicit");
    assert_eq!(first_job["conflict_policy"], "replace");
    assert_eq!(first_job["conflict_policy_provenance"], "cli_replace");
    fs::write(&source, b"different retry bytes").unwrap();

    let refused = command(&root)
        .args(["jobs", "retry", first_id, "--json"])
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(4), "{refused:?}");
    let refused: Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(refused["kind"], "job.result");
    assert_ne!(refused["job_id"], first_id);
    assert_eq!(refused["result"]["failure"]["code"], "destination_conflict");
    assert_eq!(fs::read(&destination).unwrap(), b"first replacement bytes");

    let replaced = command(&root)
        .args(["jobs", "retry", first_id, "--replace", "--json"])
        .output()
        .unwrap();
    assert_eq!(replaced.status.code(), Some(0), "{replaced:?}");
    let replaced: Value = serde_json::from_slice(&replaced.stdout).unwrap();
    let second_id = replaced["job_id"].as_str().unwrap();
    assert_ne!(second_id, first_id);
    assert_eq!(fs::read(&destination).unwrap(), b"different retry bytes");
    let shown = command(&root)
        .args(["jobs", "show", second_id, "--json"])
        .output()
        .unwrap();
    let shown: Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(shown["result"]["job"]["parent_job_id"], first_id);
    assert_eq!(shown["result"]["job"]["parent_conflict_policy"], "replace");
    assert_eq!(
        shown["result"]["job"]["parent_conflict_policy_provenance"],
        "cli_replace"
    );
    assert_eq!(shown["result"]["job"]["conflict_policy"], "replace");
    assert_eq!(
        shown["result"]["job"]["conflict_policy_provenance"],
        "retry_explicit_replace"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn failed_items_retry_is_rejected_without_creating_another_job() {
    let root = tempfile::tempdir().unwrap();
    let (source, destination, workspace) = write_source(&root);
    let copied = copy_json(&root, &source, &destination, &workspace);
    let job_id = copied["job_id"].as_str().unwrap();
    let before = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();

    let retry = command(&root)
        .args(["jobs", "retry", job_id, "--failed-items", "--json"])
        .output()
        .unwrap();
    assert_eq!(retry.status.code(), Some(3), "{retry:?}");
    let retry: Value = serde_json::from_slice(&retry.stdout).unwrap();
    assert_eq!(retry["error"]["code"], "job_failed_items_unsupported");
    let after = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(before.stdout, after.stdout);
}

#[cfg(target_os = "macos")]
#[test]
fn concurrent_processes_create_distinct_durable_jobs_without_shared_outputs() {
    let root = tempfile::tempdir().unwrap();
    let first_source = root.path().join("first.bin");
    let first_destination = root.path().join("first-output.bin");
    let first_workspace = root.path().join("first-workspace");
    let second_source = root.path().join("second.bin");
    let second_destination = root.path().join("second-output.bin");
    let second_workspace = root.path().join("second-workspace");
    fs::write(&first_source, b"first concurrent source").unwrap();
    fs::write(&second_source, b"second concurrent source").unwrap();

    let first = command(&root)
        .arg("copy")
        .arg(&first_source)
        .arg(&first_destination)
        .arg("--workspace")
        .arg(&first_workspace)
        .arg("--json")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let second = command(&root)
        .arg("copy")
        .arg(&second_source)
        .arg(&second_destination)
        .arg("--workspace")
        .arg(&second_workspace)
        .arg("--json")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let first = first.wait_with_output().unwrap();
    let second = second.wait_with_output().unwrap();
    assert_eq!(first.status.code(), Some(0), "{first:?}");
    assert_eq!(second.status.code(), Some(0), "{second:?}");
    let first: Value = serde_json::from_slice(&first.stdout).unwrap();
    let second: Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_ne!(first["job_id"], second["job_id"]);
    assert_eq!(
        fs::read(&first_destination).unwrap(),
        fs::read(&first_source).unwrap()
    );
    assert_eq!(
        fs::read(&second_destination).unwrap(),
        fs::read(&second_source).unwrap()
    );

    let listed = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(listed.status.code(), Some(0), "{listed:?}");
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed["result"]["jobs"].as_array().unwrap().len(), 2);
}

#[cfg(target_os = "macos")]
#[test]
fn retry_planning_failure_preserves_the_original_job_and_output() {
    let root = tempfile::tempdir().unwrap();
    let (source, destination, workspace) = write_source(&root);
    let first = copy_json(&root, &source, &destination, &workspace);
    let first_id = first["job_id"].as_str().unwrap();
    fs::remove_file(&source).unwrap();

    let retry = command(&root)
        .args(["jobs", "retry", first_id, "--json"])
        .output()
        .unwrap();
    assert_eq!(retry.status.code(), Some(3), "{retry:?}");
    let retry: Value = serde_json::from_slice(&retry.stdout).unwrap();
    assert_eq!(retry["kind"], "error");
    assert_eq!(retry["error"]["code"], "source_unavailable");
    assert_eq!(
        fs::read(&destination).unwrap(),
        b"durable Job history source"
    );

    let listed = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(listed.status.code(), Some(0), "{listed:?}");
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed["result"]["jobs"].as_array().unwrap().len(), 1);
    assert_eq!(listed["result"]["jobs"][0]["job_id"], first_id);
}

#[cfg(target_os = "macos")]
#[test]
fn human_retry_configuration_failure_uses_stderr_not_a_machine_document() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source.bin");
    let output_directory = root.path().join("configured-output");
    fs::write(&source, b"retry configuration fixture").unwrap();
    let configured = command(&root)
        .args(["config", "set", "output_dir"])
        .arg(&output_directory)
        .output()
        .unwrap();
    assert_eq!(configured.status.code(), Some(0), "{configured:?}");
    let first = command(&root)
        .arg("copy")
        .arg(&source)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(first.status.code(), Some(0), "{first:?}");
    let first: Value = serde_json::from_slice(&first.stdout).unwrap();
    let first_id = first["job_id"].as_str().unwrap();
    fs::remove_dir_all(&output_directory).unwrap();
    fs::write(&output_directory, b"not a directory").unwrap();

    let retry = command(&root)
        .args(["jobs", "retry", first_id])
        .output()
        .unwrap();
    assert_eq!(retry.status.code(), Some(3), "{retry:?}");
    assert!(retry.stdout.is_empty(), "{retry:?}");
    let stderr = String::from_utf8_lossy(&retry.stderr);
    assert!(stderr.contains("output directory"), "{retry:?}");
}

#[cfg(target_os = "macos")]
#[test]
fn retry_reporting_failure_returns_exit_seven_after_durable_completion() {
    let root = tempfile::tempdir().unwrap();
    let (source, destination, workspace) = write_source(&root);
    let first = copy_json(&root, &source, &destination, &workspace);
    let first_id = first["job_id"].as_str().unwrap();

    for mode in ["--json", "--jsonl", "human"] {
        let mut descriptors = [0_i32; 2];
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { libc::close(descriptors[0]) }, 0);
        let mut retry = command(&root);
        retry.args(["jobs", "retry", first_id]);
        if mode != "human" {
            retry.arg(mode);
        }
        retry
            .stdout(unsafe { Stdio::from_raw_fd(descriptors[1]) })
            .stderr(Stdio::piped());
        let output = retry.output().unwrap();
        assert_eq!(output.status.code(), Some(7), "{mode}: {output:?}");
        assert!(output.stdout.is_empty(), "{mode}: {output:?}");
    }

    let listed = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(listed.status.code(), Some(0), "{listed:?}");
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    let jobs = listed["result"]["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 4);
    assert_eq!(
        jobs.iter()
            .filter(|job| job["parent_job_id"] == first_id)
            .count(),
        3
    );
    assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
}

#[cfg(target_os = "macos")]
#[test]
fn running_transition_failure_prevents_filesystem_mutation() {
    let root = tempfile::tempdir().unwrap();
    let (source, destination, workspace) = write_source(&root);
    let initialized = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(initialized.status.code(), Some(0), "{initialized:?}");

    let connection = Connection::open(history_database(&root)).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER reject_running_transition
             BEFORE UPDATE OF state ON jobs
             WHEN OLD.state = 'admitted' AND NEW.state = 'running'
             BEGIN SELECT RAISE(ABORT, 'injected running transition failure'); END;",
        )
        .unwrap();
    drop(connection);

    let output = command(&root)
        .arg("copy")
        .arg(&source)
        .arg(&destination)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    let output: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output["kind"], "error");
    assert_eq!(output["error"]["code"], "job_history_admission_failed");
    assert!(!destination.exists());
    assert_eq!(fs::read(&source).unwrap(), b"durable Job history source");

    let listed = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(listed.status.code(), Some(0), "{listed:?}");
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed["result"]["jobs"].as_array().unwrap().len(), 1);
    assert_eq!(listed["result"]["jobs"][0]["state"], "interrupted");
}

#[cfg(target_os = "macos")]
#[test]
fn completion_write_failure_is_reported_and_remains_recoverable() {
    let root = tempfile::tempdir().unwrap();
    let (source, destination, workspace) = write_source(&root);
    let initialized = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(initialized.status.code(), Some(0), "{initialized:?}");

    let connection = Connection::open(history_database(&root)).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER reject_terminal_completion
             BEFORE UPDATE OF state ON jobs
             WHEN NEW.state IN ('succeeded', 'failed', 'cancelled')
             BEGIN SELECT RAISE(ABORT, 'injected completion failure'); END;",
        )
        .unwrap();
    drop(connection);

    let output = command(&root)
        .arg("copy")
        .arg(&source)
        .arg(&destination)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    let terminal: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(terminal["kind"], "job.result");
    assert_eq!(terminal["history_error"], "job_history_completion_failed");
    assert_eq!(terminal["result"]["state"], "succeeded");
    let job_id = terminal["job_id"].as_str().unwrap();
    assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());

    let shown = command(&root)
        .args(["jobs", "show", job_id, "--json"])
        .output()
        .unwrap();
    assert_eq!(shown.status.code(), Some(0), "{shown:?}");
    let shown: Value = serde_json::from_slice(&shown.stdout).unwrap();
    let job = &shown["result"]["job"];
    assert_eq!(job["state"], "interrupted");
    assert_eq!(job["publication_state"], "unknown");
    assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
}

#[cfg(target_os = "macos")]
#[test]
fn jsonl_completion_write_failure_has_one_terminal_record_and_uncertain_history() {
    let root = tempfile::tempdir().unwrap();
    let (source, destination, workspace) = write_source(&root);
    let initialized = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(initialized.status.code(), Some(0), "{initialized:?}");

    let connection = Connection::open(history_database(&root)).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER reject_terminal_completion
             BEFORE UPDATE OF state ON jobs
             WHEN NEW.state IN ('succeeded', 'failed', 'cancelled')
             BEGIN SELECT RAISE(ABORT, 'injected completion failure'); END;",
        )
        .unwrap();
    drop(connection);

    let output = command(&root)
        .arg("copy")
        .arg(&source)
        .arg(&destination)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--jsonl")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    let documents = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    let terminals = documents
        .iter()
        .filter(|document| document["kind"] == "job.result")
        .collect::<Vec<_>>();
    assert_eq!(terminals.len(), 1, "{documents:?}");
    let terminal = terminals[0];
    assert_eq!(terminal["history_error"], "job_history_completion_failed");
    assert_eq!(terminal["result"]["state"], "succeeded");
    let job_id = terminal["job_id"].as_str().unwrap();
    assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());

    let shown = command(&root)
        .args(["jobs", "show", job_id, "--json"])
        .output()
        .unwrap();
    assert_eq!(shown.status.code(), Some(0), "{shown:?}");
    let shown: Value = serde_json::from_slice(&shown.stdout).unwrap();
    let job = &shown["result"]["job"];
    assert_eq!(job["state"], "interrupted");
    assert_eq!(job["publication_state"], "unknown");
    assert_eq!(fs::read(destination).unwrap(), fs::read(source).unwrap());
}

#[cfg(target_os = "macos")]
#[test]
fn live_owner_is_not_interrupted_and_killed_owner_is_recovered_once() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("large-source.bin");
    let destination = root.path().join("large-destination.bin");
    let workspace = root.path().join("workspace");
    let file = fs::File::create(&source).unwrap();
    file.set_len(64 * 1024 * 1024).unwrap();

    let mut child = command(&root)
        .arg("copy")
        .arg(&source)
        .arg(&destination)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--jsonl")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let first: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert_eq!(first["event"], "started");
    assert!(first.get("job_id").is_none());
    let listed = command(&root)
        .args(["jobs", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(listed.status.code(), Some(0), "{listed:?}");
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    let job_id = listed["result"]["jobs"][0]["job_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGSTOP) },
        0,
        "test failed to suspend the live owner"
    );

    let during = command(&root)
        .args(["jobs", "show", &job_id, "--json"])
        .output()
        .unwrap();
    assert_eq!(during.status.code(), Some(0), "{during:?}");
    let during: Value = serde_json::from_slice(&during.stdout).unwrap();
    assert_eq!(during["result"]["job"]["state"], "running");

    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGKILL) },
        0
    );
    child.wait().unwrap();
    let interrupted = command(&root)
        .args(["jobs", "show", &job_id, "--json"])
        .output()
        .unwrap();
    assert_eq!(interrupted.status.code(), Some(0), "{interrupted:?}");
    let interrupted_document: Value = serde_json::from_slice(&interrupted.stdout).unwrap();
    let job = &interrupted_document["result"]["job"];
    assert_eq!(job["state"], "interrupted");
    assert_eq!(job["failure_code"], "interrupted");
    assert_eq!(job["publication_state"], "unknown");
    assert_eq!(job["items"][0]["state"], "interrupted");
    assert_eq!(fs::read(&source).unwrap().len(), 64 * 1024 * 1024);
    let destination_after_kill = fs::read(&destination).ok();

    let again = command(&root)
        .args(["jobs", "show", &job_id, "--json"])
        .output()
        .unwrap();
    assert_eq!(again.stdout, interrupted.stdout);
    assert_eq!(fs::read(&destination).ok(), destination_after_kill);
}

#[cfg(target_os = "macos")]
#[test]
fn unavailable_history_fails_before_filesystem_mutation() {
    let root = tempfile::tempdir().unwrap();
    let (source, destination, workspace) = write_source(&root);
    let initialized = command(&root).args(["config", "path"]).output().unwrap();
    assert_eq!(initialized.status.code(), Some(0), "{initialized:?}");
    let history_path = root
        .path()
        .join("home")
        .join("Library")
        .join("Application Support")
        .join("NSCB")
        .join("jobs.sqlite3");
    fs::create_dir(&history_path).unwrap();

    let output = command(&root)
        .arg("copy")
        .arg(&source)
        .arg(&destination)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    let error: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(error["kind"], "error");
    assert!(matches!(
        error["error"]["code"].as_str(),
        Some("job_history_corrupt" | "job_history_unavailable")
    ));
    assert!(!destination.exists());
    assert_eq!(fs::read(source).unwrap(), b"durable Job history source");
}

#[cfg(target_os = "macos")]
#[test]
fn human_copy_non_utf8_path_returns_input_exit_without_copy() {
    use std::os::unix::ffi::OsStringExt;

    let root = tempfile::tempdir().unwrap();
    let (source, _, workspace) = write_source(&root);
    let destination = root.path().join(std::ffi::OsString::from_vec(
        b"destination-\xFF.bin".to_vec(),
    ));
    let initialized = command(&root).args(["config", "path"]).output().unwrap();
    assert_eq!(initialized.status.code(), Some(0), "{initialized:?}");

    let output = command(&root)
        .arg("copy")
        .arg(&source)
        .arg(&destination)
        .arg("--workspace")
        .arg(&workspace)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(!destination.exists());
    assert_eq!(fs::read(source).unwrap(), b"durable Job history source");
}

#[cfg(target_os = "macos")]
#[test]
fn human_copy_history_failure_uses_localized_text_without_a_code() {
    let root = tempfile::tempdir().unwrap();
    let (source, destination, workspace) = write_source(&root);
    let initialized = command(&root).args(["config", "path"]).output().unwrap();
    assert_eq!(initialized.status.code(), Some(0), "{initialized:?}");
    fs::create_dir(history_database(&root)).unwrap();

    let output = command(&root)
        .arg("copy")
        .arg(&source)
        .arg(&destination)
        .arg("--workspace")
        .arg(&workspace)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        stderr,
        "The standalone Job history could not be updated. The reported operation result and filesystem evidence remain unchanged; inspect them before retrying.\n"
    );
    assert!(!stderr.contains("job_history_"), "{stderr}");
    assert!(!destination.exists());
    assert_eq!(fs::read(source).unwrap(), b"durable Job history source");
}
