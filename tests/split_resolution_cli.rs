mod support;

use nscb::LocalSplitTrustStore;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use support::split_fixture::{SplitFixture, sidecar_path};

static NEXT_TREE: AtomicU64 = AtomicU64::new(1);

struct TempTree(PathBuf);

impl TempTree {
    fn new(label: &str) -> Self {
        let id = NEXT_TREE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "nscb-split-cli-{label}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn state(&self) -> PathBuf {
        self.0.join("state")
    }

    fn store(&self) -> LocalSplitTrustStore {
        LocalSplitTrustStore::new(self.state().join("split-trust"))
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str], cwd: &Path, state_directory: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_nscb"))
        .args(args)
        .current_dir(cwd)
        .env("NSCB_STATE_DIR", state_directory)
        .output()
        .expect("run nscb")
}

fn json_error(output: &std::process::Output) -> Value {
    assert!(
        output.stderr.is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("one JSON document")
}

fn source(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| ((index * 17 + 3) % 251) as u8)
        .collect()
}

#[test]
fn qualified_split_json_is_additive_and_keeps_schema_version_one() {
    let tree = TempTree::new("qualified");
    let fixture = SplitFixture::new(&source(3 * 1024 + 5), 1024);
    fixture.write(&tree.0, "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);

    let output = run(
        &["resolve", "--json", "Game.nsp/01"],
        &tree.0,
        &tree.state(),
    );
    assert_eq!(output.status.code(), Some(0));
    let document = json_error(&output);
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["kind"], "input_resolution.result");
    let input = &document["result"]["inputs"][0];
    assert_eq!(input["segments"].as_array().unwrap().len(), 4);
    assert_eq!(input["qualification"]["kind"], "local_split_receipt");
    assert_eq!(input["qualification"]["manifest_schema_version"], 1);
    assert_eq!(
        input["qualification"]["original_size_bytes"],
        fixture.source.len() as u64
    );
    assert_eq!(
        input["qualification"]["original_sha256"],
        fixture.source_sha256.to_hex()
    );
}

#[test]
fn ordinary_resolution_ignores_a_relative_state_directory() {
    let tree = TempTree::new("ordinary-relative");
    fs::write(tree.0.join("ordinary.bin"), b"ordinary").unwrap();
    let output = run(
        &["resolve", "--json", "ordinary.bin"],
        &tree.0,
        Path::new("relative"),
    );
    assert_eq!(output.status.code(), Some(0));
    let document = json_error(&output);
    assert!(document["result"]["inputs"][0]["qualification"].is_null());
}

#[test]
fn relative_state_directory_is_a_configuration_exit_for_split_inputs() {
    let tree = TempTree::new("relative");
    let fixture = SplitFixture::new(&source(2048), 1024);
    fixture.write(&tree.0, "Game.nsp");
    let output = run(
        &["resolve", "--json", "Game.nsp"],
        &tree.0,
        Path::new("relative"),
    );
    assert_eq!(output.status.code(), Some(2));
    let document = json_error(&output);
    assert_eq!(
        document["error"]["code"],
        "split_trust_store_configuration_invalid"
    );
}

#[test]
fn empty_state_directory_is_a_configuration_exit_for_split_inputs() {
    let tree = TempTree::new("empty");
    let fixture = SplitFixture::new(&source(2048), 1024);
    fixture.write(&tree.0, "Game.nsp");
    let output = run(&["resolve", "--json", "Game.nsp"], &tree.0, Path::new(""));
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        json_error(&output)["error"]["code"],
        "split_trust_store_configuration_invalid"
    );
}

#[test]
fn missing_state_is_an_empty_store_and_exits_untrusted() {
    let tree = TempTree::new("missing-state");
    let fixture = SplitFixture::new(&source(2048), 1024);
    fixture.write(&tree.0, "Game.nsp");
    let output = run(
        &["resolve", "--json", "Game.nsp"],
        &tree.0,
        &tree.state().join("absent"),
    );
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        json_error(&output)["error"]["code"],
        "split_evidence_untrusted"
    );
}

#[test]
fn corrupt_state_exits_internal_failure() {
    let tree = TempTree::new("corrupt-state");
    let fixture = SplitFixture::new(&source(2048), 1024);
    fixture.write(&tree.0, "Game.nsp");
    let receipts = tree.state().join("split-trust").join("receipts");
    fs::create_dir_all(&receipts).unwrap();
    fs::write(
        receipts.join(format!("{}.json", fixture.manifest_sha256.to_hex())),
        b"corrupt",
    )
    .unwrap();

    let output = run(&["resolve", "--json", "Game.nsp"], &tree.0, &tree.state());
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(
        json_error(&output)["error"]["code"],
        "split_state_unavailable"
    );
}

#[test]
fn file_at_state_root_is_a_corrupt_store_exit() {
    let tree = TempTree::new("file-state-root");
    let fixture = SplitFixture::new(&source(2048), 1024);
    fixture.write(&tree.0, "Game.nsp");
    fs::create_dir_all(tree.state()).unwrap();
    fs::write(tree.state().join("split-trust"), b"not a directory").unwrap();

    let output = run(&["resolve", "--json", "Game.nsp"], &tree.0, &tree.state());
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(
        json_error(&output)["error"]["code"],
        "split_state_unavailable"
    );
}

#[test]
fn missing_manifest_and_missing_member_remain_input_failures() {
    let tree = TempTree::new("missing");
    let fixture = SplitFixture::new(&source(2048), 1024);
    let directory = fixture.write(&tree.0, "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);

    fs::remove_file(sidecar_path(&directory)).unwrap();
    let output = run(&["resolve", "--json", "Game.nsp"], &tree.0, &tree.state());
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        json_error(&output)["error"]["code"],
        "split_manifest_missing"
    );

    fs::write(sidecar_path(&directory), &fixture.manifest).unwrap();
    fs::remove_file(directory.join("01")).unwrap();
    let output = run(&["resolve", "--json", "Game.nsp"], &tree.0, &tree.state());
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(json_error(&output)["error"]["code"], "split_set_incomplete");
}

#[test]
fn duplicate_member_and_directory_selection_is_an_input_failure() {
    let tree = TempTree::new("duplicate");
    let fixture = SplitFixture::new(&source(2048), 1024);
    fixture.write(&tree.0, "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);

    let output = run(
        &["resolve", "--json", "Game.nsp/00", "Game.nsp"],
        &tree.0,
        &tree.state(),
    );
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(json_error(&output)["error"]["code"], "duplicate_selection");
}

#[test]
fn human_output_still_describes_a_qualified_split_input() {
    let tree = TempTree::new("human");
    let fixture = SplitFixture::new(&source(2048), 1024);
    fixture.write(&tree.0, "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);

    let output = run(&["resolve", "Game.nsp"], &tree.0, &tree.state());
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Resolved 1 logical input(s) across 2 physical segment(s)."));
    assert!(output.stderr.is_empty());
}
