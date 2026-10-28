use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TREE: AtomicU64 = AtomicU64::new(1);

struct TempTree(PathBuf);

impl TempTree {
    fn new() -> Self {
        let id = NEXT_TREE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "nscb-input-resolution-cli-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str], cwd: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_nscb"))
        .args(args)
        .current_dir(cwd)
        .env("HOME", cwd.join("test-home"))
        .env("USERPROFILE", cwd.join("test-home"))
        .env(
            "APPDATA",
            cwd.join("test-home").join("AppData").join("Roaming"),
        )
        .env(
            "LOCALAPPDATA",
            cwd.join("test-home").join("AppData").join("Local"),
        )
        .env("XDG_CONFIG_HOME", cwd.join("test-config"))
        .env("XDG_CACHE_HOME", cwd.join("test-cache"))
        .output()
        .expect("run nscb executable")
}

#[test]
fn resolve_json_emits_ordered_segments_and_selection_provenance() {
    let tree = TempTree::new();
    tree.write("one.anything", b"one");
    tree.write("batch/.hidden.nsp", b"hidden");
    tree.write("batch/a.nsz", b"a");
    tree.write("batch/ignore.txt", b"ignore");

    let output = run(&["resolve", "--json", "one.anything", "batch"], &tree.0);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["kind"], "input_resolution.result");
    let inputs = document["result"]["inputs"].as_array().unwrap();
    assert_eq!(inputs.len(), 3);
    assert_eq!(inputs[0]["segments"].as_array().unwrap().len(), 1);
    assert_eq!(inputs[0]["segments"][0]["size_bytes"], 3);
    assert_eq!(inputs[0]["provenance"]["selection_index"], 0);
    assert_eq!(inputs[1]["provenance"]["selection_index"], 1);
    assert_eq!(inputs[2]["provenance"]["selection_index"], 1);
    assert!(
        inputs[0]["provenance"]
            .get("input_list_entry_index")
            .is_none()
    );
    assert!(String::from_utf8(output.stdout).unwrap().ends_with('\n'));
}

#[test]
fn duplicate_logical_selections_are_input_errors_with_exit_three() {
    let tree = TempTree::new();
    tree.write("item.bin", b"item");

    let output = run(&["resolve", "--json", "item.bin", "./item.bin"], &tree.0);

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["kind"], "error");
    assert_eq!(document["error"]["code"], "duplicate_selection");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("item.bin"));
}

#[test]
fn split_parts_and_empty_lists_fail_as_input_errors() {
    let tree = TempTree::new();
    tree.write("game.xc0", b"split");
    tree.write(
        "empty.json",
        br#"{"schema_version":1,"kind":"nscb.input_list","required_features":[],"entries":[]}"#,
    );

    let split = run(&["resolve", "--json", "game.xc0"], &tree.0);
    assert_eq!(split.status.code(), Some(3));
    assert_eq!(
        serde_json::from_slice::<Value>(&split.stdout).unwrap()["error"]["code"],
        "unsupported_split_layout"
    );

    let empty = run(
        &["resolve", "--json", "--input-list", "empty.json"],
        &tree.0,
    );
    assert_eq!(empty.status.code(), Some(3));
    assert_eq!(
        serde_json::from_slice::<Value>(&empty.stdout).unwrap()["error"]["code"],
        "empty_selection"
    );
}

#[test]
fn input_list_arguments_resolve_from_cwd_and_keep_argument_order() {
    let tree = TempTree::new();
    tree.write("direct.bin", b"d");
    tree.write("lists/listed.bin", b"l");
    tree.write(
        "lists/selection.json",
        br#"{"schema_version":1,"kind":"nscb.input_list","required_features":[],"entries":[{"path":"listed.bin"}]}"#,
    );
    tree.write("last.bin", b"x");

    let output = run(
        &[
            "resolve",
            "--json",
            "direct.bin",
            "--input-list",
            "lists/selection.json",
            "last.bin",
        ],
        &tree.0,
    );

    assert_eq!(output.status.code(), Some(0));
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    let inputs = document["result"]["inputs"].as_array().unwrap();
    let names: Vec<_> = inputs
        .iter()
        .map(|input| {
            PathBuf::from(input["segments"][0]["path"].as_str().unwrap())
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(names, ["direct.bin", "listed.bin", "last.bin"]);
    assert_eq!(inputs[1]["provenance"]["source"], "input_list");
    assert_eq!(inputs[1]["provenance"]["input_list_entry_index"], 0);
}

#[test]
fn malformed_usage_keeps_exit_two_and_no_json_input_is_exit_three() {
    let tree = TempTree::new();
    let usage = run(&["resolve", "--json", "--input-list"], &tree.0);
    assert_eq!(usage.status.code(), Some(2));
    let usage_document: Value = serde_json::from_slice(&usage.stdout).unwrap();
    assert_eq!(usage_document["error"]["code"], "usage_error");

    let option_operand = run(
        &["resolve", "--json", "--input-list", "--recursive"],
        &tree.0,
    );
    assert_eq!(option_operand.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&option_operand.stdout).unwrap()["error"]["code"],
        "usage_error"
    );

    let empty = run(&["resolve", "--json"], &tree.0);
    assert_eq!(empty.status.code(), Some(3));
    assert_eq!(
        serde_json::from_slice::<Value>(&empty.stdout).unwrap()["error"]["code"],
        "empty_selection"
    );
}

#[test]
fn recursive_switch_controls_nested_cli_discovery() {
    let tree = TempTree::new();
    tree.write("batch/root.nsp", b"r");
    tree.write("batch/nested/child.nsp", b"c");

    let shallow = run(&["resolve", "--json", "batch"], &tree.0);
    let recursive = run(&["resolve", "--json", "--recursive", "batch"], &tree.0);
    assert_eq!(shallow.status.code(), Some(0));
    assert_eq!(recursive.status.code(), Some(0));
    assert_eq!(
        serde_json::from_slice::<Value>(&shallow.stdout).unwrap()["result"]["inputs"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&recursive.stdout).unwrap()["result"]["inputs"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[cfg(unix)]
#[test]
fn follow_symlinks_switch_is_explicit_in_the_cli() {
    use std::os::unix::fs::symlink;

    let tree = TempTree::new();
    tree.write("real.nsp", b"r");
    symlink("real.nsp", tree.0.join("alias.nsp")).unwrap();

    let default = run(&["resolve", "--json", "."], &tree.0);
    let followed = run(&["resolve", "--json", "--follow-symlinks", "."], &tree.0);
    assert_eq!(default.status.code(), Some(0));
    assert_eq!(followed.status.code(), Some(3));
    assert_eq!(
        serde_json::from_slice::<Value>(&followed.stdout).unwrap()["error"]["code"],
        "duplicate_selection"
    );
}
