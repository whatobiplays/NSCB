use nscb::{Engine, InputResolutionErrorCode, InputResolutionRequest, InputSelectionSource};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TREE: AtomicU64 = AtomicU64::new(1);

struct TempTree(PathBuf);

impl TempTree {
    fn new() -> Self {
        let id = NEXT_TREE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("nscb-input-resolution-{}-{id}", std::process::id()));
        fs::create_dir_all(&path).expect("create temporary tree");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(relative);
        fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture parent");
        fs::write(&path, bytes).expect("write fixture");
        path
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn request(tree: &TempTree) -> InputResolutionRequest {
    InputResolutionRequest::new(tree.path().to_path_buf())
}

fn resolve(request: InputResolutionRequest) -> nscb::InputResolutionResult {
    Engine::new()
        .resolve_inputs(request)
        .expect("resolve input selection")
}

#[test]
fn explicit_regular_files_ignore_extensions_and_keep_segment_provenance() {
    let tree = TempTree::new();
    let path = tree.write("input.unrecognized", b"opaque bytes");

    let result = resolve(request(&tree).with_path("input.unrecognized"));

    assert_eq!(result.inputs.len(), 1);
    let input = &result.inputs[0];
    assert_eq!(input.segments.len(), 1);
    assert_eq!(input.segments[0].path, fs::canonicalize(path).unwrap());
    assert_eq!(input.segments[0].size, 12);
    assert_eq!(
        fs::read(&input.segments[0].path).unwrap(),
        b"opaque bytes",
        "resolution must leave source bytes unchanged"
    );
    assert_eq!(input.provenance.selection_index, 0);
    assert_eq!(input.provenance.source, InputSelectionSource::Path);
    assert_eq!(
        input.provenance.selection_path,
        PathBuf::from("input.unrecognized")
    );
}

#[test]
fn explicit_selections_keep_caller_order_while_directories_sort_hidden_candidates() {
    let tree = TempTree::new();
    tree.write("first.bin", b"first");
    tree.write("batch/z.nsp", b"z");
    tree.write("batch/A.XCI", b"a");
    tree.write("batch/.hidden.NSZ", b"hidden");
    tree.write("batch/ignore.txt", b"ignore");
    tree.write("last.data", b"last");

    let result = resolve(
        request(&tree)
            .with_path("first.bin")
            .with_path("batch")
            .with_path("last.data"),
    );

    let names: Vec<_> = result
        .inputs
        .iter()
        .map(|input| {
            input.segments[0]
                .path
                .file_name()
                .unwrap()
                .to_string_lossy()
        })
        .collect();
    assert_eq!(
        names,
        ["first.bin", ".hidden.NSZ", "A.XCI", "z.nsp", "last.data"]
    );
    assert_eq!(
        result
            .inputs
            .iter()
            .map(|input| input.provenance.selection_index)
            .collect::<Vec<_>>(),
        [0, 1, 1, 1, 2]
    );
}

#[test]
fn input_lists_resolve_entries_from_the_list_parent_and_keep_entry_order() {
    let tree = TempTree::new();
    tree.write("items/first.any", b"1");
    tree.write("items/second.any", b"22");
    tree.write(
        "lists/selection.json",
        br#"{
            "schema_version": 1,
            "kind": "nscb.input_list",
            "required_features": [],
            "optional": {"future": true},
            "entries": [
                {"path": "../items/second.any", "label": "second"},
                {"path": "../items/first.any"}
            ]
        }"#,
    );

    let result = resolve(request(&tree).with_input_list("lists/selection.json"));

    let names: Vec<_> = result
        .inputs
        .iter()
        .map(|input| {
            input.segments[0]
                .path
                .file_name()
                .unwrap()
                .to_string_lossy()
        })
        .collect();
    assert_eq!(names, ["second.any", "first.any"]);
    assert!(result.inputs.iter().all(|input| {
        input.provenance.source == InputSelectionSource::InputList
            && input.provenance.selection_index == 0
            && input.provenance.input_list_entry_index.is_some()
    }));
    assert_eq!(result.inputs[0].provenance.input_list_entry_index, Some(0));
}

#[test]
fn input_list_relative_paths_use_the_list_file_location_not_the_process_directory() {
    let tree = TempTree::new();
    tree.write("lists/deep/entry.bin", b"list base");
    tree.write(
        "lists/deep/list.json",
        br#"{"schema_version":1,"kind":"nscb.input_list","required_features":[],"entries":[{"path":"entry.bin"}]}"#,
    );

    let result = resolve(request(&tree).with_input_list("lists/deep/list.json"));

    assert_eq!(result.inputs.len(), 1);
    assert_eq!(result.inputs[0].segments[0].size, 9);
    assert_eq!(
        result.inputs[0].segments[0].path,
        fs::canonicalize(tree.path().join("lists/deep/entry.bin")).unwrap()
    );
}

#[test]
fn duplicate_object_keys_are_rejected_at_every_json_depth() {
    let tree = TempTree::new();
    for (name, json) in [
        (
            "top.json",
            br#"{"schema_version":1,"kind":"nscb.input_list","kind":"nscb.input_list","required_features":[],"entries":[{"path":"a.bin"}]}"#.as_slice(),
        ),
        (
            "entry.json",
            br#"{"schema_version":1,"kind":"nscb.input_list","required_features":[],"entries":[{"path":"a.bin","path":"b.bin"}]}"#.as_slice(),
        ),
        (
            "unknown.json",
            br#"{"schema_version":1,"kind":"nscb.input_list","required_features":[],"entries":[{"path":"a.bin"}],"future":{"key":1,"key":2}}"#.as_slice(),
        ),
    ] {
        tree.write(name, json);
        let error = Engine::new()
            .resolve_inputs(request(&tree).with_input_list(name))
            .expect_err("duplicate JSON object keys must fail closed");
        assert_eq!(error.code(), InputResolutionErrorCode::InvalidInputList);
    }
}

#[test]
fn input_lists_validate_version_kind_features_and_entry_shapes() {
    let tree = TempTree::new();
    let cases: &[(&str, &[u8], InputResolutionErrorCode)] = &[
        (
            "version.json",
            br#"{"schema_version":2,"kind":"nscb.input_list","required_features":[],"entries":[]}"#,
            InputResolutionErrorCode::UnsupportedInputListVersion,
        ),
        (
            "kind.json",
            br#"{"schema_version":1,"kind":"future.list","required_features":[],"entries":[]}"#,
            InputResolutionErrorCode::InvalidInputList,
        ),
        (
            "feature.json",
            br#"{"schema_version":1,"kind":"nscb.input_list","required_features":["future-feature"],"entries":[]}"#,
            InputResolutionErrorCode::UnsupportedRequiredFeature,
        ),
        (
            "missing_features.json",
            br#"{"schema_version":1,"kind":"nscb.input_list","entries":[]}"#,
            InputResolutionErrorCode::InvalidInputList,
        ),
        (
            "bad_entry.json",
            br#"{"schema_version":1,"kind":"nscb.input_list","required_features":[],"entries":[{"path":7}]}"#,
            InputResolutionErrorCode::InvalidInputList,
        ),
    ];

    for (name, json, expected) in cases {
        tree.write(name, json);
        let error = Engine::new()
            .resolve_inputs(request(&tree).with_input_list(name))
            .expect_err("invalid v1 schema must not be guessed");
        assert_eq!(error.code(), *expected, "{name}");
    }
}

#[test]
fn empty_requests_empty_directories_and_empty_lists_are_typed_failures() {
    let tree = TempTree::new();
    fs::create_dir(tree.path().join("empty")).unwrap();
    tree.write(
        "empty.json",
        br#"{"schema_version":1,"kind":"nscb.input_list","required_features":[],"entries":[]}"#,
    );

    for request in [
        request(&tree),
        request(&tree).with_path("empty"),
        request(&tree).with_input_list("empty.json"),
    ] {
        let error = Engine::new()
            .resolve_inputs(request)
            .expect_err("empty selections must not return success");
        assert_eq!(error.code(), InputResolutionErrorCode::EmptySelection);
    }
}

#[test]
fn duplicate_paths_and_hardlinks_are_reported_as_input_failures() {
    let tree = TempTree::new();
    let original = tree.write("item.bin", b"same bytes");
    fs::create_dir(tree.path().join("sub")).unwrap();

    let error = Engine::new()
        .resolve_inputs(
            request(&tree)
                .with_path("item.bin")
                .with_path("sub/../item.bin"),
        )
        .expect_err("path aliases must not produce duplicate logical inputs");
    assert_eq!(error.code(), InputResolutionErrorCode::DuplicateSelection);

    #[cfg(unix)]
    {
        fs::hard_link(&original, tree.path().join("hardlink.bin")).unwrap();
        let error = Engine::new()
            .resolve_inputs(
                request(&tree)
                    .with_path("item.bin")
                    .with_path("hardlink.bin"),
            )
            .expect_err("hard links share filesystem identity");
        assert_eq!(error.code(), InputResolutionErrorCode::DuplicateSelection);
    }
}

#[test]
fn normalized_case_and_unicode_aliases_are_duplicate_selections() {
    let tree = TempTree::new();
    tree.write("Upper.bin", b"upper");
    tree.write("upper.bin", b"lower");
    let error = Engine::new()
        .resolve_inputs(request(&tree).with_path("Upper.bin").with_path("upper.bin"))
        .expect_err("case-normalized paths must not be selected twice");
    assert_eq!(error.code(), InputResolutionErrorCode::DuplicateSelection);

    tree.write("Café.bin", b"composed");
    tree.write("Cafe\u{301}.bin", b"decomposed");
    let error = Engine::new()
        .resolve_inputs(
            request(&tree)
                .with_path("Café.bin")
                .with_path("Cafe\u{301}.bin"),
        )
        .expect_err("canonically equivalent Unicode paths must not be selected twice");
    assert_eq!(error.code(), InputResolutionErrorCode::DuplicateSelection);
}

#[test]
fn suspected_split_parts_fail_before_standalone_or_extension_handling() {
    let tree = TempTree::new();
    for name in [
        "game.xc0",
        "game.xc1",
        "game.ns0",
        "game.ns12",
        "game.00",
        "game.nsp.00",
        "00",
    ] {
        tree.write(name, b"segment");
        let error = Engine::new()
            .resolve_inputs(request(&tree).with_path(name))
            .expect_err("suspected Split segments are not standalone inputs");
        assert_eq!(
            error.code(),
            InputResolutionErrorCode::UnsupportedSplitLayout,
            "{name}"
        );
    }

    tree.write("dir/segment.xc0", b"segment");
    tree.write("dir/candidate.nsp", b"candidate");
    let error = Engine::new()
        .resolve_inputs(request(&tree).with_path("dir"))
        .expect_err("directory discovery must inspect Split patterns before filtering");
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::UnsupportedSplitLayout
    );

    tree.write("numbered/00", b"first");
    tree.write("numbered/01", b"second");
    let error = Engine::new()
        .resolve_inputs(request(&tree).with_path("numbered"))
        .expect_err("canonical numbered layouts remain unsupported");
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::UnsupportedSplitLayout
    );
}

#[test]
fn numeric_directory_names_are_not_treated_as_split_files() {
    let selected_tree = TempTree::new();
    selected_tree.write("collection.00/game.nsp", b"game");

    let selected = resolve(request(&selected_tree).with_path("collection.00"));
    assert_eq!(selected.inputs.len(), 1);

    let discovery_tree = TempTree::new();
    discovery_tree.write("root.nsp", b"root");
    discovery_tree.write("unvisited.01/child.nsp", b"child");

    let shallow = resolve(request(&discovery_tree).with_path("."));
    assert_eq!(shallow.inputs.len(), 1);
    assert_eq!(
        shallow.inputs[0].segments[0].path.file_name().unwrap(),
        "root.nsp"
    );

    let recursive = resolve(request(&discovery_tree).with_path(".").with_recursive(true));
    assert_eq!(recursive.inputs.len(), 2);
}

#[test]
fn recursive_discovery_is_opt_in_and_candidates_are_sorted_by_relative_path() {
    let tree = TempTree::new();
    tree.write("batch/root.nsp", b"root");
    tree.write("batch/nested/child.nsp", b"child");

    let shallow = resolve(request(&tree).with_path("batch"));
    assert_eq!(shallow.inputs.len(), 1);
    assert_eq!(
        shallow.inputs[0].segments[0].path.file_name().unwrap(),
        "root.nsp"
    );

    let recursive = resolve(request(&tree).with_path("batch").with_recursive(true));
    let names: Vec<_> = recursive
        .inputs
        .iter()
        .map(|input| {
            input.segments[0]
                .path
                .file_name()
                .unwrap()
                .to_string_lossy()
        })
        .collect();
    assert_eq!(names, ["child.nsp", "root.nsp"]);
}

#[cfg(unix)]
#[test]
fn symlink_directory_traversal_requires_opt_in_and_checks_escape_and_cycles() {
    use std::os::unix::fs::symlink;

    let tree = TempTree::new();
    tree.write("real/input.nsp", b"input");
    symlink(tree.path().join("real"), tree.path().join("alias")).unwrap();

    let error = Engine::new()
        .resolve_inputs(request(&tree).with_path("alias"))
        .expect_err("a selected directory symlink needs explicit opt-in");
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::UnsupportedFilesystemEntry
    );

    let followed = resolve(request(&tree).with_path("alias").with_follow_symlinks(true));
    assert_eq!(followed.inputs.len(), 1);
    assert_eq!(
        followed.inputs[0].segments[0].path.file_name().unwrap(),
        "input.nsp"
    );

    symlink(tree.path().join("real"), tree.path().join("real/back")).unwrap();
    let cycle = resolve(
        request(&tree)
            .with_path("real")
            .with_recursive(true)
            .with_follow_symlinks(true),
    );
    assert_eq!(
        cycle.inputs.len(),
        1,
        "a cycle back-edge is bounded and skipped"
    );

    let outside = TempTree::new();
    outside.write("outside.nsp", b"outside");
    symlink(outside.path(), tree.path().join("real/escape")).unwrap();
    let error = Engine::new()
        .resolve_inputs(
            request(&tree)
                .with_path("real")
                .with_recursive(true)
                .with_follow_symlinks(true),
        )
        .expect_err("symlink traversal may not escape the selected directory");
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::UnsupportedFilesystemEntry
    );
}

#[cfg(unix)]
#[test]
fn nonrecursive_discovery_ignores_irrelevant_symlinks_when_follow_is_enabled() {
    use std::os::unix::fs::symlink;

    let tree = TempTree::new();
    tree.write("root.nsp", b"root");
    let outside = TempTree::new();
    outside.write("external.nsp", b"external");
    symlink(outside.path(), tree.path().join("unused-directory")).unwrap();
    symlink("missing-target", tree.path().join("unused.txt")).unwrap();

    let resolved = resolve(request(&tree).with_path(".").with_follow_symlinks(true));

    assert_eq!(resolved.inputs.len(), 1);
    assert_eq!(
        resolved.inputs[0].segments[0].path.file_name().unwrap(),
        "root.nsp"
    );
}

#[test]
fn invalid_bases_and_missing_paths_are_typed_failures() {
    let tree = TempTree::new();
    let error = Engine::new()
        .resolve_inputs(InputResolutionRequest::new("relative-base").with_path("item.bin"))
        .expect_err("embedding callers must supply an absolute path base");
    assert_eq!(error.code(), InputResolutionErrorCode::InvalidBaseDirectory);

    let error = Engine::new()
        .resolve_inputs(request(&tree).with_path("missing.bin"))
        .expect_err("missing explicit paths must not disappear from successful results");
    assert_eq!(error.code(), InputResolutionErrorCode::InputUnavailable);
}

#[test]
fn input_list_documents_are_size_bounded() {
    let tree = TempTree::new();
    tree.write("oversized.json", &vec![b' '; 1_048_577]);

    let error = Engine::new()
        .resolve_inputs(request(&tree).with_input_list("oversized.json"))
        .expect_err("input-list allocation must have a fixed bound");
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::ResourceLimitExceeded
    );
}

#[test]
fn recursive_discovery_stops_at_its_depth_limit() {
    let tree = TempTree::new();
    let mut path = tree.path().join("deep");
    fs::create_dir(&path).unwrap();
    for _ in 0..65 {
        path.push("d");
        fs::create_dir(&path).unwrap();
    }
    fs::write(path.join("candidate.nsp"), b"content").unwrap();

    let error = Engine::new()
        .resolve_inputs(request(&tree).with_path("deep").with_recursive(true))
        .expect_err("recursive discovery must not exceed its fixed depth bound");
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::ResourceLimitExceeded
    );
}

#[cfg(unix)]
#[test]
fn special_files_are_never_opened_as_discovered_content() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let tree = TempTree::new();
    let fifo = tree.path().join("candidate.nsp");
    let nul_terminated = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: the path is a valid NUL-terminated byte string and the mode is bounded.
    let status = unsafe { libc::mkfifo(nul_terminated.as_ptr(), 0o600) };
    assert_eq!(status, 0);

    let error = Engine::new()
        .resolve_inputs(request(&tree).with_path("candidate.nsp"))
        .expect_err("a FIFO is not a regular file");
    assert_eq!(error.code(), InputResolutionErrorCode::InputUnavailable);

    let error = Engine::new()
        .resolve_inputs(request(&tree).with_path(".").with_recursive(true))
        .expect_err("a matching special entry must not be silently accepted");
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::UnsupportedFilesystemEntry
    );
}

#[cfg(unix)]
#[test]
fn followed_file_symlink_aliases_are_detected_as_duplicate_inputs() {
    use std::os::unix::fs::symlink;

    let tree = TempTree::new();
    tree.write("real.nsp", b"payload");
    symlink("real.nsp", tree.path().join("alias.nsp")).unwrap();

    let error = Engine::new()
        .resolve_inputs(request(&tree).with_path(".").with_follow_symlinks(true))
        .expect_err("a symlink and its target identify the same logical file");
    assert_eq!(error.code(), InputResolutionErrorCode::DuplicateSelection);
}

#[test]
fn directory_discovery_uses_only_the_documented_extensions() {
    let tree = TempTree::new();
    for extension in ["nsp", "nsz", "nsx", "xci", "xcz", "nca", "ncz"] {
        tree.write(&format!("candidates/input.{extension}"), b"x");
    }
    tree.write("candidates/input.zip", b"x");
    tree.write("candidates/input.nsp.bak", b"x");

    let result = resolve(request(&tree).with_path("candidates"));

    assert_eq!(result.inputs.len(), 7);
}

#[test]
fn aggregate_input_list_work_is_bounded_across_one_request() {
    let tree = TempTree::new();
    let mut request = request(&tree);
    for index in 0..5 {
        let name = format!("item-{index}.bin");
        tree.write(&name, b"x");
        let json = format!(
            "{{\"schema_version\":1,\"kind\":\"nscb.input_list\",\"required_features\":[],\"entries\":[{{\"path\":\"../{name}\"}}]}}"
        );
        let mut bytes = json.into_bytes();
        bytes.resize(900_000, b' ');
        tree.write(&format!("lists/list-{index}.json"), &bytes);
        request = request.with_input_list(format!("lists/list-{index}.json"));
    }

    let error = Engine::new()
        .resolve_inputs(request)
        .expect_err("several bounded lists must share an aggregate work limit");
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::ResourceLimitExceeded
    );
}

#[cfg(target_os = "linux")]
#[test]
fn non_unicode_split_suffix_fails_for_explicit_and_directory_discovery() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let direct = TempTree::new();
    let direct_name = OsString::from_vec(b"bad-\xff.xc0".to_vec());
    fs::write(direct.path().join(&direct_name), b"part").unwrap();
    let error = Engine::new()
        .resolve_inputs(request(&direct).with_path(PathBuf::from(direct_name)))
        .expect_err("explicit Split suffixes remain visible with invalid UTF-8 prefixes");
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::UnsupportedSplitLayout
    );

    let discovered = TempTree::new();
    let split_name = OsString::from_vec(b"bad-\xff.xc0".to_vec());
    fs::write(discovered.path().join(&split_name), b"part").unwrap();
    discovered.write("ordinary.nsp", b"candidate");
    let error = Engine::new()
        .resolve_inputs(request(&discovered).with_path("."))
        .expect_err("discovery checks suspect names before its extension filter");
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::UnsupportedSplitLayout
    );
}
