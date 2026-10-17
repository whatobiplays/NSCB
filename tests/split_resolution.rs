mod support;

use nscb::{
    Engine, InputResolutionCapabilities, InputResolutionControl, InputResolutionErrorCode,
    InputResolutionRequest, LocalSplitTrustStore, Sha256Digest, SplitQualificationKind,
    SplitTrustReceipt, SplitTrustRestore, SplitTrustStore, SplitTrustStoreError, SplitTrustWriter,
};
use std::fs;
use std::io::{Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use support::split_fixture::{SplitFixture, sidecar_path};

static NEXT_TREE: AtomicU64 = AtomicU64::new(1);

struct TempTree(PathBuf);

impl TempTree {
    fn new(label: &str) -> Self {
        let id = NEXT_TREE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "nscb-split-resolution-{label}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temporary tree");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn store(&self) -> LocalSplitTrustStore {
        LocalSplitTrustStore::new(self.0.join("state").join("split-trust"))
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

fn capabilities(store: &dyn SplitTrustStore) -> InputResolutionCapabilities<'_> {
    InputResolutionCapabilities::new().with_split_trust_store(store)
}

fn source(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| ((index * 31 + 7) % 251) as u8)
        .collect()
}

fn resolve(
    request: InputResolutionRequest,
    store: &dyn SplitTrustStore,
) -> Result<nscb::InputResolutionResult, nscb::InputResolutionError> {
    Engine::new().resolve_inputs_with(request, capabilities(store))
}

#[test]
fn complete_multipart_set_qualifies_from_member_and_directory() {
    let tree = TempTree::new("multipart");
    let fixture = SplitFixture::new(&source(3 * 4096 + 17), 4096);
    let directory = fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);

    for selection in ["Game.nsp/00", "Game.nsp/01", "Game.nsp/02", "Game.nsp"] {
        let result = resolve(request(&tree).with_path(selection), &store).unwrap();
        assert_eq!(result.inputs.len(), 1, "selection {selection}");
        let input = &result.inputs[0];
        let canonical_directory = fs::canonicalize(&directory).unwrap();
        assert_eq!(input.segments.len(), fixture.parts.len());
        assert_eq!(
            input
                .segments
                .iter()
                .map(|segment| segment.path.clone())
                .collect::<Vec<_>>(),
            (0..fixture.parts.len())
                .map(|index| canonical_directory.join(format!("{index:02}")))
                .collect::<Vec<_>>()
        );
        let qualification = input.qualification.as_ref().expect("qualified Split input");
        assert_eq!(
            qualification.kind,
            SplitQualificationKind::LocalSplitReceipt
        );
        assert_eq!(qualification.manifest_schema_version, 1);
        assert_eq!(
            qualification.original_size_bytes,
            fixture.source.len() as u64
        );
        assert_eq!(qualification.original_sha256, fixture.source_sha256);
    }
}

#[test]
fn one_part_set_qualifies() {
    let tree = TempTree::new("single");
    let fixture = SplitFixture::new(&source(1024), 4096);
    fixture.write(tree.path(), "single.bin");
    let store = tree.store();
    fixture.issue(&store);

    let result = resolve(request(&tree).with_path("single.bin/00"), &store).unwrap();
    assert_eq!(result.inputs.len(), 1);
    assert_eq!(result.inputs[0].segments.len(), 1);
    assert!(result.inputs[0].qualification.is_some());
}

#[test]
fn split_member_through_an_input_list_qualifies() {
    let tree = TempTree::new("input-list");
    let fixture = SplitFixture::new(&source(2048), 1024);
    fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);
    fs::create_dir_all(tree.0.join("lists")).unwrap();
    fs::write(
        tree.0.join("lists").join("selection.json"),
        br#"{"schema_version":1,"kind":"nscb.input_list","required_features":[],"entries":[{"path":"../Game.nsp/01"}]}"#,
    )
    .unwrap();

    let result = resolve(
        request(&tree).with_input_list("lists/selection.json"),
        &store,
    )
    .unwrap();
    assert_eq!(result.inputs.len(), 1);
    assert!(result.inputs[0].qualification.is_some());
    assert_eq!(result.inputs[0].segments.len(), 2);
}

#[test]
fn resolver_never_issues_or_revokes_trust() {
    struct SpyStore {
        inner: LocalSplitTrustStore,
        lookups: AtomicUsize,
    }

    impl SplitTrustStore for SpyStore {
        fn lookup(
            &self,
            manifest: &nscb::Sha256Digest,
        ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
            self.lookups.fetch_add(1, Ordering::Relaxed);
            self.inner.lookup(manifest)
        }
    }

    let tree = TempTree::new("spy");
    let fixture = SplitFixture::new(&source(8192), 2048);
    fixture.write(tree.path(), "Game.nsp");
    let inner = tree.store();
    fixture.issue(&inner);
    let spy = SpyStore {
        inner,
        lookups: AtomicUsize::new(0),
    };

    resolve(request(&tree).with_path("Game.nsp"), &spy).unwrap();
    assert!(
        spy.lookups.load(Ordering::Relaxed) >= 2,
        "lookup before and after hashing"
    );
}

#[test]
fn missing_store_or_receipt_fails_untrusted() {
    let tree = TempTree::new("untrusted");
    let fixture = SplitFixture::new(&source(4096), 1024);
    fixture.write(tree.path(), "Game.nsp");

    let omitted = Engine::new()
        .resolve_inputs(request(&tree).with_path("Game.nsp"))
        .unwrap_err();
    assert_eq!(
        omitted.code(),
        InputResolutionErrorCode::SplitEvidenceUntrusted
    );

    let empty_store = tree.store();
    let missing = resolve(request(&tree).with_path("Game.nsp"), &empty_store).unwrap_err();
    assert_eq!(
        missing.code(),
        InputResolutionErrorCode::SplitEvidenceUntrusted
    );
}

#[test]
fn manifest_missing_is_distinct_from_untrusted() {
    let tree = TempTree::new("manifest-missing");
    let fixture = SplitFixture::new(&source(2048), 1024);
    let directory = fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);
    fs::remove_file(sidecar_path(&directory)).unwrap();

    let error = resolve(request(&tree).with_path("Game.nsp/00"), &store).unwrap_err();
    assert_eq!(error.code(), InputResolutionErrorCode::SplitManifestMissing);
}

#[test]
fn any_missing_member_is_incomplete() {
    let tree = TempTree::new("incomplete");
    let fixture = SplitFixture::new(&source(3 * 1024 + 3), 1024);
    let directory = fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);

    for missing in ["00", "01", "02"] {
        let path = directory.join(missing);
        fs::rename(&path, path.with_extension("missing")).unwrap();
        let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
        assert_eq!(
            error.code(),
            InputResolutionErrorCode::SplitSetIncomplete,
            "missing {missing}"
        );
        fs::rename(path.with_extension("missing"), path).unwrap();
    }
}

#[test]
fn competing_numbered_members_are_incomplete() {
    let tree = TempTree::new("competing");
    let fixture = SplitFixture::new(&source(2048), 1024);
    let directory = fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);

    fs::write(directory.join("03"), b"extra").unwrap();
    let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
    assert_eq!(error.code(), InputResolutionErrorCode::SplitSetIncomplete);
}

#[test]
fn numbered_member_replaced_by_a_directory_is_incomplete() {
    let tree = TempTree::new("member-directory");
    let fixture = SplitFixture::new(&source(2048), 1024);
    let directory = fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);

    fs::remove_file(directory.join("01")).unwrap();
    fs::create_dir(directory.join("01")).unwrap();
    let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
    assert_eq!(error.code(), InputResolutionErrorCode::SplitSetIncomplete);
}

#[test]
fn unrelated_metadata_is_ignored() {
    let tree = TempTree::new("metadata");
    let fixture = SplitFixture::new(&source(2048), 1024);
    let directory = fixture.write(tree.path(), "Game.nsp");
    fs::write(directory.join(".DS_Store"), b"metadata").unwrap();
    fs::write(directory.join("notes.txt"), b"notes").unwrap();
    let store = tree.store();
    fixture.issue(&store);

    let result = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap();
    assert_eq!(result.inputs.len(), 1);
    assert!(result.inputs[0].qualification.is_some());
}

#[test]
fn unrecognized_numeric_metadata_remains_fail_closed() {
    for (label, name) in [
        ("numeric-extension", "notes.2024"),
        ("numbered-content", "Game.1.nsp"),
    ] {
        let tree = TempTree::new(label);
        let fixture = SplitFixture::new(&source(2048), 1024);
        let directory = fixture.write(tree.path(), "Game.nsp");
        let store = tree.store();
        fixture.issue(&store);
        fs::write(directory.join(name), b"metadata").unwrap();

        let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
        assert_eq!(
            error.code(),
            InputResolutionErrorCode::SplitSetIncomplete,
            "unexpected error for {name}"
        );
    }
}

#[test]
fn same_size_part_mutation_is_an_integrity_mismatch() {
    let tree = TempTree::new("mutation");
    let fixture = SplitFixture::new(&source(4096), 1024);
    let directory = fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);

    let mut changed = fixture.parts[1].clone();
    changed[17] ^= 0xff;
    fs::write(directory.join("01"), changed).unwrap();
    let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::SplitIntegrityMismatch
    );
}

#[test]
fn sidecar_edit_invalidates_the_exact_byte_receipt() {
    let tree = TempTree::new("edited-manifest");
    let fixture = SplitFixture::new(&source(2048), 1024);
    let directory = fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);

    let path = sidecar_path(&directory);
    let mut edited = fixture.manifest.clone();
    edited.push(b'\n');
    fs::write(&path, edited).unwrap();
    let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::SplitEvidenceUntrusted
    );
}

#[test]
fn revocation_fails_closed_and_fresh_source_evidence_requalifies() {
    let tree = TempTree::new("revocation");
    let fixture = SplitFixture::new(&source(3 * 1024 + 9), 1024);
    fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);

    store.revoke(&fixture.manifest_sha256).unwrap();
    let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::SplitEvidenceUntrusted
    );

    fixture.requalify(&store);
    resolve(request(&tree).with_path("Game.nsp"), &store).unwrap();
}

#[test]
fn source_may_be_deleted_after_issuance() {
    let tree = TempTree::new("deleted-source");
    let source_path = tree.0.join("original.bin");
    let source_bytes = source(4096);
    fs::write(&source_path, &source_bytes).unwrap();
    let fixture = SplitFixture::new(&source_bytes, 1024);
    fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);
    fs::remove_file(&source_path).unwrap();

    for selection in ["Game.nsp/00", "Game.nsp"] {
        let result = resolve(request(&tree).with_path(selection), &store).unwrap();
        assert!(
            result.inputs[0].qualification.is_some(),
            "selection {selection}"
        );
    }
}

#[test]
fn moved_and_renamed_set_still_qualifies() {
    let tree = TempTree::new("relocation");
    let fixture = SplitFixture::new(&source(2048), 1024);
    let directory = fixture.write(tree.path(), "Before.nsp");
    let store = tree.store();
    fixture.issue(&store);

    let moved = tree.0.join("After.nsp");
    fs::rename(&directory, &moved).unwrap();
    fs::rename(sidecar_path(&directory), sidecar_path(&moved)).unwrap();
    let result = resolve(request(&tree).with_path("After.nsp"), &store).unwrap();
    assert!(result.inputs[0].qualification.is_some());
}

#[test]
fn two_segmentations_of_one_source_have_independent_revocations() {
    let tree = TempTree::new("segmentations");
    let original = source(4096);
    let first = SplitFixture::new(&original, 1024);
    let second = SplitFixture::new(&original, 2048);
    first.write(tree.path(), "First.nsp");
    second.write(tree.path(), "Second.nsp");
    let store = tree.store();
    first.issue(&store);
    second.issue(&store);

    store.revoke(&first.manifest_sha256).unwrap();
    let error = resolve(request(&tree).with_path("First.nsp"), &store).unwrap_err();
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::SplitEvidenceUntrusted
    );
    resolve(request(&tree).with_path("Second.nsp"), &store).unwrap();
}

#[test]
fn a_different_host_store_does_not_inherit_trust() {
    let tree = TempTree::new("cross-host");
    let fixture = SplitFixture::new(&source(2048), 1024);
    fixture.write(tree.path(), "Game.nsp");
    let issuing_store = tree.store();
    fixture.issue(&issuing_store);

    let other_host = LocalSplitTrustStore::new(tree.0.join("other-host").join("split-trust"));
    let error = resolve(request(&tree).with_path("Game.nsp"), &other_host).unwrap_err();
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::SplitEvidenceUntrusted
    );
}

#[test]
fn explicit_restoration_after_store_root_loss_preserves_qualification() {
    fn copy_tree(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    let tree = TempTree::new("state-backup");
    let fixture = SplitFixture::new(&source(2048), 1024);
    fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);
    let state = tree.0.join("state").join("split-trust");
    let backup = tree.0.join("backup").join("split-trust");
    copy_tree(&state, &backup);

    // Losing the store root while the continuity anchor survives is a state
    // failure, not silent untrusted input.
    fs::remove_dir_all(&state).unwrap();
    let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::SplitStateUnavailable
    );

    // The explicit restoration path merges the snapshot with the surviving
    // local anchor. Replacing the root by hand is not a restoration.
    let restore: SplitTrustRestore = store.restore_from_snapshot(&backup).unwrap();
    assert_eq!(restore.restored_entries, 1);
    resolve(request(&tree).with_path("Game.nsp"), &store).unwrap();

    // A raw copy of an old store root is rejected once the anchor advances.
    store
        .revoke(&fixture.manifest_sha256)
        .expect("revoke restored receipt");
    copy_tree(&backup, &state);
    let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::SplitStateUnavailable
    );
}

#[test]
fn duplicate_member_and_directory_selection_fails() {
    let tree = TempTree::new("duplicate");
    let fixture = SplitFixture::new(&source(2048), 1024);
    fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);

    let error = resolve(
        request(&tree)
            .with_path("Game.nsp/00")
            .with_path("Game.nsp"),
        &store,
    )
    .unwrap_err();
    assert_eq!(error.code(), InputResolutionErrorCode::DuplicateSelection);
}

#[test]
fn arbitrary_named_split_directory_is_discovered() {
    let tree = TempTree::new("discovery");
    let fixture = SplitFixture::new(&source(2048), 1024);
    fixture.write(&tree.0.join("backup"), "archive.zip");
    fs::write(tree.0.join("backup").join("ordinary.nsp"), b"ordinary").unwrap();
    let store = tree.store();
    fixture.issue(&store);

    let result = resolve(request(&tree).with_path("backup"), &store).unwrap();
    assert_eq!(result.inputs.len(), 2);
    assert_eq!(
        result
            .inputs
            .iter()
            .filter(|input| input.qualification.is_some())
            .count(),
        1
    );
}

#[test]
fn aggregate_split_byte_budget_is_enforced_across_inputs() {
    let tree = TempTree::new("budget");
    for (name, length) in [("first.nsp", 10), ("second.nsp", 11)] {
        let fixture = SplitFixture::new(&source(length), 5);
        fixture.write(tree.path(), name);
        fixture.issue(&tree.store());
    }
    let store = tree.store();

    let error = Engine::new()
        .resolve_inputs_with(
            request(&tree)
                .with_path("first.nsp")
                .with_path("second.nsp"),
            capabilities(&store).with_max_split_validation_bytes(15),
        )
        .unwrap_err();
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::ResourceLimitExceeded
    );
}

#[test]
fn pre_cancelled_control_stops_split_validation() {
    let tree = TempTree::new("cancel");
    let fixture = SplitFixture::new(&source(8192), 2048);
    fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);
    let control = InputResolutionControl::new();
    control.cancel();

    let error = Engine::new()
        .resolve_inputs_with(
            request(&tree).with_path("Game.nsp"),
            capabilities(&store).with_control(&control),
        )
        .unwrap_err();
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::SplitResolutionCancelled
    );
}

#[test]
fn cancellation_during_hashing_stops_without_success() {
    let tree = TempTree::new("cancel-during");
    let fixture = SplitFixture::new(&source(32 * 1024 * 1024), 1024 * 1024);
    fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);
    let control = Arc::new(InputResolutionControl::new());
    let watcher = {
        let control = Arc::clone(&control);
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if control.progress().completed_bytes > 0 {
                    control.cancel();
                    return;
                }
                std::thread::yield_now();
            }
        })
    };

    let error = Engine::new()
        .resolve_inputs_with(
            request(&tree).with_path("Game.nsp"),
            capabilities(&store).with_control(control.as_ref()),
        )
        .unwrap_err();
    watcher.join().unwrap();
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::SplitResolutionCancelled
    );
}

#[test]
fn member_mutation_during_hashing_fails_closed() {
    let tree = TempTree::new("mutation-during");
    let fixture = SplitFixture::new(&source(32 * 1024 * 1024), 8 * 1024 * 1024);
    let directory = fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);
    let first_part = directory.join("00");
    let control = Arc::new(InputResolutionControl::new());
    let watcher = {
        let control = Arc::clone(&control);
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if control.progress().completed_bytes > 0 {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .open(&first_part)
                        .unwrap();
                    file.seek(SeekFrom::Start(0)).unwrap();
                    file.write_all(b"changed").unwrap();
                    file.sync_all().unwrap();
                    return;
                }
                std::thread::yield_now();
            }
        })
    };

    let error = Engine::new()
        .resolve_inputs_with(
            request(&tree).with_path("Game.nsp"),
            capabilities(&store).with_control(control.as_ref()),
        )
        .unwrap_err();
    watcher.join().unwrap();
    assert!(
        matches!(
            error.code(),
            InputResolutionErrorCode::SplitIntegrityMismatch
                | InputResolutionErrorCode::SplitInputChanged
        ),
        "unexpected error: {:?}",
        error.code()
    );
}

#[test]
fn directory_replacement_during_hashing_fails_closed() {
    let tree = TempTree::new("directory-replacement-during");
    let fixture = SplitFixture::new(&source(32 * 1024 * 1024), 8 * 1024 * 1024);
    let directory = fixture.write(tree.path(), "Game.nsp");
    let replacement = fixture.write(&tree.path().join("replacement"), "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);

    let control = Arc::new(InputResolutionControl::new());
    let watcher = {
        let control = Arc::clone(&control);
        let tree_path = tree.path().to_path_buf();
        let directory = directory.clone();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if control.progress().completed_bytes > 0 {
                    fs::rename(&directory, tree_path.join("original.nsp")).unwrap();
                    fs::rename(&replacement, &directory).unwrap();
                    return;
                }
                std::thread::yield_now();
            }
        })
    };

    let error = Engine::new()
        .resolve_inputs_with(
            request(&tree).with_path("Game.nsp"),
            capabilities(&store).with_control(control.as_ref()),
        )
        .unwrap_err();
    watcher.join().unwrap();
    assert_eq!(error.code(), InputResolutionErrorCode::SplitInputChanged);
}

#[test]
fn sidecar_replacement_during_hashing_fails_closed() {
    let tree = TempTree::new("sidecar-replacement-during");
    let fixture = SplitFixture::new(&source(32 * 1024 * 1024), 8 * 1024 * 1024);
    let directory = fixture.write(tree.path(), "Game.nsp");
    let sidecar = sidecar_path(&directory);
    let staged = tree.path().join("staged-manifest.json");
    fs::write(&staged, &fixture.manifest).unwrap();
    let store = tree.store();
    fixture.issue(&store);

    let control = Arc::new(InputResolutionControl::new());
    let watcher = {
        let control = Arc::clone(&control);
        let tree_path = tree.path().to_path_buf();
        let sidecar = sidecar.clone();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if control.progress().completed_bytes > 0 {
                    fs::rename(&sidecar, tree_path.join("original-manifest.json")).unwrap();
                    fs::rename(&staged, &sidecar).unwrap();
                    return;
                }
                std::thread::yield_now();
            }
        })
    };

    let error = Engine::new()
        .resolve_inputs_with(
            request(&tree).with_path("Game.nsp"),
            capabilities(&store).with_control(control.as_ref()),
        )
        .unwrap_err();
    watcher.join().unwrap();
    assert_eq!(error.code(), InputResolutionErrorCode::SplitInputChanged);
}

#[test]
fn corrupt_store_is_a_state_failure() {
    let tree = TempTree::new("corrupt-store");
    let fixture = SplitFixture::new(&source(2048), 1024);
    fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    let receipts = tree.0.join("state").join("split-trust").join("receipts");
    fs::create_dir_all(&receipts).unwrap();
    fs::write(
        receipts.join(format!("{}.json", fixture.manifest_sha256.to_hex())),
        b"not a receipt",
    )
    .unwrap();

    let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::SplitStateUnavailable
    );
}

#[test]
fn ordinary_files_do_not_touch_a_corrupt_store() {
    let tree = TempTree::new("ordinary");
    fs::write(tree.0.join("ordinary.bin"), b"ordinary bytes").unwrap();
    fs::create_dir_all(tree.0.join("state").join("split-trust").join("receipts")).unwrap();
    fs::write(
        tree.0
            .join("state")
            .join("split-trust")
            .join("receipts")
            .join("junk.json"),
        b"corrupt",
    )
    .unwrap();
    let store = tree.store();

    let result = resolve(request(&tree).with_path("ordinary.bin"), &store).unwrap();
    assert_eq!(result.inputs.len(), 1);
    assert!(result.inputs[0].qualification.is_none());
}

#[test]
fn final_receipt_recheck_observes_a_revocation_during_hashing() {
    struct RevokingStore {
        inner: LocalSplitTrustStore,
        lookups: AtomicUsize,
    }

    impl SplitTrustStore for RevokingStore {
        fn lookup(
            &self,
            manifest: &nscb::Sha256Digest,
        ) -> Result<Option<SplitTrustReceipt>, SplitTrustStoreError> {
            let call = self.lookups.fetch_add(1, Ordering::SeqCst);
            let receipt = self.inner.lookup(manifest)?;
            if call == 0 {
                Ok(receipt)
            } else {
                Ok(receipt.map(|receipt| receipt.with_revoked(true)))
            }
        }
    }

    let tree = TempTree::new("revoke-during");
    let fixture = SplitFixture::new(&source(8192), 2048);
    fixture.write(tree.path(), "Game.nsp");
    let inner = tree.store();
    fixture.issue(&inner);
    let store = RevokingStore {
        inner,
        lookups: AtomicUsize::new(0),
    };

    let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::SplitEvidenceUntrusted
    );
    assert!(store.lookups.load(Ordering::SeqCst) >= 2);
}

#[test]
fn receipt_that_does_not_bind_source_evidence_is_untrusted() {
    let tree = TempTree::new("mismatched-receipt");
    let fixture = SplitFixture::new(&source(2048), 1024);
    fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    store
        .issue(SplitTrustReceipt::new(
            fixture.manifest_sha256,
            fixture.source.len() as u64 + 1,
            fixture.source_sha256,
        ))
        .unwrap();

    let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::SplitEvidenceUntrusted
    );
}

#[test]
fn whole_stream_digest_mismatch_is_an_integrity_failure() {
    let tree = TempTree::new("whole-digest");
    let fixture = SplitFixture::new(&source(3072), 1024);
    let directory = fixture.write(tree.path(), "Game.nsp");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fixture.manifest).unwrap();
    manifest["source"]["sha256"] = serde_json::Value::String("0".repeat(64));
    let manifest = serde_json::to_vec(&manifest).unwrap();
    fs::write(sidecar_path(&directory), &manifest).unwrap();
    let store = tree.store();
    store
        .issue(SplitTrustReceipt::new(
            nscb::Sha256Digest::digest(&manifest),
            fixture.source.len() as u64,
            nscb::Sha256Digest::from_bytes([0_u8; 32]),
        ))
        .unwrap();

    let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::SplitIntegrityMismatch
    );
}

#[test]
fn corrupt_store_root_is_a_state_failure() {
    let tree = TempTree::new("corrupt-root");
    let fixture = SplitFixture::new(&source(2048), 1024);
    fixture.write(tree.path(), "Game.nsp");
    fs::write(tree.0.join("state"), b"not a directory").unwrap();
    let store = tree.store();

    let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::SplitStateUnavailable
    );
}

#[test]
fn manifest_validation_is_strict_and_bounded() {
    let tree = TempTree::new("manifest-validation");
    let fixture = SplitFixture::new(&source(2048), 1024);
    let directory = fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();

    let zero = "0".repeat(64);
    let valid_segment = serde_json::json!({
        "name": "00",
        "size_bytes": 1,
        "sha256": zero,
    });
    let cases = vec![
        (
            serde_json::json!({
                "schema_version": 2,
                "kind": "nscb.split_manifest",
                "required_features": [],
                "source": {"size_bytes": 1, "sha256": zero},
                "segments": [valid_segment.clone()],
            }),
            InputResolutionErrorCode::SplitManifestVersionUnsupported,
        ),
        (
            serde_json::json!({
                "schema_version": 1,
                "kind": "other",
                "required_features": [],
                "source": {"size_bytes": 1, "sha256": zero},
                "segments": [valid_segment.clone()],
            }),
            InputResolutionErrorCode::SplitManifestInvalid,
        ),
        (
            serde_json::json!({
                "schema_version": 1,
                "kind": "nscb.split_manifest",
                "required_features": ["future"],
                "source": {"size_bytes": 1, "sha256": zero},
                "segments": [valid_segment.clone()],
            }),
            InputResolutionErrorCode::SplitManifestVersionUnsupported,
        ),
        (
            serde_json::json!({
                "schema_version": 1,
                "kind": "nscb.split_manifest",
                "required_features": [],
                "source": {"size_bytes": 2, "sha256": zero},
                "segments": [valid_segment.clone()],
            }),
            InputResolutionErrorCode::SplitManifestInvalid,
        ),
        (
            serde_json::json!({
                "schema_version": 1,
                "kind": "nscb.split_manifest",
                "required_features": [],
                "source": {"size_bytes": 1, "sha256": zero},
                "segments": [{"name": "01", "size_bytes": 1, "sha256": zero}],
            }),
            InputResolutionErrorCode::SplitManifestInvalid,
        ),
        (
            serde_json::json!({
                "schema_version": 1,
                "kind": "nscb.split_manifest",
                "required_features": [],
                "source": {"size_bytes": 1, "sha256": zero},
                "segments": [{"name": "00", "size_bytes": 0, "sha256": zero}],
            }),
            InputResolutionErrorCode::SplitManifestInvalid,
        ),
        (
            serde_json::json!({
                "schema_version": 1,
                "kind": "nscb.split_manifest",
                "required_features": [],
                "source": {"size_bytes": 1, "sha256": zero},
                "segments": [{
                    "name": "00",
                    "size_bytes": 1,
                    "sha256": "A".repeat(64),
                }],
            }),
            InputResolutionErrorCode::SplitManifestInvalid,
        ),
    ];

    for (manifest, code) in cases {
        let bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(sidecar_path(&directory), bytes).unwrap();
        let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
        assert_eq!(error.code(), code, "{manifest}");
    }

    let duplicate = format!(
        "{{\"schema_version\":1,\"schema_version\":1,\"kind\":\"nscb.split_manifest\",\"required_features\":[],\"source\":{{\"size_bytes\":1,\"sha256\":\"{zero}\"}},\"segments\":[{{\"name\":\"00\",\"size_bytes\":1,\"sha256\":\"{zero}\"}}]}}"
    );
    fs::write(sidecar_path(&directory), duplicate).unwrap();
    let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
    assert_eq!(error.code(), InputResolutionErrorCode::SplitManifestInvalid);
}

#[test]
fn zero_length_split_source_is_rejected_as_invalid() {
    let tree = TempTree::new("zero-length");
    let directory = tree.path().join("Empty.nsp");
    fs::create_dir(&directory).unwrap();
    let manifest = format!(
        "{{\"schema_version\":1,\"kind\":\"nscb.split_manifest\",\"required_features\":[],\"source\":{{\"size_bytes\":0,\"sha256\":\"{}\"}},\"segments\":[]}}",
        Sha256Digest::digest(b"").to_hex()
    );
    fs::write(sidecar_path(&directory), manifest).unwrap();

    let error = resolve(request(&tree).with_path("Empty.nsp"), &tree.store()).unwrap_err();
    assert_eq!(error.code(), InputResolutionErrorCode::SplitManifestInvalid);
}

#[test]
fn oversized_and_overlong_manifests_are_bounded() {
    let tree = TempTree::new("manifest-bounds");
    let fixture = SplitFixture::new(&source(1024), 1024);
    let directory = fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();

    fs::write(sidecar_path(&directory), vec![b' '; 262_145]).unwrap();
    let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
    assert_eq!(
        error.code(),
        InputResolutionErrorCode::ResourceLimitExceeded
    );

    let segments = (0..101)
        .map(|index| {
            serde_json::json!({
                "name": format!("{index:02}"),
                "size_bytes": 1,
                "sha256": "0".repeat(64),
            })
        })
        .collect::<Vec<_>>();
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "kind": "nscb.split_manifest",
        "required_features": [],
        "source": {"size_bytes": 101, "sha256": "0".repeat(64)},
        "segments": segments,
    }))
    .unwrap();
    fs::write(sidecar_path(&directory), manifest).unwrap();
    let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
    assert_eq!(error.code(), InputResolutionErrorCode::SplitManifestInvalid);
}

#[cfg(unix)]
#[test]
fn symlinked_members_are_rejected_without_opening_the_target() {
    let tree = TempTree::new("member-symlink");
    let fixture = SplitFixture::new(&source(2048), 1024);
    let directory = fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);
    fs::remove_file(directory.join("01")).unwrap();
    std::os::unix::fs::symlink(directory.join("00"), directory.join("01")).unwrap();

    let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
    assert_eq!(error.code(), InputResolutionErrorCode::SplitSetIncomplete);
}

#[cfg(unix)]
#[test]
fn symlinked_sidecar_is_rejected() {
    let tree = TempTree::new("sidecar-symlink");
    let fixture = SplitFixture::new(&source(2048), 1024);
    let directory = fixture.write(tree.path(), "Game.nsp");
    let sidecar = sidecar_path(&directory);
    let target = tree.path().join("manifest-target.json");
    fs::rename(&sidecar, &target).unwrap();
    std::os::unix::fs::symlink(&target, &sidecar).unwrap();

    let error = resolve(request(&tree).with_path("Game.nsp"), &tree.store()).unwrap_err();
    assert_eq!(error.code(), InputResolutionErrorCode::SplitManifestInvalid);
}

#[cfg(unix)]
#[test]
fn hardlinked_members_are_rejected_as_duplicate_identities() {
    let tree = TempTree::new("hardlink");
    let fixture = SplitFixture::new(&source(2048), 1024);
    let directory = fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);
    fs::remove_file(directory.join("01")).unwrap();
    fs::hard_link(directory.join("00"), directory.join("01")).unwrap();

    let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
    assert_eq!(error.code(), InputResolutionErrorCode::SplitSetIncomplete);
}

#[cfg(unix)]
#[test]
fn special_files_are_rejected() {
    let tree = TempTree::new("special");
    let fixture = SplitFixture::new(&source(2048), 1024);
    let directory = fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);
    fs::remove_file(directory.join("01")).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(directory.join("01")).unwrap();

    let error = resolve(request(&tree).with_path("Game.nsp"), &store).unwrap_err();
    assert_eq!(error.code(), InputResolutionErrorCode::SplitSetIncomplete);
    drop(listener);
}

#[cfg(unix)]
#[test]
fn absolute_member_above_a_symlinked_ancestor_requires_permission() {
    let tree = TempTree::new("absolute-symlink");
    let outside = TempTree::new("absolute-symlink-outside");
    let real = tree.path().join("real");
    let fixture = SplitFixture::new(&source(2048), 1024);
    fixture.write(&real, "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);
    std::os::unix::fs::symlink(&real, outside.path().join("alias")).unwrap();

    let selection = outside.path().join("alias").join("Game.nsp").join("00");
    let denied = resolve(request(&tree).with_path(selection.clone()), &store).unwrap_err();
    assert_eq!(
        denied.code(),
        InputResolutionErrorCode::UnsupportedFilesystemEntry
    );
    let allowed = resolve(
        request(&tree)
            .with_path(selection)
            .with_follow_symlinks(true),
        &store,
    )
    .unwrap();
    assert!(allowed.inputs[0].qualification.is_some());
}

#[cfg(unix)]
#[test]
fn explicit_directory_symlink_requires_traversal_permission() {
    let tree = TempTree::new("directory-symlink");
    let fixture = SplitFixture::new(&source(2048), 1024);
    let directory = fixture.write(tree.path(), "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);
    std::os::unix::fs::symlink(&directory, tree.0.join("alias.nsp")).unwrap();

    let denied = resolve(request(&tree).with_path("alias.nsp"), &store).unwrap_err();
    assert_eq!(
        denied.code(),
        InputResolutionErrorCode::UnsupportedFilesystemEntry
    );

    let allowed = resolve(
        request(&tree)
            .with_path("alias.nsp")
            .with_follow_symlinks(true),
        &store,
    )
    .unwrap();
    assert!(allowed.inputs[0].qualification.is_some());
}

#[cfg(unix)]
#[test]
fn intermediate_symlink_traversal_requires_permission() {
    let tree = TempTree::new("intermediate-symlink");
    let real = tree.path().join("real");
    let fixture = SplitFixture::new(&source(2048), 1024);
    fixture.write(&real, "Game.nsp");
    let store = tree.store();
    fixture.issue(&store);
    std::os::unix::fs::symlink(&real, tree.path().join("alias")).unwrap();

    for selection in ["alias/Game.nsp", "alias/Game.nsp/00"] {
        let denied = resolve(request(&tree).with_path(selection), &store).unwrap_err();
        assert_eq!(
            denied.code(),
            InputResolutionErrorCode::UnsupportedFilesystemEntry,
            "selection {selection}"
        );

        let allowed = resolve(
            request(&tree)
                .with_path(selection)
                .with_follow_symlinks(true),
            &store,
        )
        .unwrap();
        assert!(
            allowed.inputs[0].qualification.is_some(),
            "selection {selection}"
        );
    }
}
