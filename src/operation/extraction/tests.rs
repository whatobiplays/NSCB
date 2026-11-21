#[cfg(target_os = "macos")]
use super::super::CopyThroughRequest;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use super::super::OperationFailureCode;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use super::super::{
    ExecutionCheckpoint, OperationMilestone, OperationSession,
    execute_with_producer_and_checkpoint_and_cancellation,
};
use super::super::{OperationKind, OperationOutcome};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use super::{ExtractionIoFailurePoint, InjectedExtractionIoFailure};
use crate::extraction::ExtractionRequest;
use crate::{CancellationHandle, Engine};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::{
    ffi::CString,
    os::unix::{ffi::OsStrExt, fs::FileTypeExt},
};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn extraction_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let built = crate::test_synthetic_verification::build(
        crate::test_synthetic_verification::Spec::default(),
    );
    let root = tempfile::tempdir().expect("create extraction fixture");
    let source = root.path().join("program.nca");
    let key_file = root.path().join("prod.keys");
    let destination = root.path().join("bundle");
    std::fs::write(&source, built.nca).expect("write synthetic NCA");
    std::fs::write(&key_file, built.keys_file).expect("write synthetic keys");
    (root, source, key_file, destination)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn extraction_plan(
    source: &std::path::Path,
    key_file: &std::path::Path,
    destination: &std::path::Path,
    cancellation: CancellationHandle,
) -> super::super::OperationPlan {
    Engine::new()
        .plan_extraction(
            ExtractionRequest::new(
                source,
                destination,
                key_file,
                crate::extraction::ExtractionSelection::all(),
            ),
            cancellation,
        )
        .expect("plan synthetic extraction")
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn control_extraction_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let fixture = crate::control_nca_qualification::synthetic_fixture::build_for_program_id(
        &crate::control_nca_qualification::synthetic_fixture::romfs_with_two_files(),
        crate::control_nca_qualification::synthetic_fixture::Mutation::None,
        0x0102_0304_0506_0708,
    );
    let root = tempfile::tempdir().expect("create Control extraction fixture");
    let source = root.path().join("control.nca");
    let key_file = root.path().join("prod.keys");
    let destination = root.path().join("bundle");
    std::fs::write(&source, fixture.bytes).expect("write synthetic Control NCA");
    std::fs::write(
        &key_file,
        crate::control_nca_qualification::synthetic_fixture::key_file_bytes(),
    )
    .expect("write synthetic keys");
    (root, source, key_file, destination)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn assert_postcopy_input_change_is_rejected(replace_key: bool) {
    let (root, source, key_file, destination) = control_extraction_fixture();
    let unowned_directory = root.path().join("unowned-data");
    std::fs::create_dir(&unowned_directory).expect("create unowned directory");
    let sentinel = unowned_directory.join("keep.txt");
    std::fs::write(&sentinel, b"preserve unowned data").expect("write unowned data");
    let original_key_bytes = std::fs::read(&key_file).expect("read original key file");
    let retained_key = root.path().join("retained-original-keys");

    let cancellation = CancellationHandle::new();
    let plan = extraction_plan(&source, &key_file, &destination, cancellation.clone());
    let session = OperationSession::new();
    let mut changed_at_checkpoint = false;
    let result = execute_with_producer_and_checkpoint_and_cancellation(
        plan,
        &session,
        |_, _, _| Ok::<(), OperationFailureCode>(()),
        |checkpoint| {
            if checkpoint == ExecutionCheckpoint::BeforeAtomicPromotion && !changed_at_checkpoint {
                if replace_key {
                    std::fs::rename(&key_file, &retained_key).expect("retain original key file");
                    std::fs::write(&key_file, &original_key_bytes)
                        .expect("replace key file after payload copy");
                } else {
                    let mut changed_source =
                        std::fs::read(&source).expect("read source after payload copy");
                    changed_source[0] ^= 1;
                    std::fs::write(&source, changed_source)
                        .expect("mutate source after payload copy");
                }
                changed_at_checkpoint = true;
            }
        },
        &cancellation,
    );

    assert!(changed_at_checkpoint, "mutation checkpoint was not reached");
    assert_eq!(
        result.failure().map(|failure| failure.code()),
        Some(if replace_key {
            OperationFailureCode::KeyFileChanged
        } else {
            OperationFailureCode::SourceChanged
        })
    );
    assert!(!result.milestones().contains(&OperationMilestone::Published));
    assert!(!destination.exists());
    assert_eq!(
        std::fs::read(&sentinel).expect("read unowned data"),
        b"preserve unowned data"
    );
    if replace_key {
        assert_eq!(
            std::fs::read(retained_key).expect("read retained original key file"),
            original_key_bytes
        );
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn source_mutation_after_payload_copy_is_rejected_before_promotion() {
    assert_postcopy_input_change_is_rejected(false);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn key_replacement_after_payload_copy_is_rejected_before_promotion() {
    assert_postcopy_input_change_is_rejected(true);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct ChangeAfterFirstRead {
    source: std::fs::File,
    source_path: PathBuf,
    mutation_offset: u64,
    replacement: [u8; 4],
    changed: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl std::io::Read for ChangeAfterFirstRead {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = std::io::Read::read(&mut self.source, buffer)?;
        if read != 0 && !self.changed {
            use std::io::{Seek as _, SeekFrom, Write as _};

            let mut source = std::fs::OpenOptions::new()
                .write(true)
                .open(&self.source_path)?;
            source.seek(SeekFrom::Start(self.mutation_offset))?;
            source.write_all(&self.replacement)?;
            source.sync_all()?;
            self.changed = true;
        }
        Ok(read)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn plaintext_source_change_during_verified_copy_fails_before_publication() {
    use sha2::Digest as _;

    let root = tempfile::tempdir().expect("create verified-copy fixture");
    let source_path = root.path().join("source.bin");
    let original = b"0123456789abcdef";
    std::fs::write(&source_path, original).expect("write original source");
    let final_bundle = root.path().join("bundle");
    let unowned_directory = root.path().join("unowned-data");
    std::fs::create_dir(&unowned_directory).expect("create unowned directory");
    let sentinel = unowned_directory.join("keep.txt");
    std::fs::write(&sentinel, b"preserve unowned data").expect("write unowned data");
    let staging_directory = root.path().join("staging");
    std::fs::create_dir(&staging_directory).expect("create staging directory");
    let staged_payload = staging_directory.join("payload.bin");
    let mut destination = std::fs::File::create(&staged_payload).expect("create staged payload");
    let mut reader = ChangeAfterFirstRead {
        source: std::fs::File::open(&source_path).expect("open source"),
        source_path,
        mutation_offset: 8,
        replacement: *b"WXYZ",
        changed: false,
    };
    let selected = super::SelectedExtractionSpan {
        relative_path: "0/romfs/payload.bin".to_owned(),
        source: super::SelectedExtractionSource::Program { offset: 0 },
        size: original.len() as u64,
        sha256: crate::sha256::Sha256Digest::from_bytes(sha2::Sha256::digest(original).into()),
    };
    let mut buffer = [0; 4];
    let result = super::copy_verified_selected_bytes(
        &mut reader,
        &mut destination,
        &selected,
        &mut buffer,
        0,
        &OperationSession::new(),
    );
    drop(destination);

    assert!(reader.changed, "source did not change during the copy");
    assert_eq!(result, Err(OperationFailureCode::SourceChanged));
    assert_eq!(
        std::fs::read(&staged_payload).expect("read staged payload"),
        b"01234567WXYZcdef"
    );
    assert!(!final_bundle.exists());
    assert_eq!(
        std::fs::read(&sentinel).expect("read unowned data"),
        b"preserve unowned data"
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn assert_extraction_hard_link_is_rejected(
    relative_path: Option<&str>,
    inject_at: ExecutionCheckpoint,
    substitute_staged_name: bool,
    expected_failure: OperationFailureCode,
    published: bool,
) {
    let (root, source, key_file, destination) = extraction_fixture();
    let cancellation = CancellationHandle::new();
    let plan = extraction_plan(&source, &key_file, &destination, cancellation.clone());
    let relative_path = relative_path.map_or_else(
        || {
            let selected = plan
                .extraction
                .as_ref()
                .and_then(|extraction| extraction.selected_files.first())
                .expect("synthetic Program NCA has a selected payload file");
            format!("content/{}", selected.relative_path)
        },
        str::to_owned,
    );
    let staging_path = plan.workspace.path.join(
        plan.stage_directory_name
            .as_deref()
            .expect("extraction plans have a staging directory"),
    );
    let staged_file = staging_path.join("bundle").join(&relative_path);
    let external_link = root.path().join("external-linked-file");
    let planned_manifest_bytes = plan
        .extraction
        .as_ref()
        .expect("extraction plan has private extraction evidence")
        .manifest
        .to_json_bytes()
        .expect("serialize the planned manifest");
    let session = OperationSession::new();
    let mut linked_evidence = None;

    let result = execute_with_producer_and_checkpoint_and_cancellation(
        plan,
        &session,
        |_, _, _| Ok::<(), OperationFailureCode>(()),
        |checkpoint| {
            if checkpoint == inject_at && linked_evidence.is_none() {
                let staged_metadata =
                    std::fs::metadata(&staged_file).expect("inspect staged inode before linking");
                let original_identity = (staged_metadata.dev(), staged_metadata.ino());
                let expected_bytes = if relative_path == "manifest.json" {
                    planned_manifest_bytes.clone()
                } else {
                    std::fs::read(&staged_file).expect("read staged payload bytes before linking")
                };
                assert_eq!(
                    std::fs::read(&staged_file).expect("read staged bytes before linking"),
                    expected_bytes
                );
                if substitute_staged_name {
                    std::fs::write(&external_link, &expected_bytes)
                        .expect("seed external inode with planned manifest bytes");
                    let seeded_metadata = std::fs::metadata(&external_link)
                        .expect("inspect seeded external manifest inode");
                    assert_ne!(
                        (seeded_metadata.dev(), seeded_metadata.ino()),
                        original_identity,
                        "manifest substitution must use a distinct external inode"
                    );
                    std::fs::remove_file(&staged_file)
                        .expect("remove staged name for hard-link substitution");
                    std::fs::hard_link(&external_link, &staged_file)
                        .expect("restore staged name from external hard link");
                } else {
                    std::fs::hard_link(&staged_file, &external_link)
                        .expect("create external hard link to staged payload");
                }
                let metadata = std::fs::metadata(&external_link)
                    .expect("inspect external hard link after injection");
                assert_eq!(metadata.nlink(), 2, "injection creates a second hard link");
                linked_evidence = Some((
                    expected_bytes,
                    (metadata.dev(), metadata.ino()),
                    original_identity,
                ));
            }
        },
        &cancellation,
    );

    let (expected_bytes, linked_identity, original_identity) =
        linked_evidence.expect("hard link was injected at the requested checkpoint");
    assert_ne!(result.state(), super::super::JobState::Succeeded);
    assert_eq!(
        result.failure().map(|failure| failure.code()),
        Some(expected_failure)
    );
    assert_eq!(
        result.milestones().contains(&OperationMilestone::Published),
        published
    );
    assert_eq!(destination.exists(), published);

    let external_metadata =
        std::fs::metadata(&external_link).expect("cleanup must preserve the external hard link");
    assert_eq!(
        (external_metadata.dev(), external_metadata.ino()),
        linked_identity
    );
    assert_eq!(
        linked_identity == original_identity,
        !substitute_staged_name,
        "payload links retain their original inode and manifest substitution uses a distinct inode"
    );
    assert_eq!(
        std::fs::read(&external_link).expect("read external hard link after execution"),
        expected_bytes,
        "cleanup must preserve externally linked bytes"
    );
    if published {
        let published_file = destination.join(&relative_path);
        let published_metadata =
            std::fs::metadata(&published_file).expect("published hard-linked file remains");
        assert_eq!(
            (published_metadata.dev(), published_metadata.ino()),
            linked_identity
        );
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn staged_payload_hard_link_at_final_validation_is_rejected_and_preserved() {
    assert_extraction_hard_link_is_rejected(
        None,
        ExecutionCheckpoint::BeforeAtomicPromotion,
        false,
        OperationFailureCode::ValidationFailed,
        false,
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn staged_manifest_hard_link_substitution_is_rejected_and_preserved() {
    assert_extraction_hard_link_is_rejected(
        Some("manifest.json"),
        ExecutionCheckpoint::BeforeAtomicPromotion,
        true,
        OperationFailureCode::ValidationFailed,
        false,
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy)]
enum UnexpectedStagedEntry {
    Symlink,
    Fifo,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn assert_unexpected_staged_entry_is_rejected(entry_kind: UnexpectedStagedEntry) {
    use std::os::unix::fs::symlink;

    let (root, source, key_file, destination) = extraction_fixture();
    let outside_sentinel = root.path().join("outside-sentinel.txt");
    std::fs::write(&outside_sentinel, b"preserve outside target").expect("write outside sentinel");
    let cancellation = CancellationHandle::new();
    let plan = extraction_plan(&source, &key_file, &destination, cancellation.clone());
    let staging_path = plan.workspace.path.join(
        plan.stage_directory_name
            .as_deref()
            .expect("extraction plans have a staging directory"),
    );
    let unexpected_entry = staging_path.join("bundle").join("unexpected-entry");
    let session = OperationSession::new();
    let mut injected = false;

    let result = execute_with_producer_and_checkpoint_and_cancellation(
        plan,
        &session,
        |_, _, _| Ok::<(), OperationFailureCode>(()),
        |checkpoint| {
            if checkpoint == ExecutionCheckpoint::BeforeAtomicPromotion && !injected {
                match entry_kind {
                    UnexpectedStagedEntry::Symlink => {
                        symlink(&outside_sentinel, &unexpected_entry)
                            .expect("inject staged symlink to outside sentinel");
                    }
                    UnexpectedStagedEntry::Fifo => {
                        let path = CString::new(unexpected_entry.as_os_str().as_bytes())
                            .expect("staged path has no NUL byte");
                        assert_eq!(
                            unsafe { libc::mkfifo(path.as_ptr(), 0o600) },
                            0,
                            "inject staged FIFO"
                        );
                        assert!(
                            std::fs::symlink_metadata(&unexpected_entry)
                                .expect("inspect staged FIFO")
                                .file_type()
                                .is_fifo()
                        );
                    }
                }
                injected = true;
            }
        },
        &cancellation,
    );

    assert!(
        injected,
        "unexpected entry was injected before final validation"
    );
    assert_eq!(
        result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::ValidationFailed)
    );
    assert!(!result.milestones().contains(&OperationMilestone::Published));
    assert!(!destination.exists());
    assert_eq!(
        std::fs::read(outside_sentinel).expect("outside target remains untouched"),
        b"preserve outside target"
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn staged_symlink_to_outside_target_is_rejected_without_following_target() {
    assert_unexpected_staged_entry_is_rejected(UnexpectedStagedEntry::Symlink);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn staged_fifo_is_rejected_without_opening_special_file() {
    assert_unexpected_staged_entry_is_rejected(UnexpectedStagedEntry::Fifo);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn payload_hard_link_added_at_promotion_is_reported_uncertain_and_retained() {
    assert_extraction_hard_link_is_rejected(
        None,
        ExecutionCheckpoint::AtomicPromotionStarted,
        false,
        OperationFailureCode::PublicationUncertain,
        true,
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn manifest_hard_link_substitution_at_promotion_is_reported_uncertain_and_retained() {
    assert_extraction_hard_link_is_rejected(
        Some("manifest.json"),
        ExecutionCheckpoint::AtomicPromotionStarted,
        true,
        OperationFailureCode::PublicationUncertain,
        true,
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn assert_prepublication_io_failure(point: ExtractionIoFailurePoint) {
    let (root, source, key_file, destination) = extraction_fixture();
    let unowned_directory = root.path().join("unowned-data");
    std::fs::create_dir(&unowned_directory).expect("create unowned directory");
    let sentinel = unowned_directory.join("keep.txt");
    std::fs::write(&sentinel, b"preserve unowned data").expect("write unowned data");

    let cancellation = CancellationHandle::new();
    let plan = extraction_plan(&source, &key_file, &destination, cancellation.clone());
    let staging_path = plan.workspace.path.join(
        plan.stage_directory_name
            .as_deref()
            .expect("extraction plans have a staging directory"),
    );
    let session = OperationSession::new();
    let _failure = InjectedExtractionIoFailure::at(point);

    let result = execute_with_producer_and_checkpoint_and_cancellation(
        plan,
        &session,
        |_, _, _| Ok::<(), OperationFailureCode>(()),
        |_| {},
        &cancellation,
    );

    assert_eq!(
        result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::WriteFailed)
    );
    assert!(!result.milestones().contains(&OperationMilestone::Published));
    assert!(!destination.exists());
    assert!(result.cleanup_artifact_retained());
    assert!(result.artifacts().iter().any(|artifact| {
        artifact.path() == staging_path.as_path()
            && artifact.role() == super::super::OperationArtifactRole::PrivateStagingDirectory
            && artifact.retained()
    }));
    assert!(
        result
            .artifacts()
            .iter()
            .all(|artifact| artifact.path().starts_with(&staging_path))
    );
    assert_eq!(std::fs::read(sentinel).unwrap(), b"preserve unowned data");
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn assert_postpublication_sync_failure(point: ExtractionIoFailurePoint) {
    let (_root, source, key_file, destination) = extraction_fixture();
    let cancellation = CancellationHandle::new();
    let plan = extraction_plan(&source, &key_file, &destination, cancellation.clone());
    let session = OperationSession::new();
    let _failure = InjectedExtractionIoFailure::at(point);

    let result = execute_with_producer_and_checkpoint_and_cancellation(
        plan,
        &session,
        |_, _, _| Ok::<(), OperationFailureCode>(()),
        |_| {},
        &cancellation,
    );

    assert_eq!(
        result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::PublicationUncertain)
    );
    assert!(result.milestones().contains(&OperationMilestone::Published));
    assert!(!result.milestones().contains(&OperationMilestone::Validated));
    assert!(destination.join("manifest.json").is_file());
}

#[test]
fn extraction_operation_names_have_stable_json_values() {
    assert_eq!(
        serde_json::to_string(&OperationKind::Extract).unwrap(),
        "\"extract\""
    );
    assert_eq!(
        serde_json::to_string(&OperationOutcome::Extracted).unwrap(),
        "\"extracted\""
    );
}

#[test]
fn engine_accepts_an_extraction_request_and_cancellation_handle() {
    let request = ExtractionRequest::new(
        PathBuf::from("missing-source.nca"),
        PathBuf::from("missing-output"),
        PathBuf::from("missing-keys"),
        crate::extraction::ExtractionSelection::all(),
    );
    assert!(
        Engine::new()
            .plan_extraction(request, CancellationHandle::new())
            .is_err()
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn atomic_destination_race_preserves_the_competing_directory() {
    let (_root, source, key_file, destination) = extraction_fixture();
    let cancellation = CancellationHandle::new();
    let plan = extraction_plan(&source, &key_file, &destination, cancellation.clone());
    let sentinel = destination.join("owner-data.txt");
    let session = OperationSession::new();

    let result = execute_with_producer_and_checkpoint_and_cancellation(
        plan,
        &session,
        |_, _, _| Ok::<(), OperationFailureCode>(()),
        |checkpoint| {
            if checkpoint == ExecutionCheckpoint::AtomicPromotionStarted {
                std::fs::create_dir(&destination).unwrap();
                std::fs::write(&sentinel, b"preserve competing output").unwrap();
            }
        },
        &cancellation,
    );

    assert_eq!(
        result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::DestinationConflict)
    );
    assert!(!result.milestones().contains(&OperationMilestone::Published));
    assert_eq!(
        std::fs::read(sentinel).unwrap(),
        b"preserve competing output"
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn prepromotion_payload_write_failure_retains_only_owned_stage() {
    assert_prepublication_io_failure(ExtractionIoFailurePoint::PayloadWrite);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn prepromotion_bundle_sync_failure_retains_only_owned_stage() {
    assert_prepublication_io_failure(ExtractionIoFailurePoint::BundlePrepromotion);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn published_stage_parent_sync_failure_retains_bundle_as_uncertain() {
    assert_postpublication_sync_failure(ExtractionIoFailurePoint::StageParentAfterRename);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn published_destination_parent_sync_failure_retains_bundle_as_uncertain() {
    assert_postpublication_sync_failure(ExtractionIoFailurePoint::DestinationParentDurability);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn late_destination_parent_replacement_is_uncertain_and_preserves_both_trees() {
    let (root, source, key_file, _) = extraction_fixture();
    let destination_parent = root.path().join("output-parent");
    std::fs::create_dir(&destination_parent).expect("create output parent");
    let destination = destination_parent.join("bundle");
    let relocated_parent = root.path().join("relocated-output-parent");
    let competing_sentinel = destination.join("owner-data.txt");
    let cancellation = CancellationHandle::new();
    let plan = extraction_plan(&source, &key_file, &destination, cancellation.clone());
    let session = OperationSession::new();
    let mut replaced = false;

    let result = execute_with_producer_and_checkpoint_and_cancellation(
        plan,
        &session,
        |_, _, _| Ok::<(), OperationFailureCode>(()),
        |checkpoint| {
            if checkpoint == ExecutionCheckpoint::AfterPublishedDestinationContentInspection
                && !replaced
            {
                std::fs::rename(&destination_parent, &relocated_parent)
                    .expect("relocate original output parent");
                std::fs::create_dir(&destination_parent).expect("replace output parent route");
                std::fs::create_dir(&destination).expect("create competing bundle");
                std::fs::write(&competing_sentinel, b"preserve competing bundle")
                    .expect("write competing bundle data");
                replaced = true;
            }
        },
        &cancellation,
    );

    assert!(replaced);
    assert_eq!(
        result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::PublicationUncertain)
    );
    assert!(result.milestones().contains(&OperationMilestone::Published));
    assert!(relocated_parent.join("bundle/manifest.json").is_file());
    assert_eq!(
        std::fs::read(competing_sentinel).unwrap(),
        b"preserve competing bundle"
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn postpromotion_manifest_change_is_reported_as_uncertain_and_retained() {
    let (_root, source, key_file, destination) = extraction_fixture();
    let cancellation = CancellationHandle::new();
    let plan = extraction_plan(&source, &key_file, &destination, cancellation.clone());
    let manifest_path = destination.join("manifest.json");
    let session = OperationSession::new();

    let result = execute_with_producer_and_checkpoint_and_cancellation(
        plan,
        &session,
        |_, _, _| Ok::<(), OperationFailureCode>(()),
        |checkpoint| {
            if checkpoint == ExecutionCheckpoint::AfterPromotion {
                std::fs::write(&manifest_path, b"{}").unwrap();
            }
        },
        &cancellation,
    );

    assert_eq!(
        result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::PublicationUncertain)
    );
    assert!(result.milestones().contains(&OperationMilestone::Published));
    assert_eq!(std::fs::read(manifest_path).unwrap(), b"{}");
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn late_manifest_edit_after_inventory_hash_is_uncertain_and_retained() {
    let (_root, source, key_file, destination) = extraction_fixture();
    let cancellation = CancellationHandle::new();
    let plan = extraction_plan(&source, &key_file, &destination, cancellation.clone());
    let manifest_path = destination.join("manifest.json");
    let session = OperationSession::new();
    let mut edited = false;

    let result = execute_with_producer_and_checkpoint_and_cancellation(
        plan,
        &session,
        |_, _, _| Ok::<(), OperationFailureCode>(()),
        |checkpoint| {
            if checkpoint == ExecutionCheckpoint::AfterPublishedDestinationContentInspection
                && !edited
            {
                std::fs::write(&manifest_path, b"{}").unwrap();
                edited = true;
            }
        },
        &cancellation,
    );

    assert!(edited);
    assert_eq!(
        result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::PublicationUncertain)
    );
    assert!(result.milestones().contains(&OperationMilestone::Published));
    assert_eq!(std::fs::read(manifest_path).unwrap(), b"{}");
}

#[cfg(target_os = "macos")]
#[test]
fn existing_plan_wire_omits_an_empty_extraction_manifest() {
    let root = tempfile::tempdir().unwrap();
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let source = root.path().join("source.bin");
    std::fs::write(&source, b"source").unwrap();
    let plan = Engine::new()
        .plan_copy_through(CopyThroughRequest::new(
            &source,
            root.path().join("destination.bin"),
            &workspace,
        ))
        .unwrap();

    assert!(plan.snapshot().extraction_manifest.is_none());
    let wire = serde_json::to_value(plan.snapshot()).unwrap();
    assert!(wire.get("extraction_manifest").is_none());
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn qualified_nsp_extraction_plan() -> (
    tempfile::TempDir,
    PathBuf,
    PathBuf,
    PathBuf,
    super::super::OperationPlan,
) {
    let fixture = crate::synthetic_nsp_qualification::valid();
    let root = tempfile::tempdir().expect("create qualified NSP fixture");
    let source = root.path().join("package.nsp");
    let key_file = root.path().join("prod.keys");
    let destination = root.path().join("bundle");
    std::fs::write(&source, &fixture.package).expect("write synthetic NSP");
    std::fs::write(&key_file, &fixture.key_file).expect("write synthetic keys");
    let plan = extraction_plan(&source, &key_file, &destination, CancellationHandle::new());
    (root, source, key_file, destination, plan)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn open_planned_file(route: &super::super::ResolvedFile) -> std::fs::File {
    let directory = super::super::open_directory(&route.parent).expect("open planned parent");
    super::super::open_file_at(&directory, &route.name).expect("open planned file")
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn load_planned_nsp_keys(
    key_file: &mut std::fs::File,
    evidence: &super::super::FileEvidence,
    size: u64,
) -> Result<
    crate::key_file::NspQualificationKeys,
    crate::nsp_semantic_qualification::NspSemanticQualificationError,
> {
    use crate::nsp_semantic_qualification::{
        NspSemanticQualificationError as Error, NspSemanticQualificationErrorCode as Code,
    };
    use std::io::{Seek as _, SeekFrom};

    super::super::verify_file_evidence(key_file, evidence)
        .map_err(|_| Error::new(Code::KeyFileChangedDuringQualification))?;
    key_file
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::new(Code::KeyFileUnavailable))?;
    let keys = crate::key_file::read_nsp_qualification_keys(key_file, size)
        .map_err(crate::nsp_semantic_qualification::map_key_file_error)?;
    super::super::verify_file_evidence(key_file, evidence)
        .map_err(|_| Error::new(Code::KeyFileChangedDuringQualification))?;
    Ok(keys)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn operation_owned_nsp_input_checks_identity_size_and_revalidation() {
    use crate::nsp_semantic_qualification::{
        NspSemanticInput as _, NspSemanticQualificationErrorCode as Code,
    };

    let (_root, source, _, _, plan) = qualified_nsp_extraction_plan();
    let mut file = open_planned_file(&plan.source);
    let input = super::ExtractionNspInput {
        file: &mut file,
        route: &plan.source,
        evidence: &plan.source_baseline,
    };

    assert_eq!(input.input_size(), plan.source_baseline.snapshot.len);
    input
        .revalidate(Code::InputChangedDuringQualification)
        .expect("unchanged operation-owned input remains valid");

    let retained = source.with_extension("retained");
    std::fs::rename(&source, retained).expect("retain the opened source");
    std::fs::write(
        &source,
        vec![0; usize::try_from(plan.source_baseline.snapshot.len).unwrap()],
    )
    .expect("replace the source with a same-sized file");
    let error = input
        .revalidate(Code::InputChangedDuringQualification)
        .expect_err("same-sized path replacement must fail identity revalidation");
    assert_eq!(error.code(), Code::InputChangedDuringQualification);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn unqualified_nsp_reasons_map_to_input_or_profile_failures() {
    use crate::nsp_semantic_qualification::NspSemanticQualificationReason as Reason;
    use crate::operation::OperationFailureCode;

    assert_eq!(
        super::super::map_nsp_semantic_reason(Reason::InvalidContainerStructure),
        OperationFailureCode::InvalidContentPackage,
    );
    assert_eq!(
        super::super::map_nsp_semantic_reason(Reason::UnsupportedNcaProfile),
        OperationFailureCode::UnsupportedContentProfile,
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn path_and_operation_owned_inputs_produce_equivalent_qualification_facts() {
    use crate::nsp_semantic_qualification::{
        NspSemanticQualificationOutcome, NspSemanticQualificationProfile,
        NspSemanticQualificationRequest, NspSemanticQualificationRole,
    };

    let (_root, source, key_file, _, plan) = qualified_nsp_extraction_plan();
    let result = crate::nsp_semantic_qualification::qualify(NspSemanticQualificationRequest::new(
        &source, &key_file,
    ))
    .expect("qualify the same fixture through the path-based input");
    let evidence = plan
        .extraction
        .as_ref()
        .and_then(|extraction| extraction.nsp_evidence.as_ref())
        .expect("planning retained durable NSP evidence");
    let NspSemanticQualificationOutcome::Qualified(facts) = result.outcome else {
        panic!("path-based qualification did not qualify the synthetic package");
    };
    let program = facts
        .members
        .iter()
        .find(|member| member.role == NspSemanticQualificationRole::Program)
        .expect("qualified outcome contains a Program member");

    assert_eq!(
        facts.profile,
        NspSemanticQualificationProfile::RightsFreeBaseApplicationV1
    );
    assert_eq!(result.source_sha256, evidence.source_sha256);
    assert_eq!(facts.title_id, evidence.title_id);
    assert_eq!(facts.cnmt_program_content_id, evidence.program_content_id);
    assert_eq!(program.size, evidence.member_size);
    assert_eq!(program.sha256, evidence.member_sha256);
    let snapshot = serde_json::to_value(plan.snapshot())
        .expect("serialize the qualified extraction plan snapshot");
    let title_id = crate::inspection::ProgramId::from_u64(evidence.title_id).to_hex();
    let content_id =
        crate::extraction::NcaContentId::from_bytes(evidence.program_content_id).to_hex();
    assert_eq!(
        snapshot["extraction_container"],
        serde_json::json!({
            "profile": "rights_free_base_application_v1",
            "title_id": title_id,
            "program_content_id": content_id
        })
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn source_mutation_during_operation_owned_qualification_is_rejected() {
    use crate::nsp_semantic_qualification::{
        Checkpoint, NspSemanticQualificationErrorCode as Code, NspSemanticQualificationRequest,
    };
    use std::io::Write as _;

    let (_root, source, key_path, _, plan) = qualified_nsp_extraction_plan();
    let extraction = plan.extraction.as_ref().expect("NSP extraction plan");
    let mut source_file = open_planned_file(&plan.source);
    let mut key_file = open_planned_file(&extraction.key_file);
    let key_size = key_file.metadata().unwrap().len();
    let input = super::ExtractionNspInput {
        file: &mut source_file,
        route: &plan.source,
        evidence: &plan.source_baseline,
    };
    let mut changed = false;
    let mut checkpoint = |point| {
        if matches!(point, Checkpoint::SourceHashed) && !changed {
            changed = true;
            std::fs::OpenOptions::new()
                .append(true)
                .open(&source)
                .expect("open source for deterministic mutation")
                .write_all(b"x")
                .expect("append during semantic qualification");
        }
    };
    let mut key_loader = |_: &NspSemanticQualificationRequest| {
        load_planned_nsp_keys(&mut key_file, &extraction.key_baseline, key_size)
    };
    let result = crate::nsp_semantic_qualification::qualify_opened_for_extraction(
        NspSemanticQualificationRequest::new(&source, &key_path),
        input,
        &mut key_loader,
        &mut checkpoint,
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("source mutation during qualification must be detected"),
    };

    assert!(changed, "source mutation checkpoint was not reached");
    assert_eq!(error.code(), Code::InputChangedDuringQualification);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn key_file_mutation_during_operation_owned_qualification_is_rejected() {
    use crate::nsp_semantic_qualification::{
        NspSemanticQualificationError as Error, NspSemanticQualificationErrorCode as Code,
        NspSemanticQualificationRequest,
    };
    use std::io::{Seek as _, SeekFrom, Write as _};

    let (_root, source, key_path, _, plan) = qualified_nsp_extraction_plan();
    let extraction = plan.extraction.as_ref().expect("NSP extraction plan");
    let mut source_file = open_planned_file(&plan.source);
    let mut key_file = open_planned_file(&extraction.key_file);
    let key_size = key_file.metadata().unwrap().len();
    let input = super::ExtractionNspInput {
        file: &mut source_file,
        route: &plan.source,
        evidence: &plan.source_baseline,
    };
    let mut changed = false;
    let mut key_loader = |_: &NspSemanticQualificationRequest| {
        super::super::verify_file_evidence(&mut key_file, &extraction.key_baseline)
            .map_err(|_| Error::new(Code::KeyFileChangedDuringQualification))?;
        key_file
            .seek(SeekFrom::Start(0))
            .map_err(|_| Error::new(Code::KeyFileUnavailable))?;
        let keys = crate::key_file::read_nsp_qualification_keys(&mut key_file, key_size)
            .map_err(crate::nsp_semantic_qualification::map_key_file_error)?;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&key_path)
            .expect("open keys for deterministic mutation")
            .write_all(b"\n")
            .expect("append during semantic qualification");
        changed = true;
        super::super::verify_file_evidence(&mut key_file, &extraction.key_baseline)
            .map_err(|_| Error::new(Code::KeyFileChangedDuringQualification))?;
        Ok(keys)
    };
    let mut checkpoint = |_| {};
    let result = crate::nsp_semantic_qualification::qualify_opened_for_extraction(
        NspSemanticQualificationRequest::new(&source, &key_path),
        input,
        &mut key_loader,
        &mut checkpoint,
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("key mutation during qualification must be detected"),
    };

    assert!(changed, "key mutation hook was not reached");
    assert_eq!(error.code(), Code::KeyFileChangedDuringQualification);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn execution_rejects_stale_qualified_nsp_evidence() {
    let (_root, _, _, destination, mut plan) = qualified_nsp_extraction_plan();
    let evidence = plan
        .extraction
        .as_mut()
        .and_then(|extraction| extraction.nsp_evidence.as_mut())
        .expect("NSP extraction evidence");
    evidence.title_id ^= 1;

    let result = Engine::new().execute_operation(plan, &OperationSession::new());

    assert_eq!(
        result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::SourceChanged)
    );
    assert!(!destination.exists());
}
