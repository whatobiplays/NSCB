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
