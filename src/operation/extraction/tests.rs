#[cfg(target_os = "macos")]
use super::super::CopyThroughRequest;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use super::super::{
    ExecutionCheckpoint, OperationMilestone, OperationSession,
    execute_with_producer_and_checkpoint_and_cancellation,
};
use super::super::{OperationFailureCode, OperationKind, OperationOutcome};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use super::{ExtractionIoFailurePoint, InjectedExtractionIoFailure};
use crate::extraction::ExtractionRequest;
use crate::{CancellationHandle, Engine};
use std::path::PathBuf;

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
