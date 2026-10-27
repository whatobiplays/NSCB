#[cfg(target_os = "macos")]
use nscb::{
    ConflictPolicy, InputResolutionCapabilities, InputResolutionRequest, JobState,
    LocalSplitTrustStore, OperationArtifact, OperationArtifactRole, OperationMilestone,
    OperationOutcome, OperationSession, StagingStrategy,
};
use nscb::{CopyThroughRequest, DestinationBaseline, Engine, OperationFailureCode, PlannedEffect};
mod support;
#[cfg(target_os = "macos")]
use std::fs;
#[cfg(target_os = "macos")]
use tempfile::tempdir;

#[test]
fn failure_codes_share_canonical_display_and_serialized_names() {
    for (code, expected) in [
        (OperationFailureCode::Busy, "operation_session_busy"),
        (
            OperationFailureCode::SessionUnavailable,
            "operation_session_unavailable",
        ),
        (
            OperationFailureCode::ValidationFailed,
            "staged_output_invalid",
        ),
    ] {
        assert_eq!(code.as_str(), expected);
        assert_eq!(code.to_string(), expected);
        assert_eq!(
            serde_json::to_value(code).expect("serialize stable failure code"),
            expected
        );
    }
}

#[test]
fn public_baseline_and_effect_keep_stable_serialized_names() {
    assert_eq!(
        serde_json::to_value(DestinationBaseline::Absent).expect("serialize destination baseline"),
        serde_json::json!({"state": "absent"})
    );
    assert_eq!(
        serde_json::to_value(PlannedEffect::ReadSource).expect("serialize planned effect"),
        "read_source"
    );
}

#[cfg(target_os = "macos")]
fn operation_paths() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let root = tempdir().expect("create operation test directory");
    let source = root.path().join("source.bin");
    let destination = root.path().join("output.bin");
    fs::write(&source, b"synthetic copy-through bytes").expect("write source fixture");
    (root, source, destination)
}

#[cfg(target_os = "macos")]
fn retained_artifact(
    result: &nscb::OperationResult,
    role: OperationArtifactRole,
) -> &OperationArtifact {
    result
        .artifacts()
        .iter()
        .find(|artifact| artifact.role() == role)
        .unwrap_or_else(|| panic!("missing {role:?} artifact: {:?}", result.artifacts()))
}

#[cfg(target_os = "macos")]
fn assert_cleanup_incomplete(result: &nscb::OperationResult) {
    assert!(result.cleanup_artifact_retained(), "{result:?}");
    assert_eq!(
        result.cleanup_warning().map(|warning| warning.code()),
        Some(OperationFailureCode::CleanupIncomplete),
        "{result:?}"
    );
    assert!(!result.artifacts().is_empty(), "{result:?}");
    let serialized =
        serde_json::to_value(result.artifacts()).expect("serialize artifact inventory");
    for (artifact, value) in result
        .artifacts()
        .iter()
        .zip(serialized.as_array().unwrap())
    {
        assert!(artifact.retained(), "{artifact:?}");
        assert!(artifact.path().is_absolute(), "{artifact:?}");
        assert!(artifact.path().exists(), "{artifact:?}");
        assert!(value["role"].is_string(), "{value}");
        assert!(value["path"].is_string(), "{value}");
        for field in [
            "device",
            "inode",
            "length",
            "sha256",
            "path_identity_matches",
        ] {
            assert!(value.get(field).is_some(), "missing {field} in {value}");
        }
        assert_eq!(value["retained"], true, "{value}");
        if artifact.path_identity_matches() == Some(true) {
            assert_eq!(artifact.device(), artifact.path_device(), "{artifact:?}");
            assert_eq!(artifact.inode(), artifact.path_inode(), "{artifact:?}");
        }
    }
}

#[cfg(target_os = "macos")]
fn assert_artifact_paths_are_planned(
    planned_paths: &[std::path::PathBuf],
    result: &nscb::OperationResult,
) {
    for artifact in result.artifacts() {
        assert!(
            planned_paths.iter().any(|path| path == artifact.path()),
            "execution artifact was absent from the immutable plan: {artifact:?}"
        );
    }
}

#[test]
#[cfg(target_os = "macos")]
fn host_default_workspace_is_ephemeral_and_request_override_is_explicit() {
    let (root, source, destination) = operation_paths();
    let default_workspace = root.path().join("host-default-workspace");
    let override_workspace = root.path().join("request-override-workspace");
    fs::create_dir(&default_workspace).expect("create host default workspace");
    fs::create_dir(&override_workspace).expect("create request override workspace");
    let engine = Engine::new();

    let default_plan = engine
        .plan_copy_through(CopyThroughRequest::with_host_default_workspace(
            &source,
            &destination,
            &default_workspace,
        ))
        .expect("plan with host-provided default workspace");
    assert_eq!(
        default_plan.snapshot().workspace(),
        default_workspace.canonicalize().unwrap()
    );
    assert_eq!(
        default_plan.snapshot().staging_strategy(),
        StagingStrategy::HostWorkspace
    );
    let default_snapshot =
        serde_json::to_value(default_plan.snapshot()).expect("serialize host-workspace plan");
    assert_eq!(default_snapshot["staging_strategy"], "host_workspace");
    assert!(default_snapshot["staging_parent_identity"].is_string());

    let override_plan = engine
        .plan_copy_through(
            CopyThroughRequest::with_host_default_workspace(
                &source,
                &destination,
                &default_workspace,
            )
            .with_workspace_override(&override_workspace),
        )
        .expect("plan with per-request workspace override");
    assert_eq!(
        override_plan.snapshot().workspace(),
        override_workspace.canonicalize().unwrap()
    );
    assert_eq!(
        override_plan.snapshot().staging_strategy(),
        StagingStrategy::ExplicitWorkspace
    );
    assert_eq!(std::mem::size_of::<Engine>(), 0);
}

#[test]
#[cfg(target_os = "macos")]
fn public_plan_is_inspectable_and_copy_through_preserves_the_source() {
    let (root, source, destination) = operation_paths();
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("create workspace");
    let source_bytes = fs::read(&source).expect("read source before operation");
    let engine = Engine::new();

    let plan = engine
        .plan_copy_through(CopyThroughRequest::new(&source, &destination, &workspace))
        .expect("plan a regular-file copy-through");
    let snapshot = plan.snapshot();
    assert_eq!(snapshot.source().path(), source.canonicalize().unwrap());
    assert_eq!(snapshot.source().size(), source_bytes.len() as u64);
    assert!(!snapshot.source().identity().to_hex().is_empty());
    assert!(snapshot.required_providers().is_empty());
    assert!(snapshot.required_keys().is_empty());
    assert_eq!(
        snapshot.effects(),
        &[
            PlannedEffect::ReadSource,
            PlannedEffect::CoordinateDestination,
            PlannedEffect::CreatePrivateStagingDirectory,
            PlannedEffect::CreateStagingFile,
            PlannedEffect::CreateDestination,
        ]
    );
    let planned_paths = snapshot
        .planned_artifacts()
        .iter()
        .map(|artifact| artifact.path().to_path_buf())
        .collect::<Vec<_>>();
    let planned_directory = snapshot
        .planned_artifacts()
        .iter()
        .find(|artifact| artifact.role() == OperationArtifactRole::PrivateStagingDirectory)
        .expect("plan the private staging directory")
        .path()
        .to_path_buf();
    let planned_stage = snapshot
        .planned_artifacts()
        .iter()
        .find(|artifact| artifact.role() == OperationArtifactRole::StagedOutput)
        .expect("plan the staging file");
    let planned_stage_path = planned_stage.path().to_path_buf();
    let planned_stage_length = planned_stage.expected_length();
    let planned_stage_digest = planned_stage.expected_sha256();
    let source_digest = snapshot.source().sha256();
    assert_eq!(
        planned_stage_path.parent(),
        Some(planned_directory.as_path())
    );
    assert_eq!(planned_stage_length, Some(source_bytes.len() as u64));
    assert_eq!(planned_stage_digest, Some(source_digest));

    let result = engine.execute_operation(plan, &OperationSession::new());

    assert_eq!(result.state(), JobState::Succeeded, "{result:?}");
    assert_eq!(
        result.outcome(),
        Some(OperationOutcome::Copied),
        "{result:?}"
    );
    assert_eq!(result.failure().map(|failure| failure.code()), None);
    assert_cleanup_incomplete(&result);
    // The retained staging name is a hard link to the published output, so it
    // consumes no additional file content blocks.
    assert_eq!(result.retained_storage_bytes(), Some(0));
    assert_artifact_paths_are_planned(&planned_paths, &result);
    assert!(result.milestones().contains(&OperationMilestone::Planned));
    assert!(result.milestones().contains(&OperationMilestone::Executing));
    assert!(result.milestones().contains(&OperationMilestone::Validated));
    assert!(result.milestones().contains(&OperationMilestone::Published));
    assert_eq!(fs::read(&destination).unwrap(), source_bytes);
    assert_eq!(fs::read(&source).unwrap(), source_bytes);
    let staging_directory =
        retained_artifact(&result, OperationArtifactRole::PrivateStagingDirectory);
    let staged_output = retained_artifact(&result, OperationArtifactRole::StagedOutput);
    assert_eq!(staging_directory.path(), planned_directory);
    assert_eq!(staged_output.path(), planned_stage_path);
    assert_eq!(staged_output.length(), Some(source_bytes.len() as u64));
    assert_eq!(staged_output.sha256(), Some(source_digest));
    assert_eq!(staged_output.path_identity_matches(), Some(true));
    assert_eq!(staged_output.device(), staged_output.path_device());
    assert_eq!(staged_output.inode(), staged_output.path_inode());
    assert_eq!(fs::read(staged_output.path()).unwrap(), source_bytes);
    assert_eq!(fs::read_dir(workspace).unwrap().count(), 1);
}

#[test]
#[cfg(target_os = "macos")]
fn serialized_plan_identifies_its_kind_and_nscb_version() {
    let (root, source, destination) = operation_paths();
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("create workspace");
    let plan = Engine::new()
        .plan_copy_through(CopyThroughRequest::new(&source, &destination, &workspace))
        .expect("create inspection plan");

    let snapshot = serde_json::to_value(plan.snapshot()).expect("serialize plan snapshot");

    assert_eq!(snapshot["kind"], "operation_plan");
    assert_eq!(snapshot["nscb_version"], env!("CARGO_PKG_VERSION"));
    assert!(snapshot["staging_parent_identity"].is_string());
    assert!(snapshot.get("schema_version").is_none());
}

#[test]
#[cfg(target_os = "macos")]
fn explicitly_requested_missing_workspace_is_created_during_execution() {
    let (root, source, destination) = operation_paths();
    let workspace = root.path().join("new-workspace");
    let engine = Engine::new();

    let plan = engine
        .plan_copy_through(CopyThroughRequest::new(&source, &destination, &workspace))
        .expect("plan safe creation of the explicit workspace");

    assert_eq!(
        plan.snapshot().effects(),
        &[
            PlannedEffect::ReadSource,
            PlannedEffect::CoordinateDestination,
            PlannedEffect::CreateWorkspaceDirectory,
            PlannedEffect::CreatePrivateStagingDirectory,
            PlannedEffect::CreateStagingFile,
            PlannedEffect::CreateDestination,
        ]
    );
    let planned_paths = plan
        .snapshot()
        .planned_artifacts()
        .iter()
        .map(|artifact| artifact.path().to_path_buf())
        .collect::<Vec<_>>();
    assert!(!workspace.exists());
    let result = engine.execute_operation(plan, &OperationSession::new());

    assert_eq!(result.state(), JobState::Succeeded, "{result:?}");
    assert_cleanup_incomplete(&result);
    assert_artifact_paths_are_planned(&planned_paths, &result);
    assert!(workspace.is_dir());
    assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
    assert_eq!(fs::read_dir(workspace).unwrap().count(), 1);
}

#[test]
#[cfg(target_os = "macos")]
fn missing_workspace_created_after_planning_is_a_stale_plan() {
    let (root, source, destination) = operation_paths();
    let workspace = root.path().join("new-workspace");
    let engine = Engine::new();
    let plan = engine
        .plan_copy_through(CopyThroughRequest::new(&source, &destination, &workspace))
        .expect("plan a stable absent workspace");

    fs::create_dir(&workspace).expect("competing writer creates requested workspace");
    fs::write(workspace.join("keep.bin"), b"preserve competing entry")
        .expect("write competing workspace entry");
    let result = engine.execute_operation(plan, &OperationSession::new());

    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        result.failure().unwrap().code(),
        OperationFailureCode::StalePlan
    );
    assert!(!destination.exists());
    assert_eq!(
        fs::read(workspace.join("keep.bin")).unwrap(),
        b"preserve competing entry"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn missing_workspace_parent_is_not_created_recursively() {
    let (root, source, destination) = operation_paths();
    let workspace = root.path().join("missing-parent").join("workspace");

    let error = match Engine::new().plan_copy_through(CopyThroughRequest::new(
        &source,
        &destination,
        &workspace,
    )) {
        Ok(_) => panic!("planning does not create missing workspace parents"),
        Err(error) => error,
    };

    assert_eq!(error.code(), OperationFailureCode::WorkspaceUnavailable);
    assert!(!workspace.parent().unwrap().exists());
}

#[test]
#[cfg(target_os = "macos")]
fn copy_through_rejects_direct_and_qualified_one_part_split_representations() {
    use support::split_fixture::SplitFixture;

    let (root, _ordinary_source, destination) = operation_paths();
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("create workspace");
    let split = SplitFixture::new(b"one physical split segment", 128);
    let split_directory = split.write(root.path(), "Game.nsp");
    let store = LocalSplitTrustStore::new(root.path().join("state").join("split-trust"));
    split.issue(&store);
    let split_member = split_directory.join("00");
    assert_eq!(fs::read(&split_member).unwrap(), split.parts[0]);

    let resolved = Engine::new()
        .resolve_inputs_with(
            InputResolutionRequest::new(root.path()).with_path("Game.nsp/00"),
            InputResolutionCapabilities::new().with_split_trust_store(&store),
        )
        .expect("qualify one-part Split through the existing resolver");
    assert_eq!(resolved.inputs.len(), 1);
    assert!(resolved.inputs[0].qualification.is_some());

    for source in [&split_member, &split_directory] {
        let error = match Engine::new().plan_copy_through(CopyThroughRequest::new(
            source,
            &destination,
            &workspace,
        )) {
            Ok(_) => panic!("a qualified Split representation cannot enter copy-through"),
            Err(error) => error,
        };

        assert_eq!(error.code(), OperationFailureCode::SplitInputUnsupported);
    }
}

#[test]
#[cfg(target_os = "macos")]
fn unsupported_numeric_split_layout_is_rejected_by_input_resolution_semantics() {
    let (root, _source, destination) = operation_paths();
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("create workspace");
    let standalone = root.path().join("000");
    fs::write(&standalone, b"ordinary three-digit filename").expect("write standalone file");

    let error = Engine::new()
        .plan_copy_through(CopyThroughRequest::new(
            &standalone,
            &destination,
            &workspace,
        ))
        .err()
        .expect("resolver classifies numeric segments as unsupported Split layouts");

    assert_eq!(error.code(), OperationFailureCode::SplitInputUnsupported);
}

#[test]
#[cfg(target_os = "macos")]
fn byte_identical_destination_is_reported_as_successful_already_up_to_date() {
    let (root, source, destination) = operation_paths();
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("create workspace");
    fs::copy(&source, &destination).expect("create identical destination");
    let engine = Engine::new();
    let plan = engine
        .plan_copy_through(CopyThroughRequest::new(&source, &destination, &workspace))
        .expect("plan with an existing destination");
    assert_eq!(
        plan.snapshot().effects(),
        &[
            PlannedEffect::ReadSource,
            PlannedEffect::CoordinateDestination
        ]
    );

    let result = engine.execute_operation(plan, &OperationSession::new());

    assert_eq!(result.state(), JobState::Succeeded);
    assert_eq!(result.outcome(), Some(OperationOutcome::AlreadyUpToDate));
    assert!(result.milestones().contains(&OperationMilestone::Validated));
}

#[test]
#[cfg(target_os = "macos")]
fn same_length_source_rewrite_after_planning_cannot_be_published() {
    let (root, source, destination) = operation_paths();
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("create workspace");
    let engine = Engine::new();
    let plan = engine
        .plan_copy_through(CopyThroughRequest::new(&source, &destination, &workspace))
        .expect("plan before source rewrite");
    let mut changed_source = fs::read(&source).expect("read source before rewrite");
    changed_source[0] ^= 0xff;
    fs::write(&source, changed_source).expect("rewrite source without changing its length");

    let result = engine.execute_operation(plan, &OperationSession::new());

    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        result.failure().unwrap().code(),
        OperationFailureCode::SourceChanged
    );
    assert!(!destination.exists());
}

#[test]
#[cfg(target_os = "macos")]
fn source_metadata_rewrite_after_planning_is_detected() {
    let (_root, source, destination) = operation_paths();
    let workspace = source.parent().unwrap().join("workspace");
    fs::create_dir(&workspace).expect("create workspace");
    let bytes = fs::read(&source).expect("read source before rewrite");
    let engine = Engine::new();
    let plan = engine
        .plan_copy_through(CopyThroughRequest::new(&source, &destination, &workspace))
        .expect("plan before metadata rewrite");
    fs::write(&source, bytes).expect("rewrite the same source bytes");

    let result = engine.execute_operation(plan, &OperationSession::new());

    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        result.failure().unwrap().code(),
        OperationFailureCode::SourceChanged
    );
    assert!(!destination.exists());
}

#[test]
#[cfg(target_os = "macos")]
fn changed_destination_after_planning_is_preserved_and_rejected() {
    let (_root, source, destination) = operation_paths();
    let workspace = source.parent().unwrap().join("workspace");
    fs::create_dir(&workspace).expect("create workspace");
    let engine = Engine::new();
    let plan = engine
        .plan_copy_through(CopyThroughRequest::new(&source, &destination, &workspace))
        .expect("plan while destination is absent");
    let competing_bytes = b"destination created after planning";
    fs::write(&destination, competing_bytes).expect("create competing destination");

    let result = engine.execute_operation(plan, &OperationSession::new());

    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        result.failure().unwrap().code(),
        OperationFailureCode::DestinationChanged
    );
    assert_eq!(fs::read(&destination).unwrap(), competing_bytes);
}

#[test]
#[cfg(target_os = "macos")]
fn default_conflict_fails_and_explicit_replace_commits_atomically() {
    let (root, source, destination) = operation_paths();
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("create workspace");
    let original_destination = b"existing user content";
    fs::write(&destination, original_destination).expect("write existing destination");
    let engine = Engine::new();

    let fail_plan = engine
        .plan_copy_through(CopyThroughRequest::new(&source, &destination, &workspace))
        .expect("plan default-fail conflict");
    assert_eq!(fail_plan.snapshot().effects(), &[PlannedEffect::ReadSource]);
    let failed = engine.execute_operation(fail_plan, &OperationSession::new());
    assert_eq!(failed.state(), JobState::Failed);
    assert_eq!(
        failed.failure().unwrap().code(),
        OperationFailureCode::DestinationConflict
    );
    assert_eq!(fs::read(&destination).unwrap(), original_destination);

    let replace_plan = engine
        .plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace)
                .with_conflict_policy(ConflictPolicy::Replace),
        )
        .expect("plan an explicitly authorized replacement");
    assert_eq!(
        replace_plan.snapshot().effects(),
        &[
            PlannedEffect::ReadSource,
            PlannedEffect::CoordinateDestination,
            PlannedEffect::CreatePrivateStagingDirectory,
            PlannedEffect::CreateStagingFile,
            PlannedEffect::CreateDestinationBackup,
            PlannedEffect::ReplaceDestination,
        ]
    );

    let planned_paths = replace_plan
        .snapshot()
        .planned_artifacts()
        .iter()
        .map(|artifact| artifact.path().to_path_buf())
        .collect::<Vec<_>>();
    let planned_stage_directory = replace_plan
        .snapshot()
        .planned_artifacts()
        .iter()
        .find(|artifact| artifact.role() == OperationArtifactRole::PrivateStagingDirectory)
        .expect("plan private staging directory")
        .path()
        .to_path_buf();
    let planned_backup = replace_plan
        .snapshot()
        .planned_artifacts()
        .iter()
        .find(|artifact| artifact.role() == OperationArtifactRole::DestinationBackup)
        .expect("plan destination recovery artifact")
        .path()
        .to_path_buf();
    let planned_stage_output = replace_plan
        .snapshot()
        .planned_artifacts()
        .iter()
        .find(|artifact| artifact.role() == OperationArtifactRole::StagedOutput)
        .expect("plan staged output");
    assert_eq!(
        planned_stage_output.path().parent(),
        Some(planned_stage_directory.as_path())
    );

    let result = engine.execute_operation(replace_plan, &OperationSession::new());

    assert_eq!(result.state(), JobState::Succeeded, "{result:?}");
    assert_eq!(
        result.outcome(),
        Some(OperationOutcome::Copied),
        "{result:?}"
    );
    assert_eq!(result.failure().map(|failure| failure.code()), None);
    assert_cleanup_incomplete(&result);
    assert_artifact_paths_are_planned(&planned_paths, &result);
    assert_eq!(
        result.cleanup_warning().map(|warning| warning.code()),
        Some(OperationFailureCode::CleanupIncomplete)
    );
    assert!(result.cleanup_artifact_retained());
    assert_eq!(
        fs::read(&destination).unwrap(),
        b"synthetic copy-through bytes"
    );
    let stage_directory =
        retained_artifact(&result, OperationArtifactRole::PrivateStagingDirectory);
    let backup = retained_artifact(&result, OperationArtifactRole::DestinationBackup);
    assert_eq!(stage_directory.path(), planned_stage_directory);
    assert_eq!(backup.path(), planned_backup);
    assert_eq!(backup.path().parent(), Some(stage_directory.path()));
    assert_eq!(backup.length(), Some(original_destination.len() as u64));
    assert!(backup.sha256().is_some());
    assert_eq!(backup.path_identity_matches(), Some(true));
    assert_eq!(backup.device(), backup.path_device());
    assert_eq!(backup.inode(), backup.path_inode());
    assert_eq!(fs::read(backup.path()).unwrap(), original_destination);
}

#[test]
#[cfg(target_os = "macos")]
fn replace_refuses_a_destination_whose_baseline_changed_after_planning() {
    let (root, source, destination) = operation_paths();
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("create workspace");
    fs::write(&destination, b"planned destination").expect("write planned destination");
    let plan = Engine::new()
        .plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace)
                .with_conflict_policy(ConflictPolicy::Replace),
        )
        .expect("plan authorized replacement");
    fs::write(&destination, b"concurrent destination").expect("change destination baseline");

    let result = Engine::new().execute_operation(plan, &OperationSession::new());

    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        result.failure().unwrap().code(),
        OperationFailureCode::DestinationChanged
    );
    assert_eq!(fs::read(&destination).unwrap(), b"concurrent destination");
    assert_eq!(fs::read_dir(workspace).unwrap().count(), 0);
}

#[test]
#[cfg(target_os = "macos")]
fn planned_destination_directory_type_change_fails_before_staging_without_artifacts() {
    let root = tempdir().expect("create operation test directory");
    let source = root.path().join("source.bin");
    let destination_directory = root.path().join("destination");
    let destination = destination_directory.join("output.bin");
    let workspace = root.path().join("workspace");
    fs::write(&source, b"permission test source").expect("write source fixture");
    fs::create_dir(&destination_directory).expect("create destination directory");
    fs::create_dir(&workspace).expect("create workspace");
    let plan = Engine::new()
        .plan_copy_through(CopyThroughRequest::new(&source, &destination, &workspace))
        .expect("plan before making the destination directory unavailable");

    fs::remove_dir(&destination_directory).expect("remove planned destination directory");
    fs::write(&destination_directory, b"not a directory")
        .expect("replace planned destination directory with a regular file");

    let result = Engine::new().execute_operation(plan, &OperationSession::new());
    fs::remove_file(&destination_directory).expect("remove unavailable destination fixture");

    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        result.failure().unwrap().code(),
        OperationFailureCode::StalePlan
    );
    assert!(!result.cleanup_artifact_retained(), "{result:?}");
    assert!(result.cleanup_warning().is_none(), "{result:?}");
    assert!(result.artifacts().is_empty(), "{result:?}");
    assert!(!destination.exists());
    assert_eq!(fs::read_dir(&workspace).unwrap().count(), 0);
    assert!(!destination_directory.exists());
}

#[test]
#[cfg(target_os = "macos")]
fn unopenable_destination_lock_maps_to_destination_unavailable_through_execution() {
    let root = tempdir().expect("create operation test directory");
    let source = root.path().join("source.bin");
    let destination = root.path().join("output.bin");
    let workspace = root.path().join("workspace");
    fs::write(&source, b"destination lock failure source").expect("write source fixture");
    fs::create_dir(&workspace).expect("create workspace");
    let plan = Engine::new()
        .plan_copy_through(CopyThroughRequest::new(&source, &destination, &workspace))
        .expect("plan copy-through");
    let lock_path = plan.snapshot().destination_lock_path().to_path_buf();

    fs::create_dir(&lock_path).expect("make destination lock entry unopenable as a file");
    let result = Engine::new().execute_operation(plan, &OperationSession::new());
    fs::remove_dir(&lock_path).expect("remove destination lock fixture");

    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        result.failure().expect("operation failure").code(),
        OperationFailureCode::DestinationUnavailable
    );
    assert_eq!(result.outcome(), None);
    assert!(!result.cleanup_artifact_retained(), "{result:?}");
    assert!(result.cleanup_warning().is_none(), "{result:?}");
    assert!(result.artifacts().is_empty(), "{result:?}");
    assert_eq!(result.retained_storage_bytes(), Some(0));
    assert!(!destination.exists());
    assert_eq!(fs::read_dir(&workspace).unwrap().count(), 0);
}

#[cfg(target_os = "macos")]
#[test]
fn retargeted_parent_symlink_invalidates_the_resolved_plan() {
    use std::os::unix::fs::symlink;

    let root = tempdir().expect("create operation test directory");
    let first = root.path().join("first");
    let second = root.path().join("second");
    let workspace = root.path().join("workspace");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();
    fs::create_dir(&workspace).unwrap();
    fs::write(first.join("source.bin"), b"first source bytes").unwrap();
    fs::write(second.join("source.bin"), b"other source bytes").unwrap();
    let alias = root.path().join("source-alias");
    symlink(&first, &alias).unwrap();
    let source = alias.join("source.bin");
    let destination = root.path().join("output.bin");
    let engine = Engine::new();
    let plan = engine
        .plan_copy_through(CopyThroughRequest::new(&source, &destination, &workspace))
        .expect("plan through a resolved parent symlink");

    fs::remove_file(&alias).unwrap();
    symlink(&second, &alias).unwrap();
    let result = engine.execute_operation(plan, &OperationSession::new());

    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        result.failure().unwrap().code(),
        OperationFailureCode::StalePlan
    );
    assert!(!destination.exists());
}

#[cfg(not(target_os = "macos"))]
#[test]
fn copy_through_fails_closed_when_native_filesystem_guarantees_are_unavailable() {
    let error = Engine::new()
        .plan_copy_through(CopyThroughRequest::new(
            "source",
            "destination",
            "workspace",
        ))
        .err()
        .expect("non-macOS copy-through is not qualified");

    assert_eq!(error.code(), OperationFailureCode::UnsupportedCapability);
}
