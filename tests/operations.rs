#[cfg(target_os = "macos")]
use nscb::{
    CancellationHandle, ConflictPolicy, CopyBatchCheckpointError, CopyBatchEventKind,
    CopyBatchItemPlanState, CopyBatchItemState, CopyBatchRequest, CopyBatchSession,
    CopyBatchSessionPhase, CopyBatchSessionStatus, InputResolutionCapabilities,
    InputResolutionRequest, JobState, LocalSplitTrustStore, OperationArtifact,
    OperationArtifactRole, OperationMilestone, OperationOutcome, OperationSession, StagingStrategy,
};
use nscb::{CopyThroughRequest, DestinationBaseline, Engine, OperationFailureCode, PlannedEffect};
mod support;
#[cfg(target_os = "macos")]
use std::fs;
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStringExt;
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
#[test]
fn missing_destination_parent_is_planned_and_created_only_when_the_plan_executes() {
    let (root, source, _unused_destination) = operation_paths();
    let output_directory = root.path().join("implicit-output");
    let destination = output_directory.join("source.bin");
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("create staging workspace");
    let engine = Engine::new();

    let plan = engine
        .plan_copy_through(CopyThroughRequest::new(&source, &destination, &workspace))
        .expect("plan a missing destination parent without creating it");

    assert_eq!(
        plan.snapshot().destination(),
        root.path()
            .canonicalize()
            .unwrap()
            .join("implicit-output")
            .join("source.bin")
    );
    assert!(
        !output_directory.exists(),
        "read-only planning must not create the implicit output directory"
    );
    assert_eq!(
        serde_json::to_value(plan.snapshot().effects()).expect("serialize planned effects"),
        serde_json::json!([
            "read_source",
            "coordinate_destination",
            "create_private_staging_directory",
            "create_staging_file",
            "create_destination_parent",
            "create_destination",
        ])
    );

    let result = engine.execute_operation(plan, &OperationSession::new());

    assert_eq!(result.state(), JobState::Succeeded, "{result:?}");
    assert_eq!(result.outcome(), Some(OperationOutcome::Copied));
    assert_eq!(fs::read(destination).unwrap(), fs::read(source).unwrap());
}

#[cfg(target_os = "macos")]
#[test]
fn missing_destination_parent_created_after_planning_is_stale_and_preserved() {
    let (root, source, _unused_destination) = operation_paths();
    let output_directory = root.path().join("implicit-output");
    let destination = output_directory.join("source.bin");
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("create staging workspace");
    let engine = Engine::new();
    let plan = engine
        .plan_copy_through(CopyThroughRequest::new(&source, &destination, &workspace))
        .expect("plan a missing destination parent without creating it");

    fs::create_dir(&output_directory).expect("competing writer creates destination parent");
    fs::write(
        output_directory.join("keep.bin"),
        b"preserve competing entry",
    )
    .expect("write competing destination-parent entry");
    let result = engine.execute_operation(plan, &OperationSession::new());

    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        result.failure().unwrap().code(),
        OperationFailureCode::StalePlan
    );
    assert!(!destination.exists());
    assert_eq!(
        fs::read(output_directory.join("keep.bin")).unwrap(),
        b"preserve competing entry"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn source_planning_failure_does_not_create_the_missing_destination_parent() {
    let (root, _source, _unused_destination) = operation_paths();
    let missing_source = root.path().join("missing.bin");
    let output_directory = root.path().join("implicit-output");
    let destination = output_directory.join("missing.bin");
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("create staging workspace");

    let error = match Engine::new().plan_copy_through(CopyThroughRequest::new(
        &missing_source,
        &destination,
        &workspace,
    )) {
        Ok(_) => panic!("missing source must fail during planning"),
        Err(error) => error,
    };

    assert_eq!(error.code(), OperationFailureCode::SourceUnavailable);
    assert!(
        !output_directory.exists(),
        "source failure must not create the implicit output directory"
    );
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
fn skip_policy_reports_a_byte_identical_destination_as_already_up_to_date() {
    let (root, source, destination) = operation_paths();
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("create workspace");
    fs::copy(&source, &destination).expect("create identical destination");
    let engine = Engine::new();
    let plan = engine
        .plan_copy_through(
            CopyThroughRequest::new(&source, &destination, &workspace)
                .with_conflict_policy(ConflictPolicy::Skip),
        )
        .expect("plan an identical destination under skip");

    let result = engine.execute_operation(plan, &OperationSession::new());

    assert_eq!(result.state(), JobState::Succeeded);
    assert_eq!(result.outcome(), Some(OperationOutcome::AlreadyUpToDate));
    assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
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

/// Returns an existing directory whose filesystem differs from `reference`.
///
/// The copy-through plan only consults this directory to decide whether the
/// host workspace is qualified for the destination volume. macOS always mounts
/// devfs at `/dev`, so it provides a real cross-volume directory without
/// creating or mounting a second volume inside the test.
#[cfg(target_os = "macos")]
fn directory_on_another_filesystem(reference: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::MetadataExt;

    let reference_device = fs::metadata(reference)
        .expect("inspect destination filesystem")
        .dev();
    ["/dev", "/System/Volumes/Preboot", "/Volumes"]
        .into_iter()
        .map(std::path::PathBuf::from)
        .find(|candidate| {
            fs::metadata(candidate)
                .map(|metadata| metadata.dev() != reference_device)
                .unwrap_or(false)
        })
        .expect("locate an existing directory on another filesystem")
}

#[cfg(target_os = "macos")]
#[test]
fn cross_volume_host_workspace_falls_back_with_one_missing_output_directory() {
    let (root, source, _unused_destination) = operation_paths();
    let output_directory = root.path().join("implicit-output");
    let destination = output_directory.join("source.bin");
    let cross_volume_workspace = directory_on_another_filesystem(root.path());
    let engine = Engine::new();

    let plan = engine
        .plan_copy_through(CopyThroughRequest::with_host_default_workspace(
            &source,
            &destination,
            &cross_volume_workspace,
        ))
        .expect("plan destination-local fallback beside one missing output directory");

    assert_eq!(
        plan.snapshot().staging_strategy(),
        StagingStrategy::DestinationLocalFallback
    );
    assert_eq!(
        plan.snapshot().workspace(),
        root.path().canonicalize().unwrap()
    );
    assert!(
        !output_directory.exists(),
        "read-only planning must not create the implicit output directory"
    );
    assert_eq!(
        serde_json::to_value(plan.snapshot().effects()).expect("serialize planned effects"),
        serde_json::json!([
            "read_source",
            "coordinate_destination",
            "create_private_staging_directory",
            "create_staging_file",
            "create_destination_parent",
            "create_destination",
        ])
    );

    let result = engine.execute_operation(plan, &OperationSession::new());

    assert_eq!(result.state(), JobState::Succeeded, "{result:?}");
    assert_eq!(result.outcome(), Some(OperationOutcome::Copied));
    assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
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

#[cfg(target_os = "macos")]
fn batch_paths() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let root = tempdir().expect("create batch test directory");
    let output = root.path().join("output");
    let workspace = root.path().join("workspace");
    fs::create_dir(&output).expect("create batch output directory");
    fs::create_dir(&workspace).expect("create batch workspace");
    (root, output, workspace)
}

#[cfg(target_os = "macos")]
#[test]
fn batch_planning_rejects_duplicate_sources_keys_and_normalized_destination_collisions() {
    let (root, output, workspace) = batch_paths();
    let first = root.path().join("first.bin");
    let second = root.path().join("second.bin");
    fs::write(&first, b"first").unwrap();
    fs::write(&second, b"second").unwrap();
    let engine = Engine::new();

    let duplicate_source = engine.plan_copy_batch(
        CopyBatchRequest::new(&output, &workspace)
            .with_item(&first, output.join("first.bin"))
            .with_item(&first, output.join("alias.bin")),
    );
    assert_eq!(
        duplicate_source.err().unwrap().code(),
        OperationFailureCode::DuplicateInput
    );

    let duplicate_key = engine.plan_copy_batch(
        CopyBatchRequest::new(&output, &workspace)
            .with_keyed_item("same-key", &first, output.join("first.bin"))
            .with_keyed_item("same-key", &second, output.join("second.bin")),
    );
    assert_eq!(
        duplicate_key.err().unwrap().code(),
        OperationFailureCode::DuplicateInput
    );

    let destination_collision = engine.plan_copy_batch(
        CopyBatchRequest::new(&output, &workspace)
            .with_item(&first, output.join("shared.bin"))
            .with_item(&second, output.join("shared.bin")),
    );
    assert_eq!(
        destination_collision.err().unwrap().code(),
        OperationFailureCode::DestinationCollision
    );

    let normalized_destination = engine.plan_copy_batch(
        CopyBatchRequest::new(&output, &workspace)
            .with_item(&first, output.join("Name.bin"))
            .with_item(&second, output.join("name.bin")),
    );
    assert_eq!(
        normalized_destination.err().unwrap().code(),
        OperationFailureCode::DestinationCollision
    );

    let hardlink = root.path().join("hardlink.bin");
    fs::hard_link(&first, &hardlink).unwrap();
    let duplicate_identity = engine.plan_copy_batch(
        CopyBatchRequest::new(&output, &workspace)
            .with_item(&first, output.join("first.bin"))
            .with_item(&hardlink, output.join("hardlink.bin")),
    );
    assert_eq!(
        duplicate_identity.err().unwrap().code(),
        OperationFailureCode::DuplicateInput
    );
}

#[cfg(target_os = "macos")]
#[test]
fn batch_planning_rejects_unicode_normalization_destination_collisions() {
    let (root, output, workspace) = batch_paths();
    let first = root.path().join("first.bin");
    let second = root.path().join("second.bin");
    fs::write(&first, b"first").unwrap();
    fs::write(&second, b"second").unwrap();

    let error = Engine::new()
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&first, output.join("caf\u{e9}.bin"))
                .with_item(&second, output.join("cafe\u{301}.bin")),
        )
        .err()
        .expect("canonically equivalent destination names must collide");

    assert_eq!(error.code(), OperationFailureCode::DestinationCollision);
}

#[cfg(target_os = "macos")]
#[test]
fn batch_planning_rejects_source_destination_overlap_and_hardlink_aliases() {
    let (root, output, workspace) = batch_paths();
    let same_path = output.join("same-path.bin");
    fs::write(&same_path, b"same path source").unwrap();
    let engine = Engine::new();

    let same_path_error = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&same_path, output.join("same-path.bin")),
        )
        .err()
        .expect("a source cannot also be its destination");
    assert_eq!(same_path_error.code(), OperationFailureCode::UnsafePath);

    let source = root.path().join("source.bin");
    fs::write(&source, b"hardlink source").unwrap();
    fs::hard_link(&source, output.join("hardlink-destination.bin")).unwrap();
    let hardlink_error = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&source, output.join("hardlink-destination.bin")),
        )
        .err()
        .expect("a destination hardlink to the source is the same filesystem object");
    assert_eq!(hardlink_error.code(), OperationFailureCode::UnsafePath);
    assert_eq!(fs::read(&source).unwrap(), b"hardlink source");
}

#[cfg(target_os = "macos")]
#[test]
fn batch_planning_preserves_distinct_non_utf8_source_and_destination_names() {
    let (root, output, workspace) = batch_paths();
    let first = root
        .path()
        .join(std::ffi::OsString::from_vec(b"source-\xff.bin".to_vec()));
    let second = root
        .path()
        .join(std::ffi::OsString::from_vec(b"source-\xfe.bin".to_vec()));
    let present = root.path().join("present.bin");
    fs::write(&present, b"present").unwrap();
    let engine = Engine::new();

    let source_plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&first, output.join("first.bin"))
                .with_item(&second, output.join("second.bin"))
                .with_item(&present, output.join("present.bin")),
        )
        .expect("distinct non-UTF-8 source names must not be treated as duplicates");
    assert_eq!(source_plan.snapshot().items().len(), 3);
    assert_eq!(
        source_plan.snapshot().items()[0].state(),
        CopyBatchItemPlanState::PreflightFailed
    );
    assert_eq!(
        source_plan.snapshot().items()[1].state(),
        CopyBatchItemPlanState::PreflightFailed
    );
    assert_eq!(
        source_plan.snapshot().items()[2].state(),
        CopyBatchItemPlanState::Viable
    );

    let normal_first = root.path().join("normal-first.bin");
    let normal_second = root.path().join("normal-second.bin");
    fs::write(&normal_first, b"first").unwrap();
    fs::write(&normal_second, b"second").unwrap();
    let first_destination = output.join(std::ffi::OsString::from_vec(
        b"destination-\xff.bin".to_vec(),
    ));
    let second_destination = output.join(std::ffi::OsString::from_vec(
        b"destination-\xfe.bin".to_vec(),
    ));
    let destination_plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&normal_first, first_destination)
                .with_item(&normal_second, second_destination),
        )
        .expect("distinct non-UTF-8 destination names must not collide");
    assert_eq!(destination_plan.snapshot().items().len(), 2);
}

#[cfg(target_os = "macos")]
#[test]
fn batch_planning_keeps_only_item_local_preflight_failures_and_requires_one_viable_item() {
    let (root, output, workspace) = batch_paths();
    let present = root.path().join("present.bin");
    let missing = root.path().join("missing.bin");
    fs::write(&present, b"present").unwrap();
    let engine = Engine::new();

    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&missing, output.join("missing.bin"))
                .with_item(&present, output.join("present.bin")),
        )
        .expect("a missing ordinary source is item-local");
    assert_eq!(plan.snapshot().items().len(), 2);
    assert_eq!(
        plan.snapshot().items()[0].state(),
        CopyBatchItemPlanState::PreflightFailed
    );
    assert_eq!(
        plan.snapshot().items()[1].state(),
        CopyBatchItemPlanState::Viable
    );

    let all_failed = engine.plan_copy_batch(
        CopyBatchRequest::new(&output, &workspace).with_item(&missing, output.join("missing.bin")),
    );
    assert_eq!(
        all_failed.err().unwrap().code(),
        OperationFailureCode::SourceUnavailable
    );
}

#[cfg(target_os = "macos")]
#[test]
fn empty_directory_without_destination_is_item_local_beside_viable_copy() {
    let (root, output, workspace) = batch_paths();
    let empty_directory = root.path().join("empty-selection");
    let source = root.path().join("good.nsp");
    fs::create_dir(&empty_directory).unwrap();
    fs::write(&source, b"valid sibling").unwrap();

    let engine = Engine::new();
    let empty_failure = match engine
        .resolve_inputs_batch(
            nscb::InputResolutionRequest::new(root.path())
                .with_selection(nscb::InputSelection::Path(empty_directory.clone())),
        )
        .unwrap()
        .entries
        .into_iter()
        .next()
        .unwrap()
    {
        nscb::InputResolutionBatchEntry::Failed(failure) => failure,
        _ => panic!("empty directory must resolve to an empty-selection failure"),
    };
    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&source, output.join("good.nsp"))
                .with_resolved_empty_selection_failure(empty_failure)
                .unwrap(),
        )
        .expect("an empty directory remains an item-local failure beside viable work");

    assert_eq!(plan.snapshot().items().len(), 2);
    let expected_destination = fs::canonicalize(&output).unwrap().join("good.nsp");
    assert_eq!(
        plan.snapshot().items()[0].destination(),
        Some(expected_destination.as_path())
    );
    assert_eq!(plan.snapshot().items()[1].destination(), None);
    assert_eq!(
        plan.snapshot().items()[1].failure_code(),
        Some(OperationFailureCode::EmptySelection)
    );

    let result = engine.execute_copy_batch(plan, &CopyBatchSession::new());
    assert_eq!(result.state(), JobState::CompletedWithIssues);
    assert_eq!(result.items()[0].state(), CopyBatchItemState::Succeeded);
    assert_eq!(
        result.items()[1].state(),
        CopyBatchItemState::PreflightFailed
    );
    assert_eq!(result.items()[1].destination(), None);
    assert_eq!(
        result.items()[1].failure().map(|failure| failure.code()),
        Some(OperationFailureCode::EmptySelection)
    );
    assert_eq!(fs::read(output.join("good.nsp")).unwrap(), b"valid sibling");
}

#[cfg(target_os = "macos")]
#[test]
fn all_empty_directory_batch_fails_planning_before_admission() {
    let (root, output, workspace) = batch_paths();
    let empty_directory = root.path().join("empty-selection");
    fs::create_dir(&empty_directory).unwrap();

    let engine = Engine::new();
    let empty_failure = match engine
        .resolve_inputs_batch(
            nscb::InputResolutionRequest::new(root.path())
                .with_selection(nscb::InputSelection::Path(empty_directory.clone())),
        )
        .unwrap()
        .entries
        .into_iter()
        .next()
        .unwrap()
    {
        nscb::InputResolutionBatchEntry::Failed(failure) => failure,
        _ => panic!("empty directory must resolve to an empty-selection failure"),
    };

    let error = match engine.plan_copy_batch(
        CopyBatchRequest::new(&output, &workspace)
            .with_resolved_empty_selection_failure(empty_failure)
            .unwrap(),
    ) {
        Err(error) => error,
        Ok(_) => panic!("a batch with no viable item must fail before admission"),
    };

    assert_eq!(error.code(), OperationFailureCode::EmptySelection);
}

#[cfg(target_os = "macos")]
#[test]
fn batch_planning_rejects_untrusted_and_unsafe_split_candidates_globally() {
    use support::split_fixture::SplitFixture;

    let (root, output, workspace) = batch_paths();
    let present = root.path().join("present.bin");
    fs::write(&present, b"present").unwrap();
    let split = SplitFixture::new(b"untrusted split source", 128);
    let split_directory = split.write(root.path(), "untrusted.nsp");
    let numeric_layout = root.path().join("000");
    fs::write(&numeric_layout, b"unsafe numeric split layout").unwrap();
    let engine = Engine::new();

    for source in [&split_directory, &numeric_layout] {
        let error = engine
            .plan_copy_batch(
                CopyBatchRequest::new(&output, &workspace)
                    .with_item(source, output.join("split.nsp"))
                    .with_item(&present, output.join("present.bin")),
            )
            .err()
            .expect("untrusted or unsafe Split qualification must reject admission");
        assert_eq!(error.code(), OperationFailureCode::SplitInputUnsupported);
    }
}

#[cfg(target_os = "macos")]
#[test]
fn batch_planning_rejects_an_unqualified_split_preflight_claim_globally() {
    let (root, output, workspace) = batch_paths();
    let present = root.path().join("present.bin");
    fs::write(&present, b"present").unwrap();
    let split_directory = root.path().join("unqualified.nsp");
    fs::write(&split_directory, b"unqualified split candidate").unwrap();

    let error = Engine::new()
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_preflight_failure(
                    &split_directory,
                    output.join("unqualified.nsp"),
                    OperationFailureCode::SplitInputUnsupported,
                )
                .with_item(&present, output.join("present.bin")),
        )
        .err()
        .expect("an unqualified Split preflight claim must reject admission");

    assert_eq!(error.code(), OperationFailureCode::SplitInputUnsupported);
}

#[cfg(target_os = "macos")]
#[test]
fn batch_planning_accepts_a_qualified_split_as_one_item_local_copy_failure() {
    use support::split_fixture::SplitFixture;

    let (root, output, workspace) = batch_paths();
    let present = root.path().join("present.bin");
    fs::write(&present, b"present").unwrap();
    let split = SplitFixture::new(b"qualified split source", 128);
    let split_directory = split.write(root.path(), "qualified.nsp");
    let store = LocalSplitTrustStore::new(root.path().join("state").join("split-trust"));
    split.issue(&store);
    let engine = Engine::new();
    let resolved = engine
        .resolve_inputs_with(
            InputResolutionRequest::new(root.path()).with_path(&split_directory),
            InputResolutionCapabilities::new().with_split_trust_store(&store),
        )
        .expect("qualify the Split through host-owned trust evidence");
    assert_eq!(resolved.inputs.len(), 1);
    assert!(resolved.inputs[0].qualification.is_some());

    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_qualified_split_input_unsupported(
                    resolved.inputs[0].clone(),
                    output.join("qualified.nsp"),
                )
                .with_item(&present, output.join("present.bin")),
        )
        .expect("a qualified Split remains one item-local copy failure");
    assert_eq!(plan.snapshot().items().len(), 2);
    assert_eq!(
        plan.snapshot().items()[0].state(),
        CopyBatchItemPlanState::PreflightFailed
    );
    assert_eq!(
        plan.snapshot().items()[0].failure_code(),
        Some(OperationFailureCode::SplitInputUnsupported)
    );
    assert_eq!(
        plan.snapshot().items()[1].state(),
        CopyBatchItemPlanState::Viable
    );
}

#[cfg(target_os = "macos")]
#[test]
fn batch_skip_reports_byte_identity_truthfully_in_item_and_progress() {
    let (root, output, workspace) = batch_paths();
    let source = root.path().join("identical.bin");
    fs::write(&source, b"identical batch bytes").unwrap();
    fs::copy(&source, output.join("identical.bin")).unwrap();
    let engine = Engine::new();
    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_conflict_policy(ConflictPolicy::Skip)
                .with_item(&source, output.join("identical.bin")),
        )
        .unwrap();
    let session = CopyBatchSession::new();
    let consumer = session.subscribe_events_with_capacity(16).unwrap();

    let result = engine.execute_copy_batch(plan, &session);

    assert_eq!(result.state(), JobState::Succeeded);
    assert_eq!(result.items()[0].state(), CopyBatchItemState::Succeeded);
    assert_eq!(
        result.items()[0].outcome(),
        Some(OperationOutcome::AlreadyUpToDate)
    );
    let snapshot = session.current_operation().unwrap();
    assert_eq!(snapshot.progress().completed_items(), 1);
    assert_eq!(snapshot.progress().succeeded_items(), 1);
    assert_eq!(snapshot.progress().skipped_items(), 0);
    assert_eq!(snapshot.progress().completed_bytes(), 0);
    assert_eq!(
        snapshot.progress().total_bytes(),
        u64::try_from(b"identical batch bytes".len()).unwrap()
    );
    let mut events = Vec::new();
    while let Ok(event) = consumer.try_recv() {
        events.push(event);
    }
    let completed_item = events
        .iter()
        .find_map(|event| match event.event() {
            CopyBatchEventKind::ItemCompleted {
                state,
                outcome,
                failure_code,
                ..
            } => Some((*state, *outcome, *failure_code)),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        completed_item,
        (
            CopyBatchItemState::Succeeded,
            Some(OperationOutcome::AlreadyUpToDate),
            None
        )
    );
}

#[cfg(target_os = "macos")]
#[test]
fn conflict_skip_does_not_claim_untouched_source_bytes() {
    let (root, output, workspace) = batch_paths();
    let source = root.path().join("conflict.bin");
    fs::write(&source, b"source bytes").unwrap();
    fs::write(output.join("conflict.bin"), b"existing destination").unwrap();
    let engine = Engine::new();
    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_conflict_policy(ConflictPolicy::Skip)
                .with_item(&source, output.join("conflict.bin")),
        )
        .unwrap();
    let session = CopyBatchSession::new();

    let result = engine.execute_copy_batch(plan, &session);

    assert_eq!(result.state(), JobState::Succeeded);
    assert_eq!(result.items()[0].state(), CopyBatchItemState::Skipped);
    assert_eq!(result.items()[0].outcome(), Some(OperationOutcome::Skipped));
    let snapshot = session.current_operation().unwrap();
    assert_eq!(snapshot.progress().completed_items(), 1);
    assert_eq!(snapshot.progress().skipped_items(), 1);
    assert_eq!(snapshot.progress().completed_bytes(), 0);
    assert_eq!(
        fs::read(output.join("conflict.bin")).unwrap(),
        b"existing destination"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn skipped_item_does_not_hide_the_only_engine_failure() {
    let (root, output, workspace) = batch_paths();
    let skipped_source = root.path().join("skip.bin");
    let disappearing_source = root.path().join("removed-after-planning.bin");
    fs::write(&skipped_source, b"new bytes").unwrap();
    fs::write(&disappearing_source, b"bytes planned for copy").unwrap();
    fs::write(output.join("skip.bin"), b"existing bytes").unwrap();

    let engine = Engine::new();
    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_conflict_policy(ConflictPolicy::Skip)
                .with_item(&skipped_source, output.join("skip.bin"))
                .with_item(
                    &disappearing_source,
                    output.join("removed-after-planning.bin"),
                ),
        )
        .unwrap();
    fs::remove_file(&disappearing_source).unwrap();

    let result = engine.execute_copy_batch(plan, &CopyBatchSession::new());

    assert_eq!(result.items()[0].state(), CopyBatchItemState::Skipped);
    assert!(matches!(
        result.items()[1].state(),
        CopyBatchItemState::Failed | CopyBatchItemState::PreflightFailed
    ));
    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        fs::read(output.join("skip.bin")).unwrap(),
        b"existing bytes"
    );
    assert!(!output.join("removed-after-planning.bin").exists());
}

#[cfg(target_os = "macos")]
#[test]
fn item_completion_is_published_only_after_checkpoint_acknowledgement() {
    let (root, output, workspace) = batch_paths();
    let source = root.path().join("checkpoint-ack.bin");
    fs::write(&source, b"checkpointed bytes").unwrap();
    let engine = Engine::new();
    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&source, output.join("checkpoint-ack.bin")),
        )
        .unwrap();
    let session = CopyBatchSession::new();
    let consumer = session.subscribe_events_with_capacity(16).unwrap();
    let (checkpoint_entered_tx, checkpoint_entered_rx) = std::sync::mpsc::channel();
    let (checkpoint_release_tx, checkpoint_release_rx) = std::sync::mpsc::channel();
    let (inspect_tx, inspect_rx) = std::sync::mpsc::channel();
    let (continue_tx, continue_rx) = std::sync::mpsc::channel();
    let (before_tx, before_rx) = std::sync::mpsc::channel();
    let (after_tx, after_rx) = std::sync::mpsc::channel();

    let observer = std::thread::spawn(move || {
        inspect_rx.recv().unwrap();
        let mut before = Vec::new();
        while let Ok(event) = consumer.try_recv() {
            before.push(event);
        }
        before_tx.send(before).unwrap();
        continue_rx.recv().unwrap();
        let mut after = Vec::new();
        while let Ok(event) = consumer.try_recv() {
            after.push(event);
        }
        after_tx.send(after).unwrap();
    });
    let execution = std::thread::spawn(move || {
        engine.execute_copy_batch_with_checkpoint(
            plan,
            &session,
            CancellationHandle::new(),
            move |checkpoint| {
                checkpoint_entered_tx.send(checkpoint.sequence()).unwrap();
                checkpoint_release_rx.recv().unwrap();
                Ok(())
            },
        )
    });

    let checkpoint_sequence = checkpoint_entered_rx.recv().unwrap();
    inspect_tx.send(()).unwrap();
    let before_ack = before_rx.recv().unwrap();
    checkpoint_release_tx.send(()).unwrap();
    let result = execution.join().unwrap();
    continue_tx.send(()).unwrap();
    let after_ack = after_rx.recv().unwrap();
    observer.join().unwrap();

    assert_eq!(checkpoint_sequence, 1);
    assert_eq!(result.result().state(), JobState::Succeeded);
    assert!(
        !before_ack
            .iter()
            .any(|event| matches!(event.event(), CopyBatchEventKind::ItemCompleted { .. }))
    );
    assert_eq!(
        after_ack
            .iter()
            .filter(|event| matches!(event.event(), CopyBatchEventKind::ItemCompleted { .. }))
            .count(),
        1
    );
    let sequences = before_ack
        .iter()
        .chain(after_ack.iter())
        .map(|event| event.sequence())
        .collect::<Vec<_>>();
    assert!(sequences.windows(2).all(|pair| pair[0] < pair[1]));
}

#[cfg(target_os = "macos")]
#[test]
fn failed_checkpoint_never_publishes_item_completion() {
    let (root, output, workspace) = batch_paths();
    let first = root.path().join("checkpoint-fail-first.bin");
    let second = root.path().join("checkpoint-fail-second.bin");
    fs::write(&first, b"first item").unwrap();
    fs::write(&second, b"second item").unwrap();
    let engine = Engine::new();
    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&first, output.join("checkpoint-fail-first.bin"))
                .with_item(&second, output.join("checkpoint-fail-second.bin")),
        )
        .unwrap();
    let session = CopyBatchSession::new();
    let consumer = session.subscribe_events_with_capacity(16).unwrap();
    let (checkpoint_entered_tx, checkpoint_entered_rx) = std::sync::mpsc::channel();
    let (checkpoint_release_tx, checkpoint_release_rx) = std::sync::mpsc::channel();
    let (inspect_tx, inspect_rx) = std::sync::mpsc::channel();
    let (continue_tx, continue_rx) = std::sync::mpsc::channel();
    let (before_tx, before_rx) = std::sync::mpsc::channel();
    let (after_tx, after_rx) = std::sync::mpsc::channel();

    let observer = std::thread::spawn(move || {
        inspect_rx.recv().unwrap();
        let mut before = Vec::new();
        while let Ok(event) = consumer.try_recv() {
            before.push(event);
        }
        before_tx.send(before).unwrap();
        continue_rx.recv().unwrap();
        let mut after = Vec::new();
        while let Ok(event) = consumer.try_recv() {
            after.push(event);
        }
        after_tx.send(after).unwrap();
    });
    let execution = std::thread::spawn(move || {
        engine.execute_copy_batch_with_checkpoint(
            plan,
            &session,
            CancellationHandle::new(),
            move |_| {
                checkpoint_entered_tx.send(()).unwrap();
                checkpoint_release_rx.recv().unwrap();
                Err(CopyBatchCheckpointError)
            },
        )
    });

    checkpoint_entered_rx.recv().unwrap();
    inspect_tx.send(()).unwrap();
    let before_ack = before_rx.recv().unwrap();
    checkpoint_release_tx.send(()).unwrap();
    let result = execution.join().unwrap();
    continue_tx.send(()).unwrap();
    let after_ack = after_rx.recv().unwrap();
    observer.join().unwrap();

    assert_eq!(result.result().state(), JobState::Failed);
    assert_eq!(
        result.result().items()[1].state(),
        CopyBatchItemState::NotStarted
    );
    assert!(
        !before_ack
            .iter()
            .any(|event| matches!(event.event(), CopyBatchEventKind::ItemCompleted { .. }))
    );
    assert!(
        !after_ack
            .iter()
            .any(|event| matches!(event.event(), CopyBatchEventKind::ItemCompleted { .. }))
    );
    assert!(
        after_ack
            .iter()
            .any(|event| matches!(event.event(), CopyBatchEventKind::CheckpointFailed { .. }))
    );
}

#[cfg(target_os = "macos")]
#[test]
fn batch_checkpoint_order_is_monotonic_and_checkpoint_failure_stops_later_items() {
    let (root, output, workspace) = batch_paths();
    let first = root.path().join("first.bin");
    let second = root.path().join("second.bin");
    fs::write(&first, b"first checkpoint bytes").unwrap();
    fs::write(&second, b"second checkpoint bytes").unwrap();
    let engine = Engine::new();
    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&first, output.join("first.bin"))
                .with_item(&second, output.join("second.bin")),
        )
        .unwrap();
    let session = CopyBatchSession::new();
    let consumer = session.subscribe_events_with_capacity(16).unwrap();
    let mut checkpoints = Vec::new();
    let execution = engine.execute_copy_batch_with_checkpoint(
        plan,
        &session,
        CancellationHandle::new(),
        |checkpoint| {
            checkpoints.push((
                checkpoint.sequence(),
                checkpoint.item().item_key().to_owned(),
            ));
            Ok(())
        },
    );
    assert_eq!(execution.result().state(), JobState::Succeeded);
    assert_eq!(checkpoints.len(), 2);
    assert_eq!(
        checkpoints
            .iter()
            .map(|checkpoint| checkpoint.0)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(checkpoints[0].1, "batch-item-0001");
    assert_eq!(checkpoints[1].1, "batch-item-0002");
    assert!(execution.failed_checkpoint().is_none());
    let mut events = Vec::new();
    while let Ok(event) = consumer.try_recv() {
        events.push(event);
    }
    assert!(matches!(
        events.first().map(|event| event.event()),
        Some(CopyBatchEventKind::Started { total_items: 2, .. })
    ));
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.event(), CopyBatchEventKind::Completed { .. }))
            .count(),
        1
    );
    assert!(
        events
            .iter()
            .enumerate()
            .all(|(index, event)| event.sequence() == index as u64)
    );
    assert_eq!(
        session
            .current_operation()
            .unwrap()
            .progress()
            .completed_items(),
        2
    );

    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&first, output.join("failed-checkpoint-first.bin"))
                .with_item(&second, output.join("failed-checkpoint-second.bin")),
        )
        .unwrap();
    let failed_session = CopyBatchSession::new();
    let failed = engine.execute_copy_batch_with_checkpoint(
        plan,
        &failed_session,
        CancellationHandle::new(),
        |_| Err(CopyBatchCheckpointError),
    );
    assert_eq!(failed.result().state(), JobState::Failed);
    assert_eq!(
        failed.result().failure().unwrap().code(),
        OperationFailureCode::CheckpointFailed
    );
    assert_eq!(
        failed.failed_checkpoint().unwrap().item().state(),
        CopyBatchItemState::Succeeded
    );
    assert_eq!(
        failed.result().items()[1].state(),
        CopyBatchItemState::NotStarted
    );
}

#[cfg(target_os = "macos")]
#[test]
fn checkpoint_failure_keeps_precedence_over_accepted_cancellation() {
    let (root, output, workspace) = batch_paths();
    let source = root.path().join("checkpoint-cancel.bin");
    fs::write(&source, b"checkpoint cancellation bytes").unwrap();
    let engine = Engine::new();
    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&source, output.join("checkpoint-cancel.bin")),
        )
        .unwrap();
    let session = CopyBatchSession::new();
    let consumer = session.subscribe_events_with_capacity(16).unwrap();
    let cancellation = CancellationHandle::new();
    let checkpoint_cancellation = cancellation.clone();

    let execution =
        engine.execute_copy_batch_with_checkpoint(plan, &session, cancellation, move |_| {
            checkpoint_cancellation.cancel();
            Err(CopyBatchCheckpointError)
        });

    assert!(execution.checkpoint_failed());
    assert_eq!(execution.result().state(), JobState::Failed);
    assert_eq!(
        execution.result().failure().unwrap().code(),
        OperationFailureCode::CheckpointFailed
    );
    let snapshot = session.current_operation().unwrap();
    assert_eq!(snapshot.phase(), CopyBatchSessionPhase::Idle);
    assert_eq!(snapshot.status(), CopyBatchSessionStatus::Failed);

    let mut events = Vec::new();
    while let Ok(event) = consumer.try_recv() {
        events.push(event);
    }
    assert_eq!(
        events
            .iter()
            .filter_map(|event| match event.event() {
                CopyBatchEventKind::CancellationRequested { accepted } => Some(*accepted),
                _ => None,
            })
            .collect::<Vec<_>>(),
        vec![true]
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event.event(), CopyBatchEventKind::CheckpointFailed { .. }))
    );
    assert!(matches!(
        events.last().map(|event| event.event()),
        Some(CopyBatchEventKind::Completed { result })
            if result.state() == JobState::Failed
                && result.failure().map(|failure| failure.code())
                    == Some(OperationFailureCode::CheckpointFailed)
    ));
    assert!(!events.iter().any(|event| matches!(
        event.event(),
        CopyBatchEventKind::Completed { result }
            if result.state() == JobState::Succeeded || result.state() == JobState::Cancelled
    )));
}

#[cfg(target_os = "macos")]
#[test]
fn batch_execution_revalidates_destination_identity_and_writability_after_planning() {
    let (root, output, workspace) = batch_paths();
    let source = root.path().join("source.bin");
    fs::write(&source, b"destination revalidation bytes").unwrap();
    let engine = Engine::new();
    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&source, output.join("source.bin")),
        )
        .unwrap();
    let moved = root.path().join("moved-output");
    fs::rename(&output, &moved).unwrap();
    fs::create_dir(&output).unwrap();
    let result = engine.execute_copy_batch(plan, &CopyBatchSession::new());
    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        result.items()[0].failure().unwrap().code(),
        OperationFailureCode::StalePlan
    );
    assert!(!output.join("source.bin").exists());

    let (root, output, workspace) = batch_paths();
    let source = root.path().join("source.bin");
    fs::write(&source, b"destination writability bytes").unwrap();
    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&source, output.join("source.bin")),
        )
        .unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&output, fs::Permissions::from_mode(0o555)).unwrap();
    let result = engine.execute_copy_batch(plan, &CopyBatchSession::new());
    fs::set_permissions(&output, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        result.items()[0].failure().unwrap().code(),
        OperationFailureCode::DestinationUnavailable
    );
    assert!(!output.join("source.bin").exists());
}

#[cfg(target_os = "macos")]
#[test]
fn no_consumer_batch_completes_and_retains_terminal_completion() {
    let (root, output, workspace) = batch_paths();
    let first = root.path().join("first.bin");
    let second = root.path().join("second.bin");
    fs::write(&first, b"first no-consumer source").unwrap();
    fs::write(&second, b"second no-consumer source").unwrap();
    let engine = Engine::new();
    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&first, output.join("first.bin"))
                .with_item(&second, output.join("second.bin")),
        )
        .unwrap();
    let session = CopyBatchSession::new();

    let result = engine.execute_copy_batch(plan, &session);

    assert_eq!(result.state(), JobState::Succeeded);
    assert_eq!(
        fs::read(output.join("first.bin")).unwrap(),
        b"first no-consumer source"
    );
    assert_eq!(
        fs::read(output.join("second.bin")).unwrap(),
        b"second no-consumer source"
    );
    assert_eq!(session.last_result().unwrap(), Some(result.clone()));
    let completion = session
        .last_completion()
        .unwrap()
        .expect("batch completion is retained without a consumer");
    assert_eq!(completion.sequence(), 5);
    assert_eq!(completion.result(), &result);
    assert_eq!(completion.snapshot().phase(), CopyBatchSessionPhase::Idle);
    assert_eq!(
        completion.snapshot().status(),
        CopyBatchSessionStatus::Succeeded
    );
    assert_eq!(completion.snapshot().progress().completed_items(), 2);
}

#[cfg(target_os = "macos")]
#[test]
fn bounded_batch_event_delivery_preserves_semantic_sequence() {
    let (root, output, workspace) = batch_paths();
    let first = root.path().join("first.bin");
    let second = root.path().join("second.bin");
    fs::write(&first, b"first bounded-event source").unwrap();
    fs::write(&second, b"second bounded-event source").unwrap();
    let plan = Engine::new()
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&first, output.join("first.bin"))
                .with_item(&second, output.join("second.bin")),
        )
        .unwrap();
    let session = CopyBatchSession::new();
    let consumer = session.subscribe_events_with_capacity(1).unwrap();
    let producer_session = session.clone();
    let producer =
        std::thread::spawn(move || Engine::new().execute_copy_batch(plan, &producer_session));

    let result = producer.join().unwrap();
    let events = std::iter::from_fn(|| consumer.try_recv().ok()).collect::<Vec<_>>();

    assert_eq!(result.state(), JobState::Succeeded);
    assert_eq!(
        events.len(),
        6,
        "one start, two item pairs, and one terminal"
    );
    assert!(matches!(
        events.first().map(|event| event.event()),
        Some(CopyBatchEventKind::Started { total_items: 2, .. })
    ));
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.event(), CopyBatchEventKind::ItemStarted { .. }))
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.event(), CopyBatchEventKind::ItemCompleted { .. }))
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.event(), CopyBatchEventKind::Completed { .. }))
            .count(),
        1
    );
    assert!(
        events
            .iter()
            .enumerate()
            .all(|(index, event)| event.sequence() == index as u64)
    );
    assert!(matches!(
        consumer.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Disconnected)
    ));
    assert_eq!(
        session
            .last_completion()
            .unwrap()
            .expect("terminal completion retained")
            .result()
            .state(),
        JobState::Succeeded
    );
}

#[cfg(target_os = "macos")]
#[test]
fn batch_events_are_single_consumer_and_report_mixed_progress_in_order() {
    let (root, output, workspace) = batch_paths();
    let succeeded = root.path().join("succeeded.bin");
    let missing = root.path().join("missing.bin");
    let conflicted = root.path().join("conflicted.bin");
    fs::write(&succeeded, b"successful bytes").unwrap();
    fs::write(&conflicted, b"replacement bytes").unwrap();
    fs::write(output.join("conflicted.bin"), b"operator bytes").unwrap();

    let engine = Engine::new();
    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&succeeded, output.join("succeeded.bin"))
                .with_item(&missing, output.join("missing.bin"))
                .with_item(&conflicted, output.join("conflicted.bin")),
        )
        .unwrap();
    let session = CopyBatchSession::new();
    let consumer = session.subscribe_events_with_capacity(32).unwrap();
    assert_eq!(
        session.subscribe_events().unwrap_err(),
        OperationFailureCode::EventConsumerUnavailable
    );

    let execution = engine.execute_copy_batch(plan, &session);

    assert_eq!(execution.state(), JobState::CompletedWithIssues);
    assert_eq!(
        execution
            .items()
            .iter()
            .map(|item| item.state())
            .collect::<Vec<_>>(),
        vec![
            CopyBatchItemState::Succeeded,
            CopyBatchItemState::PreflightFailed,
            CopyBatchItemState::Failed,
        ]
    );
    let snapshot = session.current_operation().unwrap();
    assert_eq!(snapshot.phase(), CopyBatchSessionPhase::Idle);
    assert_eq!(
        snapshot.status(),
        CopyBatchSessionStatus::CompletedWithIssues
    );
    assert_eq!(snapshot.progress().total_items(), 3);
    assert_eq!(snapshot.progress().completed_items(), 3);
    assert_eq!(snapshot.progress().succeeded_items(), 1);
    assert_eq!(snapshot.progress().failed_items(), 2);
    assert_eq!(snapshot.progress().skipped_items(), 0);
    assert_eq!(snapshot.progress().cancelled_items(), 0);
    assert_eq!(snapshot.progress().current_item_key(), None);

    let mut events = Vec::new();
    while let Ok(event) = consumer.try_recv() {
        events.push(event);
    }
    assert!(matches!(
        events.first().map(|event| event.event()),
        Some(CopyBatchEventKind::Started { total_items: 3, .. })
    ));
    assert!(matches!(
        events.last().map(|event| event.event()),
        Some(CopyBatchEventKind::Completed { .. })
    ));
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.event(), CopyBatchEventKind::Completed { .. }))
            .count(),
        1
    );
    assert!(
        events
            .iter()
            .enumerate()
            .all(|(index, event)| event.sequence() == index as u64)
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.event(), CopyBatchEventKind::ItemCompleted { .. }))
            .count(),
        3
    );
}

#[cfg(target_os = "macos")]
#[test]
fn preflight_failure_preserves_cumulative_batch_bytes_and_item_progress() {
    let (root, output, workspace) = batch_paths();
    let first = root.path().join("first-100.bin");
    let missing = root.path().join("missing.bin");
    let last = root.path().join("last-50.bin");
    fs::write(&first, vec![0x11; 100]).unwrap();
    fs::write(&last, vec![0x22; 50]).unwrap();

    let engine = Engine::new();
    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&first, output.join("first-100.bin"))
                .with_item(&missing, output.join("missing.bin"))
                .with_item(&last, output.join("last-50.bin")),
        )
        .unwrap();
    let session = CopyBatchSession::new();
    let consumer = session.subscribe_events_with_capacity(16).unwrap();
    let mut checkpoints = Vec::new();

    let execution = engine.execute_copy_batch_with_checkpoint(
        plan,
        &session,
        CancellationHandle::new(),
        |_| {
            checkpoints.push(session.current_operation().unwrap().progress().clone());
            Ok(())
        },
    );

    assert_eq!(execution.result().state(), JobState::CompletedWithIssues);
    assert_eq!(
        execution
            .result()
            .items()
            .iter()
            .map(|item| item.state())
            .collect::<Vec<_>>(),
        vec![
            CopyBatchItemState::Succeeded,
            CopyBatchItemState::PreflightFailed,
            CopyBatchItemState::Succeeded,
        ]
    );
    assert_eq!(checkpoints.len(), 3);
    assert_eq!(checkpoints[0].completed_bytes(), 100);
    assert_eq!(checkpoints[0].current_item_completed_bytes(), 100);
    assert_eq!(checkpoints[0].current_item_total_bytes(), 100);
    assert_eq!(checkpoints[1].completed_bytes(), 100);
    assert_eq!(checkpoints[1].current_item_key(), None);
    assert_eq!(checkpoints[1].current_item_completed_bytes(), 0);
    assert_eq!(checkpoints[2].completed_bytes(), 150);
    assert_eq!(checkpoints[2].current_item_key(), Some("batch-item-0003"));
    assert_eq!(checkpoints[2].current_item_completed_bytes(), 50);
    assert_eq!(checkpoints[2].current_item_total_bytes(), 50);

    let events = std::iter::from_fn(|| consumer.try_recv().ok()).collect::<Vec<_>>();
    let completed = events
        .iter()
        .filter_map(|event| match event.event() {
            CopyBatchEventKind::ItemCompleted {
                item_key,
                state,
                failure_code,
                ..
            } => Some((
                item_key.as_str(),
                *state,
                *failure_code,
                event.snapshot().progress().completed_bytes(),
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        completed,
        vec![
            ("batch-item-0001", CopyBatchItemState::Succeeded, None, 100,),
            (
                "batch-item-0002",
                CopyBatchItemState::PreflightFailed,
                Some(OperationFailureCode::SourceUnavailable),
                100,
            ),
            ("batch-item-0003", CopyBatchItemState::Succeeded, None, 150,),
        ]
    );
    let aggregate_bytes = events
        .iter()
        .map(|event| event.snapshot().progress().completed_bytes())
        .collect::<Vec<_>>();
    assert!(aggregate_bytes.windows(2).all(|pair| pair[0] <= pair[1]));
    assert_eq!(
        fs::read(output.join("first-100.bin")).unwrap(),
        vec![0x11; 100]
    );
    assert_eq!(
        fs::read(output.join("last-50.bin")).unwrap(),
        vec![0x22; 50]
    );
}

#[cfg(target_os = "macos")]
#[test]
fn pre_start_cancellation_preserves_cumulative_batch_bytes() {
    let (root, output, workspace) = batch_paths();
    let first = root.path().join("first-100.bin");
    let second = root.path().join("cancelled-50.bin");
    fs::write(&first, vec![0x11; 100]).unwrap();
    fs::write(&second, vec![0x22; 50]).unwrap();

    let engine = Engine::new();
    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&first, output.join("first-100.bin"))
                .with_item(&second, output.join("cancelled-50.bin")),
        )
        .unwrap();
    let session = CopyBatchSession::new();
    let consumer = session.subscribe_events_with_capacity(16).unwrap();
    let mut checkpoints = Vec::new();
    let mut cancellation_accepted = false;

    let execution = engine.execute_copy_batch_with_checkpoint(
        plan,
        &session,
        CancellationHandle::new(),
        |_| {
            checkpoints.push(session.current_operation().unwrap().progress().clone());
            if !cancellation_accepted {
                cancellation_accepted = session.cancel();
            }
            Ok(())
        },
    );

    assert!(cancellation_accepted);
    assert_eq!(execution.result().state(), JobState::Cancelled);
    assert_eq!(
        execution
            .result()
            .items()
            .iter()
            .map(|item| item.state())
            .collect::<Vec<_>>(),
        vec![CopyBatchItemState::Succeeded, CopyBatchItemState::Cancelled]
    );
    assert_eq!(checkpoints.len(), 2);
    assert_eq!(checkpoints[0].completed_bytes(), 100);
    assert_eq!(checkpoints[0].current_item_completed_bytes(), 100);
    assert_eq!(checkpoints[1].completed_bytes(), 100);
    assert_eq!(checkpoints[1].current_item_key(), None);
    assert_eq!(checkpoints[1].current_item_completed_bytes(), 0);
    assert_eq!(checkpoints[1].current_item_total_bytes(), 0);

    let events = std::iter::from_fn(|| consumer.try_recv().ok()).collect::<Vec<_>>();
    let completed = events
        .iter()
        .filter_map(|event| match event.event() {
            CopyBatchEventKind::ItemCompleted {
                item_key, state, ..
            } => Some((
                item_key.as_str(),
                *state,
                event.snapshot().progress().completed_bytes(),
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        completed,
        vec![
            ("batch-item-0001", CopyBatchItemState::Succeeded, 100),
            ("batch-item-0002", CopyBatchItemState::Cancelled, 100),
        ]
    );
    let aggregate_bytes = events
        .iter()
        .map(|event| event.snapshot().progress().completed_bytes())
        .collect::<Vec<_>>();
    assert!(aggregate_bytes.windows(2).all(|pair| pair[0] <= pair[1]));
    assert_eq!(
        fs::read(output.join("first-100.bin")).unwrap(),
        vec![0x11; 100]
    );
    assert!(!output.join("cancelled-50.bin").exists());
}

#[cfg(target_os = "macos")]
#[test]
fn pre_cancelled_batch_handle_emits_one_cancellation_transition() {
    let (root, output, workspace) = batch_paths();
    let source = root.path().join("pre-cancelled.bin");
    fs::write(&source, b"pre-cancelled batch bytes").unwrap();
    let engine = Engine::new();
    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&source, output.join("pre-cancelled.bin")),
        )
        .unwrap();
    let session = CopyBatchSession::new();
    let consumer = session.subscribe_events_with_capacity(16).unwrap();
    let cancellation = CancellationHandle::new();
    cancellation.cancel();

    let execution =
        engine.execute_copy_batch_with_checkpoint(plan, &session, cancellation, |_| Ok(()));

    assert_eq!(execution.result().state(), JobState::Cancelled);
    assert_eq!(
        execution.result().items()[0].state(),
        CopyBatchItemState::Cancelled
    );
    assert!(!output.join("pre-cancelled.bin").exists());
    assert_eq!(
        session.current_operation().unwrap().status(),
        CopyBatchSessionStatus::Cancelled
    );
    let mut events = Vec::new();
    while let Ok(event) = consumer.try_recv() {
        events.push(event);
    }
    let transitions = events
        .iter()
        .filter_map(|event| match event.event() {
            CopyBatchEventKind::CancellationRequested { accepted } => {
                Some((*accepted, event.snapshot().status()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        transitions,
        vec![(true, CopyBatchSessionStatus::CancellationRequested)]
    );
}

#[cfg(target_os = "macos")]
#[test]
fn accepted_batch_cancellation_stops_only_unfinished_items() {
    let (root, output, workspace) = batch_paths();
    let first = root.path().join("first.bin");
    let second = root.path().join("second.bin");
    fs::write(&first, b"first cancellation bytes").unwrap();
    fs::write(&second, b"second cancellation bytes").unwrap();
    let engine = Engine::new();
    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&first, output.join("first.bin"))
                .with_item(&second, output.join("second.bin")),
        )
        .unwrap();
    let session = CopyBatchSession::new();
    let consumer = session.subscribe_events_with_capacity(16).unwrap();
    let mut cancellation_accepted = false;
    let execution = engine.execute_copy_batch_with_checkpoint(
        plan,
        &session,
        CancellationHandle::new(),
        |_| {
            if !cancellation_accepted {
                cancellation_accepted = session.cancel();
            }
            Ok(())
        },
    );

    assert!(cancellation_accepted);
    assert_eq!(execution.result().state(), JobState::Cancelled);
    assert_eq!(
        execution
            .result()
            .items()
            .iter()
            .map(|item| item.state())
            .collect::<Vec<_>>(),
        vec![CopyBatchItemState::Succeeded, CopyBatchItemState::Cancelled]
    );
    assert_eq!(
        fs::read(output.join("first.bin")).unwrap(),
        b"first cancellation bytes"
    );
    assert!(!output.join("second.bin").exists());

    let mut events = Vec::new();
    while let Ok(event) = consumer.try_recv() {
        events.push(event);
    }
    assert_eq!(
        events
            .iter()
            .filter(|event| {
                matches!(
                    event.event(),
                    CopyBatchEventKind::CancellationRequested { accepted: true }
                )
            })
            .count(),
        1
    );
    assert!(matches!(
        events.last().map(|event| event.event()),
        Some(CopyBatchEventKind::Completed { .. })
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn cancellation_after_the_last_item_checkpoint_controls_the_terminal_result() {
    let (root, output, workspace) = batch_paths();
    let source = root.path().join("last-item.bin");
    fs::write(&source, b"completed item before cancellation").unwrap();
    let engine = Engine::new();
    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&source, output.join("last-item.bin")),
        )
        .unwrap();
    let session = CopyBatchSession::new();
    let consumer = session.subscribe_events_with_capacity(16).unwrap();
    let mut cancellation_accepted = false;
    let execution = engine.execute_copy_batch_with_checkpoint(
        plan,
        &session,
        CancellationHandle::new(),
        |_| {
            cancellation_accepted = session.cancel();
            Ok(())
        },
    );

    assert!(cancellation_accepted);
    assert_eq!(execution.result().state(), JobState::Cancelled);
    assert_eq!(
        execution.result().items()[0].state(),
        CopyBatchItemState::Succeeded
    );
    let completion = session.last_completion().unwrap().unwrap();
    assert_eq!(completion.result().state(), JobState::Cancelled);
    assert_eq!(
        session.current_operation().unwrap().status(),
        CopyBatchSessionStatus::Cancelled
    );
    assert_eq!(
        fs::read(output.join("last-item.bin")).unwrap(),
        b"completed item before cancellation"
    );

    let mut events = Vec::new();
    while let Ok(event) = consumer.try_recv() {
        events.push(event);
    }
    assert_eq!(
        events
            .iter()
            .filter_map(|event| match event.event() {
                CopyBatchEventKind::CancellationRequested { accepted } => Some(*accepted),
                _ => None,
            })
            .collect::<Vec<_>>(),
        vec![true]
    );
    assert!(matches!(
        events.last().map(|event| event.event()),
        Some(CopyBatchEventKind::Completed { result })
            if result.state() == JobState::Cancelled
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn dropping_the_event_consumer_mid_batch_allows_resubscription_after_completion() {
    let (root, output, workspace) = batch_paths();
    let source = root.path().join("consumer-drop.bin");
    fs::write(&source, b"consumer lifecycle bytes").unwrap();
    let engine = Engine::new();
    let plan = engine
        .plan_copy_batch(
            CopyBatchRequest::new(&output, &workspace)
                .with_item(&source, output.join("consumer-drop.bin")),
        )
        .unwrap();
    let session = CopyBatchSession::new();
    let mut consumer = Some(session.subscribe_events_with_capacity(16).unwrap());

    let execution = engine.execute_copy_batch_with_checkpoint(
        plan,
        &session,
        CancellationHandle::new(),
        |_| {
            drop(consumer.take());
            assert_eq!(
                session.subscribe_events().unwrap_err(),
                OperationFailureCode::EventConsumerUnavailable,
                "active batch must keep its single-consumer claim"
            );
            Ok(())
        },
    );

    assert_eq!(execution.result().state(), JobState::Succeeded);
    let replacement = session
        .subscribe_events()
        .expect("completed batch must release a dropped consumer's claim");
    drop(replacement);
}
