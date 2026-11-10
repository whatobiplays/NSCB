use nscb::{Engine, LocalSplitTrustStore, SplitRequest};
#[cfg(target_os = "macos")]
use nscb::{OperationOutcome, OperationSession};
#[cfg(target_os = "macos")]
use serde_json::json;
use std::fs;

#[cfg(target_os = "macos")]
#[test]
fn source_backed_split_returns_both_paths_and_resolves_after_source_removal() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("loose.nca");
    fs::create_dir(root.path().join("output")).unwrap();
    let bundle = fs::canonicalize(root.path().join("output"))
        .unwrap()
        .join("loose.nca.split");
    let source_bytes = b"generic source bytes, not a content-recognition claim";
    fs::write(&source, source_bytes).unwrap();
    let trust = LocalSplitTrustStore::new(root.path().join("state").join("split-trust"));
    let engine = Engine::new();

    let plan = engine
        .plan_split(SplitRequest::new(&source, &bundle), &trust)
        .unwrap();
    assert_eq!(plan.snapshot().bundle_directory(), bundle);
    assert_eq!(
        plan.snapshot().canonical_directory(),
        bundle.join("loose.nca")
    );

    let session = OperationSession::new();
    let result = engine.execute_split(plan, &session);
    assert_eq!(result.outcome(), Some(OperationOutcome::SplitCreated));
    assert_eq!(result.artifacts().len(), 4);
    assert!(result.artifacts().iter().all(|artifact| {
        artifact.role() == nscb::OperationArtifactRole::PublishedDestination
            && artifact.path_identity_matches() == Some(true)
    }));
    let output = result.split_output_paths().unwrap();
    assert_eq!(output.bundle_directory(), bundle);
    assert_eq!(output.canonical_directory(), bundle.join("loose.nca"));
    let bundle_artifact = result
        .artifacts()
        .iter()
        .find(|artifact| artifact.path() == output.bundle_directory())
        .unwrap();
    let canonical_artifact = result
        .artifacts()
        .iter()
        .find(|artifact| artifact.path() == output.canonical_directory())
        .unwrap();
    let segment_artifact = result
        .artifacts()
        .iter()
        .find(|artifact| artifact.path() == output.canonical_directory().join("00"))
        .unwrap();
    let manifest_artifact = result
        .artifacts()
        .iter()
        .find(|artifact| {
            artifact.path() == output.bundle_directory().join("loose.nca.nscb-split.json")
        })
        .unwrap();
    assert_eq!(
        canonical_artifact.parent_artifact_id(),
        Some(bundle_artifact.artifact_id())
    );
    assert_eq!(
        segment_artifact.parent_artifact_id(),
        Some(canonical_artifact.artifact_id())
    );
    assert_eq!(
        manifest_artifact.parent_artifact_id(),
        Some(bundle_artifact.artifact_id())
    );
    assert_eq!(segment_artifact.length(), Some(source_bytes.len() as u64));
    assert_eq!(
        segment_artifact.sha256(),
        Some(nscb::Sha256Digest::digest(source_bytes))
    );
    assert_eq!(result.retained_storage_bytes(), Some(0));
    assert_eq!(
        fs::read(output.canonical_directory().join("00")).unwrap(),
        source_bytes
    );
    assert_eq!(fs::read(&source).unwrap(), source_bytes);

    let serialized = serde_json::to_value(&result).unwrap();
    assert_eq!(
        serialized["split_output"]["bundle_directory"],
        json!(bundle.to_str().unwrap())
    );
    assert_eq!(
        serialized["split_output"]["canonical_directory"],
        json!(bundle.join("loose.nca").to_str().unwrap())
    );

    for selected in [
        output.canonical_directory().to_path_buf(),
        output.canonical_directory().join("00"),
    ] {
        let resolved = engine
            .resolve_inputs_with(
                nscb::InputResolutionRequest::new(root.path()).with_path(selected),
                nscb::InputResolutionCapabilities::new().with_split_trust_store(&trust),
            )
            .unwrap();
        assert_eq!(resolved.inputs.len(), 1);
        assert_eq!(
            resolved.inputs[0]
                .qualification
                .as_ref()
                .unwrap()
                .original_sha256,
            nscb::Sha256Digest::digest(source_bytes)
        );
        assert_eq!(resolved.inputs[0].segments.len(), 1);
    }

    fs::remove_file(&source).unwrap();
    let resolved_without_source = engine
        .resolve_inputs_with(
            nscb::InputResolutionRequest::new(root.path()).with_path(output.canonical_directory()),
            nscb::InputResolutionCapabilities::new().with_split_trust_store(&trust),
        )
        .unwrap();
    assert_eq!(resolved_without_source.inputs.len(), 1);
    assert_eq!(
        resolved_without_source.inputs[0].segments[0].size,
        source_bytes.len() as u64
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn split_planning_fails_closed_before_creating_output_on_unqualified_platforms() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source.bin");
    let bundle = root.path().join("bundle");
    fs::write(&source, b"source").unwrap();
    let trust = LocalSplitTrustStore::new(root.path().join("state"));

    let error = Engine::new()
        .plan_split(SplitRequest::new(&source, &bundle), &trust)
        .unwrap_err();

    assert_eq!(
        error.code(),
        nscb::OperationFailureCode::UnsupportedCapability
    );
    assert!(!bundle.exists());
}
