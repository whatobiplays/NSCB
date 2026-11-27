use nscb::{Engine, LocalSplitTrustStore, SplitLayout, SplitRequest};
#[cfg(target_os = "macos")]
use nscb::{OperationOutcome, OperationSession};
#[cfg(target_os = "macos")]
use serde_json::json;
use std::fs;

#[cfg(target_os = "macos")]
fn pfs0_with_one_member(name: &str, member: &[u8]) -> Vec<u8> {
    let mut bytes = b"PFS0".to_vec();
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&u32::try_from(name.len() + 1).unwrap().to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    bytes.extend_from_slice(&u64::try_from(member.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(name.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(member);
    bytes
}

#[test]
fn split_layout_is_canonical_by_default_and_selectable() {
    let canonical = SplitRequest::new("source.bin", "bundle");
    let legacy = SplitRequest::new("source.bin", "bundle").with_layout(SplitLayout::LegacyXc);

    assert_eq!(canonical.layout(), SplitLayout::Canonical);
    assert_eq!(legacy.layout(), SplitLayout::LegacyXc);
}

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
    assert_eq!(plan.snapshot().layout(), SplitLayout::Canonical);
    assert_eq!(plan.snapshot().bundle_directory(), bundle);
    assert_eq!(
        plan.snapshot().canonical_directory(),
        bundle.join("loose.nca")
    );
    assert_eq!(plan.snapshot().split_directory(), bundle.join("loose.nca"));
    assert!(
        serde_json::to_value(plan.snapshot())
            .unwrap()
            .get("layout")
            .is_none()
    );

    let session = OperationSession::new();
    let result = engine.execute_split(plan, &session);
    assert_eq!(
        result.outcome(),
        Some(OperationOutcome::SplitCreated),
        "unexpected legacy publication result: {result:?}"
    );
    assert_eq!(result.artifacts().len(), 4);
    assert!(result.artifacts().iter().all(|artifact| {
        artifact.role() == nscb::OperationArtifactRole::PublishedDestination
            && artifact.path_identity_matches() == Some(true)
    }));
    let output = result.split_output_paths().unwrap();
    assert_eq!(output.layout(), SplitLayout::Canonical);
    assert_eq!(output.bundle_directory(), bundle);
    assert_eq!(output.canonical_directory(), bundle.join("loose.nca"));
    assert_eq!(output.split_directory(), bundle.join("loose.nca"));
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
    assert!(serialized["split_output"].get("layout").is_none());
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

#[cfg(target_os = "macos")]
#[test]
fn legacy_ns_split_publishes_expected_names_and_v2_manifest() {
    let root = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(root.path()).unwrap();
    let source = root.join("game.backup.xci");
    let bundle = root.join("game.backup.xci.split");
    let source_bytes = pfs0_with_one_member("payload.bin", b"synthetic package bytes");
    fs::write(&source, &source_bytes).unwrap();
    let trust = LocalSplitTrustStore::new(root.join("state").join("split-trust"));
    let engine = Engine::new();

    let plan = engine
        .plan_split(
            SplitRequest::new(&source, &bundle).with_layout(SplitLayout::LegacyNs),
            &trust,
        )
        .unwrap();
    assert_eq!(plan.snapshot().layout(), SplitLayout::LegacyNs);
    assert_eq!(plan.snapshot().segment_names(), &["game.backup.ns0"]);
    assert_eq!(
        plan.snapshot().manifest_path(),
        bundle.join("game.backup.xci.nscb-split.json")
    );

    let result = engine.execute_split(plan, &OperationSession::new());
    assert_eq!(result.outcome(), Some(OperationOutcome::SplitCreated));
    let output = result.split_output_paths().unwrap();
    assert_eq!(output.layout(), SplitLayout::LegacyNs);
    assert_eq!(output.split_directory(), bundle.join("game.backup.xci"));
    assert_eq!(
        fs::read(output.split_directory().join("game.backup.ns0")).unwrap(),
        source_bytes
    );
    let manifest_path = bundle.join("game.backup.xci.nscb-split.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(manifest_path).unwrap()).unwrap();
    assert_eq!(manifest["schema_version"], 2);
    assert_eq!(manifest["kind"], "nscb.split_manifest");
    assert_eq!(manifest["required_features"], serde_json::json!([]));
    assert_eq!(manifest["layout"], "legacy_ns");
    assert_eq!(manifest["segments"][0]["name"], "game.backup.ns0");
    assert_eq!(manifest["segments"][0]["name"], "game.backup.ns0");
    assert_eq!(manifest["source"]["size_bytes"], source_bytes.len());
    assert_eq!(
        manifest["source"]["sha256"],
        nscb::Sha256Digest::digest(&source_bytes).to_hex()
    );

    let serialized = serde_json::to_value(&result).unwrap();
    assert_eq!(serialized["split_output"]["layout"], "legacy_ns");
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
