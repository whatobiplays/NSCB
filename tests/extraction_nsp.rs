#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

#[allow(dead_code)]
mod support;
#[path = "support/synthetic_extraction.rs"]
#[allow(dead_code)]
mod synthetic_extraction;
#[path = "support/synthetic_nsp_qualification.rs"]
#[allow(dead_code)]
mod synthetic_nsp_qualification;
use support::synthetic_pfs0;

use nscb::{
    CancellationHandle, Engine, ExtractionRequest, ExtractionSelection, ExtractionSelectors,
    JobState, NcaContentId, NcaContentType, OperationFailureCode, OperationSession, ProgramId,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;

#[test]
fn extracts_program_bytes_from_the_qualified_nsp_profile() {
    let fixture = synthetic_nsp_qualification::valid();
    let root = tempfile::tempdir().expect("create extraction fixture directory");
    let source = root.path().join("misleading-content.bin");
    let key_file = root.path().join("deterministic-test-keys.txt");
    let destination = root.path().join("extracted-program");
    fs::write(&source, &fixture.package).expect("write synthetic NSP bytes");
    fs::write(&key_file, &fixture.key_file).expect("write synthetic key material");

    let engine = Engine::new();
    let cancellation = CancellationHandle::new();
    let plan = engine
        .plan_extraction(
            ExtractionRequest::new(&source, &destination, &key_file, ExtractionSelection::all()),
            cancellation.clone(),
        )
        .expect("plan extraction from the qualified NSP profile");
    let result = engine.execute_operation(plan, &OperationSession::new());

    assert_eq!(
        result.state(),
        JobState::Succeeded,
        "extraction failure: {:?}",
        result.failure().map(|failure| failure.code())
    );
    assert_eq!(fs::read(&source).unwrap(), fixture.package);
    assert_eq!(fs::read(&key_file).unwrap(), fixture.key_file);

    let manifest_bytes = fs::read(destination.join("manifest.json")).unwrap();
    assert!(manifest_bytes.ends_with(b"\n"));
    let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(manifest["schema_version"], 1);
    assert_eq!(manifest["content_root"], "content");
    assert_eq!(
        manifest["source"]["profile"],
        "nca3_program_partition_fs_hierarchical_sha256_aes_ctr"
    );
    assert_eq!(
        manifest["source"]["container"]["profile"],
        "rights_free_base_application_v1"
    );
    assert_eq!(
        manifest["source"]["container"]["title_id"],
        "0100123456789abc"
    );
    assert_eq!(
        manifest["source"]["container"]["program_content_id"],
        lowercase_hex(&sha2::Sha256::digest(&fixture.program_nca)[..16])
    );
    assert!(destination.join("content/0").is_dir());
    assert_eq!(
        fs::read(destination.join("content/0/unrelated.bin")).unwrap(),
        b"synthetic program section"
    );
}

#[test]
fn partial_nsp_program_selection_publishes_an_incomplete_multi_file_manifest() {
    let program_pfs0 = synthetic_pfs0::pfs0(
        &[
            synthetic_pfs0::EntrySpec {
                name: "selected.bin",
                offset: 0,
                size: 8,
            },
            synthetic_pfs0::EntrySpec {
                name: "omitted.bin",
                offset: 8,
                size: 7,
            },
        ],
        b"selectedomitted",
    );
    let fixture = synthetic_nsp_qualification::build_with_program_pfs0(program_pfs0);
    let root = tempfile::tempdir().expect("create partial extraction fixture");
    let (source, key_file, destination) = write_fixture(&root, &fixture);
    let selection =
        ExtractionSelection::selectors(ExtractionSelectors::new().with_path("selected.bin"));
    let engine = Engine::new();
    let plan = engine
        .plan_extraction(
            ExtractionRequest::new(&source, &destination, &key_file, selection),
            CancellationHandle::new(),
        )
        .expect("plan selected file from a multi-file Program PFS0");
    let result = engine.execute_operation(plan, &OperationSession::new());

    assert_eq!(result.state(), JobState::Succeeded);
    let manifest: Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["content_root"], "content");
    assert_eq!(manifest["completeness"], "incomplete");
    let files = manifest["partitions"][0]["files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["path"], "0/selected.bin");
    assert_eq!(
        fs::read(destination.join("content/0/selected.bin")).unwrap(),
        b"selected"
    );
    assert!(!destination.join("content/0/omitted.bin").exists());
}

#[test]
fn qualified_title_and_content_id_selectors_extract_the_verified_program() {
    let fixture = synthetic_nsp_qualification::valid();
    let root = tempfile::tempdir().expect("create extraction fixture directory");
    let (source, key_file, destination) = write_fixture(&root, &fixture);
    let digest = Sha256::digest(&fixture.program_nca);
    let mut content_id = [0_u8; 16];
    content_id.copy_from_slice(&digest[..16]);
    let selection = ExtractionSelection::selectors(
        ExtractionSelectors::new()
            .with_program_id(ProgramId::from_u64(synthetic_nsp_qualification::PROGRAM_ID))
            .with_title_id(ProgramId::from_u64(synthetic_nsp_qualification::PROGRAM_ID))
            .with_nca_content_id(NcaContentId::from_bytes(content_id))
            .with_nca_type(NcaContentType::Program)
            .with_partition(0)
            .with_path("unrelated.bin"),
    );
    let engine = Engine::new();
    let cancellation = CancellationHandle::new();
    let plan = engine
        .plan_extraction(
            ExtractionRequest::new(&source, &destination, &key_file, selection),
            cancellation.clone(),
        )
        .expect("plan qualified selector extraction");
    let result =
        engine.execute_operation_with_cancellation(plan, &OperationSession::new(), cancellation);

    assert_eq!(result.state(), JobState::Succeeded);
    assert_eq!(
        fs::read(destination.join("content/0/unrelated.bin")).unwrap(),
        b"synthetic program section"
    );
}

#[test]
fn qualified_identity_selectors_fail_for_mismatches_and_standalone_ncas() {
    let fixture = synthetic_nsp_qualification::valid();
    let mut content_id = [0_u8; 16];
    content_id.copy_from_slice(&Sha256::digest(&fixture.program_nca)[..16]);
    let wrong_content_id = NcaContentId::from_bytes({
        let mut bytes = content_id;
        bytes[0] ^= 1;
        bytes
    });
    let wrong_title_id = ProgramId::from_u64(synthetic_nsp_qualification::PROGRAM_ID ^ 1);

    for selection in [
        ExtractionSelection::selectors(ExtractionSelectors::new().with_title_id(wrong_title_id)),
        ExtractionSelection::selectors(
            ExtractionSelectors::new().with_nca_content_id(wrong_content_id),
        ),
        ExtractionSelection::selectors(
            ExtractionSelectors::new()
                .with_program_id(ProgramId::from_u64(synthetic_nsp_qualification::PROGRAM_ID))
                .with_title_id(wrong_title_id),
        ),
    ] {
        let root = tempfile::tempdir().expect("create extraction fixture directory");
        let (source, key_file, destination) = write_fixture(&root, &fixture);
        let error = Engine::new()
            .plan_extraction(
                ExtractionRequest::new(source, &destination, key_file, selection),
                CancellationHandle::new(),
            )
            .err()
            .expect("mismatched identity must fail planning");
        assert_eq!(error.code(), OperationFailureCode::EmptySelection);
        assert!(!destination.exists());
    }

    let standalone = synthetic_extraction::SyntheticExtractionFixture::populated();
    for selection in [
        ExtractionSelection::selectors(
            ExtractionSelectors::new()
                .with_title_id(ProgramId::from_u64(synthetic_extraction::PROGRAM_ID)),
        ),
        ExtractionSelection::selectors(
            ExtractionSelectors::new().with_nca_content_id(NcaContentId::from_bytes([0x22; 16])),
        ),
    ] {
        let root = tempfile::tempdir().expect("create standalone extraction fixture");
        let destination = root.path().join("extracted-program");
        let error = Engine::new()
            .plan_extraction(
                ExtractionRequest::new(
                    &standalone.source,
                    &destination,
                    &standalone.key_file,
                    selection,
                ),
                CancellationHandle::new(),
            )
            .err()
            .expect("standalone NCA must not satisfy package identity selectors");
        assert_eq!(error.code(), OperationFailureCode::EmptySelection);
        assert!(!destination.exists());
    }
}

#[test]
fn execution_rejects_source_and_key_changes_after_qualification_planning() {
    let fixture = synthetic_nsp_qualification::valid();
    let root = tempfile::tempdir().expect("create extraction fixture directory");
    let (source, key_file, destination) = write_fixture(&root, &fixture);
    let engine = Engine::new();
    let cancellation = CancellationHandle::new();
    let plan = engine
        .plan_extraction(
            ExtractionRequest::new(&source, &destination, &key_file, ExtractionSelection::all()),
            cancellation.clone(),
        )
        .expect("plan source-bound extraction");

    let mut changed_package = fixture.package.clone();
    let last = changed_package.len() - 1;
    changed_package[last] ^= 1;
    fs::write(&source, changed_package).unwrap();
    let result =
        engine.execute_operation_with_cancellation(plan, &OperationSession::new(), cancellation);
    assert_ne!(result.state(), JobState::Succeeded);
    assert_eq!(
        result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::SourceChanged)
    );
    assert!(!destination.exists());

    fs::write(&source, &fixture.package).unwrap();
    let second_destination = root.path().join("second-extraction");
    let second_cancel = CancellationHandle::new();
    let second_plan = engine
        .plan_extraction(
            ExtractionRequest::new(
                &source,
                &second_destination,
                &key_file,
                ExtractionSelection::all(),
            ),
            second_cancel.clone(),
        )
        .expect("plan key-bound extraction");
    let mut changed_keys = fixture.key_file.clone();
    let last_key = changed_keys.len() - 1;
    changed_keys[last_key] ^= 1;
    fs::write(&key_file, changed_keys).unwrap();
    let second_result = engine.execute_operation_with_cancellation(
        second_plan,
        &OperationSession::new(),
        second_cancel,
    );
    assert_ne!(second_result.state(), JobState::Succeeded);
    assert_eq!(
        second_result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::KeyFileChanged)
    );
    assert!(!second_destination.exists());
}

#[test]
fn cancellation_after_qualification_planning_prevents_publication() {
    let fixture = synthetic_nsp_qualification::valid();
    let root = tempfile::tempdir().expect("create extraction fixture directory");
    let (source, key_file, destination) = write_fixture(&root, &fixture);
    let engine = Engine::new();
    let cancellation = CancellationHandle::new();
    let plan = engine
        .plan_extraction(
            ExtractionRequest::new(&source, &destination, &key_file, ExtractionSelection::all()),
            cancellation.clone(),
        )
        .expect("plan cancellation fixture");
    cancellation.cancel();

    let result =
        engine.execute_operation_with_cancellation(plan, &OperationSession::new(), cancellation);
    assert_eq!(result.state(), JobState::Cancelled);
    assert_eq!(
        result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::Cancelled)
    );
    assert!(!destination.exists());
}

#[test]
fn wrong_application_key_does_not_qualify_or_publish() {
    let fixture = synthetic_nsp_qualification::valid();
    let root = tempfile::tempdir().expect("create extraction fixture directory");
    let source = root.path().join("package.nsp");
    let key_file = root.path().join("wrong.keys");
    let destination = root.path().join("extracted-program");
    fs::write(&source, &fixture.package).unwrap();
    fs::write(
        &key_file,
        synthetic_nsp_qualification::key_file_with_application_kaek([0x25; 16]),
    )
    .unwrap();
    let error = Engine::new()
        .plan_extraction(
            ExtractionRequest::new(&source, &destination, &key_file, ExtractionSelection::all()),
            CancellationHandle::new(),
        )
        .err()
        .expect("wrong application key must fail qualification");
    assert_eq!(
        error.code(),
        OperationFailureCode::KeyOrSectionIntegrityFailure
    );
    assert!(!destination.exists());
}

fn write_fixture(
    root: &tempfile::TempDir,
    fixture: &synthetic_nsp_qualification::Fixture,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let source = root.path().join("misleading-content.bin");
    let key_file = root.path().join("deterministic-test-keys.txt");
    let destination = root.path().join("extracted-program");
    fs::write(&source, &fixture.package).expect("write synthetic NSP bytes");
    fs::write(&key_file, &fixture.key_file).expect("write synthetic key material");
    (source, key_file, destination)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
