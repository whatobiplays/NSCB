#[cfg(target_os = "macos")]
use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(target_os = "macos")]
use nscb::{
    CancellationHandle, ConflictPolicy, JobState, NspSemanticQualificationOutcome,
    NspSemanticQualificationRequest, OperationFailureCode, OperationOutcome, OperationSession,
};
use nscb::{Engine, XciToNspRequest};

#[allow(dead_code)]
#[path = "support/synthetic_nsp_qualification.rs"]
mod synthetic_nsp_qualification;
#[allow(dead_code)]
#[path = "support/synthetic_xci.rs"]
mod synthetic_xci;

#[cfg(target_os = "macos")]
struct TestFiles {
    source: PathBuf,
    destination: PathBuf,
    keys: PathBuf,
    workspace: PathBuf,
}

#[cfg(target_os = "macos")]
fn write_fixture(directory: &Path, fixture: &synthetic_xci::Fixture) -> TestFiles {
    let files = TestFiles {
        source: directory.join("source.xci"),
        destination: directory.join("output.nsp"),
        keys: directory.join("keys.dat"),
        workspace: directory.join("workspace"),
    };
    fs::create_dir(&files.workspace).expect("workspace");
    fs::write(&files.source, &fixture.image).expect("source XCI");
    fs::write(&files.keys, &fixture.key_file).expect("keys");
    files
}

#[cfg(target_os = "macos")]
fn plan(files: &TestFiles) -> Result<nscb::OperationPlan, nscb::OperationError> {
    plan_with_policy(files, ConflictPolicy::Fail)
}

#[cfg(target_os = "macos")]
fn plan_with_policy(
    files: &TestFiles,
    conflict_policy: ConflictPolicy,
) -> Result<nscb::OperationPlan, nscb::OperationError> {
    Engine::new().plan_xci_to_nsp(
        XciToNspRequest::new(
            &files.source,
            &files.destination,
            &files.workspace,
            &files.keys,
        )
        .with_conflict_policy(conflict_policy),
    )
}

#[cfg(target_os = "macos")]
#[test]
fn converts_synthetic_rights_free_application_and_preserves_member_bytes() {
    let fixture = synthetic_xci::valid();
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_fixture(directory.path(), &fixture);
    let source_before = fs::read(&files.source).expect("source baseline");
    let engine = Engine::new();
    let operation_plan = plan(&files).expect("eligible synthetic XCI plans");
    let result = engine.execute_operation(operation_plan, &Default::default());

    assert_eq!(result.state(), JobState::Succeeded);
    assert_eq!(result.outcome(), Some(OperationOutcome::Converted));
    assert_eq!(
        fs::read(&files.destination).expect("NSP output"),
        fixture.package
    );
    assert_eq!(
        fs::read(&files.source).expect("source after conversion"),
        source_before
    );

    let qualified = Engine::new()
        .qualify_nsp_semantics(NspSemanticQualificationRequest::new(
            &files.destination,
            &files.keys,
        ))
        .expect("qualify the staged output profile");
    assert!(matches!(
        qualified.outcome,
        NspSemanticQualificationOutcome::Qualified(_)
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn conversion_output_is_deterministic_and_logo_may_be_absent_or_empty() {
    let fixture = synthetic_xci::valid();
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_fixture(directory.path(), &fixture);
    let first_plan = plan(&files).expect("eligible XCI plans");
    let first_result = Engine::new().execute_operation(first_plan, &OperationSession::new());
    assert_eq!(first_result.state(), JobState::Succeeded);
    let first_bytes = fs::read(&files.destination).expect("first output");

    let second_destination = directory.path().join("second.nsp");
    let second_plan = Engine::new()
        .plan_xci_to_nsp(XciToNspRequest::new(
            &files.source,
            &second_destination,
            &files.workspace,
            &files.keys,
        ))
        .expect("second eligible plan");
    let second_result = Engine::new().execute_operation(second_plan, &OperationSession::new());
    assert_eq!(second_result.state(), JobState::Succeeded);
    assert_eq!(
        fs::read(second_destination).expect("second output"),
        first_bytes
    );

    for fixture in [synthetic_xci::valid(), {
        let nsp = synthetic_nsp_qualification::valid();
        synthetic_xci::build(
            &nsp.meta_nca,
            &nsp.program_nca,
            &nsp.package,
            &nsp.key_file,
            ["meta.nca", "program.nca"],
            true,
        )
    }] {
        let fixture_dir = tempfile::tempdir().expect("logo fixture directory");
        let files = write_fixture(fixture_dir.path(), &fixture);
        assert!(plan(&files).is_ok(), "absent and empty logos are supported");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn rejects_xci_without_head_signature() {
    let mut fixture = synthetic_xci::valid();
    fixture.image[0x100..0x104].copy_from_slice(b"NOPE");
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_fixture(directory.path(), &fixture);

    assert!(
        plan(&files).is_err(),
        "XCI source must contain the HEAD marker"
    );
    assert!(!files.destination.exists());
}

#[cfg(target_os = "macos")]
#[test]
fn accepts_nonzero_hfs0_prefix_hashes() {
    let mut fixture = synthetic_xci::valid();
    fixture.set_prefix_hash(fixture.root_entries[0], 2);
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_fixture(directory.path(), &fixture);

    assert!(plan(&files).is_ok());
}

#[cfg(target_os = "macos")]
#[test]
fn rejects_zero_hfs0_hashed_size() {
    let mut fixture = synthetic_xci::valid();
    fixture.set_hashed_size(fixture.root_entries[0], 0);
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_fixture(directory.path(), &fixture);

    assert!(plan(&files).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn rejects_nonzero_hfs0_reserved_bytes_even_when_structurally_bounded() {
    let mut fixture = synthetic_xci::valid();
    let entry = fixture.root_entries[0];
    fixture.set_prefix_hash(entry, 2);
    fixture.set_reserved(entry, [1, 0, 0, 0, 0, 0, 0, 0]);
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_fixture(directory.path(), &fixture);

    assert!(plan(&files).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn rejects_hfs0_prefix_digest_mismatch() {
    let mut fixture = synthetic_xci::valid();
    fixture.corrupt_digest(fixture.secure_entries[0]);
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_fixture(directory.path(), &fixture);

    assert!(plan(&files).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn rejects_hfs0_hashed_size_past_member_bounds() {
    let mut fixture = synthetic_xci::valid();
    let entry = fixture.secure_entries[0];
    fixture.set_hashed_size(entry, (entry.data_len + 1) as u32);
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_fixture(directory.path(), &fixture);

    assert!(plan(&files).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn rejects_missing_duplicate_unknown_and_nonempty_xci_partitions() {
    let unsupported = [
        synthetic_xci::with_root_partition_names(&["normal", "secure"]),
        synthetic_xci::with_root_partition_names(&["update", "secure"]),
        synthetic_xci::with_root_partition_names(&["update", "normal"]),
        synthetic_xci::with_root_partition_names(&["update", "update", "normal", "secure"]),
        synthetic_xci::with_root_partition_names(&["update", "normal", "secure", "secure"]),
        synthetic_xci::with_root_partition_names(&["update", "normal", "secure", "dlc"]),
        synthetic_xci::with_secure_member_count(0),
        synthetic_xci::with_secure_member_count(1),
        synthetic_xci::with_extra_secure_member(),
        synthetic_xci::with_compressed_secure_member(),
        synthetic_xci::with_nonempty_partition("update"),
        synthetic_xci::with_nonempty_partition("normal"),
        synthetic_xci::with_nonempty_partition("logo"),
    ];
    for fixture in unsupported {
        let directory = tempfile::tempdir().expect("temporary directory");
        let files = write_fixture(directory.path(), &fixture);
        assert!(
            plan(&files).is_err(),
            "unsupported XCI content fails closed"
        );
        assert!(!files.destination.exists());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn rejects_cnmt_metadata_outside_the_base_application_profile() {
    let nsp = synthetic_nsp_qualification::build_with_cnmt_change(|cnmt| {
        cnmt[0x0c] = 0x81;
    });
    let fixture = synthetic_xci::build(
        &nsp.meta_nca,
        &nsp.program_nca,
        &nsp.package,
        &nsp.key_file,
        ["metadata.bin", "opaque-member.dat"],
        false,
    );
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_fixture(directory.path(), &fixture);

    let error = match plan(&files) {
        Ok(_) => panic!("unsupported CNMT profile must be rejected"),
        Err(error) => error,
    };
    assert_eq!(
        error.code(),
        OperationFailureCode::UnsupportedContentProfile
    );
    assert!(!files.destination.exists());
}

#[cfg(target_os = "macos")]
#[test]
fn detects_source_and_key_mutations_after_planning() {
    let fixture = synthetic_xci::valid();
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_fixture(directory.path(), &fixture);
    let source_plan = plan(&files).expect("source mutation plan");
    fs::write(&files.source, b"source changed after planning").expect("mutate source");
    let source_result = Engine::new().execute_operation(source_plan, &OperationSession::new());
    assert_eq!(source_result.state(), JobState::Failed);
    assert_eq!(
        source_result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::SourceChanged)
    );
    assert!(!files.destination.exists());

    fs::write(&files.source, &fixture.image).expect("restore source bytes");
    let key_plan = plan(&files).expect("key mutation plan");
    fs::write(&files.keys, b"changed key file").expect("mutate key file");
    let key_result = Engine::new().execute_operation(key_plan, &OperationSession::new());
    assert_eq!(key_result.state(), JobState::Failed);
    assert_eq!(
        key_result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::KeyFileChanged)
    );
    assert!(!files.destination.exists());
}

#[cfg(target_os = "macos")]
#[test]
fn enforces_fail_skip_replace_and_already_up_to_date_policies() {
    let fixture = synthetic_xci::valid();
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_fixture(directory.path(), &fixture);
    fs::write(&files.destination, b"unrelated existing output").expect("conflicting output");
    let fail_plan = plan(&files).expect("Fail captures an occupied destination");
    let fail = Engine::new().execute_operation(fail_plan, &OperationSession::new());
    assert_eq!(fail.state(), JobState::Failed);
    assert_eq!(
        fail.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::DestinationConflict)
    );
    assert_eq!(
        fs::read(&files.destination).expect("Fail preserves existing output"),
        b"unrelated existing output"
    );

    let skip_plan = plan_with_policy(&files, ConflictPolicy::Skip).expect("Skip plan");
    let skipped = Engine::new().execute_operation(skip_plan, &OperationSession::new());
    assert_eq!(skipped.state(), JobState::Succeeded);
    assert_eq!(skipped.outcome(), Some(OperationOutcome::Skipped));
    assert_eq!(
        fs::read(&files.destination).expect("skipped output"),
        b"unrelated existing output"
    );

    let replace_plan = plan_with_policy(&files, ConflictPolicy::Replace).expect("Replace plan");
    let replaced = Engine::new().execute_operation(replace_plan, &OperationSession::new());
    assert_eq!(replaced.state(), JobState::Succeeded);
    assert_eq!(replaced.outcome(), Some(OperationOutcome::Converted));
    assert_eq!(
        fs::read(&files.destination).expect("replaced output"),
        fixture.package
    );

    let current_plan = plan(&files).expect("matching output plan");
    let current = Engine::new().execute_operation(current_plan, &OperationSession::new());
    assert_eq!(current.state(), JobState::Succeeded);
    assert_eq!(current.outcome(), Some(OperationOutcome::AlreadyUpToDate));
    assert_eq!(
        fs::read(&files.destination).expect("current output"),
        fixture.package
    );
}

#[cfg(target_os = "macos")]
#[test]
fn pre_cancelled_operation_does_not_create_output_or_workspace_artifacts() {
    let fixture = synthetic_xci::valid();
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_fixture(directory.path(), &fixture);
    let operation_plan = plan(&files).expect("eligible plan");
    let cancellation = CancellationHandle::new();
    cancellation.cancel();

    let result = Engine::new().execute_operation_with_cancellation(
        operation_plan,
        &OperationSession::new(),
        cancellation,
    );
    assert_eq!(result.state(), JobState::Cancelled);
    assert!(!files.destination.exists());
    assert_eq!(fs::read_dir(&files.workspace).unwrap().count(), 0);
    assert_eq!(
        fs::read(&files.source).expect("source remains"),
        fixture.image
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn conversion_is_unsupported_on_non_macos_targets() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let source = directory.path().join("source.xci");
    let destination = directory.path().join("output.nsp");
    let workspace = directory.path().join("workspace");
    let keys = directory.path().join("keys.dat");

    let result =
        Engine::new().plan_xci_to_nsp(XciToNspRequest::new(source, destination, workspace, keys));

    assert!(result.is_err());
}
