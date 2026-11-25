#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod support;
#[path = "support/synthetic_extraction.rs"]
mod synthetic_extraction;

use nscb::{
    CancellationHandle, ContainerFormat, ContainerProbeRequest, Engine, ExtractionRequest,
    ExtractionSelection, JobState, OperationKind, OperationOutcome, OperationSession,
    RepackRequest,
};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use synthetic_extraction::SyntheticExtractionFixture;

fn run_extract_program(
    fixture: &SyntheticExtractionFixture,
    source: &Path,
    destination: &Path,
) -> nscb::OperationResult {
    let cancellation = CancellationHandle::new();
    let plan = Engine::new()
        .plan_extraction(
            ExtractionRequest::new(
                source,
                destination,
                &fixture.key_file,
                ExtractionSelection::all(),
            ),
            cancellation.clone(),
        )
        .expect("plan complete Program extraction");
    Engine::new().execute_operation_with_cancellation(plan, &OperationSession::new(), cancellation)
}

fn extract_program(fixture: &SyntheticExtractionFixture, source: &Path, destination: &Path) {
    let result = run_extract_program(fixture, source, destination);
    assert_eq!(
        result.state(),
        JobState::Succeeded,
        "extraction result: {result:?}"
    );
}

fn repack_program(
    fixture: &SyntheticExtractionFixture,
    bundle: &Path,
    destination: &Path,
    workspace: &Path,
) -> nscb::OperationResult {
    let plan = Engine::new()
        .plan_repack(RepackRequest::new(
            bundle.join("manifest.json"),
            destination,
            workspace,
            &fixture.key_file,
        ))
        .expect("plan one-member Program PFS0 repack");
    Engine::new().execute_operation(plan, &OperationSession::new())
}

fn embedded_program_nca(package: &Path) -> Vec<u8> {
    let result = Engine::new()
        .probe_container(ContainerProbeRequest::new(package))
        .expect("probe outer PFS0");
    assert_eq!(result.format, ContainerFormat::Pfs0);
    assert_eq!(result.entries.len(), 1);
    let entry = &result.entries[0];
    assert_eq!(
        entry.name,
        format!("{:016X}_{:08X}.nca", synthetic_extraction::PROGRAM_ID, 0)
    );
    let size = usize::try_from(entry.size).expect("synthetic NCA fits memory");
    let mut bytes = vec![0; size];
    let mut file = File::open(package).expect("open package");
    file.seek(SeekFrom::Start(entry.file_offset))
        .expect("seek to Program NCA");
    file.read_exact(&mut bytes).expect("read Program NCA");
    bytes
}

#[test]
fn extracted_payload_path_beyond_path_max_repackages() {
    let relative_path = (0..6)
        .map(|index| format!("segment{index}-{}", "x".repeat(196)))
        .collect::<Vec<_>>()
        .join("/");
    let fixture = SyntheticExtractionFixture::empty_first_partition()
        .with_program_file(relative_path.clone(), b"deep path payload".to_vec());
    let root = fixture.source.parent().expect("fixture root");
    let bundle = root.join("path-max-bundle");
    let package = root.join("path-max.pfs0");
    let complete_payload_path = bundle.join("content").join("0").join(&relative_path);
    assert!(complete_payload_path.as_os_str().len() > libc::PATH_MAX as usize);
    assert!(
        complete_payload_path
            .parent()
            .expect("payload parent")
            .as_os_str()
            .len()
            > libc::PATH_MAX as usize
    );

    let extraction = run_extract_program(&fixture, &fixture.source, &bundle);
    assert_eq!(
        extraction.state(),
        JobState::Succeeded,
        "extraction result: {extraction:?}; destination exists: {}",
        bundle.exists()
    );
    assert_eq!(
        File::open(&complete_payload_path)
            .expect_err("the full payload pathname must exceed the native syscall limit")
            .raw_os_error(),
        Some(libc::ENAMETOOLONG)
    );
    let manifest = fs::read_to_string(bundle.join("manifest.json")).expect("read manifest");
    assert!(manifest.contains(&relative_path));

    let result = repack_program(&fixture, &bundle, &package, root);
    assert_eq!(result.state(), JobState::Succeeded);
    assert!(package.is_file());
}

#[test]
fn complete_bundle_repackages_deterministically_and_reextracts_edited_files() {
    let fixture = SyntheticExtractionFixture::populated();
    let root = fixture.source.parent().expect("fixture root");
    let bundle = root.join("complete-bundle");
    assert_eq!(fs::read(&fixture.source).unwrap(), fixture.source_bytes);
    extract_program(&fixture, &fixture.source, &bundle);
    let manifest = fs::read_to_string(bundle.join("manifest.json")).unwrap();
    assert!(manifest.contains(&format!("{:016x}", synthetic_extraction::PROGRAM_ID)));
    for expected in &fixture.expected_files {
        let path = bundle
            .join("content")
            .join(expected.partition_index.to_string())
            .join(&expected.path);
        assert_eq!(fs::read(path).unwrap(), expected.bytes);
    }

    let edited = bundle.join("content/0/nested/program.bin");
    fs::write(&edited, b"updated nested Program bytes").expect("edit extracted Program payload");

    let first = root.join("rebuilt-one.pfs0");
    let second = root.join("rebuilt-two.pfs0");
    let plan = Engine::new()
        .plan_repack(RepackRequest::new(
            bundle.join("manifest.json"),
            &first,
            root,
            &fixture.key_file,
        ))
        .expect("plan one-member Program PFS0 repack");
    assert_eq!(plan.snapshot().operation_kind(), OperationKind::Repack);
    let result = Engine::new().execute_operation(plan, &OperationSession::new());
    assert_eq!(
        result.state(),
        JobState::Succeeded,
        "{:?}",
        result.failure()
    );
    assert_eq!(result.outcome(), Some(OperationOutcome::Repacked));

    let repeated = repack_program(&fixture, &bundle, &second, root);
    assert_eq!(repeated.state(), JobState::Succeeded);
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());

    let rebuilt_nca_path = root.join("rebuilt-program.nca");
    fs::write(&rebuilt_nca_path, embedded_program_nca(&first)).unwrap();
    let rebuilt_bundle = root.join("rebuilt-bundle");
    extract_program(&fixture, &rebuilt_nca_path, &rebuilt_bundle);

    assert_eq!(
        fs::read(rebuilt_bundle.join("content/0/nested/program.bin")).unwrap(),
        b"updated nested Program bytes"
    );
    assert_eq!(
        fs::read(rebuilt_bundle.join("content/0/empty.dat")).unwrap(),
        b""
    );
    assert_eq!(
        fs::read(rebuilt_bundle.join("manifest.json")).unwrap(),
        fs::read(bundle.join("manifest.json")).unwrap()
    );
    assert!(rebuilt_bundle.join("content/0/nested").is_dir());
    assert!(rebuilt_bundle.join("content/1").is_dir());
    for expected in &fixture.expected_files {
        let relative_path = format!("content/{}/{}", expected.partition_index, expected.path);
        let rebuilt = fs::read(rebuilt_bundle.join(&relative_path)).unwrap();
        let expected_bytes = if relative_path == "content/0/nested/program.bin" {
            &b"updated nested Program bytes"[..]
        } else {
            expected.bytes.as_slice()
        };
        assert_eq!(rebuilt, expected_bytes, "{relative_path}");
    }
}

#[test]
fn identical_existing_package_reports_already_up_to_date() {
    let fixture = SyntheticExtractionFixture::populated();
    let root = fixture.source.parent().unwrap();
    let bundle = root.join("complete-bundle");
    extract_program(&fixture, &fixture.source, &bundle);
    let package = root.join("program.pfs0");
    let initial = repack_program(&fixture, &bundle, &package, root);
    assert_eq!(
        initial.state(),
        JobState::Succeeded,
        "{:?}",
        initial.failure()
    );
    let before = fs::read(&package).unwrap();

    let result = repack_program(&fixture, &bundle, &package, root);

    assert_eq!(result.state(), JobState::Succeeded);
    assert_eq!(result.outcome(), Some(OperationOutcome::AlreadyUpToDate));
    assert_eq!(fs::read(&package).unwrap(), before);
}

#[test]
fn request_uses_the_supplied_manifest_path_and_rejects_a_wrong_destination_type() {
    let fixture = SyntheticExtractionFixture::populated();
    let root = fixture.source.parent().unwrap();
    let bundle = root.join("custom-manifest-bundle");
    extract_program(&fixture, &fixture.source, &bundle);
    let manifest = bundle.join("program-manifest.json");
    fs::rename(bundle.join("manifest.json"), &manifest).unwrap();

    let destination = root.join("custom-manifest.pfs0");
    let plan = Engine::new()
        .plan_repack(RepackRequest::new(
            &manifest,
            &destination,
            root,
            &fixture.key_file,
        ))
        .expect("plan using the supplied standalone manifest path");
    let result = Engine::new().execute_operation(plan, &OperationSession::new());
    assert_eq!(
        result.state(),
        JobState::Succeeded,
        "{:?}",
        result.failure()
    );

    let wrong_type = match Engine::new().plan_repack(RepackRequest::new(
        &manifest,
        root.join("wrong-output.nsp"),
        root,
        &fixture.key_file,
    )) {
        Ok(_) => panic!("repack planning must reject a non-PFS0 destination"),
        Err(error) => error,
    };
    assert_eq!(wrong_type.code().as_str(), "invalid_destination");
}

#[test]
fn repacks_a_program_with_an_empty_partition_root() {
    let fixture = SyntheticExtractionFixture::empty_first_partition();
    let root = fixture.source.parent().unwrap();
    let bundle = root.join("empty-first-partition-bundle");
    extract_program(&fixture, &fixture.source, &bundle);
    let package = root.join("empty-first-partition.pfs0");

    let result = repack_program(&fixture, &bundle, &package, root);

    assert_eq!(
        result.state(),
        JobState::Succeeded,
        "{:?}",
        result.failure()
    );
    assert_eq!(result.outcome(), Some(OperationOutcome::Repacked));
    let rebuilt_nca = root.join("empty-first-partition.nca");
    fs::write(&rebuilt_nca, embedded_program_nca(&package)).unwrap();
    let rebuilt_bundle = root.join("empty-first-partition-rebuilt");
    extract_program(&fixture, &rebuilt_nca, &rebuilt_bundle);
    assert!(rebuilt_bundle.join("content/0").is_dir());
    assert_eq!(
        fs::read(rebuilt_bundle.join("content/1/extra1.bin")).unwrap(),
        b"extra1"
    );
}

#[test]
fn planning_rejects_missing_and_undeclared_payload_files() {
    let missing_fixture = SyntheticExtractionFixture::populated();
    let missing_root = missing_fixture.source.parent().unwrap();
    let missing_bundle = missing_root.join("missing-payload-bundle");
    extract_program(&missing_fixture, &missing_fixture.source, &missing_bundle);
    fs::remove_file(missing_bundle.join("content/0/empty.dat")).unwrap();
    let missing = match Engine::new().plan_repack(RepackRequest::new(
        missing_bundle.join("manifest.json"),
        missing_root.join("missing-payload.pfs0"),
        missing_root,
        &missing_fixture.key_file,
    )) {
        Ok(_) => panic!("planning must reject a missing manifest payload"),
        Err(error) => error,
    };
    assert_eq!(missing.code().as_str(), "missing_repack_payload");

    let extra_fixture = SyntheticExtractionFixture::populated();
    let extra_root = extra_fixture.source.parent().unwrap();
    let extra_bundle = extra_root.join("extra-payload-bundle");
    extract_program(&extra_fixture, &extra_fixture.source, &extra_bundle);
    fs::write(
        extra_bundle.join("content/0/undeclared.bin"),
        b"not in the manifest",
    )
    .unwrap();
    let extra = match Engine::new().plan_repack(RepackRequest::new(
        extra_bundle.join("manifest.json"),
        extra_root.join("extra-payload.pfs0"),
        extra_root,
        &extra_fixture.key_file,
    )) {
        Ok(_) => panic!("planning must reject a payload absent from the manifest"),
        Err(error) => error,
    };
    assert_eq!(extra.code().as_str(), "staged_output_invalid");
}

#[test]
fn execution_rejects_payload_changed_after_planning_without_publishing() {
    let fixture = SyntheticExtractionFixture::populated();
    let root = fixture.source.parent().unwrap();
    let bundle = root.join("changed-after-plan-bundle");
    extract_program(&fixture, &fixture.source, &bundle);
    let destination = root.join("changed-after-plan.pfs0");
    let plan = Engine::new()
        .plan_repack(RepackRequest::new(
            bundle.join("manifest.json"),
            &destination,
            root,
            &fixture.key_file,
        ))
        .expect("plan complete bundle before the payload changes");
    fs::write(
        bundle.join("content/0/nested/program.bin"),
        b"changed after planning",
    )
    .unwrap();

    let result = Engine::new().execute_operation(plan, &OperationSession::new());

    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        result.failure().unwrap().code().as_str(),
        "repack_payload_changed"
    );
    assert!(!destination.exists());
}

#[test]
fn execution_rejects_manifest_changed_after_planning_without_publishing() {
    let fixture = SyntheticExtractionFixture::populated();
    let root = fixture.source.parent().unwrap();
    let bundle = root.join("changed-manifest-after-plan-bundle");
    extract_program(&fixture, &fixture.source, &bundle);
    let manifest_path = bundle.join("manifest.json");
    let destination = root.join("changed-manifest-after-plan.pfs0");
    let plan = Engine::new()
        .plan_repack(RepackRequest::new(
            &manifest_path,
            &destination,
            root,
            &fixture.key_file,
        ))
        .expect("plan against the original manifest identity");
    let mut manifest = fs::read(&manifest_path).unwrap();
    manifest.push(b' ');
    fs::write(&manifest_path, manifest).unwrap();

    let result = Engine::new().execute_operation(plan, &OperationSession::new());

    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(result.failure().unwrap().code().as_str(), "source_changed");
    assert!(!destination.exists());
}

#[test]
fn execution_rejects_a_replaced_payload_directory_even_with_matching_contents() {
    let fixture = SyntheticExtractionFixture::populated();
    let root = fixture.source.parent().unwrap();
    let bundle = root.join("replaced-directory-bundle");
    extract_program(&fixture, &fixture.source, &bundle);
    let destination = root.join("replaced-directory.pfs0");
    let plan = Engine::new()
        .plan_repack(RepackRequest::new(
            bundle.join("manifest.json"),
            &destination,
            root,
            &fixture.key_file,
        ))
        .expect("plan before replacing a recorded payload directory");
    let nested = bundle.join("content/0/nested");
    let moved = root.join("original-nested-directory");
    fs::rename(&nested, &moved).unwrap();
    fs::create_dir(&nested).unwrap();
    fs::write(nested.join("program.bin"), b"nested program bytes").unwrap();

    let result = Engine::new().execute_operation(plan, &OperationSession::new());

    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        result.failure().unwrap().code().as_str(),
        "repack_payload_changed"
    );
    assert!(!destination.exists());
}

#[test]
fn execution_rejects_header_key_changed_after_planning() {
    let fixture = SyntheticExtractionFixture::populated();
    let root = fixture.source.parent().unwrap();
    let bundle = root.join("changed-key-bundle");
    extract_program(&fixture, &fixture.source, &bundle);
    let destination = root.join("changed-key.pfs0");
    let plan = Engine::new()
        .plan_repack(RepackRequest::new(
            bundle.join("manifest.json"),
            &destination,
            root,
            &fixture.key_file,
        ))
        .expect("plan with the original key file");
    let mut changed_key = fixture.key_file_bytes.clone();
    changed_key[b"header_key = ".len()] = b'0';
    fs::write(&fixture.key_file, changed_key).unwrap();

    let result = Engine::new().execute_operation(plan, &OperationSession::new());

    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        result.failure().unwrap().code().as_str(),
        "key_file_changed"
    );
    assert!(!destination.exists());
}

#[test]
fn planning_rejects_symlinked_and_hard_linked_payloads() {
    let symlink_fixture = SyntheticExtractionFixture::populated();
    let symlink_root = symlink_fixture.source.parent().unwrap();
    let symlink_bundle = symlink_root.join("symlink-payload-bundle");
    extract_program(&symlink_fixture, &symlink_fixture.source, &symlink_bundle);
    let symlink_payload = symlink_bundle.join("content/0/nested/program.bin");
    fs::remove_file(&symlink_payload).unwrap();
    std::os::unix::fs::symlink(
        symlink_bundle.join("content/0/readme.txt"),
        &symlink_payload,
    )
    .unwrap();
    let symlink = match Engine::new().plan_repack(RepackRequest::new(
        symlink_bundle.join("manifest.json"),
        symlink_root.join("symlink-payload.pfs0"),
        symlink_root,
        &symlink_fixture.key_file,
    )) {
        Ok(_) => panic!("planning must reject a symlinked payload"),
        Err(error) => error,
    };
    assert_eq!(symlink.code().as_str(), "staged_output_invalid");

    let hard_link_fixture = SyntheticExtractionFixture::populated();
    let hard_link_root = hard_link_fixture.source.parent().unwrap();
    let hard_link_bundle = hard_link_root.join("hard-link-payload-bundle");
    extract_program(
        &hard_link_fixture,
        &hard_link_fixture.source,
        &hard_link_bundle,
    );
    let hard_link_payload = hard_link_bundle.join("content/0/nested/program.bin");
    fs::remove_file(&hard_link_payload).unwrap();
    fs::hard_link(
        hard_link_bundle.join("content/0/readme.txt"),
        &hard_link_payload,
    )
    .unwrap();
    let hard_link = match Engine::new().plan_repack(RepackRequest::new(
        hard_link_bundle.join("manifest.json"),
        hard_link_root.join("hard-link-payload.pfs0"),
        hard_link_root,
        &hard_link_fixture.key_file,
    )) {
        Ok(_) => panic!("planning must reject a hard-linked payload"),
        Err(error) => error,
    };
    assert_eq!(hard_link.code().as_str(), "staged_output_invalid");
}

#[test]
fn planning_rejects_a_fifo_in_place_of_a_declared_payload() {
    let fixture = SyntheticExtractionFixture::populated();
    let root = fixture.source.parent().unwrap();
    let bundle = root.join("fifo-payload-bundle");
    extract_program(&fixture, &fixture.source, &bundle);
    let fifo = bundle.join("content/0/nested/program.bin");
    fs::remove_file(&fifo).unwrap();
    let status = std::process::Command::new("/usr/bin/mkfifo")
        .arg(&fifo)
        .status()
        .expect("create FIFO payload for the special-file check");
    assert!(status.success());

    let error = match Engine::new().plan_repack(RepackRequest::new(
        bundle.join("manifest.json"),
        root.join("fifo-payload.pfs0"),
        root,
        &fixture.key_file,
    )) {
        Ok(_) => panic!("planning must reject a FIFO payload"),
        Err(error) => error,
    };

    assert_eq!(error.code().as_str(), "staged_output_invalid");
}
