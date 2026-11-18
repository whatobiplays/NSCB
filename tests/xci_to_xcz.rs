mod support;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use nscb::{
    CancellationHandle, ConflictPolicy, JobState, OperationOutcome, OperationSession,
    XciToNspRequest, XczToXciRequest,
};
use nscb::{Engine, OperationFailureCode, XciToXczRequest};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::fs;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "../src/control_nca_test_fixture.rs"]
mod synthetic_control_nca;
#[allow(dead_code)]
#[path = "support/synthetic_nsp_qualification.rs"]
mod synthetic_nsp_qualification;
#[allow(dead_code)]
#[path = "support/synthetic_xci.rs"]
mod synthetic_xci;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct TestFiles {
    source: PathBuf,
    destination: PathBuf,
    keys: PathBuf,
    workspace: PathBuf,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn write_fixture(directory: &Path, fixture: &synthetic_xci::Fixture) -> TestFiles {
    let files = TestFiles {
        source: directory.join("source.xci"),
        destination: directory.join("output.xcz"),
        keys: directory.join("keys.dat"),
        workspace: directory.join("workspace"),
    };
    fs::create_dir(&files.workspace).expect("workspace");
    fs::write(&files.source, &fixture.image).expect("source XCI");
    fs::write(&files.keys, &fixture.key_file).expect("keys");
    files
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn qualified_fixture() -> (synthetic_xci::Fixture, synthetic_nsp_qualification::Fixture) {
    let payload = vec![0xA5; 0x9000];
    let nsp = synthetic_nsp_qualification::build_with_program_payload(&payload, |_| {});
    let xci = synthetic_xci::build(
        &nsp.meta_nca,
        &nsp.program_nca,
        &nsp.package,
        &nsp.key_file,
        ["meta_payload.nca", "program_payload.nca"],
        false,
    );
    (xci, nsp)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn three_member_fixture() -> synthetic_xci::Fixture {
    let title_id = synthetic_nsp_qualification::PROGRAM_ID;
    let control = synthetic_control_nca::build_for_program_id(
        &synthetic_control_nca::empty_romfs(),
        synthetic_control_nca::Mutation::None,
        title_id,
    );
    let nsp = synthetic_nsp_qualification::build_application_with_control(&control.bytes, title_id);
    synthetic_xci::with_three_members(
        [
            ("control.nca", &nsp.control_nca),
            ("meta.nca", &nsp.meta_nca),
            ("program.nca", &nsp.program_nca),
        ],
        &nsp.meta_nca,
        &nsp.program_nca,
        &nsp.control_nca,
        &nsp.key_file,
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn pfs0_member<'a>(package: &'a [u8], expected_name: &str) -> &'a [u8] {
    assert_eq!(&package[..4], b"PFS0");
    let count = u32::from_le_bytes(package[4..8].try_into().expect("PFS0 count")) as usize;
    let names_size =
        u32::from_le_bytes(package[8..12].try_into().expect("PFS0 names size")) as usize;
    let names_start = 16 + count * 24;
    let payload_start = names_start + names_size;
    let names = &package[names_start..payload_start];
    for index in 0..count {
        let entry = 16 + index * 24;
        let offset =
            u64::from_le_bytes(package[entry..entry + 8].try_into().expect("member offset"))
                as usize;
        let length = u64::from_le_bytes(
            package[entry + 8..entry + 16]
                .try_into()
                .expect("member length"),
        ) as usize;
        let name_offset = u32::from_le_bytes(
            package[entry + 16..entry + 20]
                .try_into()
                .expect("member name"),
        ) as usize;
        let name_end = names[name_offset..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|length| name_offset + length)
            .expect("terminated member name");
        if &names[name_offset..name_end] == expected_name.as_bytes() {
            return &package[payload_start + offset..payload_start + offset + length];
        }
    }
    panic!("missing PFS0 member {expected_name}");
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn xci_secure_member_names(image: &[u8]) -> Vec<String> {
    fn hfs_table(image: &[u8], start: usize) -> (Vec<String>, Vec<u64>) {
        assert_eq!(&image[start..start + 4], b"HFS0");
        let count = u32::from_le_bytes(image[start + 4..start + 8].try_into().unwrap()) as usize;
        let names_size =
            u32::from_le_bytes(image[start + 8..start + 12].try_into().unwrap()) as usize;
        let strings_start = start + 0x10 + count * 0x40;
        let data_start = strings_start + names_size;
        let mut names = Vec::with_capacity(count);
        let mut offsets = Vec::with_capacity(count);
        for index in 0..count {
            let entry = start + 0x10 + index * 0x40;
            let offset = u64::from_le_bytes(image[entry..entry + 8].try_into().unwrap());
            let name_offset =
                u32::from_le_bytes(image[entry + 16..entry + 20].try_into().unwrap()) as usize;
            let name_start = strings_start + name_offset;
            let name_end = image[name_start..data_start]
                .iter()
                .position(|byte| *byte == 0)
                .map(|length| name_start + length)
                .expect("terminated HFS0 entry name");
            names.push(String::from_utf8(image[name_start..name_end].to_vec()).unwrap());
            offsets.push(offset);
        }
        (names, offsets)
    }

    let root_offset = u64::from_le_bytes(image[0x130..0x138].try_into().unwrap()) as usize;
    let root_table_size = 0x10
        + u32::from_le_bytes(image[root_offset + 4..root_offset + 8].try_into().unwrap()) as usize
            * 0x40
        + u32::from_le_bytes(image[root_offset + 8..root_offset + 12].try_into().unwrap()) as usize;
    let root_data = root_offset + root_table_size;
    let (root_names, root_offsets) = hfs_table(image, root_offset);
    let secure_index = root_names
        .iter()
        .position(|name| name == "secure")
        .expect("secure root partition");
    let secure_offset = root_data + usize::try_from(root_offsets[secure_index]).unwrap();
    hfs_table(image, secure_offset).0
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn compression_plan(
    files: &TestFiles,
    compression: nscb::NszCompression,
) -> Result<nscb::OperationPlan, nscb::OperationError> {
    compression_plan_with_policy(files, compression, ConflictPolicy::Fail)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn compression_plan_with_policy(
    files: &TestFiles,
    compression: nscb::NszCompression,
    policy: ConflictPolicy,
) -> Result<nscb::OperationPlan, nscb::OperationError> {
    Engine::new().plan_xci_to_xcz(
        XciToXczRequest::new(
            &files.source,
            &files.destination,
            &files.workspace,
            &files.keys,
        )
        .with_conflict_policy(policy)
        .with_compression(compression),
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn compresses_qualified_xci_and_reconstructs_exact_logical_ncas() {
    let (fixture, original_nsp) = qualified_fixture();
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_fixture(directory.path(), &fixture);
    let source_before = fs::read(&files.source).expect("source baseline");

    let result = Engine::new().execute_operation(
        compression_plan(&files, nscb::NszCompression::Balanced)
            .expect("qualified XCI plans for compression"),
        &Default::default(),
    );
    assert_eq!(result.state(), JobState::Succeeded);
    assert_eq!(result.outcome(), Some(OperationOutcome::Compressed));
    assert_eq!(
        fs::read(&files.source).expect("source after compression"),
        source_before
    );
    let compressed = fs::read(&files.destination).expect("XCZ result");
    assert_eq!(compressed[0x10D], source_before[0x10D]);
    assert_eq!(&compressed[0x118..0x11C], &source_before[0x118..0x11C]);
    assert_eq!(&compressed[0x100..0x104], &source_before[0x100..0x104]);
    assert_eq!(&compressed[0x160..0x200], &source_before[0x160..0x200]);
    assert_eq!(
        xci_secure_member_names(&compressed),
        vec![
            String::from("meta_payload.nca"),
            String::from("program_payload.ncz")
        ]
    );

    let reconstructed_xci = directory.path().join("reconstructed.xci");
    let decompressed = Engine::new().execute_operation(
        Engine::new()
            .plan_xcz_to_xci(XczToXciRequest::new(
                &files.destination,
                &reconstructed_xci,
                &files.workspace,
                &files.keys,
            ))
            .expect("generated XCZ plans for reconstruction"),
        &Default::default(),
    );
    assert_eq!(decompressed.state(), JobState::Succeeded);
    assert_eq!(decompressed.outcome(), Some(OperationOutcome::Decompressed));

    let reconstructed_nsp = directory.path().join("reconstructed.nsp");
    let converted = Engine::new().execute_operation(
        Engine::new()
            .plan_xci_to_nsp(XciToNspRequest::new(
                &reconstructed_xci,
                &reconstructed_nsp,
                &files.workspace,
                &files.keys,
            ))
            .expect("reconstructed XCI qualifies for logical NCA extraction"),
        &Default::default(),
    );
    assert_eq!(converted.state(), JobState::Succeeded);
    let reconstructed_package = fs::read(reconstructed_nsp).expect("logical NCA package");
    assert_eq!(
        pfs0_member(&reconstructed_package, "meta.nca"),
        original_nsp.meta_nca
    );
    assert_eq!(
        pfs0_member(&reconstructed_package, "program.nca"),
        original_nsp.program_nca
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn accepts_only_canonical_empty_auxiliary_partitions() {
    let nsp = synthetic_nsp_qualification::build_with_program_payload(&vec![0xA5; 0x9000], |_| {});
    let canonical = synthetic_xci::build(
        &nsp.meta_nca,
        &nsp.program_nca,
        &nsp.package,
        &nsp.key_file,
        ["program.nca", "meta.nca"],
        true,
    );
    let expanded_root = synthetic_xci::expand_root_header_padding(qualified_fixture().0);
    let accepted = [qualified_fixture().0, canonical, expanded_root];
    for (index, fixture) in accepted.into_iter().enumerate() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let files = write_fixture(directory.path(), &fixture);
        if index == 2 {
            assert!(
                Engine::new()
                    .plan_xci_to_nsp(XciToNspRequest::new(
                        &files.source,
                        directory.path().join("baseline.nsp"),
                        &files.workspace,
                        &files.keys,
                    ))
                    .is_ok(),
                "expanded zero-padded source remains valid XCI"
            );
        }
        let result = compression_plan(&files, nscb::NszCompression::Balanced);
        assert!(
            result.is_ok(),
            "canonical empty auxiliary fixture {index} is eligible: {:?}",
            result.err().map(|error| error.code())
        );
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn rejects_referenced_and_unreferenced_auxiliary_payload_before_staging() {
    let unsupported = [
        synthetic_xci::with_nonempty_partition("update"),
        synthetic_xci::with_auxiliary_unreferenced_bytes("update", &[0xA5; 0x200]),
        synthetic_xci::with_auxiliary_unreferenced_bytes("normal", &[0; 0x200]),
        synthetic_xci::with_auxiliary_gap_bytes("update", &[0x5A; 0x200]),
        synthetic_xci::with_nonzero_empty_partition_padding("normal"),
        synthetic_xci::with_nonzero_root_header_padding(),
    ];
    for fixture in unsupported {
        let directory = tempfile::tempdir().expect("temporary directory");
        let files = write_fixture(directory.path(), &fixture);
        let error = match compression_plan(&files, nscb::NszCompression::Balanced) {
            Ok(_) => panic!("noncanonical auxiliary data must fail during planning"),
            Err(error) => error,
        };
        assert_ne!(error.code(), OperationFailureCode::ValidationFailed);
        assert!(!files.destination.exists());
        assert_eq!(
            fs::read_dir(&files.workspace)
                .expect("workspace entries")
                .count(),
            0
        );
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn resolves_all_supported_compression_levels_and_rejects_out_of_range_levels() {
    let fixture = qualified_fixture().0;
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_fixture(directory.path(), &fixture);
    assert!(compression_plan(&files, nscb::NszCompression::default()).is_ok());
    for compression in [
        nscb::NszCompression::Fast,
        nscb::NszCompression::Balanced,
        nscb::NszCompression::Maximum,
    ]
    .into_iter()
    .chain((1..=19).map(nscb::NszCompression::Level))
    {
        let result = compression_plan(&files, compression);
        assert!(
            result.is_ok(),
            "compression choice {compression:?}: {:?}",
            result.err().map(|error| error.code())
        );
    }
    let error = match compression_plan(&files, nscb::NszCompression::Level(20)) {
        Ok(_) => panic!("out-of-range compression levels fail during planning"),
        Err(error) => error,
    };
    assert_eq!(error.code(), OperationFailureCode::InvalidCompressionLevel);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn rejects_a_missing_application_key_before_staging() {
    let fixture = qualified_fixture().0;
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_fixture(directory.path(), &fixture);
    let keys_without_application_key = fixture
        .key_file
        .split_inclusive(|byte| *byte == b'\n')
        .filter(|line| !line.starts_with(b"key_area_key_application_00"))
        .flat_map(|line| line.iter().copied())
        .collect::<Vec<_>>();
    fs::write(&files.keys, keys_without_application_key).expect("write incomplete key file");

    let error = match compression_plan(&files, nscb::NszCompression::Balanced) {
        Ok(_) => panic!("missing application key must fail during planning"),
        Err(error) => error,
    };

    assert_eq!(error.code(), OperationFailureCode::RequiredKeyMissing);
    assert!(!files.destination.exists());
    assert_eq!(
        fs::read_dir(&files.workspace).expect("workspace").count(),
        0
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn rejects_control_content_and_other_non_base_profiles() {
    let fixture = three_member_fixture();
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_fixture(directory.path(), &fixture);
    let error = match compression_plan(&files, nscb::NszCompression::Balanced) {
        Ok(_) => panic!("three-member Control content must be rejected"),
        Err(error) => error,
    };
    assert_eq!(
        error.code(),
        OperationFailureCode::UnsupportedContentProfile
    );
    assert!(!files.destination.exists());
    assert_eq!(
        fs::read_dir(&files.workspace).expect("workspace").count(),
        0
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn validates_compressed_output_before_resolving_destination_conflicts() {
    let fixture = qualified_fixture().0;
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_fixture(directory.path(), &fixture);
    let initial = Engine::new().execute_operation(
        compression_plan(&files, nscb::NszCompression::Fast).expect("initial compression plan"),
        &OperationSession::new(),
    );
    assert_eq!(initial.outcome(), Some(OperationOutcome::Compressed));
    let expected = fs::read(&files.destination).expect("validated XCZ");

    let current = directory.path().join("already-current.xcz");
    fs::write(&current, &expected).expect("matching destination");
    let current_files = TestFiles {
        source: files.source.clone(),
        destination: current.clone(),
        keys: files.keys.clone(),
        workspace: files.workspace.clone(),
    };
    let up_to_date = Engine::new().execute_operation(
        compression_plan(&current_files, nscb::NszCompression::Fast).expect("already-current plan"),
        &OperationSession::new(),
    );
    assert_eq!(
        up_to_date.outcome(),
        Some(OperationOutcome::AlreadyUpToDate)
    );

    for (name, policy, expected_outcome) in [
        ("fail", ConflictPolicy::Fail, None),
        (
            "skip",
            ConflictPolicy::Skip,
            Some(OperationOutcome::Skipped),
        ),
        (
            "replace",
            ConflictPolicy::Replace,
            Some(OperationOutcome::Compressed),
        ),
    ] {
        let destination = directory.path().join(format!("{name}.xcz"));
        let previous = b"preexisting destination bytes";
        fs::write(&destination, previous).expect("existing destination");
        let policy_files = TestFiles {
            source: files.source.clone(),
            destination: destination.clone(),
            keys: files.keys.clone(),
            workspace: files.workspace.clone(),
        };
        let plan = compression_plan_with_policy(&policy_files, nscb::NszCompression::Fast, policy)
            .expect("deferred destination-policy plan");
        let result = Engine::new().execute_operation(plan, &OperationSession::new());
        if let Some(outcome) = expected_outcome {
            assert_eq!(result.state(), JobState::Succeeded);
            assert_eq!(result.outcome(), Some(outcome));
        } else {
            assert_eq!(result.state(), JobState::Failed);
            assert_eq!(
                result.failure().map(|failure| failure.code()),
                Some(OperationFailureCode::DestinationConflict)
            );
        }
        if policy == ConflictPolicy::Replace {
            assert_eq!(fs::read(&destination).expect("replacement"), expected);
        } else {
            assert_eq!(
                fs::read(&destination).expect("preserved destination"),
                previous
            );
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn rejects_source_and_key_mutations_and_pre_cancel_without_publication() {
    let fixture = qualified_fixture().0;
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_fixture(directory.path(), &fixture);

    let source_plan =
        compression_plan(&files, nscb::NszCompression::Fast).expect("source-mutation plan");
    fs::write(&files.source, b"mutated source").expect("mutate source");
    let changed_source = Engine::new().execute_operation(source_plan, &OperationSession::new());
    assert_eq!(changed_source.state(), JobState::Failed);
    assert_eq!(
        changed_source.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::SourceChanged)
    );
    assert!(!files.destination.exists());

    fs::write(&files.source, &fixture.image).expect("restore source");
    let key_plan = compression_plan(&files, nscb::NszCompression::Fast).expect("key-mutation plan");
    fs::write(&files.keys, b"mutated key file").expect("mutate keys");
    let changed_keys = Engine::new().execute_operation(key_plan, &OperationSession::new());
    assert_eq!(changed_keys.state(), JobState::Failed);
    assert_eq!(
        changed_keys.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::KeyFileChanged)
    );
    assert!(!files.destination.exists());

    fs::write(&files.keys, &fixture.key_file).expect("restore keys");
    let cancel_plan =
        compression_plan(&files, nscb::NszCompression::Fast).expect("pre-cancel plan");
    let cancellation = CancellationHandle::new();
    cancellation.cancel();
    let cancelled = Engine::new().execute_operation_with_cancellation(
        cancel_plan,
        &OperationSession::new(),
        cancellation,
    );
    assert_eq!(cancelled.state(), JobState::Cancelled);
    assert!(!files.destination.exists());
    assert_eq!(
        fs::read_dir(&files.workspace).expect("workspace").count(),
        0
    );
    assert_eq!(
        fs::read(&files.source).expect("source remains"),
        fixture.image
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn preserves_a_destination_created_after_planning() {
    let fixture = qualified_fixture().0;
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_fixture(directory.path(), &fixture);
    let plan =
        compression_plan(&files, nscb::NszCompression::Fast).expect("plan before destination race");
    let raced_bytes = b"destination appeared after planning";
    fs::write(&files.destination, raced_bytes).expect("create racing destination");

    let result = Engine::new().execute_operation(plan, &OperationSession::new());
    assert_eq!(result.state(), JobState::Failed);
    assert!(matches!(
        result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::DestinationChanged | OperationFailureCode::DestinationConflict)
    ));
    assert_eq!(
        fs::read(&files.destination).expect("racing destination remains"),
        raced_bytes
    );
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
#[test]
fn reports_unsupported_capability_without_opening_inputs() {
    let error = Engine::new()
        .plan_xci_to_xcz(XciToXczRequest::new(
            "missing.xci",
            "output.xcz",
            "missing-workspace",
            "missing-keys.dat",
        ))
        .err()
        .expect("XCI compression requires native macOS arm64");
    assert_eq!(error.code(), OperationFailureCode::UnsupportedCapability);
}
