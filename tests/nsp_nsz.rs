#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::fs;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::path::{Path, PathBuf};
#[cfg(feature = "standalone-job-history")]
use std::process::Command;

#[allow(dead_code)]
#[path = "support/synthetic_nsp_qualification.rs"]
mod synthetic_nsp_qualification;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use nscb::{
    ConflictPolicy, Engine, JobState, NspToNszRequest, NszCompression, NszToNspRequest,
    OperationArtifactRole, OperationFailureCode, OperationKind, OperationOutcome, OperationSession,
};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct ConversionFiles {
    source: PathBuf,
    destination: PathBuf,
    key_file: PathBuf,
    workspace: PathBuf,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn large_fixture() -> synthetic_nsp_qualification::Fixture {
    synthetic_nsp_qualification::build_with_program_payload(&vec![0xa5; 0x9000], |_| {})
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn write_files(
    root: &Path,
    fixture: &synthetic_nsp_qualification::Fixture,
    suffix: &str,
) -> ConversionFiles {
    let files = ConversionFiles {
        source: root.join(format!("source-{suffix}.nsp")),
        destination: root.join(format!("output-{suffix}.nsz")),
        key_file: root.join("keys.dat"),
        workspace: root.join(format!("workspace-{suffix}")),
    };
    fs::create_dir(&files.workspace).expect("workspace directory");
    fs::write(&files.source, &fixture.package).expect("NSP source");
    fs::write(&files.key_file, &fixture.key_file).expect("synthetic qualification keys");
    files
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn compress_plan(files: &ConversionFiles, policy: ConflictPolicy) -> nscb::OperationPlan {
    Engine::new()
        .plan_nsp_to_nsz(
            NspToNszRequest::new(
                &files.source,
                &files.destination,
                &files.workspace,
                &files.key_file,
            )
            .with_conflict_policy(policy),
        )
        .expect("qualified NSP compression plan")
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn compress_plan_with_selection(
    files: &ConversionFiles,
    policy: ConflictPolicy,
    compression: NszCompression,
) -> nscb::OperationPlan {
    Engine::new()
        .plan_nsp_to_nsz(
            NspToNszRequest::new(
                &files.source,
                &files.destination,
                &files.workspace,
                &files.key_file,
            )
            .with_conflict_policy(policy)
            .with_compression(compression),
        )
        .expect("qualified NSP compression plan with selection")
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn encode_with_frozen_parameters(plaintext: &[u8], level: i32) -> Vec<u8> {
    use std::io::Write as _;

    let pledged_src_size = u64::try_from(plaintext.len()).expect("fixture length fits u64");
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), level)
        .expect("independent Zstandard encoder");
    encoder.window_log(27).expect("qualified window log");
    encoder.include_checksum(true).expect("qualified checksum");
    encoder
        .include_contentsize(true)
        .expect("qualified content size");
    encoder
        .set_parameter(zstd::zstd_safe::CParameter::NbWorkers(0))
        .expect("single-threaded encoder");
    encoder
        .set_pledged_src_size(Some(pledged_src_size))
        .expect("pledged source size");
    encoder
        .write_all(plaintext)
        .expect("write independent frame input");
    encoder.finish().expect("finish independent frame")
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn decompress_plan(
    source: &Path,
    destination: &Path,
    key_file: &Path,
    workspace: &Path,
) -> nscb::OperationPlan {
    Engine::new()
        .plan_nsz_to_nsp(NszToNspRequest::new(
            source,
            destination,
            workspace,
            key_file,
        ))
        .expect("structurally eligible NSZ decompression plan")
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn pfs0_members(package: &[u8]) -> Vec<(String, Vec<u8>)> {
    assert_eq!(&package[..4], b"PFS0");
    let count = u32::from_le_bytes(package[4..8].try_into().unwrap()) as usize;
    let string_table_size = u32::from_le_bytes(package[8..12].try_into().unwrap()) as usize;
    let entries_offset = 16;
    let strings_offset = entries_offset + count * 24;
    let payload_offset = strings_offset + string_table_size;
    (0..count)
        .map(|index| {
            let entry = entries_offset + index * 24;
            let offset = u64::from_le_bytes(package[entry..entry + 8].try_into().unwrap()) as usize;
            let length =
                u64::from_le_bytes(package[entry + 8..entry + 16].try_into().unwrap()) as usize;
            let name_offset =
                u32::from_le_bytes(package[entry + 16..entry + 20].try_into().unwrap()) as usize;
            let name_start = strings_offset + name_offset;
            let name_end = package[name_start..strings_offset + string_table_size]
                .iter()
                .position(|byte| *byte == 0)
                .map(|offset| name_start + offset)
                .unwrap();
            (
                String::from_utf8(package[name_start..name_end].to_vec()).unwrap(),
                package[payload_offset + offset..payload_offset + offset + length].to_vec(),
            )
        })
        .collect()
}

#[cfg(feature = "standalone-job-history")]
#[test]
fn cli_reports_compression_selection_usage_errors_consistently() {
    use std::ffi::OsString;

    let cases: [(&str, &str, &[&str]); 13] = [
        ("invalid preset", "nsp-to-nsz", &["--preset", "turbo"]),
        ("invalid level", "nsp-to-nsz", &["--level", "not-a-number"]),
        ("out-of-range level", "nsp-to-nsz", &["--level", "20"]),
        ("missing preset", "nsp-to-nsz", &["--preset"]),
        ("missing level", "nsp-to-nsz", &["--level"]),
        (
            "duplicate presets",
            "nsp-to-nsz",
            &["--preset", "fast", "--preset", "maximum"],
        ),
        (
            "duplicate levels",
            "nsp-to-nsz",
            &["--level", "3", "--level", "9"],
        ),
        (
            "preset before level",
            "nsp-to-nsz",
            &["--preset", "fast", "--level", "3"],
        ),
        (
            "level before preset",
            "nsp-to-nsz",
            &["--level", "3", "--preset", "fast"],
        ),
        (
            "preset on decompression",
            "nsz-to-nsp",
            &["--preset", "fast"],
        ),
        ("level on decompression", "nsz-to-nsp", &["--level", "9"]),
        (
            "preset on XCI conversion",
            "xci-to-nsp",
            &["--preset", "fast"],
        ),
        ("level on XCI conversion", "xci-to-nsp", &["--level", "9"]),
    ];
    let modes = [
        ("text", None, false),
        ("json", Some("--json"), true),
        ("jsonl", Some("--jsonl"), false),
    ];
    let cli = env!("CARGO_BIN_EXE_nscb");
    let home = tempfile::tempdir().expect("temporary CLI home");

    for (case_name, command, selection) in cases {
        for (mode_name, mode_option, mode_before_selection) in modes {
            let mut args = vec![OsString::from(command)];
            if mode_before_selection {
                args.push(OsString::from(mode_option.expect("machine output option")));
            }
            args.extend(
                [
                    "--source",
                    "source.nsp",
                    "--output",
                    "output.nsz",
                    "--workspace",
                    "workspace",
                    "--keys",
                    "keys.dat",
                ]
                .into_iter()
                .map(OsString::from),
            );
            args.extend(selection.iter().copied().map(OsString::from));
            if !mode_before_selection && let Some(mode_option) = mode_option {
                args.push(OsString::from(mode_option));
            }

            let output = Command::new(cli)
                .args(&args)
                .env("HOME", home.path())
                .output()
                .expect("run invalid compression CLI command");
            assert_eq!(
                output.status.code(),
                Some(2),
                "{case_name} in {mode_name} mode: {output:?}"
            );

            if mode_name == "text" {
                assert!(output.stdout.is_empty(), "text usage errors use stderr");
                assert!(
                    String::from_utf8_lossy(&output.stderr)
                        .to_ascii_lowercase()
                        .contains("usage"),
                    "text usage error lacks usage guidance: {output:?}"
                );
            } else {
                assert!(output.stderr.is_empty(), "machine errors use stdout");
                let records = output
                    .stdout
                    .split(|byte| *byte == b'\n')
                    .filter(|line| !line.is_empty())
                    .collect::<Vec<_>>();
                assert_eq!(records.len(), 1, "one error record is emitted");
                let document: serde_json::Value =
                    serde_json::from_slice(records[0]).expect("machine usage error document");
                assert_eq!(document["schema_version"], 1);
                assert_eq!(document["kind"], "error");
                assert_eq!(document["error"]["code"], "usage_error");
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn compresses_and_reconstructs_the_exact_nsp_with_content_selected_program() {
    let fixture = large_fixture();
    assert!(fixture.program_nca.len() > 0x4000);
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_files(directory.path(), &fixture, "roundtrip");
    let plan = compress_plan(&files, ConflictPolicy::Fail);
    let snapshot = plan.snapshot();
    assert_eq!(snapshot.operation_kind(), OperationKind::NspToNsz);
    let staged_output = snapshot
        .planned_artifacts()
        .iter()
        .find(|artifact| artifact.role() == OperationArtifactRole::StagedOutput)
        .expect("planned staged output");
    assert_eq!(staged_output.expected_length(), None);
    assert_eq!(staged_output.expected_sha256(), None);
    let plan_json = serde_json::to_string(snapshot).expect("serializable plan");
    assert!(!plan_json.contains("33333333333333333333333333333333"));

    let compressed = Engine::new().execute_operation(plan, &OperationSession::new());
    assert_eq!(
        compressed.state(),
        JobState::Succeeded,
        "compression failure: {:?}",
        (
            compressed.failure().map(|failure| failure.code()),
            compressed.milestones()
        )
    );
    assert_eq!(compressed.outcome(), Some(OperationOutcome::Compressed));
    let nsz = fs::read(&files.destination).expect("published NSZ");

    let balanced_destination = directory.path().join("explicit-balanced.nsz");
    let balanced_workspace = directory.path().join("workspace-explicit-balanced");
    fs::create_dir(&balanced_workspace).expect("Balanced workspace");
    let balanced_plan = Engine::new()
        .plan_nsp_to_nsz(
            NspToNszRequest::new(
                &files.source,
                &balanced_destination,
                &balanced_workspace,
                &files.key_file,
            )
            .with_compression(NszCompression::Balanced),
        )
        .expect("explicit Balanced plan");
    let balanced_result = Engine::new().execute_operation(balanced_plan, &OperationSession::new());
    assert_eq!(
        balanced_result.outcome(),
        Some(OperationOutcome::Compressed)
    );
    assert_eq!(
        fs::read(balanced_destination).expect("explicit Balanced NSZ"),
        nsz,
        "the default level 9 operation must remain byte-compatible with explicit Balanced"
    );

    let level9_destination = directory.path().join("explicit-level-9.nsz");
    let level9_workspace = directory.path().join("workspace-explicit-level-9");
    fs::create_dir(&level9_workspace).expect("explicit level 9 workspace");
    let level9_plan = Engine::new()
        .plan_nsp_to_nsz(
            NspToNszRequest::new(
                &files.source,
                &level9_destination,
                &level9_workspace,
                &files.key_file,
            )
            .with_compression(NszCompression::Level(9)),
        )
        .expect("explicit level 9 plan");
    let level9_result = Engine::new().execute_operation(level9_plan, &OperationSession::new());
    assert_eq!(level9_result.outcome(), Some(OperationOutcome::Compressed));
    assert_eq!(
        fs::read(level9_destination).expect("explicit level 9 NSZ"),
        nsz,
        "omitted selection, Balanced, and Level(9) must be byte-identical"
    );

    let nsz_members = pfs0_members(&nsz);
    assert_ne!(
        &nsz_members[1].1[0x4040..0x4048],
        &[0; 8],
        "the supported NCZ counter contains a nonzero low half"
    );
    assert_eq!(
        &nsz_members[1].1[0x4048..0x4050],
        &[0; 8],
        "the NCZ record reserves the high counter half as zero"
    );
    assert_eq!(nsz_members[0].0, "program.nca");
    assert_eq!(nsz_members[1].0, "meta.cnmt.ncz");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&files.destination)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let mut interoperable_geometry_nsz = nsz.clone();
    let record_marker = interoperable_geometry_nsz
        .windows(8)
        .position(|window| window == b"NCZSECTN")
        .expect("NCZ section record");
    let section_offset = 0x0c00_u64;
    let section_size = fixture.program_nca.len() as u64 - section_offset;
    interoperable_geometry_nsz[record_marker + 16..record_marker + 24]
        .copy_from_slice(&section_offset.to_le_bytes());
    interoperable_geometry_nsz[record_marker + 24..record_marker + 32]
        .copy_from_slice(&section_size.to_le_bytes());
    let interoperable_geometry_path = directory.path().join("upstream-geometry.nsz");
    fs::write(&interoperable_geometry_path, interoperable_geometry_nsz)
        .expect("NSZ with standard section geometry");

    let output_nsp = directory.path().join("reconstructed.nsp");
    let output_workspace = directory.path().join("workspace-decompress");
    fs::create_dir(&output_workspace).expect("decompression workspace");
    let plan = decompress_plan(
        &interoperable_geometry_path,
        &output_nsp,
        &files.key_file,
        &output_workspace,
    );
    let staged_output = plan
        .snapshot()
        .planned_artifacts()
        .iter()
        .find(|artifact| artifact.role() == OperationArtifactRole::StagedOutput)
        .expect("planned reconstructed NSP");
    assert_eq!(
        staged_output.expected_length(),
        Some(fixture.package.len() as u64)
    );
    assert_eq!(staged_output.expected_sha256(), None);
    let decompressed = Engine::new().execute_operation(plan, &OperationSession::new());
    assert_eq!(decompressed.state(), JobState::Succeeded);
    assert_eq!(decompressed.outcome(), Some(OperationOutcome::Decompressed));
    assert_eq!(
        fs::read(&output_nsp).expect("reconstructed NSP"),
        fixture.package
    );

    let current_plan = Engine::new()
        .plan_nsz_to_nsp(
            NszToNspRequest::new(
                &interoperable_geometry_path,
                &output_nsp,
                &output_workspace,
                &files.key_file,
            )
            .with_conflict_policy(ConflictPolicy::Skip),
        )
        .expect("plan against byte-identical reconstructed output");
    let current_result = Engine::new().execute_operation(current_plan, &OperationSession::new());
    assert_eq!(
        current_result.outcome(),
        Some(OperationOutcome::AlreadyUpToDate)
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn named_presets_reconstruct_the_exact_synthetic_nsp() {
    let fixture = large_fixture();
    let directory = tempfile::tempdir().expect("temporary directory");
    let presets = [
        ("fast", NszCompression::Fast),
        ("balanced", NszCompression::Balanced),
        ("maximum", NszCompression::Maximum),
    ];

    for (name, preset) in presets {
        let files = write_files(directory.path(), &fixture, name);
        let plan = Engine::new()
            .plan_nsp_to_nsz(
                NspToNszRequest::new(
                    &files.source,
                    &files.destination,
                    &files.workspace,
                    &files.key_file,
                )
                .with_compression(preset),
            )
            .expect("qualified preset plan");
        let compressed = Engine::new().execute_operation(plan, &OperationSession::new());
        assert_eq!(
            compressed.state(),
            JobState::Succeeded,
            "{name} compression failed: {:?}",
            compressed.failure().map(|failure| failure.code())
        );

        let reconstructed = directory.path().join(format!("reconstructed-{name}.nsp"));
        let decompress_workspace = directory
            .path()
            .join(format!("workspace-decompress-{name}"));
        fs::create_dir(&decompress_workspace).expect("decompression workspace");
        let plan = Engine::new()
            .plan_nsz_to_nsp(NszToNspRequest::new(
                &files.destination,
                &reconstructed,
                &decompress_workspace,
                &files.key_file,
            ))
            .expect("qualified decompression plan");
        let decompressed = Engine::new().execute_operation(plan, &OperationSession::new());
        assert_eq!(decompressed.state(), JobState::Succeeded);
        assert_eq!(
            fs::read(&reconstructed).expect("reconstructed NSP"),
            fixture.package,
            "{name} output must decode to the exact synthetic NSP"
        );
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn explicit_numeric_levels_reconstruct_the_exact_synthetic_nsp() {
    let fixture = large_fixture();
    let directory = tempfile::tempdir().expect("temporary directory");

    for level in 1..=19 {
        let suffix = format!("level-{level}");
        let files = write_files(directory.path(), &fixture, &suffix);
        let plan = Engine::new()
            .plan_nsp_to_nsz(
                NspToNszRequest::new(
                    &files.source,
                    &files.destination,
                    &files.workspace,
                    &files.key_file,
                )
                .with_compression(NszCompression::Level(level)),
            )
            .expect("qualified numeric-level plan");
        let compressed = Engine::new().execute_operation(plan, &OperationSession::new());
        assert_eq!(
            compressed.state(),
            JobState::Succeeded,
            "level {level} compression failed: {:?}",
            compressed.failure().map(|failure| failure.code())
        );
        assert_eq!(compressed.outcome(), Some(OperationOutcome::Compressed));

        let reconstructed = directory.path().join(format!("reconstructed-{suffix}.nsp"));
        let decompress_workspace = directory
            .path()
            .join(format!("workspace-decompress-{suffix}"));
        fs::create_dir(&decompress_workspace).expect("decompression workspace");
        let plan = Engine::new()
            .plan_nsz_to_nsp(NszToNspRequest::new(
                &files.destination,
                &reconstructed,
                &decompress_workspace,
                &files.key_file,
            ))
            .expect("qualified decompression plan");
        let decompressed = Engine::new().execute_operation(plan, &OperationSession::new());
        assert_eq!(
            decompressed.state(),
            JobState::Succeeded,
            "level {level} decompression failed: {:?}",
            decompressed.failure().map(|failure| failure.code())
        );
        assert_eq!(decompressed.outcome(), Some(OperationOutcome::Decompressed));
        assert_eq!(
            fs::read(&reconstructed).expect("reconstructed NSP"),
            fixture.package,
            "level {level} output must decode to the exact synthetic NSP"
        );
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn maximum_frame_matches_an_independent_zstandard_encoder() {
    let fixture = large_fixture();
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_files(directory.path(), &fixture, "independent-frame");
    let plan = compress_plan_with_selection(&files, ConflictPolicy::Fail, NszCompression::Maximum);
    let result = Engine::new().execute_operation(plan, &OperationSession::new());
    assert_eq!(result.outcome(), Some(OperationOutcome::Compressed));

    let members = pfs0_members(&fs::read(&files.destination).expect("published NSZ"));
    let program_ncz = &members
        .iter()
        .find(|(name, _)| name.ends_with(".ncz"))
        .expect("compressed Program member")
        .1;
    let emitted_frame = &program_ncz[0x4050..];
    let plaintext = zstd::stream::decode_all(emitted_frame).expect("decode emitted frame");
    let expected_maximum = encode_with_frozen_parameters(&plaintext, 19);
    let expected_balanced = encode_with_frozen_parameters(&plaintext, 9);

    assert_ne!(
        expected_maximum, expected_balanced,
        "synthetic frame input must distinguish Maximum from hardcoded level 9"
    );
    assert_eq!(
        emitted_frame, expected_maximum,
        "emitted Maximum frame must match an independent encoder with captured settings"
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn deferred_destination_policies_compare_the_validated_output() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let fixture = large_fixture();
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_files(directory.path(), &fixture, "conflicts");
    let source_plan =
        compress_plan_with_selection(&files, ConflictPolicy::Fail, NszCompression::Maximum);
    let result = Engine::new().execute_operation(source_plan, &OperationSession::new());
    assert_eq!(
        result.outcome(),
        Some(OperationOutcome::Compressed),
        "compression failure: {:?}",
        result.failure().map(|failure| failure.code())
    );
    let expected = fs::read(&files.destination).expect("reference NSZ");

    let current = directory.path().join("current.nsz");
    fs::write(&current, &expected).expect("matching destination");
    let current_plan = Engine::new()
        .plan_nsp_to_nsz(
            NspToNszRequest::new(&files.source, &current, &files.workspace, &files.key_file)
                .with_compression(NszCompression::Maximum),
        )
        .expect("plan with unknown output bytes and existing destination");
    let current_result = Engine::new().execute_operation(current_plan, &OperationSession::new());
    assert_eq!(
        current_result.outcome(),
        Some(OperationOutcome::AlreadyUpToDate)
    );

    for (suffix, policy, expected_outcome) in [
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
        let destination = directory.path().join(format!("{suffix}.nsz"));
        fs::write(&destination, b"old destination bytes").expect("existing destination");
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(&destination)
                .expect("existing destination metadata")
                .permissions();
            permissions.set_mode(0o640);
            fs::set_permissions(&destination, permissions).expect("set existing permissions");
        }
        let plan = Engine::new()
            .plan_nsp_to_nsz(
                NspToNszRequest::new(
                    &files.source,
                    &destination,
                    &files.workspace,
                    &files.key_file,
                )
                .with_conflict_policy(policy)
                .with_compression(NszCompression::Maximum),
            )
            .expect("deferred conflict planning");
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
            assert_eq!(fs::read(&destination).unwrap(), expected);
        } else {
            assert_eq!(fs::read(&destination).unwrap(), b"old destination bytes");
        }
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&destination)
                .expect("destination metadata")
                .permissions()
                .mode()
                & 0o777,
            if policy == ConflictPolicy::Replace {
                0o600
            } else {
                0o640
            },
            "{suffix} policy must preserve existing permissions or use private staged permissions"
        );
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn redacts_key_material_from_plans_events_and_results() {
    use std::fmt::Write as _;

    let fixture = large_fixture();
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_files(directory.path(), &fixture, "redaction");
    let request = NspToNszRequest::new(
        &files.source,
        &files.destination,
        &files.workspace,
        &files.key_file,
    )
    .with_compression(NszCompression::Maximum);
    let request_debug = format!("{request:?}");
    let plan = Engine::new()
        .plan_nsp_to_nsz(request)
        .expect("qualified compression plan");
    let snapshot = plan.snapshot();
    let snapshot_json = serde_json::to_string(&snapshot).expect("plan JSON");
    let snapshot_debug = format!("{snapshot:?}");
    let snapshot_value = serde_json::to_value(snapshot).expect("plan JSON value");
    assert!(snapshot_value.get("compression").is_none());
    let session = OperationSession::new();
    let consumer = session.subscribe_events().expect("event consumer");
    let result = Engine::new().execute_operation(plan, &session);
    assert_eq!(result.outcome(), Some(OperationOutcome::Compressed));
    let events = std::iter::from_fn(|| consumer.try_recv().ok()).collect::<Vec<_>>();
    let retained_spool_bytes = result
        .artifacts()
        .iter()
        .filter(|artifact| {
            artifact.retained() && artifact.role() == OperationArtifactRole::PrivateMemberSpool
        })
        .map(|artifact| artifact.length().expect("spool length"))
        .sum::<u64>();
    assert_eq!(result.retained_storage_bytes(), Some(retained_spool_bytes));
    let event_json = serde_json::to_string(&events).expect("event JSON");
    let event_debug = format!("{events:?}");
    let result_json = serde_json::to_string(&result).expect("result JSON");
    let result_debug = format!("{result:?}");

    let nsz = fs::read(&files.destination).expect("published NSZ");
    let nsz_members = pfs0_members(&nsz);
    let program_ncz = &nsz_members[1].1;
    let mut key = String::new();
    let mut counter = String::new();
    for byte in &program_ncz[0x4030..0x4040] {
        write!(&mut key, "{byte:02x}").unwrap();
    }
    for byte in &program_ncz[0x4040..0x4050] {
        write!(&mut counter, "{byte:02x}").unwrap();
    }
    let secrets = ["42".repeat(32), "24".repeat(16), key, counter];
    let surfaces = [
        request_debug,
        snapshot_json,
        snapshot_debug,
        event_json,
        event_debug,
        result_json,
        result_debug,
    ];
    for (index, surface) in surfaces.iter().enumerate() {
        for secret in &secrets {
            assert!(
                !surface.contains(secret),
                "public operation surface {index} contains key material"
            );
        }
    }

    let failed_files = write_files(directory.path(), &fixture, "redaction-failure");
    let failed_request = NspToNszRequest::new(
        &failed_files.source,
        &failed_files.destination,
        &failed_files.workspace,
        &failed_files.key_file,
    )
    .with_compression(NszCompression::Maximum);
    let failed_request_debug = format!("{failed_request:?}");
    let failed_plan = Engine::new()
        .plan_nsp_to_nsz(failed_request)
        .expect("plan selected compression for failure reporting");
    let failed_snapshot = failed_plan.snapshot();
    let failed_snapshot_json = serde_json::to_string(&failed_snapshot).expect("failure plan JSON");
    let failed_snapshot_debug = format!("{failed_snapshot:?}");
    fs::write(&failed_files.key_file, b"changed after planning").expect("mutate key file");
    let failed_session = OperationSession::new();
    let failed_consumer = failed_session
        .subscribe_events()
        .expect("failure event consumer");
    let failed_result = Engine::new().execute_operation(failed_plan, &failed_session);
    assert_eq!(failed_result.state(), JobState::Failed);
    assert_eq!(
        failed_result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::KeyFileChanged)
    );
    assert!(!failed_files.destination.exists());
    let failed_events = std::iter::from_fn(|| failed_consumer.try_recv().ok()).collect::<Vec<_>>();
    let failed_surfaces = [
        failed_request_debug,
        failed_snapshot_json,
        failed_snapshot_debug,
        serde_json::to_string(&failed_events).expect("failure event JSON"),
        format!("{failed_events:?}"),
        serde_json::to_string(&failed_result).expect("failure result JSON"),
        format!("{failed_result:?}"),
    ];
    for (index, surface) in failed_surfaces.iter().enumerate() {
        for secret in &secrets {
            assert!(
                !surface.contains(secret),
                "failure surface {index} contains key material"
            );
        }
    }
}

#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "standalone-job-history"
))]
#[test]
fn cli_history_and_diagnostics_redact_key_material() {
    let fixture = large_fixture();
    let directory = tempfile::tempdir().expect("temporary CLI home");
    let files = write_files(directory.path(), &fixture, "cli-redaction");
    let cli = env!("CARGO_BIN_EXE_nscb");
    fn find_history_databases(root: &Path, matches: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(root) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if entry.file_name() == std::ffi::OsStr::new("jobs.sqlite3") {
                matches.push(path);
            } else if entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
                find_history_databases(&path, matches);
            }
        }
    }

    let successful = Command::new(cli)
        .env("HOME", directory.path())
        .args(["nsp-to-nsz", "--source"])
        .arg(&files.source)
        .args(["--output"])
        .arg(&files.destination)
        .arg("--workspace")
        .arg(&files.workspace)
        .arg("--keys")
        .arg(&files.key_file)
        .args(["--preset", "maximum"])
        .arg("--json")
        .output()
        .expect("run compression CLI");
    assert_eq!(successful.status.code(), Some(0), "{successful:?}");
    let result: serde_json::Value =
        serde_json::from_slice(&successful.stdout).expect("conversion JSON result");
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["kind"], "nsp_nsz.job_result");
    assert_eq!(result["plan"]["operation_kind"], "nsp_to_nsz");
    assert_eq!(result["result"]["state"], "succeeded");
    assert_eq!(result["result"]["outcome"], "compressed");

    let nsz_members = pfs0_members(&fs::read(&files.destination).expect("published NSZ"));
    let program_ncz = nsz_members
        .into_iter()
        .find(|(name, _)| name.ends_with(".ncz"))
        .expect("compressed Program member")
        .1;
    let to_hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let key_sentinels = [
        "42".repeat(32),
        "24".repeat(16),
        to_hex(&program_ncz[0x4030..0x4040]),
        to_hex(&program_ncz[0x4040..0x4050]),
    ];
    let successful_output = format!(
        "{}{}",
        String::from_utf8_lossy(&successful.stdout),
        String::from_utf8_lossy(&successful.stderr)
    );
    for sentinel in &key_sentinels {
        assert!(!successful_output.contains(sentinel));
    }

    let reconstructed_nsp = directory.path().join("json-reconstructed.nsp");
    let json_decompression_workspace = directory.path().join("workspace-json-decompression");
    fs::create_dir(&json_decompression_workspace).expect("JSON decompression workspace");
    let decompressed = Command::new(cli)
        .env("HOME", directory.path())
        .args(["nsz-to-nsp", "--source"])
        .arg(&files.destination)
        .arg("--output")
        .arg(&reconstructed_nsp)
        .arg("--workspace")
        .arg(&json_decompression_workspace)
        .arg("--keys")
        .arg(&files.key_file)
        .arg("--json")
        .output()
        .expect("run decompression CLI");
    assert_eq!(decompressed.status.code(), Some(0), "{decompressed:?}");
    let decompression_result: serde_json::Value =
        serde_json::from_slice(&decompressed.stdout).expect("decompression JSON result");
    assert_eq!(decompression_result["schema_version"], 1);
    assert_eq!(decompression_result["kind"], "nsp_nsz.job_result");
    assert_eq!(decompression_result["plan"]["operation_kind"], "nsz_to_nsp");
    assert_eq!(decompression_result["result"]["state"], "succeeded");
    assert_eq!(decompression_result["result"]["outcome"], "decompressed");
    assert_eq!(
        fs::read(&reconstructed_nsp).expect("JSON reconstructed NSP"),
        fixture.package
    );

    let history = Command::new(cli)
        .env("HOME", directory.path())
        .args(["jobs", "list", "--json"])
        .output()
        .expect("read operation history");
    assert_eq!(history.status.code(), Some(0), "{history:?}");
    let history_output = format!(
        "{}{}",
        String::from_utf8_lossy(&history.stdout),
        String::from_utf8_lossy(&history.stderr)
    );
    for sentinel in &key_sentinels {
        assert!(!history_output.contains(sentinel));
    }
    let mut history_databases = Vec::new();
    find_history_databases(directory.path(), &mut history_databases);
    assert_eq!(history_databases.len(), 1, "history database discovery");
    let history_bytes = fs::read(&history_databases[0]).expect("persisted operation history");
    let history_storage = String::from_utf8_lossy(&history_bytes);
    for sentinel in &key_sentinels {
        assert!(!history_storage.contains(sentinel));
    }

    let diagnostic_keys = directory.path().join("diagnostic-keys.dat");
    let diagnostic_header_key = "66".repeat(32);
    let diagnostic_application_key = "77".repeat(16);
    fs::write(
        &diagnostic_keys,
        format!(
            "header_key = {diagnostic_header_key}\nkey_area_key_application_00 = {diagnostic_application_key}\n"
        ),
    )
    .expect("write alternate synthetic keys");
    let diagnostic = Command::new(cli)
        .env("HOME", directory.path())
        .args(["nsp-to-nsz", "--source"])
        .arg(&files.source)
        .args(["--output"])
        .arg(directory.path().join("diagnostic-output.nsz"))
        .arg("--workspace")
        .arg(directory.path().join("diagnostic-workspace"))
        .arg("--keys")
        .arg(&diagnostic_keys)
        .args(["--preset", "maximum"])
        .arg("--json")
        .output()
        .expect("run failing compression CLI");
    assert_ne!(diagnostic.status.code(), Some(0), "{diagnostic:?}");
    let diagnostic_output = format!(
        "{}{}",
        String::from_utf8_lossy(&diagnostic.stdout),
        String::from_utf8_lossy(&diagnostic.stderr)
    );
    for sentinel in key_sentinels
        .iter()
        .chain([&diagnostic_header_key, &diagnostic_application_key])
    {
        assert!(!diagnostic_output.contains(sentinel));
    }

    let jsonl_diagnostic = Command::new(cli)
        .env("HOME", directory.path())
        .args(["nsp-to-nsz", "--source"])
        .arg(&files.source)
        .arg("--output")
        .arg(directory.path().join("diagnostic-output-jsonl.nsz"))
        .arg("--workspace")
        .arg(directory.path().join("diagnostic-workspace-jsonl"))
        .arg("--keys")
        .arg(&diagnostic_keys)
        .args(["--preset", "maximum"])
        .arg("--jsonl")
        .output()
        .expect("run failing JSONL compression CLI");
    assert_ne!(
        jsonl_diagnostic.status.code(),
        Some(0),
        "{jsonl_diagnostic:?}"
    );
    for line in jsonl_diagnostic
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let _: serde_json::Value = serde_json::from_slice(line).expect("JSONL diagnostic record");
    }
    let jsonl_diagnostic_output = format!(
        "{}{}",
        String::from_utf8_lossy(&jsonl_diagnostic.stdout),
        String::from_utf8_lossy(&jsonl_diagnostic.stderr)
    );
    for sentinel in key_sentinels
        .iter()
        .chain([&diagnostic_header_key, &diagnostic_application_key])
    {
        assert!(!jsonl_diagnostic_output.contains(sentinel));
    }
}

#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "standalone-job-history"
))]
#[test]
fn conversion_cli_jsonl_preserves_event_and_terminal_record_contract() {
    fn assert_successful_jsonl(stdout: &[u8], operation_kind: &str, outcome: &str) {
        let records = stdout
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<serde_json::Value>(line).expect("JSONL record"))
            .collect::<Vec<_>>();
        assert!(
            records.len() >= 2,
            "events and terminal JSONL record are emitted"
        );
        assert_eq!(
            records[..records.len() - 1]
                .iter()
                .filter(|record| record["kind"] == "job.event")
                .count(),
            records.len() - 1
        );
        for (sequence, event) in records[..records.len() - 1].iter().enumerate() {
            assert_eq!(event["kind"], "job.event");
            assert_eq!(event["schema_version"], 1);
            assert_eq!(event["nscb_version"], env!("CARGO_PKG_VERSION"));
            assert_eq!(event["sequence"], sequence as u64);
            assert!(event["snapshot"].is_object());
        }
        let terminal = records.last().expect("terminal JSONL result");
        assert_eq!(terminal["schema_version"], 1);
        assert_eq!(terminal["nscb_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(terminal["kind"], "nsp_nsz.job_result");
        assert_eq!(terminal["plan"]["operation_kind"], operation_kind);
        assert!(terminal["plan"].get("compression").is_none());
        assert_eq!(terminal["session"]["status"], "succeeded");
        assert_eq!(terminal["result"]["state"], "succeeded");
        assert_eq!(terminal["result"]["outcome"], outcome);
    }

    let fixture = large_fixture();
    let directory = tempfile::tempdir().expect("temporary CLI home");
    let files = write_files(directory.path(), &fixture, "cli-jsonl");
    let cli = env!("CARGO_BIN_EXE_nscb");

    let compression = Command::new(cli)
        .env("HOME", directory.path())
        .args(["nsp-to-nsz", "--source"])
        .arg(&files.source)
        .arg("--output")
        .arg(&files.destination)
        .arg("--workspace")
        .arg(&files.workspace)
        .arg("--keys")
        .arg(&files.key_file)
        .args(["--preset", "maximum"])
        .arg("--jsonl")
        .output()
        .expect("run NSP-to-NSZ JSONL command");
    assert_eq!(compression.status.code(), Some(0), "{compression:?}");
    assert!(compression.stderr.is_empty());
    let compressed_member = pfs0_members(&fs::read(&files.destination).expect("compressed NSZ"))
        .into_iter()
        .find(|(name, _)| name.ends_with(".ncz"))
        .expect("compressed Program member")
        .1;
    let to_hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let key_sentinels = [
        "42".repeat(32),
        "24".repeat(16),
        to_hex(&compressed_member[0x4030..0x4040]),
        to_hex(&compressed_member[0x4040..0x4050]),
    ];
    let assert_no_key_material = |output: &[u8]| {
        let output = String::from_utf8_lossy(output);
        for sentinel in &key_sentinels {
            assert!(
                !output.contains(sentinel),
                "JSONL output contains key material"
            );
        }
    };
    assert_no_key_material(&compression.stdout);
    assert_successful_jsonl(&compression.stdout, "nsp_to_nsz", "compressed");

    let reconstructed = directory.path().join("reconstructed.nsp");
    let decompression_workspace = directory.path().join("workspace-decompression");
    fs::create_dir(&decompression_workspace).expect("decompression workspace");
    let decompression = Command::new(cli)
        .env("HOME", directory.path())
        .args(["nsz-to-nsp", "--source"])
        .arg(&files.destination)
        .arg("--output")
        .arg(&reconstructed)
        .arg("--workspace")
        .arg(&decompression_workspace)
        .arg("--keys")
        .arg(&files.key_file)
        .arg("--jsonl")
        .output()
        .expect("run NSZ-to-NSP JSONL command");
    assert_eq!(decompression.status.code(), Some(0), "{decompression:?}");
    assert!(decompression.stderr.is_empty());
    assert_no_key_material(&decompression.stdout);
    assert_successful_jsonl(&decompression.stdout, "nsz_to_nsp", "decompressed");
    assert_eq!(
        fs::read(&reconstructed).expect("reconstructed NSP"),
        fixture.package
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn altered_cleartext_ncz_keys_and_counters_fail_cnmt_qualification() {
    let fixture = large_fixture();
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_files(directory.path(), &fixture, "tamper-source");
    let result = Engine::new().execute_operation(
        compress_plan(&files, ConflictPolicy::Fail),
        &OperationSession::new(),
    );
    assert_eq!(result.outcome(), Some(OperationOutcome::Compressed));
    let original_nsz = fs::read(&files.destination).expect("compressed NSZ");
    let record_marker = original_nsz
        .windows(8)
        .position(|window| window == b"NCZSECTN")
        .expect("NCZ section record");

    for (suffix, record_offset) in [("key", 48_usize), ("counter", 64_usize)] {
        let mut corrupted = original_nsz.clone();
        corrupted[record_marker + record_offset] ^= 0x80;
        let source = directory.path().join(format!("corrupted-{suffix}.nsz"));
        let destination = directory.path().join(format!("rejected-{suffix}.nsp"));
        let workspace = directory.path().join(format!("workspace-{suffix}"));
        fs::create_dir(&workspace).expect("workspace");
        fs::write(&source, corrupted).expect("tampered NSZ");
        let plan = decompress_plan(&source, &destination, &files.key_file, &workspace);
        let result = Engine::new().execute_operation(plan, &OperationSession::new());
        assert_eq!(result.state(), JobState::Failed);
        assert!(matches!(
            result.failure().map(|failure| failure.code()),
            Some(
                OperationFailureCode::KeyOrSectionIntegrityFailure
                    | OperationFailureCode::ValidationFailed
            )
        ));
        assert!(!destination.exists());
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn decompression_requires_external_application_keys_for_semantic_qualification() {
    let fixture = large_fixture();
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_files(directory.path(), &fixture, "external-key");
    let result = Engine::new().execute_operation(
        compress_plan(&files, ConflictPolicy::Fail),
        &OperationSession::new(),
    );
    assert_eq!(result.outcome(), Some(OperationOutcome::Compressed));

    let wrong_keys = directory.path().join("wrong-application-key.dat");
    fs::write(
        &wrong_keys,
        synthetic_nsp_qualification::key_file_with_application_kaek([0x25; 16]),
    )
    .expect("wrong external application key");
    let destination = directory.path().join("must-not-publish.nsp");
    let workspace = directory.path().join("workspace-wrong-key");
    fs::create_dir(&workspace).unwrap();
    let plan = decompress_plan(&files.destination, &destination, &wrong_keys, &workspace);
    let result = Engine::new().execute_operation(plan, &OperationSession::new());
    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::KeyOrSectionIntegrityFailure)
    );
    assert!(!destination.exists());
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn rejects_trailing_data_after_the_single_ncz_frame() {
    let fixture = large_fixture();
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_files(directory.path(), &fixture, "frame-source");
    let result = Engine::new().execute_operation(
        compress_plan(&files, ConflictPolicy::Fail),
        &OperationSession::new(),
    );
    assert_eq!(result.outcome(), Some(OperationOutcome::Compressed));
    let compressed_members = pfs0_members(&fs::read(&files.destination).unwrap());
    let mut program_ncz = compressed_members[1].1.clone();
    program_ncz.push(0);
    let trailing_frame_nsz = synthetic_nsp_qualification::package_with_named_members(
        &fixture.meta_nca,
        &program_ncz,
        "program.nca",
        "meta.cnmt.ncz",
    );
    let source = directory.path().join("trailing-frame.nsz");
    let destination = directory.path().join("rejected-frame.nsp");
    let workspace = directory.path().join("workspace-trailing-frame");
    fs::create_dir(&workspace).unwrap();
    fs::write(&source, trailing_frame_nsz).unwrap();
    let plan = decompress_plan(&source, &destination, &files.key_file, &workspace);
    let result = Engine::new().execute_operation(plan, &OperationSession::new());
    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::ValidationFailed)
    );
    assert!(!destination.exists());
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn rejects_truncated_and_corrupt_ncz_frames() {
    let fixture = large_fixture();
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_files(directory.path(), &fixture, "corrupt-frame-source");
    let result = Engine::new().execute_operation(
        compress_plan(&files, ConflictPolicy::Fail),
        &OperationSession::new(),
    );
    assert_eq!(result.outcome(), Some(OperationOutcome::Compressed));
    let compressed_members = pfs0_members(&fs::read(&files.destination).unwrap());

    for (suffix, truncate) in [("truncated", true), ("corrupt", false)] {
        let mut program_ncz = compressed_members[1].1.clone();
        if truncate {
            program_ncz.pop();
        } else {
            let last = program_ncz.len() - 1;
            program_ncz[last] ^= 0x80;
        }
        let source_package = synthetic_nsp_qualification::package_with_named_members(
            &fixture.meta_nca,
            &program_ncz,
            "program.nca",
            "meta.cnmt.ncz",
        );
        let source = directory.path().join(format!("{suffix}.nsz"));
        let destination = directory.path().join(format!("{suffix}.nsp"));
        let workspace = directory.path().join(format!("workspace-{suffix}"));
        fs::create_dir(&workspace).unwrap();
        fs::write(&source, source_package).unwrap();
        let plan = decompress_plan(&source, &destination, &files.key_file, &workspace);
        let result = Engine::new().execute_operation(plan, &OperationSession::new());
        assert_eq!(result.state(), JobState::Failed);
        assert_eq!(
            result.failure().map(|failure| failure.code()),
            Some(OperationFailureCode::ValidationFailed)
        );
        assert!(!destination.exists());
    }

    let mut program_ncz = compressed_members[1].1.clone();
    // The NCZ frame begins at 0x4050; byte 5 is its first content-size byte.
    program_ncz[0x4055] ^= 0x01;
    let source_package = synthetic_nsp_qualification::package_with_named_members(
        &fixture.meta_nca,
        &program_ncz,
        "program.nca",
        "meta.cnmt.ncz",
    );
    let source = directory.path().join("mismatched-frame-size.nsz");
    let destination = directory.path().join("mismatched-frame-size.nsp");
    let workspace = directory.path().join("workspace-mismatched-frame-size");
    fs::create_dir(&workspace).unwrap();
    fs::write(&source, source_package).unwrap();
    let plan = decompress_plan(&source, &destination, &files.key_file, &workspace);
    let result = Engine::new().execute_operation(plan, &OperationSession::new());
    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::ValidationFailed)
    );
    assert!(!destination.exists());
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn rejects_block_compression_and_multiple_ncz_section_records() {
    let fixture = large_fixture();
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_files(directory.path(), &fixture, "unsupported-frame-source");
    let result = Engine::new().execute_operation(
        compress_plan(&files, ConflictPolicy::Fail),
        &OperationSession::new(),
    );
    assert_eq!(result.outcome(), Some(OperationOutcome::Compressed));
    let compressed_members = pfs0_members(&fs::read(&files.destination).unwrap());
    let multiple_records = 2_u64.to_le_bytes();
    let invalid_marker = *b"BADMARK!";
    let unsupported_section_offset = 0x5000_u64.to_le_bytes();

    for (suffix, offset, value) in [
        ("block", 0x4050_usize, b"NCZBLOCK".as_slice()),
        (
            "multiple-records",
            0x4008_usize,
            multiple_records.as_slice(),
        ),
        ("invalid-marker", 0x4010_usize, invalid_marker.as_slice()),
        (
            "unsupported-section-offset",
            0x4010_usize,
            unsupported_section_offset.as_slice(),
        ),
    ] {
        let mut program_ncz = compressed_members[1].1.clone();
        program_ncz[offset..offset + value.len()].copy_from_slice(value);
        let source_package = synthetic_nsp_qualification::package_with_named_members(
            &fixture.meta_nca,
            &program_ncz,
            "program.nca",
            "meta.cnmt.ncz",
        );
        let source = directory.path().join(format!("{suffix}.nsz"));
        let destination = directory.path().join(format!("{suffix}.nsp"));
        let workspace = directory.path().join(format!("workspace-{suffix}"));
        fs::create_dir(&workspace).unwrap();
        fs::write(&source, source_package).unwrap();
        let error = match Engine::new().plan_nsz_to_nsp(NszToNspRequest::new(
            &source,
            &destination,
            &workspace,
            &files.key_file,
        )) {
            Ok(_) => panic!("unsupported NCZ framing must fail planning"),
            Err(error) => error,
        };
        assert_eq!(
            error.code(),
            OperationFailureCode::UnsupportedContentProfile
        );
        assert!(!destination.exists());
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn detects_source_and_key_mutation_after_planning() {
    let fixture = large_fixture();
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_files(directory.path(), &fixture, "mutation");

    let source_plan =
        compress_plan_with_selection(&files, ConflictPolicy::Fail, NszCompression::Maximum);
    fs::write(&files.source, b"changed after planning").unwrap();
    let source_result = Engine::new().execute_operation(source_plan, &OperationSession::new());
    assert_eq!(source_result.state(), JobState::Failed);
    assert_eq!(
        source_result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::SourceChanged)
    );
    assert!(!files.destination.exists());

    fs::write(&files.source, &fixture.package).unwrap();
    let key_plan =
        compress_plan_with_selection(&files, ConflictPolicy::Fail, NszCompression::Maximum);
    fs::write(&files.key_file, b"changed after planning").unwrap();
    let key_result = Engine::new().execute_operation(key_plan, &OperationSession::new());
    assert_eq!(key_result.state(), JobState::Failed);
    assert_eq!(
        key_result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::KeyFileChanged)
    );
    assert!(!files.destination.exists());
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn detects_decompression_source_and_key_mutation_after_planning() {
    let fixture = large_fixture();
    let directory = tempfile::tempdir().expect("temporary directory");
    let files = write_files(directory.path(), &fixture, "decompression-mutation");
    let compressed = Engine::new().execute_operation(
        compress_plan(&files, ConflictPolicy::Fail),
        &OperationSession::new(),
    );
    assert_eq!(compressed.outcome(), Some(OperationOutcome::Compressed));
    let original_nsz = fs::read(&files.destination).expect("valid NSZ input");

    let source_destination = directory.path().join("source-changed.nsp");
    let source_workspace = directory.path().join("workspace-source-changed");
    fs::create_dir(&source_workspace).expect("source-change workspace");
    let source_plan = decompress_plan(
        &files.destination,
        &source_destination,
        &files.key_file,
        &source_workspace,
    );
    fs::write(&files.destination, b"changed after decompression planning")
        .expect("mutate NSZ after planning");
    let source_result = Engine::new().execute_operation(source_plan, &OperationSession::new());
    assert_eq!(source_result.state(), JobState::Failed);
    assert_eq!(
        source_result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::SourceChanged)
    );
    assert!(!source_destination.exists());

    fs::write(&files.destination, original_nsz).expect("restore NSZ input");
    let key_destination = directory.path().join("key-changed.nsp");
    let key_workspace = directory.path().join("workspace-key-changed");
    fs::create_dir(&key_workspace).expect("key-change workspace");
    let key_plan = decompress_plan(
        &files.destination,
        &key_destination,
        &files.key_file,
        &key_workspace,
    );
    fs::write(&files.key_file, b"changed after decompression planning")
        .expect("mutate keys after planning");
    let key_result = Engine::new().execute_operation(key_plan, &OperationSession::new());
    assert_eq!(key_result.state(), JobState::Failed);
    assert_eq!(
        key_result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::KeyFileChanged)
    );
    assert!(!key_destination.exists());
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn rejects_unsupported_member_suffixes_and_output_name_collisions() {
    let fixture = large_fixture();
    let directory = tempfile::tempdir().expect("temporary directory");
    let key_file = directory.path().join("keys.dat");
    fs::write(&key_file, &fixture.key_file).unwrap();
    for (label, program_name) in [
        ("missing-suffix", "program"),
        ("uppercase-suffix", "program.NCA"),
        ("unsupported-suffix", "program.bin"),
    ] {
        let source = directory.path().join(format!("{label}.nsp"));
        let destination = directory.path().join(format!("{label}.nsz"));
        let workspace = directory.path().join(format!("workspace-{label}"));
        fs::create_dir(&workspace).unwrap();
        let unsupported_package = synthetic_nsp_qualification::package_with_named_members(
            &fixture.meta_nca,
            &fixture.program_nca,
            "metadata.nca",
            program_name,
        );
        fs::write(&source, unsupported_package).unwrap();
        let error = match Engine::new().plan_nsp_to_nsz(NspToNszRequest::new(
            &source,
            &destination,
            &workspace,
            &key_file,
        )) {
            Ok(_) => panic!("only an exact terminal .nca suffix is supported"),
            Err(error) => error,
        };
        assert_eq!(
            error.code(),
            OperationFailureCode::UnsupportedContentProfile
        );
    }

    let too_many_members = synthetic_nsp_qualification::package_with_extra_member(
        &fixture.meta_nca,
        &fixture.program_nca,
        "extra.nca",
        b"extra member",
    );
    let source = directory.path().join("too-many-members.nsp");
    let destination = directory.path().join("too-many-members.nsz");
    let workspace = directory.path().join("workspace-too-many-members");
    fs::create_dir(&workspace).unwrap();
    fs::write(&source, too_many_members).unwrap();
    let error = match Engine::new().plan_nsp_to_nsz(NspToNszRequest::new(
        &source,
        &destination,
        &workspace,
        &key_file,
    )) {
        Ok(_) => panic!("the profile accepts exactly two members"),
        Err(error) => error,
    };
    assert_eq!(
        error.code(),
        OperationFailureCode::UnsupportedContentProfile
    );

    let files = write_files(directory.path(), &fixture, "collision-base");
    let result = Engine::new().execute_operation(
        compress_plan(&files, ConflictPolicy::Fail),
        &OperationSession::new(),
    );
    assert_eq!(result.outcome(), Some(OperationOutcome::Compressed));
    let compressed_members = pfs0_members(&fs::read(&files.destination).unwrap());
    let collision_nsz = synthetic_nsp_qualification::package_with_named_members(
        &fixture.meta_nca,
        &compressed_members[1].1,
        "program.nca",
        "program.ncz",
    );
    let collision_source = directory.path().join("collision.nsz");
    let collision_destination = directory.path().join("collision.nsp");
    let collision_workspace = directory.path().join("workspace-collision");
    fs::create_dir(&collision_workspace).unwrap();
    fs::write(&collision_source, collision_nsz).unwrap();
    let error = match Engine::new().plan_nsz_to_nsp(NszToNspRequest::new(
        &collision_source,
        &collision_destination,
        &collision_workspace,
        &files.key_file,
    )) {
        Ok(_) => panic!("renamed output members collide after suffix conversion"),
        Err(error) => error,
    };
    assert_eq!(error.code(), OperationFailureCode::InvalidContentPackage);
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
#[test]
fn conversion_is_typed_unsupported_outside_native_arm64_macos() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let engine = nscb::Engine::new();
    let selections = [
        nscb::NszCompression::Fast,
        nscb::NszCompression::Balanced,
        nscb::NszCompression::Maximum,
        nscb::NszCompression::Level(1),
        nscb::NszCompression::Level(19),
    ];
    for (index, compression) in selections.into_iter().enumerate() {
        let error = match engine.plan_nsp_to_nsz(
            nscb::NspToNszRequest::new(
                directory.path().join(format!("input-{index}.nsp")),
                directory.path().join(format!("output-{index}.nsz")),
                directory.path().join(format!("workspace-{index}")),
                directory.path().join("keys.dat"),
            )
            .with_compression(compression),
        ) {
            Ok(_) => panic!("{compression:?} conversion must be unsupported on this target"),
            Err(error) => error,
        };
        assert_eq!(
            error.code(),
            nscb::OperationFailureCode::UnsupportedCapability,
            "{compression:?} must keep the target capability boundary"
        );
    }

    let error = match engine.plan_nsz_to_nsp(nscb::NszToNspRequest::new(
        directory.path().join("input.nsz"),
        directory.path().join("output.nsp"),
        directory.path().join("workspace"),
        directory.path().join("keys.dat"),
    )) {
        Ok(_) => panic!("decompression must be unsupported on this target"),
        Err(error) => error,
    };
    assert_eq!(
        error.code(),
        nscb::OperationFailureCode::UnsupportedCapability
    );
}
