#![cfg(target_os = "macos")]

use nscb::{
    CancellationHandle, Engine, JobState, MultiContentBuildRequest, MultiContentSplitRequest,
    OperationArtifactRole, OperationFailureCode, OperationKind, OperationOutcome, OperationSession,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::process::Command;

const FIRST_PROGRAM_ID: u64 = 0x0102_0304_0506_0708;
const SECOND_PROGRAM_ID: u64 = 0x1112_1314_1516_1718;

#[test]
fn build_then_split_recovers_each_program_group_without_original_sources() {
    let root = tempfile::tempdir().expect("temporary root");
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");

    let first_component = program_nca(FIRST_PROGRAM_ID, 1, b"first component bytes");
    let related_component = program_nca(FIRST_PROGRAM_ID, 0, b"related component bytes");
    let second_component = program_nca(SECOND_PROGRAM_ID, 0, b"second program bytes");
    let first_source = root.path().join("first.pfs0");
    let second_source = root.path().join("second.pfs0");
    fs::write(
        &first_source,
        pfs0(&[
            ("arbitrary-a.bin", first_component.clone()),
            ("arbitrary-b.bin", related_component.clone()),
        ]),
    )
    .expect("first source package");
    fs::write(
        &second_source,
        pfs0(&[("not-an-identity.nca", second_component.clone())]),
    )
    .expect("second source package");
    let first_source_before = fs::read(&first_source).expect("source bytes");
    let second_source_before = fs::read(&second_source).expect("source bytes");

    let combined = root.path().join("combined.pfs0");
    let engine = Engine::new();
    let build_plan = engine
        .plan_multi_content_build(MultiContentBuildRequest::new(
            vec![second_source.clone(), first_source.clone()],
            &combined,
            &workspace,
        ))
        .expect("build plan");
    assert_eq!(
        build_plan.snapshot().operation_kind(),
        OperationKind::MultiContentBuild
    );
    assert_eq!(build_plan.snapshot().sources().len(), 2);
    assert_eq!(build_plan.snapshot().content_groups().len(), 2);
    assert_eq!(
        build_plan
            .snapshot()
            .content_groups()
            .iter()
            .map(|group| group.program_id())
            .collect::<Vec<_>>(),
        vec![FIRST_PROGRAM_ID, SECOND_PROGRAM_ID]
    );

    let build = engine.execute_operation(build_plan, &Default::default());
    assert_eq!(
        build.state(),
        JobState::Succeeded,
        "failure={:?}",
        build.failure().map(|failure| failure.code())
    );
    assert_eq!(build.outcome(), Some(OperationOutcome::Built));
    let built_bytes = fs::read(&combined).expect("combined package bytes");
    let repeated_output = root.path().join("repeated.pfs0");
    let repeated_plan = engine
        .plan_multi_content_build(MultiContentBuildRequest::new(
            vec![first_source.clone(), second_source.clone()],
            &repeated_output,
            &workspace,
        ))
        .expect("repeat build plan");
    let repeated = engine.execute_operation(repeated_plan, &Default::default());
    assert_eq!(repeated.outcome(), Some(OperationOutcome::Built));
    assert_eq!(
        fs::read(&repeated_output).expect("repeated package bytes"),
        built_bytes
    );
    assert_eq!(
        fs::read(&first_source).expect("first source remains unchanged"),
        first_source_before
    );
    assert_eq!(
        fs::read(&second_source).expect("second source remains unchanged"),
        second_source_before
    );

    let combined_members = read_pfs0(&fs::read(&combined).expect("combined package"));
    assert_eq!(
        combined_members
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        vec![
            "0102030405060708_00000000.nca",
            "0102030405060708_00000001.nca",
            "1112131415161718_00000000.nca",
        ]
    );

    // The split operation must recover its evidence from the combined package.
    fs::remove_file(&first_source).expect("remove original source package");
    fs::remove_file(&second_source).expect("remove original source package");
    let split_directory = root.path().join("split-output");
    let split_plan = engine
        .plan_multi_content_split(MultiContentSplitRequest::new(
            &combined,
            &split_directory,
            &workspace,
        ))
        .expect("split plan");
    assert_eq!(
        split_plan.snapshot().operation_kind(),
        OperationKind::MultiContentSplit
    );
    assert_eq!(split_plan.snapshot().content_groups().len(), 2);

    let split = engine.execute_operation(split_plan, &Default::default());
    assert_eq!(
        split.state(),
        JobState::Succeeded,
        "failure={:?}, cleanup_warning={:?}, milestones={:?}, artifacts={:?}",
        split.failure().map(|failure| failure.code()),
        split.cleanup_warning().map(|failure| failure.code()),
        split.milestones(),
        split.artifacts()
    );
    assert_eq!(split.outcome(), Some(OperationOutcome::Split));
    let first_output = read_pfs0(
        &fs::read(split_directory.join("0102030405060708.pfs0")).expect("first group output"),
    );
    let second_output = read_pfs0(
        &fs::read(split_directory.join("1112131415161718.pfs0")).expect("second group output"),
    );
    assert_eq!(first_output.len(), 2);
    assert_eq!(second_output.len(), 1);
    assert_eq!(first_output[0].1, related_component);
    assert_eq!(first_output[1].1, first_component);
    assert_eq!(second_output[0].1, second_component);
    assert_eq!(sha256(&first_output[0].1), sha256(&related_component));
    assert_eq!(sha256(&first_output[1].1), sha256(&first_component));
    assert_eq!(sha256(&second_output[0].1), sha256(&second_component));
    assert_eq!(
        sha256(&first_output[0].1),
        sha256(&program_nca(
            FIRST_PROGRAM_ID,
            0,
            b"related component bytes"
        ))
    );
}

#[test]
fn build_rejects_duplicate_program_content_indices_before_creating_output() {
    let root = tempfile::tempdir().expect("temporary root");
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    let source = root.path().join("duplicate.pfs0");
    fs::write(
        &source,
        pfs0(&[
            ("first.nca", program_nca(FIRST_PROGRAM_ID, 3, b"first")),
            (
                "second.nca",
                program_nca(FIRST_PROGRAM_ID, 3, b"duplicate index"),
            ),
            (
                "other.nca",
                program_nca(SECOND_PROGRAM_ID, 0, b"other program"),
            ),
        ]),
    )
    .expect("source package");
    let destination = root.path().join("combined.pfs0");

    let error = match Engine::new().plan_multi_content_build(MultiContentBuildRequest::new(
        vec![source],
        &destination,
        &workspace,
    )) {
        Err(error) => error,
        Ok(_) => panic!("duplicate identity must be rejected during planning"),
    };
    assert_eq!(error.code(), OperationFailureCode::DuplicateContentMember);
    assert!(!destination.exists());
}

#[test]
fn build_rejects_hard_link_aliases_in_the_source_selection() {
    let root = tempfile::tempdir().expect("temporary root");
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    let source = root.path().join("source.pfs0");
    fs::write(
        &source,
        pfs0(&[
            ("first.nca", program_nca(FIRST_PROGRAM_ID, 0, b"first")),
            ("second.nca", program_nca(SECOND_PROGRAM_ID, 0, b"second")),
        ]),
    )
    .expect("source package");
    let alias = root.path().join("alias.pfs0");
    fs::hard_link(&source, &alias).expect("hard-link source alias");
    let destination = root.path().join("combined.pfs0");

    let error = match Engine::new().plan_multi_content_build(MultiContentBuildRequest::new(
        vec![source, alias],
        &destination,
        &workspace,
    )) {
        Err(error) => error,
        Ok(_) => panic!("two names for one file must be rejected"),
    };
    assert_eq!(error.code(), OperationFailureCode::DuplicateInput);
    assert!(!destination.exists());
}

#[test]
fn split_revalidates_source_before_publishing_any_component_output() {
    let root = tempfile::tempdir().expect("temporary root");
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    let source = root.path().join("combined.pfs0");
    fs::write(
        &source,
        pfs0(&[
            ("first.nca", program_nca(FIRST_PROGRAM_ID, 0, b"first")),
            ("second.nca", program_nca(SECOND_PROGRAM_ID, 0, b"second")),
        ]),
    )
    .expect("combined package");
    let destination = root.path().join("split-output");
    let plan = Engine::new()
        .plan_multi_content_split(MultiContentSplitRequest::new(
            &source,
            &destination,
            &workspace,
        ))
        .expect("split plan");
    fs::write(&source, b"changed after planning").expect("change source");

    let result = Engine::new().execute_operation(plan, &Default::default());
    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::SourceChanged)
    );
    assert!(!destination.exists());
}

#[test]
fn split_conflict_policies_preserve_or_recover_existing_directory_data() {
    let root = tempfile::tempdir().expect("temporary root");
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    let source = root.path().join("combined.pfs0");
    fs::write(
        &source,
        pfs0(&[
            ("first.nca", program_nca(FIRST_PROGRAM_ID, 0, b"first")),
            ("second.nca", program_nca(SECOND_PROGRAM_ID, 0, b"second")),
        ]),
    )
    .expect("combined package");
    let engine = Engine::new();

    let fail_destination = root.path().join("fail-output");
    fs::create_dir(&fail_destination).expect("fail destination");
    fs::write(fail_destination.join("preserve.txt"), b"keep on fail")
        .expect("fail destination marker");
    let failed = engine
        .plan_multi_content_split(
            MultiContentSplitRequest::new(&source, &fail_destination, &workspace)
                .with_conflict_policy(nscb::ConflictPolicy::Fail),
        )
        .expect("fail-policy split plan");
    let failed = engine.execute_operation(failed, &Default::default());
    assert_eq!(failed.state(), JobState::Failed);
    assert_eq!(
        failed.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::DestinationConflict)
    );
    assert_eq!(
        fs::read(fail_destination.join("preserve.txt")).expect("fail destination remains"),
        b"keep on fail"
    );

    let skip_destination = root.path().join("skip-output");
    fs::create_dir(&skip_destination).expect("skip destination");
    fs::write(skip_destination.join("preserve.txt"), b"keep on skip")
        .expect("skip destination marker");
    let skipped = engine
        .plan_multi_content_split(
            MultiContentSplitRequest::new(&source, &skip_destination, &workspace)
                .with_conflict_policy(nscb::ConflictPolicy::Skip),
        )
        .expect("skip-policy split plan");
    let skipped = engine.execute_operation(skipped, &Default::default());
    assert_eq!(skipped.state(), JobState::Succeeded);
    assert_eq!(skipped.outcome(), Some(OperationOutcome::Skipped));
    assert_eq!(
        fs::read(skip_destination.join("preserve.txt")).expect("skip destination remains"),
        b"keep on skip"
    );
    assert!(!skip_destination.join("0102030405060708.pfs0").exists());

    let replace_destination = root.path().join("replace-output");
    fs::create_dir(&replace_destination).expect("replace destination");
    fs::write(
        replace_destination.join("preserve.txt"),
        b"recover on replace",
    )
    .expect("replace destination marker");
    let replace_plan = engine
        .plan_multi_content_split(
            MultiContentSplitRequest::new(&source, &replace_destination, &workspace)
                .with_conflict_policy(nscb::ConflictPolicy::Replace),
        )
        .expect("replace-policy split plan");
    let replaced = engine.execute_operation(replace_plan, &Default::default());
    assert_eq!(replaced.state(), JobState::Succeeded);
    assert_eq!(replaced.outcome(), Some(OperationOutcome::Split));
    assert!(replace_destination.join("0102030405060708.pfs0").is_file());
    assert!(replace_destination.join("1112131415161718.pfs0").is_file());
    assert!(!replace_destination.join("preserve.txt").exists());
    let displaced = replaced
        .artifacts()
        .iter()
        .find(|artifact| artifact.role() == OperationArtifactRole::DisplacedDestination)
        .expect("replaced directory retained for recovery");
    assert_eq!(
        fs::read(displaced.path().join("preserve.txt")).expect("displaced data retained"),
        b"recover on replace"
    );
}

#[test]
fn split_rejects_a_destination_created_after_planning_without_replacing_it() {
    let root = tempfile::tempdir().expect("temporary root");
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    let source = root.path().join("combined.pfs0");
    fs::write(
        &source,
        pfs0(&[
            ("first.nca", program_nca(FIRST_PROGRAM_ID, 0, b"first")),
            ("second.nca", program_nca(SECOND_PROGRAM_ID, 0, b"second")),
        ]),
    )
    .expect("combined package");
    let destination = root.path().join("split-output");
    let plan = Engine::new()
        .plan_multi_content_split(MultiContentSplitRequest::new(
            &source,
            &destination,
            &workspace,
        ))
        .expect("split plan");

    fs::create_dir(&destination).expect("interfering destination directory");
    fs::write(
        destination.join("preserve.txt"),
        b"preserve the competing entry",
    )
    .expect("interfering destination content");
    let baseline = fs::read(destination.join("preserve.txt")).expect("destination baseline");

    let result = Engine::new().execute_operation(plan, &Default::default());
    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::DestinationChanged)
    );
    assert_eq!(
        fs::read(destination.join("preserve.txt")).expect("competing content remains"),
        baseline
    );
    assert!(!destination.join("0102030405060708.pfs0").exists());
}

#[test]
fn build_rejects_a_destination_created_after_planning_without_replacing_it() {
    let root = tempfile::tempdir().expect("temporary root");
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    let source = root.path().join("source.pfs0");
    fs::write(
        &source,
        pfs0(&[
            ("first.nca", program_nca(FIRST_PROGRAM_ID, 0, b"first")),
            ("second.nca", program_nca(SECOND_PROGRAM_ID, 0, b"second")),
        ]),
    )
    .expect("source package");
    let destination = root.path().join("combined.pfs0");
    let plan = Engine::new()
        .plan_multi_content_build(MultiContentBuildRequest::new(
            vec![source],
            &destination,
            &workspace,
        ))
        .expect("build plan");
    fs::write(&destination, b"destination created after planning")
        .expect("interfering destination");
    let baseline = fs::read(&destination).expect("destination baseline");

    let result = Engine::new().execute_operation(plan, &Default::default());
    assert_eq!(result.state(), JobState::Failed);
    assert_eq!(
        result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::DestinationChanged)
    );
    assert_eq!(
        fs::read(&destination).expect("destination remains untouched"),
        baseline
    );
}

#[test]
fn cancelled_before_admission_does_not_create_a_destination() {
    let root = tempfile::tempdir().expect("temporary root");
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    let source = root.path().join("source.pfs0");
    fs::write(
        &source,
        pfs0(&[
            ("first.nca", program_nca(FIRST_PROGRAM_ID, 0, b"first")),
            ("second.nca", program_nca(SECOND_PROGRAM_ID, 0, b"second")),
        ]),
    )
    .expect("source package");
    let destination = root.path().join("combined.pfs0");
    let plan = Engine::new()
        .plan_multi_content_build(MultiContentBuildRequest::new(
            vec![source],
            &destination,
            &workspace,
        ))
        .expect("build plan");
    let cancellation = CancellationHandle::new();
    cancellation.cancel();

    let result = Engine::new().execute_operation_with_cancellation(
        plan,
        &OperationSession::new(),
        cancellation,
    );
    assert_eq!(result.state(), JobState::Cancelled);
    assert_eq!(
        result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::Cancelled)
    );
    assert!(!destination.exists());
}

#[test]
fn cli_build_and_split_emit_operation_specific_json_results() {
    let root = tempfile::tempdir().expect("temporary root");
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    let first_source = root.path().join("first.pfs0");
    let second_source = root.path().join("second.pfs0");
    fs::write(
        &first_source,
        pfs0(&[("member-a.bin", program_nca(FIRST_PROGRAM_ID, 0, b"first"))]),
    )
    .expect("first source");
    fs::write(
        &second_source,
        pfs0(&[("member-b.bin", program_nca(SECOND_PROGRAM_ID, 0, b"second"))]),
    )
    .expect("second source");
    let combined = root.path().join("combined.pfs0");

    let build = Command::new(env!("CARGO_BIN_EXE_nscb"))
        .env("HOME", root.path())
        .args(["multi-content-build", "--source"])
        .arg(&first_source)
        .arg("--source")
        .arg(&second_source)
        .args(["--output"])
        .arg(&combined)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--json")
        .output()
        .expect("run multi-content-build");
    assert_eq!(build.status.code(), Some(0), "{build:?}");
    let build_result: serde_json::Value =
        serde_json::from_slice(&build.stdout).expect("build JSON result");
    assert_eq!(build_result["kind"], "multi_content.job_result");
    assert_eq!(
        build_result["plan"]["operation_kind"],
        "multi_content_build"
    );
    assert_eq!(build_result["result"]["state"], "succeeded");
    assert_eq!(build_result["result"]["outcome"], "built");

    let jsonl_output = root.path().join("combined-jsonl.pfs0");
    let jsonl_build = Command::new(env!("CARGO_BIN_EXE_nscb"))
        .env("HOME", root.path())
        .args(["multi-content-build", "--source"])
        .arg(&first_source)
        .arg("--source")
        .arg(&second_source)
        .arg("--output")
        .arg(&jsonl_output)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--jsonl")
        .output()
        .expect("run JSONL multi-content-build");
    assert_eq!(jsonl_build.status.code(), Some(0), "{jsonl_build:?}");
    let jsonl_records = std::str::from_utf8(&jsonl_build.stdout)
        .expect("JSONL output is UTF-8")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("JSONL record"))
        .collect::<Vec<_>>();
    assert!(jsonl_records.len() >= 2);
    assert_eq!(
        jsonl_records
            .iter()
            .filter(|record| record["kind"] == "job.event")
            .count(),
        jsonl_records.len() - 1
    );
    assert_eq!(
        jsonl_records.last().expect("terminal result")["kind"],
        "multi_content.job_result"
    );
    assert_eq!(
        jsonl_records.last().expect("terminal result")["result"]["outcome"],
        "built"
    );

    fs::remove_file(&first_source).expect("remove first original");
    fs::remove_file(&second_source).expect("remove second original");
    let output_directory = root.path().join("components");
    let split = Command::new(env!("CARGO_BIN_EXE_nscb"))
        .env("HOME", root.path())
        .args(["multi-content-split", "--source"])
        .arg(&combined)
        .arg("--output-directory")
        .arg(&output_directory)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--json")
        .output()
        .expect("run multi-content-split");
    let split_result: serde_json::Value =
        serde_json::from_slice(&split.stdout).expect("split JSON result");
    assert_eq!(
        split.status.code(),
        Some(0),
        "state={}, failure={}, cleanup_warning={}",
        split_result["result"]["state"],
        split_result["result"]["failure"],
        split_result["result"]["cleanup_warning"]
    );
    assert_eq!(split_result["kind"], "multi_content.job_result");
    assert_eq!(
        split_result["plan"]["operation_kind"],
        "multi_content_split"
    );
    assert_eq!(split_result["result"]["state"], "succeeded");
    assert_eq!(split_result["result"]["outcome"], "split");
    assert!(output_directory.join("0102030405060708.pfs0").is_file());
    assert!(output_directory.join("1112131415161718.pfs0").is_file());
}

fn program_nca(program_id: u64, content_index: u32, payload: &[u8]) -> Vec<u8> {
    const HEADER_SIZE: usize = 0xc00;
    const BLOCK_SIZE: usize = 0x200;
    let mut partition = pfs0(&[("payload.bin", payload.to_vec())]);
    partition.resize(partition.len().div_ceil(BLOCK_SIZE) * BLOCK_SIZE, 0);
    let nca_size = HEADER_SIZE + partition.len();
    let mut nca = vec![0_u8; nca_size];
    nca[0x200..0x204].copy_from_slice(b"NCA3");
    nca[0x204] = 0;
    nca[0x205] = 0;
    nca[0x208..0x210].copy_from_slice(&(nca_size as u64).to_le_bytes());
    nca[0x210..0x218].copy_from_slice(&program_id.to_le_bytes());
    nca[0x218..0x21c].copy_from_slice(&content_index.to_le_bytes());
    let start_block = (HEADER_SIZE / BLOCK_SIZE) as u32;
    let end_block = (nca_size / BLOCK_SIZE) as u32;
    nca[0x240..0x244].copy_from_slice(&start_block.to_le_bytes());
    nca[0x244..0x248].copy_from_slice(&end_block.to_le_bytes());
    nca[0x248] = 1;
    nca[0x400..0x402].copy_from_slice(&[2, 0]);
    nca[0x402] = 1; // PFS0
    nca[0x403] = 1; // no hash
    nca[0x404] = 1; // no encryption
    let header_hash = Sha256::digest(&nca[0x400..0x600]);
    nca[0x280..0x2a0].copy_from_slice(&header_hash);
    nca[HEADER_SIZE..].copy_from_slice(&partition);
    nca
}

fn pfs0(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let names = entries
        .iter()
        .flat_map(|(name, _)| name.as_bytes().iter().copied().chain([0]))
        .collect::<Vec<_>>();
    let payload_size = entries.iter().map(|(_, bytes)| bytes.len()).sum::<usize>();
    let mut output = Vec::with_capacity(16 + 24 * entries.len() + names.len() + payload_size);
    output.extend_from_slice(b"PFS0");
    output.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    output.extend_from_slice(&(names.len() as u32).to_le_bytes());
    output.extend_from_slice(&0_u32.to_le_bytes());
    let mut payload_offset = 0_u64;
    let mut name_offset = 0_u32;
    for (name, bytes) in entries {
        output.extend_from_slice(&payload_offset.to_le_bytes());
        output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        output.extend_from_slice(&name_offset.to_le_bytes());
        output.extend_from_slice(&0_u32.to_le_bytes());
        payload_offset += bytes.len() as u64;
        name_offset += name.len() as u32 + 1;
    }
    output.extend_from_slice(&names);
    for (_, bytes) in entries {
        output.extend_from_slice(bytes);
    }
    output
}

fn read_pfs0(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    assert_eq!(&bytes[..4], b"PFS0");
    let count = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    let names_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let table_start = 16;
    let names_start = table_start + count * 24;
    let payload_start = names_start + names_len;
    (0..count)
        .map(|index| {
            let record = table_start + index * 24;
            let offset = u64::from_le_bytes(bytes[record..record + 8].try_into().unwrap()) as usize;
            let size =
                u64::from_le_bytes(bytes[record + 8..record + 16].try_into().unwrap()) as usize;
            let name_offset =
                u32::from_le_bytes(bytes[record + 16..record + 20].try_into().unwrap()) as usize;
            let name_tail = bytes[names_start + name_offset..names_start + names_len]
                .iter()
                .position(|byte| *byte == 0)
                .unwrap();
            let name = String::from_utf8(
                bytes[names_start + name_offset..names_start + name_offset + name_tail].to_vec(),
            )
            .unwrap();
            let start = payload_start + offset;
            (name, bytes[start..start + size].to_vec())
        })
        .collect()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
