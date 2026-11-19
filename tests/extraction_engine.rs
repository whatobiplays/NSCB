#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

//! Public Engine acceptance tests for keyed standalone Program extraction.

mod support;
#[path = "support/synthetic_extraction.rs"]
mod synthetic_extraction;

use nscb::{
    CancellationHandle, Engine, ExtractionRequest, ExtractionSelection, ExtractionSelectors,
    JobState, NcaContentType, OperationSession, ProgramId,
};
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;
use synthetic_extraction::{ExpectedFile, SyntheticExtractionFixture};

fn request(
    fixture: &SyntheticExtractionFixture,
    destination: &Path,
    selection: ExtractionSelection,
) -> ExtractionRequest {
    ExtractionRequest::new(&fixture.source, destination, &fixture.key_file, selection)
}

fn execute_success(
    fixture: &SyntheticExtractionFixture,
    destination: &Path,
    selection: ExtractionSelection,
) -> Vec<u8> {
    let engine = Engine::new();
    let cancellation = CancellationHandle::new();
    let plan = engine
        .plan_extraction(
            request(fixture, destination, selection),
            cancellation.clone(),
        )
        .expect("plan public Engine extraction");
    let result =
        engine.execute_operation_with_cancellation(plan, &OperationSession::new(), cancellation);
    assert_eq!(
        result.state(),
        JobState::Succeeded,
        "extraction failure: {:?}",
        result.failure().map(|failure| failure.code())
    );
    assert_eq!(fs::read(&fixture.source).unwrap(), fixture.source_bytes);
    assert_eq!(fs::read(&fixture.key_file).unwrap(), fixture.key_file_bytes);
    fs::read(destination.join("manifest.json")).expect("read published manifest")
}

fn parse_manifest(bytes: &[u8]) -> Value {
    assert!(bytes.ends_with(b"\n"), "manifest must end with one newline");
    serde_json::from_slice(bytes).expect("manifest is valid JSON")
}

fn partition(manifest: &Value, index: u8) -> &Value {
    manifest["partitions"]
        .as_array()
        .expect("manifest has partition records")
        .iter()
        .find(|record| record["index"].as_u64() == Some(u64::from(index)))
        .expect("requested partition is recorded")
}

fn file_path<'a>(manifest: &'a Value, partition_index: u8, source_path: &str) -> &'a str {
    let expected_path = format!("{partition_index}/{source_path}");
    let matches = partition(manifest, partition_index)["files"]
        .as_array()
        .expect("partition has a file list")
        .iter()
        .filter_map(|file| file["path"].as_str())
        .filter(|path| *path == expected_path.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        matches.len(),
        1,
        "manifest entry must use content-root path {expected_path}"
    );
    matches[0]
}

fn assert_file_bytes(destination: &Path, manifest: &Value, expected: &ExpectedFile) {
    let content_root = manifest["content_root"]
        .as_str()
        .expect("manifest names its payload directory");
    let published_path = file_path(manifest, expected.partition_index, &expected.path);
    assert_eq!(
        fs::read(destination.join(content_root).join(published_path)).unwrap(),
        expected.bytes,
        "published bytes for partition {} path {}",
        expected.partition_index,
        expected.path
    );
}

fn file_count(manifest: &Value) -> usize {
    manifest["partitions"]
        .as_array()
        .expect("manifest has partition records")
        .iter()
        .map(|partition| {
            partition["files"]
                .as_array()
                .expect("partition has a file list")
                .len()
        })
        .sum()
}

#[test]
fn all_selection_publishes_exact_bytes_and_a_complete_manifest() {
    let fixture = SyntheticExtractionFixture::populated();
    let destination = fixture.source.parent().unwrap().join("all-selection");
    let manifest_bytes = execute_success(&fixture, &destination, ExtractionSelection::all());
    let manifest = parse_manifest(&manifest_bytes);

    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(
        manifest["kind"].as_str(),
        Some("extracted_content_manifest")
    );
    assert_eq!(manifest["selection_mode"].as_str(), Some("all"));
    assert_eq!(manifest["completeness"].as_str(), Some("complete"));
    assert_eq!(manifest["content_root"].as_str(), Some("content"));
    assert_eq!(
        manifest["source"]["program_id"].as_str(),
        Some("0102030405060708")
    );
    assert_eq!(manifest["source"]["role"].as_str(), Some("program"));
    assert_eq!(file_count(&manifest), fixture.expected_files.len());
    assert_eq!(
        manifest["partitions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["index"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [0, 1]
    );
    for expected in &fixture.expected_files {
        assert_file_bytes(&destination, &manifest, expected);
    }
    for record in manifest["partitions"].as_array().unwrap() {
        for directory in record["directories"].as_array().unwrap() {
            let content_root = manifest["content_root"].as_str().unwrap();
            assert!(
                destination
                    .join(content_root)
                    .join(directory.as_str().unwrap())
                    .is_dir(),
                "published directory {directory}"
            );
        }
    }
}

#[test]
fn combined_program_and_path_selectors_publish_an_incomplete_subset() {
    let fixture = SyntheticExtractionFixture::populated();
    let destination = fixture.source.parent().unwrap().join("partial-selection");
    let expected = fixture
        .expected_files
        .iter()
        .find(|file| file.partition_index == 0 && file.path == "nested/program.bin")
        .unwrap();
    let selectors = ExtractionSelectors::new()
        .with_program_id(ProgramId::from_u64(synthetic_extraction::PROGRAM_ID))
        .with_nca_type(NcaContentType::Program)
        .with_partition(0)
        .with_path("nested/program.bin");
    let manifest_bytes = execute_success(
        &fixture,
        &destination,
        ExtractionSelection::selectors(selectors),
    );
    let manifest = parse_manifest(&manifest_bytes);

    assert_eq!(manifest["selection_mode"].as_str(), Some("selectors"));
    assert_eq!(manifest["completeness"].as_str(), Some("incomplete"));
    assert_eq!(file_count(&manifest), 1);
    assert_file_bytes(&destination, &manifest, expected);
}

#[test]
fn unmatched_program_id_is_rejected_without_creating_a_bundle() {
    let fixture = SyntheticExtractionFixture::populated();
    let destination = fixture.source.parent().unwrap().join("wrong-program-id");
    let selectors = ExtractionSelectors::new()
        .with_program_id(ProgramId::from_u64(synthetic_extraction::PROGRAM_ID + 1));
    let result = Engine::new().plan_extraction(
        request(
            &fixture,
            &destination,
            ExtractionSelection::selectors(selectors),
        ),
        CancellationHandle::new(),
    );

    assert!(result.is_err());
    assert!(!destination.exists());
}

#[test]
fn complete_manifest_retains_a_partition_with_no_files() {
    let fixture = SyntheticExtractionFixture::empty_first_partition();
    let destination = fixture.source.parent().unwrap().join("empty-partition");
    let manifest_bytes = execute_success(&fixture, &destination, ExtractionSelection::all());
    let manifest = parse_manifest(&manifest_bytes);
    let empty_partition = partition(&manifest, 0);
    let content_root = manifest["content_root"].as_str().unwrap();

    assert_eq!(manifest["completeness"].as_str(), Some("complete"));
    assert!(empty_partition["files"].as_array().unwrap().is_empty());
    let empty_directories = empty_partition["directories"]
        .as_array()
        .expect("empty partition retains directory structure");
    assert!(!empty_directories.is_empty());
    for directory in empty_directories {
        assert!(
            destination
                .join(content_root)
                .join(directory.as_str().unwrap())
                .is_dir()
        );
    }
    for expected in &fixture.expected_files {
        assert_file_bytes(&destination, &manifest, expected);
    }
}

#[test]
fn manifest_serialization_is_stable_across_distinct_output_directories() {
    let fixture = SyntheticExtractionFixture::populated();
    let first_destination = fixture.source.parent().unwrap().join("first-output");
    let second_destination = fixture.source.parent().unwrap().join("second-output");

    let first = execute_success(&fixture, &first_destination, ExtractionSelection::all());
    let second = execute_success(&fixture, &second_destination, ExtractionSelection::all());

    assert_eq!(first, second);
}

#[test]
fn destination_conflict_preserves_existing_bundle_content() {
    let fixture = SyntheticExtractionFixture::populated();
    let destination = fixture.source.parent().unwrap().join("existing-bundle");
    fs::create_dir(&destination).unwrap();
    let sentinel = destination.join("owner-data.txt");
    fs::write(&sentinel, b"preserve this file").unwrap();
    let engine = Engine::new();
    let result = engine.plan_extraction(
        request(&fixture, &destination, ExtractionSelection::all()),
        CancellationHandle::new(),
    );

    assert!(result.is_err(), "planning must reject the existing bundle");
    assert_eq!(fs::read(sentinel).unwrap(), b"preserve this file");
    assert!(!destination.join("manifest.json").exists());
}

#[test]
fn competing_publishers_to_one_destination_have_one_winner() {
    let fixture = SyntheticExtractionFixture::populated();
    let destination = fixture.source.parent().unwrap().join("competing-bundle");
    let first_engine = Engine::new();
    let second_engine = Engine::new();
    let first_cancellation = CancellationHandle::new();
    let second_cancellation = CancellationHandle::new();
    let first_plan = first_engine
        .plan_extraction(
            request(&fixture, &destination, ExtractionSelection::all()),
            first_cancellation.clone(),
        )
        .expect("plan first publisher");
    let second_plan = second_engine
        .plan_extraction(
            request(&fixture, &destination, ExtractionSelection::all()),
            second_cancellation.clone(),
        )
        .expect("plan competing publisher");
    let barrier = Arc::new(Barrier::new(2));
    let first_barrier = Arc::clone(&barrier);
    let first = thread::spawn(move || {
        first_barrier.wait();
        first_engine.execute_operation_with_cancellation(
            first_plan,
            &OperationSession::new(),
            first_cancellation,
        )
    });
    let second_barrier = Arc::clone(&barrier);
    let second = thread::spawn(move || {
        second_barrier.wait();
        second_engine.execute_operation_with_cancellation(
            second_plan,
            &OperationSession::new(),
            second_cancellation,
        )
    });
    let first = first.join().unwrap();
    let second = second.join().unwrap();

    assert_eq!(
        [first.state(), second.state()]
            .into_iter()
            .filter(|state| *state == JobState::Succeeded)
            .count(),
        1
    );
    assert_eq!(
        [first.state(), second.state()]
            .into_iter()
            .filter(|state| *state == JobState::Failed)
            .count(),
        1
    );
    let manifest = parse_manifest(&fs::read(destination.join("manifest.json")).unwrap());
    for expected in &fixture.expected_files {
        assert_file_bytes(&destination, &manifest, expected);
    }
    assert_eq!(fs::read(&fixture.source).unwrap(), fixture.source_bytes);
    assert_eq!(fs::read(&fixture.key_file).unwrap(), fixture.key_file_bytes);
}

#[test]
fn source_replacement_after_planning_is_rejected_and_preserved() {
    let fixture = SyntheticExtractionFixture::populated();
    let destination = fixture.source.parent().unwrap().join("stale-source");
    let engine = Engine::new();
    let cancellation = CancellationHandle::new();
    let plan = engine
        .plan_extraction(
            request(&fixture, &destination, ExtractionSelection::all()),
            cancellation.clone(),
        )
        .expect("plan before source replacement");
    let mut replacement = fixture.source_bytes.clone();
    replacement[0] ^= 1;
    fs::write(&fixture.source, &replacement).unwrap();

    let result =
        engine.execute_operation_with_cancellation(plan, &OperationSession::new(), cancellation);

    assert_eq!(result.state(), JobState::Failed);
    assert!(!destination.exists());
    assert_eq!(fs::read(&fixture.source).unwrap(), replacement);
    assert_eq!(fs::read(&fixture.key_file).unwrap(), fixture.key_file_bytes);
}

#[test]
fn key_replacement_after_planning_is_rejected_and_preserved() {
    let fixture = SyntheticExtractionFixture::populated();
    let destination = fixture.source.parent().unwrap().join("stale-key");
    let engine = Engine::new();
    let cancellation = CancellationHandle::new();
    let plan = engine
        .plan_extraction(
            request(&fixture, &destination, ExtractionSelection::all()),
            cancellation.clone(),
        )
        .expect("plan before key replacement");
    let mut replacement = fixture.key_file_bytes.clone();
    let key_offset = replacement.iter().position(|byte| *byte == b'=').unwrap() + 2;
    replacement[key_offset] ^= 1;
    fs::write(&fixture.key_file, &replacement).unwrap();

    let result =
        engine.execute_operation_with_cancellation(plan, &OperationSession::new(), cancellation);

    assert_eq!(result.state(), JobState::Failed);
    assert!(!destination.exists());
    assert_eq!(fs::read(&fixture.source).unwrap(), fixture.source_bytes);
    assert_eq!(fs::read(&fixture.key_file).unwrap(), replacement);
}

#[test]
fn cancellation_before_execution_preserves_source_and_key_files() {
    let fixture = SyntheticExtractionFixture::populated();
    let destination = fixture.source.parent().unwrap().join("cancelled-bundle");
    let engine = Engine::new();
    let cancellation = CancellationHandle::new();
    let plan = engine
        .plan_extraction(
            request(&fixture, &destination, ExtractionSelection::all()),
            cancellation.clone(),
        )
        .expect("plan before cancellation");
    cancellation.cancel();

    let result =
        engine.execute_operation_with_cancellation(plan, &OperationSession::new(), cancellation);

    assert_eq!(result.state(), JobState::Cancelled);
    assert!(!destination.exists());
    assert_eq!(fs::read(&fixture.source).unwrap(), fixture.source_bytes);
    assert_eq!(fs::read(&fixture.key_file).unwrap(), fixture.key_file_bytes);
}
