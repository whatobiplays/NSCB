#![cfg(feature = "standalone-job-history")]

use serde_json::Value;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::ops::Range;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Output};
use tempfile::TempDir;

#[allow(dead_code)]
#[path = "support/synthetic_nsp_qualification.rs"]
mod synthetic_nsp_qualification;
#[allow(dead_code)]
#[path = "support/synthetic_xci.rs"]
mod synthetic_xci;

const HEADER_KEY: [u8; 32] = [0x42; 32];
const APPLICATION_KAEK: [u8; 16] = [
    0x92, 0x66, 0xaa, 0x6c, 0xfa, 0xef, 0x6a, 0x62, 0x31, 0x90, 0x2a, 0x87, 0x78, 0xe6, 0xf6, 0xe6,
];
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const UPSTREAM_XCZ: &[u8] = include_bytes!("fixtures/xcz-to-xci/upstream-nsz/upstream.xcz");
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const SOURCE_XCI: &[u8] = include_bytes!("fixtures/xcz-to-xci/upstream-nsz/source.xci");
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const META_NCA: &[u8] = include_bytes!("fixtures/xcz-to-xci/upstream-nsz/meta.nca");
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const PROGRAM_NCA: &[u8] = include_bytes!("fixtures/xcz-to-xci/upstream-nsz/program.nca");
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const PROGRAM_NCZ: &[u8] = include_bytes!("fixtures/xcz-to-xci/upstream-nsz/program.ncz");

struct CliFiles {
    root: TempDir,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    source: PathBuf,
    output: PathBuf,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    key_file: PathBuf,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    workspace: PathBuf,
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn key_file(include_application_key: bool) -> Vec<u8> {
    let mut content = format!("header_key = {}\n", hex(&HEADER_KEY));
    if include_application_key {
        content.push_str(&format!(
            "key_area_key_application_00 = {}\n",
            hex(&APPLICATION_KAEK)
        ));
    }
    content.into_bytes()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn files_with(source_bytes: &[u8], key_bytes: &[u8]) -> CliFiles {
    let root = tempfile::tempdir().expect("temporary CLI directory");
    let source = root.path().join("synthetic-input.xcz");
    let output = root.path().join("reconstructed-output.xci");
    let key_file = root.path().join("synthetic-test-material.dat");
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("create CLI workspace");
    fs::write(&source, source_bytes).expect("write synthetic XCZ input");
    fs::write(&key_file, key_bytes).expect("write synthetic test key file");
    CliFiles {
        root,
        source,
        output,
        key_file,
        workspace,
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn valid_files() -> CliFiles {
    files_with(UPSTREAM_XCZ, &key_file(true))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn command(files: &CliFiles, output_mode: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nscb"));
    command
        .current_dir(files.root.path())
        .env("HOME", files.root.path())
        .args(["xcz-to-xci", "--source"])
        .arg(&files.source)
        .args(["--output"])
        .arg(&files.output)
        .arg("--workspace")
        .arg(&files.workspace)
        .arg("--keys")
        .arg(&files.key_file)
        .arg(output_mode);
    command
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn assert_success_document(document: &Value) {
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["kind"], "xcz_to_xci.job_result");
    assert_eq!(
        document
            .as_object()
            .expect("success document object")
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        [
            "kind",
            "nscb_version",
            "plan",
            "result",
            "schema_version",
            "session",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    assert_eq!(document["result"]["state"], "succeeded");
    assert_eq!(document["result"]["outcome"], "decompressed");
}

fn assert_error_document(output: &Output, exit_code: i32, code: &str, files: Option<&CliFiles>) {
    assert_eq!(output.status.code(), Some(exit_code));
    let document: Value = serde_json::from_slice(&output.stdout).expect("one JSON error document");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["kind"], "error");
    assert_eq!(document["error"]["code"], code);
    assert_eq!(
        document
            .as_object()
            .expect("error document object")
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        ["error", "kind", "nscb_version", "schema_version"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    if let Some(files) = files {
        let rendered = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let root = files.root.path().to_string_lossy();
        assert!(
            !rendered.contains(root.as_ref()),
            "error output leaked a path"
        );
        assert!(
            !rendered.contains(&hex(&HEADER_KEY)) && !rendered.contains(&hex(&APPLICATION_KAEK)),
            "error output leaked synthetic key bytes"
        );
        assert!(!files.output.exists(), "failure published an output");
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hfs_entries(image: &[u8], start: usize) -> Vec<(String, Range<usize>)> {
    let header = image.get(start..).expect("HFS0 start is in range");
    assert_eq!(header.get(..4), Some(b"HFS0".as_slice()));
    let read_u32 = |offset: usize| {
        u32::from_le_bytes(
            header
                .get(offset..offset + 4)
                .expect("HFS0 u32 is in range")
                .try_into()
                .expect("HFS0 u32 has four bytes"),
        )
    };
    let read_u64 = |offset: usize| {
        u64::from_le_bytes(
            header
                .get(offset..offset + 8)
                .expect("HFS0 u64 is in range")
                .try_into()
                .expect("HFS0 u64 has eight bytes"),
        )
    };
    let count = usize::try_from(read_u32(4)).expect("entry count fits usize");
    let string_size = usize::try_from(read_u32(8)).expect("string table size fits usize");
    let entries_start = 0x10_usize;
    let entries_size = count
        .checked_mul(0x40)
        .expect("entry table size fits usize");
    let strings_start = entries_start
        .checked_add(entries_size)
        .expect("string table offset fits usize");
    let data_start = strings_start
        .checked_add(string_size)
        .expect("data offset fits usize");
    assert!(header.get(..data_start).is_some());
    (0..count)
        .map(|index| {
            let entry = entries_start + index * 0x40;
            let member_offset = usize::try_from(read_u64(entry)).expect("member offset fits usize");
            let member_length = usize::try_from(read_u64(entry + 8)).expect("member length fits usize");
            let name_offset = usize::try_from(read_u32(entry + 16)).expect("name offset fits usize");
            let name_start = strings_start
                .checked_add(name_offset)
                .expect("name offset fits usize");
            let name_end = header[name_start..data_start]
                .iter()
                .position(|byte| *byte == 0)
                .map(|length| name_start + length)
                .expect("NUL-terminated HFS0 name");
            let name = String::from_utf8(header[name_start..name_end].to_vec())
                .expect("synthetic HFS0 names are UTF-8");
            let member_start = start
                .checked_add(data_start)
                .and_then(|offset| offset.checked_add(member_offset))
                .expect("member start fits usize");
            let member_end = member_start
                .checked_add(member_length)
                .expect("member end fits usize");
            assert!(
                image.get(member_start..member_end).is_some(),
                "HFS0 member {name} range {member_start}..{member_end} exceeds image length {} (table start {start}, data start {data_start}, relative offset {member_offset})",
                image.len()
            );
            (name, member_start..member_end)
        })
        .collect()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn assert_upstream_fixture_lineage() {
    let mut payload = vec![0xa5; 0x9000];
    for (index, byte) in payload.iter_mut().take(410).enumerate() {
        *byte = u8::try_from((index * 31 + 7) % 256).expect("synthetic byte fits u8");
    }
    let synthetic = synthetic_nsp_qualification::build_with_program_payload_and_application_kaek(
        &payload,
        APPLICATION_KAEK,
        |_| {},
    );
    assert_eq!(synthetic.meta_nca, META_NCA);
    assert_eq!(synthetic.program_nca, PROGRAM_NCA);
    let source = synthetic_xci::xci(
        &synthetic.meta_nca,
        &synthetic.program_nca,
        &synthetic.package,
        &synthetic.key_file,
    );
    assert_eq!(source.image, SOURCE_XCI);

    let source_secure = hfs_entries(SOURCE_XCI, 0xF000)
        .into_iter()
        .find(|(name, _)| name == "secure")
        .expect("source XCI secure partition")
        .1;
    let source_secure_bytes = &SOURCE_XCI[source_secure];
    let source_members = hfs_entries(source_secure_bytes, 0);
    for evidence in [META_NCA, PROGRAM_NCA] {
        assert!(
            source_members
                .iter()
                .any(|(_, range)| { &source_secure_bytes[range.clone()] == evidence })
        );
    }

    let compressed_secure = hfs_entries(UPSTREAM_XCZ, 0xF000)
        .into_iter()
        .find(|(name, _)| name == "secure")
        .expect("upstream XCZ secure partition")
        .1;
    let compressed_secure_bytes = &UPSTREAM_XCZ[compressed_secure];
    let compressed_members = hfs_entries(compressed_secure_bytes, 0);
    let ncz_members = compressed_members
        .iter()
        .filter(|(name, _)| name.ends_with(".ncz"))
        .collect::<Vec<_>>();
    assert_eq!(ncz_members.len(), 1);
    assert_eq!(
        &compressed_secure_bytes[ncz_members[0].1.clone()],
        PROGRAM_NCZ
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn assert_output_matches_uncompressed_evidence(path: &Path) {
    let output = fs::read(path).expect("read reconstructed XCI");
    let secure = hfs_entries(&output, 0xF000)
        .into_iter()
        .find(|(name, _)| name == "secure")
        .expect("output secure partition")
        .1;
    let secure_bytes = &output[secure];
    let members = hfs_entries(secure_bytes, 0);
    let nca_members = members
        .iter()
        .filter(|(name, _)| name.ends_with(".nca"))
        .collect::<Vec<_>>();
    assert_eq!(nca_members.len(), 2);
    for evidence in [META_NCA, PROGRAM_NCA] {
        let expected_digest = Sha256::digest(evidence);
        let matches = nca_members
            .iter()
            .filter(|(_, range)| Sha256::digest(&secure_bytes[range.clone()]) == expected_digest)
            .collect::<Vec<_>>();
        assert_eq!(
            matches.len(),
            1,
            "full NCA digest identifies one output member"
        );
        assert_eq!(&secure_bytes[matches[0].1.clone()], evidence);
    }
}

#[test]
fn xcz_to_xci_cli_rejects_invalid_arguments_with_the_jsonl_error_contract() {
    let root = tempfile::tempdir().expect("temporary CLI directory");
    let output = Command::new(env!("CARGO_BIN_EXE_nscb"))
        .current_dir(root.path())
        .env("HOME", root.path())
        .args(["xcz-to-xci", "--jsonl", "--unknown-option"])
        .output()
        .expect("run CLI with invalid arguments");
    assert_error_document(&output, 2, "usage_error", None);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn xcz_to_xci_cli_json_decompresses_the_upstream_fixture() {
    assert_upstream_fixture_lineage();
    let files = valid_files();
    let output = command(&files, "--json")
        .output()
        .expect("run xcz-to-xci JSON CLI");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let document: Value = serde_json::from_slice(&output.stdout).expect("one JSON result");
    assert_success_document(&document);
    assert!(files.output.is_file());
    assert_output_matches_uncompressed_evidence(&files.output);
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!rendered.contains(&files.key_file.to_string_lossy().to_string()));
    assert!(!rendered.contains(&hex(&HEADER_KEY)) && !rendered.contains(&hex(&APPLICATION_KAEK)));
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn xcz_to_xci_cli_jsonl_frames_events_before_one_terminal_result() {
    let files = valid_files();
    let output = command(&files, "--jsonl")
        .output()
        .expect("run xcz-to-xci JSONL CLI");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("JSONL output is UTF-8");
    let records = stdout
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("one JSON document per line"))
        .collect::<Vec<_>>();
    assert!(
        records.len() >= 2,
        "JSONL success includes event records and a result"
    );
    for (index, record) in records[..records.len() - 1].iter().enumerate() {
        assert_eq!(record["schema_version"], 1);
        assert_eq!(record["kind"], "job.event");
        assert!(record["nscb_version"].is_string());
        assert!(record["sequence"].as_u64().is_some());
        assert!(record["snapshot"].is_object());
        if index > 0 {
            let previous_sequence = records[index - 1]["sequence"]
                .as_u64()
                .expect("previous event sequence is an unsigned integer");
            let current_sequence = record["sequence"]
                .as_u64()
                .expect("event sequence is an unsigned integer");
            assert!(previous_sequence < current_sequence);
        }
    }
    assert_eq!(
        records
            .iter()
            .filter(|record| record["kind"] == "xcz_to_xci.job_result")
            .count(),
        1
    );
    assert!(
        records[..records.len() - 1]
            .iter()
            .all(|record| record["kind"] == "job.event")
    );
    assert_success_document(records.last().expect("terminal result is last"));
    assert!(files.output.is_file());
    assert_output_matches_uncompressed_evidence(&files.output);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn xcz_to_xci_cli_reports_missing_keys_as_one_sanitized_jsonl_error() {
    let files = files_with(UPSTREAM_XCZ, &key_file(false));
    let output = command(&files, "--jsonl")
        .output()
        .expect("run xcz-to-xci with missing Application key");
    assert_error_document(&output, 3, "required_key_missing", Some(&files));
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn xcz_to_xci_cli_reports_malformed_input_as_one_sanitized_json_error() {
    let files = files_with(b"not an XCI image", &key_file(true));
    let output = command(&files, "--json")
        .output()
        .expect("run xcz-to-xci with malformed input");
    assert_error_document(&output, 3, "unsupported_xci_profile", Some(&files));
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
#[test]
fn xcz_to_xci_cli_reports_unsupported_platform_before_opening_inputs() {
    let root = tempfile::tempdir().expect("temporary CLI directory");
    let source = root.path().join("missing-input.xcz");
    let output_path = root.path().join("output.xci");
    let key_path = root.path().join("synthetic-test-material.dat");
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("create CLI workspace");
    fs::write(&key_path, key_file(true)).expect("write synthetic key file");
    let output = Command::new(env!("CARGO_BIN_EXE_nscb"))
        .current_dir(root.path())
        .env("HOME", root.path())
        .args(["xcz-to-xci", "--source"])
        .arg(&source)
        .args(["--output"])
        .arg(&output_path)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--keys")
        .arg(&key_path)
        .arg("--json")
        .output()
        .expect("run unsupported-platform CLI");
    assert_eq!(output.status.code(), Some(3));
    let document: Value = serde_json::from_slice(&output.stdout).expect("JSON error document");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["kind"], "error");
    assert_eq!(document["error"]["code"], "unsupported_capability");
    assert!(!output_path.exists());
}
