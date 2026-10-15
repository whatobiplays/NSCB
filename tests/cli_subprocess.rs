mod support;

use nscb::{ContainerProbeRequest, Engine};
use serde_json::Value;
#[cfg(unix)]
use std::ffi::CString;
use std::fs;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use std::process::Command;
#[cfg(unix)]
use std::process::Stdio;
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::{Duration, Instant};
use support::synthetic_pfs0::{TempInput, valid_container_probe_fixture};

#[test]
fn normal_executable_probes_pfs0_without_keys_and_matches_the_public_facade() {
    let bytes = valid_container_probe_fixture();
    let input = TempInput::new(&bytes);
    let expected = Engine::new()
        .probe_container(ContainerProbeRequest::new(input.path()))
        .expect("public facade probes the same fixture without keys");

    let output = Command::new(env!("CARGO_BIN_EXE_nscb"))
        .args(["probe"])
        .arg(input.path())
        .arg("--json")
        .output()
        .expect("launch normal nscb executable");

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    let document: Value =
        serde_json::from_slice(&output.stdout).expect("one success JSON document");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["kind"], "container_probe.result");
    assert_eq!(
        document["result"],
        serde_json::to_value(expected).expect("serialize facade result")
    );
    assert_eq!(
        fs::read(input.path()).expect("read input after subprocess"),
        bytes
    );

    let output_text = String::from_utf8(output.stdout).expect("JSON output is UTF-8");
    for unsupported_claim in [
        "inspection.result",
        "verification.result",
        "Nintendo",
        "title_id",
        "decrypted",
        "signature",
        "authentic",
    ] {
        assert!(!output_text.contains(unsupported_claim));
    }
}

#[test]
fn normal_executable_emits_one_versioned_sanitized_error_document_for_bad_inputs() {
    let valid = valid_container_probe_fixture();
    let mut invalid_header = valid.clone();
    invalid_header[12] = 1;
    let mut invalid_utf8_name = valid.clone();
    invalid_utf8_name[40] = 0xff;
    let mut invalid_name_offset = valid.clone();
    invalid_name_offset[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut overflowing_entry = valid.clone();
    overflowing_entry[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
    let mut oversized = valid;
    oversized[4..8].copy_from_slice(&65_537_u32.to_le_bytes());

    let cases = [
        (b"not a PFS0 container".as_slice(), "unsupported_format"),
        (b"PFS0".as_slice(), "truncated_input"),
        (invalid_header.as_slice(), "invalid_header"),
        (invalid_utf8_name.as_slice(), "invalid_string_table"),
        (invalid_name_offset.as_slice(), "invalid_string_table"),
        (overflowing_entry.as_slice(), "invalid_entry"),
        (oversized.as_slice(), "limit_exceeded"),
    ];

    for (bytes, expected_code) in cases {
        let input = TempInput::new(bytes);
        let output = Command::new(env!("CARGO_BIN_EXE_nscb"))
            .args(["probe"])
            .arg(input.path())
            .arg("--json")
            .output()
            .expect("launch normal nscb executable");

        assert_eq!(output.status.code(), Some(3));
        assert!(output.stderr.is_empty());
        assert_eq!(
            output.stdout.iter().filter(|byte| **byte == b'\n').count(),
            1
        );
        let document: Value =
            serde_json::from_slice(&output.stdout).expect("one handled-error JSON document");
        assert_eq!(document["schema_version"], 1);
        assert_eq!(document["kind"], "error");
        assert_eq!(document["error"]["code"], *expected_code);
        assert!(
            !String::from_utf8_lossy(&output.stdout)
                .contains(input.path().to_string_lossy().as_ref())
        );
        assert_eq!(
            fs::read(input.path()).expect("read input after error"),
            bytes
        );
    }
}

#[test]
fn normal_executable_uses_english_human_presentation() {
    let input = TempInput::new(&valid_container_probe_fixture());
    let success = Command::new(env!("CARGO_BIN_EXE_nscb"))
        .args(["probe"])
        .arg(input.path())
        .output()
        .expect("launch normal nscb executable");

    assert_eq!(success.status.code(), Some(0));
    assert_eq!(
        success.stdout,
        b"PFS0 container probe found one entry; payload begins at byte 46.\n"
    );
    assert!(success.stderr.is_empty());

    let invalid = TempInput::new(b"not a PFS0 container");
    let error = Command::new(env!("CARGO_BIN_EXE_nscb"))
        .args(["probe"])
        .arg(invalid.path())
        .output()
        .expect("launch normal nscb executable");

    assert_eq!(error.status.code(), Some(3));
    assert!(error.stdout.is_empty());
    assert_eq!(
        error.stderr,
        b"The outer-container format is not supported.\n"
    );
}

#[cfg(unix)]
#[test]
fn normal_executable_rejects_a_fifo_without_waiting_for_a_writer() {
    let input = TempInput::new(b"");
    std::fs::remove_file(input.path()).expect("remove temporary regular file");
    let path =
        CString::new(input.path().as_os_str().as_bytes()).expect("temporary path has no NUL");
    // SAFETY: `path` is a valid NUL-terminated path and mkfifo reads it synchronously.
    let result = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
    assert_eq!(result, 0, "create a FIFO fixture");

    let mut child = Command::new(env!("CARGO_BIN_EXE_nscb"))
        .args(["probe"])
        .arg(input.path())
        .arg("--json")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch normal nscb executable");
    let deadline = Instant::now() + Duration::from_secs(2);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll nscb process") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("nscb did not reject the FIFO within two seconds");
        }
        thread::sleep(Duration::from_millis(10));
    };
    let output = child
        .wait_with_output()
        .expect("collect bounded subprocess output");

    assert_eq!(status.code(), Some(3));
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    let document: Value = serde_json::from_slice(&output.stdout).expect("one error JSON document");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["kind"], "error");
    assert_eq!(document["error"]["code"], "input_unavailable");
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains(input.path().to_string_lossy().as_ref())
    );
    assert!(
        std::fs::symlink_metadata(input.path())
            .expect("FIFO remains")
            .file_type()
            .is_fifo()
    );
}

#[test]
fn normal_executable_reports_json_usage_errors_with_exit_two() {
    let output = Command::new(env!("CARGO_BIN_EXE_nscb"))
        .args(["probe", "--json"])
        .output()
        .expect("launch normal nscb executable");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    let document: Value = serde_json::from_slice(&output.stdout).expect("one usage JSON document");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["kind"], "error");
    assert_eq!(document["error"]["code"], "usage_error");
}

#[test]
fn normal_executable_treats_an_unknown_long_option_as_a_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_nscb"))
        .args(["probe", "--bogus"])
        .output()
        .expect("launch normal nscb executable");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"Usage: nscb probe <path> [--json]\n");
}

#[test]
fn recognition_unknown_and_errors_are_distinct_single_documents() {
    let input = support::synthetic_pfs0::TempInput::new(b"unrecognized content");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_nscb"))
        .args(["recognize"])
        .arg(input.path())
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "content_recognition.result");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["result"]["recognition"]["outcome"], "unknown");
    assert_eq!(
        value["result"]["package_structure_eligibility"],
        "not_established"
    );
    assert_eq!(output.stdout.iter().filter(|b| **b == b'\n').count(), 1);
    let bad = support::synthetic_pfs0::TempInput::new(b"PFS0");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_nscb"))
        .arg("recognize")
        .arg(bad.path())
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "error");
    assert_eq!(value["error"]["code"], "truncated_input");
    assert!(
        !String::from_utf8_lossy(&output.stdout)
            .contains(&bad.path().to_string_lossy().to_string())
    );
}

#[test]
fn recognition_plain_output_identifies_family_and_compression_evidence() {
    let bytes = support::synthetic_pfs0::valid_container_probe_fixture();
    let input = support::synthetic_pfs0::TempInput::new(&bytes);
    let output = Command::new(env!("CARGO_BIN_EXE_nscb"))
        .arg("recognize")
        .arg(input.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("family: pfs0"));
    assert!(text.contains("compression: not_established"));
    assert!(text.contains("package structure eligibility: not_established"));
}

#[cfg(unix)]
#[test]
fn recognition_rejects_fifo_without_blocking() {
    let path = std::env::temp_dir().join(format!("nscb-recognition-fifo-{}", std::process::id()));
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let mut child = Command::new(env!("CARGO_BIN_EXE_nscb"))
        .arg("recognize")
        .arg(&path)
        .arg("--json")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            fs::remove_file(&path).unwrap();
            panic!("FIFO input blocked");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    fs::remove_file(path).unwrap();
    assert_eq!(output.status.code(), Some(3));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "input_unavailable");
}

/// Builds one HFS0 image whose members follow its 0x200-aligned header.
fn synthetic_hfs0(members: &[(&str, &[u8])]) -> (Vec<u8>, u64) {
    let mut table = Vec::new();
    let mut strings = Vec::new();
    let mut data = Vec::new();
    let mut offset = 0u64;
    for (name, member) in members {
        table.extend_from_slice(&offset.to_le_bytes());
        table.extend_from_slice(&(member.len() as u64).to_le_bytes());
        table.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        table.extend_from_slice(&0u32.to_le_bytes());
        table.extend_from_slice(&0u64.to_le_bytes());
        table.extend_from_slice(&[0; 32]);
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        data.extend_from_slice(member);
        offset += member.len() as u64;
    }
    let mut size = 16 + table.len() + strings.len();
    while size % 0x200 != 0 {
        strings.push(0);
        size += 1;
    }
    let mut image = b"HFS0".to_vec();
    image.extend_from_slice(&(members.len() as u32).to_le_bytes());
    image.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    image.extend_from_slice(&[0; 4]);
    image.extend_from_slice(&table);
    image.extend_from_slice(&strings);
    image.extend_from_slice(&data);
    (image, size as u64)
}

/// Builds one bounded partition image holding a single member.
fn synthetic_partition(member: &[u8]) -> Vec<u8> {
    let (mut image, _) = synthetic_hfs0(&[("member", member)]);
    while image.len() % 0x200 != 0 {
        image.push(0);
    }
    image
}

#[test]
fn recognition_ambiguous_polyglot_is_a_result_with_exit_three() {
    // A PFS0 frame at offset zero and the supported card profile overlap: the
    // card signature area doubles as PFS0 metadata.
    let update = synthetic_partition(&[0; 8]);
    let normal = synthetic_partition(&[0; 8]);
    let secure = synthetic_partition(&[0; 8]);
    let (root, root_size) = synthetic_hfs0(&[
        ("update", &update),
        ("normal", &normal),
        ("secure", &secure),
    ]);
    let secure_start = 0xF000 + root_size + (update.len() + normal.len()) as u64;
    let page = u32::try_from((secure_start + 0x1000) / 0x200).unwrap();
    let mut bytes = vec![0u8; 0xF000];
    bytes[..4].copy_from_slice(b"PFS0");
    bytes[0x100..0x104].copy_from_slice(b"HEAD");
    bytes[0x104..0x108].copy_from_slice(&page.to_le_bytes());
    bytes[0x130..0x138].copy_from_slice(&0xF000u64.to_le_bytes());
    bytes[0x138..0x140].copy_from_slice(&root_size.to_le_bytes());
    bytes.extend_from_slice(&root);
    let input = TempInput::new(&bytes);
    let output = Command::new(env!("CARGO_BIN_EXE_nscb"))
        .arg("recognize")
        .arg(input.path())
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "content_recognition.result");
    assert_eq!(value["result"]["recognition"]["outcome"], "ambiguous");
    assert_eq!(
        value["result"]["package_structure_eligibility"],
        "not_established"
    );
    assert_eq!(fs::read(input.path()).unwrap(), bytes);
}
