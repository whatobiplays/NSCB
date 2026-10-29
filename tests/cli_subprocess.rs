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
use support::process::isolated_command;
use support::synthetic_pfs0::{TempInput, valid_container_probe_fixture};

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn no_argument_non_tty_reports_usage_after_loading_synthetic_configuration() {
    let root = tempfile::tempdir().expect("create isolated no-argument root");
    let home = root.path().join("home");
    let config_root = root.path().join("xdg-config");
    let cache_root = root.path().join("xdg-cache");
    let output_directory = root.path().join("synthetic-output");
    fs::create_dir_all(&home).unwrap();

    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_nscb"));
        command
            .env_clear()
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_CONFIG_HOME", &config_root)
            .env("XDG_CACHE_HOME", &cache_root)
            .env("APPDATA", root.path().join("AppData").join("Roaming"))
            .env("LOCALAPPDATA", root.path().join("AppData").join("Local"))
            .env("PATH", std::env::var_os("PATH").unwrap_or_default());
        command
    };

    let configured = command()
        .args(["config", "set", "output_dir"])
        .arg(&output_directory)
        .arg("--json")
        .output()
        .expect("configure synthetic output path");
    assert_eq!(configured.status.code(), Some(0));

    let output = command()
        .output()
        .expect("launch nscb without arguments in non-TTY mode");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let usage = String::from_utf8_lossy(&output.stderr);
    assert!(usage.contains("nscb"));
    assert!(!output_directory.exists());

    #[cfg(target_os = "macos")]
    let config_file = home
        .join("Library")
        .join("Application Support")
        .join("NSCB")
        .join("config.toml");
    #[cfg(target_os = "linux")]
    let config_file = config_root.join("NSCB").join("config.toml");
    assert!(config_file.is_file());
    assert!(
        fs::read_to_string(config_file)
            .unwrap()
            .contains("synthetic-output")
    );
}

#[test]
fn normal_executable_probes_pfs0_without_keys_and_matches_the_public_facade() {
    let bytes = valid_container_probe_fixture();
    let input = TempInput::new(&bytes);
    let expected = Engine::new()
        .probe_container(ContainerProbeRequest::new(input.path()))
        .expect("public facade probes the same fixture without keys");

    let output = isolated_command()
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
        let output = isolated_command()
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
    let success = isolated_command()
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
    let error = isolated_command()
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

#[test]
fn inspect_rejects_missing_or_option_valued_path_arguments() {
    let cases: &[(&[&str], bool)] = &[
        (&["inspect", "input.nca", "--keys", "--json"], true),
        (&["inspect", "input.nca", "--cache-dir", "--json"], true),
        (&["inspect", "input.nca", "--keys"], false),
        (&["inspect", "input.nca", "--cache-dir"], false),
    ];

    for (arguments, json) in cases {
        let output = isolated_command()
            .args(*arguments)
            .output()
            .expect("launch normal nscb executable");

        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        if *json {
            assert!(output.stderr.is_empty());
            let document: Value =
                serde_json::from_slice(&output.stdout).expect("one usage-error JSON document");
            assert_eq!(document["kind"], "error");
            assert_eq!(document["error"]["code"], "usage_error");
        } else {
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).contains("nscb inspect"));
        }
    }
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

    let mut child = isolated_command()
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
    let output = isolated_command()
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
    let output = isolated_command()
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
    let output = isolated_command()
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
    let output = isolated_command()
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
    let output = isolated_command()
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
    let mut child = isolated_command()
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
    let output = isolated_command()
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

#[cfg(target_os = "macos")]
mod copy_subprocess {
    use super::*;
    use fs2::FileExt;
    use std::io::{BufRead, BufReader, Read};
    #[cfg(unix)]
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::mpsc;
    use tempfile::tempdir;

    fn nscb() -> Command {
        isolated_command()
    }

    fn line_documents(bytes: &[u8]) -> Vec<Value> {
        String::from_utf8(bytes.to_vec())
            .expect("machine output is UTF-8")
            .lines()
            .map(|line| serde_json::from_str(line).expect("valid JSON record"))
            .collect()
    }

    #[cfg(unix)]
    fn full_pipe() -> (OwnedFd, OwnedFd) {
        let mut descriptors = [-1; 2];
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        let reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        let writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        let _ = fill_pipe_writer(writer.as_raw_fd());
        (reader, writer)
    }

    #[cfg(unix)]
    fn empty_pipe() -> (OwnedFd, OwnedFd) {
        let mut descriptors = [-1; 2];
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        unsafe {
            (
                OwnedFd::from_raw_fd(descriptors[0]),
                OwnedFd::from_raw_fd(descriptors[1]),
            )
        }
    }

    #[cfg(unix)]
    fn pipe_writer_with_closed_reader() -> Stdio {
        let (reader, writer) = empty_pipe();
        drop(reader);
        Stdio::from(writer)
    }

    #[cfg(unix)]
    fn pipe_capacity() -> usize {
        let (reader, writer) = empty_pipe();
        let capacity = fill_pipe_writer(writer.as_raw_fd());
        let mut drained = 0;
        let mut buffer = [0_u8; 4096];
        while drained < capacity {
            let count = unsafe {
                libc::read(
                    reader.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len().min(capacity - drained),
                )
            };
            assert!(count > 0);
            drained += count as usize;
        }
        capacity
    }

    #[cfg(unix)]
    fn fill_pipe_writer(fd: std::os::fd::RawFd) -> usize {
        let writer_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert!(writer_flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFL, writer_flags | libc::O_NONBLOCK,) },
            0
        );
        let fill = [0x5a_u8; 4096];
        let mut total = 0;
        loop {
            let written = unsafe { libc::write(fd, fill.as_ptr().cast(), fill.len()) };
            if written > 0 {
                total += written as usize;
                continue;
            }
            assert_eq!(written, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EAGAIN)
            );
            break;
        }
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFL, writer_flags) },
            0,
            "restore the test pipe's blocking mode before giving it to the child"
        );
        total
    }

    #[cfg(unix)]
    fn duplicated_stdio(fd: std::os::fd::RawFd) -> Stdio {
        let duplicate = unsafe { libc::dup(fd) };
        assert!(duplicate >= 0);
        unsafe { Stdio::from_raw_fd(duplicate) }
    }

    #[cfg(unix)]
    struct StalledPipeProbe {
        child: std::process::Child,
        _stdout_reader: OwnedFd,
        _stderr_reader: OwnedFd,
        stdout_writer: OwnedFd,
        stderr_writer: OwnedFd,
        stdout_flags: libc::c_int,
        stderr_flags: libc::c_int,
        source: std::path::PathBuf,
        destination: std::path::PathBuf,
        source_bytes: Vec<u8>,
        destination_before: Option<Vec<u8>>,
        published_at: Option<Instant>,
        status: Option<std::process::ExitStatus>,
    }

    #[cfg(unix)]
    fn stop_children(probes: &mut [StalledPipeProbe]) {
        for probe in probes {
            if probe.status.is_none() {
                let _ = probe.child.kill();
                probe.status = probe.child.wait().ok();
            }
        }
    }

    #[test]
    fn copy_human_success_uses_stdout() {
        let root = tempdir().expect("copy fixture");
        let source = root.path().join("source.bin");
        let destination = root.path().join("destination.bin");
        let workspace = root.path().join("workspace");
        let bytes = b"human copy source bytes";
        fs::write(&source, bytes).expect("write source");
        fs::create_dir(&workspace).expect("create workspace");

        for (index, expected) in [
            "Copy-through succeeded: validated source bytes were published to the destination.",
            "Copy-through succeeded: the destination already contained the planned source bytes.",
        ]
        .into_iter()
        .enumerate()
        {
            let output = nscb()
                .arg("copy")
                .arg(&source)
                .arg(&destination)
                .arg("--workspace")
                .arg(&workspace)
                .output()
                .expect("run human copy");

            assert_eq!(output.status.code(), Some(0));
            assert!(output.stderr.is_empty(), "stderr: {:?}", output.stderr);
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(stdout.starts_with(expected), "stdout: {stdout}");
            if index == 0 {
                assert!(
                    stdout.contains("Operation-owned artifacts requiring reconciliation:"),
                    "stdout: {stdout}"
                );
                let artifacts = stdout
                    .lines()
                    .filter_map(|line| line.strip_prefix("  artifact: "))
                    .map(|line| serde_json::from_str::<Value>(line).unwrap())
                    .collect::<Vec<_>>();
                assert!(
                    artifacts
                        .iter()
                        .any(|artifact| { artifact["retained"].as_bool() == Some(true) })
                );
            } else {
                assert_eq!(stdout.lines().count(), 1);
            }
            assert_eq!(fs::read(&destination).unwrap(), bytes);
            assert_eq!(fs::read(&source).unwrap(), bytes);
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn copy_human_cleanup_warning_lists_actionable_artifact_identity_evidence() {
        let root = tempfile::tempdir().expect("copy fixture");
        let source = root.path().join("source.bin");
        let destination = root.path().join("destination.bin");
        let workspace = root.path().join("workspace");
        let source_bytes = b"replacement source bytes";
        let previous_destination = b"previous destination bytes";
        fs::write(&source, source_bytes).expect("write source");
        fs::write(&destination, previous_destination).expect("write existing destination");
        fs::create_dir(&workspace).expect("create workspace");

        let output = nscb()
            .arg("copy")
            .arg(&source)
            .arg(&destination)
            .arg("--workspace")
            .arg(&workspace)
            .arg("--replace")
            .output()
            .expect("run human replacement copy");

        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).expect("human output is UTF-8");
        assert!(
            stdout.contains("Operation-owned artifacts requiring reconciliation:"),
            "stdout: {stdout}"
        );
        assert!(
            !stdout
                .lines()
                .next()
                .unwrap()
                .contains(root.path().to_str().unwrap()),
            "generic cleanup warning must not contain filesystem paths: {stdout}"
        );
        let artifacts = stdout
            .lines()
            .filter_map(|line| line.strip_prefix("  artifact: "))
            .map(|line| serde_json::from_str::<Value>(line).expect("artifact evidence is JSON"))
            .collect::<Vec<_>>();
        assert!(!artifacts.is_empty(), "stdout: {stdout}");
        let backup = artifacts
            .iter()
            .find(|artifact| {
                artifact["role"] == "destination_backup"
                    && artifact["retained"].as_bool() == Some(true)
            })
            .expect("retained destination backup evidence");
        let backup_path = backup["path"].as_str().expect("actionable artifact path");
        assert!(std::path::Path::new(backup_path).is_absolute());
        assert_eq!(fs::read(backup_path).unwrap(), previous_destination);
        assert_eq!(backup["length"], previous_destination.len() as u64);
        assert!(backup["sha256"].as_str().is_some());
        assert_eq!(backup["path_identity_matches"], Value::Bool(true));
        assert!(backup["device"].as_u64().is_some());
        assert!(backup["inode"].as_u64().is_some());
        assert_eq!(fs::read(&source).unwrap(), source_bytes);
        assert_eq!(fs::read(&destination).unwrap(), source_bytes);
    }

    #[test]
    fn copy_human_failed_result_uses_stderr() {
        let root = tempdir().expect("copy fixture");
        let source = root.path().join("source.bin");
        let destination = root.path().join("destination.bin");
        let workspace = root.path().join("workspace");
        fs::write(&source, b"new source bytes").expect("write source");
        fs::write(&destination, b"existing destination bytes").expect("write destination");

        let output = nscb()
            .arg("copy")
            .arg(&source)
            .arg(&destination)
            .arg("--workspace")
            .arg(&workspace)
            .output()
            .expect("run human copy with a destination conflict");

        assert_eq!(output.status.code(), Some(4));
        assert!(
            output.stdout.is_empty(),
            "failed copy diagnostics must use stderr; stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "Copy-through failed: The destination already exists and replacement was not requested.\n"
        );
        assert_eq!(fs::read(&source).unwrap(), b"new source bytes");
        assert_eq!(
            fs::read(&destination).unwrap(),
            b"existing destination bytes"
        );
    }

    #[test]
    fn copy_jsonl_streams_ordered_events_then_one_terminal_record() {
        let root = tempdir().expect("copy fixture");
        let source = root.path().join("source.bin");
        let destination = root.path().join("destination.bin");
        let workspace = root.path().join("workspace");
        let bytes = vec![0x42_u8; 512 * 1024];
        fs::write(&source, &bytes).expect("write source");

        let output = nscb()
            .args(["copy"])
            .arg(&source)
            .arg(&destination)
            .arg("--workspace")
            .arg(&workspace)
            .arg("--jsonl")
            .output()
            .expect("run copy JSONL");

        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        let documents = line_documents(&output.stdout);
        assert!(
            documents.len() <= 16,
            "semantic event cardinality must not scale with bytes: {}",
            documents.len()
        );
        assert_eq!(
            documents
                .iter()
                .filter(|document| document["kind"] == "job.result")
                .count(),
            1
        );
        assert_eq!(documents.last().unwrap()["kind"], "job.result");
        for (index, document) in documents.iter().enumerate() {
            assert_eq!(document["schema_version"], 1);
            assert_eq!(document["nscb_version"], env!("CARGO_PKG_VERSION"));
            assert_eq!(document["sequence"], index as u64);
            assert!(document["snapshot"].is_object(), "snapshot: {document}");
            assert_eq!(document["snapshot"]["total_bytes"], bytes.len() as u64);
        }
        let terminal = documents.last().expect("terminal result record");
        assert_eq!(terminal["kind"], "job.result");
        assert_eq!(terminal["sequence"], (documents.len() - 1) as u64);
        assert_eq!(terminal["snapshot"]["phase"], "idle");
        assert_eq!(terminal["snapshot"]["status"], "succeeded");
        assert_eq!(terminal["snapshot"]["outcome"], "copied");
        assert_eq!(terminal["snapshot"]["completed_bytes"], bytes.len() as u64);
        assert_eq!(terminal["result"]["state"], "succeeded");
        assert_eq!(terminal["result"]["outcome"], "copied");
        assert_eq!(
            terminal["snapshot"]["completed_bytes"], terminal["snapshot"]["total_bytes"],
            "completed staging bytes must not be presented as a publication claim"
        );
        assert_eq!(
            terminal["snapshot"]["completed_bytes"],
            fs::metadata(&source).unwrap().len()
        );
        let nonterminal = documents[..documents.len() - 1]
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        for path in [&source, &destination, &workspace] {
            assert!(
                !nonterminal.contains(&path.display().to_string()),
                "nonterminal records leaked a path"
            );
        }
        assert_eq!(fs::read(&destination).unwrap(), bytes);
        assert_eq!(fs::read(&source).unwrap(), bytes);

        let standalone = nscb()
            .args(["copy"])
            .arg(&source)
            .arg(&destination)
            .arg("--workspace")
            .arg(&workspace)
            .arg("--json")
            .output()
            .expect("run standalone JSON for an identical destination");
        assert_eq!(standalone.status.code(), Some(0));
        let standalone: Value = serde_json::from_slice(&standalone.stdout).unwrap();
        let mut terminal_keys = terminal
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let mut standalone_keys = standalone
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        terminal_keys.sort();
        standalone_keys.sort();
        assert_eq!(terminal_keys, standalone_keys);
        assert_eq!(
            terminal_keys,
            [
                "kind",
                "nscb_version",
                "result",
                "schema_version",
                "sequence",
                "snapshot"
            ]
        );
        assert_eq!(standalone["kind"], "job.result");
        assert_eq!(standalone["result"]["outcome"], "already_up_to_date");
        assert_eq!(standalone["snapshot"]["completed_bytes"], 0);
        assert_eq!(standalone["snapshot"]["total_bytes"], bytes.len() as u64);
    }

    #[cfg(unix)]
    #[test]
    fn blocked_stdout_and_stderr_do_not_hold_copy_process_open_after_terminalization() {
        let root = tempdir().expect("copy fixture");
        let mut probes = Vec::new();
        for (index, mode) in ["--json", "--jsonl", "human", "human-failure"]
            .into_iter()
            .enumerate()
        {
            let source = root.path().join(format!("source-{index}.bin"));
            let destination = root.path().join(format!("destination-{index}.bin"));
            let workspace = root.path().join(format!("workspace-{index}"));
            let source_bytes = vec![0x30 + index as u8; 32 * 1024];
            fs::write(&source, &source_bytes).expect("write source");
            let destination_before = if mode == "human-failure" {
                let existing = b"keep existing destination".to_vec();
                fs::write(&destination, &existing).expect("seed conflicting destination");
                Some(existing)
            } else {
                None
            };
            let (stdout_reader, stdout_writer) = full_pipe();
            let (stderr_reader, stderr_writer) = full_pipe();
            let stdout_flags = unsafe { libc::fcntl(stdout_writer.as_raw_fd(), libc::F_GETFL) };
            let stderr_flags = unsafe { libc::fcntl(stderr_writer.as_raw_fd(), libc::F_GETFL) };
            assert!(stdout_flags >= 0 && stderr_flags >= 0);
            let mut command = nscb();
            command
                .args(["copy"])
                .arg(&source)
                .arg(&destination)
                .arg("--workspace")
                .arg(&workspace)
                .stdout(duplicated_stdio(stdout_writer.as_raw_fd()))
                .stderr(duplicated_stdio(stderr_writer.as_raw_fd()));
            if mode == "--json" || mode == "--jsonl" {
                command.arg(mode);
            }
            let child = command.spawn().expect("launch copy with full pipes");
            probes.push(StalledPipeProbe {
                child,
                _stdout_reader: stdout_reader,
                _stderr_reader: stderr_reader,
                stdout_writer,
                stderr_writer,
                stdout_flags,
                stderr_flags,
                source,
                destination,
                source_bytes,
                destination_before,
                published_at: None,
                status: None,
            });
        }

        let launch_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            for probe in &mut probes {
                if probe.published_at.is_none() && probe.destination.exists() {
                    probe.published_at = Some(Instant::now());
                }
                match probe.child.try_wait() {
                    Ok(Some(status)) => probe.status = Some(status),
                    Ok(None) => {}
                    Err(error) => {
                        stop_children(&mut probes);
                        panic!("observe copy process: {error}");
                    }
                }
            }
            if probes.iter().all(|probe| probe.published_at.is_some()) {
                break;
            }
            if Instant::now() >= launch_deadline {
                stop_children(&mut probes);
                panic!("copy Jobs did not reach their expected filesystem terminal state");
            }
            thread::sleep(Duration::from_millis(20));
        }

        loop {
            for probe in &mut probes {
                if probe.status.is_none() {
                    match probe.child.try_wait() {
                        Ok(Some(status)) => probe.status = Some(status),
                        Ok(None) => {
                            let terminalized = probe.published_at.expect("observed publication");
                            if terminalized.elapsed() > Duration::from_secs(7) {
                                stop_children(&mut probes);
                                panic!(
                                    "copy stayed open for over seven seconds with open, unread pipes"
                                );
                            }
                        }
                        Err(error) => {
                            stop_children(&mut probes);
                            panic!("observe copy process: {error}");
                        }
                    }
                }
            }
            if probes.iter().all(|probe| probe.status.is_some()) {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }

        for probe in probes {
            assert_eq!(probe.status.unwrap().code(), Some(7));
            assert_eq!(
                unsafe { libc::fcntl(probe.stdout_writer.as_raw_fd(), libc::F_GETFL) },
                probe.stdout_flags,
                "copy must preserve inherited stdout descriptor flags"
            );
            assert_eq!(
                unsafe { libc::fcntl(probe.stderr_writer.as_raw_fd(), libc::F_GETFL) },
                probe.stderr_flags,
                "copy must preserve inherited stderr descriptor flags"
            );
            assert_eq!(fs::read(&probe.source).unwrap(), probe.source_bytes);
            assert!(probe.published_at.is_some());
            match probe.destination_before {
                Some(bytes) => assert_eq!(fs::read(&probe.destination).unwrap(), bytes),
                None => assert_eq!(fs::read(&probe.destination).unwrap(), probe.source_bytes),
            }
        }
    }

    #[test]
    fn stalled_stdout_alone_does_not_hold_copy_process_open() {
        for mode in ["--json", "--jsonl", "human"] {
            let root = tempdir().expect("copy fixture");
            let source = root.path().join("source.bin");
            let destination = root.path().join("destination.bin");
            let workspace = root.path().join("workspace");
            let bytes = vec![0x72; 32 * 1024];
            fs::write(&source, &bytes).expect("write source");

            let (stdout_reader, stdout_writer) = full_pipe();
            let mut command = nscb();
            command
                .args(["copy"])
                .arg(&source)
                .arg(&destination)
                .arg("--workspace")
                .arg(&workspace)
                .stdout(duplicated_stdio(stdout_writer.as_raw_fd()))
                .stderr(Stdio::null());
            if mode != "human" {
                command.arg(mode);
            }
            let mut child = command.spawn().expect("spawn copy with unread stdout");
            drop(stdout_writer);

            let start = Instant::now();
            let published_at = loop {
                if destination.exists() {
                    break Instant::now();
                }
                if let Some(status) = child.try_wait().expect("observe copy publication") {
                    panic!("copy exited before publication: {status}");
                }
                if start.elapsed() >= Duration::from_secs(10) {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("copy did not publish with an unread stdout pipe");
                }
                thread::sleep(Duration::from_millis(20));
            };
            let status = loop {
                if let Some(status) = child.try_wait().expect("observe bounded copy exit") {
                    break status;
                }
                if published_at.elapsed() >= Duration::from_secs(7) {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("copy stayed open for over seven seconds with unread stdout");
                }
                thread::sleep(Duration::from_millis(20));
            };

            assert_eq!(status.code(), Some(7), "mode: {mode}");
            assert_eq!(fs::read(&source).unwrap(), bytes);
            assert_eq!(fs::read(&destination).unwrap(), bytes);
            drop(stdout_reader);
        }
    }

    #[test]
    fn stalled_stderr_does_not_hold_a_human_failure_open() {
        let root = tempdir().expect("copy fixture");
        let source = root.path().join("source.bin");
        let destination = root.path().join("destination.bin");
        let source_bytes = b"new source bytes";
        let destination_bytes = b"keep destination bytes";
        fs::write(&source, source_bytes).expect("write source");
        fs::write(&destination, destination_bytes).expect("write conflicting destination");

        let (stdout_reader, stdout_writer) = empty_pipe();
        let (_stderr_reader, stderr_writer) = full_pipe();
        let stderr_flags = unsafe { libc::fcntl(stderr_writer.as_raw_fd(), libc::F_GETFL) };
        assert!(stderr_flags >= 0);
        let mut child = nscb()
            .args(["copy"])
            .arg(&source)
            .arg(&destination)
            .stdout(duplicated_stdio(stdout_writer.as_raw_fd()))
            .stderr(duplicated_stdio(stderr_writer.as_raw_fd()))
            .spawn()
            .expect("spawn failed human copy with unread stderr");
        drop(stdout_writer);

        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().expect("observe failed copy") {
                break status;
            }
            if start.elapsed() >= Duration::from_secs(7) {
                let _ = child.kill();
                let _ = child.wait();
                panic!("human failure stayed open with an open, full stderr pipe");
            }
            thread::sleep(Duration::from_millis(20));
        };

        assert_eq!(status.code(), Some(7));
        let mut available = 0;
        assert_eq!(
            unsafe {
                libc::ioctl(
                    stdout_reader.as_raw_fd(),
                    libc::FIONREAD,
                    &mut available as *mut libc::c_int,
                )
            },
            0
        );
        assert_eq!(available, 0, "human errors do not write to stdout");
        assert_eq!(
            unsafe { libc::fcntl(stderr_writer.as_raw_fd(), libc::F_GETFL) },
            stderr_flags,
            "the executable must preserve inherited stderr descriptor flags"
        );
        assert_eq!(fs::read(&source).unwrap(), source_bytes);
        assert_eq!(fs::read(&destination).unwrap(), destination_bytes);
        drop(stderr_writer);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn blocked_reporting_after_cancellation_preserves_the_source_and_destination() {
        let root = tempdir().expect("copy fixture");
        let source = root.path().join("source.bin");
        let destination = root.path().join("destination.bin");
        let workspace = root.path().join("workspace");
        let source_bytes = vec![0x63_u8; 512 * 1024];
        fs::write(&source, &source_bytes).expect("write source");
        let source_lock = fs::File::open(&source).expect("open source lock");
        source_lock
            .lock_exclusive()
            .expect("hold source checkpoint");

        let pipe_capacity = pipe_capacity();
        let (stdout_reader, stdout_writer) = empty_pipe();
        let (stderr_reader, stderr_writer) = full_pipe();
        let mut child = nscb()
            .args(["copy"])
            .arg(&source)
            .arg(&destination)
            .arg("--workspace")
            .arg(&workspace)
            .arg("--jsonl")
            .stdout(duplicated_stdio(stdout_writer.as_raw_fd()))
            .stderr(duplicated_stdio(stderr_writer.as_raw_fd()))
            .spawn()
            .expect("spawn cancellable copy");
        drop(stderr_writer);

        let (line_sender, line_receiver) = mpsc::sync_channel(0);
        let reader_thread = thread::spawn(move || {
            let mut stdout = BufReader::new(fs::File::from(stdout_reader));
            let mut line = String::new();
            if stdout.read_line(&mut line).is_ok() && !line.is_empty() {
                let _ = line_sender.send(line);
            }
            stdout
        });
        let first = line_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("read started event");
        assert!(first.contains("\"event\":\"started\""), "{first}");
        let stdout = reader_thread
            .join()
            .expect("pause stdout reader after cancellation");

        let mut filler = Command::new("/bin/cat")
            .arg("/dev/zero")
            .stdout(duplicated_stdio(stdout_writer.as_raw_fd()))
            .stderr(Stdio::null())
            .spawn()
            .expect("fill stdout without changing shared descriptor flags");
        drop(stdout_writer);
        let fill_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut available: libc::c_int = 0;
            assert_eq!(
                unsafe {
                    libc::ioctl(
                        stdout.get_ref().as_raw_fd(),
                        libc::FIONREAD,
                        &mut available as *mut libc::c_int,
                    )
                },
                0
            );
            if available as usize >= pipe_capacity {
                break;
            }
            if Instant::now() >= fill_deadline {
                let _ = filler.kill();
                let _ = filler.wait();
                let _ = child.kill();
                let _ = child.wait();
                source_lock.unlock().expect("release source checkpoint");
                panic!("filler process did not saturate the stdout pipe");
            }
            thread::sleep(Duration::from_millis(5));
        }
        let checkpoint_deadline = Instant::now() + Duration::from_millis(5_250);
        while Instant::now() < checkpoint_deadline {
            if let Some(status) = child.try_wait().expect("observe held copy execution") {
                let _ = filler.kill();
                let _ = filler.wait();
                source_lock.unlock().expect("release source checkpoint");
                panic!("reporting timeout abandoned filesystem execution: {status}");
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(fs::read(&source).unwrap(), source_bytes);
        assert!(!destination.exists());
        assert_eq!(
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) },
            0
        );
        let release_at = Instant::now();
        source_lock.unlock().expect("release source checkpoint");
        let exit_deadline = release_at + Duration::from_secs(7);
        let status = loop {
            if let Some(status) = child.try_wait().expect("observe cancelled copy") {
                break status;
            }
            if Instant::now() >= exit_deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("cancelled copy did not exit with full, unread pipes");
            }
            thread::sleep(Duration::from_millis(20));
        };
        let _ = filler.kill();
        let _ = filler.wait();
        assert_eq!(status.code(), Some(7));
        assert_eq!(fs::read(source).unwrap(), source_bytes);
        assert!(!destination.exists());
        drop(stdout);
        drop(stderr_reader);
    }

    #[test]
    fn copy_json_reports_fresh_publication_success() {
        let root = tempdir().expect("copy fixture");
        let source = root.path().join("source.bin");
        let destination = root.path().join("destination.bin");
        let workspace = root.path().join("workspace");
        let bytes = vec![0x51_u8; 96 * 1024];
        fs::write(&source, &bytes).expect("write source");

        let output = nscb()
            .args(["copy"])
            .arg(&source)
            .arg(&destination)
            .arg("--workspace")
            .arg(&workspace)
            .arg("--json")
            .output()
            .expect("run copy JSON");

        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        let document: Value = serde_json::from_slice(&output.stdout).expect("one job.result");
        assert_eq!(document["schema_version"], 1);
        assert_eq!(document["kind"], "job.result");
        assert_eq!(document["nscb_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(document["result"]["state"], "succeeded");
        assert_eq!(document["result"]["outcome"], "copied");
        assert!(document["sequence"].is_u64());
        assert_eq!(document["snapshot"]["phase"], "idle");
        assert_eq!(document["snapshot"]["status"], "succeeded");
        assert_eq!(document["snapshot"]["outcome"], "copied");
        assert_eq!(document["snapshot"]["completed_bytes"], bytes.len() as u64);
        assert_eq!(document["snapshot"]["total_bytes"], bytes.len() as u64);
        assert_eq!(fs::read(&destination).unwrap(), bytes);
    }

    #[test]
    fn copy_machine_modes_report_conflict_with_exit_four_and_preserve_the_destination() {
        let root = tempdir().expect("copy fixture");
        let source = root.path().join("source.bin");
        let destination = root.path().join("destination.bin");
        fs::write(&source, b"new source bytes").unwrap();
        fs::write(&destination, b"existing destination bytes").unwrap();

        let output = nscb()
            .args(["copy"])
            .arg(&source)
            .arg(&destination)
            .arg("--json")
            .output()
            .expect("run copy JSON");

        assert_eq!(output.status.code(), Some(4));
        assert!(output.stderr.is_empty());
        let document: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(document["kind"], "job.result");
        assert_eq!(document["result"]["state"], "failed");
        assert_eq!(
            document["result"]["failure"]["code"],
            "destination_conflict"
        );
        assert_eq!(
            fs::read(&destination).unwrap(),
            b"existing destination bytes"
        );

        let streamed = nscb()
            .arg("copy")
            .arg(&source)
            .arg(&destination)
            .arg("--jsonl")
            .output()
            .expect("run copy conflict JSONL");
        assert_eq!(streamed.status.code(), Some(4));
        assert!(streamed.stderr.is_empty());
        let documents = line_documents(&streamed.stdout);
        assert_eq!(
            documents
                .iter()
                .filter(|document| document["kind"] == "job.result")
                .count(),
            1
        );
        let failed = documents
            .iter()
            .position(|document| {
                document["kind"] == "job.event"
                    && document["event"] == "milestone"
                    && document["milestone"] == "failed"
            })
            .expect("failed milestone before the conflict diagnostic");
        assert_eq!(documents[failed + 1]["kind"], "job.event");
        assert_eq!(documents[failed + 1]["event"], "failure");
        assert_eq!(documents[failed + 1]["code"], "destination_conflict");
        assert_eq!(failed + 3, documents.len());
        assert_eq!(documents[failed + 2]["kind"], "job.result");
        assert_eq!(documents[failed + 2]["result"]["state"], "failed");
        assert_eq!(
            documents[failed + 2]["result"]["failure"]["code"],
            "destination_conflict"
        );
        assert_eq!(
            fs::read(&destination).unwrap(),
            b"existing destination bytes"
        );

        let replacement = nscb()
            .args(["copy"])
            .arg(&source)
            .arg(&destination)
            .arg("--replace")
            .arg("--json")
            .output()
            .expect("run copy replacement");
        assert_eq!(replacement.status.code(), Some(0));
        assert_eq!(fs::read(&destination).unwrap(), b"new source bytes");
    }

    #[test]
    fn copy_pre_admission_failures_emit_one_typed_error_record() {
        let root = tempdir().expect("copy fixture");
        let destination = root.path().join("destination.bin");

        let missing = nscb()
            .args(["copy"])
            .arg(root.path().join("missing.bin"))
            .arg(&destination)
            .arg("--jsonl")
            .output()
            .expect("run missing copy");
        assert_eq!(missing.status.code(), Some(3));
        assert!(missing.stderr.is_empty());
        let documents = line_documents(&missing.stdout);
        assert_eq!(documents.len(), 1);
        assert_eq!(documents[0]["kind"], "error");
        assert_eq!(documents[0]["error"]["code"], "source_unavailable");
        let serialized = String::from_utf8(missing.stdout.clone()).unwrap();
        assert!(!serialized.contains(root.path().to_str().unwrap()));
        assert!(!serialized.contains("missing.bin"));
        assert!(!serialized.contains("destination.bin"));
        assert!(!destination.exists());

        let usage = nscb()
            .args(["copy", "--json"])
            .output()
            .expect("run invalid copy");
        assert_eq!(usage.status.code(), Some(2));
        assert!(usage.stderr.is_empty());
        let document: Value = serde_json::from_slice(&usage.stdout).unwrap();
        assert_eq!(document["kind"], "error");
        assert_eq!(document["error"]["code"], "usage_error");
        let serialized = String::from_utf8(usage.stdout.clone()).unwrap();
        assert!(!serialized.contains("only-one-path"));
        assert!(!serialized.contains(root.path().to_str().unwrap()));

        let mixed = nscb()
            .args(["copy", "source", "destination", "--json", "--jsonl"])
            .output()
            .expect("run mixed machine modes");
        assert_eq!(mixed.status.code(), Some(2));
        assert!(mixed.stderr.is_empty());
        let documents = line_documents(&mixed.stdout);
        assert_eq!(documents.len(), 1);
        assert_eq!(documents[0]["kind"], "error");
        assert_eq!(documents[0]["error"]["code"], "usage_error");

        for mode in ["--json", "--jsonl"] {
            let missing_workspace = nscb()
                .args(["copy", "source", "destination", "--workspace", mode])
                .output()
                .expect("run copy with an option where a workspace value is required");
            assert_eq!(missing_workspace.status.code(), Some(2));
            assert!(missing_workspace.stderr.is_empty());
            let documents = line_documents(&missing_workspace.stdout);
            assert_eq!(documents.len(), 1);
            assert_eq!(documents[0]["kind"], "error");
            assert_eq!(documents[0]["error"]["code"], "usage_error");
        }
    }

    #[test]
    fn copy_sigterm_is_accepted_before_publication() {
        assert_copy_signal_accepted_before_publication(libc::SIGTERM);
    }

    #[test]
    fn copy_sigint_is_accepted_before_publication() {
        assert_copy_signal_accepted_before_publication(libc::SIGINT);
    }

    fn assert_copy_signal_accepted_before_publication(signal: libc::c_int) {
        let root = tempdir().expect("copy fixture");
        let source = root.path().join("source.bin");
        let destination = root.path().join("destination.bin");
        let workspace = root.path().join("workspace");
        let bytes = vec![0x37_u8; 128 * 1024];
        fs::write(&source, &bytes).unwrap();
        let lock = fs::File::open(&source).unwrap();
        lock.lock_exclusive().expect("hold source lock");

        let mut child = nscb()
            .args(["copy"])
            .arg(&source)
            .arg(&destination)
            .arg("--workspace")
            .arg(&workspace)
            .arg("--jsonl")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn copy");
        let stdout = child.stdout.take().unwrap();
        let (line_sender, line_receiver) = mpsc::channel();
        let reader_thread = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else {
                    break;
                };
                if line_sender.send(line).is_err() {
                    break;
                }
            }
        });
        let first = line_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("read started event");
        assert!(first.contains("\"event\":\"started\""), "{first}");

        unsafe {
            libc::kill(child.id() as libc::pid_t, signal);
        }
        let mut documents =
            vec![serde_json::from_str::<Value>(first.trim()).expect("started JSON")];
        loop {
            let line = line_receiver
                .recv_timeout(Duration::from_secs(5))
                .expect("observe cancellation before releasing the source lock");
            let document: Value = serde_json::from_str(line.trim()).expect("event JSON");
            let cancellation_observed = document["event"] == "cancellation_requested";
            if cancellation_observed {
                assert_eq!(document["accepted"], true);
            }
            documents.push(document);
            if cancellation_observed {
                break;
            }
        }
        lock.unlock().expect("release source lock");
        let rest = line_receiver.iter().collect::<Vec<_>>();
        reader_thread.join().expect("join stdout reader");
        documents.extend(
            rest.iter()
                .map(|line| serde_json::from_str::<Value>(line.trim()).expect("record JSON")),
        );
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        let status = child.wait().expect("wait for copy");

        assert_eq!(status.code(), Some(6), "stderr: {stderr}");
        assert!(stderr.is_empty());
        assert_eq!(
            documents
                .iter()
                .filter(|document| document["kind"] == "job.result")
                .count(),
            1
        );
        assert_eq!(documents.last().unwrap()["result"]["state"], "cancelled");
        let cancelled = documents
            .iter()
            .position(|document| {
                document["kind"] == "job.event"
                    && document["event"] == "milestone"
                    && document["milestone"] == "cancelled"
            })
            .expect("cancelled milestone before the terminal result");
        assert_eq!(cancelled + 2, documents.len());
        assert_eq!(documents[cancelled + 1]["kind"], "job.result");
        assert!(
            documents
                .iter()
                .any(|document| document["event"] == "cancellation_requested")
        );
        assert!(!destination.exists());
        assert_eq!(fs::read(&source).unwrap(), bytes);
    }

    #[test]
    fn copy_stdout_transport_failure_does_not_negate_publication() {
        let root = tempdir().expect("copy fixture");
        let source = root.path().join("source.bin");
        let destination = root.path().join("destination.bin");
        let workspace = root.path().join("workspace");
        let bytes = vec![0x22_u8; 256 * 1024];
        fs::write(&source, &bytes).unwrap();
        let lock = fs::File::open(&source).unwrap();
        lock.lock_exclusive().expect("hold source lock");

        let mut child = nscb()
            .args(["copy"])
            .arg(&source)
            .arg(&destination)
            .arg("--workspace")
            .arg(&workspace)
            .arg("--jsonl")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn copy with a broken stdout reader");
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut first = String::new();
        reader.read_line(&mut first).expect("read started event");
        assert!(first.contains("\"event\":\"started\""), "{first}");

        // Closing the only reader makes every later transport write fail while
        // the already-admitted filesystem execution continues.
        drop(reader);
        lock.unlock().expect("release source lock");
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        let status = child.wait().expect("wait for copy");

        assert_eq!(status.code(), Some(7), "stderr: {stderr}");
        assert_eq!(fs::read(&destination).unwrap(), bytes);
        assert_eq!(fs::read(&source).unwrap(), bytes);
        assert!(
            stderr.contains("output"),
            "the bounded reporting-failure diagnostic uses stderr: {}",
            stderr
        );
    }

    #[test]
    fn copy_stdout_failure_after_source_change_preserves_failed_execution_state() {
        fn run_source_change(
            root: &std::path::Path,
            break_stdout: bool,
        ) -> (i32, Vec<Value>, String, Vec<u8>, Option<Vec<u8>>) {
            let source = root.join("source.bin");
            let destination = root.join("destination.bin");
            let workspace = root.join("workspace");
            fs::write(&source, b"planned source bytes").expect("write source");
            let lock = fs::File::open(&source).expect("open source lock");
            lock.lock_exclusive().expect("hold source checkpoint");

            let mut child = nscb()
                .args(["copy"])
                .arg(&source)
                .arg(&destination)
                .arg("--workspace")
                .arg(&workspace)
                .arg("--jsonl")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn copy with controlled source change");
            let mut stdout = Some(BufReader::new(child.stdout.take().unwrap()));
            let mut started = String::new();
            stdout
                .as_mut()
                .unwrap()
                .read_line(&mut started)
                .expect("read started event");
            assert!(started.contains("\"event\":\"started\""), "{started}");
            let mut documents = vec![serde_json::from_str(&started).unwrap()];
            if break_stdout {
                drop(stdout.take());
            }

            let changed_bytes = b"externally changed source bytes";
            fs::write(&source, changed_bytes).expect("change source at execution lock");
            lock.unlock().expect("release source checkpoint");
            if !break_stdout {
                let mut remaining = String::new();
                stdout
                    .as_mut()
                    .unwrap()
                    .read_to_string(&mut remaining)
                    .expect("read the authoritative failed result");
                documents.extend(line_documents(remaining.as_bytes()));
            }

            let mut stderr = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .expect("read reporting diagnostic");
            let status = child.wait().expect("wait for failed copy");
            (
                status.code().unwrap_or(-1),
                documents,
                stderr,
                fs::read(&source).unwrap(),
                fs::read(&destination).ok(),
            )
        }

        let control_root = tempdir().expect("control copy fixture");
        let (control_exit, control_documents, control_stderr, control_source, control_dest) =
            run_source_change(control_root.path(), false);
        assert_eq!(control_exit, 3, "stderr: {control_stderr}");
        let control_terminal = control_documents.last().unwrap();
        assert_eq!(control_terminal["kind"], "job.result");
        assert_eq!(control_terminal["result"]["state"], "failed");
        assert_eq!(
            control_terminal["result"]["failure"]["code"],
            "source_changed"
        );
        assert!(control_stderr.is_empty());
        assert!(control_dest.is_none());

        let broken_root = tempdir().expect("broken-output copy fixture");
        let (broken_exit, broken_documents, broken_stderr, broken_source, broken_dest) =
            run_source_change(broken_root.path(), true);
        assert_eq!(broken_exit, 7, "stderr: {broken_stderr}");
        assert!(broken_stderr.contains("output"), "stderr: {broken_stderr}");
        assert_eq!(broken_documents.len(), 1, "only the started record is read");
        assert_eq!(broken_documents[0]["event"], "started");
        assert_eq!(broken_source, control_source);
        assert_eq!(broken_dest, control_dest);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn copy_stderr_transport_failure_preserves_pre_admission_conflict() {
        let root = tempdir().expect("copy fixture");
        let source = root.path().join("source.bin");
        let destination = root.path().join("destination.bin");
        let source_bytes = b"new source bytes";
        let destination_bytes = b"keep destination bytes";
        fs::write(&source, source_bytes).unwrap();
        fs::write(&destination, destination_bytes).unwrap();

        let control = nscb()
            .args(["copy"])
            .arg(&source)
            .arg(&destination)
            .stderr(Stdio::piped())
            .output()
            .expect("run conflict copy with a consuming stderr reader");
        assert_eq!(control.status.code(), Some(4));
        assert!(control.stdout.is_empty());
        assert!(!control.stderr.is_empty());
        assert!(!String::from_utf8_lossy(&control.stderr).contains(source.to_str().unwrap()));
        assert!(!String::from_utf8_lossy(&control.stderr).contains(destination.to_str().unwrap()));
        assert_eq!(fs::read(&source).unwrap(), source_bytes);
        assert_eq!(fs::read(&destination).unwrap(), destination_bytes);

        let mut child = nscb()
            .args(["copy"])
            .arg(&source)
            .arg(&destination)
            .stderr(pipe_writer_with_closed_reader())
            .spawn()
            .expect("spawn failed copy after closing the stderr reader");
        let status = child.wait().expect("wait for failed copy");

        assert_eq!(status.code(), Some(7));
        assert_eq!(fs::read(&source).unwrap(), source_bytes);
        assert_eq!(fs::read(&destination).unwrap(), destination_bytes);
    }

    #[test]
    fn copy_already_up_to_date_is_distinct_from_a_fresh_publication() {
        let root = tempdir().expect("copy fixture");
        let source = root.path().join("source.bin");
        let destination = root.path().join("destination.bin");
        fs::write(&source, b"stable bytes").unwrap();

        let first = nscb()
            .args(["copy"])
            .arg(&source)
            .arg(&destination)
            .arg("--json")
            .output()
            .unwrap();
        assert_eq!(first.status.code(), Some(0));
        let first: Value = serde_json::from_slice(&first.stdout).unwrap();
        assert_eq!(first["result"]["outcome"], "copied");

        let second = nscb()
            .args(["copy"])
            .arg(&source)
            .arg(&destination)
            .arg("--json")
            .output()
            .unwrap();
        assert_eq!(second.status.code(), Some(0));
        let second: Value = serde_json::from_slice(&second.stdout).unwrap();
        assert_eq!(second["result"]["outcome"], "already_up_to_date");
        assert_eq!(fs::read(&destination).unwrap(), b"stable bytes");
    }
}
