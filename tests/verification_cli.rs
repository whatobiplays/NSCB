//! Subprocess tests for the standalone `nscb verify` surface.

mod support;

use serde_json::Value;
use support::process::isolated_command;
use support::synthetic_verification::{
    NpdmMode, PartitionFsMode, Spec, build, change_main_name_to_traversal,
};

fn run(args: &[&str]) -> std::process::Output {
    isolated_command()
        .args(args)
        .output()
        .expect("launch nscb executable")
}

fn document(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("one JSON document on stdout")
}

#[test]
fn structural_json_verification_passes_with_a_result_document() {
    let directory = tempfile::tempdir().unwrap();
    let built = build(Spec::default());
    let paths = built.write(directory.path());
    let output = run(&[
        "verify",
        paths.input.to_str().unwrap(),
        "--keys",
        paths.keys.to_str().unwrap(),
        "--profile",
        "structural",
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    let document = document(&output);
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["kind"], "verification.result");
    assert_eq!(document["result"]["profile"], "structural");
    assert_eq!(document["result"]["outcome"], "passed");
    assert_eq!(document["result"]["checks"].as_array().unwrap().len(), 4);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains(directory.path().to_str().unwrap()));
    assert!(!text.contains("nstool"));
}

#[test]
fn full_json_verification_passes_with_anchor() {
    let directory = tempfile::tempdir().unwrap();
    let built = build(Spec::default());
    let paths = built.write(directory.path());
    let output = run(&[
        "verify",
        paths.input.to_str().unwrap(),
        "--keys",
        paths.keys.to_str().unwrap(),
        "--trust-anchor",
        paths.anchor.to_str().unwrap(),
        "--anchor-generation",
        "5",
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document = document(&output);
    assert_eq!(document["result"]["profile"], "full");
    assert_eq!(document["result"]["outcome"], "passed");
    assert_eq!(document["result"]["checks"].as_array().unwrap().len(), 9);
    assert_eq!(document["result"]["checks"][8]["reason"], "hash_type_none");
    let limitations = document["result"]["limitations"].as_array().unwrap();
    assert!(
        limitations
            .iter()
            .any(|value| value == "payload_integrity_not_available")
    );
    assert!(
        limitations
            .iter()
            .any(|value| value == "authenticity_not_established")
    );
}

#[test]
fn full_without_anchor_exits_three_with_a_prerequisite_code() {
    let directory = tempfile::tempdir().unwrap();
    let built = build(Spec::default());
    let paths = built.write(directory.path());
    let output = run(&[
        "verify",
        paths.input.to_str().unwrap(),
        "--keys",
        paths.keys.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(3));
    let document = document(&output);
    assert_eq!(document["kind"], "error");
    assert_eq!(document["error"]["code"], "missing_trust_anchor");
}

#[test]
fn full_without_generation_exits_three_with_a_prerequisite_code() {
    let directory = tempfile::tempdir().unwrap();
    let built = build(Spec::default());
    let paths = built.write(directory.path());
    let output = run(&[
        "verify",
        paths.input.to_str().unwrap(),
        "--keys",
        paths.keys.to_str().unwrap(),
        "--trust-anchor",
        paths.anchor.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        document(&output)["error"]["code"],
        "missing_anchor_generation"
    );
}

#[test]
fn structural_with_anchor_flags_is_a_usage_error() {
    let directory = tempfile::tempdir().unwrap();
    let built = build(Spec::default());
    let paths = built.write(directory.path());
    let output = run(&[
        "verify",
        paths.input.to_str().unwrap(),
        "--profile",
        "structural",
        "--trust-anchor",
        paths.anchor.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(document(&output)["error"]["code"], "usage_error");
}

#[test]
fn unknown_profile_value_and_out_of_range_generation_are_usage_errors() {
    let directory = tempfile::tempdir().unwrap();
    let built = build(Spec::default());
    let paths = built.write(directory.path());
    let output = run(&[
        "verify",
        paths.input.to_str().unwrap(),
        "--profile",
        "partial",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(document(&output)["error"]["code"], "usage_error");

    let output = run(&[
        "verify",
        paths.input.to_str().unwrap(),
        "--keys",
        paths.keys.to_str().unwrap(),
        "--trust-anchor",
        paths.anchor.to_str().unwrap(),
        "--anchor-generation",
        "256",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(document(&output)["error"]["code"], "usage_error");
}

#[test]
fn failed_verification_exits_three_with_a_result_document() {
    let directory = tempfile::tempdir().unwrap();
    let spec = Spec {
        npdm: NpdmMode::Missing,
        ..Spec::default()
    };
    let built = build(spec);
    let paths = built.write(directory.path());
    let output = run(&[
        "verify",
        paths.input.to_str().unwrap(),
        "--keys",
        paths.keys.to_str().unwrap(),
        "--trust-anchor",
        paths.anchor.to_str().unwrap(),
        "--anchor-generation",
        "5",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(3));
    let document = document(&output);
    assert_eq!(document["kind"], "verification.result");
    assert_eq!(document["result"]["outcome"], "failed");
    assert_eq!(document["result"]["checks"][6]["reason"], "npdm_missing");
}

#[test]
fn anchor_generation_mismatch_exits_three_and_keeps_the_check_not_run() {
    let directory = tempfile::tempdir().unwrap();
    let built = build(Spec::default());
    let paths = built.write(directory.path());
    let output = run(&[
        "verify",
        paths.input.to_str().unwrap(),
        "--keys",
        paths.keys.to_str().unwrap(),
        "--trust-anchor",
        paths.anchor.to_str().unwrap(),
        "--anchor-generation",
        "4",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(3));
    let document = document(&output);
    assert_eq!(document["result"]["outcome"], "failed");
    assert_eq!(document["result"]["checks"][5]["execution"], "not_run");
    assert_eq!(
        document["result"]["checks"][5]["reason"],
        "trust_anchor_generation_mismatch"
    );
}

#[test]
fn human_output_states_the_profile_and_limitations() {
    let directory = tempfile::tempdir().unwrap();
    let built = build(Spec::default());
    let paths = built.write(directory.path());
    let output = run(&[
        "verify",
        paths.input.to_str().unwrap(),
        "--keys",
        paths.keys.to_str().unwrap(),
        "--profile",
        "structural",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Verification (structural) passed"));
    assert!(text.contains("Limitations:"));
    assert!(text.contains("signatures were not checked"));
    assert!(!text.contains("NSTool"));
    assert!(output.stderr.is_empty());

    let output = run(&[
        "verify",
        paths.input.to_str().unwrap(),
        "--keys",
        paths.keys.to_str().unwrap(),
        "--trust-anchor",
        paths.anchor.to_str().unwrap(),
        "--anchor-generation",
        "5",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Verification (full) passed"));
    assert!(text.contains("partition payload integrity is not available"));
    assert!(text.contains("the NPDM and ACID are not authenticated"));
    assert!(text.contains("content authenticity is not established"));
    assert!(text.contains("device-write authorization was not evaluated"));
    assert!(output.stderr.is_empty());
}

#[test]
fn usage_errors_exit_two_and_never_use_the_batch_exit_class() {
    let directory = tempfile::tempdir().unwrap();
    let built = build(Spec::default());
    let paths = built.write(directory.path());
    let input = paths.input.to_str().unwrap();
    let anchor = paths.anchor.to_str().unwrap();
    let invocations = [
        vec![],
        vec!["verify"],
        vec!["verify", input, "--json", "--json"],
        vec!["verify", input, "--unknown", "--json"],
        vec!["verify", input, "--profile", "partial", "--json"],
        vec![
            "verify",
            input,
            "--profile",
            "structural",
            "--trust-anchor",
            anchor,
            "--json",
        ],
        vec!["verify", input, "--keys", "--json"],
    ];
    for args in invocations {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "args: {args:?}");
        assert_ne!(output.status.code(), Some(8), "args: {args:?}");
        if args.contains(&"--json") {
            assert_eq!(
                document(&output)["error"]["code"],
                "usage_error",
                "args: {args:?}"
            );
        }
    }
}

#[test]
fn prerequisite_failures_exit_three_and_redact_paths() {
    let directory = tempfile::tempdir().unwrap();
    let built = build(Spec::default());
    let paths = built.write(directory.path());
    let missing = directory.path().join("missing.keys");
    let output = run(&[
        "verify",
        paths.input.to_str().unwrap(),
        "--keys",
        missing.to_str().unwrap(),
        "--profile",
        "structural",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(3));
    assert_ne!(output.status.code(), Some(8));
    assert_eq!(document(&output)["error"]["code"], "key_file_unavailable");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains(directory.path().to_str().unwrap()));
    assert!(!text.contains("missing.keys"));
}

#[test]
fn human_prerequisite_error_is_localized_and_omits_paths() {
    let directory = tempfile::tempdir().unwrap();
    let built = build(Spec::default());
    let paths = built.write(directory.path());
    let output = run(&[
        "verify",
        paths.input.to_str().unwrap(),
        "--keys",
        paths.keys.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(3));
    assert_ne!(output.status.code(), Some(8));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("trust anchor"));
    assert!(!stderr.contains(directory.path().to_str().unwrap()));
    assert!(!stderr.contains("NSTool"));
}

#[test]
fn executed_signature_failure_exits_three_with_check_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let built = build(Spec {
        corrupt_fixed_signature: true,
        ..Spec::default()
    });
    let paths = built.write(directory.path());
    let output = run(&[
        "verify",
        paths.input.to_str().unwrap(),
        "--keys",
        paths.keys.to_str().unwrap(),
        "--trust-anchor",
        paths.anchor.to_str().unwrap(),
        "--anchor-generation",
        "5",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(3));
    assert_ne!(output.status.code(), Some(8));
    let document = document(&output);
    assert_eq!(document["kind"], "verification.result");
    assert_eq!(document["result"]["outcome"], "failed");
    assert_eq!(document["result"]["checks"][5]["execution"], "completed");
    assert_eq!(
        document["result"]["checks"][5]["reason"],
        "signature_mismatch"
    );
}

#[test]
fn adversarial_partition_metadata_is_a_failed_cli_result() {
    for mode in [
        PartitionFsMode::Duplicate,
        PartitionFsMode::Traversal,
        PartitionFsMode::Malformed,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let built = build(Spec {
            partition_fs: mode,
            ..Spec::default()
        });
        let paths = built.write(directory.path());
        for profile in ["structural", "full"] {
            let mut args = vec![
                "verify",
                paths.input.to_str().unwrap(),
                "--keys",
                paths.keys.to_str().unwrap(),
                "--profile",
                profile,
            ];
            if profile == "full" {
                args.extend([
                    "--trust-anchor",
                    paths.anchor.to_str().unwrap(),
                    "--anchor-generation",
                    "5",
                ]);
            }
            args.push("--json");
            let output = run(&args);
            assert_eq!(
                output.status.code(),
                Some(3),
                "{mode:?} {profile}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let document = document(&output);
            assert_eq!(document["kind"], "verification.result");
            assert_eq!(document["result"]["outcome"], "failed");
            assert_eq!(
                document["result"]["checks"][3]["id"],
                "nca3.partition_entries"
            );
            assert_eq!(document["result"]["checks"][3]["outcome"], "failed");
            assert_eq!(
                document["result"]["checks"][3]["reason"],
                "partition_entries_invalid"
            );
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(!text.contains(directory.path().to_str().unwrap()));
        }
    }
}

#[test]
fn signed_hash_none_metadata_change_is_a_failed_cli_result() {
    let directory = tempfile::tempdir().unwrap();
    let built = build(Spec::default());
    let paths = built.write(directory.path());
    let mut changed = built.nca.clone();
    change_main_name_to_traversal(&mut changed);
    std::fs::write(&paths.input, changed).unwrap();

    for profile in ["structural", "full"] {
        let mut args = vec![
            "verify",
            paths.input.to_str().unwrap(),
            "--keys",
            paths.keys.to_str().unwrap(),
            "--profile",
            profile,
        ];
        if profile == "full" {
            args.extend([
                "--trust-anchor",
                paths.anchor.to_str().unwrap(),
                "--anchor-generation",
                "5",
            ]);
        }
        args.push("--json");
        let output = run(&args);
        assert_eq!(output.status.code(), Some(3), "{profile}");
        let document = document(&output);
        assert_eq!(document["result"]["outcome"], "failed");
        assert_eq!(document["result"]["checks"][3]["outcome"], "failed");
        assert_eq!(
            document["result"]["checks"][3]["reason"],
            "partition_entries_invalid"
        );
    }
}

#[cfg(unix)]
#[test]
fn verification_does_not_launch_nstool_or_consume_provider_cache() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let built = build(Spec::default());
    let paths = built.write(directory.path());
    let fake_bin = directory.path().join("bin");
    let cache = directory.path().join("cache");
    let home = directory.path().join("home");
    std::fs::create_dir(&fake_bin).unwrap();
    std::fs::create_dir(&cache).unwrap();
    std::fs::create_dir(&home).unwrap();
    let marker = directory.path().join("nstool-launched");
    let fake_nstool = fake_bin.join("nstool");
    std::fs::write(
        &fake_nstool,
        "#!/bin/sh\n: > \"$NSCB_FAKE_MARKER\"\nexit 0\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&fake_nstool).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&fake_nstool, permissions).unwrap();

    let output = isolated_command()
        .args([
            "verify",
            paths.input.to_str().unwrap(),
            "--keys",
            paths.keys.to_str().unwrap(),
            "--trust-anchor",
            paths.anchor.to_str().unwrap(),
            "--anchor-generation",
            "5",
            "--json",
        ])
        .env("PATH", &fake_bin)
        .env("HOME", &home)
        .env("XDG_CACHE_HOME", &cache)
        .env("NSCB_FAKE_MARKER", &marker)
        .output()
        .expect("launch nscb executable");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!marker.exists(), "fake NSTool was launched");
    assert!(std::fs::read_dir(&cache).unwrap().next().is_none());
    assert_eq!(document(&output)["result"]["outcome"], "passed");
}

#[test]
fn inspection_stays_available_after_verify_is_added() {
    let output = run(&["inspect", "--help"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("nscb inspect"));
}
