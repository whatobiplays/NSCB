//! Subprocess coverage for standalone configuration and key management.

mod support;

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use support::synthetic_verification::{Spec as VerificationSpec, build as build_verification};

const MAX_CONFIG_BYTES: usize = 1_048_576;

fn run(home: &Path, args: &[&str]) -> Output {
    run_with_config_home(home, &home.join("xdg-config"), args)
}

fn run_with_config_home(home: &Path, config_home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nscb"))
        .args(args)
        .env_clear()
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", config_home)
        .env("XDG_CACHE_HOME", home.join("xdg-cache"))
        .env("APPDATA", home.join("AppData").join("Roaming"))
        .env("LOCALAPPDATA", home.join("AppData").join("Local"))
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .output()
        .expect("launch nscb executable")
}

fn config_path(home: &Path) -> PathBuf {
    config_path_with_config_home(home, &home.join("xdg-config"))
}

fn config_path_with_config_home(home: &Path, _config_home: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home.join("Library")
            .join("Application Support")
            .join("NSCB")
            .join("config.toml")
    }

    #[cfg(target_os = "linux")]
    {
        _config_home.join("NSCB").join("config.toml")
    }

    #[cfg(target_os = "windows")]
    {
        home.join("AppData")
            .join("Roaming")
            .join("NSCB")
            .join("config.toml")
    }
}

fn escape_xdg_user_directory(path: &Path) -> String {
    let path = path.to_str().expect("temporary Documents path is UTF-8");
    let mut escaped = String::with_capacity(path.len());
    for character in path.chars() {
        if matches!(character, '\\' | '"' | '$' | '`') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

fn write_xdg_documents_mapping(home: &Path, documents: &Path) {
    let xdg_config = home.join("xdg-config");
    std::fs::create_dir_all(&xdg_config).unwrap();
    let escaped = escape_xdg_user_directory(documents);
    std::fs::write(
        xdg_config.join("user-dirs.dirs"),
        format!("XDG_DOCUMENTS_DIR=\"{escaped}\"\n"),
    )
    .unwrap();
}

#[test]
fn xdg_documents_mapping_escapes_shell_special_characters() {
    let path = Path::new(r#"/tmp/Documents with spaces, "quotes", $cash, `ticks`, \\slash"#);
    assert_eq!(
        escape_xdg_user_directory(path),
        r#"/tmp/Documents with spaces, \"quotes\", \$cash, \`ticks\`, \\\\slash"#
    );

    let home = tempfile::tempdir().unwrap();
    write_xdg_documents_mapping(home.path(), path);
    assert_eq!(
        std::fs::read_to_string(home.path().join("xdg-config/user-dirs.dirs")).unwrap(),
        format!(
            "XDG_DOCUMENTS_DIR=\"{}\"\n",
            r#"/tmp/Documents with spaces, \"quotes\", \$cash, \`ticks\`, \\\\slash"#
        )
    );
}

fn one_document(output: &Output) -> Value {
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1,
        "machine mode must emit exactly one document"
    );
    serde_json::from_slice(&output.stdout).expect("one JSON document on stdout")
}

fn assert_error_document(output: &Output, exit_code: i32, error_code: &str) -> Value {
    assert_eq!(
        output.status.code(),
        Some(exit_code),
        "unexpected exit; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document = one_document(output);
    assert_eq!(
        document,
        serde_json::json!({
            "schema_version": 1,
            "kind": "error",
            "nscb_version": env!("CARGO_PKG_VERSION"),
            "error": { "code": error_code },
        })
    );
    document
}

#[cfg(target_os = "linux")]
fn assert_no_atomic_replacement_artifacts(directory: &Path) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        assert!(
            !name.starts_with(".nscb-") && !name.ends_with(".bak"),
            "unexpected temporary or backup artifact: {name}"
        );
    }
}

#[cfg(unix)]
fn non_utf8_child(parent: &Path, prefix: &str) -> PathBuf {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let mut name = prefix.as_bytes().to_vec();
    name.push(0xff);
    parent.join(OsString::from_vec(name))
}

#[cfg(unix)]
fn non_utf8_config_roots(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    #[cfg(target_os = "linux")]
    let (home, config_home) = (root.to_path_buf(), non_utf8_child(root, "config-"));
    #[cfg(not(target_os = "linux"))]
    let (home, config_home) = (non_utf8_child(root, "home-"), root.join("xdg-config"));
    let path = config_path_with_config_home(&home, &config_home);
    (home, config_home, path)
}

#[cfg(unix)]
fn assert_configuration_was_not_initialized(path: &Path) {
    assert!(
        !path.exists(),
        "configuration must not be created before path representability is known"
    );
    if let Some(parent) = path.parent() {
        assert!(!parent.exists());
    }
}

fn write_config(home: &Path, contents: &str) -> PathBuf {
    write_config_with_config_home(home, &home.join("xdg-config"), contents)
}

fn write_config_with_config_home(home: &Path, config_home: &Path, contents: &str) -> PathBuf {
    let path = config_path_with_config_home(home, config_home);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, contents).unwrap();
    path
}

#[test]
fn global_help_and_version_do_not_initialize_configuration() {
    for argument in ["--help", "--version"] {
        let directory = tempfile::tempdir().unwrap();
        let output = run(directory.path(), &[argument]);

        assert_eq!(
            output.status.code(),
            Some(0),
            "{argument}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        assert!(!output.stdout.is_empty());
        assert!(
            !config_path(directory.path()).exists(),
            "{argument} must not initialize standalone state"
        );
    }
}

#[test]
fn config_path_creates_a_commented_versioned_file_and_emits_one_document() {
    let directory = tempfile::tempdir().unwrap();
    let expected = config_path(directory.path());

    let output = run(directory.path(), &["config", "path", "--json"]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document = one_document(&output);
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["kind"], "config.path");
    assert_eq!(document["result"]["path"], expected.to_str().unwrap());

    let contents = std::fs::read_to_string(&expected).expect("configuration file");
    assert!(contents.contains("# NSCB standalone configuration"));
    assert!(contents.contains("schema_version = 1"));
    assert!(contents.contains("# keys_path ="));
    assert!(contents.contains("# output_dir ="));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file_mode = std::fs::metadata(&expected).unwrap().permissions().mode();
        assert_eq!(file_mode & 0o777, 0o600);
        let directory_mode = std::fs::metadata(expected.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(directory_mode & 0o777, 0o700);
    }
}

#[cfg(unix)]
#[test]
fn control_character_home_initializes_readable_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().join("home\nwith-\u{0001}-control");
    std::fs::create_dir(&home).unwrap();
    let expected_keys_path = home.join(".switch").join("prod.keys");

    let output = run(&home, &["config", "show", "--json"]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document = one_document(&output);
    let values = document["result"]["values"].as_array().unwrap();
    assert!(values.iter().any(|value| {
        value["name"] == "keys_path"
            && value["value"] == expected_keys_path.to_str().unwrap()
            && value["source"] == "default"
    }));
    assert!(
        config_path(&home).is_file(),
        "configuration must remain readable after initialization"
    );
}

#[test]
fn ordinary_standalone_startup_initializes_configuration_before_the_command() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.pfs0");

    let output = run(
        directory.path(),
        &["probe", missing.to_str().unwrap(), "--json"],
    );

    assert_eq!(output.status.code(), Some(3));
    assert!(
        config_path(directory.path()).is_file(),
        "normal standalone startup must initialize configuration"
    );
}

#[test]
fn config_show_reports_defaults_and_redacts_sensitive_manual_values() {
    let directory = tempfile::tempdir().unwrap();
    write_config(
        directory.path(),
        "schema_version = 1\n\n[translation]\napi_key = \"synthetic-secret\"\nnote = \"manual value\"\n",
    );

    let output = run(directory.path(), &["config", "show", "--json"]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document = one_document(&output);
    assert_eq!(document["kind"], "config.show");
    assert_eq!(document["result"]["schema_version"], 1);
    let values = document["result"]["values"].as_array().unwrap();
    assert!(
        values
            .iter()
            .any(|value| { value["name"] == "keys_path" && value["source"] == "default" })
    );
    assert!(values.iter().any(|value| {
        value["name"] == "translation.api_key"
            && value["value"] == "[REDACTED]"
            && value["sensitive"] == true
    }));
    assert!(
        values.iter().any(|value| {
            value["name"] == "translation.note" && value["value"] == "manual value"
        })
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-secret"));

    let human = run(directory.path(), &["config", "show"]);
    assert_eq!(human.status.code(), Some(0));
    assert!(human.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&human.stdout).contains("synthetic-secret"));
    assert!(String::from_utf8_lossy(&human.stdout).contains("[REDACTED]"));
}

#[test]
fn config_show_preserves_a_placeholder_like_unknown_value() {
    let directory = tempfile::tempdir().unwrap();
    write_config(
        directory.path(),
        "schema_version = 1\n\n[translation]\nnote = \"{source}\"\n",
    );

    let json = run(directory.path(), &["config", "show", "--json"]);
    assert_eq!(
        json.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    let document = one_document(&json);
    assert!(
        document["result"]["values"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!({
                "name": "translation.note",
                "value": "{source}",
                "source": "file",
                "sensitive": false,
            }))
    );

    let human = run(directory.path(), &["config", "show"]);
    assert_eq!(
        human.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&human.stderr)
    );
    assert!(human.stderr.is_empty());
    assert!(String::from_utf8_lossy(&human.stdout).contains(" translation.note = {source} (file)"));
}

#[test]
fn config_show_preserves_placeholder_braces_in_the_configuration_path() {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().join("{schema_version}");
    let configured_keys_path = directory.path().join("{value}").join("prod.keys");
    let configured_output_dir = directory.path().join("{name}").join("output");
    let config_path = write_config(
        &home,
        &format!(
            "schema_version = 1\nkeys_path = {configured_keys_path:?}\noutput_dir = {configured_output_dir:?}\n",
        ),
    );

    let output = run(&home, &["config", "show"]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!(
            "Configuration file: {}\nSchema version: 1\n  keys_path = {} (file)\n  output_dir = {} (file)\n",
            config_path.display(),
            configured_keys_path.display(),
            configured_output_dir.display(),
        )
    );
}

#[test]
fn config_show_redacts_inline_and_nested_sensitive_fields() {
    let directory = tempfile::tempdir().unwrap();
    write_config(
        directory.path(),
        "schema_version = 1\ntranslation = { api_key = \"inline-secret\", nested = { refresh_token = \"nested-secret\", note = \"retain\" } }\n",
    );

    let output = run(directory.path(), &["config", "show", "--json"]);

    assert_eq!(output.status.code(), Some(0));
    let document = one_document(&output);
    let values = document["result"]["values"].as_array().unwrap();
    assert!(values.iter().any(|value| {
        value["name"] == "translation.api_key"
            && value["value"] == "[REDACTED]"
            && value["sensitive"] == true
    }));
    assert!(values.iter().any(|value| {
        value["name"] == "translation.nested.refresh_token"
            && value["value"] == "[REDACTED]"
            && value["sensitive"] == true
    }));
    assert!(
        values.iter().any(|value| {
            value["name"] == "translation.nested.note" && value["value"] == "retain"
        })
    );
    let human = run(directory.path(), &["config", "show"]);
    let rendered = String::from_utf8_lossy(&human.stdout);
    assert!(!rendered.contains("inline-secret"));
    assert!(!rendered.contains("nested-secret"));
    assert!(rendered.contains("[REDACTED]"));
}

#[test]
fn config_show_redacts_conventional_credential_fields_and_keeps_keys_path_visible() {
    let directory = tempfile::tempdir().unwrap();
    let configured_keys_path = "/synthetic/redaction-regression/keys";
    let sentinels = [
        ("aws_access_key", "SYNTHETIC_AWS_ACCESS_KEY_SENTINEL"),
        ("access_key", "SYNTHETIC_ACCESS_KEY_SENTINEL"),
        ("private_key", "SYNTHETIC_PRIVATE_KEY_SENTINEL"),
    ];
    write_config(
        directory.path(),
        &format!(
            "schema_version = 1\nkeys_path = {configured_keys_path:?}\naws_access_key = {:?}\naccess_key = {:?}\nprivate_key = {:?}\n",
            sentinels[0].1, sentinels[1].1, sentinels[2].1,
        ),
    );

    let output = run(directory.path(), &["config", "show", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document = one_document(&output);
    let values = document["result"]["values"].as_array().unwrap();
    assert!(values.iter().any(|value| {
        value["name"] == "keys_path"
            && value["value"] == configured_keys_path
            && value["sensitive"] == false
    }));
    for (name, sentinel) in sentinels {
        assert!(values.iter().any(|value| {
            value["name"] == name && value["value"] == "[REDACTED]" && value["sensitive"] == true
        }));
        assert!(!String::from_utf8_lossy(&output.stdout).contains(sentinel));
    }

    let human = run(directory.path(), &["config", "show"]);
    assert_eq!(
        human.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&human.stderr)
    );
    let rendered = String::from_utf8_lossy(&human.stdout);
    assert!(rendered.contains(configured_keys_path));
    assert!(rendered.contains("[REDACTED]"));
    for (_, sentinel) in sentinels {
        assert!(!rendered.contains(sentinel));
    }
}

#[test]
fn config_show_with_configured_output_dir_does_not_require_documents() {
    let directory = tempfile::tempdir().unwrap();
    let output_dir = directory.path().join("configured-output");
    write_config(
        directory.path(),
        &format!(
            "schema_version = 1\noutput_dir = {:?}\n",
            output_dir.to_string_lossy()
        ),
    );

    let output = run(directory.path(), &["config", "show", "--json"]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let values = one_document(&output)["result"]["values"]
        .as_array()
        .unwrap()
        .clone();
    assert!(values.iter().any(|value| {
        value["name"] == "output_dir"
            && value["value"] == output_dir.to_string_lossy().as_ref()
            && value["source"] == "file"
    }));
}

#[test]
fn config_set_preserves_unknown_values_and_reset_removes_settings_but_keeps_key_files() {
    let directory = tempfile::tempdir().unwrap();
    let configured_key = directory.path().join("configured").join("prod.keys");
    std::fs::create_dir_all(configured_key.parent().unwrap()).unwrap();
    std::fs::write(&configured_key, "configured key bytes\n").unwrap();
    let path = write_config(
        directory.path(),
        &format!(
            "schema_version = 1\nkeys_path = {configured_key:?}\n\n[translation]\napi_key = \"synthetic-secret\"\nnote = \"keep me\"\n"
        ),
    );
    let output_directory = directory.path().join("chosen-output");

    let set = run(
        directory.path(),
        &[
            "config",
            "set",
            "output_dir",
            output_directory.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(
        set.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&set.stderr)
    );
    assert_eq!(one_document(&set)["kind"], "config.set");
    let updated = std::fs::read_to_string(&path).unwrap();
    assert!(updated.contains("note = \"keep me\""));
    assert!(updated.contains("api_key = \"synthetic-secret\""));
    assert!(updated.contains(output_directory.to_str().unwrap()));

    let conventional_key = directory.path().join(".switch").join("prod.keys");
    std::fs::create_dir_all(conventional_key.parent().unwrap()).unwrap();
    std::fs::write(&conventional_key, "header_key = 00\n").unwrap();
    let reset = run(directory.path(), &["config", "reset", "--json"]);
    assert_eq!(reset.status.code(), Some(0));
    assert_eq!(one_document(&reset)["kind"], "config.reset");
    assert_eq!(
        std::fs::read_to_string(&conventional_key).unwrap(),
        "header_key = 00\n"
    );
    assert_eq!(
        std::fs::read_to_string(&configured_key).unwrap(),
        "configured key bytes\n"
    );
    let reset_contents = std::fs::read_to_string(&path).unwrap();
    assert!(reset_contents.contains("schema_version = 1"));
    assert!(!reset_contents.contains(configured_key.to_str().unwrap()));
    assert!(!reset_contents.contains(output_directory.to_str().unwrap()));
    assert!(!reset_contents.contains("keep me"));
}

#[test]
fn config_set_preserves_placeholder_braces_in_the_path_and_value() {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().join("{name}").join("{value}");
    let configured_output_dir = directory
        .path()
        .join("{name}")
        .join("{value}")
        .join("output");
    let config_path = config_path(&home);

    let output = run(
        &home,
        &[
            "config",
            "set",
            "output_dir",
            configured_output_dir.to_str().unwrap(),
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!(
            "Updated output_dir in {}: {}\n",
            config_path.display(),
            configured_output_dir.display(),
        )
    );
}

#[test]
fn legacy_config_is_read_without_rewrite_and_migrates_only_on_explicit_save() {
    let directory = tempfile::tempdir().unwrap();
    let original = "keys_path = \"/synthetic/keys\"\n\n[translation]\nnote = \"preserve\"\n";
    let path = write_config(directory.path(), original);

    let show = run(directory.path(), &["config", "show", "--json"]);
    assert_eq!(show.status.code(), Some(0));
    assert_eq!(one_document(&show)["result"]["schema_version"], 0);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);

    let output_directory = directory.path().join("migrated-output");
    let set = run(
        directory.path(),
        &[
            "config",
            "set",
            "output_dir",
            output_directory.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(
        set.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&set.stderr)
    );
    let backup = path.with_file_name("config.toml.v0.bak");
    assert_eq!(std::fs::read_to_string(backup).unwrap(), original);
    let migrated = std::fs::read_to_string(&path).unwrap();
    assert!(migrated.contains("schema_version = 1"));
    assert!(migrated.contains("note = \"preserve\""));
}

#[test]
fn conflicting_migration_backup_prevents_the_save() {
    let directory = tempfile::tempdir().unwrap();
    let original = "output_dir = \"/synthetic/original\"\n";
    let path = write_config(directory.path(), original);
    let backup = path.with_file_name("config.toml.v0.bak");
    std::fs::write(&backup, "different prior backup\n").unwrap();

    let output = run(
        directory.path(),
        &[
            "config",
            "set",
            "output_dir",
            directory.path().join("new-output").to_str().unwrap(),
            "--json",
        ],
    );

    assert_error_document(&output, 2, "config_backup_failed");
    assert_eq!(std::fs::read_to_string(path).unwrap(), original);
    assert_eq!(
        std::fs::read_to_string(backup).unwrap(),
        "different prior backup\n"
    );
}

#[test]
fn migration_rejects_oversized_backup_without_overwriting_current_files() {
    let directory = tempfile::tempdir().unwrap();
    let original = "output_dir = \"/synthetic/original\"\n";
    let path = write_config(directory.path(), original);
    let backup = path.with_file_name("config.toml.v0.bak");
    let oversized_backup = vec![b'x'; MAX_CONFIG_BYTES + 4096];
    std::fs::write(&backup, &oversized_backup).unwrap();

    let destination = directory.path().join("new-output");
    let destination_text = destination.to_str().unwrap();
    let output = run(
        directory.path(),
        &["config", "set", "output_dir", destination_text, "--json"],
    );

    assert_error_document(&output, 2, "config_backup_failed");
    assert_eq!(std::fs::read(&path).unwrap(), original.as_bytes());
    assert_eq!(std::fs::read(&backup).unwrap(), oversized_backup);
}

#[test]
fn config_set_rejects_oversized_serialization_before_backup_or_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let prefix = "output_dir = \"/a\"\n";
    let padding = "#".repeat(MAX_CONFIG_BYTES - prefix.len() - 1);
    let original = format!("{prefix}{padding}\n");
    assert_eq!(original.len(), MAX_CONFIG_BYTES);
    let path = write_config(directory.path(), &original);
    let backup = path.with_file_name("config.toml.v0.bak");
    let destination = directory.path().join("larger-output");
    let destination_text = destination.to_str().unwrap();

    let output = run(
        directory.path(),
        &["config", "set", "output_dir", destination_text, "--json"],
    );

    assert_error_document(&output, 2, "config_limit_exceeded");
    assert_eq!(std::fs::read(&path).unwrap(), original.as_bytes());
    assert!(
        !backup.exists(),
        "size validation must precede migration backup"
    );

    let show = run(directory.path(), &["config", "show", "--json"]);
    assert_eq!(show.status.code(), Some(0));
    assert_eq!(one_document(&show)["result"]["schema_version"], 0);
    assert_eq!(std::fs::read(&path).unwrap(), original.as_bytes());
}

#[cfg(unix)]
#[test]
fn migration_rejects_backup_symlink_without_changing_either_file() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let original = "keys_path = \"/synthetic/keys\"\n";
    let path = write_config(directory.path(), original);
    let backup = path.with_file_name("config.toml.v0.bak");
    symlink(&path, &backup).unwrap();
    let destination = directory.path().join("new-output");

    let output = run(
        directory.path(),
        &[
            "config",
            "set",
            "output_dir",
            destination.to_str().unwrap(),
            "--json",
        ],
    );

    assert_error_document(&output, 2, "config_backup_failed");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    assert!(
        std::fs::symlink_metadata(&backup)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read_to_string(&backup).unwrap(), original);
}

#[test]
fn future_config_version_fails_closed_without_rewriting_or_backing_up() {
    let directory = tempfile::tempdir().unwrap();
    let original = "schema_version = 9\noutput_dir = \"/synthetic/output\"\n";
    let path = write_config(directory.path(), original);

    let reset = run(directory.path(), &["config", "reset", "--json"]);

    assert_error_document(&reset, 2, "config_version_unsupported");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    assert!(!path.with_file_name("config.toml.v9.bak").exists());
}

#[test]
fn keys_set_preserves_the_complete_validated_file_and_replaces_with_private_mode() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("complete.keys");
    let key = "00".repeat(32);
    let original =
        format!("# synthetic key file\nheader_key = {key}\nunrelated_key = useful-entry\n");
    std::fs::write(&source, &original).unwrap();

    let output = run(
        directory.path(),
        &["keys", "set", source.to_str().unwrap(), "--json"],
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document = one_document(&output);
    assert_eq!(document["kind"], "keys.set");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&key));
    let destination = directory.path().join(".switch").join("prod.keys");
    assert_eq!(std::fs::read_to_string(&destination).unwrap(), original);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&destination)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert!(config_path(directory.path()).is_file());
}

#[cfg(unix)]
#[test]
fn keys_set_preserves_an_existing_switch_directory_mode() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("complete.keys");
    let key = "00".repeat(32);
    std::fs::write(&source, format!("header_key = {key}\n")).unwrap();
    let destination = directory.path().join(".switch").join("prod.keys");
    let switch_directory = destination.parent().unwrap();
    std::fs::create_dir(switch_directory).unwrap();
    std::fs::set_permissions(switch_directory, std::fs::Permissions::from_mode(0o755)).unwrap();

    let output = run(
        directory.path(),
        &["keys", "set", source.to_str().unwrap(), "--json"],
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let switch_mode = std::fs::metadata(switch_directory)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(switch_mode & 0o777, 0o755);
    let destination_mode = std::fs::metadata(&destination)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(destination_mode & 0o777, 0o600);
}

#[test]
fn keys_set_uses_provider_whitespace_and_preserves_source_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("complete.keys");
    let key = "00".repeat(32);
    let original = format!("header_key = \x0c{key}\x0c\nunrelated_key = retained\n");
    std::fs::write(&source, &original).unwrap();

    let output = run(
        directory.path(),
        &["keys", "set", source.to_str().unwrap(), "--json"],
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let destination = directory.path().join(".switch").join("prod.keys");
    assert_eq!(std::fs::read(&destination).unwrap(), original.as_bytes());
}

#[cfg(unix)]
#[test]
fn keys_set_rejects_a_source_symlink_and_preserves_the_existing_destination() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("synthetic-valid.keys");
    let key = "00".repeat(32);
    std::fs::write(&target, format!("header_key = {key}\n")).unwrap();
    let source = directory.path().join("source-link-valid.keys");
    symlink(&target, &source).unwrap();
    let destination = directory.path().join(".switch").join("prod.keys");
    std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
    let existing = b"existing destination sentinel\n";
    std::fs::write(&destination, existing).unwrap();

    let output = run(
        directory.path(),
        &["keys", "set", source.to_str().unwrap(), "--json"],
    );

    assert_error_document(&output, 3, "key_file_unavailable");
    assert_eq!(std::fs::read(&destination).unwrap(), existing);
}

#[test]
fn invalid_key_source_preserves_the_existing_destination() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("invalid.keys");
    std::fs::write(&source, "unrelated_key = useful-entry\n").unwrap();
    let destination = directory.path().join(".switch").join("prod.keys");
    std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
    std::fs::write(&destination, "existing destination\n").unwrap();

    let output = run(
        directory.path(),
        &["keys", "set", source.to_str().unwrap(), "--json"],
    );

    assert_eq!(output.status.code(), Some(3));
    let document = one_document(&output);
    assert_eq!(document["kind"], "error");
    assert_eq!(document["error"]["code"], "missing_header_key");
    assert_eq!(
        std::fs::read_to_string(&destination).unwrap(),
        "existing destination\n"
    );
}

#[test]
fn unavailable_key_source_preserves_the_existing_destination() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join(".switch").join("prod.keys");
    std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
    std::fs::write(&destination, "existing destination\n").unwrap();
    let missing = directory.path().join("missing.keys");

    let output = run(
        directory.path(),
        &["keys", "set", missing.to_str().unwrap(), "--json"],
    );

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        one_document(&output)["error"]["code"],
        "key_file_unavailable"
    );
    assert_eq!(
        std::fs::read_to_string(&destination).unwrap(),
        "existing destination\n"
    );
}

#[test]
fn malformed_key_source_preserves_the_existing_destination() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("malformed.keys");
    std::fs::write(&source, "header_key = not-a-64-byte-hex-value\n").unwrap();
    let destination = directory.path().join(".switch").join("prod.keys");
    std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
    std::fs::write(&destination, "existing destination\n").unwrap();

    let output = run(
        directory.path(),
        &["keys", "set", source.to_str().unwrap(), "--json"],
    );

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(one_document(&output)["error"]["code"], "key_file_malformed");
    assert_eq!(
        std::fs::read_to_string(&destination).unwrap(),
        "existing destination\n"
    );
}

#[test]
fn oversized_key_source_preserves_the_existing_destination() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("oversized.keys");
    std::fs::write(&source, vec![b'#'; 1024 * 1024 + 1]).unwrap();
    let destination = directory.path().join(".switch").join("prod.keys");
    std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
    std::fs::write(&destination, "existing destination\n").unwrap();

    let output = run(
        directory.path(),
        &["keys", "set", source.to_str().unwrap(), "--json"],
    );

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        one_document(&output)["error"]["code"],
        "key_file_limit_exceeded"
    );
    assert_eq!(
        std::fs::read_to_string(&destination).unwrap(),
        "existing destination\n"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn keys_set_rejects_a_non_utf8_destination_before_replacement() {
    let root = tempfile::tempdir().unwrap();
    let home = non_utf8_child(root.path(), "home-");
    let config_home = root.path().join("xdg-config");
    std::fs::create_dir(&home).unwrap();
    write_config_with_config_home(&home, &config_home, "schema_version = 1\n");
    let destination = home.join(".switch").join("prod.keys");
    std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
    let original = b"existing complete key bytes\n";
    std::fs::write(&destination, original).unwrap();
    let source = root.path().join("complete.keys");
    std::fs::write(
        &source,
        format!(
            "header_key = {}\nunrelated_key = retained\n",
            "00".repeat(32)
        ),
    )
    .unwrap();

    let output = run_with_config_home(
        &home,
        &config_home,
        &["keys", "set", source.to_str().unwrap(), "--json"],
    );

    assert_error_document(&output, 3, "key_destination_write_failed");
    assert_eq!(std::fs::read(&destination).unwrap(), original);
    assert_no_atomic_replacement_artifacts(destination.parent().unwrap());
}

#[cfg(unix)]
#[test]
fn config_set_rejects_a_non_utf8_config_path_without_creating_first_use_state() {
    let root = tempfile::tempdir().unwrap();
    #[cfg(target_os = "linux")]
    let (home, config_home) = (
        root.path().to_path_buf(),
        non_utf8_child(root.path(), "config-"),
    );
    #[cfg(not(target_os = "linux"))]
    let (home, config_home) = (
        non_utf8_child(root.path(), "home-"),
        root.path().join("xdg-config"),
    );
    let path = config_path_with_config_home(&home, &config_home);
    let output_directory = root.path().join("configured-output");

    let output = run_with_config_home(
        &home,
        &config_home,
        &[
            "config",
            "set",
            "output_dir",
            output_directory.to_str().unwrap(),
            "--json",
        ],
    );

    assert_error_document(&output, 3, "config_path_invalid");
    assert!(
        !path.exists(),
        "configuration must not be created before path representability is known"
    );
    if let Some(parent) = path.parent() {
        assert!(!parent.exists());
    }
}

#[cfg(unix)]
#[test]
fn config_path_rejects_a_non_utf8_path_without_creating_first_use_state() {
    let root = tempfile::tempdir().unwrap();
    let (home, config_home, path) = non_utf8_config_roots(root.path());

    let output = run_with_config_home(&home, &config_home, &["config", "path", "--json"]);

    assert_error_document(&output, 3, "config_path_invalid");
    assert_configuration_was_not_initialized(&path);
}

#[cfg(unix)]
#[test]
fn config_show_rejects_a_non_utf8_path_without_creating_first_use_state() {
    let root = tempfile::tempdir().unwrap();
    let (home, config_home, path) = non_utf8_config_roots(root.path());

    let output = run_with_config_home(&home, &config_home, &["config", "show", "--json"]);

    assert_error_document(&output, 3, "config_path_invalid");
    assert_configuration_was_not_initialized(&path);
}

#[cfg(unix)]
#[test]
fn ordinary_startup_rejects_a_non_utf8_config_path_without_creating_state() {
    let root = tempfile::tempdir().unwrap();
    let (home, config_home, path) = non_utf8_config_roots(root.path());
    let input = root.path().join("input.pfs0");
    std::fs::write(&input, b"synthetic input").unwrap();

    let output = run_with_config_home(
        &home,
        &config_home,
        &["probe", input.to_str().unwrap(), "--json"],
    );

    assert_error_document(&output, 3, "config_path_invalid");
    assert_configuration_was_not_initialized(&path);
}

#[cfg(target_os = "linux")]
#[test]
fn config_set_rejects_a_non_utf8_config_path_without_rewriting_existing_state() {
    let root = tempfile::tempdir().unwrap();
    let config_home = non_utf8_child(root.path(), "config-");
    let original = b"schema_version = 1\n\n[manual]\nnote = \"preserve\"\n";
    let path = write_config_with_config_home(
        root.path(),
        &config_home,
        std::str::from_utf8(original).unwrap(),
    );
    let output_directory = root.path().join("configured-output");

    let output = run_with_config_home(
        root.path(),
        &config_home,
        &[
            "config",
            "set",
            "output_dir",
            output_directory.to_str().unwrap(),
            "--json",
        ],
    );

    assert_error_document(&output, 3, "config_path_invalid");
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert_no_atomic_replacement_artifacts(path.parent().unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn read_paths_reject_a_non_utf8_config_path_without_changing_existing_state() {
    let root = tempfile::tempdir().unwrap();
    let config_home = non_utf8_child(root.path(), "config-");
    let original = b"schema_version = 1\n\n[manual]\nnote = \"preserve\"\n";
    let path = write_config_with_config_home(
        root.path(),
        &config_home,
        std::str::from_utf8(original).unwrap(),
    );

    for args in [
        &["config", "path", "--json"][..],
        &["config", "show", "--json"][..],
    ] {
        let output = run_with_config_home(root.path(), &config_home, args);
        assert_error_document(&output, 3, "config_path_invalid");
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_no_atomic_replacement_artifacts(path.parent().unwrap());
    }

    let input = root.path().join("input.pfs0");
    std::fs::write(&input, b"synthetic input").unwrap();
    let output = run_with_config_home(
        root.path(),
        &config_home,
        &["probe", input.to_str().unwrap(), "--json"],
    );
    assert_error_document(&output, 3, "config_path_invalid");
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert_no_atomic_replacement_artifacts(path.parent().unwrap());
}

#[test]
fn config_and_key_commands_default_to_redacted_human_output() {
    let directory = tempfile::tempdir().unwrap();
    let path = run(directory.path(), &["config", "path"]);
    assert_eq!(path.status.code(), Some(0));
    assert!(path.stderr.is_empty());
    assert!(String::from_utf8_lossy(&path.stdout).contains("Configuration file:"));

    let output_directory = directory.path().join("human-output");
    let set = run(
        directory.path(),
        &[
            "config",
            "set",
            "output_dir",
            output_directory.to_str().unwrap(),
        ],
    );
    assert_eq!(set.status.code(), Some(0));
    assert!(set.stderr.is_empty());
    assert!(String::from_utf8_lossy(&set.stdout).contains("Updated output_dir"));

    let key = "00".repeat(32);
    let source = directory.path().join("complete.keys");
    std::fs::write(
        &source,
        format!("header_key = {key}\nunrelated_key = retained\n"),
    )
    .unwrap();
    let keys = run(directory.path(), &["keys", "set", source.to_str().unwrap()]);
    assert_eq!(keys.status.code(), Some(0));
    assert!(keys.stderr.is_empty());
    let keys_stdout = String::from_utf8_lossy(&keys.stdout);
    assert!(keys_stdout.contains("Installed the complete key file"));
    assert!(!keys_stdout.contains(&key));

    let reset = run(directory.path(), &["config", "reset"]);
    assert_eq!(reset.status.code(), Some(0));
    assert!(reset.stderr.is_empty());
    assert!(String::from_utf8_lossy(&reset.stdout).contains("Reset standalone configuration:"));
}

#[test]
fn startup_configuration_failure_emits_one_jsonl_error_document() {
    let directory = tempfile::tempdir().unwrap();
    let original = "schema_version = [\n";
    write_config(directory.path(), original);
    let source = directory.path().join("source.bin");
    std::fs::write(&source, b"data").unwrap();

    let output = run(
        directory.path(),
        &["copy", source.to_str().unwrap(), "--jsonl"],
    );

    assert_error_document(&output, 2, "config_parse_failed");
}

#[test]
fn copy_usage_advertises_optional_destination() {
    let directory = tempfile::tempdir().unwrap();

    let output = run(directory.path(), &["copy", "--help"]);

    assert_eq!(output.status.code(), Some(2));
    let usage = String::from_utf8_lossy(&output.stderr);
    assert!(usage.contains("copy <source> [destination]"));
}

#[cfg(target_os = "macos")]
#[test]
fn copy_without_destination_uses_configured_output_directory_on_macos() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.bin");
    let output_directory = directory.path().join("configured-output");
    std::fs::write(&source, vec![0x51_u8; 96 * 1024]).unwrap();
    let configured = run(
        directory.path(),
        &[
            "config",
            "set",
            "output_dir",
            output_directory.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(configured.status.code(), Some(0));

    let output = run(
        directory.path(),
        &[
            "copy",
            source.to_str().unwrap(),
            "--workspace",
            directory.path().join("workspace").to_str().unwrap(),
            "--json",
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output_directory.join("source.bin").is_file());
}

#[cfg(not(target_os = "macos"))]
#[test]
fn copy_without_destination_fails_closed_on_non_macos() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.bin");
    let output_directory = directory.path().join("configured-output");
    std::fs::write(&source, vec![0x51_u8; 96 * 1024]).unwrap();
    let configured = run(
        directory.path(),
        &[
            "config",
            "set",
            "output_dir",
            output_directory.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(configured.status.code(), Some(0));

    let output = run(
        directory.path(),
        &[
            "copy",
            source.to_str().unwrap(),
            "--workspace",
            directory.path().join("workspace").to_str().unwrap(),
            "--json",
        ],
    );

    assert_error_document(&output, 3, "unsupported_capability");
    assert!(!output_directory.join("source.bin").exists());
}

#[cfg(target_os = "macos")]
#[test]
fn missing_source_preflight_does_not_create_or_probe_the_implicit_output_directory_on_macos() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("missing.bin");
    let output_directory = directory.path().join("configured-output");
    let configured = run(
        directory.path(),
        &[
            "config",
            "set",
            "output_dir",
            output_directory.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(configured.status.code(), Some(0));

    let output = run(
        directory.path(),
        &[
            "copy",
            source.to_str().unwrap(),
            "--workspace",
            directory.path().join("workspace").to_str().unwrap(),
            "--json",
        ],
    );

    assert_error_document(&output, 3, "source_unavailable");
    assert!(
        !output_directory.exists(),
        "source preflight failure must not create or probe an implicit output directory"
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn missing_source_copy_fails_closed_on_non_macos_without_creating_output() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("missing.bin");
    let output_directory = directory.path().join("configured-output");
    let configured = run(
        directory.path(),
        &[
            "config",
            "set",
            "output_dir",
            output_directory.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(configured.status.code(), Some(0));

    let output = run(
        directory.path(),
        &[
            "copy",
            source.to_str().unwrap(),
            "--workspace",
            directory.path().join("workspace").to_str().unwrap(),
            "--json",
        ],
    );

    assert_error_document(&output, 3, "unsupported_capability");
    assert!(!output_directory.exists());
}

#[cfg(target_os = "macos")]
#[test]
fn copy_explicit_destination_overrides_configured_output_directory_on_macos() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.bin");
    let explicit = directory.path().join("explicit.bin");
    let output_directory = directory.path().join("configured-output");
    std::fs::write(&source, vec![0x51_u8; 96 * 1024]).unwrap();
    let configured = run(
        directory.path(),
        &[
            "config",
            "set",
            "output_dir",
            output_directory.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(configured.status.code(), Some(0));

    let output = run(
        directory.path(),
        &[
            "copy",
            source.to_str().unwrap(),
            explicit.to_str().unwrap(),
            "--workspace",
            directory.path().join("workspace").to_str().unwrap(),
            "--json",
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(explicit.is_file());
    assert!(!output_directory.join("source.bin").exists());
}

#[cfg(not(target_os = "macos"))]
#[test]
fn copy_explicit_destination_fails_closed_on_non_macos() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.bin");
    let explicit = directory.path().join("explicit.bin");
    let output_directory = directory.path().join("configured-output");
    std::fs::write(&source, vec![0x51_u8; 96 * 1024]).unwrap();
    let configured = run(
        directory.path(),
        &[
            "config",
            "set",
            "output_dir",
            output_directory.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(configured.status.code(), Some(0));

    let output = run(
        directory.path(),
        &[
            "copy",
            source.to_str().unwrap(),
            explicit.to_str().unwrap(),
            "--workspace",
            directory.path().join("workspace").to_str().unwrap(),
            "--json",
        ],
    );

    assert_error_document(&output, 3, "unsupported_capability");
    assert!(!explicit.exists());
    assert!(!output_directory.join("source.bin").exists());
}

// This subprocess test writes to HOME/Documents. Windows resolves Documents
// through the native known-folder API instead of the synthetic HOME used here;
// its unavailable-Documents behavior is covered by the injected path unit test.
#[cfg(target_os = "macos")]
#[test]
fn copy_default_output_uses_documents_on_macos() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.bin");
    std::fs::write(&source, vec![0x51_u8; 96 * 1024]).unwrap();
    let documents_directory = directory.path().join("Documents");

    let path = run(directory.path(), &["config", "path", "--json"]);
    assert_eq!(path.status.code(), Some(0));

    let missing_documents = run(
        directory.path(),
        &[
            "copy",
            source.to_str().unwrap(),
            "--workspace",
            directory.path().join("workspace-1").to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(missing_documents.status.code(), Some(3));
    assert_eq!(
        one_document(&missing_documents)["error"]["code"],
        "output_directory_unavailable"
    );

    std::fs::create_dir_all(&documents_directory).unwrap();
    let success = run(
        directory.path(),
        &[
            "copy",
            source.to_str().unwrap(),
            "--workspace",
            directory.path().join("workspace-2").to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(
        success.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&success.stderr)
    );
    assert!(
        documents_directory
            .join("NSCB_output")
            .join("source.bin")
            .is_file()
    );

    std::fs::remove_file(documents_directory.join("NSCB_output").join("source.bin")).unwrap();
    std::fs::remove_dir_all(documents_directory.join("NSCB_output")).unwrap();
    std::fs::write(documents_directory.join("NSCB_output"), "not a directory").unwrap();
    let unusable = run(
        directory.path(),
        &[
            "copy",
            source.to_str().unwrap(),
            "--workspace",
            directory.path().join("workspace-3").to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(unusable.status.code(), Some(3));
    assert_eq!(
        one_document(&unusable)["error"]["code"],
        "output_directory_unavailable"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn copy_default_output_reports_unavailable_documents_before_capability_on_linux() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.bin");
    std::fs::write(&source, vec![0x51_u8; 96 * 1024]).unwrap();

    let missing_documents = run(
        directory.path(),
        &[
            "copy",
            source.to_str().unwrap(),
            "--workspace",
            directory.path().join("workspace-1").to_str().unwrap(),
            "--json",
        ],
    );

    assert_error_document(&missing_documents, 3, "output_directory_unavailable");
}

#[cfg(target_os = "linux")]
#[test]
fn copy_default_output_reports_unsupported_capability_when_documents_exist_on_linux() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.bin");
    let documents_directory = directory.path().join("Documents");
    std::fs::write(&source, vec![0x51_u8; 96 * 1024]).unwrap();
    write_xdg_documents_mapping(directory.path(), &documents_directory);
    std::fs::create_dir_all(&documents_directory).unwrap();

    let output = run(
        directory.path(),
        &[
            "copy",
            source.to_str().unwrap(),
            "--workspace",
            directory.path().join("workspace").to_str().unwrap(),
            "--json",
        ],
    );

    assert_error_document(&output, 3, "unsupported_capability");
    assert!(!documents_directory.join("NSCB_output").exists());
}

#[cfg(target_os = "macos")]
#[test]
fn actual_inspect_and_verify_use_the_configured_key_file() {
    let directory = tempfile::tempdir().unwrap();
    let built = build_verification(VerificationSpec::default());
    let paths = built.write(directory.path());
    let configured = run(
        directory.path(),
        &[
            "config",
            "set",
            "keys_path",
            paths.keys.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(
        configured.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&configured.stderr)
    );

    let cache = std::fs::canonicalize(directory.path())
        .unwrap()
        .join("inspect-cache");
    std::fs::create_dir_all(&cache).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let inspection = run(
        directory.path(),
        &[
            "inspect",
            paths.input.to_str().unwrap(),
            "--cache-dir",
            cache.to_str().unwrap(),
            "--json",
        ],
    );
    // The repository does not bundle NSTool. Reaching the provider-cache
    // boundary proves Inspection accepted the configured key file even though
    // the managed helper is intentionally absent from this synthetic test.
    assert_eq!(inspection.status.code(), Some(3));
    assert_eq!(
        one_document(&inspection)["error"]["code"],
        "provider_cache_missing"
    );

    let verification = run(
        directory.path(),
        &[
            "verify",
            paths.input.to_str().unwrap(),
            "--trust-anchor",
            paths.anchor.to_str().unwrap(),
            "--anchor-generation",
            "5",
            "--json",
        ],
    );
    assert_eq!(
        verification.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&verification.stderr)
    );
    let document = one_document(&verification);
    assert_eq!(document["result"]["profile"], "full");
    assert_eq!(document["result"]["outcome"], "passed");
}

#[cfg(target_os = "macos")]
#[test]
fn explicit_key_path_overrides_missing_configured_path() {
    let directory = tempfile::tempdir().unwrap();
    let built = build_verification(VerificationSpec::default());
    let paths = built.write(directory.path());
    let missing = directory.path().join("configured-missing.keys");
    let configured = run(
        directory.path(),
        &[
            "config",
            "set",
            "keys_path",
            missing.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(configured.status.code(), Some(0));

    let cache = std::fs::canonicalize(directory.path())
        .unwrap()
        .join("explicit-inspect-cache");
    let inspection = run(
        directory.path(),
        &[
            "inspect",
            paths.input.to_str().unwrap(),
            "--keys",
            paths.keys.to_str().unwrap(),
            "--cache-dir",
            cache.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(inspection.status.code(), Some(3));
    assert_eq!(
        one_document(&inspection)["error"]["code"],
        "provider_cache_missing"
    );

    let verification = run(
        directory.path(),
        &[
            "verify",
            paths.input.to_str().unwrap(),
            "--keys",
            paths.keys.to_str().unwrap(),
            "--trust-anchor",
            paths.anchor.to_str().unwrap(),
            "--anchor-generation",
            "5",
            "--json",
        ],
    );
    assert_eq!(
        verification.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&verification.stderr)
    );
    let document = one_document(&verification);
    assert_eq!(document["result"]["profile"], "full");
    assert_eq!(document["result"]["outcome"], "passed");
}

#[cfg(target_os = "macos")]
#[test]
fn missing_configured_key_does_not_fall_back_to_the_conventional_file() {
    let directory = tempfile::tempdir().unwrap();
    let built = build_verification(VerificationSpec::default());
    let paths = built.write(directory.path());
    let conventional = directory.path().join(".switch").join("prod.keys");
    std::fs::create_dir_all(conventional.parent().unwrap()).unwrap();
    std::fs::write(&conventional, &built.keys_file).unwrap();
    let missing = directory.path().join("configured-missing.keys");
    let configured = run(
        directory.path(),
        &[
            "config",
            "set",
            "keys_path",
            missing.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(configured.status.code(), Some(0));

    let inspection = run(
        directory.path(),
        &["inspect", paths.input.to_str().unwrap(), "--json"],
    );

    assert_eq!(inspection.status.code(), Some(3));
    assert_eq!(
        one_document(&inspection)["error"]["code"],
        "key_file_unavailable"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn conventional_home_key_is_used_when_configuration_has_no_override() {
    let directory = tempfile::tempdir().unwrap();
    let built = build_verification(VerificationSpec::default());
    let paths = built.write(directory.path());
    let conventional = directory.path().join(".switch").join("prod.keys");
    std::fs::create_dir_all(conventional.parent().unwrap()).unwrap();
    std::fs::write(&conventional, &built.keys_file).unwrap();
    let path = run(directory.path(), &["config", "path", "--json"]);
    assert_eq!(path.status.code(), Some(0));

    let verification = run(
        directory.path(),
        &[
            "verify",
            paths.input.to_str().unwrap(),
            "--trust-anchor",
            paths.anchor.to_str().unwrap(),
            "--anchor-generation",
            "5",
            "--json",
        ],
    );

    assert_eq!(
        verification.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&verification.stderr)
    );
    let document = one_document(&verification);
    assert_eq!(document["result"]["profile"], "full");
    assert_eq!(document["result"]["outcome"], "passed");
}

#[test]
fn relative_config_paths_fail_without_rewriting_the_file() {
    let directory = tempfile::tempdir().unwrap();
    let original = "schema_version = 1\n";
    let path = write_config(directory.path(), original);

    let output = run(
        directory.path(),
        &["config", "set", "output_dir", "relative-output", "--json"],
    );

    assert_error_document(&output, 2, "config_path_invalid");
    assert_eq!(std::fs::read_to_string(path).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn symlinked_configuration_path_is_rejected_without_modifying_its_target() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let path = config_path(directory.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let target = directory.path().join("outside.toml");
    std::fs::write(&target, "schema_version = 1\n").unwrap();
    symlink(&target, &path).unwrap();

    let output = run(directory.path(), &["config", "show", "--json"]);

    assert_error_document(&output, 2, "config_path_invalid");
    assert_eq!(
        std::fs::read_to_string(target).unwrap(),
        "schema_version = 1\n"
    );
}

#[test]
fn malformed_and_incorrectly_typed_configuration_fail_as_single_documents() {
    for (contents, expected_code) in [
        ("schema_version = [\n", "config_parse_failed"),
        (
            "schema_version = 1\noutput_dir = 5\n",
            "config_type_invalid",
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = write_config(directory.path(), contents);

        let output = run(directory.path(), &["config", "show", "--json"]);

        assert_error_document(&output, 2, expected_code);
        assert_eq!(std::fs::read_to_string(path).unwrap(), contents);
    }
}

#[test]
fn unavailable_configuration_home_fails_as_one_actionable_document() {
    let directory = tempfile::tempdir().unwrap();
    let not_a_directory = directory.path().join("home-file");
    std::fs::write(&not_a_directory, "not a directory").unwrap();

    let output = run(&not_a_directory, &["config", "path", "--json"]);

    assert_error_document(&output, 2, "config_write_failed");
}

#[test]
fn unavailable_configuration_lock_fails_as_a_configuration_error() {
    let directory = tempfile::tempdir().unwrap();
    let path = config_path(directory.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::create_dir(path.with_file_name("config.lock")).unwrap();

    let output = run(directory.path(), &["config", "show", "--json"]);

    assert_error_document(&output, 2, "config_lock_failed");
}

#[test]
fn unknown_config_setting_is_a_usage_error() {
    let directory = tempfile::tempdir().unwrap();
    let path = run(directory.path(), &["config", "path", "--json"]);
    assert_eq!(path.status.code(), Some(0));

    let output = run(
        directory.path(),
        &["config", "set", "unknown", "/synthetic/value", "--json"],
    );

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(one_document(&output)["error"]["code"], "usage_error");
}
