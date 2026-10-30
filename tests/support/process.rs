//! Isolated subprocess construction for integration tests.

use std::path::{Path, PathBuf};
use std::process::Command;

pub fn isolated_command() -> Command {
    let home = test_home();
    isolated_command_with_home(&home)
}

/// Creates a real NSCB command rooted in one caller-selected temporary home.
/// Tests that need several commands to share durable state use this helper so
/// unrelated tests cannot observe or prune their history.
pub fn isolated_command_with_home(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nscb"));
    command
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("xdg-config"))
        .env("XDG_CACHE_HOME", home.join("xdg-cache"))
        .env("XDG_DATA_HOME", home.join("xdg-data"))
        .env("APPDATA", home.join("AppData").join("Roaming"))
        .env("LOCALAPPDATA", home.join("AppData").join("Local"));
    command
}

fn test_home() -> PathBuf {
    let test_name = std::thread::current()
        .name()
        .unwrap_or("unscoped-test")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    let home = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "nscb-integration-home-{}-{test_name}",
        std::process::id()
    ));
    std::fs::create_dir_all(&home).expect("create isolated integration home");
    home
}
