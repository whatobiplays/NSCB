//! Isolated subprocess construction for integration tests.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

pub fn isolated_command() -> Command {
    let home = test_home();
    let mut command = Command::new(env!("CARGO_BIN_EXE_nscb"));
    command
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("xdg-config"))
        .env("XDG_CACHE_HOME", home.join("xdg-cache"))
        .env("APPDATA", home.join("AppData").join("Roaming"))
        .env("LOCALAPPDATA", home.join("AppData").join("Local"));
    command
}

fn test_home() -> &'static Path {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let home = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("nscb-integration-home-{}", std::process::id()));
        std::fs::create_dir_all(&home).expect("create isolated integration home");
        home
    })
}
