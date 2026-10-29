//! Native per-user locations used only by the standalone executable.

use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StandalonePathError {
    ConfigRoot,
    Home,
    Documents,
}

pub(crate) fn config_file_path() -> Result<PathBuf, StandalonePathError> {
    #[cfg(windows)]
    {
        windows_config_file_path(
            std::env::var_os("APPDATA").map(PathBuf::from),
            dirs::config_dir,
        )
    }
    #[cfg(not(windows))]
    {
        config_file_in(dirs::config_dir())
    }
}

pub(crate) fn conventional_key_file_path() -> Result<PathBuf, StandalonePathError> {
    #[cfg(windows)]
    {
        windows_key_file_path(
            std::env::var_os("USERPROFILE").map(PathBuf::from),
            dirs::home_dir,
        )
    }
    #[cfg(not(windows))]
    {
        key_file_in(dirs::home_dir())
    }
}

#[cfg(any(windows, test))]
fn windows_config_file_path(
    appdata: Option<PathBuf>,
    native_roaming_directory: impl FnOnce() -> Option<PathBuf>,
) -> Result<PathBuf, StandalonePathError> {
    let base = match appdata {
        Some(path) => Some(path),
        None => native_roaming_directory(),
    };
    config_file_in(base)
}

#[cfg(any(windows, test))]
fn windows_key_file_path(
    user_profile: Option<PathBuf>,
    native_profile_directory: impl FnOnce() -> Option<PathBuf>,
) -> Result<PathBuf, StandalonePathError> {
    let base = match user_profile {
        Some(path) => Some(path),
        None => native_profile_directory(),
    };
    key_file_in(base)
}

fn key_file_in(profile: Option<PathBuf>) -> Result<PathBuf, StandalonePathError> {
    profile
        .filter(|path| path.is_absolute())
        .map(|path| path.join(".switch").join("prod.keys"))
        .ok_or(StandalonePathError::Home)
}

pub(crate) fn default_output_directory() -> Result<PathBuf, StandalonePathError> {
    #[cfg(test)]
    if DOCUMENTS_UNAVAILABLE.with(std::cell::Cell::get) {
        return Err(StandalonePathError::Documents);
    }
    default_output_in(dirs::document_dir())
}

#[cfg(test)]
std::thread_local! {
    static DOCUMENTS_UNAVAILABLE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(super) fn simulate_documents_unavailable(unavailable: bool) {
    DOCUMENTS_UNAVAILABLE.with(|value| value.set(unavailable));
}

fn config_file_in(base: Option<PathBuf>) -> Result<PathBuf, StandalonePathError> {
    base.filter(|path| path.is_absolute())
        .map(|path| path.join("NSCB").join("config.toml"))
        .ok_or(StandalonePathError::ConfigRoot)
}

fn default_output_in(documents: Option<PathBuf>) -> Result<PathBuf, StandalonePathError> {
    documents
        .filter(|path| path.is_absolute())
        .map(|path| path.join("NSCB_output"))
        .ok_or(StandalonePathError::Documents)
}

#[cfg(test)]
mod tests {
    use super::{
        StandalonePathError, config_file_in, default_output_directory, default_output_in,
        simulate_documents_unavailable, windows_config_file_path, windows_key_file_path,
    };
    use std::path::PathBuf;

    #[test]
    fn simulated_platform_base_directories_append_nscb_paths() {
        let root = tempfile::tempdir().unwrap();
        let cases = [
            root.path().join("Library").join("Application Support"),
            root.path().join(".config"),
            root.path().join("AppData").join("Roaming"),
        ];
        for base in cases {
            assert_eq!(
                config_file_in(Some(base.clone())).unwrap(),
                base.join("NSCB").join("config.toml")
            );
            assert_eq!(
                default_output_in(Some(base.clone())).unwrap(),
                base.join("NSCB_output")
            );
        }
    }

    #[test]
    fn windows_roaming_config_path_prefers_appdata_and_falls_back_only_when_unset() {
        let root = tempfile::tempdir().unwrap();
        let appdata = root.path().join("profile").join("AppData").join("Roaming");
        let native = root.path().join("native-roaming");
        let fallback_called = std::cell::Cell::new(false);

        assert_eq!(
            windows_config_file_path(Some(appdata.clone()), || {
                fallback_called.set(true);
                Some(native.clone())
            })
            .unwrap(),
            appdata.join("NSCB").join("config.toml")
        );
        assert!(!fallback_called.get());

        assert_eq!(
            windows_config_file_path(None, || Some(native.clone())).unwrap(),
            native.join("NSCB").join("config.toml")
        );

        assert_eq!(
            windows_config_file_path(Some(PathBuf::from("relative")), || {
                fallback_called.set(true);
                Some(native)
            })
            .unwrap_err(),
            StandalonePathError::ConfigRoot
        );
        assert!(!fallback_called.get());
    }

    #[test]
    fn windows_key_path_prefers_userprofile_and_falls_back_only_when_unset() {
        let root = tempfile::tempdir().unwrap();
        let profile = root.path().join("profile");
        let native = root.path().join("native-profile");
        let fallback_called = std::cell::Cell::new(false);

        assert_eq!(
            windows_key_file_path(Some(profile.clone()), || {
                fallback_called.set(true);
                Some(native.clone())
            })
            .unwrap(),
            profile.join(".switch").join("prod.keys")
        );
        assert!(!fallback_called.get());

        assert_eq!(
            windows_key_file_path(None, || Some(native.clone())).unwrap(),
            native.join(".switch").join("prod.keys")
        );

        assert_eq!(
            windows_key_file_path(Some(PathBuf::from("relative")), || {
                fallback_called.set(true);
                Some(native)
            })
            .unwrap_err(),
            StandalonePathError::Home
        );
        assert!(!fallback_called.get());
    }

    #[test]
    fn unavailable_or_relative_native_bases_fail_without_fallback() {
        assert_eq!(
            config_file_in(None).unwrap_err(),
            StandalonePathError::ConfigRoot
        );
        assert_eq!(
            config_file_in(Some(PathBuf::from("relative"))).unwrap_err(),
            StandalonePathError::ConfigRoot
        );
        assert_eq!(
            default_output_in(None).unwrap_err(),
            StandalonePathError::Documents
        );
        assert_eq!(
            default_output_in(Some(PathBuf::from("relative"))).unwrap_err(),
            StandalonePathError::Documents
        );
    }

    #[test]
    fn injected_unavailable_documents_does_not_consult_or_create_host_paths() {
        let temporary_root = tempfile::tempdir().unwrap();
        let synthetic_documents = temporary_root.path().join("Documents");
        simulate_documents_unavailable(true);

        let result = default_output_directory();

        simulate_documents_unavailable(false);
        assert_eq!(result.unwrap_err(), StandalonePathError::Documents);
        assert!(!synthetic_documents.exists());
    }
}
