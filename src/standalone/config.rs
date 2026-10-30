//! Versioned TOML configuration owned by the standalone executable.

use super::paths;
use fs2::FileExt;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::Builder;
use toml_edit::{DocumentMut, Item, Value};

pub(crate) const CURRENT_SCHEMA_VERSION: i64 = 1;
const MAX_CONFIG_BYTES: u64 = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StandaloneConfigError {
    DirectoryUnavailable,
    ReadFailed,
    WriteFailed,
    LockFailed,
    LimitExceeded,
    ParseFailed,
    TypeInvalid,
    PathInvalid,
    PathUnrepresentable,
    BackupFailed,
    VersionUnsupported,
}

impl StandaloneConfigError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::DirectoryUnavailable => "config_directory_unavailable",
            Self::ReadFailed => "config_read_failed",
            Self::WriteFailed => "config_write_failed",
            Self::LockFailed => "config_lock_failed",
            Self::LimitExceeded => "config_limit_exceeded",
            Self::ParseFailed => "config_parse_failed",
            Self::TypeInvalid => "config_type_invalid",
            Self::PathInvalid => "config_path_invalid",
            Self::PathUnrepresentable => "config_path_invalid",
            Self::BackupFailed => "config_backup_failed",
            Self::VersionUnsupported => "config_version_unsupported",
        }
    }
}

impl From<paths::StandalonePathError> for StandaloneConfigError {
    fn from(value: paths::StandalonePathError) -> Self {
        match value {
            paths::StandalonePathError::ConfigRoot => Self::DirectoryUnavailable,
            paths::StandalonePathError::DataRoot => Self::DirectoryUnavailable,
            paths::StandalonePathError::Home | paths::StandalonePathError::Documents => {
                Self::PathInvalid
            }
        }
    }
}

/// A loaded configuration document. Unknown TOML entries remain in `document`
/// so later explicit saves can preserve values introduced by compatible NSCB
/// versions or maintained manually.
#[derive(Clone, Debug)]
pub(crate) struct StandaloneConfig {
    path: PathBuf,
    source_schema_version: i64,
    document: DocumentMut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConfigField {
    KeysPath,
    OutputDir,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutputPathError {
    OutputDirectoryUnavailable,
    OutputDestinationInvalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CopyDestinationSelection {
    ConfiguredOutputDirectory,
    NativeDocumentsOutput,
}

impl OutputPathError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::OutputDirectoryUnavailable => "output_directory_unavailable",
            Self::OutputDestinationInvalid => "output_destination_invalid",
        }
    }
}

impl ConfigField {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "keys_path" => Some(Self::KeysPath),
            "output_dir" => Some(Self::OutputDir),
            _ => None,
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::KeysPath => "keys_path",
            Self::OutputDir => "output_dir",
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct ConfigSnapshot {
    pub(crate) path: String,
    pub(crate) schema_version: i64,
    pub(crate) values: Vec<ConfigValueView>,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct ConfigValueView {
    pub(crate) name: String,
    pub(crate) value: String,
    pub(crate) source: &'static str,
    pub(crate) sensitive: bool,
}

impl StandaloneConfig {
    pub(crate) fn load_or_initialize() -> Result<Self, StandaloneConfigError> {
        Self::with_locked_config(|config| Ok(config.clone()))
    }

    fn with_locked_config<T>(
        operation: impl FnOnce(&mut Self) -> Result<T, StandaloneConfigError>,
    ) -> Result<T, StandaloneConfigError> {
        let path = Self::representable_config_path()?;
        Self::with_locked_config_at(path, operation)
    }

    /// Resolves the configuration path before a command can create, lock, or
    /// replace configuration state.
    ///
    /// Configuration commands and machine results expose this path as UTF-8.
    /// Rejecting an unrepresentable path here prevents first use from creating
    /// files that the command would fail to report afterward.
    fn representable_config_path() -> Result<PathBuf, StandaloneConfigError> {
        let path = paths::config_file_path()?;
        if path.to_str().is_none() {
            return Err(StandaloneConfigError::PathUnrepresentable);
        }
        Ok(path)
    }

    fn with_locked_config_at<T>(
        path: PathBuf,
        operation: impl FnOnce(&mut Self) -> Result<T, StandaloneConfigError>,
    ) -> Result<T, StandaloneConfigError> {
        let parent = path
            .parent()
            .ok_or(StandaloneConfigError::DirectoryUnavailable)?;
        create_private_directory(parent)?;
        let lock_path = path.with_file_name("config.lock");
        let lock = open_lock_file(&lock_path)?;
        lock.lock_exclusive()
            .map_err(|_| StandaloneConfigError::LockFailed)?;

        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(StandaloneConfigError::PathInvalid);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                atomic_replace(&path, initial_contents()?.as_bytes())?;
            }
            Err(_) => return Err(StandaloneConfigError::ReadFailed),
        }
        let metadata = fs::metadata(&path).map_err(|_| StandaloneConfigError::ReadFailed)?;
        if metadata.len() > MAX_CONFIG_BYTES {
            return Err(StandaloneConfigError::LimitExceeded);
        }
        let source =
            read_limited_config(File::open(&path).map_err(|_| StandaloneConfigError::ReadFailed)?)?;
        let document = source
            .parse::<DocumentMut>()
            .map_err(|_| StandaloneConfigError::ParseFailed)?;
        let source_schema_version = read_schema_version(&document)?;
        validate_known_values(&document)?;

        let mut config = Self {
            path,
            source_schema_version,
            document,
        };
        operation(&mut config)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    #[allow(dead_code)]
    pub(crate) fn source_schema_version(&self) -> i64 {
        self.source_schema_version
    }

    pub(crate) fn effective_key_file(&self) -> Result<PathBuf, StandaloneConfigError> {
        match self.document.get("keys_path").and_then(Item::as_str) {
            Some(path) => Ok(PathBuf::from(path)),
            None => paths::conventional_key_file_path().map_err(Into::into),
        }
    }

    /// Resolves an implicit Copy destination and records which durable policy
    /// chose it. Retry uses this provenance to re-run current configuration
    /// after configuration changes.
    pub(crate) fn copy_destination_with_selection(
        &self,
        source: &Path,
    ) -> Result<(PathBuf, CopyDestinationSelection), OutputPathError> {
        let configured = self
            .document
            .get("output_dir")
            .and_then(Item::as_str)
            .map(PathBuf::from);
        let (directory, selection) = match configured {
            Some(directory) => (
                directory,
                CopyDestinationSelection::ConfiguredOutputDirectory,
            ),
            None => {
                let documents =
                    dirs::document_dir().ok_or(OutputPathError::OutputDirectoryUnavailable)?;
                if !documents.is_absolute() || !documents.is_dir() {
                    return Err(OutputPathError::OutputDirectoryUnavailable);
                }
                (
                    documents.join("NSCB_output"),
                    CopyDestinationSelection::NativeDocumentsOutput,
                )
            }
        };
        match fs::metadata(&directory) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err(OutputPathError::OutputDirectoryUnavailable),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(OutputPathError::OutputDirectoryUnavailable),
        }
        let file_name = source
            .file_name()
            .ok_or(OutputPathError::OutputDestinationInvalid)?;
        Ok((directory.join(file_name), selection))
    }

    pub(crate) fn snapshot(&self) -> Result<ConfigSnapshot, StandaloneConfigError> {
        let path = self
            .path
            .to_str()
            .ok_or(StandaloneConfigError::PathUnrepresentable)?
            .to_owned();
        let mut values = vec![
            standard_config_value(&self.document, "keys_path", || {
                Ok(paths::conventional_key_file_path()?)
            })?,
            standard_config_value(&self.document, "output_dir", || {
                Ok(paths::default_output_directory()?)
            })?,
        ];
        let mut additional = Vec::new();
        flatten_unknown_values(self.document.as_table(), &mut Vec::new(), &mut additional);
        additional.sort_by(|left, right| left.name.cmp(&right.name));
        values.extend(additional);
        Ok(ConfigSnapshot {
            path,
            schema_version: self.source_schema_version,
            values,
        })
    }

    pub(crate) fn set(
        field: ConfigField,
        value_text: &str,
    ) -> Result<PathBuf, StandaloneConfigError> {
        let path = Path::new(value_text);
        if value_text.is_empty() || !path.is_absolute() {
            return Err(StandaloneConfigError::PathInvalid);
        }
        let path = Self::representable_config_path()?;
        Self::with_locked_config_at(path, |config| {
            config.document[field.name()] = toml_edit::value(value_text);
            config.document["schema_version"] = toml_edit::value(CURRENT_SCHEMA_VERSION);
            let serialized = config.document.to_string();
            if serialized.len() as u64 > MAX_CONFIG_BYTES {
                return Err(StandaloneConfigError::LimitExceeded);
            }
            config.backup_before_migration()?;
            atomic_replace(&config.path, serialized.as_bytes())?;
            config.source_schema_version = CURRENT_SCHEMA_VERSION;
            Ok(config.path.clone())
        })
    }

    pub(crate) fn reset() -> Result<PathBuf, StandaloneConfigError> {
        let path = Self::representable_config_path()?;
        Self::with_locked_config_at(path, |config| {
            config.backup_before_migration()?;
            let contents = initial_contents()?;
            atomic_replace(&config.path, contents.as_bytes())?;
            config.document = contents
                .parse::<DocumentMut>()
                .map_err(|_| StandaloneConfigError::ParseFailed)?;
            config.source_schema_version = CURRENT_SCHEMA_VERSION;
            Ok(config.path.clone())
        })
    }

    fn backup_before_migration(&self) -> Result<(), StandaloneConfigError> {
        if self.source_schema_version >= CURRENT_SCHEMA_VERSION {
            return Ok(());
        }
        let backup = self
            .path
            .with_file_name(format!("config.toml.v{}.bak", self.source_schema_version));
        let original = read_limited_config(
            File::open(&self.path).map_err(|_| StandaloneConfigError::ReadFailed)?,
        )?;
        match fs::symlink_metadata(&backup) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(StandaloneConfigError::BackupFailed);
            }
            Ok(_) => {
                let existing = read_backup_contents(
                    File::open(&backup).map_err(|_| StandaloneConfigError::BackupFailed)?,
                )?;
                return if existing == original {
                    Ok(())
                } else {
                    Err(StandaloneConfigError::BackupFailed)
                };
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(StandaloneConfigError::BackupFailed),
        }
        atomic_replace(&backup, original.as_bytes())
            .map_err(|_| StandaloneConfigError::BackupFailed)
    }
}

fn standard_config_value(
    document: &DocumentMut,
    name: &str,
    resolve_default: impl FnOnce() -> Result<PathBuf, StandaloneConfigError>,
) -> Result<ConfigValueView, StandaloneConfigError> {
    let (value, source) = match document.get(name).and_then(Item::as_str) {
        Some(value) => (value.to_owned(), "file"),
        None => (
            representable_path_text(&resolve_default()?)?.to_owned(),
            "default",
        ),
    };
    Ok(ConfigValueView {
        name: name.to_owned(),
        value,
        source,
        sensitive: is_sensitive_path(&[name]),
    })
}

/// Converts a native path to output text without replacing non-UTF-8 bytes.
///
/// Configuration display output and generated comments use UTF-8 text. A
/// native default containing other bytes is reported as
/// [`StandaloneConfigError::PathUnrepresentable`] so callers never receive a
/// lossy path that differs from the one used by the filesystem.
fn representable_path_text(path: &Path) -> Result<&str, StandaloneConfigError> {
    path.to_str()
        .ok_or(StandaloneConfigError::PathUnrepresentable)
}

fn flatten_unknown_values(
    table: &toml_edit::Table,
    prefix: &mut Vec<String>,
    output: &mut Vec<ConfigValueView>,
) {
    for (key, item) in table {
        if prefix.is_empty() && matches!(key, "schema_version" | "keys_path" | "output_dir") {
            continue;
        }
        prefix.push(key.to_owned());
        match item {
            Item::Table(table) => flatten_unknown_values(table, prefix, output),
            Item::ArrayOfTables(tables) => {
                for (index, table) in tables.iter().enumerate() {
                    prefix.push(index.to_string());
                    flatten_unknown_values(table, prefix, output);
                    prefix.pop();
                }
            }
            Item::Value(value) => flatten_value(value, prefix, output),
            _ => push_config_value(prefix, item.to_string(), output),
        }
        prefix.pop();
    }
}

fn flatten_value(value: &Value, prefix: &mut Vec<String>, output: &mut Vec<ConfigValueView>) {
    match value {
        Value::InlineTable(table) => {
            for (key, nested) in table.iter() {
                prefix.push(key.to_owned());
                flatten_value(nested, prefix, output);
                prefix.pop();
            }
        }
        Value::Array(array)
            if array
                .iter()
                .any(|nested| matches!(nested, Value::Array(_) | Value::InlineTable(_))) =>
        {
            for (index, nested) in array.iter().enumerate() {
                prefix.push(index.to_string());
                flatten_value(nested, prefix, output);
                prefix.pop();
            }
        }
        _ => {
            let raw = value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string());
            push_config_value(prefix, raw, output);
        }
    }
}

fn push_config_value(prefix: &[String], raw: String, output: &mut Vec<ConfigValueView>) {
    let sensitive = is_sensitive_path(prefix);
    output.push(ConfigValueView {
        name: prefix.join("."),
        value: if sensitive {
            "[REDACTED]".to_owned()
        } else {
            raw
        },
        source: "file",
        sensitive,
    });
}

/// Returns whether a configuration path contains a credential-like name.
///
/// Classification affects display only. Unknown TOML fields remain accepted
/// and preserved. When any segment matches, the corresponding value is redacted
/// in human and machine output; the dotted field path remains visible. Matching
/// these fragments also covers conventional compound names such as
/// `aws_access_key`, while leaving path settings such as `keys_path` visible.
fn is_sensitive_path(segments: &[impl AsRef<str>]) -> bool {
    const SENSITIVE_FRAGMENTS: &[&str] = &[
        "access_key",
        "api_key",
        "credential",
        "password",
        "private_key",
        "secret",
        "token",
    ];

    segments.iter().any(|segment| {
        let normalized = segment.as_ref().to_ascii_lowercase();
        SENSITIVE_FRAGMENTS
            .iter()
            .any(|fragment| normalized.contains(fragment))
    })
}

fn read_schema_version(document: &DocumentMut) -> Result<i64, StandaloneConfigError> {
    let Some(item) = document.get("schema_version") else {
        // Files created before versioning are compatible with schema v0.
        return Ok(0);
    };
    let version = item
        .as_integer()
        .ok_or(StandaloneConfigError::TypeInvalid)?;
    if version < 0 {
        return Err(StandaloneConfigError::TypeInvalid);
    }
    if version > CURRENT_SCHEMA_VERSION {
        return Err(StandaloneConfigError::VersionUnsupported);
    }
    Ok(version)
}

fn validate_known_values(document: &DocumentMut) -> Result<(), StandaloneConfigError> {
    for field in ["keys_path", "output_dir"] {
        let Some(item) = document.get(field) else {
            continue;
        };
        let value = item.as_str().ok_or(StandaloneConfigError::TypeInvalid)?;
        let path = Path::new(value);
        if value.is_empty() || !path.is_absolute() {
            return Err(StandaloneConfigError::PathInvalid);
        }
    }
    Ok(())
}

fn read_limited_config(reader: impl Read) -> Result<String, StandaloneConfigError> {
    let mut bytes = Vec::with_capacity((MAX_CONFIG_BYTES + 1) as usize);
    reader
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| StandaloneConfigError::ReadFailed)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(StandaloneConfigError::LimitExceeded);
    }
    String::from_utf8(bytes).map_err(|_| StandaloneConfigError::ReadFailed)
}

/// Reads a migration backup under the config size limit and maps invalid backup data to one error.
fn read_backup_contents(reader: impl Read) -> Result<String, StandaloneConfigError> {
    read_limited_config(reader).map_err(|_| StandaloneConfigError::BackupFailed)
}

fn initial_contents() -> Result<String, StandaloneConfigError> {
    let conventional_keys = paths::conventional_key_file_path().ok();
    let default_output = paths::default_output_directory().ok();
    let keys_comment = match conventional_keys {
        Some(path) => format!("# keys_path = {}", toml_string(&path)?),
        None => "# keys_path = \"<home unavailable>\"".to_owned(),
    };
    let output_comment = match default_output {
        Some(path) => format!("# output_dir = {}", toml_string(&path)?),
        None => "# output_dir = \"<Documents unavailable>\"".to_owned(),
    };
    Ok(format!(
        "# NSCB standalone configuration\n\
         # This file is versioned. NSCB preserves unknown values during edits.\n\
         schema_version = {CURRENT_SCHEMA_VERSION}\n\n\
         # Absolute path to a complete key file used by inspect and verify.\n\
         # When omitted, NSCB uses the conventional ~/.switch/prod.keys file.\n\
         {keys_comment}\n\n\
         # Absolute directory used when copy omits its destination.\n\
         # When omitted, NSCB uses Documents/NSCB_output.\n\
         {output_comment}\n"
    ))
}

/// Renders a native path as a quoted TOML string.
///
/// Returns [`StandaloneConfigError::PathUnrepresentable`] when the path's
/// bytes cannot be represented as UTF-8, because replacing those bytes would
/// make the generated documentation identify a different path.
fn toml_string(path: &Path) -> Result<String, StandaloneConfigError> {
    let mut escaped = String::from("\"");
    for character in representable_path_text(path)?.chars() {
        match character {
            '\u{0008}' => escaped.push_str("\\b"),
            '\t' => escaped.push_str("\\t"),
            '\n' => escaped.push_str("\\n"),
            '\u{000C}' => escaped.push_str("\\f"),
            '\r' => escaped.push_str("\\r"),
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            control if control.is_control() => {
                let codepoint = u32::from(control);
                if codepoint <= 0xFFFF {
                    write!(escaped, "\\u{codepoint:04X}").expect("writing to a String cannot fail");
                } else {
                    write!(escaped, "\\U{codepoint:08X}").expect("writing to a String cannot fail");
                }
            }
            character => escaped.push(character),
        }
    }
    escaped.push('"');
    Ok(escaped)
}

fn create_private_directory(path: &Path) -> Result<(), StandaloneConfigError> {
    create_private_directory_io(path).map_err(|_| StandaloneConfigError::WriteFailed)?;
    if !path.is_dir() {
        return Err(StandaloneConfigError::PathInvalid);
    }
    Ok(())
}

pub(super) fn create_private_directory_io(path: &Path) -> io::Result<()> {
    // Directory modes belong to newly created private locations. Changing an
    // existing caller-owned directory would alter permissions the user chose.
    if path.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn open_lock_file(path: &Path) -> Result<File, StandaloneConfigError> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|_| StandaloneConfigError::LockFailed)
}

fn atomic_replace(path: &Path, contents: &[u8]) -> Result<(), StandaloneConfigError> {
    atomic_replace_io(path, contents).map_err(|_| StandaloneConfigError::WriteFailed)
}

pub(super) fn atomic_replace_io(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let mut temporary = Builder::new().prefix(".nscb-").tempfile_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    temporary
        .write_all(contents)
        .and_then(|()| temporary.as_file().sync_all())?;

    #[cfg(unix)]
    let backup = create_rollback_backup(path, parent)?;
    #[cfg(windows)]
    let backup: Option<tempfile::TempPath> = None;

    replace_file(temporary.path(), path)?;
    if let Err(sync_error) = sync_parent(parent) {
        let rollback_result = match backup {
            Some(backup) => match replace_file(backup.as_ref(), path) {
                Ok(()) => Ok(()),
                Err(rollback_error) => {
                    // The backup was synced before replacement. Keep its directory entry
                    // when restoration fails so the original bytes remain recoverable.
                    let recovery_path = backup.to_path_buf();
                    let recovery_path = match backup.keep() {
                        Ok(path) => path,
                        Err(retain_error) => {
                            std::mem::forget(retain_error);
                            return Err(io::Error::other(format!(
                                "parent sync failed; rollback failed; recovery copy remains at {}",
                                recovery_path.display()
                            )));
                        }
                    };
                    return Err(io::Error::other(format!(
                        "parent sync failed ({sync_error}); rollback failed ({rollback_error}); recovery copy retained at {}",
                        recovery_path.display()
                    )));
                }
            },
            None => fs::remove_file(path),
        };
        rollback_result?;
        sync_parent(parent)?;
        return Err(sync_error);
    }
    Ok(())
}

#[cfg(unix)]
fn create_rollback_backup(path: &Path, parent: &Path) -> io::Result<Option<tempfile::TempPath>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {
            let placeholder = Builder::new()
                .prefix(".nscb-rollback-")
                .tempfile_in(parent)?;
            let backup = placeholder.into_temp_path();
            fs::remove_file(&backup)?;
            fs::hard_link(path, &backup)?;
            File::open(&backup)?.sync_all()?;
            sync_parent(parent)?;
            Ok(Some(backup))
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination is not a regular file",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(all(test, unix))]
std::thread_local! {
    static FAIL_NEXT_PARENT_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_ROLLBACK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static DESTINATION_REPLACED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(unix)]
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(test)]
    if from
        .file_name()
        .is_some_and(|name| name.to_string_lossy().starts_with(".nscb-rollback-"))
        && FAIL_NEXT_ROLLBACK.with(|fail| fail.replace(false))
    {
        return Err(io::Error::other("injected rollback failure"));
    }
    let result = fs::rename(from, to);
    #[cfg(test)]
    if result.is_ok() {
        DESTINATION_REPLACED.with(|replaced| replaced.set(true));
    }
    result
}

#[cfg(windows)]
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let from = from
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let to = to
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let replaced = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if replaced == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> io::Result<()> {
    #[cfg(test)]
    if DESTINATION_REPLACED.with(std::cell::Cell::get)
        && FAIL_NEXT_PARENT_SYNC.with(|fail| fail.replace(false))
    {
        return Err(io::Error::other("injected parent directory sync failure"));
    }
    File::open(parent)?.sync_all()
}

#[cfg(windows)]
fn sync_parent(_parent: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{StandaloneConfig, StandaloneConfigError, paths};
    use std::path::PathBuf;
    use toml_edit::DocumentMut;

    #[test]
    fn bounded_read_rejects_data_beyond_config_limit() {
        use super::{MAX_CONFIG_BYTES, StandaloneConfigError};

        let bytes = vec![b'x'; MAX_CONFIG_BYTES as usize + 1];
        let error = super::read_limited_config(std::io::Cursor::new(bytes)).unwrap_err();

        assert_eq!(error, StandaloneConfigError::LimitExceeded);
    }

    #[test]
    fn migration_backup_read_stops_at_config_limit_plus_one_byte() {
        use super::{MAX_CONFIG_BYTES, StandaloneConfigError};
        use std::io::{self, Read};

        struct CountingReader {
            remaining: usize,
            bytes_read: usize,
        }

        impl Read for CountingReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let count = buffer.len().min(self.remaining);
                buffer[..count].fill(b'x');
                self.remaining -= count;
                self.bytes_read += count;
                Ok(count)
            }
        }

        let mut reader = CountingReader {
            remaining: MAX_CONFIG_BYTES as usize + 4096,
            bytes_read: 0,
        };
        let error = super::read_backup_contents(&mut reader).unwrap_err();

        assert_eq!(error, StandaloneConfigError::BackupFailed);
        assert_eq!(reader.bytes_read, MAX_CONFIG_BYTES as usize + 1);
    }

    #[cfg(unix)]
    use super::{
        DESTINATION_REPLACED, FAIL_NEXT_PARENT_SYNC, FAIL_NEXT_ROLLBACK, atomic_replace_io,
    };

    #[cfg(unix)]
    #[test]
    fn parent_sync_failure_preserves_existing_destination() {
        use std::fs;

        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("config.toml");
        fs::write(&destination, b"old configuration").unwrap();
        FAIL_NEXT_PARENT_SYNC.with(|fail| fail.set(true));
        DESTINATION_REPLACED.with(|replaced| replaced.set(false));

        let result = atomic_replace_io(&destination, b"new configuration");

        assert!(result.is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"old configuration");
    }

    #[cfg(unix)]
    #[test]
    fn rollback_failure_retains_recovery_copy_of_existing_destination() {
        use std::fs;

        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("config.toml");
        fs::write(&destination, b"old configuration").unwrap();
        FAIL_NEXT_PARENT_SYNC.with(|fail| fail.set(true));
        FAIL_NEXT_ROLLBACK.with(|fail| fail.set(true));
        DESTINATION_REPLACED.with(|replaced| replaced.set(false));

        let result = atomic_replace_io(&destination, b"new configuration");

        let error = result.unwrap_err();
        assert!(error.to_string().contains("recovery copy retained"));
        assert_eq!(fs::read(&destination).unwrap(), b"new configuration");
        let recovery_copies = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".nscb-rollback-"))
            })
            .collect::<Vec<_>>();
        assert_eq!(recovery_copies.len(), 1);
        assert_eq!(fs::read(&recovery_copies[0]).unwrap(), b"old configuration");
    }

    #[test]
    fn configured_output_dir_does_not_resolve_documents_default() {
        let document = "schema_version = 1\nkeys_path = \"/synthetic/keys\"\noutput_dir = \"/synthetic/output\"\n"
            .parse::<DocumentMut>()
            .unwrap();
        let config = StandaloneConfig {
            path: PathBuf::from("/synthetic/config.toml"),
            source_schema_version: 1,
            document,
        };
        paths::simulate_documents_unavailable(true);

        let snapshot = config.snapshot();

        paths::simulate_documents_unavailable(false);
        let values = snapshot.unwrap().values;
        assert!(values.iter().any(|value| {
            value.name == "output_dir"
                && value.value == "/synthetic/output"
                && value.source == "file"
        }));
    }

    #[cfg(unix)]
    fn non_utf8_path() -> PathBuf {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        PathBuf::from(OsString::from_vec(
            b"/synthetic/native-default-\xff".to_vec(),
        ))
    }

    #[cfg(unix)]
    #[test]
    fn config_output_rejects_non_utf8_native_default_path() {
        let document = "schema_version = 1\n".parse::<DocumentMut>().unwrap();

        let result = super::standard_config_value(&document, "output_dir", || Ok(non_utf8_path()));

        assert_eq!(
            result.unwrap_err(),
            StandaloneConfigError::PathUnrepresentable
        );
    }

    #[cfg(unix)]
    #[test]
    fn generated_config_comment_does_not_lossily_replace_non_utf8_path() {
        let rendered = super::toml_string(&non_utf8_path());

        assert_eq!(
            rendered.unwrap_err(),
            StandaloneConfigError::PathUnrepresentable
        );
    }
}
