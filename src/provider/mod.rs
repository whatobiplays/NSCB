//! Private managed-provider boundary used by the public Inspection facade.
//!
//! Manifest selection, target qualification, cache layout, key normalization,
//! executable copying, argument construction, process ownership, and output
//! parsing remain behind this module. Production callers cannot substitute any
//! of those values.
mod cache;
mod download;
mod keys;
mod manifest;
mod nstool;
mod process;

pub(crate) use nstool::{ContentType, Distribution, ProviderFacts};

use crate::file_identity::{
    FileIdentity, FileSnapshot, file_snapshot, handle_identity, path_identity,
};
use crate::inspection::{
    CancellationHandle, InspectionErrorCode, InspectionHost, InspectionPreflightStatus,
    InspectionRequest, ProvisioningPolicy,
};
use crate::provider::keys::HeaderKey;
use crate::provider::manifest::TargetArtifact;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderFailure {
    Configuration(InspectionErrorCode),
    Prerequisite(InspectionErrorCode),
    Provisioning(InspectionErrorCode),
    Conflict(InspectionErrorCode),
    Execution(InspectionErrorCode),
    Cancelled,
    Internal(InspectionErrorCode),
}

impl ProviderFailure {
    pub(crate) const fn code(self) -> InspectionErrorCode {
        match self {
            Self::Configuration(code)
            | Self::Prerequisite(code)
            | Self::Provisioning(code)
            | Self::Conflict(code)
            | Self::Execution(code)
            | Self::Internal(code) => code,
            Self::Cancelled => InspectionErrorCode::Cancelled,
        }
    }
}

impl From<ProviderFailure> for InspectionErrorCode {
    fn from(value: ProviderFailure) -> Self {
        value.code()
    }
}

#[derive(Debug)]
struct WatchedFile {
    path: PathBuf,
    file: File,
    snapshot: FileSnapshot,
    identity: FileIdentity,
}

#[derive(Debug)]
pub(crate) struct ProviderInput {
    input: WatchedFile,
}

impl ProviderInput {
    pub(crate) fn file(&mut self) -> &mut File {
        &mut self.input.file
    }

    pub(crate) fn unchanged(&self) -> bool {
        self.input.unchanged()
    }
}

#[derive(Debug)]
pub(crate) struct ProviderReport {
    pub(crate) facts: ProviderFacts,
    pub(crate) input: ProviderInput,
    pub(crate) header: crate::nca::Header,
}

impl WatchedFile {
    fn open(path: &Path, unavailable: InspectionErrorCode) -> Result<Self, ProviderFailure> {
        Self::open_with_hook(path, unavailable, || {})
    }

    fn open_with_hook(
        path: &Path,
        unavailable: InspectionErrorCode,
        after_open: impl FnOnce(),
    ) -> Result<Self, ProviderFailure> {
        if path.as_os_str().is_empty() {
            return Err(ProviderFailure::Configuration(unavailable));
        }
        let file = open_regular(path).map_err(|_| ProviderFailure::Prerequisite(unavailable))?;
        after_open();
        let canonical =
            std::fs::canonicalize(path).map_err(|_| ProviderFailure::Prerequisite(unavailable))?;
        let metadata = file
            .metadata()
            .map_err(|_| ProviderFailure::Prerequisite(unavailable))?;
        if !metadata.file_type().is_file() {
            return Err(ProviderFailure::Prerequisite(unavailable));
        }
        let Some(identity) = handle_identity(&file) else {
            return Err(ProviderFailure::Prerequisite(unavailable));
        };
        if path_identity(&canonical) != Some(identity) {
            return Err(ProviderFailure::Prerequisite(unavailable));
        }
        let snapshot = file_snapshot(&metadata, Some(identity));
        Ok(Self {
            path: canonical,
            file,
            snapshot,
            identity,
        })
    }

    fn unchanged(&self) -> bool {
        let Ok(metadata) = self.file.metadata() else {
            return false;
        };
        if handle_identity(&self.file) != Some(self.identity)
            || path_identity(&self.path) != Some(self.identity)
        {
            return false;
        }
        file_snapshot(&metadata, Some(self.identity)) == self.snapshot
    }
}

struct PreparedInputs {
    input: WatchedFile,
    key_file: WatchedFile,
    key: HeaderKey,
    header: crate::nca::Header,
}

struct PreparedProvider {
    inputs: PreparedInputs,
    target: &'static TargetArtifact,
    artifact: cache::CachedArtifact,
}

enum Preparation {
    Ready(Box<PreparedProvider>),
    ProvisioningRequired,
}

pub(crate) fn preflight(
    request: &InspectionRequest,
    host: &InspectionHost,
) -> Result<InspectionPreflightStatus, InspectionErrorCode> {
    let preparation = prepare(request, host, false).map_err(InspectionErrorCode::from)?;
    process::probe_hard_controls().map_err(classify_containment_failure)?;
    match preparation {
        Preparation::Ready(_) => Ok(InspectionPreflightStatus::Ready),
        Preparation::ProvisioningRequired => Ok(InspectionPreflightStatus::ProvisioningRequired),
    }
}

pub(crate) fn inspect(
    request: &InspectionRequest,
    host: &InspectionHost,
) -> Result<ProviderReport, InspectionErrorCode> {
    inspect_with_containment(
        request,
        host,
        process::probe_hard_controls,
        |target, inputs| {
            let prepared = match prepare_artifact(host, target, inputs, true)? {
                Preparation::Ready(prepared) => *prepared,
                Preparation::ProvisioningRequired => {
                    return Err(ProviderFailure::Provisioning(
                        InspectionErrorCode::ProvisioningFailed,
                    ));
                }
            };
            execute(prepared, host.cancellation())
        },
    )
}

fn inspect_with_containment(
    request: &InspectionRequest,
    _host: &InspectionHost,
    probe: impl FnOnce() -> Result<(), process::ProcessFailure>,
    run_provider: impl FnOnce(
        &'static TargetArtifact,
        PreparedInputs,
    ) -> Result<ProviderReport, ProviderFailure>,
) -> Result<ProviderReport, InspectionErrorCode> {
    let (target, inputs) = prepare_inputs_and_target(request).map_err(InspectionErrorCode::from)?;
    probe().map_err(classify_containment_failure)?;
    run_provider(target, inputs).map_err(InspectionErrorCode::from)
}

fn classify_containment_failure(failure: process::ProcessFailure) -> InspectionErrorCode {
    match failure {
        process::ProcessFailure::ContainmentUnsupported => {
            InspectionErrorCode::ProviderContainmentUnsupported
        }
        process::ProcessFailure::Cancelled => InspectionErrorCode::Cancelled,
        _ => InspectionErrorCode::InternalIo,
    }
}

fn prepare(
    request: &InspectionRequest,
    host: &InspectionHost,
    allow_provisioning: bool,
) -> Result<Preparation, ProviderFailure> {
    let (target, inputs) = prepare_inputs_and_target(request)?;
    prepare_artifact(host, target, inputs, allow_provisioning)
}

fn prepare_inputs_and_target(
    request: &InspectionRequest,
) -> Result<(&'static TargetArtifact, PreparedInputs), ProviderFailure> {
    if request.capability() != crate::InspectionCapability::Nca {
        return Err(ProviderFailure::Prerequisite(
            InspectionErrorCode::UnsupportedInspectionProfile,
        ));
    }
    let target = manifest::target_artifact().map_err(classify_setup_error)?;
    let inputs = prepare_inputs(request)?;
    Ok((target, inputs))
}

fn prepare_artifact(
    host: &InspectionHost,
    target: &'static TargetArtifact,
    inputs: PreparedInputs,
    allow_provisioning: bool,
) -> Result<Preparation, ProviderFailure> {
    match cache::lookup(host.cache_dir(), target).map_err(classify_setup_error)? {
        cache::CacheLookup::Ready(artifact) => Ok(Preparation::Ready(Box::new(PreparedProvider {
            inputs,
            target,
            artifact,
        }))),
        cache::CacheLookup::Missing(problem) => match host.provisioning() {
            ProvisioningPolicy::CacheOnly => Err(ProviderFailure::Prerequisite(problem.code())),
            ProvisioningPolicy::ManagedDownload if !allow_provisioning => {
                Ok(Preparation::ProvisioningRequired)
            }
            ProvisioningPolicy::ManagedDownload => {
                if host
                    .cancellation()
                    .is_some_and(CancellationHandle::is_cancelled)
                {
                    return Err(ProviderFailure::Cancelled);
                }
                let archive = download::fetch_archive(target, host.cancellation())
                    .map_err(classify_provisioning_error)?;
                if host
                    .cancellation()
                    .is_some_and(CancellationHandle::is_cancelled)
                {
                    return Err(ProviderFailure::Cancelled);
                }
                let artifact = cache::install_archive(host.cache_dir(), target, &archive)
                    .map_err(classify_provisioning_error)?;
                Ok(Preparation::Ready(Box::new(PreparedProvider {
                    inputs,
                    target,
                    artifact,
                })))
            }
        },
    }
}

fn prepare_inputs(request: &InspectionRequest) -> Result<PreparedInputs, ProviderFailure> {
    prepare_inputs_with(request, WatchedFile::open)
}

fn prepare_inputs_with(
    request: &InspectionRequest,
    mut open: impl FnMut(&Path, InspectionErrorCode) -> Result<WatchedFile, ProviderFailure>,
) -> Result<PreparedInputs, ProviderFailure> {
    let mut input = open(request.input(), InspectionErrorCode::InputUnavailable)?;
    if request.key_file().as_os_str().is_empty() {
        return Err(ProviderFailure::Configuration(
            InspectionErrorCode::InvalidKeyPath,
        ));
    }
    let mut key_file = open(request.key_file(), InspectionErrorCode::KeyFileUnavailable)?;
    let key = keys::read_header_key(&mut key_file.file, key_file.snapshot.len)
        .map_err(ProviderFailure::Prerequisite)?;
    let header = crate::nca::read_header(&mut input.file, input.snapshot.len, key.as_bytes())
        .map_err(classify_header_error)?;
    crate::inspection::validate_nca_profile(&header).map_err(ProviderFailure::Prerequisite)?;
    Ok(PreparedInputs {
        input,
        key_file,
        key,
        header,
    })
}

fn execute(
    prepared: PreparedProvider,
    cancellation: Option<&CancellationHandle>,
) -> Result<ProviderReport, ProviderFailure> {
    let work = tempfile::Builder::new()
        .prefix("nscb-nstool-runtime-")
        .tempdir()
        .map_err(|_| ProviderFailure::Internal(InspectionErrorCode::InternalIo))?;
    let executable = work.path().join(prepared.target.executable());
    cache::snapshot_executable(&prepared.artifact, prepared.target, &executable)
        .map_err(classify_setup_error)?;

    let result = execute_in(
        prepared.inputs,
        &executable,
        work.path(),
        process::ProcessLimits::default(),
        cancellation,
    );
    work.close()
        .map_err(|_| ProviderFailure::Internal(InspectionErrorCode::InternalIo))?;
    result
}

/// Runs one already-qualified executable over prepared inputs. Kept separate
/// so tests can exercise the process, parser, and postcondition boundary with
/// a disposable executable while production only reaches it after cache
/// verification and immutable snapshot copying.
fn execute_in(
    inputs: PreparedInputs,
    executable: &Path,
    working_directory: &Path,
    limits: process::ProcessLimits,
    cancellation: Option<&CancellationHandle>,
) -> Result<ProviderReport, ProviderFailure> {
    let keyset = working_directory.join("nstool.keys");
    keys::write_sanitized(&keyset, &inputs.key).map_err(classify_setup_error)?;

    let arguments = vec![
        OsString::from("-k"),
        keyset.into_os_string(),
        OsString::from("-t"),
        OsString::from("nca"),
        OsString::from("-v"),
        OsString::from("--fstree"),
        inputs.input.path.as_os_str().to_owned(),
    ];
    let result = process::run(
        executable,
        &arguments,
        working_directory,
        limits,
        cancellation,
    );
    let input_unchanged = inputs.input.unchanged();
    let key_unchanged = inputs.key_file.unchanged();
    if !input_unchanged {
        return Err(ProviderFailure::Conflict(
            InspectionErrorCode::InputChangedDuringInspection,
        ));
    }
    if !key_unchanged {
        return Err(ProviderFailure::Conflict(
            InspectionErrorCode::KeyFileChangedDuringInspection,
        ));
    }
    let output = result.map_err(|failure| match failure {
        process::ProcessFailure::Launch => {
            ProviderFailure::Execution(InspectionErrorCode::ProviderLaunchFailed)
        }
        process::ProcessFailure::TimedOut => {
            ProviderFailure::Execution(InspectionErrorCode::ProviderTimedOut)
        }
        process::ProcessFailure::Cancelled => ProviderFailure::Cancelled,
        process::ProcessFailure::ContainmentUnsupported => {
            ProviderFailure::Prerequisite(InspectionErrorCode::ProviderContainmentUnsupported)
        }
        process::ProcessFailure::OutputExceeded => {
            ProviderFailure::Execution(InspectionErrorCode::ProviderOutputExceeded)
        }
        process::ProcessFailure::Io => ProviderFailure::Internal(InspectionErrorCode::InternalIo),
        process::ProcessFailure::TerminationFailed => {
            ProviderFailure::Internal(InspectionErrorCode::InternalIo)
        }
    })?;
    if !output.succeeded() {
        return Err(ProviderFailure::Execution(match output.status.code() {
            Some(_) => InspectionErrorCode::ProviderExitedUnsuccessfully,
            None => InspectionErrorCode::ProviderCrashed,
        }));
    }
    let facts = nstool::parse(&output.stdout, &output.stderr).map_err(classify_parse_error)?;
    Ok(ProviderReport {
        facts,
        input: ProviderInput {
            input: inputs.input,
        },
        header: inputs.header,
    })
}

fn classify_header_error(error: crate::nca::HeaderError) -> ProviderFailure {
    match error.code() {
        InspectionErrorCode::InternalIo => ProviderFailure::Internal(error.code()),
        code => ProviderFailure::Prerequisite(code),
    }
}

fn open_regular(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    let file = options.open(path)?;
    if file.metadata()?.file_type().is_file() {
        Ok(file)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ))
    }
}

fn classify_setup_error(code: InspectionErrorCode) -> ProviderFailure {
    match code {
        InspectionErrorCode::InvalidCacheDirectory | InspectionErrorCode::InvalidKeyPath => {
            ProviderFailure::Configuration(code)
        }
        InspectionErrorCode::ProviderCacheMissing
        | InspectionErrorCode::ProviderArtifactMismatch
        | InspectionErrorCode::ProviderArtifactIncomplete
        | InspectionErrorCode::ProviderUnsupportedTarget
        | InspectionErrorCode::ProviderUnqualifiedTarget => ProviderFailure::Prerequisite(code),
        InspectionErrorCode::ProviderCacheBusy => ProviderFailure::Conflict(code),
        InspectionErrorCode::Cancelled => ProviderFailure::Cancelled,
        InspectionErrorCode::ProviderManifestInvalid
        | InspectionErrorCode::CacheLockFailed
        | InspectionErrorCode::CacheCleanupFailed
        | InspectionErrorCode::AllocationFailed
        | InspectionErrorCode::InternalIo => ProviderFailure::Internal(code),
        _ if code.exit_class() == crate::inspection::InspectionExitClass::Provider => {
            ProviderFailure::Execution(code)
        }
        _ => ProviderFailure::Prerequisite(code),
    }
}

fn classify_provisioning_error(code: InspectionErrorCode) -> ProviderFailure {
    match code {
        InspectionErrorCode::Cancelled => ProviderFailure::Cancelled,
        InspectionErrorCode::ProviderCacheBusy => ProviderFailure::Conflict(code),
        InspectionErrorCode::InvalidCacheDirectory => ProviderFailure::Configuration(code),
        InspectionErrorCode::ProviderManifestInvalid
        | InspectionErrorCode::CacheLockFailed
        | InspectionErrorCode::CacheCleanupFailed
        | InspectionErrorCode::AllocationFailed
        | InspectionErrorCode::InternalIo => ProviderFailure::Internal(code),
        _ => ProviderFailure::Provisioning(code),
    }
}

fn classify_parse_error(code: InspectionErrorCode) -> ProviderFailure {
    match code {
        InspectionErrorCode::UnsupportedInspectionProfile
        | InspectionErrorCode::MissingHeaderKey => ProviderFailure::Prerequisite(code),
        InspectionErrorCode::Cancelled => ProviderFailure::Cancelled,
        _ => ProviderFailure::Execution(code),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PreparedInputs, ProviderFailure, WatchedFile, classify_parse_error, execute_in,
        inspect_with_containment, nstool, open_regular, prepare_inputs, prepare_inputs_with,
        process,
    };
    use crate::inspection::{
        CancellationHandle, InspectionErrorCode, InspectionHost, InspectionRequest,
        MemoryMonitoringPolicy, validate_provider_report,
    };
    use std::fs;
    use std::num::NonZeroU64;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    use super::preflight;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    use crate::inspection::ProvisioningPolicy;

    #[test]
    fn parser_profile_failures_remain_prerequisite_failures() {
        assert_eq!(
            classify_parse_error(InspectionErrorCode::UnsupportedInspectionProfile),
            ProviderFailure::Prerequisite(InspectionErrorCode::UnsupportedInspectionProfile)
        );
        assert_eq!(
            classify_parse_error(InspectionErrorCode::ProviderContentUnreadable),
            ProviderFailure::Execution(InspectionErrorCode::ProviderContentUnreadable)
        );
        for code in [
            InspectionErrorCode::MalformedInput,
            InspectionErrorCode::TruncatedInput,
            InspectionErrorCode::InputLimitExceeded,
            InspectionErrorCode::ProviderOutputMalformed,
        ] {
            assert_eq!(classify_parse_error(code), ProviderFailure::Execution(code));
        }
    }

    #[test]
    fn a_directory_is_not_opened_as_a_regular_file() {
        let error = open_regular(&std::env::temp_dir()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_not_followed_when_opening_a_watched_file() {
        use std::os::unix::fs::symlink;

        let base = tempfile::tempdir().unwrap();
        let target = base.path().join("regular-file");
        let link = base.path().join("link");
        fs::write(&target, b"content").unwrap();
        symlink(&target, &link).unwrap();

        assert!(open_regular(&link).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn input_and_key_setup_reject_path_replacement_after_open() {
        for replace_key in [false, true] {
            let base = tempfile::tempdir().unwrap();
            let input = base.path().join("input.nca");
            let key = base.path().join("prod.keys");
            fs::write(&input, crate::nca::synthetic_supported_nca()).unwrap();
            fs::write(&key, format!("header_key = {}\n", "42".repeat(32))).unwrap();
            let replaced_path = if replace_key { &key } else { &input };
            let backup = base.path().join("opened-file");
            let request = InspectionRequest::nca(&input, &key);

            let result = prepare_inputs_with(&request, |path, unavailable| {
                let hook = || {
                    if path == replaced_path {
                        fs::rename(path, &backup).unwrap();
                        fs::write(path, b"replacement").unwrap();
                    }
                };
                WatchedFile::open_with_hook(path, unavailable, hook)
            });

            let expected = if replace_key {
                InspectionErrorCode::KeyFileUnavailable
            } else {
                InspectionErrorCode::InputUnavailable
            };
            assert!(matches!(result, Err(ProviderFailure::Prerequisite(code)) if code == expected));
            assert!(backup.exists(), "the original opened file was retained");
        }
    }

    #[test]
    fn provider_failure_code_preserves_the_stable_classification() {
        assert_eq!(
            ProviderFailure::Prerequisite(InspectionErrorCode::ProviderCacheMissing).code(),
            InspectionErrorCode::ProviderCacheMissing
        );
    }

    #[test]
    fn memory_monitoring_policy_and_status_are_available_without_preflight() {
        let base = tempfile::tempdir().unwrap();
        let policy = MemoryMonitoringPolicy::RequirePhysicalFootprintThreshold {
            threshold_bytes: NonZeroU64::new(1024).unwrap(),
        };
        let cache_only_path = base.path().join("cache-only");
        let managed_path = base.path().join("managed");
        fs::create_dir(&cache_only_path).unwrap();
        fs::create_dir(&managed_path).unwrap();
        let cache_only =
            InspectionHost::cache_only(&cache_only_path).with_memory_monitoring_policy(policy);
        let managed =
            InspectionHost::managed_download(&managed_path).with_memory_monitoring_policy(policy);
        let threshold_bytes = NonZeroU64::new(1024).unwrap();

        for host in [&cache_only, &managed] {
            assert_eq!(host.memory_monitoring_policy(), policy);
            assert_eq!(
                host.memory_monitoring_status(),
                crate::inspection::MemoryMonitoringStatus::Unavailable { threshold_bytes }
            );
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn unavailable_physical_footprint_monitoring_is_advisory_and_inspection_proceeds() {
        let fixture = fake_fixture();
        let policy = MemoryMonitoringPolicy::RequirePhysicalFootprintThreshold {
            threshold_bytes: NonZeroU64::new(1024).unwrap(),
        };
        let threshold_bytes = NonZeroU64::new(1024).unwrap();
        let canonical_work = fixture.work.path().canonicalize().unwrap();
        let cache_only_path = canonical_work.join("cache-only");
        let managed_path = canonical_work.join("managed");
        fs::create_dir(&cache_only_path).unwrap();
        fs::create_dir(&managed_path).unwrap();
        let cache_only =
            InspectionHost::cache_only(&cache_only_path).with_memory_monitoring_policy(policy);
        let managed =
            InspectionHost::managed_download(&managed_path).with_memory_monitoring_policy(policy);
        let request = InspectionRequest::nca(&fixture.input, &fixture.key);

        for host in [&cache_only, &managed] {
            assert_eq!(host.memory_monitoring_policy(), policy);
            assert_eq!(
                host.memory_monitoring_status(),
                crate::inspection::MemoryMonitoringStatus::Unavailable { threshold_bytes }
            );
        }
        assert_eq!(
            preflight(&request, &cache_only).unwrap_err(),
            InspectionErrorCode::ProviderCacheMissing
        );
        assert_eq!(
            preflight(&request, &managed).unwrap(),
            crate::inspection::InspectionPreflightStatus::ProvisioningRequired
        );
        assert_eq!(fs::read_dir(&cache_only_path).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&managed_path).unwrap().count(), 0);

        let executable = fake_script(fixture.work.path(), &captured_body());
        let report = inspect_with_containment(
            &request,
            &cache_only,
            || Ok(()),
            |_target, inputs| {
                execute_in(
                    inputs,
                    &executable,
                    fixture.work.path(),
                    process::ProcessLimits::uncontained_test_limits(
                        Duration::from_secs(5),
                        1024,
                        1024,
                    ),
                    None,
                )
            },
        )
        .expect("unavailable optional telemetry must not block Inspection");
        let normalized = validate_provider_report(report).unwrap();
        let crate::inspection::InspectionResult::Nca(inspection) = normalized;
        assert_eq!(inspection.format_version, 3);
        assert_eq!(inspection.program_id.to_hex(), "0102030405060708");
        assert_eq!(
            cache_only.memory_monitoring_status(),
            crate::inspection::MemoryMonitoringStatus::Unavailable { threshold_bytes }
        );
        assert_eq!(fs::read_dir(&cache_only_path).unwrap().count(), 0);
    }

    #[cfg(unix)]
    struct FakeFixture {
        _base: tempfile::TempDir,
        work: tempfile::TempDir,
        inputs: PreparedInputs,
        input: PathBuf,
        key: PathBuf,
    }

    #[cfg(unix)]
    fn fake_fixture() -> FakeFixture {
        let base = tempfile::tempdir().unwrap();
        let input = base.path().join("input with spaces;touch PWNED.nca");
        fs::write(&input, crate::nca::synthetic_supported_nca()).unwrap();
        let key = base.path().join("prod.keys");
        fs::write(&key, format!("header_key = {}\n", "42".repeat(32))).unwrap();
        let inputs = prepare_inputs(&InspectionRequest::nca(&input, &key)).unwrap();
        FakeFixture {
            _base: base,
            work: tempfile::tempdir().unwrap(),
            inputs,
            input,
            key,
        }
    }

    #[test]
    fn plaintext_nca_is_rejected_by_target_independent_input_preparation() {
        let base = tempfile::tempdir().unwrap();
        let input = base.path().join("plaintext.nca");
        fs::write(&input, crate::nca::synthetic_plaintext_supported_nca()).unwrap();
        let key = base.path().join("prod.keys");
        fs::write(&key, format!("header_key = {}\n", "42".repeat(32))).unwrap();
        let request = InspectionRequest::nca(&input, &key);

        assert!(matches!(
            prepare_inputs(&request),
            Err(ProviderFailure::Prerequisite(
                InspectionErrorCode::UnsupportedFormat
            ))
        ));
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn plaintext_nca_is_unsupported_during_qualified_engine_preflight_and_inspection() {
        let base = tempfile::tempdir().unwrap();
        let input = base.path().join("plaintext.nca");
        fs::write(&input, crate::nca::synthetic_plaintext_supported_nca()).unwrap();
        let key = base.path().join("prod.keys");
        fs::write(&key, format!("header_key = {}\n", "42".repeat(32))).unwrap();
        let request = InspectionRequest::nca(&input, &key);
        let host = InspectionHost::cache_only(base.path().join("cache"));

        assert_eq!(
            crate::Engine::new()
                .preflight_inspection(&request, &host)
                .unwrap_err()
                .code(),
            InspectionErrorCode::UnsupportedFormat
        );
        assert_eq!(
            crate::Engine::new()
                .inspect(request, &host)
                .unwrap_err()
                .code(),
            InspectionErrorCode::UnsupportedFormat
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn preflight_does_not_report_provisioning_ready_without_child_containment() {
        if !matches!(
            process::probe_hard_controls(),
            Err(process::ProcessFailure::ContainmentUnsupported)
        ) {
            return;
        }

        let base = tempfile::tempdir().unwrap();
        let input = base.path().join("encrypted.nca");
        fs::write(&input, crate::nca::synthetic_supported_nca()).unwrap();
        let key = base.path().join("prod.keys");
        fs::write(&key, format!("header_key = {}\n", "42".repeat(32))).unwrap();
        let request = InspectionRequest::nca(&input, &key);
        let cache_root = base.path().canonicalize().unwrap().join("cache");
        let host = InspectionHost::managed_download(cache_root.clone());

        assert_eq!(
            preflight(&request, &host).unwrap_err(),
            InspectionErrorCode::ProviderContainmentUnsupported
        );
        assert!(!cache_root.exists());
    }

    #[cfg(unix)]
    fn fake_script(directory: &std::path::Path, body: &str) -> PathBuf {
        let path = directory.join("fake-nstool");
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    #[cfg(unix)]
    fn captured_body() -> String {
        assert!(!nstool::CAPTURED_OUTPUT.contains('\''));
        format!(
            "if [ \"$#\" -ne 7 ]; then exit 91; fi\n\
             [ \"$1\" = \"-k\" ] || exit 92\n\
             [ \"$3\" = \"-t\" ] || exit 93\n\
             [ \"$4\" = \"nca\" ] || exit 94\n\
             [ \"$5\" = \"-v\" ] || exit 95\n\
             [ \"$6\" = \"--fstree\" ] || exit 96\n\
             [ -z \"$PATH\" ] || exit 97\n\
             case \"$7\" in *'input with spaces;touch PWNED.nca') ;; *) exit 98 ;; esac\n\
             printf '%s' '{}'",
            nstool::CAPTURED_OUTPUT
        )
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn default_process_limits_run_the_helper_without_an_address_space_cap() {
        let fixture = fake_fixture();
        let executable = fake_script(fixture.work.path(), &captured_body());
        let report = execute_in(
            fixture.inputs,
            &executable,
            fixture.work.path(),
            process::ProcessLimits::default(),
            None,
        )
        .unwrap();
        assert_eq!(report.facts.format_version, 3);
        assert!(!fixture.work.path().join("PWNED.nca").exists());
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn unsupported_containment_stops_cache_only_and_managed_provisioning() {
        let base = tempfile::tempdir().unwrap();
        let input = base.path().join("input.nca");
        fs::write(&input, crate::nca::synthetic_supported_nca()).unwrap();
        let keys = base.path().join("prod.keys");
        fs::write(&keys, format!("header_key = {}\n", "42".repeat(32))).unwrap();

        for (name, host) in [
            (
                "cache-only",
                InspectionHost::cache_only(base.path().join("cache-only")),
            ),
            (
                "managed-download",
                InspectionHost::managed_download(base.path().join("managed-download")),
            ),
        ] {
            let cache_root = host.cache_dir().to_path_buf();
            let request = InspectionRequest::nca(&input, &keys);
            let mut network_attempts = 0;
            let mut cache_mutations = 0;
            let failure = inspect_with_containment(
                &request,
                &host,
                || Err(process::ProcessFailure::ContainmentUnsupported),
                |_, _| {
                    if host.provisioning() == ProvisioningPolicy::ManagedDownload {
                        network_attempts += 1;
                    }
                    cache_mutations += 1;
                    fs::create_dir_all(&cache_root).unwrap();
                    Err(ProviderFailure::Provisioning(
                        InspectionErrorCode::ProvisioningFailed,
                    ))
                },
            )
            .unwrap_err();

            assert_eq!(
                failure,
                InspectionErrorCode::ProviderContainmentUnsupported,
                "{name}"
            );
            assert_eq!(network_attempts, 0, "{name}");
            assert_eq!(cache_mutations, 0, "{name}");
            assert!(!cache_root.exists(), "{name}");
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn unqualified_provider_stops_before_child_download_or_cache_mutation() {
        use std::cell::Cell;

        let base = tempfile::tempdir().unwrap();
        let input = base.path().join("input.nca");
        fs::write(&input, crate::nca::synthetic_supported_nca()).unwrap();
        let key = base.path().join("prod.keys");
        fs::write(&key, format!("header_key = {}\n", "42".repeat(32))).unwrap();
        let cache_root = base.path().join("managed-cache");
        let host = InspectionHost::managed_download(&cache_root);
        let request = InspectionRequest::nca(&input, &key);
        let containment_probes = Cell::new(0);
        let child_launches = Cell::new(0);
        let downloads = Cell::new(0);
        let cache_mutations = Cell::new(0);

        assert!(matches!(
            inspect_with_containment(
                &request,
                &host,
                || {
                    containment_probes.set(containment_probes.get() + 1);
                    Ok(())
                },
                |_target, _inputs| {
                    child_launches.set(child_launches.get() + 1);
                    downloads.set(downloads.get() + 1);
                    cache_mutations.set(cache_mutations.get() + 1);
                    Err(ProviderFailure::Provisioning(
                        InspectionErrorCode::ProvisioningFailed,
                    ))
                },
            ),
            Err(InspectionErrorCode::ProviderUnqualifiedTarget)
        ));
        assert_eq!(containment_probes.get(), 0);
        assert_eq!(child_launches.get(), 0);
        assert_eq!(downloads.get(), 0);
        assert_eq!(cache_mutations.get(), 0);
        assert!(!cache_root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn fake_provider_success_is_independently_corroborated() {
        let fixture = fake_fixture();
        let executable = fake_script(fixture.work.path(), &captured_body());
        let report = execute_in(
            fixture.inputs,
            &executable,
            fixture.work.path(),
            process::ProcessLimits::uncontained_test_limits(Duration::from_secs(5), 1024, 1024),
            None,
        )
        .unwrap();
        let result = validate_provider_report(report).unwrap();
        let crate::inspection::InspectionResult::Nca(inspection) = result;
        assert_eq!(inspection.program_id.to_hex(), "0102030405060708");
        assert_eq!(inspection.partitions[0].entries[0].path, "hello.nca");
        assert!(!fixture.work.path().join("PWNED.nca").exists());
    }

    #[cfg(unix)]
    #[test]
    fn fake_provider_spoof_is_rejected_by_rust_postconditions() {
        let fixture = fake_fixture();
        let spoofed = captured_body().replace(
            "ProgID:          0x0102030405060708",
            "ProgID:          0x0102030405060709",
        );
        let executable = fake_script(fixture.work.path(), &spoofed);
        let report = execute_in(
            fixture.inputs,
            &executable,
            fixture.work.path(),
            process::ProcessLimits::uncontained_test_limits(Duration::from_secs(5), 1024, 1024),
            None,
        )
        .unwrap();
        assert_eq!(
            validate_provider_report(report).unwrap_err(),
            InspectionErrorCode::ProviderPostconditionMismatch
        );
    }

    #[cfg(unix)]
    #[test]
    fn fake_provider_failures_keep_their_exit_classification() {
        let fixture = fake_fixture();
        let executable = fake_script(fixture.work.path(), "exit 7");
        let failure = execute_in(
            fixture.inputs,
            &executable,
            fixture.work.path(),
            process::ProcessLimits::uncontained_test_limits(Duration::from_secs(5), 1024, 1024),
            None,
        )
        .unwrap_err();
        assert_eq!(
            failure,
            ProviderFailure::Execution(InspectionErrorCode::ProviderExitedUnsuccessfully)
        );
    }

    #[cfg(unix)]
    #[test]
    fn fake_provider_timeout_and_cancellation_are_bounded() {
        let fixture = fake_fixture();
        let executable = fake_script(fixture.work.path(), "trap '' TERM INT; /bin/sleep 30");
        let started = Instant::now();
        let failure = execute_in(
            fixture.inputs,
            &executable,
            fixture.work.path(),
            process::ProcessLimits::uncontained_test_limits(Duration::from_millis(50), 1024, 1024),
            None,
        )
        .unwrap_err();
        assert_eq!(
            failure,
            ProviderFailure::Execution(InspectionErrorCode::ProviderTimedOut)
        );
        assert!(started.elapsed() < Duration::from_secs(3));

        let fixture = fake_fixture();
        let executable = fake_script(fixture.work.path(), "trap '' TERM INT; /bin/sleep 30");
        let cancellation = CancellationHandle::new();
        let worker = cancellation.clone();
        let trigger = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            worker.cancel();
        });
        let started = Instant::now();
        let failure = execute_in(
            fixture.inputs,
            &executable,
            fixture.work.path(),
            process::ProcessLimits::uncontained_test_limits(Duration::from_secs(30), 1024, 1024),
            Some(&cancellation),
        )
        .unwrap_err();
        assert_eq!(failure, ProviderFailure::Cancelled);
        assert!(started.elapsed() < Duration::from_secs(3));
        trigger.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn fake_provider_output_bound_and_input_mutation_are_detected() {
        let fixture = fake_fixture();
        let executable = fake_script(
            fixture.work.path(),
            "i=0; while [ $i -lt 100 ]; do printf x; i=$((i+1)); done",
        );
        let failure = execute_in(
            fixture.inputs,
            &executable,
            fixture.work.path(),
            process::ProcessLimits::uncontained_test_limits(Duration::from_secs(2), 5, 1024),
            None,
        )
        .unwrap_err();
        assert_eq!(
            failure,
            ProviderFailure::Execution(InspectionErrorCode::ProviderOutputExceeded)
        );

        let fixture = fake_fixture();
        let body = format!("printf x >> \"$7\"\n{}", captured_body());
        let executable = fake_script(fixture.work.path(), &body);
        let failure = execute_in(
            fixture.inputs,
            &executable,
            fixture.work.path(),
            process::ProcessLimits::uncontained_test_limits(Duration::from_secs(5), 1024, 1024),
            None,
        )
        .unwrap_err();
        assert_eq!(
            failure,
            ProviderFailure::Conflict(InspectionErrorCode::InputChangedDuringInspection)
        );
        assert!(fs::metadata(fixture.input).unwrap().len() > 0xe00);
    }

    #[cfg(unix)]
    #[test]
    fn fake_provider_key_mutation_is_detected() {
        let fixture = fake_fixture();
        fs::write(
            fixture.work.path().join("key-path"),
            fixture.key.to_string_lossy().as_bytes(),
        )
        .unwrap();
        let body = format!(
            "read key_path < key-path\nprintf x >> \"$key_path\"\n{}",
            captured_body()
        );
        let executable = fake_script(fixture.work.path(), &body);
        let failure = execute_in(
            fixture.inputs,
            &executable,
            fixture.work.path(),
            process::ProcessLimits::uncontained_test_limits(Duration::from_secs(5), 1024, 1024),
            None,
        )
        .unwrap_err();
        assert_eq!(
            failure,
            ProviderFailure::Conflict(InspectionErrorCode::KeyFileChangedDuringInspection)
        );
    }

    #[cfg(unix)]
    #[test]
    fn fake_provider_text_is_not_repeated_in_diagnostics() {
        let fixture = fake_fixture();
        let executable = fake_script(fixture.work.path(), "printf 'TOP-SECRET provider text'");
        let failure = execute_in(
            fixture.inputs,
            &executable,
            fixture.work.path(),
            process::ProcessLimits::uncontained_test_limits(Duration::from_secs(5), 1024, 1024),
            None,
        )
        .unwrap_err();
        assert_eq!(
            failure,
            ProviderFailure::Execution(InspectionErrorCode::ProviderOutputMalformed)
        );
        assert!(!format!("{failure:?}").contains("TOP-SECRET"));
    }
}
