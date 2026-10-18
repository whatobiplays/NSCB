//! Immutable provider capability manifest baked into the Engine.
//!
//! No path, executable, digest, operation, or qualification value can be
//! supplied by a production caller. The JSON resource under `providers/` is a
//! reviewable mirror of the same compile-time data.
use crate::inspection::InspectionErrorCode;
use crate::sha256::Sha256Digest;
use serde::Deserialize;
use std::sync::OnceLock;

const MANIFEST_JSON: &str = include_str!("../../providers/nstool-v1.9.2.json");
const DOWNLOAD_BASE: &str = "https://github.com/jakcron/nstool/releases/download/v1.9.2/";

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Manifest {
    schema_version: u32,
    provider: String,
    version: String,
    upstream_repository: String,
    upstream_commit: String,
    license: String,
    operation: String,
    targets: Vec<TargetArtifact>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct TargetArtifact {
    os: String,
    arch: String,
    release_asset: String,
    download_url: String,
    archive_bytes: u64,
    archive_sha256: String,
    executable: String,
    executable_bytes: u64,
    executable_sha256: String,
    qualification: Qualification,
    qualification_scope: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Qualification {
    Qualified,
    Unqualified,
    Unsupported,
}

impl Manifest {
    fn validate(&self) -> Result<(), InspectionErrorCode> {
        if self.schema_version != 1
            || self.provider != "nstool"
            || self.version != "1.9.2"
            || self.operation != "nca.inspect"
            || self.license != "MIT"
            || self.upstream_repository != "https://github.com/jakcron/nstool"
            || self.upstream_commit != "e89ea84bd70c11b67ebec9153fb4a446f18a9d3d"
            || self.targets.is_empty()
            || self.targets.len() > 8
        {
            return Err(InspectionErrorCode::ProviderManifestInvalid);
        }

        let mut seen = Vec::new();
        let mut macos_arm64_qualified = false;
        for target in &self.targets {
            target.validate()?;
            if seen
                .iter()
                .any(|(os, arch): &(&str, &str)| *os == target.os && *arch == target.arch)
            {
                return Err(InspectionErrorCode::ProviderManifestInvalid);
            }
            seen.push((target.os.as_str(), target.arch.as_str()));
            if target.os == "macos"
                && target.arch == "aarch64"
                && target.qualification == Qualification::Qualified
                && target.qualification_scope == ["nca.inspect"]
            {
                macos_arm64_qualified = true;
            }
        }
        if !macos_arm64_qualified {
            return Err(InspectionErrorCode::ProviderManifestInvalid);
        }
        Ok(())
    }

    pub(crate) fn find(&self, os: &str, arch: &str) -> Option<&TargetArtifact> {
        self.targets
            .iter()
            .find(|target| target.os == os && target.arch == arch)
    }
}

impl TargetArtifact {
    fn validate(&self) -> Result<(), InspectionErrorCode> {
        if self.os.is_empty()
            || self.os.len() > 16
            || self.arch.is_empty()
            || self.arch.len() > 16
            || self.release_asset.is_empty()
            || self.release_asset.len() > 128
            || self.release_asset.contains(['/', '\\'])
            || self.release_asset == "."
            || self.release_asset == ".."
            || self.download_url != format!("{DOWNLOAD_BASE}{}", self.release_asset)
            || self.executable.is_empty()
            || self.executable.len() > 64
            || self.executable.contains(['/', '\\'])
            || self.executable == "."
            || self.executable == ".."
            || self.archive_bytes == 0
            || self.executable_bytes == 0
            || self.qualification_scope.len() > 1
        {
            return Err(InspectionErrorCode::ProviderManifestInvalid);
        }
        Sha256Digest::parse_hex(&self.archive_sha256)
            .map_err(|_| InspectionErrorCode::ProviderManifestInvalid)?;
        Sha256Digest::parse_hex(&self.executable_sha256)
            .map_err(|_| InspectionErrorCode::ProviderManifestInvalid)?;
        match self.qualification {
            Qualification::Qualified if self.qualification_scope != ["nca.inspect"] => {
                Err(InspectionErrorCode::ProviderManifestInvalid)
            }
            Qualification::Unqualified | Qualification::Unsupported
                if !self.qualification_scope.is_empty() =>
            {
                Err(InspectionErrorCode::ProviderManifestInvalid)
            }
            _ => Ok(()),
        }
    }

    #[cfg(test)]
    pub(crate) fn arch(&self) -> &str {
        &self.arch
    }

    pub(crate) fn download_url(&self) -> &str {
        &self.download_url
    }

    pub(crate) fn archive_bytes(&self) -> u64 {
        self.archive_bytes
    }

    pub(crate) fn archive_sha256(&self) -> Sha256Digest {
        Sha256Digest::parse_hex(&self.archive_sha256).expect("validated manifest digest")
    }

    pub(crate) fn executable(&self) -> &str {
        &self.executable
    }

    pub(crate) fn executable_bytes(&self) -> u64 {
        self.executable_bytes
    }

    pub(crate) fn executable_sha256(&self) -> Sha256Digest {
        Sha256Digest::parse_hex(&self.executable_sha256).expect("validated manifest digest")
    }
}

#[cfg(test)]
pub(crate) fn synthetic_target(executable: &[u8], archive: &[u8]) -> TargetArtifact {
    TargetArtifact {
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        release_asset: "synthetic.zip".to_owned(),
        download_url: format!("{DOWNLOAD_BASE}synthetic.zip"),
        archive_bytes: archive.len() as u64,
        archive_sha256: Sha256Digest::digest(archive).to_hex(),
        executable: "nstool".to_owned(),
        executable_bytes: executable.len() as u64,
        executable_sha256: Sha256Digest::digest(executable).to_hex(),
        qualification: Qualification::Qualified,
        qualification_scope: vec!["nca.inspect".to_owned()],
    }
}

fn parsed_manifest() -> &'static Result<Manifest, InspectionErrorCode> {
    static MANIFEST: OnceLock<Result<Manifest, InspectionErrorCode>> = OnceLock::new();
    MANIFEST.get_or_init(|| {
        let manifest: Manifest = serde_json::from_str(MANIFEST_JSON)
            .map_err(|_| InspectionErrorCode::ProviderManifestInvalid)?;
        manifest.validate()?;
        Ok(manifest)
    })
}

pub(crate) fn manifest() -> Result<&'static Manifest, InspectionErrorCode> {
    parsed_manifest().as_ref().map_err(|code| *code)
}

/// Selects the immutable artifact entry for this build target and operation.
pub(crate) fn target_artifact() -> Result<&'static TargetArtifact, InspectionErrorCode> {
    let manifest = manifest()?;
    let target = manifest
        .find(std::env::consts::OS, std::env::consts::ARCH)
        .ok_or(InspectionErrorCode::ProviderUnsupportedTarget)?;
    match target.qualification {
        Qualification::Qualified => Ok(target),
        Qualification::Unqualified => Err(InspectionErrorCode::ProviderUnqualifiedTarget),
        Qualification::Unsupported => Err(InspectionErrorCode::ProviderUnsupportedTarget),
    }
}

#[cfg(test)]
pub(crate) fn all_targets() -> &'static [TargetArtifact] {
    &manifest().expect("valid manifest").targets
}

#[cfg(test)]
mod tests {
    use super::{Qualification, all_targets, manifest, target_artifact};
    #[test]
    fn manifest_pins_the_exact_release_and_targets() {
        let manifest = manifest().expect("manifest validates");
        assert_eq!(manifest.version, "1.9.2");
        assert_eq!(
            manifest.upstream_commit,
            "e89ea84bd70c11b67ebec9153fb4a446f18a9d3d"
        );
        assert_eq!(
            manifest
                .find("macos", "aarch64")
                .expect("macOS arm64 entry")
                .qualification,
            Qualification::Qualified
        );
    }

    #[test]
    fn only_macos_arm64_is_qualified_for_this_operation() {
        for target in all_targets() {
            let expected = target.os == "macos" && target.arch == "aarch64";
            assert_eq!(target.qualification == Qualification::Qualified, expected);
        }
    }

    #[test]
    fn artifact_names_and_urls_stay_within_the_pinned_release() {
        for target in all_targets() {
            assert!(target.download_url.ends_with(&target.release_asset));
            assert!(!target.executable.contains('/'));
            assert!(!target.executable.contains('\\'));
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn current_native_target_is_qualified() {
        assert_eq!(target_artifact().expect("native target").arch(), "aarch64");
    }

    #[cfg(not(any(
        all(target_os = "macos", target_arch = "aarch64"),
        target_os = "macos",
        target_os = "linux",
        target_os = "windows"
    )))]
    #[test]
    fn unknown_targets_fail_before_execution() {
        assert_eq!(
            target_artifact().unwrap_err(),
            InspectionErrorCode::ProviderUnsupportedTarget
        );
    }
}
