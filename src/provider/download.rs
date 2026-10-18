//! Explicit, digest-pinned provider archive retrieval.
//!
//! Network access is reached only through `InspectionHost::managed_download`
//! and only after preflight reports that provisioning is required.
use crate::inspection::{CancellationHandle, InspectionErrorCode};
use crate::provider::manifest::TargetArtifact;
use crate::sha256::Sha256Digest;
use std::io::Read;
use std::time::{Duration, Instant};
use url::Url;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(2);
const WRITE_TIMEOUT: Duration = Duration::from_secs(20);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_REDIRECTS: u32 = 5;
const CHUNK: usize = 64 * 1024;

pub(crate) fn fetch_archive(
    target: &TargetArtifact,
    cancellation: Option<&CancellationHandle>,
) -> Result<Vec<u8>, InspectionErrorCode> {
    if cancellation.is_some_and(CancellationHandle::is_cancelled) {
        return Err(InspectionErrorCode::Cancelled);
    }
    let started = Instant::now();
    let deadline = started
        .checked_add(TOTAL_TIMEOUT)
        .ok_or(InspectionErrorCode::ProvisioningFailed)?;
    let mut url = parse_https_url(target.download_url())?;
    let mut redirects = 0;
    let response = loop {
        if cancellation.is_some_and(CancellationHandle::is_cancelled) {
            return Err(InspectionErrorCode::Cancelled);
        }
        let budget = remaining(deadline)?;
        let agent = ureq::AgentBuilder::new()
            .try_proxy_from_env(false)
            .https_only(true)
            .redirects(0)
            .timeout_connect(CONNECT_TIMEOUT.min(budget))
            .timeout_read(READ_TIMEOUT.min(budget))
            .timeout_write(WRITE_TIMEOUT.min(budget))
            .timeout(budget)
            .build();
        let request_timeout = remaining(deadline)?;
        match agent.get(url.as_str()).timeout(request_timeout).call() {
            Ok(response) if is_redirect(response.status()) => {
                url = follow_redirect(
                    &url,
                    response.status(),
                    response.header("Location"),
                    &mut redirects,
                )?;
            }
            Ok(response) => break response,
            Err(ureq::Error::Status(status, response)) if is_redirect(status) => {
                url = follow_redirect(&url, status, response.header("Location"), &mut redirects)?;
            }
            Err(_) => {
                return Err(
                    if cancellation.is_some_and(CancellationHandle::is_cancelled) {
                        InspectionErrorCode::Cancelled
                    } else {
                        InspectionErrorCode::ProvisioningFailed
                    },
                );
            }
        }
    };
    if response
        .header("Content-Length")
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length != target.archive_bytes())
    {
        return Err(InspectionErrorCode::ProviderArchiveInvalid);
    }
    let expected = usize::try_from(target.archive_bytes())
        .map_err(|_| InspectionErrorCode::ProviderArchiveInvalid)?;
    let mut reader = response.into_reader();
    let mut archive = Vec::new();
    archive
        .try_reserve_exact(expected.min(CHUNK))
        .map_err(|_| InspectionErrorCode::AllocationFailed)?;
    let mut buffer = [0_u8; CHUNK];
    loop {
        if cancellation.is_some_and(CancellationHandle::is_cancelled) {
            archive.fill(0);
            return Err(InspectionErrorCode::Cancelled);
        }
        if Instant::now() >= deadline {
            archive.fill(0);
            return Err(InspectionErrorCode::ProvisioningFailed);
        }
        let read = match reader.read(&mut buffer) {
            Ok(read) => read,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                if cancellation.is_some_and(CancellationHandle::is_cancelled) {
                    archive.fill(0);
                    return Err(InspectionErrorCode::Cancelled);
                }
                if Instant::now() < deadline {
                    continue;
                }
                archive.fill(0);
                return Err(InspectionErrorCode::ProvisioningFailed);
            }
            Err(_) => {
                archive.fill(0);
                return Err(InspectionErrorCode::ProvisioningFailed);
            }
        };
        if read == 0 {
            break;
        }
        if archive.len().saturating_add(read) > expected {
            archive.fill(0);
            return Err(InspectionErrorCode::ProviderArchiveInvalid);
        }
        archive
            .try_reserve(read)
            .map_err(|_| InspectionErrorCode::AllocationFailed)?;
        archive.extend_from_slice(&buffer[..read]);
    }
    if archive.len() as u64 != target.archive_bytes()
        || Sha256Digest::digest(&archive) != target.archive_sha256()
    {
        archive.fill(0);
        return Err(InspectionErrorCode::ProviderArchiveInvalid);
    }
    Ok(archive)
}

fn follow_redirect(
    current: &Url,
    status: u16,
    location: Option<&str>,
    redirects: &mut u32,
) -> Result<Url, InspectionErrorCode> {
    debug_assert!(is_redirect(status));
    if *redirects == MAX_REDIRECTS {
        return Err(InspectionErrorCode::ProvisioningFailed);
    }
    let location = location.ok_or(InspectionErrorCode::ProvisioningFailed)?;
    let target = redirect_target(current, location)?;
    *redirects += 1;
    Ok(target)
}

fn parse_https_url(value: &str) -> Result<Url, InspectionErrorCode> {
    let url = Url::parse(value).map_err(|_| InspectionErrorCode::ProviderArchiveInvalid)?;
    validate_https_url(url)
}

fn redirect_target(current: &Url, location: &str) -> Result<Url, InspectionErrorCode> {
    let url = current
        .join(location)
        .map_err(|_| InspectionErrorCode::ProviderArchiveInvalid)?;
    validate_https_url(url)
}

fn validate_https_url(url: Url) -> Result<Url, InspectionErrorCode> {
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(InspectionErrorCode::ProviderArchiveInvalid);
    }
    Ok(url)
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn remaining(deadline: Instant) -> Result<Duration, InspectionErrorCode> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(InspectionErrorCode::ProvisioningFailed)
    } else {
        Ok(remaining)
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_REDIRECTS, fetch_archive, follow_redirect, parse_https_url, redirect_target};
    use crate::inspection::{CancellationHandle, InspectionErrorCode};
    use crate::provider::manifest::manifest;

    #[test]
    fn cancellation_is_checked_before_any_network_request() {
        let target = manifest()
            .unwrap()
            .find("macos", "aarch64")
            .expect("target");
        let cancellation = CancellationHandle::new();
        cancellation.cancel();
        assert_eq!(
            fetch_archive(target, Some(&cancellation)).unwrap_err(),
            InspectionErrorCode::Cancelled
        );
    }

    #[test]
    fn https_policy_allows_the_github_cdn_and_rejects_downgrades() {
        let release =
            parse_https_url("https://github.com/jakcron/nstool/releases/file.zip").unwrap();
        let cdn = redirect_target(
            &release,
            "https://objects.githubusercontent.com/release-assets/nstool.zip",
        )
        .unwrap();
        assert_eq!(cdn.host_str(), Some("objects.githubusercontent.com"));
        assert_eq!(
            redirect_target(&release, "http://objects.githubusercontent.com/file.zip").unwrap_err(),
            InspectionErrorCode::ProviderArchiveInvalid
        );
        assert_eq!(
            parse_https_url("http://github.com/nstool.zip").unwrap_err(),
            InspectionErrorCode::ProviderArchiveInvalid
        );
    }

    #[test]
    fn redirect_budget_is_explicit_and_bounded() {
        assert_eq!(MAX_REDIRECTS, 5);
    }

    #[test]
    fn successful_redirect_response_is_followed_before_validating_its_empty_body() {
        let release =
            parse_https_url("https://github.com/jakcron/nstool/releases/file.zip").unwrap();
        let mut redirects = 0;
        let next = follow_redirect(
            &release,
            302,
            Some("https://objects.githubusercontent.com/release-assets/nstool.zip"),
            &mut redirects,
        )
        .unwrap();
        assert_eq!(next.host_str(), Some("objects.githubusercontent.com"));
        assert_eq!(redirects, 1);
    }

    #[test]
    fn redirect_without_location_or_beyond_budget_fails_closed() {
        let release =
            parse_https_url("https://github.com/jakcron/nstool/releases/file.zip").unwrap();
        let mut redirects = 0;
        assert_eq!(
            follow_redirect(&release, 302, None, &mut redirects).unwrap_err(),
            InspectionErrorCode::ProvisioningFailed
        );
        redirects = MAX_REDIRECTS;
        assert_eq!(
            follow_redirect(
                &release,
                302,
                Some("https://objects.githubusercontent.com/release-assets/nstool.zip"),
                &mut redirects,
            )
            .unwrap_err(),
            InspectionErrorCode::ProvisioningFailed
        );
        assert_eq!(redirects, MAX_REDIRECTS);
    }

    #[test]
    #[ignore = "bounded manual qualification against the pinned GitHub release"]
    fn diagnostic_fetch_reports_only_pinned_archive_length_and_digest() {
        let target = manifest()
            .unwrap()
            .find("macos", "aarch64")
            .expect("pinned macOS arm64 target");
        let archive = fetch_archive(target, None).expect("download and validate pinned archive");
        eprintln!(
            "archive_fetch=validated length={} sha256={}",
            archive.len(),
            crate::sha256::Sha256Digest::digest(&archive)
        );
        assert_eq!(archive.len() as u64, target.archive_bytes());
        assert_eq!(
            crate::sha256::Sha256Digest::digest(&archive),
            target.archive_sha256()
        );
    }
}
