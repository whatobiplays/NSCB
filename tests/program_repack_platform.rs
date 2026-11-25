#![cfg(not(all(target_os = "macos", target_arch = "aarch64")))]

use nscb::{Engine, RepackRequest};

#[test]
fn repack_planning_reports_unsupported_capability_outside_qualified_platform() {
    let error = match Engine::new().plan_repack(RepackRequest::new(
        "manifest.json",
        "output.pfs0",
        "workspace",
        "keys.txt",
    )) {
        Ok(_) => panic!("repack planning is qualified only on native macOS arm64"),
        Err(error) => error,
    };

    assert_eq!(error.code().as_str(), "unsupported_capability");
}
