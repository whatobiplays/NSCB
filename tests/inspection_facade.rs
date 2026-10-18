use nscb::{CancellationHandle, Engine, InspectionExitClass, InspectionHost, InspectionRequest};

#[test]
fn inspection_facade_is_additive_and_requires_no_helper_configuration() {
    let engine = Engine;
    let request = InspectionRequest::nca(
        "/definitely/missing/nscb-input.nca",
        "/definitely/missing/nscb-prod.keys",
    );
    let cancellation = CancellationHandle::new();
    let host = InspectionHost::cache_only("/definitely/missing/nscb-cache")
        .with_cancellation(cancellation);

    let error = engine
        .preflight_inspection(&request, &host)
        .expect_err("missing prerequisites cannot be ready");
    assert_eq!(error.code().exit_class(), InspectionExitClass::Prerequisite);
    assert!(!error.to_string().contains("/definitely/missing"));
}
