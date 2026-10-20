//! Engine-level Verification contract tests.
//!
//! Every fixture is synthetic and every signing key is generated at test
//! runtime. No production key, Nintendo key, or proprietary content is used.

mod support;

use nscb::{
    CheckApplicability, CheckExecution, CheckOutcome, Engine, PublicKeyEncoding,
    TrustProvenanceKind, VerificationCheckId, VerificationErrorCode, VerificationLimitation,
    VerificationOutcome, VerificationProfile, VerificationReason, VerificationRequest,
    VerificationResult,
};
use rsa::pkcs8::EncodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use support::synthetic_verification::{
    Built, NpdmMode, PARTITION_OFFSET, PartitionFsMode, Spec, build, change_main_name_to_traversal,
    keys_file,
};

const STRUCTURAL_IDS: [VerificationCheckId; 4] = [
    VerificationCheckId::HeaderProfile,
    VerificationCheckId::PartitionLayout,
    VerificationCheckId::PartitionFilesystem,
    VerificationCheckId::PartitionEntries,
];

const FULL_IDS: [VerificationCheckId; 9] = [
    VerificationCheckId::HeaderProfile,
    VerificationCheckId::PartitionLayout,
    VerificationCheckId::PartitionFilesystem,
    VerificationCheckId::PartitionEntries,
    VerificationCheckId::FsHeaderHash,
    VerificationCheckId::FixedKeySignature,
    VerificationCheckId::NpdmMetadata,
    VerificationCheckId::NpdmKeySignatureConsistency,
    VerificationCheckId::PayloadIntegrity,
];

fn write_fixture(spec: Spec) -> (tempfile::TempDir, Built) {
    let directory = tempfile::tempdir().unwrap();
    let built = build(spec);
    built.write(directory.path());
    (directory, built)
}

fn structural(directory: &Path) -> Result<VerificationResult, nscb::VerificationError> {
    let input = directory.join("content.nca");
    let keys = directory.join("prod.keys");
    Engine::new().verify(VerificationRequest::structural_nca(input, keys))
}

fn full(directory: &Path) -> Result<VerificationResult, nscb::VerificationError> {
    let input = directory.join("content.nca");
    let keys = directory.join("prod.keys");
    let anchor = directory.join("anchor.der");
    Engine::new().verify(VerificationRequest::full_nca(input, keys, anchor, 5))
}

fn full_with_anchor(
    directory: &Path,
    anchor: &Path,
    generation: u8,
) -> Result<VerificationResult, nscb::VerificationError> {
    let input = directory.join("content.nca");
    let keys = directory.join("prod.keys");
    Engine::new().verify(VerificationRequest::full_nca(
        input, keys, anchor, generation,
    ))
}

fn check(result: &VerificationResult, id: VerificationCheckId) -> &nscb::VerificationCheck {
    result
        .checks
        .iter()
        .find(|check| check.id == id)
        .expect("requested check must be present")
}

fn assert_immutable(path: &Path, original: &[u8]) {
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn structural_profile_reports_only_structural_checks() {
    let (directory, built) = write_fixture(Spec::default());
    let result = structural(directory.path()).unwrap();
    assert_eq!(result.profile, VerificationProfile::Structural);
    assert_eq!(result.outcome, VerificationOutcome::Passed);
    assert_eq!(
        result
            .checks
            .iter()
            .map(|check| check.id)
            .collect::<Vec<_>>(),
        STRUCTURAL_IDS
    );
    for check in &result.checks {
        assert_eq!(check.applicability, CheckApplicability::Required);
        assert_eq!(check.execution, CheckExecution::Completed);
        assert_eq!(check.outcome, CheckOutcome::Passed);
        assert_eq!(check.reason, None);
    }
    for limitation in [
        VerificationLimitation::SignaturesNotChecked,
        VerificationLimitation::HashChecksNotRun,
        VerificationLimitation::PayloadIntegrityNotAvailable,
        VerificationLimitation::AuthenticityNotEstablished,
        VerificationLimitation::DeviceWriteAuthorizationNotEvaluated,
    ] {
        assert!(result.limitations.contains(&limitation));
    }
    assert!(
        !result
            .limitations
            .contains(&VerificationLimitation::NpdmAcidAuthenticityUnverified)
    );
    assert_immutable(&directory.path().join("content.nca"), &built.nca);
}

#[test]
fn full_profile_executes_every_applicable_check() {
    let (directory, _built) = write_fixture(Spec::default());
    let result = full(directory.path()).unwrap();
    assert_eq!(result.profile, VerificationProfile::Full);
    assert_eq!(result.outcome, VerificationOutcome::Passed);
    assert_eq!(
        result
            .checks
            .iter()
            .map(|check| check.id)
            .collect::<Vec<_>>(),
        FULL_IDS
    );

    let signature = check(&result, VerificationCheckId::FixedKeySignature);
    assert_eq!(signature.outcome, CheckOutcome::Passed);
    let provenance = signature.trust_provenance.as_ref().unwrap();
    assert_eq!(
        provenance.kind,
        TrustProvenanceKind::CallerSuppliedPublicKey
    );
    assert_eq!(provenance.anchor_generation, Some(5));

    let consistency = check(&result, VerificationCheckId::NpdmKeySignatureConsistency);
    assert_eq!(consistency.outcome, CheckOutcome::Passed);
    assert_eq!(
        consistency.trust_provenance.as_ref().unwrap().kind,
        TrustProvenanceKind::EmbeddedNpdmAcidKey
    );

    let integrity = check(&result, VerificationCheckId::PayloadIntegrity);
    assert_eq!(integrity.applicability, CheckApplicability::NotApplicable);
    assert_eq!(integrity.execution, CheckExecution::NotRun);
    assert_eq!(integrity.outcome, CheckOutcome::NotApplicable);
    assert_eq!(integrity.reason, Some(VerificationReason::HashTypeNone));

    for limitation in [
        VerificationLimitation::PayloadIntegrityNotAvailable,
        VerificationLimitation::NpdmAcidAuthenticityUnverified,
        VerificationLimitation::AuthenticityNotEstablished,
        VerificationLimitation::DeviceWriteAuthorizationNotEvaluated,
    ] {
        assert!(result.limitations.contains(&limitation));
    }
    assert!(
        !result
            .limitations
            .contains(&VerificationLimitation::SignaturesNotChecked)
    );
}

#[test]
fn every_supported_public_key_encoding_is_accepted() {
    let directory = tempfile::tempdir().unwrap();
    let built = build(Spec::default());
    let paths = built.write(directory.path());
    let encodings = [
        (
            "anchor-pkcs1.pem",
            built.pkcs1_pem.clone(),
            PublicKeyEncoding::Pkcs1Pem,
        ),
        (
            "anchor-spki.pem",
            built.spki_pem.clone(),
            PublicKeyEncoding::SpkiPem,
        ),
        (
            "anchor-pkcs1.der",
            built.pkcs1_der.clone(),
            PublicKeyEncoding::Pkcs1Der,
        ),
        (
            "anchor-spki.der",
            built.spki_der.clone(),
            PublicKeyEncoding::SpkiDer,
        ),
    ];
    for (name, bytes, expected) in encodings {
        let anchor = directory.path().join(name);
        fs::write(&anchor, bytes).unwrap();
        let result = full_with_anchor(directory.path(), &anchor, 5).unwrap();
        assert_eq!(result.outcome, VerificationOutcome::Passed, "{name}");
        assert_eq!(
            check(&result, VerificationCheckId::FixedKeySignature)
                .trust_provenance
                .as_ref()
                .unwrap()
                .encoding,
            Some(expected),
            "{name}"
        );
    }
    assert_immutable(&paths.input, &built.nca);
}

#[test]
fn descriptor_reserved_byte_accepts_zero_and_one() {
    for enabled in [0_u8, 1] {
        let spec = Spec {
            descriptor_enabled: enabled,
            ..Spec::default()
        };
        let (directory, _built) = write_fixture(spec);
        let result = full(directory.path()).unwrap();
        assert_eq!(
            result.outcome,
            VerificationOutcome::Passed,
            "byte {enabled}"
        );
    }
}

#[test]
fn descriptor_bytes_outside_the_supported_convention_are_rejected() {
    let spec = Spec {
        descriptor_enabled: 2,
        ..Spec::default()
    };
    let (directory, _built) = write_fixture(spec);
    let error = full(directory.path()).unwrap_err();
    assert_eq!(error.code(), VerificationErrorCode::MalformedInput);
}

#[test]
fn anchor_generation_mismatch_is_a_prerequisite_not_a_signature_failure() {
    let spec = Spec {
        signature_generation: 5,
        ..Spec::default()
    };
    let (directory, _built) = write_fixture(spec);
    let result = full_with_anchor(directory.path(), &directory.path().join("anchor.der"), 4)
        .unwrap_or_else(|error| panic!("unexpected {error}"));
    assert_eq!(result.outcome, VerificationOutcome::Failed);
    let signature = check(&result, VerificationCheckId::FixedKeySignature);
    assert_eq!(signature.applicability, CheckApplicability::Required);
    assert_eq!(signature.execution, CheckExecution::NotRun);
    assert_eq!(signature.outcome, CheckOutcome::Failed);
    assert_eq!(
        signature.reason,
        Some(VerificationReason::TrustAnchorGenerationMismatch)
    );
    assert!(
        result
            .checks
            .iter()
            .all(|check| check.reason != Some(VerificationReason::SignatureMismatch))
    );
    assert_eq!(
        check(&result, VerificationCheckId::NpdmKeySignatureConsistency).outcome,
        CheckOutcome::Passed
    );
}

#[test]
fn executed_signature_mismatch_is_reported_after_the_check_runs() {
    let spec = Spec {
        corrupt_fixed_signature: true,
        ..Spec::default()
    };
    let (directory, _built) = write_fixture(spec);
    let result = full(directory.path()).unwrap();
    assert_eq!(result.outcome, VerificationOutcome::Failed);
    let signature = check(&result, VerificationCheckId::FixedKeySignature);
    assert_eq!(signature.execution, CheckExecution::Completed);
    assert_eq!(signature.outcome, CheckOutcome::Failed);
    assert_eq!(
        signature.reason,
        Some(VerificationReason::SignatureMismatch)
    );
    assert_eq!(
        check(&result, VerificationCheckId::NpdmKeySignatureConsistency).outcome,
        CheckOutcome::Passed
    );
}

#[test]
fn filesystem_header_hash_mismatch_is_reported() {
    let spec = Spec {
        fs_hash_corrupt: true,
        ..Spec::default()
    };
    let (directory, _built) = write_fixture(spec);
    let result = full(directory.path()).unwrap();
    assert_eq!(result.outcome, VerificationOutcome::Failed);
    let hash = check(&result, VerificationCheckId::FsHeaderHash);
    assert_eq!(hash.outcome, CheckOutcome::Failed);
    assert_eq!(hash.reason, Some(VerificationReason::FsHeaderHashMismatch));
    assert_eq!(
        check(&result, VerificationCheckId::FixedKeySignature).outcome,
        CheckOutcome::Passed
    );
}

#[test]
fn npdm_key_signature_mismatch_is_reported_only_for_consistency() {
    let spec = Spec {
        corrupt_npdm_signature: true,
        ..Spec::default()
    };
    let (directory, _built) = write_fixture(spec);
    let result = full(directory.path()).unwrap();
    assert_eq!(result.outcome, VerificationOutcome::Failed);
    let consistency = check(&result, VerificationCheckId::NpdmKeySignatureConsistency);
    assert_eq!(consistency.outcome, CheckOutcome::Failed);
    assert_eq!(
        consistency.reason,
        Some(VerificationReason::NpdmKeySignatureMismatch)
    );
    assert_eq!(
        check(&result, VerificationCheckId::FixedKeySignature).outcome,
        CheckOutcome::Passed
    );
}

#[test]
fn npdm_absent_duplicate_malformed_and_untrusted_are_distinct() {
    let cases = [
        (NpdmMode::Missing, VerificationReason::NpdmMissing),
        (NpdmMode::Duplicate, VerificationReason::NpdmDuplicate),
        (NpdmMode::MalformedSize, VerificationReason::NpdmMalformed),
    ];
    for (mode, reason) in cases {
        let spec = Spec {
            npdm: mode,
            ..Spec::default()
        };
        let (directory, _built) = write_fixture(spec);
        let result = full(directory.path()).unwrap();
        assert_eq!(result.outcome, VerificationOutcome::Failed);
        let metadata = check(&result, VerificationCheckId::NpdmMetadata);
        assert_eq!(metadata.outcome, CheckOutcome::Failed);
        assert_eq!(metadata.reason, Some(reason));
        if mode == NpdmMode::Duplicate {
            let entries = check(&result, VerificationCheckId::PartitionEntries);
            assert_eq!(entries.outcome, CheckOutcome::Failed);
            assert_eq!(
                entries.reason,
                Some(VerificationReason::PartitionEntriesInvalid)
            );
        }
        let consistency = check(&result, VerificationCheckId::NpdmKeySignatureConsistency);
        assert_eq!(consistency.execution, CheckExecution::NotRun);
        assert_eq!(
            consistency.reason,
            Some(VerificationReason::PrerequisiteCheckFailed)
        );
    }

    let spec = Spec {
        npdm: NpdmMode::WrongAcidKey,
        ..Spec::default()
    };
    let (directory, _built) = write_fixture(spec);
    let result = full(directory.path()).unwrap();
    assert_eq!(
        check(&result, VerificationCheckId::NpdmMetadata).outcome,
        CheckOutcome::Passed
    );
    let consistency = check(&result, VerificationCheckId::NpdmKeySignatureConsistency);
    assert_eq!(consistency.outcome, CheckOutcome::Failed);
    assert_eq!(
        consistency.reason,
        Some(VerificationReason::NpdmKeySignatureMismatch)
    );
}

#[test]
fn unsupported_content_type_fails_the_header_profile_before_later_checks() {
    let spec = Spec {
        content_type: 4,
        ..Spec::default()
    };
    let (directory, _built) = write_fixture(spec);
    let result = full(directory.path()).unwrap();
    assert_eq!(result.outcome, VerificationOutcome::Failed);
    let header = check(&result, VerificationCheckId::HeaderProfile);
    assert_eq!(header.outcome, CheckOutcome::Failed);
    assert_eq!(header.reason, Some(VerificationReason::UnsupportedProfile));
    let layout = check(&result, VerificationCheckId::PartitionLayout);
    assert_eq!(layout.execution, CheckExecution::NotRun);
    assert_eq!(
        layout.reason,
        Some(VerificationReason::PrerequisiteCheckFailed)
    );
}

#[test]
fn download_distribution_passes_the_full_profile() {
    let (directory, _built) = write_fixture(Spec {
        distribution: 0,
        ..Spec::default()
    });
    let result = full(directory.path()).unwrap();
    assert_eq!(result.outcome, VerificationOutcome::Passed);
    assert_eq!(
        check(&result, VerificationCheckId::HeaderProfile).outcome,
        CheckOutcome::Passed
    );
}

#[test]
fn truncated_and_plaintext_inputs_are_typed_errors() {
    let directory = tempfile::tempdir().unwrap();
    let keys = directory.path().join("prod.keys");
    fs::write(&keys, keys_file()).unwrap();

    let short = directory.path().join("short.nca");
    fs::write(&short, [0_u8; 4]).unwrap();
    let anchor = directory.path().join("anchor.der");
    fs::write(&anchor, build(Spec::default()).spki_der).unwrap();
    let error = Engine::new()
        .verify(VerificationRequest::full_nca(&short, &keys, &anchor, 5))
        .unwrap_err();
    assert_eq!(error.code(), VerificationErrorCode::TruncatedInput);

    let plaintext = directory.path().join("plaintext.nca");
    let mut bytes = vec![0_u8; 0x1200];
    bytes[0x200..0x204].copy_from_slice(b"NCA3");
    fs::write(&plaintext, bytes).unwrap();
    let error = Engine::new()
        .verify(VerificationRequest::full_nca(&plaintext, &keys, &anchor, 5))
        .unwrap_err();
    assert_eq!(error.code(), VerificationErrorCode::UnsupportedFormat);
}

#[test]
fn malformed_and_oversized_trust_anchors_are_prerequisite_errors() {
    let directory = tempfile::tempdir().unwrap();
    let built = build(Spec::default());
    let paths = built.write(directory.path());

    let garbage = directory.path().join("garbage.der");
    fs::write(&garbage, b"not a key").unwrap();
    let error = Engine::new()
        .verify(VerificationRequest::full_nca(
            &paths.input,
            &paths.keys,
            &garbage,
            5,
        ))
        .unwrap_err();
    assert_eq!(error.code(), VerificationErrorCode::TrustAnchorMalformed);

    let oversized = directory.path().join("oversized.der");
    fs::write(&oversized, vec![0_u8; 17 * 1024]).unwrap();
    let error = Engine::new()
        .verify(VerificationRequest::full_nca(
            &paths.input,
            &paths.keys,
            &oversized,
            5,
        ))
        .unwrap_err();
    assert_eq!(
        error.code(),
        VerificationErrorCode::TrustAnchorLimitExceeded
    );

    let small = directory.path().join("small.der");
    let mut rng = rand::thread_rng();
    let small_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
    let small_public = RsaPublicKey::from(&small_key);
    fs::write(&small, small_public.to_public_key_der().unwrap().as_bytes()).unwrap();
    let error = Engine::new()
        .verify(VerificationRequest::full_nca(
            &paths.input,
            &paths.keys,
            &small,
            5,
        ))
        .unwrap_err();
    assert_eq!(error.code(), VerificationErrorCode::TrustAnchorMalformed);

    let exponent = directory.path().join("exponent.der");
    let two_thousand_forty_eight =
        RsaPublicKey::from(&support::synthetic_verification::keys().anchor);
    let unusual =
        RsaPublicKey::new(two_thousand_forty_eight.n().clone(), BigUint::from(3_u32)).unwrap();
    fs::write(&exponent, unusual.to_public_key_der().unwrap().as_bytes()).unwrap();
    let error = Engine::new()
        .verify(VerificationRequest::full_nca(
            &paths.input,
            &paths.keys,
            &exponent,
            5,
        ))
        .unwrap_err();
    assert_eq!(error.code(), VerificationErrorCode::TrustAnchorMalformed);
}

#[test]
fn missing_trust_anchor_file_is_a_prerequisite_error() {
    let (directory, _built) = write_fixture(Spec::default());
    let missing = directory.path().join("missing.pem");
    let error = full_with_anchor(directory.path(), &missing, 5).unwrap_err();
    assert_eq!(error.code(), VerificationErrorCode::TrustAnchorUnavailable);
    assert_eq!(error.code().exit_code(), 3);
}

#[test]
fn invalid_partition_layout_fails_the_layout_check() {
    let spec = Spec {
        zero_size_first_partition: true,
        ..Spec::default()
    };
    let (directory, _built) = write_fixture(spec);
    let result = full(directory.path()).unwrap();
    assert_eq!(result.outcome, VerificationOutcome::Failed);
    let layout = check(&result, VerificationCheckId::PartitionLayout);
    assert_eq!(layout.outcome, CheckOutcome::Failed);
    assert_eq!(
        layout.reason,
        Some(VerificationReason::PartitionLayoutInvalid)
    );
    let filesystem = check(&result, VerificationCheckId::PartitionFilesystem);
    assert_eq!(filesystem.execution, CheckExecution::NotRun);
}

#[test]
fn cancelled_request_returns_cancelled_without_a_result() {
    let (directory, _built) = write_fixture(Spec::default());
    let cancellation = nscb::CancellationHandle::new();
    cancellation.cancel();
    let request = VerificationRequest::structural_nca(
        directory.path().join("content.nca"),
        directory.path().join("prod.keys"),
    )
    .with_cancellation(cancellation);
    let error = Engine::new().verify(request).unwrap_err();
    assert_eq!(error.code(), VerificationErrorCode::Cancelled);
    assert_eq!(error.code().exit_code(), 6);
}

#[test]
fn input_and_key_files_are_unchanged_and_errors_are_redacted() {
    let (directory, built) = write_fixture(Spec::default());
    let input = directory.path().join("content.nca");
    let keys = directory.path().join("prod.keys");
    let key_bytes = fs::read(&keys).unwrap();
    let _ = full(directory.path()).unwrap();
    assert_immutable(&input, &built.nca);
    assert_immutable(&keys, &key_bytes);

    let missing = directory.path().join("missing-content.nca");
    let error = Engine::new()
        .verify(VerificationRequest::structural_nca(&missing, &keys))
        .unwrap_err();
    assert_eq!(error.code(), VerificationErrorCode::InputUnavailable);
    let rendered = format!("{error}");
    assert!(!rendered.contains("missing-content.nca"));
    assert!(!rendered.contains(directory.path().to_str().unwrap()));
}

#[test]
fn hash_type_none_pass_does_not_assert_payload_integrity() {
    let directory = tempfile::tempdir().unwrap();
    let built = build(Spec::default());
    let paths = built.write(directory.path());
    let mut bytes = built.nca.clone();
    let payload = b"synthetic program";
    let offset = bytes
        .windows(payload.len())
        .position(|window| window == payload)
        .expect("the canonical fixture contains the main member payload");
    bytes[offset] ^= 0xff;
    fs::write(&paths.input, &bytes).unwrap();
    let result = full(directory.path()).unwrap();
    assert_eq!(result.outcome, VerificationOutcome::Passed);
    let integrity = check(&result, VerificationCheckId::PayloadIntegrity);
    assert_eq!(integrity.outcome, CheckOutcome::NotApplicable);
    assert!(
        result
            .limitations
            .contains(&VerificationLimitation::PayloadIntegrityNotAvailable)
    );
}

#[test]
fn hierarchy_conflicts_fail_both_profiles_with_stable_entries_reason() {
    for mode in [
        PartitionFsMode::HierarchyFileThenDirectory,
        PartitionFsMode::HierarchyDirectoryThenFile,
    ] {
        // The default fixture uses hash type None (1) and a valid header
        // signature, so the conflict must fail through PartitionFs validation.
        let spec = Spec {
            partition_fs: mode,
            ..Spec::default()
        };
        let (directory, _built) = write_fixture(spec);

        let structural_result = structural(directory.path()).unwrap();
        assert_eq!(structural_result.outcome, VerificationOutcome::Failed);
        let structural_entries = check(&structural_result, VerificationCheckId::PartitionEntries);
        assert_eq!(
            structural_entries.applicability,
            CheckApplicability::Required
        );
        assert_eq!(structural_entries.execution, CheckExecution::Completed);
        assert_eq!(structural_entries.outcome, CheckOutcome::Failed);
        assert_eq!(
            structural_entries.reason,
            Some(VerificationReason::PartitionEntriesInvalid)
        );

        let full_result = full(directory.path()).unwrap();
        assert_eq!(full_result.outcome, VerificationOutcome::Failed);
        let full_entries = check(&full_result, VerificationCheckId::PartitionEntries);
        assert_eq!(full_entries.applicability, CheckApplicability::Required);
        assert_eq!(full_entries.execution, CheckExecution::Completed);
        assert_eq!(full_entries.outcome, CheckOutcome::Failed);
        assert_eq!(
            full_entries.reason,
            Some(VerificationReason::PartitionEntriesInvalid)
        );
        assert_eq!(
            check(&full_result, VerificationCheckId::FixedKeySignature).outcome,
            CheckOutcome::Passed
        );
        let integrity = check(&full_result, VerificationCheckId::PayloadIntegrity);
        assert_eq!(integrity.outcome, CheckOutcome::NotApplicable);
        assert_eq!(integrity.reason, Some(VerificationReason::HashTypeNone));
    }
}

#[test]
fn result_json_uses_stable_check_ids_and_omits_absent_optional_fields() {
    let (directory, _built) = write_fixture(Spec::default());
    let result = full(directory.path()).unwrap();
    let document = serde_json::to_value(&result).unwrap();
    assert_eq!(document["profile"], "full");
    assert_eq!(document["outcome"], "passed");
    let ids: Vec<_> = document["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|check| check["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        [
            "nca3.header_profile",
            "nca3.partition_layout",
            "nca3.partition_filesystem",
            "nca3.partition_entries",
            "nca3.fs_header_hash",
            "nca3.fixed_key_signature",
            "nca3.npdm_metadata",
            "nca3.npdm_key_signature_consistency",
            "nca3.payload_integrity",
        ]
    );
    assert_eq!(document["checks"][0]["id"], "nca3.header_profile");
    assert_eq!(document["checks"][0]["applicability"], "required");
    assert_eq!(document["checks"][0]["execution"], "completed");
    assert_eq!(document["checks"][0]["outcome"], "passed");
    assert!(document["checks"][0].get("reason").is_none());
    assert!(document["checks"][0].get("partition").is_none());
    for index in [2, 3, 4, 6, 7] {
        assert_eq!(document["checks"][index]["partition"], 0);
    }
    assert_eq!(
        document["checks"][5]["trust_provenance"]["kind"],
        "caller_supplied_public_key"
    );
    assert_eq!(
        document["checks"][5]["trust_provenance"]["encoding"],
        "spki_der"
    );
    assert_eq!(
        document["checks"][5]["trust_provenance"]["anchor_generation"],
        5
    );
    assert_eq!(
        document["checks"][7]["trust_provenance"]["kind"],
        "embedded_npdm_acid_key"
    );
    assert!(
        document["checks"][7]["trust_provenance"]
            .get("encoding")
            .is_none()
    );
    assert!(
        document["checks"][7]["trust_provenance"]
            .get("anchor_generation")
            .is_none()
    );
    assert_eq!(document["checks"][8]["reason"], "hash_type_none");
    assert_eq!(document["checks"][8]["applicability"], "not_applicable");
    assert_eq!(document["checks"][8]["execution"], "not_run");
    assert_eq!(document["checks"][8]["outcome"], "not_applicable");
    assert!(document["checks"][8].get("partition").is_none());
    let limitations = document["limitations"].as_array().unwrap();
    assert!(
        limitations
            .iter()
            .any(|value| value == "authenticity_not_established")
    );
    assert!(
        limitations
            .iter()
            .any(|value| value == "device_write_authorization_not_evaluated")
    );
    let text = document.to_string();
    assert!(!text.contains(directory.path().to_str().unwrap()));
}

#[test]
fn invalid_partition_fs_metadata_never_passes_structural_or_full() {
    for mode in [
        PartitionFsMode::Duplicate,
        PartitionFsMode::Traversal,
        PartitionFsMode::Malformed,
    ] {
        let (directory, _built) = write_fixture(Spec {
            partition_fs: mode,
            ..Spec::default()
        });
        for result in [
            structural(directory.path()).unwrap(),
            full(directory.path()).unwrap(),
        ] {
            assert_eq!(result.outcome, VerificationOutcome::Failed, "{mode:?}");
            let entries = check(&result, VerificationCheckId::PartitionEntries);
            assert_eq!(entries.outcome, CheckOutcome::Failed, "{mode:?}");
            assert_eq!(
                entries.reason,
                Some(VerificationReason::PartitionEntriesInvalid),
                "{mode:?}"
            );
        }
    }
}

#[test]
fn signed_hash_none_metadata_change_cannot_pass_partition_entries() {
    let (directory, built) = write_fixture(Spec::default());
    let mut changed = built.nca.clone();
    change_main_name_to_traversal(&mut changed);
    fs::write(directory.path().join("content.nca"), &changed).unwrap();

    let structural_result = structural(directory.path()).unwrap();
    assert_eq!(structural_result.outcome, VerificationOutcome::Failed);
    assert_eq!(
        check(&structural_result, VerificationCheckId::PartitionEntries).reason,
        Some(VerificationReason::PartitionEntriesInvalid)
    );

    let full_result = full(directory.path()).unwrap();
    assert_eq!(full_result.outcome, VerificationOutcome::Failed);
    assert_eq!(
        check(&full_result, VerificationCheckId::PartitionEntries).reason,
        Some(VerificationReason::PartitionEntriesInvalid)
    );
    for id in [
        VerificationCheckId::FsHeaderHash,
        VerificationCheckId::FixedKeySignature,
        VerificationCheckId::NpdmMetadata,
        VerificationCheckId::NpdmKeySignatureConsistency,
    ] {
        assert_eq!(
            check(&full_result, id).outcome,
            CheckOutcome::Passed,
            "{id:?}"
        );
    }
    assert_eq!(
        check(&full_result, VerificationCheckId::PayloadIntegrity).outcome,
        CheckOutcome::NotApplicable
    );
    assert!(
        full_result
            .limitations
            .contains(&VerificationLimitation::PayloadIntegrityNotAvailable)
    );
}

#[test]
fn engine_verification_does_not_consume_a_provider_cache() {
    let (directory, _built) = write_fixture(Spec::default());
    let cache = directory.path().join("empty-provider-cache");
    fs::create_dir(&cache).unwrap();
    let result = full(directory.path()).unwrap();
    assert_eq!(result.outcome, VerificationOutcome::Passed);
    assert!(fs::read_dir(cache).unwrap().next().is_none());
}

const CAVP_N: &str = "a47d04e7cacdba4ea26eca8a4c6e14563c2ce03b623b768c0d49868a57121301dbf783d82f4c055e73960e70550187d0af62ac3496f0a3d9103c2eb7919a72752fa7ce8c688d81e3aee99468887a15288afbb7acb845b7c522b5c64e678fcd3d22feb84b44272700be527d2b2025a3f83c2383bf6a39cf5b4e48b3cf2f56eef0dfff18555e31037b915248694876f3047814415164f2c660881e694b58c28038a032ad25634aad7b39171dee368e3d59bfb7299e4601d4587e68caaf8db457b75af42fc0cf1ae7caced286d77fac6cedb03ad94f1433d2c94d08e60bc1fdef0543cd2951e765b38230fdd18de5d2ca627ddc032fe05bbd2ff21e2db1c2f94d8b";
const CAVP_MSG: &str = "e002377affb04f0fe4598de9d92d31d6c786040d5776976556a2cfc55e54a1dcb3cb1b126bd6a4bed2a184990ccea773fcc79d246553e6c64f686d21ad4152673cafec22aeb40f6a084e8a5b4991f4c64cf8a927effd0fd775e71e8329e41fdd4457b3911173187b4f09a817d79ea2397fc12dfe3d9c9a0290c8ead31b6690a6";
const CAVP_SIGNATURE: &str = "4f9b425c2058460e4ab2f5c96384da2327fd29150f01955a76b4efe956af06dc08779a374ee4607eab61a93adc5608f4ec36e47f2a0f754e8ff839a8a19b1db1e884ea4cf348cd455069eb87afd53645b44e28a0a56808f5031da5ba9112768dfbfca44ebe63a0c0572b731d66122fb71609be1480faa4e4f75e43955159d70f081e2a32fbb19a48b9f162cf6b2fb445d2d6994bc58910a26b5943477803cdaaa1bd74b0da0a5d053d8b1dc593091db5388383c26079f344e2aea600d0e324164b450f7b9b465111b7265f3b1b063089ae7e2623fc0fda8052cf4bf3379102fbf71d7c98e8258664ceed637d20f95ff0111881e650ce61f251d9c3a629ef222d";

#[test]
fn key_source_failures_are_typed_prerequisites() {
    let (directory, _built) = write_fixture(Spec::default());
    let input = directory.path().join("content.nca");

    let missing = directory.path().join("absent.keys");
    let error = Engine::new()
        .verify(VerificationRequest::structural_nca(&input, &missing))
        .unwrap_err();
    assert_eq!(error.code(), VerificationErrorCode::KeyFileUnavailable);
    assert_eq!(error.code().exit_code(), 3);

    let malformed = directory.path().join("malformed.keys");
    fs::write(&malformed, b"header_key = not hexadecimal\n").unwrap();
    let error = Engine::new()
        .verify(VerificationRequest::structural_nca(&input, &malformed))
        .unwrap_err();
    assert_eq!(error.code(), VerificationErrorCode::KeyFileMalformed);
    assert_eq!(error.code().exit_code(), 3);

    let missing_alias = directory.path().join("alias.keys");
    fs::write(&missing_alias, b"title_key = 00\n").unwrap();
    let error = Engine::new()
        .verify(VerificationRequest::structural_nca(&input, &missing_alias))
        .unwrap_err();
    assert_eq!(error.code(), VerificationErrorCode::MissingHeaderKey);
    assert_eq!(error.code().exit_code(), 3);

    let oversized = directory.path().join("oversized.keys");
    fs::write(&oversized, vec![b'a'; 1024 * 1024 + 1]).unwrap();
    let error = Engine::new()
        .verify(VerificationRequest::structural_nca(&input, &oversized))
        .unwrap_err();
    assert_eq!(error.code(), VerificationErrorCode::KeyFileLimitExceeded);
    assert_eq!(error.code().exit_code(), 3);

    let directory_source = directory.path().join("keys-directory");
    fs::create_dir(&directory_source).unwrap();
    let error = Engine::new()
        .verify(VerificationRequest::structural_nca(
            &input,
            &directory_source,
        ))
        .unwrap_err();
    assert_eq!(error.code(), VerificationErrorCode::KeyFileUnavailable);
}

#[test]
fn maximum_supported_key_generation_passes_the_full_profile() {
    let (directory, _built) = write_fixture(Spec {
        key_generation: 0x20,
        ..Spec::default()
    });
    let result = full(directory.path()).unwrap();
    assert_eq!(result.outcome, VerificationOutcome::Passed);
    assert_eq!(
        check(&result, VerificationCheckId::HeaderProfile).outcome,
        CheckOutcome::Passed
    );
}

#[test]
fn unsupported_key_generation_fails_closed_before_layout_checks() {
    let (directory, _built) = write_fixture(Spec {
        key_generation: 0x21,
        ..Spec::default()
    });
    let result = structural(directory.path()).unwrap();
    assert_eq!(result.outcome, VerificationOutcome::Failed);
    assert_eq!(result.checks.len(), STRUCTURAL_IDS.len());
    let header = check(&result, VerificationCheckId::HeaderProfile);
    assert_eq!(header.outcome, CheckOutcome::Failed);
    assert_eq!(header.reason, Some(VerificationReason::UnsupportedProfile));
    let layout = check(&result, VerificationCheckId::PartitionLayout);
    assert_eq!(layout.execution, CheckExecution::NotRun);
    assert_eq!(
        layout.reason,
        Some(VerificationReason::PrerequisiteCheckFailed)
    );
}

#[test]
fn unsupported_partition_hash_profile_never_claims_payload_integrity() {
    let (directory, _built) = write_fixture(Spec {
        partition_hash_type: 2,
        ..Spec::default()
    });
    let result = full(directory.path()).unwrap();
    assert_eq!(result.outcome, VerificationOutcome::Failed);
    let filesystem = check(&result, VerificationCheckId::PartitionFilesystem);
    assert_eq!(filesystem.outcome, CheckOutcome::Failed);
    assert_eq!(
        filesystem.reason,
        Some(VerificationReason::PartitionFilesystemUnsupported)
    );
    let entries = check(&result, VerificationCheckId::PartitionEntries);
    assert_eq!(entries.execution, CheckExecution::NotRun);
    let integrity = check(&result, VerificationCheckId::PayloadIntegrity);
    assert_eq!(integrity.execution, CheckExecution::NotRun);
    assert_eq!(
        integrity.reason,
        Some(VerificationReason::HashTypeUnsupported)
    );
    assert!(
        result
            .limitations
            .contains(&VerificationLimitation::PayloadIntegrityNotAvailable)
    );
}

#[test]
fn full_profile_supports_one_through_four_supported_partitions() {
    for extra_partitions in 0..=3 {
        let (directory, _built) = write_fixture(Spec {
            extra_partitions,
            ..Spec::default()
        });
        let result = full(directory.path()).unwrap();
        assert_eq!(result.outcome, VerificationOutcome::Passed);
        let partition_count = 1 + usize::from(extra_partitions);
        for id in [
            VerificationCheckId::PartitionFilesystem,
            VerificationCheckId::PartitionEntries,
            VerificationCheckId::FsHeaderHash,
        ] {
            let checks: Vec<_> = result
                .checks
                .iter()
                .filter(|check| check.id == id)
                .collect();
            assert_eq!(
                checks.len(),
                partition_count,
                "{id:?} should cover {partition_count} partitions"
            );
            for (index, check) in checks.iter().enumerate() {
                assert_eq!(check.partition, Some(u8::try_from(index).unwrap()));
                assert_eq!(check.outcome, CheckOutcome::Passed);
            }
        }
    }
}

#[test]
fn bounded_pfs0_table_errors_fail_closed_as_partition_entries_invalid() {
    let (directory, built) = write_fixture(Spec::default());
    let input = directory.path().join("content.nca");

    let mut huge_count = built.nca.clone();
    huge_count[PARTITION_OFFSET + 4..PARTITION_OFFSET + 8].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(&input, &huge_count).unwrap();
    let result = structural(directory.path()).unwrap();
    let entries = check(&result, VerificationCheckId::PartitionEntries);
    assert_eq!(entries.outcome, CheckOutcome::Failed);
    assert_eq!(
        entries.reason,
        Some(VerificationReason::PartitionEntriesInvalid)
    );

    let mut bad_magic = built.nca.clone();
    bad_magic[PARTITION_OFFSET..PARTITION_OFFSET + 4].copy_from_slice(b"BAD!");
    fs::write(&input, &bad_magic).unwrap();
    let result = structural(directory.path()).unwrap();
    let entries = check(&result, VerificationCheckId::PartitionEntries);
    assert_eq!(entries.outcome, CheckOutcome::Failed);
    assert_eq!(
        entries.reason,
        Some(VerificationReason::PartitionEntriesInvalid)
    );
}

fn decode(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

/// NIST CAVP `SigVerPSS_186-3` record: mod 2048, SHA-256, salt 32, Result P.
///
/// Source archive: `186-3rsatestvectors.zip` from the NIST CAVP DSS page,
/// SHA-256 `8405aeb3572a4f98ed4b1a3ccb3f2f49e725462dd28ec4759d6a15d88855d19c`.
/// Only public verification material is stored here; the record's private
/// exponent is deliberately omitted.
#[test]
fn cavp_pss_sha256_known_answer_verifies() {
    let key = RsaPublicKey::new(
        BigUint::from_bytes_be(&decode(CAVP_N)),
        // The record encodes the public exponent as 0x10e43f with leading
        // zero hex digits rather than the NCA profile's 0x10001.
        BigUint::from(0x0010_e43f_u32),
    )
    .unwrap();
    let digest = Sha256::digest(decode(CAVP_MSG));
    assert!(
        key.verify(
            rsa::pss::Pss::new_with_salt::<Sha256>(32),
            &digest,
            &decode(CAVP_SIGNATURE),
        )
        .is_ok()
    );
}
