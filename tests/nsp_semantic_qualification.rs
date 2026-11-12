use nscb::{
    CancellationHandle, Engine, NspSemanticQualificationOutcome, NspSemanticQualificationReason,
    NspSemanticQualificationRequest, NspSemanticQualificationRole, Sha256Digest,
};
use sha2::Digest;

#[path = "support/synthetic_nsp_qualification.rs"]
mod synthetic_nsp_qualification;
#[path = "support/synthetic_pfs0.rs"]
#[allow(dead_code)]
mod synthetic_pfs0;

#[test]
fn qualifies_byte_backed_two_member_profile_despite_misleading_names() {
    let fixture = synthetic_nsp_qualification::valid();
    let input = synthetic_pfs0::TempInput::new(&fixture.package);
    let keys = synthetic_pfs0::TempInput::new(&fixture.key_file);
    let original = std::fs::read(input.path()).expect("read the original fixture");
    let request = NspSemanticQualificationRequest::new(input.path(), keys.path());

    let first = Engine::new()
        .qualify_nsp_semantics(request.clone())
        .expect("qualify supported synthetic package");
    let second = Engine::new()
        .qualify_nsp_semantics(request)
        .expect("repeat qualification");

    assert_eq!(first, second);
    assert_eq!(first.source_sha256, Sha256Digest::digest(&fixture.package));
    assert_eq!(std::fs::read(input.path()).unwrap(), original);
    let NspSemanticQualificationOutcome::Qualified(facts) = first.outcome else {
        panic!("the supported synthetic profile must qualify");
    };
    assert_eq!(facts.title_id, synthetic_nsp_qualification::PROGRAM_ID);
    assert_eq!(
        facts.profile,
        nscb::NspSemanticQualificationProfile::RightsFreeBaseApplicationV1
    );
    assert_eq!(facts.members.len(), 2);
    assert_eq!(facts.members[0].role, NspSemanticQualificationRole::Meta);
    assert_eq!(facts.members[0].size, fixture.meta_nca.len() as u64);
    assert_eq!(
        facts.members[0].sha256,
        Sha256Digest::digest(&fixture.meta_nca)
    );
    assert_eq!(facts.members[1].role, NspSemanticQualificationRole::Program);
    assert_eq!(facts.members[1].size, fixture.program_nca.len() as u64);
    assert_eq!(
        facts.members[1].sha256,
        Sha256Digest::digest(&fixture.program_nca)
    );
    assert_eq!(
        facts.cnmt_program_content_id,
        Sha256Digest::digest(&fixture.program_nca).as_bytes()[..16]
    );
}

#[test]
fn pre_cancelled_request_returns_typed_cancellation_before_opening_paths() {
    let cancellation = CancellationHandle::new();
    cancellation.cancel();
    let request = NspSemanticQualificationRequest::new(
        "/path/that/does/not/exist.nsp",
        "/path/that/does/not/exist.keys",
    )
    .with_cancellation(cancellation);

    let error = Engine::new()
        .qualify_nsp_semantics(request)
        .expect_err("cancellation is checked before opening inputs");

    assert_eq!(
        error.code(),
        nscb::NspSemanticQualificationErrorCode::Cancelled
    );
}

#[test]
fn verifies_multiple_hash_table_entries_and_a_partial_final_block() {
    let payload = vec![0x5a; 700];
    let fixture = synthetic_nsp_qualification::build_with_program_payload(&payload, |_| {});
    let result = qualify(&fixture.package, &fixture.key_file).expect("qualify all Program blocks");

    assert!(matches!(
        result.outcome,
        NspSemanticQualificationOutcome::Qualified(_)
    ));
}

#[test]
fn rejects_each_program_row_mismatch_after_section_integrity_passes() {
    let mutations: [fn(&mut [u8; 0x88]); 6] = [
        |cnmt| cnmt[0x30] ^= 0x01,
        |cnmt| cnmt[0x50] ^= 0x01,
        |cnmt| cnmt[0x60] ^= 0x01,
        |cnmt| cnmt[0x66] = 2,
        |cnmt| cnmt[0x67] = 1,
        |cnmt| cnmt[0] ^= 0x01,
    ];
    for mutate in mutations {
        let fixture = synthetic_nsp_qualification::build_with_cnmt_change(mutate);
        assert_eq!(
            not_qualified(&fixture.package, &fixture.key_file),
            NspSemanticQualificationReason::ProgramRelationshipMismatch
        );
    }
}

#[test]
fn rejects_rights_bearing_and_unsupported_key_generation_profiles() {
    let fixture = synthetic_nsp_qualification::valid();
    let rights_program =
        synthetic_nsp_qualification::mutate_nca_header(fixture.program_nca.clone(), |header| {
            header[0x230] = 1
        });
    let rights_package =
        synthetic_nsp_qualification::package_with_members(&fixture.meta_nca, &rights_program);
    assert_eq!(
        not_qualified(&rights_package, &fixture.key_file),
        NspSemanticQualificationReason::RightsBearingContent
    );

    let generation_program =
        synthetic_nsp_qualification::mutate_nca_header(fixture.program_nca.clone(), |header| {
            header[0x220] = 2
        });
    let generation_package =
        synthetic_nsp_qualification::package_with_members(&fixture.meta_nca, &generation_program);
    assert_eq!(
        not_qualified(&generation_package, &fixture.key_file),
        NspSemanticQualificationReason::UnsupportedNcaProfile
    );
}

#[test]
fn rejects_meta_role_title_mismatch_and_unsupported_cnmt_metadata() {
    let fixture = synthetic_nsp_qualification::valid();
    let wrong_meta_title =
        synthetic_nsp_qualification::mutate_nca_header(fixture.meta_nca.clone(), |header| {
            header[0x210] ^= 0x01
        });
    let wrong_meta_package =
        synthetic_nsp_qualification::package_with_members(&wrong_meta_title, &fixture.program_nca);
    assert_eq!(
        not_qualified(&wrong_meta_package, &fixture.key_file),
        NspSemanticQualificationReason::ProgramRelationshipMismatch
    );

    for mutate in [
        (|cnmt: &mut [u8; 0x88]| cnmt[0x0c] = 0x81) as fn(&mut [u8; 0x88]),
        |cnmt| cnmt[0x12..0x14].copy_from_slice(&1_u16.to_le_bytes()),
    ] {
        let unsupported = synthetic_nsp_qualification::build_with_cnmt_change(mutate);
        assert_eq!(
            not_qualified(&unsupported.package, &unsupported.key_file),
            NspSemanticQualificationReason::UnsupportedCnmtProfile
        );
    }
}

#[test]
fn rejects_unexpected_section_hash_profiles_and_duplicate_member_roles() {
    let fixture = synthetic_nsp_qualification::valid();
    let unsupported_program =
        synthetic_nsp_qualification::mutate_nca_header(fixture.program_nca.clone(), |header| {
            header[0x403] = 3;
            let digest = sha2::Sha256::digest(&header[0x400..0x600]);
            header[0x280..0x2a0].copy_from_slice(&digest);
        });
    let unsupported_package =
        synthetic_nsp_qualification::package_with_members(&fixture.meta_nca, &unsupported_program);
    assert_eq!(
        not_qualified(&unsupported_package, &fixture.key_file),
        NspSemanticQualificationReason::UnsupportedNcaProfile
    );

    let duplicate_meta =
        synthetic_nsp_qualification::package_with_members(&fixture.meta_nca, &fixture.meta_nca);
    assert_eq!(
        not_qualified(&duplicate_meta, &fixture.key_file),
        NspSemanticQualificationReason::UnsupportedMemberSet
    );

    let duplicate_program = synthetic_nsp_qualification::package_with_members(
        &fixture.program_nca,
        &fixture.program_nca,
    );
    assert_eq!(
        not_qualified(&duplicate_program, &fixture.key_file),
        NspSemanticQualificationReason::UnsupportedMemberSet
    );
}

#[test]
fn rejects_extra_outer_members_and_plain_pfs0_framing() {
    let fixture = synthetic_nsp_qualification::valid();
    let extra = synthetic_nsp_qualification::package_with_extra_member(
        &fixture.meta_nca,
        &fixture.program_nca,
        "ticket.dat",
        b"ticket-shaped bytes",
    );
    assert_eq!(
        not_qualified(&extra, &fixture.key_file),
        NspSemanticQualificationReason::UnsupportedMemberSet
    );

    let payload = b"not an NCA member";
    let plain = synthetic_pfs0::pfs0(
        &[
            synthetic_pfs0::EntrySpec {
                name: "program.nca",
                offset: 0,
                size: 8,
            },
            synthetic_pfs0::EntrySpec {
                name: "meta.cnmt.nca",
                offset: 8,
                size: 9,
            },
        ],
        payload,
    );
    assert_eq!(
        not_qualified(&plain, &fixture.key_file),
        NspSemanticQualificationReason::InvalidNcaHeader
    );

    let one_member = synthetic_pfs0::pfs0(
        &[synthetic_pfs0::EntrySpec {
            name: "only-program.nca",
            offset: 0,
            size: fixture.program_nca.len() as u64,
        }],
        &fixture.program_nca,
    );
    assert_eq!(
        not_qualified(&one_member, &fixture.key_file),
        NspSemanticQualificationReason::UnsupportedMemberSet
    );
}

#[test]
fn rejects_trailing_unreferenced_outer_pfs0_payload() {
    let fixture = synthetic_nsp_qualification::valid();
    let mut package = fixture.package.clone();
    package.push(0xa5);

    assert_not_qualified(&package, &fixture.key_file);
}

#[test]
fn rejects_a_gap_between_outer_pfs0_member_spans() {
    let fixture = synthetic_nsp_qualification::valid();
    let mut payload = fixture.meta_nca.clone();
    payload.push(0xa5);
    payload.extend_from_slice(&fixture.program_nca);
    let package = synthetic_pfs0::pfs0(
        &[
            synthetic_pfs0::EntrySpec {
                name: "program.nca",
                offset: 0,
                size: fixture.meta_nca.len() as u64,
            },
            synthetic_pfs0::EntrySpec {
                name: "meta.cnmt.nca",
                offset: (fixture.meta_nca.len() + 1) as u64,
                size: fixture.program_nca.len() as u64,
            },
        ],
        &payload,
    );

    assert_not_qualified(&package, &fixture.key_file);
}

#[test]
fn rejects_a_leading_unreferenced_outer_pfs0_payload_gap() {
    let fixture = synthetic_nsp_qualification::valid();
    let mut payload = vec![0xa5];
    payload.extend_from_slice(&fixture.meta_nca);
    payload.extend_from_slice(&fixture.program_nca);
    let package = synthetic_pfs0::pfs0(
        &[
            synthetic_pfs0::EntrySpec {
                name: "program.nca",
                offset: 1,
                size: fixture.meta_nca.len() as u64,
            },
            synthetic_pfs0::EntrySpec {
                name: "meta.cnmt.nca",
                offset: (fixture.meta_nca.len() + 1) as u64,
                size: fixture.program_nca.len() as u64,
            },
        ],
        &payload,
    );

    assert_not_qualified(&package, &fixture.key_file);
}

#[test]
fn outer_pfs0_table_order_does_not_change_complete_payload_accounting() {
    let fixture = synthetic_nsp_qualification::valid();
    let mut payload = fixture.meta_nca.clone();
    payload.extend_from_slice(&fixture.program_nca);
    let package = synthetic_pfs0::pfs0(
        &[
            synthetic_pfs0::EntrySpec {
                name: "meta.cnmt.nca",
                offset: fixture.meta_nca.len() as u64,
                size: fixture.program_nca.len() as u64,
            },
            synthetic_pfs0::EntrySpec {
                name: "program.nca",
                offset: 0,
                size: fixture.meta_nca.len() as u64,
            },
        ],
        &payload,
    );

    let result = qualify(&package, &fixture.key_file).expect("qualify reordered table");
    assert!(matches!(
        result.outcome,
        NspSemanticQualificationOutcome::Qualified(_)
    ));
}

#[test]
fn rejects_an_empty_outer_pfs0_member() {
    let fixture = synthetic_nsp_qualification::valid();
    let package = synthetic_pfs0::pfs0(
        &[
            synthetic_pfs0::EntrySpec {
                name: "empty.nca",
                offset: 0,
                size: 0,
            },
            synthetic_pfs0::EntrySpec {
                name: "member.nca",
                offset: 0,
                size: fixture.meta_nca.len() as u64,
            },
        ],
        &fixture.meta_nca,
    );

    assert_not_qualified(&package, &fixture.key_file);
}

#[test]
fn rejects_unreferenced_payload_in_program_section_pfs0() {
    let content = b"program-content";

    let mut trailing_payload = content.to_vec();
    trailing_payload.push(0xa5);
    let trailing = synthetic_pfs0::pfs0(
        &[synthetic_pfs0::EntrySpec {
            name: "program.bin",
            offset: 0,
            size: content.len() as u64,
        }],
        &trailing_payload,
    );

    let gap_payload = b"first!!!_second";
    let gap = synthetic_pfs0::pfs0(
        &[
            synthetic_pfs0::EntrySpec {
                name: "first.bin",
                offset: 0,
                size: 8,
            },
            synthetic_pfs0::EntrySpec {
                name: "second.bin",
                offset: 9,
                size: 6,
            },
        ],
        gap_payload,
    );

    let leading_payload = [b"_".as_slice(), content].concat();
    let leading = synthetic_pfs0::pfs0(
        &[synthetic_pfs0::EntrySpec {
            name: "program.bin",
            offset: 1,
            size: content.len() as u64,
        }],
        &leading_payload,
    );

    for pfs0 in [trailing, gap, leading] {
        let fixture = synthetic_nsp_qualification::build_with_program_pfs0(pfs0);
        assert_not_qualified(&fixture.package, &fixture.key_file);
    }
}

#[test]
fn rejects_unreferenced_payload_in_meta_section_pfs0() {
    let fixture = synthetic_nsp_qualification::build_with_meta_cnmt_suffix(&[0xa5]);

    assert_not_qualified(&fixture.package, &fixture.key_file);
}

#[test]
fn rejects_a_truncated_cnmt_without_parsing_past_its_member() {
    let fixture = synthetic_nsp_qualification::build_with_cnmt_size(0x87);
    assert_eq!(
        not_qualified(&fixture.package, &fixture.key_file),
        NspSemanticQualificationReason::UnsupportedCnmtProfile
    );
}

#[test]
fn enforces_the_program_section_entry_count_ceiling() {
    let fixture = synthetic_nsp_qualification::build_with_program_entry_count(4097);
    let error = qualify(&fixture.package, &fixture.key_file).unwrap_err();
    assert_eq!(
        error.code(),
        nscb::NspSemanticQualificationErrorCode::Pfs0ResourceLimitExceeded
    );
}

#[test]
fn rejects_outer_pfs0_metadata_above_the_profile_limit_before_key_access() {
    let name = "n".repeat(4096);
    let entries = (0..257)
        .map(|_| synthetic_pfs0::EntrySpec {
            name: &name,
            offset: 0,
            size: 0,
        })
        .collect::<Vec<_>>();
    let package = synthetic_pfs0::pfs0(&entries, &[]);
    let input = synthetic_pfs0::TempInput::new(&package);
    let error = Engine::new()
        .qualify_nsp_semantics(NspSemanticQualificationRequest::new(
            input.path(),
            "/missing-key-file-is-not-opened",
        ))
        .expect_err("the outer metadata limit is checked before key access");

    assert_eq!(
        error.code(),
        nscb::NspSemanticQualificationErrorCode::Pfs0ResourceLimitExceeded
    );
}

#[test]
fn reports_missing_and_malformed_key_prerequisites_separately() {
    let fixture = synthetic_nsp_qualification::valid();
    let input = synthetic_pfs0::TempInput::new(&fixture.package);
    let only_application_key =
        format!("key_area_key_application_00 = {}\n", "24".repeat(16)).into_bytes();
    let keys = synthetic_pfs0::TempInput::new(&only_application_key);
    let error = Engine::new()
        .qualify_nsp_semantics(NspSemanticQualificationRequest::new(
            input.path(),
            keys.path(),
        ))
        .expect_err("the header key is a required prerequisite");
    assert_eq!(
        error.code(),
        nscb::NspSemanticQualificationErrorCode::MissingHeaderKey
    );

    let error = Engine::new()
        .qualify_nsp_semantics(NspSemanticQualificationRequest::new(
            input.path(),
            "/missing-qualification-key-file",
        ))
        .expect_err("an unavailable key file is an operational prerequisite failure");
    assert_eq!(
        error.code(),
        nscb::NspSemanticQualificationErrorCode::KeyFileUnavailable
    );

    let header_only = format!("header_key = {}\n", "42".repeat(32)).into_bytes();
    let error = qualify(&fixture.package, &header_only).unwrap_err();
    assert_eq!(
        error.code(),
        nscb::NspSemanticQualificationErrorCode::MissingApplicationKeyAreaKey
    );

    let malformed = format!(
        "header_key = {}\nkey_area_key_application_00 = short\n",
        "42".repeat(32)
    )
    .into_bytes();
    let error = qualify(&fixture.package, &malformed).unwrap_err();
    assert_eq!(
        error.code(),
        nscb::NspSemanticQualificationErrorCode::KeyFileMalformed
    );

    let wrong_kaek = synthetic_nsp_qualification::key_file_with_application_kaek([0x25; 16]);
    let error = qualify(&fixture.package, &wrong_kaek).unwrap_err();
    assert_eq!(
        error.code(),
        nscb::NspSemanticQualificationErrorCode::KeyOrSectionIntegrityFailure
    );

    let wrong_header_key = format!(
        "header_key = {}\nkey_area_key_application_00 = {}\n",
        "43".repeat(32),
        "24".repeat(16)
    )
    .into_bytes();
    assert_eq!(
        not_qualified(&fixture.package, &wrong_header_key),
        NspSemanticQualificationReason::InvalidNcaHeader
    );
}

#[test]
fn request_debug_output_does_not_expose_source_or_key_paths() {
    let request = NspSemanticQualificationRequest::new(
        "/private/account/source-secret.nsp",
        "/private/account/keys-secret.txt",
    );
    let debug = format!("{request:?}");
    assert!(!debug.contains("source-secret"));
    assert!(!debug.contains("keys-secret"));
    assert!(debug.contains("[REDACTED]"));
}

fn qualify(
    package: &[u8],
    key_file: &[u8],
) -> Result<nscb::NspSemanticQualificationResult, nscb::NspSemanticQualificationError> {
    let input = synthetic_pfs0::TempInput::new(package);
    let keys = synthetic_pfs0::TempInput::new(key_file);
    Engine::new().qualify_nsp_semantics(NspSemanticQualificationRequest::new(
        input.path(),
        keys.path(),
    ))
}

fn not_qualified(package: &[u8], key_file: &[u8]) -> NspSemanticQualificationReason {
    let result = qualify(package, key_file).expect("profile mismatch is not a prerequisite error");
    match result.outcome {
        NspSemanticQualificationOutcome::NotQualified(reason) => reason,
        NspSemanticQualificationOutcome::Qualified(_) => {
            panic!("the fixture does not match the supported profile")
        }
        _ => panic!("the fixture returned a future qualification outcome"),
    }
}

fn assert_not_qualified(package: &[u8], key_file: &[u8]) {
    let result = qualify(package, key_file).expect("profile mismatch is not an I/O failure");
    match result.outcome {
        NspSemanticQualificationOutcome::NotQualified(reason) => assert_eq!(
            reason,
            NspSemanticQualificationReason::UnaccountedPfs0Payload
        ),
        NspSemanticQualificationOutcome::Qualified(_) => {
            panic!("unaccounted PFS0 payload must not return Qualified")
        }
        _ => panic!("unaccounted payload returned an unexpected outcome"),
    }
}
