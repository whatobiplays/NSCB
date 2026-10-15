mod support;

use nscb::{ContainerFormat, ContainerProbeErrorCode, ContainerProbeRequest, Engine};
use std::fs;
use support::synthetic_pfs0::{TempInput, valid_container_probe_fixture};

#[test]
fn public_engine_reports_validated_outer_pfs0_structure_without_changing_input() {
    let bytes = valid_container_probe_fixture();
    let input = TempInput::new(&bytes);
    let engine = Engine::new();

    let result = engine
        .probe_container(ContainerProbeRequest::new(input.path()))
        .expect("a valid synthetic PFS0 container can be probed without keys");

    assert_eq!(result.format, ContainerFormat::Pfs0);
    assert_eq!(result.file_size, 52);
    assert_eq!(result.payload_offset, 46);
    assert_eq!(result.payload_size, 6);
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].name, "a\"\n\\b");
    assert_eq!(result.entries[0].offset, 2);
    assert_eq!(result.entries[0].size, 4);
    assert_eq!(result.entries[0].file_offset, 48);
    assert_eq!(
        fs::read(input.path()).expect("read fixture after probe"),
        bytes
    );
}

#[test]
fn public_engine_classifies_malformed_inputs_with_sanitized_probe_errors() {
    let valid = valid_container_probe_fixture();
    let mut invalid_header = valid.clone();
    invalid_header[12] = 1;

    let mut invalid_utf8_name = valid.clone();
    invalid_utf8_name[40] = 0xff;

    let mut invalid_name_offset = valid.clone();
    invalid_name_offset[32..36].copy_from_slice(&u32::MAX.to_le_bytes());

    let mut truncated = valid.clone();
    truncated.pop();

    let mut overflowing_entry = valid.clone();
    overflowing_entry[16..24].copy_from_slice(&u64::MAX.to_le_bytes());

    let mut oversized = valid;
    oversized[4..8].copy_from_slice(&65_537_u32.to_le_bytes());

    let cases = [
        (
            b"not a PFS0 container".as_slice(),
            ContainerProbeErrorCode::UnsupportedFormat,
        ),
        (b"PFS0".as_slice(), ContainerProbeErrorCode::TruncatedInput),
        (
            invalid_header.as_slice(),
            ContainerProbeErrorCode::InvalidHeader,
        ),
        (
            invalid_utf8_name.as_slice(),
            ContainerProbeErrorCode::InvalidStringTable,
        ),
        (
            invalid_name_offset.as_slice(),
            ContainerProbeErrorCode::InvalidStringTable,
        ),
        (
            truncated.as_slice(),
            ContainerProbeErrorCode::TruncatedInput,
        ),
        (
            overflowing_entry.as_slice(),
            ContainerProbeErrorCode::InvalidEntry,
        ),
        (oversized.as_slice(), ContainerProbeErrorCode::LimitExceeded),
    ];

    for (bytes, expected_code) in cases {
        let input = TempInput::new(bytes);
        let error = Engine::new()
            .probe_container(ContainerProbeRequest::new(input.path()))
            .expect_err("malformed input must fail without panicking");

        assert_eq!(error.code(), expected_code);
        assert!(
            !error
                .to_string()
                .contains(input.path().to_string_lossy().as_ref())
        );
        assert!(!error.to_string().contains("PFS0 container"));
        assert_eq!(
            fs::read(input.path()).expect("read malformed fixture"),
            bytes
        );
    }
}

#[test]
fn public_engine_reports_a_missing_input_without_disclosing_its_path() {
    let input = TempInput::new(&valid_container_probe_fixture());
    fs::remove_file(input.path()).expect("remove temporary input before probing");

    let error = Engine::new()
        .probe_container(ContainerProbeRequest::new(input.path()))
        .expect_err("an unavailable input must return a typed error");

    assert_eq!(error.code(), ContainerProbeErrorCode::InputUnavailable);
    assert_eq!(error.to_string(), "the input could not be read");
    assert!(
        !error
            .to_string()
            .contains(input.path().to_string_lossy().as_ref())
    );
}
#[test]
fn public_engine_rejects_a_directory_as_container_input() {
    let input = TempInput::new(&valid_container_probe_fixture());
    let directory = input
        .path()
        .parent()
        .expect("temporary input has a parent directory");

    let error = Engine::new()
        .probe_container(ContainerProbeRequest::new(directory))
        .expect_err("a directory is not a regular container file");

    assert_eq!(error.code(), ContainerProbeErrorCode::InputUnavailable);
    assert_eq!(error.to_string(), "the input could not be read");
}

#[test]
fn recognition_preserves_input_and_observes_only_ticket_names() {
    let bytes = support::synthetic_pfs0::pfs0(
        &[support::synthetic_pfs0::EntrySpec {
            name: "unvalidated.tik",
            offset: 0,
            size: 4,
        }],
        b"FAKE",
    );
    let input = support::synthetic_pfs0::TempInput::new(&bytes);
    let result = nscb::Engine::new()
        .recognize_content(nscb::ContentRecognitionRequest::new(input.path()))
        .unwrap();
    assert_eq!(
        result.package_structure_eligibility,
        nscb::StructuralEligibility::NotEstablished
    );
    assert_eq!(
        result.ticket_name_observation,
        nscb::TicketNameObservation::Present
    );
    assert_eq!(std::fs::read(input.path()).unwrap(), bytes);
    let error = nscb::Engine::new()
        .recognize_content(nscb::ContentRecognitionRequest::new(std::env::temp_dir()))
        .unwrap_err();
    assert_eq!(
        error.code(),
        nscb::ContentRecognitionErrorCode::InputUnavailable
    );
    assert_eq!(error.to_string(), "input_unavailable");
}
