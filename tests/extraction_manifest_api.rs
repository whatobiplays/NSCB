use nscb::ExtractionManifestSource;

#[test]
fn extraction_manifest_source_keeps_its_existing_public_struct_shape() {
    let source = ExtractionManifestSource {
        profile: "nca3_program_partition_fs",
        role: "program",
        nca_type: "program",
        program_id: "0102030405060708".to_owned(),
        content_index: 0,
    };

    assert_eq!(
        serde_json::to_value(source).expect("serialize manifest source"),
        serde_json::json!({
            "profile": "nca3_program_partition_fs",
            "role": "program",
            "nca_type": "program",
            "program_id": "0102030405060708",
            "content_index": 0
        }),
    );
}
