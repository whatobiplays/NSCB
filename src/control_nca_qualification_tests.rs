use super::{
    Checkpoint, ControlNcaQualificationError, ControlNcaQualificationErrorCode as ErrorCode,
    ControlNcaQualificationOutcome as Outcome, ControlNcaQualificationReason as Reason,
    ControlNcaQualificationRequest, IVFC_BLOCK_SIZE, MAX_INPUT_BYTES, MAX_IVFC_HASH_OPERATIONS,
    check_input_size, hash_operation_count, is_supported_table_size, qualify,
    qualify_with_checkpoint,
};
use crate::allocation::AllocationSite;
use crate::control_nca_qualification::synthetic_fixture::{
    Fixture, Mutation, block_aligned_empty_romfs, build, empty_romfs, key_file_bytes,
    media_aligned_partial_empty_romfs, oversized_metadata_romfs, romfs_with_file,
    too_many_directories_romfs, write_u32, write_u64,
};
use crate::file_identity::{file_snapshot, path_identity};
use std::fs::{self, FileTimes, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

struct TempFile(PathBuf);

impl TempFile {
    fn new(bytes: &[u8]) -> Self {
        let id = NEXT_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "nscb-control-qualification-{}-{id}.bin",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create unique test input");
        file.write_all(bytes).expect("write test input");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn append(&self, bytes: &[u8]) {
        OpenOptions::new()
            .append(true)
            .open(&self.0)
            .expect("open test input for append")
            .write_all(bytes)
            .expect("append test bytes");
    }

    fn overwrite_start_with_modified_time(&self, bytes: &[u8], modified: SystemTime) {
        let original = self.snapshot();
        assert_ne!(
            Some(modified),
            original.modified,
            "test timestamp must differ from the original file snapshot"
        );
        OpenOptions::new()
            .write(true)
            .open(&self.0)
            .expect("open test input for overwrite")
            .write_all(bytes)
            .expect("overwrite test bytes");
        OpenOptions::new()
            .write(true)
            .open(&self.0)
            .expect("open test input to set its timestamp")
            .set_times(FileTimes::new().set_modified(modified))
            .expect("set distinct test modification time");
        assert_ne!(
            self.snapshot().modified,
            original.modified,
            "same-size overwrite must change the file snapshot timestamp"
        );
    }

    fn snapshot(&self) -> crate::file_identity::FileSnapshot {
        let metadata = fs::metadata(&self.0).expect("read test file metadata");
        file_snapshot(&metadata, path_identity(&self.0))
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn distinct_test_modified_time() -> SystemTime {
    // This FAT-compatible time makes the immediate overwrite visible in the file snapshot.
    SystemTime::UNIX_EPOCH + Duration::from_secs(946_684_800)
}

fn qualify_fixture(fixture: &Fixture) -> Result<Outcome, ControlNcaQualificationError> {
    let input = TempFile::new(&fixture.bytes);
    let key_file = TempFile::new(&key_file_bytes());
    qualify(ControlNcaQualificationRequest::new(
        input.path(),
        key_file.path(),
    ))
}

fn assert_reason(fixture: &Fixture, reason: Reason) {
    assert_eq!(
        qualify_fixture(fixture).expect("qualification completes"),
        Outcome::NotQualified(reason)
    );
}

fn rebuild_directory_hash_table(bytes: &mut [u8], assets_parent: u32) {
    let mut heads = [u32::MAX; 3];
    for (offset, parent, name, link_offset) in [
        (0, 0, &b""[..], 0x220),
        (24, assets_parent, &b"assets"[..], 0x238),
        (56, 0, &b"info"[..], 0x258),
    ] {
        let bucket = super::synthetic_fixture::bucket_hash(parent, name) % heads.len();
        write_u32(bytes, link_offset, heads[bucket]);
        heads[bucket] = offset;
    }
    for (bucket, head) in heads.into_iter().enumerate() {
        write_u32(bytes, 0x204 + bucket * 4, head);
    }
}

#[test]
fn independently_constructed_control_ncas_qualify_after_tree_rebuilds() {
    let mut changed_romfs = romfs_with_file();
    changed_romfs[0x200..0x204].copy_from_slice(b"DATA");
    let fixtures = [
        (build(&romfs_with_file(), Mutation::None), 3, 1),
        (build(&empty_romfs(), Mutation::None), 1, 0),
        (build(&changed_romfs, Mutation::None), 3, 1),
    ];

    for (fixture, directories, files) in fixtures {
        let outcome = qualify_fixture(&fixture).expect("qualification completes");
        let Outcome::Qualified(facts) = outcome else {
            panic!("dirs={directories} files={files}: {outcome:?}");
        };
        assert_eq!(facts.directory_count, directories);
        assert_eq!(facts.file_count, files);
    }
}

#[test]
fn master_hash_and_each_ivfc_level_are_checked() {
    let fixture = build(&romfs_with_file(), Mutation::CorruptMasterHash);
    assert_reason(&fixture, Reason::IvfcIntegrityFailure { level: 0 });

    let valid = build(&romfs_with_file(), Mutation::None);
    for level in 0..6 {
        let mut bytes = valid.bytes.clone();
        bytes[valid.section_start + valid.level_offsets[level]] ^= 1;
        let corrupted = Fixture {
            bytes,
            section_start: valid.section_start,
            level_offsets: valid.level_offsets,
        };
        assert_reason(
            &corrupted,
            Reason::IvfcIntegrityFailure { level: level as u8 },
        );
    }
}

#[test]
fn partial_block_hash_padding_is_separate_from_stored_padding() {
    let romfs = romfs_with_file();
    assert!(matches!(
        qualify_fixture(&build(&romfs, Mutation::None)).expect("qualification completes"),
        Outcome::Qualified(_)
    ));

    let valid = build(&romfs, Mutation::None);
    let mut root_padding = valid.bytes.clone();
    root_padding[valid.section_start + valid.level_offsets[0] + 32] ^= 1;
    assert_reason(
        &Fixture {
            bytes: root_padding,
            section_start: valid.section_start,
            level_offsets: valid.level_offsets,
        },
        Reason::InvalidIvfcPadding,
    );

    assert_reason(
        &build(&romfs, Mutation::NonzeroStoredTablePadding),
        Reason::InvalidIvfcPadding,
    );

    let mut physical_padding = valid.bytes.clone();
    physical_padding[valid.section_start + valid.level_offsets[5] + romfs.len()] ^= 1;
    assert_reason(
        &Fixture {
            bytes: physical_padding,
            section_start: valid.section_start,
            level_offsets: valid.level_offsets,
        },
        Reason::InvalidIvfcPadding,
    );
}

#[test]
fn one_block_section_tail_depends_on_romfs_descriptor_alignment() {
    let aligned = build(&block_aligned_empty_romfs(), Mutation::FullSectionTailBlock);
    assert!(matches!(
        qualify_fixture(&aligned).expect("qualification completes"),
        Outcome::Qualified(_)
    ));

    assert_reason(
        &build(
            &media_aligned_partial_empty_romfs(),
            Mutation::FullSectionTailBlock,
        ),
        Reason::InvalidIvfcLayout,
    );
}

#[test]
fn unsupported_nca_and_filesystem_profiles_are_rejected() {
    for (mutation, reason) in [
        (Mutation::WrongNcaMagic, Reason::InvalidNcaHeader),
        (Mutation::WrongContentType, Reason::UnsupportedNcaProfile),
        (Mutation::RightsBearing, Reason::RightsBearingContent),
        (Mutation::KeyGeneration(2), Reason::UnsupportedNcaProfile),
        (Mutation::WrongKaekIndex, Reason::UnsupportedNcaProfile),
        (Mutation::WrongFilesystem, Reason::UnsupportedNcaProfile),
        (Mutation::WrongHashType, Reason::UnsupportedNcaProfile),
        (Mutation::WrongEncryption, Reason::UnsupportedNcaProfile),
        (Mutation::ExtendedFilesystem, Reason::UnsupportedNcaProfile),
    ] {
        assert_reason(&build(&romfs_with_file(), mutation), reason);
    }
}

#[test]
fn additional_nca_partition_is_rejected() {
    assert_reason(
        &build(&romfs_with_file(), Mutation::AdditionalPartition),
        Reason::UnsupportedNcaProfile,
    );
}

#[test]
fn nonzero_reserved_filesystem_bytes_are_rejected() {
    assert_reason(
        &build(&romfs_with_file(), Mutation::NonzeroFilesystemReserved),
        Reason::UnsupportedNcaProfile,
    );
}

#[test]
fn malformed_ivfc_profiles_and_header_digests_are_rejected() {
    for mutation in [
        Mutation::WrongIvfcSignature,
        Mutation::WrongIvfcId,
        Mutation::WrongMasterHashSize,
        Mutation::WrongLevelCount,
        Mutation::WrongBlockExponent,
        Mutation::MisalignedDescriptor,
        Mutation::AliasedDescriptor,
        Mutation::NonzeroDescriptorReserved,
        Mutation::NonzeroIvfcReserved,
        Mutation::OverflowingDescriptor,
        Mutation::OutOfBoundsDescriptor,
    ] {
        assert_reason(
            &build(&romfs_with_file(), mutation),
            Reason::InvalidIvfcLayout,
        );
    }
    assert_reason(
        &build(&romfs_with_file(), Mutation::CorruptFilesystemDigest),
        Reason::InvalidNcaHeader,
    );
}

#[test]
fn malformed_romfs_layout_graph_and_hash_chains_are_rejected() {
    let mut bad_layout = romfs_with_file();
    write_u64(&mut bad_layout, 24, 0x211);
    assert_reason(
        &build(&bad_layout, Mutation::None),
        Reason::InvalidRomFsLayout,
    );

    let mut dangling_directory = romfs_with_file();
    write_u32(&mut dangling_directory, 0x218, 0x1234);
    assert_reason(
        &build(&dangling_directory, Mutation::None),
        Reason::InvalidRomFsGraph,
    );

    let mut cyclic_siblings = romfs_with_file();
    write_u32(&mut cyclic_siblings, 0x22c, 24);
    assert_reason(
        &build(&cyclic_siblings, Mutation::None),
        Reason::InvalidRomFsGraph,
    );

    let mut missing_bucket_heads = romfs_with_file();
    missing_bucket_heads[0x204..0x210].fill(0xff);
    assert_reason(
        &build(&missing_bucket_heads, Mutation::None),
        Reason::InvalidRomFsGraph,
    );

    let mut cyclic_hash_chain = romfs_with_file();
    write_u32(&mut cyclic_hash_chain, 0x258, 56);
    assert_reason(
        &build(&cyclic_hash_chain, Mutation::None),
        Reason::InvalidRomFsGraph,
    );

    let mut unreachable_directories = romfs_with_file();
    write_u32(&mut unreachable_directories, 0x218, u32::MAX);
    assert_reason(
        &build(&unreachable_directories, Mutation::None),
        Reason::InvalidRomFsGraph,
    );

    let mut wrong_parent = romfs_with_file();
    write_u32(&mut wrong_parent, 0x228, 7);
    rebuild_directory_hash_table(&mut wrong_parent, 7);
    assert_reason(
        &build(&wrong_parent, Mutation::None),
        Reason::InvalidRomFsGraph,
    );

    let mut malformed_root_record = romfs_with_file();
    write_u32(&mut malformed_root_record, 0x224, 1);
    assert_reason(
        &build(&malformed_root_record, Mutation::None),
        Reason::InvalidRomFsGraph,
    );

    let mut nonzero_record_padding = romfs_with_file();
    nonzero_record_padding[0x246] = 1;
    assert_reason(
        &build(&nonzero_record_padding, Mutation::None),
        Reason::InvalidRomFsGraph,
    );
}

#[test]
fn duplicate_romfs_names_and_invalid_file_extents_are_rejected() {
    let mut duplicate_name = romfs_with_file();
    duplicate_name.resize(0x298, 0);
    write_u64(&mut duplicate_name, 64, 0x28);
    write_u32(&mut duplicate_name, 0x21c, 0);
    write_u32(&mut duplicate_name, 0x234, u32::MAX);
    write_u32(&mut duplicate_name, 0x270, 0);
    write_u32(&mut duplicate_name, 0x28c, 6);
    duplicate_name[0x290..0x296].copy_from_slice(b"assets");
    duplicate_name[0x264..0x270].fill(0xff);
    let file_bucket = super::synthetic_fixture::bucket_hash(0, b"assets") % 3;
    write_u32(&mut duplicate_name, 0x264 + file_bucket * 4, 0);
    assert_reason(
        &build(&duplicate_name, Mutation::None),
        Reason::InvalidRomFsGraph,
    );

    for data_offset in [1_u64, 16] {
        let mut invalid_extent = romfs_with_file();
        write_u64(&mut invalid_extent, 0x278, data_offset);
        assert_reason(
            &build(&invalid_extent, Mutation::None),
            Reason::InvalidRomFsExtent,
        );
    }

    let mut crosses_file_data_end = romfs_with_file();
    write_u64(&mut crosses_file_data_end, 0x280, 5);
    assert_reason(
        &build(&crosses_file_data_end, Mutation::None),
        Reason::InvalidRomFsExtent,
    );

    let mut wrong_file_parent = romfs_with_file();
    write_u32(&mut wrong_file_parent, 0x270, 0);
    wrong_file_parent[0x264..0x270].fill(0xff);
    let file_bucket = super::synthetic_fixture::bucket_hash(0, b"data") % 3;
    write_u32(&mut wrong_file_parent, 0x264 + file_bucket * 4, 0);
    assert_reason(
        &build(&wrong_file_parent, Mutation::None),
        Reason::InvalidRomFsGraph,
    );
}

#[test]
fn metadata_record_and_key_file_ceilings_return_typed_resource_errors() {
    for romfs in [oversized_metadata_romfs(), too_many_directories_romfs()] {
        let error = qualify_fixture(&build(&romfs, Mutation::None))
            .expect_err("resource ceiling rejects the fixture");
        assert_eq!(error.code(), ErrorCode::ResourceLimitExceeded);
    }

    let fixture = build(&romfs_with_file(), Mutation::None);
    let input = TempFile::new(&fixture.bytes);
    let key_file = TempFile::new(b"");
    OpenOptions::new()
        .write(true)
        .open(key_file.path())
        .expect("open sparse oversized key fixture")
        .set_len(crate::key_file::MAX_KEY_FILE_BYTES + 1)
        .expect("extend key fixture beyond its bound");
    let request = ControlNcaQualificationRequest::new(input.path(), key_file.path());
    assert_eq!(
        qualify(request)
            .expect_err("oversized key file is refused")
            .code(),
        ErrorCode::KeyFileLimitExceeded
    );
}

#[test]
fn input_and_hash_operation_limits_include_the_boundary() {
    assert!(check_input_size(MAX_INPUT_BYTES).is_ok());
    assert_eq!(
        check_input_size(MAX_INPUT_BYTES + 1)
            .expect_err("input above the ceiling is refused")
            .code(),
        ErrorCode::InputLimitExceeded
    );

    let block_size = IVFC_BLOCK_SIZE as u64;
    let child_sizes = [1_u64, 1, 1, 1, MAX_INPUT_BYTES - 4];
    let sizes = [
        block_size,
        child_sizes[0],
        child_sizes[1],
        child_sizes[2],
        child_sizes[3],
        child_sizes[4],
    ];
    assert_eq!(hash_operation_count(sizes), Some(MAX_IVFC_HASH_OPERATIONS));
    assert_eq!(MAX_IVFC_HASH_OPERATIONS, 4_194_309);

    let required = block_size;
    assert!(is_supported_table_size(required, required));
    assert!(is_supported_table_size(required + block_size, required));
    assert!(!is_supported_table_size(
        required + 2 * block_size,
        required
    ));
}

#[test]
fn cancellation_is_observed_before_work_and_at_each_phase_boundary() {
    let fixture = build(&romfs_with_file(), Mutation::None);

    let input = TempFile::new(&fixture.bytes);
    let key_file = TempFile::new(&key_file_bytes());
    let cancellation = crate::CancellationHandle::new();
    cancellation.cancel();
    let request = ControlNcaQualificationRequest::new(input.path(), key_file.path())
        .with_cancellation(cancellation);
    assert_eq!(
        qualify(request)
            .expect_err("pre-cancelled work is refused")
            .code(),
        ErrorCode::Cancelled
    );

    for target in [
        Checkpoint::InputOpened,
        Checkpoint::KeysRead,
        Checkpoint::HeaderRead,
        Checkpoint::IvfcBlock,
        Checkpoint::RomFsMetadata,
        Checkpoint::BeforeFinalRevalidation,
    ] {
        let input = TempFile::new(&fixture.bytes);
        let key_file = TempFile::new(&key_file_bytes());
        let cancellation = crate::CancellationHandle::new();
        let request = ControlNcaQualificationRequest::new(input.path(), key_file.path())
            .with_cancellation(cancellation.clone());
        let mut reached = false;
        let error = qualify_with_checkpoint(request, |checkpoint| {
            if checkpoint == target {
                cancellation.cancel();
                reached = true;
            }
        })
        .expect_err("phase cancellation is returned");
        assert!(reached, "checkpoint {target:?} was not reached");
        assert_eq!(error.code(), ErrorCode::Cancelled, "checkpoint {target:?}");
    }
}

#[test]
fn record_count_scanning_observes_cancellation() {
    let cancellation = crate::CancellationHandle::new();
    cancellation.cancel();
    let request = ControlNcaQualificationRequest::new("unused.nca", "unused.keys")
        .with_cancellation(cancellation);
    let error = super::scan_record_count(&[0; 0x18], 0x18, 20, true, &request)
        .expect_err("record scanning checks cancellation before reading records");
    assert_eq!(error.code(), ErrorCode::Cancelled);
}

#[test]
fn unavailable_input_and_key_files_return_sanitized_errors() {
    let fixture = build(&romfs_with_file(), Mutation::None);
    let input = TempFile::new(&fixture.bytes);
    let key_file = TempFile::new(&key_file_bytes());
    let missing_input = input.path().to_owned();
    drop(input);
    let request = ControlNcaQualificationRequest::new(&missing_input, key_file.path());
    assert_eq!(
        qualify(request)
            .expect_err("missing input is refused")
            .code(),
        ErrorCode::InputUnavailable
    );

    let input = TempFile::new(&fixture.bytes);
    let missing_key_file = key_file.path().to_owned();
    drop(key_file);
    let request = ControlNcaQualificationRequest::new(input.path(), &missing_key_file);
    assert_eq!(
        qualify(request)
            .expect_err("missing key file is refused")
            .code(),
        ErrorCode::KeyFileUnavailable
    );
}

#[test]
fn qualification_leaves_source_and_key_files_unchanged() {
    let fixture = build(&romfs_with_file(), Mutation::None);
    let input = TempFile::new(&fixture.bytes);
    let key_bytes = key_file_bytes();
    let key_file = TempFile::new(&key_bytes);
    let input_snapshot = input.snapshot();
    let key_snapshot = key_file.snapshot();

    let outcome = qualify(ControlNcaQualificationRequest::new(
        input.path(),
        key_file.path(),
    ))
    .expect("qualification completes");
    assert!(matches!(outcome, Outcome::Qualified(_)));
    assert_eq!(
        fs::read(input.path()).expect("read qualified source"),
        fixture.bytes
    );
    assert_eq!(fs::read(key_file.path()).expect("read key file"), key_bytes);
    assert_eq!(input.snapshot(), input_snapshot);
    assert_eq!(key_file.snapshot(), key_snapshot);
}

#[test]
fn source_and_key_mutation_are_detected_after_open() {
    let fixture = build(&romfs_with_file(), Mutation::None);
    let input = TempFile::new(&fixture.bytes);
    let key_file = TempFile::new(&key_file_bytes());
    let request = ControlNcaQualificationRequest::new(input.path(), key_file.path());
    let mut changed = false;
    let error = qualify_with_checkpoint(request, |checkpoint| {
        if !changed && checkpoint == Checkpoint::InputOpened {
            input.append(b"source changed");
            changed = true;
        }
    })
    .expect_err("changed source is rejected");
    assert!(changed);
    assert_eq!(error.code(), ErrorCode::InputChangedDuringQualification);

    let input = TempFile::new(&fixture.bytes);
    let key_file = TempFile::new(&key_file_bytes());
    let request = ControlNcaQualificationRequest::new(input.path(), key_file.path());
    let mut changed = false;
    let error = qualify_with_checkpoint(request, |checkpoint| {
        if !changed && checkpoint == Checkpoint::KeysRead {
            key_file.append(b"\n# changed after read\n");
            changed = true;
        }
    })
    .expect_err("changed key file is rejected");
    assert!(changed);
    assert_eq!(error.code(), ErrorCode::KeyFileChangedDuringQualification);

    let input = TempFile::new(&fixture.bytes);
    let key_file = TempFile::new(&key_file_bytes());
    let request = ControlNcaQualificationRequest::new(input.path(), key_file.path());
    let mut changed = false;
    let error = qualify_with_checkpoint(request, |checkpoint| {
        if !changed && checkpoint == Checkpoint::InputOpened {
            input.overwrite_start_with_modified_time(b"X", distinct_test_modified_time());
            changed = true;
        }
    })
    .expect_err("same-size source mutation is rejected");
    assert!(changed);
    assert_eq!(error.code(), ErrorCode::InputChangedDuringQualification);

    let input = TempFile::new(&fixture.bytes);
    let key_file = TempFile::new(&key_file_bytes());
    let request = ControlNcaQualificationRequest::new(input.path(), key_file.path());
    let mut changed = false;
    let error = qualify_with_checkpoint(request, |checkpoint| {
        if !changed && checkpoint == Checkpoint::KeysRead {
            key_file.overwrite_start_with_modified_time(b"#", distinct_test_modified_time());
            changed = true;
        }
    })
    .expect_err("same-size key mutation is rejected");
    assert!(changed);
    assert_eq!(error.code(), ErrorCode::KeyFileChangedDuringQualification);
}

#[test]
fn expected_key_snapshot_and_secret_redaction_are_enforced() {
    let fixture = build(&romfs_with_file(), Mutation::None);
    let input = TempFile::new(&fixture.bytes);
    let key_file = TempFile::new(&key_file_bytes());
    let expected_snapshot = key_file.snapshot();
    key_file.append(b"# changed\n");
    let request = ControlNcaQualificationRequest::new(input.path(), key_file.path())
        .with_expected_key_snapshot(expected_snapshot);
    let error = qualify(request).expect_err("stale key snapshot is rejected");
    assert_eq!(error.code(), ErrorCode::KeyFileChangedDuringQualification);

    let input = TempFile::new(&fixture.bytes);
    let secret = b"UNIQUE_SYNTHETIC_SECRET_SENTINEL";
    let key_file = TempFile::new(secret);
    let request = ControlNcaQualificationRequest::new(input.path(), key_file.path());
    let debug = format!("{request:?}");
    assert!(!debug.contains(&input.path().to_string_lossy().to_string()));
    assert!(!debug.contains(&key_file.path().to_string_lossy().to_string()));
    assert!(!debug.contains(std::str::from_utf8(secret).unwrap()));
    let error = qualify(request).expect_err("malformed test key file is rejected");
    assert_eq!(error.code(), ErrorCode::KeyFileMalformed);
    assert!(!format!("{error}").contains(&input.path().to_string_lossy().to_string()));
    assert!(!format!("{error}").contains(&key_file.path().to_string_lossy().to_string()));
    assert!(!format!("{error:?}").contains(&input.path().to_string_lossy().to_string()));
    assert!(!format!("{error:?}").contains(&key_file.path().to_string_lossy().to_string()));
    assert!(!format!("{error}").contains(std::str::from_utf8(secret).unwrap()));
    assert!(!format!("{error:?}").contains(std::str::from_utf8(secret).unwrap()));
}

#[test]
fn bounded_allocation_refusals_remain_typed() {
    for (site, occurrence) in [
        (AllocationSite::ControlIvfcHashBuffer, 1),
        (AllocationSite::ControlRomfsMetadata, 1),
        (AllocationSite::ControlRomfsRecords, 1),
        (AllocationSite::ControlRomfsRecords, 2),
        (AllocationSite::ControlRomfsTraversal, 1),
        (AllocationSite::ControlRomfsTraversal, 2),
        (AllocationSite::ControlRomfsNames, 1),
        (AllocationSite::ControlRomfsExtents, 1),
    ] {
        let fixture = build(&romfs_with_file(), Mutation::None);
        let input = TempFile::new(&fixture.bytes);
        let key_bytes = key_file_bytes();
        let key_file = TempFile::new(&key_bytes);
        let input_snapshot = input.snapshot();
        let key_snapshot = key_file.snapshot();
        let request = ControlNcaQualificationRequest::new(input.path(), key_file.path());
        let (result, observation) =
            crate::test_allocator::with_refusal(site, occurrence, || qualify(request));
        assert!(
            observation.is_exact_refusal(site, occurrence),
            "{site:?} occurrence {occurrence}: {observation:?}"
        );
        assert_eq!(
            result
                .expect_err("refused allocation returns a typed error")
                .code(),
            ErrorCode::AllocationFailed,
            "{site:?} occurrence {occurrence}"
        );
        assert_eq!(
            fs::read(input.path()).expect("read source after refusal"),
            fixture.bytes
        );
        assert_eq!(
            fs::read(key_file.path()).expect("read key after refusal"),
            key_bytes
        );
        assert_eq!(input.snapshot(), input_snapshot);
        assert_eq!(key_file.snapshot(), key_snapshot);
    }
}
