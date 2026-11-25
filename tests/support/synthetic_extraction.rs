//! Synthetic keyed NCA3 inputs for public Engine extraction tests.
//!
//! Headers and keys come from the verification test fixture. Partition payloads
//! stay clear and use the supported unhashed PartitionFs profile.

use crate::support::synthetic_verification::{
    PARTITION_OFFSET, PARTITION_SIZE, Spec, build as build_nca,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

/// Program ID encoded by the synthetic NCA header.
pub const PROGRAM_ID: u64 = 0x0102_0304_0506_0708;

/// One source file whose published bytes are checked by an extraction test.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedFile {
    /// NCA partition containing the source file.
    pub partition_index: u8,
    /// Exact path relative to the partition root.
    pub path: String,
    /// Expected regular-file contents.
    pub bytes: Vec<u8>,
}

/// Keyed source paths, source bytes, and expected payloads for an Engine test.
pub struct SyntheticExtractionFixture {
    _directory: TempDir,
    /// Path to the synthetic standalone Program NCA.
    pub source: PathBuf,
    /// Path to the file containing its synthetic header key.
    pub key_file: PathBuf,
    /// Original source bytes, for preservation checks.
    pub source_bytes: Vec<u8>,
    /// Original key-file bytes, for preservation checks.
    pub key_file_bytes: Vec<u8>,
    /// Files expected from a complete extraction.
    pub expected_files: Vec<ExpectedFile>,
}

impl SyntheticExtractionFixture {
    /// Builds a two-partition Program with nested, zero-byte, and regular files.
    pub fn populated() -> Self {
        let mut built = build_nca(Spec {
            distribution: 0,
            extra_partitions: 1,
            ..Spec::default()
        });
        let program_files =
            read_pfs0(&built.nca[PARTITION_OFFSET..PARTITION_OFFSET + PARTITION_SIZE]);
        let mut program_files = program_files;
        program_files.extend([
            (
                "nested/program.bin".to_owned(),
                b"nested program bytes".to_vec(),
            ),
            ("empty.dat".to_owned(), Vec::new()),
            ("readme.txt".to_owned(), b"program partition bytes".to_vec()),
        ]);
        replace_first_partition(&mut built.nca, &program_files);

        let mut expected_files = program_files
            .into_iter()
            .map(|(path, bytes)| ExpectedFile {
                partition_index: 0,
                path,
                bytes,
            })
            .collect::<Vec<_>>();
        expected_files.push(ExpectedFile {
            partition_index: 1,
            path: "extra1.bin".to_owned(),
            bytes: b"extra1".to_vec(),
        });
        Self::write(built.nca, built.keys_file, expected_files)
    }

    /// Adds a payload to the synthetic Program NCA and updates the extraction expectations.
    #[allow(dead_code)]
    pub fn with_program_file(mut self, path: String, bytes: Vec<u8>) -> Self {
        let mut files =
            read_pfs0(&self.source_bytes[PARTITION_OFFSET..PARTITION_OFFSET + PARTITION_SIZE]);
        files.push((path.clone(), bytes.clone()));
        replace_first_partition(&mut self.source_bytes, &files);
        fs::write(&self.source, &self.source_bytes).expect("write updated synthetic NCA");
        self.expected_files.push(ExpectedFile {
            partition_index: 0,
            path,
            bytes,
        });
        self
    }

    /// Builds a valid empty PartitionFs followed by one populated partition.
    pub fn empty_first_partition() -> Self {
        let mut built = build_nca(Spec {
            distribution: 0,
            extra_partitions: 1,
            ..Spec::default()
        });
        replace_first_partition(&mut built.nca, &[]);
        Self::write(
            built.nca,
            built.keys_file,
            vec![ExpectedFile {
                partition_index: 1,
                path: "extra1.bin".to_owned(),
                bytes: b"extra1".to_vec(),
            }],
        )
    }

    fn write(nca: Vec<u8>, key_file_bytes: Vec<u8>, expected_files: Vec<ExpectedFile>) -> Self {
        let directory = tempfile::tempdir().expect("create extraction fixture directory");
        assert_local_apfs(directory.path());
        let source = directory.path().join("program.nca");
        let key_file = directory.path().join("prod.keys");
        fs::write(&source, &nca).expect("write synthetic Program NCA");
        fs::write(&key_file, &key_file_bytes).expect("write synthetic header key");
        Self {
            _directory: directory,
            source,
            key_file,
            source_bytes: nca,
            key_file_bytes,
            expected_files,
        }
    }
}

fn replace_first_partition(nca: &mut [u8], files: &[(String, Vec<u8>)]) {
    let partition = pfs0(files);
    assert!(partition.len() <= PARTITION_SIZE);
    let mut padded = vec![0; PARTITION_SIZE];
    padded[..partition.len()].copy_from_slice(&partition);
    nca[PARTITION_OFFSET..PARTITION_OFFSET + PARTITION_SIZE].copy_from_slice(&padded);
}

fn read_pfs0(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    assert_eq!(&bytes[..4], b"PFS0");
    let count = read_u32(bytes, 4) as usize;
    let string_size = read_u32(bytes, 8) as usize;
    let string_start = 0x10 + count * 0x18;
    let data_start = string_start + string_size;
    let strings = &bytes[string_start..data_start];
    (0..count)
        .map(|index| {
            let record = 0x10 + index * 0x18;
            let data_offset = read_u64(bytes, record) as usize;
            let data_size = read_u64(bytes, record + 8) as usize;
            let name_offset = read_u32(bytes, record + 0x10) as usize;
            let name_end = strings[name_offset..]
                .iter()
                .position(|byte| *byte == 0)
                .expect("PFS0 name has a terminator");
            let name = std::str::from_utf8(&strings[name_offset..name_offset + name_end])
                .expect("synthetic PFS0 name is UTF-8")
                .to_owned();
            let data =
                bytes[data_start + data_offset..data_start + data_offset + data_size].to_vec();
            (name, data)
        })
        .collect()
}

fn pfs0(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut strings = Vec::new();
    let mut records = Vec::with_capacity(files.len());
    let mut payload = Vec::new();
    for (name, bytes) in files {
        let name_offset = u32::try_from(strings.len()).expect("fixture name table fits");
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        let data_offset = u64::try_from(payload.len()).expect("fixture payload fits");
        let data_size = u64::try_from(bytes.len()).expect("fixture file size fits");
        records.push((data_offset, data_size, name_offset));
        payload.extend_from_slice(bytes);
    }

    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PFS0");
    bytes.extend_from_slice(
        &u32::try_from(files.len())
            .expect("fixture file count fits")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(
        &u32::try_from(strings.len())
            .expect("fixture name table fits")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    for (data_offset, data_size, name_offset) in records {
        bytes.extend_from_slice(&data_offset.to_le_bytes());
        bytes.extend_from_slice(&data_size.to_le_bytes());
        bytes.extend_from_slice(&name_offset.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
    }
    bytes.extend_from_slice(&strings);
    bytes.extend_from_slice(&payload);
    bytes
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn assert_local_apfs(path: &Path) {
    let output = Command::new("/bin/df")
        .args(["-P", path.to_str().expect("fixture path is UTF-8")])
        .output()
        .expect("resolve the fixture filesystem device");
    assert!(output.status.success(), "df failed for {path:?}");
    let filesystem = String::from_utf8(output.stdout).expect("df output is UTF-8");
    let device = filesystem
        .lines()
        .last()
        .and_then(|line| line.split_whitespace().next())
        .expect("df reports a filesystem device");
    assert!(
        device.starts_with("/dev/disk"),
        "fixture directory must reside on a local disk: {device}"
    );
    let output = Command::new("/usr/sbin/diskutil")
        .args(["info", device])
        .output()
        .expect("inspect the fixture filesystem with diskutil");
    assert!(output.status.success(), "diskutil info failed for {device}");
    let details = String::from_utf8(output.stdout).expect("diskutil output is UTF-8");
    assert_eq!(field(&details, "File System Personality"), Some("APFS"));
}

fn field<'a>(details: &'a str, name: &str) -> Option<&'a str> {
    details.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == name).then_some(value.trim())
    })
}
