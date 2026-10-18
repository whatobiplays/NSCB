//! Internal parser for the NCA3 header facts used by Inspection.
//!
//! The parser accepts only encrypted NCA headers with the caller-supplied XTS
//! header key. It deliberately returns only header facts;
//! filesystem payload validation belongs to the operation that owns that
//! partition. Signature, authenticity, and integrity are not established here.
use crate::inspection::InspectionErrorCode;
use aes::Aes128;
use aes::cipher::KeyInit;
use aes::cipher::generic_array::GenericArray;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use xts_mode::Xts128;

pub(crate) const HEADER_SIZE: usize = 0xc00;
const PAGE_SIZE: u64 = 0x200;
const MAX_PARTITIONS: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeaderError {
    UnsupportedFormat,
    TruncatedInput,
    MalformedInput,
    InputUnavailable,
}

impl HeaderError {
    pub(crate) const fn code(self) -> InspectionErrorCode {
        match self {
            Self::UnsupportedFormat => InspectionErrorCode::UnsupportedFormat,
            Self::TruncatedInput => InspectionErrorCode::TruncatedInput,
            Self::MalformedInput => InspectionErrorCode::MalformedInput,
            Self::InputUnavailable => InspectionErrorCode::InputUnavailable,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Distribution {
    Download,
    GameCard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ContentType {
    Program,
    Meta,
    Control,
    Manual,
    Data,
    PublicData,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Partition {
    pub(crate) index: u8,
    pub(crate) offset: u64,
    pub(crate) size: u64,
    pub(crate) filesystem: u8,
    pub(crate) hash_type: u8,
    pub(crate) encryption: u8,
    pub(crate) extended: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Header {
    pub(crate) format_version: u8,
    pub(crate) distribution: Distribution,
    pub(crate) content_type: ContentType,
    pub(crate) key_generation: u8,
    pub(crate) signature_generation: u8,
    pub(crate) kaek_index: u8,
    pub(crate) declared_size: u64,
    pub(crate) program_id: u64,
    pub(crate) content_index: u32,
    pub(crate) partitions: Vec<Partition>,
}

pub(crate) fn read_header(
    file: &mut File,
    file_size: u64,
    header_key: &[u8; 32],
) -> Result<Header, HeaderError> {
    if file_size < HEADER_SIZE as u64 {
        return Err(HeaderError::TruncatedInput);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| HeaderError::InputUnavailable)?;
    let mut block = [0_u8; HEADER_SIZE];
    file.read_exact(&mut block)
        .map_err(|_| HeaderError::InputUnavailable)?;
    if &block[0x200..0x204] == b"NCA3" {
        return Err(HeaderError::UnsupportedFormat);
    }
    decrypt_header(&mut block, header_key);
    if &block[0x200..0x204] != b"NCA3" {
        return Err(HeaderError::UnsupportedFormat);
    }
    parse_header_block(&block, file_size)
}

fn decrypt_header(block: &mut [u8; HEADER_SIZE], key: &[u8; 32]) {
    let first = Aes128::new(GenericArray::from_slice(&key[..0x10]));
    let second = Aes128::new(GenericArray::from_slice(&key[0x10..]));
    let xts = Xts128::new(first, second);
    xts.decrypt_area(&mut block[..0x400], 0x200, 0, nintendo_tweak);
    xts.decrypt_area(&mut block[0x400..], 0x200, 2, nintendo_tweak);
}

fn nintendo_tweak(index: u128) -> [u8; 16] {
    index.to_be_bytes()
}

/// Validates the common NCA3 header and partition descriptors from a complete
/// header block whose declared size is measured relative to that block.
///
/// Recognition uses this same structural validation before applying its own
/// read-only profile checks. Filesystem-layer layout checks that depend on a
/// particular support profile remain with the operation that supports it.
pub(crate) fn parse_header_block(
    block: &[u8; HEADER_SIZE],
    file_size: u64,
) -> Result<Header, HeaderError> {
    let distribution = match block[0x204] {
        0 => Distribution::Download,
        1 => Distribution::GameCard,
        _ => return Err(HeaderError::MalformedInput),
    };
    let content_type = match block[0x205] {
        0 => ContentType::Program,
        1 => ContentType::Meta,
        2 => ContentType::Control,
        3 => ContentType::Manual,
        4 => ContentType::Data,
        5 => ContentType::PublicData,
        _ => return Err(HeaderError::MalformedInput),
    };
    let declared_size = u64le(&block[0x208..0x210]);
    if declared_size != file_size {
        return Err(HeaderError::MalformedInput);
    }
    if !(block[0x207] < 3 || block[0x207] == 0xff)
        || block[0x222..0x230].iter().any(|byte| *byte != 0)
    {
        return Err(HeaderError::MalformedInput);
    }

    let mut previous_end = HEADER_SIZE as u64;
    let mut absent = false;
    let mut partitions = Vec::new();
    for index in 0..MAX_PARTITIONS {
        let descriptor = &block[0x240 + index * 16..0x250 + index * 16];
        let offset = u32le(&descriptor[..4])
            .checked_mul(PAGE_SIZE)
            .ok_or(HeaderError::MalformedInput)?;
        let end = u32le(&descriptor[4..8])
            .checked_mul(PAGE_SIZE)
            .ok_or(HeaderError::MalformedInput)?;
        let fs = &block[0x400 + index * 0x200..0x600 + index * 0x200];
        if offset == 0 && end == 0 {
            absent = true;
            if descriptor.iter().any(|byte| *byte != 0) || fs.iter().any(|byte| *byte != 0) {
                return Err(HeaderError::MalformedInput);
            }
            continue;
        }
        if absent || offset < previous_end || end <= offset || end > file_size {
            return Err(HeaderError::MalformedInput);
        }
        let size = end - offset;
        if u32le(&descriptor[8..12])
            .checked_mul(PAGE_SIZE)
            .is_none_or(|target| target > size)
            || descriptor[12..].iter().any(|byte| *byte != 0)
            || fs[..2] != [2, 0]
            || fs[2] > 1
            || !(1..=6).contains(&fs[3])
            || !(1..=6).contains(&fs[4])
            || fs[5] > 1
            || fs[6..8].iter().any(|byte| *byte != 0)
        {
            return Err(HeaderError::MalformedInput);
        }
        previous_end = end;
        partitions.push(Partition {
            index: index as u8,
            offset,
            size,
            filesystem: fs[2],
            hash_type: fs[3],
            encryption: fs[4],
            extended: fs[5] != 0,
        });
    }
    if partitions.is_empty() {
        return Err(HeaderError::MalformedInput);
    }
    Ok(Header {
        format_version: 3,
        distribution,
        content_type,
        key_generation: block[0x206].max(block[0x220]),
        signature_generation: block[0x221],
        kaek_index: block[0x207],
        declared_size,
        program_id: u64le(&block[0x210..0x218]),
        content_index: u32le(&block[0x218..0x21c]) as u32,
        partitions,
    })
}

fn u32le(bytes: &[u8]) -> u64 {
    u64::from(u32::from_le_bytes(bytes.try_into().expect("four bytes")))
}

fn u64le(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("eight bytes"))
}

/// Builds a synthetic plaintext standalone NCA3 image for input-policy tests.
#[cfg(test)]
pub(crate) fn synthetic_plaintext_supported_nca() -> Vec<u8> {
    const PARTITION_OFFSET: usize = HEADER_SIZE;
    const PARTITION_SIZE: usize = 0x200;
    const FILE_NAME: &[u8] = b"hello.nca";
    const FILE_BYTES: &[u8] = b"data";

    let string_table_size = FILE_NAME.len() + 1;
    let data_offset = 16 + 24 + string_table_size;
    let mut partition = vec![0_u8; PARTITION_SIZE];
    partition[..4].copy_from_slice(b"PFS0");
    partition[4..8].copy_from_slice(&1_u32.to_le_bytes());
    partition[8..12].copy_from_slice(&(string_table_size as u32).to_le_bytes());
    partition[16..24].copy_from_slice(&0_u64.to_le_bytes());
    partition[24..32].copy_from_slice(&(FILE_BYTES.len() as u64).to_le_bytes());
    partition[32..36].copy_from_slice(&0_u32.to_le_bytes());
    partition[40..40 + FILE_NAME.len()].copy_from_slice(FILE_NAME);
    partition[data_offset..data_offset + FILE_BYTES.len()].copy_from_slice(FILE_BYTES);

    let mut nca = vec![0_u8; PARTITION_OFFSET + PARTITION_SIZE];
    nca[0x200..0x204].copy_from_slice(b"NCA3");
    nca[0x204] = 1;
    nca[0x205] = 0;
    nca[0x206] = 0;
    nca[0x207] = 0;
    nca[0x208..0x210].copy_from_slice(&((PARTITION_OFFSET + PARTITION_SIZE) as u64).to_le_bytes());
    nca[0x210..0x218].copy_from_slice(&0x0102_0304_0506_0708_u64.to_le_bytes());
    nca[0x218..0x21c].copy_from_slice(&0_u32.to_le_bytes());
    nca[0x240..0x244].copy_from_slice(&6_u32.to_le_bytes());
    nca[0x244..0x248].copy_from_slice(&7_u32.to_le_bytes());
    nca[0x248..0x24c].copy_from_slice(&1_u32.to_le_bytes());
    nca[0x400..0x402].copy_from_slice(&[2, 0]);
    nca[0x402] = 1;
    nca[0x403] = 1;
    nca[0x404] = 1;
    let fs_header_hash = <sha2::Sha256 as sha2::Digest>::digest(&nca[0x400..0x600]);
    nca[0x280..0x2a0].copy_from_slice(&fs_header_hash);
    nca[PARTITION_OFFSET..].copy_from_slice(&partition);
    nca
}

/// Builds a synthetic encrypted NCA for provider-boundary tests. The fixed
/// test key is not a production credential.
#[cfg(test)]
pub(crate) fn synthetic_supported_nca() -> Vec<u8> {
    synthetic_nca_with_header_fields(0, 0, 0, 0)
}

/// Builds a synthetic encrypted NCA with independently selected header fields.
/// The fixed AES key is test data and is never a production credential.
#[cfg(test)]
pub(crate) fn synthetic_nca_with_header_fields(
    legacy_generation: u8,
    modern_generation: u8,
    signature_generation: u8,
    kaek_index: u8,
) -> Vec<u8> {
    synthetic_nca_with_header_fields_and_key(
        legacy_generation,
        modern_generation,
        signature_generation,
        kaek_index,
        &[0x42; 32],
    )
}

/// Builds a synthetic encrypted NCA using a caller-selected test header key.
#[cfg(test)]
pub(crate) fn synthetic_nca_with_header_fields_and_key(
    legacy_generation: u8,
    modern_generation: u8,
    signature_generation: u8,
    kaek_index: u8,
    header_key: &[u8; 32],
) -> Vec<u8> {
    let mut nca = synthetic_plaintext_supported_nca();
    nca[0x206] = legacy_generation;
    nca[0x207] = kaek_index;
    nca[0x220] = modern_generation;
    nca[0x221] = signature_generation;
    let first = Aes128::new(GenericArray::from_slice(&header_key[..0x10]));
    let second = Aes128::new(GenericArray::from_slice(&header_key[0x10..]));
    let xts = Xts128::new(first, second);
    xts.encrypt_area(&mut nca[..0x400], 0x200, 0, nintendo_tweak);
    xts.encrypt_area(&mut nca[0x400..0xc00], 0x200, 2, nintendo_tweak);
    nca
}

#[cfg(test)]
mod tests {
    use super::{ContentType, Distribution, HeaderError, read_header};
    use std::io::{Seek, Write};

    const KEY: [u8; 32] = [0x42; 32];

    fn fixture(partitions: &[(u64, u64, u8, u8, u8, bool)], file_size: u64) -> [u8; 0xc00] {
        let mut block = [0_u8; 0xc00];
        block[0x200..0x204].copy_from_slice(b"NCA3");
        block[0x204] = 1;
        block[0x205] = 0;
        block[0x206] = 0;
        block[0x207] = 0;
        block[0x208..0x210].copy_from_slice(&file_size.to_le_bytes());
        block[0x210..0x218].copy_from_slice(&0x0102_0304_0506_0708_u64.to_le_bytes());
        block[0x218..0x21c].copy_from_slice(&7_u32.to_le_bytes());
        for (index, &(offset, size, filesystem, hash_type, encryption, extended)) in
            partitions.iter().enumerate()
        {
            let descriptor = 0x240 + index * 16;
            block[descriptor..descriptor + 4]
                .copy_from_slice(&u32::try_from(offset / 0x200).unwrap().to_le_bytes());
            block[descriptor + 4..descriptor + 8].copy_from_slice(
                &u32::try_from((offset + size) / 0x200)
                    .unwrap()
                    .to_le_bytes(),
            );
            block[descriptor + 8..descriptor + 12]
                .copy_from_slice(&u32::try_from(size / 0x200).unwrap().to_le_bytes());
            let fs = 0x400 + index * 0x200;
            block[fs..fs + 2].copy_from_slice(&[2, 0]);
            block[fs + 2] = filesystem;
            block[fs + 3] = hash_type;
            block[fs + 4] = encryption;
            block[fs + 5] = u8::from(extended);
        }
        block
    }

    fn encrypted_block(mut block: [u8; 0xc00]) -> [u8; 0xc00] {
        use aes::Aes128;
        use aes::cipher::KeyInit;
        use aes::cipher::generic_array::GenericArray;
        use xts_mode::Xts128;

        let first = Aes128::new(GenericArray::from_slice(&KEY[..0x10]));
        let second = Aes128::new(GenericArray::from_slice(&KEY[0x10..]));
        let xts = Xts128::new(first, second);
        xts.encrypt_area(&mut block[..0x400], 0x200, 0, |index| index.to_be_bytes());
        xts.encrypt_area(&mut block[0x400..], 0x200, 2, |index| index.to_be_bytes());
        block
    }

    #[test]
    fn parses_four_supported_partitions_and_preserves_key_alias_facts() {
        let partitions = (0..4)
            .map(|index| (0xc00 + index * 0x200, 0x200, 1, 1, 1, false))
            .collect::<Vec<_>>();
        let header = fixture(&partitions, 0x1400);
        let parsed = super::parse_header_block(&header, 0x1400).unwrap();
        assert_eq!(parsed.format_version, 3);
        assert_eq!(parsed.distribution, Distribution::GameCard);
        assert_eq!(parsed.content_type, ContentType::Program);
        assert_eq!(parsed.program_id, 0x0102_0304_0506_0708);
        assert_eq!(parsed.content_index, 7);
        assert_eq!(parsed.kaek_index, 0);
        assert_eq!(parsed.partitions.len(), 4);
        assert_eq!(parsed.partitions[3].offset, 0x1200);
    }

    #[test]
    fn reads_effective_generation_signature_and_kaek_from_encrypted_header() {
        let mut block = fixture(&[(0xc00, 0x200, 1, 1, 1, false)], 0xe00);
        // These are independent raw-byte values, not values emitted by the
        // parser or copied from its constants.
        block[0x206] = 3;
        block[0x207] = 1;
        block[0x220] = 8;
        block[0x221] = 5;

        let encrypted = encrypted_block(block);
        let mut contents = vec![0_u8; 0xe00];
        contents[..encrypted.len()].copy_from_slice(&encrypted);
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&contents).unwrap();
        file.as_file_mut()
            .seek(std::io::SeekFrom::Start(0))
            .unwrap();

        let parsed = read_header(file.as_file_mut(), contents.len() as u64, &KEY).unwrap();
        assert_eq!(parsed.key_generation, 8);
        assert_eq!(parsed.signature_generation, 5);
        assert_eq!(parsed.kaek_index, 1);
    }

    #[test]
    fn plaintext_nca_header_is_typed_unsupported_input() {
        let plaintext = fixture(&[(0xc00, 0x200, 1, 1, 1, false)], 0xe00);
        let mut contents = vec![0_u8; 0xe00];
        contents[..plaintext.len()].copy_from_slice(&plaintext);
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&contents).unwrap();

        assert_eq!(
            read_header(file.as_file_mut(), contents.len() as u64, &KEY),
            Err(HeaderError::UnsupportedFormat)
        );
    }

    #[test]
    fn encrypted_header_is_decrypted_only_with_the_supplied_header_key() {
        let partitions = [(0xc00, 0x200, 1, 1, 1, false)];
        let encrypted = encrypted_block(fixture(&partitions, 0xe00));
        let mut contents = vec![0_u8; 0xe00];
        contents[..encrypted.len()].copy_from_slice(&encrypted);
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&contents).unwrap();
        file.as_file_mut()
            .seek(std::io::SeekFrom::Start(0))
            .unwrap();
        let parsed = read_header(file.as_file_mut(), contents.len() as u64, &KEY).unwrap();
        assert_eq!(parsed.declared_size, 0xe00);
        assert_eq!(parsed.partitions[0].size, 0x200);
    }

    #[test]
    fn malformed_partition_order_and_size_are_rejected() {
        let partitions = [
            (0xe00, 0x200, 1, 1, 1, false),
            (0xc00, 0x200, 1, 1, 1, false),
        ];
        let header = fixture(&partitions, 0x1000);
        assert_eq!(
            super::parse_header_block(&header, 0x1000),
            Err(HeaderError::MalformedInput)
        );
        let header = fixture(&[(0xc00, 0x200, 1, 1, 1, false)], 0x1200);
        assert_eq!(
            super::parse_header_block(&header, 0x1000),
            Err(HeaderError::MalformedInput)
        );
    }

    #[test]
    fn unsupported_or_extended_partition_metadata_remains_visible_to_policy() {
        let header = fixture(&[(0xc00, 0x200, 1, 2, 1, true)], 0xe00);
        let parsed = super::parse_header_block(&header, 0xe00).unwrap();
        assert_eq!(parsed.partitions[0].hash_type, 2);
        assert!(parsed.partitions[0].extended);
        assert_eq!(
            crate::inspection::validate_nca_profile(&parsed),
            Err(crate::inspection::InspectionErrorCode::UnsupportedInspectionProfile)
        );
    }
}
