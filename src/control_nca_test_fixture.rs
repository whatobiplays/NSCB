//! Runtime-built, rights-free NCA fixtures used by Control qualification tests.

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};
use xts_mode::Xts128;

pub(crate) const NCA_HEADER_KEY: [u8; 32] = [0x42; 32];
pub(crate) const APPLICATION_KAEK: [u8; 16] = [0x24; 16];
pub(crate) const SECTION_KEY: [u8; 16] = [0x31; 16];
pub(crate) const SECTION_CTR: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

const NCA_HEADER_SIZE: usize = 0xc00;
const SECTION_START: usize = NCA_HEADER_SIZE;
const BLOCK_SIZE: usize = 0x4000;
const SECTION_START_PAGE: u32 = (SECTION_START / 0x200) as u32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Mutation {
    None,
    CorruptMasterHash,
    WrongNcaMagic,
    WrongContentType,
    RightsBearing,
    KeyGeneration(u8),
    WrongKaekIndex,
    WrongFilesystem,
    WrongHashType,
    WrongEncryption,
    ExtendedFilesystem,
    AdditionalPartition,
    NonzeroFilesystemReserved,
    WrongIvfcSignature,
    WrongIvfcId,
    WrongMasterHashSize,
    WrongLevelCount,
    WrongBlockExponent,
    MisalignedDescriptor,
    AliasedDescriptor,
    NonzeroDescriptorReserved,
    NonzeroIvfcReserved,
    OverflowingDescriptor,
    OutOfBoundsDescriptor,
    NonzeroStoredTablePadding,
    CorruptFilesystemDigest,
    FullSectionTailBlock,
}

pub(crate) struct Fixture {
    pub(crate) bytes: Vec<u8>,
    pub(crate) section_start: usize,
    pub(crate) level_offsets: [usize; 6],
}

pub(crate) fn key_file_bytes() -> Vec<u8> {
    format!(
        "header_key = {}\nkey_area_key_application_00 = {}\n",
        hex(&NCA_HEADER_KEY),
        hex(&APPLICATION_KAEK)
    )
    .into_bytes()
}

pub(crate) fn empty_romfs() -> Vec<u8> {
    empty_romfs_with_file_hash_table_end(0x230)
}

pub(crate) fn media_aligned_partial_empty_romfs() -> Vec<u8> {
    empty_romfs_with_file_hash_table_end(0x400)
}

pub(crate) fn block_aligned_empty_romfs() -> Vec<u8> {
    empty_romfs_with_file_hash_table_end(BLOCK_SIZE)
}

fn empty_romfs_with_file_hash_table_end(file_hash_table_end: usize) -> Vec<u8> {
    assert!(file_hash_table_end >= 0x224 && file_hash_table_end.is_multiple_of(4));
    let mut bytes = vec![0; file_hash_table_end];
    write_u64(&mut bytes, 0, 0x50);
    write_u64(&mut bytes, 8, 0x200);
    write_u64(&mut bytes, 16, 12);
    write_u64(&mut bytes, 24, 0x20c);
    write_u64(&mut bytes, 32, 0x18);
    write_u64(&mut bytes, 40, 0x224);
    write_u64(&mut bytes, 48, (file_hash_table_end - 0x224) as u64);
    write_u64(&mut bytes, 56, file_hash_table_end as u64);
    write_u64(&mut bytes, 64, 0);
    write_u64(&mut bytes, 72, 0x200);

    let root_bucket = (123_456_789_u32 % 3) as usize;
    write_u32(&mut bytes, 0x200 + root_bucket * 4, 0);
    for bucket in 0..3 {
        if bucket != root_bucket {
            write_u32(&mut bytes, 0x200 + bucket * 4, u32::MAX);
        }
    }
    write_u32(&mut bytes, 0x20c, 0);
    write_u32(&mut bytes, 0x210, u32::MAX);
    write_u32(&mut bytes, 0x214, u32::MAX);
    write_u32(&mut bytes, 0x218, u32::MAX);
    write_u32(&mut bytes, 0x21c, u32::MAX);
    write_u32(&mut bytes, 0x220, 0);

    for bucket in bytes[0x224..].as_chunks_mut::<4>().0 {
        bucket.copy_from_slice(&u32::MAX.to_le_bytes());
    }
    bytes
}

pub(crate) fn romfs_with_file() -> Vec<u8> {
    let mut bytes = vec![0; 0x294];
    write_u64(&mut bytes, 0, 0x50);
    write_u64(&mut bytes, 8, 0x204);
    write_u64(&mut bytes, 16, 12);
    write_u64(&mut bytes, 24, 0x210);
    write_u64(&mut bytes, 32, 0x54);
    write_u64(&mut bytes, 40, 0x264);
    write_u64(&mut bytes, 48, 12);
    write_u64(&mut bytes, 56, 0x270);
    write_u64(&mut bytes, 64, 0x24);
    write_u64(&mut bytes, 72, 0x200);
    bytes[0x200..0x204].copy_from_slice(b"data");

    let mut directory_heads = [u32::MAX; 3];
    for (record_offset, parent, name, hash_next_offset) in [
        (0, 0, &b""[..], 0x220),
        (24, 0, &b"assets"[..], 0x238),
        (56, 0, &b"info"[..], 0x258),
    ] {
        let bucket = bucket_hash(parent, name) % directory_heads.len();
        write_u32(&mut bytes, hash_next_offset, directory_heads[bucket]);
        directory_heads[bucket] = record_offset;
    }
    for (bucket, head) in directory_heads.into_iter().enumerate() {
        write_u32(&mut bytes, 0x204 + bucket * 4, head);
    }

    write_u32(&mut bytes, 0x210, 0);
    write_u32(&mut bytes, 0x214, u32::MAX);
    write_u32(&mut bytes, 0x218, 24);
    write_u32(&mut bytes, 0x21c, u32::MAX);
    write_u32(&mut bytes, 0x224, 0);

    write_u32(&mut bytes, 0x228, 0);
    write_u32(&mut bytes, 0x22c, 56);
    write_u32(&mut bytes, 0x230, u32::MAX);
    write_u32(&mut bytes, 0x234, 0);
    write_u32(&mut bytes, 0x23c, 6);
    bytes[0x240..0x246].copy_from_slice(b"assets");

    write_u32(&mut bytes, 0x248, 0);
    write_u32(&mut bytes, 0x24c, u32::MAX);
    write_u32(&mut bytes, 0x250, u32::MAX);
    write_u32(&mut bytes, 0x254, u32::MAX);
    write_u32(&mut bytes, 0x25c, 4);
    bytes[0x260..0x264].copy_from_slice(b"info");

    let mut file_heads = [u32::MAX; 3];
    let file_bucket = bucket_hash(24, b"data") % file_heads.len();
    file_heads[file_bucket] = 0;
    for (bucket, head) in file_heads.into_iter().enumerate() {
        write_u32(&mut bytes, 0x264 + bucket * 4, head);
    }
    write_u32(&mut bytes, 0x270, 24);
    write_u32(&mut bytes, 0x274, u32::MAX);
    write_u64(&mut bytes, 0x278, 0);
    write_u64(&mut bytes, 0x280, 4);
    write_u32(&mut bytes, 0x288, u32::MAX);
    write_u32(&mut bytes, 0x28c, 4);
    bytes[0x290..0x294].copy_from_slice(b"data");
    bytes
}

pub(crate) fn oversized_metadata_romfs() -> Vec<u8> {
    let directory_hash_size = 1_048_472_usize;
    let directory_hash_offset = 0x200_usize;
    let directory_meta_offset = directory_hash_offset + directory_hash_size;
    let directory_meta_size = 0x18_usize;
    let file_hash_offset = directory_meta_offset + directory_meta_size;
    let file_meta_offset = file_hash_offset + 4;
    let mut bytes = vec![0; file_meta_offset];

    write_u64(&mut bytes, 0, 0x50);
    write_u64(&mut bytes, 8, directory_hash_offset as u64);
    write_u64(&mut bytes, 16, directory_hash_size as u64);
    write_u64(&mut bytes, 24, directory_meta_offset as u64);
    write_u64(&mut bytes, 32, directory_meta_size as u64);
    write_u64(&mut bytes, 40, file_hash_offset as u64);
    write_u64(&mut bytes, 48, 4);
    write_u64(&mut bytes, 56, file_meta_offset as u64);
    write_u64(&mut bytes, 64, 0);
    write_u64(&mut bytes, 72, 0x200);

    for bucket in bytes[directory_hash_offset..directory_meta_offset]
        .as_chunks_mut::<4>()
        .0
    {
        bucket.copy_from_slice(&u32::MAX.to_le_bytes());
    }
    let root_bucket = bucket_hash(0, b"") % (directory_hash_size / 4);
    write_u32(&mut bytes, directory_hash_offset + root_bucket * 4, 0);
    write_u32(&mut bytes, directory_meta_offset + 4, u32::MAX);
    write_u32(&mut bytes, directory_meta_offset + 8, u32::MAX);
    write_u32(&mut bytes, directory_meta_offset + 12, u32::MAX);
    write_u32(&mut bytes, directory_meta_offset + 16, u32::MAX);
    write_u32(&mut bytes, file_hash_offset, u32::MAX);
    bytes
}

pub(crate) fn too_many_directories_romfs() -> Vec<u8> {
    let directory_count = 32_769_usize;
    let directory_meta_size = 0x18 + (directory_count - 1) * 0x1c;
    let directory_hash_offset = 0x200_usize;
    let directory_meta_offset = directory_hash_offset + 4;
    let file_hash_offset = directory_meta_offset + directory_meta_size;
    let file_meta_offset = file_hash_offset + 4;
    let mut bytes = vec![0; file_meta_offset];

    write_u64(&mut bytes, 0, 0x50);
    write_u64(&mut bytes, 8, directory_hash_offset as u64);
    write_u64(&mut bytes, 16, 4);
    write_u64(&mut bytes, 24, directory_meta_offset as u64);
    write_u64(&mut bytes, 32, directory_meta_size as u64);
    write_u64(&mut bytes, 40, file_hash_offset as u64);
    write_u64(&mut bytes, 48, 4);
    write_u64(&mut bytes, 56, file_meta_offset as u64);
    write_u64(&mut bytes, 64, 0);
    write_u64(&mut bytes, 72, 0x200);
    write_u32(&mut bytes, directory_hash_offset, 0);

    write_u32(&mut bytes, directory_meta_offset + 4, u32::MAX);
    write_u32(&mut bytes, directory_meta_offset + 8, u32::MAX);
    write_u32(&mut bytes, directory_meta_offset + 12, u32::MAX);
    write_u32(&mut bytes, directory_meta_offset + 16, u32::MAX);
    for record_index in 1..directory_count {
        let record = directory_meta_offset + 0x18 + (record_index - 1) * 0x1c;
        write_u32(&mut bytes, record, 0);
        write_u32(&mut bytes, record + 4, u32::MAX);
        write_u32(&mut bytes, record + 8, u32::MAX);
        write_u32(&mut bytes, record + 12, u32::MAX);
        write_u32(&mut bytes, record + 16, u32::MAX);
        write_u32(&mut bytes, record + 20, 4);
        bytes[record + 24..record + 28].copy_from_slice(b"node");
    }
    bytes
}

pub(crate) fn build(romfs: &[u8], mutation: Mutation) -> Fixture {
    let mut levels: [Vec<u8>; 6] = std::array::from_fn(|_| Vec::new());
    levels[5].extend_from_slice(romfs);
    for index in (0..5).rev() {
        let (parents, children) = levels.split_at_mut(index + 1);
        let parent = &mut parents[index];
        let child = &children[0];
        let block_count = child.len().div_ceil(BLOCK_SIZE);
        for block_index in 0..block_count {
            let start = block_index * BLOCK_SIZE;
            let mut block = [0_u8; BLOCK_SIZE];
            let count = child.len().saturating_sub(start).min(BLOCK_SIZE);
            block[..count].copy_from_slice(&child[start..start + count]);
            parent.extend_from_slice(&Sha256::digest(block));
        }
        let padded_size = parent.len().div_ceil(BLOCK_SIZE) * BLOCK_SIZE;
        parent.resize(padded_size, 0);
    }
    if mutation == Mutation::NonzeroStoredTablePadding {
        let table_bytes = levels[2].len().div_ceil(BLOCK_SIZE) * 32;
        levels[1][table_bytes] = 1;
        let mut root = Vec::new();
        for child_block in levels[1].chunks(BLOCK_SIZE) {
            let mut block = [0_u8; BLOCK_SIZE];
            block[..child_block.len()].copy_from_slice(child_block);
            root.extend_from_slice(&Sha256::digest(block));
        }
        root.resize(root.len().div_ceil(BLOCK_SIZE) * BLOCK_SIZE, 0);
        levels[0] = root;
    }

    let mut level_offsets = [0_usize; 6];
    for index in 1..6 {
        level_offsets[index] = level_offsets[index - 1] + levels[index - 1].len();
    }
    let logical_section_size = level_offsets[5] + levels[5].len();
    let section_size = if mutation == Mutation::FullSectionTailBlock {
        logical_section_size + BLOCK_SIZE
    } else {
        logical_section_size.div_ceil(BLOCK_SIZE) * BLOCK_SIZE
    };
    let additional_partition_size = usize::from(mutation == Mutation::AdditionalPartition) * 0x200;
    let file_size = SECTION_START + section_size + additional_partition_size;
    let mut section = vec![0; section_size];
    for index in 0..6 {
        let start = level_offsets[index];
        section[start..start + levels[index].len()].copy_from_slice(&levels[index]);
    }

    let mut header = [0_u8; NCA_HEADER_SIZE];
    header[0x200..0x204].copy_from_slice(b"NCA3");
    header[0x204] = 0;
    header[0x205] = 2;
    header[0x206] = 0;
    header[0x207] = 0;
    write_u64_array(&mut header, 0x208, file_size as u64);
    write_u64_array(&mut header, 0x210, 0x0100_0000_0000_1000);
    write_u32_array(&mut header, 0x240, SECTION_START_PAGE);
    write_u32_array(
        &mut header,
        0x244,
        ((SECTION_START + section_size) / 0x200) as u32,
    );
    header[0x248] = 1;
    if mutation == Mutation::AdditionalPartition {
        let second_partition_start = SECTION_START + section_size;
        write_u32_array(&mut header, 0x250, (second_partition_start / 0x200) as u32);
        write_u32_array(&mut header, 0x254, (file_size / 0x200) as u32);
        header[0x600..0x608].copy_from_slice(&[2, 0, 0, 3, 3, 0, 0, 0]);
    }
    let fs = &mut header[0x400..0x600];
    fs[..8].copy_from_slice(&[2, 0, 0, 3, 3, 0, 0, 0]);
    fs[0x140..0x148].copy_from_slice(&SECTION_CTR);

    let ivfc = &mut fs[8..8 + 0xe0];
    ivfc[..4].copy_from_slice(b"IVFC");
    write_u32(ivfc, 4, 0x20000);
    write_u32(ivfc, 8, 0x20);
    write_u32(ivfc, 12, 7);
    for index in 0..6 {
        let descriptor = 0x10 + index * 0x18;
        write_u64(ivfc, descriptor, level_offsets[index] as u64);
        write_u64(ivfc, descriptor + 8, levels[index].len() as u64);
        write_u32(ivfc, descriptor + 16, 14);
    }
    ivfc[0xc0..0xe0].copy_from_slice(&Sha256::digest(&levels[0]));

    match mutation {
        Mutation::None
        | Mutation::CorruptFilesystemDigest
        | Mutation::NonzeroStoredTablePadding
        | Mutation::FullSectionTailBlock
        | Mutation::AdditionalPartition => {}
        Mutation::CorruptMasterHash => ivfc[0xc0] ^= 1,
        Mutation::WrongNcaMagic => header[0x203] = b'2',
        Mutation::WrongContentType => header[0x205] = 1,
        Mutation::RightsBearing => header[0x230] = 1,
        Mutation::KeyGeneration(value) => header[0x206] = value,
        Mutation::WrongKaekIndex => header[0x207] = 1,
        Mutation::WrongFilesystem => fs[2] = 1,
        Mutation::WrongHashType => fs[3] = 2,
        Mutation::WrongEncryption => fs[4] = 1,
        Mutation::ExtendedFilesystem => fs[5] = 1,
        Mutation::NonzeroFilesystemReserved => fs[0xe8] = 1,
        Mutation::WrongIvfcSignature => ivfc[0] = b'X',
        Mutation::WrongIvfcId => write_u32(ivfc, 4, 0x20001),
        Mutation::WrongMasterHashSize => write_u32(ivfc, 8, 0x40),
        Mutation::WrongLevelCount => write_u32(ivfc, 12, 6),
        Mutation::WrongBlockExponent => write_u32(ivfc, 0x10 + 16, 15),
        Mutation::MisalignedDescriptor => write_u64(ivfc, 0x10 + 0x18, level_offsets[1] as u64 + 1),
        Mutation::AliasedDescriptor => write_u64(ivfc, 0x10 + 0x18, 0),
        Mutation::NonzeroDescriptorReserved => write_u32(ivfc, 0x10 + 5 * 0x18 + 20, 1),
        Mutation::NonzeroIvfcReserved => ivfc[0xa0] = 1,
        Mutation::OverflowingDescriptor => write_u64(ivfc, 0x10 + 5 * 0x18 + 8, u64::MAX),
        Mutation::OutOfBoundsDescriptor => write_u64(
            ivfc,
            0x10 + 5 * 0x18 + 8,
            (section_size - level_offsets[5] + 1) as u64,
        ),
    }

    let fs_digest = Sha256::digest(&header[0x400..0x600]);
    header[0x280..0x2a0].copy_from_slice(&fs_digest);
    if mutation == Mutation::AdditionalPartition {
        let second_fs_digest = Sha256::digest(&header[0x600..0x800]);
        header[0x2a0..0x2c0].copy_from_slice(&second_fs_digest);
    }
    if mutation == Mutation::CorruptFilesystemDigest {
        header[0x280] ^= 1;
    }

    let mut encrypted_key_area = [0_u8; 0x40];
    let key_cipher = Aes128::new(GenericArray::from_slice(&APPLICATION_KAEK));
    for (index, block) in encrypted_key_area
        .as_chunks_mut::<16>()
        .0
        .iter_mut()
        .enumerate()
    {
        block.fill(0x20 + index as u8);
        if index == 2 {
            block.copy_from_slice(&SECTION_KEY);
        }
        key_cipher.encrypt_block(GenericArray::from_mut_slice(block));
    }
    header[0x300..0x340].copy_from_slice(&encrypted_key_area);

    let mut counter = [0_u8; 16];
    for (destination, source) in counter[..8].iter_mut().zip(SECTION_CTR.iter().rev()) {
        *destination = *source;
    }
    counter[8..].copy_from_slice(&((SECTION_START / 16) as u64).to_be_bytes());
    Ctr128BE::<Aes128>::new_from_slices(&SECTION_KEY, &counter)
        .expect("fixture key and counter")
        .apply_keystream(&mut section);

    let (first, second) = header_key_halves();
    let xts = Xts128::new(first, second);
    xts.encrypt_area(&mut header[..0x400], 0x200, 0, nintendo_tweak);
    xts.encrypt_area(&mut header[0x400..], 0x200, 2, nintendo_tweak);

    let mut bytes = Vec::with_capacity(file_size);
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(&section);
    bytes.resize(file_size, 0);
    Fixture {
        bytes,
        section_start: SECTION_START,
        level_offsets,
    }
}

fn header_key_halves() -> (Aes128, Aes128) {
    (
        Aes128::new(GenericArray::from_slice(&NCA_HEADER_KEY[..16])),
        Aes128::new(GenericArray::from_slice(&NCA_HEADER_KEY[16..])),
    )
}

fn nintendo_tweak(index: u128) -> [u8; 16] {
    index.to_be_bytes()
}

pub(crate) fn bucket_hash(parent: u32, name: &[u8]) -> usize {
    let mut hash = parent ^ 123_456_789;
    for byte in name {
        hash = hash.rotate_right(5) ^ u32::from(*byte);
    }
    hash as usize
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("write hex fixture");
    }
    encoded
}

pub(crate) fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_array(bytes: &mut [u8; NCA_HEADER_SIZE], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_array(bytes: &mut [u8; NCA_HEADER_SIZE], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
