use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use sha2::{Digest, Sha256};
use xts_mode::Xts128;

pub const HEADER_KEY: [u8; 32] = [0x42; 32];
pub const APPLICATION_KAEK: [u8; 16] = [0x24; 16];
pub const PROGRAM_ID: u64 = 0x0100_1234_5678_9abc;

pub struct Fixture {
    pub package: Vec<u8>,
    pub key_file: Vec<u8>,
    pub meta_nca: Vec<u8>,
    pub program_nca: Vec<u8>,
}

pub fn valid() -> Fixture {
    build_with_cnmt_change(|_| {})
}

pub fn build_with_cnmt_change(change: impl FnOnce(&mut [u8; 0x88])) -> Fixture {
    build_with_program_payload(b"synthetic program section", change)
}

pub fn build_with_program_payload(
    program_payload: &[u8],
    change: impl FnOnce(&mut [u8; 0x88]),
) -> Fixture {
    let program_pfs0 = pfs0(&[("unrelated.bin", program_payload)]);
    build_with_program_pfs0(program_pfs0, change)
}

pub fn build_with_program_entry_count(entry_count: usize) -> Fixture {
    let names = (0..entry_count)
        .map(|index| format!("file-{index:04}.bin"))
        .collect::<Vec<_>>();
    let empty = b"";
    let entries = names
        .iter()
        .map(|name| (name.as_str(), empty.as_slice()))
        .collect::<Vec<_>>();
    build_with_program_pfs0(pfs0(&entries), |_| {})
}

pub fn build_with_cnmt_size(cnmt_size: usize) -> Fixture {
    let program_pfs0 = pfs0(&[("program-data.bin", b"synthetic")]);
    let program_nca = nca(0, &program_pfs0, PROGRAM_ID);
    let meta_pfs0 = pfs0(&[("metadata.cnmt", &vec![0; cnmt_size])]);
    let meta_nca = nca(1, &meta_pfs0, PROGRAM_ID);
    let package = package_with_members(&meta_nca, &program_nca);
    Fixture {
        package,
        key_file: key_file_with_application_kaek(APPLICATION_KAEK),
        meta_nca,
        program_nca,
    }
}

fn build_with_program_pfs0(program_pfs0: Vec<u8>, change: impl FnOnce(&mut [u8; 0x88])) -> Fixture {
    let program_nca = nca(0, &program_pfs0, PROGRAM_ID);
    let program_digest = Sha256::digest(&program_nca);

    let mut cnmt = [0_u8; 0x88];
    cnmt[0..8].copy_from_slice(&PROGRAM_ID.to_le_bytes());
    cnmt[0x0c] = 0x80;
    cnmt[0x0e..0x10].copy_from_slice(&0x10_u16.to_le_bytes());
    cnmt[0x10..0x12].copy_from_slice(&1_u16.to_le_bytes());
    cnmt[0x30..0x50].copy_from_slice(&program_digest);
    cnmt[0x50..0x60].copy_from_slice(&program_digest[..16]);
    put_u40(&mut cnmt[0x60..0x65], program_nca.len() as u64);
    cnmt[0x66] = 1;
    cnmt[0x67] = 0;
    change(&mut cnmt);

    let meta_pfs0 = pfs0(&[("misleading.txt", &cnmt)]);
    let meta_nca = nca(1, &meta_pfs0, PROGRAM_ID);
    let package = package_with_members(&meta_nca, &program_nca);
    let key_file = key_file_with_application_kaek(APPLICATION_KAEK);

    Fixture {
        package,
        key_file,
        meta_nca,
        program_nca,
    }
}

pub fn package_with_members(meta_nca: &[u8], program_nca: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(meta_nca.len() + program_nca.len());
    payload.extend_from_slice(meta_nca);
    payload.extend_from_slice(program_nca);
    pfs0_with_payload(
        &[("program.nca", meta_nca), ("meta.cnmt.nca", program_nca)],
        payload,
    )
}

pub fn package_with_extra_member(
    meta_nca: &[u8],
    program_nca: &[u8],
    extra_name: &str,
    extra: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(meta_nca.len() + program_nca.len() + extra.len());
    payload.extend_from_slice(meta_nca);
    payload.extend_from_slice(program_nca);
    payload.extend_from_slice(extra);
    pfs0_with_payload(
        &[
            ("program.nca", meta_nca),
            ("meta.cnmt.nca", program_nca),
            (extra_name, extra),
        ],
        payload,
    )
}

pub fn key_file_with_application_kaek(kaek: [u8; 16]) -> Vec<u8> {
    format!(
        "header_key = {}\nkey_area_key_application_00 = {}\n",
        hex(&HEADER_KEY),
        hex(&kaek),
    )
    .into_bytes()
}

pub fn mutate_nca_header(mut nca: Vec<u8>, mutate: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let first = Aes128::new(GenericArray::from_slice(&HEADER_KEY[..0x10]));
    let second = Aes128::new(GenericArray::from_slice(&HEADER_KEY[0x10..]));
    let xts = Xts128::new(first, second);
    xts.decrypt_area(&mut nca[..0x400], 0x200, 0, |index| index.to_be_bytes());
    xts.decrypt_area(&mut nca[0x400..0xc00], 0x200, 2, |index| {
        index.to_be_bytes()
    });
    mutate(&mut nca[..0xc00]);
    xts.encrypt_area(&mut nca[..0x400], 0x200, 0, |index| index.to_be_bytes());
    xts.encrypt_area(&mut nca[0x400..0xc00], 0x200, 2, |index| {
        index.to_be_bytes()
    });
    nca
}

fn nca(content_type: u8, pfs0_bytes: &[u8], program_id: u64) -> Vec<u8> {
    const SECTION_OFFSET: usize = 0xc00;
    const PFS0_OFFSET: usize = 0x200;
    const BLOCK_SIZE: usize = 0x200;

    let hash_count = pfs0_bytes.len().div_ceil(BLOCK_SIZE);
    let hash_table_size = hash_count * 32;
    let pfs0_offset = hash_table_size.max(PFS0_OFFSET).div_ceil(BLOCK_SIZE) * BLOCK_SIZE;
    let required_section_size = pfs0_offset + pfs0_bytes.len();
    let section_size = required_section_size.div_ceil(BLOCK_SIZE) * BLOCK_SIZE;
    let mut section = vec![0_u8; section_size];
    for (index, block) in pfs0_bytes.chunks(BLOCK_SIZE).enumerate() {
        section[index * 32..(index + 1) * 32].copy_from_slice(&Sha256::digest(block));
    }
    section[pfs0_offset..pfs0_offset + pfs0_bytes.len()].copy_from_slice(pfs0_bytes);
    let mut nca = vec![0_u8; SECTION_OFFSET + section_size];
    nca[0x200..0x204].copy_from_slice(b"NCA3");
    nca[0x204] = 0;
    nca[0x205] = content_type;
    nca[0x206] = 0;
    nca[0x207] = 0;
    let nca_size = nca.len() as u64;
    nca[0x208..0x210].copy_from_slice(&nca_size.to_le_bytes());
    nca[0x210..0x218].copy_from_slice(&program_id.to_le_bytes());
    nca[0x218..0x21c].copy_from_slice(&0_u32.to_le_bytes());
    nca[0x240..0x244].copy_from_slice(&6_u32.to_le_bytes());
    let section_end_page = u32::try_from(6 + section_size / BLOCK_SIZE).unwrap();
    nca[0x244..0x248].copy_from_slice(&section_end_page.to_le_bytes());
    nca[0x248] = 1;

    let section_ctr = [
        0x10 + content_type,
        0x21,
        0x32,
        0x43,
        0x54,
        0x65,
        0x76,
        0x87,
    ];
    let fs_header_hash = {
        let fs = &mut nca[0x400..0x600];
        fs[0..2].copy_from_slice(&[2, 0]);
        fs[2] = 1;
        fs[3] = 2;
        fs[4] = 3;
        fs[0x08..0x28].copy_from_slice(&Sha256::digest(&section[..hash_table_size]));
        fs[0x28..0x2c].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes());
        fs[0x2c..0x30].copy_from_slice(&2_u32.to_le_bytes());
        fs[0x30..0x38].copy_from_slice(&0_u64.to_le_bytes());
        fs[0x38..0x40].copy_from_slice(&(hash_table_size as u64).to_le_bytes());
        fs[0x40..0x48].copy_from_slice(&(pfs0_offset as u64).to_le_bytes());
        fs[0x48..0x50].copy_from_slice(&(pfs0_bytes.len() as u64).to_le_bytes());
        fs[0x140..0x148].copy_from_slice(&section_ctr);
        Sha256::digest(&*fs)
    };
    nca[0x280..0x2a0].copy_from_slice(&fs_header_hash);

    let mut area = [0_u8; 0x40];
    let section_key = [0x33; 0x10];
    area[..0x10].copy_from_slice(&[0x11; 0x10]);
    area[0x10..0x20].copy_from_slice(&[0x22; 0x10]);
    area[0x20..0x30].copy_from_slice(&section_key);
    area[0x30..0x40].copy_from_slice(&[0x44; 0x10]);
    let area_cipher = Aes128::new(GenericArray::from_slice(&APPLICATION_KAEK));
    for block in area.chunks_mut(16) {
        area_cipher.encrypt_block(GenericArray::from_mut_slice(block));
    }
    nca[0x300..0x340].copy_from_slice(&area);

    encrypt_section(
        &mut section,
        SECTION_OFFSET as u64,
        &section_key,
        &section_ctr,
    );
    nca[SECTION_OFFSET..].copy_from_slice(&section);

    let first = Aes128::new(GenericArray::from_slice(&HEADER_KEY[..0x10]));
    let second = Aes128::new(GenericArray::from_slice(&HEADER_KEY[0x10..]));
    let xts = Xts128::new(first, second);
    xts.encrypt_area(&mut nca[..0x400], 0x200, 0, |index| index.to_be_bytes());
    xts.encrypt_area(&mut nca[0x400..0xc00], 0x200, 2, |index| {
        index.to_be_bytes()
    });
    nca
}

fn encrypt_section(section: &mut [u8], absolute_start: u64, key: &[u8], section_ctr: &[u8]) {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut initial_counter = [0_u8; 16];
    for (dst, src) in initial_counter[..8]
        .iter_mut()
        .zip(section_ctr.iter().rev())
    {
        *dst = *src;
    }
    initial_counter[8..].copy_from_slice(&(absolute_start / 16).to_be_bytes());
    for (index, chunk) in section.chunks_mut(16).enumerate() {
        let counter_value = u64::from_be_bytes(initial_counter[8..].try_into().unwrap())
            .checked_add(index as u64)
            .unwrap();
        let mut counter = initial_counter;
        counter[8..].copy_from_slice(&counter_value.to_be_bytes());
        let mut stream = GenericArray::clone_from_slice(&counter);
        cipher.encrypt_block(&mut stream);
        for (byte, key_byte) in chunk.iter_mut().zip(stream.iter()) {
            *byte ^= *key_byte;
        }
    }
}

fn pfs0(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let payload = entries
        .iter()
        .flat_map(|(_, bytes)| *bytes)
        .copied()
        .collect::<Vec<_>>();
    encode_pfs0(entries, &payload)
}

fn pfs0_with_payload(entries: &[(&str, &[u8])], payload: Vec<u8>) -> Vec<u8> {
    encode_pfs0(entries, &payload)
}

fn encode_pfs0(entries: &[(&str, &[u8])], payload: &[u8]) -> Vec<u8> {
    let mut strings = Vec::new();
    let mut name_offsets = Vec::with_capacity(entries.len());
    let mut data_offset = 0_u64;
    let mut records = Vec::with_capacity(entries.len());
    for (name, data) in entries {
        name_offsets.push(strings.len() as u32);
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        records.push((data_offset, data.len() as u64));
        data_offset += data.len() as u64;
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PFS0");
    bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    for ((offset, size), name_offset) in records.into_iter().zip(name_offsets) {
        bytes.extend_from_slice(&offset.to_le_bytes());
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(&name_offset.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
    }
    bytes.extend_from_slice(&strings);
    bytes.extend_from_slice(payload);
    bytes
}

fn put_u40(bytes: &mut [u8], value: u64) {
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (value >> (index * 8)) as u8;
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[usize::from(byte >> 4)] as char);
        result.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    result
}
