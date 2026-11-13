use sha2::{Digest, Sha256};

const ROOT_OFFSET: usize = 0xF000;

#[derive(Clone, Copy, Debug)]
pub struct EntryLocation {
    pub table_offset: usize,
    pub data_offset: usize,
    pub data_len: usize,
}

pub struct Fixture {
    pub image: Vec<u8>,
    pub package: Vec<u8>,
    pub key_file: Vec<u8>,
    pub root_entries: Vec<EntryLocation>,
    pub secure_entries: Vec<EntryLocation>,
}

struct Member<'a> {
    name: &'a str,
    bytes: &'a [u8],
}

struct HfsImage {
    bytes: Vec<u8>,
    header_size: usize,
    entries: Vec<EntryLocation>,
}

pub fn valid() -> Fixture {
    let nsp = crate::synthetic_nsp_qualification::valid();
    let canonical_package = canonical_package(&nsp.meta_nca, &nsp.program_nca);
    build(
        &nsp.meta_nca,
        &nsp.program_nca,
        &canonical_package,
        &nsp.key_file,
        ["program.nca", "meta.nca"],
        false,
    )
}

fn canonical_package(meta_nca: &[u8], program_nca: &[u8]) -> Vec<u8> {
    let members = [("meta.nca", meta_nca), ("program.nca", program_nca)];
    let mut strings = Vec::new();
    let mut entries = Vec::new();
    let mut payload = Vec::new();
    for (name, bytes) in members {
        let name_offset = u32::try_from(strings.len()).expect("synthetic names fit PFS0");
        let data_offset = u64::try_from(payload.len()).expect("synthetic payload fits PFS0");
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        entries.push((
            data_offset,
            u64::try_from(bytes.len()).expect("member fits PFS0"),
            name_offset,
        ));
        payload.extend_from_slice(bytes);
    }
    let mut output = Vec::new();
    output.extend_from_slice(b"PFS0");
    output.extend_from_slice(&2_u32.to_le_bytes());
    output.extend_from_slice(
        &u32::try_from(strings.len())
            .expect("synthetic names fit PFS0")
            .to_le_bytes(),
    );
    output.extend_from_slice(&0_u32.to_le_bytes());
    for (offset, size, name_offset) in entries {
        output.extend_from_slice(&offset.to_le_bytes());
        output.extend_from_slice(&size.to_le_bytes());
        output.extend_from_slice(&name_offset.to_le_bytes());
        output.extend_from_slice(&0_u32.to_le_bytes());
    }
    output.extend_from_slice(&strings);
    output.extend_from_slice(&payload);
    output
}

pub fn build(
    meta_nca: &[u8],
    program_nca: &[u8],
    package: &[u8],
    key_file: &[u8],
    secure_names: [&str; 2],
    include_empty_logo: bool,
) -> Fixture {
    let mut root_partition_names = vec!["update", "normal"];
    if include_empty_logo {
        root_partition_names.push("logo");
    }
    root_partition_names.push("secure");
    build_profile(
        meta_nca,
        program_nca,
        package,
        key_file,
        secure_names,
        &root_partition_names,
        None,
        2,
        None,
        &[],
    )
}

pub fn with_nonempty_partition(partition_name: &str) -> Fixture {
    let nsp = crate::synthetic_nsp_qualification::valid();
    let package = canonical_package(&nsp.meta_nca, &nsp.program_nca);
    build_profile(
        &nsp.meta_nca,
        &nsp.program_nca,
        &package,
        &nsp.key_file,
        ["program.nca", "meta.nca"],
        &["update", "normal", "logo", "secure"],
        Some(partition_name),
        2,
        None,
        &[],
    )
}

pub fn with_root_partition_names(names: &[&str]) -> Fixture {
    let nsp = crate::synthetic_nsp_qualification::valid();
    let package = canonical_package(&nsp.meta_nca, &nsp.program_nca);
    build_profile(
        &nsp.meta_nca,
        &nsp.program_nca,
        &package,
        &nsp.key_file,
        ["program.nca", "meta.nca"],
        names,
        None,
        2,
        None,
        &[],
    )
}

pub fn with_extra_secure_member() -> Fixture {
    let nsp = crate::synthetic_nsp_qualification::valid();
    let package = canonical_package(&nsp.meta_nca, &nsp.program_nca);
    build_profile(
        &nsp.meta_nca,
        &nsp.program_nca,
        &package,
        &nsp.key_file,
        ["program.nca", "meta.nca"],
        &["update", "normal", "secure"],
        None,
        2,
        None,
        &[("unknown.dat", b"synthetic extra member")],
    )
}

pub fn with_secure_member_count(count: usize) -> Fixture {
    let nsp = crate::synthetic_nsp_qualification::valid();
    let package = canonical_package(&nsp.meta_nca, &nsp.program_nca);
    build_profile(
        &nsp.meta_nca,
        &nsp.program_nca,
        &package,
        &nsp.key_file,
        ["program.nca", "meta.nca"],
        &["update", "normal", "secure"],
        None,
        count,
        None,
        &[],
    )
}

pub fn with_compressed_secure_member() -> Fixture {
    let nsp = crate::synthetic_nsp_qualification::valid();
    let package = canonical_package(&nsp.meta_nca, &nsp.program_nca);
    let compressed = ncz_member();
    build_profile(
        &nsp.meta_nca,
        &nsp.program_nca,
        &package,
        &nsp.key_file,
        ["compressed.ncz", "ignored.bin"],
        &["update", "normal", "secure"],
        None,
        2,
        Some([&compressed, &nsp.program_nca]),
        &[],
    )
}

#[allow(clippy::too_many_arguments)]
fn build_profile(
    meta_nca: &[u8],
    program_nca: &[u8],
    package: &[u8],
    key_file: &[u8],
    secure_names: [&str; 2],
    root_partition_names: &[&str],
    nonempty_partition: Option<&str>,
    secure_member_count: usize,
    secure_member_override: Option<[&[u8]; 2]>,
    extra_secure_members: &[(&str, &[u8])],
) -> Fixture {
    let secure_member_bytes = secure_member_override.unwrap_or([meta_nca, program_nca]);
    let mut secure_members = Vec::new();
    if secure_member_count >= 1 {
        secure_members.push(Member {
            name: secure_names[0],
            bytes: secure_member_bytes[0],
        });
    }
    if secure_member_count >= 2 {
        secure_members.push(Member {
            name: secure_names[1],
            bytes: secure_member_bytes[1],
        });
    }
    secure_members.extend(
        extra_secure_members
            .iter()
            .map(|(name, bytes)| Member { name, bytes }),
    );
    let secure = hfs_image(&secure_members);

    let mut partitions: Vec<(String, Vec<u8>, Vec<EntryLocation>)> = Vec::new();
    for name in root_partition_names {
        let (bytes, entries) = match *name {
            "secure" => (secure.bytes.clone(), secure.entries.clone()),
            name if nonempty_partition == Some(name) => {
                let payload = b"synthetic unsupported partition member";
                let partition = hfs_image(&[Member {
                    name: "unsupported.bin",
                    bytes: payload,
                }]);
                (partition.bytes, partition.entries)
            }
            _ => (padded_empty_partition(), Vec::new()),
        };
        partitions.push((name.to_string(), bytes, entries));
    }

    let root_members: Vec<Member<'_>> = partitions
        .iter()
        .map(|(name, bytes, _)| Member { name, bytes })
        .collect();
    let root = hfs_image(&root_members);
    let root_header_size = root.header_size;
    let root_entries = root.entries;

    let mut image = vec![0; ROOT_OFFSET];
    image[0x100..0x104].copy_from_slice(b"HEAD");
    image[0x10D] = 0xFA;
    image[0x118..0x11C].copy_from_slice(&0x20_0000_u32.to_le_bytes());
    image[0x130..0x138].copy_from_slice(&(ROOT_OFFSET as u64).to_le_bytes());
    image[0x138..0x140].copy_from_slice(&(root_header_size as u64).to_le_bytes());
    image.extend_from_slice(&root.bytes);

    let mut secure_offset = 0;
    for ((name, _, _), root_entry) in partitions.iter().zip(&root_entries) {
        let start = ROOT_OFFSET + root_entry.data_offset;
        if name == "secure" {
            secure_offset = start;
        }
    }
    image[0x104..0x108].copy_from_slice(&(((secure_offset + 0x1000) / 0x200) as u32).to_le_bytes());

    let secure_root_index = partitions.iter().position(|(name, _, _)| name == "secure");
    let secure_entries = secure_root_index
        .map(|secure_root_index| {
            let secure_partition_start = ROOT_OFFSET + root_entries[secure_root_index].data_offset;
            partitions[secure_root_index]
                .2
                .iter()
                .map(|entry| EntryLocation {
                    table_offset: secure_partition_start + entry.table_offset,
                    data_offset: secure_partition_start + entry.data_offset,
                    data_len: entry.data_len,
                })
                .collect()
        })
        .unwrap_or_default();
    let root_entries = root_entries
        .into_iter()
        .map(|entry| EntryLocation {
            table_offset: ROOT_OFFSET + entry.table_offset,
            data_offset: ROOT_OFFSET + entry.data_offset,
            data_len: entry.data_len,
        })
        .collect();

    Fixture {
        image,
        package: package.to_vec(),
        key_file: key_file.to_vec(),
        root_entries,
        secure_entries,
    }
}

impl Fixture {
    pub fn set_prefix_hash(&mut self, entry: EntryLocation, size: usize) {
        let data = &self.image[entry.data_offset..entry.data_offset + size];
        let digest = Sha256::digest(data);
        let table = entry.table_offset;
        self.image[table + 20..table + 24].copy_from_slice(&(size as u32).to_le_bytes());
        self.image[table + 32..table + 64].copy_from_slice(&digest);
    }

    pub fn set_hashed_size(&mut self, entry: EntryLocation, size: u32) {
        self.image[entry.table_offset + 20..entry.table_offset + 24]
            .copy_from_slice(&size.to_le_bytes());
    }

    pub fn set_reserved(&mut self, entry: EntryLocation, bytes: [u8; 8]) {
        self.image[entry.table_offset + 24..entry.table_offset + 32].copy_from_slice(&bytes);
    }

    pub fn corrupt_digest(&mut self, entry: EntryLocation) {
        self.image[entry.table_offset + 32] ^= 0x80;
    }
}

fn padded_empty_partition() -> Vec<u8> {
    let mut bytes = b"HFS0\0\0\0\0\0\0\0\0\0\0\0\0".to_vec();
    bytes.resize(0x200, 0);
    bytes
}

fn ncz_member() -> Vec<u8> {
    let mut bytes = vec![0; 0x4000];
    bytes.extend_from_slice(b"NCZSECTN");
    bytes.extend_from_slice(&1_u64.to_le_bytes());
    for field in [0x4000_u64, 16, 1, 0] {
        bytes.extend_from_slice(&field.to_le_bytes());
    }
    bytes.extend_from_slice(&[0; 32]);
    bytes.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0x20, 16, 0x81, 0, 0]);
    bytes.extend_from_slice(&[0; 16]);
    bytes
}

fn hfs_image(members: &[Member<'_>]) -> HfsImage {
    let mut strings = Vec::new();
    let mut member_offsets = Vec::new();
    let mut payload = Vec::new();
    for member in members {
        let name_offset = strings.len() as u32;
        strings.extend_from_slice(member.name.as_bytes());
        strings.push(0);
        member_offsets.push((name_offset, payload.len(), member.bytes.len()));
        payload.extend_from_slice(member.bytes);
    }

    let table_size = members.len() * 64;
    let unpadded_header = 16 + table_size + strings.len();
    let header_size = (unpadded_header + 0x1FF) & !0x1FF;
    strings.resize(strings.len() + header_size - unpadded_header, 0);
    let mut table = Vec::with_capacity(table_size);
    let mut locations = Vec::with_capacity(members.len());
    for (index, member) in members.iter().enumerate() {
        let (name_offset, data_offset, data_len) = member_offsets[index];
        let data_offset_u64 = data_offset as u64;
        let size_u64 = data_len as u64;
        let hashed_size = u32::try_from(data_len).expect("synthetic member fits HFS0 hashed size");
        let digest = Sha256::digest(member.bytes);
        table.extend_from_slice(&data_offset_u64.to_le_bytes());
        table.extend_from_slice(&size_u64.to_le_bytes());
        table.extend_from_slice(&name_offset.to_le_bytes());
        table.extend_from_slice(&hashed_size.to_le_bytes());
        table.extend_from_slice(&[0; 8]);
        table.extend_from_slice(&digest);
        locations.push(EntryLocation {
            table_offset: 16 + index * 64,
            data_offset: header_size + data_offset,
            data_len,
        });
    }

    let mut bytes = b"HFS0".to_vec();
    bytes.extend_from_slice(&(members.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(&table);
    bytes.extend_from_slice(&strings);
    bytes.extend_from_slice(&payload);
    HfsImage {
        bytes,
        header_size,
        entries: locations,
    }
}
