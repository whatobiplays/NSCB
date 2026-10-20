//! Synthetic NCA3 fixtures for Verification tests.
//!
//! Every RSA key and AES header key in this module is generated or fixed at
//! test runtime. The fixtures contain no production credential, no Nintendo
//! key, and no proprietary content. Signature generation uses the test-only
//! private keys; production Verification only ever reads public keys.

use aes::Aes128;
use aes::cipher::KeyInit;
use aes::cipher::generic_array::GenericArray;
use rand::thread_rng;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::pss::Pss;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use xts_mode::Xts128;

/// Fixed, non-secret AES key used to encrypt synthetic headers.
pub const HEADER_KEY: [u8; 32] = [0x42; 32];
/// Absolute partition offset in the synthetic NCA.
pub const PARTITION_OFFSET: usize = 0xc00;
/// Page-aligned partition size in the synthetic NCA.
pub const PARTITION_SIZE: usize = 0x600;
const EXTRA_PARTITION_SIZE: usize = 0x200;

fn partition_offset(index: usize) -> usize {
    if index == 0 {
        PARTITION_OFFSET
    } else {
        PARTITION_OFFSET + PARTITION_SIZE + (index - 1) * EXTRA_PARTITION_SIZE
    }
}

/// Test-only RSA key pair shared by a test binary.
pub struct TestKeys {
    /// Key the caller supplies as its trust anchor.
    pub anchor: RsaPrivateKey,
    /// Key embedded in the synthetic NPDM ACID.
    pub acid: RsaPrivateKey,
}

/// Returns the test-only key pair, generating it on first use.
pub fn keys() -> &'static TestKeys {
    static KEYS: OnceLock<TestKeys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut rng = thread_rng();
        TestKeys {
            anchor: RsaPrivateKey::new(&mut rng, 2048).expect("generate synthetic anchor key"),
            acid: RsaPrivateKey::new(&mut rng, 2048).expect("generate synthetic ACID key"),
        }
    })
}

/// Shape of the synthetic `main.npdm` member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NpdmMode {
    /// One canonical member whose ACID embeds the matching key.
    Canonical,
    /// No `main.npdm` member.
    Missing,
    /// Two top-level members with the canonical name.
    Duplicate,
    /// ACID size field inconsistent with the declared member size.
    MalformedSize,
    /// ACID embeds a key that did not sign the header's second signature.
    WrongAcidKey,
}

/// Structural shape of the canonical PartitionFs member table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PartitionFsMode {
    /// Canonical NPDM and program members with unique normalized names.
    Canonical,
    /// Two members resolve to the same normalized path.
    Duplicate,
    /// A member name contains a parent-directory segment.
    Traversal,
    /// A member name contains an empty interior path segment.
    Malformed,
    /// A file entry followed by a child below the same path.
    HierarchyFileThenDirectory,
    /// A child entry followed by a file at the parent path.
    HierarchyDirectoryThenFile,
}

/// Independently selectable fixture properties.
#[derive(Clone, Copy, Debug)]
pub struct Spec {
    /// Header signature-key generation byte (`0x221`).
    pub signature_generation: u8,
    /// Effective NCA key generation byte (`0x206`).
    pub key_generation: u8,
    /// NCA distribution byte (`0x204`): `0` Download, `1` Game Card.
    pub distribution: u8,
    /// Byte `0x8` of the partition descriptor.
    pub descriptor_enabled: u8,
    /// NCA content-type byte (`0x205`).
    pub content_type: u8,
    /// Partition hash-type byte of the filesystem header (`0x403`).
    pub partition_hash_type: u8,
    /// Number of additional supported PartitionFs partitions after the first.
    pub extra_partitions: u8,
    /// Shape of the synthetic NPDM member.
    pub npdm: NpdmMode,
    /// Shape the remaining PartitionFs member names.
    pub partition_fs: PartitionFsMode,
    /// Build the first partition with an empty declared span.
    pub zero_size_first_partition: bool,
    /// Corrupt the stored filesystem-header hash after computing it.
    pub fs_hash_corrupt: bool,
    /// Corrupt the fixed-key signature after signing.
    pub corrupt_fixed_signature: bool,
    /// Corrupt the NPDM-key signature after signing.
    pub corrupt_npdm_signature: bool,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            signature_generation: 5,
            key_generation: 0,
            distribution: 1,
            descriptor_enabled: 1,
            content_type: 0,
            partition_hash_type: 1,
            extra_partitions: 0,
            npdm: NpdmMode::Canonical,
            partition_fs: PartitionFsMode::Canonical,
            zero_size_first_partition: false,
            fs_hash_corrupt: false,
            corrupt_fixed_signature: false,
            corrupt_npdm_signature: false,
        }
    }
}

/// One built synthetic NCA plus the encodings of its trust anchor.
pub struct Built {
    /// Encrypted NCA bytes.
    pub nca: Vec<u8>,
    /// `prod.keys` content carrying only the synthetic header key.
    pub keys_file: Vec<u8>,
    /// Trust anchor in PKCS#1 PEM.
    pub pkcs1_pem: Vec<u8>,
    /// Trust anchor in SubjectPublicKeyInfo PEM.
    pub spki_pem: Vec<u8>,
    /// Trust anchor in PKCS#1 DER.
    pub pkcs1_der: Vec<u8>,
    /// Trust anchor in SubjectPublicKeyInfo DER.
    pub spki_der: Vec<u8>,
}

/// Paths for one written fixture.
pub struct Paths {
    pub input: PathBuf,
    pub keys: PathBuf,
    pub anchor: PathBuf,
}

/// Builds one synthetic NCA3 fixture with the requested properties.
pub fn build(spec: Spec) -> Built {
    let keys = keys();
    let partition_count = 1 + usize::from(spec.extra_partitions);
    assert!(
        partition_count <= 4,
        "synthetic fixtures support at most four partitions"
    );

    let mut partitions = Vec::with_capacity(partition_count);
    let mut first = partition(spec);
    assert!(first.len() <= PARTITION_SIZE);
    first.resize(PARTITION_SIZE, 0);
    partitions.push(first);
    for index in 1..partition_count {
        let name = format!("extra{index}.bin");
        let payload = format!("extra{index}");
        let mut extra = pfs0(&[(&name, payload.as_bytes())]);
        extra.resize(EXTRA_PARTITION_SIZE, 0);
        partitions.push(extra);
    }

    let file_size = partitions
        .iter()
        .enumerate()
        .map(|(index, data)| partition_offset(index) + data.len())
        .max()
        .expect("at least one partition");
    let mut header = [0_u8; 0xc00];
    header[0x200..0x204].copy_from_slice(b"NCA3");
    header[0x204] = spec.distribution;
    header[0x205] = spec.content_type;
    header[0x206] = spec.key_generation;
    header[0x207] = 0;
    header[0x208..0x210].copy_from_slice(&(file_size as u64).to_le_bytes());
    header[0x210..0x218].copy_from_slice(&0x0102_0304_0506_0708_u64.to_le_bytes());
    header[0x218..0x21c].copy_from_slice(&0_u32.to_le_bytes());
    header[0x220] = 0;
    header[0x221] = spec.signature_generation;
    for (index, data) in partitions.iter().enumerate() {
        let descriptor = 0x240 + index * 0x10;
        let start = u32::try_from(partition_offset(index) / 0x200).unwrap();
        let end = if index == 0 && spec.zero_size_first_partition {
            start
        } else {
            u32::try_from((partition_offset(index) + data.len()) / 0x200).unwrap()
        };
        header[descriptor..descriptor + 4].copy_from_slice(&start.to_le_bytes());
        header[descriptor + 4..descriptor + 8].copy_from_slice(&end.to_le_bytes());
        header[descriptor + 8] = if index == 0 {
            spec.descriptor_enabled
        } else {
            1
        };

        let fs_header = 0x400 + index * 0x200;
        header[fs_header..fs_header + 2].copy_from_slice(&[2, 0]);
        header[fs_header + 2] = 1;
        header[fs_header + 3] = spec.partition_hash_type;
        header[fs_header + 4] = 1;
        header[fs_header + 5] = 0;
        let fs_hash = Sha256::digest(&header[fs_header..fs_header + 0x200]);
        header[0x280 + index * 0x20..0x280 + (index + 1) * 0x20].copy_from_slice(&fs_hash);
    }
    if spec.fs_hash_corrupt {
        header[0x280] ^= 0xff;
    }

    let signed = header[0x200..0x400].to_vec();
    let fixed = sign(&keys.anchor, &signed);
    let npdm_signature = sign(&keys.acid, &signed);
    header[0..0x100].copy_from_slice(&fixed);
    header[0x100..0x200].copy_from_slice(&npdm_signature);
    if spec.corrupt_fixed_signature {
        header[0] ^= 0xff;
    }
    if spec.corrupt_npdm_signature {
        header[0x100] ^= 0xff;
    }
    encrypt(&mut header);

    let mut nca = header.to_vec();
    for data in &partitions {
        nca.extend_from_slice(data);
    }
    let anchor = RsaPublicKey::from(&keys.anchor);
    Built {
        nca,
        keys_file: keys_file(),
        pkcs1_pem: anchor.to_pkcs1_pem(LineEnding::LF).unwrap().into_bytes(),
        spki_pem: anchor
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
            .into_bytes(),
        pkcs1_der: anchor.to_pkcs1_der().unwrap().as_bytes().to_vec(),
        spki_der: anchor.to_public_key_der().unwrap().as_bytes().to_vec(),
    }
}

impl Built {
    /// Writes the fixture into `directory` and returns its paths.
    pub fn write(&self, directory: &Path) -> Paths {
        let input = directory.join("content.nca");
        let keys = directory.join("prod.keys");
        let anchor = directory.join("anchor.der");
        std::fs::write(&input, &self.nca).expect("write synthetic NCA");
        std::fs::write(&keys, &self.keys_file).expect("write synthetic key file");
        std::fs::write(&anchor, &self.spki_der).expect("write synthetic trust anchor");
        Paths {
            input,
            keys,
            anchor,
        }
    }
}

/// Returns `prod.keys` content carrying only the synthetic header key.
pub fn keys_file() -> Vec<u8> {
    format!("header_key = {}\n", hex(&HEADER_KEY)).into_bytes()
}

/// Encodes bytes as lowercase hexadecimal without separators.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn partition(spec: Spec) -> Vec<u8> {
    let npdm = npdm(spec);
    if spec.partition_fs != PartitionFsMode::Canonical {
        return match spec.partition_fs {
            PartitionFsMode::Duplicate => pfs0(&[
                ("main.npdm", &npdm),
                ("main", b"synthetic program"),
                ("main", b"duplicate name"),
            ]),
            PartitionFsMode::Traversal => {
                pfs0(&[("main.npdm", &npdm), ("../main", b"synthetic program")])
            }
            PartitionFsMode::Malformed => {
                pfs0(&[("main.npdm", &npdm), ("main//child", b"synthetic program")])
            }
            PartitionFsMode::HierarchyFileThenDirectory => pfs0(&[
                ("main.npdm", &npdm),
                ("main", b"synthetic program"),
                ("main/child", b"conflicting child"),
            ]),
            PartitionFsMode::HierarchyDirectoryThenFile => pfs0(&[
                ("main.npdm", &npdm),
                ("main/child", b"conflicting child"),
                ("main", b"synthetic program"),
            ]),
            PartitionFsMode::Canonical => unreachable!(),
        };
    }
    match spec.npdm {
        NpdmMode::Missing => pfs0(&[("main", b"synthetic program")]),
        NpdmMode::Duplicate => pfs0(&[("main.npdm", &npdm), ("main.npdm", b"duplicate")]),
        _ => pfs0(&[("main.npdm", &npdm), ("main", b"synthetic program")]),
    }
}

/// Changes the canonical `main` entry name to the same-length traversal `../x`.
///
/// Header signatures and the filesystem-header hash do not cover partition
/// payload metadata in the supported hash-type-None profile, so this helper
/// exercises metadata changed after fixture signing.
pub fn change_main_name_to_traversal(nca: &mut [u8]) {
    let string_table = PARTITION_OFFSET + 16 + 2 * 24;
    let main_name = string_table + "main.npdm".len() + 1;
    assert_eq!(&nca[main_name..main_name + 4], b"main");
    nca[main_name..main_name + 4].copy_from_slice(b"../x");
}

fn npdm(spec: Spec) -> Vec<u8> {
    let keys = keys();
    let mut meta = vec![0_u8; 0x80];
    meta[0..4].copy_from_slice(b"META");
    meta[0x70..0x74].copy_from_slice(&0x80_u32.to_le_bytes());
    meta[0x74..0x78].copy_from_slice(&0x40_u32.to_le_bytes());
    meta[0x78..0x7c].copy_from_slice(&0xc0_u32.to_le_bytes());
    meta[0x7c..0x80].copy_from_slice(&0x240_u32.to_le_bytes());

    let mut aci0 = vec![0_u8; 0x40];
    aci0[0..4].copy_from_slice(b"ACI0");

    let mut acid = vec![0_u8; 0x240];
    let modulus_source = if spec.npdm == NpdmMode::WrongAcidKey {
        RsaPublicKey::from(&keys.anchor)
    } else {
        RsaPublicKey::from(&keys.acid)
    };
    acid[0x100..0x200].copy_from_slice(&modulus(&modulus_source));
    acid[0x200..0x204].copy_from_slice(b"ACID");
    let size = if spec.npdm == NpdmMode::MalformedSize {
        0x100_u32
    } else {
        0x140_u32
    };
    acid[0x204..0x208].copy_from_slice(&size.to_le_bytes());

    [meta, aci0, acid].concat()
}

fn modulus(key: &RsaPublicKey) -> [u8; 256] {
    let bytes = key.n().to_bytes_be();
    assert!(bytes.len() <= 256);
    let mut padded = [0_u8; 256];
    padded[256 - bytes.len()..].copy_from_slice(&bytes);
    padded
}

fn sign(key: &RsaPrivateKey, message: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(message);
    key.sign_with_rng(&mut thread_rng(), Pss::new_with_salt::<Sha256>(32), &digest)
        .expect("sign synthetic header")
}

fn encrypt(block: &mut [u8; 0xc00]) {
    let first = Aes128::new(GenericArray::from_slice(&HEADER_KEY[..0x10]));
    let second = Aes128::new(GenericArray::from_slice(&HEADER_KEY[0x10..]));
    let xts = Xts128::new(first, second);
    xts.encrypt_area(&mut block[..0x400], 0x200, 0, |index| index.to_be_bytes());
    xts.encrypt_area(&mut block[0x400..], 0x200, 2, |index| index.to_be_bytes());
}

fn pfs0(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut strings = Vec::new();
    let mut name_offsets = Vec::new();
    for (name, _) in entries {
        name_offsets.push(u32::try_from(strings.len()).unwrap());
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
    }
    let mut payload = Vec::new();
    let mut records = Vec::new();
    for (_, data) in entries {
        records.push((
            u64::try_from(payload.len()).unwrap(),
            u64::try_from(data.len()).unwrap(),
        ));
        payload.extend_from_slice(data);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PFS0");
    bytes.extend_from_slice(&u32::try_from(entries.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(&u32::try_from(strings.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    for ((offset, size), name_offset) in records.iter().zip(name_offsets) {
        bytes.extend_from_slice(&offset.to_le_bytes());
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(&name_offset.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
    }
    bytes.extend_from_slice(&strings);
    bytes.extend_from_slice(&payload);
    bytes
}
