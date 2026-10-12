use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FILE_ID: AtomicU64 = AtomicU64::new(0);

pub struct EntrySpec<'a> {
    pub name: &'a str,
    pub offset: u64,
    pub size: u64,
}

pub struct TempInput {
    path: PathBuf,
}

impl TempInput {
    pub fn new(bytes: &[u8]) -> Self {
        let id = NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("nscb-synthetic-{}-{id}.pfs0", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create a unique synthetic test input");
        file.write_all(bytes).expect("write synthetic test input");
        Self { path }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempInput {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn valid_container_probe_fixture() -> Vec<u8> {
    let name = "a\"\n\\b";
    pfs0(
        &[EntrySpec {
            name,
            offset: 2,
            size: 4,
        }],
        b"--DATA",
    )
}

pub fn pfs0(entries: &[EntrySpec<'_>], payload: &[u8]) -> Vec<u8> {
    let mut strings = Vec::new();
    let mut string_offsets = Vec::with_capacity(entries.len());
    for entry in entries {
        string_offsets.push(strings.len() as u32);
        strings.extend_from_slice(entry.name.as_bytes());
        strings.push(0);
    }

    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PFS0");
    bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    for (entry, name_offset) in entries.iter().zip(string_offsets) {
        bytes.extend_from_slice(&entry.offset.to_le_bytes());
        bytes.extend_from_slice(&entry.size.to_le_bytes());
        bytes.extend_from_slice(&name_offset.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
    }
    bytes.extend_from_slice(&strings);
    bytes.extend_from_slice(payload);
    bytes
}
