mod support;

use nscb::split_finalization::{SplitFinalizationErrorCode, finalize_split_directory};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use support::split_fixture::SplitFixture;

static NEXT_TREE: AtomicU64 = AtomicU64::new(1);

struct TempTree(PathBuf);

impl TempTree {
    fn new(label: &str) -> Self {
        let id = NEXT_TREE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "nscb-split-finalization-{label}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn source(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| ((index * 17 + 3) % 251) as u8)
        .collect()
}

#[test]
fn finalizer_rejects_unlisted_entries_without_removing_them() {
    let tree = TempTree::new("inventory");
    let fixture = SplitFixture::new(&source(2048), 1024);
    let directory = fixture.write(&tree.0, "Game.nsp");
    let extra = directory.join(".DS_Store");
    fs::write(&extra, b"unrelated").unwrap();

    let error = finalize_split_directory(&directory).unwrap_err();

    assert_eq!(error.code(), SplitFinalizationErrorCode::InvalidSplitSet);
    assert_eq!(fs::read(extra).unwrap(), b"unrelated");
}

#[test]
fn finalizer_rejects_test_sized_segments_without_changing_the_set() {
    let tree = TempTree::new("profile");
    let fixture = SplitFixture::new(&source(2048), 1024);
    let directory = fixture.write(&tree.0, "Game.nsp");
    let first_part = fs::read(directory.join("00")).unwrap();

    let error = finalize_split_directory(&directory).unwrap_err();

    assert_eq!(error.code(), SplitFinalizationErrorCode::InvalidSplitSet);
    assert_eq!(fs::read(directory.join("00")).unwrap(), first_part);
}

#[cfg(unix)]
#[test]
fn finalizer_rejects_a_symlink_alias() {
    use std::os::unix::fs::symlink;

    let tree = TempTree::new("symlink");
    let fixture = SplitFixture::new(&source(2048), 4096);
    let directory = fixture.write(&tree.0, "Game.nsp");
    let alias = tree.0.join("selected.nsp");
    symlink(&directory, &alias).unwrap();

    let error = finalize_split_directory(&alias).unwrap_err();

    assert_eq!(error.code(), SplitFinalizationErrorCode::InvalidSplitSet);
    assert!(directory.is_dir());
}

#[test]
fn finalizer_accepts_a_consistent_single_segment_without_a_receipt() {
    let tree = TempTree::new("without-receipt");
    let fixture = SplitFixture::new(&source(2048), 4096);
    let directory = fixture.write(&tree.0, "Game.nsp");

    finalize_split_directory(&directory).unwrap();
}
