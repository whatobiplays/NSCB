//! Test-only source-backed Split fixtures.
//!
//! The issuer in this module models the evidence seam that a future Split
//! producer uses. It hashes and measures the original synthetic source bytes
//! independently, writes an ordered canonical representation, re-reads and
//! validates every emitted part against that source, and only then commits a
//! local receipt. Tests must never derive trust from the generated parts alone.

use nscb::{Sha256Digest, SplitTrustReceipt, SplitTrustWriter};
use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};

/// One synthetic source and its canonical Split representation.
pub struct SplitFixture {
    pub source: Vec<u8>,
    pub parts: Vec<Vec<u8>>,
    pub manifest: Vec<u8>,
    pub source_sha256: Sha256Digest,
    pub manifest_sha256: Sha256Digest,
    written_directory: RefCell<Option<PathBuf>>,
}

impl SplitFixture {
    /// Splits `source` into deterministic nonempty parts of at most `part_size`.
    pub fn new(source: &[u8], part_size: usize) -> Self {
        assert!(!source.is_empty(), "v1 fixtures use nonempty sources");
        assert!(part_size > 0, "part size must be positive");
        let parts = source
            .chunks(part_size)
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        let manifest = manifest_for_parts(source, &parts);
        Self {
            source: source.to_vec(),
            parts,
            manifest_sha256: Sha256Digest::digest(&manifest),
            source_sha256: Sha256Digest::digest(source),
            manifest,
            written_directory: RefCell::new(None),
        }
    }

    /// Writes the canonical directory and sibling sidecar under `root`.
    pub fn write(&self, root: &Path, directory_name: &str) -> PathBuf {
        let directory = root.join(directory_name);
        fs::create_dir_all(&directory).expect("create Split directory");
        for (index, part) in self.parts.iter().enumerate() {
            fs::write(directory.join(format!("{index:02}")), part).expect("write Split part");
        }
        fs::write(sidecar_path(&directory), &self.manifest).expect("write Split manifest");
        *self.written_directory.borrow_mut() = Some(directory.clone());
        directory
    }

    /// Commits a first issuance through the test-only evidence seam.
    pub fn issue(&self, store: &dyn SplitTrustWriter) {
        self.revalidate_source_and_parts();
        store
            .issue(SplitTrustReceipt::new(
                self.manifest_sha256,
                self.source.len() as u64,
                self.source_sha256,
            ))
            .expect("issue first Split receipt");
    }

    /// Revalidates the source and outputs, then issues against the current
    /// store revision. This models a fresh authorized source-backed operation
    /// after revocation rather than a stale retry.
    pub fn requalify(&self, store: &dyn SplitTrustWriter) {
        self.revalidate_source_and_parts();
        let revision = store
            .lookup(&self.manifest_sha256)
            .expect("look up current Split revision")
            .map_or(0, |receipt| receipt.predecessor_revision());
        store
            .issue(
                SplitTrustReceipt::new(
                    self.manifest_sha256,
                    self.source.len() as u64,
                    self.source_sha256,
                )
                .with_predecessor_revision(revision),
            )
            .expect("issue fresh Split receipt");
    }

    /// Asserts that the manifest describes exactly the source and parts.
    pub fn revalidate_source_and_parts(&self) {
        let reconstructed = self.parts.concat();
        assert_eq!(
            reconstructed, self.source,
            "parts must reconstruct the source"
        );
        assert_eq!(
            self.manifest,
            manifest_for_parts(&self.source, &self.parts),
            "manifest must bind exact source and part evidence"
        );
        if let Some(directory) = self.written_directory.borrow().as_ref() {
            assert_eq!(
                fs::read(sidecar_path(directory)).expect("read written Split manifest"),
                self.manifest,
                "written manifest must equal the validated manifest"
            );
            for (index, part) in self.parts.iter().enumerate() {
                assert_eq!(
                    fs::read(directory.join(format!("{index:02}")))
                        .expect("read written Split part"),
                    *part,
                    "written part must equal its source slice"
                );
            }
        }
    }
}

/// Returns the deterministic sibling manifest path for a Split directory.
pub fn sidecar_path(directory: &Path) -> PathBuf {
    let mut name = directory
        .file_name()
        .expect("Split directory has a basename")
        .to_os_string();
    name.push(".nscb-split.json");
    directory.with_file_name(name)
}

/// Builds the exact bytes of a schema-v1 manifest for the supplied evidence.
pub fn manifest_document(source: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let segments = parts
        .iter()
        .enumerate()
        .map(|(index, part)| {
            serde_json::json!({
                "name": format!("{index:02}"),
                "size_bytes": part.len(),
                "sha256": Sha256Digest::digest(part).to_hex(),
            })
        })
        .collect::<Vec<_>>();
    let document = serde_json::json!({
        "schema_version": 1,
        "kind": "nscb.split_manifest",
        "required_features": [],
        "source": {
            "size_bytes": source.len(),
            "sha256": Sha256Digest::digest(source).to_hex(),
        },
        "segments": segments,
    });
    serde_json::to_vec_pretty(&document).expect("serialize Split manifest")
}

/// Convenience wrapper accepting owned parts.
pub fn manifest_for_parts(source: &[u8], parts: &[Vec<u8>]) -> Vec<u8> {
    let borrowed = parts.iter().map(Vec::as_slice).collect::<Vec<_>>();
    manifest_document(source, &borrowed)
}
