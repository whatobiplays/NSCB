# XCI to NSP with Control Content

## Policy provenance

Slice B uses owner-approved policy revision
`e2afa055d1126763c69f0e0392d25b86bab98014`. The approval leaves production
Skill activation pending.

Slice A's qualification contract retains its historical policy revision
`142422527de28b8e20dea1158d2f54d020dcdcd5` in
`docs/testing/xci-to-nsp-slice-a.md`.

## 1. Supported source profiles

The conversion accepts two secure-member profiles:

1. A rights-free base Application with one Meta NCA and one Program NCA. This is the existing profile.
2. A rights-free base Application with one Meta NCA, one Program NCA, and one Control NCA.

Member roles come from parsed NCA headers and content relationships. Filenames do not select a role. The three-member profile requires an Application CNMT with exactly two rows: one Program row and one Control row. Program uses CNMT content-row type `1`; Control uses row type `3`. The NCA header uses Control content type `2`.

Each row must have zero attributes and ID offset, the exact NCA size, the complete 32-byte SHA-256 of the NCA, and the corresponding 16-byte ContentId. The CNMT title ID and each NCA header provide title identity. Content rows do not contain a title ID.

The two-member public NSP semantic qualifier remains limited to Meta and Program. XCI conversion keeps private tagged facts for the two- and three-member profiles, so both source planning and output requalification use the evidence for the selected profile.

## 2. Control NCA checks

The three-member profile sends the exact Control NCA byte span to the crate-private Control qualifier. The bounded reader checks that the span fits inside the opened XCI or NSP file and treats its start as NCA offset zero. It does not create a temporary NCA file.

The qualifier checks a rights-free NCA3 Control header, supported key generation and key-area slot, one supported RomFS section, the section header digest, the full supported IVFC SHA-256 chain, required hash padding, and the RomFS metadata graph. It checks directory and file records, their links and extents, and the resource limits used by the existing validator. Unsupported layouts and malformed integrity data fail closed.

These checks establish structure and byte integrity for the supported profile. They do not establish signature authenticity, installability, retail compatibility, or Full Verification.

## 3. Output and operation behavior

The output is a canonical PFS0 package ordered as `meta.nca`, `program.nca`, then `control.nca`. Each NCA is copied byte-for-byte. Conversion applies no rights, delta, RSV, account, key-generation, or partition patches.

Planning captures source and key-file identity. Execution checks cancellation and revalidates those identities around qualification and publication. Staged output and an `AlreadyUpToDate` destination are requalified through the matching private profile path. Destination conflict policies retain their existing behavior, including no-change handling for `Skip` and `AlreadyUpToDate`.

The public request and result types, CLI flags, JSON and JSONL envelopes, and the two-member semantic qualification API remain unchanged. On targets without the native macOS conversion capability, the operation continues to report unsupported capability.

## 4. Synthetic qualification tests

Fixtures are built at test time and contain no redistributable game content. The tests cover both member profiles, misleading names, row order and linkage, duplicate and unsupported member sets, rights-bearing content, malformed Control headers, IVFC and RomFS faults, bounded-reader limits, source and key mutation, cancellation, staged-output validation, destination races, and conflict policies.

For Control integrity failures, the synthetic package builder recomputes the CNMT digest and the XCI/HFS0 wrapper evidence from the malformed NCA bytes. This keeps each test focused on the Control NCA check under test.

## 5. Native qualification record

Qualification ran on native macOS 27.0.1, build `26A434`, architecture `arm64`.
The repository's pinned Rust toolchain was used for the final test run.

```text
uname -m
arm64

rustc -vV
rustc 1.98.1 (48a229cea 2026-09-01)
binary: rustc
commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985
commit-date: 2026-09-01
host: aarch64-apple-darwin
release: 1.98.1
LLVM version: 22.1.8

cargo -V
cargo 1.98.1 (797e8a9bc 2026-08-05)
```

Focused results for this candidate:

| Command | Exit | Test output |
| --- | ---: | --- |
| `cargo test --locked --no-default-features --test xci_to_nsp` | 0 | 19 passed, 0 failed |
| `cargo test --locked --no-default-features --test xci_to_nsp_cli` | 0 | 1 passed, 0 failed |
| `cargo test --locked --features standalone-job-history --test xci_to_nsp_cli` | 0 | 4 passed, 0 failed |
| `cargo test --locked --no-default-features --lib nsp_semantic_qualification` | 0 | 12 passed, 0 failed |
| `cargo test --locked --no-default-features --lib control_nca_qualification` | 0 | 23 passed, 0 failed |
| `cargo test --locked --no-default-features --lib xci` | 0 | 25 passed, 0 failed |
| `make all` | 0 | 25 Rust test summaries: 1775 passed, 0 failed, 8 ignored |
| `cargo fmt --all -- --check` | 0 | Passed |
| `git diff --check` | 0 | Passed |
| `python3 -B scripts/check_content_policy.py` | 0 | Content policy passed for the Git index and working tree |

Coverage used `-C instrument-coverage`, profiles merged with Rust 1.98.1's
`llvm-profdata`, and reports generated with its matching `llvm-cov`. The
profile includes the XCI-to-NSP integration tests and the NSP semantic,
Control qualification, and XCI operation unit-test filters.

| Source file | Executed lines | Coverage |
| --- | ---: | ---: |
| `src/xci_to_nsp.rs` | 492 / 560 | 87.86% |
| `src/control_nca_qualification.rs` | 1162 / 1446 | 80.36% |
| `src/nsp_semantic_qualification.rs` | 1210 / 1631 | 74.19% |
| `src/operation.rs` | 2550 / 13272 | 19.21% |

The 90% goal was not met for these files. The operation module percentage
covers many unrelated operations; this run does not report a separate
percentage for its XCI-to-NSP paths. Uncovered lines remain in error, limit,
and general operation branches.
