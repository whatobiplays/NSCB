# Control NCA qualification run — 2026-11-14

## Candidate and environment

- Repository: `whatobiplays/NSCB`
- Approved baseline: `3cc7d4eeca4f29a954f45419122f635f58ee5040`
- Local validation base HEAD: `360ef607cd937c702513d841bf62ca1e709591f1`
- Baseline-to-candidate implementation diff SHA-256, excluding this run record: `e3b44a920ccfca5fffe71f8982ea1d60f0f5e5d5fdefc78659b3d69d856dfe4b`
- Draft PR: [#81](https://github.com/whatobiplays/NSCB/pull/81); the PR description records the final commit, complete diff identity, and platform CI outcomes.
- Policy pin: `e2afa055d1126763c69f0e0392d25b86bab98014`
- Branch: `codex/issue-79-control-ivfc-romfs-qualification`
- Worktree: `/Users/daniel/.codex/worktrees/issue-79-control-ivfc-romfs-qualification/NSCB`
- Host: macOS 27.0.1 (build 26A434), Darwin arm64
- Rust: `rustc 1.98.1 (48a229cea 2026-09-01)`; Cargo 1.98.1
- Coverage tool: `cargo-llvm-cov 0.9.1`, official Apple silicon release SHA-256
  `7e821a6c90c0884f79f759f5d9be50799ade67bb82515186d922f26032ef43b8`

Fixtures are built at runtime from synthetic bytes and fixed test keys. They
contain no retail content or proprietary keys.

## Local qualification

All commands used the pinned Rust 1.98.1 toolchain.

| Command | Result |
| --- | --- |
| `make all` | Passed. All configured checks, builds, smoke checks, and test targets completed. Rust test binaries reported 1,749 passed, 0 failed, and 8 ignored across both feature configurations. |
| `cargo test --locked --no-default-features --lib control_nca_qualification::tests::` | Passed: 19 tests. |
| `cargo test --locked --no-default-features --lib control_nca_qualification::tests::source_and_key_mutation_are_detected_after_open` | Passed: 1 test with a fixed FAT-compatible modification time for same-size mutations. |
| `cargo test --locked --no-default-features --lib nca_crypto::tests::` | Passed: 4 tests. |
| `cargo test --locked --no-default-features --lib nsp_semantic_qualification::tests::` | Passed: 11 tests. |
| `cargo test --locked --no-default-features --test nsp_semantic_qualification` | Passed. |
| `cargo test --locked --no-default-features --test xci_to_nsp` | Passed. |
| `cargo test --locked --features standalone-job-history --test xci_to_nsp_cli` | Passed. |
| `cargo test --locked --no-default-features --lib verification::tests::` | Passed. |

The repository's `make all` target also passed content policy, formatting,
Clippy with warnings denied, Cargo checks, build, and CLI smoke checks. Its
Python policy and cleanup suites passed 53 and 11 tests respectively.

The first PR CI candidate failed the Windows same-size mutation assertion
because an immediate write could preserve the timestamp reported by the
filesystem. The regression now sets the modified time to 2000-01-01, which is
within FAT's supported range and asserts that the timestamp differs from the
original snapshot. The first run was `43590398374` on HEAD
`360ef607cd937c702513d841bf62ca1e709591f1`. Windows Clippy, Windows NSP/XCI,
Linux NSP/XCI, and macOS `make all` jobs passed. The final platform run is
recorded in the linked PR.

## Coverage

Coverage was collected with the versioned `cargo-llvm-cov 0.9.1` release:

```sh
cargo llvm-cov --locked --no-default-features --lib --lcov \
  --output-path /tmp/nscb-issue79-tools/coverage.lcov \
  --ignore-filename-regex 'control_nca_(qualification_tests|test_fixture)\.rs'
```

The report excludes the separate qualification test and fixture files. The
qualifier source file still contains inline `#[cfg(test)]` support code, so its
file-level result includes those lines. The JSON summary measured:

| Production source | Covered executable lines | Line coverage |
| --- | ---: | ---: |
| `control_nca_qualification.rs` | 1,107 / 1,381 | 80.2% |
| `nca_crypto.rs` | 152 / 172 | 88.4% |
| Combined | 1,259 / 1,553 | 81.1% |

Combined file-level coverage is 81.1%, below the 90% target. The target is
advisory rather than a release gate. Uncovered lines include defensive error
and malformed-input branches. LCOV SHA-256:
`634c3fe1fabb21064eb09caee564ddd0f55cd2f770e5b4212ab866edba386225`.

## Format sources

The parser and padding rules were independently cross-checked against these
fixed revisions. They are community references rather than normative
specifications:

- hactool `1d64a83450e025622f3468c28fc4164dad2c5ef6`: [`ivfc.h`](https://github.com/SciresM/hactool/blob/1d64a83450e025622f3468c28fc4164dad2c5ef6/ivfc.h), [`nca.c`](https://github.com/SciresM/hactool/blob/1d64a83450e025622f3468c28fc4164dad2c5ef6/nca.c), and [`romfs.c`](https://github.com/SciresM/hactool/blob/1d64a83450e025622f3468c28fc4164dad2c5ef6/romfs.c).
- hacPack `e506cb58b7843d86df7518156debd28f3b575638`: [`ivfc.c`](https://github.com/DarkMatterCore/hacPack/blob/e506cb58b7843d86df7518156debd28f3b575638/ivfc.c), [`nca.c`](https://github.com/DarkMatterCore/hacPack/blob/e506cb58b7843d86df7518156debd28f3b575638/nca.c), and [`romfs.c`](https://github.com/DarkMatterCore/hacPack/blob/e506cb58b7843d86df7518156debd28f3b575638/romfs.c).
- Switchbrew NCA page revision 14983: [pinned page](https://switchbrew.org/w/index.php?title=NCA&oldid=14983).

The supported profile, zero-padding distinctions, and derivation of the
4,194,309 hash-operation ceiling are documented in
[`control-nca-qualification.md`](../control-nca-qualification.md). The exact
candidate SHA, cumulative diff hash, independent review findings, and
Windows/Linux CI results are recorded in the Issue #79 draft PR description.
