# Control NCA qualification run — 2026-11-14

## Candidate and environment

- Repository: `whatobiplays/NSCB`
- Approved baseline: `3cc7d4eeca4f29a954f45419122f635f58ee5040`
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
| `cargo test --locked --no-default-features --lib control_nca_qualification::tests::` | Passed: 16 tests. |
| `cargo test --locked --no-default-features --lib nca_crypto::tests::` | Passed: 4 tests. |
| `cargo test --locked --no-default-features --lib nsp_semantic_qualification::tests::` | Passed: 11 tests. |
| `cargo test --locked --no-default-features --test nsp_semantic_qualification` | Passed. |
| `cargo test --locked --no-default-features --test xci_to_nsp` | Passed. |
| `cargo test --locked --features standalone-job-history --test xci_to_nsp_cli` | Passed. |
| `cargo test --locked --no-default-features --lib verification::tests::` | Passed. |

The repository's `make all` target also passed content policy, formatting,
Clippy with warnings denied, Cargo checks, build, and CLI smoke checks. Its
Python policy and cleanup suites passed 53 and 11 tests respectively.

## Coverage

Coverage was collected with the versioned `cargo-llvm-cov 0.9.1` release:

```sh
cargo llvm-cov --locked --no-default-features --lib --lcov \
  --output-path /tmp/nscb-issue79-tools/coverage.lcov \
  --ignore-filename-regex 'control_nca_(qualification_tests|test_fixture)\.rs'
```

The report excludes the separate qualification test and fixture files, the
inline `#[cfg(test)]` code, and the test-only checkpoint adapter. It measured:

| Production source | Covered executable lines | Line coverage |
| --- | ---: | ---: |
| `control_nca_qualification.rs` | 1,053 / 1,229 | 85.7% |
| `nca_crypto.rs` | 93 / 106 | 87.7% |
| Combined | 1,146 / 1,335 | 85.8% |

Combined production line coverage is 85.8%, below the 90% target. The target is
advisory rather than a release gate. Uncovered lines include defensive error
and malformed-input branches.

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
