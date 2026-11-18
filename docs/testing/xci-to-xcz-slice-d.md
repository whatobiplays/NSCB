# XCI to XCZ Slice D Qualification

## 1. Authorization and supported profile

The product owner approved interoperable XCZ output that carries the selected 16-byte Program section key and counter in plaintext NCZ metadata, limited to the rights-free base Application profile. The approval is recorded in [Issue #17](https://github.com/whatobiplays/NSCB/issues/17#issuecomment-6957933172). NSP/NSZ approval was not used as authorization for this slice.

The synthetic fixtures contain no game content. The implementation retains key redaction, zeroization, private staging, and semantic validation. A published XCZ exposes the selected key and counter to anyone who obtains it. No result here establishes Nintendo authenticity, signature validity, Full Verification, or console installability.

## 2. Candidate and environment

- Repository: `whatobiplays/NSCB`
- Baseline: `2790b5bed2010211a75c9c8c8008f146b3557626`
- Branch: `codex/issue-17-xci-to-xcz-compression`
- Worktree: `/Users/daniel/.codex/worktrees/issue-17-xci-to-xcz-compression/NSCB`
- Host: macOS 27.0.1, build 26A434, Darwin arm64
- Rust: 1.98.1, host `aarch64-apple-darwin`, LLVM 22.1.8
- Cargo: 1.98.1

## 3. Acceptance results

| Group | Result | Evidence |
| --- | --- | --- |
| PAC-1: Format and interoperability | Pass | The interoperability run produced a 148,992-byte XCZ with SHA-256 `50cc8ab489b89249aecaf9a1dadfe29cab183567dcf2683ea387f2dbaa40e897`. Pinned NSZ commit `148218ff89bb4b607d07730a8cf87d5e1f249ebc` decoded the generated artifact successfully. The staged verifier checked HFS0 geometry and hashes, including the canonical empty auxiliary partitions. |
| PAC-2: Compression selection | Pass | The eight Engine tests and two CLI tests cover Balanced 9, Fast 3, Maximum 19, numeric levels 1–19, invalid levels, and frozen execution settings. |
| PAC-3: Round trip | Pass | Native tests exercise XCI → XCZ → XCI and compare exact logical Meta and Program NCA bytes. The pinned upstream decoder reconstructed Meta (`87bfa1629b651e3f49a9ba053fb3842c5c34e31c9303e6e1807703cd84e68e7f`) and Program (`166f438248bd9fbad65125fb76af5e002812e7a104902a516d626f3a6850bd2c`) byte-for-byte. The test does not require whole-XCI byte equality. |
| PAC-4: Safe publication | Pass | Engine tests cover Fail, Skip, Replace, AlreadyUpToDate, cancellation, source/key mutation, destination races, staged-output validation, and preservation of competing destinations. |
| PAC-5: Adversarial and regression behavior | Pass on native tests; cross-platform runtime unverified | Native tests reject malformed HFS0/NCZ data, bad hashes and frames, invalid offsets, unsupported profiles, and populated or otherwise nonempty auxiliary payload regions. They also verify missing application-key rejection before staging and report a Zstandard output write failure. Existing NSP/NSZ, XCI → NSP, and XCZ → XCI focused regressions pass. Linux and Windows GNU test targets compile; their tests were not executed on this macOS host. |
| PAC-6: Qualification evidence | Partial | Rights-free synthetic inputs, byte-identical deterministic replay, pinned upstream interoperability, and native macOS arm64 tests pass. The final `make all` run passed. Windows MSVC cross-compilation is unavailable because the host lacks the MSVC C toolchain/SDK. |

Deterministic replay produced byte-identical XCZ output with the same length and SHA-256. The artifact and replay both measured 148,992 bytes and had SHA-256 `50cc8ab489b89249aecaf9a1dadfe29cab183567dcf2683ea387f2dbaa40e897`. Both successful operation results reported `cleanup_incomplete`; the operation artifact inventory recorded the retained staging artifacts in their private workspaces. The temporary workspaces were removed after evidence capture. The interoperability artifact and replay predate the final zeroizing-buffer change in `src/ncz.rs`; `make all` passed with that change, but the external decoder and replay were not rerun against that exact source.

## 4. Local validation

All Cargo commands used the repository-pinned Rust 1.98.1 toolchain.

| Command or check | Result |
| --- | --- |
| `cargo test --locked --features standalone-job-history --test xci_to_xcz --test xci_to_xcz_cli --test nsp_nsz --test xci_to_nsp --test xci_to_nsp_cli --test xcz_to_xci_cli` | Pass: 56 tests, 0 failures. Suite counts: 9, 2, 17, 19, 4, and 5. |
| `make all` | Pass on the final source tree. Both library runs passed 595 tests with 4 ignored each; both serialized `cli_subprocess` runs passed. |
| `cargo check --locked --all-targets --all-features --target x86_64-unknown-linux-gnu` | Pass. This compiles the Linux unsupported-capability test; it does not execute it. |
| `CC_x86_64_pc_windows_gnu=/opt/homebrew/bin/x86_64-w64-mingw32-gcc cargo check --locked --all-targets --all-features --target x86_64-pc-windows-gnu` | Pass. This compiles the Windows GNU unsupported-capability test; it does not execute it. |
| Windows MSVC all-target check | Blocked by the host toolchain: the `ring` build cannot find `assert.h` without the MSVC compiler and Windows SDK. |
| Earlier full-suite and isolated flaky-test runs | Two earlier full runs hit `tests/cli_subprocess.rs::copy_subprocess::blocked_reporting_after_cancellation_preserves_the_source_and_destination` (`tests/cli_subprocess.rs:1268`): `filler process did not saturate the stdout pipe`. Its isolated rerun and the final full `make all` run both passed. Baseline reproduction was not run. |
| `cargo fmt --all -- --check`, Clippy, and content-policy checks | Pass in the full validation run. |

## 5. Changed-source coverage

Coverage used the Rust 1.98.1 `llvm-profdata` and `llvm-cov` tools with instrumented Slice D and adjacent conversion tests. External crates and Rust toolchain sources were excluded. The coverage run predates the final zeroizing-buffer change in `src/ncz.rs`, so its row does not measure that change. These are whole-file line metrics; large shared modules include unrelated behavior, so their percentages are not Slice D-only coverage.

| Source file | Executed / total lines | Line coverage |
| --- | ---: | ---: |
| `src/ncz.rs` | 439 / 486 | 90.33% |
| `src/nsp_nsz.rs` | 381 / 456 | 83.55% |
| `src/xci_format.rs` | 339 / 357 | 94.96% |
| `src/xci_to_xcz.rs` | 495 / 566 | 87.46% |
| `src/xcz_to_xci.rs` | 626 / 735 | 85.17% |
| `src/operation.rs` | 4,752 / 9,624 | 49.38% |
| `src/engine.rs` | 54 / 209 | 25.84% |

`src/operation.rs` and `src/engine.rs` contain many unrelated operations; their whole-file percentages are not used as Slice D thresholds. The coverage export did not provide a separate source row for `src/cli.rs`; the CLI behavior is covered by the passing JSON CLI tests, but no line percentage is claimed for that file. A broader profile merge was rejected because profiles from separate full-suite binaries used incompatible raw profile format versions; the focused profile set above merged successfully.

## 6. Evidence limits and follow-up

Linux and Windows GNU checks establish compilation of the unsupported-capability paths, not runtime behavior on those operating systems. Windows MSVC remains unverified. The final local `make all` run passed after earlier timing-sensitive failures in an unmodified pipe-saturation test. Draft-PR CI results and final candidate HEAD are recorded in the PR description after publication. No release qualification is claimed.
