# Issue #75 native Windows 11 qualification

**Capture date:** 2026-11-14

**Policy revision:** `danielbyon/development-process@e2afa055d1126763c69f0e0392d25b86bab98014`

**Source issue:** [Issue #75](https://github.com/whatobiplays/NSCB/issues/75)

**Qualified source revision:** `5877bae6c05c86e03bf29e887387fb8885064376`

**Integration baseline:** `3cc7d4eeca4f29a954f45419122f635f58ee5040`

## Owner-approved decision

The contract is to reject directories. The `std::io::ErrorKind` returned while opening a directory may vary by platform, so the directory test now checks rejection without requiring `InvalidInput`. Separate regressions keep missing-path behavior at `NotFound` and confirm that a regular file opens successfully.

No production code changed. `open_regular`, file identity comparisons, Unix `O_NOFOLLOW`, the Unix symlink regression, and the Unix path-replacement regression remain unchanged. This evidence supersedes the pending decision language in the earlier Slice A record; that historical report remains unmodified.

## Host and toolchain

- Host: OBIGAMING, Windows 11 Pro x86_64, OS version `10.0.26200`, build `26200.9974` (25H2).
- Rust: `rustc 1.98.1 (48a229cea 2026-09-01)`, host `x86_64-pc-windows-msvc`.
- Cargo: `1.98.1 (797e8a9bc 2026-08-05)`; Clippy: `0.1.98 (48a229ceae 2026-09-01)`.
- MSVC: x64 compiler `19.51.36260.0`, tool directory `14.51.36231`; `vcvars64.bat` was initialized for the qualification commands.
- Actual worktree: `%USERPROFILE%\.codex\worktrees\issue-75-final-windows-qualification\nscb`, the Windows case-insensitive match for the approved `...\NSCB` path.
- `RUSTUP_TOOLCHAIN` was set to `1.98.1-x86_64-pc-windows-msvc` for every Cargo run.

## Reproduction and native results

The baseline directory test was run before edits at the integration baseline. It failed as expected: Windows returned `NotFound`, while the old assertion required `InvalidInput` (exit 101; 0 passed, 1 failed, 265 filtered). Its raw output files were opened at `2026-11-14T06:07:36.882Z`; the exit sidecar was recorded at `2026-11-14T06:07:53.350Z`. The first reproduction did not have separate start/end marker files; its exact command, working directory, output and exit are preserved privately.

The committed source revision was then tested on OBIGAMING:

| Command | UTC start – finish | Result |
|---|---|---|
| `cargo test --locked --no-default-features --lib provider::tests::a_directory_is_not_opened_as_a_regular_file -- --exact` | 06:19:07.9197850Z – 06:19:09.5888779Z | exit 0; 1 passed |
| `cargo test --locked --no-default-features --lib provider::tests::a_missing_path_remains_not_found -- --exact` | 06:19:09.6155674Z – 06:19:12.0889809Z | exit 0; 1 passed |
| `cargo test --locked --no-default-features --lib provider::tests::a_regular_file_is_accepted -- --exact` | 06:19:12.0944848Z – 06:19:16.8316882Z | exit 0; 1 passed |
| `cargo test --locked --no-default-features --lib` | 06:19:16.8398638Z – 06:19:25.3457799Z | exit 0; 264 passed, 0 failed, 4 ignored; 268 total |
| `cargo clippy --locked --no-default-features --lib -- -D warnings` | 06:19:25.3724633Z – 06:19:29.5936767Z | exit 0; no warnings |
| `cargo fmt --all -- --check` | 06:19:29.6044994Z – 06:19:34.4072047Z | exit 0 |

Each command ran from the task worktree with the selected MSVC toolchain. The complete raw stdout and stderr, command runners, exit sidecars, and UTC markers remain private under `%LOCALAPPDATA%\NSCB\qualification\issue-75\windows11-20261114T055937Z\`. They were not committed. The JSON manifest records SHA-256 digests for the raw qualification outputs and the sanitized log.

## CI and platform boundaries

The workflow adds separate Windows Server 2025 jobs for the full no-default-features library suite and strict library Clippy, both pinned and host-checked as Rust 1.98.1 MSVC. It also adds a hosted macOS 15 ARM64 `make all` job. These are GitHub-hosted checks and are not evidence from OBIGAMING; their results are recorded by the draft PR checks.

The native Windows full suite does not compile Unix-gated symlink and path-replacement tests. Their source and security behavior are unchanged; the hosted macOS `make all` job exercises the applicable Unix tests when that job runs. No local macOS execution is claimed. PAC/TAC identifiers were not present in Issue #75; none were invented, and Issue #73's PAC-5 remains separate and unchanged.

## Review, scope, and risk

- Independent read-only Standards and Spec reviews covered the full implementation and CI diff from the approved baseline; both returned no actionable findings.
- Risk classification: **low**. The code change is test-only; production file opening, identity, and security behavior does not change. Hosted Windows Server and macOS CI outcomes are reported separately on the draft PR.
- No Issue #73 or Issue #47 obligations were changed. Issue #75 remains open; this work does not merge or close it.

The sanitized output excerpts are in [the companion log](qualification-run-windows-11-2026-11-14.sanitized.log); raw and sanitized digests are in the companion JSON manifest.
