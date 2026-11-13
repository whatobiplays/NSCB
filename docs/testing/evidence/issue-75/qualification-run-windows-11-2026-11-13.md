# Issue #75 native Windows 11 library qualification

**Capture date:** 2026-11-13
**Policy revision:** 142422527de28b8e20dea1158d2f54d020dcdcd5 ([development-process](https://github.com/danielbyon/development-process/commit/142422527de28b8e20dea1158d2f54d020dcdcd5))
**Source issue:** [Issue #75](https://github.com/whatobiplays/NSCB/issues/75)
**Scope:** Slice A diagnosis and sanitized evidence only. No production fixes, persistent behavioral-test changes, or CI changes were made.

## Decision summary

The exact base and candidate were tested on the same native Windows 11 x86_64 host with Rust 1.98.1 MSVC. The complete approved library-test and strict Clippy matrix failed on both revisions in the same seven tests and at the same Clippy import. All seven failures are baseline behavior; none was introduced or materially worsened by the candidate. No PR #74 post-merge regression escalation was triggered.

The unmodified full library run reported **234 passed, 7 failed, 4 ignored** on base and **250 passed, 7 failed, 4 ignored** on candidate. Serial runs produced the same counts. The candidate's four focused allocator-wrapper tests passed. The complete Windows library suite did not pass.

The root causes are established for all seven tests and strict Clippy:

- The directory test expects InvalidInput, while opening an existing directory through Windows OpenOptions returns NotFound / Win32 ERROR_PATH_NOT_FOUND (3) before the metadata check.
- Five cache tests fail at the same initial object install: Windows rejects renaming the temporary object directory while its executable file handle is still open. The rename returns PermissionDenied / ERROR_ACCESS_DENIED (5); after dropping the file handle, the same rename succeeds.
- The Split cleanup test's held-lock probe returns Uncategorized / ERROR_LOCK_VIOLATION (33), which the current loop does not treat as retryable contention; it returns Unavailable before cancellation is observed.
- Strict Clippy rejects an unused Windows AsRawHandle import. The same import and same diagnostic are present at base and candidate.

## Revision and worktree identity

| Role | Commit | Git tree |
|---|---|---|
| Integration baseline | a50bf383d16412a30f636a4011d43378974c0632 | task branch parent |
| Base | bb1c6a8a5bd067ad49e3fab04f28fc181c6352fc | 7ce878845687d55089fb98e57c8f8a46e9d93e25 |
| Candidate | 0878126cf35f769a70bd74a1ad054be1bb70edd4 | 90741884c4cf9eaf57aaaf7faa1e9714e49930e9 |

The task branch is codex/issue-75-windows-library-portability, based on the approved integration baseline. Live origin/main was verified as the same baseline during bootstrap and immediately before evidence publication. The base and candidate qualification worktrees were detached and clean before the matrix. Temporary diagnostic edits were restored; both are clean at the exact commits above.

Relevant source SHA-256 fingerprints, including test-only candidate changes, are recorded in the adjacent JSON manifest. src/provider/cache.rs, src/split_trust.rs, and src/provider/process.rs are byte-identical across the two source revisions. The original Issue #73 evidence was not modified.

During bootstrap, fetching the missing integration commit briefly advanced the local origin/main tracking ref from ae16343827b5425779cf519e48aec38c6f55660c to the verified live a50bf383d16412a30f636a4011d43378974c0632. The old tracking-ref value was immediately restored with compare-and-swap. The primary checkout remained clean; no existing worktree was modified.

## Host and toolchain

- Host: OBIGAMING, platform API Windows-11-10.0.26200-SP0, display version 25H2, build 26200.9974, AMD64 / x86_64.
- Windows registry ProductName reads Windows 10 Pro; the platform API reports Windows 11 and the build is recorded above.
- Rust: rustc 1.98.1 (48a229cea 2026-09-01), host x86_64-pc-windows-msvc; Cargo 1.98.1; Clippy 0.1.98.
- MSVC: compiler 19.51.36260, tool directory 14.51.36231; vcvars64.bat was initialized for all qualification commands.
- Each revision had independent Cargo home, Cargo target, TEMP, TMP, and NSCB state roots. Test fixtures used isolated temporary roots; no actual provider cache or Split trust state was accessed.
- The repo's checked-in Rust toolchain file selects GNU by default, so the command explicitly selected the installed 1.98.1-x86_64-pc-windows-msvc toolchain.

## Exact command matrix and results

Each Cargo command ran as:

rtk proxy rustup.exe run 1.98.1-x86_64-pc-windows-msvc cargo <Cargo arguments>

The full Cargo argument arrays, run phases, exact exit codes, raw stdout/stderr SHA-256 values, sanitized excerpts, and excerpt hashes are recorded per run in the JSON manifest. The unmodified matrix was recorded before instrumentation. After restoring the diagnostic patches, the full parallel and serial suites, all seven exact targeted tests, strict Clippy, and candidate allocator tests were run again against the restored source.

| Command | Base | Candidate |
|---|---:|---:|
| cargo test --locked --no-default-features --lib | exit 101; 234 passed, 7 failed, 4 ignored | exit 101; 250 passed, 7 failed, 4 ignored |
| Same, with -- --test-threads=1 | exit 101; 234 passed, 7 failed, 4 ignored | exit 101; 250 passed, 7 failed, 4 ignored |
| Seven individually targeted tests | each exit 101; each 0 passed, 1 failed | each exit 101; each 0 passed, 1 failed |
| cargo clippy --locked --no-default-features --lib -- -D warnings | exit 101 | exit 101 |
| cargo test --locked --no-default-features --lib test_allocator::tests -- --test-threads=1 | not applicable | exit 0; 4 passed |

The seven targeted test names are the directory test; the five cache tests for corrupt orphan, interrupted temporary entry, malformed newest pointer, tampered executable, and missing object; and split_trust::tests::cleanup_lease_cancellation_interrupts_store_lock_wait_without_leaking.

No broader default-feature test suite, integration suite, CI job, make workflow, real provider download, or test against the user's state was run. These are outside the approved Slice A matrix. No full Windows suite pass is claimed.

## Root-cause classification

| Failure | Base / candidate | Underlying I/O or lint cause | Classification |
|---|---|---|---|
| provider::tests::a_directory_is_not_opened_as_a_regular_file | Same failure | Instrumentation confirmed the temp path exists and is a directory (metadata=Ok(true)). OpenOptions::open returns NotFound, raw OS error 3, before open_regular reaches its metadata check. The local Windows SDK maps 3 to ERROR_PATH_NOT_FOUND. The directory is rejected; the assertion expects an error kind Windows does not return here. | Pre-existing / baseline |
| provider::cache::tests::corrupt_orphan_object_is_repaired_without_losing_the_archive_identity | Same failure | Initial install_archive reaches install_object.rename; rename returns PermissionDenied, raw 5. The temporary source exists and final destination does not. A diagnostic retry after dropping the still-open executable handle succeeds. | Pre-existing / baseline |
| provider::cache::tests::interrupted_temporary_entries_are_cleaned_without_removing_valid_generations | Same failure | Same initial object-install rename and handle-lifetime cause. | Pre-existing / baseline |
| provider::cache::tests::malformed_newest_pointer_falls_back_to_last_valid_artifact | Same failure | Same initial object-install rename and handle-lifetime cause; the later pointer fallback assertions are not reached. | Pre-existing / baseline |
| provider::cache::tests::tampered_cached_executable_is_not_reported_ready | Same failure | Same initial object-install rename and handle-lifetime cause. | Pre-existing / baseline |
| provider::cache::tests::new_pointer_with_missing_object_falls_back_to_previous_valid_artifact | Same failure | Same initial object-install rename and handle-lifetime cause. | Pre-existing / baseline |
| split_trust::tests::cleanup_lease_cancellation_interrupts_store_lock_wait_without_leaking | Same failure | The held lock yields ErrorKind::Uncategorized, raw 33 (ERROR_LOCK_VIOLATION). The retry loop handles WouldBlock and Interrupted, so this Windows contention result becomes Unavailable before the cancellation predicate is polled again. | Pre-existing / baseline |
| Strict Clippy | Same failure | src/provider/process.rs imports std::os::windows::io::AsRawHandle, but the Windows implementation uses the fully qualified trait path. Clippy reports the import as unused under -D warnings. | Pre-existing / baseline |

No failure is classified as environmental, non-reproducible, candidate-introduced, materially worsened, or unresolved. The failure signatures were reproduced in parallel, serial, individually targeted, and post-restoration runs. The cache and Split source files are identical across the revisions. No candidate-introduced P0/P1 was found.

## Candidate test allocator

The candidate adds a test-only global allocator wrapper (src/test_allocator.rs) and registers it under cfg(test). It delegates to System except for a scoped, thread-local refusal matching the exact tagged allocation site, occurrence, and layout. Its four focused tests passed. The seven library failures also reproduce on the base, have I/O or lock error signatures rather than allocation errors, and remain in serial execution. The allocator wrapper therefore does not explain the differential failures. Strict Clippy checks the non-test library and reports the same unused import on both revisions.

## Temporary instrumentation and restoration

Instrumentation was confined to the two disposable qualification worktrees and ran only after all unmodified results had been captured. It added error-stage/raw-code reporting for directory open, cache installation, and Split lock acquisition. A separate rename control logged source/destination state, dropped the open executable handle, and retried the rename. A final directory-path check recorded existence and metadata for the test's temp directory.

The exact patch-overlay SHA-256 identities, run-to-patch mapping, and diagnostic output hashes are in the JSON manifest. Diagnostic retries are not counted as qualification passes. Afterward, git restore removed all diagnostic edits. Both worktrees have empty git status; source file SHA-256 fingerprints match the original revisions.

The Win32 error mappings were checked against the locally installed Windows SDK winerror.h version 10.0.26100.0: ERROR_PATH_NOT_FOUND=3, ERROR_ACCESS_DENIED=5, and ERROR_LOCK_VIOLATION=33.

## Proposed Slice B work, pending a new ChatGPT-reviewed plan

These are proposals only. No production correction, persistent behavioral-test edit, or CI change was made in Slice A.

1. **Provider cache rename lifetime:** close the executable file handle after write/sync and before renaming its temporary parent directory. Preserve object immutability, digest validation, no-overwrite behavior, atomic publication, cleanup reporting, and recovery invariants. Add native Windows tests for first install, repair, interrupted temp cleanup, and failure cleanup.
2. **Split trust lock contention:** classify the observed Windows lock-violation result as retryable contention at the narrow lock-acquisition boundary, preserving cancellation polling, lock ownership, receipt authority, and cleanup guarantees. Add contention, cancellation, lock-release/reacquisition, and no-leak regressions.
3. **Directory rejection contract:** decide whether open_regular must normalize the error to InvalidInput or whether the contract is simply to reject directories. If the exact error kind is contractual, design a Windows-safe check that also preserves missing-path behavior and avoids weakening file identity checks. Add tests for an existing directory, missing path, and regular file.
4. **Strict Clippy:** remove or correctly scope the unused Windows trait import, then rerun the exact strict Clippy command on both revisions and the eventual implementation commit.
5. **CI follow-up:** no CI-specific root cause was established. Any Windows CI coverage change should be scoped separately after the correction slices and their native tests are reviewed.

All implementation slices require a new plan and ChatGPT review. Preserve Issue #73's supported NSP semantic profile and all cache integrity, Split trust authority, locking, cancellation, and recovery invariants.

## Evidence integrity and preservation

- Raw capture remains private and unchanged at %LOCALAPPDATA%\NSCB\qualification\issue-75\windows11-20261113T091610Z\raw; only sanitized excerpts and cryptographic digests are published.
- Original Issue #73 qualification logs and documentation were not altered.
- Sanitized run manifest: qualification-run-windows-11-2026-11-13.json
- Manifest SHA-256: a3f2a602d8b356017c96229cb2094d35245c491eaf28f59e1f4b0f64aa2fb392
- The candidate and base diagnostic patch files are retained only in the private capture root. Their hashes are recorded in the manifest.
- Issue #75 and Issue #47 remain open. PR #74 is already merged; Issue #73 remains closed.
