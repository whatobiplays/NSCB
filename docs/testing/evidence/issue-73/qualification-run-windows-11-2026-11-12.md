# Issue #73 native Windows 11 x86_64 qualification

**Run date:** 2026-11-12 (America/Los_Angeles)  
**Run window:** 2026-11-13 05:23:28Z–05:28:39Z  
**Host:** `OBIGAMING`  
**Source:** `0878126cf35f769a70bd74a1ad054be1bb70edd4`  
**Policy revision (provided for this run):** `142422527de28b8e20dea1158d2f54d020dcdcd5`

This record documents the supported, synthetic, rights-free NSP semantic
qualifier profile. It does not expand that profile or change implementation
source or tests. The working tree was clean at the tested source commit. The
Cargo lockfile SHA-256 was
`efbaf094a72ec521b1ffea750c4b67147fc0a625588c62d38dda2fe7add429ad`.

## Host and toolchain

| Item | Observed value |
| --- | --- |
| Computer | `OBIGAMING` |
| Windows edition/version/build | Windows 11 Pro, 25H2, version `10.0.26200`, build `26200.9974` |
| OS architecture | 64-bit / `X64` |
| Process architecture | `.NET RuntimeInformation.ProcessArchitecture = X64` |
| CPU | Intel(R) Core(TM) i7-14700K; WMI architecture `9` (x64), address/data width 64 |
| System manufacturer/model | Gigabyte Technology Co., Ltd.; Z790 AORUS ELITE AX |
| Virtualization observations | WMI `HypervisorPresent=True`; `VirtualizationFirmwareEnabled=False`, `VMMonitorModeExtensions=False`, `SecondLevelAddressTranslation=False`. The reported system is the local OBIGAMING desktop; WMI reports no VM product model. The hypervisor flag is retained as observed and is not treated as evidence of architecture emulation. |
| Rust compiler | `rustc 1.98.1 (48a229cea 2026-09-01)`; host `x86_64-pc-windows-msvc`; LLVM `22.1.8` |
| Cargo | `cargo 1.98.1 (797e8a9bc 2026-08-05)` |
| Active rustup toolchain | `1.98.1-x86_64-pc-windows-msvc` |
| MSVC | Visual Studio 18 BuildTools; MSVC tools `14.51.36231`; Windows SDK `10.0.26100.0`; x64 `cl.exe` and `link.exe` available |

The test process used the native MSVC target, an x64 Visual Studio developer
environment, and no Cargo target override or compiler wrapper. No Windows
Server, cross-compiled, or architecture-emulated result is counted here. The
system model and CPU identify the local physical desktop; the available
evidence did not identify a separate VM host, so no guest-to-host provenance
is claimed.

## Commands and results

All six requested commands ran and passed. The applicable focused NCA mapping,
allocator-refusal, source-read sanitization, and PFS0 checks also passed.
Together, the twelve focused invocations produced 57 passing test executions
(some individual checks repeat tests selected by a broader filter); none
failed, were ignored, or were skipped.

Each linked sanitized log contains the exact Cargo argument vector and capture
wrapper, sanitized working-directory marker, source revision, start/end UTC,
exit status, test counts, raw stdout/stderr SHA-256 values, and complete
captured stdout and stderr. The companion
[hash manifest](windows11-2026-11-12/hash-manifest.json) records each
sanitized-log SHA-256 alongside the raw-stream hashes. The exact local working
directory and unredacted command metadata are retained only in the private raw
archive.

| # | Exact Cargo command | Result | Sanitized log |
| --- | --- | --- | --- |
| 1 | `cargo test --locked --no-default-features --lib nsp_semantic_qualification::tests::` | 11 passed | [01](windows11-2026-11-12/logs/01-nsp-semantic-unit-sanitized.log) |
| 2 | `cargo test --locked --no-default-features --lib key_file::qualification_tests::` | 4 passed | [02](windows11-2026-11-12/logs/02-key-file-sanitized.log) |
| 3 | `cargo test --locked --no-default-features --lib pfs0::tests::caller_metadata_limit_is_checked_before_reading_declared_tables` | 1 passed | [03](windows11-2026-11-12/logs/03-pfs0-metadata-limit-sanitized.log) |
| 4 | `cargo test --locked --no-default-features --test nsp_semantic_qualification` | 20 passed | [04](windows11-2026-11-12/logs/04-nsp-semantic-integration-sanitized.log) |
| 5 | `cargo test --locked --no-default-features --lib reservation -- --test-threads=1` | 8 passed | [05](windows11-2026-11-12/logs/05-reservation-sanitized.log) |
| 6 | `cargo test --locked --no-default-features --lib test_allocator::tests:: -- --test-threads=1` | 4 passed | [06](windows11-2026-11-12/logs/06-test-allocator-sanitized.log) |
| 7 | `cargo test --locked --no-default-features --lib nca_allocation_failure -- --test-threads=1` | 4 passed | [07](windows11-2026-11-12/logs/07-nca-error-mappings-sanitized.log) |
| 8 | `cargo test --locked --no-default-features --lib nsp_semantic_qualification::tests::actual_bounded_qualifier_reservations_refuse_with_sanitized_errors -- --test-threads=1` | 1 passed | [08](windows11-2026-11-12/logs/08-end-to-end-allocator-refusal-sanitized.log) |
| 9 | `cargo test --locked --no-default-features --lib nsp_semantic_qualification::tests::allocation_reservation_failure_maps_to_a_typed_error -- --test-threads=1` | 1 passed | [09](windows11-2026-11-12/logs/09-typed-allocation-failure-sanitized.log) |
| 10 | `cargo test --locked --no-default-features --lib nca_member_source_read_failure_is_sanitized_and_typed` | 1 passed | [10](windows11-2026-11-12/logs/10-sanitized-source-read-sanitized.log) |
| 11 | `cargo test --locked --no-default-features --lib parses_payload_relative_spans_without_reading_payload_bytes` | 1 passed | [11](windows11-2026-11-12/logs/11-pfs0-payload-spans-sanitized.log) |
| 12 | `cargo test --locked --no-default-features --lib nca::tests::span_reservation_refusal_is_typed_and_inspection_mapped -- --test-threads=1` | 1 passed | [12](windows11-2026-11-12/logs/12-nca-inspection-mapping-sanitized.log) |

The broader native checks were also run and are reported without treating
their failures as passes:

| # | Exact command | Result | Sanitized log |
| --- | --- | --- | --- |
| 13 | `cargo test --locked --no-default-features --lib` | Exit 101; 250 passed, 7 failed, 4 ignored | [13](windows11-2026-11-12/logs/13-full-no-default-lib-sanitized.log) |
| 14 | `cargo clippy --locked --no-default-features --lib -- -D warnings` | Exit 101; unused import `std::os::windows::io::AsRawHandle` in `src/provider/process.rs:16` | [14](windows11-2026-11-12/logs/14-clippy-lib-sanitized.log) |
| 15 | `cargo test --locked --no-default-features --lib -- --test-threads=1` | Exit 101; reproduced 250 passed, 7 failed, 4 ignored | [15](windows11-2026-11-12/logs/diagnostics/15-full-no-default-lib-serial-sanitized.log) |
| 16 | `cargo test --locked --no-default-features --lib provider::cache::tests::malformed_newest_pointer_falls_back_to_last_valid_artifact -- --exact` | Exit 101; isolated provider-cache failure | [16](windows11-2026-11-12/logs/diagnostics/16-provider-cache-single-sanitized.log) |
| 17 | `cargo test --locked --no-default-features --lib provider::tests::a_directory_is_not_opened_as_a_regular_file -- --exact` | Exit 101; observed `NotFound`, expected `InvalidInput` | [17](windows11-2026-11-12/logs/diagnostics/17-provider-directory-single-sanitized.log) |
| 18 | `cargo test --locked --no-default-features --lib split_trust::tests::cleanup_lease_cancellation_interrupts_store_lock_wait_without_leaking -- --exact` | Exit 101; isolated `Unavailable` failure | [18](windows11-2026-11-12/logs/diagnostics/18-split-trust-single-sanitized.log) |

The seven broad-library failures were: the provider directory-open error
kind assertion above; five provider-cache tests failing at
`install_archive(...).unwrap()` with `InternalIo`; and
`split_trust::tests::cleanup_lease_cancellation_interrupts_store_lock_wait_without_leaking`
returning `Unavailable`. The serial rerun reproduced the same seven failures,
and each representative failure was reproduced in isolation. The underlying
I/O cause reported through `InternalIo` was not exposed, so no cause is
inferred. The provider-cache and split-trust implementation files are outside
the PR's changed-file set; the directory-open assertion is in a changed
provider module but exercises a separate path from the NCA allocation mapping
under qualification. These failures remain visible for final review.

`make all` was not run because `make` was not available on this host. No Miri,
sanitizer, or real operating-system memory-pressure run was performed. No
controlled or uncontrolled OOM experiment was attempted.

## Raw and sanitized evidence

Original stdout and stderr streams and exact command metadata are byte-
preserved in the private archive at
`%LOCALAPPDATA%\NSCB\qualification\issue-73\windows11-20261113T052326Z\raw`.
The published files are sanitized derivatives; their headers disclose path
redaction and preserve the original raw-stream hashes. No raw output was
rewritten. Sanitized logs were checked for user names, private home/worktree
paths, secret-like strings, proprietary keys, and rights-bearing content.

The sanitized hash manifest SHA-256 is
`356c60ad8398ce9678abfe997bc81eca1c916106924024770d53e8b6880cf83c`.
It lists the original raw stdout and stderr SHA-256 values separately from
each sanitized log SHA-256. The raw stream hashes are also embedded in each
sanitized log header. The failed first capture attempt from earlier in the
session is not part of this run and is not used as qualification evidence.

## PAC/FUP disposition

| Item | Status after this run |
| --- | --- |
| FUP-1 / PAC-3 | **PASS — owner accepted for the supported profile.** Twelve site-attributed refusal cases remain the evidence boundary. Standard-library path-buffer requests remain `NOT_EVIDENCED`; genuine OS memory pressure remains `NOT_RUN`; capacity overflow is separate. The same-handle snapshot threat model and its hostile-writer-with-restored-metadata limitation are unchanged. |
| FUP-2 / PAC-5 | **PASS for the supported profile's focused native Windows 11 x86_64 qualification.** All six required commands and the applicable focused mapping/refusal tests passed at the exact source SHA above. Supplemental full-library and Clippy failures are disclosed above and remain for final readiness review. |
| FUP-3 | **Updated** with this Windows host record, the sanitized logs, and separate raw/sanitized hashes. |
| FUP-4 | **Independent evidence-delta review PASS; final ChatGPT readiness review pending.** Non-authoring standards/evidence-hygiene and requirements reviews found no blocking findings. |

## Independent evidence-delta review

The non-authoring `evidence_standards_review` verified evidence hygiene,
privacy, link integrity, all 36 raw stdout/stderr hashes, all sanitized-log
hashes, and the manifest SHA-256. It returned `PASS` with no blocking finding.
The non-authoring `evidence_spec_review` checked the evidence against the
qualification requirements, including the disclosed broad-suite failures and
FUP/PAC scope. It returned `PASS` with no blocking spec mismatch. Neither
reviewer changed files or ran tests. The final ChatGPT readiness review remains
pending; this record does not authorize merging or closing Issue #73.

This Windows run contributes partial software evidence for Issue #47's
Windows 11 x86_64 row only. Issue #47's full platform workload and its
separate responder/provider, driver/permission, helper-license/hash, and
physical-device obligations remain open. No merge or issue closure is
authorized by this record.
