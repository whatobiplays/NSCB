# NSP semantic qualification acceptance

## PAC crosswalk

Statuses below describe the current implementation evidence. `UNVERIFIED`
means that some required evidence is still missing; it is not a pass.

| PAC | Status | Evidence and remaining gap |
| --- | --- | --- |
| PAC-1 — Positive semantics | PASS | `qualifies_byte_backed_two_member_profile_despite_misleading_names` checks profile id `rights_free_base_application_v1`, byte-derived roles, exact member digests and sizes, source digest, deterministic repeat results, and unchanged input bytes. `verifies_multiple_hash_table_entries_and_a_partial_final_block` covers multiple table entries and a partial last block. hactool and NSTool independently read the synthetic NCA/PFS0; NSTool also displayed the expected Application CNMT and Program row. |
| PAC-2 — Negative semantics | PASS | The integration suite covers plain PFS0, misleading names, one or extra outer members, empty outer members, trailing, leading, and inter-member unreferenced payload at the outer level, the same unreferenced-payload cases in Program PFS0, trailing unreferenced Meta PFS0 payload, and valid reversed outer table order. It also covers duplicate Meta/Program roles, truncated and unsupported CNMT, unsupported section and key-generation profiles, nonzero RightsId, missing and malformed key prerequisites, wrong header key (`invalid_nca_header`), wrong key-area key (`key_or_section_integrity_failure`), Meta/Program title mismatch, and Program row hash, ContentId, size, type, IdOffset, and title-ID mismatches. |
| PAC-3 — Boundary safety | UNVERIFIED | Existing range, bounded-I/O, mutation, cancellation, and sanitized-read-failure tests remain. Test-only GlobalAlloc refusal is now attributed and observed at all 12 explicit bounded reservation sites, including the recorded site, occurrence, expected layout, actual layout, and single refusal. Standard-library path-buffer allocations remain `NOT_EVIDENCED`. The `usize::MAX` capacity-overflow case reaches the reservation wrapper but records no GlobalAlloc refusal. Genuine operating-system memory pressure is `NOT_RUN`, and the owner-approved same-handle snapshot still cannot detect a hostile writer that restores all observed metadata. PAC-3 awaits owner review of those limitations. |
| PAC-4 — API and compatibility | PASS | `make all` passed on macOS 27.0.1 arm64. The public change is additive and Engine-only, with no CLI/TUI qualification command. A separate unrestricted `cargo test --no-default-features` invocation fails in the existing `multi_content_operations` CLI integration test because the `nscb` binary requires `standalone-job-history`; the Makefile's supported no-default gate tests the library and runs integration tests with that feature. |
| PAC-5 — Native qualification | UNVERIFIED | The current host is macOS 27.0.1 build `26A434`, arm64. Prior PR CI run `43205172852` passed on macOS 15 arm64, Windows Server 2025 x86_64, Linux glibc x86_64, and Linux glibc arm64. No qualifying Windows 11 x86_64 host was available for this run, so FUP-2 is `NOT_RUN`. Windows Server 2025, cross-compilation, and architecture-emulated execution do not substitute. |
| PAC-6 — Review and format evidence | PASS | Pinned hactool, NSTool, and hacPack source references and synthetic-reader results are documented. The Issue #73 candidate received independent full-diff review, correction-delta review, and final direct ChatGPT source review; see the review record below. |

## Issue #73 follow-up crosswalk

| Follow-up | Status | Evidence and remaining decision |
| --- | --- | --- |
| FUP-1 — Allocator exhaustion / PAC-3 | Twelve tagged reservation sites evidenced; path-buffer requests `NOT_EVIDENCED`; PAC-3 remains `UNVERIFIED` | Each tagged site is targeted with a one-shot, per-thread failpoint that records its site, occurrence, expected layout, actual layout, and one refusal. Standard-library path buffers in `open_snapshot_file` are not site-tagged and remain `NOT_EVIDENCED`. The separate `usize::MAX` case records an unrepresentable layout and no injected refusal; it does not claim observed OS pressure. Genuine operating-system resource pressure is `NOT_RUN`; owner disposition of that residual and the preserved snapshot limitation is still required. |
| FUP-2 — Native Windows 11 x86_64 / PAC-5 | `NOT_RUN`; PAC-5 remains `UNVERIFIED` | The available host is macOS 27.0.1 arm64. No qualifying Windows 11 x86_64 host was available. A native x86_64 virtualized guest on a native x86_64 host is acceptable with host provenance; architecture-emulated x64 on ARM64 is excluded. Issue #73 stays open. |
| FUP-3 — Durable evidence and PAC crosswalk | Recorded | The [Issue #73 run record](evidence/issue-73/qualification-run-2026-11-12.md) contains the observed host/process limits, exact environment and commands, results, and durable raw logs. It preserves the distinct allocator-refusal, capacity-overflow, path-buffer `NOT_EVIDENCED`, and OS-pressure statuses. The original Issue #71 exception and snapshot threat model remain in the existing records. |
| FUP-4 — Independent and direct review | Recorded | Independent non-authoring full-diff review, independent review of the evidence-provenance correction, and final direct ChatGPT source review are complete. Review findings and dispositions are recorded below. |

## Issue #73 review record

Cubic's final local review could not save its session and changed no files:
"Cubic couldn't save the review session on this computer. No files were
changed." The approved non-authoring Codex review fallback was used.

The independent full-diff review used the v4 review snapshot with SHA-256
`eaa3dba7da685031352c1ab7ed460edbb7eedfbd48bc7e99ed590fbb34886bf2`
(76,055 bytes). The snapshot excluded raw transcripts; their hashes are in the
durable run record. Reviewers checked the source, tests, CI, documentation,
allocation attribution, PFS0 bounds, error mappings, and public scope. They
reported no blocking findings in the v4 candidate.

One reviewer found that the earlier source-patch digest lacked a reproducible
hashing procedure. The run record now lists SHA-256 hashes for all 12 changed
Rust source files. A full-diff reviewer confirmed every source hash, the
Cargo.lock hash, and both transcript hashes against the worktree. The
independent correction-delta review confirmed the manifest resolved the
finding and reported no remaining issues. Reviewers did not rerun tests;
validation results and raw logs are recorded separately.

Final direct ChatGPT source review found no unresolved in-scope findings. The
review confirmed that `PathBuf` allocation requests remain `NOT_EVIDENCED`,
genuine operating-system pressure remains `NOT_RUN`, FUP-2 remains `NOT_RUN`,
PAC-3 remains `UNVERIFIED`, and PAC-5 remains `UNVERIFIED`. These review
outcomes do not close Issue #73 or resolve the remaining owner decisions.

FUP-1 coverage note: the twelve refusal cases exercise the explicitly tagged
fallible reservations. `open_snapshot_file` also obtains canonical paths and
copies requested paths through standard-library APIs. Those `PathBuf`
allocation requests are not tagged and remain `NOT_EVIDENCED`; no allocator
failpoint is claimed for them. PAC-3 remains `UNVERIFIED`.

## Relationship to Issue #47

[Issue #47](https://github.com/whatobiplays/NSCB/issues/47) requires native
functional and safety testing on macOS arm64, Windows 11 x86_64, Linux glibc
2.35+ x86_64, and Linux glibc 2.35+ aarch64, plus exact responder/provider
qualification. Issue #47 also requires responder versions, MTP capabilities,
driver and permission setup, helper hashes and licenses, synthetic-fixture
coverage, and sanitized physical-device qualification evidence. This Issue #73
work provides only partial software-test evidence for the macOS arm64 row. It
does not establish the other host results or those responder/provider and
physical-device requirements. Issue #47's v1 universal-capability and
conditional DBI0 gates also remain separate; this task changes no advertised
capabilities. A future qualifying Windows 11 run may contribute to that row,
but it would not complete Issue #47, which remains open. No Issue #47
acceptance is claimed as complete here.

## Prior independent review record

The original full-diff review was performed by the non-authoring Codex agent
Porygon (`01a1cebd-e1f9-7123-8209-ae9fc771f39d`) against reviewed candidate
`d43c64b4663c9cc63a0818d7b13830f04dfd8119`. The reviewer initially raised a
P1 about the `0x88` CNMT extent, then withdrew it after checking the pinned
NSTool and libpietendo implementation: those sources include the trailing
digest in the extent and copy its bytes, but do not establish a rule for
recomputing its value. Two actionable P2 findings were corrected before that
candidate: allocation now uses fallible reservation, and exported result types
are `#[non_exhaustive]`. The reviewer checked the correction delta and the
wrong-header-key negative case, then reported no remaining P0/P1 issue. The
separate correction-delta review had no distinct committed SHA; the reviewed
candidate SHA above is retained as the original review anchor.

## Follow-up independent review record

The non-authoring reviewer Eevee (agent id
`01a1cf69-ff55-7ba2-ac78-560ed5595a69`) reviewed the complete PR diff from
`45adc24ebeb09bdd8738df035faa44dece2e60f4` through
`f647cbbbfe82bd777d9a3fa11aa423f7c2913ad3`, then checked the correction
commit against the original implementation. The reviewer confirmed the outer
and nested complete-payload checks, table-order independence, unchanged
generic PFS0 behavior, sanitized source-read fault test, and documented
same-handle limitation. The review found no P0–P3 issues.

The reviewer inspected the CI and dependency manifests, qualification and
dependency documents, Engine and key interfaces, NCA/PFS0/verification code,
the qualifier, synthetic fixtures, and integration tests. No tests were run
by the reviewer. The pinned base-to-head `git diff --check` completed with no
output, and the reviewer made no changes. CodeGraph marked the changed files
stale and TokenSave was bound to the primary checkout, so the reviewer checked
the pinned diff and current worktree source directly.

## Focused test evidence

The current focused commands are:

```sh
cargo test --locked --no-default-features --test nsp_semantic_qualification
cargo test --locked --no-default-features --lib nsp_semantic_qualification::tests::nca_member_source_read_failure_is_sanitized_and_typed
cargo test --locked --no-default-features --lib pfs0::tests::parses_payload_relative_spans_without_reading_payload_bytes
cargo test --locked --no-default-features --lib
```

The allocator-focused checks run separately and serially:

```sh
cargo test --locked --no-default-features --lib reservation -- --test-threads=1
cargo test --locked --no-default-features --lib test_allocator::tests:: -- --test-threads=1
```

Focused mapping and boundary checks also run with:

```sh
cargo test --locked --no-default-features --lib nca_allocation_failure -- --test-threads=1
cargo test --locked --no-default-features --lib nsp_semantic_qualification::tests::actual_bounded_qualifier_reservations_refuse_with_sanitized_errors -- --test-threads=1
cargo test --locked --no-default-features --lib nsp_semantic_qualification::tests::allocation_reservation_failure_maps_to_a_typed_error -- --test-threads=1
```

The test-only global allocator is armed for one reservation site and
occurrence. The reservation wrapper records its expected layout; the allocator
callback records the layout it receives and refuses only when both match.
Unrelated allocations and allocations on other threads use `System`. The
failpoint refuses once, clears its site scope on return or unwind, and falls
back to `System` if thread-local state is unavailable. Each positive site test
fails if it does not observe exactly one matching refusal. The allocator
callbacks use fixed-size, const-initialized thread-local state; they allocate
nothing, do not format diagnostics, and do not unwind.

The tests cover key-file bytes; PFS0 metadata, entries, spans, and repeated
filename copies; qualification records, result members, coverage spans, source
hash buffer, and section-hash buffer; and NCA header spans and completed
partitions. All expected and observed layouts match. The end-to-end qualifier
cases check `allocation_failed`, sanitized messages, unchanged input and key
files, and successful post-error reads and renames. The 1 MiB assertion records
the largest request in these synthetic fixture cases only; it is not a global
qualifier allocation ceiling. The source-derived PFS0 limits are listed in the
architecture document, including an outer entry-vector request of 2,097,072
bytes and up to 16 MiB of copied-name requests per PFS0 parse. The NCA tests
also cover the separate
`InspectionErrorCode::AllocationFailed`
mapping and the Verification, Recognition, and multi-content mappings below.

The `usize::MAX` test records one attempted reservation, no representable
expected layout, zero injected refusals, and a failpoint that remains armed
until its scope ends. It exercises the capacity-overflow path without
asserting a private `TryReserveError` discriminator or observed OS allocation.
It does not qualify genuine operating-system memory pressure; that evidence
remains `NOT_RUN`.

| NCA error consumer | Required mapping | Regression evidence |
| --- | --- | --- |
| NSP semantic qualifier | `NspSemanticQualificationErrorCode::AllocationFailed` | End-to-end refusal at both NCA reservations |
| Inspection | `InspectionErrorCode::AllocationFailed` classified as internal | `HeaderError::code()` and provider classification tests |
| Verification | `VerificationErrorCode::AllocationFailed` | `map_header_error` test |
| Recognition | `ContentRecognitionErrorCode::ResourceLimitExceeded` | `map_nca_header_error` test |
| Multi-content parsing | `FormatError::ResourceLimit` | `map_header_error` test |

`HeaderSyntax::present_partition_indices()` remains unchanged. CodeGraph and
caller search found Verification as its only caller; the NSP qualifier uses
the parsed spans directly. The helper returns at most four indices. Its
regression test checks descriptor order and absent-entry filtering.

The latest focused run passed 20 semantic-qualification integration tests, the
sanitized source-read fault-injection test, and the generic PFS0 payload-span
test. The mapping filter passed four consumer regressions; the serialized
reservation and allocator-harness filters passed eight and four tests. The
end-to-end refusal and capacity-overflow tests each passed. The no-default-
features library suite passed 518 tests with 4 ignored. These checks confirm
that qualification rejects unaccounted payload while the general PFS0 parser
still accepts payload-relative gaps. The tests use fixed, test-only keys and
generated encrypted bytes. No proprietary keys, tickets, or retail content
are stored in the repository.

## Independent reader run

The fixture was generated from
`tests/support/synthetic_nsp_qualification.rs` and written only under
`/tmp/nscb-issue71-fixture-generator/output` for the independent read. The
Program NCA SHA-256 was
`785502b450c913702623235a2298874aa6510b1ce0d2ca2ab4614cb65fa42ef7`.

hactool at commit
`1d64a83450e025622f3468c28fc4164dad2c5ef6` reported both NCA FS-header master
hashes and PFS0 hash tables as good. NSTool v1.9.2 at commit
`e89ea84bd70c11b67ebec9153fb4a446f18a9d3d` read the package, both NCA roles,
and the decrypted Meta CNMT. The CNMT output showed Application type `0x80`,
the fixture title ID, zero PatchId, Program content type `1`, ContentId equal
to the first 16 Program digest bytes, size `0x1000`, and the full Program
digest. Both readers reported expected failures for the synthetic NCA header
signatures. NSTool also warned that the optional `title.keys` file was absent;
this profile does not use tickets or title keys. These warnings are not
treated as successful verification.

## Repository validation and target matrix

The latest `make all` run exited successfully on macOS 27.0.1 build `26A434`,
arm64, using Rust/Cargo 1.98.1. It ran against baseline
`bb1c6a8a5bd067ad49e3fab04f28fc181c6352fc` with the Issue #73 candidate changes
in the task worktree. `Cargo.lock` SHA-256 was
`d63a9c75de9da3c14901f54f20ba41209ec283df2ddbf67298eba3d919ddb370`.
Content policy passed (53 tests); cleanup tests passed (11 tests); typecheck,
format, Clippy, build, and CLI checks passed. Both no-default library runs
reported 518 passed and 4 ignored. The standalone-feature library run reported
188 passed. All integration targets passed; the `nsp_semantic_qualification`
target reported 20 passed. The [durable run record](evidence/issue-73/qualification-run-2026-11-12.md)
links the complete `make all` and focused transcripts. No test group reported
a failure. An unrestricted `cargo test --no-default-features` invocation also
selects an existing CLI integration test whose binary requires
`standalone-job-history`; that separate invocation is not the repository's
no-default-features gate.

The native CI qualification commands were also run locally on the same macOS
arm64 host. Results were: qualifier unit tests 11 passed; key-file tests 4
passed; PFS0 metadata-limit test 1 passed; semantic integration tests 20
passed; serialized reservation tests 8 passed; and serialized allocator
harness tests 4 passed. The four allocation mapping regressions passed for
Inspection, Verification, Recognition, and multi-content parsing. Separate
checks passed for the typed/sanitized qualifier refusal, capacity-overflow
classification, NCA member read sanitization, and generic PFS0 payload spans.
These local runs do not substitute for the other native CI runners or FUP-2.

Before merge readiness, run and record:

```sh
make all
```

Native runs must execute the semantic unit and integration tests on macOS 15+
arm64, Windows 11 x86_64, Linux x86_64 with glibc 2.35+, and Linux aarch64
with glibc 2.35+. Record the OS version, architecture, libc floor where
applicable, Rust toolchain, commands, and test counts for each host. An
unavailable host remains `NOT_RUN`; do not count cross-compilation or
emulation as native evidence.

## FUP-2 Windows 11 x86_64 procedure

FUP-2 is `NOT_RUN` for this change because no qualifying Windows 11 x86_64
host was available in the execution environment. The available host is macOS
27.0.1, build `26A434`, arm64. Windows Server 2025 CI does not satisfy this
requirement.

Run the tests from a native Windows 11 x86_64 PowerShell session. Record the
edition, version, build, OS architecture, processor architecture, and whether
the guest is virtualized:

```powershell
Get-CimInstance Win32_OperatingSystem |
  Format-List Caption,Version,BuildNumber,OSArchitecture
Get-CimInstance Win32_ComputerSystem |
  Format-List Manufacturer,Model,HypervisorPresent
Get-CimInstance Win32_Processor |
  Format-List Name,Architecture,AddressWidth
[System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
```

For a virtual machine, include host-side evidence of the host OS/build,
processor architecture, hypervisor product/version, and the VM's x86_64 guest
configuration. A guest report alone does not establish host provenance. Accept
hardware virtualization on a native x86_64 host; reject x86_64 emulation on an
ARM64 host.

From the clean, approved source commit, record `git rev-parse HEAD`,
`git status --porcelain`, the SHA-256 of `Cargo.lock`,
`rustup show active-toolchain`, `rustc --version --verbose`, and
`cargo --version`. The Rust host target must be
`x86_64-pc-windows-msvc`. Capture the commands and their complete output in a
PowerShell transcript, then run:

```powershell
cargo test --locked --no-default-features --lib nsp_semantic_qualification::tests::
cargo test --locked --no-default-features --lib key_file::qualification_tests::
cargo test --locked --no-default-features --lib pfs0::tests::caller_metadata_limit_is_checked_before_reading_declared_tables
cargo test --locked --no-default-features --test nsp_semantic_qualification
cargo test --locked --no-default-features --lib reservation -- --test-threads=1
cargo test --locked --no-default-features --lib test_allocator::tests:: -- --test-threads=1
```

Record test counts, ignored tests, failures, and skips. No cross-compiled or
architecture-emulated run can close FUP-2. Until this evidence exists,
PAC-5 remains `UNVERIFIED` and Issue #73 stays open.
