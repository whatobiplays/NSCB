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
| PAC-6 — Review and format evidence | PASS | Pinned hactool, NSTool, and hacPack source references and synthetic-reader results are documented. The corrected candidate passed independent full-diff and correction-delta reviews and the final direct ChatGPT reassessment recorded below. |

## Issue #73 follow-up crosswalk

| Follow-up | Status | Evidence and remaining decision |
| --- | --- | --- |
| FUP-1 — Allocator exhaustion / PAC-3 | Twelve tagged reservation sites evidenced; path-buffer requests `NOT_EVIDENCED`; PAC-3 remains `UNVERIFIED` | Each tagged site is targeted with a one-shot, per-thread failpoint that records its site, occurrence, expected layout, actual layout, and one refusal. Standard-library path buffers in `open_snapshot_file` are not site-tagged and remain `NOT_EVIDENCED`. The separate `usize::MAX` case records an unrepresentable layout and no injected refusal; it does not claim observed OS pressure. Genuine operating-system resource pressure is `NOT_RUN`; owner disposition of that residual and the preserved snapshot limitation is still required. |
| FUP-2 — Native Windows 11 x86_64 / PAC-5 | `NOT_RUN`; PAC-5 remains `UNVERIFIED` | The available host is macOS 27.0.1 arm64. No qualifying Windows 11 x86_64 host was available. A native x86_64 virtualized guest on a native x86_64 host is acceptable with host provenance; architecture-emulated x64 on ARM64 is excluded. Issue #73 stays open. |
| FUP-3 — Durable evidence and PAC crosswalk | Recorded | The [Issue #73 run record](evidence/issue-73/qualification-run-2026-11-12.md) links sanitized repository transcripts and records the host/process limits, exact environment and commands, results, and hashes. Byte-preserved original transcripts remain in a private local archive. The record keeps allocator refusal, capacity overflow, path-buffer `NOT_EVIDENCED`, and OS pressure as separate statuses. The original Issue #71 exception and snapshot threat model remain in the existing records. |
| FUP-4 — Independent and direct review | Recorded | The full-candidate review, v8-to-v9 correction-delta review, and final direct ChatGPT reassessment are bound to their exact snapshots below. |

## Issue #73 review record

This review found that the committed focused transcript prints command lines
such as `cargo test test --locked ...` without an argv record or per-command
exit status. The available transcript is byte-identical to a saved temporary
copy, but neither file establishes the executed argument vector. The original
command provenance is therefore unverified; the corrected run is recorded
separately.

The committed `make all` transcript contains user-specific absolute paths. A
sanitized derivative replaces those paths and normalizes whitespace. The raw
files were preserved byte-for-byte in an owner-private local archive. The
sanitized files are not byte-identical to the raw files. Commit
`e9c5ef8f7d6d6bff33012ff26010e5e21602fcfa` still contains the original raw
transcripts and remains reachable in PR history; no history rewrite is being
performed.

The prior PR candidate's claim that final ChatGPT source review had completed is withdrawn.
The earlier ChatGPT review covered snapshot `6dd3572392d0ff375ce30847da3a7f64e7b733c16b64018cb700c778880911e7`; it missed F2 and is recorded as preliminary.
The corrected full candidate `ee9be9c51159332a1161f6df2037ab81e748bc0e65ddd6d18b045b2030a63a0b` passed independent review, correction-delta review, and final direct ChatGPT reassessment.
PAC-6 is `PASS`; FUP-4 is `Recorded`.

### Independent review provenance

The records below identify the reviewer, candidate snapshot or delta, and result for each review.
They distinguish the earlier preliminary review from the final reassessment of the corrected candidate.

| Review | Reviewer and execution reference | Reviewed candidate | Output and limits |
| --- | --- | --- | --- |
| Prior full-diff review | Codex sub-agent `Rawls`; agent ID `01a1d214-4c19-7520-944a-71696a1f7645`; review submission `01a1d232-1cf5-7e31-a254-ef5b29e69fd1` | v4 snapshot, 76,055 bytes, SHA-256 `eaa3dba7da685031352c1ab7ed460edbb7eedfbd48bc7e99ed590fbb34886bf2`, against baseline `bb1c6a8a5bd067ad49e3fab04f28fc181c6352fc` | Exact verdict: `PASS — no blocking findings`. Covered source, tests, CI, bounds, error mappings, and public scope. The reviewer did not run tests or contact GitHub; raw log bodies were outside this snapshot. |
| Fresh source/docs review | Codex sub-agent `Mew` (runtime `Arendt`); agent/run ID `01a1d2a5-9192-7a33-9823-a26c8c7e7a67` | 16-path source/docs patch, 80,447 bytes, SHA-256 `7c9d366796d302f4867a9e27535ae69586d11fa9f09787457bf6d8713a1a26f4`, base `bb1c6a8a5bd067ad49e3fab04f28fc181c6352fc`, prior PR source HEAD `e9c5ef8f7d6d6bff33012ff26010e5e21602fcfa` | Exact summary: `No blocking source or test issue found in the reviewed changes.` Reported two documentation findings. Its P2 identified that prior PR HEAD `e9c5ef8f7d6d6bff33012ff26010e5e21602fcfa` marked PAC-6 `PASS`, FUP-4 `Recorded`, and asserted final ChatGPT source review without candidate-bound evidence. Those claims are withdrawn; the corrected candidate initially marked PAC-6 `UNVERIFIED` and FUP-4 `Pending` until fresh review. Its P3 identified the unqualified allocation sentence in the architecture document; the current delta narrows that claim. No tests or GitHub checks were run; the three transcript bodies were outside this review. |
| Evidence-correction review | Codex sub-agent `Eevee`; agent ID `01a1d299-71ff-7ee0-9637-21a6409acb82`; review submission `01a1d2a0-9aa1-72b1-b563-d9652a7fab1a` | Correction delta against prior PR HEAD `e9c5ef8f7d6d6bff33012ff26010e5e21602fcfa`; candidate snapshot SHA-256 `3a16764a786faef9109b0fa259c9619633725816e01da0b2819f919e1ddea4c4` | Exact verdict: `PASS — Eevee, independent non-authoring evidence review.` Verified raw and sanitized hashes, path/whitespace sanitization, 11 argv/status records and test counts, disclosed PAC/FUP statuses, and the e9c history disclosure. No files were edited, no tests were run, and GitHub was not contacted. |
| Evidence-summary correction review | Codex sub-agent `Eevee`; agent ID `01a1d299-71ff-7ee0-9637-21a6409acb82`; review request `01a1d2ca-1252-7952-bbcd-0f6e93ff696e` | Three-document correction delta, 19,781 bytes, SHA-256 `fbf821fdb86c6a3a44b9caf9a0055bff8d3934915f72a904b152700406fb4e0a`, against prior PR HEAD `e9c5ef8f7d6d6bff33012ff26010e5e21602fcfa` | Exact verdict: `FAIL — P3 warning-count mismatch.` The reviewer identified that the run record said one linker warning while the sanitized `make all` transcript contains two occurrences during the same `provider::process::tests::production_launch_enforces_supported_darwin_hard_limits` test. The run record now states two occurrences and notes that both invocations passed; Mew confirmed the corrected count in the final delta review below. |
| Correction-delta review | Codex sub-agent `Mew` (runtime `Arendt`); agent/run ID `01a1d2a5-9192-7a33-9823-a26c8c7e7a67`; review request `01a1d2db-de7c-7802-846e-860568d17359`; log-path confirmation `01a1d2e1-9b5b-70c0-9dbd-1cbbe32bd3ed` | Three-document delta, 21,242 bytes, SHA-256 `11ef582a13717cb31c89681a29744b97024dd12bf105b44d387e39d313f3997a`, against `e9c5ef8f7d6d6bff33012ff26010e5e21602fcfa`; log paths checked in full candidate `6dd3572392d0ff375ce30847da3a7f64e7b733c16b64018cb700c778880911e7` | Exact output: `PASS — 11ef582a13717cb31c89681a29744b97024dd12bf105b44d387e39d313f3997a — no remaining finding IDs; P2/P3 resolved, two warnings confirmed, scope and PAC/FUP states accurate.` Mew also confirmed all three sanitized log targets exist in the full candidate. No tests or GitHub checks were run. |
| Status/provenance correction review | Codex sub-agent `Mew` (runtime `Arendt`); agent/run ID `01a1d2a5-9192-7a33-9823-a26c8c7e7a67`; review request `01a1d2e7-e411-7cb2-9c1f-aa0385296717` | Three-document delta, 23,374 bytes, SHA-256 `934aab6c8551561717ee69db026338040d7c121751503a420f673b9136ecbc67`, against `e9c5ef8f7d6d6bff33012ff26010e5e21602fcfa`; full candidate snapshot `87a5fcce6d2e5fcd1edcf0ae82c0714d540b5db4884046ffe83adf2ef6c9b002` | Exact output: `PASS — 934aab6c8551561717ee69db026338040d7c121751503a420f673b9136ecbc67; no remaining findings. P2/P3 resolved; partial-patch F1 closed.` No tests or GitHub checks were run. |
| Partial docs-delta review | Codex sub-agent `Averroes` (task codename `Jolteon`); agent/run ID `01a1d2ce-8ef4-74d0-87d8-3d5c74fe69ac`; review request `01a1d2d8-d4af-70a3-912d-ff986141adfc` | Three-document delta SHA-256 `11ef582a13717cb31c89681a29744b97024dd12bf105b44d387e39d313f3997a`; it intentionally excluded log bodies | Exact output: `FAIL | 11ef582a13717cb31c89681a29744b97024dd12bf105b44d387e39d313f3997a | F1`. The finding was that a linked sanitized log was absent from the docs-only review artifact. Full candidate snapshot `6dd3572392d0ff375ce30847da3a7f64e7b733c16b64018cb700c778880911e7` includes all three log files; link-integrity check passed, and Mew confirmed the paths. This was a review-packet scope issue, not a missing file in the candidate. |
| Full-candidate correction review | Codex sub-agent `Averroes` (task codename `Jolteon`); agent/run ID `01a1d2ce-8ef4-74d0-87d8-3d5c74fe69ac`; full-review request `01a1d2dd-41fa-7073-b32a-1118d5774703` | Full baseline-to-candidate snapshot, 278,488 bytes, SHA-256 `6dd3572392d0ff375ce30847da3a7f64e7b733c16b64018cb700c778880911e7` | Exact output: `FAIL | 6dd3572392d0ff375ce30847da3a7f64e7b733c16b64018cb700c778880911e7 | F2`. The reviewer said the run record claimed the workflow was unchanged while the PR diff added test commands in `.github/workflows/ci.yml`. The run record now states that PR HEAD `e9c5ef8` has six jobs and that this evidence-correction change does not modify the workflow. Independent re-review is pending. |
| Preliminary direct ChatGPT source/evidence review | ChatGPT direct review in this task | Source/evidence snapshot, 278,488 bytes, SHA-256 `6dd3572392d0ff375ce30847da3a7f64e7b733c16b64018cb700c778880911e7`; source HEAD `e9c5ef8f7d6d6bff33012ff26010e5e21602fcfa` | Direct review found no source or test issue in the allocation wrappers and failpoint, qualifier cleanup and sanitization tests, NCA mappings and `present_partition_indices()` caller, or CI job structure. It did not catch the workflow-summary wording later flagged as F2. No tests were run during this review; the corrected focused capture records 56 passing tests on the same source HEAD. Final direct reassessment of the corrected wording is pending. |
| V9 full-candidate correction review | Codex sub-agent `Averroes`; agent ID `01a1d2ce-8ef4-74d0-87d8-3d5c74fe69ac`; request `01a1d2fb-6529-7322-b67f-2b2d844c450e` | Baseline-to-v9 patch, 283,551 bytes, SHA-256 `ee9be9c51159332a1161f6df2037ab81e748bc0e65ddd6d18b045b2030a63a0b`; source HEAD `e9c5ef8f7d6d6bff33012ff26010e5e21602fcfa` | Exact result: `PASS`; findings: `None`. Reviewer identified as Codex GPT-6; a separate execution run ID was not exposed. The request ID and agent ID are recorded here. No tests or GitHub checks were run. |
| V8-to-v9 provenance correction-delta review | Codex sub-agent `Mew` (runtime `Arendt`); agent/run ID `01a1d2a5-9192-7a33-9823-a26c8c7e7a67`; orchestration request `01a1d305-3130-7d02-8bdf-92d3ecb856bb` | v8-to-v9 documentation delta, 8,922 bytes, SHA-256 `1f515f946a82f417d90ca5fbb025c86f7d5bc76d071881295fa813f43911018e`; v9 full candidate SHA-256 `ee9be9c51159332a1161f6df2037ab81e748bc0e65ddd6d18b045b2030a63a0b` | Exact result: `PASS — no findings.` Mew reported that no separate review submission ID was assigned for this delta. |
| Standards-axis review | Codex sub-agent `Beauvoir` (assigned codename `Charmander`); agent ID `01a1d308-96ef-7660-869e-8f4c49fc527e` | Full v9 candidate, 283,551 bytes, SHA-256 `ee9be9c51159332a1161f6df2037ab81e748bc0e65ddd6d18b045b2030a63a0b` | Exact summary: no documented-standard breach. One possible duplicate mapping was reported as a judgment-call smell. No tests or edits were made. |
| Spec-axis review | Codex sub-agent `Harvey` (assigned codename `Bulbasaur`); agent ID `01a1d308-9860-71e0-b672-3ec88d30d3f8`; request `01a1d310-2858-7f42-a39d-e4edb2858831` | Full v9 candidate, 283,551 bytes, SHA-256 `ee9be9c51159332a1161f6df2037ab81e748bc0e65ddd6d18b045b2030a63a0b` | Exact summary: no source-level spec mismatch. Remaining gaps were FUP-2/PAC-5, untagged path-buffer allocations, and untested OS memory pressure. The review saw FUP-4 as pending before the final direct reassessment. No tests or edits were made. |
| Final direct ChatGPT reassessment | ChatGPT, this task | Full v9 candidate, 283,551 bytes, SHA-256 `ee9be9c51159332a1161f6df2037ab81e748bc0e65ddd6d18b045b2030a63a0b`; source HEAD `e9c5ef8f7d6d6bff33012ff26010e5e21602fcfa` | Result: `PASS — no remaining source or evidence-provenance finding.` The review rechecked the corrected review states, evidence links and hashes, sanitizer disclosures, preserved scope, and unchanged source/test revision. No Rust tests were run during this review. |
| Local Cubic review | `cubic review --json` | Full v9 candidate, SHA-256 `ee9be9c51159332a1161f6df2037ab81e748bc0e65ddd6d18b045b2030a63a0b` | Earlier runs flagged two P2 review-history wording contradictions. Those labels were corrected; the latest run returned `issues: []`. |

Mew's source/docs review and Eevee's evidence review cover the original PR paths. The F1 finding came from a docs-only review packet that omitted the linked logs; the full candidate included all three sanitized files. The F2 workflow wording is corrected.

Averroes passed the full v9 review, and Mew passed the v8-to-v9 provenance delta review. The standards review found no documented-rule breach; it noted one possible duplicate mapping as a judgment call. The spec review found no source-level mismatch. The final direct ChatGPT reassessment found no remaining source or evidence-provenance finding.

PAC-6 is `PASS` and FUP-4 is `Recorded`. PAC-3 and PAC-5 remain `UNVERIFIED`; FUP-2 remains `NOT_RUN`.

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

`HeaderSyntax::present_partition_indices()` remains unchanged. It collects at
most four indices into a `Vec`. Aside from its unit test, `Verification` is
the only caller; the NSP qualifier reads the parsed spans without calling this
helper. That bounded Verification allocation is outside FUP-1's inventory of
paths reached by the qualifier, so changing it would not improve FUP-1
coverage. The regression test checks descriptor order and absent-entry
filtering.

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
