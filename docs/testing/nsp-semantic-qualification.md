# NSP semantic qualification acceptance

## PAC crosswalk

Statuses below describe the current implementation evidence. `UNVERIFIED`
means that some required evidence is still missing; it is not a pass.

| PAC | Status | Evidence and remaining gap |
| --- | --- | --- |
| PAC-1 — Positive semantics | PASS | `qualifies_byte_backed_two_member_profile_despite_misleading_names` checks profile id `rights_free_base_application_v1`, byte-derived roles, exact member digests and sizes, source digest, deterministic repeat results, and unchanged input bytes. `verifies_multiple_hash_table_entries_and_a_partial_final_block` covers multiple table entries and a partial last block. hactool and NSTool independently read the synthetic NCA/PFS0; NSTool also displayed the expected Application CNMT and Program row. |
| PAC-2 — Negative semantics | PASS | The integration suite covers plain PFS0, misleading names, one or extra outer members, empty outer members, trailing, leading, and inter-member unreferenced payload at the outer level, the same unreferenced-payload cases in Program PFS0, trailing unreferenced Meta PFS0 payload, and valid reversed outer table order. It also covers duplicate Meta/Program roles, truncated and unsupported CNMT, unsupported section and key-generation profiles, nonzero RightsId, missing and malformed key prerequisites, wrong header key (`invalid_nca_header`), wrong key-area key (`key_or_section_integrity_failure`), Meta/Program title mismatch, and Program row hash, ContentId, size, type, IdOffset, and title-ID mismatches. |
| PAC-3 — Boundary safety | UNVERIFIED | Tests cover checked member and section ranges, bounded reads/seeks, parent I/O propagation, a deterministic source-read failure mapped to sanitized `input_unavailable`, PFS0 metadata rejection before table reads, entry ceilings, input-size boundaries, source mutation after hashing, cancellation after the last hash chunk, and capacity-overflow mapping to `allocation_failed`. Key-file partial-read failure is injected. Real allocator exhaustion remains untested. The owner-approved same-handle strategy detects ordinary mutation and observable identity changes, but cannot detect a hostile writer that restores all observed metadata. No temporary-copy subsystem was added. |
| PAC-4 — API and compatibility | PASS | `make all` passed on macOS 27.0.1 arm64. The public change is additive and Engine-only, with no CLI/TUI qualification command. A separate unrestricted `cargo test --no-default-features` invocation fails in the existing `multi_content_operations` CLI integration test because the `nscb` binary requires `standalone-job-history`; the Makefile's supported no-default gate tests the library and runs integration tests with that feature. |
| PAC-5 — Native qualification | UNVERIFIED | `make all` and the focused suite passed natively on macOS 27.0.1 arm64. The CI workflow adds Windows Server 2025 x86_64, Linux x86_64, and Linux aarch64 jobs. Windows 11 x86_64 remains `NOT_RUN`; the Server runner does not substitute for it. |
| PAC-6 — Review and format evidence | UNVERIFIED | Pinned hactool, NSTool, and hacPack source references and synthetic-reader results are documented. The prior independent review record and its corrected P2 dispositions are preserved below. A separate non-authoring review of the follow-up commit and complete PR diff remains required; ChatGPT owner review remains outstanding. |

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

## Focused test evidence

The current focused commands are:

```sh
cargo test --locked --no-default-features --test nsp_semantic_qualification
cargo test --locked --no-default-features --lib nsp_semantic_qualification::tests::nca_member_source_read_failure_is_sanitized_and_typed
cargo test --locked --no-default-features --lib pfs0::tests::parses_payload_relative_spans_without_reading_payload_bytes
cargo test --locked --no-default-features --lib
```

The latest focused run passed 20 semantic-qualification integration tests, the
sanitized source-read fault-injection test, and the generic PFS0 payload-span
test. The no-default-features library suite passed 502 tests with 4 ignored.
These checks confirm that qualification rejects unaccounted payload while the
general PFS0 parser still accepts payload-relative gaps. The tests use fixed,
test-only keys and generated encrypted bytes. No proprietary keys, tickets, or
retail content are stored in the repository.

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

The latest `make all` run exited successfully on macOS 27.0.1 arm64 with the
repository's pinned Rust 1.98.1 toolchain. The gate includes no-default-features
library validation, standalone-feature test suites, content policy, lint,
formatting, builds, and CLI checks; no test group reported a failure. An
unrestricted `cargo test --no-default-features` invocation also selects an
existing CLI integration test whose binary requires
`standalone-job-history`; that separate invocation is not the repository's
no-default-features gate.

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
