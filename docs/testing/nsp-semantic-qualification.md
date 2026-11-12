# NSP semantic qualification acceptance

## PAC crosswalk

Statuses below describe the current implementation evidence. `UNVERIFIED`
means that some required evidence is still missing; it is not a pass.

| PAC | Status | Evidence and remaining gap |
| --- | --- | --- |
| PAC-1 — Positive semantics | PASS | `qualifies_byte_backed_two_member_profile_despite_misleading_names` checks profile id `rights_free_base_application_v1`, byte-derived roles, exact member digests and sizes, source digest, deterministic repeat results, and unchanged input bytes. `verifies_multiple_hash_table_entries_and_a_partial_final_block` covers multiple table entries and a partial last block. hactool and NSTool independently read the synthetic NCA/PFS0; NSTool also displayed the expected Application CNMT and Program row. |
| PAC-2 — Negative semantics | PASS | The integration suite covers plain PFS0, misleading names, one or extra outer members, duplicate Meta/Program roles, truncated and unsupported CNMT, unsupported section and key-generation profiles, nonzero RightsId, missing and malformed key prerequisites, wrong header key (`invalid_nca_header`), wrong key-area key (`key_or_section_integrity_failure`), Meta/Program title mismatch, and Program row hash, ContentId, size, type, IdOffset, and title-ID mismatches. |
| PAC-3 — Boundary safety | UNVERIFIED | Tests cover checked member and section ranges, bounded reads/seeks, parent I/O propagation, PFS0 metadata rejection before table reads, entry ceilings, input-size boundaries, source mutation after hashing, cancellation after the last hash chunk, and capacity-overflow mapping to `allocation_failed`. Key-file partial-read failure is injected. Real allocator exhaustion and source-file read failure are not fault-injected. The same-handle approach cannot detect a hostile writer that restores all observable metadata. |
| PAC-4 — API and compatibility | PASS | `make all` passed on macOS 27.0.1 arm64. The public change is additive and Engine-only, with no CLI/TUI qualification command. A separate unrestricted `cargo test --no-default-features` invocation fails in the existing `multi_content_operations` CLI integration test because the `nscb` binary requires `standalone-job-history`; the Makefile's supported no-default gate tests the library and runs integration tests with that feature. |
| PAC-5 — Native qualification | UNVERIFIED | `make all` and the focused suite passed natively on macOS 27.0.1 arm64. The CI workflow adds Windows Server 2025 x86_64, Linux x86_64, and Linux aarch64 jobs. Windows 11 x86_64 remains `NOT_RUN`; the Server runner does not substitute for it. |
| PAC-6 — Review and format evidence | UNVERIFIED | hactool and NSTool source revisions, licenses, and synthetic-reader results are documented. A separate non-authoring Codex review and review of its correction delta found no remaining P0/P1 issue; ChatGPT owner review remains outstanding. |

## Focused test evidence

The current focused commands are:

```sh
cargo test --lib nsp_semantic_qualification::tests::
cargo test --lib key_file::qualification_tests::
cargo test --lib pfs0::tests::caller_metadata_limit_is_checked_before_reading_declared_tables
cargo test --test nsp_semantic_qualification
```

The latest focused run passed 8 semantic-qualifier unit tests, 4 key-file
qualification unit tests, 1 PFS0 metadata-limit unit test, and 13
semantic-qualification integration tests. The tests use fixed, test-only keys
and generated encrypted bytes. No proprietary keys, tickets, or retail content
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

The latest `make all` run passed on macOS 27.0.1 arm64 with the repository's
pinned Rust 1.98.1 toolchain. It reported 23 Rust test groups, 1,617 passed,
8 ignored, and no failures. The gate includes the no-default-features library check,
the standalone-feature test suites, content policy, lint, build, and CLI smoke
checks. An unrestricted `cargo test --no-default-features` invocation also
selects an existing CLI integration test whose binary requires
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
