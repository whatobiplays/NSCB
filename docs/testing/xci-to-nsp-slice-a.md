# XCI to NSP Slice A qualification contract

This contract covers the first XCI-to-NSP implementation slice for the
synthetic, rights-free base Application profile. It defines candidate
acceptance and evidence to collect. Passing these checks does not establish
authenticity, retail compatibility, installability, Full Verification, or
support for other content profiles.

## Candidate identity

| Item | Value |
| --- | --- |
| Repository | `whatobiplays/NSCB` |
| Issue | [#16 — Container Conversion](https://github.com/whatobiplays/NSCB/issues/16) |
| Approved base | `a50bf383d16412a30f636a4011d43378974c0632` |
| Task branch | `codex/issue-16-xci-to-nsp-slice-a` |
| Governing policy revision | `142422527de28b8e20dea1158d2f54d020dcdcd5` |
| Qualification host | Native macOS arm64; record the actual host and Rust toolchain with each run |

The synthetic fixtures contain generated data only. They must not include
proprietary content or key material. The key file used by tests is generated
in a temporary directory and is never checked in.

## Product acceptance criteria

| ID | Acceptance requirement | Evidence |
| --- | --- | --- |
| I16-A-PAC-01 | Require the XCI `HEAD` signature at offset `0x100`, then accept only an image with exactly one structurally valid `update`, `normal`, and `secure` partition. `update` and `normal` must be empty. `logo` may be absent or empty. Reject duplicate, unknown, or nonempty unsupported partitions. | Invalid `HEAD` marker; synthetic partition-profile cases; HFS0 parser tests |
| I16-A-PAC-02 | Verify every root and nested HFS0 entry's bounded, nonzero prefix hash. Reject nonzero reserved bytes and prefix digest mismatches. | Valid-prefix, zero-size, out-of-bounds, reserved-byte, and digest-mismatch fixtures |
| I16-A-PAC-03 | Require exactly two secure members and assign Meta and Program roles only from the existing NSP semantic qualification facts. Source member names and file extensions do not establish roles. | Reversed and misleading member names; unsupported member-count cases |
| I16-A-PAC-04 | Preserve both qualified NCA byte streams and emit deterministic PFS0 metadata with `meta.nca` followed by `program.nca`. | Byte-for-byte fixture comparison, repeat conversion, and post-conversion NSP semantic qualification |
| I16-A-PAC-05 | Keep planning immutable and bind source, key file, destination, expected output, and staged output to independent identity and content evidence. Revalidate source and key state before publication and report no `Converted` outcome before validated publication. | Source/key mutation, staged-output corruption, cancellation during semantic verification, and destination-race tests; artifact evidence in terminal results |
| I16-A-PAC-06 | Preserve `fail`, `replace`, and `skip` conflict behavior. `AlreadyUpToDate` and `Skip` still require qualified source evidence, key revalidation, and destination evidence. | Conflict-policy integration cases and existing operation regression tests |
| I16-A-PAC-07 | Add the typed Engine request and CLI command `xci-to-nsp --source XCI --output NSP --workspace DIR --keys FILE`, with conflict policy, JSON, and JSONL support. Keep existing 1.x API and output contracts intact. | API tests, feature-enabled CLI tests, and existing CLI regression suite |
| I16-A-PAC-08 | Do not change source NCAs, remove rights, rewrite encrypted payloads, alter key generation, apply RSV or account changes, or discard unsupported partition content. | Source-byte comparison and adversarial profile fixtures |
| I16-A-PAC-09 | Keep non-macOS builds working and return `unsupported_capability` for execution requests on unsupported targets. | No-default library test and non-macOS CLI test in hosted CI |

## Technical acceptance criteria

| ID | Implementation requirement | Evidence |
| --- | --- | --- |
| I16-A-TAC-01 | Require the XCI `HEAD` marker and reuse the bounded XCI/HFS0 parser. Add conversion-only HFS0 prefix-hash checks without broadening generic NSP recognition. | Recognition and conversion integration tests |
| I16-A-TAC-02 | Feed validated secure-member spans through the existing NSP semantic qualifier and existing PFS0 writer. Do not add another NCA or package parser. | Qualified positive fixture and output semantic requalification |
| I16-A-TAC-03 | Resolve member roles from semantic facts, then map those facts back to a unique source span using size and SHA-256. Reject missing or ambiguous matches. | Misleading-name and member-cardinality fixtures |
| I16-A-TAC-04 | Use the immutable operation plan and guarded publication path. Honor cancellation, destination locks, capacity checks, replacement handling, and cleanup evidence. | Cancellation during staged semantic verification, conflict, race, corruption, and cleanup-result cases |
| I16-A-TAC-05 | Do not serialize key bytes, key paths, or key fingerprints in Debug output, snapshots, JSON, JSONL, events, diagnostics, or history. | Request Debug and CLI redaction tests; inspect serialized plan and event records |
| I16-A-TAC-06 | Keep source compatibility for existing 1.x consumers. Add operation variants only at the established non-exhaustive API boundary and leave existing operation behavior unchanged. | Existing library, CLI, Build, Split, and NSP qualification regression suites |
| I16-A-TAC-07 | Reach at least 90% meaningful coverage of new first-party conversion logic. Report the coverage tool, measured files, excluded platform branches, and remaining gaps. | Candidate-bound coverage report |

## Required local commands

Run these on the native macOS arm64 host and retain their exit codes and
complete output with the candidate evidence:

```sh
uname -m
rustc -vV
cargo test --locked --no-default-features --test xci_to_nsp
cargo test --locked --no-default-features --test xci_to_nsp_cli
cargo test --locked --features standalone-job-history --test xci_to_nsp_cli
make all
```

The no-default CLI test covers the public request's key-path redaction because
the standalone executable requires the `standalone-job-history` feature. The
feature-enabled CLI command runs subprocess tests against the current binary.
Do not use an executable left by an earlier build as CLI evidence.

Hosted CI must compile and exercise the unsupported-capability path on
non-macOS targets. Record the actual runner, target triple, toolchain, command,
exit status, and check URL. CI evidence does not replace native macOS arm64
qualification.

## Scope exclusions

Slice A does not add support for nonempty update, normal, or logo partitions;
additional secure members; rights-managed or delta content; key-generation,
RSV, or account changes; any other NSP semantic profile; general XCI
recognition claims; authenticity; installability; device behavior; or
cross-filesystem publication guarantees beyond the existing operation
contract.
