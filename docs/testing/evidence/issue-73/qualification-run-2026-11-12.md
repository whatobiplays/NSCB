# Issue #73 qualification run evidence

## Candidate and environment

- Repository: `whatobiplays/NSCB`
- Branch: `codex/issue-73-nsp-semantic-qualification`
- Worktree: `/Users/daniel/.codex/worktrees/issue-73-nsp-semantic-qualification/NSCB`
- Base commit: `bb1c6a8a5bd067ad49e3fab04f28fc181c6352fc`
- `Cargo.lock` SHA-256: `d63a9c75de9da3c14901f54f20ba41209ec283df2ddbf67298eba3d919ddb370`
- Host: macOS 27.0.1, build `26A434`, arm64
- Validation toolchain: Rust and Cargo 1.98.1

The transcripted runs used the Rust source files listed below. Their hashes
can be checked from the worktree root with `shasum -a 256` and the listed paths.
No Rust source or test code changed after these runs; later edits update
documentation and retain the transcripts.

| Rust source file | SHA-256 |
| --- | --- |
| `src/allocation.rs` | `15a8efc1dc3c48caaccaf800d2d9d47503ed789b0cc94fe3f28bdea7ce9260a7` |
| `src/key_file.rs` | `a6ef6cd634f408c168d20703336f3834744d3ae0f6c493397bef37c19f6690c5` |
| `src/lib.rs` | `af95a498eec65859e83b564d56b02330cd73ea76ed47c342e3481eb5f47b12fb` |
| `src/main.rs` | `609f7fbe480061ceac5fc16eaa839da86663154854e0bcf96330573e70476160` |
| `src/multi_content_format.rs` | `2fa0406abd96411e703572c4d78383424c3ec2a0f77b402563ed78b1ee58cfa4` |
| `src/nca.rs` | `0569918cc0ad97de493f6cbd58284633a45e56e972145f856c1c8151441064e0` |
| `src/nsp_semantic_qualification.rs` | `e6e3b15a65acf67d03d54eb1151951cdb29cdea61997ec08c85ec2a2543a41bd` |
| `src/pfs0.rs` | `0e336dc1b1809ecce704c70ceb4b3070cea27fc56f7ae3defe9cface186d4680` |
| `src/provider/mod.rs` | `5cb295868aeaf863c469e3785d34a022606796f793f8359fcf071792f3f86d0c` |
| `src/recognition.rs` | `d466f1994ce939d438a7ac4153806d36b357115532ac7a8a89d0ef3cd46b6a63` |
| `src/test_allocator.rs` | `c7d9e3c2502f37aca64946d48bbc83edeab390be14624968fa506df447eb855d` |
| `src/verification.rs` | `10a54f1b7ca4ed58670d99c1c24e15d3135c9021dcbb3181a3f71a7fa1867748` |

## Memory limits observed

The host reports 25,769,803,776 bytes of physical memory (24 GiB). A Python
probe launched from the validation shell reported `RLIM_INFINITY` for
`RLIMIT_AS`, `RLIMIT_DATA`, `RLIMIT_RSS`, and `RLIMIT_MEMLOCK`; the shell's
address-space and data-size limits were also unlimited. The probe was run while
preparing this record, after the test transcripts were captured; it records the
current limits visible from the validation shell, not an in-process sample of
each test. It does not report currently available RAM or prove that no limit
exists below the process level. No operating-system memory pressure was
induced.

## Validation commands and results

`make all` passed. Content policy passed 53 checks; cleanup checks passed 11.
Each of the two no-default-feature library runs reported 518 passed and 4
ignored. Those four ignored entries were one manual pinned-release diagnostic,
one manual NSTool check, and two worker-test entrypoints run by their parent
tests. The standalone-feature library run reported 188 passed. Every
integration target passed, including 20 semantic-qualification tests. Type
checking, formatting, Clippy, build, and CLI checks passed. No requested test
group failed. The full log records each integration target's count. It also
contains one linker warning about the absent `/usr/local/lib` directory; the
affected test target still passed.

The focused transcript records these successful groups:

| Focus | Result |
| --- | ---: |
| Qualifier unit tests | 11 passed |
| Key-file qualification tests | 4 passed |
| PFS0 metadata-limit regression | 1 passed |
| Semantic-qualification integration tests | 20 passed |
| Serialized reservation refusal tests | 8 passed |
| Serialized allocator harness tests | 4 passed |
| NCA consumer error mappings | 4 passed |
| End-to-end qualifier refusal | 1 passed |
| Capacity-overflow regression | 1 passed |
| Sanitized source-read regression | 1 passed |
| PFS0 payload-span regression | 1 passed |

The exact invocations, test output, ignored counts, and failure counts are in
the linked transcripts. A separate unrestricted
`cargo test --no-default-features` invocation is not a supported repository
gate: its existing `multi_content_operations` CLI integration test requires
`standalone-job-history`. The Makefile's supported no-default-feature library
gate and feature-enabled integration gates passed.

## Allocator and pressure evidence

The qualifier also obtains canonical paths and copies the requested paths in
`open_snapshot_file` through standard-library APIs. Those `PathBuf` allocation
requests are not tagged by the reservation wrapper and remain `NOT_EVIDENCED`;
the focused tests make no positive refusal claim for them. The limited
integration exception and same-handle snapshot threat model from Issue #71
remain unchanged.

The focused tests recorded an exact one-shot refusal at each of these
reservation sites: `KeyFileBytes`, `Pfs0Metadata`, `Pfs0Entries`,
`Pfs0Spans`, `Pfs0NameBytes`, `NspRecords`, `NspMembers`, `NspSpans`,
`NspSourceHashBuffer`, `NspSectionHashBuffer`, `NcaHeaderSpans`, and
`NcaHeaderPartitions`. Each positive test asserts the targeted site,
occurrence, requested layout, and one observed refusal. The repeated-name
case targets its second reservation. Input and key-file bytes remain unchanged,
diagnostics remain sanitized, and the files can be read and renamed after the
refusal.

The `usize::MAX` regression records an attempted reservation with no
representable expected layout and zero injected allocator refusals. It is
reported as capacity overflow evidence and does not claim a GlobalAlloc refusal
or operating-system pressure. Genuine operating-system memory pressure is
`NOT_RUN`; PAC-3 remains `UNVERIFIED` pending owner review of that residual and
the preserved same-handle snapshot limitation.

## Platform status and Issue #47

No qualifying Windows 11 x86_64 host was available. FUP-2 remains `NOT_RUN` and
PAC-5 remains `UNVERIFIED`. Windows Server 2025, cross-compilation, and
architecture-emulated x64 execution do not satisfy this requirement. A native
x86_64 virtual machine on a native x86_64 host is acceptable when its
architecture, virtualization status, and host provenance are recorded.

Issue #47 remains open as a separate, broader four-target qualification. This
run provides partial macOS arm64 software-test evidence only; it does not
establish the Windows 11 or Linux host results, responder versions, MTP
capabilities, driver and permission setup, helper hashes and licenses,
synthetic-fixture coverage, or sanitized physical-device evidence required by
Issue #47. Its v1 universal-capability and conditional DBI0 gates remain
separate, and this task changes no advertised capabilities. No Issue #47
acceptance is claimed complete.

## Durable transcripts

- [`make all` transcript](make-all-macos-arm64-2026-11-12.log) — SHA-256
  `860a0c8394653158c1bb0a842a1f94c8fcb791ac921e20476c5b3a5506833784`
- [Focused validation transcript](focused-macos-arm64-2026-11-12.log) —
  SHA-256 `b715bf09ca8654c59f5610819b306dce1a509faebea830fb086c3f7fda7d0cae`
