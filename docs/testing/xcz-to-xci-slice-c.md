# XCZ to XCI Slice C qualification

## 1. Policy provenance

This slice follows owner-approved policy revision
`e2afa055d1126763c69f0e0392d25b86bab98014`. The owner selected the XCZ-only
absent-HFS0-hash rule, the shared NCZ decoder boundary, and this policy pin.
The `min(member_length, 0x200)` output HFS0 hash prefix is an implementation
design decision, not a separate owner-approved invariant.

The source policy file at the pinned revision embeds distribution pin
`142422527de28b8e20dea1158d2f54d020dcdcd5`; the installed
`/Users/daniel/.agents/skills/delegation-executor/SKILL.md` embeds the
owner-approved `e2afa...` revision. The observed difference is limited to the
pin line. The discrepancy is recorded here; no policy file was changed.
Production Skill activation remains pending.

## 2. Upstream fixture provenance and limits

The external fixture used upstream NSZ commit
[`148218ff89bb4b607d07730a8cf87d5e1f249ebc`](https://github.com/nicoboss/nsz/tree/148218ff89bb4b607d07730a8cf87d5e1f249ebc).
Its outer XCI/HFS0 container was written with that revision's `XciStream` and
`Hfs0Stream` classes. It reproduces the upstream zero-sized, zero-digest HFS0
entries, one-NUL-byte empty partition tables, and copied card header. The
fixture's Program NCZ member was generated from the independent synthetic
Program NCA using NSCB's existing encoder; it was not produced by the upstream
full compression command.

The pinned upstream CLI was also tried with the synthetic NCA and key file,
but rejected the synthetic key material before compression. As a result, this
qualification demonstrates upstream container-writer compatibility and
NSCB decompression of the supported NCZ record; it does not claim a complete
upstream-compressor-to-NSCB end-to-end oracle.

Fixture files and the generator were kept under `/tmp/nscb-upstream-fixture`
and were not stored in the repository. The fixture does not need a repository
binary registry entry. Recorded fixture SHA-256 values:

| Artifact | SHA-256 |
| --- | --- |
| `upstream.xcz` | `11bba8dc02535bbc8e1d631c6011702726b4e86605ff70a4d7f8767e8e522417` |
| `meta.nca` | `6004d5de4eb90696acb8a118c0d8953d0754027e788f67c90edffbbcdd847577` |
| `program.nca` | `18937f6c024d638ca5730fe1c0b68c446b7dd1fa7c9af69d47c4a2206676cb31` |
| `program.ncz` | `b235f7e37898189282340a6982bf0d25b2bdbfd537ac5ffc3c8797dc7f401d4c` |
| `reconstructed.xci` | `20736de6953b022384fca27d7a16e547b7a9aee68949e499816b233314739777` |

The successful standalone CLI conversion returned `succeeded` with outcome
`decompressed`. Its result also reported `cleanup_incomplete`: the existing
operation artifact-retention path kept staged artifacts in the external
workspace. This is not a conversion failure, but the retained artifact state
is recorded rather than hidden.

Independent inspection confirmed that reconstructed Meta and Program bytes
and full SHA-256 digests match the synthetic uncompressed evidence. It also
checked every output HFS0 prefix hash, root digest, card-header geometry,
preserved opaque bytes, and output length. The staged image was recognized by
the existing XCI recognizer. Output HFS0 hash reads totaled 2,560 bytes for
this fixture.

## 3. PAC and TAC evidence

### PAC-1 — Correct decompression

The Engine end-to-end test and the external fixture both reconstruct the
Program NCA and preserve the Meta NCA. The semantic qualifier checks the
two-member Application CNMT against full NCA sizes, digests, content IDs,
types, and title identity. Full NCA digests are separate from output HFS0
prefix hashes.

### PAC-2 — Failure safety

Tests cover malformed NCZ framing and records, unsupported NCZBLOCK framing,
malformed HFS0 names and hashes, incorrect present hashes, invalid absent
hash tuples, stale root-hash handling, malformed keys, missing keys,
unsupported profiles, and bounded size/geometry arithmetic. Failures do not
publish a partial destination.

### PAC-3 — Publication safety

Tests cover cancellation during member hashing and semantic qualification,
source and key identity changes, destination races, staged-output rejection,
and conflict behavior. Output is written in protected staging and checked
independently before destination conflict resolution and atomic publication.

### PAC-4 — Public integration

The operation is exposed through the typed Engine and `xcz-to-xci` CLI
integration. Public recognition and ordinary XCI conversion remain strict.
NSP↔NSZ regression tests continue to exercise the shared decoder and existing
operation behavior.

## 4. Native validation

Native qualification uses macOS arm64 and the repository's pinned Rust 1.98.1
toolchain. An earlier `make all` completed before the final cancellation-probe
follow-up. On the final rerun, content policy (53 tests), all-target checks,
formatting, and strict Clippy passed. The run reached `tests/test_cleanup.py`
while the host disk was full; several cleanup cases errored and I interrupted
the suite to prevent further disk exhaustion. That last `make all` run is not
a pass.

After the final bounded-reader reuse, the pinned toolchain passed the full
library suite (594 passed, four ignored), the NSP↔NSZ integration suite (17
passed), and the ordinary XCI-to-NSP integration suites (19 and 4 passed).
Strict Clippy passed for all targets and features. The x86_64 Apple and x86_64
Linux all-target checks passed. The final library suite includes the
cancellation checkpoint tests. A separately instrumented standalone CLI run
converted the upstream fixture, and its invalid-argument and usage paths
completed with their expected CLI errors.

The x86_64-apple-darwin target passed `cargo check --locked --all-targets
--all-features` with Rust 1.98.1. The x86_64-unknown-linux-gnu target also
passed `cargo check --locked --all-targets --all-features` with Rust 1.98.1,
including the unsupported-capability planner branch. Linux AArch64 cross-
compilation could not run because
`aarch64-linux-gnu-gcc` is unavailable. Windows MSVC cross-compilation could
not run because the host toolchain lacks Windows SDK/C headers. These are not
runtime qualification results. Native qualification for other platforms
remains outstanding; CI results are recorded with the published draft PR.

Coverage is generated with Rust's `-C instrument-coverage` and the matching
Xcode `llvm-profdata` and `llvm-cov`. The changed-code calculation counts
changed Rust lines that LLVM records as executable, and excludes comments,
inline `#[cfg(test)]` modules, documentation, unchanged source lines, and
test-only helpers. It combines library coverage with the separate instrumented
CLI run. This is the last measured snapshot before the cancellation-probe
follow-up. The final code adds executable cancellation paths; aggregate
coverage was not rerun, so the percentages below do not describe the exact
final diff.

| Source file | Covered changed executable lines |
| --- | ---: |
| `src/cli.rs` | 41 / 41 (100.00%) |
| `src/engine.rs` | 6 / 6 (100.00%) |
| `src/lib.rs` | 1 / 1 (100.00%) |
| `src/ncz.rs` | 262 / 289 (90.66%) |
| `src/nsp_nsz.rs` | 39 / 40 (97.50%) |
| `src/operation.rs` | 313 / 354 (88.42%) |
| `src/recognition.rs` | 131 / 134 (97.76%) |
| `src/xci_to_nsp.rs` | 1 / 1 (100.00%) |
| `src/xcz_to_xci.rs` | 1,292 / 1,400 (92.29%) |
| **Changed Rust executable lines** | **2,086 / 2,266 (92.06%)** |

The aggregate exceeds the 90% target. The changed `src/operation.rs` lines are
below 90%; remaining gaps are in rare staging, I/O, and resource-limit failure
branches. Whole-file coverage for shared files is not presented as slice
coverage. The unsupported-capability branch compiled in the Linux cross-check
is not part of the native macOS runtime coverage profile.

## 5. Independent review and release boundary

Local Cubic passes reviewed the source, recognition, integration, fixture,
and documentation changes. One pass questioned the staged root-offset check.
XCZ planning first uses the strict XCI structural parser, which rejects a
root HFS0 offset other than `0xF000`; the reconstructed output uses that same
offset. The concern does not apply to this qualified profile.

Another pass found that the Engine exposed XCZ planning on every target while
the operation planner existed only on macOS. The planner now returns
`UnsupportedCapability` outside macOS and on macOS targets other than arm64.
The pinned Rust 1.98.1 x86_64 Linux all-target check passes with this branch.

A later pass questioned whether the input root digest could cover partition
data or exceed the read budget, and whether `ncz` compiled outside macOS. The
parser requires the root table to fit in the declared root region, the region
to fit the input file, and each root entry to begin after that region. It
hashes only the declared region, including padding, and charges those bytes
to the unchanged cumulative 256 MiB budget. The Linux all-target check also
passed.

An earlier complete-diff Cubic pass reported two P1 architecture findings:
the use of shared copy-through planning for XCZ and the feature-specific
`XczSemanticInput` virtual PFS0 adapter. A later pass reported one P1 and one
P2:

1. The P1 finding says XCZ is modeled as copy-through because planning starts
   with `plan_copy_through_unix_for_output`.
2. The P2 finding notes that the 1,785-line `src/xcz_to_xci.rs` module
   contains qualification, the virtual reader, layout and serialization,
   staged verification, and tests.

The plan reuses the output planner for source and destination evidence,
protected staging, and conflict metadata. It then sets
`OperationKind::XczToXci` and attaches `XczToXciPlan`; execution selects the
XCZ producer. The plan carries no CopyThrough-specific state, and I found no
copy-through behavior leak. Shared key-identity and staging-context helpers
use names that describe their cross-route use.

`XczSemanticInput` exposes bounded reads and seeks over the preserved Meta
span and reconstructed Program spool. It revalidates source and spool
identities and lets the existing qualifier check CNMT relationships without
writing another package or changing the qualifier interface. The module is
large; its implementation groups the source profile, virtual package view,
XCI layout, writer, and verifier for this operation. Splitting those pieces
would add module boundaries beyond the approved design. These findings remain
recorded as architecture and maintainability concerns. Neither review found
a reproducible correctness or safety defect that required a behavior change.

The final Cubic pass reported a P1 concern that the XCZ root digest might
extend beyond the declared root region. The finding does not account for the
first parser pass in `inspect_xcz_for_conversion`: `Parser::xci` requires the
declared region to fit in the input, the parsed table to fit in that region,
and every root entry to begin after it. The conversion pass then hashes
exactly the declared region, including padding, under the same 256 MiB read
budget. I found no unbounded root-hash read and made no behavior change.

An independent spec review found that staged semantic qualification did not
poll cancellation while `qualify_xci` hashed full NCA members and checked CNMT
relationships. The validator now uses `qualify_xci_with_cancellation_probe`,
which polls during bounded member hashing and passes the probe through the
virtual-input qualifier's work checkpoints. Tests cover cancellation in both
phases. The review also noted that the upstream-writer fixture is external
and cannot be replayed by CI from this candidate. Its provenance and hashes
remain recorded here; it was generated outside the repository, so no binary
fixture registry entry was added.

The final local Cubic pass found a duplicate bounded `SpanReader` in
`nsp_nsz.rs` and `ncz.rs`. Since NSP↔NSZ already uses the shared NCZ module,
`nsp_nsz.rs` now imports the shared reader and the duplicate implementation
has been removed. That pass also repeated the module-size P2 concern. Splitting
the operation's qualification, virtual input, writer, and verifier into more
modules would broaden the approved architecture, so that maintainability
suggestion remains deferred. A follow-up local Cubic review after the reader
change found no issues.

Cubic reviewed the local diff without GitHub repository context. No GitHub
review was requested. CI is tracked separately on the draft PR linked to
Issue #17. This slice does not authorize merge, issue closure, or production
policy activation.
