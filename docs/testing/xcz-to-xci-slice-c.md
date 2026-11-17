# XCZ to XCI Slice C qualification

## 1. Policy provenance

This slice follows owner-approved policy revision
`e2afa055d1126763c69f0e0392d25b86bab98014`. The owner selected the XCZ-only
absent-HFS0-hash rule, the shared NCZ decoder boundary, and this policy pin.
The output HFS0 prefix length `min(member_length, 0x200)` is an implementation
design decision, not a separately owner-approved invariant.

The source policy file at the pinned revision embeds distribution pin
`142422527de28b8e20dea1158d2f54d020dcdcd5`; the installed
`/Users/daniel/.agents/skills/delegation-executor/SKILL.md` embeds the
owner-approved `e2afa...` revision. The observed difference is limited to the
pin line. It is recorded here; no policy file was changed. Production Skill
activation remains pending.

## 2. Upstream interoperability fixture

### 2.1. Repository-controlled complete fixture

The acceptance fixture is a rights-free synthetic two-member Application. The
repository helpers build and retain the source XCI, Meta NCA, and uncompressed
Program NCA. Pinned upstream NSZ generates the Program NCZ payload and the
solid XCZ container. NSCB's encoder does not produce the NCZ payload.

The upstream source is
[NSZ commit `148218ff89bb4b607d07730a8cf87d5e1f249ebc`](https://github.com/nicoboss/nsz/tree/148218ff89bb4b607d07730a8cf87d5e1f249ebc).
The CLI entry path is `nsz.py -> nsz.main -> compress -> solidCompressXci ->
processContainer`. The generator invokes `nsz.py` with `-C --solid --level 1
--threads 1 --multi 1`; it omits `--block`. The run uses an XCI input, solid
compression, one worker and one stream, and a synthetic key file. The synthetic
keys pass the pinned parser's CRC checks, and the derived Application KAEK is
checked against the NCA evidence. No production or proprietary keys are used.

The recorded generator environment is Python 3.14.4 with these pinned package
versions:

| Package | Version |
| --- | ---: |
| `blessed` | 1.52.0 |
| `enlighten` | 1.14.1 |
| `jinxed` | 2.1.0 |
| `prefixed` | 0.9.0 |
| `pycryptodome` | 4.5.0 |
| `wcwidth` | 0.9.4 |
| `zstandard` | 0.25.0 |

`tests/fixtures/xcz-to-xci/upstream-nsz/generate.py` verifies the upstream
checkout's exact commit and requires its tracked and untracked working tree to
be clean before importing NSZ code. It disables Python bytecode writes in that
checkout. The generator verifies the source XCI's Meta and Program members
against retained evidence, creates the temporary synthetic key file inside the
fixture directory, invokes the upstream CLI, and extracts the Program NCZ
member from the resulting XCZ. The key file is removed when the generator
exits. The CLI test reads its input evidence from checked-in artifacts and
creates and removes its own temporary directory. It does not rely on artifacts
left in `/tmp` or an upstream checkout.

A negative generator check added an untracked sentinel to the upstream
checkout and confirmed generation stopped with a clean-checkout error. After
removing the sentinel, generation succeeded and reproduced the recorded
artifact hashes.

The raw upstream output is retained as `upstream-raw.xcz`. Its root HFS0 table
declares a secure-partition extent that ends 410 bytes after the raw file. The
acceptance fixture `upstream.xcz` appends exactly 410 zero alignment bytes so
the declared region is present. The generator confirms the missing length
before applying this adaptation. It does not change the card header, HFS0
tables, entry records, or compressed member bytes. The raw artifact remains
available so this difference is inspectable.

An upstream `--quick-verify` attempt on this source reported a hash mismatch.
The cause was not isolated, and that command is not used as passing evidence.
Acceptance instead checks the reconstructed Meta and Program members byte for
byte and by full-content SHA-256 against the retained uncompressed files.

To rebuild the upstream-produced artifacts, check out the pinned upstream
commit, install the versions in `requirements.lock`, then run:

```sh
git clone https://github.com/nicoboss/nsz.git /path/to/nsz-checkout
git -C /path/to/nsz-checkout checkout 148218ff89bb4b607d07730a8cf87d5e1f249ebc
python3.14 -m venv /path/to/nsz-env
/path/to/nsz-env/bin/python -m pip install -r tests/fixtures/xcz-to-xci/upstream-nsz/requirements.lock
/path/to/nsz-env/bin/python tests/fixtures/xcz-to-xci/upstream-nsz/generate.py --upstream-root /path/to/nsz-checkout
```

The fixture generator prints a JSON manifest with settings, the synthetic key
file SHA-256, the alignment adjustment, and artifact hashes. The key file
itself is transient. Its recorded SHA-256 is
`56c8ea6f228e6acee7a886481eecf035d62277daca67a7aa94b5ae837bc9fa0a`.

| Stored artifact | SHA-256 |
| --- | --- |
| `source.xci` | `32f9ceef52681b648bfc296e5603e8fb92a452ea23d9e1f529e9e7e059832573` |
| `meta.nca` | `87bfa1629b651e3f49a9ba053fb3842c5c34e31c9303e6e1807703cd84e68e7f` |
| `program.nca` | `166f438248bd9fbad65125fb76af5e002812e7a104902a516d626f3a6850bd2c` |
| `program.ncz` | `7047c3de8d7b777769181a037e7b6b538d6de9ac1833e460ef9b0fab6be58321` |
| `upstream-raw.xcz` | `7cd4b1890666d573426b08d834da788b30cd630f7014acdbb14d4e2eed5434c3` |
| `upstream.xcz` | `55e2c70ccd5e0c3de60158104426147fb90a30614273c7a3dc400dd84ee70115` |

The six binary artifacts are registered in `tests/fixtures/registry.json`
because they are stored in the repository. The reconstructed XCI is generated
inside the CLI test and is not stored or registered.

### 2.2. Earlier partial fixture record

An earlier external fixture combined an upstream XCI/HFS0 container writer with
a Program NCZ produced by NSCB's encoder. It established compatibility with
upstream's zero-sized, zero-digest HFS0 entries, one-NUL-byte empty partition
tables, and copied card header. The pinned upstream compression CLI rejected
that fixture's initial synthetic key material. This hybrid did not satisfy the
complete upstream-producer criterion and is retained here only as historical
evidence. Its files were kept under `/tmp`, were not stored in the repository,
and therefore had no registry entry.

| Earlier external artifact | SHA-256 |
| --- | --- |
| `upstream.xcz` | `11bba8dc02535bbc8e1d631c6011702726b4e86605ff70a4d7f8767e8e522417` |
| `meta.nca` | `6004d5de4eb90696acb8a118c0d8953d0754027e788f67c90edffbbcdd847577` |
| `program.nca` | `18937f6c024d638ca5730fe1c0b68c446b7dd1fa7c9af69d47c4a2206676cb31` |
| `program.ncz` | `b235f7e37898189282340a6982bf0d25b2bdbfd537ac5ffc3c8797dc7f401d4c` |
| `reconstructed.xci` | `20736de6953b022384fca27d7a16e547b7a9aee68949e499816b233314739777` |

That conversion returned `succeeded` with outcome `decompressed`, and the
reconstructed Meta and Program bytes matched the external uncompressed
evidence. The run also reported `cleanup_incomplete` because it retained
staging artifacts in an external workspace. The output was inspected for HFS0
prefix hashes, the root digest, geometry, opaque fields, and image length. This
partial fixture is superseded by the repository-controlled fixture above.

## 3. PAC acceptance evidence

### PAC-1: upstream interoperability and content qualification

The native CLI test rebuilds the source XCI from repository helpers and checks
it byte for byte against `source.xci`. It confirms the upstream XCZ contains
the retained `program.ncz`, then runs `xcz-to-xci` and compares both output NCA
members to the retained Meta and Program files by full bytes and full SHA-256.
The semantic qualifier independently checks the two-member Application CNMT
relationships, sizes, content IDs, types, and title identity. These full NCA
checks are separate from HFS0 prefix hashes.

The source has upstream's absent HFS0 entry hashes and a copied card-header
root hash. XCZ qualification accepts only the approved absent tuple
`(hashed_size = 0, digest = all-zero)`. It treats the copied root hash as stale
evidence rather than successful verification. Output construction recomputes
the card-header root HFS0 hash and independently verifies it in staged output.
The ordinary XCI path still rejects zero-sized entry hashes.

### PAC-2: failure safety and strict ordinary conversion

Existing tests cover malformed NCZ framing and records, unsupported NCZBLOCK
framing, malformed HFS0 names and hashes, incorrect present hashes, invalid
absent-hash tuples, stale root-hash handling, malformed and missing keys,
unsupported profiles, and bounded size and geometry arithmetic. They also
cover source and key identity changes, cancellation, destination races,
staged-output rejection, conflict handling, and failure without publishing a
partial destination. Output uses protected staging and is independently
checked before conflict resolution and atomic publication.

Ordinary XCI conversion remains strict. `tests/xci_to_nsp.rs` explicitly
rejects zero-sized HFS0 hashes and bad prefix digests. NSP-to-NSZ and NSZ-to-NSP
continue to use the shared bounded NCZ decoder and retain their existing
contracts.

### PAC-3: large-member HFS0 prefix validation

`recognition::tests::bounded_hfs_prefixes_keep_large_member_hashing_inside_the_shared_budget`
builds a sparse XCI with a nominal 150 MiB Program member. It runs the strict
root and nested HFS0 parser through a byte-counting reader. The test checks
every declared prefix equals `min(member_length, 0x200)`, checks the entry
digests by requiring strict parsing to succeed, and counts actual bytes read
across the parser passes against the unchanged 256 MiB cumulative budget. The
sparse extension avoids allocating a 150 MiB in-memory payload.

The test changes a byte beyond the Program entry's 0x200-byte prefix and
confirms that the HFS0 digest remains unchanged. Prefix validation therefore
does not claim full-member integrity. Full-content NCA SHA-256 and CNMT
qualification supply the separate semantic checks. Existing unit tests cover
short members, `u64`-sized lengths, checked HFS0 hash sizing, and distinct
prefix and full-content spans without allocating multi-gigabyte fixtures.

### PAC-4: CLI contract

`tests/xcz_to_xci_cli.rs` runs the actual `nscb xcz-to-xci` executable with
synthetic inputs and keys. The successful JSON test checks the exact existing
top-level schema, version, operation kind, result state, and outcome. The JSONL
test checks one JSON object per line, schema version, event kind, increasing
event sequence, and exactly one terminal result after all events. Both modes
compare reconstructed Meta and Program bytes and full digests to retained
evidence.

The subprocess tests also check invalid arguments (exit 2), missing keys and
malformed input (exit 3), stable error documents, no output on failure, and
sanitized diagnostics without temporary paths or synthetic key bytes. A
non-macOS arm64 test checks `unsupported_capability` before opening input
paths. No public JSON or JSONL fields were added.

## 4. Validation and coverage

Native runtime qualification uses macOS arm64 and the repository's Rust
1.98.1 toolchain. The final `cargo test --locked --all-features` run passed all
24 test targets: 1,211 passed, 0 failed, and 4 ignored. This includes the
150 MiB sparse HFS0 test, all five XCZ CLI tests, NSP↔NSZ tests, ordinary
XCI-to-NSP tests, and three doctests. Both `rustc` and `rustdoc` were pinned to
1.98.1 for this run.

`cargo fmt --check` and strict all-target, all-feature Clippy also passed on
the pinned toolchain. The focused sparse-parser test passed independently. The
x86_64 Linux all-target check compiled the unsupported-platform CLI test. The
x86_64 macOS all-target check compiled with existing unused-code warnings in
architecture-gated NCZ and provider modules. These cross-target checks establish
compilation only.

The x86_64 Linux all-target check exercises compilation of the
unsupported-platform CLI test. The x86_64 macOS all-target check also compiles;
it reports existing unused-code warnings in architecture-gated NCZ and
provider modules. No runtime claim follows from either cross-target check.

The instrumented `cargo test --locked --all-features` attempt exited 1. The
non-instrumented run exposed a toolchain mismatch: the shell paired pinned Rust
1.98.1 `rustc` with Homebrew `rustdoc`, which caused incompatible-crate errors
in doctests. The full suite passed after both tools were pinned. The
`cargo-llvm-cov` subcommand is unavailable. Xcode's `llvm-cov` could read the
generated profiles but did not produce a trustworthy changed-line aggregate,
so no current coverage percentage is reported.

The following coverage table is the last measured snapshot from before the
cancellation-probe follow-up. It is retained as historical evidence only and
does not describe the current PR head:

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

That earlier calculation excluded comments, inline `#[cfg(test)]` modules,
documentation, unchanged source lines, and test-only helpers. It combined
library coverage with a separately instrumented CLI run. `src/operation.rs`
was below the former 90% target; the gaps were in rare staging, I/O, and
resource-limit failure branches. The table is not current coverage evidence.

Earlier validation history includes a `make all` run interrupted at
`tests/test_cleanup.py` when the host disk was full; cleanup cases errored, so
that run did not pass. Linux AArch64 cross-compilation was not available when
`aarch64-linux-gnu-gcc` was missing, and Windows MSVC compilation was not
available without the Windows SDK and C headers. Those checks are not runtime
qualification.

## 5. Independent review history

Earlier local Cubic passes reviewed the implementation, recognition rules,
integration, fixtures, and documentation. Their findings and dispositions
remain part of this record:

1. A staged root-offset concern was assessed against the existing strict XCI
   parser. XCZ planning accepts only the qualified profile with root HFS0 at
   `0xF000`, and reconstructed output uses the same offset.
2. A cross-platform planning concern was fixed. The Engine now returns
   `UnsupportedCapability` outside macOS arm64 before opening inputs.
3. A root digest range and read-budget concern was assessed against
   `inspect_xcz_for_conversion`: the parser bounds the declared root region to
   the input, requires the table and entries to fit, and charges root hashing
   to the existing cumulative 256 MiB budget.
4. Two P1 architecture findings requested shared copy-through planning and a
   feature-specific `XczSemanticInput` adapter. A later pass repeated the
   shared-planning finding. The operation reuses
   `plan_copy_through_unix_for_output` to collect source and destination
   evidence, protected staging, and conflict metadata, then sets
   `OperationKind::XczToXci` and attaches `XczToXciPlan`. The plan carries no
   copy-through-only state, and review found no copy-through behavior in the
   XCZ route. `XczSemanticInput` exposes bounded reads over the retained Meta
   span and reconstructed Program spool so the existing semantic qualifier
   can check CNMT relationships without changing its interface.
5. The later review also reported a P2 maintainability finding: `src/xcz_to_xci.rs`
   groups source qualification, the virtual package view, XCI layout and
   serialization, staged verification, and tests. Splitting it would add
   module boundaries beyond the approved design, so the suggestion remains
   deferred.
6. An independent specification review found that staged semantic
   qualification did not poll cancellation while hashing full NCA members and
   checking CNMT relationships. Qualification now polls cancellation during
   bounded member hashing and at work checkpoints. Tests cover cancellation in
   those phases.
7. A Cubic pass found a duplicate bounded `SpanReader` in `nsp_nsz.rs` and
   `ncz.rs`. The duplicate was removed and NSP↔NSZ now uses the shared reader
   in the NCZ module. Follow-up review found no issue with that correction.

An earlier review also objected that the first upstream fixture was external
and hybrid. The repository-controlled upstream fixture in §2.1 supersedes that
limitation. The earlier partial fixture and its hashes remain in §2.2.

The current cumulative-diff Cubic review record, including the reviewed
candidate tree, reviewer provenance, findings, and correction-delta
dispositions, is stored with the local qualification evidence for this PR.
No GitHub review was requested. The draft PR and Issue #17 remain open until
ChatGPT completes renewed direct source and test review.
