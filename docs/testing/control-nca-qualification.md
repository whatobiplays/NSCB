# Control NCA IVFC/RomFS qualification

## Scope

`control_nca_qualification` checks one crate-private Control NCA profile. Its
qualification result reports the NCA program ID, section and RomFS sizes,
directory and file counts, and the number of IVFC hash operations. The
standalone extraction path can also request a private tree and file-span
inventory from that qualification pass. Neither result establishes
signatures, Nintendo authenticity, installability, full Verification, or
readiness for conversion. Issue #16 Slice B owns conversion, CNMT and member
relationships, planning, and publication.

The production code uses NSCB's NCA header parser and key-file reader. The
private `nca_crypto` module supplies only the shared key-area slot-two decryptor
and bounded AES-CTR reader. The NSP qualifier keeps its existing profile and
behavior.

## Accepted profile

The qualifier accepts a rights-free NCA3 download Control title with one base
RomFS partition. It requires key generation zero or one, key-area index zero,
a zero RightsId, Hierarchical SHA-256, AES-CTR, no extended filesystem, and
zero reserved filesystem-header bytes. Unsupported, patch, sparse, compressed,
and additional-section profiles fail closed.

The RomFS superblock must contain an IVFC header with six descriptors, level
count seven, ID `0x20000`, a 32-byte master hash, and block exponent 14. Each
hash block is 16,384 bytes. The root descriptor is exactly one block.

Input size is limited to 64 GiB. The RomFS metadata budget is 1 MiB, including
the fixed 0x50-byte header and all directory/file hash and metadata tables.
The combined directory and file record count is limited to 32,768. IVFC
verification uses a fixed 64 KiB table buffer and one 16 KiB hash block at a
time. The key file is checked against NSCB's existing key-file byte ceiling
before parsing. Metadata, record vectors, traversal state, and file extents use
checked, fallible allocations within those limits.

## IVFC layout and hashing

The six descriptors must have contiguous starts, nonzero sizes, and checked
ends within the section. Descriptor starts are block-aligned; the last RomFS
descriptor may have a partial final block. The hash table for a child level
needs `ceil(child_size / 16,384) * 32` bytes. The containing level may include
zero-filled physical padding to the next block boundary. If the hash table
length is already block-aligned, this profile also accepts one extra
zero-filled block, matching the pinned hacPack builder's aligned output.

The root descriptor contains the hash table for level one and zero-filled
stored padding. Its full 16 KiB is checked against the master hash. For each
child descriptor, the verifier reads the declared bytes in a block and hashes
those bytes followed by zeros up to 16 KiB when the last block is partial.
Those temporary zeros exist only in the hash buffer. They are distinct from
physical padding stored after a hash table or after the final descriptor.
At the pinned hacPack revision, the RomFS builder records the unpadded size,
then appends zeros to its temporary file before the IVFC builder creates the
parent hash. The descriptor keeps the unpadded size, so the verifier hashes
that declared range with temporary zero fill and checks stored bytes after the
descriptor as a separate range.

Stored padding is checked separately. Padding in each parent descriptor must
be zero. Section bytes after the six descriptors must also be zero. If the
final RomFS descriptor is partial, the section tail must be smaller than one
16 KiB block. If it is block-aligned, the profile allows at most one full
block of tail padding. hacPack applies the same rule when padding its RomFS
input: it appends the bytes needed to reach the next block and appends a full
block when the input is already aligned. A partial final RomFS block hashes
its declared bytes plus temporary zero fill; any stored bytes after the
descriptor are a separate range and must pass the physical-padding check.

This zero-only padding rule is a restriction of this supported profile.
Integrity hashes alone do not require every possible stored gap in every IVFC
producer to contain zeros.

### Hash-operation ceiling

Let `B = 16,384` bytes and let `S1` through `S5` be the declared spans of the
five child descriptors. These spans include physical padding recorded inside
each descriptor. The six descriptors are contiguous within one section, so
`S1 + ... + S5` is no larger than the section, which is smaller than or equal
to the 64 GiB NCA input limit. The root descriptor is one `B`-byte block whose
master digest is counted separately.

The total operation count is:

```text
1 + sum(ceil(Si / B), i = 1..5)
```

For five terms, the sum of the rounded-up counts is at most the rounded-up
combined size plus four:

```text
sum(ceil(Si / B)) <= ceil((S1 + ... + S5) / B) + 4
ceil(64 GiB / 16,384) = 4,194,304
maximum operations = 1 master digest + 4,194,304 blocks + 4 rounding terms
                  = 4,194,309
```

The one master digest accounts for level zero. The five block-count terms
account for levels one through five, including their descriptor padding. A
partial block still costs one operation. Section padding after the last
descriptor is checked for zero bytes and adds no hash operation. The test
`input_and_hash_operation_limits_include_the_boundary` exercises the bound,
including four partial child spans and one span just below a block boundary.

## RomFS validation

The parser requires the 0x50-byte header and checked, adjacent table ranges. It
validates four-byte table alignment, variable-length record sizes and padding,
names, file extents, directory and file hash buckets, hash-chain links, parent
references, child and sibling links, and the root-reachable graph. File data
occupies the range from `data_offset` up to `directory_hash_offset`; file record
offsets are relative to `data_offset` and must remain within that range. It
rejects cycles, duplicate names, invalid parents, and records that cannot be
reached from the root. Traversal is iterative and checks cancellation while
scanning tables, records, hash chains, names, graph links, and extents.

Tests rebuild the IVFC tree after changing RomFS bytes. Graph and extent
failures therefore reach the RomFS validator instead of failing at an earlier
hash level.

## Extraction inventory

The extraction-only qualifier entry point uses the same header, IVFC, and
RomFS checks. It creates directory paths and file spans from the records that
passed those checks. A file span is bounded by the accepted partition and
section, and its CTR offset is relative to the start of the Control section.
This path does not add a second RomFS parser or relax the qualification rules.

Planning reads selected file spans as plaintext through the existing bounded
AES-CTR reader and records a digest for each file. The private operation plan
keeps span offsets, digests, and non-secret section metadata; it does not keep
the section key. Execution derives the key again from the verified source and
key files, streams each span through AES-CTR, and checks the staged file digest
against the planning digest. Source and key evidence is checked again before
publication. The extraction inventory is not exposed through Inspection or
Verification.

Control `All` selection includes every validated directory and can publish a
complete bundle when the tree has no files. Explicit selector requests must
match at least one file. The shared portable-path checks apply to selected
names, while valid UTF-8 names that are not portable may remain unselected if
they do not make a selected path ambiguous.

## Source, key, and failure handling

Input and key files are opened read-only and must be regular files. The
qualifier checks file identity and snapshots after opening and again before it
returns a completed result. A caller may also provide the expected key-file
snapshot. Cancellation is checked before work and during IVFC and RomFS
processing.

Results and errors are crate-private and typed. Error formatting does not
include paths, key contents, or underlying OS messages. Key material,
decrypted key-area bytes, hash blocks, and metadata buffers that can contain
file data are held in zeroizing storage. Qualification does not write to the
source or key file.

## Format references

The implementation was cross-checked against these pinned source revisions.
They document the inspected format behavior; they are community references,
not normative specifications. The production build adds no dependency on them.

| Reference | Pinned sources | Cross-check |
| --- | --- | --- |
| hactool, `1d64a83450e025622f3468c28fc4164dad2c5ef6` | [`ivfc.h`](https://github.com/SciresM/hactool/blob/1d64a83450e025622f3468c28fc4164dad2c5ef6/ivfc.h#L8-L59), [`nca.c`](https://github.com/SciresM/hactool/blob/1d64a83450e025622f3468c28fc4164dad2c5ef6/nca.c#L853-L879), [`romfs.c`](https://github.com/SciresM/hactool/blob/1d64a83450e025622f3468c28fc4164dad2c5ef6/romfs.c) | IVFC header and descriptor sizes, six physical levels, 16 KiB block profile, full-block hashing with zero fill for the final partial block, and RomFS record structures. |
| hacPack, `e506cb58b7843d86df7518156debd28f3b575638` | [`ivfc.c`](https://github.com/DarkMatterCore/hacPack/blob/e506cb58b7843d86df7518156debd28f3b575638/ivfc.c#L24-L69), [`nca.c`](https://github.com/DarkMatterCore/hacPack/blob/e506cb58b7843d86df7518156debd28f3b575638/nca.c#L53-L76), [`romfs.c`](https://github.com/DarkMatterCore/hacPack/blob/e506cb58b7843d86df7518156debd28f3b575638/romfs.c#L401-L516) | Six-level construction, cumulative descriptor offsets, 16 KiB hashing, RomFS padding, bucket hashing, record layouts, and the extra stored block emitted when a hash table already ends on a block boundary. |
| Switchbrew NCA page, revision 14983 (`oldid=14983`) | [NCA format page at the pinned revision](https://switchbrew.org/w/index.php?title=NCA&oldid=14983) | NCA and filesystem-header field descriptions used as a secondary reverse-engineered reference. |

The qualifier follows the declared descriptor sizes. For a partial final
block, the hashed bytes are the declared bytes followed by zero fill in the
temporary block. A producer may also store zero padding outside that declared
span. The verifier treats and checks that stored padding separately.

## Acceptance coverage

| Criterion | Evidence in this module |
| --- | --- |
| PAC-1: positive, independent qualification | Runtime-built rights-free fixtures qualify through the private API; unsupported NCA and filesystem profiles fail closed. No conversion operation is invoked. |
| PAC-2: complete IVFC verification | Master hash and all six descriptor levels have corruption cases. Malformed IDs, counts, exponents, offsets, alignment, overlap, overflow, out-of-bounds spans, padding, and filesystem-header digest are rejected. |
| PAC-3: RomFS graph and extents | Rebuilt trees cover malformed tables and records, bucket-chain and sibling cycles, dangling links, duplicate names, invalid parents, unreachable records, and invalid file extents. |
| PAC-4: bounded read-only behavior | Tests cover cancellation checkpoints, missing and mutated input/key files, expected key snapshots, unchanged file bytes and snapshots, resource ceilings, allocation refusal at each tagged site, typed failures, and key/path redaction. |
| PAC-5: compatibility | Crypto-helper tests cover arbitrary CTR read offsets, counter boundaries, and key-area behavior. The existing NSP semantic qualifier suite and repository regression suites exercise preserved behavior. The qualifier remains private and does not change public Inspection or Verification results; Slice B's additive extraction selectors and manifest values are covered below. |
| TAC-1: documented parser and resource limits | Accepted profile, parser constraints, padding rules, checked budgets, and the operation ceiling are documented above. |
| TAC-2: independent synthetic fixtures | Test fixtures are generated at runtime from fixed synthetic keys and byte arrays; they contain no retail content or proprietary keys. |
| TAC-3: candidate-bound qualification | The Issue #79 run record documents the exact source candidate, toolchain, commands, exit statuses, coverage, and platform results. |
| TAC-4: isolated work and review gates | The candidate is developed in the approved isolated worktree and branch. The draft PR must record independent review provenance and the direct source/test inspection handoff. |

Issue #79 lists four TAC bullets without numeric identifiers. TAC-1 through
TAC-4 above follow the order of those bullets in the issue.

## Issue #18 Slice B extraction acceptance

The qualification criteria above establish the Control profile. The following
criteria cover its use by standalone extraction.

| Criterion | Evidence |
| --- | --- |
| PAC-B1: profile and selector behavior | Engine tests cover complete and selective byte-exact extraction, directory-only trees, zero-length files, selector misses, case mismatches, type mismatches, path aliases, and unselected nonportable names. CLI tests cover `--role control` and `--nca-type control`. |
| PAC-B2: deterministic manifests | Engine tests compare complete and incomplete Control manifest bytes across separate output bundles and check the completeness value. Existing Program extraction tests continue to cover manifest ordering and serialization. |
| PAC-B3: integrity and file correspondence | Qualification tests corrupt the master hash and each IVFC level. Engine tests reject a corrupt IVFC tree before planning and compare extracted file bytes to independently built synthetic RomFS content. |
| PAC-B4: traversal and publication safety | RomFS tests reject malformed tables, links, duplicate names, invalid parents, unreachable records, and out-of-range file extents. Extraction publication tests cover staged symlinks, FIFOs, hard links, destination races, uncertainty retention, and cleanup. |
| PAC-B5: bounds, mutation, and cancellation | Tests cover input, metadata, record, allocation, selector, and hash-operation limits; each of the six extraction-inventory reservations is refused at its tagged site and maps to a resource-limit error; source and key mutation or replacement after planning; cancellation; destination conflicts; and unchanged input bytes after allocation refusal. |
| TAC-B1: synthetic inputs | Fixtures use fixed synthetic keys and generated NCA/RomFS bytes; they contain no retail content or proprietary keys. |
| TAC-B2: native qualification | Native macOS arm64/APFS runs passed 39 Control qualification and extraction tests, 17 extraction operation tests, 9 CLI tests, and 9 partition-path budget tests using rights-free synthetic fixtures. The Control group includes a direct execution-time stale-evidence test. |
| TAC-B3: build and coverage | `make all` passed. All-target Linux GNU and Windows GNU checks passed; Windows MSVC stops in `ring` because this host lacks Windows SDK `assert.h`, so that target remains unqualified. An earlier merged LLVM profile measured line coverage of `resolve_control_extraction` 100%, `resolve_extraction_from_inventory` 95.38%, CLI `parse_extraction` 93.27%, `normalize_romfs_tree` 82.66%, `join_romfs_path` 95.45%, `prepare_control_runtime` 98.08%, `verify_control_key_handle` 90.91%, `copy_selected_span` 96.97%, `copy_verified_selected_bytes` 94.29%, `copy_control_selected_span` 97.22%, `write_extraction_tree` 98.33%, `validate_bundle_tree` 97.96%, and `derive_control_extraction_key` 75.61%. Those measurements predate the stale-evidence test and the final directory-path storage correction, so they do not describe the final source. The Rust 1.98.1 raw profile uses format version 11, while the available LLVM profile tools expect version 10; refreshed merged percentages are unavailable. The earlier measurements put `normalize_romfs_tree` and `derive_control_extraction_key` below the 90% target. The current tests exercise stale program identity, section-counter, and NCA-header rejection during key derivation. Each of the six inventory allocation refusal sites is also exercised directly. |
| TAC-B4: review and CI | Local Cubic reviews raised concerns about duplicate directory paths, unused qualification facts in extraction results, and the private output-mode enum. The implementation now stores one normalized path per directory and returns only the extraction inventory from extraction qualification. The output-mode concern remains disputed because the existing facts result is unchanged, the two internal callers select their corresponding modes, and both use one IVFC/RomFS validation path. The final full-diff correction review found no issues. Focused tests passed. GitHub Actions CI run 112 passed on implementation commit `2506667665b414879fe80067b1b7119175c9f548`, including macOS arm64 `make all` and hosted Windows MSVC library and Clippy jobs. Direct ChatGPT source/test inspection remains pending. |
