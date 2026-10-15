# Content recognition

`Engine::recognize_content(ContentRecognitionRequest::new(path))` performs bounded,
read-only recognition of a regular file. `nscb recognize <path> [--json]` uses that
same facade. JSON is one document with schema version 1 and kind
`content_recognition.result`; malformed/operational failures use the existing
sanitized `error` envelope. Recognized results exit 0, Unknown and Ambiguous exit
3, usage exits 2, allocation/output failures exit 7, and other input errors exit 3.

## Evidence matrix

| Input | Positive evidence | Conclusion and limitations |
| --- | --- | --- |
| NSP/PFS0 | Existing complete PFS0 header, entries, string table, checked nonoverlapping spans | PFS0 family; NSP/NSX identity and uncompressed representation remain unestablished |
| NSZ | Validated PFS0 plus independently validated NCZ member bytes | PFS0 with NCZ representation; names never establish compression |
| NCZ | NCZSECTN at 0x4000, complete section records, optional complete NCZBLOCK framing, encoded Zstandard frame structure | Standalone archive representation; no authenticity or decoded-content correctness claim |
| XCI | HEAD at 0x100, root partition at its documented 0xF000 placement, only the known root names once each with update, normal, and secure present, one bounded partition HFS0 per root entry, and the ordinary card's RomArea page relation | Card-image family; uncompressed variant remains unestablished |
| XCZ | Validated card profile plus independently validated leaf NCZ bytes, with the copied source card page inside the RomSize-declared capacity and no later than the declared valid-data end | Card-image family with NCZ representation; no decompression-correctness claim |
| NCA | Readable supported NCA3 header and archive/section relationships | Conditional standalone archive recognition; ordinary encrypted headers yield no positive NCA identity |
| NSX | No unique keyless structural discriminator | Identity unestablished; ticket-like names do not establish ticket absence, validity, or NSX |

Sources are [NSZ formats](https://github.com/nicoboss/nsz/blob/master/docs/formats.md),
[Header.py](https://github.com/nicoboss/nsz/blob/master/nsz/Header.py),
[Decompressor.py](https://github.com/nicoboss/nsz/blob/master/nsz/Decompressor.py),
[SectionFs.py](https://github.com/nicoboss/nsz/blob/master/nsz/SectionFs.py),
[BlockCompressor.py](https://github.com/nicoboss/nsz/blob/master/nsz/BlockCompressor.py),
[BlockDecompressorReader.py](https://github.com/nicoboss/nsz/blob/master/nsz/BlockDecompressorReader.py),
[Zstandard framing](https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md),
[hactool XCI](https://github.com/SciresM/hactool/blob/master/xci.h),
[Atmosphere HFS0 metadata](https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libstratosphere/include/stratosphere/fssystem/fssystem_partition_file_system_meta.hpp),
[Atmosphere NCA header](https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libstratosphere/include/stratosphere/fssystem/fssystem_nca_header.hpp), and
[NCA reader](https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libstratosphere/source/fssystem/fssystem_nca_reader.cpp).

## Exact structural boundaries

NCZ has one eight-byte NCZSECTN marker at 0x4000, an unsigned little-endian
64-bit nonzero count at 0x4008, and 64-byte records at 0x4010. Records contain
64-bit offset, nonzero size, supported crypto type (1, 3, or 4), eight zero
padding bytes, and 16-byte key/counter slots each. Key/counter slots are bounded
but never read or reported. Records describe checked contiguous original-image
spans. The first span can precede 0x4000 or follow it with an implicit gap.
Reconstructed length is the final section end minus 0x4000; it is independent
of physical compressed EOF. Other section layouts produce unsupported_structure.

Optional NCZBLOCK follows the records: version 2, type 1, unused 0, exponent
14–32, 32-bit block count, 64-bit reconstructed size, and the complete 32-bit
size list. Count equals ceil(size/block size). Each nonzero physical block size
is at most its expected reconstructed length. Equal sizes are stored raw;
smaller sizes require Zstandard framing. Every physical span is checked and
final physical position equals enclosing archive EOF. Solid NCZ validates
Zstandard frames through EOF. Frame descriptors, dictionary policy, declared
sizes, block types/lengths, last-block markers, and optional checksum spans are
checked; encoded block bodies are skipped. Nonzero external dictionary IDs are
unsupported. No decompression, checksum verification, entropy validation, or
content authenticity is performed.

XCI requires the full 0x200-byte header, HEAD at 0x100, a root offset at 0x130
that places the root partition at its documented 0xF000 file position, and a
declared header span at 0x138. Root and partition starts align to 0x200.
Declared header span is bounded independently of calculated metadata and may
include padding. The root HFS0 carries at most four partitions that use only the
known names update, normal, logo, and secure, each at most once, and must
include update, normal, and secure. Switchbrew documents that named layout;
hactool additionally rejects unrecognized or duplicated names and more than
four partitions, so the required trio is a conservative reading of the
documented card profile rather than a hactool rule. Every root member is parsed
as a bounded partition HFS0 and all leaf members are examined before success; an
unsupported readable NCA member profile is treated as unavailable optional
evidence and leaves the proven container structure intact. HFS0 metadata
consists of a 16-byte header, 64-byte records, and names. Entries have checked
ordered/nonoverlapping immediate-parent spans, UTF-8 terminated names, and
hash-target offset plus hashed size within the member. The 64-bit field at entry
offset 0x18 is a hash-target offset, not reserved padding.
RomAreaStartPageAddress at 0x104 counts 0x200-byte pages from the physical card
origin, which lies 0x1000 bytes before the first byte of a card image, so an
ordinary card relates it to the secure partition placement. Compressed cards
rebuild partitions while copying the source card header, so a validated NCZ
leaf permits a copied address that differs from the rebuilt secure partition
position. The copied page must still be at least 0x80, the page containing the
documented root placement at file offset 0xF000. It must also fit the geometry
the card header itself declares: RomSize at 0x10D selects a documented 1, 2, 4,
8, 16, or 32 GiB card capacity, the page must start inside that capacity and no
later than the ValidDataEndAddress at 0x118, and that valid-data end, also in
0x200-byte pages, must not exceed the capacity. A page later than the declared
valid-data end is impossible whichever way the end field counts its final page,
and an undocumented RomSize code cannot establish card geometry; both are
rejected as unsupported. The bounds follow the per-card declaration rather than
a universal maximum card size.
Signatures, hashes, and key material are never verified. There is no generic
recursive discovery.

Readable NCA recognition currently supports NCA3 only, a full 0xC00 header,
valid distribution/content/key-index values, enclosing archive size equality,
and nonempty ordered sector spans beyond the header. Absent slots must be
consistent. FS header version 2, known enums/reserved fields, and a PartitionFs/HierarchicalSha256 profile with checked layer count,
power-of-two block size, ordered bounded layer regions, and hash-table capacity
are validated. Modern FsType is byte 2 (PartitionFs = 1); HashType is byte 3
(HierarchicalSha256 = 2). Older hactool uses different field names. Patch, sparse, compression,
metadata-hash, other hash-tree and extended encryption profiles return
unsupported_structure pending qualification; modern extended fields are not
misrepresented as universally reserved. Signatures, title identity, keys, and
section content are neither interpreted nor verified.

## Public result semantics

`recognition` is a tagged result: recognized with a family and compression
variant, unknown, or ambiguous with deterministic conflicting families.
Multiple independent top-level claims yield Ambiguous. Malformed, unsupported
structural profiles and budget violations are typed errors, never partial
success or Unknown. An unproven compressed or uncompressed variant remains
not_established. Filename extensions produce a separate extension observation.

`package_structure_eligibility` describes consideration by future whole-container
package/card-image operations, based only on uncontested top-level structure:

| Evidence | State |
| --- | --- |
| PFS0 framing alone | not_established |
| Standalone positively proven NCA or NCZ | ineligible |
| Validated PFS0 containing independently validated NCZ | eligible |
| Valid card profile: documented root placement, known unique partition names, required update/normal/secure hierarchy, bounded partition headers | eligible |
| Valid card profile whose validated NCZ members establish the compressed variant | eligible |
| Unknown, insufficient, or conflicting evidence | not_established |

Nested archives never disqualify their enclosing container. This scalar is not
execution authorization or readiness of any operation. It establishes no keys,
Verification, authenticity, or decompression correctness, and compressed-format
compatibility does not establish genuine Nintendo content. No per-operation
capability list is exposed.

`ticket_name_observation` is present for a case-insensitive .tik member suffix,
not_observed after complete validated PFS0 names without that suffix, and
not_applicable without applicable validated PFS0 metadata. It never interprets
ticket contents, rights, package/NSX identity, or eligibility.

## Cumulative budgets and preservation

One ledger covers all nested processing: 16 MiB structural metadata (including
fixed headers, NCZ slots/lists and frame headers), 256 MiB actual reads including
repeated reads, 65,536 aggregate entries/section records/block-list records,
and 16 MiB copied/validated names with 4 KiB per name. A separate cumulative
parser-work ceiling of 1,000,000 units shares the same ledger: one NCZ section
descriptor, NCZBLOCK block-size descriptor, Zstandard frame, and Zstandard
block header each cost one unit, and the counter spans every nested parse of
one input. Exceeding it returns the stable limit_exceeded error. Only parser
work is capped by this ceiling; the metadata, read, entry, and name byte
ceilings above remain unchanged. The ceiling binds before those byte ceilings
can be reached: every counted unit also charges at least three metadata bytes,
so the 16 MiB metadata budget alone admits at most about 5.6 million units.
Container traversal is fixed at top-level
card → root partitions → leaf archives. No per-member tier limits or
early-success shortcuts apply. Arithmetic, allocations and spans are checked.
Encoded payloads are seek-skipped, never accumulated or persisted. The separate
Container Probe and all of its supported ceilings remain unchanged.

## Issue #5 acceptance replacement for owner review

The following wording is proposed for replacing the issue acceptance criteria;
this document does not edit the GitHub issue.

## Acceptance criteria

1. Recognition is exposed through a typed, host-neutral Rust Engine operation and a normal CLI command using the same facade. Recognition request, result, and error types are distinct from Container Probe. Machine output includes an explicit schema version and a distinct recognition result kind.

2. Equivalent input bytes produce the same structural recognition and package_structure_eligibility regardless of filename or extension. Extensions cannot establish format, resolve ambiguity, or admit an input. Extension disagreements are reported separately from structural conclusions.

3. Unknown and Ambiguous are separate typed recognition results, both producing CLI exit class 3 and failing closed. Operational failures and malformed, truncated, or budget-exceeding structures produce distinct typed, stable, sanitized errors. Ambiguity is never resolved by filenames, ticket-name observations, or helper fallback.

4. Every positive format or compressed-variant conclusion requires documented, validated structural byte evidence. The approved evidence matrix covers NSP/NSZ, NCZ, XCI/HFS0, XCZ, NCA, and NSX, including mixed compressed and uncompressed members. Positive card-image recognition additionally requires the documented root placement, only known unique partition names with update, normal, and secure present, and one bounded nested HFS0 per root entry; an extension or member filename never substitutes for that evidence. Synthetic fixture signatures cannot substitute for actual format evidence. Exact format invariants are documented from the approved format research.

5. Standalone NCA is positively recognized only when approved research establishes sufficient keyless byte evidence. If that proof cannot be established within this slice, NCA identity remains unestablished and recognition fails closed. No key discovery, decryption, cryptographic operation, helper fallback, or automatic Inspection fallback is introduced.

6. NSX is positively recognized only when unique positive byte evidence distinguishes it from other package conventions. Without that evidence, NSX identity remains unestablished regardless of ticket-name observations or filename extensions. If NSX is positively established, its read-only restriction is explicitly documented without introducing per-operation capability modeling.

7. Recognition exposes one public scalar package_structure_eligibility with only Eligible, Ineligible, or NotEstablished. It describes whether the established top-level structure supports future whole-container package or card-image consideration. The mapping is: PFS0 framing alone → NotEstablished; positively proven standalone NCA or NCZ → Ineligible; validated top-level PFS0 containing validated NCZ → Eligible; valid XCI card header and required HFS0 hierarchy → Eligible; valid XCZ structure with independently validated NCZ → Eligible; Unknown or insufficient evidence → NotEstablished. Ambiguous remains a separate typed result that fails closed with CLI exit class 3. Embedded archives do not by their presence make an otherwise established top-level container Ineligible. The scalar does not authorize execution, indicate implemented-operation readiness, establish keys or Verification, or model eligibility per operation. Compressed-format compatibility does not establish genuine Nintendo content or correct decompression.

8. ticket_name_observation uses only present, not_observed, or not_applicable and derives solely from validated PFS0 member-name metadata. present reports an observed ticket-like member name; not_observed reports its absence from completely validated PFS0 name metadata; not_applicable applies when validated PFS0 name metadata is unavailable or outside the recognized structure. The observation makes no claim about ticket contents, validity, rights, package identity, NSX identity, or package_structure_eligibility.

9. Recognition admits regular files read-only, uses checked arithmetic and container-derived bounds, and enforces explicit cumulative budgets across all nested structures and member processing. Reads, metadata allocations, copied names, member counts, and nesting are bounded for the entire recognition request. Inputs are not mutated and payloads are not persisted.

10. Engine::probe_container and its public request/result/error types, PFS0 validation ceilings, CLI behavior, exit classes, and JSON contracts remain unchanged. Container Probe remains separately requested and keyless. Neither Probe nor recognition implies content-aware Inspection, Verification, title identity, authenticity, or execution authorization.

11. Deterministic synthetic or explicitly registry-backed redistributable tests cover every supported positive structural claim and every package_structure_eligibility mapping, conditional NCA and NSX outcomes, identical bytes under different extensions, mismatch notices, Unknown and Ambiguous results, ticket-name observation independence, nested archives without automatic top-level disqualification, adversarial bounds, cumulative nested/member budgets, sanitized errors, nonregular inputs, source-byte preservation, and Probe regressions.

12. Targeted tests and ordinary make all pass with locked Cargo validation and the existing content-policy gates. This issue does not authorize make all-git-ai-paused, changes to global Git AI service state, arbitrary helper execution, or weakening validation gates.
