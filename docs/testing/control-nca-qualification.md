# Control NCA IVFC/RomFS qualification

## Scope

`control_nca_qualification` checks one crate-private, read-only Control NCA
profile. A qualified result reports the NCA program ID, section and RomFS
sizes, directory and file counts, and the number of IVFC hash operations. It
does not establish signatures, Nintendo authenticity, installability, full
Verification, or readiness for conversion. Issue #16 Slice B owns conversion,
CNMT and member relationships, planning, and publication.

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
| PAC-5: compatibility | Crypto-helper tests cover arbitrary CTR read offsets, counter boundaries, and key-area behavior. The existing NSP semantic qualifier suite and repository regression suites exercise preserved behavior. No public API, CLI, JSON/JSONL, Verification, or conversion path is added. |
| TAC-1: documented parser and resource limits | Accepted profile, parser constraints, padding rules, checked budgets, and the operation ceiling are documented above. |
| TAC-2: independent synthetic fixtures | Test fixtures are generated at runtime from fixed synthetic keys and byte arrays; they contain no retail content or proprietary keys. |
| TAC-3: candidate-bound qualification | The Issue #79 run record documents the exact source candidate, toolchain, commands, exit statuses, coverage, and platform results. |
| TAC-4: isolated work and review gates | The candidate is developed in the approved isolated worktree and branch. The draft PR must record independent review provenance and the direct source/test inspection handoff. |

Issue #79 lists four TAC bullets without numeric identifiers. TAC-1 through
TAC-4 above follow the order of those bullets in the issue.
