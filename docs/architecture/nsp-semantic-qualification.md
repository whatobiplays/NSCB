# NSP semantic qualification

## Purpose and limits

`Engine::qualify_nsp_semantics` checks one narrow, read-only package profile.
It establishes byte-level consistency among an outer PFS0, one Meta NCA, one
Program NCA, and one Application CNMT. It does not establish Nintendo
authenticity, Full Verification, console installation, or compatibility with
ordinary retail packages.

The operation is separate from Content Recognition and Verification. A PFS0
probe remains framing evidence only. Recognition does not promote PFS0 to
positive NSP identity, and this result is not a Verification result.

## Supported profile

The outer PFS0 must contain exactly two nonempty members. Their checked spans,
sorted by payload offset, must start at zero, meet without gaps or overlap, and
end at the complete PFS0 payload size. The check does not depend on entry-table
order. Leading gaps, inter-member gaps, trailing bytes, and empty members
return `NotQualified(unaccounted_pfs0_payload)`. File names and extensions do
not assign member roles. The decrypted NCA headers must identify exactly one
Meta member and one Program member. Other base Application roles, including
Control, Data, Manual, and PublicData, are unsupported. Tickets, patches, DLC,
system updates, delta content, multiple titles, and rights-bearing NCAs are
outside the profile.

Each NCA must be NCA3, Download distribution, RightsId zero, effective key
revision zero, and key-area index zero. Its declared archive size must match
its bounded outer member. Exactly one section must be present, at index zero.
That section must use PartitionFs, Hierarchical SHA-256, AES-CTR, and no
extended section metadata.

The Meta and Program section PFS0 payloads follow the same complete-coverage
rule. Every entry must be nonempty, and the sorted entry spans must account for
the full PFS0 data region. The Meta PFS0 must contain exactly one file of
exactly `0x88` bytes. That extent is the `0x20`-byte CNMT header, `0x10`-byte
Application extended header, one `0x38`-byte content row, and the trailing
`0x20`-byte CNMT digest. The digest field is present inside the Meta section's
checked hash tree; this qualification does not recompute its value or use it
as an authenticity claim.
NSTool v1.9.2 includes the digest in its CNMT size calculation and reads it as
the final field. The [pinned CNMT layout](https://github.com/jakcron/libpietendo/blob/5d50d02f8f3b8918bdfbbb599b8c4c1628660d89/include/pietendo/hac/define/cnmt.h)
defines the digest size, and the [CNMT parser](https://github.com/jakcron/libpietendo/blob/5d50d02f8f3b8918bdfbbb599b8c4c1628660d89/src/hac/ContentMeta.cpp)
includes it in the extent and copies the final field.

The supported CNMT has Application type `0x80`, platform byte zero, a `0x10` byte
extended header, one content row, no content-meta rows, and zero content-meta
attributes. Its Application extended header has a zero PatchId. The single
row uses the modern five-byte size representation and zero ContentAttributes;
other CNMT encodings are unsupported.

The Program row must match the Program NCA's title ID, complete raw-member
SHA-256, first 16 digest bytes as ContentId, exact raw-member size, content type
`1`, and IdOffset `0`. The Meta NCA is accounted for separately by its own raw
size and digest. It is not required to appear as its own CNMT row.

## Key and header checks

The caller supplies a key file containing a 32-byte `header_key` or
`nca_header_key` and a pre-derived 16-byte
`key_area_key_application_00`. The latter is the Application key-area key for
revision zero. The qualifier does not derive keys, search for keys, read
tickets, or accept a title key.

The existing NCA reader decrypts the NCA3 header with AES-XTS and validates the
header and section descriptors. Header bytes `0x206` and `0x220` contain the
legacy and modern key-generation fields. The effective generation is the
larger value, with `0` and `1` both mapping to revision zero. The profile
accepts only effective revision zero. Byte `0x207` selects key-area index zero;
bytes `0x230..0x240` hold the RightsId and must all be zero.

The 64-byte encrypted key area at `0x300..0x340` is decrypted with AES-128-ECB
under the supplied Application key-area key. The third 16-byte key slot,
`0x320..0x330` after decryption, is the AES-CTR section key. The AES and CTR
operations use RustCrypto crates; NSCB does not implement AES.

The decrypted FS header for section zero occupies `0x400..0x600`. The existing
Verification helper checks its SHA-256 against the digest at `0x280..0x2a0`.
The FS header records the master hash at `0x08..0x28`, block size at
`0x28..0x2c`, layer count at `0x2c..0x30`, hash-table range at `0x30..0x40`,
PFS0 range at `0x40..0x50`, and section CTR at `0x140..0x148`. The accepted
layout has two layers, a power-of-two block size from `0x200` through
`0x100000`, checked non-overlapping ranges, and no unsupported metadata.

For a section-relative byte offset, the CTR counter's first eight bytes are
the reversed FS-header section CTR. Its last eight bytes are the big-endian
value `absolute_section_start / 16 + relative_offset / 16`. A read beginning
inside a 16-byte AES block skips the preceding keystream bytes. The section
start is the absolute NCA byte offset from the validated partition descriptor.

The qualifier hashes the complete hash-table range and compares that digest
with the FS-header master hash. It then checks each PFS0 data block against its
32-byte table entry. The final partial block is hashed using only its actual
bytes. The table length must equal
`ceil(PFS0 size / block size) * 32`.

## Bounded reads and source stability

The existing PFS0 parser validates names, bounds, and overlaps. It continues to
allow gaps for unrelated callers. This qualification layer adds its own
complete-coverage check and returns `unaccounted_pfs0_payload` for a readable
PFS0 whose nonempty member spans leave any bytes outside them. It supplies a
1 MiB total metadata limit and a profile-specific entry limit. Its member
reader checks `start + length` with checked arithmetic, caps every read at the
member end, and rejects seeks past that end. Nested Meta PFS0 and CNMT reads
are bounded again by their immediate parent ranges.

The no-gap rule is limited to this profile. The pinned hacPack writer at commit
[`e506cb58b7843d86df7518156debd28f3b575638`](https://github.com/DarkMatterCore/hacPack/tree/e506cb58b7843d86df7518156debd28f3b575638)
sets each PFS0 file offset to the cumulative preceding file sizes and writes
those files consecutively. Its PFS0 header alignment bytes are included in the
string table, while its hash-table alignment is placed before the PFS0 range.
This writer documents a compact PFS0 layout. Its output does not establish the
behavior of every PFS0 producer. The qualification profile accepts no
member-data padding; a broader padding rule requires separate owner review.

The source is opened once and read through that handle. The operation records
filesystem identity and metadata before reading, hashes the full source and
each raw member, rechecks the source at phase boundaries, and rechecks the key
file immediately after loading it. This detects observable replacement,
resizing, ordinary mutation, and inconsistent short reads. A hostile writer
that changes bytes and restores observable metadata may evade detection; this
is not an atomic snapshot and the result must not authorize later conversion.

Limits are part of this initial profile, not Nintendo format limits:

| Resource | Limit |
| --- | ---: |
| Source file | 64 GiB |
| PFS0 metadata | 1 MiB |
| Program-section PFS0 entries | 4,096 |
| Working buffer | 1 MiB |
| Hash block size | `0x200`–`0x100000` |
| CNMT file | exactly `0x88` bytes |

All format offsets and lengths use checked arithmetic. Allocation uses
fallible reservation. Cancellation is checked during source hashing,
hierarchical-hash verification, and between member checks.

## API and result meaning

The public API is additive and Engine-only:

Exported outcome, profile, role, facts, member, and result types are marked
`#[non_exhaustive]` so future evidence fields or variants can be added without
breaking downstream callers.

```rust
pub fn qualify_nsp_semantics(
    &self,
    request: NspSemanticQualificationRequest,
) -> Result<NspSemanticQualificationResult, NspSemanticQualificationError>;
```

`Qualified` carries the source digest and deterministic Meta-then-Program
member accounting and the explicit profile id
`rights_free_base_application_v1`. `NotQualified(reason)` means the source was
read but failed the selected profile. Typed errors report missing or malformed
prerequisites, cancellation, resource limits, input changes, and operational
failures. Source read errors are mapped to the sanitized `input_unavailable`
error without retaining the underlying OS message or path. If a supplied
Application key fails encrypted-section integrity checks, the stable error is
`key_or_section_integrity_failure`; it does not guess whether the key or the
encrypted bytes caused the mismatch.

Key-file contents, key bytes, and input paths do not appear in results or
diagnostics. Key buffers, decrypted key-area bytes, section keys, and streaming
buffers are zeroized on drop. The AES dependency enables its zeroization
support.

## Existing code and independent references

NSCB reuses its PFS0 parser, NCA3 header decryption and descriptor checks,
filesystem identity snapshots, SHA-256 digest type, and Verification's
filesystem-header hash check. New code is limited to bounded member access,
the supported AES-CTR section reader, the narrow CNMT parser, and the typed
Engine operation.

The byte layout and key-generation mapping were checked against Switchbrew's
[NCA format](https://switchbrew.org/wiki/NCA) and [CNMT format](https://switchbrew.org/wiki/CNMT).
The independent reader check used hactool at commit
[`1d64a83450e025622f3468c28fc4164dad2c5ef6`](https://github.com/SciresM/hactool/tree/1d64a83450e025622f3468c28fc4164dad2c5ef6).
NSTool v1.9.2 at commit
[`e89ea84bd70c11b67ebec9153fb4a446f18a9d3d`](https://github.com/jakcron/nstool/tree/e89ea84bd70c11b67ebec9153fb4a446f18a9d3d)
was built with its pinned submodules in a temporary directory. hactool read the
synthetic PFS0, Meta NCA, and Program NCA and reported the NCA profiles,
FS-header master hashes, hash tables, and PFS0 ranges as valid. NSTool read the
two-member package and both NCAs, then parsed the decrypted Meta CNMT. It
reported Application type `0x80`, the matching title ID, one Program row,
ContentId `785502b450c913702623235a2298874a`, size `0x1000`, and the full row
hash `785502b450c913702623235a2298874aa6510b1ce0d2ca2ab4614cb65fa42ef7`,
which matches the raw Program NCA digest. The synthetic NCA header signatures
failed as expected; NSTool also warned that the optional `title.keys` file was
unavailable. Neither warning is treated as a semantic pass. These checks do
not establish Nintendo authenticity or console installability.

Both readers were built in temporary directories and are not linked, bundled,
or invoked by NSCB. Their CLI and extraction paths do not provide the bounded
member and sanitized-error contract used by this Engine API. The runtime
implementation uses the existing NSCB parsers and RustCrypto primitives
instead of adding a package-reader dependency. hactool is ISC-licensed;
NSTool is MIT-licensed and brings separately licensed submodules. Both remain
external validation tools only.

## Remaining Issue #16 work

This prerequisite does not unblock Issue #16. Conversion still needs a
qualified XCI source profile and partition/member mapping, an explicit
transformation decision record, a deterministic NSP writer, an immutable
operation plan, safe conflict and cancellation behavior, no-change behavior,
staged destination semantic checks, publication postconditions, and the
required native platform evidence. Issue #16 must remain open until those
conversion requirements are implemented and reviewed.
