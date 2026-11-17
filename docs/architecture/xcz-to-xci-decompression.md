# XCZ to XCI decompression

## Scope

This operation reconstructs a rights-free base Application XCI from one
qualified XCZ. The secure partition must contain exactly one Meta NCA and one
Program NCZ. NCA headers and the Meta NCA's CNMT determine the roles and
relationships; filenames do not. Control, Update, DLC, rights-bearing, and
other profiles remain unsupported. Native execution is qualified on macOS
arm64.

The operation reconstructs the supported NCA bytes and a valid bounded XCI
layout. It does not claim byte-for-byte restoration of the original XCI,
signature validity, Nintendo authenticity, console installability, or Full
Verification.

## XCZ input qualification

XCZ input has a private HFS0 policy. A declared entry hash is checked as
SHA-256 over exactly `hashed_size` bytes beginning at that entry's bounded
data span. The parser rejects a hash length larger than the member, an invalid
span, an incorrect digest, or a nonzero eight-byte field at HFS0 entry offset
`0x18`.

Only this exact tuple means that an upstream HFS0 hash is absent:

```text
hashed_size = 0
digest      = 32 zero bytes
```

Every other zero-length combination is malformed. An HFS0 table with no
entries is also accepted in the private XCZ path only when its entry count is
zero, its string-table size is one, and its single string byte is NUL. Public
recognition and ordinary XCI conversion retain their existing stricter rules;
ordinary XCI conversion continues to reject absent entry hashes.

The card-header root HFS0 digest at `[0x140..0x160]` is handled separately
from entry hashes. XCZ writers can copy the original 0x200-byte card header
after rebuilding HFS0 tables, so this digest can describe the earlier layout.
The input path calculates SHA-256 over the root HFS0 region declared by the
header. A match is recorded as verified. A mismatch is accepted only when
every root and nested HFS0 entry hash uses the exact absent representation;
the status is then `StaleUnverified`, never successful verification. If any
entry hash is present, the root digest must match. Present entry hashes are
still checked even if other entries use the approved absent form.

The structural parser requires the parsed root HFS0 table to fit inside the
card header's declared root-header region, requires that region to fit inside
the input file, and requires each root entry to begin after it. The digest
therefore covers the declared root-header bytes, including padding, without
including partition payloads. Hashing uses the parser's shared cumulative
256 MiB read budget; the XCZ path does not enlarge that budget or reinterpret
the declared hash span.

## Shared NCZ decoder and semantic checks

`src/ncz.rs` owns the bounded NCZ record reader and decoder used by both
NSP/NSZ and XCZ/XCI operations. The XCZ adapter first bounds HFS0 spans,
identifies the Meta and Program roles from NCA headers, and accepts the
existing single-section NCZ profile. It then decodes the Program member
through the shared reader and keeps the existing framing, window, size,
streaming, diagnostic, and key/counter zeroization boundaries.

The decompressed Program NCA and preserved Meta NCA are checked against the
Application CNMT. This includes the full NCA sizes and SHA-256 values, title
identity, content IDs, types, and row relationships. These full-content
checks are separate from HFS0's bounded prefix hashes.

## Reconstructed XCI layout

All arithmetic is checked before serialization. Unsupported or unrepresentable
layouts fail instead of wrapping offsets, truncating fields, or changing the
integrity rule.

1. The card header is `0x200` bytes. The root HFS0 begins at file offset
   `0xF000`; its declared region is `0x8000` bytes. Its serialized table and
   names must fit inside that region. Root entries are ordered as `update`,
   `normal`, `secure`, and optional `logo`.
2. Each partition HFS0 declares a `0x8000`-byte header region. `update` and
   `normal` are empty partition tables; `secure` contains the Meta and Program
   entries. When the source has a logo partition, the reconstructed image
   retains an empty logo partition. Member offsets and lengths are checked
   against their immediate HFS0 parent and the staged file. NCA payload starts
   and partition boundaries are aligned to `0x200` bytes.
3. Each required nonempty HFS0 member uses the implementation's bounded
   prefix rule: `hashed_size = min(member_length, 0x200)`. The serialized
   32-bit field is checked, and SHA-256 is calculated over exactly that prefix
   from the member's data start. This rule applies to root partition entries
   and nested secure NCA entries. It keeps cumulative reads within the
   recognition parser's unchanged 256 MiB budget; the supported output needs
   at most 3 KiB of HFS0 hash reads. The 0x200 prefix is an implementation
   choice, not a separately owner-approved policy invariant.
4. `RomAreaStartPageAddress`, card-header bytes `[0x104..0x108]`, is recomputed
   as `(secure_file_offset + 0x1000) / 0x200`. This uses the existing physical
   card-origin convention: the physical origin is `0x1000` bytes before file
   offset zero.
5. The output's physical end is `output_file_length + 0x1000`; its page count
   is rounded up in `0x200`-byte units. It must fit both the capacity named by
   the preserved `RomSize` byte `[0x10D]` and the preserved
   `ValidDataEndAddress` `[0x118..0x11C]`. Unsupported capacity codes and
   arithmetic overflow fail the operation.
6. Card-header root offset `[0x130..0x138]` is set to `0xF000`, declared root
   HFS0 size `[0x138..0x140]` is set to `0x8000`, and the root digest
   `[0x140..0x160]` is recomputed as SHA-256 over those exact `0x8000` staged
   bytes, including padding.

The source card-header signature `[0x000..0x100]` and opaque bytes
`[0x160..0x200]`, including `InitialDataHash` at `[0x160..0x180]`, are copied
unchanged. The operation does not recompute fields it cannot derive or
authenticate. Changing header fields while retaining the source signature
does not establish that the signature remains valid or that the image is
authentic. `RomSize` and `ValidDataEndAddress` are preserved constraints, not
proofs of authenticity.

## Independent staged verification and publication

Before destination conflict resolution, a verifier reads the staged output
independently and checks its length, root placement and declared size, HFS0
entry names, offsets, lengths, alignment, exact prefix lengths and digests,
`RomAreaStartPageAddress`, physical-end bounds, recomputed root digest, and
the preserved opaque header ranges. It also checks reconstructed Meta and
Program NCA bytes against the qualified source evidence and reruns semantic
CNMT qualification. The existing XCI structural parser is used for the
checks it implements; it is not treated as verifying the separate header
postconditions listed here.

Only after staged verification does the existing operation flow check the
source and key identities, evaluate `Fail`, `Skip`, or `Replace`, and publish
through the atomic publication path. Planning remains immutable; reconstruction
and validation use protected staging. Cancellation and conflict outcomes
retain the existing Engine and CLI contracts.
