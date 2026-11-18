# XCI to XCZ compression

## Scope and authorization

The operation accepts one rights-free base Application XCI with exactly one
Meta NCA and one Program NCA in its secure partition. Content roles come from
the NCA headers and the Meta NCA's CNMT. The operation rejects Control
content, rights-bearing NCAs, populated auxiliary partitions, and other
profiles. It is qualified for native macOS arm64 execution.

The owner separately approved extending the plaintext NCZ section-key and
counter policy from NSP-to-NSZ to this XCI-to-XCZ profile in
[Issue #17](https://github.com/whatobiplays/NSCB/issues/17#issuecomment-6957933172).
The approval is restricted to the qualified rights-free base Application
profile. Standard NCZ metadata exposes the selected 16-byte Program section
key and counter to anyone who obtains the artifact, who may then decrypt the
associated compressed section. Plans and diagnostics redact keys and
counters, in-memory buffers are zeroized, temporary output remains private
until validation, and semantic CNMT checks are repeated against staged bytes.
These controls do not conceal the standard metadata in a published XCZ.

## Shared format components

`src/ncz.rs` owns NCZ framing, the bounded streaming encoder and decoder, and
the frozen Zstandard settings. NSP/NSZ and XCI/XCZ adapters supply container
member spans and section geometry. Their qualification and orchestration
remain separate.

`src/xci_format.rs` owns checked card-header geometry, HFS0 serialization,
hash calculation, bounded span copying, and padding. XCZ-to-XCI and XCI-to-XCZ
keep separate plans, writers, verifiers, and publication paths. The shared
extraction preserves the existing XCZ-to-XCI card-header and HFS0 behavior.

## Accepted source bytes

The root HFS0 must contain `update`, `normal`, and `secure`, with optional
`logo`. Each auxiliary partition must be one exact `0x200`-byte HFS0 block:

- `HFS0` magic, entry count zero, string-table size zero, and reserved field
  zero.
- Every byte in the block from offset `0x10` through `0x1FF` is zero.
- The root HFS0 entry length and hashed size are exactly `0x200`, its reserved
  offset is zero, and its prefix digest is valid.

The root HFS0 table must fit within the card header's declared root region;
bytes between the serialized table and the declared region end must be zero.
The card-to-root gap, gaps between referenced root partitions, and any bytes
after the last root partition must also be zero. These gaps are treated only as
padding. The validator streams them through a fixed 64 KiB buffer. Referenced
auxiliary entries, oversized auxiliary spans, nonzero padding, and hidden
nonzero bytes in unreferenced gaps fail during planning before staging begins.
The writer emits canonical empty auxiliary blocks and does not preserve
populated auxiliary partitions.

## Output and verification

The Meta NCA is copied byte-for-byte. The Program member alone is compressed
through the shared NCZ encoder. Its basename is retained and its terminal
lowercase `.nca` suffix becomes `.ncz`; unsupported suffixes and name
collisions fail closed.

The writer retains the source `RomSize` and `ValidDataEndAddress` values as
limits, recomputes the secure start page, root HFS0 geometry, and root digest,
and preserves the card-header signature and opaque fields. It rejects layouts
that exceed either declared physical bound instead of enlarging those fields.

Execution writes the NCZ member to a private spool, measures it, then builds
the final HFS0 table from the measured length. Before resolving destination
conflicts, an independent staged-output pass checks HFS0 spans and hashes,
root geometry and digest, header postconditions, Meta identity, NCZ framing,
and exact Program reconstruction. It repeats semantic CNMT qualification and
compares the reconstructed NCA identity and digest with the planned source.
Cancellation, source/key mutation checks, destination races, and atomic
publication use the existing Engine flow.

The operation proves bounded container structure, encoded-byte reconstruction,
and the qualified semantic relationships. It does not establish signature
validity, Nintendo authenticity, console installability, Full Verification,
or byte-identical restoration of an entire XCI.
