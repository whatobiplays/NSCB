# NSP and NSZ conversion

## Scope

The conversion supports one rights-free Application package profile on macOS
arm64. The outer PFS0 must contain exactly two nonempty, contiguous members:
one Meta NCA and one Program NCA. The roles come from decrypted NCA headers,
not filenames. Other package roles and layouts are unsupported.

Compression converts only the Program NCA to NCZ. The Meta NCA is copied
byte-for-byte. The package must already pass the existing NSP semantic
qualifier. This operation does not establish Nintendo authenticity, console
installability, or Full Verification.

`src/nsp_nsz.rs` owns NSP/NSZ qualification and orchestration. The shared
`src/ncz.rs` module owns NCZ member framing and the container-independent
encoder and decoder. The adapter supplies the already-qualified Program NCA
span and section geometry; moving the encoder does not change NSP/NSZ
qualification or output layout.

## Planning and output sizing

Planning reads and qualifies the source and records immutable file identities,
member spans, names, and source digests. It does not encode bytes or retain
section keys or counters. The compressed member size and digest are unknown
until execution finishes encoding.

Execution streams the encoded Program member to a private spool inside the
operation's staging directory. The spool is measured and hashed, then its exact
length is used to build the final PFS0 layout. The final NSZ is written to a
separate staged output. This keeps the PFS0 metadata accurate without a
deterministic second encoding pass.

The output is independently checked before publication. For NSP-to-NSZ,
validation decodes the staged Program NCZ, compares the reconstructed Program
NCA with the planned source bytes, checks the unchanged Meta NCA, and confirms
the source's semantic qualification again. For NSZ-to-NSP, validation
reconstructs the Program NCA and runs the existing semantic qualifier over the
staged NSP. The Program row must match the reconstructed NCA's title identity,
ContentId, size, content type, and SHA-256. The Meta NCA remains byte-for-byte
unchanged and is qualified as part of that final package check.

The decompressor requires the external NCA header key and revision-zero
Application key-area key used by the semantic qualifier. The NCZ section key
and counter are enough to reconstruct Program bytes, but they do not prove the
package's CNMT relationships. No original NSP is needed when validating an
NSZ input: the reconstructed Program NCA is checked against the CNMT carried
by the preserved Meta NCA.

Destination conflict decisions are made after staged output has passed these
checks. Byte-identical output returns `AlreadyUpToDate`; otherwise the
operation applies the requested Fail, Skip, or Replace policy using the
existing publication path.

## Frozen compression settings

An NSP-to-NSZ plan records its private encoder settings without changing the
public Operation Plan snapshot, JSON, or JSONL schemas. The public Rust request
uses `NszCompression`: `Fast` resolves to level 3, `Balanced` resolves to level
9, `Maximum` resolves to level 19, and `Level(i32)` accepts levels 1 through
19. The request constructor defaults to `Balanced`, preserving the existing
level 9 behavior. The CLI exposes mutually exclusive `--preset
fast|balanced|maximum` and `--level 1..19` options on `nsp-to-nsz` and
`xci-to-xcz`.

The private plan freezes the Zstandard identity and version, resolved level,
window log 27, checksum enabled, content size enabled, zero worker threads,
no dictionary, and the exact NCZ section suffix length as the pledged source
size. Execution uses those values and rejects a version or input-size mismatch;
it does not resolve the preset again or adjust settings. The numeric ceiling
of 19 is the supported range for both compression operations. Zstandard 1.5.7
accepts a wider set of provider levels, but those levels are outside the
qualified profile. Zstandard documents that higher levels generally require
more memory, so the operation's cap is a profile boundary rather than the
codec's maximum.

The project pins `zstd` 0.14.4, `zstd-safe` 8.3.0, and
`zstd-sys` 2.1.3+zstd.1.5.7. Planning captures the linked version and rejects
any build that does not provide that qualified codec. The build omits the
`zstdmt` feature; Zstandard's worker parameter defaults to zero, and the plan
rejects any other worker count. The 128 MiB window limit constrains decoder
back-reference distance. It is not a bound on encoder peak memory. Preset names
describe the selected level's speed or ratio intent; measured performance is
specific to the synthetic input and host used for qualification.

## NCZ format limits

The writer preserves the first `0x4000` Program NCA bytes and writes one
`NCZSECTN` record followed by one solid Zstandard frame. The record describes
AES-CTR section data and contains the section key and counter in plaintext, as
required for interoperable NCZ. The decoder accepts the emitted clipped
geometry and the standard upstream section geometry. It rejects NCZBLOCK,
multiple section records, extra frame data, unsupported section layouts, and
packages above 64 GiB. PFS0 metadata is limited to 1 MiB and streaming uses
64 KiB buffers with a maximum Zstandard window of 128 MiB.

Only an exact terminal lowercase `.nca` or `.ncz` suffix is accepted. The
Program member keeps its basename while its suffix changes. Missing, uppercase,
or otherwise unsupported suffixes are rejected; arbitrary names are not
rewritten. Normalized output-name collisions reject the package. Names never
select Meta or Program roles.

## Key handling

The owner approved standard interoperable NCZ, including plaintext section
keys in the published NCZ artifact, for the NSP-to-NSZ first slice in
[Issue #17](https://github.com/whatobiplays/NSCB/issues/17#issuecomment-6894369005).
XCI-to-XCZ uses a separate authorization recorded in the same issue.
The implementation keeps key material out of plans, results, progress events,
and diagnostics. In-memory key and counter buffers are zeroized on drop.
Temporary files use mode `0600` in private directories with mode `0700`.
These controls reduce accidental exposure; they do not hide the standard NCZ
keys from someone who can read the output artifact.

## Evidence boundaries

Structural recognition checks the supported PFS0 and NCZ framing. Byte
reconstruction checks that NCZ decoding recreates the Program NCA bytes.
Semantic qualification checks the reconstructed package against its Meta NCA
and CNMT using the external keys. Full Verification remains a separate
operation and is not implied by any of these checks.

The codec interoperability check used upstream NSZ commit
[`148218ff89bb4b607d07730a8cf87d5e1f249ebc`](https://github.com/nicoboss/nsz/tree/148218ff89bb4b607d07730a8cf87d5e1f249ebc)
with synthetic keys and content. The upstream decoder reproduced an NSCB
output NSP byte-for-byte, and NSCB reproduced the upstream compressor's NSP
byte-for-byte. This checks framing and codec interoperability only. The
synthetic fixture is not retail content, and the upstream decoder's CNMT-based
NCA report did not qualify its preserved synthetic Meta NCA. The result is not
Full Verification evidence.

The native codec dependency and its pinned versions are recorded in the
[third-party dependency assessment](../research/third-party-dependency-assessment.md#issue-17-nspnsz-conversion).
