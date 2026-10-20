# Content Verification architecture

## Scope

Verification is a read-only Engine operation that evaluates a standalone
encrypted NCA3 file and returns typed evidence for each check the selected
profile requires. It reads the input and key source; it never rewrites either
file. The current capability supports one deliberately narrow profile:

- NCA3 header encrypted with an available header key.
- Program content type.
- Game Card or Download distribution.
- Effective key generation `0x00` through `0x20`.
- One through four PartitionFs (PFS0) partitions.
- Partition hash type `None` (raw byte `1` in the filesystem header).
- Clear partition content (encryption type `None`, raw byte `1`).
- No extended partition metadata.

Full verification adds the filesystem-header hash, the fixed-key signature,
NPDM metadata validation, the NPDM-key signature consistency check, and a
payload integrity check. Structural verification runs the common structural
checks only. Other content types, filesystems, hash layers, encryption
profiles, container families, and hosts remain outside the qualified profile
and fail closed with a typed result or prerequisite error.

Verification is implemented natively in Rust. It does not invoke NSTool or
any other provider, so a successful Inspection provider run is not evidence
for a Verification result.

## Public API

```rust
use nscb::{
    CancellationHandle, Engine, VerificationCheckId, VerificationOutcome,
    VerificationRequest, VerificationResult,
};

let engine = Engine::new();
let request = VerificationRequest::full_nca(
    "content.nca",
    "prod.keys",
    "anchor.der",
    5,
)
.with_cancellation(CancellationHandle::new());

let result: VerificationResult = engine.verify(request)?;
for check in &result.checks {
    println!("{}: {:?}", check.id.as_str(), check.outcome);
}
if result.outcome == VerificationOutcome::Passed {
    println!("every applicable check passed");
}
# Ok::<(), nscb::VerificationError>(())
```

`VerificationRequest::structural_nca(input, key_file)` creates a Structural
request. `VerificationRequest::full_nca(input, key_file, trust_anchor,
anchor_generation)` creates a Full request. Neither constructor performs I/O;
`Engine::verify` opens the paths and returns a sanitized
`VerificationError` when the operation cannot produce a result. A completed
operation returns `VerificationResult` whether the aggregate outcome is
`Passed` or `Failed`.

The public types are additive: `VerificationProfile`, `VerificationOutcome`,
`CheckApplicability`, `CheckExecution`, `CheckOutcome`,
`VerificationCheckId`, `VerificationReason`, `VerificationLimitation`,
`TrustProvenanceKind`, `PublicKeyEncoding`, `TrustProvenance`,
`VerificationCheck`, `VerificationResult`, and `VerificationErrorCode`.
RSA key types remain internal; callers supply a path rather than key material
through the public API.

## Profiles and stable checks

Checks always appear in the order below. Structural reports the first four.
Full reports all nine.

| Order | Check ID | Structural | Full |
| ---: | --- | :---: | :---: |
| 0 | `nca3.header_profile` | required | required |
| 1 | `nca3.partition_layout` | required | required |
| 2 | `nca3.partition_filesystem` | required per present partition | required per present partition |
| 3 | `nca3.partition_entries` | required per present partition | required per present partition |
| 4 | `nca3.fs_header_hash` | outside profile | required per present partition |
| 5 | `nca3.fixed_key_signature` | outside profile | required |
| 6 | `nca3.npdm_metadata` | outside profile | required |
| 7 | `nca3.npdm_key_signature_consistency` | outside profile | required |
| 8 | `nca3.payload_integrity` | outside profile | required or not applicable |

Each check carries:

- `applicability`: `required` or `not_applicable`.
- `execution`: `completed` or `not_run`.
- `outcome`: `passed`, `failed`, or `not_applicable`.
- An optional stable `reason` for a non-passing check.
- An optional partition index for per-partition checks.
- Optional trust provenance for signature checks.

A required check that cannot run is reported as `not_run` with outcome
`failed` and reason `prerequisite_check_failed`. It never becomes
`not_applicable` or `passed`. A check outside the selected profile is
omitted from the result rather than reported as skipped. Structural results
therefore contain no signature or hash entries and no claim about them.

Stable reasons are `unsupported_profile`, `partition_layout_invalid`,
`partition_filesystem_unsupported`, `partition_entries_invalid`,
`fs_header_hash_mismatch`, `signature_mismatch`,
`trust_anchor_generation_mismatch`, `npdm_missing`, `npdm_duplicate`,
`npdm_malformed`, `npdm_key_signature_mismatch`,
`prerequisite_check_failed`, `hash_type_none`, and
`hash_type_unsupported`.

## Shared NCA validation

The shared `nca` module parses the encrypted NCA3 header after decryption and
validates four partition descriptors. Descriptor byte `0x8` occupies the
first byte of an eight-byte field that hactool documents as padding and
Switchbrew documents as reserved. libpietendo names that byte `enabled` and
the remaining seven bytes `reserved`; hacPack-family writers have been
observed to write `1`. NSCB therefore accepts `0` or `1` in byte `0x8` and
requires bytes `0x9` through `0xF` to be zero. It does not interpret the
field as a block count.

Primary references:

- Switchbrew, [NCA FsEntry](https://switchbrew.org/wiki/NCA#FsEntry): offset
  `0x8`, size `0x8`, "Reserved".
- hactool, [nca.h](https://github.com/SciresM/hactool/blob/master/nca.h):
  `nca_section_entry_t` contains `uint8_t _0x8[0x8]; /* Padding. */`.
- libpietendo,
  [nca.h](https://github.com/jakcron/libpietendo/blob/5d50d02f8f3b8918bdfbbb599b8c4c1628660d89/include/pietendo/hac/define/nca.h#L133-L139):
  `sPartitionEntry` contains `byte_t enabled` followed by seven reserved
  bytes.

Descriptor span relationships are validated separately from byte syntax.
That separation lets Structural and Full verification report an invalid
layout as `partition_layout_invalid` while preserving the byte-level
acceptance rule above.

The filesystem header for partition index `i` begins at
`0x400 + i * 0x200` in the decrypted header block. Byte `0x2` is FsType
(`1` is PartitionFs), byte `0x3` is HashType, byte `0x4` is EncryptionType,
and byte `0x5` is the extended-metadata flag. This profile accepts FsType
`1`, HashType `1` (None), EncryptionType `1` (None), and a zero extended
flag. Switchbrew documents HashType `1` as None and HashType `2` as
HierarchicalSha256; the latter is outside this slice.

### Partition entries

For each supported partition, Verification probes the PartitionFs table and
then applies the same bounded path validation used by Inspection. Member
names must be relative, normalized paths; control characters, backslashes,
empty segments, leading or trailing separators, `.` segments, `..` segments,
and segments with surrounding whitespace fail. Two members resolving to the
same normalized path inside one partition also fail. Entry count, total name
bytes, total expanded path bytes, and path-segment count share explicit
cumulative limits across the file.

An invalid member table records `nca3.partition_entries` as completed and
failed with `partition_entries_invalid` for that partition. Neither
Structural nor Full can report a structural pass for that partition. Full
may still evaluate later checks, but the aggregate Verification result fails.

## Full check details

### Filesystem-header hash

For each present partition, NSCB computes SHA-256 over the decrypted
filesystem header `0x400 + i * 0x200` through `0x600 + i * 0x200` and
compares it with the stored hash at `0x280 + i * 0x20`. A mismatch is
reported as `fs_header_hash_mismatch`.

### Fixed-key signature

The first `0x100` bytes of the decrypted header hold an RSA-2048 signature
over bytes `0x200` through `0x400`. Full verification checks that signature
with the caller-supplied trust anchor using RSA-PSS with SHA-256, MGF1-SHA-256,
and a 32-byte salt.

The anchor generation supplied with the request must equal the header
signature-key-generation byte at `0x221`. A mismatch is a prerequisite
mismatch: the check is recorded as `not_run` with reason
`trust_anchor_generation_mismatch`, the aggregate result fails, and the CLI
exits `3`. Only an executed RSA verification can produce
`signature_mismatch`.

### NPDM metadata

Full verification looks for exactly one top-level `main.npdm` member in
partition zero. Missing and duplicate members are distinct failures. The
member size must be at least the `0x80`-byte META header and at most 4 MiB.
NSCB validates the META magic, ACI0 and ACID offsets and sizes, both magic
values, non-overlapping regions, and every declared subrange before reading.
Malformed metadata is `npdm_malformed`.

The RSA modulus embedded in the ACID is treated as untrusted input. It is used
only to check whether the same key signed the header's second signature. NSCB
does not authenticate the NPDM, the ACID, the embedded key, or the chain that
produced them.

### NPDM-key signature consistency

The second `0x100` header signature at `0x100` through `0x200` covers the
same `0x200` through `0x400` header bytes. NSCB verifies it with the ACID
modulus using the same RSA-PSS parameters. A failure is
`npdm_key_signature_mismatch`. A pass means the embedded key and the header
agree; it does not establish that the key is trusted.

### Payload integrity

This slice has no supported partition hash layer. Hash type None stores no
payload-byte integrity information, so the payload check is
`not_applicable` with reason `hash_type_none` and the aggregate result may
still pass. Any other hash type is outside the supported profile and makes
the payload check `not_run` with reason `hash_type_unsupported`.

A Full pass therefore does not prove that payload bytes are unchanged. A
payload edit outside the filesystem header can pass every applicable check
when the partition declares hash type None. The result always includes the
`payload_integrity_not_available` limitation in that case.

## Trust anchor input

The trust anchor is a caller-supplied RSA public key. Accepted encodings are:

- PKCS#1 `RSAPublicKey` in PEM armor.
- SubjectPublicKeyInfo in PEM armor.
- PKCS#1 `RSAPublicKey` in DER.
- SubjectPublicKeyInfo in DER.

Parsing is strict. The key must be RSA-2048 with a 2048-bit modulus and
exponent `65537`. The anchor file must be a regular file no larger than
16 KiB. Private-key material, other key sizes, other exponents, trailing
garbage, and malformed encodings are rejected with
`trust_anchor_malformed` or `trust_anchor_limit_exceeded`. The accepted
encoding is reported in `trust_provenance.encoding`.

## Input identity, cancellation, and errors

Verification opens the input, key source, and trust anchor as regular files,
canonicalizes each resolved pathname, records the handle identity and file
snapshot, and confirms the initial pathname still refers to the opened handle.
Before returning a result it repeats the handle-identity, canonical-path,
caller-path resolution, and snapshot comparison for all three paths. Replacing
or retargeting a path and leaving the replacement in place produces
`input_changed_during_verification`,
`key_file_changed_during_verification`, or
`trust_anchor_changed_during_verification` and exit class `4`, even when the
replacement happens after the original inode has already been opened. A
replacement that is restored to the original identity before final
revalidation is not distinguishable by this metadata comparison.
Failure to establish a stable handle identity is a closed internal error.
Cancellation is checked before work begins, between major phases, and before
revalidation.

Error messages contain stable codes and localized text. Normal results and
errors omit input paths, key values, provider paths, and raw file content.

## Process exit classes

The CLI surface is:

```text
nscb verify <input> [--profile full|structural] [--keys <path>]
            [--trust-anchor <path> --anchor-generation <n>] [--json]
```

| Exit | Meaning |
| ---: | --- |
| 0 | Completed result with outcome `passed` |
| 2 | Usage or configuration error, including a trust anchor supplied to Structural |
| 3 | Completed result with outcome `failed`, or a prerequisite failure such as a missing key, generation, or trust anchor |
| 4 | Input, key source, or trust anchor changed during verification |
| 6 | Cancellation |
| 7 | Internal allocation, filesystem, or signal-registration failure |

Exit `8` is reserved for independent batch `CompletedWithIssues` reporting.
The single-input `verify` command never emits it. A failed signature or hash
is a completed verification result and exits `3`; it is not a usage error.

With `--json`, a completed result is one schema-version-1 document with
`kind: "verification.result"`, `nscb_version`, and `result`. A handled
failure before a completed result is one schema-version-1 error document with
`kind: "error"` and a sanitized stable error code. JSON output never contains
local paths or key material. Without `--json`, success and failure use
localized human-readable text.

## Cryptographic dependency

RSA-PSS verification uses the Rust `rsa` crate pinned at `0.9.10` with
SHA-2 support. The repository includes an RSA-PSS/SHA-256 known-answer test
derived from a NIST CAVP signature-verification vector. Signature generation
for synthetic fixtures exists only in test code and uses ephemeral,
test-only private keys.

`cargo audit` reports RUSTSEC-2023-0071 (CVE-2023-49092), a timing
side-channel in RSA private-key operations in the `rsa` crate. Production
Verification performs public-key operations only; it does not decrypt or
sign with private key material. The advisory remains relevant to the test
dependency path that generates synthetic signatures and would become
relevant if private-key operations were ever added to production code.

## Deliberate limitations

A passing Full result establishes only that the checks in this profile ran
and passed on the tested input bytes. It does not establish:

- Payload-byte integrity when the partition hash type is None.
- Authenticity of the NPDM, its ACID, or the embedded key chain.
- Nintendo content authenticity or certificate trust.
- Suitability or authorization for a device write.
- Support for RomFs, compressed, sparse, patched, or encrypted partitions.
- Support for NSP, XCI, or other container families.
- Support for hosts or content families outside the tested qualification.
