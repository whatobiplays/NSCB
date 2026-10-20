# Verification qualification evidence

## Scope

This document records the evidence for the native Rust Verification slice. It
separates what the tests actually establish from what they do not. The
synthetic profile is the only qualified Full Verification profile in this
slice.

The Verification operation does not launch NSTool or any other provider. The
Issue #7 Inspection qualification remains Inspection evidence and is not
reused as Verification evidence.

## Synthetic fixtures and provenance

Every Verification fixture is generated in memory at test runtime by
`tests/support/synthetic_verification.rs`. The fixture contains:

- A synthetic NCA3 header encrypted with a fixed, non-secret AES key
  `[0x42; 32]`. This key is a test value and is not a Nintendo credential.
- One through four PartitionFs partitions. The primary partition contains the
  synthetic `main.npdm` and a `main` member; each additional partition
  contains one synthetic member.
- A synthetic META/ACI0/ACID chain with a runtime-generated RSA modulus.
- RSA-2048 key pairs generated on first use for the header signature and the
  ACID key.

No Nintendo key, ticket, firmware image, certificate, game byte, or other
proprietary content is stored in the repository or produced by the tests.
Private keys exist only in test process memory. The CLI accepts only a public
trust anchor.

The test fixture writes `1` in descriptor byte `0x8`, following the
hacPack-family convention. The shared parser accepts `0` or `1` and
requires the remaining seven bytes to be zero. See
[Verification architecture](../architecture/verification.md#shared-nca-validation)
for the primary format references.

## RSA-PSS known-answer evidence

`tests/verification.rs` embeds a public RSA key, message, and signature from
the NIST CAVP PSS signature-verification set. The test asserts that the
embedded `rsa` version accepts the vector with SHA-256 and MGF1-SHA-256. The
source archive used during development was:

```text
file: pss.zip
SHA-256: 8405aeb3572a4f98ed4b1a3ccb3f2f49e725462dd28ec4759d6a15d88855d19c
record: SigVerPSS_186-3.rsp, Msg at line 962
```

Only the public verification material is retained in the repository. The
archive and its private-key material are not committed. The vector uses an
RSA exponent other than 65537; the trust-anchor input validation still
requires exponent 65537 for supplied anchors, and the known-answer test
exercises the primitive independently of that input policy.

## Coverage

| Area | Evidence |
| --- | --- |
| Structural profile | Four checks in stable order; no signature or hash entries |
| Full profile | Nine checks in stable order; every applicable check completed |
| Partition count | One, two, three, and four supported PFS0 partitions pass per-partition filesystem, entry, and FS-header checks |
| Partition layout | A zero-length declared partition span fails the layout check with `partition_layout_invalid` |
| Descriptor bytes | `0` and `1` accepted; `2` and non-zero reserved bytes rejected |
| Distribution | Game Card (`1`) and Download (`0`) both pass the Full profile |
| Key encodings | PKCS#1 PEM/DER and SubjectPublicKeyInfo PEM/DER accepted |
| Anchor validation | 1024-bit key, exponent 3, garbage, and 17 KiB file rejected |
| Anchor source | A missing anchor path reports `trust_anchor_unavailable` and exits 3 |
| Anchor generation | Mismatch records signature `not_run` and exits 3 |
| Executed signature failure | `signature_mismatch` only after RSA verification runs |
| Filesystem hash | Stored-hash corruption reported as `fs_header_hash_mismatch` |
| NPDM metadata | Missing, duplicate, malformed size, and wrong ACID key distinct |
| NPDM bounds | Private parser tests cover oversized length, bad magic, overlap, size mismatch, and subrange overflow |
| Partition entries | Corrupt PFS0 magic, oversized count, duplicate normalized names, traversal names, regular-file/directory hierarchy conflicts in either insertion order, malformed path relationships, and post-signing hash-None metadata changes fail closed |
| Partition budgets | Cumulative name and path byte budgets are enforced across partitions; the global entry budget is exercised within one partition |
| Key sources | Missing, malformed, missing alias, oversized, and directory paths typed |
| Key generation | `0x00` and `0x20` pass the Full profile; `0x21` fails the header profile before layout checks |
| Hash profile | Raw `2` reports partition filesystem unsupported and payload integrity not run |
| Payload limitation | A modified payload byte and changed unprotected PFS0 metadata still leave the header hash and signatures valid when hash type is None; the metadata change is rejected only by structural entry validation |
| Input identity | Private tests prove in-place mutation, rename replacement, Unix symlink substitution, and Unix symlink retargeting conflict codes for input, key source, and trust anchor; integration tests assert original input and key bytes are unchanged |
| Cancellation | A pre-cancelled request and cancellation after all three handles open return `cancelled` with exit class 6 and no result |
| Provider independence | Public Engine tests leave an empty provider cache untouched; the CLI passes with a fake NSTool first on PATH and never launches it |
| Redaction | Error and result JSON omit local paths and key material |
| Exit classes | Unit test covers every error code; CLI tests assert usage 2, failure 3, and no exit 8; a CLI renderer test covers conflict 4, cancellation 6, and internal 7 |

Focused results from the post-PR #59 forward-port worktree (2026-10-19):

```text
cargo test --locked --lib partition_fs
  4 passed

cargo test --locked --lib verification::tests
  6 passed

cargo test --locked --lib inspection::tests
  6 passed

cargo test --locked --test verification
  28 passed

cargo test --locked --test verification_cli
  17 passed

cargo test --locked --lib nca
  22 passed
```

The same focused suites and the full `make all` gate passed in the
forward-port worktree. The all-features library suite reported 216 passed
and 4 ignored (manual provider checks and subprocess workers); the binary
suite reported 33 passed.

Corrective requalification on 2026-10-19 added hierarchy-conflict,
payload-byte, distribution-boundary, key-generation-boundary, and
symlink-retarget regressions to the same worktree:

```text
cargo test --locked --lib partition_fs
  9 passed

cargo test --locked --lib verification::tests
  8 passed

cargo test --locked --lib inspection::tests
  6 passed

cargo test --locked --test verification
  31 passed

cargo test --locked --test verification_cli
  17 passed

cargo test --locked --lib nca
  22 passed
```

The full `make all` gate passed with 223 library tests passed and 4
ignored; the binary suite reported 33 passed. The separate
`make test-content-policy-git` suite passed 12 tests.

## Local review dispositions

A local Cubic review reported two findings. Both were evaluated against the
repository contracts and were not accepted as implementation defects.

1. The review suggested Full verification should reject inputs with more than
   one PartitionFs partition. The shared Inspection profile documented in
   [NSTool v1.9.2 provider qualification](../providers/nstool-v1.9.2.md)
   supports one through four partitions, and the structural header parser
   already rejects empty or gapped layouts. Verification evaluates every
   present partition independently. The synthetic test exercises one through
   four partitions and substantiates that behavior.
2. The review suggested a missing default key path should use a key-source
   prerequisite error instead of `invalid_key_path`. The resolver returns
   `invalid_key_path` only when no explicit path, configured path, or home
   directory exists, which is a host configuration failure and matches the
   existing Inspection exit class. A resolved path that does not exist still
   fails later as `key_file_unavailable` and exits 3.

Both dispositions were rechecked against the post-PR #59 source. The
one-through-four partition test now substantiates the first disposition, and
the resolver behavior in `src/cli.rs` and `src/provider/mod.rs` still
substantiates the second.

## Native Inspection regression

The shared NCA parser changed descriptor handling, so the native Issue #7
Inspection qualification was rerun on 2026-10-18 from the Issue #8
implementation worktree. The worktree base commit is
`f82391a72e4a751c444fab8b2cbc845c06a812d6` with the uncommitted Issue #8
changes applied. The host was macOS 27 arm64 with Rust 1.99.0.

The evidence directory is
`/private/tmp/nscb-issue8-native-inspection-qualification/`. It is outside
the repository and contains only synthetic fixtures, logs, and public
artifact hashes.

The existing synthetic input (3,584 bytes, SHA-256
`9b6670151efff00f4e54b24872de57914d48cc8d389b7dfc7e277dc29fad7538`)
and key file (82 bytes, SHA-256
`8b5ac5df58721de3fb4bff9a4cf32e8bc1cbda1780f545f4c723f51ce26f8895`)
were unchanged before and after the run.

A fresh managed cache first exercised the cache-only and managed-preflight
paths:

```text
cache_only_preflight_before_provisioning_error=provider_cache_missing
managed_preflight_before_provisioning=ProvisioningRequired
memory_monitoring_status=Unavailable { threshold_bytes: 1073741824 }
```

Managed Engine inspection then downloaded the pinned artifact. The cached
executable is 5,946,680 bytes with SHA-256
`381343160daea53ae70205885bb111518643571c971aef3c695dc1a63aa2343e`,
matching the provider manifest. The Engine reported NCA3, game-card
distribution, Program content, key generation 8, signature generation 5,
program ID `0102030405060708`, and one 512-byte PartitionFs partition at
offset `0xc00` containing `hello.nca` (4 bytes). Cache-only preflight then
returned `Ready`, and a second cache-only inspection returned the same facts.

The CLI exercised the same cache without downloading:

| Mode | Exit | Output |
| --- | ---: | --- |
| `--preflight --json` | 0 | `inspection.preflight` with result `ready` |
| `--preflight` | 0 | `NSTool v1.9.2 is ready for NCA inspection.` |
| `--json` | 0 | `inspection.result` with the facts above |
| human | 0 | NCA3 Program, program ID, generations, and `hello.nca` |

This rerun shows that the descriptor correction preserves the previously
qualified Inspection behavior for the synthetic fixture. It does not extend
Inspection to Verification, qualify another host, or qualify another content
family. The synthetic Full profile remains the only qualified Verification
profile.

### Corrective shared PartitionFs validation rerun

After Inspection and Verification were changed to share the bounded
PartitionFs name, duplicate, path-relationship, and budget validator, the
native Issue #7 Inspection qualification was repeated on 2026-10-19 from the
same synthetic input and key file. The preserved historical evidence root
remains `/private/tmp/nscb-issue8-native-inspection-qualification/`; the
corrective evidence root is
`/private/tmp/nscb-issue8-corrective-native-inspection-qualification/`.

The synthetic input and key hashes remained unchanged:

```text
input 9b6670151efff00f4e54b24872de57914d48cc8d389b7dfc7e277dc29fad7538
key   8b5ac5df58721de3fb4bff9a4cf32e8bc1cbda1780f545f4c723f51ce26f8895
```

The fresh managed cache downloaded the pinned NSTool executable (5,946,680
bytes, SHA-256
`381343160daea53ae70205885bb111518643571c971aef3c695dc1a63aa2343e`). The
cache-only preflight failed closed as `provider_cache_missing`, managed
preflight reported `ProvisioningRequired`, and the managed and subsequent
cache-only Engine inspections returned identical expected NCA3 Program facts.
All four CLI modes (preflight JSON/human and inspection JSON/human) exited
`0`; their stderr files were empty.

## Limitations

A passing Full result on these fixtures does not establish:

- Payload-byte integrity when the partition hash type is None. The modified
  payload test demonstrates that a Full pass can coexist with changed payload
  bytes.
- Authenticity of the NPDM, ACI0, ACID, or the embedded RSA key.
- Nintendo content authenticity or trust in any Nintendo certificate.
- Authorization or safety for a device write.
- Support for hash type HierarchicalSha256 or any other hash layer.
- Support for RomFs, compressed, sparse, patched, or encrypted partitions.
- Support for NSP, XCI, or other container families.
- Qualification on hosts or inputs outside the tested environment.

The production cryptographic path receives a public key and executes RSA-PSS
verification. RUSTSEC-2023-0071 applies to private-key RSA operations; the
production path does not perform them. Test-only signing uses ephemeral
private keys. See
[third-party dependency assessment](../research/third-party-dependency-assessment.md#rust-cryptographic-dependency).
