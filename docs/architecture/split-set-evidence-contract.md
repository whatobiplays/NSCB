# Split-set evidence contract (accepted v1 architecture)

**Status:** Accepted architecture under ADR 0028. Issue #6 implements read-only canonical resolution, the local receipt lookup contract, and a test-only source-backed issuance seam. Production source-to-Split publication and user-facing issuance remain future work; the wire protocol is not released.

**Authority:** Accepted ADR 0028, interpreted with ADRs 0007, 0008, 0010, 0011, 0013, 0022, 0023, 0025, 0026, and 0027.

**Origin:** Decisions 1-46 from the NSCB Split-set contract review.

**Scope:** Canonical FAT32-style numbered directory and local, source-backed evidence; no keys, Nintendo certificates, title interpretation, or third-party content authenticity claims.

## 1. Vocabulary and proof claims

- **Logical byte stream:** An ordered, exact byte sequence and length reconstructed from one or more physical segments. It may be arbitrary file content.
- **Generic byte-stream splitting:** A byte-preserving filesystem operation that divides any explicitly selected regular file into ordered segments without requiring Content Recognition. It establishes no Nintendo Content identity, authenticity, Verification, or package-operation eligibility.
- **Container-aware Content splitting:** A Content transformation that splits supported package or container input, or input selected through an extracted-content manifest, under ADR 0022's eligibility rules. A standalone loose NCA remains ineligible.
- **Split-layout identification:** The representation grammar that discovers possible ordered segments. It does not establish completeness.
- **Split-set completeness evidence:** An expectation of the exact original byte length and SHA-256 recorded from an observed single-file source *independently of the surviving output segments* during an authorized NSCB Split operation.
- **Manifest:** A versioned, unsigned sidecar declaring expected logical bytes and each ordered segment. It supplies consistency data, not independent trust.
- **Local trust receipt:** Host-retained, durable evidence binding the precise manifest bytes to the source evidence established during a completed, source-backed Split operation. This is local application trust within an accidental-corruption model, not cryptographic proof of origin.
- **Qualified Split set:** A recognized canonical layout whose complete segment sequence, sizes, SHA-256 hashes, whole-stream SHA-256, manifest, and unrevoked local trust receipt all agree at resolution time.

A qualified Split set **does not** imply that the source was Nintendo Switch Content, that its source was genuine or complete relative to any upstream producer, or that Content Verification has passed. In particular, a source file which was already truncated before NSCB observed it can be reproduced exactly without establishing historical upstream completeness.

These operations have distinct eligibility rules: Q37 ([accepted decision ledger](../research/split-set-contract-decisions-01-46.md)) permits generic byte-stream splitting of any explicitly selected regular file, including a loose NCA, while ADR 0022 continues to restrict container-aware Content splitting to supported package/container inputs or input selected through an extracted-content manifest. Generic splitting does not change eligibility for any Content operation.

Only a qualified logical byte stream may be returned as a successful Split `ResolvedInput`. Untrusted candidate sets may be described diagnostically but must never become successful provisional inputs.

## 2. Canonical representation and discovery

Example:

```text
Game.nsp.nscb-split.json
Game.nsp/
    00
    01
    02
    .DS_Store
```

- The numbered members are exactly the ASCII two-character basenames `00`, `01`, ..., at most `99`, with a contiguous zero-based sequence. One member `00` is permitted.
- Numeric entries outside the declared contiguous sequence (including `03`) and other recognizable competing Split members must cause an ambiguity/incomplete-set error, even when declared members validate. Unrelated files such as `.DS_Store` may be ignored; no broad deletion or interpretation of unrelated data is allowed.
- Segments are physical regular files, with unique filesystem identities where the platform can establish them; segment symlinks, reparse-point aliases, duplicate hardlinks, devices, FIFOs, and other special files are not permitted. The source path may be a regular file selected through the existing explicit-file policy.
- Selecting the directory or any recognized numbered member discovers the adjacent sidecar by deterministic sibling derivation (`<directory-name>.nscb-split.json`). No directory-wide sidecar scanning, implicit network lookup, or heuristic fallback.
- An explicitly selected symlink to the *directory* may be resolved only under the current directory-root symlink policy. Sidecar discovery uses the canonical/real directory's parent, not the alias parent. Individual numbered member symlinks remain rejected.
- On compatible FAT32 hosts, the archive/ConcatenationFile attribute is a representation/interoperability concern, not the proof of completeness. Attribute loss on another filesystem must not be mistaken for manifest or receipt evidence; exported Switch-facing layout compatibility needs separate qualification.
- Relative manifest member identifiers are limited to validated segment basenames, not directory paths. Any path separator, drive prefix, `.`/`..`, Unicode-lookalike number, non-ASCII numeric form, absolute path, duplicate key, or duplicate normalized identity is invalid.
- Directory expansion collapses the complete set into one logical input at its sorted discovery position. Qualified canonical Split directory candidates may have arbitrary source basenames (for example `backup.zip/`) and must be eligible for bounded discovery independently of the existing *single-file* Nintendo Content extension filter, using precise canonical-segment and sibling-manifest evidence rather than arbitrary recursive directory probing. Independent overlapping selections are duplicate logical identities and fail under the existing resolution rules, preserving explicit argument/list order and prior path normalization.

## 3. Manifest format

Suggested independent wire identity:

```json
{
  "schema_version": 1,
  "kind": "nscb.split_manifest",
  "required_features": [],
  "source": {
    "size_bytes": 1234567890,
    "sha256": "<64-lowercase-hex-characters>"
  },
  "segments": [
    {"name": "00", "size_bytes": 1073741824, "sha256": "<64-lowercase-hex-characters>"},
    {"name": "01", "size_bytes": 160826066, "sha256": "<64-lowercase-hex-characters>"}
  ]
}
```

Values above are schematic placeholders, **not** a valid manifest fixture. Exact decimal sizes are nonnegative integers representable as `u64`. `source.size_bytes` must be exactly the checked sum of the ordered segment sizes. `source.sha256` and each part's digest are SHA-256 digests of the actual source/reconstructed bytes, not content-derived metadata or signatures.

Contract rules:

1. Required keys: `schema_version`, `kind`, `required_features`, `source`, `segments`. The nested fields above are required. `segments` has 1-100 entries and must describe exactly `00` through `count-1`. Every entry's filename is immutable within the manifest. Unknown optional extension keys may be ignored; unknown *required* features and unsupported versions fail closed.
2. Top-level and nested duplicate JSON keys, floats for sizes, negative values, Unicode-normalization tricks, invalid SHA-256 spelling, malformed UTF-8, and unsafe paths fail. No semantically ambiguous duplicate fields are tolerated.
3. Bound manifest size to **256 KiB**, with bounded JSON nesting/collections and work limits; the exact implementation also observes the request's existing discovery budgets. Exceeding bounds is a typed limit failure, never success.
4. Canonical v1 writer uses a deterministic default part size of `0xFFFF0000` (4,294,901,760) bytes, a value documented by upstream FAT32 concatenation implementations. Smaller requested sizes are supported only after explicit canonical-consumer interoperability qualification, and every selected size must obey the target FAT32 maximum and 100-part cap. Unsupported combinations fail during planning, never by producing a subtly noncanonical output.
5. All nonfinal parts of a nonempty source use the chosen part size; the final part contains the remaining 1..part-size bytes. A zero-length source yields a single `00` of length 0 only if that exact representation passes the interoperability qualification; otherwise reject it explicitly as unsupported. Do not silently create zero-length terminal padding segments.
6. No absolute paths, receipt identifiers, timestamps, original source filename, producing-host identity, or content recognition facts are required in the manifest. Optional descriptive fields may be added compatibly without becoming proof evidence. The manifest's **exact published UTF-8 bytes**, including optional fields and JSON formatting, are committed by the trust receipt; editing any byte invalidates that receipt, even when semantic data appears equivalent.
7. The manifest is not a replacement for the versioned `nscb.input_list` schema. It cannot select operations, authorize writes, override policy, or serve as an executable Operation Plan.

## 4. Local receipt and trust lifecycle

A host-supplied explicit trust-store capability provides atomic lookup, issue, revoke, and durable-commit operations. Standalone NSCB supplies its own versioned local durable implementation; embedded hosts provide a compatible capability without inheriting standalone configuration or storage. The Engine must remain runtime-neutral; callers who omit a provider may continue using the existing non-Split resolver but cannot successfully resolve a Split set.

Receipt identity is the SHA-256 of the **exact manifest bytes** together with source size/hash evidence independently recorded during the producing Split operation. A host may store a stable versioned receipt containing `manifest_sha256`, `source.size_bytes`, `source.sha256`, an issuance-completion marker, and revocation state. Absolute paths and filesystem identities are not trust anchors. Identical copies of the same manifest and segments on the same host share a receipt; renaming/relocating the directory and corresponding sidecar leaves trust intact.

- Never issue a receipt by hashing preexisting arbitrary parts or copying information from an unsigned sidecar alone. Only an NSCB-authorized original-source-backed Split operation can issue it.
- Revocation is **per exact manifest identity** and affects all byte-identical copies. Distinct segmentation/manifests of the same source have separate receipt identities. Revoked evidence cannot be resurrected from the sidecar; the user can explicitly perform a new source-backed operation to establish new evidence.
- Do not automatically delete receipts because a directory is moved, deleted, unmounted, off-line, unavailable, or an external drive is detached. Explicit revocation is the authority.
- Missing receipt, mismatched receipt, revoked receipt, missing source-evidence commitment, unavailable trust-store data, and corrupt state all fail closed. Restoration of an independently trusted backup of the **same host-owned evidence store** is allowed with versioned transactional migration; simply copying a receipt to another machine is not a v1 trust-transfer mechanism.
- The original source is not required for future resolution once the qualified receipt is durably committed. If the original and independent trust store are both lost, the sidecar and segments alone cannot re-create qualification.
- The threat model detects accidental loss or corruption, not intentional host-state forgery. Do not present a local receipt as a digitally authenticated origin certificate.

## 5. Source-backed issuance and publication

For the user-facing producer, a reviewed Operation Plan must resolve an explicit source, destination, segment-size/interoperability profile, conflict policy, resource requirements, and host store capability. The operation does not modify its original source.

1. Establish a read-only opened regular-file identity for the source, obtain its length, and SHA-256 its exact bytes; reject unreadable/unstable inputs. Do not infer Nintendo content identity.
2. Acquire *destination-scoped* exclusive publication coordination (not a machine-wide Engine lock). Create a durable ownership record **before** creating artifacts, with exact artifact names, locations, identity and versioned run state. Existing destination data is never overwritten without the governed conflict decision.
3. Write parts into isolated staging on the destination filesystem where possible. Stream with bounded memory; compute per-part and whole-file hashes; honor cancellation until the final publication critical section. Never expose any partial output as successfully qualified.
4. Re-read and hash the resulting output parts, reconstruct whole-stream SHA-256 and length, and compare against the independently observed source evidence. Revalidate source identity/content through the retained opened handle before publishing. Changed source, short write, missing member, alias or checksum mismatch aborts without issuance.
5. Durably finalize the sidecar and coordinated output publication as a coherent unit where possible. Atomic moves and fsync/durability semantics must be specified per supported platform. A committed local receipt is the **last qualification step**; successful outcome is reported only after durable evidence and qualified output are both present.
6. If cancellation was accepted before receipt commit, no successful qualification is recorded and ownership-safe cleanup applies. Cancellation after durable commit cannot undo or misreport the completed result. Conflicting concurrent actors are handled by exclusive/atomic destination logic with last-moment revalidation; no last-writer-wins behavior.

**Interrupted output cleanup:** Q30 permits automatic cleanup of an uncommitted provisional output if the durable ownership journal proves each artifact is unchanged and was created by NSCB. Cleanup does not issue trust, resurrect a receipt, delete unrelated added files, recursively remove arbitrary user directories, or remove completed published user data. If artifact identity/ownership cannot be proved, preserve it and record an actionable failure. This is a narrow explicit qualification to ADR 0013's general rule against pruning published user data; the latter remains intact for committed results. No durable recovery mechanism may promote orphaned sidecars to trust.

**Already up to date:** A candidate existing destination may be reported as already up to date only when its exact expected manifest, source/part hashes, unrevoked trust receipt, and destination policy all positively qualify. Merely matching an existing directory or sidecar cannot authorize retroactive receipt issuance. Source and destination collisions remain explicit.

## 6. Resolution, execution, progress and cancellation

- On `Engine::resolve_inputs`, first locate the canonical directory and sidecar, validate grammar/schema, retrieve an unrevoked receipt, enumerate expected segments, verify membership and unique physical identities, then stream all segment bytes once while calculating individual SHA-256 and the whole-file SHA-256. Check aggregate size and exact expected digest. Fail on cancellation, I/O error, mismatch, unexpected competing part or suspected source mutation.
- A successful response remains one logical input with ordered `segments`, original selection `provenance`, and an additive typed evidence description such as `qualification: { kind: "local_split_receipt", manifest_schema_version: 1, original_size_bytes: ..., original_sha256: ... }`. That metadata means **Split completeness evidence** only; it grants no Content Verification, authenticity, or executable Plan authorization.
- Existing single regular files retain the existing success and output semantics, with no synthetic Split qualification requirement. Previously supported Rust builders/constructors and JSON version-1 fields remain compatible; additive fields may be introduced where the stable 1.x surface permits them.
- Large hashing operations use bounded buffers, host-provided progress/cancellation, and aggregate request budgets; never concatenate a giant intermediate file simply to recognize segments. Progress conforms to ADR 0011's latest-value state and semantic events; `--json` produces exactly one versioned document on stdout with all progress on stderr or other explicitly separate channel.
- A successfully resolved path is not an indefinitely valid execution handle. On execution, revalidate membership, opened identities, trust, hashes, and extent. Detect mutation while consuming bytes; read-only operations may complete only after validating bytes actually consumed. For irreversible or externally visible side effects, require an isolated verified snapshot or other proven stable mechanism before effectful publication. Do not claim that pinned handles alone make mutable files immutable.
- The internal virtual reader maps checked, monotonically increasing logical offsets to verified individual regular-file handles; `Read + Seek` must reject overflow, out-of-bounds, short read, aliases, and source replacement. Qualification of real handles, platform confinement, mutation, and parser integration is mandatory before activation.

## 7. Typed failures and machine output

All normal structured outputs obey ADR 0023's `schema_version`/`kind`; original input-list parsing/semantics remain unchanged. New stable codes must be defined additively and never repurposed. Suggested code families (final spelling fixed before release):

| Code | Meaning | Exit class |
| --- | --- | --- |
| `split_manifest_missing` | Canonical candidate lacks expected sidecar | 3 prerequisite/input |
| `split_evidence_untrusted` | Receipt missing, revoked, or not binding current exact manifest | 3 prerequisite/input |
| `split_manifest_invalid` | Malformed/unsafe/inconsistent manifest | 3 prerequisite/input |
| `split_manifest_version_unsupported` | Unsupported schema/version/required feature | 3 prerequisite/input (usage/configuration errors remain 2 where applicable) |
| `split_set_incomplete` | Declared segment absent, invalid numbering or conflicting extra Split-like member | 3 prerequisite/input |
| `split_integrity_mismatch` | Segment or reconstructed whole-stream digest/length mismatch | 3 prerequisite/input |
| `split_input_changed` | Input mutation observed before or during validation/use | 3 prerequisite/input |
| `split_state_unavailable` | Required host evidence store cannot be read or committed due to internal state failure | 7 internal failure |

An output destination conflict uses existing class **4**, cancellation/interruption class **6**, and resource/internal errors existing class **7** where classified as internal. Incorrect invocation/configuration uses class **2**. Preserve established code `unsupported_split_layout` for unqualified legacy and unrecognized representations; do not repurpose it to mean a trusted canonical set with a missing sidecar. Normalize and sanitize messages via the existing host localization boundary.

## 8. Implementation sequencing and migration

- **Issue #6:** Land additive source-evidence model, receipt interface, manifest parser, qualified canonical resolver, virtual-reader qualification, CLI/Rust error and JSON shape, and synthetic tests backed by trusted fixtures *derived from original unsplit test sources*. Test fixtures are not a production API for certifying imported parts. Do not require Issue #14's user-facing writer to implement or test the resolver.
- **Issue #9:** Reuse the evidence/publication seam inside immutable Plans, staged publication, and host-managed progress/cancellation/recovery.
- **Issue #14:** Implement full source-to-Split producer, local receipt issuance, canonical FAT32 archive-attribute interoperability and conflict policy. Keep legacy output layouts opt-in and blocked until independent evidence qualification; do not silently weaken Issue #14's remaining legacy acceptance work.
- Update ADR 0013 with only the explicit distinction between *uncommitted ownership-tracked provisional artifacts* and committed *published user data*, reflecting Decisions 30/32. Preserve all other user-data protections.
- ADR 0028 is accepted as architecture; do not mark Issue #6 complete merely because the design has been accepted. Production activation requires the [Split-set contract acceptance scenarios](../testing/split-set-contract-acceptance.md) to pass under each supported OS/filesystem profile.

## 9. Non-goals

No key extraction, title rights changes, device installation, embedded content authenticity claims, accepted unsigned cross-host manifests, signature/key management, legacy `.xcN`/`.nsN` positive resolution, speculative XCI-header terminal proof, restoration from surviving parts without original source evidence, background persistent qualification Job on every read-only resolution, automatic source deletion, or hidden mutable global Engine state.
