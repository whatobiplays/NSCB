# Split-set evidence contract (accepted v1 architecture)

**Status:** Accepted architecture under ADR 0028. Issue #6 implements read-only canonical resolution, the local receipt lookup contract, and a test-only source-backed issuance seam. Issue #14 adds a source-backed producer and user-facing command. Native tests exercise local APFS directory publication; other OS/filesystem combinations, FAT32 archive attributes, canonical-consumer interoperability, and legacy layouts remain unqualified. The wire protocol is not released.

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
- A producer request names the **outer bundle directory**. The bundle contains an inner canonical Split directory named after the selected source and a sibling manifest inside the bundle: `<bundle>/<source-name>/00...` and `<bundle>/<source-name>.nscb-split.json`. Typed and JSON results return both the outer bundle path and inner canonical directory path. Resolution accepts the returned canonical directory or a numbered member; it does not discover or unwrap a parent bundle.
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
Planning hashes the source in bounded chunks. `Engine::plan_split_with_cancellation` honors caller cancellation between chunks and returns a typed cancellation failure before destination mutation. Execution progress and cancellation remain owned by the shared Operation Session.
2. Acquire stable, *destination-scoped* exclusive publication coordination. A destination-specific lock serializes cooperating NSCB writers targeting the same destination. Validate its identity and the destination-parent route before publication decisions. This coordination does not exclude uncoordinated external writers. Before creating any artifacts, durably record the exact planned artifact names and locations, parent identity, and versioned recovery state. Existing-destination Replace is unsupported as a publication operation. If an occupied destination satisfies the qualified AlreadyUpToDate predicate, return AlreadyUpToDate without staging or mutation; otherwise fail planning before staging or mutation. Keep the public policy variant, but do not publish by replacing an existing destination.
3. Write parts into isolated staging on the destination filesystem where possible. Stream with bounded memory; compute per-part and whole-file hashes; honor cancellation until the final publication critical section. Never expose any partial output as successfully qualified.
4. Re-read and hash the resulting output parts, reconstruct whole-stream SHA-256 and length, and compare against the independently observed source evidence. Poll cancellation during each bounded source-validation, part-readback, and reconstruction chunk until publication begins. Revalidate source identity/content through the retained opened handle before publishing. Changed source, short write, missing member, alias or checksum mismatch aborts without issuance.
5. Durably finalize the sidecar and coordinated output publication as a coherent unit where possible. Specify atomic-move and fsync durability semantics for each supported platform. A committed local receipt is the last qualification step; report success only after durable evidence and qualified output are both present.
6. If cancellation is accepted before receipt commit, do not record successful qualification. The 2026-11-03 preservation-only slice retains provisional artifacts and recovery inventory. In the current candidate, cleanup may remove provisional output only after durable ownership evidence and an exact-manifest lease prove that no receipt was ever committed; absent, ambiguous, or unavailable receipt state retains it. An accepted cancellation stops cleanup and retains its journal and artifacts for recovery. Cancellation is refused once promotion begins. An interruption after commit preserves the committed bundle and reconciles the journal on recovery. Destination-scoped coordination serializes cooperating NSCB writers only; it does not make uncoordinated external writes safe or provide last-writer-wins behavior.

**Historical cleanup decision and approved sequencing amendment:** Q30 and Q32 retain the original decisions recorded in the research decision ledger. Automatic cleanup is permitted only for uncommitted artifacts with durably established, verified ownership; completed user data and unknown or modified artifacts must not be pruned; a crash must not issue trust automatically. The 2026-11-03 acceptance slice required durable recovery inventory and non-destructive retention, then deferred positive reclamation to a separate qualification task. The current candidate implements that separately scoped work. Neither the original rationale nor the historical TAC-7 run record is changed by the candidate.

Current interrupted-output policy: Record exact planned artifact names and parent identity before creation. After creation, durably record each verified artifact identity and the content or metadata evidence needed for later recovery. A crash between artifact creation and identity recording leaves ownership ambiguous. Preserve ambiguous, changed, unknown, or possibly committed artifacts and retain the recovery inventory. Missing, malformed, torn, or inconsistent journals cannot authorize deletion. Recovery must establish the receipt state for the exact manifest before deciding the transaction outcome, preserve any confirmed committed output, and never issue trust retroactively for orphaned parts. The historical preservation-only candidate performed no deletion, including for apparently clean provisional artifacts. The current candidate allows cleanup only when an exact-manifest lease and complete ownership proof both authorize it.

**Reclamation requirements:** The candidate qualification uses an identity-bound removal mechanism within an owner-only private namespace. It states its filesystem and writer assumptions and preserves artifacts if path displacement or ownership cannot be resolved; directory permissions, a destination lock, or a prior inode check alone do not establish race-free removal. Receipt issuance and cleanup for one exact manifest digest acquire the same manifest-scoped serialization primitive. Receipt issuance holds it through durable receipt commit and the journal's committed/completed transition. Cleanup holds it from its final receipt lookup through the durable cleanup intent, identity-bound removals, and terminal journal transition; it may proceed only when the receipt is confirmed never committed and the transaction is uncommitted. An active receipt, an unavailable lookup, or any uncertain commit state requires preservation. After a crash, recovery reacquires the same primitive and reconciles the durable journal and receipt before continuing; it never issues trust from orphaned parts or retroactively after cleanup. Qualification must prove preservation of committed, modified, unknown, or externally substituted data.

The current local implementation acquires the trust store's existing cross-process `.lock` with cancellation-aware nonblocking retries. It recovers pending store transactions and validates both authoritative indexes and the exact receipt file before granting a lease. The lease stays held through cleanup and the terminal journal update. Writers that inherit the default `Ok(None)` lease keep their artifacts. Lock order is the destination lock directly under `.nscb-split-locks`, the receipt-state lock under `.nscb-split-locks/.receipt-state-locks`, then the host trust-store lock. Source and destination basenames that case or Unicode normalization can resolve to `.nscb-split-locks` or `.nscb-operation-directory.lock` are rejected before lock setup. Destination basenames that resolve to `.receipt-state-locks` are rejected before marker creation, including case and normalization aliases recognized by the volume. The receipt-state lock file remains in its private child directory. Store issue, revoke, and restore do not acquire Split locks, and cleanup calls no other trust-store method while holding the lease.

Artifact ownership is established separately from receipt state. The journal records planned names and parent identity before creation, then records each artifact's identity and verified content as soon as those facts are safe to establish. Cleanup uses descriptor-relative operations to move verified artifacts into an owner-only quarantine with exclusive same-volume renames. It checks identity and digest again there before removal. Cleanup hashes check cancellation between bounded reads; cancellation preserves artifacts that have not passed final ownership checks and releases the held locks as cleanup returns. A failed or incomplete check retains the artifact and journal. This coordination covers cooperating NSCB destination operations on the qualified local APFS path. Uncoordinated external writers, including same-user processes that can bypass directory permissions, remain outside the guarantee; when displacement is observed and final state is uncertain, cleanup retains the evidence.

**Already up to date:** A candidate existing destination may be reported as already up to date only when its exact expected manifest, source/part hashes, unrevoked trust receipt, and destination policy all positively qualify. Merely matching an existing directory or sidecar cannot authorize retroactive receipt issuance. Source and destination collisions remain explicit.

For producer execution, the active receipt, exact planned source length and SHA-256, intended segment lengths and membership, manifest bytes, and selected destination policy must all match. A different but otherwise valid Split set is a destination conflict or an explicit skip; it is not already up to date.

**Durable transaction record:** The append-only ownership journal records prepared, staging, verified, publishing, published, receipt_commit_started, receipt_committed, completed, rolled_back, cleanup_complete, and uncertain. Artifact entries move from planned to created and, for verified files, to verified. The historical preservation-only implementation recorded cleanup_complete only when the destination parent had no staging root and the journal had no verified root identity. In the current candidate, cleanup first writes a durable cleaning intent with the private quarantine name and parent identity. It then moves each fully evidenced artifact by a descriptor-relative exclusive rename, rechecks identity and digest in quarantine, and removes it only after those checks pass. Recovery reacquires the exact-manifest lease and resumes or retains the artifacts according to their recorded evidence. If an artifact or its state is unproven, cleanup fails closed and retains the artifact and journal. Receipt state is reported as not attempted, confirmed uncommitted, confirmed committed, or uncertain. If the receipt writer returns an error after a possible commit, the producer checks durable evidence for the exact manifest receipt before deciding transaction status; uncertainty preserves the published bundle and recovery evidence. Restart recovery may restore only the recorded, unchanged, previously qualified destination; it never issues a receipt for orphaned parts. Rollback and recovery remove artifacts only when the exact-manifest lease and unchanged ownership evidence permit it; otherwise they retain the artifacts and journal.

**Terminal OperationResult inventory:** A Split result reports journal-backed artifact records alongside observations from the current filesystem. It keeps recorded identity and content evidence separate from current path identity and content, and reports parent identity and artifact relationships. Missing journal fields, paths without a recorded artifact, and changed or substituted entries remain uncertain; a path or matching name alone does not prove operation ownership. Published versus uncertain state and retained versus removed state follow the durable journal and verified current observation. Retained storage totals include known retained bytes beyond a positively verified published destination and count a filesystem identity once, even when multiple paths alias it. The total is unknown when retained data lacks enough identity or size evidence. A result must not invent identity, digest, ownership, publication success, or complete evidence.

**Platform publication:** The current producer requires a destination volume that passes the local APFS capability checks. New bundles use Darwin renameatx_np(RENAME_EXCL). Existing-destination replacement is unsupported. A Replace request for an occupied destination that does not satisfy the qualified AlreadyUpToDate predicate fails before staging or mutation. A destination with an exact active receipt and the planned source and Split representation returns AlreadyUpToDate without staging or publication. If accidental external interference displaces a path after publication and the final state cannot be established, report PublicationUncertain and retain recoverable artifacts and evidence. Other operating systems and filesystems fail planning before destination mutation. Native tests exercise directory operations on the current host; they do not establish qualification for every Darwin volume or filesystem. Destination-scoped locks coordinate cooperating NSCB writers; uncoordinated external writers remain outside this guarantee.

The producer writes ordinary numbered files and does not establish FAT32 archive/`ConcatenationFile` attribute behavior. Archive attribute handling, FAT32 filesystem interoperability, and consumption by target devices require separate qualification. Small-segment test fixtures exercise producer, publisher, resolver, and virtual-reader mechanics only; they do not prove FAT32 interoperability. The user-facing part size remains fixed at `0xFFFF0000` bytes.

**Candidate lock and deletion boundary (2026-11-08):** The lock order is destination lock, private receipt-state lock, then LocalSplitTrustStore `.lock`. The receipt-state file lives in a child directory so its name cannot collide with a destination marker. Issue, revoke, and restore take only the store lock, so there is no reverse acquisition. Both receipt-state and cleanup-store lock acquisition use nonblocking attempts with cancellation checks. Cancellation while waiting or before deletion retains provisional artifacts and the recovery journal; RAII releases acquired locks and leases on return. Cleanup does not call another trust-store method while the lease is held.

Cleanup uses directory descriptors. It atomically renames each recorded entry to an exclusive quarantine name, reopens that name without following links, and rechecks its identity, parent, contents, and directory emptiness before unlinking it. A durable cleanup intent lets recovery resume after a quarantine rename or partial unlink. The pathname check and `unlinkat` are separate operations. Safety relies on same-volume APFS rename semantics, owner-only `0700` staging and quarantine ancestors, and supported NSCB writers honoring both locks. Other users cannot reach the private entries. A same-effective-user process or root can bypass the permissions and advisory locks; this cleanup qualification excludes those actors. If that assumption changes, the artifacts must be retained.

The preservation-only instructions in the earlier sequencing record describe that historical acceptance slice. This candidate implements the separately deferred, lease-gated reclamation work under the assumptions above. Passing candidate tests does not rewrite the earlier rationale, promote the historical TAC-7 run, or close Issue #14's legacy interoperability requirement.

If journal initialization stops after creating `.journal.initializing` but before its identity is durably recorded, keep the file and report the artifact as retained. Later recovery leaves the initializer untouched and does not treat it as a transaction record: without a durable destination binding or file identity, it cannot prove receipt state or authorize cleanup.

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
- **Issue #14:** The source-to-Split producer, local receipt issuance, bundle publication, and conflict policy are implemented. Canonical FAT32 archive-attribute interoperability and legacy output layouts remain unqualified; keep legacy layouts opt-in and blocked until independent evidence qualification. Do not silently weaken Issue #14's remaining legacy acceptance work.
- Update ADR 0013 with only the explicit distinction between *uncommitted ownership-tracked provisional artifacts* and committed *published user data*, reflecting Decisions 30/32. Preserve all other user-data protections.
- ADR 0028 is accepted as architecture; do not mark Issue #6 complete merely because the design has been accepted. Production activation requires the [Split-set contract acceptance scenarios](../testing/split-set-contract-acceptance.md) to pass under each supported OS/filesystem profile.

## 9. Non-goals

No key extraction, title rights changes, device installation, embedded content authenticity claims, accepted unsigned cross-host manifests, signature/key management, legacy `.xcN`/`.nsN` positive resolution, speculative XCI-header terminal proof, restoration from surviving parts without original source evidence, background persistent qualification Job on every read-only resolution, automatic source deletion, or hidden mutable global Engine state.
