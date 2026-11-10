# Split-set qualification: accepted acceptance scenarios

**Status:** Accepted architectural acceptance scenarios, not yet executed as a production qualification. Synthetic-data only; no Nintendo copyrighted content, title keys, device responder, certificates, or signatures required.

**Expected behavior:** A test passes only when it demonstrates the exact specified qualification or fail-closed outcome, not merely a matching diagnostic string.

## Evidence versus fixture truth

Each fixture record must separately state (1) fixture producer's ground truth; (2) independently observable source evidence retained by the host; (3) manifest declaration; (4) filesystem observations; (5) exact expected result; and (6) code/CLI result. Incomplete and complete source histories may be observationally indistinguishable once terminal segments are lost. A candidate with no independently retained trust evidence never receives successful Split qualification, even when all surviving parts match its unsigned manifest.

## Core matrix

| Case | Expected qualification |
| --- | --- |
| Complete 3-part canonical set; matching issued receipt and both digest levels | One `ResolvedInput` with ordered parts and typed local completeness evidence |
| Select `00`, `01`, `02`, or root directory individually | Each selection resolves the identical logical set and sidecar |
| Complete single part `00` with source-backed receipt | Qualified (even if underlying bytes are not recognized Nintendo Content) |
| Directory expansion encounters qualified `backup.zip/` Split directory | Discover by canonical segment plus sibling-manifest evidence regardless of the ordinary single-file extension filter, preserving sorted order and duplicate checks |
| Original regular file without Split representation | Existing single-file behavior, no Split receipt required |
| Missing terminal `02` while `00`, `01` remain contiguous | `split_set_incomplete` / mismatch; no successful input |
| Missing first or middle part | `split_set_incomplete` |
| Manifest absent; all numbered parts exist | `split_manifest_missing`; do not guess final segment |
| Manifest matches all surviving parts but no independent receipt exists | `split_evidence_untrusted` |
| Manifest derived post hoc from arbitrary existing parts | Remains untrusted, even if bytes agree |
| Receipt revoked; manifest and parts still match | `split_evidence_untrusted` |
| Manifest edited only in whitespace or optional metadata | Receipt binding to exact bytes fails |
| Manifest declares length different from checked sum of parts | `split_manifest_invalid` |
| Segment byte changed without size change | `split_integrity_mismatch` |
| One segment and all declared hashes match, but whole-file digest mismatches | `split_integrity_mismatch` |
| Extra unlisted numbered `03` when manifest declares `00`-`02` | `split_set_incomplete` / competing-member failure |
| Unrelated `.DS_Store`, `notes.txt`, or other non-Split metadata | Ignored; still qualified if all claimed members validate |
| Numbered member is a symlink or special file | Typed input failure; no external target opened |
| Two member names alias same hardlink identity | Fail on duplicate identity where supported; on unsupported platforms fail closed if uniqueness cannot be proven |
| Explicit directory symlink with traversal permission | Resolve using real target directory and sibling sidecar |
| Explicit directory symlink without traversal permission | Respect existing traversal rejection contract |
| Two independent selections address the same set by member/root/alias | Existing `duplicate_selection` error; never process twice |
| Duplicate manifest JSON keys, unknown required feature, wrong version or kind | Appropriate versioned typed failure; no guessing |
| Segment name outside ASCII `00`-`99` or directory escape in manifest | Invalid manifest / unsupported competing layout |
| 101+ declared segments or cumulative-length overflow | Bounded input failure; no wraparound or partial success |
| Zero-length source and single zero-length `00` | Only accepted after explicit canonical consumer interoperability qualification; else typed unsupported configuration |
| Alternate smaller segment size | Allowed only for validated interoperable profile; otherwise rejected at planning |
| Original source modified during split | No receipt committed, no qualified published output |
| Source replaced at same path after file opened | Opened identity/revalidation detects replacement and fails |
| Segment mutated after successful resolve but before execution | Execution rejects or safely revalidates; no irreversible effect from untrusted bytes |
| Segment mutated while operation reads | No successful final output; externally irreversible effects require prior verified stable snapshot |
| Cancellation during plan-time source hashing, staged part read-back, reconstructed-stream hashing, or source revalidation | Typed cancellation before planning returns or execution qualifies output; no successful Split result and machine stdout remains valid |
| Cancellation after committed receipt | Committed success preserved and reported truthfully |
| Concurrent processes attempt same destination | Destination scoped coordination or typed exit-4 conflict; no silent overwrite |
| Failure after sidecar publication but before receipt commit | Remains unqualified; ownership-safe cleanup only; never promote trust by matching orphaned sidecar |
| Failure during staged cleanup and unrelated user file appears | Preserve unrelated files and any artifact whose ownership/unchanged identity cannot be proved |
| Existing qualified destination byte-for-byte identical | `Already up to date` only with normal destination policy and positive trust verification |
| Existing output matches sidecar but lacks trusted receipt | Conflict/untrusted; no automatic evidence issuance |
| Directory and sidecar moved/renamed together on the same host | Qualifies with existing content-addressed receipt |
| Two different segmentations of the same source | Distinct manifests and independent revocation identity |
| Revoke one manifest then resolve copied identical manifest | Fails on every identical copy; differently segmented qualified set stays trusted |
| Trust store inaccessible/corrupt | Fail closed; internal/state failure, not reconstructed from sidecar |
| Restore independently trusted same-host state backup | Qualification resumes only after versioned/validated store restoration |
| Copy set + sidecar to different machine without local receipt | Untrusted in v1, even with matching hashes |
| Temporarily unmounted external volume | Does not revoke receipts or trigger deletion |
| Resource ceiling reached during hashing/manifest parse | Bounded failure and sanitized diagnostics; no partial JSON success |
| Non-UTF-8 path in CLI machine result | Preserve established `unrepresentable_path` behavior; Rust paths stay native |
| Legacy `.xcN` / `.nsN` or ordinary numbered directory without trusted evidence | Continue fail-closed behavior (`unsupported_split_layout` or typed missing evidence as applicable) |

## Correction-specific acceptance scenarios

These scenarios identify their implementation owner. Issue #6 resolver tests use an isolated test-only evidence issuer based on synthetic unsplit sources; they do not depend on Issue #14's production writer.

### Issue #6 resolver and evidence-seam scenarios

- **Q21 — Original source may be deleted:** Split a complete synthetic regular-file source through the test-only evidence issuer, independently retain its length and digest, validate every output part and the reconstructed whole-stream length/digest against the source, and commit the trusted receipt. Delete the original source file. Resolve the unchanged canonical set by selecting a member and the directory; both selections return the same successful logical byte-stream input using the retained receipt and manifest evidence. Resolution must neither require nor recreate the deleted source.
- **Q36 — Trust-store provider is omitted:** Construct an Engine using the existing construction path without a host trust-store provider. Resolving an ordinary regular file succeeds with its established single-segment result. Resolving a canonical Split candidate fails closed with a typed missing-capability outcome. This intentional omission is distinct from a configured provider whose store is unreadable or corrupt, which fails as a store-state error such as `split_state_unavailable`. Omitting the optional capability must not break existing Engine construction or ordinary resolution. Final public error spelling is fixed during release compatibility review.
- **Q44 — Requalification requires fresh source evidence:** Issue and resolve a synthetic source-backed set, then revoke its manifest identity. Resolution of the set and byte-identical copies fails as `split_evidence_untrusted`; rescanning parts or copying the unsigned sidecar cannot restore trust. Use the original single-file source in a fresh authorized source-backed operation through the Issue #6 test-only evidence seam, independently record and recheck its length and digest, validate the resulting parts, and commit a new active receipt only after successful validation. Resolution then succeeds. Also run this sequence when the new manifest bytes are identical to the revoked manifest: only the newly committed source-backed receipt may re-establish trust for that identity. Issue #14 separately qualifies the production-writer path.

### Issue #14 producer and eligibility scenarios

The 2026-11-03 acceptance run is preservation-only: it requires durable recovery inventory, non-destructive retention, and no automatic deletion of provisional artifacts. Existing tests prove retention when ownership is ambiguous or artifact identity or content differs, including partial files, changed directory permissions, foreign children, symlink and hardlink substitutions, replaced parents, and torn journals. A boundary regression substitutes a symlink after the final identity check and verifies that both the replacement and staged bytes survive. Clean provisional output is retained as well. Historical TAC-7 remains failed/blocked; this text does not reclassify its run record. Native evidence is limited to Darwin arm64/APFS. Linux and Windows checks are compile-only; FAT32/Switch interoperability and positive legacy-layout compatibility remain unqualified.

#### Owner-approved acceptance sequencing amendment (2026-11-03)

Q30, Q32, and the original cleanup decision remain unchanged in the historical research decision ledger. This amendment records the original Issue #14 acceptance sequence:

1. Original preservation-only slice: Prove durable recovery inventory, non-destructive retention, and no automatic deletion of provisional artifacts. Passing this prerequisite does not change the historical TAC-7 result.
2. Historical deferred-reclamation decision: Positive automatic reclamation was left for separate qualification. That decision and the failed/blocked historical TAC-7 run remain recorded; this candidate does not rewrite either.

The current reclamation qualification uses an identity-bound removal mechanism in a private namespace. Receipt issuance and cleanup for the same manifest digest use the same manifest-scoped serialization primitive. Recovery reconciles journal and receipt state after crashes, preserves committed, modified, unknown, or uncertain data, and never issues trust retroactively for orphaned parts. Directory permissions, destination locks, and pre-removal identity checks alone do not prove race-free deletion.

#### Current candidate reclamation addendum (2026-11-08)

The candidate adds optional `SplitTrustWriter::acquire_cleanup_lease(&Sha256Digest, &dyn Fn() -> bool)`. Its default returns `Ok(None)`, so existing writer implementations remain source-compatible and cleanup stays unavailable. `LocalSplitTrustStore` acquires the existing cross-process `.lock` with cancellation-aware nonblocking retries, recovers pending commits, and grants the lease only when valid authoritative indexes agree, the exact manifest has no history, and no receipt file exists. Issued, revoked, historically committed, corrupt, missing, unavailable, cancelled, or ambiguous state retains the artifacts. The lease stays held through cleanup and the terminal journal update.

Ownership evidence remains separate from receipt state. A creation intent and parent identity are durable before artifact creation. Later identity, size, digest, and parent evidence authorize cleanup only after revalidation. Descriptor-relative exclusive renames move proven artifacts into an owner-only quarantine; identity and content are checked again there before removal. Cleanup can resume after interruption following quarantine rename or the first unlink. The lock order is destination, private receipt-state, then host store. Store operations have no reverse dependency on Split locks, and cleanup makes no other trust-store call while holding the lease. Tests exercise this path for cooperating NSCB writers on the local APFS host. Uncoordinated external writers remain outside the guarantee.

This candidate evidence does not change the historical TAC-7 run result. It does not qualify legacy `.xcN` or `.nsN` layouts, FAT32 archive attributes, or Switch hardware. The full Issue #14 legacy interoperability requirement remains open.

The public ConflictPolicy::Replace variant remains available, but it does not enable replacement of an occupied destination. If the destination satisfies the qualified AlreadyUpToDate predicate, return AlreadyUpToDate without staging, publication, or receipt issuance. Otherwise, a Replace request fails planning with SplitReplacementUnsupported, before staging or mutation. Publication must not use rename-swap or speculative compensating rename after an identity mismatch. Stable destination-scoped coordination serializes cooperating NSCB writers targeting the same destination and validates lock identity and parent route. It does not guarantee exclusion of uncoordinated external writers. If path displacement is detected and the final state cannot be established, return PublicationUncertain and retain recoverable artifacts and evidence.

**Owner-approved TAC-8 canonical-v1 scope amendment (2026-11-08):** The original technical acceptance wording called for validated positive Replace, but the accepted v1 evidence/publication contract rejects occupied nonmatching destinations. For this canonical-v1 slice, TAC-8 requires a positive demonstration that an occupied nonmatching Replace request fails before filesystem mutation with `SplitReplacementUnsupported`, without changing or deleting the existing bundle or its exact-manifest receipt. Independently verify Skip of a different qualified bundle, AlreadyUpToDate only for an exact fully qualified match, destination-scoped concurrency, aliases, path substitutions, rollback and cancellation. A request whose destination is already qualified and identical may return AlreadyUpToDate, not a replacement. Positive replacement is **deferred**, not implemented or passed, until an owner-approved contract defines displaced-bundle retention/location, exact-manifest receipt disposition, and crash recovery. Preserve the original TAC-8 wording and blocked run evidence as historical records; this amendment governs new canonical-v1 qualifications only.

- **Q37 — Generic versus container-aware splitting:** A generic byte-stream split accepts an explicitly selected regular file, including a standalone loose NCA, without requiring Content Recognition and preserves its exact bytes across the ordered output segments. The result makes no Content identity, authenticity, Verification, or package-eligibility claim. For a standalone loose NCA independently established under ADR 0027, planning a prohibited container-aware Content transformation, including container-aware Content splitting, remains ineligible under ADR 0022.
- **Q38 — Canonical segment sizing:** Let `S = 0xFFFF0000` bytes. Planning and bounded test fixtures must produce these segment lengths without allocating the corresponding large files:

  | Source length | Expected ordered segment lengths |
  | --- | --- |
  | `S - 1` | `[S - 1]` |
  | `S` | `[S]` |
  | `S + 1` | `[S, 1]` |
  | `2S - 1` | `[S, S - 1]` |
  | `2S` | `[S, S]` |
  | `2S + 1` | `[S, S, 1]` |
  | `100S` | 100 parts, each of length `S`, named `00` through `99` |
  | `100S + 1` | Planning rejects the source because it requires 101 parts |

  Every nonempty final part is exactly the remaining 1 through `S` bytes; exact-boundary inputs have no empty terminal part. The producer accepts at most 100 parts (`00`–`99`). Configured sizes smaller than `S` remain unavailable unless the selected size has passed the documented canonical-consumer interoperability qualification. Production-boundary arithmetic must be tested without large allocations. A private test-only segment-size seam may drive real producer, publisher, resolver, and virtual-reader round trips; those synthetic parts do not establish FAT32 or device interoperability.

The 2026-11-03 preservation prerequisite and deferred reclamation gate record the earlier candidate scope and sequencing. This 2026-11-08 candidate implements the separately deferred reclamation work under the cleanup assumptions stated in the architecture contract. A result for this candidate does not revise the earlier TAC-7 record or establish a pass for another candidate.

Receipt cleanup acquires locks in this order: destination lock, private receipt-state lock, then the LocalSplitTrustStore `.lock`. Receipt-state acquisition and LocalSplitTrustStore cleanup and recovery lookup poll cancellation while waiting for a lock. The source-compatible default recovery lookup calls the existing `lookup` method, so a custom writer may block until that lookup returns; recovery checks cancellation immediately afterward. If cancellation is accepted while waiting or before cleanup starts, recovery returns `Cancelled` and retains the journal and artifacts. Substitution regressions replace an entry after initial ownership verification; cleanup reopens and rechecks it before unlinking. Qualification assumes owner-private staging and cooperating NSCB writers. Same-effective-user or root processes that bypass NSCB locks are outside that threat model.

## Acceptance gates

1. **Producer-independent resolver tests:** Construct synthetic unsplit source bytes, generate trusted fixtures using an isolated test-only evidence issuer that independently retains source length/digest, then select any segment. Negative fixtures must not manufacture proof from the parts themselves.
2. **Virtual reader:** Exercise real temporary regular files, cross-part `Read + Seek`, exact EOF, integer overflow, short reads, metadata changes, reparse points, file-handle replacement, and parser use. In-memory mock-only tests are insufficient for production qualification.
3. **Publication and recovery inventory:** Exercise interruption at each before/after-write, fsync, rename, sidecar publication, and receipt-commit transition. Prove the durable inventory identifies planned artifact names and parent identity before creation and records verified identity and content/metadata evidence after creation. The historical preservation-only run retained provisional output and recovery evidence; that TAC-7 record remains unchanged. For this candidate, also cancel after publication but before receipt commit, interrupt cleanup after quarantine rename and after the first unlink, restart recovery, and prove it retains or removes only owned uncommitted artifacts without issuing a receipt.
4. **Public compatibility:** Existing `resolve` CLI and JSON input list fixtures remain unchanged. Additive Rust/JSON fields are accepted by consumers; versioning and exit classes conform to ADRs 0023 and 0026. All error messages come from localized resources.
5. **Supported host platforms:** Explicitly qualify macOS arm64, Linux x86_64/aarch64, and any additional supported platform in the repository's release matrix. Characterize FAT archive attribute handling separately from source-byte qualification.
6. **Worktree governance:** All validation and review tools must bind the exact implementation worktree. Never fabricate or retrofit an old Delegation result; complete separate attestation as authorized.
7. **Bundle paths:** The explicit destination is the outer bundle directory. Results expose that path and the inner canonical Split directory. Resolver tests pass the returned canonical directory and its numbered members directly; wrapper-directory discovery is not permitted.
8. **Already-up-to-date:** A destination qualifies only when its active receipt, exact planned source length and SHA-256, manifest, segment membership and lengths, and destination policy match. A different valid Split representation must conflict or follow the explicit skip policy.
9. **Publication policy and destination coordination:** Qualify new-destination create primitives separately on every supported OS/filesystem. A request to replace an existing destination fails before staging or mutation. Test stable destination-scoped exclusion for cooperating NSCB writers on the same destination and concurrent progress for independent destinations; validate lock identity and parent route. Do not claim protection against uncoordinated external writers. Detected path displacement with unknown final state returns `PublicationUncertain`, retains recoverable artifacts, and does not attempt compensating rename.
10. **Receipt uncertainty:** Exercise an issue call that reports an error after durable commit and a store whose follow-up lookup is unavailable. Reconcile durable receipt evidence before deciding transaction status. The current candidate serializes exact-manifest issuance with cleanup; only authoritative never-committed state can grant a lease. Unavailable, revoked, corrupt, historical, or uncertain state preserves output and recovery evidence. Recovery never issues trust. A committed receipt with a stale journal remains committed after recovery.
11. **Archive attributes:** Record archive/`ConcatenationFile` handling separately from byte-stream completeness. Do not claim FAT32 interoperability from small-segment synthetic tests.

**Journal initialization recovery:** Force failure after creating the empty `.journal.initializing` file but before recording its identity. Assert the failed operation reports retained state and preserves the file. Verify recovery leaves the unbound initializer untouched and does not treat it as a transaction record.

## Terminal OperationResult inventory

Qualify the inventory through the public `OperationResult` accessors. Cover successful publication; AlreadyUpToDate and Skip; failure before artifact creation; retained provisional output; cancellation before cleanup removal; receipt commit with a stale journal; publication uncertainty; modified and substituted artifacts; and interruption during cleanup recovery. For each artifact, compare planned or journal-recorded evidence with current path identity, size, digest, parent identity, role, and retention state. Added unrelated entries must remain identified as uncertain and retained. A missing or torn journal must leave unknown evidence unknown. Retained storage totals must include known bytes outside a verified published destination, return unknown when evidence is insufficient, and count hard-link aliases to the same filesystem identity once. These assertions describe evidence available at the terminal result; they do not establish ownership or authorize deletion by themselves.

## Issue sequencing acceptance

- Approved Issue #14 sequencing amendment: Preserve Q30/Q32 and the original cleanup decision in the historical ledger. The 2026-11-03 slice remains preservation-only, and its TAC-7 result remains failed/blocked. The current Option 1 candidate separately implements the deferred reclamation work; its status requires fresh candidate-bound validation and review. It does not retroactively approve the historical run or close the full Issue #14 legacy interoperability requirement.
- Issue #6 can close only after the positive canonical resolver, local evidence qualification seam, independently derived test fixtures, safe failure cases, and public compatibility gates are implemented and reviewed. Do **not** pretend production user-facing Split output exists simply because test-only trusted fixtures work.
- Issue #9 implements the governed Plan/execution/staged-output publication foundation needed by producer logic.
- Issue #14 implements the canonical source-backed Split producer and durable receipt during an NSCB-owned operation. Existing-destination replacement remains unsupported until separately qualified. FAT32 archive-attribute/device interoperability and legacy compatibility remain separate positive-qualification obligations or require explicitly approved ticket rescoping, never silent default support.
