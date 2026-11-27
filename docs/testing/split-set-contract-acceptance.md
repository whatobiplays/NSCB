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
| Directory expansion encounters qualified `backup.zip/` Split directory | Discover by declared member plus sibling-manifest evidence regardless of the ordinary single-file extension filter, preserving sorted order and duplicate checks |
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
| Segment name outside the selected layout's grammar or directory escape in manifest | Invalid manifest / unsupported competing layout |
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
| Schema-v2 `legacy_xc` manifest declares exact contiguous `.xcN` members and active receipt | Resolve a recognized, uncompressed XCI set identically by selecting a member or its Split directory |
| Schema-v2 `legacy_ns` manifest declares exact contiguous `.nsN` members and active receipt | Resolve a recognized PFS0 set without NCZ members identically by selecting a member or its Split directory |
| Legacy-looking member or ordinary numbered directory lacks a supported manifest and active receipt | Fail closed (`unsupported_split_layout` or the applicable typed missing-evidence error) |

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
7. **Bundle paths:** The explicit destination is the outer bundle directory. Results expose that path and the inner Split directory. Resolver tests pass the returned directory and its manifest-declared members directly; wrapper-directory discovery is not permitted.
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
- The canonical source-backed Split producer and durable local receipt are implemented through the existing APFS publication path. Existing-destination replacement remains unsupported until separately qualified.
- FAT32 transfer, targeted archive-attribute finalization, and independent Horizon consumption remain separate obligations. The [canonical FAT32 qualification protocol](canonical-fat32-split-qualification.md) contains the PAC/TAC mapping and physical test procedure. Physical FAT32 and Horizon evidence remains `NOT RUN` until separately authorized and successfully completed.
- At the time this contract was written, legacy `.xcN` and `.nsN` compatibility remained separate from canonical qualification. Issue #14 Slice C covers that compatibility work.

### Issue #14 Slice C PAC/TAC matrix

The PAC identifiers come from the approved Slice C plan. The canonical FAT32 protocol has a separate matrix with overlapping numbers; the `TAC-C` prefix identifies Slice C technical checks.

| PAC | Product acceptance criterion | Technical evidence | Current disposition |
| --- | --- | --- | --- |
| PAC-1 | Both legacy layouts can be selected explicitly; canonical remains the default. | TAC-C1 | PASS in host tests. |
| PAC-2 | Legacy member names, order, and size bounds are deterministic. | TAC-C2 | PASS in host tests. |
| PAC-3 | Qualified legacy sets reconstruct the original bytes exactly. | TAC-C5 | PASS in host tests for both layouts. |
| PAC-4 | Partial, corrupted, ambiguous, and untrusted sets fail closed. | TAC-C3, TAC-C6 | PASS in synthetic host tests. |
| PAC-5 | Publication, cancellation, replacement, and interruption preserve the approved safety guarantees. | TAC-C7, TAC-C8 | PASS at tested host boundaries; see the replacement limit in TAC-C8. |
| PAC-6 | The pinned legacy consumer reconstructs the synthetic source bytes exactly. | TAC-C10 | **UNPROVEN; no consumer output or digest comparison is available.** |
| PAC-7 | Existing canonical behavior remains unchanged. | TAC-C1, TAC-C9 | PASS in host tests. |

| TAC | Measurable check and evidence | Candidate result |
| --- | --- | --- |
| TAC-C1 — Selection and defaults | `src/cli.rs::split_cli_tests` checks the canonical default, both `--layout` values, and duplicate or invalid options. `tests/split_operation.rs::split_layout_is_canonical_by_default_and_selectable` and `legacy_ns_split_publishes_expected_names_and_v2_manifest` check the public API and emitted layout. | PASS; four CLI tests pass, and `make all` passes. |
| TAC-C2 — V2 naming and bounds | `split_operation::producer_tests::legacy_plan_uses_recognized_bytes_and_source_basename_rules`, `split_manifest::tests::deterministic_legacy_writer_emits_v2_names_and_layout`, `legacy_writer_enforces_its_ten_segment_limit`, `accepts_version_two_legacy_xc_with_unpadded_names_through_index_99`, and `split_operation::tests::legacy_layouts_allow_ten_segments_and_reject_eleven` cover basename-derived names, numeric ordering, the 10-member writer cap, and the 100-member resolver bound. | PASS; the trusted resolver reaches member index 99 for both layouts. |
| TAC-C3 — Operation-specific eligibility | `legacy_plan_accepts_xci_with_unsupported_nested_nca_profile_without_ncz` proves that an XCI remains eligible when a nested NCA has an unsupported filesystem profile and recognition reports `NotEstablished` for compression. `legacy_plan_rejects_wrong_family_compression_and_unknown_sources` covers NCZ evidence in both secure-member positions, malformed NCZ structures, malformed and unsupported XCI structure, wrong-family inputs, and PFS0 bytes named `.xci`. `source_change_after_generic_recognition_error_with_unchanged_snapshot_is_source_changed`, `source_change_after_non_pfs0_recognition_with_unchanged_snapshot_is_source_changed`, `source_change_after_recognition_with_unchanged_snapshot_is_not_mapped_as_xci_failure` and `source_change_after_successful_recognition_with_unchanged_snapshot_is_not_unsupported_layout` mutate source bytes after recognition and simulate unchanged metadata; each requires `SourceChanged` before stale recognition or layout errors can be returned. `source_change_after_recognition_with_changed_snapshot_is_source_changed` covers the ordinary metadata-detected change path. `source_confirmation_rejects_digest_change_with_stable_metadata` verifies that a digest mismatch is rejected even when the file snapshot and size match. Partial `HEA` at offset `0x100` remains unsupported, while a complete `HEAD` marker in a truncated image returns `InvalidXciImage`. The earlier conversion-inspector fixture changed a nested NCA after the synthetic HFS0 hashes were computed. This left the enclosing secure-partition digest stale, so the strict inspector rejected the hash before evaluating the NCA profile. Recognition reported no established compression; the fixture did not show NCZ evidence escaping detection. Global recognition and the conversion-profile gate remain unchanged. | PASS; focused eligibility and source-change regressions pass, and `make all` passes. |
| TAC-C4 — V2 stem and relocation rules | `tests/input_resolution.rs::mismatched_v2_legacy_stem_is_rejected_before_members_are_consumed` rejects a mismatch between the member stem and the file stem of the inner-directory basename for both layouts, before opening any member. `trusted_legacy_resolver_accepts_one_hundred_members_after_outer_bundle_relocation` resolves the inner directory and both `.xc99` and `.ns99` selections after the intact outer bundle moves. The canonical-v1 directory-and-sidecar rename test remains separate and confirms its existing rename behavior. | PASS. |
| TAC-C5 — Exact byte-stream reads | `split_operation::producer_tests::legacy_layouts_round_trip_exact_bytes_through_segmented_and_virtual_readers` reads one-part and multipart XCI/PFS0 sources back byte-for-byte through segmented and virtual readers, including seeks across multipart boundaries. Resolver tests also select a member and the inner directory. | PASS. |
| TAC-C6 — Resolver fail-closed evidence | `legacy_v2_incomplete_corrupt_and_competing_members_fail_closed_for_both_layouts` checks missing and modified members and unlisted `.xcN` or `.nsN` competitors. `absent_and_revoked_legacy_v2_receipts_fail_closed_for_both_layouts` checks absent and revoked trust. `unmanifested_legacy_member_fails_closed` and the stem-mismatch test cover unsupported and inconsistent representations; existing tests cover identity, alias, traversal, mutation, and digest failures. | PASS in host tests. |
| TAC-C7 — Layout-specific publication and recovery | `interrupted_legacy_create_recovers_and_publishes_declared_members` and `committed_legacy_journal_recovers_with_manifest_member_names` exercise interrupted and committed recovery for both LegacyXc and LegacyNs. | PASS. |
| TAC-C8 — Layout-specific failure injection, replacement, and finalization | `legacy_cancellation_before_publication_retains_unpublished_artifacts_without_receipt`, `legacy_promotion_failure_retains_staged_members_without_receipt`, `legacy_receipt_commit_uncertainty_retains_published_members_for_both_layouts`, and `legacy_recovery_rejects_journal_layout_member_mismatch_without_mutation` inject and check failures for both layouts. `legacy_layouts_reject_nonidentical_replacement_without_mutating_bundle` verifies that replacement is refused without changing either bundle or receipt. `legacy_verified_split_is_rejected_before_backend_calls` checks finalization rejection for both layouts. | PASS for the approved boundary; nonidentical replacement remains unsupported. |
| TAC-C9 — Canonical compatibility | Canonical-v1 manifest golden tests, the canonical default, the journal-v1 assertion in `real_multipart_writer_resolver_and_virtual_reader_round_trip`, and `trusted_canonical_v1_split_remains_valid_after_directory_rename` cover the existing format and rename behavior. `restart_recovery_retains_published_uncommitted_create_new_output` now checks that every persisted canonical JSONL journal record uses v1 without the v2-only `layout` and `segment_names` fields, then exercises recovery after reopening. `journal_segment_names_follow_layout_specific_rules` accepts metadata-free canonical-v1 journals and rejects version-2 records that declare the canonical layout. | PASS; new canonical transactions continue to emit journal v1, and interrupted v1 records recover after reopening. |
| TAC-C10 — Pinned consumer | Run the pinned NSC_BUILDER v0.99 `--joinfile` path against synthetic `.xcN` and `.nsN` fixtures in Windows Sandbox. Each consumer output must match the source length and SHA-256. | **UNPROVEN.** The Sandbox could not be launched, so no consumer command or output was produced. See the PAC-6 Sandbox record. |
| TAC-C11 — Candidate validation and review | Local validation, changed-production-line coverage, Cubic, and independent reviews must be tied to the final patch. Hosted CI and the draft PR body must be checked against its pushed commit. | **PENDING at this candidate-record revision.** Local evidence is recorded, but the candidate is not pushed. Exact-head CI and the refreshed PR body remain publication gates; record the final commit and CI result in the candidate evidence and PR body after push. PAC-6 remains **UNPROVEN**. |

### Journal-version compatibility ruling

Canonical journal v1 must remain recoverable after upgrades because a crash can leave a transaction journal for a later NSCB process to replay. The original writer at `4f305f084d7c95b797c633a6af0ccf6943a6208c` emitted v1. The legacy-layout change at `bccf264ef0d2b621e409d634929e7d09b059218a` kept canonical records at v1 and used v2 only for explicit legacy layouts and member names. The new fields are omitted from canonical records, so their v1 wire shape stays unchanged. PR #93's approved starting head `c43cae9cd6adeac9a48fae36b34d5c4b203a9683` also emitted canonical v1 and legacy v2. The restart-recovery test checks the metadata-free v1 shape and recovers the interrupted transaction after reopening. Repository history and documentation show no canonical-v2 writer or consumer requirement. No known canonical-v2 record format needs to be preserved.

Recovery treats v1 as canonical and accepts v2 only with an explicit legacy layout and member names. `JournalRecord::new` emits v1 for new canonical transactions and v2 for new legacy transactions. Recovery rejects v2 records that declare the canonical layout. Revisit this rule if a canonical-v2 writer or consumer requirement is documented. The test replays a current v1 record with the pre-legacy field shape; it does not use a journal captured from an earlier executable.

### Issue #14 Slice C execution record (2026-11-27)

The PR #93 candidate starts from approved head `c43cae9cd6adeac9a48fae36b34d5c4b203a9683`, based on main commit `836b1388a1abc811f3b1589004c6733ea7e0f086`. Worktree: `/Users/daniel/.codex/worktrees/issue-14-legacy-split-layouts/NSCB`, branch `codex/issue-14-legacy-split-layouts`.

Changed-line coverage used Homebrew LLVM 23.1.6 at `/opt/homebrew/opt/llvm/bin/llvm-cov` and `llvm-profdata`. `coverage-run-final12.log` records the instrumented library and affected `input_resolution`, `split_operation`, `split_resolution`, `split_finalization`, and `split_resolution_cli` suites: 829 passed, none failed, and 4 were ignored. `coverage_isolated_final12.py` combined 11 profile groups into 61 compatible object/profile pairs and skipped 5 mismatches. It covered 133 of 149 changed executable production lines (89.3%). `coverage_eligibility_final12.py` checks the 11 excluded lines against the analyzer's uncovered-line list and reports 133 of 138 eligible lines covered (96.4%), above the approved 90% threshold. The exclusions are seven file I/O or `InputUnavailable` paths that the current `std::fs::File` seam cannot inject deterministically (`split_operation.rs` lines 567, 570, 582, 585, 676, 725, 1141), and four invalid states rejected by existing checks (`split_operation.rs` lines 776 and 778; `split_resolution.rs` lines 203 and 208). The remaining uncovered lines are the short-source check at `split_operation.rs:574`, source revalidation after a recognition error at `split_operation.rs:753`, and cancellation checkpoints at `split_operation.rs:666`, `split_operation.rs:771`, and `split_operation.rs:1146`. `source_change_after_recognition_with_changed_snapshot_is_source_changed` covers the metadata-detected source mutation branch. Host coverage does not establish Windows consumer compatibility or PAC-6.

The first full local run, `make-all-final9.log`, stopped after 720 passed, 1 failed, and 4 ignored. `concurrent_recovery_and_writers_serialize_stale_stage_cleanup` failed an assertion that did not print the losing operation's error code. Source review showed that `DestinationChanged` is a valid outcome when a competing plan observes the other writer's publication. The test now allows that outcome and includes the full dispositions in any future assertion failure. The isolated rerun passed. `make-all-final10.log` and the final `make-all-final11.log` passed with 37 Rust result groups (2,217 passed, 0 failed, 8 ignored) and four Python suites (74 passed). The final run also checked that interrupted canonical journals persist as v1 without v2-only fields and recover after reopening. `cargo fmt --all -- --check`, Clippy with warnings denied, `git diff --check`, and the 53-test content-policy suite passed.

The task follows development-process release `2026.11.25`, revision `8e391636cb50f9bfe6e8def2d0f54eeb65d1d157`. The owner-dispatched qualification is [run 45612390118](https://github.com/danielbyon/development-process/actions/runs/45612390118), attempt 1, owner ID `327737`. The approved release context and bundle are artifacts `15020776261` and `15021765219`. The owner verified the release manifest, frozen context, and three provenance sidecars; their artifact and payload digests match the immutable release assets. This task needs no new pin or repeat qualification. NSC_BUILDER v0.99 is pinned separately at `92690c0137f520b6ee4d6c20b6f5abe8a3ce5738`.

GPT Repo MCP does not currently enroll this worktree. Its read-only root listing showed the primary checkout at `/Users/daniel/Projects/NSCB`, and the current-work-session lookup found no session. Codex client connection settings and MCP server lifecycle remain unchanged. Work proceeds manually under owner approval. CodeGraph and TokenSave are initialized for this branch, and Serena is active in the worktree.

PAC-6 requires output bytes produced by the pinned NSC_BUILDER v0.99 consumer and a matching source length and SHA-256. At commit `92690c0137f520b6ee4d6c20b6f5abe8a3ce5738`, `py/ztools/squirrel.py --joinfile` contains the join path, and `py/ztools/JOINER.bat` invokes it before a later rename step. Source inspection shows that the script derives `.xci` from `.xc0` and `.nsp` from `.ns0`, finds sibling parts in the same directory, sorts them, and copies their bytes in buffered reads. This is a compatibility hypothesis until the pinned consumer emits and verifies output.

An earlier isolated attempt used Python 3.10.22 on macOS 27.2 with a 9,499-byte synthetic source split into `synthetic.xc0` and `synthetic.xc1` at byte 1,731. The source SHA-256 was `b52469a9581c4d15f20420a015a763396a215f86b350a64296f933e8550fe36e`. It exited with `ModuleNotFoundError: No module named 'Crypto'`; the literal command was not retained, and no output was written. No dependency was installed. The upstream README specifies Windows, and the joiner assumes Windows drive-path behavior. This attempt does not satisfy PAC-6.

### PAC-6 Windows Sandbox follow-up (2026-11-27)

**Status: UNPROVEN.** A read-only preflight ran on the designated OBIGAMING host through its existing Codex remote PowerShell session. The host is Windows 11 Pro, build 26200, 64-bit, with an Intel Core i7-14700K (20 cores and 28 logical processors), 31.8 GiB of RAM, and 8.09 GiB free on C:. Microsoft lists Pro as a supported edition and requires enabled virtualization, at least 4 GiB of RAM, two CPU cores, and 1 GiB of free disk space. The host meets the edition and reported resource minimums. Space for the pinned source and offline wheelhouse has not been measured. The host reports `HypervisorPresent=True`, but CIM reports firmware virtualization, VM monitor extensions, and SLAT as `False`. These flags need owner investigation before Sandbox can be qualified. See Microsoft's [Windows Sandbox overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/) and [installation guide](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install).

The `Containers-DisposableClientVM` optional feature is disabled (`InstallState=2`). The current token is not an administrator; the elevated feature query returned “The requested operation requires elevation.” `WindowsSandbox.exe` is absent, no Sandbox Appx package is installed, and `wsb` is not available. The existing Codex connection provided PowerShell but no interactive desktop control. This session therefore cannot launch or control Sandbox. Microsoft's [Sandbox CLI guide](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-cli) also requires an active user session for interactive connection and notes that `wsb exec` does not return process output. Any later automated run must write its results to the mapped output folder. No feature change, reboot, `.wsb` launch, or consumer execution occurred.

The pinned [NSC_BUILDER source at commit `92690c0137f520b6ee4d6c20b6f5abe8a3ce5738`](https://github.com/julesontheroad/NSC_BUILDER/tree/92690c0137f520b6ee4d6c20b6f5abe8a3ce5738) has no dependency lockfile or requirements file. `squirrel.py` imports `urllib3`, `tqdm`, and `pykakasi`; on Windows it also imports `win32api` and `win32con`. Its import chain includes `Crypto.Cipher.AES`. A static scan of roughly 60 reachable modules found other possible packages, including `PIL`, `bs4`, `chardet`, `colorama`, `googletrans`, `requests`, `ujson`, and `zstandard`, but did not establish which ones `--joinfile` needs. The join-path dependency set, versions, and wheel hashes remain unresolved. No offline wheelhouse has been prepared or installed. The proposed read-only input set uses `C:\NSCB-PAC6\input\requirements-pac6.txt` and `C:\NSCB-PAC6\input\wheelhouse\`; leave these empty until the required packages and hashes are verified. The imports are visible in the pinned [`squirrel.py`](https://github.com/julesontheroad/NSC_BUILDER/blob/92690c0137f520b6ee4d6c20b6f5abe8a3ce5738/py/ztools/squirrel.py#L25-L61) and [`pyNCA3.py`](https://github.com/julesontheroad/NSC_BUILDER/blob/92690c0137f520b6ee4d6c20b6f5abe8a3ce5738/py/ztools/Fs/pyNCA3.py#L2-L19). An earlier Python 3.10.22 attempt stopped at startup with `ModuleNotFoundError: No module named 'Crypto'`.

Proposed host folders are `C:\NSCB-PAC6\input` and `C:\NSCB-PAC6\output`. The read-only input folder will contain a clean export of the pinned source, the official Python 3.14.10 x64 Windows installer and its expected SHA-256 (`92480239264744fe0386a1bd8275786fefa126e3129e56a68e22b52c73329965`), a wheelhouse with exact package versions and a SHA-256 manifest, and a deterministic fixture generator and verifier. The Python 3.14.10 installer is a candidate runtime; compatibility with the pinned v0.99 source and its dependencies has not been tested. Python 3.10.22 is source-only and has no Windows installer. The writable output folder will hold only consumer output and logs. Neither folder may contain repository credentials, personal files, Nintendo key material, or production data.

Proposed `.wsb` configuration:

```xml
<Configuration>
  <vGPU>Disable</vGPU>
  <Networking>Disable</Networking>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>C:\NSCB-PAC6\input</HostFolder>
      <SandboxFolder>C:\PAC6\input</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>C:\NSCB-PAC6\output</HostFolder>
      <SandboxFolder>C:\PAC6\output</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
</Configuration>
```

Networking, vGPU, audio and video input, printer access, and clipboard redirection are disabled. Only the pinned input and dedicated output folders are mapped. Output writes persist on the host after Sandbox closes, so the output folder must remain dedicated to this qualification. The settings follow Microsoft's [Sandbox configuration guide](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file). This configuration is proposed only; it has not been launched.

**Preflight commands run in the existing remote session:**

```powershell
Get-CimInstance Win32_ComputerSystem | Select-Object Name,Manufacturer,Model,TotalPhysicalMemory,HypervisorPresent
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,WindowsDirectory
Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,VirtualizationFirmwareEnabled,VMMonitorModeExtensions,SecondLevelAddressTranslationExtensions
Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object DeviceID,FreeSpace,Size
Get-CimInstance Win32_OptionalFeature -Filter "Name='Containers-DisposableClientVM'" | Select-Object Name,InstallState,Status,Caption
Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM | Select-Object FeatureName,State,RestartRequired
Test-Path "$env:WINDIR\System32\WindowsSandbox.exe"
Get-AppxPackage -Name WindowsSandbox
Get-Command wsb -All -ErrorAction SilentlyContinue
wsb --help
```

The CIM feature query returned `InstallState=2` (Disabled). `Get-WindowsOptionalFeature` failed because the session was not elevated. `Test-Path` returned `False`; `Get-AppxPackage` and `Get-Command wsb` returned no result; and `wsb --help` was not recognized. No source or fixture files were staged. The remote PowerShell output was transcribed into this record; no raw host-preflight log was preserved in the task evidence directory.

**Proposed qualification procedure after the owner resolves the host prerequisites:**

1. From an active interactive OBIGAMING session, recheck firmware virtualization and Sandbox feature state. Prepare only the two task-specific host folders and the pinned read-only input set. The owner must enable the optional feature from an elevated session and reboot only if Windows requests it.
2. Launch the proposed `.wsb` file. Inside Sandbox, verify the Python 3.14.10 x64 installer against the published SHA-256 above, install it, and create `C:\PAC6\work\venv`. After dependency closure is verified, install only from the mapped offline inputs with `C:\PAC6\work\venv\Scripts\python.exe -m pip install --no-index --find-links C:\PAC6\input\wheelhouse --require-hashes -r C:\PAC6\input\requirements-pac6.txt`. This runtime is a candidate until the pinned source and dependency imports are checked inside Sandbox. Copy the pinned source into the Sandbox's local `C:\PAC6\work\NSC_BUILDER_v0.99` directory because `squirrel.py` creates a database directory at startup. Record Python, package, source, and wheel hashes. The exact dependency lock and Windows wheel hashes must be established before this step. See the official [Python 3.14.10 Windows release](https://www.python.org/downloads/release/python-31410/) and [Python 3.10.22 source-only release](https://www.python.org/downloads/release/python-31022/).
3. Generate the 9,499-byte reference stream with `bytes((i * 131 + 17) & 0xff for i in range(9499))`. Split at byte 1,731 into parts of 1,731 and 7,768 bytes. Use separate fixture folders for `synthetic.xc0`/`synthetic.xc1` and `synthetic.ns0`/`synthetic.ns1`. The expected source SHA-256 is `eaf692cc182eb3b7e8a4b5eba09cb540f3db78ce52bdf7045c3c38041681a426`.
4. Run the pinned script from its Sandbox-local copy. In v0.99, the parser registers `--joinfile` only on Windows. `JOINER.bat` invokes the same join path with an output folder and buffer; these direct commands use one isolated fixture at a time:
   ```powershell
   $Python = 'C:\PAC6\work\venv\Scripts\python.exe'
   $Script = 'C:\PAC6\work\NSC_BUILDER_v0.99\py\ztools\squirrel.py'
   & $Python $Script -o 'C:\PAC6\output\xc' -b 65536 --joinfile 'C:\PAC6\work\fixtures\xc\synthetic.xc0'
   & $Python $Script -o 'C:\PAC6\output\ns' -b 65536 --joinfile 'C:\PAC6\work\fixtures\ns\synthetic.ns0'
   Get-Item 'C:\PAC6\output\xc\synthetic.xci', 'C:\PAC6\output\ns\synthetic.nsp' | Select-Object FullName,Length
   Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\PAC6\output\xc\synthetic.xci', 'C:\PAC6\output\ns\synthetic.nsp'
   ```
   The pinned join code scans sibling names, sorts the selected parts, and copies their bytes to `synthetic.xci` and `synthetic.nsp`. Compare each output length and SHA-256 with the reference values above. Record the commands, exit codes, output byte counts, and both digest comparisons in the mapped output folder. This two-part consumer fixture covers indexes 0 and 1 only; it makes no claim about indexes 10 through 99.

An earlier macOS attempt used a different 9,499-byte fixture split at byte 1,731. Its source SHA-256 was `b52469a9581c4d15f20420a015a763396a215f86b350a64296f933e8550fe36e`; startup stopped with `ModuleNotFoundError: No module named 'Crypto'`. Because the pinned source registers `--joinfile` only on Windows, that run could not qualify the consumer path. No Windows consumer command has run. There are no consumer output bytes, lengths, or digest comparisons to report. PAC-6 remains **UNPROVEN**.

**Owner actions:** Resolve the reported firmware or nested-virtualization settings, enable `Containers-DisposableClientVM` from an elevated session, and reboot only if Windows requests it. Make an active interactive desktop session available to Codex, then recheck `WindowsSandbox.exe` and `wsb`. No feature activation or reboot has been authorized or performed.
