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
| PAC-1 | Both legacy layouts are explicitly selectable; canonical remains the default. | TAC-C1 | PASS in host tests. |
| PAC-2 | Legacy member names, order, and size bounds are deterministic. | TAC-C2 | PASS in host tests. |
| PAC-3 | Qualified legacy sets reconstruct the original bytes exactly. | TAC-C4, TAC-C5 | PASS in host tests for both layouts. |
| PAC-4 | Partial, corrupted, ambiguous, and untrusted sets fail closed. | TAC-C3, TAC-C6 | PASS in synthetic host tests. |
| PAC-5 | Publication, cancellation, replacement, and interruption preserve the approved safety guarantees. | TAC-C7, TAC-C8 | PASS for the tested host boundaries; see TAC-C8 for replacement limits. |
| PAC-6 | The pinned legacy consumer emits reconstructed bytes that match the synthetic source digest. | TAC-C10 | **UNPROVEN; hard closeout blocker.** |
| PAC-7 | Existing canonical behavior remains unchanged. | TAC-C1, TAC-C9 | PASS in host tests. |

| TAC | Measurable check and evidence | Candidate result |
| --- | --- | --- |
| TAC-C1 — Selection and defaults | `src/cli.rs::split_cli_tests` checks the canonical default, both `--layout` values, and duplicate or invalid options. `tests/split_operation.rs::split_layout_is_canonical_by_default_and_selectable` and `legacy_ns_split_publishes_expected_names_and_v2_manifest` check the public API and emitted layout. | PASS; the CLI suite has 4 passing tests, and `make all` passes. |
| TAC-C2 — V2 naming and bounds | `split_operation::producer_tests::legacy_plan_uses_recognized_bytes_and_source_basename_rules`, `split_manifest::tests::deterministic_legacy_writer_emits_v2_names_and_layout`, `legacy_writer_enforces_its_ten_segment_limit`, `accepts_version_two_legacy_xc_with_unpadded_names_through_index_99`, and `split_operation::tests::legacy_layouts_allow_ten_segments_and_reject_eleven` cover basename-derived names, numeric ordering, the 10-member writer cap, and the 100-member parser bound. | PASS; the 100-member resolver case also selects member index 99 for both layouts. |
| TAC-C3 — Operation-specific eligibility | `legacy_plan_accepts_xci_with_unsupported_nested_nca_profile_without_ncz` and `legacy_plan_rejects_wrong_family_compression_and_unknown_sources` cover XCI/PFS0 eligibility. The rejection test checks valid NCZ evidence and malformed NCZ headers in the first and second XCI secure members and in PFS0. The earlier strict-inspector fixture failed because its HFS0 hash was stale; it did not show that NCZ evidence escaped recognition. No global recognition change or strict conversion-profile gate was added. | PASS; the focused eligibility regression and `make all` pass. |
| TAC-C4 — V2 stem and relocation rules | `tests/input_resolution.rs::mismatched_v2_legacy_stem_is_rejected_before_members_are_consumed` rejects a stem mismatch for both layouts before opening members. `trusted_legacy_resolver_accepts_one_hundred_members_after_outer_bundle_relocation` resolves the directory and member index 99 after moving each intact outer bundle. The canonical-v1 directory and sidecar rename test remains separate. | PASS. |
| TAC-C5 — Exact byte-stream reads | `split_operation::producer_tests::legacy_layouts_round_trip_exact_bytes_through_segmented_and_virtual_readers` reads one-part and multipart XCI/PFS0 sources back byte-for-byte and seeks across a multipart boundary for both layouts. Resolver tests also select both the member and directory. | PASS. |
| TAC-C6 — Resolver fail-closed evidence | `legacy_v2_incomplete_corrupt_and_competing_members_fail_closed_for_both_layouts` checks missing and modified members and an unlisted `.xcN` or `.nsN` competitor. `absent_and_revoked_legacy_v2_receipts_fail_closed_for_both_layouts` checks absent and revoked trust. `unmanifested_legacy_member_fails_closed` and the stem-mismatch test cover unsupported and inconsistent representations; inherited tests cover identity, alias, traversal, mutation, and digest failures. | PASS in host tests. |
| TAC-C7 — Layout-specific publication and recovery | `interrupted_legacy_create_recovers_and_publishes_declared_members` and `committed_legacy_journal_recovers_with_manifest_member_names` exercise interrupted and committed recovery for LegacyXc and LegacyNs. | PASS. |
| TAC-C8 — Layout-specific failure injection, replacement, and finalization | `legacy_cancellation_before_publication_retains_unpublished_artifacts_without_receipt`, `legacy_promotion_failure_retains_staged_members_without_receipt`, `legacy_receipt_commit_uncertainty_retains_published_members_for_both_layouts`, and `legacy_recovery_rejects_journal_layout_member_mismatch_without_mutation` inject failures for both layouts. `legacy_layouts_reject_nonidentical_replacement_without_mutating_bundle` verifies that replacement is refused without changing either legacy bundle or its receipt. `legacy_verified_split_is_rejected_before_backend_calls` covers finalization rejection for both layouts. | PASS for the approved boundary; nonidentical replacement remains unsupported. |
| TAC-C9 — Canonical compatibility | Canonical-v1 manifest golden tests, the canonical default, `real_multipart_writer_resolver_and_virtual_reader_round_trip`'s journal-v1 assertion, and `trusted_canonical_v1_split_remains_valid_after_directory_rename` cover the existing format and rename behavior. `journal_segment_names_follow_layout_specific_rules` accepts metadata-free v1 canonical journals and rejects v2 records that declare canonical layout. | PASS; new canonical transactions still emit journal v1. |
| TAC-C10 — Pinned consumer | Qualify the pinned NSC_BUILDER v0.99 `--joinfile` path in Windows Sandbox with synthetic `.xcN` and `.nsN` fixtures. A pass requires consumer-emitted output bytes whose length and SHA-256 match the source. Source inspection and harness reconstruction are partial evidence. | **UNPROVEN.** No Windows command or consumer output was produced. See the PAC-6 Sandbox record. |
| TAC-C11 — Candidate validation and review | Repository validation, changed-production-line coverage, local Cubic, independent full-diff and correction-delta reviews, and PR CI must all identify the same candidate. | Host validation is recorded below. Final review and PR-head CI remain required; PAC-6 stays separate. |

### Journal-version compatibility ruling

There is no demonstrated compatibility requirement for accepting canonical version-2 journals. The canonical producer introduced in `4f305f084d7c95b797c633a6af0ccf6943a6208c` writes version 1. The legacy-layout change in `bccf264ef0d2b621e409d634929e7d09b059218a` keeps canonical journals at version 1 and uses version 2 for explicit legacy layout and member names. PR #93 head `c43cae9cd6adeac9a48fae36b34d5c4b203a9683` widened the reader's version-2 gate but added no canonical version-2 writer; the PR remains an unmerged draft. Repository history contains no published canonical version-2 writer or tag.

The journal contract remains version 1 for canonical records with implicit layout and version 2 for legacy records with explicit layout and exact member names. `JournalRecord::new` still emits version 1 for canonical transactions and version 2 for legacy transactions. Recovery rejects version 2 when it declares the canonical layout. A canonical-v2 writer or released consumer would provide new evidence for reconsidering this rule; none has been identified.

### Issue #14 Slice C execution record (2026-11-27)

Implementation uses clean baseline `836b1388a1abc811f3b1589004c6733ea7e0f086` in worktree `/Users/daniel/.codex/worktrees/issue-14-legacy-split-layouts/NSCB`, branch `codex/issue-14-legacy-split-layouts`.

The full local `make all` run on 2026-11-27 passed with 37 test-result groups: 2,205 passed, 0 failed, and 8 ignored. `cargo fmt --all -- --check` and `git diff --check` also passed. The content-policy check passed after this record was added.

LLVM 23.1.6 line coverage came from isolated executions of `journal_segment_names_follow_layout_specific_rules`, `mismatched_v2_legacy_stem_is_rejected_before_members_are_consumed`, `trusted_legacy_resolver_accepts_one_hundred_members_after_outer_bundle_relocation`, and `trusted_canonical_v1_split_remains_valid_after_directory_rename`. Of 17 executable lines added to production code, 15 were covered (88.2%). The two uncovered lines are `ok_or_else` fallbacks for a missing directory basename and an empty segment list. The production candidate reader canonicalizes the directory, and the manifest parser rejects empty segment lists before this function runs, so supported callers cannot reach those fallback paths. The v2 match and mismatch, canonical-v1 rename, and journal-v1/v2 decisions were exercised. This host coverage does not establish Windows consumer compatibility or PAC-6.

The task follows development-process release `2026.11.25`, revision `8e391636cb50f9bfe6e8def2d0f54eeb65d1d157`. The owner-dispatched qualification is [run 45612390118](https://github.com/danielbyon/development-process/actions/runs/45612390118), attempt 1, owner ID `327737`. The approved release context and bundle are artifacts `15020776261` and `15021765219`. The owner verified the release manifest, frozen context, and three provenance sidecars; their artifact and payload digests match the immutable release assets. This task needs no new pin or repeat qualification. NSC_BUILDER v0.99 is pinned separately at `92690c0137f520b6ee4d6c20b6f5abe8a3ce5738`.

GPT Repo MCP does not currently enroll this worktree. Its read-only root listing showed the primary checkout at `/Users/daniel/Projects/NSCB`, and the current-work-session lookup found no session. Codex client connection settings and MCP server lifecycle remain unchanged. Work proceeds manually under owner approval. CodeGraph and TokenSave are initialized for this branch, and Serena is active in the worktree.

PAC-6 requires output bytes produced by the pinned NSC_BUILDER v0.99 consumer and a matching source length and SHA-256. At commit `92690c0137f520b6ee4d6c20b6f5abe8a3ce5738`, `py/ztools/squirrel.py --joinfile` contains the join path, and `py/ztools/JOINER.bat` invokes it before a later rename step. Source inspection shows that the script derives `.xci` from `.xc0` and `.nsp` from `.ns0`, finds sibling parts in the same directory, sorts them, and copies their bytes in buffered reads. This is a compatibility hypothesis until the pinned consumer emits and verifies output.

An earlier isolated attempt used Python 3.10.22 on macOS 27.2 with a 9,499-byte synthetic source split into `synthetic.xc0` and `synthetic.xc1` at byte 1,731. The source SHA-256 was `b52469a9581c4d15f20420a015a763396a215f86b350a64296f933e8550fe36e`. It exited with `ModuleNotFoundError: No module named 'Crypto'`; the literal command was not retained, and no output was written. No dependency was installed. The upstream README specifies Windows, and the joiner assumes Windows drive-path behavior. This attempt does not satisfy PAC-6.

### PAC-6 Windows Sandbox follow-up (2026-11-27)

**Status: UNPROVEN.** The owner designated OBIGAMING as the Windows 11 qualification host. Codex lists an `NSCB OBIGAMING` remote project, confirming that a host connection exists, but this task has no remote shell. The local CUA surface is macOS (`noWindowsAvailable`), and this Mac's SSH lookup could not resolve OBIGAMING. No command ran on the host. Its Windows edition and build, virtualization state, Sandbox feature, available disk space, and usable command channel remain unverified. No Windows feature or machine setting was changed, and no reboot was requested.

Microsoft lists Windows Pro, Enterprise, Pro Education/SE, and Education as supported editions; Windows Home is unsupported. The installation guide requires enabled hardware virtualization, at least 4 GB RAM, two CPU cores, and 1 GB of free disk space, and recommends 8 GB RAM. The proposed production-size test needs about 16 GB free to retain its input and output for the `0xFFFF0000`-byte segment profile and working space. Enabling the optional feature requires an administrator and can require a restart. See Microsoft's [Windows Sandbox overview and edition table](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/) and [installation guide](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install).

The pinned source tree has no dependency lockfile or requirements file. A static import scan of 60 Python modules reachable from `squirrel.py` found candidate external imports including `Crypto`, `PIL`, `bs4`, `chardet`, `colorama`, `googletrans`, `pykakasi`, `requests`, `tqdm`, `ujson`, `urllib3`, `win32api`, `win32con`, and `zstandard`. The scan includes code paths not proven to run during `--joinfile`, so it is not a resolved dependency list. The pinned `File_chunk2.py` directly imports `Crypto.Cipher.AES`, `PIL.Image`, and `tqdm`; the earlier attempt confirms that its bare Python 3.10.22 environment lacked `Crypto`. Package versions and wheel hashes remain unresolved. No offline wheelhouse was prepared or installed.

Proposed host folders are `C:\NSCB-PAC6\input` and `C:\NSCB-PAC6\output`. The read-only input folder would hold a pinned source export without `.git`, a Python 3.10.22 installer, a version- and hash-verified offline wheelhouse, and deterministic synthetic-fixture scripts. The writable output folder would hold only consumer output and result logs. Neither folder should contain repository credentials, personal files, Nintendo key material, or production data.

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

Only the pinned input and a dedicated output folder are mapped. Networking and clipboard redirection are disabled. Writes to the output mapping persist on the host after the Sandbox closes, so keep that directory dedicated to this qualification. The settings follow Microsoft's [Sandbox configuration guide](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file). No `.wsb` file was launched.

Proposed procedure:

1. Run this read-only PowerShell preflight on OBIGAMING and save its output:
   ```powershell
   Get-ComputerInfo | Select-Object CsName, WindowsProductName, WindowsVersion, OsBuildNumber, CsTotalPhysicalMemory
   Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, VirtualizationFirmwareEnabled
   Get-CimInstance Win32_ComputerSystem | Select-Object Model, HypervisorPresent
   Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM | Select-Object FeatureName, State
   Get-PSDrive -Name C | Select-Object Used, Free
   Get-Command WindowsSandbox.exe, wsb -ErrorAction SilentlyContinue | Select-Object Name, Source
   Get-AppxPackage -Name WindowsSandbox | Select-Object Name, Version
   ```
   The Windows 11 24H2 Sandbox CLI can start and connect to a Sandbox. Its `exec` command requires an active user session and does not return process output, so scripts must write logs and digest results to the mapped output folder. See Microsoft's [Sandbox CLI reference](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-cli).

2. If Windows Sandbox is already enabled, launch the proposed `.wsb` file through a usable remote desktop session. Inside the Sandbox, install Python and the verified wheelhouse without network access. Copy the pinned source tree to Sandbox-local writable storage before running it because `squirrel.py` creates a database directory at startup.

3. Run the fixture generator inside the Sandbox to create synthetic `.xc0`–`.xc9` and `.ns0`–`.ns9` sets under `C:\PAC6\work\fixtures`. Record each source length and SHA-256. Invoke the pinned script from the Sandbox-local source copy, writing output to the mapped results folder and bypassing `JOINER.bat`'s later rename step:
   ```powershell
   C:\PAC6\python\python.exe C:\PAC6\work\NSC_BUILDER_v0.99\py\ztools\squirrel.py --joinfile C:\PAC6\work\fixtures\small-xc\synthetic.xc0 --ofolder C:\PAC6\output\small-xc --buffer 65536
   C:\PAC6\python\python.exe C:\PAC6\work\NSC_BUILDER_v0.99\py\ztools\squirrel.py --joinfile C:\PAC6\work\fixtures\small-ns\synthetic.ns0 --ofolder C:\PAC6\output\small-ns --buffer 65536
   ```
   The expected outputs are `synthetic.xci` and `synthetic.nsp`. A standard-library verifier should record output length and SHA-256 beside each source result. Repeat with production-size parts, including a nonempty terminal member, only after confirming sufficient host space. Preserve the consumer-emitted bytes and comparison logs in the mapped output folder. NSCB's resolver support through index 99 does not establish consumer support for those indexes.

The Codex project registry lists the OBIGAMING remote NSCB project, but this task cannot invoke commands in that session. The host preflight and PAC-6 run therefore remain pending. The owner can attach a command-capable remote shell to this task or run the read-only preflight and return its output. If Sandbox is not enabled, enabling it, changing virtualization settings, using administrator privileges, or rebooting requires separate owner authorization. PAC-6 remains UNPROVEN until the pinned consumer's output length and SHA-256 match the synthetic source.
