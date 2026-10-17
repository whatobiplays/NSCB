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
| Cancellation during source/segment hashing | Exit 6 or typed cancellation, no successful Split input, stdout machine output remains valid |
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

  Every nonempty final part is exactly the remaining 1 through `S` bytes; exact-boundary inputs have no empty terminal part. The producer accepts at most 100 parts (`00`–`99`). Configured sizes smaller than `S` remain unavailable unless the selected size has passed the documented canonical-consumer interoperability qualification.

## Acceptance gates

1. **Producer-independent resolver tests:** Construct synthetic unsplit source bytes, generate trusted fixtures using an isolated test-only evidence issuer that independently retains source length/digest, then select any segment. Negative fixtures must not manufacture proof from the parts themselves.
2. **Virtual reader:** Exercise real temporary regular files, cross-part `Read + Seek`, exact EOF, integer overflow, short reads, metadata changes, reparse points, file-handle replacement, and parser use. In-memory mock-only tests are insufficient for production qualification.
3. **Publication:** Exercise interruption at every before/after-write, fsync, rename, sidecar publication, and receipt-commit transition. Test ownership-safe cleanup and refusal to delete modified/user-added files; prove source untouched.
4. **Public compatibility:** Existing `resolve` CLI and JSON input list fixtures remain unchanged. Additive Rust/JSON fields are accepted by consumers; versioning and exit classes conform to ADRs 0023 and 0026. All error messages come from localized resources.
5. **Supported host platforms:** Explicitly qualify macOS arm64, Linux x86_64/aarch64, and any additional supported platform in the repository's release matrix. Characterize FAT archive attribute handling separately from source-byte qualification.
6. **Worktree governance:** All validation and review tools must bind the exact implementation worktree. Never fabricate or retrofit an old Delegation result; complete separate attestation as authorized.

## Issue sequencing acceptance

- Issue #6 can close only after the positive canonical resolver, local evidence qualification seam, independently derived test fixtures, safe failure cases, and public compatibility gates are implemented and reviewed. Do **not** pretend production user-facing Split output exists simply because test-only trusted fixtures work.
- Issue #9 implements the governed Plan/execution/staged-output publication foundation needed by producer logic.
- Issue #14 produces the real canonical FAT32 Split set and durable receipt during an NSCB-owned source-backed Split operation. Legacy compatibility remains a separate positive-qualification obligation or requires explicitly approved ticket rescoping, never silent default support.
