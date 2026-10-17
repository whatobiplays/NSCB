---
status: accepted
---

# Qualify Split sets from independently retained source evidence

A Split set is a representation of a logical byte stream, not proof that its underlying bytes constitute recognized Nintendo Switch Content. NSCB will resolve a canonical numbered directory as one qualified input only when all listed physical segments reconstruct the exact byte length and SHA-256 digest of a known single-file source, and independently retained host-owned local evidence establishes that those expectations were recorded during an NSCB-controlled, completed Split operation. The adjacent, unsigned manifest is a portable consistency declaration, not its own trust anchor. This prevents missing terminal segments from being accepted merely because surviving names, sizes, archive attributes, or structural prefixes appear plausible. The threat model addresses accidental loss/corruption; it does not claim adversarial source authenticity or resistance to manipulation of host-controlled state.

Q37 ([accepted decision ledger](../research/split-set-contract-decisions-01-46.md)) permits generic byte-stream splitting: a byte-preserving filesystem operation that accepts any explicitly selected regular file, including a loose NCA, without Content Recognition. This operation establishes no Nintendo Content identity, authenticity, Verification, or package-operation eligibility. Container-aware Content splitting remains subject to ADR 0022; a standalone loose NCA remains ineligible for that transformation.

The first supported representation is the canonical FAT32-style directory containing contiguous, two-digit parts `00` through at most `99` (one-part sets allowed), with a deterministic adjacent `*.nscb-split.json` sidecar. Legacy `.xcN`/`.nsN`, manifest-free third-party sets, and any layout without independently established source evidence remain fail-closed. Each versioned manifest binds an exact ordered set of basenames, sizes, per-part SHA-256 hashes, original-source byte length, and whole-stream SHA-256. Unlisted, unrelated directory metadata is ignored, but unlisted Split-like members and segment symlinks or aliases are rejected. Selecting any recognized member, or the containing directory, deterministically identifies its one sidecar and one logical input. Directory aliases use the existing explicit traversal permission and locate evidence beside the actual resolved target.

Trust receipts belong to an explicit host-supplied durable store, never implicit global Engine state. Receipt identity binds the exact published manifest bytes and source evidence, not an absolute path, permitting relocation and byte-identical copies on the same host. Receipts survive missing or unmounted filesystems and are revoked only explicitly, per manifest identity. Transfer to an unrelated host is unsupported in v1 without independently established trust; copying an unsigned sidecar is not sufficient. Restoration of an independently trusted same-host backup is permitted. Requalification after revocation requires a new authorized source-backed Split operation; the original single file need not be retained after successful publication.

The source and resulting parts are checked with bounded streaming. Full part and whole-stream hash validation is required before a Split input is returned as successfully qualified; content-aware recognition, container validation, and cryptographic Verification remain separate operations. Execution revalidates its inputs and detects mutation during use, obtaining a verified snapshot whenever irreversible effects cannot safely await end-of-stream validation. Progress and cancellation use the established host-owned execution semantics. The public Rust and JSON surfaces evolve additively with stable typed evidence and failure codes under ADRs 0010, 0023, 0026, and 0027.

A Split operation uses staged, validated, ownership-tracked artifacts and exclusive destination coordination. It durably publishes the sidecar before making an atomic local trust-receipt commit the last qualification step. Cancellation before that commit leaves no success claim; cancellation arriving after the commit cannot retroactively cancel a completed result. Interrupted, unqualified artifacts may be automatically removed only when durable ownership records prove their identity and unchanged state; completed published user data and unrelated or unproven artifacts are never pruned. No crash recovery is permitted to promote an untrusted sidecar into trust. Output conflicts are governed explicitly and source files are never modified.

The detailed architecture contract, qualification tests, and rollout seams are specified in [Split-set evidence contract](../architecture/split-set-evidence-contract.md) and [Split-set contract acceptance scenarios](../testing/split-set-contract-acceptance.md). This ADR is **Accepted** as the governing Split-evidence architecture, not as an assertion of completed implementation. It does not activate production Split acceptance. It narrows the future implementation of Issue #6's resolver and evidence seam; Issue #9 owns generalized staged publication and Issue #14 owns user-facing FAT32 Split output.

## Considered alternatives

- **Infer completeness from numbered parts or archive attributes:** rejected; indistinguishable complete and truncated sets exist.
- **Treat a matching unsigned sidecar as authoritative:** rejected; it can describe an already incomplete source.
- **Require signatures, keys, or global Engine persistence:** deferred; unnecessary for the selected accidental-corruption/local-trust v1 threat model and inconsistent with host-owned lifecycle.
- **Authenticate a subset of XCI headers for manifest-free acceptance:** separate future qualification; no supported proof policy yet.

## Consequences

- Imported third-party or cross-host Split sets lacking qualified local evidence are rejected even if their bytes are structurally readable.
- The sidecar is not a JSON batch-input list, Operation Plan, Plan snapshot, or assertion of recognized/verified Nintendo Switch Content.
- Source-backed evidence issuance must be designed as an independent, testable seam before Issue #14's user-facing Split writer, avoiding an Issue #6 -> #14 -> #6 dependency cycle.
- ADR 0013's protection for **completed published user data** remains intact; any ownership-safe automatic cleanup exception must apply only to **uncommitted provisional artifacts**, and this distinction must be recorded explicitly when implementation changes ADR 0013.
