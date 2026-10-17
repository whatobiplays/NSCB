# Split-set contract decision ledger

**Status:** Approved decision record under Accepted ADR 0028; not a declaration of implemented behavior. Decisions 1-46 reflect the user's choices in the design interview. The two decision intersections called out below are deliberate and must be preserved in implementation.

| Q | Selection | Resolved decision |
|---:|:---:|---|
| 1 | A | Successful Split reconstruction equals the length and bytes of a known single-file source |
| 2 | C | Trusted and untrusted evidence are distinct; untrusted declarations do not qualify |
| 3 | A | Canonical FAT32-style directory layout first; legacy later |
| 4 | A | Accidental-loss/corruption threat model; no adversarial authentication requirement |
| 5 | A | Establish source evidence only during an NSCB-controlled original-source Split |
| 6 | A | Adjacent sidecar outside numbered-parts directory |
| 7 | B | Whole-source and individual segment SHA-256 digests |
| 8 | A | Independent local trust receipt anchors sidecar to observed source |
| 9 | A | Deterministic sibling sidecar lookup |
| 10 | A | Typed, actionable failure when evidence absent |
| 11 | A | Verify written output fully before publishing qualification evidence |
| 12 | A | v1 local trust; no implicit cross-machine portability |
| 13 | A | Host-owned store; no hidden Engine persistence |
| 14 | A | Independent additive versioned sidecar schema |
| 15 | A | Full hash validation before successful Split resolution |
| 16 | A | Strict successful resolution with typed completeness evidence |
| 17 | A | Manifest/content-addressed rather than absolute-path identity |
| 18 | A | Revalidate at execution; protect against changes during use |
| 19 | A | Failure between sidecar and receipt remains unqualified; no trust recovery |
| 20 | A | Small set of stable typed Split failures |
| 21 | A | Original single-file source can be deleted after qualification |
| 22 | A | Strict `00`..`99` contiguous naming, maximum 100 parts |
| 23 | A | One-part `00` sets allowed with qualifying evidence |
| 24 | C | Ignore unrelated unlisted files such as filesystem metadata |
| 25 | A | Relative segment names and exact-manifest-byte content-addressed identity |
| 26 | A | Explicit output conflict policy; no silent overwrite |
| 27 | A | Reject unlisted Split-like numbered members even though unrelated files are ignored |
| 28 | A | Explicit local receipt revocation, not automatic removal on path disappearance |
| 29 | A | Exclusive destination-scoped publication coordination and atomic receipt updates |
| 30 | B | Automatically clean interrupted **provably owned, uncommitted** artifacts |
| 31 | A | Commit durable local trust receipt last; success only thereafter |
| 32 | A | Durable ownership journal before creating artifacts; clean unchanged owned data only |
| 33 | A | Retained original-file identity and post-split revalidation |
| 34 | A | Fail closed on store loss; permit trusted same-host backup restore |
| 35 | A | Real regular-file segments, no member symlinks/aliases |
| 36 | A | Explicit host-supplied trust-store capability through Engine boundary |
| 37 | B | Explicit regular files can be split without Nintendo content recognition |
| 38 | A | Deterministic qualified FAT32-friendly default; configurable qualified smaller sizes |
| 39 | A | Minimal manifest with version/kind, source and per-segment integrity |
| 40 | A | Bounded streaming with progress and cancellation |
| 41 | A | Existing exit classes preserved with additive Split error codes |
| 42 | A | Qualified logical byte stream is independent from recognized Nintendo Content |
| 43 | A | Revocation per exact manifest identity, affecting identical copies only |
| 44 | A | Requalification after revocation requires new source-backed evidence |
| 45 | A | Committed receipt wins over late cancellation |
| 46 | A | Permitted directory alias resolves to actual target's sibling sidecar |

## Intersections and defaults resolved without new product decisions

- **Q24 + Q27:** Ignore `.DS_Store`/unrelated files but reject unlisted Split-like numbered members. A directory is not invalid merely for containing unrelated sidecars.
- **Q19 + Q30 + Q32:** No automatic trust issuance or recovery after a crash; automatic cleanup *is* allowed for uncommitted artifacts with durable, verified ownership. Never prune completed user data or unknown/modified artifacts.
- **Q17 + Q25 + Q43:** Trust identity uses exact manifest bytes and independently recorded source evidence; moving directory and sidecar together is allowed, but editing the sidecar requires a new authorized source-backed issuance.
- **Q4 + Q8 + Q12 + Q34:** A locally retained receipt is a declared trust boundary in an accidental-corruption model, not signed cryptographic origin proof. Same-host trusted backup restoration is permitted; untrusted cross-host copying is not.
- **Q29 + ADR 0008:** Coordination is scoped to the destination and atomic publication, not a machine-wide exclusive Engine lock.
- **Q37 + Q42:** Generic byte-level splitting does not reclassify arbitrary files as Nintendo Content; content-specific operations still require established eligibility.
- **Q40 + ADR 0011/0023:** Progress is latest-value host state; machine stdout stays a single valid structured document. Cancellation uses existing class 6.
- **Q38 + canonical interoperability:** Choose `0xFFFF0000` bytes as the proposed default, reflecting upstream concatenation support; configurable smaller part sizes are admitted only when independently tested to interoperate with the canonical target, not merely because each part fits FAT32.
- **Issue #6, #9, #14:** Issue #6 must establish a testable canonical resolver/evidence seam; #9 supplies staged publication and Plans; #14 supplies the complete production Split writer. This keeps the tracked dependency direction acyclic.

**Still required:** Repository integration and qualification-source reconciliation, public-wire release compatibility review, implementation, and platform-specific tests. Architecture acceptance does not complete Issue #6. No further unresolved product-level choices were identified.
