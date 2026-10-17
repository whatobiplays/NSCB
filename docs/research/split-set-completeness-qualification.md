# Split-set completeness qualification

## Status and scope

This is a research result for NSCB Issue #6 at baseline `4b5b77a7cd240227b8cc22f1f48764e155b1973a`. It does not change production behavior or the existing authority contracts. Accepted ADR 0028 now governs future evidence-backed qualification, but it does not activate positive Split resolution; the current resolver continues returning `unsupported_split_layout` for suspected Split inputs.

The central result is that numbering, visible member count, file sizes, a valid container prefix, and a canonical archive marker can establish useful structural facts, but none of the reviewed layouts independently tells a host that it has seen the actual last part. Synthetic complete/incomplete pairs with byte-for-byte identical visible members are direct counterexamples to any rule based only on those observations. The paired results and the wider adversarial matrix are in [the evidence matrix](split-set-completeness-evidence-matrix.md).

The XCI `ValidDataEndAddress` is a promising, narrow layout-native evidence source when authenticated. It is not presently enough to enable Split acceptance: its endpoint semantics and producer behavior need qualification; the header signature must actually be verified; and a valid header does not integrity-check the full payload. No ADR draft was included in the original spike because the research had not settled those product and trust choices. Accepted ADR 0028 subsequently chose a source-backed manifest and local-receipt architecture; the empirical findings and limitations in this document remain the evidence record for that decision.

## Evidence terms

These terms keep the fixture author’s knowledge separate from what a resolver can observe:

1. **Fixture ground truth** is the scenario label assigned by the experiment harness, such as “expected part count is three.” It exists for evaluation only and is unavailable to the resolver.
2. **Direct observations** are facts available from the selected filesystem and bytes: names, entry types, file identities, observed lengths, hashes, attributes, and parsed fields.
3. **Structural consistency** means the observed members have an allowed shape and the bytes read so far satisfy parser bounds. It does not establish that the set has no missing terminal member.
4. **Terminal completeness evidence** independently states where the logical stream ends or how many ordered members must exist, and is checked against the observed members.
5. **Authenticity** establishes who or what vouched for that terminal evidence. A digest proves equality to the digest it is compared with; it does not establish who produced the digest or whether the expected value describes the intended complete source.
6. **Source stability** establishes that the files consumed after resolution are the same bytes that were qualified. Path and size observations alone do not provide this guarantee.

Fixture labels are never counted as terminal evidence. If two cases expose identical names, bytes, sizes, and relevant metadata but have different fixture ground truth, a deterministic resolver without an independent oracle must return the same result for both. If that result is success, one case is falsely accepted; if it is rejection, the heuristic has not established completeness.

## Existing NSCB boundary

The current input resolver returns ordered physical segments and selection provenance, but does not read content bytes or recognize a content family. Its supported v1 input is one physical segment. Suspected numeric and legacy suffix layouts remain fail-closed under the accepted Issue #6 implementation.

The recognizer and PFS0 probe accept internal `Read + Seek` readers, so an ordered virtual reader could present multiple already-qualified files as one logical stream without building a large concatenated temporary file. That trait boundary answers only the parser-integration question. It cannot supply a missing part count or prove that the final segment is present.

The PFS0 probe checks each declared span against the observed payload size and rejects spans that run beyond it. It does not require declared spans to cover all payload bytes through EOF; trailing bytes and gaps can remain. A structurally valid observed prefix can therefore pass when the omitted tail was not referenced by a declared span. See [the PFS0 probe](../../src/pfs0.rs) and [container probe contract](../container-probe.md).

The XCI recognizer checks bounded HFS0 structure against the caller-supplied observed size. It does not authenticate the XCI header signature. For compressed card images it uses `ValidDataEndAddress` as a geometry bound; for ordinary XCI it does not use that field to require an exact observed EOF. These checks establish a supported structural profile, not completeness of a multi-file set. See [the recognizer](../../src/recognition.rs).

Resolution also records paths and sizes rather than retaining immutable file snapshots. A later open can see bytes changed after discovery, including same-size replacements. Any future streaming design must qualify path confinement, regular-file identity, aggregate parser budgets, offset overflow, and source mutation separately.

## Canonical FAT32 concatenation layout

### Reviewed conventions

The pinned [libnx filesystem API](https://github.com/switchbrew/libnx/blob/20cbcfd90567f7bf84df7725f27e345e2164fa6b/nx/include/switch/services/fs.h) defines `FsCreateOption_BigFile` as creating a `ConcatenationFile` directory with the archive bit, instead of a regular file. The [nxdumptool helper](https://github.com/DarkMatterCore/nxdumptool/blob/ade1a481121498ec649fbc832afe733050790acd/source/core/nxdt_utils.c#L825-L841) creates this object with initial size zero before subsequent writes. The nxdumptool maintainer describes numbered directory parts as the FAT32 representation used to mimic Horizon’s concatenation file in [discussion #143](https://github.com/DarkMatterCore/nxdumptool/discussions/143).

The pinned [GCDumpTool README](https://github.com/DDinghoya/gcdumptool/blob/211cca9945f5849940376347509d10c0151f380b/README.md) documents `00`, `01`, … members and says the archive attribute is set when the directory is created. It also describes different part-size policies for XCI/raw and NSP output. This is one producer’s behavior, not a universal segment-size contract.

These sources support the following limited conclusions:

- The marker identifies the representation as a Horizon-style concatenation directory. It is not a completion bit: reviewed producers set it before all bytes have been written.
- The visible sequence can be enumerated and its internal gaps can be detected once a grammar is selected. Contiguous numbering does not state the expected final index.
- The reviewed creation route supplies no expected final part count or logical byte length to the filesystem create call. This does not establish that no other producer or format version records such evidence.
- Attribute preservation across macOS, Linux, Windows, FAT32-compatible transfer tools, and archive/extraction workflows was not tested. Until a cross-platform matrix establishes preservation, absence or presence of this attribute on a host cannot be treated as a portable proof.

**Conclusion: Insufficient evidence.** The marker plus a contiguous visible sequence is structural consistency only. A complete one-part directory and an interrupted one-part prefix can expose identical observations; the same is true for any visible multi-part prefix.

## Legacy `.xcN` and `.nsN` layouts

The original public [NSC_BUILDER v0.99 source](https://github.com/julesontheroad/NSC_BUILDER/tree/92690c0137f520b6ee4d6c20b6f5abe8a3ce5738) provides behavioral evidence for `.xc0`, `.xc1`, … and `.ns0`, `.ns1`, … names. Its `File_chunk.py` reader searches the sibling directory for matching numbered members, collects the files it finds, sorts them, and chains the found streams. The reviewed reader path has no independently recorded expected final suffix, total length, or set digest. Its behavior is not a format guarantee and is not used as architecture authority.

This approach can detect visible gaps if it insists on contiguous indexes, but a missing final member leaves no later index to reveal the gap. The member names and ordering alone do not distinguish a complete set ending at `.xc1` from an incomplete set whose `.xc2` is absent. A short or full-sized final-looking part does not change that conclusion without a qualified producer-specific length rule.

The pinned [hactool CLI documentation](https://github.com/SciresM/hactool/blob/1d64a83450e025622f3468c28fc4164dad2c5ef6/README.md) documents one `<file>` input and verification options; the reviewed interface does not document a general numbered-sibling Split-set contract. This is a statement about the reviewed source, not proof that every hactool-related consumer rejects every split form.

**Conclusion: Insufficient evidence.** The reviewed legacy reader can reconstruct the bytes of members it finds, but reconstruction is not evidence that no later member is missing. Other legacy producers and consumers need separate pinned review before NSCB can claim broader compatibility.

## XCI end-address evidence: a candidate, not an acceptance rule

The [Switchbrew XCI format reference](https://www.switchbrew.org/wiki/XCI) describes `ValidDataEndAddress` as a 32-bit page address in 0x200-byte gamecard units and places it inside a signed card header. The pinned [hactool XCI implementation](https://github.com/SciresM/hactool/blob/1d64a83450e025622f3468c28fc4164dad2c5ef6/xci.c) verifies an RSA signature over the card-header bytes when `--verify` is requested. Its pinned header structure calls the corresponding older field `cart_size`, illustrating that field mapping and generation scope must be resolved before treating this as a stable cross-version contract.

An authenticated end address could potentially provide positive terminal evidence for a narrow XCI profile: the reader would need to validate the header signature, interpret the field for that exact profile, check the complete ordered segment stream against that endpoint, and establish how permitted card-capacity padding relates to the logical XCI EOF. That would address expected extent; it would not authenticate every payload byte or prove that equal-length members were not replaced. HFS0/NCA digests would need separate analysis of what bytes they cover.

NSCB’s current recognizer does not verify this signature. For ordinary XCI, it does not use the field as an exact EOF check. Synthetic experiments in this spike did not include an authenticated XCI header, and no legally safe signed fixture was available. Therefore this is a research lead only.

**Conclusion: Insufficient evidence.** Do not treat the field name or an unsigned value as proof. A future XCI-only qualification may be possible if header authenticity, endpoint semantics, padding, transfer representation, producer variants, and payload integrity are explicitly bounded and tested.

## Completeness proof obligations

| Obligation | What the resolver needs | Current finding |
| --- | --- | --- |
| Segment discovery | Deterministic, bounded enumeration under a specified grammar | Feasible for visible entries; grammar differs by layout and producer |
| Sequence consistency | Reject gaps, duplicate identities, illegal sizes, order ambiguity, and overlap | Feasible only after part-size and numbering rules are selected; aliases need filesystem identity handling |
| Terminal completeness | An independent expected terminal index or exact logical endpoint | Not established for either reviewed Split layout; authenticated XCI end address remains an unqualified candidate |
| Logical-file integrity | Evidence that observed bytes match the intended logical file | A count/length alone is insufficient; hashes need a trusted expected value and precise coverage |
| Source stability | Ensure the parser reads the same qualified bytes | Not provided by path and size metadata; needs stable handles plus mutation/integrity policy or an immutable snapshot |

Structural parsing supplies bounds and consistency checks, not a missing expected end. PFS0 spans may leave trailing data. XCI and compressed XCI have profile-specific structure, but the currently implemented checks do not turn segment enumeration into an authenticated end-of-set rule. Padding, trimmed images, compressed representations, and producer-specific final-part sizing must each be specified before a length comparison can be normative.

## Proof-policy comparison

### Option A — Layout-native proof

This can be safe only for a narrowly specified profile where the format itself supplies independently verifiable terminal evidence. The signed XCI header is the strongest lead found in this spike. It still requires an explicit version/profile mapping, signature-verification policy, exact endpoint and padding semantics, ordered part grammar, and a defined integrity scope. The generic FAT32 concatenation marker does not qualify: it marks representation and can be present during creation, but carries no terminal count in the reviewed creation path. Generic PFS0 extents likewise do not prove that the physical stream ends at the final declared span.

Do not generalize an XCI-only proof to `.nsN`, `.xcN`, NCZ/XCZ, or arbitrary canonical directories. Each layout must pass its own qualification.

### Option B — Explicit manifest-backed proof

A separate, versioned manifest could identify the logical object and record:

- Exact ordered member names or stable member identities and expected segment count.
- Expected length of every segment and exact total logical length.
- A digest for each segment and/or for the reconstructed logical stream, with a specified algorithm and byte coverage.
- Format/profile identity, manifest version, and any permitted padding or trimming rule.
- Producer/completion provenance and a publication rule that writes the manifest only after all expected bytes and digests have been checked.

The manifest values must come from a trusted source of completeness. A manifest generated by scanning currently visible parts can faithfully describe a truncated prefix and is not independent evidence. A trusted producer can calculate expected length and count from its complete source, verify all output bytes, then publish an authenticated completion record atomically. Alternatively, a host may explicitly trust a user-supplied signed manifest under a documented key policy. Hashes prove the observed bytes match the manifest; a signature or an explicit trusted-source rule establishes who vouched for the manifest. Neither digest nor signature alone proves that the producer’s declared source was itself the intended complete Content unless that provenance is part of the trust policy.

Do not repurpose `nscb.input_list` v1. It selects paths and is not an integrity or execution manifest. Any future manifest needs its own schema, versioning, required-feature semantics, stable errors, size limits, duplicate-key policy, and additive compatibility plan.

### Option C — Continued fail-closed handling

Continue returning `unsupported_split_layout` for suspected Split inputs unless one of the explicitly qualified proof profiles is enabled. This matches the current contract and is the only option supported as an immediate implementation policy by this evidence.

## Streaming-reader feasibility and constraints

**Feasibility finding:** a bounded virtual reader can implement `Read + Seek` over already-qualified open file handles and reuse the internal PFS0 and content parsers. It need not concatenate large segments to a temporary file. The spike built a disposable in-memory prototype and ran two focused tests covering cross-segment reads, empty segments, EOF and bounded seeks, and checked cumulative-length overflow. The prototype did not exercise real file handles, NSCB parsers, mutation, confinement, or platform behavior, and no repository or production interface was added.

Before such a reader is implemented, its acceptance tests need to cover:

1. Checked prefix offsets and total length, including overflow and configured segment-count limits.
2. Reads across boundaries, reads at EOF, zero-length segments, and exact-boundary seeks.
3. `Start`, `Current`, and `End` seeks, including negative offsets and arithmetic overflow; the accepted out-of-range behavior must be documented.
4. Regular-file and identity checks for every opened member, symlink confinement, and cycle/alias behavior during discovery.
5. Parser limits aggregated across the virtual stream rather than reset per segment; existing metadata, read, entry, name, and work budgets remain in force.
6. Mutation after discovery, including same-size replacement or in-place edits. Holding handles prevents path retargeting but does not make contents immutable. A trusted digest checked over the bytes actually consumed or a private immutable snapshot may be needed.

These are unresolved execution qualifications, not reasons to alter the existing parser API now.

## Public-contract and acceptance implications

`ResolvedInput` already preserves an ordered `segments` vector and selection provenance, and its public types are designed for additive evolution. Preserve that v1 shape for non-Split inputs. A future successful Split result must not appear without its positive completeness basis; the proof type, provenance, and JSON representation need a separate compatibility review.

Keep the v1 JSON input list as path-selection data. Do not silently extend its meaning into an integrity manifest. Keep suspected unsupported layouts as typed input-resolution failures under ADR 0023’s exit-3 class unless a reviewed, additive error contract establishes otherwise. Do not change the accepted Split-set definition or recognition/Verification authority boundaries.

The original Delegation v3 Split-dependent acceptance criteria remain blocked. This spike does not satisfy Issue #6’s requirement that selecting any valid segment resolve exactly one complete Split set.

## Provisional recommendation and architecture gate

1. **Immediate policy:** retain fail-closed resolution for canonical and legacy Split layouts. Do not infer a terminal part from numbering, sequence continuity, short/full part size, archive attribute, prefix parsing, PFS0 spans, or fixture truth.
2. **Research priority:** qualify the signed XCI end-address path as a possible XCI-only proof profile, including field-version mapping, exact extent and padding semantics, safe fixtures, signature verification, and payload-integrity limits. Do not extend it to other formats by analogy.
3. **Manifest direction:** if no layout-native evidence proves completion for a target layout, consider a new, separately versioned manifest contract only when its length/count/hash values have a defined trusted producer or signature policy.
4. **Before implementation:** decide which trust model is acceptable, whether XCI-only proof may be scoped separately, whether a new manifest is in scope, what a successful result must expose about its proof, and how mutation during later operations is prevented or detected.

At the time of the spike, no ADR was proposed at this gate. Accepted ADR 0028 now resolves the architecture decision; this historical recommendation does not itself authorize implementation or alter production behavior.

## Sources reviewed

All source code links below are pinned where a commit exists. The Switchbrew XCI page is a living format reference and should be rechecked during any future implementation.

1. [libnx filesystem API at `20cbcfd`](https://github.com/switchbrew/libnx/blob/20cbcfd90567f7bf84df7725f27e345e2164fa6b/nx/include/switch/services/fs.h) — `FsCreateOption_BigFile` and concatenation-file semantics.
2. [nxdumptool helper at `ade1a48`](https://github.com/DarkMatterCore/nxdumptool/blob/ade1a481121498ec649fbc832afe733050790acd/source/core/nxdt_utils.c) and [maintainer discussion #143](https://github.com/DarkMatterCore/nxdumptool/discussions/143) — canonical directory creation and usage context.
3. [GCDumpTool README at `211cca9`](https://github.com/DDinghoya/gcdumptool/blob/211cca9945f5849940376347509d10c0151f380b/README.md) — numbered parts, early archive attribute, and differing part-size policies.
4. [NSC_BUILDER v0.99 reader at `92690c0`](https://github.com/julesontheroad/NSC_BUILDER/blob/92690c0137f520b6ee4d6c20b6f5abe8a3ce5738/py/ztools/lib/File_chunk.py) — legacy reader behavior only, not authority.
5. [hactool CLI at `1d64a83`](https://github.com/SciresM/hactool/blob/1d64a83450e025622f3468c28fc4164dad2c5ef6/README.md), [XCI structure](https://github.com/SciresM/hactool/blob/1d64a83450e025622f3468c28fc4164dad2c5ef6/xci.h), and [XCI verifier](https://github.com/SciresM/hactool/blob/1d64a83450e025622f3468c28fc4164dad2c5ef6/xci.c) — single-file interface and signed-header verification.
6. [Switchbrew XCI format reference](https://www.switchbrew.org/wiki/XCI) — `ValidDataEndAddress` units and header placement.
7. NSCB baseline source: [input resolution](../../src/input_resolution.rs), [PFS0 probe](../../src/pfs0.rs), [recognition](../../src/recognition.rs), and [input-selection contract](../input-selection.md).
