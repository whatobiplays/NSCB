# NSCB

NSCB is a Nintendo Switch content-file toolkit. It exists to inspect, verify, transform, package, extract, compress, restore, and move supported content while keeping device-management concerns narrow.

## Language

**Content file**:
A supported Nintendo Switch content container or archive, represented as a regular file or as a qualified Split set whose reconstructed bytes independently establish a supported Content family.
_Avoid_: game file, ROM

**Logical byte stream**:
An exact ordered sequence of bytes with a known length, independently of whether it is recognized Nintendo Switch Content.
_Avoid_: Content file, verified container

**Split set**:
A single logical byte stream represented by an ordered, complete collection of physical segments in a recognized split layout. It is Nintendo Switch Content only when independently recognized as such.
_Avoid_: separate content files, partial valid archive

**Candidate Split representation**:
A filesystem arrangement resembling a Split layout whose completeness and consistency have not yet been established. It is not a qualified Split set.
_Avoid_: partial valid Split set, qualified Content

**Qualified Split set**:
A Split set whose segment membership and exact reconstructed bytes are established by independently retained source evidence.
_Avoid_: plausible Split set, recognized Content

**Split manifest**:
A versioned declaration of a source's expected length and digest and the ordered physical segments intended to reproduce it. A manifest alone is not authoritative source evidence.
_Avoid_: input list, executable plan, trust certificate

**Split-set completeness evidence**:
Independently retained evidence that a Split set reconstructs the exact bytes and length of an observed source file. It makes no claim about that source's upstream provenance or authenticity.
_Avoid_: Content Verification, signature validity

**Local trust receipt**:
A revocable host-retained record linking a Split manifest to source evidence established during an authorized, completed Split operation. It is not a portable digital signature.
_Avoid_: signed manifest, authenticity certificate

**Content transformation**:
An operation that produces changed content or a changed container from one or more content files, such as repacking, conversion, container-aware Content splitting, trimming, patching, compression, decompression, or restoration.
_Avoid_: mode, processing mode

**Generic byte-stream splitting**:
A byte-preserving filesystem operation that divides any explicitly selected regular file into ordered segments. It requires no Content Recognition and establishes no Nintendo Content identity, authenticity, Verification, or eligibility for container-aware operations.
_Avoid_: Content transformation, container-aware Content splitting

**Container-aware Content splitting**:
A Content transformation that splits supported package or container input, or input selected through an extracted-content manifest, under ADR 0022's eligibility rules. A standalone loose NCA is ineligible for this transformation.
_Avoid_: generic byte-stream splitting, arbitrary file splitting

**Content patch**:
An explicitly requested content transformation that changes a compatibility, rights, metadata, or composition property, such as title-rights removal, delta removal, RSV/keygeneration lowering, update-partition removal, or linked-account requirement patching.
_Avoid_: cleaning, safe mode, recommended patch profile

**Container Probe**:
Separately requested, read-only validation and reporting of supported outer-container framing. It does not interpret embedded content or establish content identity.
_Avoid_: Inspection, Verification

**Inspection**:
Read-only, content-aware interpretation of supported content and metadata.
_Avoid_: file info mode

**Verification**:
A distinct read-only operation that validates a content file's structure, integrity, signatures, hashes, or cryptographic metadata where applicable.
_Avoid_: checking

**Verification profile**:
A named, typed scope of verification checks. v1 defines Full, which includes every applicable structural, integrity, hash, signature, and cryptographic check, and Structural, which validates container structure and relationships without claiming cryptographic authenticity. Verification succeeds only when every applicable check in the selected profile runs and passes.
_Avoid_: verification level, best-effort verification

**Modification-qualified device write**:
An explicitly authorized Installation or Storage transfer of intentionally modified Content, based on the file's recognized modification semantics and all remaining applicable integrity/compatibility checks rather than the identity of the producing tool. It never treats invalid original signatures as Full Verification success.
_Avoid_: Full Verification, ignoring signature errors, unrestricted device transfer

**Extraction**:
Materializing selected embedded content or filesystem data from a content file without changing the source.
_Avoid_: advanced mode

**Extracted-content manifest**:
A versioned stable description of extracted logical structure, content roles or identities, and relative extracted paths. It can be used later to repack current extracted files, including intentionally edited files.
_Avoid_: executable plan, immutable extraction hash list

**Restoration**:
Reconstructing original content, when sufficient evidence exists, from content that was previously transformed in a reversible way.
_Avoid_: undo

**Rename/Sanitize**:
A filesystem-organization operation that deterministically changes a Content file's path or filename without changing its content bytes. Sanitization removes or replaces path components that are unsafe or incompatible with the destination platform; romanization remains a separate explicit choice.
_Avoid_: content transformation, repack, implicit romanization

**Output directory**:
The user-visible directory where standalone NSCB publishes validated results. The standalone configuration field is `output_dir`; its default is `NSCB_output` under the current user's platform Documents directory.
_Avoid_: workspace, temp directory, output root

**Workspace**:
Disposable storage used for intermediate execution artifacts before validated publication. Workspace data is not user output and may be cleaned when NSCB can prove it owns the abandoned artifacts.
_Avoid_: output directory, published results

**Operation Plan**:
A fully resolved, immutable specification of a Job's work that contains the decisions and context needed to execute without further user input or prompting, including selected inputs, outputs, operations, providers, prerequisites, and conflict policy.
_Avoid_: dry run, preview, interactive execution recipe

**Plan snapshot**:
A read-only serialized representation of an Operation Plan for inspection or automation output. A Plan snapshot is not itself executable or a replay contract.
_Avoid_: saved executable plan

**Job**:
A user-requested unit of work containing one or more content operations that can be tracked as a whole.
_Avoid_: work list, queued text list

**Completed with issues**:
A terminal Job outcome for independent-item work where at least one item completed successfully and at least one item failed. It is not an overall success outcome.
_Avoid_: partial success

**Interrupted Job**:
A prior job run that was active when its owning process ended and therefore reached a terminal state without completing, failing, or being cancelled normally.
_Avoid_: paused job, resumable job

**No changes required**:
A successful outcome for an explicitly requested transformation whose preconditions are satisfied but whose target change is already unnecessary. It does not imply that a replacement artifact was created.
_Avoid_: skipped, failed eligibility

**Already up to date**:
A successful outcome when an existing destination is positively proven identical to the artifact the operation intends to publish, so rewriting it is unnecessary.
_Avoid_: overwrite skipped, assumed identical

**Metadata enrichment**:
Optional external catalog information layered onto metadata derived from the content itself, such as regional descriptions, images, release data, or update/DLC availability. Enrichment can improve the experience but is never required for core local operations.
_Avoid_: authoritative metadata, required metadata service

**Device responder**:
Switch-side software that exposes host-accessible device capabilities such as installation, storage transfer, inventory, or dumping. The responder is a user-owned prerequisite rather than software managed by NSCB.
_Avoid_: device driver, NSCB service

**Device transport**:
The host-side mechanism used to communicate with a Device responder. Different supported platforms may use different transport adapters while exposing the same NSCB device semantics.
_Avoid_: device protocol, responder

**Device protocol**:
The host-to-responder communication contract NSCB depends on, including its transport and responder-specific capability semantics.
_Avoid_: responder implementation

**Device capability set**:
The operations a currently connected Switch and its compatible responder can demonstrably support for the active connection, such as installation, storage transfer, inventory, or dumping. Planning relies on capabilities rather than assuming features from a responder name or version alone.
_Avoid_: device mode, assumed responder features

**Installation**:
Sending supported content to a connected Switch through the responder's installation pathway.
_Avoid_: device transfer, send

**Storage transfer**:
Copying supported content to an exposed destination on connected Switch storage without implying installation.
_Avoid_: install, generic send

**Dump**:
Copying responder-exposed device data from a connected Switch to host storage through a qualified NSCB dump/backup capability. Dump may include supported content and non-content data such as save data when that capability is modeled and qualified by NSCB.
_Avoid_: generic device export

**Legacy implementation**:
The whatobiplays/NSC_BUILDER codebase used as behavioral evidence and reference material, not as an architectural or compatibility contract.
_Avoid_: canonical implementation
