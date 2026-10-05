# NSCB

NSCB is a Nintendo Switch content-file toolkit. It exists to inspect, verify, transform, package, extract, compress, restore, and move supported content while keeping device-management concerns narrow.

## Language

**Content file**:
A supported Nintendo Switch content container or archive handled by NSCB, including NSP, XCI, NSZ, XCZ, NCA, and supported split-file variants.
_Avoid_: game file, ROM

**Content transformation**:
An operation that produces changed content or a changed container from one or more content files, such as repacking, conversion, splitting, trimming, patching, compression, decompression, or restoration.
_Avoid_: mode, processing mode

**Content patch**:
An explicitly requested content transformation that changes a compatibility, rights, metadata, or composition property, such as title-rights removal, delta removal, RSV/keygeneration lowering, update-partition removal, or linked-account requirement patching.
_Avoid_: cleaning, safe mode, recommended patch profile

**Inspection**:
Read-only interpretation of a content file's structure and metadata.
_Avoid_: file info mode

**Verification**:
Read-only validation of a content file's structure, integrity, signatures, hashes, or cryptographic metadata where applicable.
_Avoid_: checking

**Verification profile**:
A named, typed scope of verification checks. Verification succeeds only when every check applicable to the selected profile actually runs and passes.
_Avoid_: verification level, best-effort verification

**Extraction**:
Materializing selected embedded content or filesystem data from a content file without changing the source.
_Avoid_: advanced mode

**Restoration**:
Reconstructing original content, when sufficient evidence exists, from content that was previously transformed in a reversible way.
_Avoid_: undo

**Operation Plan**:
A fully resolved, immutable specification of a Job's work that contains the decisions and context needed to execute without further user input or prompting, including selected inputs, outputs, operations, providers, prerequisites, and conflict policy.
_Avoid_: dry run, preview, interactive execution recipe

**Plan snapshot**:
A read-only serialized representation of an Operation Plan for inspection or automation output. A Plan snapshot is not itself executable or a replay contract.
_Avoid_: saved executable plan

**Job**:
A user-requested unit of work containing one or more content operations that can be tracked as a whole.
_Avoid_: work list, queued text list

**Interrupted Job**:
A prior job run that was active when its owning process ended and therefore reached a terminal state without completing, failing, or being cancelled normally.
_Avoid_: paused job, resumable job

**Metadata enrichment**:
Optional external catalog information layered onto metadata derived from the content itself, such as regional descriptions, images, release data, or update/DLC availability. Enrichment can improve the experience but is never required for core local operations.
_Avoid_: authoritative metadata, required metadata service

**Device capability set**:
The operations a currently connected Switch and its compatible responder can demonstrably support for the active connection, such as installation, storage transfer, inventory, or dumping. Planning relies on capabilities rather than assuming features from a responder name or version alone.
_Avoid_: device mode, assumed responder features

**Device transfer**:
Moving supported content from the host to a connected Nintendo Switch for installation or storage without broad device administration.
_Avoid_: MTP mode

**Dump**:
Copying supported content from a connected Nintendo Switch to host storage.
_Avoid_: backup, export

**Legacy implementation**:
The whatobiplays/NSC_BUILDER codebase used as behavioral evidence and reference material, not as an architectural or compatibility contract.
_Avoid_: canonical implementation
