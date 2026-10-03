# NSCB

NSCB is a Nintendo Switch content-file toolkit. It exists to inspect, verify, transform, package, extract, compress, restore, and move supported content while keeping device-management concerns narrow.

## Language

**Content file**:
A supported Nintendo Switch content container or archive handled by NSCB, including NSP, XCI, NSZ, XCZ, NCA, and supported split-file variants.
_Avoid_: game file, ROM

**Content transformation**:
An operation that produces changed content or a changed container from one or more content files, such as repacking, conversion, splitting, trimming, patching, compression, decompression, or restoration.
_Avoid_: mode, processing mode

**Inspection**:
Read-only interpretation of a content file's structure and metadata.
_Avoid_: file info mode

**Verification**:
Read-only validation of a content file's structure, integrity, signatures, hashes, or cryptographic metadata where applicable.
_Avoid_: checking

**Extraction**:
Materializing selected embedded content or filesystem data from a content file without changing the source.
_Avoid_: advanced mode

**Restoration**:
Reconstructing original content, when sufficient evidence exists, from content that was previously transformed in a reversible way.
_Avoid_: undo

**Job**:
A user-requested unit of work containing one or more content operations that can be tracked as a whole.
_Avoid_: work list, queued text list

**Device transfer**:
Moving supported content from the host to a connected Nintendo Switch for installation or storage without broad device administration.
_Avoid_: MTP mode

**Dump**:
Copying supported content from a connected Nintendo Switch to host storage.
_Avoid_: backup, export

**Legacy implementation**:
The whatobiplays/NSC_BUILDER codebase used as behavioral evidence and reference material, not as an architectural or compatibility contract.
_Avoid_: canonical implementation
