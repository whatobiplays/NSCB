# Standalone Program extraction

Slice A covers extraction from one standalone Nintendo Content Archive (NCA)
Program with an encrypted NCA3 header and clear, unhashed PartitionFs
partitions. It does not establish title authenticity, signature validity,
payload integrity, or device eligibility.

Production extraction has been implemented, but runtime qualification is
still pending.

## Request and command line

The Rust domain API represents a request with `ExtractionRequest`. It carries
the source NCA, a new bundle destination, the header-key file, and an
`ExtractionSelection`:

```rust
use std::path::PathBuf;
use nscb::{
    ExtractionRequest, ExtractionSelection, ExtractionSelectors, NcaContentType,
    ProgramId, ProgramIdParseError,
};

fn make_request(
    source: PathBuf,
    destination: PathBuf,
    key_file: PathBuf,
) -> Result<ExtractionRequest, ProgramIdParseError> {
    let program_id = ProgramId::from_hex("0102030405060708")?;
    let selection = ExtractionSelection::selectors(
        ExtractionSelectors::new()
            .with_program_id(program_id)
            .with_nca_type(NcaContentType::Program)
            .with_partition(0)
            .with_path("romfs/data.bin"),
    );
    Ok(ExtractionRequest::new(
        source,
        destination,
        key_file,
        selection,
    ))
}
```

The standalone command accepts the same selection dimensions:

```text
nscb extract --source <NCA> [--keys <FILE>] [--output-directory <NEW-DIR>] \
    (--all | [--program-id <16-HEX>] [--nca-type program | --role program] \
    [--partition 0..3]... [--path <PARTITION-RELATIVE-PATH>]...) \
    [--json | --jsonl]
```

Provide `--all` or at least one selector; `--all` cannot be combined with
selectors. The CLI accepts at most one `--program-id` and at most one of
`--nca-type` or `--role`. Repeated partition and path values are ORed within
their dimension; populated dimensions are combined with AND.
Program IDs must contain exactly 16 ASCII hexadecimal digits. Either letter
case is accepted, and manifests use lowercase. The only supported type and
role value is `program`. Repeated singleton options and malformed values are
usage errors.

Paths are exact, case-sensitive names relative to a partition root. A path
present in more than one selected partition matches in each such partition.
Every supplied selector value must match a file in the final selection. A
partition with no selected files, an absent path, or a mismatched Program ID
fails planning. The CLI rejects an empty selector set as a usage error; the
Rust planner rejects an empty typed selector set.

When `--output-directory` is omitted, the standalone CLI uses the configured
`output_dir`, or `Documents/NSCB_output` when no directory is configured. It
uses `<source-name>.extracted` as the bundle leaf only when that name passes
the portable-name policy. Otherwise it uses `nca-extracted`. The fallback is
a generic bundle name; the manifest carries the NCA identity. An existing
destination is a conflict and is never overwritten.

The CLI resolves keys from explicit `--keys`, the configured `keys_path`, then
the conventional `~/.switch/prod.keys` path. Embedded callers provide a key
path through `ExtractionRequest`; the Engine does not read standalone
configuration.

## Validation boundary and path policy

Extraction reuses native parsing for the encrypted NCA header, supported NCA
profile, partition bounds, PFS0 tables, normalized relative paths, hierarchy
checks, and checked file spans. Native inspection facts include each file's
partition index, normalized path, absolute offset, and length. Payload reads
use the selected spans, and extraction checks their byte correspondence with
the staged files and the immutable plan.

Inspection's NSTool launch and provider-tree corroboration are not part of
extraction. A separate NSTool comparison may provide diagnostic evidence, but
it does not qualify extraction or establish authenticity. Extraction also
does not run Full Verification.

Native validation covers the complete source structure. Publishing applies
additional rules to selected names: each path component and bundle leaf must
match `[A-Za-z0-9._-]+`. Accepted names are preserved exactly. Extraction
does not sanitize, transliterate, or silently rename content. It rejects:

- Empty components, `.` and `..`, components longer than 255 bytes, and names
  ending in a dot or space.
- Windows-reserved device basenames, including names with extensions, such as
  `CON`, `NUL`, `COM1`, and `LPT9`.
- ASCII case-folded aliases of selected files or directories, including
  aliases caused by trailing dots or spaces.
- File/directory prefix conflicts and selected paths that collide with a
  source file or directory after portable comparison.

The public `is_portable_bundle_leaf` helper lets adapters apply the same leaf
rule when choosing a fallback name. Extraction validates the requested bundle
leaf with this policy as well.

The existing PartitionFs parser bounds the source to 65,536 file entries,
16 MiB of total name bytes, 16 MiB of total normalized path bytes, and 62 path
segments. Selector count and selector path bytes use the corresponding
existing budgets.

Unselected names that fail only the portable publishing rule do not block a
safe selective extraction. They still pass native structural checks, and an
unselected name that aliases or makes a selected path ambiguous is an error.
A full-tree extraction validates the portable rule for every published name.

The bundle contains regular files and directories. It does not materialize
symlinks, hard links, or special objects. Destination and staging paths are
revalidated before publication; a path that changes identity or type fails
closed.

## Bundle and manifest v1

Each bundle has one versioned `manifest.json` and one `content/` directory:

```text
<bundle>/
    manifest.json
    content/
        0/
            romfs/
                data.bin
```

Manifest paths are relative to `content_root` and include the partition index.
Directories include the partition root. A partition's `files` array lists
regular files only.

```json
{
  "schema_version": 1,
  "kind": "extracted_content_manifest",
  "selection_mode": "selectors",
  "content_root": "content",
  "required_features": ["nca3_program_partition_fs"],
  "completeness": "incomplete",
  "source": {
    "profile": "nca3_program_partition_fs",
    "role": "program",
    "nca_type": "program",
    "program_id": "0102030405060708",
    "content_index": 0
  },
  "partitions": [
    {
      "index": 0,
      "filesystem": "partition_fs",
      "directories": ["0", "0/romfs"],
      "files": [{"path": "0/romfs/data.bin"}]
    }
  ]
}
```

`selection_mode` records how the request selected files. `completeness` records
what the bundle represents. A selector request is complete when every
validated source file is selected and the manifest includes every partition
and directory, including empty partition roots. If any source file is omitted,
the manifest is incomplete and lists only represented partitions and the
directories needed by their selected files.

The writer orders partitions by index, directories by bytewise path order, and
files by partition index then bytewise path order. It emits deterministic
UTF-8 JSON with a final newline. The manifest records no payload hashes,
execution fingerprints, absolute source paths, or key evidence. Users may edit
payload files without invalidating the manifest by definition; a future
repacker must validate the current tree and its structure when it is
implemented.

The fields retained for that future workflow are the schema version and kind,
required features, content root, completeness, source profile and role, NCA
type, canonical Program ID, content index, partition indices and filesystem
types, directories, and file paths. Slice A does not add title ownership or
Nintendo Content ID, and does not implement repacking or exact Restoration.
The manifest is structural metadata, not proof of authenticity or an
execution receipt.

## Planning, cancellation, and publication

Planning validates the entire source structure, resolves selectors, binds
source and key evidence, and constructs an immutable in-memory plan. Planning
does not change the source, key file, or destination. A serialized plan
snapshot is informational and cannot be used to replay execution.

Execution streams selected file spans with bounded buffers. It checks copied
byte counts and staged paths against the plan before publication. The
destination is a new bundle directory; existing destinations are not
replaced. Publication requires an atomic no-clobber directory operation on
writable local APFS. Runtime qualification remains pending.

Cancellation is cooperative. `OperationSession::cancel()` is accepted while
the operation is in `Executing` and refused after it enters `Promoting` or
`Completing`. The publication step is not interrupted. If cancellation wins
before the cutoff, execution reports cancellation and does not report a
successful publication.

If the destination state cannot be proven after publication, the operation
preserves the uncertain artifact, records available artifact evidence, and
returns `PublicationUncertain`. It does not delete an entry or roll back
through data that may already have been published. Treat that result as a
manual reconciliation case; a retry may conflict with a bundle that is already
present. If publication is confirmed but a temporary artifact cannot be
removed safely, the result can report a cleanup warning and retained evidence
without changing the confirmed publication outcome. The original NCA and key
file remain untouched and are never deleted.

In machine mode, `--json` emits one `job.result` for an admitted operation or
one `error` record for a pre-admission failure. `--jsonl` emits ordered
`job.event` records followed by the terminal `job.result`. Diagnostics use
stable codes instead of raw OS messages or key contents. A reporting failure
does not change the operation's publication outcome. See
[job execution and machine output](job-execution.md) for the common event and
result contract.

## Support and qualification

The approved runtime target is native macOS arm64 on writable local APFS with
rights-free synthetic keyed fixtures. Qualification must record the candidate
SHA, tested SHA, OS, Rust toolchain, filesystem, commands, results, and
limitations. Production extraction evidence has not yet been recorded. Other
operating systems and filesystem types remain unqualified until separately
tested.

Slice A does not claim Nintendo authenticity, Full Verification, installation
eligibility, encrypted partition support, RomFs support, additional NCA
roles, package/container extraction, repacking, or Restoration. See
[Inspection architecture](inspection.md),
[publication architecture](publication.md), and
[ADR-0024: versioned extracted-content manifests](../adr/0024-versioned-extracted-content-manifests.md)
for the related trust, publication, and format contracts.
