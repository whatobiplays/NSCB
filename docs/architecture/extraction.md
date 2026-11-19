# Standalone Program and Control extraction

Slice A extracts a standalone Nintendo Content Archive (NCA) Program with an
encrypted NCA3 header and clear, unhashed PartitionFs partitions. Slice B adds
one rights-free NCA3 Control profile with a single AES-CTR RomFS section and
the qualified IVFC SHA-256 integrity checks. The supported Control profile's
integrity checks do not establish title authenticity, signature validity,
general NCA authenticity, or device eligibility.

Slice A passed Engine and CLI runtime tests on native macOS arm64 with writable
local APFS and rights-free synthetic keyed fixtures. Slice B qualification
results are recorded under [Support and qualification](#support-and-qualification).

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
    (--all | [--program-id <16-HEX>] [--nca-type <program|control> | --role <program|control>] \
    [--partition 0..3]... [--path <PARTITION-RELATIVE-PATH>]...) \
    [--json | --jsonl]
```

Provide `--all` or at least one selector; `--all` cannot be combined with
selectors. The CLI accepts at most one `--program-id` and at most one of
`--nca-type` or `--role`. Repeated partition and path values are ORed within
their dimension; populated dimensions are combined with AND.
Program IDs must contain exactly 16 ASCII hexadecimal digits. Either letter
case is accepted, and manifests use lowercase. The accepted type and role
values are `program` and `control`; each still requires its matching qualified
profile. Repeated singleton options and malformed values are usage errors.

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

Program extraction reuses native parsing for the encrypted NCA header,
supported profile, partition bounds, PartitionFs tables, normalized relative
paths, hierarchy checks, and checked file spans. Control extraction uses the
existing private qualifier to verify the complete IVFC tree and RomFS graph.
It builds its private directory and file-span inventory from the RomFS records
that passed those checks; public Inspection output is unchanged. Planning
decrypts each selected span with the existing bounded AES-CTR reader and
records its digest. Execution derives the section key again from verified
source and key handles, streams the selected bytes, and checks each staged
file against the planned digest before publication.

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

The Program PartitionFs parser bounds the source to 65,536 file entries,
16 MiB of total name bytes, 16 MiB of total normalized path bytes, and 62 path
segments. Selector count and selector path bytes use the corresponding
existing budgets. The Control metadata, record, input, and IVFC hash-operation
limits are listed in [Control NCA qualification](../testing/control-nca-qualification.md).

Unselected valid UTF-8 names that fail only the portable publishing rule do
not block a safe selective extraction. They still pass native structural
checks, and an unselected name that aliases or makes a selected path ambiguous
is an error. A full-tree extraction validates the portable rule for every
published name.

The bundle contains regular files and directories. Staged and published
validation opens payloads and the manifest without following symlinks, requires
exactly one hard link per regular file, and reopens each directory entry to
confirm that it still names the checked file. Destination and staging paths are
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

Control manifests use `nca3_control_romfs_ivfc_sha256_aes_ctr` for both
`source.profile` and the sole `required_features` entry. They record `control`
for `source.role` and `source.nca_type`, and `romfs` for the partition
filesystem. `--all` can produce a complete Control manifest for a validated
directory-only tree. Explicit selectors must match at least one file. Program
manifest values and serialized bytes remain unchanged.

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
writable local APFS. See [Support and qualification](#support-and-qualification) for the tested macOS arm64/APFS scope.

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
rights-free synthetic keyed fixtures. Slice A passed 15 extraction backend
tests, 10 Engine integration tests, and 7 CLI tests with Rust 1.98.1. Slice B
passed `make all` and its native Control extraction tests on macOS arm64 with
APFS. The targeted native runs passed 39 Control qualification and extraction
tests, 17 extraction operation tests, 9 CLI tests, and 9 partition-path
budget tests. Fixtures use generated, rights-free NCA and RomFS bytes with
synthetic keys.

Linux GNU and Windows GNU all-target cross-compilation passed. The Windows GNU
check reported existing target-specific warnings. The Windows MSVC build
stopped in `ring` because this host lacks the Windows SDK header `assert.h`;
that target remains unqualified. Cross-compilation does not establish runtime
filesystem support, so other operating systems and filesystem types remain
unqualified until separately tested.

Focused LLVM line coverage in the latest compatible merged profile reached
100% in `resolve_control_extraction`, 95.38% in
`resolve_extraction_from_inventory`, and 93.27% in the CLI
`parse_extraction`. It also measured 94.29% in the shared verified byte-copy
loop, 98.08% in `prepare_control_runtime`, 97.22% in
`copy_control_selected_span`, and 97.96% in `validate_bundle_tree`. The RomFS
inventory normalizer reached 82.66%, and execution-time key derivation reached
75.61%; both were below the 90% target. A later direct stale-evidence test
passed and covers changed program identity, section-counter, and NCA-header
rejection. Its raw profile uses format version 11, which the available LLVM
profile tools reject because they expect version 10, so the listed profile
percentages exclude that test. The normalizer's measured misses are defensive
overflow, path-budget, and malformed-record branches behind bounded
validation. All six new inventory allocation reservations were refused
individually in tests and returned typed resource-limit errors without
changing the inputs or creating a destination.

Neither slice claims Nintendo authenticity, Full Verification, or installation
eligibility. Slice A does not support encrypted partitions or RomFS. Slice B
supports only its qualified Control profile. Neither slice adds package or
container extraction, repacking, or Restoration. See
[Inspection architecture](inspection.md),
[publication architecture](publication.md), and
[ADR-0024: versioned extracted-content manifests](../adr/0024-versioned-extracted-content-manifests.md)
for the related trust, publication, and format contracts.
