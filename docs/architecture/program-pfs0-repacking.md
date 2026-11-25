# Program PFS0 repacking

The request takes a complete standalone extraction manifest and its adjacent
`content/` tree. NSCB rebuilds one Program NCA from the manifest and current
payload bytes, then writes it as the only member of a deterministic PFS0. It
does not reuse bytes from the source NCA.

## Input profile

The manifest must use schema version 1 and identify the standalone
`nca3_program_partition_fs` profile. It must mark the bundle complete, identify
the source as a Program NCA, and list every partition, directory, and file in
the extracted tree. The directory tree and regular files under `content/` must
match that list exactly. Partial selections and manifests for NSP-derived
Program content are outside this profile.

The request requires a header-key file, a `.pfs0` destination, and a workspace
for staged publication. Planning captures manifest, payload, key, and
filesystem identities. Execution rechecks that evidence before reading the
inputs. Missing files, extra files, unsafe paths, or changed inputs fail the
operation.

Rust callers use `Engine::plan_repack`:

```rust
use std::path::PathBuf;
use nscb::{Engine, OperationError, OperationPlan, RepackRequest};

fn plan_repack(
    manifest: PathBuf,
    destination: PathBuf,
    workspace: PathBuf,
    key_file: PathBuf,
) -> Result<OperationPlan, OperationError> {
    Engine::new().plan_repack(RepackRequest::new(
        manifest,
        destination,
        workspace,
        key_file,
    ))
}
```

The standalone command is:

```text
nscb repack --manifest <FILE> --output <PFS0> --workspace <DIR> \
    --key-file <FILE> [--conflict-policy fail|replace|skip] [--json|--jsonl]
```

Execution is supported only on native macOS arm64 with writable local APFS.
The workspace and destination must use the same supported volume. The PFS0
member is named from the immutable manifest identity using the canonical
format `{program_id:016X}_{content_index:08X}.nca`. Publication uses the
Engine's staged path and destination checks.

## Rebuild and validation

NSCB creates a canonical NCA3 header from the manifest and encrypts it with the
supplied header key. It rebuilds each clear PartitionFs section from the current
payload bytes, with deterministic PFS0 metadata and media-unit padding. The
writer sorts entries by their manifest paths and records no timestamps. The
same manifest, payload bytes, and header key produce the same output bytes.

Before packaging, NSCB independently reads the rebuilt NCA through its
supported parser. It checks the encrypted header, declared size, partition
layout, clear PartitionFs profile, filesystem-header hashes, file inventory,
and payload spans. It also compares the rebuilt payload bytes with the planned
bundle evidence. If the NCA fails any supported check, NSCB stops before writing
the outer PFS0.

NSCB records a SHA-256 digest for each extracted payload during planning, then
checks it while rebuilding and comparing the payload. These operation-specific
digest comparisons detect changes and verify that the rebuilt NCA payload spans
match the extracted files. The clear, unhashed PartitionFS profile provides no
NCA-native cryptographic payload authentication.

After packaging, NSCB parses the staged PFS0 separately. It requires exactly
one entry with the canonical member name, checks the entry metadata and
payload extent, and verifies that the embedded bytes match the validated NCA.
The publisher then checks the staged output digest and identity before
publication.

## Output qualification

The output is a one-member PFS0 with a Program NCA that passed the supported
structural and integrity checks. A structurally valid PFS0 does not
automatically qualify as an NSP. This output contains no Meta NCA or CNMT and
has not passed NSP qualification. The repacking operation does not run
`Engine::verify` with the `Full` profile. It does not establish Nintendo
authenticity or installability.

Describe the result as a one-member PFS0 repack. Do not present it as a
qualified NSP, Nintendo-authentic content, Full-verified content, or installable
content. This operation does not write a standalone `.nca` file.

The single-member repacking profile is separate from multi-content Build.
Program-only Build continues to require at least two distinct Program ID
groups. Repacking does not relax that requirement.
