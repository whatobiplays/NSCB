# Multi-content Build and Split

## Supported package profile

Build and Split accept PFS0 packages whose direct members each contain a readable NCA3 Program header. Each NCA must have one clear, un-hashed PartitionFS section with valid PFS0 framing. Member names must be safe, path-free ASCII names without case-fold collisions. Names do not establish content identity.

The operation reads the 64-bit ProgramId and content index from each NCA header. A logical component is the set of admitted Program NCA members with the same exact ProgramId, ordered by content index. A package needs at least two distinct ProgramId groups. Duplicate ProgramId/content-index pairs and unsupported or ambiguous members fail planning.

## Build and Split behavior

Build combines the validated NCA members from the selected PFS0 sources into a new deterministic PFS0. Its member names come from ProgramId and content index. Split reads those identities from the NCA bytes and writes one PFS0 per ProgramId into a staged output directory.

The writer streams member bytes in bounded chunks and checks each member against its planned SHA-256 digest. Before publication, the operation revalidates source evidence, reparses the staged PFS0 output or outputs, and compares each parsed member digest with the planned evidence. Build and Split use the Engine's immutable plan, operation session, conflict policy, and staged publication path. Sources remain unchanged.

On qualified macOS/APFS volumes, invoke the CLI with:

```text
nscb multi-content-build --source FIRST.pfs0 --source SECOND.pfs0 --output COMBINED.pfs0 --workspace WORKSPACE --json
nscb multi-content-split --source COMBINED.pfs0 --output-directory COMPONENTS --workspace WORKSPACE --json
```

Use `--jsonl` for job events and a terminal result. `--conflict-policy` accepts `fail`, `replace`, or `skip`.

## Limits

Encrypted NCA profiles and structures outside this profile are rejected. Header and PFS0 checks establish structural consistency; they do not establish full content verification, signature validity, or authenticity. Build creates a new PFS0 and does not restore the original NSP container bytes or headers. Split preserves the admitted NCA member bytes and leaves its source package in place.

This operation groups content using NCA metadata. It does not implement Issue #14's generic byte-stream Split, legacy `.xcN`/`.nsN` layouts, or imported multi-content formats whose component ownership cannot be established from the supported bytes.
