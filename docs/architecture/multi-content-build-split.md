# Multi-content Build and Split

## Profiles

Build and Split default to `ProgramOnly`. This profile accepts direct PFS0 members with clear NCA3 Program headers and one clear, un-hashed PartitionFS section containing valid PFS0 framing. It groups members by the ProgramId and content index read from each header. A selection needs at least two ProgramId groups. Duplicate identities and unsupported members fail planning.

The optional `RightsFreeBaseApplicationV1` profile accepts rights-free base Applications with either one Meta and one Program NCA, or one Meta, one Program, and one Control NCA. The operation reads PFS0 member spans, decrypts NCA headers with the selected key file, and groups members by title ID, role, and content index. Package names do not establish member identity. An Application Build requires at least two distinct title ID groups. Split accepts one complete group and requalifies each staged package.

Each Application group must be complete and unique. The Meta CNMT must describe the matching Program and, when present, Control member. The existing semantic qualifier checks the two-member or three-member relationship. Three-member groups also pass the Control NCA integrity and RomFS checks. Orphaned, duplicate, ambiguous, rights-bearing, mixed, or contradictory groups fail planning.

## Build and Split behavior

Build combines selected members into a new deterministic PFS0. Split reads the same identities from the member bytes and writes one PFS0 per title ID. Program-only names retain the existing ProgramId and content-index format. Application-profile Meta and Control names include their role and content index; Program names keep the existing format.

The writer streams raw NCA member bytes in bounded chunks and checks each member against its planned SHA-256 digest. Before publication, the operation revalidates the source packages and key file, reparses and requalifies the staged output, and compares every member with the planned identity and digest. The serialized plan records the key-file path, opaque file identity, and length. It does not include key lines, parsed values, or derived keys. Build and Split use the Engine's operation plan, session, conflict policy, and staged publication path. Source packages remain unchanged.

On qualified macOS/APFS volumes, the default Program-only commands are:

```text
nscb multi-content-build --source FIRST.pfs0 --source SECOND.pfs0 --output COMBINED.pfs0 --workspace WORKSPACE --json
nscb multi-content-split --source COMBINED.pfs0 --output-directory COMPONENTS --workspace WORKSPACE --json
```

Select the Application profile with `--profile rights-free-base-application-v1`. `--keys FILE` selects a key file explicitly. Without it, the standalone CLI uses the configured `keys_path`, then `~/.switch/prod.keys`. Embedded Engine callers must supply the key-file path for this profile. Program-only commands do not need a key file. Use `--jsonl` for job events and a terminal result. `--conflict-policy` accepts `fail`, `replace`, or `skip`.

## Limits

The Application profile covers rights-free base Applications with supported NCA3 members and CNMT layouts. It does not accept tickets, updates, DLC, modified or third-party content, legacy `.xcN` or `.nsN` layouts, or groups whose ownership cannot be established from the supported NCA and CNMT bytes.

These checks establish bounded structural consistency and the stated member relationships. They do not establish Nintendo signature validity, authenticity, installability, or broad package compatibility. Build creates a new PFS0; it does not restore the original package bytes or headers. Split preserves the admitted NCA member bytes and leaves its source package in place. This operation does not implement Issue #14's generic byte-stream Split.
