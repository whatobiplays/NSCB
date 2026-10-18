# Content Inspection architecture

## What Inspection means

Inspection is a typed, read-only Engine operation that requires a key source
when the selected profile needs one. It may select, verify, provision, and run
an exact managed helper, but it returns only facts that NSCB has independently
parsed and cross-checked. Container Probe and Content Recognition remain
separate operations. Neither one becomes a keyless substitute for Inspection.

The current capability is `InspectionCapability::Nca`. It inspects a
standalone NCA3 file with the profile documented in
[NSTool v1.9.2 provider qualification](../providers/nstool-v1.9.2.md). It does
not prove signature authenticity, file integrity, or Verification success.
Inspection accepts an encrypted NCA header when its header key is available;
it returns a typed unsupported-profile error for a plaintext NCA header.
Content Recognition keeps its existing behavior for both header forms.

## Public facade

The public API is intentionally narrow:

```rust
use nscb::{
    CancellationHandle, Engine, InspectionError, InspectionHost,
    InspectionPreflightStatus, InspectionRequest, InspectionResult,
};

let engine = Engine::new();
let request = InspectionRequest::nca("content.nca", "prod.keys");
let cache_root = std::env::temp_dir().join("nscb/providers");
let host = InspectionHost::cache_only(cache_root);

match engine.preflight_inspection(&request, &host)? {
    InspectionPreflightStatus::Ready => {}
    InspectionPreflightStatus::ProvisioningRequired => {
        // The host must explicitly choose managed_download before retrying.
    }
    _ => {}
}

let result = engine.inspect(request, &host)?;
if let InspectionResult::Nca(inspection) = result {
    println!("program {:?}", inspection.program_id);
}
# Ok::<(), InspectionError>(())
```

A host that permits network provisioning opts in explicitly:

```rust
# use nscb::{InspectionHost, CancellationHandle};
let cancellation = CancellationHandle::new();
let cache_root = std::env::temp_dir().join("nscb/providers");
let host = InspectionHost::managed_download(cache_root)
    .with_cancellation(cancellation.clone());
```

`Engine::new()`, `Engine::default()`, and direct unit construction with
`Engine` remain available without helper configuration. Admission is owned by
the explicitly constructed `InspectionHost` session: clones share its one
active-helper slot, and a second concurrent operation in that session returns
a typed conflict. This keeps `Engine` directly constructible in unit tests
without adding a process runtime or global execution slot. Closing an
operation or dropping a cancellation handle does not intentionally leave its
child process running.

The host chooses an absolute cache directory and network policy. The request chooses
only the input path, key path, and capability. Production callers cannot
supply a manifest, executable, command line, digest, or provider output.
Test-only fixtures are compiled behind `#[cfg(test)]` and have no Cargo
feature or public API path.

## Operation sequence

1. The Engine checks the host-session admission guard and capability name.
2. The provider module selects the immutable target artifact for the host
   operating system and architecture. Missing, unsupported, and unqualified
   targets fail before input processing or helper launch.
3. The input and key file are opened as regular files. Their opened-handle and
   path identities are recorded, and neither may be empty or a symlink
   substituted between those checks.
4. The key file is read under its byte limit. Exactly one recognized header
   key alias is resolved; conflicting aliases fail without exposing values.
5. NSCB reads and validates the NCA3 header independently. A plaintext NCA3
   header returns `unsupported_inspection_profile`; an encrypted header is
   decrypted with the selected header key. Inspection then selects a supported
   filesystem/hash/encryption profile before doing any provider work.
6. During ordinary Inspection, required child-process controls are checked
   before provider-cache lookup. During preflight, a read-only cache lookup may
   happen before those controls; preflight never installs or downloads an
   artifact. A cache-only host stops with a typed prerequisite if provisioning
   is required. A managed-download host may fetch only the manifest URL after
   Inspection has checked the mandatory controls and the host has explicitly
   enabled network provisioning.
7. The verified executable is copied from its already-open content-addressed
   object into a fresh private directory. The copy is digested again. The
   temporary key file contains only the selected header key and uses
   restrictive permissions.
8. NSTool runs directly with a fixed argument vector, cleared environment,
   null standard input, controlled working directory, process-group ownership,
   deadline, cancellation polling, and bounded concurrent pipe capture. On
   qualified macOS hosts NSCB applies CPU, open-file, file-size, and core-dump
   limits. It does not apply `RLIMIT_AS` or claim hard memory containment. An
   embedding host may request an optional physical-footprint threshold. When no
   supported sampler is available, Inspection proceeds without sampling or
   enforcement; `InspectionHost::memory_monitoring_status()` reports the
   configured threshold as unavailable.
9. NSCB detects input and key changes, then parses the provider output with the
   pinned grammar. It rejects unknown or contradictory fields, unreadable
   partitions, unsupported profiles, and raw provider trees outside the
   expected partition structure.
10. NSCB independently parses the same NCA header and each PartitionFs table.
    Provider partition facts, file names, sizes, and tree membership must match
    the Rust-derived facts. Only then is a normalized `InspectionResult`
    returned.

If any step fails, the public operation returns a sanitized
`InspectionErrorCode`. Provider stdout, stderr, argv, cache paths, key values,
and private input paths are not repeated in normal results or diagnostics.

The host-owned `MemoryMonitoringPolicy` defaults to `Disabled`. A host may
request a nonzero physical-footprint threshold. The current macOS target has no
supported sampler, so this optional request does not block Inspection and the
threshold is not enforced. Callers can query
`InspectionHost::memory_monitoring_status()` before or after Inspection; it
returns `Unavailable` with the requested threshold. No telemetry-triggered
termination is implemented or claimed.

The provider contract follows [ADR-0029](../adr/0029-qualified-native-helper-execution.md).

## Shared NCA validation

The common NCA3 header and four partition-descriptor checks live in the
internal `nca` module. Content Recognition uses the same
`parse_header_block` function before applying its byte-only recognition
profile. Inspection adds its own stricter support profile after the shared
checks. This is the appropriate reuse for this operation because Inspection
has a standalone NCA input.

XCI and HFS0 parsing in `recognition` remain separate: an XCI is a game-card
container with a root HFS0 hierarchy and nested HFS0/NCA members, while this
operation accepts a standalone NCA. Reusing an XCI validator here would mix
container eligibility with NCA filesystem inspection. Future XCI inspection
should share the container parser explicitly rather than copying or
substituting it for this profile.

For NCA3, the legacy key-generation byte is at `0x206`, the key-area
encryption-key index (KAEK) at `0x207`, the modern key-generation byte at
`0x220`, and the signature-key-generation byte at `0x221`. NSTool's pinned
`libpietendo` parser uses the greater of the legacy and modern generation
bytes as the effective generation, while preserving the signature generation
and KAEK as separate fields. NSCB uses the same rule and independently checks
all three values against provider output. See the
[pinned parser implementation](https://github.com/jakcron/libpietendo/blob/5d50d02f8f3b8918bdfbbb599b8c4c1628660d89/src/hac/ContentArchiveHeader.cpp#L123-L127)
and [packed NCA header definition](https://github.com/jakcron/libpietendo/blob/5d50d02f8f3b8918bdfbbb599b8c4c1628660d89/include/pietendo/hac/define/nca.h#L110-L124).

The Rust postcondition path parses the NCA header and PFS0 entry tables, but
it does not reproduce NSTool's interpretation of encrypted partition layers
or decode signed metadata. That limitation is why this capability reports a
clear PartitionFs profile only and why a valid structural tree is not an
authenticity or integrity claim.

## Error classes

Inspection follows the machine-output contract in ADR 0023:

| Class | Exit | Meaning | Representative codes |
| --- | ---: | --- | --- |
| Success | 0 | Validated result returned | none |
| Configuration | 2 | Host supplied invalid cache or key-path configuration | `invalid_cache_directory`, `invalid_key_path` |
| Prerequisite | 3 | Missing, malformed, unsupported, changed, tampered, or unqualified prerequisite before provider success | input/key errors, `provider_cache_missing`, `provider_unqualified_target`, `provider_containment_unsupported`, `unsupported_inspection_profile`, `provider_artifact_mismatch` |
| Conflict | 4 | Concurrent mutation or unsafe cache contention | `input_changed_during_inspection`, `provider_cache_busy`, `provider_execution_busy` |
| Provider | 5 | A qualified provider actually ran and failed or produced an invalid result | `provider_launch_failed`, `provider_exited_unsuccessfully`, `provider_timed_out`, `provider_output_malformed`, `provider_postcondition_mismatch` |
| Cancelled | 6 | Cancellation observed | `cancelled` |
| Internal | 7 | Internal invariant, filesystem, signal registration, or allocation failure | `provider_manifest_invalid`, `cache_lock_failed`, `allocation_failed`, `internal_io`, `signal_handler_failed` |

The complete stable mapping is implemented by
`InspectionErrorCode::exit_class()` and checked by a table-driven unit test.

## Cache and lifecycle invariants

The cache root must be absolute. Each cache-directory enumeration stops at
1,024 entries, and at most 256 pointer candidates are retained and sorted.
The same bounds apply to lookup, sequence selection, and cleanup; cleanup
enumerates and validates its bounded candidate sets before mutating anything.
An over-limit directory fails as a typed cache error.

The cache contains immutable objects addressed by the archive digest and
pointer files addressed by monotonically increasing sequence names. A pointer
is published after its object and executable digests are verified. Newer
valid pointers take precedence; a malformed newest pointer does not destroy a
last known-valid generation. Installation and cleanup use bounded temporary
names and rename, with directory synchronization where the platform supports
it.

On Unix, object access opens each cache component relative to an already-open
directory with `O_NOFOLLOW`; the executable is held as an open handle and
copied from that handle. This avoids treating a final path string as the
verified artifact. On other platforms, the cache chain and final component
are checked before use and the executable is opened with the platform's
no-follow flags where available.

On macOS, the process runner applies a 60-second CPU limit, a 64 MiB file-size
limit, a 64-descriptor limit, and disabled core dumps before launching the
child. It fails closed if any required control is unavailable. NSCB does not
set an address-space limit or claim hard memory containment. Physical-footprint
sampling is disabled by default. When a host requests a threshold, this target
continues without sampling or enforcement; the host status reports the
threshold as unavailable because no supported sampler exists.

The process runner owns a process group or job, drains stdout and stderr in
parallel, enforces independent byte caps, and uses one shared reader-join
deadline after termination. Timeout and cancellation first terminate the
owned process tree, so descendants holding inherited pipes are closed before
the bounded joins. An uncooperative child that escapes the owned process
group is outside the provider contract; the pinned executable is trusted only
for this exact qualified operation.
