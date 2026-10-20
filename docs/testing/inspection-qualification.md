# Inspection qualification evidence

## Scope and synthetic content

Inspection tests use repository-owned synthetic NCA3 and PartitionFs data and
captured NSTool v1.9.2 text. They contain no Nintendo keys, tickets, firmware,
certificates, or copyrighted game content. Test keys are fixed synthetic
values and are not production credentials.

The provider manifest pins the macOS arm64 release artifact to:

```text
provider: NSTool v1.9.2
upstream commit: e89ea84bd70c11b67ebec9153fb4a446f18a9d3d
archive: nstool-v1.9.2-macos_arm64.zip
archive bytes: 1473441
archive SHA-256: fe3df0b0e7ec8205d56834577a20b26e42554456e086e86e3b9e5fe749d3b378
executable: nstool
executable bytes: 5946680
executable SHA-256: 381343160daea53ae70205885bb111518643571c971aef3c695dc1a63aa2343e
```

The archive was downloaded to the external corrective evidence directory and
its size and SHA-256 matched the manifest before extraction. This verifies the
artifact identity; it does not qualify an NSCB production launch.

## Current native qualification status

A native macOS arm64 qualification completed on macOS 27.0.1 with Rust
1.99.0 (`aarch64-apple-darwin`). It used the pinned NSTool v1.9.2 macOS arm64
archive and a repository-owned synthetic encrypted NCA and key file. The
archive SHA-256 and executable SHA-256 matched the manifest values above.

The bounded Engine qualification began with an empty cache. Cache-only
preflight returned `provider_cache_missing` without creating the cache;
managed-download preflight returned `ProvisioningRequired` without creating
it. Managed Engine inspection then downloaded and installed the pinned helper
and returned NCA format version 3, game-card distribution, Program content,
key generation 8, signature generation 5, program ID `0102030405060708`, and
one `hello.nca` PartitionFs entry. A subsequent cache-only preflight returned
`Ready`, and a second cache-only Engine inspection returned the same normalized
result. The synthetic input SHA-256 was
`9b6670151efff00f4e54b24872de57914d48cc8d389b7dfc7e277dc29fad7538`; the
synthetic key-file SHA-256 was
`8b5ac5df58721de3fb4bff9a4cf32e8bc1cbda1780f545f4c723f51ce26f8895`. Both
hashes were identical before and after the Engine and CLI runs.

CLI preflight JSON and human mode and inspection JSON and human mode each
exited 0 against the provisioned cache. JSON preflight reported `ready`; JSON
inspection returned the same normalized NCA facts as Engine inspection. The
human output reported an NCA3 Program, the same program ID and generations,
and one 512-byte PartitionFs partition containing `hello.nca` (4 bytes).

The child is launched as the digest-verified cached NSTool executable directly,
with typed fixed arguments, no shell, and no PATH override. ADR-0029 does not
require a `taskpolicy` wrapper, and this qualification does not invoke one.
Runtime qualification verified the exact cached executable digest and the
direct-launch implementation;
short `ps` sampling did not capture a transient NSTool PID, so PID/PPID/PGID
observation is not claimed. The supported Darwin hard limits were exercised by
the native helper check: CPU 60 seconds, 64 open files, 64 MiB file size, and
zero core-file size. There is no `RLIMIT_AS`, supported physical-footprint
sampler, or aggregate process-tree memory limit; ADR-0029 does not require hard
aggregate memory containment for this profile. Default execution uses
monitoring disabled. A host can request an optional
physical-footprint threshold, but this target has no supported sampler.
Inspection proceeds with sampling and threshold enforcement unavailable;
`InspectionHost::memory_monitoring_status()` reports `Unavailable` and retains
the configured threshold. Deterministic tests cover cache-only preflight,
managed preflight, and successful provider inspection with the unavailable
status. No telemetry-triggered termination behavior is implemented or claimed.

The sampler capability check ran on macOS 27.0.1 arm64 with the macOS 27.0
SDK. A disposable same-user native probe forked a child and called the public
Mach `task_for_pid` API to obtain a task port for `task_info(TASK_VM_INFO)`;
the call returned `KERN_FAILURE` (5), so the parent could not read the child's
physical footprint through this route. Apple documents the footprint field in
[`task_vm_info_data_t`](https://developer.apple.com/documentation/kernel/task_vm_info_data_t),
but that metric is useful here only if the host can obtain the provider's task
port. The alternative `proc_pidinfo` and `proc_pid_rusage` declarations are in
Apple's [`libproc.h`](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.h),
whose header identifies its interfaces as private and subject to change; NSCB
does not use them. No supported sampler or sampling-failure path is available
for this profile, so the tests assert truthful unavailability and continued
Inspection rather than claiming threshold-triggered termination.

The qualification also covers negative cases through deterministic tests:
unsupported hard controls fail closed before launch; cache-only misses do not
provision; archive digest mismatch is rejected; malformed archive member
metadata is rejected without publishing cache entries; launch failure,
nonzero exit, signal exit, timeout, cancellation, output limits, reader startup
failure, termination failure, descendant pipe retention, and child reaping have
focused coverage. A downloader regression follows HTTPS 302 responses from
GitHub before validating the archive body. The manual diagnostic fetch reports
only byte count and SHA-256, never payload, keys, or local paths.

Qualification logs and CLI captures are stored outside the repository at
`/private/tmp/nscb-issue7-native-production-qualification/`. These results
qualify this synthetic `nca.inspect` flow on the tested macOS arm64 host. They
do not establish hard memory containment, aggregate process-tree limits,
malicious-helper sandboxing, or qualification for other targets or inputs.
Process cleanup is bounded for the owned child and known process group; it does
not prevent a malicious helper from escaping ordinary process-group cleanup.

## Standalone pinned NSTool evidence

Standalone execution runs the checksum-verified NSTool binary directly over a
synthetic encrypted NCA. It verifies NSTool's reported header fields and tree
output only. It bypasses NSCB's production launcher and resource controls, so
it is kept separate from production qualification. The command, binary
identity, fixture values, process status, and captured output for the
standalone differential-generation check are recorded outside the repository
at:

```text
/tmp/nscb-issue7-corrective-evidence-20261017T160000Z/standalone-nstool-modern-generation-evidence.txt
```

The direct NSTool process exited successfully. Its synthetic fixture sets
legacy generation 3, modern generation 8, signature generation 5, and KAEK
index 1; NSTool reported effective key generation 8, signature generation 5,
and KAEK index 1. The full standard output is captured at
`/tmp/nscb-issue7-corrective-evidence-20261017T160000Z/standalone-nstool-stdout.log`.
The repository's ignored standalone test also passed after checking the
executable size and SHA-256 against the manifest, then parsing the expected
generation, signature, KAEK, and tree fields. Its output is captured at
`/tmp/nscb-issue7-corrective-evidence-20261017T160000Z/standalone-nstool-rust-test.log`.
These checks confirm standalone NSTool behavior for this fixture only. They do
not qualify NSCB's production launcher or resource containment.

## Deterministic tests without NSTool

These tests exercise NSCB's own parsing and boundaries without launching the
provider:

- `provider::nstool` parses captured output, rejects repeated fields even
  when values match, rejects unknown or unsupported semantics, and bounds
  line count, raw tree names, and expanded retained tree paths.
- `nca` tests parse encrypted NCA headers with synthetic keys and keep the
  legacy generation, modern generation, signature generation, and KAEK index
  as independent inputs.
- `inspection` tests validate the public error classes and NCA profile. The
  PFS0 postcondition path builder rejects excessive segment depth and bounds
  cumulative generated directory and file paths independently of raw name
  bytes.
- `provider::tests` uses a test-only fake executable to exercise argument
  construction, environment clearing, output parsing, independent
  postcondition checks, process failures, cancellation, output caps, input
  mutation, key mutation, and diagnostic redaction.
- `provider::process` tests direct executable launch, the supported Darwin
  hard limits, process-group termination, cancellation, output caps, pipe-reader
  cleanup, and child reaping. The physical-footprint threshold remains
  unavailable on this macOS target.
- `provider::download` tests HTTPS redirect validation and bounded redirect
  handling. An explicitly ignored manual qualification test records only the
  pinned archive byte count and digest.
- `provider::cache` accepts the pinned single-file layout, rejects symlink
  file-type metadata without publishing a cache object or pointer, and has a
  manual exact-byte install test for the pinned macOS arm64 archive.

The fake executable exists only behind `#[cfg(test)]`. Production callers
cannot replace the manifest, executable, arguments, or provider output.

The exact-limit parser test exercises the 16 MiB raw tree-name ceiling. A
separate path-expansion test exercises the generated-path ceiling. A reported
60,000-file run proves only that those 60,000 entries completed in that run;
it does not prove the 65,536-entry maximum or the 16 MiB aggregate name-byte
limit.

## Historical run notes

An earlier draft of this document recorded successful native NSCB runs for
one-partition, four-partition, and 60,000-file inputs, plus CLI and managed
provisioning examples. The underlying logs and confirmation that the production
child limits were enforced are not present in the current corrective evidence
set. Those observations are retained as historical notes only; they are not
current production qualification and must not be cited as proof that NSCB
successfully launched NSTool under memory containment.

## Cross-target evidence

The manifest includes macOS arm64, macOS x86_64, Linux x86_64, and Windows
x86_64 release assets. Only the macOS arm64 artifact is marked qualified for
`nca.inspect`; the other entries remain unqualified. Cross-target build
attempts in this environment did not complete because the installed Rust
target toolchain could not find a usable cross C compiler, including
`x86_64-linux-gnu-gcc`. This is a compile-environment blocker, not a passing
cross-target result. No native Linux or Windows execution is reported.

## Commands

The repository validation entry point is `make all`. Focused checks include:

```sh
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo build --locked
```

Native production qualification requires a supported macOS arm64 host where
the child resource limits can be enforced. A standalone NSTool run is not a
substitute for this qualification.

## Issue #8 shared-parser regression rerun

The shared NCA parser changed partition descriptor handling for Issue #8.
The native macOS arm64 Inspection qualification was rerun from the Issue #8
worktree on 2026-10-18 with the same repository-owned synthetic fixture and
pinned NSTool v1.9.2 artifact. The worktree base commit was
`f82391a72e4a751c444fab8b2cbc845c06a812d6` with the uncommitted Issue #8
changes applied; the host used Rust 1.99.0.

Engine preflight on a fresh cache returned `provider_cache_missing` without
creating the cache. Managed preflight returned `ProvisioningRequired`.
Managed inspection downloaded and installed the pinned artifact, whose cached
executable remained 5,946,680 bytes with SHA-256
`381343160daea53ae70205885bb111518643571c971aef3c695dc1a63aa2343e`.
The normalized result matched the earlier qualification: NCA3, game-card
distribution, Program content, key generation 8, signature generation 5,
program ID `0102030405060708`, and one 512-byte PartitionFs partition
containing `hello.nca` (4 bytes).

Cache-only preflight returned `Ready`, and the CLI preflight JSON, preflight
human, inspection JSON, and inspection human modes each exited 0 with the
expected facts. The synthetic input SHA-256
`9b6670151efff00f4e54b24872de57914d48cc8d389b7dfc7e277dc29fad7538`
and key-file SHA-256
`8b5ac5df58721de3fb4bff9a4cf32e8bc1cbda1780f545f4c723f51ce26f8895`
were unchanged before and after the run.

Evidence is stored outside the repository at
`/private/tmp/nscb-issue8-native-inspection-qualification/`. This rerun
qualifies only the existing synthetic `nca.inspect` flow on the tested host.
It does not qualify Verification, other content families, memory containment,
or other targets.

### Post-PR #59 forward-port rerun

The native macOS arm64 Inspection regression was repeated on 2026-10-19 from
the clean post-PR #59 forward-port worktree at baseline
`29a4259d507d327d0029a24cb799f10a0b23d272` with the uncommitted Issue #8
changes applied. The host ran macOS 27.0.1 arm64 with Rust 1.99.1.

A fresh cache returned `provider_cache_missing` for cache-only preflight and
`ProvisioningRequired` for managed preflight; neither preflight created the
cache. Managed Inspection downloaded and installed the pinned NSTool v1.9.2
artifact. The cached executable was 5,946,680 bytes with SHA-256
`381343160daea53ae70205885bb111518643571c971aef3c695dc1a63aa2343e`.

Managed and cache-only Engine Inspection both returned NCA3, game-card
distribution, Program content, key generation 8, signature generation 5,
program ID `0102030405060708`, and one 512-byte PartitionFs partition
containing `hello.nca` (4 bytes). Cache-only preflight after provisioning
returned `Ready`. CLI preflight JSON, preflight human, Inspection JSON, and
Inspection human modes each exited 0 with no stderr.

The synthetic input SHA-256
`9b6670151efff00f4e54b24872de57914d48cc8d389b7dfc7e277dc29fad7538`
and key-file SHA-256
`8b5ac5df58721de3fb4bff9a4cf32e8bc1cbda1780f545f4c723f51ce26f8895`
were unchanged before and after the run. Evidence is stored outside the
repository at
`/Users/daniel/.codex/qualification-evidence/issue-8-post-pr59/03-validation/native/`.

This rerun qualifies only the existing synthetic `nca.inspect` flow on the
tested host. It does not qualify Verification, other content families, memory
containment, or other targets.

### Corrective requalification

The same native macOS arm64 Inspection regression was repeated on 2026-10-19
against the corrective candidate. The host ran macOS 27.0.1 arm64 with Rust
1.99.1. A fresh cache returned `provider_cache_missing` for cache-only
preflight and `ProvisioningRequired` for managed preflight without creating
the cache. Managed Inspection installed the pinned NSTool v1.9.2 artifact;
the cached executable was 5,946,680 bytes with SHA-256
`381343160daea53ae70205885bb111518643571c971aef3c695dc1a63aa2343e`.

Managed and cache-only Engine Inspection both returned NCA3, game-card
distribution, Program content, key generation 8, signature generation 5,
program ID `0102030405060708`, and one 512-byte PartitionFs partition
containing `hello.nca` (4 bytes). Cache-only preflight after provisioning
returned `Ready`. CLI preflight JSON, preflight human, Inspection JSON, and
Inspection human modes each exited 0 with no stderr.

The synthetic input SHA-256
`9b6670151efff00f4e54b24872de57914d48cc8d389b7dfc7e277dc29fad7538`
and key-file SHA-256
`8b5ac5df58721de3fb4bff9a4cf32e8bc1cbda1780f545f4c723f51ce26f8895`
were unchanged before and after the run. Evidence is stored outside the
repository at
`/Users/daniel/.codex/qualification-evidence/issue-8-post-pr59-corrective-1/03-validation/native/`.

This rerun qualifies only the existing synthetic `nca.inspect` flow on the
tested host. It does not qualify Verification, other content families, memory
containment, or other targets.
