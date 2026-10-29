# NSCB

This repository contains bounded Rust Engine capabilities for PFS0 probing, content recognition, deterministic input resolution, qualified NCA inspection, and validated local copy-through publication.

## Standalone configuration

The `nscb` executable owns a per-user, schema-versioned TOML configuration.
Normal commands create or load it before Engine startup; embedded hosts remain
responsible for their own configuration and receive no CLI state through the
library.

```text
nscb --help
nscb --version
nscb config path|show|set|reset [--json]
nscb config set <keys_path|output_dir> <absolute-path> [--json]
nscb keys set <source> [--json]
```

The generated file is `NSCB/config.toml` under the native per-user
configuration directory. Version 1 supports an absolute `keys_path` and
`output_dir`; `config set` preserves compatible manual values, `config reset`
does not remove key files, and secret-looking additional values are redacted by
`config show`. A compatible older schema migrates only during an explicit set
or reset and first creates a byte-identical backup. Future schema versions,
malformed files, and unsafe paths fail closed.

Inspection and Verification resolve keys as explicit `--keys`, configured
`keys_path`, then `~/.switch/prod.keys`. `keys set` validates and atomically
replaces the entire conventional key file, using user-only permissions on Unix;
it never echoes key values. See [standalone configuration](docs/configuration.md)
for commands, native locations, migration and failure behavior, key safety,
machine records, and platform qualification limits.

## Container Probe

The public Rust facade exposes `Engine::probe_container(ContainerProbeRequest)`. It validates PFS0 outer-container framing and reports the observed file size, payload region, and declared entry names and spans. It reads the header and metadata tables, not payload bytes, and does not modify the input.

The probe reports outer-container structure only. A valid PFS0 structure does not establish that a file is a genuine NSP, identify a Nintendo title, or identify supported embedded content. The probe does not interpret embedded content, consume or validate keys, decrypt, or make integrity, signature, authenticity, or Verification-success claims.

Use the normal CLI command:

```text
nscb probe <path> [--json]
```

Successful JSON output is one versioned document with `kind: "container_probe.result"`. With `--json`, handled errors produce one versioned error document with a sanitized code. Exit classes are 0 for success, 2 for usage errors, 3 for input errors, and 7 for internal resource or output failures. No keys or credentials are required for this operation.

See [the Container Probe documentation](docs/container-probe.md) for the typed result, validation bounds, JSON fields, error categories, and tested-platform evidence.

## Content Inspection

The provider-dependent read-only Inspection operation is available through
`Engine::preflight_inspection` and `Engine::inspect`. The first capability,
`InspectionCapability::Nca`, inspects a standalone NCA3 Program with a clear
PartitionFs profile. It accepts encrypted NCA headers when a header key is
available; plaintext NCA headers return a typed unsupported-profile error.
Content Recognition retains its existing plaintext and encrypted-header
behavior. Inspection selects the exact NSTool v1.9.2 artifact from an
immutable manifest; callers cannot supply an executable or provider output.

```text
nscb inspect <path> [--keys <path>] [--cache-dir <absolute-dir>]
             [--allow-download] [--preflight] [--json]
```

The CLI uses an explicitly supplied `--keys <path>` first, then the configured
absolute `keys_path`, then `~/.switch/prod.keys`. A configured path that is
missing or invalid fails closed rather than falling back to the conventional
file. Embedding callers provide an explicit key path through
`InspectionRequest`.

`--preflight` validates request, cache, and required child-process controls
without launching NSTool or downloading. It may start a disposable system
process to verify the qualified CPU, open-file, file-size, and core-dump limits.
For Inspection, NSCB validates the request and inputs, then checks mandatory
child-process controls before launching NSTool and before any opt-in download,
installation, or network access. A read-only provider-cache lookup may happen
before those controls during preflight; it does not provision or mutate the
cache. NSCB does not impose an address-space limit or claim hard memory
containment. Physical-footprint
sampling is disabled by default. An embedding host may request an optional
threshold through `MemoryMonitoringPolicy`; because this macOS build has no
supported sampler, Inspection proceeds without sampling or threshold
enforcement. `InspectionHost::memory_monitoring_status()` reports this as
unavailable. NSCB does not claim memory containment.
`--allow-download` is an explicit host policy for the digest-pinned artifact;
without it, a missing cache artifact fails with a prerequisite error. Human
output is localized from a separate Inspection resource. Results contain only
facts that NSCB independently parsed and corroborated; raw NSTool text is
never exposed.

The cache root must be absolute. Directory enumeration is bounded to 1,024
entries and pointer candidates retained for sorting are bounded to 256. The
child process must pass its qualified hard process-control setup before
launch; unsupported controls return the typed
`provider_containment_unsupported` prerequisite error. NSTool is launched
directly with typed arguments, a cleared environment, controlled working
directory and standard input, bounded output, deadline, cancellation, and
process-group cleanup.

The initial profile supports an encrypted NCA header and clear PartitionFs
partitions with hash type
`None` and encryption type `None`. It does not support general encrypted NCA
partition content, plaintext NCA headers in Inspection, RomFs, hierarchical
hash layers, extended metadata, signatures, authenticity, integrity
verification, extraction, writing, or patch application. The manifest selects
the pinned macOS arm64 artifact for `nca.inspect`; the production qualification
and tested hard limits are recorded in [Inspection qualification
evidence](docs/testing/inspection-qualification.md). No hard physical-memory
or aggregate process-tree memory guarantee is claimed. macOS x86_64, Linux,
and Windows remain unqualified, and Linux arm64 is unsupported.

See [Inspection architecture](docs/architecture/inspection.md), [NSTool v1.9.2
provider qualification](docs/providers/nstool-v1.9.2.md), and [Inspection
qualification evidence](docs/testing/inspection-qualification.md).

## Content verification

The read-only `Engine::verify` operation returns typed per-check evidence for a
standalone encrypted NCA3 Program with a clear PartitionFs profile. The
default `Full` profile executes the structural checks, the filesystem-header
hash, the fixed-key RSA-PSS signature, NPDM metadata validation, and the
NPDM-key consistency check. The explicit `Structural` profile runs only the
structural checks and never claims signature, hash, or authenticity success.

```text
nscb verify <path> [--profile full|structural] [--keys <path>]
            [--trust-anchor <path> --anchor-generation <n>] [--json]
```

`Full` requires a caller-supplied RSA-2048 public key with exponent 65537 in
PKCS#1 or SubjectPublicKeyInfo encoding, in PEM or DER. The anchor generation
must equal the NCA header signature generation. A mismatch is a prerequisite
failure: the signature check remains `not_run` with
`trust_anchor_generation_mismatch`, and the command exits 3.

A passing result does not prove payload integrity when the partition hash type
is `None`, does not authenticate the NPDM or ACID chain, does not establish
Nintendo content authenticity, and does not authorize a device write. Each
result includes the limitations applicable to its profile and checks.

Exit classes are 0 for a passed result, 2 for usage errors, 3 for a failed
verification or prerequisite error, 4 for a conflict or input mutation, 6 for
cancellation, and 7 for internal failures. Exit 8 remains reserved for
independent batch `CompletedWithIssues` reporting and is never emitted by
`verify`. See [Verification architecture](docs/architecture/verification.md)
and [Verification qualification evidence](docs/testing/verification-qualification.md).

## Input resolution

Use the read-only resolver to preserve ordered explicit paths, discover supported directory candidates, or load a versioned JSON input list:

```text
nscb resolve [--json] [--recursive] [--follow-symlinks] [--input-list FILE] [PATH...]
```

Explicit non-Split regular files are accepted regardless of extension; numeric Split-like names are interpreted through the canonical Split rules and fail closed when incomplete. Directory discovery filters ordinary files by documented extensions, sorts candidates deterministically, and includes hidden files. Duplicate logical selections fail as input errors.

A canonical Split set is a directory of contiguous two-digit members with a sibling <directory-name>.nscb-split.json manifest. It resolves as one logical input only when the exact manifest bytes have an active host-local receipt, the declared source evidence matches, and every member and the reconstructed whole stream pass size and SHA-256 validation. The resolver performs lookup only; it never issues trust. A missing receipt fails closed, a missing state directory is treated as an empty store, and a corrupt or unreadable store is an internal state failure.

The standalone CLI reads Split receipts from the state directory selected by the absolute NSCB_STATE_DIR environment variable, or from the platform state directory when it is unset. Relative or empty explicit state paths are configuration errors for Split inputs. A resolved store path that does not yet exist is treated as an empty store; if no native state-root environment exists, Split evidence is unavailable. Ordinary single-file resolution does not read the trust store.

See [Input selection and resolution](docs/input-selection.md) for the Rust API, the additive resolve_inputs_with capability, JSON v1 qualification fields, relative-path bases, traversal and Split budgets, cancellation, state-directory rules, duplicate identity behavior, and the test-only issuance seam.

Split receipts are host-local. Preserve the store root and its sibling continuity file as a unit: a copied root without local continuity evidence, a rolled-back authority index, or a receipt from another store fails closed. Recover a lost store root with `LocalSplitTrustStore::restore_from_snapshot`, which runs under the store lock and preserves later local revocations. Issuance and revocation are lock-serialized and journaled before state files are replaced. Newly created directories are synchronized on Unix; Windows uses write-through file replacement, but ordering of newly created directories is not qualified there.

## Safe copy-through publication

`Engine::plan_copy_through` resolves one ordinary regular file for copy-through
to a host-selected destination. Planning records the source identity, metadata,
byte length, SHA-256 evidence, destination baseline, selected workspace, and
parent identity without modifying either path. Execution revalidates that plan.
The host supplies a non-persistent default workspace; a request may select an
explicit workspace instead. A host-default workspace on another filesystem can
use a qualified destination-local fallback that stages beside the existing
destination anchor, including when one final output directory is safely
missing; an explicit cross-filesystem override fails with
`UnsupportedCapability`.

`ConflictPolicy::Fail` is the default. An absent destination is published with
atomic no-clobber `linkat`, so a concurrently created entry is never replaced.
`ConflictPolicy::Replace` is explicit and is available only when the destination
volume advertises `VOL_CAP_INT_RENAME_SWAP` and the actual
`renameatx_np(RENAME_SWAP)` exchange succeeds. Execution revalidates the source,
destination baseline, staging identity, and destination-parent coordination
before promotion. The exchange remains name-atomic and is not
identity-conditional.

Before staging, execution holds a cooperative shared lock on the source and a
persistent advisory marker coordinates NSCB operations that share a destination
parent directory. These mechanisms coordinate only NSCB participants. A
noncooperating same-user process can change a source or destination pathname
between the final check and the publication syscall.

Retained accounting separates evidence from a retained claim. Under Fail, a
late destination competitor is retained and counted only when its independently
captured alias matches the identity, length, and digest observed for that
publication attempt and the artifact reports `retained() == true`. Under
Replace, the atomic exchange captures the entry actually displaced and verifies
it as a distinct `DisplacedDestination` artifact; that entry may differ from the
planned baseline, and its own post-swap identity and content evidence is what
supports retention. In both cases, byte accounting requires `retained() ==
true` and sufficient identity and length evidence. A path-linked competitor
that does not match its earlier observation can still be inventoried as an
`UncertainEntry` with complete evidence for the object actually linked;
`retained()` is then `false` and its bytes are excluded. A matching private
alias remains retained and counted if the destination pathname changes after
the alias is created. The descriptor used to inspect the competitor stays open
until the pathname link and the private alias have both been verified, so the
observed inode cannot be reallocated during that interval. If the Fail
competitor is removed, substituted, unreadable, or otherwise cannot be verified
before capture, execution returns `PublicationUncertain`; the earlier observed
inode receives no retained claim and its bytes are not counted. This
observed-only boundary is accepted for copy-through v1 and does not promise
preservation of bytes independently removed or modified by a noncooperating
process.

Retained staging, recovery, displaced, and uncertain artifacts are inventoried
because path-only removal cannot be conditioned on an expected identity.
`UncertainEntry` is an inventory category, not a claim that all identity and
content fields are absent or that the entry is retained. It can describe a
retained verified alias, an unretained path-linked alias with complete
self-evidence, or a genuinely uncertain entry that lacks ownership evidence.
Callers must check both `retained()` and the evidence fields. Hosts must present
the retained-byte estimate and artifact inventory and provide manual
reconciliation.
Reconciliation must not edit or truncate
artifact contents. Any future removal must first establish ownership, parent
identity, unchanged file identity, and content evidence; uncertain artifacts
must remain in place. No `PublicationUncertain` result triggers automatic
rollback through potentially published or uncertain data.

Copy-through v1 is qualified only on the tested local macOS filesystem
configuration. Linux, Windows, network filesystems, and unverified volume or
mount configurations remain unqualified. See
[publication architecture](docs/architecture/publication.md),
[publication qualification](docs/testing/publication-qualification.md), and
[ADR-0030](docs/adr/0030-darwin-copy-through-qualification.md) for details.

## Copy-through CLI and job observation

`nscb copy` invokes the qualified copy-through Job without prompts. It requires
an explicit source; the destination is optional:

```text
nscb copy <source> [<destination>] [--workspace <path>] [--replace] [--json | --jsonl]
```

An explicit positional destination always overrides the configured output
directory. When it is omitted, NSCB uses the configured `output_dir`, or the
native `Documents/NSCB_output` default, followed by the source file name. The
default directory must be creatable and writable; failures are reported without
falling back to another location. Destination resolution does not change
conflict, planning, validation, or publication behavior. There is no `--output`
option.

The default conflict policy refuses to replace a different existing
destination. `--replace` selects the qualified atomic replacement path. When
`--workspace` is omitted, staging uses the host temporary directory under
`nscb-copy-through`. Copy execution does not persist configuration or execution
history.

When reporting succeeds, `--json` emits one `job.result` document for an
admitted execution, including failure, cancellation, and publication
uncertainty. `--jsonl` emits ordered `job.event` records followed by one
terminal `job.result`. A usage or planning failure before admission emits one
typed `error` document in machine mode. A transport failure can leave a record
absent or partial; it does not alter the operation result or trigger a second
terminal record. Machine mode keeps stdout free of human text and sends human
diagnostics to stderr.

Human copy output includes the complete serialized artifact records when
cleanup retains or cannot safely remove operation-owned entries. Each
`artifact:` line carries its path and observed identity/content evidence for
manual reconciliation. The warning sentence and semantic events remain free
of raw paths.

Exit classes are 0 for validated success, 2 for usage or configuration, 3 for
input or prerequisite failure, 4 for a destination conflict or change, and 6
for cancellation. Exit 7 covers internal, write, validation, publication, and
reporting failures. Exit 5 is reserved for provider or device failures, which
copy-through does not produce. Exit 8 is reserved for future batch results
completed with issues. A cleanup warning preserves the successful operation
exit class when reporting succeeds.

A reporting failure can occur after publication, so exit 7 is ambiguous about
filesystem state. Automation must inspect a delivered complete result and
reconcile source, destination, and artifact evidence before deciding whether
to retry. It must not retry automatically based only on exit 7.

Rust hosts can use the same execution without a prescribed runtime.
`OperationSession::subscribe_events()` claims one event consumer for the next
execution. `last_result()` and `last_completion()` recover the authoritative
terminal result independently of event delivery; the latter also carries the
terminal event sequence and snapshot. `Engine::execute_operation_with_cancellation()`
binds a cancellation handle to one invocation. The synchronous
`Engine::execute_operation()` interface remains available. See
[job execution and machine output](docs/architecture/job-execution.md) for the
event, progress, cancellation, and reconciliation contract.

## Build and validation

Rust 1.98.1 is pinned as both the development toolchain and the minimum
supported Rust version. Dependency versions are recorded in `Cargo.lock`.
`rust-toolchain.toml` selects that pinned toolchain when rustup dispatches
Cargo. A `make all` run instead uses whichever Cargo toolchain is active in
the invoking environment. Run `rustup run 1.98.1 make all` for Rust 1.98.1
qualification. GPT Repo MCP `all` executes under the MCP server's effective
Rust toolchain and must be recorded as separate evidence; it is not Rust
1.98.1 evidence unless the server actually selected 1.98.1.

The content-policy checker and its tests use only the Python 3.11+ standard library. It checks prohibited-content patterns and verifies provenance for every binary fixture against both the Git index and working tree. The initial fixture registry is intentionally empty because the repository contains no binary fixtures.

The repository-owned `Makefile` is the canonical entrypoint for local validation and GPT Repo MCP validation profiles:

```sh
make all
```

Individual profiles are also available through `make content-policy`, `make test-content-policy`, `make test-content-policy-git`, `make test-cleanup`, `make test-cleanup-git`, `make typecheck`, `make lint`, `make test`, `make build`, and `make smoke`. Use `make` to list every target. `make fmt` applies formatting. Validation targets never modify source files.

Run `make clean` only after stopping builds, tests, Python imports, and other artifact producers. It deletes the entire conventional worktree-local `target/`, including generated internal locks, then independently removes untracked Python bytecode under `scripts/` and `tests/`. Do not store durable content in `target/`. Tracked target files or known protected state prevent target deletion; symlinked roots are rejected, and external symlink destinations are never followed. Custom Cargo target/build locations are reported outside scope. The offline Python standard-library driver never invokes Cargo, installs tools, or provisions a toolchain. Documentation, Delegation provenance, tracked files, environments, provider/application state, and other durable content remain. Reports show independent category outcomes and approximate logical bytes; missing directories and repeated runs succeed. See [cleanup qualification](docs/testing/cleanup-qualification.md) for exact exclusions, exit statuses, failure/retry behavior, and host limits.

Routine `make test` and `make all` use a standard-library in-memory index fixture, so they do not initialize disposable repositories or depend on Git daemon lifecycle state. Production `make content-policy` still inspects the real Git index and working tree. Genuine Git behavior has a separate `make test-content-policy-git` suite, which is intentionally excluded from routine validation and runs as the required `content-policy-git` GitHub Actions job.

GitHub Actions runs `make all` plus the separate Git integration job on `ubuntu-24.04` for pushes to `main` and pull requests. If branch protection uses explicit required-check names, `content-policy-git` must be enrolled there as well. See [development validation](docs/validation.md) for exact commands, the MCP profile-to-target mapping, and server-side configuration. See [the repository content policy](docs/adr/0016-repository-content-policy.md) for fixture provenance and prohibited-content rules.

## Content recognition

`cargo run --locked -- recognize <path> --json` reports byte-derived container
or archive structure through `Engine::recognize_content`. Unknown and Ambiguous
are distinct results with exit 3. Package/card structural eligibility is not
execution authorization. See [Content recognition](docs/content-recognition.md)
for supported profiles, encrypted NCA/NSX limitations, evidence and budgets.
