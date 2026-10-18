# NSCB

This repository contains bounded, read-only Rust Engine capabilities for PFS0 probing, content recognition, deterministic input resolution, and qualified NCA inspection.

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

The CLI uses an explicitly supplied `--keys <path>` first. If omitted, it uses
`~/.switch/prod.keys`. Embedding callers provide an explicit key path through
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

## Build and validation

Rust 1.98.1 is pinned as both the development toolchain and minimum supported Rust version. Dependency versions are recorded in `Cargo.lock`.

The content-policy checker and its tests use only the Python 3.11+ standard library. It checks prohibited-content patterns and verifies provenance for every binary fixture against both the Git index and working tree. The initial fixture registry is intentionally empty because the repository contains no binary fixtures.

The repository-owned `Makefile` is the canonical entrypoint for local validation and GPT Repo MCP validation profiles:

```sh
make all
```

Individual profiles are also available through `make content-policy`, `make typecheck`, `make lint`, `make test`, `make build`, and `make smoke`. Use `make` to list every target. `make fmt` applies formatting, and `make clean` removes Cargo-generated build artifacts. Validation targets never modify source files.

Use `make all-git-ai-paused` when a full validation run should temporarily stop the global Git AI background service while the Python content-policy suite runs. This affects Git AI users across repositories for the duration of that suite. Normal `make all`, `make test`, and GitHub Actions do not pause Git AI. See [development validation](docs/validation.md) for restoration limits, concurrency risks, and recovery steps.

That opt-in executes the profiles in `make all` order even with `-j`; only the Python content-policy suite uses the pause wrapper.

GitHub Actions runs `make all` on `ubuntu-24.04` for pushes to `main` and pull requests. See [development validation](docs/validation.md) for the exact commands, the MCP profile-to-target mapping, and the server-side configuration required to enable MCP validation. See [the repository content policy](docs/adr/0016-repository-content-policy.md) for fixture provenance and prohibited-content rules.

## Content recognition

`cargo run --locked -- recognize <path> --json` reports byte-derived container
or archive structure through `Engine::recognize_content`. Unknown and Ambiguous
are distinct results with exit 3. Package/card structural eligibility is not
execution authorization. See [Content recognition](docs/content-recognition.md)
for supported profiles, encrypted NCA/NSX limitations, evidence and budgets.
