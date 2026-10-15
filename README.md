# NSCB

This repository contains bounded, read-only Rust Engine capabilities for PFS0 probing, content recognition, and deterministic input resolution.

## Container Probe

The public Rust facade exposes `Engine::probe_container(ContainerProbeRequest)`. It validates PFS0 outer-container framing and reports the observed file size, payload region, and declared entry names and spans. It reads the header and metadata tables, not payload bytes, and does not modify the input.

The probe reports outer-container structure only. A valid PFS0 structure does not establish that a file is a genuine NSP, identify a Nintendo title, or identify supported embedded content. The probe does not interpret embedded content, consume or validate keys, decrypt, or make integrity, signature, authenticity, or Verification-success claims.

Use the normal CLI command:

```text
nscb probe <path> [--json]
```

Successful JSON output is one versioned document with `kind: "container_probe.result"`. With `--json`, handled errors produce one versioned error document with a sanitized code. Exit classes are 0 for success, 2 for usage errors, 3 for input errors, and 7 for internal resource or output failures. No keys or credentials are required for this operation.

See [the Container Probe documentation](docs/container-probe.md) for the typed result, validation bounds, JSON fields, error categories, and tested-platform evidence.

## Input resolution

Use the read-only resolver to preserve ordered explicit paths, discover supported directory candidates, or load a versioned JSON input list:

```text
nscb resolve [--json] [--recursive] [--follow-symlinks] [--input-list FILE] [PATH...]
```

Explicit regular files are accepted regardless of extension. Directory discovery filters by documented extensions, sorts candidates deterministically, and includes hidden files. Duplicate logical selections and suspected Split parts fail as input errors. No Split layout is reported as resolved until its completeness rules are positively qualified.

See [Input selection and resolution](docs/input-selection.md) for the Rust API, JSON v1 contract, relative-path bases, traversal limits, duplicate identity behavior, and current Split-set deferral.

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
