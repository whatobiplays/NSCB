# ADR 0016: Keep proprietary content out of the repository

## Status

Accepted.

## Context

NSCB processes container formats associated with commercial software. Repository history, working copies, tests, and public CI must not contain third-party copyrighted or proprietary material without explicit redistribution rights. This includes commercial game data or excerpts, Nintendo firmware, system or title content, keys, tickets, certificates, and proprietary derived assets or metadata.

Public tests and CI need deterministic inputs that do not depend on private content. Optional qualification with real content may happen privately outside Git, but it cannot be the sole required public CI gate.

## Decision

Every binary fixture in the Git index and working tree must be listed in `tests/fixtures/registry.json` and have documented provenance. Fixtures must be synthetic or clearly redistributable. The registry uses UTF-8 JSON with this top-level shape:

```json
{
  "schema_version": 1,
  "fixtures": []
}
```

Each entry has exactly these fields:

```json
{
  "path": "tests/fixtures/example.bin",
  "sha256": "lowercase SHA-256 digest of the fixture bytes",
  "source": "How the fixture bytes were obtained",
  "provenance": {
    "kind": "synthetic",
    "generator": "Path or name of the generator",
    "reproduction": "How to recreate the bytes"
  },
  "license_basis": "Why the bytes may be redistributed"
}
```

For fixture redistribution rights, `provenance` instead has exactly `kind: "redistributable"` and a nonempty `details` string documenting the source and rights. Description values must be printable, nonempty strings no longer than 1,024 characters. Paths must be repository-relative, use `/`, and contain no empty, `.` or `..` components. Duplicate entries and duplicate JSON object keys are invalid. An empty registry is valid when no binary fixtures exist.

The standard-library Python checker runs from `make content-policy`, and `make all` includes that production gate. The checker independently scans stage-zero index blobs by object ID and current working-tree content, including nonignored untracked paths reported by Git. It does not traverse directories to discover ignored untracked paths or untracked special files that Git omits. It parses and applies the registry to each snapshot separately. A staged secret or invalid fixture remains subject to scanning even when the working copy is benign; a staged registry cannot authorize a different working-tree fixture, and a working registry cannot conceal an invalid staged fixture. Unresolved index conflicts fail the scan. Deleted indexed files are still examined through their index blobs, while deleted registry references or missing worktree fixtures are reported.

When the registry is newly created but not yet staged, the checker permits its absence from the index only while the index snapshot contains no binary files. The working-tree registry is always required. This permits an initially empty registry to remain unstaged while ensuring binary fixtures are not accepted into the index without indexed provenance.

Production inspection uses the real Git index and working tree. A narrow internal command runner separates that enforcement from test fixtures. Production Git commands set `GIT_NO_REPLACE_OBJECTS=1` and `GIT_NO_LAZY_FETCH=1`, and the command line exposes no bypass or insecure fallback.

Routine tests use a test-only in-memory index fixture and do not create disposable Git repositories. A separate genuine-Git integration suite covers real initialization, staging, commits, index divergence, conflicts, replacement-object resistance, and cleanup diagnostics requiring a physical `.git` directory. It is a required hosted-CI job and is intentionally excluded from `make test` and `make all`. The fixture is not a production reader and cannot sanction repository state.

The checker rejects Git-visible symlinks and non-regular files, does not follow links, and fails closed if it cannot safely inspect Git or filesystem state. Limits are 10,000 file versions across both snapshots (a path present in both counts twice), 16 MiB per file version (1 MiB for the registry), 256 MiB of total bytes read, 64 MiB of stdout and 64 KiB of stderr per Git command, and 10 seconds per Git command. Any Git stderr, including a successful enumeration warning, fails with a sanitized diagnostic. Diagnostics use fixed rule codes and bounded repository-relative paths; they do not print matched bytes, registry contents, stderr, or raw Git errors.

Detection covers common prohibited filenames, private-key headers, GitHub token forms, AWS credential patterns, and concrete hexadecimal Nintendo-key assignments. This scan is a guardrail, not proof: it cannot identify every secret, determine the copyright status of arbitrary files, or validate the truth of provenance statements. Human review remains required.

## Consequences

- Synthetic fixtures and the existing facade, CLI, and container-format tests remain the public test baseline.
- The initial registry is empty because no binary fixture is required by this decision.
- CI runs the same `make all` contract used locally and by GPT Repo MCP, plus the separate required `content-policy-git` integration job.
- Private real-content qualification remains outside Git and public CI.
- A clean scan proves only that the implemented checks found no listed violation. It is not a legal conclusion or a guarantee that the repository contains no sensitive material.
