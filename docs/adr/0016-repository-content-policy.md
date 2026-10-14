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

For a fixture with redistribution rights, `provenance` instead has exactly `kind: "redistributable"` and a nonempty `details` string documenting the source and rights. Description values are printable, nonempty strings no longer than 1,024 characters. Paths must be repository-relative, use `/`, and contain no empty, `.` or `..` components. Duplicate entries and duplicate JSON object keys are invalid. The empty registry is valid when there are no binary fixtures.

The standard-library Python checker runs from `make content-policy`, and `make all` includes that target. Its behavioural tests run from `make test`, which also runs the Rust test suite. The checker independently scans stage-zero index blobs by object ID and current working-tree content, including nonignored untracked paths reported by Git. It does not traverse directories to discover ignored untracked paths or untracked special files that Git omits. It parses and applies the registry from each snapshot separately. A staged secret or invalid fixture remains subject to scanning even when the working copy is benign; a staged registry cannot authorize a different working-tree fixture, and a working registry cannot conceal an invalid staged fixture. Unresolved index conflicts fail the scan. Deleted indexed files are still examined from their index blobs; a deleted registry reference or missing worktree fixture is reported.

When the registry is newly created but not yet staged, the checker permits its absence from the index only if that index snapshot contains no binary files. The working-tree registry is always required. This permits the initial empty registry to remain unstaged while ensuring that binary fixtures are not accepted into the index without indexed provenance.

The checker rejects Git-visible symlinks and non-regular files, does not follow links, and fails closed if it cannot safely inspect Git or filesystem state. Its limits are 10,000 file versions across both snapshots (a path present in both counts twice), 16 MiB per file version (1 MiB for the registry), 256 MiB total bytes read, 64 MiB of stdout and 64 KiB of stderr per Git command, and 10 seconds per Git command. Any Git stderr, including a successful enumeration warning, fails with a sanitized diagnostic. Diagnostics use fixed rule codes and bounded repository-relative paths; they do not print matched bytes, registry contents, stderr, or raw Git errors.

Detection covers common prohibited filenames, private-key headers, GitHub token forms, AWS credential patterns, and concrete hexadecimal Nintendo-key assignments. This scan is a guardrail, not proof: it cannot identify every secret, determine the copyright status of arbitrary files, or validate the truth of provenance statements. Human review remains required.

## Consequences

- Synthetic fixtures and existing facade, CLI, and container-format tests remain the public test baseline.
- The initial registry is empty; no binary fixture is required by this decision.
- CI runs the same `make all` contract as local and GPT Repo MCP validation.
- Private real-content qualification remains outside Git and public CI.
- A clean scan is evidence that the implemented checks found no violation; it is not a legal conclusion or a guarantee that the repository contains no sensitive material.
