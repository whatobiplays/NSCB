# Development validation

NSCB uses a repository-owned `Makefile` as the canonical validation contract for local development, GitHub Actions, and GPT Repo MCP. GNU or BSD Make, Git, Python 3.11 or newer, and the Rust toolchain pinned in `rust-toolchain.toml` are required. All Cargo commands use the checked-in `Cargo.lock`. Python validation uses only the standard library.

| Validation profile | Make target | Commands |
| --- | --- | --- |
| `content-policy` | `make content-policy` | `PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/check_content_policy.py` |
| `test-content-policy` | `make test-content-policy` | `PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_content_policy.py'` |
| `test-content-policy-git` | `make test-content-policy-git` | `PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_content_policy_git.py'` |
| `typecheck` | `make typecheck` | `cargo check --locked --all-targets --all-features` |
| `lint` | `make lint` | `cargo fmt --all -- --check`, then `cargo clippy --locked --all-targets --all-features -- -D warnings` |
| `test` | `make test` | The Git-free `test-content-policy` suite, then `cargo test --locked` |
| `build` | `make build` | `cargo build --locked` |
| `smoke` | `make smoke` | `cargo test --locked --test cli_subprocess` |
| `all` | `make all` | `content-policy`, `typecheck`, `lint`, `test`, `build`, and `smoke`, in that order |

`make` prints every target. `make fmt` modifies Rust source files and is not a validation target. `make clean` runs `cargo clean` and is intentionally outside `make all`.

## Content-policy testing split

Production `make content-policy` inspects the real Git index and working tree. It reads stage-zero index blobs by object ID, enumerates nonignored untracked paths, scans the worktree independently, and rejects unresolved index conflicts. Production Git commands run with bounded stdout, stderr, time, and repository-safe opening rules. They also set `GIT_NO_REPLACE_OBJECTS=1` and `GIT_NO_LAZY_FETCH=1`.

Routine `make test-content-policy` must remain usable without creating disposable Git repositories. It supplies the checker with a test-only `InMemoryGitFixture` containing an index, immutable blobs, independent worktree, untracked, ignored, and unmerged registries. The fixture supports only the checker's read-only commands:

- `rev-parse --show-toplevel`
- `ls-files --unmerged -z`
- `ls-files --stage -z`
- `ls-files --others --exclude-standard -z`
- `cat-file -s <object-id>`
- `cat-file blob <object-id>`

The fixture does not model commits, refs, packs, replacement objects, or a general object database. Routine tests also install a guard that rejects Git initialization, staging, commits, index mutation, replacement objects, and physical `.git` creation from both direct and subprocess execution paths. A fake `git` executable exercises the production command-line entry point without initializing a repository.

`make test-content-policy-git` is the required genuine-Git integration profile. It creates disposable repositories and verifies initialization, staging, commits, staged and worktree divergence, tracked, untracked, ignored, deleted, and unmerged behavior, object-ID blob reads, and resistance to `git replace`. It also exercises bounded cleanup diagnostics for disposable repository cleanup. This suite is deliberately excluded from `make test` and `make all`.

## Repository content policy

The checker applies `tests/fixtures/registry.json` independently to the index and current worktree. It reports findings from either snapshot without displaying matched bytes, registry content, raw Git errors, or absolute host paths. The initial registry is empty. An unstaged new registry is accepted in the index only while the index contains no binary fixtures; the worktree registry remains required once present.

Resource limits apply across both snapshots: 10,000 file versions, 16 MiB per file version, 64 KiB total stderr per command, 64 MiB total stdout, and 10 seconds per command. A path present in both snapshots counts twice. Any Git stderr output fails closed with a sanitized code. Pattern scanning does not establish copyright status, identify every secret, or validate the truth of provenance statements. Human review remains required. See [ADR 0016](adr/0016-repository-content-policy.md) for the fixture registry and prohibited-content rules.

The native Inspection qualification described below is separate from content-policy enforcement. It does not replace `make content-policy` or `make test-content-policy-git`.

## GitHub Actions

The `validate` job runs `make all` on `ubuntu-24.04` for pushes to `main` and pull requests. A separate required job named `content-policy-git` uses the same pinned checkout action, read-only repository permissions, and a bounded timeout to run `make test-content-policy-git`. Neither job uses `continue-on-error`, broad skips, or an allowed-failure mode.

Repository branch protection is external GitHub configuration. If protection uses explicit required-check names, `content-policy-git` must be enrolled there in addition to `validate`; updating this workflow cannot prove that remote setting.

## GPT Repo MCP integration

`repo_validate` accepts named validation profiles rather than arbitrary shell commands. The approved repository entry in GPT Repo MCP's local `config.local.json` must map profiles to these Make targets while preserving its other policy settings:

```json
{
  "enabled": true,
  "validation_enabled": true,
  "validation_profiles": {
    "test": { "runner": "make", "target": "test" },
    "build": { "runner": "make", "target": "build" },
    "lint": { "runner": "make", "target": "lint" },
    "typecheck": { "runner": "make", "target": "typecheck" },
    "smoke": { "runner": "make", "target": "smoke" },
    "all": { "runner": "make", "target": "all" }
  }
}
```

That fragment belongs inside the repository's `operations` object. Do not copy local server configuration or credentials into NSCB. Validation also requires the server-side operation policy to permit the selected repository and command.

After updating the server configuration, use `repo_list_roots` to confirm the intended repository ID and exact worktree root. Run `repo_validate` with a dry run first to verify the selected command, then run the approved profile without the dry run. MCP validation profiles do not accept focused test paths; run focused Rust tests directly in a trusted terminal when needed.

## Recognition validation

Run these focused checks before the full repository gate when changing recognition:

```sh
cargo test --locked --all-features recognition::tests
cargo test --locked --all-features --test public_facade
cargo test --locked --all-features --test cli_subprocess
make all
```

Recognition fixtures are deterministic generated source data. No proprietary binaries or cryptographic material are required.

## Inspection validation

Inspection uses the same repository validation entry point:

```sh
make all
```

Focused Rust verification can be run directly:

```sh
cargo test --locked --all-features inspection::tests
cargo test --locked --all-features provider::
cargo test --locked --all-features cli::inspection_cli_tests
cargo clippy --locked --all-targets --all-features -- -D warnings
```

Provider cache tests create temporary directories and files without changing the repository or host cache. Fake-provider tests are compiled only under `#[cfg(test)]` and cover argv, environment, output bounds, signals, nonzero exits, reader cleanup, cancellation, timeouts, process reaping, descendant processes, input and key mutation, and postcondition rejection without network access. Native NSTool qualification remains limited to macOS arm64 and is recorded in [Inspection qualification evidence](testing/inspection-qualification.md).
