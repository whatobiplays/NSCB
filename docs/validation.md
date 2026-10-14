# Development validation

NSCB uses a repository-owned `Makefile` for consistent local and automated validation. GNU/BSD Make, Git, Python 3.11 or newer, and Rust 1.98.1 are required; `rust-toolchain.toml` pins Rust and includes `rustfmt` and `clippy`. Python policy infrastructure uses only the standard library. All Cargo targets use the checked-in `Cargo.lock`.

| Validation profile | Make target | Commands |
| --- | --- | --- |
| `content-policy` | `make content-policy` | `PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/check_content_policy.py` |
| `typecheck` | `make typecheck` | `cargo check --locked --all-targets --all-features` |
| `lint` | `make lint` | `cargo fmt --all -- --check`, then `cargo clippy --locked --all-targets --all-features -- -D warnings` |
| `test` | `make test` | Python policy tests (`PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_content_policy.py'`), fake-only lifecycle tests (`PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_git_ai_isolation.py'`), then `cargo test --locked` |
| `build` | `make build` | `cargo build --locked` |
| `smoke` | `make smoke` | `cargo test --locked --test cli_subprocess` (real CLI subprocess tests) |
| `all` | `make all` | All six profiles above, in the order shown |
| `all-git-ai-paused` | `make all-git-ai-paused` | Sequentially runs `content-policy`, `typecheck`, `lint`, `test-git-ai-paused`, `build`, and `smoke` in `all` order; the pause wrapper replaces only the Python content-policy suite |

`make` prints the available targets. `make fmt` **modifies source files** and must not be mapped to a validation profile. `make lint` only checks formatting.

Python recipes set `PYTHONDONTWRITEBYTECODE=1` and use `PYTHONDONTWRITEBYTECODE=1 python3 -B` so validation does not leave `.pyc` files in the working tree.

The content-policy checker independently inspects stage-zero Git index blobs and current working-tree files, including nonignored untracked paths reported by Git. It validates each snapshot against that snapshot's own `tests/fixtures/registry.json`; one registry cannot authorize or conceal content in the other snapshot. Unresolved Git index conflicts stop the check. It does not walk directories to discover ignored untracked paths or untracked FIFOs and other special files that Git omits. A Git-visible path that is a symlink or special file fails safely. The combined scan is limited to 10,000 file versions across the index and worktree (a path present in both counts twice), 16 MiB per file version (1 MiB for the registry), and 256 MiB total bytes. Each Git command is limited to 64 MiB of stdout, 64 KiB of stderr, and 10 seconds. Any Git stderr causes a sanitized failure; raw warnings are never displayed. Diagnostics contain rule codes and bounded relative paths, never matched content.

The registry starts empty. When it is first added as an unstaged, nonignored file, an absent index copy is accepted only while the index contains no binary assets; the worktree copy remains required. Add the registry and any binary fixture together to the Git index before treating the indexed snapshot as a valid registered-fixture state. The checker detects common prohibited filenames and key/credential patterns, but pattern scanning cannot establish that arbitrary content is redistributable or identify every secret. Human review of fixture provenance remains required. See [ADR 0016](adr/0016-repository-content-policy.md) for the registry contract and detection limits.

`make clean` runs `cargo clean` to remove generated Cargo build artifacts. It does not remove source files or `Cargo.lock`, and is deliberately excluded from the `all` validation profile.

`make all-git-ai-paused` is an explicit opt-in for a full validation run that pauses Git AI only while the Python content-policy suite executes. If Git AI is installed and its daemon is running, the wrapper gracefully shuts down that global service and starts it again after the suite. Other repositories, editors, and tools using Git AI are affected during that interval. If the daemon was already stopped or Git AI is unavailable, the wrapper leaves its state unchanged. The ordinary `make all` and `make test` targets and GitHub Actions never stop Git AI automatically.

The wrapper serializes its own invocations, but its lock cannot prevent another application or Git AI's service manager from restarting the daemon. It detects an unexpected restart during the isolated suite and aborts. Avoid running the opt-in target while other users or automation rely on the global service. SIGINT and SIGTERM trigger bounded cleanup and restoration; SIGKILL, a machine crash, or power loss can interrupt restoration. If the wrapper cannot confirm that its test process group has exited, do not restore the daemon; recover only after group termination is confirmed.

If the wrapper reports that restoration failed after it stopped a daemon that was initially running, inspect the service from outside a repository and start it if status confirms it is stopped:

```sh
(cd / && git-ai bg status)
(cd / && git-ai bg start)
(cd / && git-ai bg status)
```

The wrapper returns a failure status when restoration fails. Check the reported initial state before manually starting Git AI, since an initially stopped daemon should remain stopped.

## GPT Repo MCP integration

GPT Repo MCP's `repo_validate` accepts named validation profiles, not arbitrary shell commands. Its Make runner requires an explicit mapping in the MCP server's **local** `config.local.json` for the approved NSCB repository.

Merge the following fields into that repository entry's existing `operations` object, preserving any other policy settings:

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

This fragment is the `operations` object, not an entire MCP configuration. Do not copy the server's local config or credentials into NSCB. Validation also requires the server-side repository operation policy to permit validation; defining the Makefile alone does not enable it.

After updating the server configuration, use `repo_validate` with the approved repository ID, `profile: "all"`, and `dry_run: true` to verify that the selected command is `make all`. Run the same profile without `dry_run` to execute the checks. Individual profiles select their matching `make` target.

**Focused-test limitation:** MCP-declared Make profiles do not support `test_paths`. Omit that field entirely (do not send an empty array). For a focused Rust test invocation, run Cargo directly in a trusted local terminal. Registration-time delegation validation metadata is a separate contract and is not rewritten by these targets.

## CI usage

GitHub Actions runs `make all` on `ubuntu-24.04` for pushes to `main` and pull requests. It installs the Rust channel and components declared in `rust-toolchain.toml`; the Makefile remains the single owner of validation commands. The workflow exercises Linux x86_64 only and does not change the broader platform qualification matrix.
