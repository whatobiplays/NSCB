# Development validation

NSCB uses a repository-owned `Makefile` for consistent local and automated validation. GNU/BSD Make and Rust 1.98.1 are required; `rust-toolchain.toml` pins Rust and includes `rustfmt` and `clippy`. All compilation and test targets use the checked-in `Cargo.lock`.

| Validation profile | Make target | Commands |
| --- | --- | --- |
| `typecheck` | `make typecheck` | `cargo check --locked --all-targets --all-features` |
| `lint` | `make lint` | `cargo fmt --all -- --check`, then `cargo clippy --locked --all-targets --all-features -- -D warnings` |
| `test` | `make test` | `cargo test --locked` |
| `build` | `make build` | `cargo build --locked` |
| `smoke` | `make smoke` | `cargo test --locked --test cli_subprocess` (real CLI subprocess tests) |
| `all` | `make all` | All five profiles above, in the order shown |

`make` prints the available targets. `make fmt` **modifies source files** and must not be mapped to a validation profile. `make lint` only checks formatting.

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

Any future CI workflow should invoke `make all` so CI and MCP use the same validation contract. The Makefile does not, by itself, introduce a CI workflow or change the supported platform qualification matrix.
