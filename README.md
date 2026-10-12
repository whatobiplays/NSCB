# NSCB

This repository currently contains a bounded, read-only PFS0 Container Probe.

## Container Probe

The public Rust facade exposes `Engine::probe_container(ContainerProbeRequest)`. It validates PFS0 outer-container framing and reports the observed file size, payload region, and declared entry names and spans. It reads the header and metadata tables, not payload bytes, and does not modify the input.

The probe reports outer-container structure only. A valid PFS0 structure does not establish that a file is a genuine NSP, identify a Nintendo title, or identify supported embedded content. The probe does not interpret embedded content, consume or validate keys, decrypt, or make integrity, signature, authenticity, or Verification-success claims.

Use the normal CLI command:

```text
nscb probe <path> [--json]
```

Successful JSON output is one versioned document with `kind: "container_probe.result"`. With `--json`, handled errors produce one versioned error document with a sanitized code. Exit classes are 0 for success, 2 for usage errors, 3 for input errors, and 7 for internal resource or output failures. No keys or credentials are required for this operation.

See [the Container Probe documentation](docs/container-probe.md) for the typed result, validation bounds, JSON fields, error categories, and tested-platform evidence.

## Build and validation

Rust 1.98.1 is pinned as both the development toolchain and minimum supported Rust version. Dependency versions are recorded in `Cargo.lock`.

```text
cargo fmt --all -- --check
cargo test --locked
cargo build --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
```
