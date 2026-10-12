# PFS0 Container Probe

## API and scope

The Rust library exposes one host-neutral `Engine` facade. Callers create a `ContainerProbeRequest` with a file path and call `Engine::probe_container`. A successful `ContainerProbeResult` contains the recognized outer-container format, observed file size, payload region, and ordered `ContainerProbeEntry` values. Each entry reports its UTF-8 name, payload-relative offset, declared size, and checked absolute file position.

The probe validates supported outer-container framing only. It does not interpret embedded content or establish content identity. A PFS0 signature and entry table do not prove that an input is a genuine NSP, identify a Nintendo title, or establish the identity or support status of embedded content. The operation does not consume or validate keys, decrypt, or make integrity, signature, authenticity, or Verification-success claims.

The facade requires no key source, global state, persistent storage, or asynchronous runtime. It admits regular files only, opens them read-only, and reads the fixed PFS0 header and bounded entry and string tables. On Unix-like systems, it opens with `O_NONBLOCK` and validates the opened handle, so even a path that resolves to a FIFO cannot make the probe wait for a writer. Other targets reject known non-regular paths before opening and validate the opened handle; the path preflight alone is not treated as a race-free guarantee. The probe does not load payload bytes into memory or write to the input.

## PFS0 validation and resource bounds

The parser validates the header, entry table, string table, names, and declared spans against the observed file size. Entry offsets are relative to the payload region, which begins after the header, entry records, and string table. The returned `file_offset` is computed with checked addition from that payload start.

Validation includes:

1. The 16-byte header, PFS0 magic, zero reserved header and entry fields, and consistent entry-count/string-table declarations.
2. At most 65,536 entries and a string table no larger than 16 MiB.
3. NUL-terminated UTF-8 names, nonempty names, valid offsets at string boundaries, and names no longer than 4 KiB.
4. At most 16 MiB of copied filename bytes across the result, so repeated references cannot amplify a small table into an unbounded result allocation.
5. Checked table and entry arithmetic, complete metadata and declared entry spans within the observed file size, and no overlapping nonempty entry spans.

The `payload_size` is the number of bytes after the metadata tables. Those bytes are not read. Names and sizes are reported as PFS0 entry metadata; the probe does not infer what an entry contains.

Probe errors expose stable categories such as `unsupported_format`, `truncated_input`, `invalid_header`, `invalid_string_table`, `invalid_entry`, `limit_exceeded`, `name_too_long`, `input_unavailable`, and `resource_limit_exceeded`. Error values and CLI output omit paths, parser internals, and input bytes.

## CLI and JSON contract

The normal command is:

```text
nscb probe <path> [--json]
```

The CLI uses the same typed Engine facade as Rust callers. It accepts no key path, credentials, test flag, environment bypass, or alternate probe path. `--json` writes one newline-terminated JSON document to stdout for success and handled errors. Success uses `schema_version: 1` and `kind: "container_probe.result"`; handled errors use `kind: "error"` with a stable error code. The result schema is identified by its Container Probe kind and is separate from content-aware Inspection and Verification contracts.

Exit classes are 0 for success, 2 for usage errors, 3 for input errors, and 7 for internal resource or output failures. JSON-mode handled errors leave stderr empty. Non-JSON usage, success, input-error, and output-failure presentation comes from the bundled English resource at `locales/en.json`; stable Engine error codes remain independent of that CLI presentation.

## Tests and platform evidence

Tests generate deterministic synthetic PFS0 bytes. They exercise the public facade, the real `CARGO_BIN_EXE_nscb` subprocess, equivalent facade and CLI results, malformed and adversarial inputs, stable sanitized errors, input-byte preservation, and single-document JSON output. Parser tests also verify that payload bytes are not read and that supported size limits and arithmetic checks remain in force.

The required checks were run on macOS 27.0 arm64 (`aarch64-apple-darwin`) with Rust 1.98.1. This host-local evidence does not qualify Windows, Linux, or other architectures.

## Toolchain and dependencies

`rust-toolchain.toml` pins Rust 1.98.1, and `Cargo.toml` declares the same MSRV. `serde` derives serialization for typed output, while `serde_json` provides the versioned JSON wire format and escaping. Both dependencies are locked in `Cargo.lock`.

## Deferred boundaries

Content-aware Inspection, Verification, key discovery and configuration, embedded-content interpretation, and support for other container formats are outside this Container Probe. The probe is a separately requested structural operation and is never an automatic Inspection fallback.
