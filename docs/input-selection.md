# Input selection and resolution

NSCB resolves ordered paths, directory candidates, and versioned JSON input lists through one read-only Engine operation. Resolution returns filesystem paths, observed file sizes, ordered physical segments, and the selection provenance for each result. It does not inspect content bytes, recognize a Nintendo content family, validate identity, or establish authenticity.

## Rust API

Embedding hosts call `Engine::resolve_inputs` with an explicit absolute base directory:

```rust
use nscb::{Engine, InputResolutionRequest};

let request = InputResolutionRequest::new(host_input_root)
    .with_path("first.bin")
    .with_input_list("lists/selection.json")
    .with_recursive(true);

let result = Engine::new().resolve_inputs(request)?;
```

Relative direct paths use the request's base directory. Relative paths inside an input list use the directory containing that list. The Engine does not consult the process working directory; a host must choose both bases through the request and list location.

The request preserves selection order. Each `ResolvedInput` contains an ordered `segments` vector and `provenance`. A supported v1 non-Split input has one segment. The vector and non-exhaustive public result types allow future additive segment support without changing the existing v1 representation. A segment record reports a canonical absolute path and the file size observed during resolution.

## CLI

```text
nscb resolve [--json] [--recursive] [--follow-symlinks] [--input-list FILE] [PATH...]
```

Each positional path and each `--input-list FILE` is one selection at the position where it appears. Repeating `--input-list` is allowed. Direct CLI paths and list-file paths are relative to the current working directory. List entries are relative to their list file.

Explicit regular files are eligible regardless of filename extension. Directories use this candidate extension set, case-insensitively:

```text
.nsp  .nsz  .nsx  .xci  .xcz  .nca  .ncz
```

The extension filter applies only to directory discovery. Hidden matching files are included. Directory candidates are sorted by NFC-normalized, lowercased relative path; caller selections and entries within each list retain their supplied order. An empty request, empty list, empty directory result, or any unusable selected path is a typed failure rather than a successful empty batch.

Directory discovery is nonrecursive and skips discovered symlinks by default. `--recursive` enables recursive discovery. `--follow-symlinks` allows traversal through discovered symlinks; discovered directory symlinks are traversed only when recursion is also enabled. An explicitly selected directory symlink can be used as the discovery root with `--follow-symlinks` alone. Explicit regular-file symlinks are eligible selections. A symlink target reached during discovery must stay within the selected directory tree. Cycle back-edges are skipped. Reaching the same directory through another alias or selecting the same logical file more than once returns `duplicate_selection`.

## JSON input-list v1

A list is data for selecting paths; it is not an Operation Plan and cannot request execution. Its required shape is:

```json
{
  "schema_version": 1,
  "kind": "nscb.input_list",
  "required_features": [],
  "entries": [
    { "path": "../incoming/item.nsp" },
    { "path": "archive/another.nsz", "label": "optional metadata" }
  ]
}
```

The top-level `schema_version`, `kind`, `required_features`, and `entries` fields are required. Each entry must be an object with a nonempty string `path`. Absolute entry paths remain absolute; relative entries use the list file's parent directory. Unknown optional fields are ignored, but duplicate keys are rejected anywhere in the JSON document. The v1 resolver supports no required features, so a nonempty `required_features` array fails with `unsupported_required_feature`. Unknown schema versions and malformed entry shapes fail with typed errors.

Successful CLI JSON uses one versioned document:

```json
{
  "schema_version": 1,
  "kind": "input_resolution.result",
  "nscb_version": "…",
  "result": {
    "inputs": [
      {
        "segments": [
          { "path": "/absolute/path/item.nsp", "size_bytes": 4096 }
        ],
        "provenance": {
          "selection_index": 0,
          "source": "path",
          "selection_path": "item.nsp"
        }
      }
    ]
  }
}
```

The segment array is ordered. Provenance indexes top-level selections from zero; list entries also carry their zero-based `input_list_entry_index` and original `input_list_entry_path`. Directory discoveries include `discovered_directory` and `discovered_relative_path`. Optional provenance fields are omitted when they do not apply. Successful CLI JSON encodes every path as valid UTF-8. If a result or provenance path cannot be represented that way, the command emits the typed `unrepresentable_path` error with exit 3 instead of writing an ambiguous path. The Rust API retains native `PathBuf` values.

Handled failures use the existing versioned `kind: "error"` document with a sanitized `error.code`. Exit classes follow ADR 0023: 0 means success, 2 means usage/configuration error, 3 means input or prerequisite failure, and 7 means internal or output failure. Duplicate logical selections are input-resolution failures and use exit 3.

## Split-set deferral

No Split layout is currently supported. A file selected explicitly or encountered during directory discovery is rejected with `unsupported_split_layout` when its name resembles a numbered canonical segment or a legacy `.xcN` / `.nsN` part. The conservative checks include numeric-only filenames, numeric suffixes, and the legacy `.xcN` and `.nsN` patterns. These checks identify suspicion only; they do not infer a segment count, completeness, order, content family, or validity.

The canonical directory/archive layout and legacy compatibility layouts remain deferred until their exact segment grammar, completeness evidence, overlap behavior, and collision handling are qualified. A suspected Split part is never returned as a successful standalone input.

## Duplicate identity, bounds, and filesystem limits

Resolution rejects duplicate canonical paths, case- and NFC-normalized path keys, and file identities when the operating system exposes a stable identity. Unix uses device and inode values, which also detect hard links. On other targets without a stable identity in the supported Rust standard library, duplicate detection falls back to canonical paths and normalized path keys; distinct hard-link names on those filesystems may not be recognized as duplicates. Network and virtual filesystems can expose unstable identities, so their duplicate guarantees depend on their metadata behavior.

Traversal is bounded to 64 directory levels and 100,000 entries per request. Each JSON input list is limited to 1 MiB; all lists together are limited to 4 MiB and 100,000 entries per request. Special files are not opened as content; an explicitly selected non-regular file or a matching special directory entry fails. Resolution records metadata observed during the call and does not hold file handles or guarantee that files remain unchanged afterward.
