# Input selection and resolution

NSCB resolves ordered paths, directory candidates, and versioned JSON input lists through one read-only Engine operation. Resolution returns filesystem paths, observed file sizes, ordered physical segments, and the selection provenance for each result. Ordinary inputs are resolved from metadata. A canonical Split set additionally requires a host-owned local receipt and is validated by streaming its complete bytes. Resolution does not recognize a Nintendo content family, validate identity, or establish authenticity.

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

Engine::resolve_inputs accepts ordinary files and directories without any Split capability. Canonical Split candidates fail with split_evidence_untrusted because no receipt store was supplied. Hosts that resolve Split sets call the additive Engine::resolve_inputs_with method:

```rust
use nscb::{
    Engine, InputResolutionCapabilities, InputResolutionControl,
    InputResolutionRequest, LocalSplitTrustStore,
};

let store = LocalSplitTrustStore::new(host_state_directory.join("split-trust"));
let control = InputResolutionControl::new();
let capabilities = InputResolutionCapabilities::new()
    .with_split_trust_store(&store)
    .with_control(&control);
let result = Engine::new().resolve_inputs_with(request, capabilities)?;
```
The capability is evaluated once per call. It adds no mutable Engine state and is not stored globally. Omitting the trust store preserves the existing Engine::new() unit-struct construction and ordinary resolution behavior.

Relative direct paths use the request's base directory. Relative paths inside an input list use the directory containing that list. The Engine does not consult the process working directory; a host must choose both bases through the request and list location.

The request preserves selection order. Each `ResolvedInput` contains an ordered `segments` vector, `provenance`, and an optional `qualification`. A non-Split input has one segment and no qualification. A qualified canonical Split set has one segment per declared member and a `SplitQualification` that reports the evidence family, manifest schema version, original source size, and original source SHA-256. The non-exhaustive public result types allow future additive evidence without changing the version-1 representation. A segment record reports a canonical absolute path and the file size observed during resolution.

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

Directory discovery is nonrecursive and skips discovered symlinks by default. `--recursive` enables recursive discovery. `--follow-symlinks` allows traversal through discovered symlinks; discovered directory symlinks are traversed only when recursion is also enabled. An explicitly selected directory symlink can be used as the discovery root with `--follow-symlinks` alone. Explicit regular-file symlinks are eligible selections. A canonical Split directory or numbered member reached through an intermediate symlinked path also requires `--follow-symlinks`, matching the directory alias policy. A symlink target reached during discovery must stay within the selected directory tree. Cycle back-edges are skipped. Reaching the same directory through another alias or selecting the same logical file more than once returns `duplicate_selection`.

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
        },
        "qualification": {
          "kind": "local_split_receipt",
          "manifest_schema_version": 1,
          "original_size_bytes": 4096,
          "original_sha256": "…"
        }
      }
    ]
  }
}
```

The segment array is ordered. Provenance indexes top-level selections from zero; list entries also carry their zero-based `input_list_entry_index` and original `input_list_entry_path`. Directory discoveries include `discovered_directory` and `discovered_relative_path`. Optional provenance fields are omitted when they do not apply. Successful CLI JSON encodes every path as valid UTF-8. If a result or provenance path cannot be represented that way, the command emits the typed `unrepresentable_path` error with exit 3 instead of writing an ambiguous path. The Rust API retains native `PathBuf` values.

Handled failures use the existing versioned `kind: "error"` document with a sanitized `error.code`. Exit classes follow ADR 0023: 0 means success, 2 means usage/configuration error, 3 means input or prerequisite failure, 6 means cooperative cancellation (including `split_resolution_cancelled`), and 7 means internal or output failure (including `split_state_unavailable`). Duplicate logical selections are input-resolution failures and use exit 3.

## Canonical Split sets

`qualification` is omitted for non-Split inputs. It establishes Split-set completeness only. It grants no content-recognition, authenticity, Verification, or execution authority.

A canonical v1 Split set is a directory containing contiguous two-digit members `00` through at most `99`, plus a deterministic sibling manifest named `<directory-name>.nscb-split.json`. One-part sets containing only `00` are supported. Selecting any member or the directory resolves the same logical input. Directory discovery recognizes a canonical Split directory by its members and sibling manifest even when the directory has an arbitrary name such as `backup.zip/`; the ordinary single-file extension filter continues to apply to files.

The unsigned manifest declares the source length and SHA-256, the ordered member names, and each member's length and SHA-256. The manifest is a consistency declaration, not a trust anchor. Resolution computes each member digest and the reconstructed whole-stream digest while streaming the opened files once. It also revalidates the opened handles, member identities and lengths, the directory identity, the exact manifest bytes, and the receipt after hashing. Missing, replaced, mutated, aliased, symlinked, special, or competing members fail closed.

The resolver only looks up receipts. It never issues, refreshes, or revives trust. A successful qualification requires an active receipt whose identity is the SHA-256 of the exact manifest bytes and whose source size and digest match the manifest's independently observed source evidence. Moving a qualified directory and manifest together on the same host preserves qualification because paths are not trust anchors. Copying the set and manifest to a host without an independent receipt does not.

Revocation is explicit and durable. A stale issuance that began before a revocation cannot overwrite the revocation; the store rejects it as stale evidence. Re-establishing trust after revocation requires a fresh authorized source-backed operation that revalidates the original source and resulting parts. Issue #6 contains only a test-only fixture issuer for this seam. It does not contain the production source-to-Split writer, which remains Issue #14 scope.

Legacy `.xcN` and `.nsN` layouts, manifest-free numbered directories, and unrecognized numbered names remain fail-closed. They are never returned as successful standalone inputs.

To keep that boundary conservative, numeric-only filenames, numeric extensions such as `notes.2024`, and numbered suffixes before a recognized content extension such as `Game.1.nsp` are treated as suspected Split-like names. Inside a canonical directory they cause incompleteness instead of being silently ignored.

## Local trust store and state directory

The standalone CLI resolves Split sets through `LocalSplitTrustStore::from_environment()`. The store root is:

1. `$NSCB_STATE_DIR/split-trust` when `NSCB_STATE_DIR` is set. The value must be an absolute, nonempty path.
2. `$XDG_STATE_HOME/nscb/split-trust` on Unix-like systems when `XDG_STATE_HOME` is an absolute path.
3. `$HOME/Library/Application Support/nscb/split-trust` on macOS.
4. `$HOME/.local/state/nscb/split-trust` on other Unix-like systems.
5. `%LOCALAPPDATA%\nscb\split-trust` on Windows.

A missing store directory is an empty store, not a configuration failure. A relative or empty `NSCB_STATE_DIR` override is a configuration error and exits 2 when a Split set is actually resolved. An unreadable, malformed, or internally inconsistent store fails with `split_state_unavailable` and exits 7. If no native state-root environment is available and the store path is missing, Split resolution fails with `split_state_unavailable`. Ordinary single-file and directory resolution does not read, create, or validate the trust store, so it succeeds even when the configured store is invalid or corrupt.

The store root contains `authority.json` and a `receipts/` directory. A sibling file named `<store-name>-continuity.json` is the host-local continuity anchor and lives outside the replaceable store root. The authority index records a random authority identifier, a monotonically advancing generation, and the issued or revoked revision of every manifest. A receipt also binds the authority identifier. Resolution requires the root authority index and the continuity anchor to agree exactly on the authority identifier, generation, and entries. A copied store root without matching local continuity evidence, a rolled-back authority index, or a foreign receipt fails closed instead of establishing trust.

Every mutation is serialized across processes by an advisory lock. Issuance and revocation compare the revision they supersede, so a stale issuance cannot erase a later revocation, and a revocation can only be replaced by fresh source-backed requalification. A complete target state, including any replacement receipt, is written to `commit.pending` before the receipt and indexes are replaced, and the journal is replayed before later reads or writes. On Unix, newly created directories and their parents are synchronized so a commit cannot outlive the directory entries it depends on. Replacement uses write-through flags on Windows; ordering of newly created directories is not qualified on Windows.

Hosts that back up a store should preserve the store root and sibling continuity file as one unit. To recover a lost root, call `LocalSplitTrustStore::restore_from_snapshot` with a snapshot taken from the same host. Restoration runs under the store lock, requires the snapshot to carry the local authority identifier, rejects a newer generation, copies only validated issued receipts, and preserves local revocations. Replacing `authority.json` or individual receipt files by hand is not restoration and fails closed. Deleting or replacing the continuity anchor is likewise not a supported recovery path.

`SplitTrustReceipt` and `SplitTrustWriter` are the public low-level seam for a future production source-backed Split producer. Constructing a receipt or calling `issue` does not itself observe the original source or validate the published output. A production caller is responsible for both steps and must never issue trust by hashing an existing sidecar and parts alone. The resolver receives only the read-only `SplitTrustStore` capability. The synthetic issuer under `tests/support` exercises the writer seam only in tests.

## Progress, cancellation, and resource bounds

`InputResolutionControl` is an optional host-owned, latest-value progress and cancellation handle. A newly constructed control reports input index 0, 0 completed bytes, and `total_bytes: None`, which means no Split input is active. While a Split set is hashed, the resolver publishes the current logical input index, total bytes read so far, and the declared source size as the expected total. The host may call `cancel()` from another thread. Cancellation is checked before and during bounded-buffer hashing and after qualification. A cancelled Split resolution returns `split_resolution_cancelled` and does not report a successful input.

The resolver uses a 1 MiB hashing buffer and never concatenates segments into a temporary file. One request may traverse at most 100,000 directory entries, parse at most 4 MiB of input lists and 100,000 list entries, and resolve at most 100,000 physical segments. Split validation is additionally bounded by `InputResolutionCapabilities::with_max_split_validation_bytes`. The budget applies to the sum of validated source sizes across every Split input in one request; exceeding it returns `resource_limit_exceeded` without producing partial JSON success. The default budget covers the largest canonical FAT32 set (100 parts of 0xFFFF0000 bytes).

An opened handle is not an immutable snapshot. Resolution validates the bytes it actually read, but later effectful operations must repeat membership, identity, receipt, and digest validation or use a verified snapshot before publishing externally visible results.

## Duplicate identity, bounds, and filesystem limits

Resolution rejects duplicate canonical paths, case- and NFC-normalized path keys, and file identities when the operating system exposes a stable identity. Unix uses device and inode values, which also detect hard links inside a Split set. Windows uses the volume serial number and file index. When a supported platform cannot prove a stable identity for a Split member or directory, qualification fails closed. Network and virtual filesystems can expose unstable identities, so their duplicate guarantees depend on their metadata behavior.

Traversal is bounded to 64 directory levels and 100,000 entries per request. Each JSON input list is limited to 1 MiB; all lists together are limited to 4 MiB and 100,000 entries per request. Special files are not opened as content; an explicitly selected non-regular file or a matching special directory entry fails. Resolution records metadata observed during the call and does not hold file handles or guarantee that files remain unchanged afterward.
