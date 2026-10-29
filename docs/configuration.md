# Standalone configuration and key files

The `nscb` executable stores persistent settings in one per-user TOML file.
The setting is available to standalone Inspection, Verification, and Copy
commands. The Rust Engine library does not load this file or create user state;
embedding hosts continue to choose their own configuration and destination
policy.

## First use and global information

The first ordinary standalone command creates the configuration directory and
`config.toml` when they do not exist. Later commands load the same file. If the
configuration cannot be created, read, parsed, or validated, the command stops
with exit class 2 and an actionable error. This includes malformed or invalid
TOML, an unsupported schema version, invalid settings, unavailable
configuration directories, and lock, write, or backup failures. A
non-representable configuration path is a prerequisite failure and uses exit
class 3. The configuration path is checked for representation before first use
can create its directory, lock, or file, so that failure leaves no new
configuration state. A native default path displayed by `config show` or
included in generated comments must also be representable as UTF-8. If it is
not, NSCB reports `config_path_invalid` and exit class 3 instead of
substituting replacement characters in the displayed path.

The root help and version options are available before configuration startup:

```text
nscb --help
nscb -h
nscb --version
nscb -V
```

These commands do not create or read configuration. A no-argument non-TTY
invocation keeps its existing usage behavior, while normal commands initialize
configuration before the Engine operation starts.

## Native locations

NSCB uses the platform's per-user configuration and Documents locations. The
runtime locations are:

| Platform | Configuration file | Default Copy destination base |
| --- | --- | --- |
| macOS | `~/Library/Application Support/NSCB/config.toml` | `~/Documents/NSCB_output` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/NSCB/config.toml` | The `XDG_DOCUMENTS_DIR` entry from the XDG `user-dirs.dirs` file, followed by `NSCB_output` |
| Windows | `%APPDATA%\NSCB\config.toml` (native roaming-data fallback only if `APPDATA` is absent) | The native Documents known-folder location, followed by `NSCB_output` |

The platform-specific configuration locations and default `output_dir`
resolution above are configuration behavior. They do not extend Copy-through
execution support to Linux or Windows. Copy-through is qualified only on macOS;
on every other target, planning and execution fail closed with
`UnsupportedCapability`, so Copy-through does not modify or publish a
destination.

On Linux, the XDG configuration directory is used only when it is an absolute
path. The Documents location comes from the XDG user-directories file; NSCB
does not substitute `~/Documents` when that definition is absent or unusable.
Configuration and profile bases must be absolute before NSCB appends its
product paths. Normal startup creates the configuration parent directories when
needed. A configured key path may refer to a file that does not exist yet;
commands that use or replace that file handle its availability. The Documents
location follows separate rules: it must resolve to an absolute, existing
directory before Copy can use the implicit destination. The `NSCB_output`
child may be missing. Planning records that safely without creating or
write-probing it; execution creates the final child only after source preflight
succeeds and before atomic publication. A missing or unwritable Documents
location makes an implicit Copy destination fail. NSCB does not recursively
create missing intermediate directories or fall back to the current directory,
executable directory, temporary directory, or home directory.

The conventional key file is `~/.switch/prod.keys` on macOS and Linux. On
Windows it is `%USERPROFILE%\.switch\prod.keys`; NSCB uses the native profile
known folder only when `USERPROFILE` is absent. Windows Documents resolution
remains native and is independent of these configuration and profile paths.

## Configuration file

Schema version 1 contains two optional absolute-path settings:

```toml
# NSCB standalone configuration
# This file is versioned. NSCB preserves unknown values during edits.
schema_version = 1

# Absolute path to a complete key file used by inspect and verify.
# When omitted, NSCB uses the conventional ~/.switch/prod.keys file.
# keys_path = "/home/alice/.switch/prod.keys"

# Absolute directory used when copy omits its destination.
# When omitted, NSCB uses Documents/NSCB_output.
# output_dir = "/home/alice/Documents/NSCB_output"
```

The generated file uses the actual paths available on the host. When a
location cannot be resolved, the generated comment reports that condition
instead of inventing a fallback.

`keys_path` changes the configured key source for Inspection and Verification.
`output_dir` supplies the directory used by Copy when its destination argument
is omitted. `config show` resolves the Documents default only when `output_dir`
is not configured. `config set` checks that both values are nonempty and
absolute. It does not require the target to exist; commands that use the path
report an unavailable path when needed.

NSCB preserves manually maintained TOML values when `config set` rewrites a
compatible file. `config show` lists unknown values after the two recognized
settings and marks values redacted when any field name in the path contains
`access_key`, `api_key`, `credential`, `password`, `private_key`, `secret`, or
`token`, ignoring case. This covers identifiers such as `aws_access_key` while
leaving the recognized `keys_path` setting visible. The classifier walks
regular and inline tables, including nested tables in arrays, so a sensitive
leaf is redacted without hiding unrelated sibling values. Unknown values
remain accepted and preserved. This is a display safety mechanism for
compatible files; it does not enable a translation or credential feature.
`config reset` intentionally replaces the complete file with the currently
generated schema-version-1 baseline. It therefore discards configured settings
and compatible unknown TOML values.

## Configuration commands

```text
nscb config path [--json]
nscb config show [--json]
nscb config set <keys_path|output_dir> <absolute-path> [--json]
nscb config reset [--json]
```

`config path` creates a missing file and prints its path. `config show` prints
the file path, schema version, effective values, whether each recognized value
came from the file or its default, and compatible additional values. Human
output is the default. Sensitive values are replaced by `[REDACTED]` in both
human and machine output.

Human output preserves literal brace text in paths and values. Text resembling
`{name}`, `{value}`, or `{schema_version}` is printed unchanged.

`config set` changes one recognized field while retaining compatible unknown
TOML entries. `config reset` replaces the complete file with the commented
schema-version-1 baseline, removing configured `keys_path` and `output_dir`
settings as well as compatible unknown TOML entries. It does not delete files
referenced by those settings or the conventional `~/.switch/prod.keys` file;
other data outside the configuration file is also preserved.

## Key-file precedence

Inspection and Verification choose the key source in this order:

1. An explicit `--keys <path>` argument.
2. A configured absolute `keys_path`.
3. The conventional `~/.switch/prod.keys` file.

A configured path that is missing or invalid fails closed. NSCB does not fall
back to the conventional file when `keys_path` is present. Normal Inspection
and Verification never copy, refresh, or modify a key file.

## Replacing the conventional key file

Use the following command when the user has explicitly chosen a replacement:

```text
nscb keys set <source> [--json]
```

The source must be an ordinary file no larger than 1 MiB. It must contain at
least one `header_key` or `nca_header_key` entry whose value is exactly 64
hexadecimal characters. Conflicting duplicate header keys and malformed key
entries are rejected.

Successful replacement copies the complete source byte-for-byte to
`~/.switch/prod.keys`, including comments, unrelated entries, and original line
endings. NSCB does not merge the source with the old destination. The command
creates the destination directory when needed, uses mode `0600` for the file
and `0700` for the directory on Unix, and uses an atomic whole-file replacement.
On Windows, it uses the native replace-existing and write-through file move.

Validation errors cannot modify the destination. On Unix, a save keeps a
same-directory rollback link to an existing regular destination until the new
file and parent directory are synchronized. If the post-replacement directory
sync fails, NSCB restores the previous destination before reporting failure.
If restoring that link also fails, NSCB retains the already-synchronized old
bytes in a `.nscb-rollback-*` recovery file beside the destination and reports
a write failure. The destination may still contain the new bytes; the retained
file contains the prior bytes and can be used to restore it. The CLI keeps the
recovery path out of user-facing diagnostics.
Key values are
never accepted as command-line arguments, printed by the command, included in
machine output, or included in diagnostics. `keys set` always updates the
conventional file; it does not rewrite `keys_path` in configuration.

## Copy destination resolution

Copy supports both forms:

```text
nscb copy <source> <destination> [--workspace <path>] [--replace] [--json | --jsonl]
nscb copy <source> [--workspace <path>] [--replace] [--json | --jsonl]
```

Copy-through remains macOS-only even when these rules resolve a destination on
Linux or Windows: planning and execution fail closed with
`UnsupportedCapability`, and no destination is published.

An explicit positional destination always overrides `output_dir`. When the
destination is omitted, NSCB uses the configured `output_dir`, or the native
`Documents/NSCB_output` default when `output_dir` is not configured, and appends
the source file name. Planning does not create or write-probe a missing final
destination directory. The plan records the existing parent anchor; execution
revalidates it, performs source preflight, and creates the missing final
directory immediately before the existing atomic publication path. An
unavailable or unwritable location is an input error with no silent fallback.
There is no `--output` option.

Destination selection does not change Copy conflict handling, immutable
planning, pre-publication validation, cancellation, or publication semantics.
The embedded Engine continues to require a concrete destination in its typed
request; only the standalone CLI resolves this default.

Copy is a normal standalone command, so startup loads or initializes the
standalone configuration before planning. Copy does not persist per-job source,
destination, workspace, or replacement choices back into that configuration.

## Machine output and exit classes

Every new configuration and key command accepts `--json`. Machine mode writes
exactly one newline-terminated versioned document to stdout:

```json
{
  "schema_version": 1,
  "kind": "config.path",
  "nscb_version": "0.1.0",
  "result": { "path": "/example/config.toml" }
}
```

Success kinds are `config.path`, `config.show`, `config.set`, `config.reset`,
and `keys.set`. A handled non-success emits one document with `kind: "error"`
and a sanitized `error.code`; it contains no TOML source, key value, raw
operating-system error, or path unless a success result requires that path.

Human-readable output is written to stdout on success and stderr on failure.
Machine mode keeps human diagnostics off stdout. Exit class 0 means success.
Exit class 2 covers invalid command usage and configuration errors. Exit class
3 covers key validation, other input or prerequisite failures, and paths that
cannot be represented. A startup configuration failure requested with
`--jsonl` emits one versioned error document because no Copy job has been
admitted yet. Exit class 7 is reserved for an internal failure writing the
required result.
Existing Probe and Copy machine contracts and exit classes remain unchanged.

## Schema migration and file safety

Files without `schema_version` are read as compatible version 0 files. A read
or `config show` does not rewrite them. Before the first explicit `config set`
or `config reset` migration, NSCB saves the exact original bytes as
`config.toml.v0.bak` in the same directory, then atomically writes schema
version 1. An identical regular backup is reused. Symlink and non-regular
backup targets are rejected; if a different regular backup exists, migration
stops with `config_backup_failed` and leaves the configuration and backup
unchanged.

Files with a schema version newer than the running NSCB supports, negative
versions, malformed TOML, incorrectly typed settings, invalid paths, a
configuration over 1 MiB, or a symlink/non-regular configuration path fail
closed. NSCB does not reset or overwrite a file merely because it cannot read
the schema.

NSCB-created configuration directories use mode `0700` on Unix. Configuration,
lock, and key files use mode `0600` on Unix. Saves use a temporary file in the
target directory, write and synchronize the complete contents, replace the
target, and synchronize the parent directory on Unix. If that final sync fails,
an existing regular file is restored (or a newly created target is removed)
before failure is reported. If restoration itself fails, the previous bytes
remain in a `.nscb-rollback-*` file beside the destination instead of being
deleted with the temporary-file guard. Windows uses `MoveFileExW` with
replace-existing and write-through semantics. A cooperative configuration lock
serializes NSCB processes; it does not coordinate with arbitrary programs that
edit the same file.

## Platform qualification

The implementation uses native directory APIs through `dirs` 6.0 and has been
natively exercised on macOS. Unit tests simulate representative macOS, Linux,
and Windows base directories. That simulation verifies path composition and
missing/relative-root rejection; it does not qualify Linux XDG discovery,
Windows Documents known-folder lookup, Windows replacement behavior, Unix file
permissions on Linux, or any platform-specific filesystem behavior. Those
claims require native execution on each platform.
