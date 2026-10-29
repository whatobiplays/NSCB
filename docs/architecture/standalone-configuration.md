# Standalone configuration architecture

## Scope and ownership

Persistent standalone state is owned by the `nscb` executable, not by the
public Engine library. `src/standalone` is a binary-only module that handles
global information commands, configuration, key replacement, native paths, and
the implicit Copy destination. The embedded `Engine`, operation request types,
and publication model receive only explicitly resolved values from the
standalone adapter. The copy-through resolver also supports one missing final
destination-directory component beneath an existing canonical anchor. Immutable
planning records that state without creating or write-probing the directory;
execution revalidates the anchor and creates the directory before publication.

This boundary keeps embedded hosts in control of runtime, storage, lifecycle,
and destination policy. It also prevents an embedding application from loading
or creating a user's NSCB CLI configuration as a library side effect.

## Startup sequence

The binary handles arguments in this order:

1. If the first argument is `-h`, `--help`, `-V`, or `--version`, write the
   global information and exit without creating configuration.
2. If the command is `config` or `keys`, run the standalone command handler.
   These handlers load or initialize configuration before acting.
3. For every other normal command, load or initialize configuration before
   constructing the Engine or invoking CLI planning.
4. For standalone Copy, resolve an omitted destination through the loaded
   configuration and then pass a concrete destination to the Engine.

A configuration startup failure is reported through the same human/machine
separation as a handled command failure. A requested `--json` or `--jsonl` mode
receives one versioned error document on stdout; JSONL job events are not
started before a Copy job is admitted. Human diagnostics use stderr.
Configuration failures use exit class 2. A path that cannot be represented as
UTF-8 for the standalone contract uses exit class 3. Configuration path
representation is checked before loading, locking, or first-use creation, so
`config path`, `config show`, and ordinary command startup fail without
creating or changing configuration state when that path is unrepresentable.

## Native path policy

The path resolver has three independent results:

- The per-user configuration file is `<per-user config base>/NSCB/config.toml`.
- The conventional key file is `<user profile>/.switch/prod.keys`.
- The default output base is `dirs::document_dir()/NSCB_output`.

The configuration and profile bases must be absolute before NSCB appends the
`NSCB` or `.switch/prod.keys` product path. Normal startup creates the
configuration parent directories when needed. A configured key path is stored
without requiring the key file to exist; commands that use or replace the file
handle its availability.
On Linux, `dirs` supplies XDG configuration semantics and reads the
`XDG_DOCUMENTS_DIR` user-directory definition. On Windows, `APPDATA` and
`USERPROFILE` select the configuration and key-file bases when those standard
environment values are present. If either is absent, NSCB uses the matching
native known-folder result. The default output continues to use the native
Documents known folder. On macOS, configuration uses Application Support and
the default output uses Documents under the home directory.

Output policy is separate from configuration path policy. An unresolved
configuration root is a configuration failure. The Documents resolver has its
own availability rules: an implicit Copy destination requires an absolute,
existing Documents directory. `NSCB_output` may be missing. Planning records an
existing canonical anchor without creating or write-probing the child;
execution creates that one final child after source preflight and before atomic
publication. NSCB does not recursively create a missing Documents path or
choose a fallback. This resolution is needed only when `output_dir` is unset and
a command needs the default. An explicit `output_dir` lets `config show` render
configuration without resolving Documents.

## Configuration state

The loaded state contains the file path, the original source schema version,
and a parsed `toml_edit::DocumentMut`. Keeping the editable document allows an
explicit save to preserve tables, values, comments, and formatting that schema
version 1 does not interpret.

Schema version 1 recognizes only:

- `schema_version = 1`
- Optional absolute `keys_path`
- Optional absolute `output_dir`

Known values are type checked on every load. Unknown values remain available to
the editable document and to `config show`. A missing `schema_version` is read
as schema version 0. A version newer than the binary supports is rejected
without fallback, rewrite, or reset.

## Mutation and migration

`config set` edits the in-memory document and then performs an atomic save. It
preserves unrecognized values in compatible files. `config reset` intentionally
constructs a fresh schema-version-1 document, so it does not preserve previous
manual or unknown values.

An explicit save from schema version 0 first writes the exact original bytes to
`config.toml.v0.bak`. The backup is written through the same atomic replacement
primitive. If the backup path already contains identical bytes, NSCB reuses it;
if it contains different bytes, the save stops with `config_backup_failed` and
neither file is changed. Symlink and non-regular backup targets are rejected
without modifying the backup or configuration. Only after a durable backup
succeeds does the explicit save write schema version 1.

No load path performs an automatic migration. A compatible older file can be
shown or used as-is until an explicit set or reset asks NSCB to save it.

## Atomic replacement and locking

Configuration commands open `config.lock` and hold an exclusive file lock for
the complete read-modify-write sequence. The lock coordinates NSCB processes;
it cannot prevent a separate editor from changing the file.

Configuration and key saves use `atomic_replace_io`:

- Create the destination directory with mode `0700` on Unix.
- Create a temporary file in the destination directory with mode `0600` on
  Unix so replacement never passes through a permissive new file.
- Write all bytes and synchronize the temporary file.
- Replace the destination atomically with `rename` on Unix or
  `MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` on Windows.
- On Unix, keep a same-directory hard link to an existing regular destination
  until the replacement and parent-directory synchronization succeed. If the
  post-replacement sync fails, restore the previous file and synchronize the
  rollback before returning an error; remove a newly created destination on
  that failure path. If restoring the hard link itself fails, retain it as a
  `.nscb-rollback-*` recovery file in the destination directory. The destination
  may still contain the new bytes; the retained, pre-synchronized link holds
  the previous bytes for manual recovery. User-facing errors remain redacted.

The configuration path itself must be an ordinary file. Symlinks and other
non-regular entries are rejected. Configuration is limited to 1 MiB. A partial
temporary file cannot become the visible destination.

## Redaction classification

`config show` renders each unknown TOML value with its dotted path. A path
segment containing `access_key`, `api_key`, `credential`, `password`,
`private_key`, `secret`, or `token`, case-insensitively, is classified as
sensitive. The fragment rule covers conventional compound identifiers such as
`aws_access_key` without treating the recognized `keys_path` setting as a
credential. Regular tables, inline tables, and nested tables in arrays are
traversed recursively, so only sensitive leaves are replaced with `[REDACTED]`;
their machine records have `sensitive: true`. Classification affects display
only: unknown values remain accepted and preserved.

The classification mechanism exists so compatible future configuration can be
displayed safely. Version 1 does not implement translation credentials or add
new sensitive settings. Error documents carry only stable error codes and never
echo TOML values or operating-system error text.

## Complete key replacement

`keys set <source>` reads and validates the selected complete file, then writes
those exact bytes to the conventional key path. The standalone command and
provider share a pure header-key parser. The provider serializes the parsed
header into its reduced temporary helper input; `keys set` uses the parser only
for validation and persists the untouched source bytes, including comments,
unrelated entries, and original whitespace.

Validation requires an ordinary source no larger than 1 MiB with at least one
valid `header_key` or `nca_header_key`. Duplicate aliases must agree. The parser
validates a bounded in-memory copy and zeroes that copy before returning.
Destination path representation and parent discovery complete before the
complete file is read. After the read, a local owner holds the bytes through
validation and atomic installation and uses volatile writes to zero the entire
buffer on every return or unwind. The destination replacement then uses the
common atomic primitive, creating the `.switch` directory with user-only
permissions on Unix.

A rejected source returns before destination creation or replacement. A failure
while preparing the temporary destination leaves the previous key file in
place. Key values never appear in command arguments, human output, JSON, error
codes, or diagnostics. The command always targets the conventional path; it
does not edit `keys_path`.

## Key and output resolution

Inspection and Verification receive a resolved key source from the CLI:

1. Explicit `--keys` path.
2. Configured `keys_path`.
3. Conventional `~/.switch/prod.keys`.

Once a configured path exists, a missing file fails closed; the conventional
path is not a fallback. Embedded callers continue to pass their key selection
in the typed operation request.

Copy destination resolution is also standalone-only:

1. Explicit positional destination.
2. Configured absolute `output_dir`, followed by the source file name.
3. Native `Documents/NSCB_output`, followed by the source file name.

The implicit directory may be missing and is not created or write-probed during
planning. The resolved path becomes the concrete Engine request destination.
The immutable plan records one missing final component beneath an existing
canonical anchor. Execution revalidates that anchor, performs source preflight,
creates only that final component, and then continues through conflict policy,
staging, validation, and atomic publication. There is no fallback. No
`--output` alias is introduced.

Copy is a normal standalone command, so startup loads or initializes the
standalone configuration before planning. Copy does not persist per-job source,
destination, workspace, or replacement choices back into that configuration.

## Machine contract

Configuration and key commands support only human mode and a single-document
`--json` mode; they do not use JSONL. Success documents use schema version 1
and kinds `config.path`, `config.show`, `config.set`, `config.reset`, or
`keys.set`. Handled failures use schema version 1 and `kind: "error"` with a
sanitized code.

Exit class 0 means success. Exit class 2 covers invalid command usage and
configuration failures. Exit class 3 covers key validation, input or
prerequisite failures, and paths that cannot be represented. Exit class 7
means failure to write the required document. Human success goes to stdout and
human failure to stderr. Machine stdout contains exactly one document and no
human diagnostics. Existing Probe and Copy records and exit classes remain
compatible.

## Qualification limits

Real-binary tests execute on the build host and use isolated HOME, XDG, APPDATA,
cache, key, and output paths. The current native qualification host is macOS.
Path composition tests cover representative macOS, Linux, and Windows base
directories, and integration tests exercise the current host's native path
resolver. Those checks do not qualify native Linux XDG discovery, Windows
Documents resolution, or Windows replacement behavior. Cross-platform
qualification requires running the real binary and relevant failure cases on
each platform.
