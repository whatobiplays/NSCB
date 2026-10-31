# Standalone configuration architecture

## Scope and ownership

Persistent standalone state is owned by the `nscb` executable, not by the
public Engine library. The `src/standalone` binary-only module handles global
information commands, configuration, key replacement, native paths, the
implicit Copy destination, and durable Job history. The embedded `Engine`,
operation request types,
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
3. For every other normal command, including `jobs list`, `jobs show`, and
   `jobs clear`, load or initialize configuration before constructing the
   Engine or invoking CLI planning. `jobs retry` reconstructs a typed Copy
   request and replans under the loaded configuration.
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

The path resolver has four independent results:

- The per-user configuration file is `<per-user config base>/NSCB/config.toml`.
- The per-user Job database is `<platform-local data base>/NSCB/jobs.sqlite3`.
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

## Job history state

SQLite history is owned only by the standalone executable and lives beside
standalone state under the platform-local application-data root. The database
uses NSCB's SQLite application ID, a checked integer schema version, foreign
keys, WAL journaling, full synchronization, restrictive Unix permissions, and
a bounded busy timeout. A cross-process schema-initialization lock serializes
first use and migration. It prevents two processes from racing while creating
the database, changing journal mode, or applying a schema migration.

After planning succeeds, the process locks one persistent entry in the fixed
slot registry before opening the admission writer transaction. The admission
transaction stores the new Job and an opaque claim token in SQLite and links
that claim to the slot, along with the per-item planning intent. Each V3 slot
file contains only its immutable opaque slot ID. A released legacy V2 record is
rewritten in place to that identity-only form only after SQLite confirms that
no blocking claim remains and the process holds the exclusive slot lock. The
version marker is made durable before the legacy suffix is truncated, so an
interrupted conversion remains parseable. Slot files are never unlinked or
replaced. The transaction commits before filesystem execution may begin. The
process transitions the Job to `running` only after admission, and a failure
prevents workspace mutation.
The operating system releases the slot's advisory lock when the owning process
exits; PID values, timestamps, and pathname presence are not ownership proof.

Recovery and history commands scan admitted/running records. They try to lock
the recorded slot without waiting and verify its stable slot ID against the
SQLite slot mapping. The Job ID and claim token are stored in SQLite and
rechecked in the recovery transaction; legacy V2 owner fields, when present,
must match those values. Lease acquisition failure, token mismatch, missing
slot evidence, or ambiguity preserves the current state. Lock release proves
the previous owner exited; it does not justify reusing a slot whose publication
outcome is unresolved. Such a claim remains blocking until a separately
justified reconciliation transition.
The Job record retains source intent, selected destination and workspace
provenance, conflict policy provenance, retry linkage, completion snapshot,
item evidence, and observed operation artifacts needed for reconciliation.

Completion updates are committed before terminal JSON/JSONL or human delivery.
If that update fails after filesystem execution, the CLI reports a stable
history error and keeps the prior running record available for later
interruption/reconciliation; it never reports an untracked success silently.
History never stores copied content bytes, keys, credentials, helper output,
or secret values.

The `standalone-job-history` Cargo feature is opt-in and required by the
standalone binary. It alone activates the optional `rusqlite` dependency;
standalone build and test commands enable it explicitly. The embedded library
default graph excludes the standalone history modules and SQLite. The
equivalent dependency-free build remains covered by
`cargo check --locked --lib --no-default-features`.

Automatic pruning runs after terminal completion and retains the newest 1,000
terminal Jobs with `pruneable = 1`. Interrupted Jobs and Jobs with uncertain
publication, cleanup retention, or retained artifact evidence use
`pruneable = 0` and do not count against that ordinary cap. Unresolved
protected evidence may raise the total above 1,000 until reconciliation.
Parent linkage is a textual Job ID, so a child remains inspectable if its
parent record is pruned.
`jobs clear` deletes terminal history rows and cascading item/artifact rows in
one transaction and preserves admitted/running and unknown future-state rows.
Before that transaction, opening history may initialize or inspect the
persistent database, SQLite sidecars, schema lock, and fixed lease-slot files.
The clear operation does not delete published outputs, workspaces,
configuration, caches, keys, or operation artifacts. The deletion predicate is
an explicit terminal-state allowlist.

A result without an outcome but with an actual returned
`PublishedDestination` artifact is recorded as `published_unresolved` and is
nonpruneable. An explicit publication-uncertain failure is recorded as
`uncertain`. Neither state is interpreted as `not_completed` or used as proof of
cleanup ownership.

For a nontrivial history migration, NSCB writes and verifies a recovery copy
before applying schema changes. The V2-to-V3 migration first opens an immediate
transaction to coordinate writers and check legacy owners, then creates or
validates the backup before executing schema statements inside that transaction.
Reuse of an existing recovery copy is allowed only when its application ID,
schema, and every current Job column match the source. The comparison derives
its projection from the actual `jobs` table columns so added history fields
cannot silently escape backup verification.

On Unix, directory creation, lock-file opens, and database or backup preflight
opens use directory descriptors and no-follow opens for path components. The
SQLite database and recovery-backup operations still use pathname-based SQLite
interfaces, including `VACUUM INTO`; those calls do not remain bound to a
previously opened parent directory. Parent-directory substitution during those
SQLite operations is therefore not closed by this implementation.

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
destination, workspace, or replacement choices back into that configuration;
after admission, those choices and their selection provenance are recorded in
standalone Job history.

## Job history commands and retry

`jobs list` orders newest admission first and uses the Job ID as the final
deterministic tie-breaker. `jobs show` reads one record and its ordered items.
`jobs clear` removes only non-active history records. Unknown IDs, active retry
targets, unsupported failed-item selections, and invalid flags map to stable
typed errors and do not create or mutate a Job unnecessarily.

`jobs retry` does not deserialize or replay the stored plan snapshot. It reads
the source intent and selection provenance, reconstructs a typed
`CopyThroughRequest`, and calls the current planner again. Explicit destination
and workspace selections retain their stored paths. Configured and native
destination selections are resolved again from current configuration. A
host-default workspace is selected under the current host environment. Missing
source or invalid current prerequisites fail before admission.

Every admitted Job stores its invocation directory. Relative explicit paths in
an older Job are anchored to that stored directory, while implicit destination
and workspace choices are resolved again. The retry records the directory of
the retry invocation and stores the anchored paths in its new intent, so
subsequent working-directory changes cannot retarget them.

The retry boundary accepts only a terminal `copy_through` record with `single`
submission and `all` scope. Unsupported kinds, batch submissions, failed-item
scopes, malformed enumeration values, and missing absolute invocation context
return `job_retry_ineligible` before planning or admission.

Each retry is a fresh request and starts with the refuse policy, recording
`retry_default` regardless of the parent's policy. It does not inherit
`--replace`: previous published outputs remain untouched unless the user
explicitly supplies `--replace` again, which records `retry_explicit_replace`.
A newly admitted retry stores its parent Job ID, parent conflict policy, and
that policy's original provenance. Prior Job records remain immutable.
Failed-item
selection filters persisted items whose individual state is actually `failed`;
because this issue does not implement batch execution, a nonempty selection is
then rejected as unsupported before creating a retry Job.

## Machine contract

Configuration and key commands support only human mode and a single-document
`--json` mode; they do not use JSONL. Success documents use schema version 1
and kinds `config.path`, `config.show`, `config.set`, `config.reset`, or
`keys.set`. Handled failures use schema version 1 and `kind: "error"` with a
sanitized code. Job history success kinds are `jobs.list`, `jobs.show`, and
`jobs.clear`; retry emits the standard `job.result` or `job.event` documents.
Standalone Copy adds top-level `job_id`; `history_error` appears only when
completion persistence fails after the authoritative operation result exists.

Exit class 0 means success. Exit class 2 covers invalid command usage and
configuration failures. Exit class 3 covers key validation, input or
prerequisite failures, and paths that cannot be represented. Exit class 7
means failure to write the required document. Human success goes to stdout and
human failure to stderr. Machine stdout contains exactly one document and no
human diagnostics. Existing Probe records and base Copy event semantics remain
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

Job-history integration evidence currently comes from the macOS qualification
host. Separate history, retry, recovery, concurrency, migration, retention,
clear, and output tests exercise the standalone CLI there. Portable schema and
path-composition tests keep other targets compiling but do not qualify their
native SQLite locking, permissions, crash durability, or filesystem behavior.
