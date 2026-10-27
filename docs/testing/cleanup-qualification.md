# Worktree cleanup

Run `make clean` from an idle worktree root. The operator stops builds, tests,
imports, package managers, and other artifact producers first. The command does
not check for running processes or coordinate with producers.

## Scope

The Python 3.11+ standard-library driver verifies its worktree using read-only
Git root and tracked-path queries. It does not invoke Cargo, build code, install
tools, provision a toolchain, or access the network.

The conventional `target/` directory is disposable in its entirety. This
includes binaries, incremental output, unknown development output, profiles,
and generated internal lock files. Do not store durable files there. Cleanup
rejects a symlinked target root, tracked target content, and known durable state
such as Git metadata, Delegation provenance, environments, and application data.
Generated documentation sources and extracted package sources/manifests inside
the target are disposable, including their generated `Cargo.lock` files. The tracked repository
`Cargo.lock` outside the target is never removed. Descendant symlinks are
unlinked by standard filesystem deletion without following their destinations.

Custom Cargo target/build settings in the environment, ancestor `.cargo/config`
or `config.toml`, or Cargo home cause the Cargo category to skip. The driver
does not resolve custom paths or follow them. An external Cargo home alone is
allowed. Unreadable or malformed configuration fails the Cargo category.

Python cleanup walks only `scripts/` and `tests/`, to a maximum depth of 128.
It deletes untracked `.pyc` files and removes empty `__pycache__/` directories.
Tracked bytecode and unknown cache contents remain. Symlinked source roots
are skipped and symlinked descendants are not followed. Source-associated and
orphaned bytecode are both regenerable under this contract.

Protected Python subtrees include fixtures, virtual environments (including
`virtualenv`), operation evidence, provider/application state,
publication/recovery state, `.git`, `.chatgpt`, `.serena`, `.codegraph`,
`.tokensave`, and `.nscb` recovery/split names. Name checks conservatively fold
case. All other directories, documentation, source, and configuration outside
the two explicit cleanup scopes remain untouched.

## Reports and failures

Cargo and Python independently report `removed`, `absent`, `skipped`, or
`failed`, with file counts, logical byte totals, and a reason. Byte totals are
approximate reclaimed storage, not a physical disk-space guarantee. A target
deletion that fails may have partially removed its tree; failed Cargo reports
do not claim those uncounted bytes. A successful Python removal remains counted
if a later Python operation fails. One category's failure permits the other
category to run. Retry after addressing the reported error.

Direct driver exits are 0 for completion, 1 for failure, 2 for a skip, and 130
for interruption. Make converts nonzero recipe exits to 2; inspect the report
to distinguish them. Missing directories and repeated cleanup succeed. There
is no persistent cleanup state or per-artifact provenance classification.

## Qualification

`make test-cleanup` uses disposable Git-free fixtures and `RoutineGitGuard`.
`make test-cleanup-git` uses disposable genuine Git repositories and linked
worktrees, with actual `py_compile` output. The tests cover positive whole-target
and Python deletion, generated-lock deletion, empty/repeated runs, durable and
tracked preservation, independent worktrees, custom/external locations,
symlinks, basic permission/I/O errors, and retry. Destructive public clean runs
only in fixtures. Full repository validation uses the pinned installed Rust
toolchain separately from cleanup.

The implementation uses ordinary `os.walk`, `Path.unlink`, and `shutil.rmtree`.
Local qualification is on macOS arm64; CI runs the same portable checks on
Linux. Windows and unusual filesystems are not locally qualified. No hostile
filesystem, concurrent-producer, mount-race, inode/FSID, or atomic deletion
guarantee is claimed or required. Exact candidate hashes, commands, counts, and
review outcomes belong in the orchestrator's registered result evidence.
