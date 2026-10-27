# Development validation

NSCB uses a repository-owned `Makefile` as the canonical validation contract for local development, GitHub Actions, and GPT Repo MCP. GNU or BSD Make, Git, Python 3.11 or newer, and the Rust toolchain pinned in `rust-toolchain.toml` are required. All Cargo commands use the checked-in `Cargo.lock`. Python validation uses only the standard library.

| Validation profile | Make target | Commands |
| --- | --- | --- |
| `content-policy` | `make content-policy` | `PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/check_content_policy.py` |
| `test-content-policy` | `make test-content-policy` | `PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_content_policy.py'` |
| `test-content-policy-git` | `make test-content-policy-git` | `PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_content_policy_git.py'` |
| `typecheck` | `make typecheck` | `cargo check --locked --all-targets --all-features` |
| `lint` | `make lint` | `cargo fmt --all -- --check`, then `cargo clippy --locked --all-targets --all-features -- -D warnings` |
| `test` | `make test` | The Git-free `test-content-policy` suite, then `cargo test --locked` |
| `build` | `make build` | `cargo build --locked` |
| `smoke` | `make smoke` | `cargo test --locked --test cli_subprocess` |
| `all` | `make all` | `content-policy`, `typecheck`, `lint`, `test`, `build`, and `smoke`, in that order |

`make` prints every target. `make fmt` modifies Rust source files and is not a validation target. `make clean` runs `cargo clean` and is intentionally outside `make all`.

Issue #9 and Issue #10 copy-through, observation, and machine-output tests run
only on macOS. A successful `make all` on another operating system verifies the
repository's portable tests and the fail-closed platform guard; it does not
qualify copy-through publication, host event delivery, or admitted JSONL job
records there. Replace also requires the destination volume to report Darwin's
`VOL_CAP_INT_RENAME_SWAP` capability and the actual atomic exchange call to
succeed. The test results do not establish network-filesystem behavior or
crash durability.

## Content-policy testing split

Production `make content-policy` inspects the real Git index and working tree. It reads stage-zero index blobs by object ID, enumerates nonignored untracked paths, scans the worktree independently, and rejects unresolved index conflicts. Production Git commands run with bounded stdout, stderr, time, and repository-safe opening rules. They also set `GIT_NO_REPLACE_OBJECTS=1` and `GIT_NO_LAZY_FETCH=1`.

Routine `make test-content-policy` must remain usable without creating disposable Git repositories. It supplies the checker with a test-only `InMemoryGitFixture` containing an index, immutable blobs, independent worktree, untracked, ignored, and unmerged registries. The fixture supports only the checker's read-only commands:

- `rev-parse --show-toplevel`
- `ls-files --unmerged -z`
- `ls-files --stage -z`
- `ls-files --others --exclude-standard -z`
- `cat-file -s <object-id>`
- `cat-file blob <object-id>`

The fixture does not model commits, refs, packs, replacement objects, or a general object database. Routine tests also install a guard that rejects Git initialization, staging, commits, index mutation, replacement objects, and physical `.git` creation from both direct and subprocess execution paths. A fake `git` executable exercises the production command-line entry point without initializing a repository.

`make test-content-policy-git` is the required genuine-Git integration profile. It creates disposable repositories and verifies initialization, staging, commits, staged and worktree divergence, tracked, untracked, ignored, deleted, and unmerged behavior, object-ID blob reads, and resistance to `git replace`. It also exercises bounded cleanup diagnostics for disposable repository cleanup. This suite is deliberately excluded from `make test` and `make all`.

## Repository content policy

The checker applies `tests/fixtures/registry.json` independently to the index and current worktree. It reports findings from either snapshot without displaying matched bytes, registry content, raw Git errors, or absolute host paths. The initial registry is empty. An unstaged new registry is accepted in the index only while the index contains no binary fixtures; the worktree registry remains required.

Resource limits apply across both snapshots: 10,000 file versions, 16 MiB per file version, 64 KiB total stderr per command, 64 MiB total stdout, and 10 seconds per command. A path present in both snapshots counts twice. Any Git stderr output fails closed with a sanitized code. Pattern scanning does not establish copyright status, identify every secret, or validate the truth of provenance statements. Human review remains required. See [ADR 0016](adr/0016-repository-content-policy.md) for the fixture registry and prohibited-content rules.

The native Inspection qualification described below is separate from content-policy enforcement. It does not replace `make content-policy` or `make test-content-policy-git`.

## GitHub Actions

The `validate` job runs `make all` on `ubuntu-24.04` for pushes to `main` and pull requests. A separate required job named `content-policy-git` uses the same pinned checkout action, read-only repository permissions, and a bounded timeout to run `make test-content-policy-git`. Neither job uses `continue-on-error`, broad skips, or an allowed-failure mode.

Repository branch protection is external GitHub configuration. If protection uses explicit required-check names, `content-policy-git` must be enrolled there in addition to `validate`; updating this workflow cannot prove that remote setting.

## GPT Repo MCP integration

`repo_validate` accepts named validation profiles rather than arbitrary shell commands. The approved repository entry in GPT Repo MCP's local `config.local.json` must map profiles to these Make targets while preserving its other policy settings:

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

That fragment belongs inside the repository's `operations` object. Do not copy local server configuration or credentials into NSCB. Validation also requires the server-side operation policy to permit the selected repository and command.

After updating the server configuration, use `repo_list_roots` to confirm the intended repository ID and exact worktree root. Run `repo_validate` with a dry run first to verify the selected command, then run the approved profile without the dry run. MCP validation profiles do not accept focused test paths; run focused Rust tests directly in a trusted terminal when needed.

The repository qualification uses `rustup run 1.98.1` for Cargo commands.
`make all` otherwise uses the active Cargo toolchain. GPT Repo MCP `all`
executes under the MCP server's effective Rust toolchain, so its validation ID
and Rust version are separate evidence from the Rust 1.98.1 run.

## Recognition validation

Run these focused checks before the full repository gate when changing recognition:

```sh
cargo test --locked --all-features recognition::tests
cargo test --locked --all-features --test public_facade
cargo test --locked --all-features --test cli_subprocess
make all
```

Recognition fixtures are deterministic generated source data. No proprietary binaries or cryptographic material are required.

## Inspection validation

Inspection uses the same repository validation entry point:

```sh
make all
```

Focused Rust verification can be run directly:

```sh
cargo test --locked --all-features inspection::tests
cargo test --locked --all-features provider::
cargo test --locked --all-features cli::inspection_cli_tests
cargo clippy --locked --all-targets --all-features -- -D warnings
```

Provider cache tests create temporary directories and files without changing the repository or host cache. Fake-provider tests are compiled only under `#[cfg(test)]` and cover argv, environment, output bounds, signals, nonzero exits, reader cleanup, cancellation, timeouts, process reaping, descendant processes, input and key mutation, and postcondition rejection without network access. Native NSTool qualification remains limited to macOS arm64 and is recorded in [Inspection qualification evidence](testing/inspection-qualification.md).

## Verification validation

Verification uses the same repository validation entry point:

```sh
make all
```

Focused checks can be run directly:

```sh
cargo test --locked --all-features verification::tests
cargo test --locked --all-features --test verification
cargo test --locked --all-features --test verification_cli
cargo clippy --locked --all-targets --all-features -- -D warnings
```

The Engine tests generate synthetic NCA3, PFS0, and NPDM data at runtime.
RSA key pairs used for signing are ephemeral and test-only; no private key is
stored in the repository. The public CAVP verification vector is test data
only. The tests do not require network access, a provider executable, Nintendo
keys, or proprietary content.

Focused evidence and the limits of the synthetic profile are recorded in
[Verification qualification evidence](testing/verification-qualification.md).

## Copy-through publication and job-contract validation

Final-hash and pre-syscall checkpoints assert that the shared session remains
`Executing` and accepts cancellation through final source and destination
validation. The atomic-syscall checkpoint asserts `Promoting` and refused
cancellation. After that checkpoint, the staging inode and persistent lock
marker are rechecked before the path-based syscall. Post-publication checks and
final inventory run in `Completing`; the wrapper enters that phase before
cleanup, competitor capture, inventory, or result assembly. Cancellation
accepted at the pre-finalization handoff produces `Cancelled`, while later
cancellation is refused.

The copy-through suites use Rust 1.98.1 and cover planned-length copying,
independent staged-output validation, source and destination mutation,
cooperative source locking, same-parent destination coordination, atomic Fail,
explicit qualified Replace, retention accounting, cleanup evidence, and stale
plan rejection. They run on macOS; other targets verify the typed
`UnsupportedCapability` guard and do not qualify copy-through publication.
Copy-planning signal tests use `cfg(target_os = "macos")` and are executed only
on macOS. The separate non-macOS tests cover the fail-closed capability error;
they do not claim copy-planning signal or publication qualification. A library
test pauses at the entry to `operation::plan_copy_through`, delivers SIGINT or
SIGTERM while the Engine's synchronous planning call is active, and then lets
the planner return. A CLI test separately pauses at the CLI planning entry,
after `ScopedCancellation` is installed and immediately before the Engine
planner is called. It delivers both signals through the real invocation guard,
then verifies cancellation before staging, preservation of the typed error when
planning fails, and isolation from later invocations. Other CLI tests pause at
the plan-result handoff. Each barrier uses channel synchronization rather than
timing sleeps. Planning I/O itself is not interruptible.

The retained-verified-competitor case proves that an independently captured
alias matching the earlier observation remains inventoried and counted after a
later destination pathname change. The descriptor used to inspect the
competitor remains open through alias creation and verification, preventing
inode reuse during that interval. The equal-content pre-link replacement test
proves that substitution before alias creation returns `PublicationUncertain`,
leaves the observed competitor unretained and uncounted, and can still record
complete evidence for the replacement alias with `retained() == false`. Current
path and content fields are refreshed independently from historical evidence;
only artifacts marked retained contribute to `retained_storage_bytes()`.

The operation integration suite replaces the permission-dependent destination
directory test with a deterministic change from the planned directory to a
regular file. Execution rejects the stale plan before staging and creates no
artifacts, so the test no longer passes vacuously when the host filesystem does
not enforce a directory's write permission for the current user. A separate
execution-level case places a directory at the planned destination-lock path;
the real execution path reports `DestinationUnavailable` before staging and
creates no artifacts.

`UncertainEntry` is an inventory role rather than a declaration that every
identity field is unknown or that the entry is retained. It covers retained
aliases, unretained path-linked aliases with complete self-evidence, and
genuinely uncertain entries. Callers must inspect `retained()` for the
retention claim and the evidence fields for what is known. Unretained records
are excluded from `retained_storage_bytes()` even when their alias identity,
length, and digest are complete.

Run the focused and repository checks with the pinned compiler:

```sh
rustup run 1.98.1 cargo test --locked --lib operation::tests
rustup run 1.98.1 cargo test --locked --test operations
rustup run 1.98.1 cargo test --locked --test cli_subprocess
rustup run 1.98.1 cargo test --locked --test job_observation
rustup run 1.98.1 make all
rustup run 1.98.1 make test-content-policy-git
```

The `job_observation` suite exercises the additive Rust observation surface:
single-consumer admission, ordered and bounded events, terminal uniqueness,
dropped consumers, repeated admissions, authoritative result recovery,
invocation-bound cancellation, and latest-value progress. The
`cli_subprocess` suite exercises `nscb copy` through `--json` and `--jsonl`,
including exit classes, stdout and stderr separation, SIGTERM cancellation at an
established execution checkpoint, and a broken stdout transport. The separate
`copy_cli_tests::stalled_jsonl_writer_does_not_block_filesystem_execution`
in-process unit test uses a controllable writer and releases it before joining
the reporting thread. It proves filesystem execution remains independent of
reporting; it does not prove bounded CLI termination when an actual connected
stdout reader stops consuming. The operation unit tests exercise accepted and refused cancellation at
the promotion boundary, source and destination preservation, and the
distinction between copied bytes and completed publication.
They also assert ordered failure, cancellation, and cleanup-warning transitions,
stable typed diagnostic codes, exactly one final completion, and result recovery.
The inspection CLI unit suite additionally checks the signal guard's lifetime
at the Engine handoff in isolated test subprocesses, without provider execution.

The complete evidence record, including the pinned compiler and the limits of
the macOS filesystem qualification, is in
[job contract qualification](testing/job-contracts-qualification.md).

The genuine-Git content-policy suite is separate from `make all`. Run the GPT
Repo MCP `all` profile through its supported dry-run and execution workflow
against this exact candidate root. MCP does not accept focused commands and
executes under its server-effective Rust toolchain; record that validation ID
and version separately from the Rust 1.98.1 results.

Staging, recovery, displaced, and uncertain artifacts are retained and
inventoried because path-only deletion cannot be conditioned on identity.
Manual reconciliation must not mutate artifact contents and must prove
ownership, parent identity, unchanged file identity, and content before any
removal. Detailed inventory fields and platform limits are recorded in
[publication qualification](testing/publication-qualification.md); publication
guarantees and the ADR 0008 scope are recorded in
[publication architecture](architecture/publication.md).


## Reporting transport qualification

Executable job-reporting tests use prefilled macOS pipes whose readers stay
open and unread. They check human, JSON, and JSONL output with stdout blocked,
both streams blocked, stderr blocked during a human failure, broken pipes,
cancellation, and unchanged filesystem outcomes. This subprocess evidence is
separate from the in-process stalled-writer unit test. The five-second shared
reporting budget begins immediately after Engine execution and operation-owned
cleanup return. Tests allow a documented two-second scheduling margin; they do
not claim a hard real-time exit or equivalent behavior on other operating
systems or sink drivers.
