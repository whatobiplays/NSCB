# Job contract qualification

This document records the evidence for the copy-through Job, observation,
cancellation, and machine-output contracts defined in
[job execution](../architecture/job-execution.md). It distinguishes evidence
that was executed from conditions that remain unqualified.

## Candidate and environment

### Earlier validation candidate

This table records an earlier validation candidate. Its base revision matched
`origin/main` at the time and remains historical evidence; it does not identify
the final Issue #12 candidate.

| Item | Value |
| --- | --- |
| Repository | `whatobiplays/NSCB` |
| Earlier candidate base revision | `09f70d632cf7c4a79d6eaf9d48a20b3d7aaeb7c3` (matched `origin/main` at that time) |
| Worktree | Isolated Git worktree; the primary checkout was not modified |
| Host | macOS 27.0.1, Darwin 27.0.0, arm64 |
| Compiler | Rust 1.98.1 (48a229cea 2026-09-01) |
| Toolchain pin | `rust-toolchain.toml` and `rustup run 1.98.1` |

### Final Issue #12 candidate

The final Issue #12 candidate used baseline
`ee85e6a283b884791a69a34a4503a9f9f50e377c` and snapshot HEAD
`9d99624aee2b8f5458ffca3255dbf1c184072649`. Because this document is part of
the hashed candidate, the authoritative final manifest and hashes are recorded
in `RESULT.json` rather than embedded here.

Copy-through evidence applies only to this macOS filesystem configuration.
No Linux, Windows, network-filesystem, crash-durability, provider, Nintendo
authenticity, or device-write qualification is implied.

## Routine Rust evidence

The full Rust suite was run with the pinned compiler:

```sh
rustup run 1.98.1 cargo test --locked
```

Historical baseline result before the product-contract correction: 536 tests
passed, 0 failed, and 4 were ignored. Those counts do not qualify the corrected
candidate. The final correction run is captured separately with complete logs,
timestamps, exit codes, environment details, and output hashes in the portable
review archive.

Focused suites used during implementation:

```sh
rustup run 1.98.1 cargo test --locked --lib operation::tests
rustup run 1.98.1 cargo test --locked --test operations
rustup run 1.98.1 cargo test --locked --test cli_subprocess
rustup run 1.98.1 cargo test --locked --test job_observation
rustup run 1.98.1 cargo test --locked --bin nscb
```

## Observation and completion evidence

The public `job_observation` suite exercises:

- A dropped event consumer before admission: execution still completes, the
  destination is correct, and `last_result()` returns the complete terminal
  result.
- A second consumer refused with `EventConsumerUnavailable`; dropping the
  first releases the claim.
- A consumer dropped during execution does not block publication; the
  destination remains correct and `last_result()` returns the complete result.
- Ordered sequences starting at zero, bounded cardinality on a 512 KiB copy,
  exactly one terminal completion, and no artifact, source, destination, or
  workspace path in nonterminal events.
- Repeated admissions replacing the previous terminal result and resetting
  sequence numbers.
- A failed planning attempt followed by a successful unrelated execution on
  the same session.
- `AlreadyUpToDate` reporting zero completed bytes and the planned total.
- Terminal artifact identity and path evidence, including serialization of
  the full result in the machine document.

Unit evidence in `operation::tests` additionally covers:

- Failure and cancellation emit their matching terminal milestone before the
  single `Completed` event. A failed result also emits a stable typed `Failure`
  code. Cleanup uncertainty emits `CleanupIncomplete` and a typed `Warning`
  after any failed or published milestone. Tests check combined failure and
  cleanup ordering, consecutive sequence numbers, bounded cardinality,
  source/destination preservation, and `last_result()` recovery.
- Cancellation accepted at the `BeforeAtomicPromotion` checkpoint: the result
  is `Cancelled`, the destination is absent, the source bytes are unchanged,
  no `Published` milestone is recorded, and exactly one terminal event exists.
- Cancellation refused at `AtomicPromotionStarted` while the session is
  `Promoting`: the test observes one refused cancellation event, exactly one
  terminal event, a successful result, unchanged source bytes, and correct
  destination bytes.
- A pre-promotion checkpoint after staging and validation reports the planned
  total and full completed staging bytes. Cancellation at that point leaves the
  destination absent and source unchanged. The terminal result retains the
  `Cancelled` failure and `CleanupIncomplete` warning, emits the warning after
  the cancellation milestone, and ends with one `Completed` event whose
  snapshot still does not claim publication.
- An accepted `CancellationHandle` request observed at the promotion boundary
  reports `Completing` with `CancellationRequested` before final cleanup, and
  terminates as `Cancelled` with no destination.
- An accepted cancellation during an unverified destination-competitor capture
  preserves the terminal `PublicationUncertain` failure and the unverified
  artifact evidence; it does not become a clean cancellation.
- Cancellation immediately before a replacement promotion preserves the
  original destination and source bytes, emits no published milestone, and
  produces exactly one terminal event.
- A forced validation failure after the copy loop finishes reports
  `completed_bytes == total_bytes` with a `Failed` state, no destination, and
  unchanged source bytes. Copied bytes are not treated as a publication claim.
- A `Busy` admission attempt during an active execution does not publish a
  terminal event and does not replace the result recovered after completion.
- Subscription attempted during execution is refused.
- The failed-planning isolation test abandons an already-cancelled handle,
  verifies the session remains `Idle` with no terminal result, and proves a
  later execution with a fresh handle succeeds.
- Existing source-change, destination-change, conflict, retention, cleanup, and
  `PublicationUncertain` tests continue to pass.

No test assumes the host runtime provides Tokio, persistence, history, or a
daemon.

## Planning-time signal latching

The copy CLI installs its invocation-local SIGINT and SIGTERM guard before it
calls the Engine's synchronous copy planner. A macOS-only CLI test uses a
private thread-local checkpoint at the CLI planning entry to deliver each
signal while that guard is live. The test then verifies that successful
planning is followed by cancellation before staging, a failed plan retains its
`source_unavailable` pre-admission error, and neither outcome affects a later
invocation.

A separate macOS-only operation test pauses at the entry to
`operation::plan_copy_through` and delivers each signal before the synchronous
planner returns. It verifies that the cancellation flag is latched while
planning is active. The CLI checkpoint and operation checkpoint use channels,
not sleeps. Planning I/O itself is not interruptible.

## Deterministic CLI cancellation evidence

`copy_subprocess::copy_sigterm_is_accepted_before_publication` synchronizes at
an established execution checkpoint without timing guesses:

1. The test opens the source and holds an exclusive file lock.
2. The CLI is started with `--jsonl` and reads the `started` record, proving
   admission.
3. The test sends SIGTERM while the source lock is still held, so the CLI is in
   the cooperative source-lock retry loop.
4. The test waits for the `cancellation_requested` record with
   `accepted: true` before releasing the lock. That record proves the signal
   was delivered and the execution observed it; the test does not sleep or
   guess when delivery occurred.
5. The test releases the lock and reads the remaining records.

The observed exit is 6, exactly one `job.result` is present with state
`cancelled`, a `cancellation_requested` event with `accepted: true` is present,
the destination does not exist, the source bytes are unchanged, and stderr is
empty. The reporting-deadline subprocess variant keeps stdout and stderr full
and unread for 5.25 seconds while the source-lock checkpoint holds execution.
The process remains alive and the destination remains absent during that hold.
After SIGINT and lock release, it exits 7 within the shared reporting budget
plus scheduling allowance, with the source unchanged and destination absent.
The execution therefore remains cancellable before publication without a
`SIGSTOP`/`SIGCONT` race, and reporting timeout does not become an execution
timeout.

The refused boundary is covered by the promoted-state unit test described
above. Cancellation near the boundary is covered by both the accepted
`BeforeAtomicPromotion` checkpoint and the refused `AtomicPromotionStarted`
checkpoint.

## Signal-handler lifecycle

The CLI uses one scoped guard for SIGINT and SIGTERM. The guard unregisters its
signal-hook actions when the invocation ends, including cleanup after a failed
second registration. signal-hook 0.3 does not restore the previous or default
process signal disposition when the final action is unregistered; this
limitation is documented and is not concealed by a restoration claim.

Qualification is therefore process-scoped:

- Copy signal cancellation is exercised in real CLI subprocesses.
- `inspection_signal_guard_reaches_the_execution_boundary` runs separately for
  SIGINT and SIGTERM in isolated test subprocesses. A test-only checkpoint in
  the real inspection CLI path raises the signal immediately before the Engine
  handoff and checks the shared cancellation flag passed to the host. This
  proves the scoped signal actions remain registered across host construction;
  it uses missing prerequisites and does not launch or qualify a provider.
- A successful result does not claim that a later in-process invocation would
  regain the default disposition.
- Inspection and Verification continue to use the same scoped registration and
  their existing cancellation path.
- Non-Unix targets install no signal handlers.

Hosts that need repeated signal installation in one long-lived process must
isolate commands in subprocesses. The binary's normal one-command-per-process
mode satisfies this boundary.

The supported v1 CLI performs one command invocation per process. It unregisters invocation-owned SIGINT/SIGTERM actions but does not guarantee restoration of the prior/default process-wide signal disposition. Embedded Engine hosts retain their own signal-handling responsibility. Repeated in-process CLI invocation requiring disposition restoration is unsupported.

## Machine-output evidence

CLI subprocess tests verify the frozen terminal shape: standalone `--json` and
the final JSONL `job.result` both contain `schema_version`, `kind`,
`nscb_version`, the logical terminal `sequence`, a coherent final `snapshot`,
and the complete `result`. Every JSONL semantic event carries its own
execution-local sequence and immutable snapshot. Pre-admission failures remain
one typed `error` record with no fictional Job sequence or snapshot. Event
cardinality stays bounded for large input; progress does not add per-byte
records.

The executable stalled-pipe tests prefill actual OS pipes and keep their
readers open and unread until process exit. They cover human, `--json`, and
`--jsonl` with stdout alone blocked; all three modes with both streams blocked;
and a human destination-conflict diagnostic with stderr alone blocked. Each
process exits within the five-second report budget plus a two-second
scheduling allowance after observed publication or pre-admission failure. The
tests check source bytes and destination state, and the both-stream test checks
that inherited descriptor flags are unchanged. A source-lock checkpoint test
holds execution for longer than the reporting budget with both pipes blocked,
then delivers SIGINT before publication and releases the lock. It verifies exit
7, preserved source bytes, and no destination publication. Broken stdout after
successful publication and after a source-change execution failure exits 7
without changing the corresponding filesystem state. Broken stderr after a
pre-admission destination conflict also exits 7 and preserves both files.

Reporter unit tests exercise bounded queue admission, write and flush failure,
the exact shared deadline origin, late worker failure diagnostics, and dropping
the session while a worker is blocked. The executable subprocess tests provide
the process-shutdown evidence; the in-process stalled-writer unit test does
not establish bounded process exit. A blocked pipe can prevent delivery of the
terminal record or diagnostic even though the process exits at its reporting
deadline. Exit 7 is therefore ambiguous about publication and must not trigger
an automatic blind retry.

`copy_cli_tests::stalled_jsonl_writer_does_not_block_filesystem_execution` is
an in-process unit test using a controllable Rust writer. It checks that the
filesystem operation continues while the writer is stalled. The actual CLI
termination claim comes only from the separate executable subprocess tests.

Other CLI tests verify human success on stdout, failed and cancelled localized
diagnostics on stderr, machine stdout/stderr separation, pre-admission error
codes, and artifact-path sanitization. A blocked pipe may prevent delivery of
the terminal record or diagnostic even though the process exits on its report
deadline.

`copy_subprocess::copy_human_cleanup_warning_lists_actionable_artifact_identity_evidence`
exercises a replacement that retains its destination backup. It verifies that
human output includes the exact retained path, role, device/inode identity,
length, digest, and path-identity status, and that the backup still contains
the original destination bytes.

## Artifact reconciliation evidence

The terminal `job.result` intentionally embeds the complete artifact inventory
so a human or host can reconcile retained and uncertain entries. Tests locate a
`PublishedDestination` artifact, compare its path with the canonical
destination, verify path identity and length evidence, and confirm that the
serialized terminal result contains the actionable path.

Generic errors, nonterminal events, warnings, and progress snapshots do not
contain artifact or unrelated source, destination, or workspace paths.
Human copy output has a separate, intentional `artifact:` list after the
path-free cleanup warning so an operator can reconcile retained entries
without inferring paths from a count or role name.
Issue #9's retained-competitor, pre-link replacement, cleanup-incomplete, and
`PublicationUncertain` operation tests continue to exercise the conservative
retention and uncertainty accounting on the same publication path.
`retained_storage_bytes()` and Issue #9's conservative `PublicationUncertain`
behavior are unchanged.

## Repository gates

The historical pre-correction candidate passed the pinned compiler checks and
repository Makefile profiles:

```sh
rustup run 1.98.1 cargo check --locked --all-targets --all-features
rustup run 1.98.1 cargo clippy --locked --all-targets --all-features -- -D warnings
rustup run 1.98.1 make all
```

Those results are historical and do not qualify the product-contract
correction. The correction's final pinned results and test counts are in its
portable review archive.

## Content-policy evidence

The genuine-Git content-policy profile is separate from `make all`:

```sh
rustup run 1.98.1 make test-content-policy-git
```

This suite creates disposable repositories and tests index, worktree, ignored,
untracked, staged, and unmerged behavior. It does not qualify Job semantics.

## Independent implementation review

Three separate read-only Codex sessions reviewed the original implementation on
2026-10-23. They inspected source, tests, the run prompt, and the architecture
documents; they did not run the validation suites. The implementer reran every
gate after applying the verified findings.

- Alakazam performed the specification review. The review compared every PAC
  and TAC with observable evidence and found coverage gaps around SIGINT,
  mixed machine options, fresh `--json` success, live progress, cancellation at
  the promotion boundary, and reserved exit classes. The added subprocess and
  checkpoint tests, exact schema documentation, and limitation statements
  address those findings. The review also confirmed the pre-publication
  cancellation ordering, result recovery, artifact paths, and macOS scope.
- Snorlax performed the filesystem and cancellation review. It found that an
  accepted signal or handle request did not update the live session status to
  `CancellationRequested`, and that the `total_bytes` documentation described
  an unobservable admission window. Both were corrected and covered by new
  tests. The review's concern that finalization could mask
  `PublicationUncertain` is now enforced explicitly and tested against a
  path-only competitor. A replacement cancellation test also verifies that
  cancellation before promotion preserves the original destination.
- Metagross performed the Rust and API review. It found that a non-Unicode path
  could fail serialization after preceding bytes had reached stdout, that
  `--workspace` could consume `--json` or `--jsonl` as a path value, and that
  the stalled-writer test was not macOS-gated. Records are now serialized into
  memory before one stdout write, machine paths are checked before execution,
  option-like workspace values are rejected, and the test is platform-gated.
  Documentation now states that a caller-owned cancelled handle remains
  cancelled when deliberately reused; a fresh handle is required for an
  independently cancellable next execution.

These historical reports and implementer dispositions are implementation
evidence, not independent post-fix closure or a product-review attestation.
Post-correction qualification may be recorded separately in a portable review
archive containing exact commands, timestamps, exit codes, output hashes, and
complete changed-path source inventories immediately before and after
qualification. A portable review archive must identify Standards, Spec, and
filesystem/cancellation reviews as pending until their report files are
actually included. This document does not claim those reviews are complete or
present. The original Delegation prompt, manifest, gate, and result remain
historical evidence and are not rebound to the corrected source.

## Remaining limitations

- Copy-through and all Job execution evidence are macOS-only.
- The operation does not claim continuous source snapshots against
  noncooperating same-user writers.
- Directory durability and crash consistency are not established.
- `Completing` and `Promoting` remain noninterruptible; a request during those
  phases is refused and does not roll back a completed promotion.
- Retained artifacts require manual reconciliation; no automatic deletion is
  performed.
- On the qualified macOS executable copy path, open non-consuming stdout or
  stderr pipes do not hold normal process shutdown indefinitely. The five-second
  shared reporting budget and exit-7 precedence are tested with the readers
  kept open and unread. Other operating systems and sink drivers remain
  unqualified.
- The qualification does not include product-review attestation unless a
  separate review evidence artifact exists for this run.

## Issue #12 standalone Job history evidence

The standalone history candidate was exercised on the native macOS
qualification host with Rust 1.98.1:

```sh
rustup run 1.98.1 cargo test --locked --features standalone-job-history --bin nscb standalone::history::tests
rustup run 1.98.1 cargo test --locked --features standalone-job-history --test job_history_cli
rustup run 1.98.1 cargo test --locked --features standalone-job-history --test config_cli
rustup run 1.98.1 cargo test --locked --features standalone-job-history --test cli_subprocess
rustup run 1.98.1 cargo check --locked --lib --no-default-features
rustup run 1.98.1 cargo fmt --all -- --check
make all
```

An earlier qualification run recorded 47 passing history unit tests and 22
passing real-binary Job history tests. Those results are historical evidence
for that run and are not the final counts.

The final native macOS focused run reported no failures or ignored tests:

| Focused suite | Passed |
| --- | ---: |
| History unit tests | 56 |
| Real-binary Job history tests | 23 |
| Configuration tests | 49 |
| CLI subprocess tests | 29 |

An intermediate rerun of the filtered history suite observed 55 passed and 1
failed:
`standalone::history::tests::v1_migration_process_crash_before_commit_preserves_backup_and_retries`
read an empty marker (`[]`) instead of `ddl-applied`. The captured failure log
remains in the validation evidence. Five isolated reproductions of the same
test passed (5/5). At an earlier point, one focused rerun passed 56/0, and an
earlier historical stabilization sequence recorded three consecutive focused
runs at 56/0. Those results remain historical evidence for that run and do not
describe the final candidate's complete repeat-run sequence.

Final-candidate validation repeated the focused history command with the
default parallel test execution. Its initial run produced 55 passed and 1
failed: the same migration process-crash test read `[]` instead of
`ddl-applied`. The retained final-candidate repeat sequence produced 56/0,
56/0, and 55/1 with the same assertion. A subsequent serialized confirmation
using `RUST_TEST_THREADS=1` produced 56/0. The canonical `gmake all` gate also
passed, including this crash-injection test in its 135-test binary suite.

The known failure is a `std::fs::write` marker-visibility race in the test
harness: the parent waited for the marker path to exist while the child
created or truncated the file before writing its bytes. It is classified as
a nonblocking test-reliability follow-up under the amended Issue #12 contract.
The test harness was not changed under the documentation-only authorization.
The race is not evidence of a migration behavior failure and does not waive
TAC-12.

The canonical `gmake all` gate passed and includes both `make test` and
`make smoke`. `make test` reported 1,051 passing executions and 8 ignored: the
no-default-feature and feature-enabled library suites each passed 323 tests
with 4 ignored, the feature-enabled binary suite passed 135 tests, integration
test targets passed 268 tests, and documentation tests passed 2. `make smoke`
added 52 passing executions, consisting of 29 CLI subprocess tests and 23
real-binary Job-history CLI tests. The raw `make all` accounting is therefore
1,103 passing executions and 8 ignored. These are execution counts across
target invocations, not distinct tests. Deduplication across unique targets
yields 728 passed and 4 ignored because the 323-test library suite ran under
both feature configurations and smoke reran targets already selected by
`make test`. The focused runs above are separate evidence and are not added
to these canonical counts.

`make test` and `make smoke` set `RUST_TEST_THREADS=1` so concurrent
subprocess suites cannot consume scheduling margin enforced by real
blocked-pipe timing assertions. The embedded no-default-feature library check
passed, and its active dependency graph contained no `rusqlite` package.

An earlier qualification run also passed a cross-target `cargo check
--all-targets` for `x86_64-unknown-linux-gnu` with `RUSTC` bound to the pinned
toolchain, confirming that macOS-only copy-success subprocess cases are excluded
while portable history tests still compile. The final evidence archive did not
retain that Linux log, and the final documentation-only cycle did not rerun the
check.

The initial feature-enabled Windows GNU all-target check failed with `E0463`
because Cargo invoked `/opt/homebrew/bin/rustc` (Rust 1.99.1); this is
historical evidence. The pinned Rust 1.98.1 Windows GNU all-target check
exited 0. The final run used a disposable temporary target directory; its
ephemeral path is omitted from this semantic command:

```sh
RUSTC=/Users/daniel/.rustup/toolchains/1.98.1-aarch64-apple-darwin/bin/rustc CARGO_TARGET_DIR=<temporary-validation-directory> rustup run 1.98.1 cargo check --locked --all-targets --features standalone-job-history --target x86_64-pc-windows-gnu -vv
```

This establishes compile-only qualification for the feature-enabled
`x86_64-pc-windows-gnu` all-target build. Native Windows execution, ACL and
lease behavior, crash recovery, retry behavior, and copy publication remain
unqualified. The prospective TAC-13 result is supported by the completed
native macOS canonical gate and focused tests and by the Windows all-target
compilation; native Windows execution and copy publication are not claimed.

The history unit evidence covers fresh schema initialization, SQLite application
identity and user version, corruption and future-schema rejection, migration
backup equivalence, failed migration rollback, admission rollback, durable
completion and item evidence, deterministic ordering, failed-item selection,
all-column recovery comparison, publication-unresolved retention, fail-closed
future-state clearing, artifact isolation, and process-lifetime leases. The
lease evidence covers a fixed 64-slot registry, stable slot files and
identities, same-slot multi-process exclusion, slot exhaustion, token
mismatch, V3 identity-only slot files with Job/token claims in SQLite, in-place
legacy V2 slot conversion after claim eligibility, interrupted-conversion
recovery without inode replacement, abrupt-owner-exit recovery, live-peer
preservation, exclusive stale recovery, and refused reuse of unresolved
claims. The real-binary evidence covers planning and unavailable-history failures before
filesystem mutation, admission and running-transition failures, completion
persistence failure with recoverable uncertainty, interrupted-owner recovery,
live-owner preservation, concurrent processes, current-configuration retry,
retry from a different working directory, malformed future retry records,
parent conflict-policy provenance, noninheritance of replacement
authorization, retry reporting failure with exit 7 and durable completion,
failed-item rejection, JSONL completion failure with one terminal record, and
configuration/key/cache/output/artifact-preserving clear.

### Historical TAC-6 cleanup and NDR-1 boundary

The automatic-cleanup requirement originally associated with TAC-6 is
historical. Under the live amended Issue #12, NDR-1 prospectively supersedes
that cleanup condition. NDR-1 passes by acquiring one exclusive per-Job OS
lease, atomically recording a durable interruption, retaining evidence, and
refusing to replay an interrupted request. It does not require or establish
automatic artifact deletion.

This candidate intentionally performs no automatic artifact deletion. ADR-0030
rejects a pathname identity check followed by unlink, and `planned_artifacts`
records possible paths and expected content rather than durable proof that the
operation created a particular filesystem object. Actual creation ownership and
the required race-safe identity-bound deletion primitive belong to the
operation lifecycle in `src/operation.rs`, which is outside this run's allowed
scope.

The standalone history layer therefore retains workspace, planned, displaced,
retained, symlinked, foreign, modified, and publication-uncertain artifacts for
manual reconciliation. History pruning deletes selected terminal database
rows. Opening history for `jobs clear` may initialize or inspect the persistent
database, SQLite sidecars, schema lock, and fixed lease-slot files. Its clear
transaction removes selected terminal Job and cascading evidence rows,
including their durable lease claims, without deleting or changing outputs,
workspaces, configuration, caches, or artifact files.
ADR-0030's threat model and prohibition remain in force: a pathname check
cannot establish operation-created identity, so check-then-unlink remains
prohibited. Automatic artifact reclamation remains a separate follow-up and
is not claimed by NDR-1.

Native Linux and Windows history behavior remains unqualified. Portable tests
cover path composition and schema rejection, but they do not establish native
SQLite locking, file permissions, process-lifetime lease semantics, crash
durability, or filesystem publication on those platforms.
