# Job execution, observation, and machine output

This document defines the contract added for the first explicit copy-through
Job: the `nscb copy` command, ordered semantic-event observation for Rust
hosts, authoritative latest-value progress, cooperative cancellation, and
JSON/JSONL reporting. A reader does not need prior knowledge of the
implementation to use this contract.

## Scope and compatibility

The contract is additive. The synchronous
`Engine::execute_operation(plan, session)` interface remains available and
unchanged for hosts that do not need events. `OperationSession::cancel()` keeps
its existing behavior: cancellation is accepted only while an execution is in
the `Executing` phase and is refused once the execution enters `Promoting` or
`Completing`.

The existing read-only JSON kinds (`container_probe.result`,
`content_recognition.result`, `input_resolution.result`, `inspection.result`,
`inspection.preflight`, and `verification.result`) are unchanged. The new
machine kinds are `job.result`, `job.event`, and the existing `error` shape.

Copy-through is qualified only on macOS. Other targets fail planning and
execution with `UnsupportedCapability`. The contract does not add Tokio,
NSCB-owned persistence, a daemon, execution history, replay, or a generic
command dispatcher.

## Command line

```
nscb copy <source> <destination> [--workspace <path>] [--replace] [--json | --jsonl]
```

The command requires exactly one source and one destination. It never prompts.
The default conflict policy refuses to replace a different existing
destination. `--replace` selects the qualified replacement path. Without
`--workspace`, staging uses the host temporary directory under
`nscb-copy-through`; no configuration is persisted. The workspace directory
created for an invocation remains operation-owned evidence and is reported in
the terminal artifact inventory.

`--json` and `--jsonl` are mutually exclusive. Repeating an option, supplying an
unknown `--` option, omitting a `--workspace` value, or providing anything other
than one source and one destination is a usage error with exit class 2. When a
machine mode was requested, the invocation emits one `error` record with code
`usage_error`.

The value following `--workspace` must be a path that does not begin with `--`;
an option-like token in that position is treated as a missing value. Machine
copy modes require every source, destination, workspace, lock, and planned
artifact path to be representable as a UTF-8 JSON string. A non-Unicode path is
rejected before execution with the existing stable `unrepresentable_path` code
and exit class 3, so publication cannot complete with an unrepresentable
terminal record.

When reporting succeeds, `--json` emits one `job.result` document for each
admitted execution, including failure, cancellation, and publication
uncertainty. `--jsonl` emits ordered `job.event` records followed by one
terminal `job.result`. Usage and planning failures before admission emit one
`error` document with a stable code. A reporting failure can leave a record
absent or partial; it does not change the logical terminal result, and the CLI
does not append a replacement record after uncertain delivery.

If the JSONL execution worker cannot be created, the CLI releases the
invocation's event consumer and cancellation registration, then emits one
pre-admission `error` document with code `execution_worker_start_failed` and
exit class 7. No `started` event or Job terminal result is fabricated because
execution was never admitted.

Human mode writes successful copy summaries to stdout. Failed and cancelled
outcomes write localized diagnostics to stderr; their exit class still follows
the authoritative operation result.

When the result retains an operation-owned artifact, the human output appends
one `artifact:` record per item from the complete typed artifact inventory.
These records intentionally expose paths and observed identity/content fields
for manual reconciliation. The localized warning sentence and semantic events
remain path-free.

Exit classes are stable:

| Exit | Meaning |
| --- | --- |
| 0 | Validated success, including `AlreadyUpToDate` and success with a cleanup warning |
| 2 | Usage or configuration error |
| 3 | Prerequisite or input failure, including unsupported host capability or a machine path that cannot be represented in JSON |
| 4 | Destination conflict or destination change |
| 5 | Reserved for provider or device failures; copy-through produces none |
| 6 | Cancelled or interrupted execution |
| 7 | Internal, session, write, staged-validation, publication, or reporting failure, including `PublicationUncertain` |
| 8 | Reserved for future completed-with-issues batch results; never fabricated |

`PublicationUncertain` is reported as a failed job with exit 7. The destination
may exist; the result and artifact inventory carry the evidence and the
operation does not roll back over uncertain data.

## Planning, admission, and host-owned execution

Planning reads the source, destination, and selected workspace without
creating or modifying anything. The returned `OperationPlan` is an in-memory
capability and cannot be reconstructed from its snapshot.

Execution is host-owned. A host that needs events performs these steps:

1. Create or reuse an `OperationSession`.
2. Call `subscribe_events()` while the session is idle to claim the single
   event consumer for the next execution.
3. Run `Engine::execute_operation` or
   `Engine::execute_operation_with_cancellation` on a host-managed thread.
4. Consume events from the returned `OperationEventConsumer`.
5. Recover the authoritative `OperationResult` from the execution return value
   or from `OperationSession::last_result()`.

The host chooses its threading model. The contract does not prescribe an async
runtime, a worker pool, or a persistence layer.

`subscribe_events()` claims exactly one logical consumer for the next
execution. A second live consumer, or a claim attempted while an execution is
active, returns `EventConsumerUnavailable`. Dropping a consumer before
execution releases the claim; dropping it during or after execution never
blocks or fails the execution.

Admission remains exclusive per session. A second execution admitted while
one is active returns a `Busy` failure result without emitting an execution
event and without replacing the active or previous authoritative terminal
result.

## Semantic events

Events are ordered and execution-local. `OperationEvent::sequence()` starts at
zero for each admitted execution and advances for every logical event, whether
or not a consumer exists. Cardinality is bounded by milestones and terminal
decisions; progress never creates per-byte or per-chunk events.

`OperationEvent::snapshot()` is captured under the session lock with the event
sequence and transition. It records `phase`, `status`, `milestone`, `outcome`,
`failure`, `completed_bytes`, and `total_bytes` at that transition. A delayed
consumer sees the original snapshot, not a later session read.

Event kinds are `Started { total_bytes }`, `Milestone { milestone }`,
`CancellationRequested { accepted }`, `Failure { code }`, `Warning { code }`,
and `Completed { result }`. Finalization emits the typed failure or cleanup
warning after its milestone and before exactly one `Completed` event. The
terminal result reflects final artifact reconciliation, including
`PublicationUncertain` precedence. Nonterminal events contain no artifact,
source, destination, or workspace paths.

`OperationSession::last_completion()` retains the logical terminal event's
sequence and snapshot together with the complete result, independently of
subscription and event delivery. This is one latest completion, not replay or
history. `last_result()` and synchronous Engine execution remain available.

## Progress

Progress is an authoritative latest-value snapshot, not an event stream.
`completed_bytes` counts complete source chunks confirmed written to private
staging. It remains zero for `AlreadyUpToDate` and for failures or cancellation
before copying. During a partial copy it reports only confirmed chunks. It can
equal `total_bytes` after staging even if later verification, promotion, or
publication fails or cancellation is accepted. Therefore, copied bytes never
by themselves imply validation or publication. `total_bytes` is the planned
source length.

## Cancellation and signals

`OperationSession::cancel()` keeps its existing behavior: it targets the active
execution and refuses cancellation after the publication cutoff. `Promoting`
and `Completing` remain noninterruptible. A cancellation request does not
become sticky state for a future operation.

The copy CLI creates a fresh invocation-local cancellation handle and installs
SIGINT/SIGTERM actions before planning. A pending signal is passed to admission
and honored before staging if planning succeeds. A planning failure remains a
pre-admission error and cannot affect a later invocation. Synchronous planning
I/O is not promised to be interruptible. Inspection and Verification retain
their existing signal behavior. Signal tests run in isolated subprocesses;
signal-hook 0.3 unregistering its final action does not restore the prior
default signal disposition.

## Authoritative completion

The host owns execution and completion: it calls the synchronous Engine API,
receives the complete `OperationResult`, and can recover the latest result and
terminal sequence/snapshot through `OperationSession::last_result()` and
`last_completion()`. Event delivery is optional and has one logical consumer.
A dropped or slow consumer cannot change filesystem execution or discard the
retained terminal result. A successful admission clears the previous
completion and stores its own when execution completes; a planning failure or
refused busy admission does not clear the previous completion.

The CLI's output workers are a reporting adapter around that host-owned seam.
They do not own, detach, or time out filesystem execution.

## Artifact reconciliation

The terminal result is the intentional reconciliation surface. It contains the
full artifact inventory, including each artifact's role, absolute path, parent
identity evidence, recorded and current device and inode, length, SHA-256, path
identity result, and retained flag. `OperationResult::artifacts()` exposes the
same data to Rust hosts. `job.result` embeds the complete result, including
artifact paths, because manual reconciliation requires location and identity
evidence.

Nonterminal events, generic errors, warnings, and progress snapshots never
carry artifact, source, destination, or workspace paths. `retained_storage_bytes()`
keeps Issue #9's conservative accounting: only retained file data with
sufficient identity and size evidence contributes, hard-link aliases are
deduplicated, and unretained or uncertain evidence contributes zero bytes.
`PublicationUncertain` and cleanup uncertainty remain distinct from verified
clean success.

## Machine record shapes

A terminal `job.result` has exactly six top-level fields: `schema_version`,
`kind`, `nscb_version`, `sequence`, `snapshot`, and `result`. Standalone `--json`
and the final JSONL record use this same shape. The sequence and snapshot are
those of the logical `Completed` event.

```json
{"schema_version":1,"kind":"job.result","nscb_version":"<version>","sequence":3,"snapshot":{"phase":"idle","status":"succeeded","milestone":"validated","outcome":"already_up_to_date","failure":null,"completed_bytes":0,"total_bytes":123},"result":{...}}
```

The `result` object serializes the complete `OperationResult`: `state`,
`outcome`, `failure`, `cleanup_warning`, `milestones`,
`cleanup_artifact_retained`, and `artifacts`. Artifact evidence may include
`artifact_id`, `parent_artifact_id`, `relative_name`, parent and artifact
identity fields, `role`, `path`, `length`, hashes, and `retained`; unavailable
evidence is null. Only terminal results intentionally contain artifact paths.

Each nonterminal JSONL record is a `job.event` with `schema_version`, `kind`,
`nscb_version`, `sequence`, immutable `snapshot`, and its typed event payload.
The `Completed` event is represented by the one terminal `job.result`, not a
second event line. Pre-admission errors retain the existing single `error`
record and have no fictional Job sequence or snapshot:

```json
{"schema_version":1,"kind":"job.event","nscb_version":"<version>","sequence":0,"snapshot":{"phase":"executing","status":"running","milestone":"executing","outcome":null,"failure":null,"completed_bytes":0,"total_bytes":123},"event":"started","total_bytes":123}
{"schema_version":1,"kind":"error","nscb_version":"<version>","error":{"code":"source_unavailable"}}
```

## Delivery failures

Copy reporting serializes each complete record before nonblocking admission to
bounded per-stream queues (16 semantic stdout records and four stderr
records). One stdout and one stderr worker own duplicated descriptors; writes
and flushes are acknowledged in stream order. The copy path does not change
inherited descriptor flags, hold standard-stream locks, or join a potentially
blocked writer.

For an admitted Job, a single five-second monotonic budget starts immediately
after the synchronous Engine call returns and operation cleanup is complete.
The JSONL execution worker records this time before the supervisor finishes
draining semantic events or releases the signal guard. A
pre-admission error starts the same budget when it is known. The budget is
shared by stdout, stderr, and diagnostics; it does not reset per stream or
record. Queue saturation, a broken pipe, a failed write or flush, or an
unacknowledged record by the deadline makes reporting fail. Normal executable
shutdown then ends detached reporting workers. The deadline never abandons
filesystem work, skips cleanup, or changes an `OperationResult`.

A reporting failure or timeout makes CLI exit code `7` take precedence over
the operation's exit class. Exit `7` is ambiguous about filesystem
publication: the Job may already have published successfully, and a terminal
record or diagnostic may be undeliverable. Automation must inspect a delivered
complete result and reconcile filesystem and artifact evidence before deciding
whether to retry. Blind retry based only on exit `7` is prohibited. The CLI
emits at most one terminal record and never fabricates a replacement after
uncertain delivery. Diagnostics use the same deadline, so blocked stderr does
not start another wait.

SIGINT and SIGTERM do not unblock a synchronous OS pipe write. A cancellation
request can affect filesystem execution only before its publication cutoff;
reporting then has its own deadline. Subprocess qualification keeps both pipe
readers open and unread, observes process exit within five seconds plus the
documented scheduling allowance, and checks the resulting filesystem state.
This is a macOS pipe qualification, not a hard real-time OS guarantee or a
claim for other sink drivers.

## Platform and qualification limits

Copy-through remains macOS-only and observed-only: it does not claim continuous
source snapshots against noncooperating writers, crash durability,
network-filesystem support, or Linux and Windows publication. The bounded
reporting behavior is likewise qualified for the macOS executable pipe path;
other operating systems and sink drivers require separate qualification. Replacement
requires the destination volume's qualified atomic exchange capability. The
event and machine-output contract does not imply broader filesystem,
provider, Nintendo-authenticity, or device-write qualification.

The accepted ADRs are unchanged. See
[publication guarantees](publication.md),
[ADR 0011](../adr/0011-events-and-progress.md), and
[ADR 0023](../adr/0023-machine-output-contract.md) for the surrounding
decisions, and [job contract qualification](../testing/job-contracts-qualification.md)
for the evidence and its limits.
