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
`inspection.preflight`, and `verification.result`) are unchanged. Job-output
machine kinds are `job.result`, `job.event`, and the existing `error` shape;
standalone durable history adds `jobs.list`, `jobs.show`, and `jobs.clear`.

Copy-through is qualified only on macOS. Other targets fail planning and
execution with `UnsupportedCapability`. The standalone executable owns
persistent Job history. The public Engine library remains stateless with
respect to configuration, SQLite, lifecycle, and filesystem history. This
contract adds no daemon, automatic replay, or generic command dispatcher.

The executable declares the non-default `standalone-job-history` feature as
required, and that feature alone enables the optional `rusqlite` dependency.
Standalone build and test commands enable it explicitly. The library default
graph and `--no-default-features` builds exclude standalone SQLite and history
modules from the Engine dependency graph.

## Command line

```
nscb copy <source> [<destination>] [--workspace <path>] [--replace] [--json | --jsonl]
nscb copy-batch <source>... [--input-list <path>]... --output-dir <existing-directory> [--workspace <path>] [--conflict fail|replace|skip | --replace | --skip] [--recursive] [--follow-symlinks] [--json | --jsonl]
nscb jobs list [--json]
nscb jobs show <id> [--json]
nscb jobs retry <id> [--failed-items] [--replace | --skip] [--json | --jsonl]
nscb jobs clear [--json]
```

`copy-batch` stops option parsing at `--`. Later arguments are positional
source names even when they begin with `--`. If parsing fails, the diagnostic
pre-scan also stops at that delimiter; a name such as `--json` cannot select
machine output after it.

The command requires one source and accepts zero or one destination. An
explicit destination overrides standalone configuration. When the destination
is omitted, the standalone adapter resolves the configured `output_dir`, or
the native `Documents/NSCB_output` default, followed by the source file name.
The Engine still receives one concrete destination. The command never prompts.
The default conflict policy refuses to replace a different existing
destination. `--replace` selects the qualified replacement path. Without
`--workspace`, staging uses the host temporary directory under
`nscb-copy-through`. Normal standalone startup initializes or loads the
standalone configuration; a Copy invocation does not write those per-job
choices back into configuration. After planning succeeds, standalone Job
history records the source intent, the explicit, configured, or native
destination selection, the explicit or host-default workspace selection, and
whether replacement was selected. The workspace directory created for an
invocation remains operation-owned evidence and is reported in the terminal
artifact inventory; history does not claim that every planned path was created.

`--json` and `--jsonl` are mutually exclusive. Repeating an option, supplying an
unknown `--` option, omitting a `--workspace` value, or providing anything other
than one source and at most one destination is a usage error with exit class 2. When a
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
| 8 | At least one `Copied` or `AlreadyUpToDate` item and at least one failed item (`CompletedWithIssues`) |

`PublicationUncertain` is reported as a failed job with exit 7. The destination
may exist; the result and artifact inventory carry the evidence and the
operation does not roll back over uncertain data.
Exit class 8 is used when a batch has at least one actual copy success (`Copied`
or `AlreadyUpToDate`) and a failed item. Skipped items do not count as successes.
A `CompletedWithIssues` batch exits 8 unless an item has an internal failure,
which exits 7. A cancelled batch exits 6 unless an item has an internal failure,
which exits 7. A failed batch selects the highest-ranked aggregate or item exit:
internal 7, cancellation 6, conflict 4, input 3. Every current failure code
selects one of the four exits. A failed batch with no recorded failure exits 7.
A succeeded batch exits 0.

## Planning, admission, and host-owned execution

Planning reads the source, destination, and selected workspace without
creating or modifying anything. The returned `OperationPlan` is an in-memory
capability and cannot be reconstructed from its snapshot.

For copy-through, one missing final destination-directory component is allowed
beneath an existing canonical parent. Planning records that immutable
precondition and a `CreateDestinationParent` effect without creating or
write-probing the directory. Execution revalidates the anchor, completes source
preflight, and creates only that final component before continuing through
conflict checks, staging, validation, and atomic publication. Additional missing
parent components remain unavailable.

A host-default workspace on another volume still selects the destination-local
fallback for one safely missing final directory. That fallback stages beside the
same existing anchor, and execution creates the missing component before any
staging entry appears.

Execution is host-owned. A host that needs events performs these steps:

1. Create or reuse an `OperationSession`.
2. Call `subscribe_events()` while the session is idle to claim the single
   event consumer for the next execution.
3. Run `Engine::execute_operation` or
   `Engine::execute_operation_with_cancellation` on a host-managed thread.
4. Consume events from the returned `OperationEventConsumer`.
5. Recover the authoritative `OperationResult` from the execution return value
   or from `OperationSession::last_result()`.

The host chooses its threading model. The embedded contract does not prescribe
an async runtime or worker pool. The standalone executable adds its binary-only
SQLite lifecycle around this seam; constructing or using the Engine library
never opens configuration or Job history.

`subscribe_events()` claims exactly one logical consumer for the next
execution. A second live consumer, or a claim attempted while an execution is
active, returns `EventConsumerUnavailable`. Dropping a consumer before
execution releases the claim. During execution, dropping the consumer
disconnects its queue. Delivery is best-effort after that point; execution
does not wait for a disconnected consumer, and the claim remains until the
terminal result.

Admission remains exclusive per session. A second execution admitted while
one is active returns a `Busy` failure result without emitting an execution
event and without replacing the active or previous authoritative terminal
result.

## Independent copy batches

`CopyBatchRequest` accepts an existing output directory, a workspace, a
conflict policy, and ordered items. `with_source` adds a source and derives its
destination from the source basename in the output directory. `with_item` adds
a source with an exact destination path. `with_keyed_item` preserves a retry's
item key and destination. `with_preflight_failure` represents a
general item-local failure that the resolver has already established.
`SplitInputUnsupported` is different: it is item-local only after Split
qualification succeeds. Callers pass the resolved qualification evidence to
`with_qualified_split_input_unsupported`. An untrusted, unsafe, or unqualified
raw Split preflight claim rejects the whole request before admission. Planning
rejects duplicate source identities, duplicate keys, normalized destination
collisions, unsafe or unrepresentable paths, and a request with no viable
item. The output directory must exist. Planning does not create or write-probe
it.

`Engine::execute_copy_batch` and `Engine::execute_copy_batch_with_cancellation`
execute viable items sequentially through the same copy core as a single Copy.
Each item revalidates its destination directory identity, writability, source,
workspace, locks, and publication preconditions after planning. An item-local
preflight failure does not stop later items. A batch-level session, resolver,
or checkpoint failure does.

`Engine::execute_copy_batch_with_checkpoint` accepts a host callback with a
one-based sequence for item checkpoint order. This sequence is separate from
the job-event sequence. The callback receives the complete typed item result,
including its publication outcome and recovered artifact evidence. The Engine
publishes `ItemCompleted` and advances completed progress only after the
callback confirms the durable checkpoint. If the callback fails, execution
stops, later items remain `not_started`, and the journal records
`CheckpointFailed` without an `ItemCompleted` event. The aggregate result
reports `checkpoint_failed`. `CopyBatchExecution::failed_checkpoint` retains
the result whose durable write failed so the standalone adapter can persist the
available publication evidence during finalization. A host that cannot commit
a checkpoint must treat the Job as uncertain and must not continue it.

The aggregate state is `Cancelled` when an item result was cancelled or when
cancellation is accepted before the atomic completion decision, even if the
last item checkpoint already succeeded. A checkpoint persistence failure takes
precedence and produces `Failed` with `checkpoint_failed`, even when the same
run also received an accepted cancellation. If any item reports
`PublicationUncertain`, the aggregate remains `Failed` with that batch-level
failure. Otherwise it is `Failed` when an item remains not started, `Succeeded`
when no item failed, `CompletedWithIssues` when at least one item succeeded
and another failed, and `Failed` when failures occurred without an actual
success. Skipped items do not count as successes for this decision. A batch
with only skipped items still produces `Succeeded`. The result retains every
item in plan order and one aggregate terminal decision.

Conflict policy is `Fail` by default. `Replace` and `Skip` require explicit
selection. Byte identity is checked before conflict policy: an existing
destination with the same bytes reports `already_up_to_date`. `Skip` applies
only to a differing existing destination. That item has item state and outcome
`skipped`, its destination remains unchanged, and it does not count as a
copied or already-up-to-date success for aggregate classification. `Fail` and
`Replace` keep their existing conflict behavior.
The CLI exits 0 for an all-skipped batch. Mixed success and failure exits 8
unless an item has an internal failure, which exits 7. For a failed batch, the
CLI selects the highest-ranked aggregate or item exit: internal 7, cancellation
6, conflict 4, input 3. Every current failure code selects one of those four
exits. A failed batch with no recorded failure exits 7.

## Standalone Job lifecycle

The standalone executable places durable history around the plan-first Engine
contract for both single Copy and independent copy batches. It plans first and
keeps planning read-only. Admission begins only after a viable immutable plan
and JSON-representable machine paths exist. The
transaction records the source intent, destination and workspace selection
provenance, conflict policy and its provenance, retry linkage, required
providers and keys, planned item evidence, and a tagged batch intent when
applicable. Planning and configuration
failures therefore create no Job.

For JSONL Copy, the event consumer and execution worker are started before the
admission transaction commits so worker-start failure can roll the transaction
back without creating a fictitious Job. The worker starts behind an in-memory
gate and the Engine is not called until the admission transaction commits and
the gate is released. Before opening the admission writer transaction, the
process exclusively locks one persistent slot from a fixed, bounded registry.
Each V3 slot file contains only its immutable opaque slot ID. The admission
transaction stores the Job ID and opaque claim token in SQLite and links that
claim to the slot. A released legacy V2 slot is rewritten in place to the V3
identity record only after SQLite confirms that no blocking claim remains and
the process holds its exclusive OS lock. The version marker is made durable
before the legacy suffix is truncated, so an interrupted conversion remains
parseable. Slot files are never unlinked or replaced. The process records the
transition to `running` before filesystem execution. A failed commit, slot
claim, or running transition
prevents filesystem mutation. Synchronous JSON and human Copy commit admission
and complete the lease/running transition before calling the Engine.

Copy-batch does not use the single-Copy execution worker. It sizes a bounded
event queue from the plan, commits admission, records the running transition,
then executes on the host thread with the same invocation-scoped cancellation
handle. The caller's capacity is an initial allocation hint; the session
retains every bounded semantic transition in order for the connected consumer
and never waits for it to make room. The session's latest progress and
retained terminal completion remain authoritative. A second consumer is
refused for that batch.

SQLite transactions are limited to schema initialization, admission, durable
state transitions, completion, retention pruning, recovery, and explicit clear
operations. The Engine never runs while an admission or completion transaction
is open. The OS releases the process-lifetime lease when its owner exits; a
stored PID, timestamp, or pathname is not ownership proof.

The worker obtains the authoritative result from the Engine return value or
`OperationSession::last_completion()` and commits the terminal outcome and
artifact evidence before any human, `job.result`, or semantic terminal output is
delivered. Reporting failure does not change the persisted result. If history
completion fails after filesystem execution, the base terminal result remains
authoritative, `history_error` exposes the persistence failure, and the CLI
exits 7 rather than silently reporting an untracked success. The admitted or
running record remains available for interruption and reconciliation.
The same output-failure exit class applies to retry in JSON, JSONL, and human
mode even when the retry's filesystem result and history row completed.

For an independent batch, the CLI supplies a checkpoint callback that commits
each item result and its publication evidence before the next item begins. The
v4 checkpoint row records the stable item key, monotonic sequence, item state,
outcome, failure code, publication classification, and complete typed item
evidence. The aggregate completion transaction then records the terminal
result and artifact ownership, releases or retains the lease claim, and applies
retention. If aggregate completion fails, the transaction rolls back its
aggregate writes while completed item checkpoints remain available for
recovery.
Newly admitted v4 item records use `nscb.copy_batch_item_provenance`. A
migrated v3 Job gets the `nscb.legacy_unqualified_batch_sources` source-intent
marker, and each migrated item gets
`nscb.legacy_unqualified_copy_batch_item_provenance`. These markers preserve
job and item history for inspection without inventing resolver provenance.
Failed-item retry rejects records whose marker does not establish qualified
source and item identity.

On startup and before history queries, NSCB scans nonterminal records and tries
to acquire each record's slot lock without waiting. Recovery checks the slot
file's stable ID against the SQLite slot mapping and verifies the Job ID and
claim token from SQLite again inside the recovery transaction. A legacy V2
file's embedded owner values must also match; V3 files contain no Job or token
values. The Job and item transitions and the claim's move to `unresolved` share
one transaction while the slot lock remains held. An active lease, mismatch,
missing file, or lock error preserves existing state. Lock release proves the
previous owner exited; it does not by itself prove safe slot reuse or
publication reconciliation. An unresolved claim therefore keeps the slot
unavailable until a separately justified reconciliation transition exists.
There is no daemon, automatic resumption, or fabricated terminal publication.
For a batch, recovery keeps committed item results and their artifact evidence.
It marks only items without a terminal checkpoint as `interrupted`; it does not
replay the remaining items or convert completed work into a fresh success.

`jobs retry` does not deserialize a stored plan or inherit authorization. It
loads the source intent and selection provenance, reconstructs a typed request,
and plans current filesystem and configuration state. Explicit destination and
workspace paths stay explicit; configured and native destination choices are
resolved again; a host-default workspace is selected again. The new Job links
to the parent Job ID and records the parent's conflict policy and original
policy provenance, but starts with the fail policy unless the operator supplies
fresh `--replace` or `--skip` authorization. The parent record and outputs are
unchanged.

Each Job stores its absolute invocation directory. A retry anchors relative
explicit source, destination, and workspace strings to the original Job's
invocation directory. The newly admitted Job records the retry invocation's own
directory while storing the anchored paths, so later retries cannot silently
change targets because the operator changed working directories. Single-Copy
retry accepts only terminal `copy_through` records with a `single` submission
and `all` scope. Independent batches use `--failed-items`; that path accepts
only stored item rows in state `failed`, after validating the tagged intent and
exact plan-item order. It reconstructs the saved source, destination, item key,
and path bases without expanding a directory or input list again. Prior
successes and skipped items are excluded and remain unchanged. Unknown kinds,
malformed intent, invalid successor states, an empty failed set, or missing
absolute context is rejected before planning. A failed `empty_selection` item
without a destination is also rejected before admission because reconstructing
its selection would require expanding a directory or input list again.

Before planning the retry, each saved Split failure is resolved at its exact
logical path under the stored base and current local trust store. The source
qualification and manifest digest must match the saved evidence; resolution
checks the current receipt, declared membership, and member contents. A mismatch
rejects the whole retry before admission. Resolver-wide state or configuration
failures retain their stable input-resolution code and exit class, including
`split_state_unavailable` and `split_trust_store_configuration_invalid`. The
input list is never read again.

Version 4 stores each batch source item with a versioned provenance object:
`schema_version: 1` and `kind: nscb.copy_batch_item_provenance`. The object
records the top-level selection, request base, optional input-list entry, and
optional directory discovery. A failure discovered while scanning or appending
a directory stores the canonical directory in `discovered_directory` and the
exact child path in `discovered_relative_path`. Failed-item retry joins those
two saved values and reconstructs the item without scanning the selected
directory again. The item keeps its original key, source, destination, order,
and path bases while the new Job records the retry invocation directory
separately. Successful and skipped siblings remain outside the retry selection,
and children added after the parent batch receive no retry work.

History written by the earlier v4 implementation can contain the same batch
record with untagged item provenance. NSCB keeps those records available for
inspection and preserves their stored evidence unchanged. It does not normalize
the records or infer qualification from them. `jobs retry --failed-items`
rejects them with `job_failed_items_unsupported`.

Retention keeps the newest 1,000 ordinary pruneable terminal records.
Nonterminal and `Interrupted` records, plus terminal records carrying unresolved
artifact, cleanup, or publication evidence, are protected from pruning and do
not count toward that cap. These records may raise the total above 1,000 until
reconciliation completes. Parent linkage is stored by Job ID so the child
remains inspectable after parent pruning. `jobs
clear` removes only terminal history and its cascading item/artifact rows,
preserves active records and unknown future states, and performs no filesystem
deletion. Terminal deletion uses an explicit state allowlist.

This contract does not automatically reclaim workspace or other artifact files.
`planned_artifacts` records possible paths and expected content rather than
proof that the operation created an artifact. The operation-owned result is the
authority for actual artifact identity and retention. When creation ownership or
unchanged identity cannot be proved, the artifact remains untouched and is
reported for manual reconciliation.

Publication classification uses the artifacts returned by the authoritative
operation result. A result without an operation outcome but with a
`PublishedDestination` artifact becomes `published_unresolved` rather than
`not_completed`. This state is nonpruneable so the published object remains
available for reconciliation even when no outcome was established.

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

`CopyBatchSession` exposes its own execution-local sequence. Its event kinds are
`Started`, `ItemStarted`, `ItemCompleted`, `CancellationRequested`,
`CheckpointFailed`, and one terminal `Completed`. Per-item transitions carry a
stable key, state, outcome, and sanitized failure code. Nonterminal events
contain no item paths. Delivery uses the caller-sized bounded queue from
`subscribe_events_with_capacity`; the requested size is an initial allocation
hint. The journal can hold no more than the fixed bound derived from the plan:
one `Started`, up to two transitions for each item, one accepted and one refused
cancellation, an optional `CheckpointFailed`, and one `Completed`. Queue
capacity never makes execution wait for a slow or disconnected consumer.
Progress remains a latest-value snapshot and is not added to the semantic
queue. `current_operation()` is the latest-value progress source, and
`last_completion()` retains the terminal sequence, snapshot, and aggregate
result independently of delivery. The session accepts one live event consumer
and one admission at a time. A cancellation request made while the session is
`Completing` returns false. The first such request records one
`CancellationRequested { accepted: false }` transition before `Completed`;
later requests return false without adding another event.
Dropping the consumer during active execution stops event delivery without
blocking execution, but keeps the claim until completion. The completed session
then accepts a new consumer.

## Progress

Progress is an authoritative latest-value snapshot, not an event stream.
`completed_bytes` counts complete source chunks confirmed written to private
staging. It remains zero for `AlreadyUpToDate` and for failures or cancellation
before copying. During a partial copy it reports only confirmed chunks. It can
equal `total_bytes` after staging even if later verification, promotion, or
publication fails or cancellation is accepted. Therefore, copied bytes never
by themselves imply validation or publication. `total_bytes` is the planned
source length.

For a batch, progress also reports total, completed, succeeded, failed, skipped,
and cancelled item counts plus the current stable item key. A skipped item
increments both succeeded and skipped counts. A preflight failure increments
the failed count. `completed_bytes` counts source bytes actually transferred
during successful copies, plus confirmed staging bytes for failed or cancelled
copies. An `AlreadyUpToDate` result or conflict `Skip` contributes zero copied
bytes. Progress mirrors the active inner operation while a copy is running,
then records the item's final byte count and status. The byte count does not
claim publication by itself. These counters advance under the session lock
with the corresponding event sequence.

## Cancellation and signals

`OperationSession::cancel()` keeps its existing behavior: it targets the active
execution and refuses cancellation after the publication cutoff. `Promoting`
and `Completing` remain noninterruptible. A cancellation request does not
become sticky state for a future operation.

`CopyBatchSession::cancel()` is accepted only while that batch is running. It
cancels unfinished items and leaves completed item checkpoints intact. The
first request refused during each aggregate-completion phase records one
ordered `CancellationRequested { accepted: false }` event. Later refusals from
the same `Completing` phase return `false` without another event, so repeated
requests are idempotent and the journal remains within its fixed bound. A
cancellation handle already set before batch admission
causes every item to be attempted as cancelled without publishing it. Each
later admission binds the handle supplied to that execution, and a caller-owned
cancelled handle remains cancelled if the host deliberately reuses it. A later
batch that needs independent cancellation must receive a fresh
`CancellationHandle`; admission does not reset an existing handle.

The CLI creates a fresh invocation-local cancellation handle and installs
SIGINT/SIGTERM actions before planning or batch input resolution. `copy-batch`
binds that handle to `InputResolutionControl`. A pending signal rejects batch
resolution with `split_resolution_cancelled` before planning or admission. The
resolver checks before filesystem work and between directory entries; Split
validation also checks while hashing. An I/O call already in progress may finish
before the next check. A planning failure remains a pre-admission error and
cannot affect a later invocation. Inspection and Verification retain their
existing signal behavior. Signal tests run in isolated subprocesses;
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

Batch execution makes one aggregate terminal decision from ordered item
results. `CopyBatchExecution::result()` is authoritative whether or not a
consumer receives the `Completed` event. For standalone history, the CLI waits
for aggregate persistence before writing the terminal JSON, JSONL, or human
record. A completion failure adds `history_error`, returns exit 7, and leaves
the prior checkpoints available for recovery.

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

Single-copy `job.event` and `job.result` envelopes remain at schema version 1.
A single-copy `job.result` has exactly six top-level fields: `schema_version`,
`kind`, `nscb_version`, `sequence`, `snapshot`, and `result`. The sequence and
snapshot are those of the logical `Completed` event. Standalone Copy `--json`
and the final JSONL record add top-level `job_id`. If durable completion failed
after the authoritative result existed, they also add top-level
`history_error`; otherwise that field is absent. Existing Probe records and the
Job event envelope are unchanged.

```json
{"schema_version":1,"kind":"job.result","nscb_version":"<version>","sequence":3,"snapshot":{"phase":"idle","status":"succeeded","milestone":"validated","outcome":"already_up_to_date","failure":null,"completed_bytes":0,"total_bytes":123},"result":{...}}
```

The `result` object serializes the complete `OperationResult`: `state`,
`outcome`, `failure`, `cleanup_warning`, `milestones`,
`cleanup_artifact_retained`, and `artifacts`. Artifact evidence may include
`artifact_id`, `parent_artifact_id`, `relative_name`, parent and artifact
identity fields, `role`, `path`, `length`, hashes, and `retained`; unavailable
evidence is null. Only terminal results intentionally contain artifact paths.

Copy-batch `job.result` records use schema version 2 in JSON and JSONL. Batch
`job.event` records use version 2 in JSONL. Both include top-level
`submission_kind: "independent_batch"`. Their snapshots use the flattened
batch progress shape, and the result contains the aggregate `state`, optional
batch failure, and an ordered `items` array. Each item carries its stable key,
resolved source and destination, state, outcome, failure, milestones, cleanup
fields, and artifact inventory. `--json` emits one terminal document.
`--jsonl` may emit `job.event` records first, each with the same
`submission_kind`, but only the final record contains the aggregate result. A
skipped item serializes state and outcome as `skipped` in both the event and
terminal item record.

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
readers open and unread, waits for durable terminalization, then uses a bounded
deadline to detect a process hang and checks the resulting filesystem state.
The deadline is a hang guard, not a process-latency target. This is a macOS pipe
qualification, not a claim for other sink drivers.

## Platform and qualification limits

Single Copy and independent copy batches remain macOS-only and observed-only.
They do not claim continuous source snapshots against noncooperating writers, crash durability,
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
