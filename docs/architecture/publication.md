# Copy-through publication guarantees

Issue #9 copy-through v1 copies one ordinary regular file to a host-selected
destination. It preserves the source, does not interpret file contents, and
does not invoke providers, keys, devices, or operation history. This specific
operation is supported only on macOS when its required filesystem operations
are available. Linux, Windows, network filesystems, and unqualified filesystem
configurations are outside this version's qualification.

## Planning and destination policy

`Engine::plan_copy_through(CopyThroughRequest)` reads the source and destination
and inspects the selected workspace without creating files or directories. A
host supplies a non-persistent default workspace with
`CopyThroughRequest::with_host_default_workspace`; the request's
`with_workspace_override` method selects a different location for one
operation. `CopyThroughRequest::new` continues to accept an explicit workspace.
The Engine stores no workspace configuration. The plan captures source
identity, metadata, length, and SHA-256; the authoritative destination
baseline; the selected workspace path; and the immediate parent identity when
the workspace's final component is absent. An absent workspace is created
only after that parent is revalidated. The staging strategy and staging-parent identity are captured in the immutable
plan and revalidated during execution. When the host-default workspace and
destination are on different filesystems, planning selects destination-local
fallback when the destination volume is qualified for it. An explicit
cross-filesystem workspace override returns `UnsupportedCapability`. Missing
ancestors and a workspace that appears after planning fail closed.

When one final output directory is safely missing, execution revalidates the
destination's existing anchor, creates that directory, and only then begins
destination-local staging beside the anchor.

The serialized inspection snapshot carries `kind`, `nscb_version`, the source
evidence, explicit workspace, destination baseline, policy, and planned
artifact paths. It cannot reconstruct or replay the in-memory plan. A stale
plan must be planned again by the caller.

`ConflictPolicy::Fail` is the default and refuses to overwrite a different
existing destination. If the destination already matches the planned source,
execution may return `AlreadyUpToDate` after rechecking the source and
destination. For a missing destination, `linkat` creates a hard-link alias:
the retained staged path and published destination name refer to the same
inode. Editing or truncating either alias changes the published bytes.
`ConflictPolicy::Replace` must be explicitly selected. Copying a
physical Split member or a path the existing input resolver identifies as a
Split representation is rejected, including qualified one-part sets.

## Source evidence and cooperation

Source hashing and comparison read no more than the planned byte length plus
one growth-probe byte. Reads use a fixed-size buffer. Truncation or detected
growth is a typed `SourceChanged` failure before publication. Execution
revalidates source identity, metadata, and content at checkpoints and holds a
cooperative shared source lock through publication, post-publication cleanup,
competitor evidence capture, artifact inventory, and terminal result assembly.
The lock is released only after the result has been constructed.

The lock coordinates only writers using the same protocol. Darwin provides no
operation that atomically combines final source validation with publication.
A noncooperating same-user writer can mutate the source between the last
revalidation and the publication syscall. If the change is detected after
promotion, the operation returns `PublicationUncertain`, keeps the published
output and related evidence, and does not roll back. The output may have been
visible before detection. Repeated hashes and metadata checks do not establish
a continuous or atomic source snapshot.

## Fail and Replace publication

For an absent destination, the operation uses same-filesystem `linkat` to
create the destination name for the validated staging inode. The call does not
replace an entry that appears concurrently. A competing entry is preserved
when it can be captured and independently verified; otherwise the typed result
is `PublicationUncertain` and no retention claim is made. If the filesystem
rejects the required operation, publication fails closed.

Replace is qualified only when the destination volume advertises Darwin's
`VOL_CAP_INT_RENAME_SWAP` capability and the actual
`renameatx_np(RENAME_SWAP)` call succeeds. Execution revalidates the destination
baseline and retains a recovery copy before exchange. The syscall atomically
exchanges entries at two names but does not compare either entry with the
identity recorded during planning.

Replace captures the entry actually displaced by the atomic exchange and
inventories it as a distinct `DisplacedDestination` artifact. That entry can
differ from the planned baseline; it is not required to match the baseline to
be retained. It is retained and counted when its own post-swap identity,
length, and digest evidence is established, and a difference from the planned
baseline produces `DestinationChanged`. If the entry is removed, substituted,
unreadable, or otherwise unverifiable, the result is `PublicationUncertain` and
no unproven bytes are counted. When post-promotion state cannot be proven,
recovery evidence and the uncertain entry remain inventoried. The operation
never performs automatic rollback through uncertain data and never claims
identity-conditional replacement.

After publication checks finish, inventory refreshes any displaced entry
through its held parent descriptor with bounded reads. A verified current
identity and content update changes an unexpected competitor to
`DestinationChanged`. A missing, unreadable, substituted, or identity-uncertain
entry changes the result to `PublicationUncertain`. A post-promotion
`PublicationUncertain` result takes precedence over a later
`DestinationChanged` classification.

An advisory destination lock coordinates NSCB operations that follow the same
protocol. The lock is one fixed marker entry per opened destination parent
directory. The operation records the parent descriptor's device and inode and
revalidates that identity, then opens the marker relative to the descriptor.
This conservatively serializes destinations in the same parent directory and
also coalesces case, normalization, or other path spellings that resolve to the
same parent entry. Independently constructed sessions have separate admission
and current-operation state, but executions for the same parent still use the
same filesystem marker. Distinct destination files in one parent may therefore
serialize; this is an intentional throughput limitation, not a broader safety
guarantee. A noncooperating same-user process can still race final validation
and the name-based publication syscall. Final checks detect marker or staging
retargeting observed before the syscall but cannot close the remaining
check-to-syscall interval. The persistent marker is protocol state, is never
removed or replaced by NSCB, and is excluded from per-operation artifact and
retained-storage accounting.

## Retained artifacts and capacity

Cleanup preserves and inventories per-operation staging, recovery, displaced,
and uncertain entries. This implementation does not automatically unlink
artifacts because Darwin pathname removal cannot atomically require the identity
observed through a handle. Path inspection alone cannot authorize deleting an
entry; uncertain ownership, identity, or content evidence leaves the artifact
in place.

A late regular-file competitor is linked by the destination parent descriptor
and name into a randomly named private directory in that parent. A race exists
between reading the observed inode through a descriptor and the pathname-based
`linkat`: a noncooperating writer can replace the destination name in that
interval, causing the link to capture a different inode. The operation
keeps the descriptor used for observation open while creating and verifying the
private alias. Holding that descriptor prevents the observed inode from being
reallocated during the pathname-based `linkat` interval, and the operation
revalidates the private alias identity, length, and digest against the earlier
observation. A match is marked `retained() == true` and counted once. A
mismatch returns `PublicationUncertain`; the alias remains unretained and
uncounted. Its artifact can still record complete identity, length, and digest
for the object actually linked, but that evidence does not prove the earlier
observed inode still exists at the destination pathname.

The inspected Darwin SDK provides no supported public descriptor-source
hard-link operation that eliminates this pathname interval. Copy-through v1
therefore accepts observed-only, fail-closed retention. An alias that matches
the earlier observation is retained and remains durable evidence even if the
destination pathname is later replaced. An alias that does not match remains
an unretained record, while an unverifiable or vanished pre-link competitor is
typed uncertainty. Neither case is retained data. This does not guarantee
preservation of bytes that a noncooperating same-user process independently
removes or modifies.

The public `UncertainEntry` role is an inventory category for entries that are
not planned outputs, destinations, backups, or displaced destination entries.
It covers retained and unretained competitor aliases as well as genuinely
uncertain entries. A path-linked alias that does not match the earlier
observation can carry complete identity, length, digest, and
path-verification evidence while reporting `retained() == false`; its bytes do
not contribute to `retained_storage_bytes()`. A genuinely uncertain entry may
omit even that alias evidence or describe only its current pathname. Consumers
must inspect the retained flag and evidence fields rather than treating the
role name as proof of ownership, retention, or anonymity.

Before reporting current path presence or retaining a competitor, final
inventory performs a fresh directory-relative name lookup after content
hashing. A changed or vanished identity is `PublicationUncertain`; a stale
handle does not establish destination ownership, while bytes of an
independently verified operation-owned staging inode remain eligible for
retained accounting. If Fail-policy `linkat` reports `EEXIST` but the competitor
disappears before its first capture open, the result contains a path-only,
unretained `UncertainEntry`, returns `PublicationUncertain`, and counts no
undocumented competitor bytes.

Darwin `fclonefileat` and `fcopyfile` were evaluated as alternatives. Clone
support is filesystem- and volume-specific, including APFS clone capability,
and neither API documents an atomic content snapshot matching bytes hashed
before a concurrent writer mutates the same inode. `fcopyfile` can use an open
source descriptor, which avoids pathname redirection but not mutation of that
inode; a digest after the copy can detect a mismatch but cannot recover or
preserve earlier bytes. These limitations explain the accepted observed-only
boundary; they do not qualify a stronger retention guarantee.

The artifact inventory reports each role, planned path, parent identity,
recorded device and inode, last-recorded length and digest, and current path
identity, length, and freshly read digest when available. Current digest reads
are bounded by recorded length and use a one-byte growth probe. An unreadable
or changed-length file has no current digest; its recorded digest remains
separately available as historical evidence. If a parent directory moves, the
planned absolute path remains paired with parent-identity evidence, and child
path evidence is reported as unknown where current parent identity cannot be
established.

Capacity preflight uses `fstatfs` on the already opened workspace or
workspace-creation-parent directory descriptor. It checks planned source bytes,
the destination recovery copy when Replace is selected, and a 64 MiB reserve.
The operation fails with `InsufficientStorage` when the estimate does not fit
and fails closed when descriptor-based volume capacity cannot be established.
The preflight does not reserve space and does not re-resolve a workspace
pathname that may have been retargeted after the directory was opened.

`OperationResult::retained_storage_bytes()` reports known retained file-data
bytes beyond the published output, deduplicating hard-link aliases of the same
inode. It counts only artifacts whose `retained()` value is `true`; an
unretained evidence record contributes zero bytes. It returns `None` when
retained data lacks identity or size evidence.
Hosts should present that cost together with the artifact inventory and provide
a manual reconciliation path. A successful operation may carry a
`CleanupIncomplete` warning without changing its `Succeeded` state.

Manual reconciliation must never edit or truncate retained artifact contents.
Under Fail, the staging name and destination may be hard-link aliases to the
same inode, so changing either alias changes published output. The
implementation does not automatically unlink operation artifacts. Any future
cleanup must prove ownership, parent identity, unchanged file identity, and
content before removal; uncertain artifacts must remain in place.

## Session state scope

`OperationSession` exposes an ephemeral current-operation snapshot containing
phase, status, latest milestone, completed and total source bytes, and terminal
outcome or failure. Cloned sessions share admission and current state;
separately constructed sessions do not. `AlreadyUpToDate` is an operation
outcome with Succeeded status, not a separate terminal job state. The snapshot
is per shared session and is replaced when another operation is admitted; a
refused busy admission leaves the previous snapshot unchanged. It is not
Engine-global admission, execution history, or an ordered event stream.

The snapshot is the authoritative latest-value progress surface.
`completed_bytes()` counts source bytes successfully written into private
staging by the copy loop. It is zero for `AlreadyUpToDate` and for failures or
cancellation before copying, and it can equal `total_bytes()` after a later
verification or publication failure. Copy completion therefore does not claim
verification or publication success.

`OperationSession::subscribe_events()` claims one logical ordered event consumer
for the next execution. Events carry execution-local sequence numbers and do
not include per-byte progress. Dropping or failing to service the consumer never
blocks execution. `OperationSession::last_result()` retains the complete
terminal result until the next admission, independently of event delivery.

Cancellation requested through `OperationSession::cancel()` remains accepted
only while the execution is in `Executing`. The additive
`Engine::execute_operation_with_cancellation()` binds a `CancellationHandle` to
one invocation, so a pre-execution request is never stored on an idle session.
NSCB does not clear the caller-owned handle after execution; callers must use a
fresh handle when a later execution should not inherit an earlier cancellation.
The CLI installs SIGINT and SIGTERM actions
only for the command invocation and unregisters them at the end. signal-hook 0.3
does not restore the process's previous or default signal disposition when the
final action is removed, so the CLI qualifies signal behavior in isolated
subprocesses and does not claim process-global restoration. Inspection and
Verification use the same scoped registration.

ADR-0008 describes broader Engine-scoped operation lifecycle behavior. Issue
#9 keeps `Engine` zero-sized and stateless, while `execute_operation` performs
filesystem publication. Admission and current-operation state remain
host-owned by the shared `OperationSession`. Independent sessions keep
separate admission state, while executions for destinations in the same parent
still coordinate through the filesystem marker. This records a scoped
discrepancy without amending ADR-0008.

Replace retains a hard-link recovery alias for the planned output. The alias
shares the output inode and adds a directory entry without duplicating the
file's data blocks. If a noncooperating process later replaces the destination
name, final inventory reports the planned output through the recovery alias and
reports the current destination inode separately. A destination-local
competitor alias is retained and counted only when identity, length, and digest
revalidation match the earlier observation. If the pre-link pathname is
replaced or disappears, the result is `PublicationUncertain`, the captured
alias is unretained and uncounted, and no claim is made that the earlier
observed inode survived. The pre-link test proves that fail-closed boundary;
the post-link tests prove that an already verified alias survives later
pathname replacement. Verified aliases and the planned output contribute once
per inode to `retained_storage_bytes()`. While the destination still names the
planned output, editing or truncating the recovery alias changes the bytes
visible at the destination, so reconciliation must never mutate either alias.

## Session state phases

`Executing` includes the final full-file verification of the source,
destination baseline, and staged output. `Promoting` includes brief final
workspace, staging-entry, and lock-marker path checks followed by `linkat` or
`renameatx_np(RENAME_SWAP)`. The stage entry is checked by inode identity and
planned length; full SHA-256 verification is completed before this phase.
`Completing` covers post-publication checks, artifact inventory, and terminal
result assembly. The execution wrapper enters `Completing` before cleanup,
competitor capture, artifact inventory, or result construction, including
finalization after an earlier execution failure. Cancellation is accepted
while `Executing`; a request accepted before the wrapper's finalization handoff
normally produces `Cancelled`, while the phase transition and accepted
disposition are committed together. If finalization has already established
`PublicationUncertain`, that uncertainty takes precedence over cancellation and
remains the terminal failure. The in-progress snapshot reports `Completing`
with `CancellationRequested`; later cancellation is refused. Finalization
preserves owned staging and any independently verified competitor evidence. Cancellation
is refused from the start of `Promoting` and throughout `Completing`. The final
pathname checks remain separate from the name-based syscall and do not establish
inode-conditional publication.

## Platform and durability limits

Non-macOS targets fail planning and execution with `UnsupportedCapability`.
Replace also fails closed when the current volume does not advertise the
required exchange capability. Other volume types and mount configurations
remain unqualified unless tested separately. Staged file contents are
synchronized; containing directories are not. Crash durability after power
loss or kernel failure is not claimed.

ADR-0030 records this narrow Issue #9 decision. ADR-0013 remains the general
publication policy for every unrelated operation.
