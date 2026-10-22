# ADR-0030: Qualify copy-through publication on macOS

**Status:** Accepted
**Date:** 2026-10-21
**Related decision:** [ADR-0013: Stage and validate artifacts before publication](0013-staged-validated-artifact-publication.md)

## Context

Issue #9 adds copy-through publication for one ordinary regular file. The
operation must preserve the planned source bytes, avoid overwriting an
unexpected destination, and retain enough evidence to reconcile data after an
uncertain publication. Darwin provides atomic name operations, but it does not
provide a syscall that atomically combines a final source-content check with
publication or conditions a rename exchange on the identity observed during
planning.

ADR-0013 remains the general publication decision for every other operation.
This decision states the narrower guarantees for Issue #9 copy-through v1; it
does not relax ADR-0013 requirements for other operations, published user data,
or provisional artifacts.

## Decision

### Qualification boundary

Copy-through v1 is qualified only on macOS when the required filesystem
operations succeed. Planning and execution return `UnsupportedCapability` on
other operating systems. Linux, Windows, network filesystems, and filesystem
configurations not covered by the local Darwin qualification remain
unqualified. Replace additionally requires the destination volume to advertise
`VOL_CAP_INT_RENAME_SWAP` and the actual `renameatx_np(RENAME_SWAP)` call to
succeed.

### Planned source and observed destination

The in-memory plan records the source identity, metadata, byte length, and
SHA-256 digest; the destination baseline; the selected workspace; and the
workspace creation-parent evidence when its final component is absent. The
host provides a non-persistent default workspace through
`CopyThroughRequest::with_host_default_workspace`; a per-request
`with_workspace_override` selects another location. `CopyThroughRequest::new`
continues to take an explicit workspace. The Engine does not own workspace
configuration. The serialized inspection snapshot includes `kind`,
`nscb_version`, the source evidence, the selected workspace, the staging
strategy and parent identity, and the authoritative destination baseline. It
cannot be deserialized into an executable plan. When the host-default workspace
and destination are on different filesystems, planning selects destination-local
fallback when that volume is qualified for it. An explicit cross-filesystem
workspace override returns `UnsupportedCapability`; execution revalidates the
planned strategy and parent identity.

Source evidence reads exactly the planned byte length in fixed-size chunks and
then probes one byte for growth. A short read or observed growth is
`SourceChanged`; no read follows an unbounded source stream. Execution holds a
cooperative shared source lock through publication and revalidates the source
at operation checkpoints. A detected change before promotion fails without
publishing. A change detected after promotion returns `PublicationUncertain`,
retains the published output and relevant artifacts, and never attempts an
automatic rollback. The final source check and promotion syscall are separate;
a same-user noncooperating writer can change the source between them. The
contract does not promise continuous source stability or that stale bytes are
never briefly visible.

### Destination conflict policy

`ConflictPolicy::Fail` is the default. For an absent destination, `linkat`
creates a second name for the validated staging inode and fails without
replacing a name that appeared concurrently. The retained staged path and
published destination are hard-link aliases to the same inode; editing or
truncating either alias changes the published bytes. An unsupported link
operation fails closed.

`ConflictPolicy::Replace` is explicit. Before promotion, execution revalidates
the destination identity and content, creates a recovery copy, and checks the
Darwin volume capability. `RENAME_SWAP` exchanges the entries at the two names
atomically, but does not condition the exchange on either entry having the
identity observed during planning. An unexpected displaced entry is retained
and counted only after the actual captured entry passes identity, length, and
digest revalidation. If the entry is removed, substituted, unreadable, or
otherwise unverifiable, the result is `PublicationUncertain`, the entry is
unretained and uncounted, and the operation makes no claim about the earlier
observed inode. The planned output and all independently verified recovery
evidence remain inventoried. No uncertain replacement is automatically rolled
back.

After publication's final output and source checks, inventory rereads each
displaced entry through its opened parent descriptor with bounded reads. A
same-identity length or content change detected before inventory completes
returns `DestinationChanged`; missing, unreadable, substituted, or
identity-uncertain post-promotion evidence returns `PublicationUncertain`.
This late inventory classification cannot erase an earlier post-promotion
`PublicationUncertain` result.

Shared `OperationSession` admission and filesystem advisory locks coordinate
NSCB operations that use this protocol. The destination lock is a persistent
regular-file marker, never removed or replaced by NSCB and excluded from
per-operation artifacts and storage accounting. The marker path is revalidated
immediately before promotion. A noncooperating process can retarget it after
that check, or replace the staging name after its identity check, before the
name-based syscall. These intervals are not atomic. The operation makes no
identity-conditional replacement claim and does not coordinate arbitrary
same-user processes.

### Retention and storage

Darwin's pathname removal API cannot condition an unlink on expected file
identity. A check followed by unlink can therefore remove a same-user
process's substituted entry. Copy-through retains its staging directory,
staged output, destination recovery copy, displaced entries, and uncertain
entries rather than deleting by pathname. The result inventories each entry's
role, recorded identity and content evidence when observed, planned path,
parent identity, and current path evidence when available. Current length and
digest are refreshed at inventory time; a changed-length or unreadable artifact
has no current digest, while its last-recorded digest remains separately
available as historical evidence. Successful publication may include a
`CleanupIncomplete` warning.

For Fail, a competing entry is marked retained only after an independently
captured alias matches the identity, length, and digest observed for that
publication attempt. A pre-link substitution, disappearance, or unverifiable
entry returns `PublicationUncertain`; it is not marked retained, its bytes are
not included in the retained total, and the operation does not claim that the
earlier observed inode survived. For Replace, the entry actually displaced by
the atomic exchange is verified and inventoried as a distinct
`DisplacedDestination`; it may differ from the planned baseline. Its own
identity and content evidence supports retention and byte accounting, while a
verified difference produces `DestinationChanged`. A retained verified alias
remains retained if the destination pathname changes later. This is the
accepted observed-only boundary for copy-through v1.

Before staging, the operation queries `fstatfs` using the already-open
workspace or workspace-creation-parent directory descriptor. It requires free
space for the planned source, the destination recovery copy for Replace, and a
64 MiB safety reserve. An unsupported, invalid, or failed descriptor-based
capacity query fails closed. The query does not resolve the pathname again
after the directory was opened and validated. This preflight estimate does not
reserve space; another process can consume capacity before or during staging.

`OperationResult::retained_storage_bytes()` reports known retained file-data
cost beyond published output and returns `None` if retained data lacks enough
identity or size evidence for a safe total. Embedding hosts must expose the
cost and artifact inventory to callers. Reconciliation is manual; names and
directory permissions alone do not prove ownership. The host must not edit or
truncate retained artifact contents during cleanup. Under Fail, writing through
either hard-link alias changes published content. This implementation preserves
per-operation artifacts and does not automatically unlink them. Any future
cleanup must establish ownership, parent identity, unchanged file identity, and
content before removal; uncertain artifacts remain in place.

### Current session state and ADR-0008 scope

The shared `OperationSession` exposes an ephemeral queryable current-operation
snapshot with phase, status, latest milestone, and terminal outcome or failure.
Clones share that state, while independently constructed sessions do not.
Independently constructed sessions can still coordinate publication through
the per-parent filesystem marker, so distinct destination files in one parent
may serialize. That conservative throughput limitation does not make their
admission state shared and does not expand the filesystem safety guarantee.
`AlreadyUpToDate` remains a successful operation outcome with Succeeded status.
The snapshot is per shared session and is cleared on the next admission; it is
not Engine-global admission, a runtime handle, an event stream, or durable
history.

ADR-0008 describes broader Engine-scoped lifecycle behavior. For Issue #9,
`Engine` remains zero-sized and stateless, while `execute_operation` performs
filesystem publication. Operation admission and current state remain host-owned
by a shared `OperationSession`. Independent sessions keep separate admission
state while still coordinating same-parent publication through the marker.
This records the scope discrepancy without changing ADR-0008.

### Phase and evidence reporting

`Executing` covers staging and the final full-file checks of source,
destination baseline, and staged output; cancellation is accepted through the
last of those checks. `Promoting` begins at the cancellation cutoff, before the
brief final workspace, staging-entry, and lock-marker operand checks. It then
covers `linkat` or `renameatx_np(RENAME_SWAP)`. The stage entry is checked by
inode identity and planned length in `Promoting`; full SHA-256 validation
occurred during `Executing`. `Completing` follows a successful publication
syscall for post-publication checks, artifact inventory, and result assembly.
The execution wrapper also enters `Completing` before cleanup, competitor
capture, inventory, or result assembly after an earlier execution failure.
Cancellation accepted before that handoff is honored as `Cancelled`; later
cancellation is refused. An already-identical destination skips `Promoting`
and enters `Completing` after its final comparison. The final pathname checks
are separate from the syscall and do not establish inode-conditional
publication.

If final inventory finds that the published destination name now identifies a
different inode, the inventory reports the planned output from a retained
staging or recovery alias and emits a separate `UncertainEntry` for the
current name. A competitor contributes to retained storage only after a
destination-local alias passes identity and content revalidation. Replace
retains a hard-link recovery alias for the planned output. The alias adds no
data blocks, but it is retained evidence and must never be edited or truncated
during reconciliation.

There is a pathname race while anchoring a late competitor. The implementation
reads the observed inode through an open file descriptor, then calls `linkat`
with the destination parent descriptor and name. A noncooperating writer can
replace that name before `linkat` resolves it, so the new alias may identify a
different inode. The operation compares the alias identity, length, and digest
with the earlier observation. A mismatch returns `PublicationUncertain`; the
alias is unretained and uncounted, and the operation makes no claim that the
earlier inode remains available. The inspected Darwin SDK provides no
supported public descriptor-source hard-link operation that eliminates this
interval.

For copy-through v1, this is the accepted observed-only, fail-closed boundary.
A deterministic post-link replacement proves that an already verified alias
survives a later name replacement. A deterministic pre-link substitution or
disappearance proves typed uncertainty without false retained-inode evidence
or competitor-byte accounting. The contract does not assert that every
previously observed competitor inode survives arbitrary noncooperating
changes.

Apple's `fclonefileat` and `fcopyfile` APIs do not close this content race.
Clone availability is filesystem- and volume-specific, including APFS clone
capability, and neither API documents an atomic snapshot of bytes previously
hashed when another process may mutate the same inode. `fcopyfile` can use an
open descriptor to avoid a pathname switch, but the referenced inode remains
mutable. A post-copy digest can detect different bytes but cannot restore the
earlier content. These limitations explain why the approved contract is
observed-only and do not support an identity-conditional `linkat` or rename
claim.

### Qualification limits

Tests exercise bounded source growth and truncation, cooperative source-lock
holding through publication, deterministic source and destination races,
combined source and destination mutation, late displaced-artifact mutation
before inventory, atomic no-clobber publication, replacement exchange
behavior, artifact digest refresh, retention accounting, and descriptor-based
free-space querying after pathname retargeting. They also cover the shared
session snapshot, per-request workspace override, and completed-guard drop
behavior after a newer operation is admitted through the shared session. The
named `late_fail_competitor_anchor_survives_second_replacement` and
`late_replace_competitor_anchor_survives_second_replacement` cases prove that
verified aliases remain inventoried across later pathname replacement. The
`late_competitor_replaced_before_link_is_uncertain_and_not_counted` case proves
the observed-only pre-link boundary.

These tests qualify only the tested local macOS environment. They do not
establish filesystem crash durability, network-filesystem behavior, or an
atomic source snapshot against noncooperating writers. Containing directories
are not synchronized for crash durability.

## Consequences

Copy-through can complete successfully while reporting retained staging and
recovery data. Hosts must present the warning and byte estimate, preserve the
inventory, and provide a manual reconciliation path. A `PublicationUncertain`
result must not trigger an automatic retry or rollback through data that may
already be visible. Other publication operations remain governed by ADR-0013.
