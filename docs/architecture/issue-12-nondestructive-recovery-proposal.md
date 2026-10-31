# Non-authoritative proposal: nondestructive interruption recovery for Issue 12

**Status:** Proposal only. This document does not change an ADR, an existing
acceptance criterion, `PROMPT.md`, `run.json`, or `RESULT.json`.

**Scope:** Issue #12 standalone Job history and interruption recovery.

**Authority:** The original Issue #12 run prompt and
[ADR-0030](../adr/0030-darwin-copy-through-qualification.md).

## 1. Purpose

Issue #12 currently includes TAC-6, which combines interruption recovery with
cleanup of operation-owned disposable artifacts. That wording assumes the
implementation can prove both which filesystem entries NSCB created and that
removing a particular entry is safe. Those are different claims from proving
that an interrupted Job is accurately represented and that uncertain files are
preserved.

This proposal separates the achievable recovery acceptance from future artifact
reclamation. It offers a replacement criterion for owner consideration. It is
not a qualification result, does not establish that TAC-6 passes, and does not
authorize cleanup code.

## 2. Why the current criterion needs revision

TAC-6 asks for safe cleanup of only artifacts whose ownership is positively
proven and whose contents remain unchanged. The current Darwin publication
boundary cannot turn a pathname observation into an identity-bound removal
operation.

ADR-0030 records these relevant limits:

1. Darwin's pathname removal interface cannot condition unlink on the identity
   observed at that pathname.
2. A check followed by unlink has an interval in which a noncooperating
   same-user process can replace the checked entry. Unlinking the replacement
   would remove an object that NSCB did not verify.
3. An open descriptor can provide reliable identity and content observations,
   but a descriptor-backed unlink operation alone does not make a later
   pathname-based removal conditional on that descriptor's identity.
4. NSCB's advisory locks coordinate cooperative NSCB participants. They do not
   exclude arbitrary same-user processes from changing names.
5. Publication results intentionally use an observed-only, fail-closed
   boundary. They preserve retained and uncertain entries rather than promise
   that every previously observed peer inode survives an arbitrary concurrent
   change.

Adding more checks inside `src/operation.rs` would not close these gaps. The
Engine operation can gather observations, but it cannot by itself create a
durable, restart-safe creation receipt or provide an identity-conditional
filesystem removals primitive. The operation layer also cannot decide the
standalone history transaction, cross-process recovery protocol, or repository
threat model.

## 3. Proposed criterion: NDR-1

The following is a proposed, explicitly revised nondestructive interruption
recovery criterion for Issue #12. It is intended to cover recovery and history
preservation only. It is not a general artifact-cleanup criterion.

> **NDR-1 - Nondestructive interruption recovery:** A standalone Job interrupted
> by process termination is classified as `Interrupted` only after exclusive
> acquisition of its per-Job operating-system lease demonstrates that no owner
> remains in the supported local-filesystem model. The Job and item history
> transition is atomic and durable, preserves the admissible admission record,
> does not invent a terminal publication outcome, and does not automatically
> resume or replay the Job. All operation artifacts remain in place and remain
> queryable with their recorded role, planned path, parent identity evidence,
> object identity evidence, content evidence, and retention classification.
> Recovery, retention, and explicit history clearing perform no automatic
> filesystem deletion. Workspace roots, staging directories and files, backups,
> displaced entries, uncertain entries, hard-link aliases, and objects with
> incomplete ownership evidence remain available for reconciliation. A planned
> path alone never establishes that NSCB created an artifact.

This criterion has four required parts.

### 3.1 Liveness-proven interruption

Recovery may transition an `admitted` or `running` record only after a
nonblocking acquisition of that Job's advisory lease succeeds. A live owner, an
acquisition error, or an otherwise ambiguous lease result must leave the record
unchanged. A stored PID, start time, path, or absence from a process table is
not ownership proof because those facts can be stale or reused.

The recovery transition must update the Job and its active items atomically.
Concurrent recovery attempts must not produce duplicate terminal transitions.
The lease acquisition and database transition are evidence of abandonment in
the documented cooperative local filesystem model. This proposal does not
extend that model to arbitrary network filesystems or hostile same-user
changes.

### 3.2 Accurate durable history

History must preserve admission provenance, state transitions, timestamps,
typed outcomes, failure categories, and item evidence. A missing authoritative
operation result must not be converted into success. If publication might have
occurred without an outcome, the record must retain that uncertainty and remain
available for reconciliation.

A completion write failure must remain visible to the caller and must not erase
the already returned filesystem result. If the durable row cannot record that
completion, it must remain nonterminal and later become `Interrupted` only
under the liveness rule above.

### 3.3 Retained or reconcilable uncertain artifacts

Interruption recovery must not assume that stdout, a JSONL stream, or the most
recent in-memory state contains the complete artifact inventory. Persisted
history must retain every authoritative artifact record that was committed and
must keep records with retained, publish-unresolved, or otherwise uncertain
evidence outside ordinary pruning.

Artifact evidence should preserve, where available:

1. Role, planned path, relative name, and parent artifact identifier.
2. Recorded device and inode for the parent and object.
3. Recorded length and SHA-256 evidence, including historical evidence that
   differs from current observations.
4. Current path identity, length, and retention state when reconciliation can
   still observe them.

Incomplete evidence is itself a preservation reason. It must not be treated as
permission to remove an object.

### 3.4 No automatic filesystem deletion

Under NDR-1, recovery, retention pruning, and `jobs clear` do not unlink,
truncate, overwrite, or recursively delete operation artifacts. `jobs clear`
removes explicitly allowed history rows and their dependent rows only. A
published destination, source, configuration, key, cache, workspace root,
staging artifact, backup, displaced entry, or uncertain entry remains on disk.

The absence of automatic deletion is part of the acceptance result. It makes
interruption recovery nondestructive even when the process did not finish its
normal artifact-inventory path.

## 4. Creation evidence and deletion authority are different

The following evidence classes must remain distinct in implementation plans,
results, and user-facing diagnostics.

| Evidence class | What it establishes | What it does not establish |
| --- | --- | --- |
| Planned artifact | A future execution may create a named entry with expected content. | That execution created the entry, that the name still refers to it, or that any object is safe to remove. |
| Artifact inventory | An object, parent, role, and content were observed at a named point. | Which process created the object or whether a later pathname names the same object. |
| Actual-creation evidence | NSCB created a specific namespace entry while holding a durable creation record tied to the Job, parent identity, entry identity, and creation phase. | That the object is safe to unlink later if a pathname can be substituted. |
| Retention evidence | An observed object or alias remains available for reconciliation. | Ownership of an arbitrary same-user replacement or permission for automatic removal. |
| Identity-bound deletion authority | A deletion protocol can remove exactly the authorized entry, or return without deleting when identity cannot be established atomically. | Anything merely by comparing a pathname and then calling a separate unlink operation. |

Actual-creation evidence must be recorded before or atomically with creation
exposure. A durable record written only after the process returns, or only in
the normal completion path, cannot prove creation when a crash occurs between
filesystem creation and history persistence.

Identity-bound deletion must close the check-to-remove interval. A comparison
of `lstat` or descriptor identity followed by `unlink`, `unlinkat`,
`remove_file`, or recursive directory removal is a pathname check-then-unlink
sequence and is unsafe under ADR-0030's same-user threat model.

## 5. Why changing `src/operation.rs` alone cannot establish the weakened boundary

`src/operation.rs` can provide richer observations at operation checkpoints. It
cannot independently supply the remaining requirements:

1. Durable persistence across process death is owned by standalone history,
   while the public Engine operation remains embeddable without SQLite.
2. A creation receipt must be committed around the filesystem operation so a
   restart can tell which Job and parent acquired which entry.
3. Recovery must coordinate a live owner, a dead owner, the history database,
   and any future deleter without relying on PID or elapsed time.
4. A qualified atomic removal protocol may require a platform adapter or
   broker outside the current pathname operation code.
5. The accepted same-user threat model is an architecture decision. Operation
   code cannot silently weaken it.

A future owner decision therefore needs to identify the failure being solved,
the participating processes, the crash-consistency protocol, and the exact
filesystem primitive or isolation boundary. Adding assertions around the
current cleanup function would leave the check-to-unlink race unresolved.

## 6. Decisions reserved for future owner authorization

This proposal makes no selection among these options. Each would require an
explicit owner decision and, where it changes accepted guarantees, an ADR
revision or new ADR.

### Option A: retain-only v1, followed by a separate reclamation design

Issue #12 accepts NDR-1 and performs no automatic artifact deletion. Automatic
reclamation moves to a follow-up issue. This is the smallest change and keeps
the current observed-only threat model intact.

### Option B: exclusive namespace or ownership broker

A future architecture creates reclaimable entries through a namespace whose
lifecycle is controlled by a broker or platform isolation boundary. The design
must prove that arbitrary same-user processes cannot replace the owned entry
between authorization and removal, and that broker crash and restart behavior
remain fail-closed. A cooperative lock file alone does not establish this
property.

### Option C: explicit threat-model revision

An owner may choose to accept that a noncooperating same-user process can cause
removal of a substituted entry under precisely documented conditions. The
revision must state the changed guarantee, affected platforms, user-facing
warning, recovery limits, and test obligations. This proposal does not make or
recommend that weakening.

### Option D: qualified identity-bound removal primitive

If a supported platform offers an operation that atomically removes only an
entry whose identity matches an opened parent and object, a future design may
qualify that primitive. The decision must also cover file and directory
semantics, hard links, open handles, filesystem support, and crash recovery.
No current pathname check plus unlink sequence qualifies.

## 7. Acceptance checks for the proposed criterion

These checks describe what a future implementation must demonstrate. This
document does not claim that they have been run for Issue #12.

1. A live owner keeps its Job nonterminal, while an abandoned owner's Job and
   active items transition once to `Interrupted`.
2. Lease acquisition failure, lease uncertainty, and concurrent recovery leave
   the record unchanged or produce one atomic transition without duplicates.
3. Injected Job or item write failure rolls back the recovery transition and
   leaves the persisted record available for another attempt.
4. A missing completion is shown as uncertain or unknown publication when no
   authoritative outcome exists, never as success.
5. Completion persistence failure preserves the authoritative execution result
   in the caller's output while the durable record remains nonterminal and
   reconcileable.
6. Retained, published-unresolved, and uncertain records remain outside normal
   pruning and retain their artifact evidence after restart.
7. `jobs clear` removes only allowlisted history rows and leaves all checked
   filesystem objects, including symlinks and substituted names, untouched.
8. No recovery, pruning, or clearing path invokes artifact unlinking, even when
   a record claims that an artifact is ordinarily disposable.
9. Planning-only entries never cause a file to be classified as created or
   removed.
10. Published destinations, source files, configuration, keys, caches,
    workspace roots, staging artifacts, backups, displaced entries, and
    uncertain entries survive interruption recovery and explicit history
    clearing.

## 8. Non-claims

This proposal does not:

1. Modify or reinterpret TAC-6 as published in the run prompt.
2. Claim that TAC-6 or any other acceptance criterion passes.
3. Authorize automatic cleanup or storage reclamation.
4. Change ADR-0030 or the accepted same-user Darwin threat model.
5. Claim crash durability, network-filesystem behavior, or atomic source
   snapshots beyond the qualified local Darwin boundary.
6. Establish that current candidate tests were rerun for this document.
