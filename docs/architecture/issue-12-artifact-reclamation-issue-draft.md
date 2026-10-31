# Draft non-authoritative follow-up issue: automatic artifact reclamation

**Status:** Draft for review only. This is not a published GitHub issue, an
approved plan, or a change to Issue #12 acceptance criteria.

## Title

**Design and qualify race-safe automatic reclamation of owned NSCB Job artifacts**

## Context

Issue #12 adds durable standalone Job history around copy-through execution.
The current recovery-safe behavior is expected to preserve operation artifacts
for reconciliation and to avoid automatic filesystem deletion. That preserves
user data, but retained staging directories, files, backups, displaced entries,
uncertain entries, and advisory lock files can accumulate.

[ADR-0030](../adr/0030-darwin-copy-through-qualification.md) documents why a
straightforward cleanup sweep is not safe on the qualified Darwin boundary.
Darwin does not expose a pathname unlink operation that is conditional on the
identity observed immediately before removal. Checking a name and then calling
unlink creates an interval in which a noncooperating same-user process can
substitute another entry. Advisory locks coordinate NSCB participants only and
do not exclude arbitrary same-user processes.

The existing artifact inventory is useful reconciliation evidence. It records
roles, planned paths, observed identities, content evidence, and retention
state, but those observations do not by themselves prove actual creation by a
particular Job. `planned_artifacts` describes possible entries and is not
creation evidence.

## Goals

1. Establish durable actual-creation evidence for entries that a future
   reclamation feature may remove.
2. Define a deletion authorization protocol that cannot remove a substituted
   same-user entry between its identity check and removal.
3. Preserve published destinations, source files, user configuration, keys,
   caches, workspace roots, and foreign or modified content under every
   interruption and restart boundary.
4. Handle hard-link aliases and published inodes without charging or deleting
   the same content twice.
5. Recover safely after crashes before creation, during creation-record commit,
   during filesystem creation, during publication, during inventory, during
   reclamation, and during durable completion.
6. Produce deterministic machine-readable outcomes for reclaimed bytes,
   retained artifacts, skipped candidates, failures, and manual-reconciliation
   requirements.
7. Qualify behavior only on filesystems and platforms where every required
   filesystem primitive is documented and tested.

## Non-goals

1. Rework Issue #12 into an automatic cleanup implementation.
2. Delete or modify the original Issue #12 run prompt, run metadata, result, or
   acceptance criteria.
3. Treat pathname, filename prefix, PID, timestamp, age, or missing receipt as
   sufficient ownership evidence.
4. Sweep arbitrary directories or recurse through a user-selected workspace.
5. Remove published output, source content, displaced user content, uncertain
   entries, modified artifacts, symlinks, configuration, keys, caches, or
   database recovery files.
6. Weaken the same-user Darwin threat model as part of implementation. A
   threat-model change requires an explicit owner decision and ADR revision.
7. Implement batch execution, device workflows, or unrelated Job features.
8. Create or publish this issue as part of the documentation task that produced
   this draft.

## Required design decisions

The implementation plan must resolve these decisions before coding:

1. **Creation authority.** Which process records actual creation, at what point
   relative to namespace exposure, and how can a restart associate the entry
   with one Job and one parent identity?
2. **Removal authority.** Which filesystem primitive or isolated broker can
   remove exactly the authorized parent-directory entry and object, or fail
   without removal?
3. **Threat model.** If no identity-bound primitive is available, will the
   owner reject automatic reclamation or explicitly authorize a revised
   same-user threat model? The implementation cannot choose this silently.
4. **Scope of eligible artifacts.** Which roles may ever be reclaimed, and why
   are workspace roots, published destinations, displaced destination content,
   hard-link aliases shared with published output, and uncertain entries always
   excluded?
5. **Platform qualification.** Which filesystems and operating systems provide
   the required namespace, identity, hard-link, and crash semantics?
6. **Operator control.** Is the feature disabled by default, explicit per
   command, threshold-based, or automatic? Every mode must remain fail-closed.
7. **Privacy and evidence.** Which path, identity, content, and failure facts
   are durable and machine-readable without persisting copied bytes or secrets?

## Acceptance checks

1. A reclamation candidate has durable evidence that NSCB created a unique
   namespace entry for the recorded Job and parent directory. A merely planned
   path does not qualify.
2. The recorded creation evidence binds the Job, artifact role, parent device
   and inode, entry device and inode, creation phase, and relevant content
   expectations before a crash can strand the object.
3. Removal is atomic with respect to the authorized parent entry and expected
   object identity, or the candidate remains untouched. No pathname check
   followed by a separate unlink is accepted as identity-bound deletion.
4. A same-user rename, replacement, symlink substitution, hard-link creation,
   or parent-directory swap cannot cause reclamation of the replacement or an
   unrelated object.
5. A live NSCB owner is never reclaimed. Process absence, stale PID, record
   age, and path absence are not substitutes for a liveness proof.
6. Crash injection at every creation, history, inventory, reclamation, and
   completion boundary leaves either a truthful retained record or a
   deterministic reconciliation path. It never produces an untracked deletion.
7. Published destinations and inodes aliased by published destinations survive
   even when another retained role points at the same inode.
8. Workspace roots, source files, configuration, keys, caches, foreign files,
   modified files, symlinks, displaced entries, and uncertain artifacts remain
   byte-for-byte unchanged in all negative cases.
9. Reclamation reports exact bytes reclaimed, retained bytes whose total cannot
   be established, skipped candidates, failure categories, and manual actions
   without deleting evidence needed to reconcile them.
10. A failed reclamation leaves the Job history and every unproven artifact
    available for a later retry or inspection. It never converts the original
    Job outcome into a false success or failure.
11. Qualification evidence identifies the exact operating systems, filesystems,
    volume capabilities, process-isolation assumptions, and unsupported
    configurations. Unsupported platforms perform no automatic deletion.
12. An ADR records the chosen ownership and threat model before implementation
    is accepted. If the model is revised, the ADR states precisely which
    same-user adversary is now trusted and what user-visible risk remains.

## Explicit preservation and safety tests

The test suite must include real filesystem tests on each qualified platform.
Mocks may supplement those tests but cannot replace race and crash evidence.

### Identity and substitution tests

1. Replace the candidate with another regular file after its final pathname
   check. The replacement must survive and reclamation must remain fail-closed.
2. Rename the candidate away and install a symlink at the original name. The
   symlink and its target must survive.
3. Replace the parent directory name after a descriptor is opened. Reclamation
   must not follow the replacement pathname.
4. Remove and recreate the expected name with identical length and SHA-256. The
   new inode must not be removed.
5. Modify the recorded object before reclamation. The modified object and its
   last durable evidence must remain for reconciliation.
6. Exercise a hard-link alias shared with published output. No path may remove
   the published inode or report its bytes as reclaimed twice.

### Ownership and scope tests

1. A planned artifact with no actual-creation receipt is not reclaimed.
2. A receipt from another Job, parent, volume, or artifact role does not
   authorize removal.
3. A filename that matches NSCB's naming convention but lacks creation evidence
   is not reclaimed.
4. A workspace root, source, configuration file, key file, cache, published
   destination, displaced entry, or uncertain entry is never reclaimed.
5. An unknown future state or artifact role remains untouched by an older
   implementation.

### Liveness and concurrency tests

1. A live owner holding the Job lease prevents reclamation.
2. A dead owner becomes eligible only after the supported liveness mechanism
   distinguishes it from a concurrent live process.
3. Two concurrent reclaimers produce at most one successful removal and one
   consistent history result.
4. Lease acquisition errors, unsupported lock semantics, and uncertain owner
   state leave all candidates untouched.

### Crash and durability tests

1. Inject termination before creation, after creation but before the creation
   receipt commits, and after the receipt commits. Every restart state is
   truthful and no unproven entry is removed.
2. Inject termination before, during, and after the removal transaction. A
   retry reconciles the unknown outcome without deleting a replacement object.
3. Inject database failure before and after filesystem removal. History and disk
   state remain distinguishable, and failure does not fabricate success.
4. Exercise a corrupt, unavailable, or newer-schema history database. Automatic
   reclamation is disabled and artifacts remain present.
5. Reopen the database and artifacts after restart and verify that every
   preserved object's path, identity, content evidence, and retention reason
   remain inspectable.

### User-content preservation tests

1. A foreign file added to a workspace survives recovery and reclamation.
2. A user-modified staging-like file survives byte-for-byte.
3. A symlink inside a candidate directory is not followed or removed.
4. A published destination whose pathname changes after publication remains
   protected and its artifact evidence remains honest about the change.
5. A failed reclamation leaves a complete reconciliation report and does not
   alter the original Job's authoritative outcome.

## Expected deliverables

1. Owner-approved ADR for actual-creation evidence, removal authority, threat
   model, and platform qualification.
2. Revised architecture documentation defining the artifact lifecycle and
   reclamation state machine.
3. Implementation with fail-closed platform adapters and durable history
   integration.
4. Synthetic filesystem, crash-injection, concurrency, and preservation tests.
5. Qualification evidence for the exact supported platform and filesystem
   combinations.
6. User documentation and machine-output documentation for eligibility,
   retained storage, failures, and manual reconciliation.
