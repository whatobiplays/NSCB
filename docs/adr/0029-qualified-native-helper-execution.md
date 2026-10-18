# ADR-0029: Qualify native managed-helper execution with explicit resource guarantees

**Status:** Accepted — 2026-10-17  
**Scope:** Managed external helpers in NSCB v1, initially macOS arm64 Issue #7.  
**Related:** ADR-0002 (managed providers), ADR-0008 (embedded lifecycle), ADR-0014 (qualification), ADR-0021 (helper trust), Issue #2 (v1 specification), Issue #7 (managed helper providers).

## Context

NSCB delegates specialized content operations to qualified, pinned external executables while treating content and helper output as untrusted. ADR-0002 and ADR-0021 require an exact qualified executable, typed arguments without a shell, a controlled environment and working directory, and truthful output verification. They do not specify a non-bypassable 4 GiB aggregate memory cap, a virtual machine, or a general sandbox.

During Issue #7 implementation, a stricter proposed containment profile prevented all production provider-backed Inspection on the only artifact-qualified host, macOS arm64. A proposed `RLIMIT_AS` cap returned `EINVAL` on the qualification host. An investigation of `/usr/sbin/taskpolicy -m 4096 -P kill` found a directly enforced footprint limit but did not establish reliable inheritance or aggregate containment across descendants, protection against nested policy changes, or cleanup of a child escaping its process group. These observations **do not** qualify `taskpolicy` as a non-bypassable sandbox.

## Decision

1. **Native execution is the v1 baseline.** Launch the exact pinned, SHA-256-verified, capability-qualified helper executable directly by its absolute path with typed arguments. No shell, PATH resolution, arbitrary executable override, implicit privilege elevation, runtime EULA, VM, mandatory external service, or `taskpolicy` wrapper. Keep helper selection and provisioning behind the private managed-provider module and host-owned policies.

2. **Mandatory enforceable controls are specific and testable.** Before launch, require the security controls that the platform can actually enforce for this profile: verified provider identity; required key and input prerequisites; bounded process-admission concurrency; controlled environment/cwd/stdin and file access to the extent supported; bounded stdout/stderr capture and parsing; a wall-clock deadline and cancellation; and bounded termination/reaping attempts with sanitized typed failures. Enforce additional OS CPU, file-size, descriptor, or address-space limits **only where independently qualified on the native target**. An optional or unsupported OS limit is not silently represented as active. A failed **mandatory** control fails closed before helper execution. Containment-related prerequisites are assessed before opt-in download, installation, or network activity.

3. **Memory budgets are observational unless independently enforceable.** The macOS v1 profile does **not** require a non-bypassable hard 4 GiB virtual-memory, resident-memory, physical-footprint, or process-tree aggregate limit. Use supported process-memory telemetry with a documented, host-configurable threshold where available; observe at bounded intervals and request termination if sampled usage exceeds the threshold. Bound monitoring overhead and communicate whether monitoring was active. A sampled threshold cannot prevent all peak allocations, account for every escaping descendant, or promise an aggregate hard ceiling. If telemetry is unavailable, report that limitation without claiming a hard memory guarantee; a host that explicitly requires a stronger resource policy may refuse execution through its own configuration. Do not invent an enforceable limit by renaming `RLIMIT_AS` or substituting `taskpolicy`.

4. **Lifecycle guarantees must remain truthful.** Own the immediate child, cancel and reap it, attempt to terminate its known descendants/process group, and bound cleanup time. A privileged or compromised helper might fork, reparent, or create a new session and evade ordinary host-process cleanup. Do not label such cleanup as non-bypassable process-tree confinement. Preserve host lifecycle ownership and the runtime-neutral public Engine interface.

5. **Trust model is explicit.** Digest pinning and native operation qualification protect provider identity and integration correctness, but do not prove the helper is free of vulnerabilities. Native execution is **not a sandbox** against a malicious or compromised helper. It runs with the permissions granted by the host process and may read accessible data, including intentionally supplied keys; operational input/output protections and independent NSCB postconditions remain mandatory. Any future stronger isolation or aggregate-memory guarantee is a separately reviewed capability, not a prerequisite for ordinary v1 Inspection.

6. **No inferred qualification.** Native execution, provider artifact availability, per-operation adapter support, and release-platform support are separate claims. Issue #7's real end-to-end managed `Engine::inspect`/CLI operation must execute on a qualified native target using its actual production policy, with synthetic licensed input, mandatory keys, normalized positive facts, and independent Rust corroboration. Successful standalone NSTool execution, fake-adapter tests, or untested platform builds do not confer production qualification. Until that evidence exists, advertise the corresponding capability as unqualified.

## Testing and acceptance

- Exercise the public Rust Engine and CLI Inspection seam on the native host, not just a separately launched helper. Cover successful key-required Inspection, preflight and offline failure, exact executable digest, sanitized typed errors, host-owned cache/network policy, localized and JSON output, and original-input immutability.
- Test timeout, cancellation, output bounds, provider crash/nonzero exit, deliberate helper-output spoofing, cleanup, monitor-triggered termination, monitor unavailability, and failed mandatory control initialization with deterministic fixtures. Do not create unbounded stress tests.
- Record the exact resource controls proven active on each target. Label advisory memory monitoring as **best effort** and report process-escape limitations; do not claim hard aggregate containment without independent native evidence.
- Preserve prior Issue #6 Split contracts, existing public API and machine-output compatibility, authorization scope, and synthetic-fixture/proprietary-content restrictions.

## Consequences

This decision replaces the **Issue #7 implementation proposal**, not an existing ADR, to require non-bypassable 4 GiB aggregate memory isolation before any native provider could run. It retains the direct-execution architecture of ADR-0002 and the helper-trust requirements of ADR-0021. It knowingly accepts the documented risk of running a qualified native binary on the host. Virtualization or an isolation service remains an optional future architectural proposal and is **not** necessary for Issue #7.

Historical Delegation v3 manifests, results and recorded failed qualification evidence remain unchanged. Issue #7 requires a new correctly worktree-bound review/attestation against this amended policy before acceptance; the existing root-run claims are not retroactively approved.
