# Separate semantic events from latest-value progress

NSCB execution exposes lossless ordered semantic events for stage transitions, warnings, failures, cancellation transitions, and terminal results, while high-frequency progress is authoritative latest-value state rather than a queued event stream. Every semantic event carries an execution-local monotonically increasing sequence number. Slow or disconnected consumers never backpressure execution; hosts reconcile from the Execution Handle's authoritative current state/result rather than relying on an NSCB replay log.

The Engine promises one logical host event consumer per execution. Hosts that need multiple subscribers, replay, or persistence own that fanout/history themselves. This keeps event delivery aligned with host-owned lifecycle and persistence rather than introducing a hidden broadcast or durable event subsystem inside NSCB.
