# Separate semantic events from latest-value progress

NSCB execution exposes lossless ordered semantic events for stage transitions, warnings, failures, cancellation transitions, and terminal results, while high-frequency progress is authoritative latest-value state rather than a queued event stream. Slow or disconnected consumers never backpressure execution; hosts can reconcile from the Execution Handle's current state without requiring NSCB to implement complex progress-event coalescing queues.
