# Use plan-first in-process jobs

Every mutating NSCB operation is resolved into an immutable Operation Plan before execution, and user-requested work runs as an in-process Job that emits structured progress and results. NSCB does not require a daemon; v1 interrupted jobs restart rather than resume, cancellation is cooperative with managed-process termination as a fallback, and automation never prompts for missing decisions or output conflicts.
