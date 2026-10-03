# Let embedding hosts own outer lifecycle and persistence

When NSCB is embedded, the host owns the outer job lifecycle, durable history, configuration, and product policy while NSCB owns planning, execution semantics, provider qualification, progress/events, cancellation behavior, and typed results. Embedded NSCB never silently opens standalone NSCB configuration or job state, and Argus-specific translation and admission policy live entirely in Argus.
