# Keep the embedded engine runtime-neutral and host-configured

The supported NSCB embedding facade does not require callers to adopt Tokio or standalone NSCB filesystem state. A reusable NSCB engine owns the executor resources needed by its implementation and is constructed from explicit host-provided key, workspace, tool-provisioning, storage, and related capabilities; planning and execution require no NSCB SQLite database, and hosts observe work through typed execution handles with events, completion, and cancellation.
