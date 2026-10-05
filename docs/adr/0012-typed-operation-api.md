# Use typed operation requests at the public Rust boundary

NSCB exposes strongly typed operation requests, plans, events, and results through its supported Rust facade rather than a generic command-name/JSON execution API. CLI, JSON/JSONL, Flutter, and other transport surfaces translate at their outer boundaries, while the Rust type system owns operation-specific validity and shared value types are introduced only where semantics genuinely overlap.
