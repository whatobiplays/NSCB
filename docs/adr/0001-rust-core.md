# Use Rust for the authoritative NSCB core

NSCB will use Rust for its authoritative domain/application core, CLI, TUI, jobs, and frontend-neutral APIs. Rust was selected over Go, Python, Dart, and C++ because NSCB prioritizes correctness and safety in binary/cryptographic workflows, maintainability and testability, native macOS/Linux distribution, predictable large-file streaming and process control, and a clean future C-compatible boundary for Flutter; the greenfield rewrite also removes Python's main advantage of incremental reuse.
