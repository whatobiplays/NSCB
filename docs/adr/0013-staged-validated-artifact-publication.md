# Stage and validate artifacts before publication

Mutating NSCB operations never modify source files in place and never destroy an existing destination before a replacement is complete. Final artifacts are built on the destination filesystem where practical, validated against operation-specific postconditions, and only then atomically promoted or replaced; helper exit success alone is insufficient, while planning revalidates input identity and destination/workspace safety immediately before mutation.
