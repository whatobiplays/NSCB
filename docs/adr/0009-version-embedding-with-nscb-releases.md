# Version the embedding facade with NSCB releases

One NSCB SemVer release governs the supported Rust embedding facade, CLI behavior, and immutable qualified-provider manifest. Independent Rust hosts such as Argus consume immutable released Git tags at exact versions rather than tracking `main` or a package registry, and run their own integration qualification before updating; NSCB tests its public facade independently rather than coupling release CI to another repository's moving branch.
