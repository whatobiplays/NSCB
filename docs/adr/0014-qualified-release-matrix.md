# Qualify releases against pinned toolchains and native target evidence

NSCB development, CI, and releases use an exact pinned Rust toolchain with a separately declared MSRV and a committed lockfile; unsafe code is denied by default and isolated behind narrow reviewed adapters only when unavoidable. A helper enters the immutable provider manifest only after its exact version is qualified for each claimed capability and v1 target, and official releases require native execution evidence where platform-specific behavior matters across macOS arm64, Windows x86_64, Linux x86_64, and Linux arm64.
