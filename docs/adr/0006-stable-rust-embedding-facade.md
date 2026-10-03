# Expose one stable Rust embedding facade

External Rust hosts integrate NSCB through one deliberately small semver-governed facade rather than importing internal workspace crates. The CLI/TUI, the first-party Flutter bridge, and hosts such as Argus consume the same application capabilities through outer adapters, allowing NSCB to restructure its internal domain, application, infrastructure, and runtime crates without turning those internals into compatibility commitments.
