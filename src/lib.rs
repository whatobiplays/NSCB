//! Runtime-neutral Rust facade for a read-only PFS0 Container Probe.
//!
//! The probe validates outer-container framing and reports structural facts.
//! It does not interpret embedded content, read payload bytes, or establish
//! content identity.

mod engine;
mod error;
mod pfs0;

pub use engine::{
    ContainerFormat, ContainerProbeEntry, ContainerProbeRequest, ContainerProbeResult, Engine,
};
pub use error::{ContainerProbeError, ContainerProbeErrorCode};
