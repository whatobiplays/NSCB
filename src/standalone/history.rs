//! Durable standalone Job history.
//!
//! This module compiles only into the `nscb` executable. The public Engine
//! library never opens the database, creates history directories, or depends
//! on a background process. A Job becomes visible only after immutable
//! planning succeeds and its admission transaction commits.

mod lease;
mod model;
mod storage;
mod store;
#[cfg(test)]
mod tests;

pub(crate) use lease::JobLease;
pub(crate) use model::*;
pub(crate) use store::{HistoryStore, PendingAdmission};

pub(crate) const CURRENT_SCHEMA_VERSION: i64 = 3;
pub(crate) const RETENTION_LIMIT: usize = 1_000;
const APPLICATION_ID: i64 = 0x4e53_4342;
const BUSY_TIMEOUT_MILLIS: u64 = 5_000;
