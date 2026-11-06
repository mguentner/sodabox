//! Shared types for sodabox, used across the CLI, supervisor, filter proxy and
//! DNS filter.
//!
//! Design references:
//!   - policy model      -> ADR-0006
//!   - event schema      -> ADR-0009
//!   - control protocol  -> ADR-0007

pub mod allowlist;
pub mod blocklist;
pub mod dotfiles;
pub mod event;
pub mod git;
pub mod paths;
pub mod policy;
pub mod profile;
pub mod protocol;
pub mod provider;
pub mod quota;
pub mod request;
pub mod ssh;
pub mod storage;
pub mod vm;
