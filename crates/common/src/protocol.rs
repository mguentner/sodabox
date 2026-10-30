//! Per-VM control socket protocol (ADR-0007): line-delimited JSON `Request` /
//! `Response` over `$XDG_RUNTIME_DIR/sodabox/<vm>/control.sock`. The
//! server side lives in the supervisor's control module.

use crate::policy::VmPolicy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Status,
    PolicyGet,
    PolicySet {
        policy: VmPolicy,
    },
    Allow {
        rule: String,
    },
    Deny {
        rule: String,
    },
    Stop,
    /// Begin streaming the live event feed (ADR-0009).
    Subscribe,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "resp", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Status { state: String, policy_version: u32 },
    Policy { policy: VmPolicy },
    Error { msg: String },
}
