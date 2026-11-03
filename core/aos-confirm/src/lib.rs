//! Approval requests and the development confirmer (SPEC §12.3, §12.4, §12.7).
//!
//! Summary lines and previews are produced here, from the intent's own fields
//! and payload. `agent_summary` is copied through and marked as the agent's
//! words; it is never a summary line.

mod dev;
mod request;

use std::fmt;

pub use dev::{Approval, DEV_BANNER, DevConfirmer};
pub use request::{
    AGENT_SUMMARY_MARK, ApprovalRequest, ConfirmService, Item, PreviewInput, RequestInput, SUMMARY_LABELS, SummaryLine,
    approval_message, preview_of, sign_bytes, summary_of, trust_id, verify_bytes,
};

#[derive(Debug)]
pub enum Error {
    DebugOnly,
    Bad(String),
    BadKey,
    Signature,
    Decision,
    Io(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::DebugOnly => f.write_str("开发确认器只能在 debug 构建里启用"),
            Error::Bad(m) => write!(f, "{m}"),
            Error::BadKey => f.write_str("invalid signing key"),
            Error::Signature => f.write_str("signature rejected"),
            Error::Decision => f.write_str("decision must be approve or deny"),
            Error::Io(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}
