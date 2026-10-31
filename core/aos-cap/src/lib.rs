//! Capability tokens (SPEC §9.1).
//!
//! A token is an immutable grant signed by the capability service. Spending
//! does not re-sign it; the service keeps the remaining quota. Agents have
//! no way to produce a signature the service will accept.

mod pattern;
mod service;
mod token;

pub use pattern::{channel_covers, channel_within, parse_channel, parse_right, right_covers, right_within};
pub use service::{CapabilityService, Cost, IssueRequest};
pub use token::{Capability, Limits};
