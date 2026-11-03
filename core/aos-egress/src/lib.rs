//! Egress intents, policy, and the gate (SPEC §11).
//!
//! `Transport` is the only way bytes leave. The gate calls it after a
//! standing rule allows the intent, or after a one-time approval whose
//! payload hash still matches. Confirm-class intents on a task branch stay
//! pending until [`Gate::release`].

mod gate;
mod transport;

use std::fmt;

pub use gate::{Gate, ReleaseItem, binding_hash, settle};
pub use transport::{Outbound, Recorded, RecordingTransport, Transport};

#[derive(Debug)]
pub enum Error {
    Policy(String),
    Confirm(String),
    Expired,
    Replay,
    Mismatch(String),
    Bad(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Policy(m) | Error::Confirm(m) | Error::Mismatch(m) | Error::Bad(m) => write!(f, "{m}"),
            Error::Expired => f.write_str("approval expired"),
            Error::Replay => f.write_str("approval already used"),
        }
    }
}

impl std::error::Error for Error {}
