//! The seam between an action invocation and the egress gate (SPEC §11.3).
//!
//! The runtime does not decide policy. After the guest returns it shows each
//! new intent to an [`IntentReview`]. With no reviewer attached, intents stay
//! pending exactly as M2 left them.

use aos_types::{Digest, FieldValue, ObjectId, Sensitivity, Taint};

#[derive(Clone, Debug)]
pub struct IntentView {
    pub id: ObjectId,
    pub channel: String,
    pub target: String,
    pub payload: FieldValue,
    pub payload_hash: Digest,
    pub cost_cents: u64,
    pub sensitivity: Sensitivity,
    pub target_taint: Taint,
    pub payload_taint: Taint,
    pub agent_summary: Option<String>,
    pub reversibility: String,
    pub on_main: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Review {
    Skip,
    Confirm { rule: String },
    Deny { rule: String },
    Allow { rule: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dispatch {
    pub ok: bool,
    pub detail: String,
    pub at_ms: i64,
}

pub trait IntentReview {
    fn review(&mut self, intent: &IntentView) -> Result<Review, String>;
    fn dispatch(&mut self, intent: &IntentView) -> Result<Dispatch, String>;
    /// The action transaction did not commit. Drop any spend reserved while
    /// reviewing; nothing was sent.
    fn commit_failed(&mut self) {}
}
