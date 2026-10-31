//! The AOS log: append-only, hash-chained, the single source of truth
//! (SPEC §7.1, §7.5, §7.7).

pub mod entry;
pub mod log;
pub mod store;

pub use entry::{Body, BranchName, BranchOp, Decoded, Entry, GENESIS, TxRecord, Write};
pub use log::{Anchor, Corruption, Log, OpenError, Recovery};
pub use store::{LogStore, MemoryStore};
