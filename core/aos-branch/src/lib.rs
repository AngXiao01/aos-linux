//! The AOS object graph over the log: transactions, branches, diffs, commit
//! into `main`, and revert (SPEC §7).
//!
//! Everything here is rebuilt from the log on open; the log is the only
//! source of truth.

mod diff;
mod error;
mod graph;
mod history;
mod merge;
mod revert;
mod tx;

pub use diff::{Change, ChangeKind, Diff, TxSummary, TypeChanges};
pub use error::{Conflict, Error, MergeConflict, OpenError};
pub use graph::{BranchInfo, BranchState, Graph, Snapshot};
pub use merge::{NoPreconditions, Preconditions, ReadView, View};
pub use tx::{NewObject, Tx, TxMeta};
