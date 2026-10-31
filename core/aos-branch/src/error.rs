use std::fmt;
use std::io;

use aos_log::BranchName;
use aos_types::{Actor, ObjectId, TxId};

use crate::graph::BranchState;

/// A transaction read or wrote an object that changed on its branch since
/// the transaction's snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conflict {
    pub id: ObjectId,
    /// Version the transaction saw (`None`: absent).
    pub expected: Option<u64>,
    pub found: Option<u64>,
}

/// An object both the branch and `main` wrote after the branch's base
/// (SPEC §7.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeConflict {
    pub id: ObjectId,
    pub base_version: Option<u64>,
    pub main_version: Option<u64>,
}

#[derive(Debug)]
pub enum Error {
    NoSuchBranch(BranchName),
    BranchExists(BranchName),
    BadState {
        branch: BranchName,
        state: BranchState,
        op: &'static str,
    },
    NotPermitted {
        actor: Actor,
        op: &'static str,
    },
    Conflict(Vec<Conflict>),
    /// A transaction must write at least one object.
    Empty,
    NotFound(ObjectId),
    Deleted(ObjectId),
    Invalid(String),
    TxNotFound(TxId),
    AlreadyReverted(TxId),
    /// Later transactions wrote objects of the one being reverted
    /// (SPEC §7.6). Revert those first.
    Dependents(Vec<TxId>),
    /// The branch stays under review with these reasons (SPEC §7.5).
    Rejected {
        conflicts: Vec<MergeConflict>,
        preconditions: Vec<(TxId, String)>,
    },
    Io(io::Error),
    /// The in-memory state disagrees with the log; a bug.
    Internal(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoSuchBranch(b) => write!(f, "no open branch {b}"),
            Error::BranchExists(b) => write!(f, "branch {b} already exists"),
            Error::BadState { branch, state, op } => write!(f, "cannot {op} branch {branch} in state {state:?}"),
            Error::NotPermitted { actor, op } => write!(f, "{actor} may not {op}"),
            Error::Conflict(c) => write!(f, "{} conflicting objects", c.len()),
            Error::Empty => f.write_str("transaction writes nothing"),
            Error::NotFound(id) => write!(f, "object {id} not found"),
            Error::Deleted(id) => write!(f, "object {id} is deleted"),
            Error::Invalid(m) => write!(f, "invalid: {m}"),
            Error::TxNotFound(t) => write!(f, "transaction {t} not on this branch"),
            Error::AlreadyReverted(t) => write!(f, "transaction {t} is already reverted"),
            Error::Dependents(ts) => write!(f, "{} later transactions depend on it", ts.len()),
            Error::Rejected { conflicts, preconditions } => {
                write!(f, "rejected: {} conflicts, {} failed preconditions", conflicts.len(), preconditions.len())
            }
            Error::Io(e) => write!(f, "log I/O: {e}"),
            Error::Internal(m) => write!(f, "internal: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

#[derive(Debug)]
pub enum OpenError {
    Log(aos_log::OpenError),
    /// The log verified but does not describe a valid history.
    Inconsistent {
        seq: u64,
        reason: String,
    },
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::Log(e) => e.fmt(f),
            OpenError::Inconsistent { seq, reason } => write!(f, "log entry {seq} is inconsistent: {reason}"),
        }
    }
}

impl std::error::Error for OpenError {}

impl From<aos_log::OpenError> for OpenError {
    fn from(e: aos_log::OpenError) -> Self {
        OpenError::Log(e)
    }
}
