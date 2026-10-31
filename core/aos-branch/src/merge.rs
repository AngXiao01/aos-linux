//! Rebase and commit of a branch into `main` (SPEC §7.5).

use std::sync::Arc;

use aos_log::{Body, BranchName, BranchOp, LogStore, TxRecord};
use aos_types::{Actor, Object, ObjectId, TxId};

use crate::error::{Error, MergeConflict};
use crate::graph::{BranchData, BranchState, Graph, Snapshot, require_human};

/// Read access for precondition checks.
pub trait ReadView {
    /// Current state, tombstones included.
    fn read(&self, id: ObjectId) -> Option<Arc<Object>>;
    fn read_version(&self, id: ObjectId, version: u64) -> Option<Arc<Object>>;
}

pub struct View<'g, S> {
    graph: &'g Graph<S>,
    snapshot: Snapshot,
}

impl<S: LogStore> ReadView for View<'_, S> {
    fn read(&self, id: ObjectId) -> Option<Arc<Object>> {
        self.graph.lookup(&self.snapshot, id).cloned()
    }

    fn read_version(&self, id: ObjectId, version: u64) -> Option<Arc<Object>> {
        self.graph.lookup_version(&self.snapshot, id, version).cloned()
    }
}

/// Re-evaluates action preconditions at commit. Implemented by the action
/// runtime (M2), which knows each action's declaration.
pub trait Preconditions {
    /// Checks `tx` against `view`: the rebased state just before `tx`, i.e.
    /// `main`'s head plus the branch's earlier transactions.
    fn check(&self, view: &dyn ReadView, tx: &TxRecord) -> Result<(), String>;
}

/// For transactions without declared preconditions.
pub struct NoPreconditions;

impl Preconditions for NoPreconditions {
    fn check(&self, _: &dyn ReadView, _: &TxRecord) -> Result<(), String> {
        Ok(())
    }
}

impl<S: LogStore> Graph<S> {
    /// Objects the branch wrote that `main` also wrote after the branch's
    /// base.
    fn merge_conflicts(&self, b: &BranchData) -> Vec<MergeConflict> {
        let mut out: Vec<_> = b
            .overlay
            .keys()
            .filter_map(|&id| {
                let h = self.main.get(&id)?;
                h.changed_since(b.base).then(|| MergeConflict {
                    id,
                    base_version: h.at(b.base).map(|o| o.version),
                    main_version: h.last().map(|o| o.version),
                })
            })
            .collect();
        out.sort_by_key(|c| c.id);
        out
    }

    /// Moves the branch's base to `main`'s head, if no object it wrote has
    /// changed on `main` since its base.
    pub fn rebase(&mut self, name: &BranchName, actor: Actor) -> Result<(), Error> {
        let b = self.live_branch(name)?;
        let conflicts = self.merge_conflicts(b);
        if !conflicts.is_empty() {
            return Err(Error::Rejected { conflicts, preconditions: Vec::new() });
        }
        let base = self.log.len();
        self.append(vec![Body::Branch { branch: name.clone(), actor, op: BranchOp::Rebase { base } }])?;
        Ok(())
    }

    /// Commits a branch under review: checks conflicts against `main`,
    /// re-evaluates every transaction's preconditions on the rebased state,
    /// then appends the branch's transactions to `main` as one atomic group,
    /// each keeping its tx id so it can be reverted alone. On rejection the
    /// branch stays under review. Returns the seq of the commit record.
    pub fn merge(&mut self, name: &BranchName, actor: Actor, preconditions: &dyn Preconditions) -> Result<u64, Error> {
        require_human(&actor, "commit a branch")?;
        let b = self.branch(name)?;
        if b.state != BranchState::Submitted {
            return Err(Error::BadState { branch: name.clone(), state: b.state, op: "commit" });
        }
        let conflicts = self.merge_conflicts(b);
        let head = self.log.len();
        let mut failed: Vec<(TxId, String)> = Vec::new();
        for &seq in &b.txs {
            let tx = &self.txs[&seq];
            let view = View { graph: self, snapshot: Snapshot { branch: name.clone(), base: head, upto: seq } };
            if let Err(reason) = preconditions.check(&view, tx) {
                failed.push((tx.tx, reason));
            }
        }
        if !conflicts.is_empty() || !failed.is_empty() {
            return Err(Error::Rejected { conflicts, preconditions: failed });
        }
        let mut bodies: Vec<Body> = b
            .txs
            .iter()
            .map(|seq| {
                let mut copy = (*self.txs[seq]).clone();
                copy.branch = BranchName::main();
                copy.merged_from = Some(name.clone());
                Body::Tx(copy)
            })
            .collect();
        bodies.push(Body::Commit { branch: name.clone(), actor, txs: b.txs.len() as u64 });
        let seqs = self.append(bodies)?;
        Ok(*seqs.last().expect("commit record"))
    }
}
