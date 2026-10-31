//! Revert (SPEC §7.6): a reverse transaction is appended; the log is never
//! rewritten.

use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;

use aos_log::{Body, BranchName, LogStore, TxRecord, Write};
use aos_types::{Actor, ObjRef, Object, TxId};

use crate::error::Error;
use crate::graph::{Graph, Snapshot};

impl<S: LogStore> Graph<S> {
    /// Reverts transaction `target` on `branch`, where it was applied (on
    /// `main` this includes transactions merged from branches).
    ///
    /// Each object the transaction wrote goes back to its previous version's
    /// content; objects it created become tombstones. Reverting is refused,
    /// listing the dependent transactions, if any later transaction wrote
    /// one of those objects. Reverting a revert redoes the original.
    pub fn revert(&mut self, branch: &BranchName, target: TxId, actor: Actor) -> Result<TxId, Error> {
        self.check_writable(branch, &actor)?;
        let seq = self
            .tx_locs
            .get(&target)
            .and_then(|locs| locs.iter().find(|(b, _)| b == branch))
            .map(|(_, seq)| *seq)
            .ok_or(Error::TxNotFound(target))?;
        let record = self.txs[&seq].clone();
        let head = self.snapshot(branch)?;
        if self.is_reverted(&head, target) {
            return Err(Error::AlreadyReverted(target));
        }

        let mut dependents = BTreeSet::new();
        for w in &record.writes {
            for later in self.visible_versions(&head, w.id()).into_iter().filter(|o| o.version > w.new_version()) {
                dependents.insert(later.provenance.tx);
            }
        }
        if !dependents.is_empty() {
            return Err(Error::Dependents(dependents.into_iter().collect()));
        }

        let id = TxId(self.new_id());
        let writes = record
            .writes
            .iter()
            .map(|w| {
                let current = self.lookup(&head, w.id()).expect("written objects are visible");
                let mut restored = match w.prev_version {
                    None => Object { tombstone: true, ..(**current).clone() },
                    Some(p) => (**self.lookup_version(&head, w.id(), p).expect("earlier versions are visible")).clone(),
                };
                restored.version = current.version + 1;
                restored.provenance.actor = actor.clone();
                restored.provenance.tx = id;
                Write { prev_version: Some(current.version), object: Arc::new(restored) }
            })
            .collect();
        let reverse = TxRecord {
            branch: branch.clone(),
            tx: id,
            actor,
            capability: None,
            action: None,
            inputs: Default::default(),
            writes,
            intents: Vec::new(),
            revert_of: Some(target),
            merged_from: None,
        };
        self.append(vec![Body::Tx(reverse)])?;
        Ok(id)
    }

    /// Whether `tx` is reverted as seen from `snap`: some visible revert of
    /// it is not itself reverted.
    pub(crate) fn is_reverted(&self, snap: &Snapshot, tx: TxId) -> bool {
        self.reverts_of.get(&tx).is_some_and(|reverts| {
            reverts.iter().any(|(b, seq, r)| self.visible(snap, b, *seq) && !self.is_reverted(snap, *r))
        })
    }

    fn visible(&self, snap: &Snapshot, branch: &BranchName, seq: u64) -> bool {
        if *branch == snap.branch { seq < snap.upto } else { branch.is_main() && seq < snap.base }
    }

    pub fn is_tx_reverted(&self, branch: &BranchName, tx: TxId) -> Result<bool, Error> {
        Ok(self.is_reverted(&self.snapshot(branch)?, tx))
    }

    /// Whether `object` was written by a reverted transaction or derives,
    /// directly or through `derived_from`, from a version that was: "基于已撤销
    /// 版本" (SPEC §7.6). Computed on demand, not stored.
    pub fn is_stale(&self, branch: &BranchName, object: &Object) -> Result<bool, Error> {
        let snap = self.snapshot(branch)?;
        if self.is_reverted(&snap, object.provenance.tx) {
            return Ok(true);
        }
        let mut seen: HashSet<ObjRef> = HashSet::new();
        let mut stack: Vec<ObjRef> = object.provenance.derived_from.iter().copied().collect();
        while let Some(r) = stack.pop() {
            if !seen.insert(r) {
                continue;
            }
            let Some(source) = r.version.and_then(|v| self.lookup_version(&snap, r.id, v)) else { continue };
            if self.is_reverted(&snap, source.provenance.tx) {
                return Ok(true);
            }
            stack.extend(source.provenance.derived_from.iter().copied());
        }
        Ok(false)
    }
}
