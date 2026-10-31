//! Diffs: what a branch changes relative to its base (SPEC §7.4). This is the
//! generic part; provider-specific summaries (e.g. dataset member tables)
//! build on [`Graph::changes`].

use std::collections::BTreeMap;

use aos_log::{BranchName, LogStore};
use aos_types::cbor::Value;
use aos_types::codec::record;
use aos_types::{Actor, Digest, Object, ObjectId, ToCbor, TxId, TypeRef};

use crate::error::Error;
use crate::graph::Graph;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChangeKind {
    Created,
    Updated,
    Deleted,
}

/// The net change to one object between the base and the branch head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub id: ObjectId,
    pub type_ref: TypeRef,
    pub kind: ChangeKind,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TypeChanges {
    pub created: u64,
    pub updated: u64,
    pub deleted: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxSummary {
    pub tx: TxId,
    pub actor: Actor,
    pub action: Option<String>,
    pub writes: usize,
    pub revert_of: Option<TxId>,
    pub reverted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diff {
    pub branch: BranchName,
    pub base: u64,
    /// Identifies exactly this state of the branch; bound into approval
    /// requests as `diff_hash` (SPEC §12.3).
    pub digest: Digest,
    pub txs: Vec<TxSummary>,
    /// Egress intents created on the branch and still live.
    pub intents: Vec<ObjectId>,
    pub by_type: BTreeMap<TypeRef, TypeChanges>,
}

/// Content as a reader sees it; versions and provenance do not count.
fn same_content(a: &Object, b: &Object) -> bool {
    a.type_ref == b.type_ref && a.fields == b.fields && a.extra == b.extra && a.sensitivity == b.sensitivity
}

impl<S: LogStore> Graph<S> {
    /// Net changes, sorted by object id. An object created and then deleted
    /// on the branch, or edited back to its base content, is not a change.
    pub fn changes(&self, branch: &BranchName) -> Result<Vec<Change>, Error> {
        if branch.is_main() {
            return Err(Error::Invalid("main has no diff".into()));
        }
        let b = self.live_branch(branch)?;
        let mut out: Vec<Change> = b
            .overlay
            .iter()
            .filter_map(|(&id, h)| {
                let head = h.last()?;
                let base = self.main.get(&id).and_then(|m| m.at(b.base)).filter(|o| !o.tombstone);
                let kind = match (base, head.tombstone) {
                    (None, false) => ChangeKind::Created,
                    (Some(_), true) => ChangeKind::Deleted,
                    (Some(base), false) if !same_content(base, head) => ChangeKind::Updated,
                    _ => return None,
                };
                Some(Change { id, type_ref: head.type_ref.clone(), kind })
            })
            .collect();
        out.sort_unstable_by_key(|c| c.id);
        Ok(out)
    }

    /// One page of changes, optionally of one type and kind, after `after`.
    pub fn changes_page(
        &self,
        branch: &BranchName,
        filter: Option<(&TypeRef, ChangeKind)>,
        after: Option<ObjectId>,
        limit: usize,
    ) -> Result<Vec<Change>, Error> {
        Ok(self
            .changes(branch)?
            .into_iter()
            .filter(|c| after.is_none_or(|a| c.id > a))
            .filter(|c| filter.is_none_or(|(t, k)| c.type_ref == *t && c.kind == k))
            .take(limit)
            .collect())
    }

    pub fn diff(&self, branch: &BranchName) -> Result<Diff, Error> {
        let changes = self.changes(branch)?;
        let b = self.live_branch(branch)?;
        let head = self.snapshot(branch)?;
        let mut by_type: BTreeMap<TypeRef, TypeChanges> = BTreeMap::new();
        for c in &changes {
            let t = by_type.entry(c.type_ref.clone()).or_default();
            match c.kind {
                ChangeKind::Created => t.created += 1,
                ChangeKind::Updated => t.updated += 1,
                ChangeKind::Deleted => t.deleted += 1,
            }
        }
        let mut txs = Vec::with_capacity(b.txs.len());
        let mut intents = Vec::new();
        for seq in &b.txs {
            let rec = &self.txs[seq];
            txs.push(TxSummary {
                tx: rec.tx,
                actor: rec.actor.clone(),
                action: rec.action.clone(),
                writes: rec.writes.len(),
                revert_of: rec.revert_of,
                reverted: self.is_reverted(&head, rec.tx),
            });
            for &i in &rec.intents {
                let live = self.lookup(&head, i).is_some_and(|o| !o.tombstone);
                if live && !intents.contains(&i) {
                    intents.push(i);
                }
            }
        }
        let digest = Digest::of_value(&record([
            ("branch", Value::from(branch.as_str())),
            ("base", Value::Unsigned(b.base)),
            ("head", b.last_hash.to_cbor()),
        ]));
        Ok(Diff { branch: branch.clone(), base: b.base, digest, txs, intents, by_type })
    }
}
