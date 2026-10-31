//! The object graph: an in-memory index over the log, rebuilt by replaying
//! it (SPEC §7, §A7).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aos_log::{Anchor, Body, BranchName, BranchOp, Entry, Log, LogStore, Recovery, TxRecord};
use aos_types::ulid::{Clock, Entropy, UlidGenerator};
use aos_types::{Actor, Digest, Object, ObjectId, Timestamp, TxId, Ulid};

use crate::error::{Error, OpenError};
use crate::history::History;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BranchState {
    /// The agent is working on it.
    Open,
    /// Waiting for human review; only the user may still edit it.
    Submitted,
    Committed,
    Discarded,
}

pub(crate) struct BranchData {
    /// `main` entries with `seq < base` are visible on the branch.
    pub base: u64,
    pub state: BranchState,
    /// The branch's own writes, layered over `main` at `base`.
    pub overlay: HashMap<ObjectId, History>,
    /// Seqs of the branch's own transactions, in order.
    pub txs: Vec<u64>,
    /// Hash of the latest entry concerning this branch.
    pub last_hash: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchInfo {
    pub name: BranchName,
    pub state: BranchState,
    pub base: u64,
    pub txs: usize,
}

/// A consistent read position: `main` entries with `seq < base`, plus the
/// branch's own entries with `seq < upto`. On `main`, `base == upto`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub branch: BranchName,
    pub base: u64,
    pub upto: u64,
}

struct Ids {
    generator: UlidGenerator,
    entropy: Box<dyn Entropy + Send>,
}

pub struct Graph<S> {
    pub(crate) log: Log<S>,
    clock: Box<dyn Clock + Send>,
    ids: Mutex<Ids>,
    pub(crate) main: HashMap<ObjectId, History>,
    pub(crate) branches: HashMap<BranchName, BranchData>,
    /// Every transaction entry, by seq.
    pub(crate) txs: HashMap<u64, Arc<TxRecord>>,
    /// Where each transaction was applied. A committed branch transaction
    /// appears twice: on the branch and as its copy on `main`.
    pub(crate) tx_locs: HashMap<TxId, Vec<(BranchName, u64)>>,
    /// Reverse transactions targeting each transaction: (branch, seq, id).
    pub(crate) reverts_of: HashMap<TxId, Vec<(BranchName, u64, TxId)>>,
}

impl<S: LogStore> Graph<S> {
    /// Opens the log (verifying it, and rolling back an unfinished commit)
    /// and rebuilds the index by replaying every entry.
    pub fn open(
        store: S,
        anchor: Option<Anchor>,
        clock: Box<dyn Clock + Send>,
        entropy: Box<dyn Entropy + Send>,
    ) -> Result<(Self, Recovery), OpenError> {
        let (log, recovery, entries) = Log::open_with_entries(store, anchor)?;
        let mut graph = Graph {
            log,
            clock,
            ids: Mutex::new(Ids { generator: UlidGenerator::new(), entropy }),
            main: HashMap::new(),
            branches: HashMap::new(),
            txs: HashMap::new(),
            tx_locs: HashMap::new(),
            reverts_of: HashMap::new(),
        };
        for entry in entries {
            let seq = entry.seq;
            graph.apply(entry).map_err(|reason| OpenError::Inconsistent { seq, reason })?;
        }
        Ok((graph, recovery))
    }

    pub fn anchor(&self) -> Anchor {
        self.log.anchor()
    }

    pub fn log(&self) -> &Log<S> {
        &self.log
    }

    pub fn into_store(self) -> S {
        self.log.into_store()
    }

    pub fn new_id(&self) -> Ulid {
        let mut ids = self.ids.lock().unwrap_or_else(|e| e.into_inner());
        let Ids { generator, entropy } = &mut *ids;
        generator.next(&*self.clock, &mut **entropy).expect("clock within ULID range")
    }

    fn now(&self) -> Timestamp {
        Timestamp::from_unix_ms(self.clock.now_ms() as i64).expect("clock within timestamp range")
    }

    // ---- branches -------------------------------------------------------

    pub fn branch_info(&self, name: &BranchName) -> Option<BranchInfo> {
        self.branches.get(name).map(|b| BranchInfo {
            name: name.clone(),
            state: b.state,
            base: b.base,
            txs: b.txs.len(),
        })
    }

    pub fn branches(&self) -> Vec<BranchInfo> {
        let mut out: Vec<_> = self.branches.keys().filter_map(|n| self.branch_info(n)).collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Forks `name` from the current head of `main`. O(1): nothing is
    /// copied; reads fall through to `main` at the fork point.
    pub fn fork(&mut self, name: &BranchName, actor: Actor) -> Result<Snapshot, Error> {
        if name.is_main() || self.branches.contains_key(name) {
            return Err(Error::BranchExists(name.clone()));
        }
        let base = self.log.len();
        self.append(vec![Body::Branch { branch: name.clone(), actor, op: BranchOp::Fork { base } }])?;
        self.snapshot(name)
    }

    /// Sends the branch for review.
    pub fn submit(&mut self, name: &BranchName, actor: Actor) -> Result<(), Error> {
        self.transition(name, actor, BranchOp::Submit, &[BranchState::Open], false)
    }

    /// Returns a branch under review to the agent.
    pub fn reopen(&mut self, name: &BranchName, actor: Actor) -> Result<(), Error> {
        self.transition(name, actor, BranchOp::Reopen, &[BranchState::Submitted], true)
    }

    pub fn discard(&mut self, name: &BranchName, actor: Actor) -> Result<(), Error> {
        self.transition(name, actor, BranchOp::Discard, &[BranchState::Open, BranchState::Submitted], true)
    }

    fn transition(
        &mut self,
        name: &BranchName,
        actor: Actor,
        op: BranchOp,
        from: &[BranchState],
        human_only: bool,
    ) -> Result<(), Error> {
        let state = self.branch(name)?.state;
        if !from.contains(&state) {
            return Err(Error::BadState { branch: name.clone(), state, op: op_name(&op) });
        }
        if human_only {
            require_human(&actor, op_name(&op))?;
        }
        self.append(vec![Body::Branch { branch: name.clone(), actor, op }])?;
        Ok(())
    }

    pub(crate) fn branch(&self, name: &BranchName) -> Result<&BranchData, Error> {
        self.branches.get(name).ok_or_else(|| Error::NoSuchBranch(name.clone()))
    }

    /// Branches that can still be read: open or under review.
    pub(crate) fn live_branch(&self, name: &BranchName) -> Result<&BranchData, Error> {
        let b = self.branch(name)?;
        match b.state {
            BranchState::Open | BranchState::Submitted => Ok(b),
            state => Err(Error::BadState { branch: name.clone(), state, op: "read" }),
        }
    }

    /// Agents never write `main` (SPEC §7.3); a branch under review accepts
    /// only the user's edits.
    pub(crate) fn check_writable(&self, branch: &BranchName, actor: &Actor) -> Result<(), Error> {
        if branch.is_main() {
            if matches!(actor, Actor::AgentTask(_)) {
                return Err(Error::NotPermitted { actor: actor.clone(), op: "write to main" });
            }
            return Ok(());
        }
        match self.branch(branch)?.state {
            BranchState::Open => Ok(()),
            BranchState::Submitted if *actor == Actor::User => Ok(()),
            state => Err(Error::BadState { branch: branch.clone(), state, op: "write" }),
        }
    }

    // ---- reads ----------------------------------------------------------

    pub fn snapshot(&self, branch: &BranchName) -> Result<Snapshot, Error> {
        let upto = self.log.len();
        if branch.is_main() {
            return Ok(Snapshot { branch: branch.clone(), base: upto, upto });
        }
        let b = self.live_branch(branch)?;
        Ok(Snapshot { branch: branch.clone(), base: b.base, upto })
    }

    /// The object as of `snap`, tombstones included.
    pub(crate) fn lookup(&self, snap: &Snapshot, id: ObjectId) -> Option<&Arc<Object>> {
        if !snap.branch.is_main()
            && let Some(o) = self.overlay(snap, id).and_then(|h| h.at(snap.upto))
        {
            return Some(o);
        }
        self.main.get(&id).and_then(|h| h.at(snap.base))
    }

    /// Version `version` of the object, if visible in `snap`.
    pub(crate) fn lookup_version(&self, snap: &Snapshot, id: ObjectId, version: u64) -> Option<&Arc<Object>> {
        self.main
            .get(&id)
            .and_then(|h| h.version(version, snap.base))
            .or_else(|| self.overlay(snap, id).and_then(|h| h.version(version, snap.upto)))
    }

    /// All versions visible in `snap`, oldest first.
    pub(crate) fn visible_versions(&self, snap: &Snapshot, id: ObjectId) -> Vec<&Arc<Object>> {
        let mut out: Vec<_> = self.main.get(&id).map(|h| h.upto(snap.base).collect()).unwrap_or_default();
        if let Some(h) = self.overlay(snap, id) {
            out.extend(h.upto(snap.upto));
        }
        out
    }

    fn overlay(&self, snap: &Snapshot, id: ObjectId) -> Option<&History> {
        if snap.branch.is_main() {
            return None;
        }
        self.branches.get(&snap.branch).and_then(|b| b.overlay.get(&id))
    }

    /// The current state of an object on a branch, tombstones included.
    pub fn read(&self, branch: &BranchName, id: ObjectId) -> Result<Option<Arc<Object>>, Error> {
        let snap = self.snapshot(branch)?;
        Ok(self.lookup(&snap, id).cloned())
    }

    /// The object as of an earlier snapshot of the same branch.
    pub fn read_at(&self, snap: &Snapshot, id: ObjectId) -> Result<Option<Arc<Object>>, Error> {
        if !snap.branch.is_main() {
            self.live_branch(&snap.branch)?;
        }
        Ok(self.lookup(snap, id).cloned())
    }

    pub fn read_version(&self, branch: &BranchName, id: ObjectId, version: u64) -> Result<Option<Arc<Object>>, Error> {
        let snap = self.snapshot(branch)?;
        Ok(self.lookup_version(&snap, id, version).cloned())
    }

    /// Every visible version of the object, oldest first (SPEC §13.2 "版本历史").
    pub fn history(&self, branch: &BranchName, id: ObjectId) -> Result<Vec<Arc<Object>>, Error> {
        let snap = self.snapshot(branch)?;
        Ok(self.visible_versions(&snap, id).into_iter().cloned().collect())
    }

    /// Ids of all objects ever written on `main`.
    pub fn main_ids(&self) -> impl Iterator<Item = ObjectId> + '_ {
        self.main.keys().copied()
    }

    // ---- writing the log ------------------------------------------------

    /// Appends entries and applies them. Callers validate first, so applying
    /// cannot fail unless there is a bug.
    /// Returns the seqs of the appended entries.
    pub(crate) fn append(&mut self, bodies: Vec<Body>) -> Result<Vec<u64>, Error> {
        let entries = self.log.append(self.now(), bodies)?;
        let seqs = entries.iter().map(|e| e.seq).collect();
        for e in entries {
            self.apply(e).map_err(Error::Internal)?;
        }
        Ok(seqs)
    }

    /// Applies one verified entry. Shared by live writes and replay, so a
    /// reopened graph is identical to the one that wrote the log.
    fn apply(&mut self, entry: Entry) -> Result<(), String> {
        let seq = entry.seq;
        let hash = self.log.hash_of(seq).ok_or("entry beyond log")?;
        match &entry.body {
            Body::Tx(_) => {
                let Body::Tx(rec) = entry.body else { unreachable!() };
                self.apply_tx(seq, hash, rec)
            }
            Body::Branch { branch, op, .. } => {
                if let BranchOp::Fork { base } = op {
                    if branch.is_main() || self.branches.contains_key(branch) || *base > seq {
                        return Err(format!("bad fork of {branch}"));
                    }
                    let data = BranchData {
                        base: *base,
                        state: BranchState::Open,
                        overlay: HashMap::new(),
                        txs: Vec::new(),
                        last_hash: hash,
                    };
                    self.branches.insert(branch.clone(), data);
                    return Ok(());
                }
                let b = self.branches.get_mut(branch).ok_or_else(|| format!("unknown branch {branch}"))?;
                let (from, to): (&[BranchState], _) = match op {
                    BranchOp::Rebase { base } => {
                        if *base > seq || *base < b.base {
                            return Err("bad rebase".into());
                        }
                        b.base = *base;
                        (&[BranchState::Open, BranchState::Submitted], b.state)
                    }
                    BranchOp::Submit => (&[BranchState::Open], BranchState::Submitted),
                    BranchOp::Reopen => (&[BranchState::Submitted], BranchState::Open),
                    BranchOp::Discard => (&[BranchState::Open, BranchState::Submitted], BranchState::Discarded),
                    BranchOp::Fork { .. } => unreachable!("handled above"),
                };
                if !from.contains(&b.state) {
                    return Err(format!("{} in state {:?}", op_name(op), b.state));
                }
                b.state = to;
                b.last_hash = hash;
                if to == BranchState::Discarded {
                    b.overlay = HashMap::new();
                }
                Ok(())
            }
            Body::Commit { branch, .. } => {
                let b = self.branches.get_mut(branch).ok_or_else(|| format!("unknown branch {branch}"))?;
                if b.state != BranchState::Submitted {
                    return Err(format!("commit in state {:?}", b.state));
                }
                b.state = BranchState::Committed;
                b.last_hash = hash;
                b.overlay = HashMap::new();
                Ok(())
            }
        }
    }

    fn apply_tx(&mut self, seq: u64, hash: Digest, rec: TxRecord) -> Result<(), String> {
        rec.check().map_err(|e| e.to_string())?;
        // Check every write against the current version before changing
        // anything, so a bad entry leaves the index untouched.
        if rec.branch.is_main() {
            for w in &rec.writes {
                let current = self.main.get(&w.id()).and_then(History::last).map(|o| o.version);
                if current != w.prev_version {
                    return Err(format!("{}: index at {current:?}, log expects {:?}", w.id(), w.prev_version));
                }
            }
            for w in &rec.writes {
                self.main.entry(w.id()).or_default().push(seq, w.object.clone());
            }
        } else {
            let b = self.branches.get(&rec.branch).ok_or_else(|| format!("unknown branch {}", rec.branch))?;
            if !matches!(b.state, BranchState::Open | BranchState::Submitted) {
                return Err(format!("write to branch in state {:?}", b.state));
            }
            for w in &rec.writes {
                let current = b
                    .overlay
                    .get(&w.id())
                    .and_then(History::last)
                    .or_else(|| self.main.get(&w.id()).and_then(|h| h.at(b.base)))
                    .map(|o| o.version);
                if current != w.prev_version {
                    return Err(format!("{}: branch at {current:?}, log expects {:?}", w.id(), w.prev_version));
                }
            }
            let b = self.branches.get_mut(&rec.branch).expect("checked above");
            for w in &rec.writes {
                b.overlay.entry(w.id()).or_default().push(seq, w.object.clone());
            }
            b.txs.push(seq);
            b.last_hash = hash;
        }
        let rec = Arc::new(rec);
        self.tx_locs.entry(rec.tx).or_default().push((rec.branch.clone(), seq));
        if let Some(target) = rec.revert_of {
            self.reverts_of.entry(target).or_default().push((rec.branch.clone(), seq, rec.tx));
        }
        self.txs.insert(seq, rec);
        Ok(())
    }
}

/// Merging, reopening and discarding are human decisions (SPEC §13.2);
/// `system` acts for the user in automated flows such as budget exhaustion.
pub(crate) fn require_human(actor: &Actor, op: &'static str) -> Result<(), Error> {
    match actor {
        Actor::User | Actor::System => Ok(()),
        _ => Err(Error::NotPermitted { actor: actor.clone(), op }),
    }
}

fn op_name(op: &BranchOp) -> &'static str {
    match op {
        BranchOp::Fork { .. } => "fork",
        BranchOp::Rebase { .. } => "rebase",
        BranchOp::Submit => "submit",
        BranchOp::Reopen => "reopen",
        BranchOp::Discard => "discard",
    }
}
