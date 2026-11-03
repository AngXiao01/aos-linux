//! Transactions: optimistic, serializable within a branch (SPEC §7.2).
//!
//! A transaction reads from the snapshot it began with and buffers its
//! writes. At commit, every object it read or wrote must still be at the
//! version it saw; otherwise it aborts with the conflicting objects. Writes
//! become one log entry, so they take effect together or not at all.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use aos_log::{Body, BranchName, LogStore, TxRecord, Write};
use aos_types::{Actor, FieldValue, ObjRef, Object, ObjectId, Origin, Provenance, Sensitivity, Taint, TxId, TypeRef};

use crate::error::{Conflict, Error};
use crate::graph::{Graph, Snapshot};

/// Who performs a transaction and on whose behalf (SPEC §7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxMeta {
    pub actor: Actor,
    pub capability: Option<String>,
    pub action: Option<String>,
    pub inputs: BTreeMap<String, FieldValue>,
}

impl TxMeta {
    pub fn new(actor: Actor) -> Self {
        TxMeta { actor, capability: None, action: None, inputs: BTreeMap::new() }
    }

    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }
}

/// The caller-chosen parts of a new object; identity, version and the
/// writing actor are filled in by the transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewObject {
    pub type_ref: TypeRef,
    pub fields: BTreeMap<String, FieldValue>,
    pub extra: BTreeMap<String, FieldValue>,
    pub sensitivity: Sensitivity,
    pub origin: Origin,
    pub taint: Taint,
    pub derived_from: BTreeSet<ObjRef>,
}

impl NewObject {
    pub fn new(type_ref: TypeRef) -> Self {
        NewObject {
            type_ref,
            fields: BTreeMap::new(),
            extra: BTreeMap::new(),
            sensitivity: Sensitivity::default(),
            origin: Origin::Internal,
            taint: Taint::Clean,
            derived_from: BTreeSet::new(),
        }
    }

    pub fn field(mut self, name: &str, value: FieldValue) -> Self {
        self.fields.insert(name.to_owned(), value);
        self
    }

    pub fn derived_from(mut self, r: ObjRef) -> Self {
        self.derived_from.insert(r);
        self
    }

    pub fn taint(mut self, taint: Taint) -> Self {
        self.taint = taint;
        self
    }
}

pub struct Tx {
    id: TxId,
    snapshot: Snapshot,
    meta: TxMeta,
    /// Version of every object read or written, as first seen.
    observed: HashMap<ObjectId, Option<u64>>,
    /// Written objects in first-write order; that order is kept in the log.
    order: Vec<ObjectId>,
    staged: HashMap<ObjectId, Object>,
    intents: Vec<ObjectId>,
}

impl Tx {
    pub fn id(&self) -> TxId {
        self.id
    }

    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    pub fn branch(&self) -> &BranchName {
        &self.snapshot.branch
    }

    /// Objects this transaction has staged, in first-write order.
    pub fn staged_ids(&self) -> &[ObjectId] {
        &self.order
    }

    /// A staged write, without recording a new read.
    pub fn peek(&self, id: ObjectId) -> Option<&Object> {
        self.staged.get(&id)
    }

    fn observe<S: LogStore>(&mut self, g: &Graph<S>, id: ObjectId) -> Option<u64> {
        *self.observed.entry(id).or_insert_with(|| g.lookup(&self.snapshot, id).map(|o| o.version))
    }

    /// The object as this transaction sees it (its own writes first),
    /// tombstones included.
    pub fn read<S: LogStore>(&mut self, g: &Graph<S>, id: ObjectId) -> Option<Object> {
        if let Some(o) = self.staged.get(&id) {
            return Some(o.clone());
        }
        self.observe(g, id);
        g.lookup(&self.snapshot, id).map(|o| (**o).clone())
    }

    pub fn create<S: LogStore>(&mut self, g: &Graph<S>, new: NewObject) -> ObjectId {
        let id = ObjectId(g.new_id());
        self.observed.insert(id, None);
        let object = Object {
            id,
            type_ref: new.type_ref,
            version: 1,
            fields: new.fields,
            provenance: Provenance {
                actor: self.meta.actor.clone(),
                origin: new.origin,
                taint: new.taint,
                derived_from: new.derived_from,
                tx: self.id,
            },
            sensitivity: new.sensitivity,
            extra: new.extra,
            tombstone: false,
        };
        self.stage(g, object);
        id
    }

    /// Applies `f` to a copy of a live object. Identity, version and the
    /// writing actor are reset afterwards.
    pub fn update<S: LogStore>(
        &mut self,
        g: &Graph<S>,
        id: ObjectId,
        f: impl FnOnce(&mut Object),
    ) -> Result<(), Error> {
        let mut object = self.read(g, id).ok_or(Error::NotFound(id))?;
        if object.tombstone {
            return Err(Error::Deleted(id));
        }
        f(&mut object);
        object.id = id;
        self.stage(g, object);
        Ok(())
    }

    /// Writes `object` whole, if the caller last saw it at `expected_version`
    /// (`aos_write`, SPEC §8.4). Can revive a tombstone.
    pub fn put<S: LogStore>(
        &mut self,
        g: &Graph<S>,
        object: Object,
        expected_version: Option<u64>,
    ) -> Result<(), Error> {
        let id = object.id;
        let current = self.read(g, id).map(|o| o.version);
        if current != expected_version {
            return Err(Error::Conflict(vec![Conflict { id, expected: expected_version, found: current }]));
        }
        self.stage(g, object);
        Ok(())
    }

    /// Writes a tombstone version (SPEC §6.3).
    pub fn delete<S: LogStore>(&mut self, g: &Graph<S>, id: ObjectId) -> Result<(), Error> {
        self.update(g, id, |o| o.tombstone = true)
    }

    pub fn intent_ids(&self) -> &[ObjectId] {
        &self.intents
    }

    /// Records that this transaction created egress intent `id` (SPEC §11).
    pub fn add_intent(&mut self, id: ObjectId) {
        if !self.intents.contains(&id) {
            self.intents.push(id);
        }
    }

    fn stage<S: LogStore>(&mut self, g: &Graph<S>, mut object: Object) {
        let id = object.id;
        let prev = self.observe(g, id);
        object.version = prev.map_or(1, |v| v + 1);
        object.provenance.tx = self.id;
        object.provenance.actor = self.meta.actor.clone();
        if self.staged.insert(id, object).is_none() {
            self.order.push(id);
        }
    }
}

impl<S: LogStore> Graph<S> {
    pub fn begin(&self, branch: &BranchName, meta: TxMeta) -> Result<Tx, Error> {
        self.check_writable(branch, &meta.actor)?;
        Ok(Tx {
            id: TxId(self.new_id()),
            snapshot: self.snapshot(branch)?,
            meta,
            observed: HashMap::new(),
            order: Vec::new(),
            staged: HashMap::new(),
            intents: Vec::new(),
        })
    }

    pub fn commit(&mut self, mut tx: Tx) -> Result<TxId, Error> {
        let branch = tx.snapshot.branch.clone();
        self.check_writable(&branch, &tx.meta.actor)?;
        if tx.order.is_empty() {
            return Err(Error::Empty);
        }
        let head = self.snapshot(&branch)?;
        let mut conflicts: Vec<Conflict> = tx
            .observed
            .iter()
            .filter_map(|(&id, &expected)| {
                let found = self.lookup(&head, id).map(|o| o.version);
                (found != expected).then_some(Conflict { id, expected, found })
            })
            .collect();
        if !conflicts.is_empty() {
            conflicts.sort_by_key(|c| c.id);
            return Err(Error::Conflict(conflicts));
        }
        for id in &tx.order {
            self.validate_write(&head, &tx.staged, &tx.staged[id])?;
        }
        if let Some(i) = tx.intents.iter().find(|i| !tx.staged.contains_key(i)) {
            return Err(Error::Invalid(format!("intent {i} is not written by this transaction")));
        }
        let writes = tx
            .order
            .iter()
            .map(|id| Write { prev_version: tx.observed[id], object: Arc::new(tx.staged.remove(id).expect("staged")) })
            .collect();
        let record = TxRecord {
            branch,
            tx: tx.id,
            actor: tx.meta.actor,
            capability: tx.meta.capability,
            action: tx.meta.action,
            inputs: tx.meta.inputs,
            writes,
            intents: tx.intents,
            revert_of: None,
            merged_from: None,
        };
        self.append(vec![Body::Tx(record)])?;
        Ok(tx.id)
    }

    /// Shape, stable type name, and taint monotonicity: an object derived
    /// from tainted data is tainted (SPEC §10).
    fn validate_write(&self, head: &Snapshot, staged: &HashMap<ObjectId, Object>, o: &Object) -> Result<(), Error> {
        o.check_shape().map_err(|e| Error::Invalid(format!("{}: {e}", o.id)))?;
        if let Some(prev) = self.lookup(head, o.id)
            && prev.type_ref.name != o.type_ref.name
        {
            return Err(Error::Invalid(format!("{}: type changes from {} to {}", o.id, prev.type_ref, o.type_ref)));
        }
        for r in &o.provenance.derived_from {
            let v = r.version.expect("check_shape pins versions");
            let source = staged
                .get(&r.id)
                .filter(|s| s.version == v)
                .or_else(|| self.lookup_version(head, r.id, v).map(|a| &**a));
            match source {
                None => return Err(Error::Invalid(format!("{}: derived_from {r} is not visible", o.id))),
                Some(s) if s.provenance.taint > o.provenance.taint => {
                    return Err(Error::Invalid(format!("{}: derived from tainted {r} but marked clean", o.id)));
                }
                Some(_) => {}
            }
        }
        Ok(())
    }
}
