//! Shared test helpers: a graph over an in-memory log with deterministic time
//! and ids, and a one-field item type.

#![allow(dead_code)]

use aos_branch::{Graph, NewObject, TxMeta};
use aos_log::{BranchName, MemoryStore};
use aos_types::sim::{ManualClock, SeededEntropy};
use aos_types::{Actor, FieldValue, ObjectId, TypeRef, Ulid};

pub type G = Graph<MemoryStore>;

pub const START_MS: u64 = 1_793_582_024_000;

pub fn graph() -> G {
    open(MemoryStore::new(), 1)
}

/// Opens `store`. Use a different `seed` per reopen of the same store, so
/// new ids do not repeat ids created before.
pub fn open(store: MemoryStore, seed: u64) -> G {
    let (g, recovery) =
        Graph::open(store, None, Box::new(ManualClock::new(START_MS)), Box::new(SeededEntropy::new(seed))).unwrap();
    assert_eq!(recovery.dropped, 0);
    g
}

pub fn ty() -> TypeRef {
    "test/Item@1".parse().unwrap()
}

pub fn item(value: i64) -> NewObject {
    NewObject::new(ty()).field("value", FieldValue::Int(value))
}

pub fn main() -> BranchName {
    BranchName::main()
}

pub fn br(name: &str) -> BranchName {
    name.parse().unwrap()
}

pub fn user() -> TxMeta {
    TxMeta::new(Actor::User)
}

pub fn agent() -> Actor {
    Actor::AgentTask(Ulid::from_u128(42))
}

pub fn create(g: &mut G, branch: &BranchName, value: i64) -> ObjectId {
    let mut tx = g.begin(branch, user()).unwrap();
    let id = tx.create(g, item(value));
    g.commit(tx).unwrap();
    id
}

pub fn create_many(g: &mut G, branch: &BranchName, values: &[i64]) -> Vec<ObjectId> {
    let mut tx = g.begin(branch, user()).unwrap();
    let ids = values.iter().map(|&v| tx.create(g, item(v))).collect();
    g.commit(tx).unwrap();
    ids
}

pub fn set(g: &mut G, branch: &BranchName, id: ObjectId, value: i64) -> aos_types::TxId {
    let mut tx = g.begin(branch, user()).unwrap();
    tx.update(g, id, |o| {
        o.fields.insert("value".into(), FieldValue::Int(value));
    })
    .unwrap();
    g.commit(tx).unwrap()
}

/// The live value: `None` if absent or deleted.
pub fn value(g: &G, branch: &BranchName, id: ObjectId) -> Option<i64> {
    let o = g.read(branch, id).unwrap()?;
    if o.tombstone {
        return None;
    }
    match o.fields.get("value") {
        Some(FieldValue::Int(v)) => Some(*v),
        other => panic!("unexpected value field {other:?}"),
    }
}
