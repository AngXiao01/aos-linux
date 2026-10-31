//! SPEC §16.1 log properties: the hash chain is intact, and any alteration of
//! stored entries is detected on open.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use aos_log::{Anchor, Body, BranchName, BranchOp, Corruption, Log, LogStore, MemoryStore, OpenError, TxRecord, Write};
use aos_types::{Actor, FieldValue, Object, ObjectId, Origin, Provenance, Sensitivity, Taint, Timestamp, TxId, Ulid};
use proptest::prelude::*;

fn ts() -> Timestamp {
    Timestamp::from_unix_ms(1_793_582_024_000).unwrap()
}

fn tx(n: u128, branch: &str, merged_from: Option<&str>) -> Body {
    let tx = TxId(Ulid::from_u128(1000 + n));
    let object = Object {
        id: ObjectId(Ulid::from_u128(n)),
        type_ref: "ml/Sample@1".parse().unwrap(),
        version: 1,
        fields: BTreeMap::from([("score".into(), FieldValue::float(0.5)), ("n".into(), FieldValue::Int(n as i64))]),
        provenance: Provenance {
            actor: Actor::User,
            origin: Origin::Internal,
            taint: Taint::Clean,
            derived_from: BTreeSet::new(),
            tx,
        },
        sensitivity: Sensitivity::Private,
        extra: BTreeMap::new(),
        tombstone: false,
    };
    Body::Tx(TxRecord {
        branch: branch.parse().unwrap(),
        tx,
        actor: Actor::User,
        capability: None,
        action: Some("test.write@1".into()),
        inputs: BTreeMap::new(),
        writes: vec![Write { prev_version: None, object: Arc::new(object) }],
        intents: vec![],
        revert_of: None,
        merged_from: merged_from.map(|b| b.parse().unwrap()),
    })
}

fn branch_op(name: &str, op: BranchOp) -> Body {
    Body::Branch { branch: name.parse().unwrap(), actor: Actor::System, op }
}

fn commit(name: &str, txs: u64) -> Body {
    Body::Commit { branch: name.parse().unwrap(), actor: Actor::User, txs }
}

/// main tx, fork, branch tx, submit, merged copy + commit.
fn sample_bodies() -> Vec<Body> {
    vec![
        tx(1, "main", None),
        branch_op("task/a", BranchOp::Fork { base: 1 }),
        tx(2, "task/a", None),
        branch_op("task/a", BranchOp::Submit),
        tx(2, "main", Some("task/a")),
        commit("task/a", 1),
    ]
}

fn sample_log() -> Log<MemoryStore> {
    let (mut log, _) = Log::open(MemoryStore::new(), None).unwrap();
    for body in sample_bodies() {
        log.append(ts(), vec![body]).unwrap();
    }
    log
}

fn reopen(store: MemoryStore, anchor: Option<Anchor>) -> Result<Log<MemoryStore>, OpenError> {
    Log::open(store, anchor).map(|(log, _)| log)
}

#[test]
fn round_trips_through_storage() {
    let log = sample_log();
    let anchor = log.anchor();
    let expected: Vec<_> = log.entries().map(Result::unwrap).collect();
    let reopened = reopen(log.into_store(), Some(anchor)).unwrap();
    assert_eq!(reopened.anchor(), anchor);
    let entries: Vec<_> = reopened.entries().map(Result::unwrap).collect();
    assert_eq!(entries, expected);
    assert_eq!(entries.iter().map(|e| e.body.clone()).collect::<Vec<_>>(), sample_bodies());
    for pair in entries.windows(2) {
        assert_eq!(pair[1].prev_hash, pair[0].hash());
    }
}

#[test]
fn every_single_byte_change_is_detected() {
    let store = sample_log().into_store();
    for (i, record) in store.records().iter().enumerate() {
        for at in 0..record.len() {
            for flip in [0x01u8, 0x80] {
                let mut bad = store.clone();
                bad.records_mut()[i][at] ^= flip;
                assert!(reopen(bad, None).is_err(), "record {i} byte {at} ^ {flip:#x} went unnoticed");
            }
        }
    }
}

#[test]
fn removed_reordered_or_replaced_entries_are_detected() {
    let store = sample_log().into_store();

    let mut removed = store.clone();
    removed.records_mut().remove(2);
    assert!(matches!(reopen(removed, None), Err(OpenError::Corrupt { seq: 2, reason: Corruption::WrongSeq })));

    let mut swapped = store.clone();
    swapped.records_mut().swap(1, 2);
    assert!(matches!(reopen(swapped, None), Err(OpenError::Corrupt { seq: 1, .. })));

    // A self-consistent entry from another log does not chain.
    let (mut other, _) = Log::open(MemoryStore::new(), None).unwrap();
    other.append(ts(), vec![tx(9, "main", None)]).unwrap();
    let mut spliced = store.clone();
    spliced.records_mut()[0] = other.store().records()[0].clone();
    spliced.records_mut()[1] = other.store().records()[0].clone();
    assert!(matches!(reopen(spliced, None), Err(OpenError::Corrupt { seq: 1, .. })));
}

#[test]
fn dropping_the_tail_needs_the_anchor_to_be_detected() {
    let log = sample_log();
    let anchor = log.anchor();
    let mut store = log.into_store();
    store.records_mut().pop();
    store.records_mut().pop();
    // Without an anchor a shorter log is indistinguishable from an older one.
    assert!(reopen(store.clone(), None).is_ok());
    assert!(matches!(reopen(store, Some(anchor)), Err(OpenError::AnchorMismatch)));
}

#[test]
fn anchor_must_match_the_entry_it_names() {
    let log = sample_log();
    let mut anchor = log.anchor();
    anchor.head = aos_types::Digest::of(b"forged");
    assert!(matches!(reopen(log.into_store(), Some(anchor)), Err(OpenError::AnchorMismatch)));
}

#[test]
fn unfinished_commit_group_is_rolled_back() {
    let (mut log, _) = Log::open(MemoryStore::new(), None).unwrap();
    for body in &sample_bodies()[..4] {
        log.append(ts(), vec![body.clone()]).unwrap();
    }
    let before = log.anchor();
    let group = vec![tx(2, "main", Some("task/a")), tx(3, "main", Some("task/a")), commit("task/a", 2)];

    let mut store = log.into_store();
    store.fail_next_append_after(2);
    let (mut log, _) = Log::open(store, None).unwrap();
    assert!(log.append(ts(), group.clone()).is_err());
    assert!(log.append(ts(), vec![tx(4, "main", None)]).is_err(), "a failed append poisons the log");

    let (mut log, recovery) = Log::open(log.into_store(), Some(before)).unwrap();
    assert_eq!(recovery.dropped, 2);
    assert_eq!(log.anchor(), before);
    log.append(ts(), group).unwrap();
    assert_eq!(log.len(), before.len + 3);
}

#[test]
fn malformed_groups_are_corruption() {
    let open_with = |bodies: Vec<Body>| {
        let (mut log, _) = Log::open(MemoryStore::new(), None).unwrap();
        log.append(ts(), bodies).unwrap();
        reopen(log.into_store(), None)
    };
    let interrupted = open_with(vec![tx(1, "main", Some("task/a")), tx(2, "main", None), commit("task/a", 1)]);
    assert!(matches!(interrupted, Err(OpenError::Corrupt { seq: 1, reason: Corruption::BadGroup(_) })));
    let orphan = open_with(vec![tx(1, "main", None), commit("task/a", 1)]);
    assert!(matches!(orphan, Err(OpenError::Corrupt { seq: 1, reason: Corruption::BadGroup(_) })));
    let miscounted = open_with(vec![tx(1, "main", Some("task/a")), commit("task/a", 2)]);
    assert!(matches!(miscounted, Err(OpenError::Corrupt { seq: 1, reason: Corruption::BadGroup(_) })));
    assert!(open_with(vec![commit("task/empty", 0)]).is_ok());
}

#[test]
fn stored_transactions_satisfy_their_invariants() {
    let Body::Tx(mut bad) = tx(1, "main", None) else { unreachable!() };
    let mut object = (*bad.writes[0].object).clone();
    object.version = 2;
    bad.writes[0].object = Arc::new(object);
    let (mut log, _) = Log::open(MemoryStore::new(), None).unwrap();
    log.append(ts(), vec![Body::Tx(bad)]).unwrap();
    assert!(matches!(
        reopen(log.into_store(), None),
        Err(OpenError::Corrupt { seq: 0, reason: Corruption::Undecodable(_) })
    ));
}

#[test]
fn branch_is_part_of_the_record() {
    let log = sample_log();
    let main = BranchName::main();
    let entries: Vec<_> = log.entries().map(Result::unwrap).collect();
    let Body::Tx(copy) = &entries[4].body else { panic!() };
    assert_eq!(copy.branch, main);
    assert_eq!(copy.merged_from.as_ref().map(BranchName::as_str), Some("task/a"));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn random_corruption_is_detected(
        record in 0usize..6,
        at in any::<prop::sample::Index>(),
        xor in 1u8..=255,
    ) {
        let mut store = sample_log().into_store();
        let bytes = &mut store.records_mut()[record];
        let i = at.index(bytes.len());
        bytes[i] ^= xor;
        prop_assert!(reopen(store, None).is_err());
    }

    #[test]
    fn random_truncation_is_detected_with_anchor(keep in 0u64..6) {
        let log = sample_log();
        let anchor = log.anchor();
        let mut store = log.into_store();
        store.truncate(keep).unwrap();
        prop_assert!(matches!(reopen(store, Some(anchor)), Err(OpenError::AnchorMismatch)));
    }
}
