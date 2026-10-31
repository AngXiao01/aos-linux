//! Scenario tests for transactions, branches, commit, revert and diffs.

mod common;

use std::collections::BTreeSet;

use aos_branch::{BranchState, ChangeKind, Error, NewObject, Preconditions, ReadView, TxMeta, TypeChanges};
use aos_log::{Body, LogStore, TxRecord};
use aos_types::{Actor, FieldValue, ObjRef, Taint};
use common::*;

#[test]
fn transaction_versions_and_tombstones() {
    let mut g = graph();
    let id = create(&mut g, &main(), 1);
    set(&mut g, &main(), id, 2);
    assert_eq!(value(&g, &main(), id), Some(2));
    assert_eq!(g.read(&main(), id).unwrap().unwrap().version, 2);

    let mut tx = g.begin(&main(), user()).unwrap();
    tx.delete(&g, id).unwrap();
    assert!(matches!(tx.delete(&g, id), Err(Error::Deleted(_))));
    g.commit(tx).unwrap();
    let tomb = g.read(&main(), id).unwrap().unwrap();
    assert!(tomb.tombstone && tomb.version == 3);
    assert_eq!(value(&g, &main(), id), None);

    let versions: Vec<_> = g.history(&main(), id).unwrap().iter().map(|o| o.version).collect();
    assert_eq!(versions, [1, 2, 3]);
    assert!(matches!(g.commit(g.begin(&main(), user()).unwrap()), Err(Error::Empty)));
}

#[test]
fn multiple_writes_in_one_transaction_bump_each_version_once() {
    let mut g = graph();
    let id = create(&mut g, &main(), 1);
    let mut tx = g.begin(&main(), user()).unwrap();
    let other = tx.create(&g, item(10));
    for v in 2..5 {
        tx.update(&g, id, |o| {
            o.fields.insert("value".into(), FieldValue::Int(v));
        })
        .unwrap();
    }
    tx.update(&g, other, |o| {
        o.fields.insert("value".into(), FieldValue::Int(11));
    })
    .unwrap();
    let tx_id = g.commit(tx).unwrap();
    let o = g.read(&main(), id).unwrap().unwrap();
    assert_eq!((o.version, o.provenance.tx), (2, tx_id));
    assert_eq!(g.read(&main(), other).unwrap().unwrap().version, 1);
    assert_eq!(value(&g, &main(), other), Some(11));
    let entry = g.log().read(g.log().len() - 1).unwrap();
    let Body::Tx(rec) = entry.body else { panic!() };
    assert_eq!(rec.writes.iter().map(|w| w.id()).collect::<Vec<_>>(), [other, id], "first-write order");
}

#[test]
fn a_failed_append_leaves_no_trace() {
    let mut g = graph();
    let a = create(&mut g, &main(), 1);
    let store = {
        let mut store = g.into_store();
        store.fail_next_append_after(0);
        store
    };
    let mut g = open(store, 2);
    let mut tx = g.begin(&main(), user()).unwrap();
    tx.create(&g, item(5));
    tx.update(&g, a, |o| {
        o.fields.insert("value".into(), FieldValue::Int(9));
    })
    .unwrap();
    assert!(matches!(g.commit(tx), Err(Error::Io(_))));
    assert_eq!(value(&g, &main(), a), Some(1));
    let g = open(g.into_store(), 3);
    assert_eq!(value(&g, &main(), a), Some(1));
    assert_eq!(g.log().len(), 1);
}

#[test]
fn concurrent_writers_conflict_on_objects_they_touched() {
    let mut g = graph();
    let [a, b] = create_many(&mut g, &main(), &[1, 2])[..] else { panic!() };

    // Write-write.
    let mut t1 = g.begin(&main(), user()).unwrap();
    let mut t2 = g.begin(&main(), user()).unwrap();
    t1.update(&g, a, |o| {
        o.extra.insert("x".into(), FieldValue::Int(1));
    })
    .unwrap();
    t2.update(&g, a, |o| {
        o.extra.insert("y".into(), FieldValue::Int(1));
    })
    .unwrap();
    g.commit(t1).unwrap();
    let Err(Error::Conflict(c)) = g.commit(t2) else { panic!("expected conflict") };
    assert_eq!((c[0].id, c[0].expected, c[0].found), (a, Some(1), Some(2)));

    // Read-write: t3 read b and wrote a; t4 wrote b first.
    let mut t3 = g.begin(&main(), user()).unwrap();
    let seen = t3.read(&g, b).unwrap();
    t3.update(&g, a, |o| o.fields = seen.fields.clone()).unwrap();
    set(&mut g, &main(), b, 20);
    assert!(matches!(g.commit(t3), Err(Error::Conflict(c)) if c[0].id == b));

    // Disjoint transactions both commit.
    let mut t5 = g.begin(&main(), user()).unwrap();
    let mut t6 = g.begin(&main(), user()).unwrap();
    t5.update(&g, a, |o| o.sensitivity = aos_types::Sensitivity::Public).unwrap();
    t6.update(&g, b, |o| o.sensitivity = aos_types::Sensitivity::Public).unwrap();
    g.commit(t6).unwrap();
    g.commit(t5).unwrap();
}

#[test]
fn put_checks_the_expected_version() {
    let mut g = graph();
    let id = create(&mut g, &main(), 1);
    let current = (*g.read(&main(), id).unwrap().unwrap()).clone();
    let mut tx = g.begin(&main(), user()).unwrap();
    assert!(matches!(tx.put(&g, current.clone(), Some(7)), Err(Error::Conflict(_))));
    let mut next = current;
    next.fields.insert("value".into(), FieldValue::Int(3));
    tx.put(&g, next, Some(1)).unwrap();
    g.commit(tx).unwrap();
    assert_eq!(value(&g, &main(), id), Some(3));
}

#[test]
fn who_may_write_where() {
    let mut g = graph();
    let agent_meta = TxMeta::new(agent());
    assert!(matches!(g.begin(&main(), agent_meta.clone()), Err(Error::NotPermitted { .. })));

    let task = br("task/1");
    g.fork(&task, Actor::System).unwrap();
    let id = {
        let mut tx = g.begin(&task, agent_meta.clone()).unwrap();
        let id = tx.create(&g, item(1));
        g.commit(tx).unwrap();
        id
    };
    let pending = g.begin(&task, agent_meta.clone()).unwrap();
    g.submit(&task, agent()).unwrap();
    assert!(matches!(g.commit(pending), Err(Error::BadState { state: BranchState::Submitted, .. })));
    assert!(matches!(g.begin(&task, agent_meta.clone()), Err(Error::BadState { .. })));
    set(&mut g, &task, id, 2); // the user edits during review (SPEC §7.3)

    assert!(matches!(g.merge(&task, agent(), &aos_branch::NoPreconditions), Err(Error::NotPermitted { .. })));
    assert!(matches!(g.reopen(&task, agent()), Err(Error::NotPermitted { .. })));
    g.merge(&task, Actor::User, &aos_branch::NoPreconditions).unwrap();
    assert_eq!(g.branch_info(&task).unwrap().state, BranchState::Committed);
    assert!(matches!(g.begin(&task, user()), Err(Error::BadState { .. })));
    assert!(matches!(g.fork(&task, Actor::System), Err(Error::BranchExists(_))));
    assert_eq!(value(&g, &main(), id), Some(2));
}

#[test]
fn fork_is_constant_time_and_branches_are_isolated() {
    let mut g = graph();
    let values: Vec<i64> = (0..10_000).collect();
    let ids = create_many(&mut g, &main(), &values);
    let entries_before = g.log().len();
    let started = std::time::Instant::now();
    g.fork(&br("a"), Actor::System).unwrap();
    g.fork(&br("b"), Actor::System).unwrap();
    assert!(started.elapsed().as_millis() < 10, "fork took {:?}", started.elapsed());
    assert_eq!(g.log().len(), entries_before + 2, "a fork is one small entry, nothing copied");

    set(&mut g, &br("a"), ids[0], -1);
    set(&mut g, &main(), ids[1], -2);
    let created = create(&mut g, &br("b"), 77);
    assert_eq!(value(&g, &br("a"), ids[0]), Some(-1));
    assert_eq!(value(&g, &main(), ids[0]), Some(0));
    assert_eq!(value(&g, &br("b"), ids[0]), Some(0));
    assert_eq!(value(&g, &br("a"), ids[1]), Some(1), "main writes after the fork stay out of the branch");
    assert_eq!(value(&g, &main(), ids[1]), Some(-2));
    assert_eq!(value(&g, &main(), created), None);
    assert_eq!(value(&g, &br("a"), created), None);
}

#[test]
fn rebase_picks_up_main_or_reports_conflicts() {
    let mut g = graph();
    let [x, y] = create_many(&mut g, &main(), &[1, 2])[..] else { panic!() };
    g.fork(&br("t"), Actor::System).unwrap();
    set(&mut g, &br("t"), x, 10);
    set(&mut g, &main(), y, 20);
    g.rebase(&br("t"), Actor::System).unwrap();
    assert_eq!(value(&g, &br("t"), y), Some(20));
    assert_eq!(value(&g, &br("t"), x), Some(10));

    set(&mut g, &main(), x, 30);
    let Err(Error::Rejected { conflicts, .. }) = g.rebase(&br("t"), Actor::System) else { panic!() };
    assert_eq!((conflicts[0].id, conflicts[0].base_version, conflicts[0].main_version), (x, Some(1), Some(2)));
    assert_eq!(value(&g, &br("t"), x), Some(10));
}

#[test]
fn commit_appends_each_branch_transaction_and_keeps_ids() {
    let mut g = graph();
    let x = create(&mut g, &main(), 1);
    let t = br("task/a");
    g.fork(&t, Actor::System).unwrap();
    let t1 = set(&mut g, &t, x, 2);
    let y = create(&mut g, &t, 5);
    let t3 = set(&mut g, &t, y, 6);
    g.submit(&t, Actor::System).unwrap();
    let before = g.log().len();
    let commit_seq = g.merge(&t, Actor::User, &aos_branch::NoPreconditions).unwrap();
    assert_eq!(commit_seq, before + 3);
    assert_eq!((value(&g, &main(), x), value(&g, &main(), y)), (Some(2), Some(6)));

    let copies: Vec<TxRecord> = (before..commit_seq)
        .map(|s| match g.log().read(s).unwrap().body {
            Body::Tx(r) => r,
            other => panic!("{other:?}"),
        })
        .collect();
    assert!(copies.iter().all(|r| r.branch.is_main() && r.merged_from.as_ref() == Some(&t)));
    assert_eq!(copies[0].tx, t1);
    assert_eq!(copies[2].tx, t3);

    // A single merged transaction can be reverted on main.
    g.revert(&main(), t3, Actor::User).unwrap();
    assert_eq!((value(&g, &main(), x), value(&g, &main(), y)), (Some(2), Some(5)));
}

#[test]
fn rejected_commit_keeps_the_branch_under_review() {
    let mut g = graph();
    let x = create(&mut g, &main(), 1);
    let t = br("task/a");
    g.fork(&t, Actor::System).unwrap();
    set(&mut g, &t, x, 2);
    g.submit(&t, Actor::System).unwrap();
    set(&mut g, &main(), x, 3);
    let Err(Error::Rejected { conflicts, preconditions }) = g.merge(&t, Actor::User, &aos_branch::NoPreconditions)
    else {
        panic!()
    };
    assert_eq!(conflicts.len(), 1);
    assert!(preconditions.is_empty());
    assert_eq!(g.branch_info(&t).unwrap().state, BranchState::Submitted);
    assert_eq!(value(&g, &main(), x), Some(3));
    g.discard(&t, Actor::User).unwrap();
    assert!(g.read(&t, x).is_err());
}

/// Requires the object named by the `subject` input to have a positive value
/// in the view, and records what each check saw.
struct PositiveSubject(std::cell::RefCell<Vec<Option<i64>>>);

impl Preconditions for PositiveSubject {
    fn check(&self, view: &dyn ReadView, tx: &TxRecord) -> Result<(), String> {
        let Some(FieldValue::Ref(r)) = tx.inputs.get("subject") else { return Ok(()) };
        let v = view.read(r.id).and_then(|o| match o.fields.get("value") {
            Some(FieldValue::Int(v)) => Some(*v),
            _ => None,
        });
        self.0.borrow_mut().push(v);
        match v {
            Some(v) if v > 0 => Ok(()),
            _ => Err(format!("subject {} must be positive", r.id)),
        }
    }
}

#[test]
fn preconditions_are_rechecked_against_the_rebased_state() {
    let mut g = graph();
    let [subject, target] = create_many(&mut g, &main(), &[5, 0])[..] else { panic!() };
    let t = br("task/a");
    g.fork(&t, Actor::System).unwrap();

    let action = |g: &mut G, value: i64| {
        let mut meta = user().action("test.bump@1");
        meta.inputs.insert("subject".into(), FieldValue::Ref(ObjRef::latest(subject)));
        let mut tx = g.begin(&t, meta).unwrap();
        tx.update(g, target, |o| {
            o.fields.insert("value".into(), FieldValue::Int(value));
        })
        .unwrap();
        g.commit(tx).unwrap()
    };
    action(&mut g, 1);
    set(&mut g, &t, subject, 7);
    action(&mut g, 2);
    g.submit(&t, Actor::System).unwrap();

    // Each check sees the state just before its transaction: the first sees
    // main's 5, the second sees the branch's own earlier write of 7.
    let check = PositiveSubject(Default::default());
    g.merge(&t, Actor::User, &check).unwrap();
    assert_eq!(*check.0.borrow(), [Some(5), Some(7)]);

    // A precondition failure caused only by main's state.
    let mut g = graph();
    let [subject, target] = create_many(&mut g, &main(), &[5, 0])[..] else { panic!() };
    g.fork(&t, Actor::System).unwrap();
    let mut meta = user().action("test.bump@1");
    meta.inputs.insert("subject".into(), FieldValue::Ref(ObjRef::latest(subject)));
    let mut tx = g.begin(&t, meta).unwrap();
    tx.update(&g, target, |o| {
        o.fields.insert("value".into(), FieldValue::Int(1));
    })
    .unwrap();
    let only = g.commit(tx).unwrap();
    g.submit(&t, Actor::System).unwrap();
    set(&mut g, &main(), subject, -1);
    let check = PositiveSubject(Default::default());
    let Err(Error::Rejected { conflicts, preconditions }) = g.merge(&t, Actor::User, &check) else { panic!() };
    assert!(conflicts.is_empty(), "the branch never wrote the subject");
    assert_eq!(preconditions.len(), 1);
    assert_eq!(preconditions[0].0, only);
    assert_eq!(*check.0.borrow(), [Some(-1)]);
    assert_eq!(g.branch_info(&t).unwrap().state, BranchState::Submitted);
}

#[test]
fn revert_restores_refuses_dependents_and_redoes() {
    let mut g = graph();
    let [a, b] = create_many(&mut g, &main(), &[1, 1])[..] else { panic!() };
    let t2 = set(&mut g, &main(), a, 2);
    let t3 = set(&mut g, &main(), b, 3);
    let t4 = set(&mut g, &main(), a, 4);

    let Err(Error::Dependents(deps)) = g.revert(&main(), t2, Actor::User) else { panic!() };
    assert_eq!(deps, [t4]);

    let r3 = g.revert(&main(), t3, Actor::User).unwrap();
    assert_eq!(value(&g, &main(), b), Some(1));
    assert!(g.is_tx_reverted(&main(), t3).unwrap());
    assert!(matches!(g.revert(&main(), t3, Actor::User), Err(Error::AlreadyReverted(_))));

    let r3r = g.revert(&main(), r3, Actor::User).unwrap();
    assert_eq!(value(&g, &main(), b), Some(3));
    assert!(!g.is_tx_reverted(&main(), t3).unwrap());
    assert!(g.is_tx_reverted(&main(), r3).unwrap());
    let o = g.read(&main(), b).unwrap().unwrap();
    assert_eq!((o.version, o.provenance.tx), (4, r3r));

    let c = create(&mut g, &main(), 9);
    let created_by = g.read(&main(), c).unwrap().unwrap().provenance.tx;
    g.revert(&main(), created_by, Actor::User).unwrap();
    assert!(g.read(&main(), c).unwrap().unwrap().tombstone);
    assert!(matches!(
        g.revert(&main(), aos_types::TxId(aos_types::Ulid::from_u128(1)), Actor::User),
        Err(Error::TxNotFound(_))
    ));
}

#[test]
fn objects_derived_from_reverted_work_are_stale() {
    // The E2E-ML step 4 shape: dedupe produces v14, later work derives from it.
    let mut g = graph();
    let v13 = create(&mut g, &main(), 13);
    let new_version = |g: &mut G, from: aos_types::ObjectId, value: i64| {
        let parent = g.read(&main(), from).unwrap().unwrap();
        let mut tx = g.begin(&main(), user()).unwrap();
        let id = tx.create(g, item(value).derived_from(parent.pinned_ref()));
        (g.commit(tx).unwrap(), id)
    };
    let (dedupe, v14) = new_version(&mut g, v13, 14);
    let (_, v15) = new_version(&mut g, v14, 15);
    let (_, experiment) = new_version(&mut g, v15, 100);
    let (_, unrelated) = new_version(&mut g, v13, 200);

    let stale = |g: &G, id| g.is_stale(&main(), &g.read(&main(), id).unwrap().unwrap()).unwrap();
    assert!(!stale(&g, experiment));
    g.revert(&main(), dedupe, Actor::User).unwrap();
    assert!(g.read(&main(), v14).unwrap().unwrap().tombstone);
    assert!(stale(&g, v15) && stale(&g, experiment));
    assert!(!stale(&g, unrelated) && !stale(&g, v13));
}

#[test]
fn derived_objects_must_be_visible_and_keep_taint() {
    let mut g = graph();
    let mut tx = g.begin(&main(), user()).unwrap();
    let ext = tx.create(&g, item(1).taint(Taint::External));
    g.commit(tx).unwrap();
    let ext_ref = g.read(&main(), ext).unwrap().unwrap().pinned_ref();

    let mut tx = g.begin(&main(), user()).unwrap();
    tx.create(&g, item(2).derived_from(ext_ref));
    assert!(matches!(g.commit(tx), Err(Error::Invalid(m)) if m.contains("tainted")));

    let mut tx = g.begin(&main(), user()).unwrap();
    tx.create(&g, item(2).derived_from(ext_ref).taint(Taint::External));
    g.commit(tx).unwrap();

    let mut tx = g.begin(&main(), user()).unwrap();
    tx.create(&g, item(3).derived_from(ObjRef::at(ext, 9)).taint(Taint::External));
    assert!(matches!(g.commit(tx), Err(Error::Invalid(m)) if m.contains("not visible")));

    // Within one transaction, derived_from may name objects it creates.
    let mut tx = g.begin(&main(), user()).unwrap();
    let parent = tx.create(&g, item(4));
    tx.create(&g, item(5).derived_from(ObjRef::at(parent, 1)));
    g.commit(tx).unwrap();
}

#[test]
fn diff_counts_net_changes_by_type() {
    let mut g = graph();
    let ids = create_many(&mut g, &main(), &[1, 2, 3, 4]);
    let t = br("task/a");
    g.fork(&t, Actor::System).unwrap();
    let empty = g.diff(&t).unwrap();
    assert!(empty.by_type.is_empty() && empty.txs.is_empty());

    set(&mut g, &t, ids[0], 10); // updated
    let mut tx = g.begin(&t, user()).unwrap();
    tx.delete(&g, ids[1]).unwrap(); // deleted
    let new = tx.create(&g, item(5)); // created
    let transient = tx.create(&g, item(6));
    tx.create(&g, NewObject::new("test/Other@1".parse().unwrap()));
    tx.add_intent(new);
    g.commit(tx).unwrap();
    let mut tx = g.begin(&t, user()).unwrap();
    tx.delete(&g, transient).unwrap(); // created then deleted: no change
    tx.update(&g, ids[2], |o| o.sensitivity = aos_types::Sensitivity::Public).unwrap();
    g.commit(tx).unwrap();
    let mut tx = g.begin(&t, user()).unwrap();
    tx.update(&g, ids[2], |o| o.sensitivity = aos_types::Sensitivity::Private).unwrap(); // back to base
    g.commit(tx).unwrap();

    let diff = g.diff(&t).unwrap();
    assert_eq!(diff.by_type[&ty()], TypeChanges { created: 1, updated: 1, deleted: 1 });
    assert_eq!(diff.by_type[&"test/Other@1".parse().unwrap()], TypeChanges { created: 1, updated: 0, deleted: 0 });
    assert_eq!(diff.txs.len(), 4);
    assert_eq!(diff.intents, [new]);

    let created = g.changes_page(&t, Some((&ty(), ChangeKind::Created)), None, 10).unwrap();
    assert_eq!(created.iter().map(|c| c.id).collect::<Vec<_>>(), [new]);
    let all: Vec<_> = g.changes(&t).unwrap().into_iter().map(|c| c.id).collect();
    let page1 = g.changes_page(&t, None, None, 2).unwrap();
    let page2 = g.changes_page(&t, None, Some(page1[1].id), 2).unwrap();
    assert_eq!(page1.iter().chain(&page2).map(|c| c.id).collect::<Vec<_>>(), all);

    let before = diff.digest;
    set(&mut g, &t, ids[3], 40);
    assert_ne!(g.diff(&t).unwrap().digest, before);
    assert!(g.diff(&main()).is_err());
}

#[test]
fn reopening_rebuilds_the_same_graph() {
    let mut g = graph();
    let ids = create_many(&mut g, &main(), &[1, 2, 3]);
    let t = br("task/a");
    let u = br("task/b");
    g.fork(&t, Actor::System).unwrap();
    g.fork(&u, Actor::System).unwrap();
    set(&mut g, &t, ids[0], 10);
    let tx = set(&mut g, &u, ids[1], 20);
    g.revert(&u, tx, Actor::User).unwrap();
    set(&mut g, &u, ids[2], 30);
    g.submit(&t, Actor::System).unwrap();
    g.merge(&t, Actor::User, &aos_branch::NoPreconditions).unwrap();
    g.submit(&u, Actor::System).unwrap();

    let diff = g.diff(&u).unwrap();
    let branches = g.branches();
    let anchor = g.anchor();
    let read_all =
        |g: &G| [main(), u.clone()].map(|b| ids.iter().map(|&id| g.read(&b, id).unwrap()).collect::<Vec<_>>());
    let before = read_all(&g);

    let (g2, _) = aos_branch::Graph::open(
        g.into_store(),
        Some(anchor),
        Box::new(aos_types::sim::ManualClock::new(START_MS)),
        Box::new(aos_types::sim::SeededEntropy::new(99)),
    )
    .unwrap();
    assert_eq!(read_all(&g2), before);
    assert_eq!(g2.branches(), branches);
    assert_eq!(g2.diff(&u).unwrap(), diff);
}

#[test]
fn a_crash_during_commit_rolls_the_whole_group_back() {
    let mut g = graph();
    let x = create(&mut g, &main(), 1);
    let t = br("task/a");
    g.fork(&t, Actor::System).unwrap();
    set(&mut g, &t, x, 2);
    let y = create(&mut g, &t, 3);
    g.submit(&t, Actor::System).unwrap();
    let anchor = g.anchor();

    let mut store = g.into_store();
    store.fail_next_append_after(1); // first merged copy written, then power loss
    let mut g = open(store, 2);
    assert!(g.merge(&t, Actor::User, &aos_branch::NoPreconditions).is_err());
    let store = g.into_store();
    assert_eq!(store.len(), anchor.len + 1);

    let (mut g, recovery) = aos_branch::Graph::open(
        store,
        Some(anchor),
        Box::new(aos_types::sim::ManualClock::new(START_MS)),
        Box::new(aos_types::sim::SeededEntropy::new(3)),
    )
    .unwrap();
    assert_eq!(recovery.dropped, 1);
    assert_eq!(value(&g, &main(), x), Some(1));
    assert_eq!(value(&g, &main(), y), None);
    assert_eq!(g.branch_info(&t).unwrap().state, BranchState::Submitted);
    g.merge(&t, Actor::User, &aos_branch::NoPreconditions).unwrap();
    assert_eq!((value(&g, &main(), x), value(&g, &main(), y)), (Some(2), Some(3)));
}

#[test]
fn closed_branches_are_not_readable() {
    let mut g = graph();
    let t = br("t");
    g.fork(&t, Actor::System).unwrap();
    g.discard(&t, Actor::System).unwrap();
    assert!(matches!(g.snapshot(&t), Err(Error::BadState { state: BranchState::Discarded, .. })));
    assert!(matches!(g.discard(&t, Actor::System), Err(Error::BadState { .. })));
    assert!(matches!(g.submit(&br("nope"), Actor::System), Err(Error::NoSuchBranch(_))));
    let ids: BTreeSet<_> = g.main_ids().collect();
    assert!(ids.is_empty());
}
