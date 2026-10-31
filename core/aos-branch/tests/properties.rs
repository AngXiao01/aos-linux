//! SPEC §16.1 property tests for transactions, branches and revert, each
//! checked against a deliberately naive model.

mod common;

use std::collections::{BTreeMap, BTreeSet, HashMap};

use aos_branch::{Error, NoPreconditions, Tx};
use aos_log::BranchName;
use aos_types::{Actor, FieldValue, ObjectId, TxId};
use common::*;
use proptest::prelude::*;

// ---- transactions: optimistic concurrency is serializable --------------

const K: usize = 4;

#[derive(Clone, Debug)]
enum Op {
    Read(usize),
    /// Writes (sum of values read so far in this transaction) + delta, so
    /// written values depend on what was read.
    Write(usize, i64),
}

fn arb_script() -> impl Strategy<Value = Vec<Op>> {
    let op = prop_oneof![(0..K).prop_map(Op::Read), (0..K, -5i64..5).prop_map(|(k, d)| Op::Write(k, d))];
    prop::collection::vec(op, 1..5)
}

enum Run {
    Pending,
    Running { tx: Box<Tx>, next: usize, sum: i64, trace: Vec<(Op, i64)>, begun_at: u64 },
    Done,
}

fn tx_value(tx: &mut Tx, g: &G, id: ObjectId) -> i64 {
    match tx.read(g, id).unwrap().fields.get("value") {
        Some(FieldValue::Int(v)) => *v,
        other => panic!("{other:?}"),
    }
}

struct Committed {
    trace: Vec<(Op, i64)>,
    seq: u64,
}

/// Advances transaction `i` by one step: begin, one operation, or commit.
fn step(
    g: &mut G,
    ids: &[ObjectId],
    scripts: &[Vec<Op>],
    runs: &mut [Run],
    i: usize,
    committed: &mut Vec<Committed>,
    aborted: &mut Vec<(u64, BTreeSet<usize>)>,
) {
    match std::mem::replace(&mut runs[i], Run::Done) {
        Run::Pending => {
            let tx = Box::new(g.begin(&main(), user()).unwrap());
            runs[i] = Run::Running { tx, next: 0, sum: 0, trace: Vec::new(), begun_at: g.log().len() };
        }
        Run::Running { mut tx, next, mut sum, mut trace, begun_at } if next < scripts[i].len() => {
            let op = scripts[i][next].clone();
            match op {
                Op::Read(k) => {
                    let v = tx_value(&mut tx, g, ids[k]);
                    sum += v;
                    trace.push((op, v));
                }
                Op::Write(k, d) => {
                    let w = sum + d;
                    tx.update(g, ids[k], |o| {
                        o.fields.insert("value".into(), FieldValue::Int(w));
                    })
                    .unwrap();
                    trace.push((op, w));
                }
            }
            runs[i] = Run::Running { tx, next: next + 1, sum, trace, begun_at };
        }
        Run::Running { tx, trace, begun_at, .. } => {
            let touched: BTreeSet<usize> = trace
                .iter()
                .map(|(op, _)| match op {
                    Op::Read(k) | Op::Write(k, _) => *k,
                })
                .collect();
            let writes = trace.iter().any(|(op, _)| matches!(op, Op::Write(..)));
            match g.commit(*tx) {
                Ok(_) => committed.push(Committed { trace, seq: g.log().len() - 1 }),
                Err(Error::Empty) if !writes => {}
                Err(Error::Conflict(_)) => aborted.push((begun_at, touched)),
                Err(e) => panic!("unexpected {e}"),
            }
        }
        Run::Done => {}
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn optimistic_transactions_are_serializable(
        scripts in prop::collection::vec(arb_script(), 1..6),
        picks in prop::collection::vec(any::<u8>(), 0..40),
    ) {
        let mut g = graph();
        let ids = create_many(&mut g, &main(), &[0; K]);
        let mut runs: Vec<Run> = scripts.iter().map(|_| Run::Pending).collect();
        let mut committed = Vec::new();
        let mut aborted = Vec::new();
        for p in picks {
            let i = p as usize % scripts.len();
            step(&mut g, &ids, &scripts, &mut runs, i, &mut committed, &mut aborted);
        }
        for i in 0..scripts.len() {
            while !matches!(runs[i], Run::Done) {
                step(&mut g, &ids, &scripts, &mut runs, i, &mut committed, &mut aborted);
            }
        }

        // Committed transactions behave as if run one at a time, in commit
        // order: each read saw exactly the serial state.
        let mut model = [0i64; K];
        let mut writers: Vec<(u64, BTreeSet<usize>)> = Vec::new();
        for c in &committed {
            let mut local = model;
            let mut wrote = BTreeSet::new();
            for (op, v) in &c.trace {
                match op {
                    Op::Read(k) => prop_assert_eq!(local[*k], *v, "read diverged from serial order"),
                    Op::Write(k, _) => {
                        local[*k] = *v;
                        wrote.insert(*k);
                    }
                }
            }
            model = local;
            writers.push((c.seq, wrote));
        }
        for k in 0..K {
            prop_assert_eq!(value(&g, &main(), ids[k]), Some(model[k]));
        }
        // Every abort was caused by a commit, after the transaction began,
        // of an object it touched.
        for (begun_at, touched) in &aborted {
            prop_assert!(writers.iter().any(|(seq, wrote)| seq >= begun_at && !wrote.is_disjoint(touched)));
        }
    }
}

// ---- branches: isolation, rebase and commit against a copying model ----

const SLOTS: usize = 3;

#[derive(Clone, Debug)]
enum BOp {
    Fork(usize),
    Main(usize, Option<i64>),
    Branch(usize, usize, Option<i64>),
    Rebase(usize),
    Merge(usize),
    Discard(usize),
}

fn arb_bop() -> impl Strategy<Value = BOp> {
    let val = prop_oneof![4 => (0i64..100).prop_map(Some), 1 => Just(None)];
    prop_oneof![
        2 => (0..SLOTS).prop_map(BOp::Fork),
        3 => (0..K, val.clone()).prop_map(|(k, v)| BOp::Main(k, v)),
        4 => (0..SLOTS, 0..K, val).prop_map(|(s, k, v)| BOp::Branch(s, k, v)),
        1 => (0..SLOTS).prop_map(BOp::Rebase),
        2 => (0..SLOTS).prop_map(BOp::Merge),
        1 => (0..SLOTS).prop_map(BOp::Discard),
    ]
}

/// A branch modelled by copying `main` at the fork.
struct MBranch {
    name: BranchName,
    base: [Option<i64>; K],
    base_writes: [u64; K],
    overlay: HashMap<usize, Option<i64>>,
}

impl MBranch {
    fn view(&self, k: usize) -> Option<i64> {
        self.overlay.get(&k).copied().unwrap_or(self.base[k])
    }

    fn conflicts(&self, main_writes: &[u64; K]) -> bool {
        self.overlay.keys().any(|&k| main_writes[k] != self.base_writes[k])
    }
}

/// Sets (`Some`) or deletes (`None`) item `id`; `Err(Deleted)` if already deleted.
fn write(g: &mut G, branch: &BranchName, id: ObjectId, v: Option<i64>) -> Result<(), Error> {
    let mut tx = g.begin(branch, user()).unwrap();
    match v {
        Some(v) => tx.update(g, id, |o| {
            o.fields.insert("value".into(), FieldValue::Int(v));
        })?,
        None => tx.delete(g, id)?,
    }
    g.commit(tx).map(drop)
}

fn check_views(g: &G, ids: &[ObjectId], main_model: &[Option<i64>; K], slots: &[Option<MBranch>]) {
    for k in 0..K {
        assert_eq!(value(g, &main(), ids[k]), main_model[k], "main object {k}");
        for b in slots.iter().flatten() {
            assert_eq!(value(g, &b.name, ids[k]), b.view(k), "branch {} object {k}", b.name);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    #[test]
    fn branches_match_a_copying_model(ops in prop::collection::vec(arb_bop(), 1..40)) {
        let mut g = graph();
        let ids = create_many(&mut g, &main(), &[0; K]);
        let mut main_model: [Option<i64>; K] = [Some(0); K];
        let mut main_writes = [0u64; K];
        let mut slots: Vec<Option<MBranch>> = (0..SLOTS).map(|_| None).collect();
        let mut generation = 0;

        for op in ops {
            match op {
                BOp::Fork(s) if slots[s].is_none() => {
                    generation += 1;
                    let name = br(&format!("b{s}/g{generation}"));
                    g.fork(&name, Actor::System).unwrap();
                    slots[s] = Some(MBranch { name, base: main_model, base_writes: main_writes, overlay: HashMap::new() });
                }
                BOp::Main(k, v) => {
                    let result = write(&mut g, &main(), ids[k], v);
                    if main_model[k].is_some() {
                        result.unwrap();
                        main_model[k] = v;
                        main_writes[k] += 1;
                    } else {
                        prop_assert!(matches!(result, Err(Error::Deleted(_))));
                    }
                }
                BOp::Branch(s, k, v) => if let Some(b) = &mut slots[s] {
                    let result = write(&mut g, &b.name, ids[k], v);
                    if b.view(k).is_some() {
                        result.unwrap();
                        b.overlay.insert(k, v);
                    } else {
                        prop_assert!(matches!(result, Err(Error::Deleted(_))));
                    }
                },
                BOp::Rebase(s) => if let Some(b) = &mut slots[s] {
                    let result = g.rebase(&b.name, Actor::System);
                    if b.conflicts(&main_writes) {
                        prop_assert!(matches!(result, Err(Error::Rejected { .. })), "expected rejection, got {:?}", result);
                    } else {
                        result.unwrap();
                        b.base = main_model;
                        b.base_writes = main_writes;
                    }
                },
                BOp::Merge(s) => if let Some(b) = &slots[s] {
                    g.submit(&b.name, Actor::System).unwrap();
                    let result = g.merge(&b.name, Actor::User, &NoPreconditions);
                    if b.conflicts(&main_writes) {
                        prop_assert!(matches!(result, Err(Error::Rejected { .. })), "expected rejection, got {:?}", result);
                        g.reopen(&b.name, Actor::User).unwrap();
                    } else {
                        result.unwrap();
                        for (&k, &v) in &b.overlay {
                            main_model[k] = v;
                            main_writes[k] += 1;
                        }
                        slots[s] = None;
                    }
                },
                BOp::Discard(s) => if let Some(b) = slots[s].take() {
                    g.discard(&b.name, Actor::User).unwrap();
                },
                BOp::Fork(_) => {}
            }
            check_views(&g, &ids, &main_model, &slots);
        }

        let reopened = open(g.into_store(), 7);
        check_views(&reopened, &ids, &main_model, &slots);
    }
}

// ---- revert: equals replay without the reverted transactions -----------

#[derive(Clone, Debug)]
enum WOp {
    Set(usize, i64),
    Delete(usize),
    Create(i64),
}

fn arb_tx() -> impl Strategy<Value = Vec<WOp>> {
    let op = prop_oneof![
        5 => (0usize..8, 0i64..100).prop_map(|(k, v)| WOp::Set(k, v)),
        1 => (0usize..8).prop_map(WOp::Delete),
        2 => (0i64..100).prop_map(WOp::Create),
    ];
    prop::collection::vec(op, 1..4)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3_000))]

    #[test]
    fn revert_equals_replay_without_reverted(
        scripts in prop::collection::vec(arb_tx(), 1..8),
        attempts in prop::collection::vec(any::<prop::sample::Index>(), 1..6),
    ) {
        let mut g = graph();
        let mut pool = Vec::new();
        // Original transactions, each with its writes: id -> value (None: deleted).
        let mut original: Vec<(TxId, BTreeMap<ObjectId, Option<i64>>)> = Vec::new();

        let mut tx = g.begin(&main(), user()).unwrap();
        let mut writes = BTreeMap::new();
        for v in 0..3 {
            let id = tx.create(&g, item(v));
            pool.push(id);
            writes.insert(id, Some(v));
        }
        original.push((g.commit(tx).unwrap(), writes));

        for script in &scripts {
            let mut tx = g.begin(&main(), user()).unwrap();
            let mut writes = BTreeMap::new();
            let mut created = Vec::new();
            for op in script {
                let known = pool.len() + created.len();
                let id_at = |k: usize| if k < pool.len() { pool[k] } else { created[k - pool.len()] };
                match *op {
                    WOp::Set(k, v) => {
                        let id = id_at(k % known);
                        if tx.update(&g, id, |o| {
                            o.fields.insert("value".into(), FieldValue::Int(v));
                        }).is_ok() {
                            writes.insert(id, Some(v));
                        }
                    }
                    WOp::Delete(k) => {
                        let id = id_at(k % known);
                        if tx.delete(&g, id).is_ok() {
                            writes.insert(id, None);
                        }
                    }
                    WOp::Create(v) => {
                        let id = tx.create(&g, item(v));
                        created.push(id);
                        writes.insert(id, Some(v));
                    }
                }
            }
            if writes.is_empty() {
                continue;
            }
            original.push((g.commit(tx).unwrap(), writes));
            pool.extend(created);
        }

        // Actual history, reverse transactions included: (tx, objects written).
        let mut history: Vec<(TxId, BTreeSet<ObjectId>)> =
            original.iter().map(|(t, w)| (*t, w.keys().copied().collect())).collect();
        let mut reverted = BTreeSet::new();
        for at in attempts {
            let (target, target_writes) = &original[at.index(original.len())];
            let position = history.iter().position(|(t, _)| t == target).unwrap();
            let dependents: BTreeSet<TxId> = history[position + 1..]
                .iter()
                .filter(|(_, objs)| target_writes.keys().any(|id| objs.contains(id)))
                .map(|(t, _)| *t)
                .collect();
            let result = g.revert(&main(), *target, Actor::User);
            if reverted.contains(target) {
                prop_assert!(matches!(result, Err(Error::AlreadyReverted(_))));
            } else if !dependents.is_empty() {
                let Err(Error::Dependents(listed)) = result else {
                    return Err(TestCaseError::fail(format!("expected dependents, got {result:?}")));
                };
                prop_assert_eq!(listed.into_iter().collect::<BTreeSet<_>>(), dependents);
            } else {
                let r = result.unwrap();
                reverted.insert(*target);
                history.push((r, target_writes.keys().copied().collect()));
            }
        }

        let mut expected: HashMap<ObjectId, Option<i64>> = HashMap::new();
        for (t, writes) in &original {
            if !reverted.contains(t) {
                expected.extend(writes.iter().map(|(id, v)| (*id, *v)));
            }
        }
        for &id in &pool {
            prop_assert_eq!(value(&g, &main(), id), expected.get(&id).copied().flatten(), "object {}", id);
        }
        let reopened = open(g.into_store(), 5);
        for &id in &pool {
            prop_assert_eq!(value(&reopened, &main(), id), expected.get(&id).copied().flatten());
        }
    }
}
