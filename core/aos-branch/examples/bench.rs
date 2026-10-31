//! SPEC §7.8 performance targets, on the in-memory log backend.
//!
//!     cargo run --release -p aos-branch --example bench
//!
//! Objects are shaped like `ml/Sample` (an asset ref, a label ref, a quality
//! score). The 1M-object diff stands in for the dataset diff target until the
//! member-table format exists (M6).

use std::time::{Duration, Instant};

use aos_branch::{Graph, NewObject, NoPreconditions, TxMeta};
use aos_log::{BranchName, MemoryStore};
use aos_types::sim::{ManualClock, SeededEntropy};
use aos_types::{Actor, FieldValue, ObjRef, ObjectId, TypeRef, Ulid};

type G = Graph<MemoryStore>;

fn sample(ty: &TypeRef, i: u64) -> NewObject {
    NewObject::new(ty.clone())
        .field("asset", FieldValue::Ref(ObjRef::latest(ObjectId(Ulid::from_u128(i as u128 + 1)))))
        .field("label", FieldValue::Ref(ObjRef::latest(ObjectId(Ulid::from_u128(7)))))
        .field("quality_score", FieldValue::float((i % 1000) as f64 / 1000.0))
}

fn create(g: &mut G, branch: &BranchName, ty: &TypeRef, n: u64) -> (Vec<ObjectId>, Duration) {
    let mut tx = g.begin(branch, TxMeta::new(Actor::User).action("bench.create@1")).unwrap();
    let ids = (0..n).map(|i| tx.create(g, sample(ty, i))).collect();
    let started = Instant::now();
    g.commit(tx).unwrap();
    (ids, started.elapsed())
}

fn report(what: &str, took: Duration, target: Option<Duration>) {
    let verdict = match target {
        Some(t) if took <= t => format!("target {t:?}: pass"),
        Some(t) => format!("target {t:?}: FAIL"),
        None => "info".into(),
    };
    println!("{what:<52} {:>10.1} ms   {verdict}", took.as_secs_f64() * 1e3);
}

fn main() {
    let ty: TypeRef = "ml/Sample@1".parse().unwrap();
    let main = BranchName::main();
    let (mut g, _) = Graph::open(
        MemoryStore::new(),
        None,
        Box::new(ManualClock::new(1_793_582_024_000)),
        Box::new(SeededEntropy::new(1)),
    )
    .unwrap();

    // 100k objects already on main.
    let mut existing = Vec::new();
    for _ in 0..10 {
        existing.extend(create(&mut g, &main, &ty, 10_000).0);
    }

    let started = Instant::now();
    for i in 0..100 {
        g.fork(&format!("fork/{i}").parse().unwrap(), Actor::System).unwrap();
    }
    report(
        "fork a branch (mean of 100, 100k objects on main)",
        started.elapsed() / 100,
        Some(Duration::from_millis(10)),
    );

    let started = Instant::now();
    let mut tx = g.begin(&main, TxMeta::new(Actor::User)).unwrap();
    let ids: Vec<_> = (0..10_000).map(|i| tx.create(&g, sample(&ty, i))).collect();
    let staged = started.elapsed();
    let started = Instant::now();
    let created = g.commit(tx).unwrap();
    report("commit a transaction creating 10k objects", started.elapsed(), Some(Duration::from_secs(2)));
    report("  (staging those 10k creates)", staged, None);

    let started = Instant::now();
    g.revert(&main, created, Actor::User).unwrap();
    report("revert that 10k-write transaction", started.elapsed(), Some(Duration::from_secs(2)));
    assert!(g.read(&main, ids[0]).unwrap().unwrap().tombstone);

    let mut tx = g.begin(&main, TxMeta::new(Actor::User)).unwrap();
    for &id in &existing[..10_000] {
        tx.update(&g, id, |o| {
            o.fields.insert("quality_score".into(), FieldValue::float(0.0));
        })
        .unwrap();
    }
    let started = Instant::now();
    let updated = g.commit(tx).unwrap();
    report("commit a transaction updating 10k objects", started.elapsed(), Some(Duration::from_secs(2)));
    let started = Instant::now();
    g.revert(&main, updated, Actor::User).unwrap();
    report("revert that 10k-update transaction", started.elapsed(), Some(Duration::from_secs(2)));

    // A branch that creates 1M objects.
    let task: BranchName = "task/bench".parse().unwrap();
    g.fork(&task, Actor::System).unwrap();
    let started = Instant::now();
    for _ in 0..100 {
        create(&mut g, &task, &ty, 10_000);
    }
    report("  (build a branch with 1M new objects, 100 txs)", started.elapsed(), None);
    let started = Instant::now();
    let diff = g.diff(&task).unwrap();
    report("diff a branch with 1M changed objects", started.elapsed(), Some(Duration::from_secs(5)));
    assert_eq!(diff.by_type[&ty].created, 1_000_000);

    g.submit(&task, Actor::System).unwrap();
    let started = Instant::now();
    g.merge(&task, Actor::User, &NoPreconditions).unwrap();
    report("  (commit that branch into main)", started.elapsed(), None);

    let entries = g.log().len();
    let started = Instant::now();
    let (reopened, _) =
        Graph::open(g.into_store(), None, Box::new(ManualClock::new(0)), Box::new(SeededEntropy::new(2))).unwrap();
    report(&format!("  (reopen: verify and replay {entries} entries, 2.2M writes)"), started.elapsed(), None);
    assert!(reopened.read(&main, existing[0]).unwrap().is_some());
}
