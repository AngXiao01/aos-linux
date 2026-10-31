//! Sandbox and capability acceptance tests (SPEC §16.1): undeclared types abort,
//! direct I/O aborts and records a violation, unauthorized calls are rejected,
//! and quotas move by exactly the declared cost.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use aos_action::{Call, Catalog, Error, Runtime};
use aos_branch::{Error as BranchError, Graph, NewObject, TxMeta};
use aos_cap::{CapabilityService, IssueRequest, Limits};
use aos_log::{BranchName, MemoryStore};
use aos_types::cbor::{self, Value};
use aos_types::codec;
use aos_types::sim::{ManualClock, SeededEntropy};
use aos_types::{Actor, FieldValue, ObjectId, Taint, Ulid};

const START_MS: u64 = 1_700_000_000_000;

fn graph() -> Graph<MemoryStore> {
    Graph::open(MemoryStore::new(), None, Box::new(ManualClock::new(START_MS)), Box::new(SeededEntropy::new(1)))
        .unwrap()
        .0
}

fn catalog() -> Catalog {
    let mut cat = Catalog::system();
    cat.load_dir(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("decls/demo")).unwrap();
    cat
}

fn service() -> CapabilityService {
    CapabilityService::new(Box::new(SeededEntropy::new(3)), Box::new(ManualClock::new(START_MS)))
}

fn agent() -> Actor {
    Actor::AgentTask(Ulid::from_u128(42))
}

fn branch() -> BranchName {
    "task/demo".parse().unwrap()
}

fn later(svc: &CapabilityService, ms: i64) -> aos_types::Timestamp {
    aos_types::Timestamp::from_unix_ms(svc.now().unix_ms() + ms).unwrap()
}

struct Issued {
    runtime: Runtime,
    id: String,
}

fn runtime_with(rights: &[&str], steps: u64, cpu_ms: u64, channels: &[&str]) -> Issued {
    let mut caps = service();
    let root = caps
        .root(
            BTreeSet::from(["*".into()]),
            Limits {
                steps: 10_000,
                cpu_ms: 10_000_000,
                gpu_ms: 0,
                money_cents: 0,
                egress_channels: BTreeSet::from(["*".into()]),
            },
            later(&caps, 86_400_000),
        )
        .unwrap();
    let child = caps
        .issue(
            &Actor::User,
            &root.id,
            IssueRequest {
                subject: agent(),
                rights: rights.iter().map(|s| (*s).to_owned()).collect(),
                object_scope: BTreeMap::new(),
                limits: Limits {
                    steps,
                    cpu_ms,
                    gpu_ms: 0,
                    money_cents: 0,
                    egress_channels: channels.iter().map(|s| (*s).to_owned()).collect(),
                },
                expires_at: later(&caps, 3_600_000),
            },
        )
        .unwrap();
    let id = child.id.clone();
    Issued { runtime: Runtime::new(catalog(), caps).unwrap(), id }
}

fn counter_wasm() -> &'static [u8] {
    static WASM: OnceLock<Vec<u8>> = OnceLock::new();
    WASM.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("guests/counter");
        let status = Command::new("cargo")
            .args(["build", "--release", "--target", "wasm32-unknown-unknown", "--manifest-path"])
            .arg(dir.join("Cargo.toml"))
            .status()
            .expect("cargo");
        assert!(status.success(), "demo counter guest failed to build");
        std::fs::read(dir.join("target/wasm32-unknown-unknown/release/demo_counter.wasm")).unwrap()
    })
}

fn place_counter(g: &mut Graph<MemoryStore>, value: i64) -> ObjectId {
    let main = BranchName::main();
    let mut tx = g.begin(&main, TxMeta::new(Actor::User)).unwrap();
    let id = tx.create(g, NewObject::new("demo/Counter@1".parse().unwrap()).field("value", FieldValue::Int(value)));
    g.commit(tx).unwrap();
    g.fork(&branch(), agent()).unwrap();
    id
}

fn value_of(g: &Graph<MemoryStore>, id: ObjectId) -> i64 {
    match g.read(&branch(), id).unwrap().unwrap().fields.get("value") {
        Some(FieldValue::Int(n)) => *n,
        other => panic!("counter value {other:?}"),
    }
}

fn call(cap: &str, action: &str, inputs: BTreeMap<String, FieldValue>, wasm: Vec<u8>) -> Call {
    Call {
        branch: branch(),
        actor: agent(),
        capability: cap.to_owned(),
        action: action.to_owned(),
        inputs,
        literal_taint: Taint::Clean,
        wasm,
    }
}

fn violations(g: &Graph<MemoryStore>) -> Vec<aos_types::Object> {
    g.object_ids(&branch())
        .unwrap()
        .into_iter()
        .filter_map(|id| {
            let obj = g.read(&branch(), id).unwrap()?;
            (obj.type_ref.to_string() == "sys/ActionViolation@1" && !obj.tombstone).then_some((*obj).clone())
        })
        .collect()
}

#[test]
fn quota_is_exact_and_a_rejected_call_does_not_move_it() {
    let mut g = graph();
    let id = place_counter(&mut g, 0);
    let mut world = runtime_with(&["demo.counter.write"], 3, 4_000, &[]);
    let wasm = counter_wasm().to_vec();
    let inputs = BTreeMap::from([("counter".into(), FieldValue::Ref(aos_types::ObjRef::latest(id)))]);
    for expected in [1, 2] {
        world.runtime.invoke(&mut g, call(&world.id, "demo.counter.inc@1", inputs.clone(), wasm.clone())).unwrap();
        assert_eq!(value_of(&g, id), expected);
    }
    let before = world.runtime.caps().remaining(&world.id).unwrap().clone();
    assert_eq!(before.steps, 1);
    assert_eq!(before.cpu_ms, 1_000);
    let err = world.runtime.invoke(&mut g, call(&world.id, "demo.counter.inc@1", inputs, wasm)).unwrap_err();
    assert!(matches!(err, Error::Quota(_)), "{err}");
    assert_eq!(world.runtime.caps().remaining(&world.id).unwrap(), &before);
    assert_eq!(value_of(&g, id), 2);
    assert_eq!(world.runtime.caps().get(&world.id).unwrap().limits.steps, 3);
    assert!(violations(&g).is_empty());
}

#[test]
fn replay_does_not_apply_or_charge_twice() {
    let mut g = graph();
    let id = place_counter(&mut g, 0);
    let mut caps = service();
    let root = caps
        .root(
            BTreeSet::from(["*".into()]),
            Limits { steps: 100, cpu_ms: 0, gpu_ms: 0, money_cents: 0, egress_channels: BTreeSet::new() },
            later(&caps, 86_400_000),
        )
        .unwrap();
    let child = caps
        .issue(
            &Actor::User,
            &root.id,
            IssueRequest {
                subject: agent(),
                rights: BTreeSet::from(["demo.counter.write".into()]),
                object_scope: BTreeMap::new(),
                limits: Limits { steps: 5, cpu_ms: 0, gpu_ms: 0, money_cents: 0, egress_channels: BTreeSet::new() },
                expires_at: later(&caps, 3_600_000),
            },
        )
        .unwrap();
    let mut catalog = catalog();
    catalog
        .add_yaml(
            r#"
action: demo.counter.once
version: 1
provider: demo
summary: "只生效一次的加一"
inputs:
  counter: { ref: demo/Counter, required: true }
outputs:
  counter: { ref: demo/Counter }
effects:
  reads: [demo/Counter]
  writes: [demo/Counter]
  egress: []
reversibility: undo
preconditions:
  - "counter.value >= 0"
cost:
  steps: "1"
  cpu_seconds_estimate: "0"
capability: "demo.counter.write"
idempotency_key: "{counter.id}"
"#,
        )
        .unwrap();
    let mut runtime = Runtime::new(catalog, caps).unwrap();
    let inputs = BTreeMap::from([("counter".into(), FieldValue::Ref(aos_types::ObjRef::latest(id)))]);
    let wasm = counter_wasm().to_vec();
    runtime.invoke(&mut g, call(&child.id, "demo.counter.once@1", inputs.clone(), wasm.clone())).unwrap();
    let again = runtime.invoke(&mut g, call(&child.id, "demo.counter.once@1", inputs, wasm)).unwrap();
    assert!(again.replay);
    assert_eq!(value_of(&g, id), 1);
    assert_eq!(runtime.caps().remaining(&child.id).unwrap().steps, 4);
}

#[test]
fn unauthorized_call_is_rejected_and_records_a_violation() {
    let mut g = graph();
    let id = place_counter(&mut g, 0);
    let mut world = runtime_with(&["demo.counter.read"], 5, 10_000, &[]);
    let inputs = BTreeMap::from([("counter".into(), FieldValue::Ref(aos_types::ObjRef::latest(id)))]);
    let err = world
        .runtime
        .invoke(&mut g, call(&world.id, "demo.counter.inc@1", inputs, counter_wasm().to_vec()))
        .unwrap_err();
    assert!(matches!(err, Error::Unauthorized(_)), "{err}");
    assert_eq!(value_of(&g, id), 0);
    assert_eq!(world.runtime.caps().remaining(&world.id).unwrap().steps, 5);
    let found = violations(&g);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].fields.get("kind"), Some(&FieldValue::text("capability")));
}

#[test]
fn undeclared_read_and_write_abort_without_changing_state() {
    let mut g = graph();
    let main = BranchName::main();
    let mut tx = g.begin(&main, TxMeta::new(Actor::User)).unwrap();
    let id = tx.create(&g, NewObject::new("demo/Counter@1".parse().unwrap()).field("value", FieldValue::Int(7)));
    let foreign = tx.create(&g, NewObject::new("test/Item@1".parse().unwrap()).field("value", FieldValue::Int(9)));
    g.commit(tx).unwrap();
    g.fork(&branch(), agent()).unwrap();
    let mut world = runtime_with(&["demo.counter.write"], 5, 10_000, &[]);
    let inputs = BTreeMap::from([("counter".into(), FieldValue::Ref(aos_types::ObjRef::latest(id)))]);

    let err = world
        .runtime
        .invoke(&mut g, call(&world.id, "demo.counter.inc@1", inputs.clone(), read_foreign(&foreign.to_string())))
        .unwrap_err();
    assert!(
        matches!(err, Error::Violation(ref v) if v.kind == "undeclared_type" && v.detail.contains("read")),
        "{err}"
    );
    assert_eq!(value_of(&g, id), 7);

    let err = world
        .runtime
        .invoke(&mut g, call(&world.id, "demo.counter.inc@1", inputs, write_foreign(&foreign.to_string())))
        .unwrap_err();
    assert!(
        matches!(err, Error::Violation(ref v) if v.kind == "undeclared_type" && v.detail.contains("write")),
        "{err}"
    );
    assert_eq!(value_of(&g, id), 7);
    let kinds: Vec<_> = violations(&g).iter().map(|o| o.fields.get("kind").unwrap().clone()).collect();
    assert_eq!(kinds.len(), 2);
}

#[test]
fn direct_io_aborts_and_records_a_violation() {
    let mut g = graph();
    let id = place_counter(&mut g, 3);
    let mut world = runtime_with(&["demo.counter.write"], 5, 10_000, &[]);
    let inputs = BTreeMap::from([("counter".into(), FieldValue::Ref(aos_types::ObjRef::latest(id)))]);
    let wasm = wat::parse_str(
        r#"(module
            (import "wasi_snapshot_preview1" "random_get" (func (param i32 i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "aos_invoke") (param i32 i32) (result i32) i32.const 0))"#,
    )
    .unwrap();
    let err = world.runtime.invoke(&mut g, call(&world.id, "demo.counter.inc@1", inputs, wasm)).unwrap_err();
    assert!(matches!(err, Error::Violation(ref v) if v.kind == "io" && v.detail.contains("random_get")), "{err}");
    assert_eq!(value_of(&g, id), 3);
    assert_eq!(world.runtime.caps().remaining(&world.id).unwrap().steps, 5);
    let found = violations(&g);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].fields.get("action"), Some(&FieldValue::text("demo.counter.inc@1")));
}

#[test]
fn intent_stays_pending_and_local_job_is_only_an_object() {
    let mut g = graph();
    g.fork(&branch(), agent()).unwrap();
    let mut world = runtime_with(&["demo.notify.send", "demo.job.submit"], 4, 0, &["notify:*", "compute:*"]);
    let body = codec::record([
        ("channel", Value::from("notify:email")),
        ("target", codec::record([("literal", Value::from("collector@example.com"))])),
        ("payload", codec::record([("kind", Value::from("text")), ("body", Value::from("please recollect"))])),
        ("reversibility", Value::from("irreversible")),
        ("cost_cents", Value::Unsigned(0)),
        ("agent_summary", Value::from("补采通知")),
    ]);
    let bytes = cbor::encode(&body);
    let wasm = wat::parse_str(format!(
        r#"(module
            (import "aos" "intent_create" (func $i (param i32 i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "{esc}")
            (func (export "aos_invoke") (param i32 i32) (result i32)
              (drop (call $i (i32.const 0) (i32.const {len})))
              i32.const 0))"#,
        esc = wat_escape(&bytes),
        len = bytes.len(),
    ))
    .unwrap();
    world.runtime.invoke(&mut g, call(&world.id, "demo.notify.draft@1", BTreeMap::new(), wasm)).unwrap();
    let intent = objects_of(&g, "sys/EgressIntent@1");
    assert_eq!(intent.len(), 1);
    assert_eq!(intent[0].fields.get("status"), Some(&FieldValue::text("pending")));
    assert_eq!(intent[0].fields.get("channel"), Some(&FieldValue::text("notify:email")));
    assert_eq!(intent[0].fields.get("target_taint"), Some(&FieldValue::text("clean")));

    let job = codec::record([("kind", Value::from("local")), ("spec", Value::from("train"))]);
    let job_bytes = cbor::encode(&job);
    let job_wasm = wat::parse_str(format!(
        r#"(module
            (import "aos" "job_submit" (func $j (param i32 i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "{esc}")
            (func (export "aos_invoke") (param i32 i32) (result i32)
              (drop (call $j (i32.const 0) (i32.const {len})))
              i32.const 0))"#,
        esc = wat_escape(&job_bytes),
        len = job_bytes.len(),
    ))
    .unwrap();
    world.runtime.invoke(&mut g, call(&world.id, "demo.job.submit@1", BTreeMap::new(), job_wasm)).unwrap();
    let jobs = objects_of(&g, "sys/Job@1");
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].fields.get("state"), Some(&FieldValue::text("queued")));
    assert_eq!(jobs[0].fields.get("kind"), Some(&FieldValue::text("local")));
    assert_eq!(objects_of(&g, "sys/EgressIntent@1").len(), 1);
}

#[test]
fn merge_rechecks_preconditions_against_the_rebased_view() {
    let mut g = graph();
    let main = BranchName::main();
    let mut tx = g.begin(&main, TxMeta::new(Actor::User)).unwrap();
    let counter = tx.create(&g, NewObject::new("demo/Counter@1".parse().unwrap()).field("value", FieldValue::Int(0)));
    let flag = tx.create(&g, NewObject::new("demo/Counter@1".parse().unwrap()).field("value", FieldValue::Int(1)));
    g.commit(tx).unwrap();
    g.fork(&branch(), agent()).unwrap();

    let mut caps = service();
    let root = caps
        .root(
            BTreeSet::from(["*".into()]),
            Limits { steps: 10, cpu_ms: 10_000, gpu_ms: 0, money_cents: 0, egress_channels: BTreeSet::new() },
            later(&caps, 86_400_000),
        )
        .unwrap();
    let child = caps
        .issue(
            &Actor::User,
            &root.id,
            IssueRequest {
                subject: agent(),
                rights: BTreeSet::from(["demo.counter.write".into()]),
                object_scope: BTreeMap::new(),
                limits: Limits { steps: 5, cpu_ms: 5_000, gpu_ms: 0, money_cents: 0, egress_channels: BTreeSet::new() },
                expires_at: later(&caps, 3_600_000),
            },
        )
        .unwrap();
    let mut cat = catalog();
    cat.add_yaml(
        r#"
action: demo.counter.bump
version: 1
provider: demo
summary: "在标志允许时把计数器加一"
inputs:
  counter: { ref: demo/Counter, required: true }
  flag: { ref: demo/Counter, required: true }
outputs:
  counter: { ref: demo/Counter }
effects:
  reads: [demo/Counter]
  writes: [demo/Counter]
  egress: []
reversibility: undo
preconditions:
  - "flag.value == 1"
cost:
  steps: "1"
  cpu_seconds_estimate: "0"
capability: "demo.counter.write"
"#,
    )
    .unwrap();
    let mut runtime = Runtime::new(cat, caps).unwrap();
    let inputs = BTreeMap::from([
        ("counter".into(), FieldValue::Ref(aos_types::ObjRef::latest(counter))),
        ("flag".into(), FieldValue::Ref(aos_types::ObjRef::latest(flag))),
    ]);
    runtime.invoke(&mut g, call(&child.id, "demo.counter.bump@1", inputs, counter_wasm().to_vec())).unwrap();
    assert_eq!(value_of(&g, counter), 1);

    let mut tx = g.begin(&main, TxMeta::new(Actor::User)).unwrap();
    tx.update(&g, flag, |o| {
        o.fields.insert("value".into(), FieldValue::Int(0));
    })
    .unwrap();
    g.commit(tx).unwrap();
    g.submit(&branch(), Actor::User).unwrap();
    let err = g.merge(&branch(), Actor::User, runtime.catalog()).unwrap_err();
    assert!(matches!(err, BranchError::Rejected { .. }), "{err}");
    assert!(g.read(&main, counter).unwrap().unwrap().fields.get("value") == Some(&FieldValue::Int(0)));
}

fn read_foreign(id: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(module
            (import "aos" "read" (func $r (param i32 i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "{id}")
            (func (export "aos_invoke") (param i32 i32) (result i32)
              (drop (call $r (i32.const 0) (i32.const {len})))
              i32.const 0))"#,
        len = id.len(),
    ))
    .unwrap()
}

fn write_foreign(id: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(module
            (import "aos" "write" (func $w (param i32 i32 i64 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "{id}")
            (func (export "aos_invoke") (param i32 i32) (result i32)
              (i32.store8 (i32.const 64) (i32.const 160))
              (drop (call $w (i32.const 0) (i32.const {len}) (i64.const 1) (i32.const 64) (i32.const 1)))
              i32.const 0))"#,
        len = id.len(),
    ))
    .unwrap()
}

fn objects_of(g: &Graph<MemoryStore>, ty: &str) -> Vec<aos_types::Object> {
    g.object_ids(&branch())
        .unwrap()
        .into_iter()
        .filter_map(|id| {
            let obj = g.read(&branch(), id).unwrap()?;
            (obj.type_ref.to_string() == ty && !obj.tombstone).then_some((*obj).clone())
        })
        .collect()
}

fn wat_escape(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\{b:02x}")).collect()
}
