//! Egress and policy acceptance (SPEC §16.1): nothing is sent without a
//! release, a swapped payload, channel or target is refused, signatures
//! cannot be replayed or used after expiry, and approval text is regenerated
//! by the confirm service.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use aos_action::{Call, Catalog, IntentReview, IntentView, Review, Runtime};
use aos_branch::{Graph, NewObject, TxMeta};
use aos_cap::{CapabilityService, IssueRequest, Limits};
use aos_confirm::DevConfirmer;
use aos_egress::{Error, Gate, RecordingTransport, binding_hash, settle};
use aos_log::{BranchName, MemoryStore};
use aos_policy::{key_id, parse, sign};
use aos_types::cbor::{self, Value};
use aos_types::codec::{self, ToCbor};
use aos_types::sim::{ManualClock, SeededEntropy};
use aos_types::ulid::Clock;
use aos_types::{Actor, FieldValue, ObjectId, Sensitivity, Taint, Ulid};

const START: u64 = 1_700_000_000_000;

const POLICY: &str = r#"
policy: nightly-ml
signed_by: placeholder
grants:
  - rights: ["demo.*"]
    limits: {steps: 50, cpu_hours: 1, gpu_hours: 0, money_cny: 10, egress_channels: ["notify:*", "deliver:*", "model:default"]}
    max_ttl: 12h
rules:
  - allow: { channel: "notify:*" }
  - allow: { channel: "model:default", max_sensitivity: internal }
  - confirm: { channel: "notify:*", when: "intent.lineage.target_taint == 'external'" }
  - confirm: { channel: "deliver:*" }
  - deny: { channel: "*", min_sensitivity: secret }
default: confirm
"#;

fn clock() -> (Arc<ManualClock>, Arc<dyn Clock + Send + Sync>) {
    let manual = Arc::new(ManualClock::new(START));
    let shared: Arc<dyn Clock + Send + Sync> = manual.clone();
    (manual, shared)
}

fn dev() -> DevConfirmer {
    DevConfirmer::ephemeral(&mut SeededEntropy::new(5)).unwrap()
}

fn gate_with(
    policy_src: &str,
    transport: RecordingTransport,
) -> (Gate<RecordingTransport>, DevConfirmer, Arc<ManualClock>) {
    let confirmer = dev();
    let (manual, shared) = clock();
    let mut gate = Gate::new(confirmer.verifying(), transport, shared, Box::new(SeededEntropy::new(6)));
    gate.register_yaml(include_str!("../channels/notify.email.yaml")).unwrap();
    if !policy_src.is_empty() {
        let mut policy = parse(policy_src).unwrap();
        policy.signed_by = key_id(&confirmer.verifying());
        // key_id in aos-policy and the confirmer must agree.
        assert_eq!(policy.signed_by, confirmer.key_id());
        let signed = sign(&policy, confirmer.signing_key()).unwrap();
        gate.install(signed).unwrap();
    }
    (gate, confirmer, manual)
}

fn payload(body: &str) -> FieldValue {
    FieldValue::Map(BTreeMap::from([
        ("kind".into(), FieldValue::text("text")),
        ("body".into(), FieldValue::text(body)),
    ]))
}

fn view(channel: &str, target: &str, body: &str, taint: Taint, sensitivity: Sensitivity, cents: u64) -> IntentView {
    let payload = payload(body);
    IntentView {
        id: ObjectId(Ulid::from_u128(7)),
        channel: channel.into(),
        target: target.into(),
        payload_hash: binding_hash(channel, target, &payload),
        payload,
        cost_cents: cents,
        sensitivity,
        target_taint: taint,
        payload_taint: Taint::Clean,
        agent_summary: Some("SENTINEL_AGENT_TEXT".into()),
        reversibility: "compensate".into(),
        on_main: false,
    }
}

#[test]
fn nothing_is_sent_without_a_release_and_taint_forces_confirm() {
    let (mut gate, _, _) = gate_with(POLICY, RecordingTransport::default());
    let clean = view("notify:email", "a@b.c", "hello", Taint::Clean, Sensitivity::Private, 0);
    assert!(matches!(gate.review(&clean).unwrap(), Review::Allow { .. }));

    let tainted = view("notify:email", "a@b.c", "hello", Taint::External, Sensitivity::Private, 0);
    assert!(matches!(gate.review(&tainted).unwrap(), Review::Confirm { .. }), "confirm beats the allow rule");

    let secret = view("model:default", "gpt", "hello", Taint::Clean, Sensitivity::Secret, 0);
    assert!(matches!(gate.review(&secret).unwrap(), Review::Deny { .. }));

    let deliver = view("deliver:acme", "s3://bucket/", "hello", Taint::Clean, Sensitivity::Public, 0);
    assert!(matches!(gate.review(&deliver).unwrap(), Review::Confirm { .. }));

    assert!(gate.transport().sent.is_empty());
    let unknown = view("shell:root", "x", "hello", Taint::Clean, Sensitivity::Public, 0);
    let (mut bare, _, _) = gate_with("", RecordingTransport::default());
    assert!(matches!(bare.review(&unknown).unwrap(), Review::Confirm { rule } if rule == "default"));
    assert!(bare.transport().sent.is_empty());
}

#[test]
fn daily_cap_and_channel_registration() {
    let src = r#"
policy: cap
signed_by: placeholder
rules:
  - allow: { channel: "notify:*", max_cost_cny_per_day: 1 }
default: confirm
"#;
    let (mut gate, _, _) = gate_with(src, RecordingTransport::default());
    let first = view("notify:email", "a@b.c", "one", Taint::Clean, Sensitivity::Public, 60);
    let second = view("notify:email", "a@b.c", "two", Taint::Clean, Sensitivity::Public, 50);
    assert!(matches!(gate.review(&first).unwrap(), Review::Allow { .. }));
    assert!(matches!(gate.review(&second).unwrap(), Review::Confirm { .. }));
    gate.dispatch(&first).unwrap();
    assert_eq!(gate.transport().sent.len(), 1);
    assert_eq!(gate.transport().sent[0].payload_hash, first.payload_hash.to_string());

    let request = gate.approval_for(std::slice::from_ref(&first), "task/demo", "sha256:diff", 60_000).unwrap();
    assert_eq!(request.items[0].external_reversibility, "irreversible");
    assert!(request.summary.iter().all(|l| l.value != "SENTINEL_AGENT_TEXT"));
    assert_eq!(request.items[0].agent_summary.as_deref(), Some("SENTINEL_AGENT_TEXT"));
}

#[test]
fn approval_rejects_tamper_replay_and_expiry() {
    let (mut gate, confirmer, _) = gate_with(POLICY, RecordingTransport::default());
    let intent = view("deliver:acme", "s3://bucket/a", "model", Taint::Clean, Sensitivity::Public, 0);
    let request = gate.approval_for(std::slice::from_ref(&intent), "task/demo", "sha256:diff", 1_000).unwrap();
    let approval = confirmer.approve(&request.canonical_bytes(), "approve").unwrap();

    let mut swapped_payload = intent.clone();
    swapped_payload.payload = payload("other");
    let refused = gate.release(&request, &approval, &[swapped_payload]).unwrap();
    assert!(!refused[0].ok);
    assert!(refused[0].attempted);
    assert!(gate.transport().sent.is_empty());

    let again = gate.release(&request, &approval, std::slice::from_ref(&intent));
    assert!(matches!(again, Err(Error::Replay)));

    let (mut gate, confirmer, _) = gate_with(POLICY, RecordingTransport::default());
    let request = gate.approval_for(std::slice::from_ref(&intent), "task/demo", "sha256:diff", 1_000).unwrap();
    let approval = confirmer.approve(&request.canonical_bytes(), "approve").unwrap();
    let mut moved = intent.clone();
    moved.target = "s3://bucket/b".into();
    let refused = gate.release(&request, &approval, &[moved]).unwrap();
    assert!(!refused[0].ok);
    assert!(gate.transport().sent.is_empty());

    let (mut gate, confirmer, _) = gate_with(POLICY, RecordingTransport::default());
    let request = gate.approval_for(std::slice::from_ref(&intent), "task/demo", "sha256:diff", 1_000).unwrap();
    let approval = confirmer.approve(&request.canonical_bytes(), "approve").unwrap();
    let mut moved = intent.clone();
    moved.channel = "deliver:other".into();
    let refused = gate.release(&request, &approval, &[moved]).unwrap();
    assert!(!refused[0].ok && gate.transport().sent.is_empty());

    let (mut gate, confirmer, manual) = gate_with(POLICY, RecordingTransport::default());
    let request = gate.approval_for(std::slice::from_ref(&intent), "task/demo", "sha256:diff", 1_000).unwrap();
    let approval = confirmer.approve(&request.canonical_bytes(), "approve").unwrap();
    manual.advance(1_001);
    assert!(matches!(gate.release(&request, &approval, std::slice::from_ref(&intent)), Err(Error::Expired)));
    assert!(gate.transport().sent.is_empty());

    let (mut gate, confirmer, _) = gate_with(POLICY, RecordingTransport::default());
    let mut request = gate.approval_for(std::slice::from_ref(&intent), "task/demo", "sha256:diff", 60_000).unwrap();
    request.summary[0].value = "SENTINEL_AGENT_TEXT".into();
    gate.resign(&mut request);
    let approval = confirmer.approve(&request.canonical_bytes(), "approve").unwrap();
    let refused = gate.release(&request, &approval, std::slice::from_ref(&intent)).unwrap();
    assert!(!refused[0].ok);
    assert!(refused[0].detail.contains("confirm service"));
    assert!(gate.transport().sent.is_empty());

    let (mut gate, confirmer, _) = gate_with(POLICY, RecordingTransport::default());
    let request = gate.approval_for(std::slice::from_ref(&intent), "task/demo", "sha256:diff", 60_000).unwrap();
    let approval = confirmer.approve(&request.canonical_bytes(), "approve").unwrap();
    let sent = gate.release(&request, &approval, std::slice::from_ref(&intent)).unwrap();
    assert!(sent[0].ok);
    assert_eq!(gate.transport().sent.len(), 1);
    assert_eq!(gate.transport().sent[0].target, intent.target);
    assert_eq!(gate.transport().sent[0].payload, intent.payload.to_canonical_bytes());
    assert!(matches!(gate.release(&request, &approval, std::slice::from_ref(&intent)), Err(Error::Replay)));

    let (mut gate, confirmer, _) = gate_with(POLICY, RecordingTransport::default());
    let request = gate.approval_for(std::slice::from_ref(&intent), "task/demo", "sha256:diff", 60_000).unwrap();
    let approval = confirmer.approve(&request.canonical_bytes(), "deny").unwrap();
    let outcome = gate.release(&request, &approval, std::slice::from_ref(&intent)).unwrap();
    assert!(!outcome[0].attempted);
    assert!(gate.transport().sent.is_empty());
}

#[test]
fn a_failed_send_is_still_a_receipt() {
    let mut g =
        Graph::open(MemoryStore::new(), None, Box::new(ManualClock::new(START)), Box::new(SeededEntropy::new(1)))
            .unwrap()
            .0;
    let branch: BranchName = "task/demo".parse().unwrap();
    g.fork(&branch, Actor::User).unwrap();
    let intent = view("deliver:acme", "s3://bucket/a", "model", Taint::Clean, Sensitivity::Public, 0);
    let mut tx = g.begin(&branch, TxMeta::new(Actor::User)).unwrap();
    let id = tx.create(
        &g,
        NewObject::new("sys/EgressIntent@1".parse().unwrap())
            .field("channel", FieldValue::text(&intent.channel))
            .field("target", FieldValue::text(&intent.target))
            .field("payload", FieldValue::Blob(aos_types::Digest::of(b"blob")))
            .field("payload_hash", FieldValue::text(intent.payload_hash.to_string()))
            .field("external_reversibility", FieldValue::text("irreversible"))
            .field("cost_cents", FieldValue::Int(0))
            .field("target_taint", FieldValue::text("clean"))
            .field("payload_taint", FieldValue::text("clean"))
            .field("tainted_inputs", FieldValue::List(vec![]))
            .field("status", FieldValue::text("pending")),
    );
    g.commit(tx).unwrap();
    let mut stored = intent.clone();
    stored.id = id;

    let (mut gate, confirmer, _) = gate_with(POLICY, RecordingTransport::failing("down"));
    let request = gate.approval_for(std::slice::from_ref(&stored), "task/demo", "sha256:diff", 60_000).unwrap();
    let approval = confirmer.approve(&request.canonical_bytes(), "approve").unwrap();
    let outcome = gate.release(&request, &approval, std::slice::from_ref(&stored)).unwrap();
    assert!(!outcome[0].ok);
    assert!(gate.transport().sent.is_empty());
    settle(&mut g, &branch, &stored, &outcome[0]).unwrap();
    let updated = g.read(&branch, id).unwrap().unwrap();
    assert_eq!(updated.fields.get("status"), Some(&FieldValue::text("failed")));
    let receipts: Vec<_> = g
        .object_ids(&branch)
        .unwrap()
        .into_iter()
        .filter_map(|oid| {
            let obj = g.read(&branch, oid).unwrap()?;
            (obj.type_ref.to_string() == "sys/EgressReceipt@1").then_some((*obj).clone())
        })
        .collect();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].fields.get("ok"), Some(&FieldValue::Bool(false)));
    assert_eq!(receipts[0].provenance.taint, Taint::External);
}

#[test]
fn intent_create_sends_only_when_the_rule_allows() {
    let mut g =
        Graph::open(MemoryStore::new(), None, Box::new(ManualClock::new(START)), Box::new(SeededEntropy::new(2)))
            .unwrap()
            .0;
    let branch: BranchName = "task/demo".parse().unwrap();
    g.fork(&branch, agent()).unwrap();
    let mut caps = CapabilityService::new(Box::new(SeededEntropy::new(3)), Box::new(ManualClock::new(START)));
    let root = caps
        .root(
            BTreeSet::from(["*".into()]),
            Limits { steps: 100, cpu_ms: 0, gpu_ms: 0, money_cents: 0, egress_channels: BTreeSet::from(["*".into()]) },
            aos_types::Timestamp::from_unix_ms(START as i64 + 86_400_000).unwrap(),
        )
        .unwrap();
    let child = caps
        .issue(
            &Actor::User,
            &root.id,
            IssueRequest {
                subject: agent(),
                rights: BTreeSet::from(["demo.notify.send".into()]),
                object_scope: BTreeMap::new(),
                limits: Limits {
                    steps: 10,
                    cpu_ms: 0,
                    gpu_ms: 0,
                    money_cents: 0,
                    egress_channels: BTreeSet::from(["notify:*".into(), "deliver:*".into()]),
                },
                expires_at: aos_types::Timestamp::from_unix_ms(START as i64 + 3_600_000).unwrap(),
            },
        )
        .unwrap();
    let mut cat = Catalog::system();
    cat.load_dir(&std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../aos-action/decls/demo")).unwrap();
    let mut runtime = Runtime::new(cat, caps).unwrap();

    let (mut allow_gate, _, _) = gate_with(POLICY, RecordingTransport::default());
    runtime
        .invoke_reviewed(
            &mut g,
            call(&child.id, &branch, Taint::Clean, "notify:email", "please recollect"),
            &mut allow_gate,
        )
        .unwrap();
    assert_eq!(allow_gate.transport().sent.len(), 1);
    assert!(allow_gate.transport().sent[0].payload_hash.starts_with("sha256:"));
    let intents = objects(&g, &branch, "sys/EgressIntent@1");
    assert_eq!(intents[0].fields.get("status"), Some(&FieldValue::text("executed")));
    assert_eq!(intents[0].fields.get("policy_decision"), Some(&FieldValue::text("allow")));
    let receipts = objects(&g, &branch, "sys/EgressReceipt@1");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].fields.get("ok"), Some(&FieldValue::Bool(true)));

    let (mut hold_gate, _, _) = gate_with(POLICY, RecordingTransport::default());
    runtime
        .invoke_reviewed(
            &mut g,
            call(&child.id, &branch, Taint::External, "notify:email", "from outside"),
            &mut hold_gate,
        )
        .unwrap();
    assert_eq!(hold_gate.transport().sent.len(), 0);
    let pending: Vec<_> = objects(&g, &branch, "sys/EgressIntent@1")
        .into_iter()
        .filter(|o| o.fields.get("status") == Some(&FieldValue::text("pending")))
        .collect();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].fields.get("target_taint"), Some(&FieldValue::text("external")));
    assert_eq!(pending[0].fields.get("policy_decision"), Some(&FieldValue::text("confirm")));
}

fn agent() -> Actor {
    Actor::AgentTask(Ulid::from_u128(42))
}

fn call(cap: &str, branch: &BranchName, taint: Taint, channel: &str, body: &str) -> Call {
    let cbor_body = codec::record([
        ("channel", Value::from(channel)),
        ("target", codec::record([("literal", Value::from("a@b.c"))])),
        ("payload", codec::record([("kind", Value::from("text")), ("body", Value::from(body))])),
        ("reversibility", Value::from("irreversible")),
        ("cost_cents", Value::Unsigned(0)),
        ("agent_summary", Value::from("SENTINEL_AGENT_TEXT")),
    ]);
    let bytes = cbor::encode(&cbor_body);
    let wasm = wat::parse_str(format!(
        r#"(module
            (import "aos" "intent_create" (func $i (param i32 i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "{esc}")
            (func (export "aos_invoke") (param i32 i32) (result i32)
              (drop (call $i (i32.const 0) (i32.const {len})))
              i32.const 0))"#,
        esc = bytes.iter().map(|b| format!("\\{b:02x}")).collect::<String>(),
        len = bytes.len(),
    ))
    .unwrap();
    Call {
        branch: branch.clone(),
        actor: agent(),
        capability: cap.to_owned(),
        action: "demo.notify.draft@1".into(),
        inputs: BTreeMap::new(),
        literal_taint: taint,
        wasm,
    }
}

fn objects(g: &Graph<MemoryStore>, branch: &BranchName, ty: &str) -> Vec<aos_types::Object> {
    g.object_ids(branch)
        .unwrap()
        .into_iter()
        .filter_map(|id| {
            let obj = g.read(branch, id).unwrap()?;
            (obj.type_ref.to_string() == ty && !obj.tombstone).then_some((*obj).clone())
        })
        .collect()
}
