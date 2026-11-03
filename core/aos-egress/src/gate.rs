//! Decides an intent, and sends it only with a matching authorization.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use aos_action::{Dispatch, IntentReview, IntentView, Review, eval_bool, parse_expr};
use aos_branch::{Graph, NewObject, TxMeta};
use aos_cap::channel_covers;
use aos_cap::parse_channel;
use aos_confirm::{
    Approval, ApprovalRequest, ConfirmService, Item, PreviewInput, RequestInput, preview_of, summary_of,
};
use aos_log::{BranchName, LogStore};
use aos_policy::{Decision, Effect, Facts, SignedPolicy, verify};
use aos_types::cbor::Value;
use aos_types::codec::{ToCbor, record};
use aos_types::ulid::{Clock, Entropy};
use aos_types::yaml::{self, Yaml};
use aos_types::{Actor, Digest, FieldValue, ObjectId, Origin, Taint, Timestamp};
use p256::ecdsa::VerifyingKey;

use crate::Error;
use crate::transport::{Outbound, Transport};

const DAY_MS: u64 = 86_400_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseItem {
    pub id: ObjectId,
    /// The gate tried to execute (or refused an execution). A signer deny
    /// is not an execution.
    pub attempted: bool,
    pub ok: bool,
    pub detail: String,
    pub at_ms: i64,
}

pub struct Gate<T: Transport> {
    user: VerifyingKey,
    confirm: ConfirmService,
    policy: Option<SignedPolicy>,
    transport: T,
    spent: BTreeMap<(i64, String), u64>,
    reserved: BTreeMap<String, u64>,
    used_sigs: BTreeSet<Vec<u8>>,
    used_nonces: BTreeSet<Vec<u8>>,
    channels: Vec<(String, String)>,
    queued: Vec<ApprovalRequest>,
}

impl<T: Transport> Gate<T> {
    pub fn new(
        user: VerifyingKey,
        transport: T,
        clock: Arc<dyn Clock + Send + Sync>,
        entropy: Box<dyn Entropy + Send>,
    ) -> Self {
        Gate {
            user,
            confirm: ConfirmService::new(entropy, clock),
            policy: None,
            transport,
            spent: BTreeMap::new(),
            reserved: BTreeMap::new(),
            used_sigs: BTreeSet::new(),
            used_nonces: BTreeSet::new(),
            channels: Vec::new(),
            queued: Vec::new(),
        }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn queued(&self) -> &[ApprovalRequest] {
        &self.queued
    }

    pub fn install(&mut self, signed: SignedPolicy) -> Result<(), Error> {
        verify(&signed, &self.user).map_err(|e| Error::Policy(e.to_string()))?;
        self.policy = Some(signed);
        Ok(())
    }

    pub fn register(&mut self, name: &str, reversibility: &str) -> Result<(), Error> {
        parse_channel(name).map_err(|e| Error::Bad(e.to_string()))?;
        if !matches!(reversibility, "undo" | "compensate" | "irreversible") {
            return Err(Error::Bad(format!("bad reversibility {reversibility}")));
        }
        self.channels.push((name.to_owned(), reversibility.to_owned()));
        Ok(())
    }

    pub fn register_yaml(&mut self, text: &str) -> Result<(), Error> {
        let doc = yaml::parse(text).map_err(|e| Error::Bad(e.to_string()))?;
        let name = yaml_str(&doc, "channel")?;
        let reversibility = yaml_str(&doc, "reversibility")?;
        self.register(&name, &reversibility)
    }

    pub fn approval_for(
        &mut self,
        intents: &[IntentView],
        branch: &str,
        diff_hash: &str,
        ttl_ms: u64,
    ) -> Result<ApprovalRequest, Error> {
        let items = self.preview_inputs(intents)?;
        self.confirm
            .egress(RequestInput { branch: branch.to_owned(), diff_hash: diff_hash.to_owned(), ttl_ms, items })
            .map_err(|e| Error::Confirm(e.to_string()))
    }

    pub fn resign(&self, request: &mut ApprovalRequest) {
        self.confirm.resign(request);
    }

    /// Checks the approval and, only if it still matches the payloads,
    /// sends. A bad signature, an expiry or a replay is an error and does
    /// not send. A payload, channel, target or summary that no longer
    /// matches is a failed execution: the signature is consumed and nothing
    /// is sent.
    pub fn release(
        &mut self,
        request: &ApprovalRequest,
        approval: &Approval,
        intents: &[IntentView],
    ) -> Result<Vec<ReleaseItem>, Error> {
        let bytes = request.canonical_bytes();
        request.verify_os(&self.confirm.os_verifying()).map_err(|_| Error::Confirm("os signature".into()))?;
        approval.verify(&self.user, &bytes).map_err(|e| Error::Confirm(e.to_string()))?;
        let now = self.confirm.now_ms() as i64;
        if now > request.expires_at.unix_ms() {
            return Err(Error::Expired);
        }
        if self.used_sigs.contains(&approval.signature) || self.used_nonces.contains(&request.nonce) {
            return Err(Error::Replay);
        }
        self.used_sigs.insert(approval.signature.clone());
        self.used_nonces.insert(request.nonce.clone());
        if approval.decision == "deny" {
            return Ok(intents
                .iter()
                .map(|intent| ReleaseItem {
                    id: intent.id,
                    attempted: false,
                    ok: false,
                    detail: "denied".into(),
                    at_ms: now,
                })
                .collect());
        }
        if approval.decision != "approve" {
            return Err(Error::Confirm("decision".into()));
        }
        let expected = self.items_of(intents).map_err(|e| Error::Bad(e.to_string()))?;
        if request.summary != summary_of(&expected) || request.items != expected {
            return Ok(fail_all(intents, now, "approval text was not produced by the confirm service"));
        }
        for (intent, item) in intents.iter().zip(&request.items) {
            let actual = binding_hash(&intent.channel, &intent.target, &intent.payload);
            if intent.channel != item.channel || intent.target != item.target || actual.to_string() != item.payload_hash
            {
                return Ok(fail_all(intents, now, "payload, channel or target does not match the approval"));
            }
        }
        let mut out = Vec::new();
        for intent in intents {
            let actual = binding_hash(&intent.channel, &intent.target, &intent.payload);
            let bytes = intent.payload.to_canonical_bytes();
            match self.transport.send(&Outbound {
                channel: &intent.channel,
                target: &intent.target,
                payload: &bytes,
                payload_hash: &actual.to_string(),
            }) {
                Ok(detail) => {
                    self.add_spend(&intent.channel, intent.cost_cents);
                    out.push(ReleaseItem {
                        id: intent.id,
                        attempted: true,
                        ok: true,
                        detail: format!("{detail}; approval {}", request.request_id),
                        at_ms: now,
                    });
                }
                Err(e) => out.push(ReleaseItem { id: intent.id, attempted: true, ok: false, detail: e, at_ms: now }),
            }
        }
        Ok(out)
    }

    fn decide(&self, intent: &IntentView) -> Result<Decision, Error> {
        let Some(signed) = &self.policy else {
            return Ok(Decision { effect: Effect::Confirm, rule: "default".into() });
        };
        let facts = Facts {
            channel: &intent.channel,
            sensitivity: intent.sensitivity,
            cost_cents: intent.cost_cents,
            spent_today_cents: self.spent_total(&intent.channel),
        };
        let inputs = when_inputs(intent);
        Ok(signed.policy.decide(&facts, |src| {
            let expr = parse_expr(src)?;
            eval_bool(&expr, &inputs, |_| Err("when cannot load objects".into()))
        }))
    }

    fn preview_inputs(&self, intents: &[IntentView]) -> Result<Vec<PreviewInput>, Error> {
        intents
            .iter()
            .map(|intent| {
                let hash = binding_hash(&intent.channel, &intent.target, &intent.payload);
                Ok(PreviewInput {
                    channel: intent.channel.clone(),
                    target: intent.target.clone(),
                    payload: intent.payload.clone(),
                    payload_hash: hash.to_string(),
                    cost_cents: intent.cost_cents,
                    external_reversibility: self.effective(&intent.channel, &intent.reversibility),
                    target_tainted: intent.target_taint == Taint::External,
                    payload_tainted: intent.payload_taint == Taint::External,
                    agent_summary: intent.agent_summary.clone(),
                })
            })
            .collect()
    }

    fn items_of(&self, intents: &[IntentView]) -> Result<Vec<Item>, Error> {
        self.preview_inputs(intents)?
            .into_iter()
            .map(|item| {
                Ok(Item {
                    channel: item.channel,
                    target: item.target,
                    payload_hash: item.payload_hash,
                    preview: preview_of(&item.payload).map_err(|e| Error::Bad(e.to_string()))?,
                    agent_summary: item.agent_summary,
                    cost_cents: item.cost_cents,
                    external_reversibility: item.external_reversibility,
                    target_tainted: item.target_tainted,
                    payload_tainted: item.payload_tainted,
                })
            })
            .collect()
    }

    fn effective(&self, channel: &str, claimed: &str) -> String {
        let registered = self
            .channels
            .iter()
            .filter(|(name, _)| channel_covers(name, channel))
            .map(|(_, rev)| rev.as_str())
            .max_by_key(|rev| rev_rank(rev));
        let reg = registered.unwrap_or("irreversible");
        if rev_rank(reg) >= rev_rank(claimed) { reg.to_owned() } else { claimed.to_owned() }
    }

    fn spent_total(&self, channel: &str) -> u64 {
        let day = (self.confirm.now_ms() / DAY_MS) as i64;
        self.spent.get(&(day, channel.to_owned())).copied().unwrap_or(0)
            + self.reserved.get(channel).copied().unwrap_or(0)
    }

    fn add_spend(&mut self, channel: &str, cents: u64) {
        let day = (self.confirm.now_ms() / DAY_MS) as i64;
        *self.spent.entry((day, channel.to_owned())).or_default() += cents;
    }

    fn release_reserve(&mut self, intent: &IntentView) {
        if let Some(v) = self.reserved.get_mut(&intent.channel) {
            *v = v.saturating_sub(intent.cost_cents);
        }
    }
}

impl<T: Transport> IntentReview for Gate<T> {
    fn review(&mut self, intent: &IntentView) -> Result<Review, String> {
        let decision = self.decide(intent).map_err(|e| e.to_string())?;
        match decision.effect {
            Effect::Deny => Ok(Review::Deny { rule: decision.rule }),
            Effect::Confirm => {
                if intent.on_main {
                    let hash = binding_hash(&intent.channel, &intent.target, &intent.payload).to_string();
                    let req = self
                        .approval_for(std::slice::from_ref(intent), "main", &hash, 15 * 60 * 1000)
                        .map_err(|e| e.to_string())?;
                    self.queued.push(req);
                }
                Ok(Review::Confirm { rule: decision.rule })
            }
            Effect::Allow => {
                *self.reserved.entry(intent.channel.clone()).or_default() += intent.cost_cents;
                Ok(Review::Allow { rule: decision.rule })
            }
        }
    }

    fn dispatch(&mut self, intent: &IntentView) -> Result<Dispatch, String> {
        self.release_reserve(intent);
        let at_ms = self.confirm.now_ms() as i64;
        let actual = binding_hash(&intent.channel, &intent.target, &intent.payload);
        if actual != intent.payload_hash {
            return Ok(Dispatch { ok: false, detail: "payload hash mismatch".into(), at_ms });
        }
        let decision = self.decide(intent).map_err(|e| e.to_string())?;
        if decision.effect != Effect::Allow {
            return Ok(Dispatch { ok: false, detail: format!("policy is {}", decision.effect), at_ms });
        }
        let bytes = intent.payload.to_canonical_bytes();
        match self.transport.send(&Outbound {
            channel: &intent.channel,
            target: &intent.target,
            payload: &bytes,
            payload_hash: &actual.to_string(),
        }) {
            Ok(detail) => {
                self.add_spend(&intent.channel, intent.cost_cents);
                Ok(Dispatch { ok: true, detail: format!("{detail}; rule {}", decision.rule), at_ms })
            }
            Err(e) => Ok(Dispatch { ok: false, detail: e, at_ms }),
        }
    }

    fn commit_failed(&mut self) {
        self.reserved.clear();
    }
}

pub fn binding_hash(channel: &str, target: &str, payload: &FieldValue) -> Digest {
    Digest::of_value(&record([
        ("channel", Value::from(channel)),
        ("target", Value::from(target)),
        ("payload", payload.to_cbor()),
    ]))
}

/// Writes the post-approval status, and a receipt when an execution was attempted.
pub fn settle<S: LogStore>(
    graph: &mut Graph<S>,
    branch: &BranchName,
    view: &IntentView,
    item: &ReleaseItem,
) -> Result<(), Error> {
    let mut tx = graph
        .begin(branch, TxMeta::new(Actor::System).action("sys.egress.receipt@1"))
        .map_err(|e| Error::Bad(e.to_string()))?;
    let status = if !item.attempted {
        "denied"
    } else if item.ok {
        "executed"
    } else {
        "failed"
    };
    tx.update(graph, view.id, |o| {
        o.fields.insert("status".into(), FieldValue::text(status));
    })
    .map_err(|e| Error::Bad(e.to_string()))?;
    if item.attempted {
        let version = tx.peek(view.id).map(|o| o.version).ok_or_else(|| Error::Bad("intent vanished".into()))?;
        let adapter = view.channel.split(':').next().filter(|s| aos_types::id::is_slug(s)).unwrap_or("egress");
        let at = Timestamp::from_unix_ms(item.at_ms).unwrap_or_else(|| Timestamp::from_unix_ms(0).expect("epoch"));
        let detail: String = item.detail.chars().take(2000).collect();
        let mut receipt = NewObject::new("sys/EgressReceipt@1".parse().unwrap())
            .field("intent", FieldValue::text(view.id.to_string()))
            .field("channel", FieldValue::text(&view.channel))
            .field("target", FieldValue::text(&view.target))
            .field("payload_hash", FieldValue::text(view.payload_hash.to_string()))
            .field("ok", FieldValue::Bool(item.ok))
            .field("detail", FieldValue::text(detail))
            .derived_from(aos_types::ObjRef::at(view.id, version))
            .taint(Taint::External);
        receipt.sensitivity = view.sensitivity;
        receipt.origin =
            Origin::External { adapter: adapter.to_owned(), external_id: view.id.to_string(), fetched_at: at };
        tx.create(graph, receipt);
    }
    graph.commit(tx).map_err(|e| Error::Bad(e.to_string()))?;
    Ok(())
}

fn fail_all(intents: &[IntentView], at_ms: i64, detail: &str) -> Vec<ReleaseItem> {
    intents
        .iter()
        .map(|intent| ReleaseItem { id: intent.id, attempted: true, ok: false, detail: detail.to_owned(), at_ms })
        .collect()
}

fn when_inputs(intent: &IntentView) -> BTreeMap<String, FieldValue> {
    let lineage = BTreeMap::from([
        ("target_taint".into(), FieldValue::text(intent.target_taint.as_str())),
        ("payload_taint".into(), FieldValue::text(intent.payload_taint.as_str())),
    ]);
    let mut body = BTreeMap::new();
    body.insert("channel".into(), FieldValue::text(&intent.channel));
    body.insert("target".into(), FieldValue::text(&intent.target));
    body.insert("lineage".into(), FieldValue::Map(lineage));
    body.insert("cost_cents".into(), FieldValue::Int(i64::try_from(intent.cost_cents).unwrap_or(i64::MAX)));
    BTreeMap::from([("intent".into(), FieldValue::Map(body))])
}

fn rev_rank(s: &str) -> u8 {
    match s {
        "undo" => 0,
        "compensate" => 1,
        _ => 2,
    }
}

fn yaml_str(doc: &Yaml, key: &str) -> Result<String, Error> {
    Ok(doc
        .need(key)
        .map_err(|e| Error::Bad(e.to_string()))?
        .as_str()
        .map_err(|e| Error::Bad(e.to_string()))?
        .to_owned())
}
