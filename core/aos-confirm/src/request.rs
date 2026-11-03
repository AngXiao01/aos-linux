//! Canonical approval requests (SPEC §12.3). The OS key signs the request
//! bytes. The user signs `request_bytes || decision`.

use std::sync::Arc;

use crate::Error;
use aos_types::cbor::{self, Value};
use aos_types::codec::{self, SchemaError, record};
use aos_types::ulid::{Clock, Entropy, UlidGenerator};
use aos_types::{FieldValue, Timestamp};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

pub const SUMMARY_LABELS: &[&str] = &["通道", "目标", "代价", "外部可逆性", "载荷哈希", "标注", "出口"];

pub const AGENT_SUMMARY_MARK: &str = "agent 自述";

const TEXT_LIMIT: usize = 1000;
const LINE_LIMIT: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryLine {
    pub label: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub channel: String,
    pub target: String,
    pub payload_hash: String,
    pub preview: String,
    pub agent_summary: Option<String>,
    pub cost_cents: u64,
    pub external_reversibility: String,
    pub target_tainted: bool,
    pub payload_tainted: bool,
}

#[derive(Clone, Debug)]
pub struct PreviewInput {
    pub channel: String,
    pub target: String,
    pub payload: FieldValue,
    pub payload_hash: String,
    pub cost_cents: u64,
    pub external_reversibility: String,
    pub target_tainted: bool,
    pub payload_tainted: bool,
    pub agent_summary: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RequestInput {
    pub branch: String,
    pub diff_hash: String,
    pub ttl_ms: u64,
    pub items: Vec<PreviewInput>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub request_id: String,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub nonce: Vec<u8>,
    pub kind: String,
    pub summary: Vec<SummaryLine>,
    pub items: Vec<Item>,
    pub branch: String,
    pub diff_hash: String,
    pub os_signature: Vec<u8>,
}

pub struct ConfirmService {
    os: SigningKey,
    ids: UlidGenerator,
    clock: Arc<dyn Clock + Send + Sync>,
    entropy: Box<dyn Entropy + Send>,
}

impl ConfirmService {
    pub fn new(entropy: Box<dyn Entropy + Send>, clock: Arc<dyn Clock + Send + Sync>) -> Self {
        let mut entropy = entropy;
        let os = signing_key(&mut *entropy);
        ConfirmService { os, ids: UlidGenerator::new(), clock, entropy }
    }

    pub fn os_verifying(&self) -> VerifyingKey {
        VerifyingKey::from(&self.os)
    }

    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    pub fn egress(&mut self, input: RequestInput) -> Result<ApprovalRequest, Error> {
        if input.ttl_ms == 0 || input.branch.is_empty() || input.items.is_empty() {
            return Err(Error::Bad("approval request is incomplete".into()));
        }
        let items = input
            .items
            .iter()
            .map(|item| {
                Ok(Item {
                    channel: item.channel.clone(),
                    target: item.target.clone(),
                    payload_hash: item.payload_hash.clone(),
                    preview: preview_of(&item.payload)?,
                    agent_summary: item.agent_summary.clone(),
                    cost_cents: item.cost_cents,
                    external_reversibility: item.external_reversibility.clone(),
                    target_tainted: item.target_tainted,
                    payload_tainted: item.payload_tainted,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let summary = summary_of(&items);
        if summary.len() > LINE_LIMIT {
            return Err(Error::Bad("summary longer than 12 lines".into()));
        }
        for line in &summary {
            if !SUMMARY_LABELS.contains(&line.label.as_str()) {
                return Err(Error::Bad(format!("summary label {} is not generated here", line.label)));
            }
        }
        let mut nonce = vec![0u8; 16];
        self.entropy.fill(&mut nonce);
        let clock = Arc::clone(&self.clock);
        let request_id = self.ids.next(&*clock, &mut *self.entropy).map_err(|e| Error::Bad(e.to_string()))?.to_string();
        let created_at = Timestamp::from_unix_ms(clock.now_ms() as i64).ok_or_else(|| Error::Bad("clock".into()))?;
        let expires_at = Timestamp::from_unix_ms(created_at.unix_ms().saturating_add(input.ttl_ms as i64))
            .ok_or_else(|| Error::Bad("expiry".into()))?;
        let mut request = ApprovalRequest {
            request_id,
            created_at,
            expires_at,
            nonce,
            kind: "egress".into(),
            summary,
            items,
            branch: input.branch,
            diff_hash: input.diff_hash,
            os_signature: Vec::new(),
        };
        request.os_signature = sign_bytes(&self.os, &request.canonical_bytes());
        Ok(request)
    }

    pub fn resign(&self, request: &mut ApprovalRequest) {
        request.os_signature = sign_bytes(&self.os, &request.canonical_bytes());
    }
}

impl ApprovalRequest {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        cbor::encode(&self.body())
    }

    pub fn verify_os(&self, key: &VerifyingKey) -> Result<(), Error> {
        verify_bytes(key, &self.canonical_bytes(), &self.os_signature)
    }

    pub fn to_envelope(&self) -> Vec<u8> {
        cbor::encode(&record([
            ("request", Value::Bytes(self.canonical_bytes())),
            ("os_signature", Value::Bytes(self.os_signature.clone())),
        ]))
    }

    pub fn from_envelope(bytes: &[u8]) -> Result<Self, Error> {
        let value = cbor::decode(bytes).map_err(|e| Error::Bad(e.to_string()))?;
        let mut r = codec::Record::new(&value).map_err(|e| Error::Bad(e.to_string()))?;
        let request = r.req("request", cbor_bytes).map_err(|e| Error::Bad(e.to_string()))?.to_vec();
        let os_signature = r.req("os_signature", cbor_bytes).map_err(|e| Error::Bad(e.to_string()))?.to_vec();
        r.finish().map_err(|e| Error::Bad(e.to_string()))?;
        let mut parsed = Self::from_canonical(&request)?;
        if parsed.canonical_bytes() != request {
            return Err(Error::Bad("request is not canonical".into()));
        }
        parsed.os_signature = os_signature;
        Ok(parsed)
    }

    fn body(&self) -> Value {
        let summary = Value::Array(
            self.summary
                .iter()
                .map(|l| record([("label", Value::from(l.label.as_str())), ("value", Value::from(l.value.as_str()))]))
                .collect(),
        );
        record([
            ("request_id", Value::from(self.request_id.as_str())),
            ("created_at", Value::int(self.created_at.unix_ms())),
            ("expires_at", Value::int(self.expires_at.unix_ms())),
            ("nonce", Value::Bytes(self.nonce.clone())),
            ("kind", Value::from(self.kind.as_str())),
            ("summary", summary),
            ("items", Value::Array(self.items.iter().map(Item::to_cbor).collect())),
            ("branch", Value::from(self.branch.as_str())),
            ("diff_hash", Value::from(self.diff_hash.as_str())),
        ])
    }

    fn from_canonical(bytes: &[u8]) -> Result<Self, Error> {
        let value = cbor::decode(bytes).map_err(|e| Error::Bad(e.to_string()))?;
        let mut r = codec::Record::new(&value).map_err(|e| Error::Bad(e.to_string()))?;
        let request = ApprovalRequest {
            request_id: req_text(&mut r, "request_id")?,
            created_at: timestamp(r.req("created_at", codec::int).map_err(|e| Error::Bad(e.to_string()))?)?,
            expires_at: timestamp(r.req("expires_at", codec::int).map_err(|e| Error::Bad(e.to_string()))?)?,
            nonce: r.req("nonce", cbor_bytes).map_err(|e| Error::Bad(e.to_string()))?.to_vec(),
            kind: req_text(&mut r, "kind")?,
            summary: summary_from(r.req("summary", codec::array).map_err(|e| Error::Bad(e.to_string()))?)?,
            items: items_from(r.req("items", codec::array).map_err(|e| Error::Bad(e.to_string()))?)?,
            branch: req_text(&mut r, "branch")?,
            diff_hash: req_text(&mut r, "diff_hash")?,
            os_signature: Vec::new(),
        };
        r.finish().map_err(|e| Error::Bad(e.to_string()))?;
        Ok(request)
    }
}

impl Item {
    fn to_cbor(&self) -> Value {
        record([
            ("channel", Value::from(self.channel.as_str())),
            ("target", Value::from(self.target.as_str())),
            ("payload_hash", Value::from(self.payload_hash.as_str())),
            ("preview", Value::from(self.preview.as_str())),
            ("agent_summary", self.agent_summary.as_deref().map(Value::from).unwrap_or(Value::Null)),
            ("cost_cents", Value::Unsigned(self.cost_cents)),
            ("external_reversibility", Value::from(self.external_reversibility.as_str())),
            ("target_tainted", Value::Bool(self.target_tainted)),
            ("payload_tainted", Value::Bool(self.payload_tainted)),
        ])
    }
}

pub fn summary_of(items: &[Item]) -> Vec<SummaryLine> {
    let mut lines = Vec::new();
    if items.len() == 1 {
        let item = &items[0];
        lines.push(line("通道", &item.channel));
        lines.push(line("目标", &item.target));
        lines.push(line("代价", &money(item.cost_cents)));
        lines.push(line("外部可逆性", &item.external_reversibility));
        lines.push(line("载荷哈希", &item.payload_hash));
    } else {
        lines.push(line("出口", &format!("{} 项", items.len())));
        for (i, item) in items.iter().take(LINE_LIMIT - 2).enumerate() {
            lines.push(line("出口", &format!("{}. {} → {}", i + 1, item.channel, item.target)));
        }
    }
    if items.iter().any(|i| i.target_tainted) {
        lines.push(line("标注", "目标来自外部内容"));
    }
    lines
}

fn line(label: &str, value: &str) -> SummaryLine {
    SummaryLine { label: label.to_owned(), value: value.to_owned() }
}

fn money(cents: u64) -> String {
    format!("{}.{:02} CNY", cents / 100, cents % 100)
}

pub fn preview_of(payload: &FieldValue) -> Result<String, Error> {
    let FieldValue::Map(map) = payload else {
        return Err(Error::Bad("payload is not a map".into()));
    };
    let kind = match map.get("kind") {
        Some(FieldValue::Text(s)) => s.as_str(),
        _ => return Err(Error::Bad("payload.kind is missing".into())),
    };
    match kind {
        "text" => match map.get("body") {
            Some(FieldValue::Text(s)) => Ok(truncate_text(s)),
            _ => Err(Error::Bad("text payload has no body".into())),
        },
        "files" => files_preview(map.get("files").ok_or_else(|| Error::Bad("files missing".into()))?),
        "structured" => structured_preview(map.get("fields").ok_or_else(|| Error::Bad("fields missing".into()))?),
        other => Err(Error::Bad(format!("unknown payload kind {other}"))),
    }
}

fn truncate_text(body: &str) -> String {
    let count = body.chars().count();
    if count <= TEXT_LIMIT {
        return body.to_owned();
    }
    let head: String = body.chars().take(TEXT_LIMIT).collect();
    format!("{head}\n… 共 {count} 字")
}

fn files_preview(files: &FieldValue) -> Result<String, Error> {
    let FieldValue::List(list) = files else {
        return Err(Error::Bad("files is not a list".into()));
    };
    let mut lines = Vec::new();
    for file in list.iter().take(LINE_LIMIT) {
        let FieldValue::Map(map) = file else {
            return Err(Error::Bad("file is not a map".into()));
        };
        let name = match map.get("name") {
            Some(FieldValue::Text(s)) => s.as_str(),
            _ => return Err(Error::Bad("file name".into())),
        };
        let size = match map.get("size") {
            Some(FieldValue::Int(n)) if *n >= 0 => *n as u64,
            _ => return Err(Error::Bad("file size".into())),
        };
        let hash = match map.get("blob") {
            Some(FieldValue::Text(s)) => short_hash(s),
            Some(FieldValue::Blob(d)) => short_hash(&d.to_string()),
            _ => return Err(Error::Bad("file blob".into())),
        };
        lines.push(format!("{name} {size}B {hash}"));
    }
    if list.len() > LINE_LIMIT {
        lines.pop();
        lines.push(format!("其余 {} 个文件", list.len() - (LINE_LIMIT - 1)));
    }
    Ok(lines.join("\n"))
}

fn short_hash(text: &str) -> String {
    text.strip_prefix("sha256:").unwrap_or(text).chars().take(12).collect()
}

fn structured_preview(fields: &FieldValue) -> Result<String, Error> {
    let mut flat = Vec::new();
    flatten("", fields, &mut flat)?;
    flat.sort();
    let total = flat.len();
    let mut lines: Vec<String> = flat.into_iter().take(LINE_LIMIT).map(|(k, v)| format!("{k}: {v}")).collect();
    if total > LINE_LIMIT {
        lines.pop();
        lines.push(format!("其余 {} 项", total - (LINE_LIMIT - 1)));
    }
    Ok(lines.join("\n"))
}

fn flatten(prefix: &str, value: &FieldValue, out: &mut Vec<(String, String)>) -> Result<(), Error> {
    match value {
        FieldValue::Map(map) => {
            for (k, child) in map {
                let path = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                flatten(&path, child, out)?;
            }
            Ok(())
        }
        other => {
            out.push((prefix.to_owned(), display_leaf(other)?));
            Ok(())
        }
    }
}

fn display_leaf(v: &FieldValue) -> Result<String, Error> {
    Ok(match v {
        FieldValue::Text(s) => truncate_text(s),
        FieldValue::Int(n) => n.to_string(),
        FieldValue::Bool(b) => b.to_string(),
        FieldValue::Float(f) => f.0.to_string(),
        FieldValue::Blob(d) => short_hash(&d.to_string()),
        FieldValue::Ref(r) => r.to_string(),
        FieldValue::Timestamp(t) => t.to_string(),
        FieldValue::Null => "null".into(),
        FieldValue::List(_) | FieldValue::Map(_) => return Err(Error::Bad("structured leaf".into())),
    })
}

pub fn sign_bytes(key: &SigningKey, bytes: &[u8]) -> Vec<u8> {
    let sig: Signature = key.sign(bytes);
    sig.to_bytes().into_iter().collect()
}

pub fn verify_bytes(key: &VerifyingKey, bytes: &[u8], signature: &[u8]) -> Result<(), Error> {
    let sig = Signature::from_slice(signature).map_err(|_| Error::Signature)?;
    key.verify(bytes, &sig).map_err(|_| Error::Signature)
}

pub fn trust_id(key: &VerifyingKey) -> String {
    let point = key.to_encoded_point(true);
    let mut hex = String::with_capacity(point.as_bytes().len() * 2);
    for b in point.as_bytes() {
        hex.push(char::from(b"0123456789abcdef"[(b >> 4) as usize]));
        hex.push(char::from(b"0123456789abcdef"[(b & 0xf) as usize]));
    }
    format!("iphone:{hex}")
}

pub fn approval_message(request_bytes: &[u8], decision: &str) -> Vec<u8> {
    let mut msg = request_bytes.to_vec();
    msg.extend(decision.as_bytes());
    msg
}

pub(crate) fn signing_key(entropy: &mut dyn Entropy) -> SigningKey {
    loop {
        let mut buf = [0u8; 32];
        entropy.fill(&mut buf);
        if let Ok(key) = SigningKey::from_slice(&buf) {
            return key;
        }
    }
}

pub(crate) fn cbor_bytes(v: &Value) -> Result<&[u8], SchemaError> {
    v.as_bytes().ok_or_else(|| SchemaError::new("expected byte string"))
}

fn timestamp(ms: i64) -> Result<Timestamp, Error> {
    Timestamp::from_unix_ms(ms).ok_or_else(|| Error::Bad("timestamp".into()))
}

fn summary_from(values: &[Value]) -> Result<Vec<SummaryLine>, Error> {
    values
        .iter()
        .map(|v| {
            let mut r = codec::Record::new(v).map_err(|e| Error::Bad(e.to_string()))?;
            let line = SummaryLine { label: req_text(&mut r, "label")?, value: req_text(&mut r, "value")? };
            r.finish().map_err(|e| Error::Bad(e.to_string()))?;
            Ok(line)
        })
        .collect()
}

fn items_from(values: &[Value]) -> Result<Vec<Item>, Error> {
    values
        .iter()
        .map(|v| {
            let mut r = codec::Record::new(v).map_err(|e| Error::Bad(e.to_string()))?;
            let item = Item {
                channel: req_text(&mut r, "channel")?,
                target: req_text(&mut r, "target")?,
                payload_hash: req_text(&mut r, "payload_hash")?,
                preview: req_text(&mut r, "preview")?,
                agent_summary: opt_text(&mut r, "agent_summary")?,
                cost_cents: r.req("cost_cents", codec::uint).map_err(|e| Error::Bad(e.to_string()))?,
                external_reversibility: req_text(&mut r, "external_reversibility")?,
                target_tainted: r.req("target_tainted", codec::boolean).map_err(|e| Error::Bad(e.to_string()))?,
                payload_tainted: r.req("payload_tainted", codec::boolean).map_err(|e| Error::Bad(e.to_string()))?,
            };
            r.finish().map_err(|e| Error::Bad(e.to_string()))?;
            Ok(item)
        })
        .collect()
}

fn req_text(r: &mut codec::Record<'_>, key: &'static str) -> Result<String, Error> {
    Ok(r.req(key, codec::text).map_err(|e| Error::Bad(e.to_string()))?.to_owned())
}

fn opt_text(r: &mut codec::Record<'_>, key: &'static str) -> Result<Option<String>, Error> {
    match r.opt(key, |v| Ok(v.clone())).map_err(|e| Error::Bad(e.to_string()))? {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Text(s)) => Ok(Some(s)),
        Some(_) => Err(Error::Bad(format!("{key} must be text or null"))),
    }
}
