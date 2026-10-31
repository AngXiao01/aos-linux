//! Signed capability grants (SPEC §9.1). The signature covers the canonical
//! CBOR of every field except `signature`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use aos_types::cbor::{self, Value};
use aos_types::codec::{self, FromCbor, Record, SchemaError, ToCbor, record};
use aos_types::id::{Actor, ObjectId};
use aos_types::time::Timestamp;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

use crate::pattern::{self, PatternError};

pub const ROOT_ID: &str = "cap:user-root";
pub const TASK_CREATE: &str = "sys.task.create";

/// Remaining or granted budget. Time is milliseconds and money is cents
/// (0.01 CNY) so deduction is exact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub steps: u64,
    pub cpu_ms: u64,
    pub gpu_ms: u64,
    pub money_cents: u64,
    pub egress_channels: BTreeSet<String>,
}

impl Limits {
    pub fn none() -> Self {
        Limits { steps: 0, cpu_ms: 0, gpu_ms: 0, money_cents: 0, egress_channels: BTreeSet::new() }
    }

    pub fn within(&self, parent: &Limits) -> bool {
        self.steps <= parent.steps
            && self.cpu_ms <= parent.cpu_ms
            && self.gpu_ms <= parent.gpu_ms
            && self.money_cents <= parent.money_cents
            && self.egress_channels.iter().all(|c| parent.egress_channels.iter().any(|p| pattern::channel_within(p, c)))
    }

    pub fn checked_sub(&self, cost: &crate::Cost) -> Option<Limits> {
        Some(Limits {
            steps: self.steps.checked_sub(cost.steps)?,
            cpu_ms: self.cpu_ms.checked_sub(cost.cpu_ms)?,
            gpu_ms: self.gpu_ms.checked_sub(cost.gpu_ms)?,
            money_cents: self.money_cents.checked_sub(cost.money_cents)?,
            egress_channels: self.egress_channels.clone(),
        })
    }

    pub fn add(&self, cost: &crate::Cost) -> Limits {
        Limits {
            steps: self.steps.saturating_add(cost.steps),
            cpu_ms: self.cpu_ms.saturating_add(cost.cpu_ms),
            gpu_ms: self.gpu_ms.saturating_add(cost.gpu_ms),
            money_cents: self.money_cents.saturating_add(cost.money_cents),
            egress_channels: self.egress_channels.clone(),
        }
    }
}

impl ToCbor for Limits {
    fn to_cbor(&self) -> Value {
        record([
            ("steps", Value::Unsigned(self.steps)),
            ("cpu_ms", Value::Unsigned(self.cpu_ms)),
            ("gpu_ms", Value::Unsigned(self.gpu_ms)),
            ("money_cents", Value::Unsigned(self.money_cents)),
            ("egress_channels", Value::Array(self.egress_channels.iter().map(|c| Value::from(c.as_str())).collect())),
        ])
    }
}

impl FromCbor for Limits {
    fn from_cbor(v: &Value) -> Result<Self, SchemaError> {
        let mut r = Record::new(v)?;
        let limits = Limits {
            steps: r.req("steps", codec::uint)?,
            cpu_ms: r.req("cpu_ms", codec::uint)?,
            gpu_ms: r.req("gpu_ms", codec::uint)?,
            money_cents: r.req("money_cents", codec::uint)?,
            egress_channels: r.req("egress_channels", |v| {
                let mut set = BTreeSet::new();
                for (i, item) in codec::array(v)?.iter().enumerate() {
                    let s = codec::text(item).map_err(|e| e.within(i))?.to_owned();
                    if !set.insert(s.clone()) {
                        return Err(SchemaError::new("duplicate channel").within(i));
                    }
                }
                Ok(set)
            })?,
        };
        r.finish()?;
        Ok(limits)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    pub id: String,
    pub subject: Actor,
    pub rights: BTreeSet<String>,
    pub object_scope: BTreeMap<String, BTreeSet<ObjectId>>,
    pub limits: Limits,
    pub expires_at: Timestamp,
    pub parent: Option<String>,
    pub signature: Vec<u8>,
}

impl Capability {
    pub fn is_root(&self) -> bool {
        self.id == ROOT_ID
    }

    pub fn allows_right(&self, right: &str) -> bool {
        self.rights.iter().any(|g| pattern::right_covers(g, right))
    }

    pub fn allows_channel(&self, channel: &str) -> bool {
        self.limits.egress_channels.iter().any(|g| pattern::channel_covers(g, channel))
    }

    /// Structural attenuation against `parent`'s grant (not its remaining
    /// budget). Empty parent scope is unrestricted; a child may only narrow it.
    pub fn within(&self, parent: &Capability) -> bool {
        self.rights.iter().all(|r| parent.rights.iter().any(|g| pattern::right_within(g, r)))
            && self.limits.within(&parent.limits)
            && self.expires_at <= parent.expires_at
            && scope_within(&parent.object_scope, &self.object_scope)
            && self.parent.as_deref() == Some(parent.id.as_str())
    }

    pub fn grants_task_create(&self) -> bool {
        self.rights.iter().any(|r| pattern::covers_task_create(r))
    }

    pub(crate) fn sign(mut self, key: &SigningKey) -> Self {
        let sig: Signature = key.sign(&self.unsigned_bytes());
        self.signature = sig.to_bytes().into_iter().collect();
        self
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), SchemaError> {
        let sig = Signature::from_slice(&self.signature).map_err(|_| SchemaError::new("bad signature"))?;
        key.verify(&self.unsigned_bytes(), &sig).map_err(|_| SchemaError::new("signature mismatch"))
    }

    fn unsigned_bytes(&self) -> Vec<u8> {
        cbor::encode(&self.unsigned())
    }

    fn unsigned(&self) -> Value {
        let rights = Value::Array(self.rights.iter().map(|r| Value::from(r.as_str())).collect());
        let scope = Value::Map(
            self.object_scope
                .iter()
                .map(|(k, ids)| {
                    let list = Value::Array(ids.iter().map(|id| Value::from(id.to_string())).collect());
                    (Value::from(k.as_str()), list)
                })
                .collect(),
        );
        record([
            ("id", Value::from(self.id.as_str())),
            ("subject", Value::from(self.subject.to_string())),
            ("rights", rights),
            ("object_scope", scope),
            ("limits", self.limits.to_cbor()),
            ("expires_at", Value::int(self.expires_at.unix_ms())),
            ("parent", self.parent.as_ref().map(|p| Value::from(p.as_str())).unwrap_or(Value::Null)),
        ])
    }
}

fn scope_within(parent: &BTreeMap<String, BTreeSet<ObjectId>>, child: &BTreeMap<String, BTreeSet<ObjectId>>) -> bool {
    if parent.is_empty() {
        return true;
    }
    parent.iter().all(|(k, ids)| child.get(k).is_some_and(|c| c.is_subset(ids)))
}

impl ToCbor for Capability {
    fn to_cbor(&self) -> Value {
        let mut v = self.unsigned();
        let Value::Map(map) = &mut v else { unreachable!() };
        map.insert(Value::from("signature"), Value::Bytes(self.signature.clone()));
        v
    }
}

impl FromCbor for Capability {
    fn from_cbor(v: &Value) -> Result<Self, SchemaError> {
        let mut r = Record::new(v)?;
        let cap = Capability {
            id: r.req("id", codec::text)?.to_owned(),
            subject: r.req("subject", codec::parsed)?,
            rights: r.req("rights", string_set)?,
            object_scope: r.req("object_scope", scope_from)?,
            limits: r.req("limits", Limits::from_cbor)?,
            expires_at: r.req("expires_at", timestamp)?,
            parent: r.req("parent", |v| match v {
                Value::Null => Ok(None),
                Value::Text(s) => Ok(Some(s.clone())),
                _ => Err(SchemaError::new("expected text or null")),
            })?,
            signature: r.req("signature", codec_bytes)?.to_vec(),
        };
        r.finish()?;
        validate_shape(&cap).map_err(|e| SchemaError::new(e.0))?;
        Ok(cap)
    }
}

fn codec_bytes(v: &Value) -> Result<&[u8], SchemaError> {
    v.as_bytes().ok_or_else(|| SchemaError::new("expected byte string"))
}

fn timestamp(v: &Value) -> Result<Timestamp, SchemaError> {
    Timestamp::from_unix_ms(codec::int(v)?).ok_or_else(|| SchemaError::new("timestamp out of range"))
}

fn string_set(v: &Value) -> Result<BTreeSet<String>, SchemaError> {
    let mut set = BTreeSet::new();
    for (i, item) in codec::array(v)?.iter().enumerate() {
        let s = codec::text(item).map_err(|e| e.within(i))?.to_owned();
        if !set.insert(s) {
            return Err(SchemaError::new("duplicate").within(i));
        }
    }
    Ok(set)
}

fn scope_from(v: &Value) -> Result<BTreeMap<String, BTreeSet<ObjectId>>, SchemaError> {
    let mut out = BTreeMap::new();
    for (k, val) in codec::text_entries(v)? {
        let mut ids = BTreeSet::new();
        for (i, item) in codec::array(val).map_err(|e| e.within(k))?.iter().enumerate() {
            let id: ObjectId = codec::parsed(item).map_err(|e| e.within(i).within(k))?;
            if !ids.insert(id) {
                return Err(SchemaError::new("duplicate id").within(i).within(k));
            }
        }
        out.insert(k.to_owned(), ids);
    }
    Ok(out)
}

pub fn validate_shape(cap: &Capability) -> Result<(), PatternError> {
    if cap.id != ROOT_ID && !(cap.id.starts_with("cap:") && cap.id[4..].parse::<aos_types::Ulid>().is_ok()) {
        return Err(PatternError(format!("invalid capability id {}", cap.id)));
    }
    if cap.rights.is_empty() {
        return Err(PatternError("rights are empty".into()));
    }
    for r in &cap.rights {
        pattern::parse_right(r)?;
    }
    for c in &cap.limits.egress_channels {
        pattern::parse_channel(c)?;
    }
    for key in cap.object_scope.keys() {
        if !aos_types::id::is_ident(key) {
            return Err(PatternError(format!("invalid scope key {key}")));
        }
    }
    Ok(())
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}
