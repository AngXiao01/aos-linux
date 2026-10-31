//! State one action invocation can see: its transaction, its declaration and
//! the objects it has read.

use std::collections::{BTreeMap, BTreeSet};

use aos_branch::{Graph, NewObject, Tx};
use aos_cap::CapabilityService;
use aos_log::LogStore;
use aos_types::cbor::{self, Value};
use aos_types::codec::{self, FromCbor, ToCbor};
use aos_types::schema::{TypeDecl, TypeRef};
use aos_types::{Actor, Digest, FieldValue, ObjRef, Object, ObjectId, Origin, Sensitivity, Taint};

use crate::catalog::Catalog;
use crate::decl::ActionDecl;
use crate::query;

pub const NOT_FOUND: i32 = -1;
pub const BAD_ARG: i32 = -2;
pub const CONFLICT: i32 = -3;
pub const DENIED: i32 = -4;

#[derive(Clone, Debug)]
pub struct Violation {
    pub kind: &'static str,
    pub detail: String,
}

pub enum Fail {
    Code(i32),
    Violation(Violation),
}

pub enum HostValue {
    Bytes(Vec<u8>),
    Status(i32),
}

#[derive(Clone, Debug)]
struct ReadNote {
    id: ObjectId,
    version: u64,
    taint: Taint,
    sensitivity: Sensitivity,
}

#[derive(Default)]
pub struct BlobStore {
    blobs: BTreeMap<Digest, Vec<u8>>,
}

impl BlobStore {
    pub fn write(&mut self, bytes: &[u8]) -> Digest {
        let hash = Digest::of(bytes);
        self.blobs.entry(hash).or_insert_with(|| bytes.to_vec());
        hash
    }

    pub fn read(&self, hash: &Digest, offset: u64, len: u64) -> Option<Vec<u8>> {
        let data = self.blobs.get(hash)?;
        let start = usize::try_from(offset).ok()?;
        let len = usize::try_from(len).ok()?;
        let end = start.checked_add(len)?;
        if end > data.len() {
            return None;
        }
        Some(data[start..end].to_vec())
    }
}

pub struct Ctx<'a, S: LogStore> {
    pub graph: &'a Graph<S>,
    pub tx: &'a mut Tx,
    pub catalog: &'a Catalog,
    pub action: &'a ActionDecl,
    pub blobs: &'a mut BlobStore,
    pub caps: &'a mut CapabilityService,
    pub cap_id: &'a str,
    pub inputs: BTreeMap<String, FieldValue>,
    pub literal_taint: Taint,
    pub charged: aos_cap::Cost,
    reads: Vec<ReadNote>,
    created: BTreeSet<ObjectId>,
    literal_intents: Vec<ObjectId>,
    pub logs: Vec<(i32, String)>,
}

impl<'a, S: LogStore> Ctx<'a, S> {
    pub fn new(
        graph: &'a Graph<S>,
        tx: &'a mut Tx,
        catalog: &'a Catalog,
        action: &'a ActionDecl,
        blobs: &'a mut BlobStore,
        caps: &'a mut CapabilityService,
        cap_id: &'a str,
        inputs: BTreeMap<String, FieldValue>,
        literal_taint: Taint,
        charged: aos_cap::Cost,
    ) -> Self {
        Ctx {
            graph,
            tx,
            catalog,
            action,
            blobs,
            caps,
            cap_id,
            inputs,
            literal_taint,
            charged,
            reads: Vec::new(),
            created: BTreeSet::new(),
            literal_intents: Vec::new(),
            logs: Vec::new(),
        }
    }

    pub fn input(&mut self, name: &str) -> Result<HostValue, Fail> {
        let value = self.inputs.get(name).ok_or(Fail::Code(NOT_FOUND))?;
        Ok(HostValue::Bytes(value.to_canonical_bytes()))
    }

    pub fn read(&mut self, id: ObjectId) -> Result<HostValue, Fail> {
        let obj = self.tx.read(self.graph, id).ok_or(Fail::Code(NOT_FOUND))?;
        self.ensure_read(&obj.type_ref.name)?;
        self.note(&obj);
        Ok(HostValue::Bytes(obj.to_canonical_bytes()))
    }

    pub fn write(&mut self, id: ObjectId, expected: u64, patch: &Value) -> Result<HostValue, Fail> {
        let current = self.tx.read(self.graph, id).ok_or(Fail::Code(NOT_FOUND))?;
        self.ensure_write(&current.type_ref.name)?;
        if !self.created.contains(&id) {
            self.note(&current);
        }
        if current.version != expected {
            return Err(Fail::Code(CONFLICT));
        }
        let mut obj = current;
        let fields = patch.as_map().ok_or(Fail::Code(BAD_ARG))?;
        let decl = self.decl(&obj.type_ref)?;
        for (key, value) in fields.iter() {
            let name = key.as_text().ok_or(Fail::Code(BAD_ARG))?.to_owned();
            let parsed = FieldValue::from_cbor(value).map_err(|_| Fail::Code(BAD_ARG))?;
            if decl.fields.contains_key(&name) {
                obj.fields.insert(name, parsed);
            } else {
                obj.extra.insert(name, parsed);
            }
        }
        self.check(&obj)?;
        let version = obj.version;
        self.tx.put(self.graph, obj, Some(version)).map_err(|_| Fail::Code(CONFLICT))?;
        let new_version = self.tx.peek(id).map(|o| o.version).ok_or(Fail::Code(BAD_ARG))?;
        i32::try_from(new_version).map(HostValue::Status).map_err(|_| Fail::Code(BAD_ARG))
    }

    pub fn create(&mut self, type_name: &str, fields: &Value) -> Result<HostValue, Fail> {
        let type_ref: TypeRef = type_name.parse().map_err(|_| Fail::Code(BAD_ARG))?;
        self.ensure_write(&type_ref.name)?;
        let decl = self.decl(&type_ref)?;
        let map = fields.as_map().ok_or(Fail::Code(BAD_ARG))?;
        let mut obj = NewObject::new(type_ref.clone());
        for (key, value) in map.iter() {
            let name = key.as_text().ok_or(Fail::Code(BAD_ARG))?.to_owned();
            let parsed = FieldValue::from_cbor(value).map_err(|_| Fail::Code(BAD_ARG))?;
            if decl.fields.contains_key(&name) {
                obj.fields.insert(name, parsed);
            } else {
                obj.extra.insert(name, parsed);
            }
        }
        let probe = probe_object(&type_ref, &obj);
        decl.check_object(&probe, Some(&self.refs())).map_err(|_| Fail::Code(BAD_ARG))?;
        let id = self.tx.create(self.graph, obj);
        self.created.insert(id);
        Ok(HostValue::Bytes(id.to_string().into_bytes()))
    }

    pub fn query(&mut self, query_cbor: &Value) -> Result<HostValue, Fail> {
        let from = query_cbor
            .as_map()
            .and_then(|m| m.get(&Value::from("from")))
            .and_then(|v| v.as_text())
            .ok_or(Fail::Code(BAD_ARG))?;
        let type_name: TypeNameOwned = parse_type_name(from)?;
        self.ensure_read(&type_name)?;
        let mut objects = Vec::new();
        let mut ids = self.graph.object_ids(self.tx.branch()).map_err(|e| Fail::Code(bad_arg_err(e.to_string())))?;
        for id in self.tx.staged_ids() {
            if !ids.contains(id) {
                ids.push(*id);
            }
        }
        for id in ids {
            if let Some(obj) = self.tx.read(self.graph, id) {
                if !obj.tombstone && obj.type_ref.name == type_name {
                    self.note(&obj);
                }
                objects.push(obj);
            }
        }
        let result = query::execute(&objects, query_cbor).map_err(|e| Fail::Code(bad_arg_err(e)))?;
        Ok(HostValue::Bytes(cbor::encode(&result)))
    }

    pub fn blob_write(&mut self, bytes: &[u8]) -> Result<HostValue, Fail> {
        let hash = self.blobs.write(bytes);
        Ok(HostValue::Bytes(hash.to_string().into_bytes()))
    }

    pub fn blob_read(&mut self, hash: &Digest, offset: u64, len: u64) -> Result<HostValue, Fail> {
        let bytes = self.blobs.read(hash, offset, len).ok_or(Fail::Code(NOT_FOUND))?;
        Ok(HostValue::Bytes(bytes))
    }

    pub fn intent(&mut self, body: &Value) -> Result<HostValue, Fail> {
        let mut r = codec::Record::new(body).map_err(|_| Fail::Code(BAD_ARG))?;
        let channel = r.req("channel", codec::text).map_err(|_| Fail::Code(BAD_ARG))?.to_owned();
        let target_v = r.req("target", |v| Ok(v.clone())).map_err(|_| Fail::Code(BAD_ARG))?;
        let payload_v = r.req("payload", |v| Ok(v.clone())).map_err(|_| Fail::Code(BAD_ARG))?;
        let reversibility =
            r.opt("reversibility", codec::text).map_err(|_| Fail::Code(BAD_ARG))?.unwrap_or("irreversible").to_owned();
        let cost_cents = r.opt("cost_cents", codec::uint).map_err(|_| Fail::Code(BAD_ARG))?.unwrap_or(0);
        let summary = r.opt("agent_summary", codec::text).map_err(|_| Fail::Code(BAD_ARG))?.map(str::to_owned);
        r.finish().map_err(|_| Fail::Code(BAD_ARG))?;
        if !matches!(reversibility.as_str(), "undo" | "compensate" | "irreversible") {
            return Err(Fail::Code(BAD_ARG));
        }
        if !self.action.allows_channel(&channel) {
            return Err(Fail::Violation(Violation { kind: "undeclared_effect", detail: format!("channel {channel}") }));
        }
        let cap = self.caps.get(self.cap_id).ok_or(Fail::Code(DENIED))?;
        if !cap.allows_channel(&channel) {
            return Err(Fail::Violation(Violation {
                kind: "capability",
                detail: format!("channel {channel} is outside the token"),
            }));
        }
        if cost_cents > 0 {
            let extra = aos_cap::Cost { money_cents: cost_cents, ..aos_cap::Cost::zero() };
            self.caps.try_charge(self.cap_id, &extra).map_err(|e| Fail::Code(bad_arg_err(e.to_string())))?;
            self.charged.money_cents = self.charged.money_cents.saturating_add(cost_cents);
        }
        let (target, target_taint, literal) = self.resolve_target(&target_v)?;
        let payload = FieldValue::from_cbor(&payload_v).map_err(|_| Fail::Code(BAD_ARG))?;
        let payload_taint = self.payload_taint(&payload)?;
        let payload_bytes = payload.to_canonical_bytes();
        let payload_hash = Digest::of_value(&codec::record([
            ("channel", Value::from(channel.as_str())),
            ("target", Value::from(target.as_str())),
            ("payload", payload.to_cbor()),
        ]));
        let blob = self.blobs.write(&payload_bytes);
        let tainted = self.tainted_inputs();
        let type_ref = "sys/EgressIntent@1".parse::<TypeRef>().unwrap();
        let mut new = NewObject::new(type_ref);
        new.fields.insert("channel".into(), FieldValue::text(channel));
        new.fields.insert("target".into(), FieldValue::text(target));
        new.fields.insert("payload".into(), FieldValue::Blob(blob));
        if let Some(summary) = summary {
            new.fields.insert("agent_summary".into(), FieldValue::text(summary));
        }
        new.fields.insert("payload_hash".into(), FieldValue::text(payload_hash.to_string()));
        new.fields.insert("external_reversibility".into(), FieldValue::text(reversibility));
        new.fields
            .insert("cost_cents".into(), FieldValue::Int(i64::try_from(cost_cents).map_err(|_| Fail::Code(BAD_ARG))?));
        new.fields.insert("target_taint".into(), FieldValue::text(target_taint.as_str()));
        new.fields.insert("payload_taint".into(), FieldValue::text(payload_taint.as_str()));
        new.fields.insert("tainted_inputs".into(), FieldValue::List(tainted));
        new.fields.insert("status".into(), FieldValue::text("pending"));
        new.sensitivity = Sensitivity::Internal;
        let id = self.tx.create(self.graph, new);
        self.created.insert(id);
        self.tx.add_intent(id);
        if literal {
            self.literal_intents.push(id);
        }
        self.check_id(id)?;
        Ok(HostValue::Bytes(id.to_string().into_bytes()))
    }

    pub fn job(&mut self, body: &Value) -> Result<HostValue, Fail> {
        let mut r = codec::Record::new(body).map_err(|_| Fail::Code(BAD_ARG))?;
        let kind = r.req("kind", codec::text).map_err(|_| Fail::Code(BAD_ARG))?.to_owned();
        let spec = r.req("spec", codec::text).map_err(|_| Fail::Code(BAD_ARG))?.to_owned();
        let channel = r.opt("channel", codec::text).map_err(|_| Fail::Code(BAD_ARG))?.map(str::to_owned);
        r.finish().map_err(|_| Fail::Code(BAD_ARG))?;
        if !matches!(kind.as_str(), "local" | "remote") {
            return Err(Fail::Code(BAD_ARG));
        }
        if kind == "remote" {
            let channel = channel.ok_or(Fail::Code(BAD_ARG))?;
            let intent = codec::record([
                ("channel", Value::from(channel.as_str())),
                ("target", Value::Map(cbor::Map::from_iter([(Value::from("literal"), Value::from(spec.as_str()))]))),
                ("payload", codec::record([("kind", Value::from("text")), ("body", Value::from(spec.as_str()))])),
                ("reversibility", Value::from("compensate")),
                ("agent_summary", Value::from("remote job")),
            ]);
            self.intent(&intent)?;
        }
        let type_ref = "sys/Job@1".parse::<TypeRef>().unwrap();
        let mut new = NewObject::new(type_ref);
        new.fields.insert("state".into(), FieldValue::text("queued"));
        new.fields.insert("kind".into(), FieldValue::text(kind));
        new.fields.insert("spec".into(), FieldValue::text(spec));
        new.sensitivity = Sensitivity::Internal;
        let id = self.tx.create(self.graph, new);
        self.created.insert(id);
        self.check_id(id)?;
        Ok(HostValue::Bytes(id.to_string().into_bytes()))
    }

    pub fn log(&mut self, level: i32, msg: String) -> Result<HostValue, Fail> {
        self.logs.push((level, msg));
        Ok(HostValue::Status(0))
    }

    /// Sets provenance from the read set (SPEC §10) and refreshes literal
    /// intent lineage now that the read set is complete.
    pub fn finish(&mut self) -> Result<(), String> {
        let taint = self.read_taint();
        let derived: BTreeSet<ObjRef> = self.reads.iter().map(|r| ObjRef::at(r.id, r.version)).collect();
        let sensitivity = self.reads.iter().map(|r| r.sensitivity).max().unwrap_or(Sensitivity::Private);
        let tainted = self.tainted_inputs();
        let literal = self.literal_intents.clone();
        for id in literal {
            self.tx
                .update(self.graph, id, |o| {
                    o.fields.insert("target_taint".into(), FieldValue::text(taint.as_str()));
                    o.fields.insert("tainted_inputs".into(), FieldValue::List(tainted.clone()));
                })
                .map_err(|e| e.to_string())?;
        }
        let ids: Vec<ObjectId> = self.tx.staged_ids().to_vec();
        for id in ids {
            self.tx
                .update(self.graph, id, |o| {
                    o.provenance.taint = taint;
                    o.provenance.derived_from = derived.clone();
                    o.provenance.origin = Origin::Internal;
                    o.sensitivity = sensitivity;
                    o.provenance.actor = Actor::System; // stage() overwrites this with the tx actor
                })
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn read_taint(&self) -> Taint {
        let from_reads = self.reads.iter().map(|r| r.taint).max().unwrap_or(Taint::Clean);
        from_reads.max(self.literal_taint)
    }

    fn tainted_inputs(&self) -> Vec<FieldValue> {
        self.reads
            .iter()
            .filter(|r| r.taint == Taint::External)
            .map(|r| FieldValue::text(ObjRef::at(r.id, r.version).to_string()))
            .collect()
    }

    fn resolve_target(&mut self, target: &Value) -> Result<(String, Taint, bool), Fail> {
        let mut r = codec::Record::new(target).map_err(|_| Fail::Code(BAD_ARG))?;
        if let Some(literal) = r.opt("literal", codec::text).map_err(|_| Fail::Code(BAD_ARG))? {
            r.finish().map_err(|_| Fail::Code(BAD_ARG))?;
            return Ok((literal.to_owned(), self.read_taint(), true));
        }
        let id: ObjectId = r.req("ref", codec::parsed).map_err(|_| Fail::Code(BAD_ARG))?;
        let field = r.req("field", codec::text).map_err(|_| Fail::Code(BAD_ARG))?.to_owned();
        r.finish().map_err(|_| Fail::Code(BAD_ARG))?;
        let obj = self.tx.read(self.graph, id).ok_or(Fail::Code(NOT_FOUND))?;
        self.ensure_read(&obj.type_ref.name)?;
        self.note(&obj);
        let value = obj.fields.get(&field).ok_or(Fail::Code(BAD_ARG))?;
        Ok((display_value(value), obj.provenance.taint, false))
    }

    fn payload_taint(&mut self, payload: &FieldValue) -> Result<Taint, Fail> {
        let mut ids = Vec::new();
        collect_refs(payload, &mut ids);
        let mut taint = Taint::Clean;
        for id in ids {
            let obj = self.tx.read(self.graph, id).ok_or(Fail::Code(NOT_FOUND))?;
            self.ensure_read(&obj.type_ref.name)?;
            self.note(&obj);
            taint = taint.max(obj.provenance.taint);
        }
        Ok(taint)
    }

    fn note(&mut self, obj: &Object) {
        if self.created.contains(&obj.id) || self.reads.iter().any(|r| r.id == obj.id) {
            return;
        }
        self.reads.push(ReadNote {
            id: obj.id,
            version: obj.version,
            taint: obj.provenance.taint,
            sensitivity: obj.sensitivity,
        });
    }

    fn ensure_read(&self, ty: &aos_types::TypeName) -> Result<(), Fail> {
        if self.action.allows_read(ty) {
            Ok(())
        } else {
            Err(Fail::Violation(Violation { kind: "undeclared_type", detail: format!("read {ty}") }))
        }
    }

    fn ensure_write(&self, ty: &aos_types::TypeName) -> Result<(), Fail> {
        if self.action.allows_write(ty) {
            Ok(())
        } else {
            Err(Fail::Violation(Violation { kind: "undeclared_type", detail: format!("write {ty}") }))
        }
    }

    fn decl(&self, ty: &TypeRef) -> Result<&TypeDecl, Fail> {
        self.catalog.type_decl(ty).ok_or(Fail::Code(BAD_ARG))
    }

    fn check(&self, obj: &Object) -> Result<(), Fail> {
        let decl = self.decl(&obj.type_ref)?;
        decl.check_object(obj, Some(&self.refs())).map_err(|_| Fail::Code(BAD_ARG))
    }

    fn check_id(&mut self, id: ObjectId) -> Result<(), Fail> {
        let obj = self.tx.peek(id).cloned().ok_or(Fail::Code(BAD_ARG))?;
        let decl = self.decl(&obj.type_ref)?;
        if let Err(_problems) = decl.check_object(&obj, Some(&self.refs())) {
            return Err(Fail::Code(BAD_ARG));
        }
        Ok(())
    }

    fn refs(&self) -> Refs<'_, S> {
        Refs { graph: self.graph, tx: self.tx }
    }
}

struct Refs<'a, S> {
    graph: &'a Graph<S>,
    tx: &'a Tx,
}

impl<S: LogStore> aos_types::schema::RefTypes for Refs<'_, S> {
    fn type_of(&self, id: ObjectId) -> Option<aos_types::TypeName> {
        let obj = self
            .tx
            .peek(id)
            .cloned()
            .or_else(|| self.graph.read(self.tx.branch(), id).ok().flatten().map(|o| (*o).clone()))?;
        if obj.tombstone { None } else { Some(obj.type_ref.name) }
    }
}

type TypeNameOwned = aos_types::TypeName;

fn parse_type_name(from: &str) -> Result<aos_types::TypeName, Fail> {
    let name = from.split_once('@').map(|(n, _)| n).unwrap_or(from);
    name.parse().map_err(|_| Fail::Code(BAD_ARG))
}

fn display_value(v: &FieldValue) -> String {
    match v {
        FieldValue::Text(s) => s.clone(),
        FieldValue::Int(n) => n.to_string(),
        FieldValue::Bool(b) => b.to_string(),
        FieldValue::Float(f) => f.0.to_string(),
        FieldValue::Ref(r) => r.to_string(),
        FieldValue::Blob(d) => d.to_string(),
        FieldValue::Timestamp(t) => t.to_string(),
        _ => String::new(),
    }
}

fn collect_refs(v: &FieldValue, out: &mut Vec<ObjectId>) {
    match v {
        FieldValue::Ref(r) => out.push(r.id),
        FieldValue::List(items) => items.iter().for_each(|v| collect_refs(v, out)),
        FieldValue::Map(m) => m.values().for_each(|v| collect_refs(v, out)),
        _ => {}
    }
}

fn probe_object(type_ref: &TypeRef, new: &NewObject) -> Object {
    use aos_types::{Provenance, TxId, Ulid};
    Object {
        id: ObjectId(Ulid::from_u128(1)),
        type_ref: type_ref.clone(),
        version: 1,
        fields: new.fields.clone(),
        provenance: Provenance {
            actor: Actor::System,
            origin: Origin::Internal,
            taint: Taint::Clean,
            derived_from: BTreeSet::new(),
            tx: TxId(Ulid::from_u128(1)),
        },
        sensitivity: new.sensitivity,
        extra: new.extra.clone(),
        tombstone: false,
    }
}

fn bad_arg_err(msg: String) -> i32 {
    let _ = msg;
    BAD_ARG
}
