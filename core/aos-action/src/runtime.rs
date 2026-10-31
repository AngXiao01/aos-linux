//! Runs one action inside wasmtime with fuel and a memory cap (SPEC §8.3, §A8).

use std::collections::BTreeMap;
use std::sync::Arc;

use aos_branch::{Graph, NewObject, ReadView, Tx, TxMeta};
use aos_cap::Cost;
use aos_log::{BranchName, LogStore};
use aos_types::schema::{FieldKind, TypeRef};
use aos_types::{Actor, FieldValue, Object, ObjectId, Sensitivity, Taint, TxId};
use wasmtime::{Config, Engine, Linker, Module, Store};

use crate::Host;
use crate::abi;
use crate::catalog::Catalog;
use crate::context::{BlobStore, Ctx, Violation};
use crate::decl::ActionDecl;
use crate::expr;

pub const IMPORTS: &[&str] = &[
    "input",
    "read",
    "write",
    "create",
    "query",
    "blob_read",
    "blob_write",
    "intent_create",
    "job_submit",
    "log",
    "handle_len",
    "handle_copy",
];

const FUEL: u64 = 100_000_000;
const MEMORY: usize = 32 * 1024 * 1024;

pub struct Runtime {
    engine: Engine,
    catalog: Catalog,
    caps: aos_cap::CapabilityService,
    blobs: BlobStore,
}

pub struct Call {
    pub branch: BranchName,
    pub actor: Actor,
    pub capability: String,
    pub action: String,
    pub inputs: BTreeMap<String, FieldValue>,
    pub literal_taint: Taint,
    pub wasm: Vec<u8>,
}

#[derive(Debug)]
pub struct Outcome {
    pub tx: TxId,
    pub writes: Vec<ObjectId>,
    pub replay: bool,
}

#[derive(Debug)]
pub enum Error {
    BadAction(String),
    BadModule(String),
    Unauthorized(String),
    Quota(String),
    Precondition(String),
    Violation(Violation),
    Trap(String),
    Failed(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BadAction(m) => write!(f, "bad action: {m}"),
            Error::BadModule(m) => write!(f, "bad module: {m}"),
            Error::Unauthorized(m) => write!(f, "unauthorized: {m}"),
            Error::Quota(m) => write!(f, "quota: {m}"),
            Error::Precondition(m) => write!(f, "precondition: {m}"),
            Error::Violation(v) => write!(f, "violation {}: {}", v.kind, v.detail),
            Error::Trap(m) => write!(f, "trap: {m}"),
            Error::Failed(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

impl Runtime {
    pub fn new(catalog: Catalog, caps: aos_cap::CapabilityService) -> Result<Self, Error> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Disable);
        let engine = Engine::new(&config).map_err(|e| Error::Failed(e.to_string()))?;
        Ok(Runtime { engine, catalog, caps, blobs: BlobStore::default() })
    }

    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    pub fn caps(&self) -> &aos_cap::CapabilityService {
        &self.caps
    }

    pub fn caps_mut(&mut self) -> &mut aos_cap::CapabilityService {
        &mut self.caps
    }

    pub fn invoke<S: LogStore>(&mut self, graph: &mut Graph<S>, call: Call) -> Result<Outcome, Error> {
        let action = self
            .catalog
            .action(&call.action)
            .cloned()
            .ok_or_else(|| Error::BadAction(format!("unknown {}", call.action)))?;
        let module = Module::new(&self.engine, &call.wasm).map_err(|e| Error::BadModule(e.to_string()))?;
        if let Some(violation) = illegal_import(&module) {
            let _ = self.record(graph, &call, &violation);
            return Err(Error::Violation(violation));
        }
        if let Err(e) = self.caps.authorize(&call.capability, &action.capability) {
            let violation = Violation { kind: "capability", detail: e.to_string() };
            let _ = self.record(graph, &call, &violation);
            return Err(Error::Unauthorized(e.to_string()));
        }
        let cap =
            self.caps.get(&call.capability).cloned().ok_or_else(|| Error::Unauthorized("missing token".into()))?;
        if cap.subject != call.actor {
            let violation = Violation { kind: "capability", detail: "token subject does not match the actor".into() };
            let _ = self.record(graph, &call, &violation);
            return Err(Error::Unauthorized(violation.detail.clone()));
        }
        let inputs = resolve_inputs(&action, &call.inputs)?;
        if let Err(e) = check_scope(&cap, &inputs) {
            if let Error::Unauthorized(detail) = &e {
                let violation = Violation { kind: "capability", detail: detail.clone() };
                let _ = self.record(graph, &call, &violation);
            }
            return Err(e);
        }
        let mut touched = Vec::new();
        let key = render_key(graph, &call.branch, &action, &inputs, &mut touched)?;
        let mut inputs = inputs;
        if let Some(key) = &key {
            if let Some(prev) = find_replay(graph, &call.branch, &action.qualified(), key)? {
                let writes = graph
                    .transactions(&call.branch)
                    .map_err(|e| Error::Failed(e.to_string()))?
                    .into_iter()
                    .find(|t| t.tx == prev)
                    .map(|t| t.writes.iter().map(|w| w.id()).collect())
                    .unwrap_or_default();
                return Ok(Outcome { tx: prev, writes, replay: true });
            }
            inputs.insert("idempotency_key".into(), FieldValue::text(key));
        }
        if let Err(reason) = eval_pre(&action, graph, &call.branch, &inputs, &mut touched) {
            let violation = Violation { kind: "precondition", detail: reason.clone() };
            let _ = self.record(graph, &call, &violation);
            return Err(Error::Precondition(reason));
        }
        let cost = action_cost(&action, graph, &call.branch, &inputs)?;
        self.caps.try_charge(&call.capability, &cost).map_err(|e| Error::Quota(e.to_string()))?;

        let mut meta = TxMeta::new(call.actor.clone());
        meta.capability = Some(call.capability.clone());
        meta.action = Some(action.qualified());
        meta.inputs = inputs.clone();
        let mut tx = match graph.begin(&call.branch, meta) {
            Ok(tx) => tx,
            Err(e) => {
                self.caps.refund(&call.capability, &cost);
                return Err(Error::Failed(e.to_string()));
            }
        };
        for id in &touched {
            let _ = tx.read(graph, *id);
        }
        if let Err(reason) = eval_pre_tx(&action, graph, &mut tx, &inputs) {
            self.caps.refund(&call.capability, &cost);
            let violation = Violation { kind: "precondition", detail: reason.clone() };
            let _ = self.record(graph, &call, &violation);
            return Err(Error::Precondition(reason));
        }

        let run = self.run_wasm(graph, &mut tx, &action, &call, &inputs, cost.clone());
        match run {
            Ok(()) => {}
            Err(Error::Violation(v)) => {
                self.caps.refund(&call.capability, &cost);
                let _ = self.record(graph, &call, &v);
                return Err(Error::Violation(v));
            }
            Err(e) => {
                self.caps.refund(&call.capability, &cost);
                return Err(e);
            }
        }
        let snap = tx.snapshot().clone();
        if let Err(reason) = self.catalog.check_tx(&Snap { graph, snap: &snap }, &preview(&tx, &call, &action, &inputs))
        {
            self.caps.refund(&call.capability, &cost);
            let violation = Violation { kind: "precondition", detail: reason.clone() };
            let _ = self.record(graph, &call, &violation);
            return Err(Error::Precondition(reason));
        }
        let writes = tx.staged_ids().to_vec();
        let tx_id = match graph.commit(tx) {
            Ok(id) => id,
            Err(e) => {
                self.caps.refund(&call.capability, &cost);
                return Err(Error::Failed(e.to_string()));
            }
        };
        Ok(Outcome { tx: tx_id, writes, replay: false })
    }

    fn run_wasm<S: LogStore>(
        &mut self,
        graph: &mut Graph<S>,
        tx: &mut Tx,
        action: &ActionDecl,
        call: &Call,
        inputs: &BTreeMap<String, FieldValue>,
        charged: Cost,
    ) -> Result<(), Error> {
        let mut linker = Linker::new(&self.engine);
        abi::define::<S>(&mut linker).map_err(|e| Error::Failed(e.to_string()))?;
        let module = Module::new(&self.engine, &call.wasm).map_err(|e| Error::BadModule(e.to_string()))?;
        let mut ctx = Ctx::new(
            graph,
            tx,
            &self.catalog,
            action,
            &mut self.blobs,
            &mut self.caps,
            &call.capability,
            inputs.clone(),
            call.literal_taint,
            charged,
        );
        let host = Host {
            cx: &mut ctx as *mut Ctx<'_, S> as *mut (),
            limiter: crate::Limiter { memory_bytes: MEMORY },
            handles: Vec::new(),
            violation: None,
        };
        let mut store = Store::new(&self.engine, host);
        store.set_fuel(FUEL).map_err(|e| Error::Failed(e.to_string()))?;
        store.limiter(|h| &mut h.limiter);
        let instance = linker.instantiate(&mut store, &module).map_err(|e| classify(&store, e))?;
        let func = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "aos_invoke")
            .map_err(|e| Error::BadModule(e.to_string()))?;
        let call_result = func.call(&mut store, (0, 0));
        let violation = store.data().violation.clone();
        drop(store);
        if let Err(e) = call_result {
            if let Some(v) = violation {
                return Err(Error::Violation(v));
            }
            if format!("{e}").contains("all fuel") || format!("{e:?}").contains("OutOfFuel") {
                return Err(Error::Violation(Violation { kind: "resource", detail: "fuel exhausted".into() }));
            }
            return Err(Error::Trap(e.to_string()));
        }
        ctx.finish().map_err(Error::Failed)?;
        // Charge any extra the guest incurred (intents) on top of the estimate.
        // `ctx.charged` includes the estimate; the estimate was already taken,
        // so only the difference is due. try_charge inside intent already took it.
        let _ = ctx.charged;
        Ok(())
    }

    fn record<S: LogStore>(
        &mut self,
        graph: &mut Graph<S>,
        call: &Call,
        violation: &Violation,
    ) -> Result<ObjectId, Error> {
        let mut meta = TxMeta::new(Actor::System);
        meta.action = Some("sys.violation.record@1".into());
        let mut tx = graph.begin(&call.branch, meta).map_err(|e| Error::Failed(e.to_string()))?;
        let mut new = NewObject::new("sys/ActionViolation@1".parse::<TypeRef>().unwrap());
        new.sensitivity = Sensitivity::Internal;
        new.fields.insert("action".into(), FieldValue::text(&call.action));
        new.fields.insert("kind".into(), FieldValue::text(violation.kind));
        let detail: String = violation.detail.chars().take(2000).collect();
        new.fields.insert("detail".into(), FieldValue::text(detail));
        let id = tx.create(graph, new);
        graph.commit(tx).map_err(|e| Error::Failed(e.to_string()))?;
        Ok(id)
    }
}

fn illegal_import(module: &Module) -> Option<Violation> {
    for import in module.imports() {
        if import.module() != "aos" || !IMPORTS.contains(&import.name()) {
            return Some(Violation { kind: "io", detail: format!("import {}::{}", import.module(), import.name()) });
        }
    }
    None
}

fn classify(store: &Store<Host>, err: wasmtime::Error) -> Error {
    if let Some(v) = store.data().violation.clone() {
        return Error::Violation(v);
    }
    Error::BadModule(err.to_string())
}

fn resolve_inputs(
    action: &ActionDecl,
    given: &BTreeMap<String, FieldValue>,
) -> Result<BTreeMap<String, FieldValue>, Error> {
    let mut out = BTreeMap::new();
    for param in &action.inputs {
        match given.get(&param.name) {
            Some(v) => {
                if !kind_ok(&param.kind, v) {
                    return Err(Error::BadAction(format!("input {} has the wrong type", param.name)));
                }
                out.insert(param.name.clone(), v.clone());
            }
            None => match &param.default {
                Some(v) => {
                    out.insert(param.name.clone(), v.clone());
                }
                None if param.required => return Err(Error::BadAction(format!("missing input {}", param.name))),
                None => {}
            },
        }
    }
    for name in given.keys() {
        if !action.inputs.iter().any(|p| &p.name == name) {
            return Err(Error::BadAction(format!("unknown input {name}")));
        }
    }
    Ok(out)
}

fn kind_ok(kind: &FieldKind, v: &FieldValue) -> bool {
    match (kind, v) {
        (FieldKind::Bool, FieldValue::Bool(_))
        | (FieldKind::Blob, FieldValue::Blob(_))
        | (FieldKind::Timestamp, FieldValue::Timestamp(_))
        | (FieldKind::Text { .. }, FieldValue::Text(_))
        | (FieldKind::Enum { .. }, FieldValue::Text(_))
        | (FieldKind::Ref { .. }, FieldValue::Ref(_)) => true,
        (FieldKind::Int { min, max }, FieldValue::Int(n)) => min.is_none_or(|m| *n >= m) && max.is_none_or(|m| *n <= m),
        (FieldKind::Float { min, max }, FieldValue::Float(f)) => {
            f.0.is_finite() && min.is_none_or(|m| f.0 >= m.0) && max.is_none_or(|m| f.0 <= m.0)
        }
        (FieldKind::Float { .. }, FieldValue::Int(_)) => true,
        _ => false,
    }
}

fn check_scope(cap: &aos_cap::Capability, inputs: &BTreeMap<String, FieldValue>) -> Result<(), Error> {
    for (key, ids) in &cap.object_scope {
        match inputs.get(key) {
            Some(FieldValue::Ref(r)) if ids.contains(&r.id) => {}
            Some(FieldValue::Ref(_)) => {
                return Err(Error::Unauthorized(format!("input {key} is outside the token scope")));
            }
            _ => return Err(Error::Unauthorized(format!("token scope {key} is not an input"))),
        }
    }
    Ok(())
}

fn render_key<S: LogStore>(
    graph: &Graph<S>,
    branch: &BranchName,
    action: &ActionDecl,
    inputs: &BTreeMap<String, FieldValue>,
    touched: &mut Vec<ObjectId>,
) -> Result<Option<String>, Error> {
    let Some(template) = &action.idempotency_key else { return Ok(None) };
    let rendered = template
        .render(|path| expr::resolve_path(path, inputs, |id| load(graph, branch, id, touched)).ok())
        .map_err(|e| Error::BadAction(e.to_string()))?;
    Ok(Some(rendered))
}

fn eval_pre<S: LogStore>(
    action: &ActionDecl,
    graph: &Graph<S>,
    branch: &BranchName,
    inputs: &BTreeMap<String, FieldValue>,
    touched: &mut Vec<ObjectId>,
) -> Result<(), String> {
    for pre in &action.preconditions {
        let ok = expr::eval_bool(pre, inputs, |id| load(graph, branch, id, touched))?;
        if !ok {
            return Err(format!("precondition failed: {pre}"));
        }
    }
    Ok(())
}

fn eval_pre_tx<S: LogStore>(
    action: &ActionDecl,
    graph: &Graph<S>,
    tx: &mut Tx,
    inputs: &BTreeMap<String, FieldValue>,
) -> Result<(), String> {
    for pre in &action.preconditions {
        let ok = expr::eval_bool(pre, inputs, |id| {
            tx.read(graph, id).filter(|o| !o.tombstone).ok_or_else(|| format!("{id} is not visible"))
        })?;
        if !ok {
            return Err(format!("precondition failed: {pre}"));
        }
    }
    Ok(())
}

fn action_cost<S: LogStore>(
    action: &ActionDecl,
    graph: &Graph<S>,
    branch: &BranchName,
    inputs: &BTreeMap<String, FieldValue>,
) -> Result<Cost, Error> {
    let mut touched = Vec::new();
    let steps = whole(
        expr::eval_number(&action.cost.steps, inputs, |id| load(graph, branch, id, &mut touched))
            .map_err(Error::BadAction)?,
    )?;
    let cpu = millis(
        expr::eval_number(&action.cost.cpu_seconds, inputs, |id| load(graph, branch, id, &mut touched))
            .map_err(Error::BadAction)?,
    )?;
    let gpu = millis(
        expr::eval_number(&action.cost.gpu_seconds, inputs, |id| load(graph, branch, id, &mut touched))
            .map_err(Error::BadAction)?,
    )?;
    let money = cents(
        expr::eval_number(&action.cost.money_cny, inputs, |id| load(graph, branch, id, &mut touched))
            .map_err(Error::BadAction)?,
    )?;
    Ok(Cost { steps, cpu_ms: cpu, gpu_ms: gpu, money_cents: money })
}

fn whole(n: f64) -> Result<u64, Error> {
    if !n.is_finite() || n < 0.0 {
        return Err(Error::BadAction("negative cost".into()));
    }
    let r = n.round();
    if (n - r).abs() > 1e-6 {
        return Err(Error::BadAction("steps must be a whole number".into()));
    }
    Ok(r as u64)
}

fn millis(seconds: f64) -> Result<u64, Error> {
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(Error::BadAction("negative cost".into()));
    }
    Ok((seconds * 1000.0).ceil() as u64)
}

fn cents(cny: f64) -> Result<u64, Error> {
    if !cny.is_finite() || cny < 0.0 {
        return Err(Error::BadAction("negative cost".into()));
    }
    Ok((cny * 100.0).ceil() as u64)
}

fn load<S: LogStore>(
    graph: &Graph<S>,
    branch: &BranchName,
    id: ObjectId,
    touched: &mut Vec<ObjectId>,
) -> Result<Object, String> {
    if !touched.contains(&id) {
        touched.push(id);
    }
    match graph.read(branch, id).map_err(|e| e.to_string())? {
        Some(obj) if !obj.tombstone => Ok((*obj).clone()),
        Some(_) => Err(format!("{id} is deleted")),
        None => Err(format!("{id} is not visible")),
    }
}

fn find_replay<S: LogStore>(
    graph: &Graph<S>,
    branch: &BranchName,
    action: &str,
    key: &str,
) -> Result<Option<TxId>, Error> {
    let txs = graph.transactions(branch).map_err(|e| Error::Failed(e.to_string()))?;
    let key = FieldValue::text(key);
    Ok(txs
        .into_iter()
        .rev()
        .find(|tx| tx.action.as_deref() == Some(action) && tx.inputs.get("idempotency_key") == Some(&key))
        .map(|tx| tx.tx))
}

fn preview(tx: &Tx, call: &Call, action: &ActionDecl, inputs: &BTreeMap<String, FieldValue>) -> aos_log::TxRecord {
    aos_log::TxRecord {
        branch: call.branch.clone(),
        tx: tx.id(),
        actor: call.actor.clone(),
        capability: Some(call.capability.clone()),
        action: Some(action.qualified()),
        inputs: inputs.clone(),
        writes: Vec::new(),
        intents: Vec::new(),
        revert_of: None,
        merged_from: None,
    }
}

struct Snap<'a, S> {
    graph: &'a Graph<S>,
    snap: &'a aos_branch::Snapshot,
}

impl<S: LogStore> ReadView for Snap<'_, S> {
    fn read(&self, id: ObjectId) -> Option<Arc<Object>> {
        self.graph.read_at(self.snap, id).ok().flatten()
    }

    fn read_version(&self, id: ObjectId, version: u64) -> Option<Arc<Object>> {
        self.graph.read_version(&self.snap.branch, id, version).ok().flatten()
    }
}

impl wasmtime::ResourceLimiter for crate::Limiter {
    fn memory_growing(&mut self, _current: usize, desired: usize, _maximum: Option<usize>) -> wasmtime::Result<bool> {
        Ok(desired <= self.memory_bytes)
    }

    fn table_growing(&mut self, _current: usize, desired: usize, _maximum: Option<usize>) -> wasmtime::Result<bool> {
        // Rust's wasm function table is larger than a hand-written module.
        Ok(desired <= 10_000)
    }
}
