//! Action and type declarations (SPEC §8.1, §6.2). YAML parsing was deferred
//! to this milestone.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use aos_types::FieldValue;
use aos_types::id::is_ident;
use aos_types::schema::{FieldDecl, FieldKind, RelationDecl, TypeDecl, TypeName, ViewHint};
use aos_types::template::Template;

use aos_types::yaml::{self, Yaml};

use crate::expr::{self, Expr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reversibility {
    Undo,
    Compensate,
    Irreversible,
}

impl Reversibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Reversibility::Undo => "undo",
            Reversibility::Compensate => "compensate",
            Reversibility::Irreversible => "irreversible",
        }
    }
}

impl fmt::Display for Reversibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Param {
    pub name: String,
    pub kind: FieldKind,
    pub required: bool,
    pub default: Option<FieldValue>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CostExpr {
    pub steps: Expr,
    pub cpu_seconds: Expr,
    pub gpu_seconds: Expr,
    pub money_cny: Expr,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ActionDecl {
    pub name: String,
    pub version: u32,
    pub provider: String,
    pub summary: String,
    pub inputs: Vec<Param>,
    pub outputs: Vec<Param>,
    pub reads: BTreeSet<TypeName>,
    pub writes: BTreeSet<TypeName>,
    pub egress: Vec<String>,
    pub reversibility: Reversibility,
    pub preconditions: Vec<Expr>,
    pub cost: CostExpr,
    /// Concrete right required to invoke the action. No wildcards.
    pub capability: String,
    pub idempotency_key: Option<Template>,
}

impl ActionDecl {
    pub fn qualified(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }

    pub fn allows_read(&self, ty: &TypeName) -> bool {
        self.reads.contains(ty)
    }

    pub fn allows_write(&self, ty: &TypeName) -> bool {
        self.writes.contains(ty)
    }

    pub fn allows_channel(&self, channel: &str) -> bool {
        self.egress.iter().any(|p| aos_cap::channel_covers(p, channel))
    }
}

pub fn parse_type(text: &str) -> Result<TypeDecl, String> {
    let doc = yaml::parse(text).map_err(|e| e.to_string())?;
    type_from_yaml(&doc)
}

pub fn parse_action(text: &str) -> Result<ActionDecl, String> {
    let doc = yaml::parse(text).map_err(|e| e.to_string())?;
    action_from_yaml(&doc)
}

pub fn is_action_doc(doc: &Yaml) -> bool {
    doc.get("action").is_some()
}

fn type_from_yaml(doc: &Yaml) -> Result<TypeDecl, String> {
    expect_keys(doc, &["type", "major", "fields", "relations", "view_hint"])?;
    let name: TypeName = doc
        .need("type")
        .map_err(|e| e.0)?
        .as_str()
        .map_err(|e| e.0)?
        .parse()
        .map_err(|_| "bad type name".to_owned())?;
    let major = u32_of(doc.need("major").map_err(|e| e.0)?)?;
    let fields = field_map(doc.need("fields").map_err(|e| e.0)?, false)?;
    let mut relations = BTreeMap::new();
    if let Some(rel) = doc.get("relations") {
        for (name, body) in rel.as_map().map_err(|e| e.0)? {
            expect_keys(body, &["many", "via"])?;
            let many: TypeName = body
                .need("many")
                .map_err(|e| e.0)?
                .as_str()
                .map_err(|e| e.0)?
                .parse()
                .map_err(|_| format!("bad relation {name}"))?;
            let via = body.need("via").map_err(|e| e.0)?.as_str().map_err(|e| e.0)?.to_owned();
            relations.insert(name.clone(), RelationDecl { many, via });
        }
    }
    let mut view_hint = ViewHint::default();
    if let Some(hint) = doc.get("view_hint") {
        expect_keys(hint, &["title", "primary_fields"])?;
        if let Some(title) = hint.get("title") {
            view_hint.title = Some(title.as_str().map_err(|e| e.0)?.to_owned());
        }
        if let Some(fields) = hint.get("primary_fields") {
            view_hint.primary_fields = fields
                .as_seq()
                .map_err(|e| e.0)?
                .iter()
                .map(|v| v.as_str().map(|s| s.to_owned()).map_err(|e| e.0))
                .collect::<Result<_, _>>()?;
        }
    }
    let decl = TypeDecl { name, major, fields, relations, view_hint };
    decl.check_decl().map_err(|ps| format!("{ps:?}"))?;
    Ok(decl)
}

fn action_from_yaml(doc: &Yaml) -> Result<ActionDecl, String> {
    expect_keys(
        doc,
        &[
            "action",
            "version",
            "provider",
            "summary",
            "inputs",
            "outputs",
            "effects",
            "reversibility",
            "preconditions",
            "cost",
            "capability",
            "idempotency_key",
        ],
    )?;
    let name = doc.need("action").map_err(|e| e.0)?.as_str().map_err(|e| e.0)?.to_owned();
    check_action_name(&name)?;
    let version = u32_of(doc.need("version").map_err(|e| e.0)?)?;
    if version == 0 {
        return Err("action version starts at 1".into());
    }
    let provider = doc.need("provider").map_err(|e| e.0)?.as_str().map_err(|e| e.0)?.to_owned();
    if name.split('.').next() != Some(provider.as_str()) {
        return Err(format!("provider {provider} does not match {name}"));
    }
    let summary = doc.need("summary").map_err(|e| e.0)?.as_str().map_err(|e| e.0)?.to_owned();
    if summary.is_empty() || summary.chars().count() > 500 {
        return Err("summary must be 1..=500 characters".into());
    }
    let inputs = named_params(doc.get("inputs"), true)?;
    let outputs = named_params(doc.get("outputs"), true)?;
    let effects = doc.need("effects").map_err(|e| e.0)?;
    expect_keys(effects, &["reads", "writes", "egress"])?;
    let reads = type_list(effects.need("reads").map_err(|e| e.0)?)?;
    let writes = type_list(effects.need("writes").map_err(|e| e.0)?)?;
    let egress = effects
        .need("egress")
        .map_err(|e| e.0)?
        .as_seq()
        .map_err(|e| e.0)?
        .iter()
        .map(|v| {
            let s = v.as_str().map_err(|e| e.0)?.to_owned();
            aos_cap::parse_channel(&s).map_err(|e| e.to_string())?;
            Ok(s)
        })
        .collect::<Result<Vec<_>, String>>()?;
    let rev = doc.need("reversibility").map_err(|e| e.0)?.as_str().map_err(|e| e.0)?;
    let reversibility = match rev {
        "undo" => Reversibility::Undo,
        "compensate" => Reversibility::Compensate,
        "irreversible" => Reversibility::Irreversible,
        other => return Err(format!("unknown reversibility {other}")),
    };
    if egress.is_empty() && reversibility != Reversibility::Undo {
        return Err("an internal action must be undo".into());
    }
    if egress.is_empty() && reversibility == Reversibility::Undo {
        // required shape
    } else if egress.is_empty() {
        return Err("compensate and irreversible actions declare an egress channel".into());
    }
    if !egress.is_empty() && reversibility == Reversibility::Undo {
        return Err("an action with egress cannot be undo".into());
    }
    for p in inputs.iter().chain(&outputs) {
        if let FieldKind::Ref { target } = &p.kind {
            let set = if inputs.iter().any(|i| i.name == p.name) { &reads } else { &writes };
            if !set.contains(target) && !reads.contains(target) && !writes.contains(target) {
                return Err(format!("parameter {} uses undeclared type {target}", p.name));
            }
        }
    }
    for p in &inputs {
        if let FieldKind::Ref { target } = &p.kind
            && !reads.contains(target)
        {
            return Err(format!("input {} reads {target}, which is not in effects.reads", p.name));
        }
    }
    let preconditions = match doc.get("preconditions") {
        None => Vec::new(),
        Some(list) => list
            .as_seq()
            .map_err(|e| e.0)?
            .iter()
            .map(|v| expr::parse(v.as_str().map_err(|e| e.0)?))
            .collect::<Result<Vec<_>, _>>()?,
    };
    let cost = parse_cost(doc.get("cost"))?;
    let capability = doc.need("capability").map_err(|e| e.0)?.as_str().map_err(|e| e.0)?.to_owned();
    aos_cap::parse_right(&capability).map_err(|e| e.to_string())?;
    if capability.contains('*') {
        return Err("action capability must be a concrete right".into());
    }
    let idempotency_key = match doc.get("idempotency_key") {
        None => None,
        Some(v) => Some(v.as_str().map_err(|e| e.0)?.parse::<Template>().map_err(|e| e.to_string())?),
    };
    Ok(ActionDecl {
        name,
        version,
        provider,
        summary,
        inputs,
        outputs,
        reads,
        writes,
        egress,
        reversibility,
        preconditions,
        cost,
        capability,
        idempotency_key,
    })
}

fn parse_cost(node: Option<&Yaml>) -> Result<CostExpr, String> {
    let mut steps = expr::parse("1")?;
    let mut cpu_seconds = expr::parse("0")?;
    let mut gpu_seconds = expr::parse("0")?;
    let mut money_cny = expr::parse("0")?;
    if let Some(node) = node {
        expect_keys(node, &["steps", "cpu_seconds_estimate", "gpu_seconds_estimate", "money_cny"])?;
        if let Some(v) = node.get("steps") {
            steps = expr_of(v)?;
        }
        if let Some(v) = node.get("cpu_seconds_estimate") {
            cpu_seconds = expr_of(v)?;
        }
        if let Some(v) = node.get("gpu_seconds_estimate") {
            gpu_seconds = expr_of(v)?;
        }
        if let Some(v) = node.get("money_cny") {
            money_cny = expr_of(v)?;
        }
    }
    Ok(CostExpr { steps, cpu_seconds, gpu_seconds, money_cny })
}

fn expr_of(v: &Yaml) -> Result<Expr, String> {
    match v {
        Yaml::Str(s) => expr::parse(s),
        Yaml::Int(n) => expr::parse(&n.to_string()),
        Yaml::Float(f) => expr::parse(&format!("{f}")),
        _ => Err("cost expression must be a string or number".into()),
    }
}

fn named_params(node: Option<&Yaml>, allow_default: bool) -> Result<Vec<Param>, String> {
    let Some(node) = node else { return Ok(Vec::new()) };
    let mut out = Vec::new();
    for (name, body) in node.as_map().map_err(|e| e.0)? {
        if !is_ident(name) {
            return Err(format!("bad parameter name {name}"));
        }
        let (kind, required, default) = param_body(body, allow_default)?;
        out.push(Param { name: name.clone(), kind, required, default });
    }
    Ok(out)
}

fn field_map(node: &Yaml, allow_default: bool) -> Result<BTreeMap<String, FieldDecl>, String> {
    let mut out = BTreeMap::new();
    for (name, body) in node.as_map().map_err(|e| e.0)? {
        if !is_ident(name) {
            return Err(format!("bad field name {name}"));
        }
        let (kind, required, default) = param_body(body, allow_default)?;
        if default.is_some() {
            return Err(format!("type field {name} cannot have a default"));
        }
        out.insert(name.clone(), FieldDecl { kind, required });
    }
    Ok(out)
}

fn param_body(body: &Yaml, allow_default: bool) -> Result<(FieldKind, bool, Option<FieldValue>), String> {
    let mut kind = None;
    let mut required = false;
    let mut default = None;
    for (key, value) in body.as_map().map_err(|e| e.0)? {
        match key.as_str() {
            "required" => required = value.as_bool().map_err(|e| e.0)?,
            "default" if allow_default => default = Some(value.clone()),
            "default" => return Err("default is not allowed here".into()),
            other if is_kind(other) => {
                if kind.is_some() {
                    return Err(format!("two kinds on one field ({other})"));
                }
                kind = Some(kind_of(other, value)?);
            }
            other => return Err(format!("unknown field attribute {other}")),
        }
    }
    let kind = kind.ok_or("field is missing a type")?;
    let default = match default {
        Some(v) => Some(literal(&kind, &v)?),
        None => None,
    };
    Ok((kind, required, default))
}

fn is_kind(s: &str) -> bool {
    matches!(s, "bool" | "int" | "float" | "text" | "enum" | "ref" | "blob" | "timestamp" | "list" | "map")
}

fn kind_of(kind: &str, body: &Yaml) -> Result<FieldKind, String> {
    match kind {
        "bool" => {
            empty_map(body)?;
            Ok(FieldKind::Bool)
        }
        "blob" => {
            empty_map(body)?;
            Ok(FieldKind::Blob)
        }
        "timestamp" => {
            empty_map(body)?;
            Ok(FieldKind::Timestamp)
        }
        "ref" => {
            let target = body
                .as_str()
                .map_err(|e| e.0)?
                .parse()
                .map_err(|_| format!("bad ref target {}", body.as_str().unwrap_or("")))?;
            Ok(FieldKind::Ref { target })
        }
        "int" => {
            expect_keys(body, &["min", "max"])?;
            Ok(FieldKind::Int { min: opt_i64(body, "min")?, max: opt_i64(body, "max")? })
        }
        "float" => {
            expect_keys(body, &["min", "max"])?;
            Ok(FieldKind::Float {
                min: opt_f64(body, "min")?.map(aos_types::cbor::F64),
                max: opt_f64(body, "max")?.map(aos_types::cbor::F64),
            })
        }
        "text" => {
            expect_keys(body, &["max"])?;
            Ok(FieldKind::Text { max: opt_u32(body, "max")? })
        }
        "enum" => {
            expect_keys(body, &["values"])?;
            let values = body
                .need("values")
                .map_err(|e| e.0)?
                .as_seq()
                .map_err(|e| e.0)?
                .iter()
                .map(|v| v.as_str().map(|s| s.to_owned()).map_err(|e| e.0))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(FieldKind::Enum { values })
        }
        "list" => {
            expect_keys(body, &["of", "max_len"])?;
            let of = body.need("of").map_err(|e| e.0)?;
            let (k, _) = single_kind(of)?;
            Ok(FieldKind::List { of: Box::new(k), max_len: opt_u32(body, "max_len")? })
        }
        "map" => {
            expect_keys(body, &["values"])?;
            let values = body.need("values").map_err(|e| e.0)?;
            let (k, _) = single_kind(values)?;
            Ok(FieldKind::Map { values: Box::new(k) })
        }
        _ => Err(format!("unknown kind {kind}")),
    }
}

fn single_kind(body: &Yaml) -> Result<(FieldKind, ()), String> {
    let map = body.as_map().map_err(|e| e.0)?;
    if map.len() != 1 {
        return Err("nested type must be a single kind".into());
    }
    let (k, v) = &map[0];
    Ok((kind_of(k, v)?, ()))
}

fn empty_map(body: &Yaml) -> Result<(), String> {
    let map = body.as_map().map_err(|e| e.0)?;
    if map.is_empty() { Ok(()) } else { Err("expected {}".into()) }
}

fn literal(kind: &FieldKind, v: &Yaml) -> Result<FieldValue, String> {
    match kind {
        FieldKind::Bool => Ok(FieldValue::Bool(v.as_bool().map_err(|e| e.0)?)),
        FieldKind::Int { .. } => Ok(FieldValue::Int(v.as_i64().map_err(|e| e.0)?)),
        FieldKind::Float { .. } => Ok(FieldValue::float(v.as_f64().map_err(|e| e.0)?)),
        FieldKind::Text { .. } | FieldKind::Enum { .. } => Ok(FieldValue::text(v.as_str().map_err(|e| e.0)?)),
        FieldKind::Ref { .. } => {
            Ok(FieldValue::Ref(v.as_str().map_err(|e| e.0)?.parse().map_err(|_| "bad default ref".to_owned())?))
        }
        _ => Err("this kind cannot have a default".into()),
    }
}

fn type_list(node: &Yaml) -> Result<BTreeSet<TypeName>, String> {
    let mut set = BTreeSet::new();
    for item in node.as_seq().map_err(|e| e.0)? {
        let name: TypeName = item.as_str().map_err(|e| e.0)?.parse().map_err(|_| "bad type name".to_owned())?;
        set.insert(name);
    }
    Ok(set)
}

fn expect_keys(node: &Yaml, allowed: &[&str]) -> Result<(), String> {
    for key in node.keys().map_err(|e| e.0)? {
        if !allowed.contains(&key) {
            return Err(format!("unknown key {key}"));
        }
    }
    Ok(())
}

fn u32_of(v: &Yaml) -> Result<u32, String> {
    u32::try_from(v.as_i64().map_err(|e| e.0)?).map_err(|_| "not a u32".into())
}

fn opt_i64(body: &Yaml, key: &str) -> Result<Option<i64>, String> {
    match body.get(key) {
        None => Ok(None),
        Some(v) => Ok(Some(v.as_i64().map_err(|e| e.0)?)),
    }
}

fn opt_f64(body: &Yaml, key: &str) -> Result<Option<f64>, String> {
    match body.get(key) {
        None => Ok(None),
        Some(v) => Ok(Some(v.as_f64().map_err(|e| e.0)?)),
    }
}

fn opt_u32(body: &Yaml, key: &str) -> Result<Option<u32>, String> {
    match body.get(key) {
        None => Ok(None),
        Some(v) => Ok(Some(u32_of(v)?)),
    }
}

fn check_action_name(name: &str) -> Result<(), String> {
    let parts: Vec<_> = name.split('.').collect();
    if parts.len() < 2 || !parts.iter().all(|p| is_ident(p)) {
        return Err(format!("invalid action name {name}"));
    }
    Ok(())
}
