//! Type declarations: field kinds, object validation and type evolution
//! (SPEC §6.2, §6.5).

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use crate::cbor::{F64, Value};
use crate::codec::{self, FromCbor, Record, SchemaError, ToCbor, record};
use crate::id::{ObjectId, ParseError, is_ident, is_type_ident, parse_version};
use crate::object::Object;
use crate::template::Template;
use crate::value::FieldValue;

/// `provider/Name`, e.g. `ml/DatasetVersion`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeName {
    provider: String,
    name: String,
}

impl TypeName {
    pub fn new(provider: &str, name: &str) -> Option<Self> {
        (is_ident(provider) && is_type_ident(name))
            .then(|| TypeName { provider: provider.to_owned(), name: name.to_owned() })
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for TypeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.provider, self.name)
    }
}

impl fmt::Debug for TypeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for TypeName {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (provider, name) = s.split_once('/').ok_or(ParseError("expected provider/Name"))?;
        TypeName::new(provider, name).ok_or(ParseError("invalid type name"))
    }
}

/// A type at a major version: `ml/DatasetVersion@1`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeRef {
    pub name: TypeName,
    pub major: u32,
}

impl fmt::Display for TypeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.major)
    }
}

impl fmt::Debug for TypeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for TypeRef {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (name, major) = s.split_once('@').ok_or(ParseError("expected provider/Name@major"))?;
        let major = u32::try_from(parse_version(major)?).map_err(|_| ParseError("major too large"))?;
        Ok(TypeRef { name: name.parse()?, major })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldKind {
    Bool,
    Int {
        min: Option<i64>,
        max: Option<i64>,
    },
    /// Values must be finite.
    Float {
        min: Option<F64>,
        max: Option<F64>,
    },
    /// `max` counts Unicode scalar values.
    Text {
        max: Option<u32>,
    },
    Enum {
        values: Vec<String>,
    },
    Ref {
        target: TypeName,
    },
    Blob,
    Timestamp,
    List {
        of: Box<FieldKind>,
        max_len: Option<u32>,
    },
    Map {
        values: Box<FieldKind>,
    },
}

impl FieldKind {
    pub fn name(&self) -> &'static str {
        match self {
            FieldKind::Bool => "bool",
            FieldKind::Int { .. } => "int",
            FieldKind::Float { .. } => "float",
            FieldKind::Text { .. } => "text",
            FieldKind::Enum { .. } => "enum",
            FieldKind::Ref { .. } => "ref",
            FieldKind::Blob => "blob",
            FieldKind::Timestamp => "timestamp",
            FieldKind::List { .. } => "list",
            FieldKind::Map { .. } => "map",
        }
    }

    /// Whether values of this kind cannot carry free text, and so may be shown
    /// to the planning model even when tainted (SPEC §6.2, §10).
    pub fn is_constrained(&self) -> bool {
        match self {
            FieldKind::Bool
            | FieldKind::Int { .. }
            | FieldKind::Float { .. }
            | FieldKind::Enum { .. }
            | FieldKind::Ref { .. }
            | FieldKind::Blob
            | FieldKind::Timestamp => true,
            FieldKind::List { of, .. } => of.is_constrained(),
            FieldKind::Text { .. } | FieldKind::Map { .. } => false,
        }
    }

    fn check_decl(&self, path: &str, problems: &mut Vec<Problem>) {
        let mut bad = |kind| problems.push(Problem::new(path, kind));
        match self {
            FieldKind::Int { min: Some(lo), max: Some(hi) } if lo > hi => bad(ProblemKind::BadBounds),
            FieldKind::Float { min, max } => {
                let (lo, hi) = (min.map(|f| f.0), max.map(|f| f.0));
                if lo.is_some_and(|f| !f.is_finite()) || hi.is_some_and(|f| !f.is_finite()) {
                    bad(ProblemKind::BadBounds);
                } else if let (Some(lo), Some(hi)) = (lo, hi)
                    && lo > hi
                {
                    bad(ProblemKind::BadBounds);
                }
            }
            FieldKind::Text { max: Some(0) } => bad(ProblemKind::BadBounds),
            FieldKind::Enum { values } => {
                if values.is_empty() {
                    bad(ProblemKind::EmptyEnum);
                }
                for (i, v) in values.iter().enumerate() {
                    if v.is_empty() || values[..i].contains(v) {
                        bad(ProblemKind::BadEnumValue(v.clone()));
                    }
                }
            }
            FieldKind::List { of, .. } => of.check_decl(&format!("{path}[]"), problems),
            FieldKind::Map { values } => values.check_decl(&format!("{path}{{}}"), problems),
            _ => {}
        }
    }

    fn check_value(&self, v: &FieldValue, path: &str, refs: Option<&dyn RefTypes>, problems: &mut Vec<Problem>) {
        let mut bad = |kind| problems.push(Problem::new(path, kind));
        match (self, v) {
            (FieldKind::Bool, FieldValue::Bool(_))
            | (FieldKind::Blob, FieldValue::Blob(_))
            | (FieldKind::Timestamp, FieldValue::Timestamp(_)) => {}
            (FieldKind::Int { min, max }, FieldValue::Int(n)) => {
                if min.is_some_and(|m| *n < m) || max.is_some_and(|m| *n > m) {
                    bad(ProblemKind::OutOfRange);
                }
            }
            (FieldKind::Float { min, max }, FieldValue::Float(f)) => {
                let f = f.0;
                if !f.is_finite() {
                    bad(ProblemKind::NonFinite);
                } else if min.is_some_and(|m| f < m.0) || max.is_some_and(|m| f > m.0) {
                    bad(ProblemKind::OutOfRange);
                }
            }
            (FieldKind::Text { max }, FieldValue::Text(s)) => {
                if let Some(max) = max
                    && s.chars().count() > *max as usize
                {
                    bad(ProblemKind::TooLong { max: *max });
                }
            }
            (FieldKind::Enum { values }, FieldValue::Text(s)) => {
                if !values.contains(s) {
                    bad(ProblemKind::NotInEnum);
                }
            }
            (FieldKind::Ref { target }, FieldValue::Ref(r)) => {
                if let Some(refs) = refs {
                    match refs.type_of(r.id) {
                        None => bad(ProblemKind::DanglingRef),
                        Some(found) if found != *target => {
                            bad(ProblemKind::RefTarget { expected: target.clone(), found })
                        }
                        Some(_) => {}
                    }
                }
            }
            (FieldKind::List { of, max_len }, FieldValue::List(items)) => {
                if let Some(max) = max_len
                    && items.len() > *max as usize
                {
                    bad(ProblemKind::TooLong { max: *max });
                }
                for (i, item) in items.iter().enumerate() {
                    of.check_value(item, &format!("{path}[{i}]"), refs, problems);
                }
            }
            (FieldKind::Map { values }, FieldValue::Map(m)) => {
                for (k, item) in m {
                    values.check_value(item, &format!("{path}{{{k:?}}}"), refs, problems);
                }
            }
            (expected, found) => bad(ProblemKind::WrongKind { expected: expected.name(), found: found.kind_name() }),
        }
    }

    fn entries(&self) -> Vec<(&'static str, Value)> {
        let mut e = vec![("kind", Value::from(self.name()))];
        match self {
            FieldKind::Int { min, max } => {
                e.extend(min.map(|m| ("min", Value::int(m))));
                e.extend(max.map(|m| ("max", Value::int(m))));
            }
            FieldKind::Float { min, max } => {
                e.extend(min.map(|m| ("min", Value::Float(m))));
                e.extend(max.map(|m| ("max", Value::Float(m))));
            }
            FieldKind::Text { max } => e.extend(max.map(|m| ("max", Value::Unsigned(m as u64)))),
            FieldKind::Enum { values } => {
                e.push(("values", Value::Array(values.iter().map(|v| Value::from(v.as_str())).collect())))
            }
            FieldKind::Ref { target } => e.push(("target", Value::from(target.to_string()))),
            FieldKind::List { of, max_len } => {
                e.push(("of", of.to_cbor()));
                e.extend(max_len.map(|m| ("max_len", Value::Unsigned(m as u64))));
            }
            FieldKind::Map { values } => e.push(("values", values.to_cbor())),
            FieldKind::Bool | FieldKind::Blob | FieldKind::Timestamp => {}
        }
        e
    }

    fn read(r: &mut Record<'_>) -> Result<Self, SchemaError> {
        let kind = r.req("kind", codec::text)?;
        Ok(match kind {
            "bool" => FieldKind::Bool,
            "int" => FieldKind::Int { min: r.opt("min", codec::int)?, max: r.opt("max", codec::int)? },
            "float" => FieldKind::Float {
                min: r.opt("min", |v| codec::float(v).map(F64))?,
                max: r.opt("max", |v| codec::float(v).map(F64))?,
            },
            "text" => FieldKind::Text { max: r.opt("max", uint32)? },
            "enum" => FieldKind::Enum {
                values: r
                    .req("values", |v| codec::array(v)?.iter().map(|x| codec::text(x).map(str::to_owned)).collect())?,
            },
            "ref" => FieldKind::Ref { target: r.req("target", codec::parsed)? },
            "blob" => FieldKind::Blob,
            "timestamp" => FieldKind::Timestamp,
            "list" => {
                FieldKind::List { of: Box::new(r.req("of", FieldKind::from_cbor)?), max_len: r.opt("max_len", uint32)? }
            }
            "map" => FieldKind::Map { values: Box::new(r.req("values", FieldKind::from_cbor)?) },
            other => return Err(SchemaError::new(format!("unknown field kind {other:?}")).within("kind")),
        })
    }
}

fn uint32(v: &Value) -> Result<u32, SchemaError> {
    u32::try_from(codec::uint(v)?).map_err(|_| SchemaError::new("exceeds u32"))
}

impl ToCbor for FieldKind {
    fn to_cbor(&self) -> Value {
        record(self.entries())
    }
}

impl FromCbor for FieldKind {
    fn from_cbor(v: &Value) -> Result<Self, SchemaError> {
        let mut r = Record::new(v)?;
        let kind = FieldKind::read(&mut r)?;
        r.finish()?;
        Ok(kind)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDecl {
    pub kind: FieldKind,
    pub required: bool,
}

impl ToCbor for FieldDecl {
    fn to_cbor(&self) -> Value {
        let mut e = self.kind.entries();
        e.push(("required", Value::Bool(self.required)));
        record(e)
    }
}

impl FromCbor for FieldDecl {
    fn from_cbor(v: &Value) -> Result<Self, SchemaError> {
        let mut r = Record::new(v)?;
        let required = r.req("required", codec::boolean)?;
        let kind = FieldKind::read(&mut r)?;
        r.finish()?;
        Ok(FieldDecl { kind, required })
    }
}

/// A reverse relation: all objects of type `many` whose field `via` refers to
/// this object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationDecl {
    pub many: TypeName,
    pub via: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ViewHint {
    /// A [`Template`] over this type's fields.
    pub title: Option<String>,
    pub primary_fields: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeDecl {
    pub name: TypeName,
    pub major: u32,
    pub fields: BTreeMap<String, FieldDecl>,
    pub relations: BTreeMap<String, RelationDecl>,
    pub view_hint: ViewHint,
}

/// Looks up the type of a referenced object, so that `ref` fields can be
/// checked against their declared target.
pub trait RefTypes {
    fn type_of(&self, id: ObjectId) -> Option<TypeName>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// Field path, or a declaration element such as `view_hint.title`.
    pub path: String,
    pub kind: ProblemKind,
}

impl Problem {
    fn new(path: &str, kind: ProblemKind) -> Self {
        Problem { path: path.to_owned(), kind }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProblemKind {
    // Object problems.
    WrongType { expected: TypeRef, found: TypeRef },
    Missing,
    Undeclared,
    DeclaredFieldInExtra,
    WrongKind { expected: &'static str, found: &'static str },
    OutOfRange,
    NonFinite,
    TooLong { max: u32 },
    NotInEnum,
    DanglingRef,
    RefTarget { expected: TypeName, found: TypeName },
    // Declaration problems.
    BadName,
    BadMajor,
    BadBounds,
    EmptyEnum,
    BadEnumValue(String),
    BadTemplate(String),
    UnknownField,
}

/// Fields a template path may start from besides declared fields.
const BUILTIN_PATHS: [&str; 2] = ["id", "version"];

impl TypeDecl {
    pub fn type_ref(&self) -> TypeRef {
        TypeRef { name: self.name.clone(), major: self.major }
    }

    /// Fields whose values may reach the planning model even when the object
    /// is tainted (SPEC §10).
    pub fn constrained_fields(&self) -> impl Iterator<Item = &str> {
        self.fields.iter().filter(|(_, d)| d.kind.is_constrained()).map(|(n, _)| n.as_str())
    }

    /// Internal consistency of the declaration itself.
    pub fn check_decl(&self) -> Result<(), Vec<Problem>> {
        let mut problems = Vec::new();
        if self.major == 0 {
            problems.push(Problem::new("major", ProblemKind::BadMajor));
        }
        for (name, decl) in &self.fields {
            if !is_ident(name) {
                problems.push(Problem::new(name, ProblemKind::BadName));
            }
            decl.kind.check_decl(name, &mut problems);
        }
        for (name, rel) in &self.relations {
            if !is_ident(name) || !is_ident(&rel.via) {
                problems.push(Problem::new(&format!("relations.{name}"), ProblemKind::BadName));
            }
        }
        if let Some(title) = &self.view_hint.title {
            match title.parse::<Template>() {
                Err(e) => problems.push(Problem::new("view_hint.title", ProblemKind::BadTemplate(e.0))),
                Ok(t) => {
                    for path in t.paths() {
                        let head = path[0].as_str();
                        if !self.fields.contains_key(head) && !BUILTIN_PATHS.contains(&head) {
                            problems.push(Problem::new("view_hint.title", ProblemKind::UnknownField));
                        }
                    }
                }
            }
        }
        for f in &self.view_hint.primary_fields {
            if !self.fields.contains_key(f) {
                problems.push(Problem::new("view_hint.primary_fields", ProblemKind::UnknownField));
            }
        }
        if problems.is_empty() { Ok(()) } else { Err(problems) }
    }

    /// Checks an object against this declaration. Ref targets are checked only
    /// when `refs` is given. Tombstones are not checked: they only mean
    /// "deleted".
    pub fn check_object(&self, obj: &Object, refs: Option<&dyn RefTypes>) -> Result<(), Vec<Problem>> {
        if obj.type_ref != self.type_ref() {
            return Err(vec![Problem::new(
                "type",
                ProblemKind::WrongType { expected: self.type_ref(), found: obj.type_ref.clone() },
            )]);
        }
        if obj.tombstone {
            return Ok(());
        }
        let mut problems = Vec::new();
        for (name, decl) in &self.fields {
            match obj.fields.get(name) {
                Some(v) => decl.kind.check_value(v, name, refs, &mut problems),
                None if decl.required => problems.push(Problem::new(name, ProblemKind::Missing)),
                None => {}
            }
        }
        for name in obj.fields.keys().filter(|n| !self.fields.contains_key(*n)) {
            problems.push(Problem::new(name, ProblemKind::Undeclared));
        }
        for name in obj.extra.keys().filter(|n| self.fields.contains_key(*n)) {
            problems.push(Problem::new(name, ProblemKind::DeclaredFieldInExtra));
        }
        if problems.is_empty() { Ok(()) } else { Err(problems) }
    }
}

impl ToCbor for TypeDecl {
    fn to_cbor(&self) -> Value {
        let fields = self.fields.iter().map(|(n, d)| (Value::from(n.as_str()), d.to_cbor())).collect();
        let relations = self
            .relations
            .iter()
            .map(|(n, r)| {
                let v = record([("many", Value::from(r.many.to_string())), ("via", Value::from(r.via.as_str()))]);
                (Value::from(n.as_str()), v)
            })
            .collect();
        let mut hint = vec![(
            "primary_fields",
            Value::Array(self.view_hint.primary_fields.iter().map(|f| Value::from(f.as_str())).collect()),
        )];
        hint.extend(self.view_hint.title.as_ref().map(|t| ("title", Value::from(t.as_str()))));
        record([
            ("type", Value::from(self.name.to_string())),
            ("major", Value::Unsigned(self.major as u64)),
            ("fields", Value::Map(fields)),
            ("relations", Value::Map(relations)),
            ("view_hint", record(hint)),
        ])
    }
}

impl FromCbor for TypeDecl {
    fn from_cbor(v: &Value) -> Result<Self, SchemaError> {
        let mut r = Record::new(v)?;
        let decl = TypeDecl {
            name: r.req("type", codec::parsed)?,
            major: r.req("major", uint32)?,
            fields: r.req("fields", |v| {
                codec::text_entries(v)?
                    .into_iter()
                    .map(|(k, v)| Ok((k.to_owned(), FieldDecl::from_cbor(v).map_err(|e| e.within(k))?)))
                    .collect()
            })?,
            relations: r.req("relations", |v| {
                codec::text_entries(v)?
                    .into_iter()
                    .map(|(k, v)| {
                        let mut rr = Record::new(v).map_err(|e| e.within(k))?;
                        let rel = RelationDecl {
                            many: rr.req("many", codec::parsed).map_err(|e| e.within(k))?,
                            via: rr.req("via", codec::text).map_err(|e| e.within(k))?.to_owned(),
                        };
                        rr.finish().map_err(|e| e.within(k))?;
                        Ok((k.to_owned(), rel))
                    })
                    .collect()
            })?,
            view_hint: r.req("view_hint", |v| {
                let mut hr = Record::new(v)?;
                let hint = ViewHint {
                    title: hr.opt("title", codec::text)?.map(str::to_owned),
                    primary_fields: hr.req("primary_fields", |v| {
                        codec::array(v)?.iter().map(|x| codec::text(x).map(str::to_owned)).collect()
                    })?,
                };
                hr.finish()?;
                Ok(hint)
            })?,
        };
        r.finish()?;
        Ok(decl)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evolution {
    /// Same major: existing objects stay valid in place.
    Compatible,
    /// Next major: needs a migration action (SPEC §6.5).
    NewMajor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvolutionError {
    NameChanged,
    /// Majors may only stay the same or increase by one.
    BadMajor,
    FieldChanged(String),
    FieldRemoved(String),
    NewRequiredField(String),
}

/// Classifies a change from `old` to `new`. Within a major, only optional
/// fields may be added and only `relations` and `view_hint` may change.
pub fn check_evolution(old: &TypeDecl, new: &TypeDecl) -> Result<Evolution, Vec<EvolutionError>> {
    if old.name != new.name {
        return Err(vec![EvolutionError::NameChanged]);
    }
    if old.major.checked_add(1) == Some(new.major) {
        return Ok(Evolution::NewMajor);
    }
    if new.major != old.major {
        return Err(vec![EvolutionError::BadMajor]);
    }
    let mut errors = Vec::new();
    for (name, decl) in &old.fields {
        match new.fields.get(name) {
            None => errors.push(EvolutionError::FieldRemoved(name.clone())),
            Some(d) if d != decl => errors.push(EvolutionError::FieldChanged(name.clone())),
            Some(_) => {}
        }
    }
    for (name, decl) in &new.fields {
        if !old.fields.contains_key(name) && decl.required {
            errors.push(EvolutionError::NewRequiredField(name.clone()));
        }
    }
    if errors.is_empty() { Ok(Evolution::Compatible) } else { Err(errors) }
}
