//! Objects and their provenance (SPEC §6.1).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use crate::cbor::Value;
use crate::codec::{self, FromCbor, Record, SchemaError, ToCbor, record};
use crate::digest::Digest;
use crate::id::{Actor, ObjRef, ObjectId, ParseError, TxId, is_ident, is_slug};
use crate::schema::TypeRef;
use crate::time::Timestamp;
use crate::value::{self, FieldValue};

/// Whether data came from outside the system (SPEC §10). `Clean < External`,
/// so the taint of derived data is the maximum of its inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Taint {
    Clean,
    External,
}

/// `Public < Internal < Private < Secret`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sensitivity {
    Public,
    Internal,
    /// Default for user data.
    #[default]
    Private,
    Secret,
}

macro_rules! text_enum {
    ($ty:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        impl $ty {
            pub fn as_str(self) -> &'static str {
                match self { $($ty::$variant => $text),+ }
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl FromStr for $ty {
            type Err = ParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($text => Ok($ty::$variant),)+
                    _ => Err(ParseError(concat!("unknown ", stringify!($ty)))),
                }
            }
        }
    };
}

text_enum!(Taint { Clean => "clean", External => "external" });
text_enum!(Sensitivity { Public => "public", Internal => "internal", Private => "private", Secret => "secret" });

/// Where an object came from. External objects are created only by the
/// ingress gateway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    Internal,
    External { adapter: String, external_id: String, fetched_at: Timestamp },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provenance {
    pub actor: Actor,
    pub origin: Origin,
    pub taint: Taint,
    /// Exact versions this object was derived from.
    pub derived_from: BTreeSet<ObjRef>,
    pub tx: TxId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    pub id: ObjectId,
    pub type_ref: TypeRef,
    /// Concurrency counter, starting at 1. Carries no business meaning.
    pub version: u64,
    pub fields: BTreeMap<String, FieldValue>,
    pub provenance: Provenance,
    pub sensitivity: Sensitivity,
    /// Fields the type does not declare (SPEC §6.5).
    pub extra: BTreeMap<String, FieldValue>,
    /// This version marks the object as deleted (SPEC §6.3).
    pub tombstone: bool,
}

impl Object {
    /// Structural invariants that hold regardless of the object's type.
    /// Decoding enforces them; type-specific rules live in
    /// [`TypeDecl::check_object`](crate::schema::TypeDecl::check_object).
    pub fn check_shape(&self) -> Result<(), SchemaError> {
        if self.version == 0 {
            return Err(SchemaError::new("versions start at 1").within("version"));
        }
        for (section, map) in [("fields", &self.fields), ("extra", &self.extra)] {
            for name in map.keys() {
                if !is_ident(name) {
                    return Err(SchemaError::new("invalid field name").within(name).within(section));
                }
            }
        }
        if let Some((name, _)) = self.fields.iter().find(|(_, v)| **v == FieldValue::Null) {
            return Err(SchemaError::new("typed fields cannot be null; omit them").within(name).within("fields"));
        }
        if let Some(name) = self.fields.keys().find(|k| self.extra.contains_key(*k)) {
            return Err(SchemaError::new("present in both fields and extra").within(name).within("extra"));
        }
        let p = &self.provenance;
        if p.derived_from.iter().any(|r| r.version.is_none()) {
            return Err(SchemaError::new("derived_from must pin versions").within("derived_from").within("provenance"));
        }
        if let Origin::External { adapter, external_id, .. } = &p.origin {
            if p.taint != Taint::External {
                return Err(SchemaError::new("external origin implies external taint").within("provenance"));
            }
            if !is_slug(adapter) || external_id.is_empty() {
                return Err(SchemaError::new("invalid external origin").within("origin").within("provenance"));
            }
        }
        Ok(())
    }

    /// The blobs this object references; this set decides blob retention
    /// (SPEC §6.4).
    pub fn blob_refs(&self) -> BTreeSet<Digest> {
        let mut out = BTreeSet::new();
        for v in self.fields.values().chain(self.extra.values()) {
            v.visit_blobs(&mut |d| {
                out.insert(d);
            });
        }
        out
    }

    /// A reference pinned to this version.
    pub fn pinned_ref(&self) -> ObjRef {
        ObjRef::at(self.id, self.version)
    }
}

impl ToCbor for Origin {
    fn to_cbor(&self) -> Value {
        match self {
            Origin::Internal => Value::from("internal"),
            Origin::External { adapter, external_id, fetched_at } => record([
                ("adapter", Value::from(adapter.as_str())),
                ("external_id", Value::from(external_id.as_str())),
                ("fetched_at", Value::int(fetched_at.unix_ms())),
            ]),
        }
    }
}

impl FromCbor for Origin {
    fn from_cbor(v: &Value) -> Result<Self, SchemaError> {
        if v.as_text() == Some("internal") {
            return Ok(Origin::Internal);
        }
        let mut r = Record::new(v)?;
        let origin = Origin::External {
            adapter: r.req("adapter", codec::text)?.to_owned(),
            external_id: r.req("external_id", codec::text)?.to_owned(),
            fetched_at: r.req("fetched_at", |v| {
                Timestamp::from_unix_ms(codec::int(v)?).ok_or_else(|| SchemaError::new("timestamp out of range"))
            })?,
        };
        r.finish()?;
        Ok(origin)
    }
}

impl ToCbor for Provenance {
    fn to_cbor(&self) -> Value {
        record([
            ("actor", Value::from(self.actor.to_string())),
            ("origin", self.origin.to_cbor()),
            ("taint", Value::from(self.taint.as_str())),
            ("derived_from", Value::Array(self.derived_from.iter().map(|r| Value::from(r.to_string())).collect())),
            ("tx", Value::from(self.tx.to_string())),
        ])
    }
}

impl FromCbor for Provenance {
    fn from_cbor(v: &Value) -> Result<Self, SchemaError> {
        let mut r = Record::new(v)?;
        let p = Provenance {
            actor: r.req("actor", codec::parsed)?,
            origin: r.req("origin", Origin::from_cbor)?,
            taint: r.req("taint", codec::parsed)?,
            derived_from: r.req("derived_from", sorted_refs)?,
            tx: r.req("tx", codec::parsed)?,
        };
        r.finish()?;
        Ok(p)
    }
}

/// An array of references in strictly increasing order, as a set encodes.
fn sorted_refs(v: &Value) -> Result<BTreeSet<ObjRef>, SchemaError> {
    let mut out = BTreeSet::new();
    for (i, item) in codec::array(v)?.iter().enumerate() {
        let r: ObjRef = codec::parsed(item).map_err(|e| e.within(i))?;
        if out.last().is_some_and(|last| *last >= r) {
            return Err(SchemaError::new("not strictly increasing").within(i));
        }
        out.insert(r);
    }
    Ok(out)
}

impl ToCbor for Object {
    fn to_cbor(&self) -> Value {
        record([
            ("id", Value::from(self.id.to_string())),
            ("type", Value::from(self.type_ref.to_string())),
            ("version", Value::Unsigned(self.version)),
            ("fields", value::map_to_cbor(&self.fields)),
            ("provenance", self.provenance.to_cbor()),
            ("sensitivity", Value::from(self.sensitivity.as_str())),
            ("extra", value::map_to_cbor(&self.extra)),
            ("tombstone", Value::Bool(self.tombstone)),
        ])
    }
}

impl FromCbor for Object {
    fn from_cbor(v: &Value) -> Result<Self, SchemaError> {
        let mut r = Record::new(v)?;
        let obj = Object {
            id: r.req("id", codec::parsed)?,
            type_ref: r.req("type", codec::parsed)?,
            version: r.req("version", codec::uint)?,
            fields: r.req("fields", value::map_from_cbor)?,
            provenance: r.req("provenance", Provenance::from_cbor)?,
            sensitivity: r.req("sensitivity", codec::parsed)?,
            extra: r.req("extra", value::map_from_cbor)?,
            tombstone: r.req("tombstone", codec::boolean)?,
        };
        r.finish()?;
        obj.check_shape()?;
        Ok(obj)
    }
}
