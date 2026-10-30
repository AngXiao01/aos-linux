//! Field values: the self-describing data stored in object fields and
//! `extra` (SPEC §6.1, §6.2).

use std::collections::BTreeMap;

use crate::cbor::{F64, Value};
use crate::codec::{self, FromCbor, SchemaError, ToCbor};
use crate::digest::Digest;
use crate::id::ObjRef;
use crate::time::Timestamp;

/// CBOR tags for AOS-specific field values, from the IANA first-come
/// first-served range (unregistered; see DECISIONS.md).
pub const TAG_REF: u64 = 0x414F_5301;
pub const TAG_BLOB: u64 = 0x414F_5302;
pub const TAG_TIMESTAMP: u64 = 0x414F_5303;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldValue {
    /// Only inside `extra`, lists and maps; typed fields are either present
    /// with a value or absent.
    Null,
    Bool(bool),
    Int(i64),
    Float(F64),
    Text(String),
    Ref(ObjRef),
    Blob(Digest),
    Timestamp(Timestamp),
    List(Vec<FieldValue>),
    Map(BTreeMap<String, FieldValue>),
}

impl FieldValue {
    pub fn float(f: f64) -> Self {
        FieldValue::Float(F64(f))
    }

    pub fn text(s: impl Into<String>) -> Self {
        FieldValue::Text(s.into())
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            FieldValue::Null => "null",
            FieldValue::Bool(_) => "bool",
            FieldValue::Int(_) => "int",
            FieldValue::Float(_) => "float",
            FieldValue::Text(_) => "text",
            FieldValue::Ref(_) => "ref",
            FieldValue::Blob(_) => "blob",
            FieldValue::Timestamp(_) => "timestamp",
            FieldValue::List(_) => "list",
            FieldValue::Map(_) => "map",
        }
    }

    /// Calls `f` for every blob digest in this value, recursively.
    pub fn visit_blobs(&self, f: &mut impl FnMut(Digest)) {
        match self {
            FieldValue::Blob(d) => f(*d),
            FieldValue::List(items) => items.iter().for_each(|v| v.visit_blobs(f)),
            FieldValue::Map(m) => m.values().for_each(|v| v.visit_blobs(f)),
            _ => {}
        }
    }
}

impl ToCbor for FieldValue {
    fn to_cbor(&self) -> Value {
        match self {
            FieldValue::Null => Value::Null,
            FieldValue::Bool(b) => Value::Bool(*b),
            FieldValue::Int(n) => Value::int(*n),
            FieldValue::Float(f) => Value::Float(*f),
            FieldValue::Text(s) => Value::Text(s.clone()),
            FieldValue::Ref(r) => Value::Tag(TAG_REF, Box::new(Value::Text(r.to_string()))),
            FieldValue::Blob(d) => Value::Tag(TAG_BLOB, Box::new(d.to_cbor())),
            FieldValue::Timestamp(t) => Value::Tag(TAG_TIMESTAMP, Box::new(Value::int(t.unix_ms()))),
            FieldValue::List(items) => Value::Array(items.iter().map(ToCbor::to_cbor).collect()),
            FieldValue::Map(m) => map_to_cbor(m),
        }
    }
}

pub(crate) fn map_to_cbor(m: &BTreeMap<String, FieldValue>) -> Value {
    Value::Map(m.iter().map(|(k, v)| (Value::from(k.as_str()), v.to_cbor())).collect())
}

pub(crate) fn map_from_cbor(v: &Value) -> Result<BTreeMap<String, FieldValue>, SchemaError> {
    codec::text_entries(v)?
        .into_iter()
        .map(|(k, v)| Ok((k.to_owned(), FieldValue::from_cbor(v).map_err(|e| e.within(k))?)))
        .collect()
}

impl FromCbor for FieldValue {
    fn from_cbor(v: &Value) -> Result<Self, SchemaError> {
        Ok(match v {
            Value::Null => FieldValue::Null,
            Value::Bool(b) => FieldValue::Bool(*b),
            Value::Unsigned(_) | Value::Negative(_) => FieldValue::Int(codec::int(v)?),
            Value::Float(f) => FieldValue::Float(*f),
            Value::Text(s) => FieldValue::Text(s.clone()),
            Value::Array(items) => FieldValue::List(
                items
                    .iter()
                    .enumerate()
                    .map(|(i, x)| FieldValue::from_cbor(x).map_err(|e| e.within(i)))
                    .collect::<Result<_, _>>()?,
            ),
            Value::Map(_) => FieldValue::Map(map_from_cbor(v)?),
            Value::Tag(TAG_REF, inner) => FieldValue::Ref(codec::parsed(inner)?),
            Value::Tag(TAG_BLOB, inner) => FieldValue::Blob(Digest::from_cbor(inner)?),
            Value::Tag(TAG_TIMESTAMP, inner) => FieldValue::Timestamp(
                Timestamp::from_unix_ms(codec::int(inner)?)
                    .ok_or_else(|| SchemaError::new("timestamp out of range"))?,
            ),
            Value::Tag(t, _) => return Err(SchemaError::new(format!("unknown tag {t:#x}"))),
            Value::Bytes(_) => return Err(SchemaError::new("bare byte strings are not field values")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor;

    #[test]
    fn tagged_values_round_trip() {
        let values = [
            FieldValue::Ref("01JC8Z3K9Q6V2X4M7N1P0R5T8W@3".parse().unwrap()),
            FieldValue::Blob(Digest::of(b"x")),
            FieldValue::Timestamp(Timestamp::from_unix_ms(-5).unwrap()),
            FieldValue::Map(BTreeMap::from([("a".into(), FieldValue::Null), ("bb".into(), FieldValue::Int(-1))])),
        ];
        for v in values {
            let bytes = v.to_canonical_bytes();
            assert_eq!(FieldValue::from_canonical_bytes(&bytes).unwrap(), v);
        }
    }

    #[test]
    fn ref_encoding_is_tagged_text() {
        let v = FieldValue::Ref("01JC8Z3K9Q6V2X4M7N1P0R5T8W".parse().unwrap());
        let bytes = v.to_canonical_bytes();
        assert_eq!(&bytes[..5], &[0xda, 0x41, 0x4f, 0x53, 0x01]);
        assert_eq!(bytes[5], 0x78); // text, one-byte length follows
        assert_eq!(bytes[6], 26);
    }

    #[test]
    fn rejects_foreign_shapes() {
        let bad = [
            Value::Bytes(vec![1]),
            Value::Tag(1, Box::new(Value::int(0))),
            Value::Tag(TAG_BLOB, Box::new(Value::Bytes(vec![0; 31]))),
            Value::Tag(TAG_REF, Box::new(Value::from("not-an-id"))),
            Value::Unsigned(u64::MAX),
            Value::Map([(Value::int(1), Value::Null)].into_iter().collect()),
        ];
        for v in bad {
            assert!(FieldValue::from_canonical_bytes(&cbor::encode(&v)).is_err(), "{v:?}");
        }
    }
}
