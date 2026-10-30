//! Deterministic CBOR (RFC 8949 §4.2.1), the only encoding used for hashing
//! and signing (SPEC §7.1).
//!
//! The decoder accepts exactly the byte strings the encoder produces: for any
//! input `b`, `decode(b)` succeeds iff `encode(&decode(b)?) == b`. Hashes and
//! signatures can therefore be checked against decoded values without keeping
//! the original bytes around.

mod decode;
mod encode;
mod float;

use std::collections::BTreeMap;

pub use decode::{DecodeError, MAX_DEPTH, decode};
pub use encode::{encode, encode_into};

/// A CBOR data item, restricted to what AOS uses: 64-bit integers, byte and
/// text strings, arrays, maps, tags, `false`/`true`/`null` and floats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// Major type 0: the integer `n`.
    Unsigned(u64),
    /// Major type 1: the integer `-1 - n`.
    Negative(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Map),
    Tag(u64, Box<Value>),
    Bool(bool),
    Null,
    Float(F64),
}

/// An `f64` compared by its canonical encoding: all NaNs are equal, and
/// `0.0 != -0.0`.
#[derive(Clone, Copy, Debug)]
pub struct F64(pub f64);

impl F64 {
    fn canonical_bits(self) -> u64 {
        if self.0.is_nan() { f64::NAN.to_bits() } else { self.0.to_bits() }
    }
}

impl PartialEq for F64 {
    fn eq(&self, other: &Self) -> bool {
        self.canonical_bits() == other.canonical_bits()
    }
}

impl Eq for F64 {}

/// A CBOR map. Entries are kept in canonical order: bytewise lexicographic
/// order of the keys' deterministic encodings (RFC 8949 §4.2.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Map {
    entries: BTreeMap<Vec<u8>, (Value, Value)>,
}

impl Map {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts an entry, returning the previous value for an equal key.
    pub fn insert(&mut self, key: Value, value: Value) -> Option<Value> {
        self.entries.insert(encode(&key), (key, value)).map(|(_, old)| old)
    }

    pub fn get(&self, key: &Value) -> Option<&Value> {
        self.entries.get(&encode(key)).map(|(_, v)| v)
    }

    pub fn remove(&mut self, key: &Value) -> Option<Value> {
        self.entries.remove(&encode(key)).map(|(_, v)| v)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterates in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = (&Value, &Value)> {
        self.entries.values().map(|(k, v)| (k, v))
    }
}

/// Later entries replace earlier ones with an equal key.
impl FromIterator<(Value, Value)> for Map {
    fn from_iter<I: IntoIterator<Item = (Value, Value)>>(iter: I) -> Self {
        let mut map = Map::new();
        for (k, v) in iter {
            map.insert(k, v);
        }
        map
    }
}

impl Value {
    pub fn int(n: i64) -> Value {
        if n >= 0 {
            Value::Unsigned(n as u64)
        } else {
            // -1 - m = n  <=>  m = !n (two's complement)
            Value::Negative(!(n as u64))
        }
    }

    pub fn text(s: impl Into<String>) -> Value {
        Value::Text(s.into())
    }

    pub fn float(f: f64) -> Value {
        Value::Float(F64(f))
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Unsigned(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Unsigned(n) => i64::try_from(*n).ok(),
            Value::Negative(n) => i64::try_from(*n).ok().map(|m| !m),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Float(f) => Some(f.0),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&Map> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_tag(&self) -> Option<(u64, &Value)> {
        match self {
            Value::Tag(t, v) => Some((*t, v)),
            _ => None,
        }
    }
}

impl From<u64> for Value {
    fn from(n: u64) -> Self {
        Value::Unsigned(n)
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Value::int(n)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Text(s.to_owned())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Text(s)
    }
}

impl From<Vec<Value>> for Value {
    fn from(a: Vec<Value>) -> Self {
        Value::Array(a)
    }
}

impl From<Map> for Value {
    fn from(m: Map) -> Self {
        Value::Map(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_conversions_cover_i64_range() {
        for n in [0, 1, -1, -10, 23, -24, i64::MAX, i64::MIN] {
            assert_eq!(Value::int(n).as_i64(), Some(n), "{n}");
        }
        assert_eq!(Value::Negative(u64::MAX).as_i64(), None);
        assert_eq!(Value::Unsigned(u64::MAX).as_i64(), None);
    }

    #[test]
    fn map_orders_by_encoded_key() {
        // Shorter text keys sort first because the length is in the header.
        let m: Map =
            [("bb", 1), ("a", 2), ("c", 3)].into_iter().map(|(k, v)| (Value::from(k), Value::int(v))).collect();
        let keys: Vec<_> = m.iter().map(|(k, _)| k.as_text().unwrap()).collect();
        assert_eq!(keys, ["a", "c", "bb"]);
    }

    #[test]
    fn map_replaces_equal_keys() {
        let mut m = Map::new();
        assert_eq!(m.insert("k".into(), Value::int(1)), None);
        assert_eq!(m.insert("k".into(), Value::int(2)), Some(Value::int(1)));
        assert_eq!(m.len(), 1);
        assert_eq!(m.get(&"k".into()), Some(&Value::int(2)));
    }

    #[test]
    fn nan_equality_is_canonical() {
        assert_eq!(F64(f64::NAN), F64(-f64::NAN));
        assert_ne!(F64(0.0), F64(-0.0));
    }
}
