//! Conversions between AOS data structures and CBOR values.
//!
//! Every structure has exactly one CBOR form. Decoding is strict: unknown
//! keys, wrong types and non-canonical orderings are errors, so a decoded
//! structure re-encodes to the same bytes.

use std::fmt;
use std::str::FromStr;

use crate::cbor::{self, DecodeError, Map, Value};
use crate::digest::Digest;

pub trait ToCbor {
    fn to_cbor(&self) -> Value;

    fn to_canonical_bytes(&self) -> Vec<u8> {
        cbor::encode(&self.to_cbor())
    }

    fn digest(&self) -> Digest {
        Digest::of(&self.to_canonical_bytes())
    }
}

pub trait FromCbor: Sized {
    fn from_cbor(value: &Value) -> Result<Self, SchemaError>;

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_cbor(&cbor::decode(bytes)?)?)
    }
}

/// A CBOR value that does not have the expected shape. `path` locates it,
/// outermost first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaError {
    pub path: Vec<String>,
    pub message: String,
}

impl SchemaError {
    pub fn new(message: impl Into<String>) -> Self {
        SchemaError { path: Vec::new(), message: message.into() }
    }

    /// Prefixes the path with an enclosing key or index.
    pub fn within(mut self, segment: impl fmt::Display) -> Self {
        self.path.insert(0, segment.to_string());
        self
    }
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            f.write_str(&self.message)
        } else {
            write!(f, "{}: {}", self.path.join("."), self.message)
        }
    }
}

impl std::error::Error for SchemaError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Decode(DecodeError),
    Schema(SchemaError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decode(e) => write!(f, "decode: {e}"),
            Error::Schema(e) => write!(f, "schema: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Self {
        Error::Decode(e)
    }
}

impl From<SchemaError> for Error {
    fn from(e: SchemaError) -> Self {
        Error::Schema(e)
    }
}

/// Builds a map with text keys (the form every AOS record uses).
pub fn record<'a>(entries: impl IntoIterator<Item = (&'a str, Value)>) -> Value {
    Value::Map(entries.into_iter().map(|(k, v)| (Value::from(k), v)).collect())
}

/// Reads a map with text keys, tracking which keys were consumed so that
/// [`Record::finish`] can reject unknown ones.
pub struct Record<'a> {
    map: &'a Map,
    used: Vec<&'static str>,
}

impl<'a> Record<'a> {
    pub fn new(value: &'a Value) -> Result<Self, SchemaError> {
        let map = value.as_map().ok_or_else(|| SchemaError::new("expected map"))?;
        Ok(Record { map, used: Vec::new() })
    }

    pub fn req<T>(
        &mut self,
        key: &'static str,
        read: impl FnOnce(&'a Value) -> Result<T, SchemaError>,
    ) -> Result<T, SchemaError> {
        match self.opt(key, read)? {
            Some(v) => Ok(v),
            None => Err(SchemaError::new("missing").within(key)),
        }
    }

    pub fn opt<T>(
        &mut self,
        key: &'static str,
        read: impl FnOnce(&'a Value) -> Result<T, SchemaError>,
    ) -> Result<Option<T>, SchemaError> {
        let Some(v) = self.map.get(&Value::from(key)) else {
            return Ok(None);
        };
        self.used.push(key);
        read(v).map(Some).map_err(|e| e.within(key))
    }

    pub fn finish(self) -> Result<(), SchemaError> {
        if self.used.len() == self.map.len() {
            return Ok(());
        }
        let unknown: Vec<String> = self
            .map
            .iter()
            .filter(|(k, _)| !k.as_text().is_some_and(|k| self.used.contains(&k)))
            .map(|(k, _)| format!("{k:?}"))
            .collect();
        Err(SchemaError::new(format!("unknown keys {}", unknown.join(", "))))
    }
}

pub fn text(v: &Value) -> Result<&str, SchemaError> {
    v.as_text().ok_or_else(|| SchemaError::new("expected text"))
}

pub fn uint(v: &Value) -> Result<u64, SchemaError> {
    v.as_u64().ok_or_else(|| SchemaError::new("expected unsigned integer"))
}

pub fn int(v: &Value) -> Result<i64, SchemaError> {
    v.as_i64().ok_or_else(|| SchemaError::new("expected 64-bit signed integer"))
}

pub fn float(v: &Value) -> Result<f64, SchemaError> {
    v.as_f64().ok_or_else(|| SchemaError::new("expected float"))
}

pub fn boolean(v: &Value) -> Result<bool, SchemaError> {
    v.as_bool().ok_or_else(|| SchemaError::new("expected bool"))
}

pub fn array(v: &Value) -> Result<&[Value], SchemaError> {
    v.as_array().ok_or_else(|| SchemaError::new("expected array"))
}

/// Text parsed with `FromStr`.
pub fn parsed<T: FromStr>(v: &Value) -> Result<T, SchemaError>
where
    T::Err: fmt::Display,
{
    let s = text(v)?;
    s.parse().map_err(|e: T::Err| SchemaError::new(format!("{s:?}: {e}")))
}

/// Text map keys, iterated in canonical order.
pub fn text_entries(v: &Value) -> Result<Vec<(&str, &Value)>, SchemaError> {
    let map = v.as_map().ok_or_else(|| SchemaError::new("expected map"))?;
    map.iter().map(|(k, v)| Ok((text(k).map_err(|e| e.within("<key>"))?, v))).collect()
}

impl ToCbor for Digest {
    fn to_cbor(&self) -> Value {
        Value::Bytes(self.as_bytes().to_vec())
    }
}

impl FromCbor for Digest {
    fn from_cbor(v: &Value) -> Result<Self, SchemaError> {
        let bytes = v.as_bytes().ok_or_else(|| SchemaError::new("expected byte string"))?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| SchemaError::new("digest must be 32 bytes"))?;
        Ok(Digest::from_bytes(arr))
    }
}
