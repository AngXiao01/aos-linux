use std::fmt;

use super::{F64, Map, Value, float};

/// Maximum nesting of arrays, maps and tags accepted by [`decode`].
pub const MAX_DEPTH: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    UnexpectedEnd,
    TrailingBytes,
    /// An integer, length or tag not written in the shortest form.
    NonCanonicalHead,
    /// Indefinite-length item or a stray break code.
    Indefinite,
    /// Additional information 28–30.
    Reserved,
    /// A simple value other than `false`, `true`, `null`.
    UnsupportedSimple,
    /// A float with a shorter exact form, or a NaN other than `f9 7e00`.
    NonCanonicalFloat,
    /// Map keys not strictly increasing in encoded order (includes duplicates).
    UnsortedKeys,
    InvalidUtf8,
    TooDeep,
    /// A declared length that cannot fit in the remaining input.
    LengthTooLarge,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            DecodeError::UnexpectedEnd => "unexpected end of input",
            DecodeError::TrailingBytes => "trailing bytes after item",
            DecodeError::NonCanonicalHead => "integer or length not in shortest form",
            DecodeError::Indefinite => "indefinite-length item or stray break",
            DecodeError::Reserved => "reserved additional information",
            DecodeError::UnsupportedSimple => "unsupported simple value",
            DecodeError::NonCanonicalFloat => "float not in shortest form or non-canonical NaN",
            DecodeError::UnsortedKeys => "map keys not in canonical order or duplicated",
            DecodeError::InvalidUtf8 => "text string is not valid UTF-8",
            DecodeError::TooDeep => "nesting exceeds maximum depth",
            DecodeError::LengthTooLarge => "declared length exceeds input",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for DecodeError {}

/// Decodes exactly one deterministically encoded item spanning all of `bytes`.
pub fn decode(bytes: &[u8]) -> Result<Value, DecodeError> {
    let mut d = Decoder { buf: bytes, pos: 0 };
    let value = d.item(0)?;
    if d.pos != bytes.len() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(value)
}

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if n > self.remaining() {
            return Err(DecodeError::UnexpectedEnd);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn be<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        Ok(self.take(N)?.try_into().expect("take returned N bytes"))
    }

    /// Reads the argument of a head, rejecting non-shortest forms.
    fn argument(&mut self, info: u8) -> Result<u64, DecodeError> {
        let (n, min) = match info {
            0..=23 => return Ok(info as u64),
            24 => (self.byte()? as u64, 24),
            25 => (u16::from_be_bytes(self.be()?) as u64, 1 << 8),
            26 => (u32::from_be_bytes(self.be()?) as u64, 1 << 16),
            27 => (u64::from_be_bytes(self.be()?), 1 << 32),
            28..=30 => return Err(DecodeError::Reserved),
            _ => return Err(DecodeError::Indefinite),
        };
        if n < min {
            return Err(DecodeError::NonCanonicalHead);
        }
        Ok(n)
    }

    /// Reads a length and checks that `n * min_item_size` bytes remain.
    fn length(&mut self, info: u8, min_item_size: usize) -> Result<usize, DecodeError> {
        let n = usize::try_from(self.argument(info)?).map_err(|_| DecodeError::LengthTooLarge)?;
        match n.checked_mul(min_item_size) {
            Some(total) if total <= self.remaining() => Ok(n),
            _ => Err(DecodeError::LengthTooLarge),
        }
    }

    fn item(&mut self, depth: usize) -> Result<Value, DecodeError> {
        if depth > MAX_DEPTH {
            return Err(DecodeError::TooDeep);
        }
        let initial = self.byte()?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        match major {
            0 => Ok(Value::Unsigned(self.argument(info)?)),
            1 => Ok(Value::Negative(self.argument(info)?)),
            2 => {
                let n = self.length(info, 1)?;
                Ok(Value::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = self.length(info, 1)?;
                let bytes = self.take(n)?;
                let s = std::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8)?;
                Ok(Value::Text(s.to_owned()))
            }
            4 => {
                let n = self.length(info, 1)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let n = self.length(info, 2)?;
                let mut map = Map::new();
                let mut prev: Option<&[u8]> = None;
                for _ in 0..n {
                    let start = self.pos;
                    let key = self.item(depth + 1)?;
                    // The key was itself decoded strictly, so its bytes are
                    // its deterministic encoding.
                    let key_bytes = &self.buf[start..self.pos];
                    if prev.is_some_and(|p| key_bytes <= p) {
                        return Err(DecodeError::UnsortedKeys);
                    }
                    prev = Some(key_bytes);
                    let value = self.item(depth + 1)?;
                    map.entries.insert(key_bytes.to_vec(), (key, value));
                }
                Ok(Value::Map(map))
            }
            6 => {
                let tag = self.argument(info)?;
                let inner = self.item(depth + 1)?;
                Ok(Value::Tag(tag, Box::new(inner)))
            }
            _ => self.simple_or_float(info),
        }
    }

    fn simple_or_float(&mut self, info: u8) -> Result<Value, DecodeError> {
        match info {
            20 => Ok(Value::Bool(false)),
            21 => Ok(Value::Bool(true)),
            22 => Ok(Value::Null),
            25 => {
                let h = u16::from_be_bytes(self.be()?);
                let f = float::half_to_f64(h);
                if f.is_nan() && h != float::CANONICAL_NAN_HALF {
                    return Err(DecodeError::NonCanonicalFloat);
                }
                Ok(Value::Float(F64(f)))
            }
            26 => {
                let f = f32::from_bits(u32::from_be_bytes(self.be()?)) as f64;
                if f.is_nan() || float::half_exact(f).is_some() {
                    return Err(DecodeError::NonCanonicalFloat);
                }
                Ok(Value::Float(F64(f)))
            }
            27 => {
                let f = f64::from_bits(u64::from_be_bytes(self.be()?));
                if f.is_nan() || float::single_exact(f) {
                    return Err(DecodeError::NonCanonicalFloat);
                }
                Ok(Value::Float(F64(f)))
            }
            28..=30 => Err(DecodeError::Reserved),
            31 => Err(DecodeError::Indefinite),
            _ => Err(DecodeError::UnsupportedSimple),
        }
    }
}
