use super::{Value, float};

/// Encodes `value` deterministically.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

/// Appends the deterministic encoding of `value` to `out`.
pub fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Unsigned(n) => head(out, 0, *n),
        Value::Negative(n) => head(out, 1, *n),
        Value::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            head(out, 4, items.len() as u64);
            for item in items {
                encode_into(item, out);
            }
        }
        Value::Map(map) => {
            head(out, 5, map.len() as u64);
            for (key_bytes, (_, v)) in &map.entries {
                out.extend_from_slice(key_bytes);
                encode_into(v, out);
            }
        }
        Value::Tag(tag, inner) => {
            head(out, 6, *tag);
            encode_into(inner, out);
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
        Value::Float(f) => float::encode(f.0, out),
    }
}

/// Writes an initial byte plus argument in the shortest form.
fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= u8::MAX as u64 {
        out.push(m | 24);
        out.push(n as u8);
    } else if n <= u16::MAX as u64 {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}
