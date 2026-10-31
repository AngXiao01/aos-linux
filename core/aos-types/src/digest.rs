//! SHA-256 digests, written `sha256:<64 lowercase hex>` (SPEC §6.4, §7.1).

use std::fmt;
use std::str::FromStr;

use sha2::{Digest as _, Sha256};

use crate::cbor::{self, Value};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest([u8; 32]);

const PREFIX: &str = "sha256:";

impl Digest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Digest(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn of(data: &[u8]) -> Self {
        Digest(Sha256::digest(data).into())
    }

    /// Digest of the deterministic CBOR encoding of `value`.
    pub fn of_value(value: &Value) -> Self {
        Self::of(&cbor::encode(value))
    }
}

/// Incremental SHA-256 for data too large to hold in memory.
#[derive(Clone, Default)]
pub struct Hasher(Sha256);

impl Hasher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finish(self) -> Digest {
        Digest(self.0.finalize().into())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(PREFIX)?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseDigestError;

impl fmt::Display for ParseDigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected sha256: followed by 64 lowercase hex digits")
    }
}

impl std::error::Error for ParseDigestError {}

impl FromStr for Digest {
    type Err = ParseDigestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = s.strip_prefix(PREFIX).ok_or(ParseDigestError)?.as_bytes();
        if hex.len() != 64 {
            return Err(ParseDigestError);
        }
        let mut out = [0u8; 32];
        for (i, pair) in hex.chunks_exact(2).enumerate() {
            out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(Digest(out))
    }
}

fn nibble(c: u8) -> Result<u8, ParseDigestError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(ParseDigestError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABC: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn known_vector() {
        assert_eq!(Digest::of(b"abc").to_string(), ABC);
    }

    #[test]
    fn incremental_matches_one_shot() {
        let mut h = Hasher::new();
        h.update(b"a");
        h.update(b"bc");
        assert_eq!(h.finish(), Digest::of(b"abc"));
    }

    #[test]
    fn parse_round_trips_and_is_strict() {
        assert_eq!(ABC.parse::<Digest>().unwrap().to_string(), ABC);
        assert!(ABC.to_uppercase().parse::<Digest>().is_err());
        assert!(ABC.trim_end_matches('d').parse::<Digest>().is_err());
        assert!(ABC.replace("sha256:", "sha512:").parse::<Digest>().is_err());
    }
}
