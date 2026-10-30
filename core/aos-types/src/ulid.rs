//! ULIDs: 48-bit millisecond timestamp + 80 random bits, written as 26
//! Crockford base32 characters (SPEC §6.1).
//!
//! Time and randomness come from the caller through [`Clock`] and [`Entropy`];
//! this module performs no I/O.

use std::fmt;
use std::str::FromStr;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const RANDOM_BITS: u32 = 80;
const RANDOM_MASK: u128 = (1 << RANDOM_BITS) - 1;
/// Largest timestamp a ULID can hold.
pub const MAX_TIMESTAMP_MS: u64 = (1 << 48) - 1;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ulid(u128);

impl Ulid {
    pub const fn from_u128(n: u128) -> Self {
        Ulid(n)
    }

    pub const fn to_u128(self) -> u128 {
        self.0
    }

    pub fn from_parts(timestamp_ms: u64, random: u128) -> Option<Self> {
        if timestamp_ms > MAX_TIMESTAMP_MS || random > RANDOM_MASK {
            return None;
        }
        Some(Ulid(((timestamp_ms as u128) << RANDOM_BITS) | random))
    }

    pub fn timestamp_ms(self) -> u64 {
        (self.0 >> RANDOM_BITS) as u64
    }

    pub fn random(self) -> u128 {
        self.0 & RANDOM_MASK
    }
}

impl fmt::Display for Ulid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; 26];
        for (i, c) in buf.iter_mut().enumerate() {
            let shift = 125 - 5 * i as u32;
            *c = ALPHABET[((self.0 >> shift) & 31) as usize];
        }
        f.write_str(std::str::from_utf8(&buf).expect("alphabet is ASCII"))
    }
}

impl fmt::Debug for Ulid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseUlidError;

impl fmt::Display for ParseUlidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected 26 uppercase Crockford base32 characters, first at most 7")
    }
}

impl std::error::Error for ParseUlidError {}

/// Strict: uppercase only, no Crockford aliases (`I`, `L`, `O`, `U`), so every
/// ULID has exactly one textual form.
impl FromStr for Ulid {
    type Err = ParseUlidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();
        if bytes.len() != 26 {
            return Err(ParseUlidError);
        }
        let mut n: u128 = 0;
        for (i, &c) in bytes.iter().enumerate() {
            let v = ALPHABET.iter().position(|&a| a == c).ok_or(ParseUlidError)? as u128;
            if i == 0 && v > 7 {
                return Err(ParseUlidError);
            }
            n = (n << 5) | v;
        }
        Ok(Ulid(n))
    }
}

pub trait Clock {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> u64;
}

pub trait Entropy {
    fn fill(&mut self, buf: &mut [u8]);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UlidError {
    TimestampOutOfRange,
    /// More than 2^80 ids requested within one millisecond.
    RandomOverflow,
}

impl fmt::Display for UlidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UlidError::TimestampOutOfRange => f.write_str("clock beyond ULID range"),
            UlidError::RandomOverflow => f.write_str("ULID random component exhausted"),
        }
    }
}

impl std::error::Error for UlidError {}

/// Generates strictly increasing ULIDs. When the clock has not advanced (or
/// went backwards), the previous id is incremented instead of drawing new
/// randomness, so ids from one generator sort in creation order.
#[derive(Clone, Debug, Default)]
pub struct UlidGenerator {
    last: Option<Ulid>,
}

impl UlidGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next(&mut self, clock: &dyn Clock, entropy: &mut dyn Entropy) -> Result<Ulid, UlidError> {
        let now = clock.now_ms();
        if now > MAX_TIMESTAMP_MS {
            return Err(UlidError::TimestampOutOfRange);
        }
        let id = match self.last {
            Some(last) if now <= last.timestamp_ms() => {
                if last.random() == RANDOM_MASK {
                    return Err(UlidError::RandomOverflow);
                }
                Ulid(last.0 + 1)
            }
            _ => {
                let mut buf = [0u8; 16];
                entropy.fill(&mut buf[6..]);
                let random = u128::from_be_bytes(buf);
                Ulid::from_parts(now, random).expect("checked ranges")
            }
        };
        self.last = Some(id);
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedClock(u64);
    impl Clock for FixedClock {
        fn now_ms(&self) -> u64 {
            self.0
        }
    }

    struct Bytes(u8);
    impl Entropy for Bytes {
        fn fill(&mut self, buf: &mut [u8]) {
            buf.fill(self.0);
        }
    }

    #[test]
    fn timestamp_encoding_matches_reference() {
        // From the ULID specification: ulid(1469918176385) starts with 01ARYZ6S41.
        let id = Ulid::from_parts(1469918176385, 0).unwrap();
        assert!(id.to_string().starts_with("01ARYZ6S41"), "{id}");
        assert_eq!(id.to_string().parse::<Ulid>().unwrap().timestamp_ms(), 1469918176385);
    }

    #[test]
    fn text_round_trip_and_bounds() {
        let max = Ulid::from_u128(u128::MAX);
        assert_eq!(max.to_string(), "7ZZZZZZZZZZZZZZZZZZZZZZZZZ");
        assert_eq!("7ZZZZZZZZZZZZZZZZZZZZZZZZZ".parse::<Ulid>().unwrap(), max);
        assert_eq!(Ulid::from_u128(0).to_string(), "00000000000000000000000000");
        assert!("80000000000000000000000000".parse::<Ulid>().is_err());
        assert!("01arz3ndektsv4rrffq69g5fav".parse::<Ulid>().is_err());
        assert!("01ARZ3NDEKTSV4RRFFQ69G5FAU".parse::<Ulid>().is_err());
        assert!("01ARZ3NDEKTSV4RRFFQ69G5FA".parse::<Ulid>().is_err());
        let id: Ulid = "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap();
        assert_eq!(id.to_string(), "01ARZ3NDEKTSV4RRFFQ69G5FAV");
    }

    #[test]
    fn generator_is_strictly_increasing() {
        let mut g = UlidGenerator::new();
        let mut rng = Bytes(0x42);
        let a = g.next(&FixedClock(1000), &mut rng).unwrap();
        let b = g.next(&FixedClock(1000), &mut rng).unwrap();
        let c = g.next(&FixedClock(999), &mut rng).unwrap();
        let d = g.next(&FixedClock(1001), &mut rng).unwrap();
        assert!(a < b && b < c && c < d);
        assert_eq!(b.to_u128(), a.to_u128() + 1);
        assert_eq!(c.timestamp_ms(), 1000);
        assert_eq!(d.timestamp_ms(), 1001);
    }

    #[test]
    fn generator_reports_exhaustion() {
        let mut g = UlidGenerator::new();
        let mut rng = Bytes(0xff);
        g.next(&FixedClock(5), &mut rng).unwrap();
        assert_eq!(g.next(&FixedClock(5), &mut rng), Err(UlidError::RandomOverflow));
        assert_eq!(g.next(&FixedClock(MAX_TIMESTAMP_MS + 1), &mut rng), Err(UlidError::TimestampOutOfRange));
    }
}
