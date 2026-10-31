//! Deterministic time and randomness, for tests and simulations. Production
//! code supplies an OS clock and entropy source instead.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::ulid::{Clock, Entropy};

/// A clock that only moves when told to.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    pub fn new(start_ms: u64) -> Self {
        ManualClock(AtomicU64::new(start_ms))
    }

    pub fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::Relaxed);
    }

    pub fn set(&self, ms: u64) {
        self.0.store(ms, Ordering::Relaxed);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

impl<C: Clock + ?Sized> Clock for std::sync::Arc<C> {
    fn now_ms(&self) -> u64 {
        (**self).now_ms()
    }
}

/// SplitMix64: a seeded, reproducible byte stream. Not cryptographic.
#[derive(Clone, Debug)]
pub struct SeededEntropy(u64);

impl SeededEntropy {
    pub fn new(seed: u64) -> Self {
        SeededEntropy(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

impl Entropy for SeededEntropy {
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_entropy_is_reproducible() {
        let (mut a, mut b) = (SeededEntropy::new(7), SeededEntropy::new(7));
        let (mut x, mut y) = ([0u8; 13], [0u8; 13]);
        a.fill(&mut x);
        b.fill(&mut y);
        assert_eq!(x, y);
        assert_ne!(x, [0u8; 13]);
    }

    #[test]
    fn manual_clock_moves_on_request() {
        let c = ManualClock::new(10);
        c.advance(5);
        assert_eq!(c.now_ms(), 15);
        c.set(3);
        assert_eq!(c.now_ms(), 3);
    }
}
