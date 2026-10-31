//! Shortest-form floats: a value is written in the narrowest of f16, f32 and
//! f64 that represents it exactly; NaN is always `f9 7e00`.

/// The only NaN encoding accepted (RFC 8949 §4.2.2).
pub(super) const CANONICAL_NAN_HALF: u16 = 0x7e00;

pub(super) fn encode(f: f64, out: &mut Vec<u8>) {
    if f.is_nan() {
        out.push(0xf9);
        out.extend_from_slice(&CANONICAL_NAN_HALF.to_be_bytes());
    } else if let Some(h) = half_exact(f) {
        out.push(0xf9);
        out.extend_from_slice(&h.to_be_bytes());
    } else if single_exact(f) {
        out.push(0xfa);
        out.extend_from_slice(&(f as f32).to_bits().to_be_bytes());
    } else {
        out.push(0xfb);
        out.extend_from_slice(&f.to_bits().to_be_bytes());
    }
}

/// The binary16 bits of `f` if `f` (not NaN) is exactly representable.
pub(super) fn half_exact(f: f64) -> Option<u16> {
    let bits = f.to_bits();
    let sign = ((bits >> 63) as u16) << 15;
    if f == 0.0 {
        return Some(sign);
    }
    if f.is_infinite() {
        return Some(sign | 0x7c00);
    }
    if f.is_nan() {
        return None;
    }
    let biased = ((bits >> 52) & 0x7ff) as i32;
    if biased == 0 {
        // f64 subnormals are far below the f16 range.
        return None;
    }
    let exp = biased - 1023;
    let mant = bits & ((1u64 << 52) - 1);
    if exp > 15 {
        return None;
    }
    if exp >= -14 {
        // Normal f16: 10 mantissa bits, so the low 42 bits must be zero.
        if mant & ((1u64 << 42) - 1) != 0 {
            return None;
        }
        let e16 = (exp + 15) as u16;
        return Some(sign | (e16 << 10) | (mant >> 42) as u16);
    }
    if exp < -24 {
        return None;
    }
    // Subnormal f16: value = m * 2^-24 with 1 <= m < 1024.
    let significand = (1u64 << 52) | mant;
    let shift = (28 - exp) as u32;
    if significand & ((1u64 << shift) - 1) != 0 {
        return None;
    }
    Some(sign | (significand >> shift) as u16)
}

pub(super) fn half_to_f64(h: u16) -> f64 {
    let sign = if h & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exp = (h >> 10) & 0x1f;
    let mant = (h & 0x3ff) as f64;
    match exp {
        0 => sign * mant * 2f64.powi(-24),
        31 if mant == 0.0 => sign * f64::INFINITY,
        31 => f64::NAN,
        _ => sign * (1.0 + mant / 1024.0) * 2f64.powi(exp as i32 - 15),
    }
}

/// Whether `f` (not NaN) is exactly representable as an f32.
pub(super) fn single_exact(f: f64) -> bool {
    (f as f32) as f64 == f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_half_value_round_trips_as_half() {
        for h in 0..=u16::MAX {
            let f = half_to_f64(h);
            if f.is_nan() {
                continue;
            }
            assert_eq!(half_exact(f), Some(h), "{h:#06x} -> {f}");
        }
    }

    #[test]
    fn values_between_halves_are_rejected() {
        for f in [1.0 + 2f64.powi(-11), 65520.0, 2f64.powi(-25), 1e-300, 0.1] {
            assert_eq!(half_exact(f), None, "{f}");
        }
    }

    #[test]
    fn single_detection() {
        assert!(single_exact(100000.0));
        assert!(single_exact(f32::MAX as f64));
        assert!(!single_exact(1.1));
        assert!(!single_exact(1e300));
    }
}
