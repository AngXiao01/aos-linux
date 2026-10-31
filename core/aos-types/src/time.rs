//! Millisecond UTC timestamps, written `YYYY-MM-DDTHH:MM:SS.mmmZ`.

use std::fmt;
use std::str::FromStr;

const MS_PER_DAY: i64 = 86_400_000;

/// Milliseconds since the Unix epoch, limited to years 0000–9999 so the text
/// form is always fixed-width RFC 3339.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    pub const MIN: Timestamp = Timestamp(-62_167_219_200_000); // 0000-01-01T00:00:00.000Z
    pub const MAX: Timestamp = Timestamp(253_402_300_799_999); // 9999-12-31T23:59:59.999Z

    pub fn from_unix_ms(ms: i64) -> Option<Self> {
        (Self::MIN.0..=Self::MAX.0).contains(&ms).then_some(Timestamp(ms))
    }

    pub fn unix_ms(self) -> i64 {
        self.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let days = self.0.div_euclid(MS_PER_DAY);
        let ms_of_day = self.0.rem_euclid(MS_PER_DAY);
        let (y, m, d) = civil_from_days(days);
        let secs = ms_of_day / 1000;
        write!(
            f,
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
            secs / 3600,
            secs / 60 % 60,
            secs % 60,
            ms_of_day % 1000
        )
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseTimestampError;

impl fmt::Display for ParseTimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected YYYY-MM-DDTHH:MM:SS[.mmm]Z")
    }
}

impl std::error::Error for ParseTimestampError {}

/// Accepts `YYYY-MM-DDTHH:MM:SSZ` and `YYYY-MM-DDTHH:MM:SS.mmmZ`; UTC only, no
/// leap seconds.
impl FromStr for Timestamp {
    type Err = ParseTimestampError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let b = s.as_bytes();
        let ms = match b.len() {
            20 => 0,
            24 if b[19] == b'.' => digits(&b[20..23])?,
            _ => return Err(ParseTimestampError),
        };
        let fixed = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
        if fixed.iter().any(|&(i, c)| b[i] != c) || b[b.len() - 1] != b'Z' {
            return Err(ParseTimestampError);
        }
        let (y, mo, d) = (digits(&b[0..4])?, digits(&b[5..7])?, digits(&b[8..10])?);
        let (h, mi, sec) = (digits(&b[11..13])?, digits(&b[14..16])?, digits(&b[17..19])?);
        if !(1..=12).contains(&mo) || d < 1 || d > days_in_month(y, mo) || h > 23 || mi > 59 || sec > 59 {
            return Err(ParseTimestampError);
        }
        let days = days_from_civil(y, mo, d);
        let total = days * MS_PER_DAY + ((h * 60 + mi) * 60 + sec) * 1000 + ms;
        Timestamp::from_unix_ms(total).ok_or(ParseTimestampError)
    }
}

fn digits(b: &[u8]) -> Result<i64, ParseTimestampError> {
    b.iter().try_fold(0i64, |acc, &c| {
        if c.is_ascii_digit() { Ok(acc * 10 + (c - b'0') as i64) } else { Err(ParseTimestampError) }
    })
}

fn is_leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// Howard Hinnant's civil calendar algorithms (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(ms: i64) -> String {
        Timestamp::from_unix_ms(ms).unwrap().to_string()
    }

    #[test]
    fn known_instants() {
        assert_eq!(ts(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(ts(1469918176385), "2016-07-30T22:36:16.385Z");
        assert_eq!(ts(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(ts(-1), "1969-12-31T23:59:59.999Z");
        assert_eq!(Timestamp::MIN.to_string(), "0000-01-01T00:00:00.000Z");
        assert_eq!(Timestamp::MAX.to_string(), "9999-12-31T23:59:59.999Z");
    }

    #[test]
    fn parse_round_trip() {
        for ms in [0, -1, 1469918176385, Timestamp::MIN.0, Timestamp::MAX.0, 1_793_582_024_000] {
            let t = Timestamp::from_unix_ms(ms).unwrap();
            assert_eq!(t.to_string().parse::<Timestamp>().unwrap(), t);
        }
        assert_eq!("2026-11-02T01:13:44Z".parse::<Timestamp>().unwrap().to_string(), "2026-11-02T01:13:44.000Z");
    }

    #[test]
    fn day_counts_agree_over_full_range() {
        let first = days_from_civil(0, 1, 1);
        let last = days_from_civil(9999, 12, 31);
        for day in (first..=last).step_by(97) {
            let (y, m, d) = civil_from_days(day);
            assert_eq!(days_from_civil(y, m, d), day);
            assert!(d >= 1 && d <= days_in_month(y, m));
        }
    }

    #[test]
    fn parse_rejects_invalid() {
        for s in [
            "2026-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:00:60Z",
            "2026-01-01T00:00:00+00:00",
            "2026-01-01 00:00:00Z",
            "2026-01-01T00:00:00.5Z",
            "2026-01-01T00:00:00.000z",
        ] {
            assert!(s.parse::<Timestamp>().is_err(), "{s}");
        }
        assert!("2000-02-29T00:00:00Z".parse::<Timestamp>().is_ok());
    }
}
