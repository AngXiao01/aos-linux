//! RFC 8949 Appendix A examples that are in deterministic form, plus inputs a
//! strict deterministic decoder must reject.

use aos_types::cbor::{DecodeError, MAX_DEPTH, Map, Value, decode, encode};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn text(s: &str) -> Value {
    Value::from(s)
}

fn arr(items: Vec<Value>) -> Value {
    Value::Array(items)
}

fn map(entries: Vec<(Value, Value)>) -> Value {
    Value::Map(entries.into_iter().collect::<Map>())
}

fn appendix_a() -> Vec<(Value, &'static str)> {
    let n = Value::int;
    let f = Value::float;
    vec![
        (n(0), "00"),
        (n(1), "01"),
        (n(10), "0a"),
        (n(23), "17"),
        (n(24), "1818"),
        (n(25), "1819"),
        (n(100), "1864"),
        (n(1000), "1903e8"),
        (n(1000000), "1a000f4240"),
        (n(1000000000000), "1b000000e8d4a51000"),
        (Value::Unsigned(18446744073709551615), "1bffffffffffffffff"),
        (Value::Negative(18446744073709551615), "3bffffffffffffffff"),
        (n(-1), "20"),
        (n(-10), "29"),
        (n(-100), "3863"),
        (n(-1000), "3903e7"),
        (f(0.0), "f90000"),
        (f(-0.0), "f98000"),
        (f(1.0), "f93c00"),
        (f(1.1), "fb3ff199999999999a"),
        (f(1.5), "f93e00"),
        (f(65504.0), "f97bff"),
        (f(100000.0), "fa47c35000"),
        (f(3.4028234663852886e+38), "fa7f7fffff"),
        (f(1.0e+300), "fb7e37e43c8800759c"),
        (f(5.960464477539063e-8), "f90001"),
        (f(0.00006103515625), "f90400"),
        (f(-4.0), "f9c400"),
        (f(-4.1), "fbc010666666666666"),
        (f(f64::INFINITY), "f97c00"),
        (f(f64::NAN), "f97e00"),
        (f(f64::NEG_INFINITY), "f9fc00"),
        (Value::Bool(false), "f4"),
        (Value::Bool(true), "f5"),
        (Value::Null, "f6"),
        (Value::Tag(0, Box::new(text("2013-03-21T20:04:00Z"))), "c074323031332d30332d32315432303a30343a30305a"),
        (Value::Tag(1, Box::new(n(1363896240))), "c11a514b67b0"),
        (Value::Tag(1, Box::new(f(1363896240.5))), "c1fb41d452d9ec200000"),
        (Value::Tag(23, Box::new(Value::Bytes(hex("01020304")))), "d74401020304"),
        (
            Value::Tag(32, Box::new(text("http://www.example.com"))),
            "d82076687474703a2f2f7777772e6578616d706c652e636f6d",
        ),
        (Value::Bytes(vec![]), "40"),
        (Value::Bytes(hex("01020304")), "4401020304"),
        (text(""), "60"),
        (text("a"), "6161"),
        (text("IETF"), "6449455446"),
        (text("\"\\"), "62225c"),
        (text("\u{00fc}"), "62c3bc"),
        (text("\u{6c34}"), "63e6b0b4"),
        (text("\u{10151}"), "64f0908591"),
        (arr(vec![]), "80"),
        (arr(vec![n(1), n(2), n(3)]), "83010203"),
        (arr(vec![n(1), arr(vec![n(2), n(3)]), arr(vec![n(4), n(5)])]), "8301820203820405"),
        (arr((1..=25).map(n).collect()), "98190102030405060708090a0b0c0d0e0f101112131415161718181819"),
        (map(vec![]), "a0"),
        (map(vec![(n(1), n(2)), (n(3), n(4))]), "a201020304"),
        (map(vec![(text("a"), n(1)), (text("b"), arr(vec![n(2), n(3)]))]), "a26161016162820203"),
        (arr(vec![text("a"), map(vec![(text("b"), text("c"))])]), "826161a161626163"),
        (
            map(vec![
                (text("e"), text("E")),
                (text("d"), text("D")),
                (text("c"), text("C")),
                (text("b"), text("B")),
                (text("a"), text("A")),
            ]),
            "a56161614161626142616361436164614461656145",
        ),
    ]
}

#[test]
fn encodes_appendix_a() {
    for (value, expected) in appendix_a() {
        assert_eq!(encode(&value), hex(expected), "{value:?}");
    }
}

#[test]
fn decodes_appendix_a() {
    for (value, bytes) in appendix_a() {
        assert_eq!(decode(&hex(bytes)), Ok(value), "{bytes}");
    }
}

#[test]
fn map_keys_sort_bytewise_across_types() {
    // Encoded keys: 0x0a, 0x18 0x64, 0x20, 0x61 0x7a, 0x62 0x61 0x61, 0x81 0x18 0x64, 0xf4.
    let m = map(vec![
        (Value::Bool(false), n(7)),
        (arr(vec![n(100)]), n(6)),
        (text("aa"), n(5)),
        (text("z"), n(4)),
        (n(-1), n(3)),
        (n(100), n(2)),
        (n(10), n(1)),
    ]);
    assert_eq!(encode(&m), hex("a70a011864022003617a046261610581186406f407"));
}

fn n(v: i64) -> Value {
    Value::int(v)
}

#[test]
fn rejects_non_deterministic_input() {
    use DecodeError::*;
    let cases: &[(&str, DecodeError)] = &[
        // Integers and lengths not in shortest form.
        ("1817", NonCanonicalHead),
        ("1900ff", NonCanonicalHead),
        ("1a0000ffff", NonCanonicalHead),
        ("1b00000000ffffffff", NonCanonicalHead),
        ("3817", NonCanonicalHead),
        ("5801ff", NonCanonicalHead),
        ("780161", NonCanonicalHead),
        ("980101", NonCanonicalHead),
        ("b8010102", NonCanonicalHead),
        ("d81701", NonCanonicalHead),
        // Indefinite lengths and stray breaks.
        ("5f4101ff", Indefinite),
        ("7f6161ff", Indefinite),
        ("9f01ff", Indefinite),
        ("bf616101ff", Indefinite),
        ("ff", Indefinite),
        ("1f", Indefinite),
        // Reserved additional information.
        ("1c", Reserved),
        ("fc", Reserved),
        // Simple values other than false/true/null.
        ("f7", UnsupportedSimple),
        ("f0", UnsupportedSimple),
        ("f820", UnsupportedSimple),
        // Floats with a shorter exact form, and non-canonical NaNs.
        ("fa3f800000", NonCanonicalFloat),
        ("fb3ff0000000000000", NonCanonicalFloat),
        ("fb40f86a0000000000", NonCanonicalFloat),
        ("fa7fc00000", NonCanonicalFloat),
        ("fb7ff8000000000000", NonCanonicalFloat),
        ("f97e01", NonCanonicalFloat),
        ("f9fe00", NonCanonicalFloat),
        // Map keys out of order or duplicated.
        ("a2616201616102", UnsortedKeys),
        ("a2616101616102", UnsortedKeys),
        ("a262616101616202", UnsortedKeys),
        ("a2200a0a01", UnsortedKeys),
        // Truncation, trailing data, bad UTF-8, absurd lengths.
        ("", UnexpectedEnd),
        ("19", UnexpectedEnd),
        ("62c3", LengthTooLarge),
        ("0101", TrailingBytes),
        ("62c328", InvalidUtf8),
        ("9bffffffffffffffff", LengthTooLarge),
        ("bb7fffffffffffffff", LengthTooLarge),
        ("8401", LengthTooLarge),
    ];
    for (bytes, err) in cases {
        assert_eq!(decode(&hex(bytes)), Err(err.clone()), "{bytes}");
    }
}

#[test]
fn enforces_depth_limit() {
    let mut ok = vec![0x81u8; MAX_DEPTH];
    ok.push(0x00);
    assert!(decode(&ok).is_ok());
    let mut too_deep = vec![0x81u8; MAX_DEPTH + 1];
    too_deep.push(0x00);
    assert_eq!(decode(&too_deep), Err(DecodeError::TooDeep));
}
