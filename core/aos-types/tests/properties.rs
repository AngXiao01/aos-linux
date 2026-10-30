//! Property tests: canonical round trips for CBOR values, field values and
//! objects, and canonicality of everything the decoder accepts.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use aos_types::cbor::{self, Map, Value};
use aos_types::{
    Actor, Digest, FieldValue, FromCbor, ObjRef, Object, ObjectId, Origin, Provenance, Sensitivity, Taint, Timestamp,
    ToCbor, TxId, TypeRef, Ulid,
};
use proptest::prelude::*;

fn arb_float() -> impl Strategy<Value = f64> {
    prop_oneof![
        any::<f64>(),
        any::<f32>().prop_map(f64::from),
        any::<i16>().prop_map(f64::from),
        Just(f64::NAN),
        Just(-0.0),
    ]
}

fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        any::<u64>().prop_map(Value::Unsigned),
        any::<u64>().prop_map(Value::Negative),
        (0u64..30).prop_map(Value::Unsigned),
        prop::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
        ".{0,20}".prop_map(Value::Text),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
        arb_float().prop_map(Value::float),
    ];
    leaf.prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            prop::collection::vec((inner.clone(), inner.clone()), 0..8)
                .prop_map(|kv| Value::Map(kv.into_iter().collect())),
            (any::<u64>(), inner).prop_map(|(t, v)| Value::Tag(t, Box::new(v))),
        ]
    })
}

fn arb_ulid() -> impl Strategy<Value = Ulid> {
    any::<u128>().prop_map(Ulid::from_u128)
}

fn arb_ref(pinned: bool) -> impl Strategy<Value = ObjRef> {
    let version = if pinned { (1u64..1000).prop_map(Some).boxed() } else { prop::option::of(1u64..1000).boxed() };
    (arb_ulid(), version).prop_map(|(u, version)| ObjRef { id: ObjectId(u), version })
}

fn arb_timestamp() -> impl Strategy<Value = Timestamp> {
    (Timestamp::MIN.unix_ms()..=Timestamp::MAX.unix_ms()).prop_map(|ms| Timestamp::from_unix_ms(ms).unwrap())
}

fn arb_field_value() -> impl Strategy<Value = FieldValue> {
    let leaf = prop_oneof![
        Just(FieldValue::Null),
        any::<bool>().prop_map(FieldValue::Bool),
        any::<i64>().prop_map(FieldValue::Int),
        arb_float().prop_map(FieldValue::float),
        ".{0,12}".prop_map(FieldValue::Text),
        arb_ref(false).prop_map(FieldValue::Ref),
        any::<[u8; 32]>().prop_map(|b| FieldValue::Blob(Digest::from_bytes(b))),
        arb_timestamp().prop_map(FieldValue::Timestamp),
    ];
    leaf.prop_recursive(3, 32, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(FieldValue::List),
            prop::collection::btree_map(".{0,8}", inner, 0..6).prop_map(FieldValue::Map),
        ]
    })
}

fn arb_fields(prefix: &'static str) -> impl Strategy<Value = BTreeMap<String, FieldValue>> {
    let non_null = arb_field_value().prop_filter("typed fields are never null", |v| *v != FieldValue::Null);
    prop::collection::btree_map("[a-z0-9_]{0,10}".prop_map(move |s| format!("{prefix}{s}")), non_null, 0..6)
}

fn arb_object() -> impl Strategy<Value = Object> {
    let origin = prop_oneof![
        Just(Origin::Internal),
        ("[a-z][a-z0-9-]{0,8}", ".{1,12}", arb_timestamp())
            .prop_map(|(adapter, external_id, fetched_at)| Origin::External { adapter, external_id, fetched_at }),
    ];
    let actor = prop_oneof![
        Just(Actor::User),
        Just(Actor::System),
        arb_ulid().prop_map(Actor::AgentTask),
        "[a-z][a-z0-9_-]{0,8}".prop_map(Actor::Adapter),
    ];
    let taint = prop_oneof![Just(Taint::Clean), Just(Taint::External)];
    let sensitivity = prop_oneof![
        Just(Sensitivity::Public),
        Just(Sensitivity::Internal),
        Just(Sensitivity::Private),
        Just(Sensitivity::Secret),
    ];
    let provenance = (actor, origin, taint, prop::collection::btree_set(arb_ref(true), 0..4), arb_ulid()).prop_map(
        |(actor, origin, taint, derived_from, tx)| {
            // External origin implies external taint.
            let taint = if matches!(origin, Origin::External { .. }) { Taint::External } else { taint };
            Provenance { actor, origin, taint, derived_from, tx: TxId(tx) }
        },
    );
    (
        arb_ulid(),
        "[a-z][a-z0-9_]{0,6}",
        "[A-Z][A-Za-z0-9]{0,8}",
        1u32..5,
        1u64..1_000_000,
        arb_fields("f"),
        provenance,
        sensitivity,
        arb_fields("x"),
        any::<bool>(),
    )
        .prop_map(|(id, provider, name, major, version, fields, provenance, sensitivity, extra, tombstone)| {
            Object {
                id: ObjectId(id),
                type_ref: TypeRef { name: format!("{provider}/{name}").parse().unwrap(), major },
                version,
                fields,
                provenance,
                sensitivity,
                extra,
                tombstone,
            }
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn value_round_trips(v in arb_value()) {
        let bytes = cbor::encode(&v);
        prop_assert_eq!(cbor::decode(&bytes), Ok(v));
    }

    #[test]
    fn accepted_random_bytes_are_canonical(bytes in prop::collection::vec(any::<u8>(), 0..48)) {
        if let Ok(v) = cbor::decode(&bytes) {
            prop_assert_eq!(cbor::encode(&v), bytes);
        }
    }

    #[test]
    fn accepted_mutations_are_canonical(v in arb_value(), at in any::<prop::sample::Index>(), byte in any::<u8>()) {
        let mut bytes = cbor::encode(&v);
        let i = at.index(bytes.len());
        bytes[i] = byte;
        if let Ok(decoded) = cbor::decode(&bytes) {
            prop_assert_eq!(cbor::encode(&decoded), bytes);
        }
    }

    #[test]
    fn map_encoding_ignores_insertion_order(entries in prop::collection::vec((arb_value(), arb_value()), 0..10)) {
        let mut seen = HashSet::new();
        let unique: Vec<_> = entries.into_iter().filter(|(k, _)| seen.insert(cbor::encode(k))).collect();
        let forward: Map = unique.iter().cloned().collect();
        let backward: Map = unique.iter().rev().cloned().collect();
        prop_assert_eq!(cbor::encode(&Value::Map(forward)), cbor::encode(&Value::Map(backward)));
    }

    #[test]
    fn field_value_round_trips(v in arb_field_value()) {
        let bytes = v.to_canonical_bytes();
        prop_assert_eq!(FieldValue::from_canonical_bytes(&bytes), Ok(v));
    }

    #[test]
    fn object_round_trips(obj in arb_object()) {
        prop_assert_eq!(obj.check_shape(), Ok(()));
        let bytes = obj.to_canonical_bytes();
        let back = Object::from_canonical_bytes(&bytes).unwrap();
        prop_assert_eq!(back.digest(), obj.digest());
        prop_assert_eq!(back, obj);
    }

    #[test]
    fn blob_refs_find_every_blob(obj in arb_object()) {
        let mut expected = BTreeSet::new();
        fn walk(v: &FieldValue, out: &mut BTreeSet<Digest>) {
            match v {
                FieldValue::Blob(d) => { out.insert(*d); }
                FieldValue::List(items) => items.iter().for_each(|x| walk(x, out)),
                FieldValue::Map(m) => m.values().for_each(|x| walk(x, out)),
                _ => {}
            }
        }
        obj.fields.values().chain(obj.extra.values()).for_each(|v| walk(v, &mut expected));
        prop_assert_eq!(obj.blob_refs(), expected);
    }
}
