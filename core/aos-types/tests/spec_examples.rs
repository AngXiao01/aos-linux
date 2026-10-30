//! The SPEC §6.1 object and §6.2 type declaration, checked end to end.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use aos_types::cbor::{self, Value};
use aos_types::codec::Error;
use aos_types::schema::{Evolution, EvolutionError, ProblemKind, RefTypes, RelationDecl, ViewHint, check_evolution};
use aos_types::template::Template;
use aos_types::{
    Actor, Digest, FieldDecl, FieldKind, FieldValue, FromCbor, ObjRef, Object, ObjectId, Origin, Provenance,
    Sensitivity, Taint, Timestamp, ToCbor, TxId, TypeDecl, TypeName,
};

const DATASET: &str = "01JC8Z0000000000000000DSET";
const PARENT: &str = "01JC8Y00000000000000000V12";
const VERSION: &str = "01JC8Z3K9Q6V2X4M7N1P0R5T8W";
const TASK: &str = "01JC9000000000000000000TSK";
const TX: &str = "01JC91000000000000000000TX";

fn id(s: &str) -> ObjectId {
    s.parse().unwrap()
}

fn ty(s: &str) -> TypeName {
    s.parse().unwrap()
}

fn field(kind: FieldKind, required: bool) -> FieldDecl {
    FieldDecl { kind, required }
}

/// SPEC §6.2.
fn dataset_version_decl() -> TypeDecl {
    TypeDecl {
        name: ty("ml/DatasetVersion"),
        major: 1,
        fields: BTreeMap::from([
            ("dataset".into(), field(FieldKind::Ref { target: ty("ml/Dataset") }, true)),
            ("number".into(), field(FieldKind::Int { min: Some(1), max: None }, true)),
            ("parent".into(), field(FieldKind::Ref { target: ty("ml/DatasetVersion") }, false)),
            ("members".into(), field(FieldKind::Blob, true)),
            ("sample_count".into(), field(FieldKind::Int { min: Some(0), max: None }, true)),
            ("note".into(), field(FieldKind::Text { max: Some(2000) }, false)),
        ]),
        relations: BTreeMap::from([(
            "children".into(),
            RelationDecl { many: ty("ml/DatasetVersion"), via: "parent".into() },
        )]),
        view_hint: ViewHint {
            title: Some("{dataset.name} v{number}".into()),
            primary_fields: vec!["sample_count".into(), "note".into()],
        },
    }
}

/// SPEC §6.1, with the elided ids filled in.
fn dataset_version() -> Object {
    Object {
        id: id(VERSION),
        type_ref: "ml/DatasetVersion@1".parse().unwrap(),
        version: 1,
        fields: BTreeMap::from([
            ("dataset".into(), FieldValue::Ref(ObjRef::latest(id(DATASET)))),
            ("number".into(), FieldValue::Int(13)),
            ("parent".into(), FieldValue::Ref(ObjRef::latest(id(PARENT)))),
            ("members".into(), FieldValue::Blob(Digest::of(b"members of v13"))),
            ("sample_count".into(), FieldValue::Int(48213)),
            ("note".into(), FieldValue::text("去重后")),
        ]),
        provenance: Provenance {
            actor: format!("agent:task/{TASK}").parse().unwrap(),
            origin: Origin::Internal,
            taint: Taint::External,
            derived_from: BTreeSet::from([ObjRef::at(id(PARENT), 1)]),
            tx: TX.parse().unwrap(),
        },
        sensitivity: Sensitivity::Internal,
        extra: BTreeMap::new(),
        tombstone: false,
    }
}

struct Registry(HashMap<ObjectId, TypeName>);

impl RefTypes for Registry {
    fn type_of(&self, id: ObjectId) -> Option<TypeName> {
        self.0.get(&id).cloned()
    }
}

fn registry() -> Registry {
    Registry(HashMap::from([(id(DATASET), ty("ml/Dataset")), (id(PARENT), ty("ml/DatasetVersion"))]))
}

fn problems(obj: &Object) -> Vec<(String, ProblemKind)> {
    match dataset_version_decl().check_object(obj, Some(&registry())) {
        Ok(()) => vec![],
        Err(ps) => ps.into_iter().map(|p| (p.path, p.kind)).collect(),
    }
}

#[test]
fn spec_declaration_and_object_are_valid() {
    let decl = dataset_version_decl();
    assert_eq!(decl.check_decl(), Ok(()));
    assert_eq!(problems(&dataset_version()), vec![]);
    let constrained: Vec<_> = decl.constrained_fields().collect();
    assert_eq!(constrained, ["dataset", "members", "number", "parent", "sample_count"]);
}

#[test]
fn canonical_encoding_is_pinned() {
    // Guards the wire format: any change here invalidates every stored hash
    // and signature, so it must be a deliberate, recorded decision. The bytes
    // were cross-checked against Python cbor2 (canonical mode).
    let obj = dataset_version();
    let bytes = obj.to_canonical_bytes();
    assert_eq!(
        obj.digest().to_string(),
        "sha256:6e6d2b6869c13dcd7d44ae97296926c0c580da2a8d551982feeee8b773f16a2d",
        "canonical bytes: {}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    assert_eq!(Object::from_canonical_bytes(&bytes), Ok(obj));
}

#[test]
fn title_template_renders() {
    let decl = dataset_version_decl();
    let obj = dataset_version();
    let title: Template = decl.view_hint.title.as_deref().unwrap().parse().unwrap();
    let rendered = title
        .render(|path| match path {
            [f, n] if f == "dataset" && n == "name" => Some("fall-detection".into()),
            [f] => match obj.fields.get(f.as_str()) {
                Some(FieldValue::Int(n)) => Some(n.to_string()),
                _ => None,
            },
            _ => None,
        })
        .unwrap();
    assert_eq!(rendered, "fall-detection v13");
}

#[test]
fn invalid_objects_are_reported_per_field() {
    let mut obj = dataset_version();
    obj.fields.remove("members");
    obj.fields.insert("sample_count".into(), FieldValue::Int(-1));
    obj.fields.insert("note".into(), FieldValue::text("x".repeat(2001)));
    obj.fields.insert("number".into(), FieldValue::float(13.0));
    obj.fields.insert("dataset".into(), FieldValue::Ref(ObjRef::latest(id(PARENT))));
    obj.fields.insert("parent".into(), FieldValue::Ref(ObjRef::latest(id(TASK))));
    obj.fields.insert("color".into(), FieldValue::text("red"));
    let mut got = problems(&obj);
    got.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        got,
        vec![
            ("color".into(), ProblemKind::Undeclared),
            ("dataset".into(), ProblemKind::RefTarget { expected: ty("ml/Dataset"), found: ty("ml/DatasetVersion") }),
            ("members".into(), ProblemKind::Missing),
            ("note".into(), ProblemKind::TooLong { max: 2000 }),
            ("number".into(), ProblemKind::WrongKind { expected: "int", found: "float" }),
            ("parent".into(), ProblemKind::DanglingRef),
            ("sample_count".into(), ProblemKind::OutOfRange),
        ]
    );
}

#[test]
fn declared_fields_cannot_hide_in_extra_and_tombstones_skip_checks() {
    let mut obj = dataset_version();
    let note = obj.fields.remove("note").unwrap();
    obj.extra.insert("note".into(), note);
    assert_eq!(problems(&obj), vec![("note".into(), ProblemKind::DeclaredFieldInExtra)]);

    let mut tomb = dataset_version();
    tomb.version = 2;
    tomb.tombstone = true;
    tomb.fields.clear();
    assert_eq!(problems(&tomb), vec![]);
}

#[test]
fn wrong_type_is_rejected_first() {
    let mut obj = dataset_version();
    obj.type_ref = "ml/DatasetVersion@2".parse().unwrap();
    assert!(matches!(problems(&obj).as_slice(), [(_, ProblemKind::WrongType { .. })]));
}

#[test]
fn declaration_problems_are_found() {
    let mut decl = dataset_version_decl();
    decl.fields.insert("Bad".into(), field(FieldKind::Bool, false));
    decl.fields.insert("range".into(), field(FieldKind::Int { min: Some(5), max: Some(1) }, false));
    decl.fields.insert("tags".into(), field(FieldKind::Enum { values: vec!["a".into(), "a".into()] }, false));
    decl.view_hint.title = Some("{missing}".into());
    decl.view_hint.primary_fields.push("nope".into());
    let kinds: Vec<_> = decl.check_decl().unwrap_err().into_iter().map(|p| p.kind).collect();
    assert_eq!(
        kinds,
        vec![
            ProblemKind::BadName,
            ProblemKind::BadBounds,
            ProblemKind::BadEnumValue("a".into()),
            ProblemKind::UnknownField,
            ProblemKind::UnknownField,
        ]
    );
}

#[test]
fn type_declaration_round_trips() {
    let mut decl = dataset_version_decl();
    decl.fields.insert(
        "scores".into(),
        field(
            FieldKind::List {
                of: Box::new(FieldKind::Float { min: Some(aos_types::cbor::F64(0.0)), max: None }),
                max_len: Some(10),
            },
            false,
        ),
    );
    decl.fields.insert(
        "split".into(),
        field(FieldKind::Enum { values: vec!["train".into(), "val".into(), "test".into()] }, false),
    );
    decl.fields.insert("labels".into(), field(FieldKind::Map { values: Box::new(FieldKind::Timestamp) }, false));
    let bytes = decl.to_canonical_bytes();
    assert_eq!(TypeDecl::from_canonical_bytes(&bytes), Ok(decl));
}

#[test]
fn evolution_rules() {
    let old = dataset_version_decl();

    let mut added = old.clone();
    added.fields.insert("source".into(), field(FieldKind::Text { max: None }, false));
    added.view_hint.title = Some("v{number}".into());
    assert_eq!(check_evolution(&old, &added), Ok(Evolution::Compatible));

    let mut breaking = old.clone();
    breaking.fields.insert("source".into(), field(FieldKind::Text { max: None }, true));
    breaking.fields.insert("note".into(), field(FieldKind::Text { max: Some(100) }, false));
    breaking.fields.remove("parent");
    assert_eq!(
        check_evolution(&old, &breaking),
        Err(vec![
            EvolutionError::FieldChanged("note".into()),
            EvolutionError::FieldRemoved("parent".into()),
            EvolutionError::NewRequiredField("source".into()),
        ])
    );

    breaking.major = 2;
    assert_eq!(check_evolution(&old, &breaking), Ok(Evolution::NewMajor));
    breaking.major = 3;
    assert_eq!(check_evolution(&old, &breaking), Err(vec![EvolutionError::BadMajor]));
    breaking.name = ty("ml/Other");
    assert_eq!(check_evolution(&old, &breaking), Err(vec![EvolutionError::NameChanged]));
}

/// Encodes `obj` without validation, then decodes it.
fn reencode(obj: &Object) -> Result<Object, Error> {
    Object::from_canonical_bytes(&obj.to_canonical_bytes())
}

#[test]
fn decoding_enforces_object_shape() {
    type Mutation = Box<dyn Fn(&mut Object)>;
    let cases: Vec<(&str, Mutation)> = vec![
        ("version 0", Box::new(|o| o.version = 0)),
        (
            "null field",
            Box::new(|o| {
                o.fields.insert("note".into(), FieldValue::Null);
            }),
        ),
        (
            "bad name",
            Box::new(|o| {
                o.fields.insert("Note".into(), FieldValue::Int(1));
            }),
        ),
        (
            "overlap",
            Box::new(|o| {
                o.extra.insert("note".into(), FieldValue::Int(1));
            }),
        ),
        (
            "unpinned derivation",
            Box::new(|o| {
                o.provenance.derived_from.insert(ObjRef::latest(id(PARENT)));
            }),
        ),
        (
            "external origin, clean taint",
            Box::new(|o| {
                o.provenance.taint = Taint::Clean;
                o.provenance.origin = Origin::External {
                    adapter: "minio".into(),
                    external_id: "s3://bucket/a.jpg".into(),
                    fetched_at: Timestamp::from_unix_ms(0).unwrap(),
                };
            }),
        ),
    ];
    for (name, mutate) in cases {
        let mut obj = dataset_version();
        mutate(&mut obj);
        assert!(matches!(reencode(&obj), Err(Error::Schema(_))), "{name}");
    }

    let mut external = dataset_version();
    external.provenance.actor = Actor::Adapter("minio".into());
    external.provenance.origin = Origin::External {
        adapter: "minio".into(),
        external_id: "s3://bucket/a.jpg".into(),
        fetched_at: "2026-11-02T01:13:44Z".parse().unwrap(),
    };
    assert_eq!(reencode(&external), Ok(external));
}

#[test]
fn decoding_rejects_unknown_keys_and_unsorted_derivations() {
    let obj = dataset_version();
    let Value::Map(mut top) = obj.to_cbor() else { unreachable!() };

    let mut with_extra_key = top.clone();
    with_extra_key.insert("blobs".into(), Value::Array(vec![]));
    assert!(Object::from_cbor(&Value::Map(with_extra_key)).is_err());

    let Some(Value::Map(prov)) = top.get(&"provenance".into()).cloned() else { unreachable!() };
    let mut prov = prov;
    let later = format!("{PARENT}@2");
    let earlier = format!("{PARENT}@1");
    prov.insert("derived_from".into(), Value::Array(vec![later.as_str().into(), earlier.as_str().into()]));
    top.insert("provenance".into(), Value::Map(prov));
    let err = Object::from_canonical_bytes(&cbor::encode(&Value::Map(top))).unwrap_err();
    assert!(err.to_string().contains("not strictly increasing"), "{err}");
}

#[test]
fn ids_used_in_examples_are_valid() {
    for s in [DATASET, PARENT, VERSION, TASK, TX] {
        let _: TxId = s.parse().unwrap();
    }
}
