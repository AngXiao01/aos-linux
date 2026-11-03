//! Declaration files parse, and the catalog can answer §8.6 questions.

use std::path::PathBuf;

use aos_action::{Catalog, parse_action, parse_type};

#[test]
fn spec_samples_and_shipped_declarations_parse() {
    let action = parse_action(
        r#"
action: ml.dataset.dedupe
version: 1
provider: ml
summary: "按感知哈希相似度去重，产出新的数据集版本"
inputs:
  version:   { ref: ml/DatasetVersion }
  threshold: { float: {min: 0.5, max: 1.0}, default: 0.95 }
outputs:
  new_version: { ref: ml/DatasetVersion }
effects:
  reads:  [ml/DatasetVersion, ml/Sample]
  writes: [ml/DatasetVersion, ml/Sample]
  egress: []
reversibility: undo
preconditions:
  - "version.sample_count > 0"
cost:
  cpu_seconds_estimate: "0.002 * version.sample_count"
capability: "ml.dataset.write"
idempotency_key: "{version.id}:{threshold}"
"#,
    )
    .unwrap();
    assert_eq!(action.qualified(), "ml.dataset.dedupe@1");
    match &action.inputs.iter().find(|p| p.name == "threshold").unwrap().default {
        Some(aos_types::FieldValue::Float(f)) => assert!((f.0 - 0.95).abs() < 1e-9),
        other => panic!("threshold default {other:?}"),
    }

    let decl = parse_type(
        r#"
type: ml/DatasetVersion
major: 1
fields:
  dataset:      { ref: ml/Dataset, required: true }
  number:       { int: {min: 1}, required: true }
  parent:       { ref: ml/DatasetVersion }
  members:      { blob: {}, required: true }
  sample_count: { int: {min: 0}, required: true }
  note:         { text: {max: 2000} }
relations:
  children: { many: ml/DatasetVersion, via: parent }
view_hint:
  title: "{dataset.name} v{number}"
  primary_fields: [sample_count, note]
"#,
    )
    .unwrap();
    assert_eq!(decl.fields.len(), 6);
    assert!(decl.fields["members"].required);

    let mut cat = Catalog::new();
    cat.load_dir(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("decls")).unwrap();
    let counter = "demo/Counter".parse().unwrap();
    let names: Vec<_> = cat.actions_for(&counter).iter().map(|a| a.qualified()).collect();
    assert!(names.iter().any(|n| n == "demo.counter.inc@1"));
    assert_eq!(cat.action("demo.notify.draft@1").unwrap().egress, ["notify:*"]);
    assert!(cat.type_decl(&"sys/ActionViolation@1".parse().unwrap()).is_some());
    assert!(cat.type_decl(&"sys/EgressIntent@1".parse().unwrap()).is_some());
    assert!(cat.type_decl(&"sys/EgressReceipt@1".parse().unwrap()).is_some());
    assert!(cat.type_decl(&"sys/Job@1".parse().unwrap()).is_some());
}
