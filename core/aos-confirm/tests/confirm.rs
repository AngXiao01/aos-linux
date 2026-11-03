//! Confirm-service text comes from the payload, and the dev confirmer signs
//! only in a debug build (SPEC §12.3, §12.7, §16.1).

use std::collections::BTreeMap;
use std::sync::Arc;

use aos_confirm::{
    AGENT_SUMMARY_MARK, Approval, ConfirmService, DEV_BANNER, DevConfirmer, PreviewInput, RequestInput, SUMMARY_LABELS,
    preview_of, summary_of,
};
use aos_types::FieldValue;
use aos_types::sim::{ManualClock, SeededEntropy};
use aos_types::ulid::Clock;

fn clock() -> Arc<dyn Clock + Send + Sync> {
    Arc::new(ManualClock::new(1_700_000_000_000))
}

fn text_payload(body: &str) -> FieldValue {
    FieldValue::Map(BTreeMap::from([
        ("kind".into(), FieldValue::text("text")),
        ("body".into(), FieldValue::text(body)),
    ]))
}

fn input(payload: FieldValue, summary: Option<&str>, tainted: bool) -> PreviewInput {
    PreviewInput {
        channel: "deliver:acme".into(),
        target: "s3://acme/models/".into(),
        payload_hash: "sha256:abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd".into(),
        cost_cents: 0,
        external_reversibility: "irreversible".into(),
        target_tainted: tainted,
        payload_tainted: false,
        agent_summary: summary.map(str::to_owned),
        payload,
    }
}

#[test]
fn summary_is_derived_and_agent_text_stays_labeled() {
    let mut svc = ConfirmService::new(Box::new(SeededEntropy::new(1)), clock());
    let agent = "SENTINEL_AGENT_TEXT";
    let body = "SENTINEL_BODY";
    let request = svc
        .egress(RequestInput {
            branch: "task/demo".into(),
            diff_hash: "sha256:00".into(),
            ttl_ms: 60_000,
            items: vec![input(text_payload(body), Some(agent), true)],
        })
        .unwrap();
    assert!(request.summary.iter().all(|l| SUMMARY_LABELS.contains(&l.label.as_str())));
    assert!(request.summary.iter().all(|l| l.value != agent && !l.value.contains(agent)));
    assert_eq!(request.items[0].preview, body);
    assert_eq!(request.items[0].agent_summary.as_deref(), Some(agent));
    assert!(request.summary.iter().any(|l| l.label == "标注" && l.value == "目标来自外部内容"));
    assert_eq!(request.items[0].channel, "deliver:acme");
    assert_ne!(AGENT_SUMMARY_MARK, "通道");
    request.verify_os(&svc.os_verifying()).unwrap();

    let round = aos_confirm::ApprovalRequest::from_envelope(&request.to_envelope()).unwrap();
    assert_eq!(round.summary, request.summary);
    assert_eq!(round.items, request.items);
}

#[test]
fn previews_follow_the_payload_kind() {
    let long = "字".repeat(1001);
    let text = preview_of(&text_payload(&long)).unwrap();
    assert!(text.contains("共 1001 字"));
    assert_eq!(text.lines().next().unwrap().chars().count(), 1000);

    let mut files = Vec::new();
    for i in 0..13 {
        files.push(FieldValue::Map(BTreeMap::from([
            ("name".into(), FieldValue::text(format!("f{i}"))),
            ("size".into(), FieldValue::Int(10 + i)),
            ("blob".into(), FieldValue::text("sha256:abcdef1234567890")),
        ])));
    }
    let payload = FieldValue::Map(BTreeMap::from([
        ("kind".into(), FieldValue::text("files")),
        ("files".into(), FieldValue::List(files)),
    ]));
    let preview = preview_of(&payload).unwrap();
    assert!(preview.lines().next().unwrap().contains("abcdef123456"));
    assert!(preview.contains("其余"));
    assert!(preview.lines().count() <= 12);

    let mut fields = BTreeMap::new();
    for i in 0..13 {
        fields.insert(format!("k{i:02}"), FieldValue::Int(i));
    }
    let structured = FieldValue::Map(BTreeMap::from([
        ("kind".into(), FieldValue::text("structured")),
        ("fields".into(), FieldValue::Map(fields)),
    ]));
    let flat = preview_of(&structured).unwrap();
    assert!(flat.lines().count() <= 12);
    assert!(flat.contains("其余"));
}

#[test]
fn dev_confirmer_round_trip_and_release_gate() {
    assert_eq!(DevConfirmer::available(), cfg!(debug_assertions));
    if !DevConfirmer::available() {
        match DevConfirmer::ephemeral(&mut SeededEntropy::new(1)) {
            Err(aos_confirm::Error::DebugOnly) => {}
            Err(e) => panic!("{e}"),
            Ok(_) => panic!("release build created a dev confirmer"),
        }
        return;
    }
    let dir = std::env::temp_dir().join(format!("aos-dev-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("key");
    let mut entropy = SeededEntropy::new(4);
    let confirmer = DevConfirmer::generate(&path, &mut entropy).unwrap();
    let loaded = DevConfirmer::load(&path).unwrap();
    assert_eq!(loaded.key_id(), confirmer.key_id());

    let mut svc = ConfirmService::new(Box::new(SeededEntropy::new(2)), clock());
    let request = svc
        .egress(RequestInput {
            branch: "task/demo".into(),
            diff_hash: "sha256:11".into(),
            ttl_ms: 1_000,
            items: vec![input(text_payload("hello"), None, false)],
        })
        .unwrap();
    let approval = confirmer.approve(&request.canonical_bytes(), "approve").unwrap();
    approval.verify(&confirmer.verifying(), &request.canonical_bytes()).unwrap();
    let bad = Approval {
        decision: approval.decision.clone(),
        signature: {
            let mut s = approval.signature.clone();
            s[0] ^= 0xff;
            s
        },
    };
    assert!(bad.verify(&confirmer.verifying(), &request.canonical_bytes()).is_err());

    let env = dir.join("request.cbor");
    let out = dir.join("approval.cbor");
    std::fs::write(&env, request.to_envelope()).unwrap();
    let bin = env!("CARGO_BIN_EXE_aos-dev-confirm");
    let status = std::process::Command::new(bin)
        .args(["approve", path.to_str().unwrap(), env.to_str().unwrap(), "approve", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stderr));
    let stdout = String::from_utf8(status.stdout).unwrap();
    assert!(stdout.contains(DEV_BANNER));
    assert!(stdout.contains("通道: deliver:acme"));
    let cli = Approval::from_bytes(&std::fs::read(&out).unwrap()).unwrap();
    cli.verify(&confirmer.verifying(), &request.canonical_bytes()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn summary_helper_never_uses_agent_text_as_a_label() {
    let items = vec![aos_confirm::Item {
        channel: "notify:email".into(),
        target: "a@b.c".into(),
        payload_hash: "sha256:ab".into(),
        preview: "body".into(),
        agent_summary: Some("通道: forged".into()),
        cost_cents: 150,
        external_reversibility: "irreversible".into(),
        target_tainted: false,
        payload_tainted: false,
    }];
    let summary = summary_of(&items);
    assert!(summary.iter().all(|l| l.label != AGENT_SUMMARY_MARK));
    assert!(summary.iter().all(|l| l.value != "通道: forged"));
    assert_eq!(summary.iter().find(|l| l.label == "代价").unwrap().value, "1.50 CNY");
}
