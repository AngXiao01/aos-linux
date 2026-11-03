//! Standing-rule acceptance (SPEC §16.1): deny beats confirm beats allow,
//! the default is confirm, every condition in a rule must hold, and grants
//! cover a proposal only when rights, limits and ttl all fit.

use std::collections::BTreeSet;

use aos_cap::Limits;
use aos_policy::{Effect, Facts, Proposal, key_id, parse, sign, verify};
use aos_types::Sensitivity;
use aos_types::sim::SeededEntropy;
use aos_types::ulid::Entropy;
use p256::ecdsa::SigningKey;

const SPEC: &str = r#"
policy: nightly-ml
signed_by: iphone:pubkey/example
grants:
  - rights: ["ml.*"]
    limits: {steps: 500, cpu_hours: 8, gpu_hours: 4, money_cny: 200, egress_channels: ["fetch:registered-sources", "model:default", "compute:remote-gpu", "deliver:*", "notify:*"]}
    max_ttl: 12h
rules:
  - allow: { channel: "model:default", max_sensitivity: internal }
  - allow: { channel: "compute:remote-gpu", max_cost_cny_per_day: 200 }
  - confirm: { channel: "deliver:*" }
  - confirm: { channel: "notify:*", when: "intent.lineage.target_taint == 'external'" }
  - deny: { channel: "*", min_sensitivity: secret }
default: confirm
"#;

fn facts(channel: &str, sensitivity: Sensitivity, cost: u64, spent: u64) -> Facts<'_> {
    Facts { channel, sensitivity, cost_cents: cost, spent_today_cents: spent }
}

#[test]
fn spec_document_parses_and_grants_cover_only_a_subset() {
    let policy = parse(SPEC).unwrap();
    assert_eq!(policy.rules.len(), 5);
    assert_eq!(policy.default, Effect::Confirm);
    assert_eq!(policy.grants[0].max_ttl_ms, 12 * 3_600_000);
    assert_eq!(policy.grants[0].limits.money_cents, 20_000);
    assert_eq!(policy.grants[0].limits.cpu_ms, 8 * 3_600_000);

    let limits = policy.grants[0].limits.clone();
    let inside = Proposal {
        rights: vec!["ml.dataset.write".into()],
        limits: Limits { steps: 500, ..limits.clone() },
        ttl_ms: 12 * 3_600_000,
    };
    assert!(policy.covers(&inside));

    let mut outside_right = inside.clone();
    outside_right.rights.push("sys.task.create".into());
    assert!(!policy.covers(&outside_right));

    let mut too_long = inside.clone();
    too_long.ttl_ms += 1;
    assert!(!policy.covers(&too_long));

    let mut too_much_money = inside.clone();
    too_much_money.limits.money_cents = 20_001;
    assert!(!policy.covers(&too_much_money));

    let mut extra_channel = inside.clone();
    extra_channel.limits.egress_channels.insert("shell:root".into());
    assert!(!policy.covers(&extra_channel));

    let mut no_channels = inside.clone();
    no_channels.limits.egress_channels = BTreeSet::new();
    assert!(policy.covers(&no_channels));
}

#[test]
fn deny_beats_confirm_beats_allow_and_partial_rules_do_not_match() {
    let policy = parse(SPEC).unwrap();
    let never = |_: &str| Ok(false);
    let external = |src: &str| Ok(src.contains("external"));

    let secret = policy.decide(&facts("model:default", Sensitivity::Secret, 0, 0), never);
    assert_eq!(secret.effect, Effect::Deny);

    let model = policy.decide(&facts("model:default", Sensitivity::Internal, 0, 0), never);
    assert_eq!(model.effect, Effect::Allow);

    let private_model = policy.decide(&facts("model:default", Sensitivity::Private, 0, 0), never);
    assert_eq!(private_model.effect, Effect::Confirm, "max_sensitivity is part of the rule");

    let deliver = policy.decide(&facts("deliver:acme", Sensitivity::Public, 0, 0), never);
    assert_eq!(deliver.effect, Effect::Confirm);

    let unknown = policy.decide(&facts("shell:root", Sensitivity::Public, 0, 0), never);
    assert_eq!(unknown.effect, Effect::Confirm);
    assert_eq!(unknown.rule, "default");

    let clean_notify = policy.decide(&facts("notify:email", Sensitivity::Public, 0, 0), never);
    assert_eq!(
        clean_notify.effect,
        Effect::Confirm,
        "when is false, so the confirm rule misses and nothing else matches"
    );

    let tainted = policy.decide(&facts("notify:email", Sensitivity::Public, 0, 0), external);
    assert_eq!(tainted.effect, Effect::Confirm);

    let over_budget = policy.decide(&facts("compute:remote-gpu", Sensitivity::Public, 100, 20_000), never);
    assert_eq!(over_budget.effect, Effect::Confirm, "cost condition fails, so the allow rule misses");

    let within_budget = policy.decide(&facts("compute:remote-gpu", Sensitivity::Public, 100, 19_900), never);
    assert_eq!(within_budget.effect, Effect::Allow);
}

#[test]
fn a_changed_rule_breaks_the_signature() {
    let mut entropy = SeededEntropy::new(9);
    let mut buf = [0u8; 32];
    let key = loop {
        entropy.fill(&mut buf);
        if let Ok(key) = SigningKey::from_slice(&buf) {
            break key;
        }
    };
    let mut policy = parse(SPEC).unwrap();
    policy.signed_by = key_id(&p256::ecdsa::VerifyingKey::from(&key));
    let signed = sign(&policy, &key).unwrap();
    verify(&signed, &p256::ecdsa::VerifyingKey::from(&key)).unwrap();

    let mut tampered = signed.clone();
    tampered.policy.rules[0].effect = Effect::Deny;
    assert!(verify(&tampered, &p256::ecdsa::VerifyingKey::from(&key)).is_err());

    let mut other = policy.clone();
    other.signed_by = "iphone:someone-else".into();
    assert!(sign(&other, &key).is_err());
}
