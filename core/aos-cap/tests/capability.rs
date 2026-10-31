//! Capability attenuation, rejection of unauthorized use, and exact quotas
//! (SPEC §16.1).

use std::collections::{BTreeMap, BTreeSet};

use aos_cap::{CapabilityService, Cost, IssueRequest, Limits};
use aos_types::id::Actor;
use aos_types::sim::{ManualClock, SeededEntropy};
use aos_types::time::Timestamp;
use aos_types::{ObjectId, Ulid};

fn service(seed: u64) -> CapabilityService {
    let clock = ManualClock::new(1_700_000_000_000);
    CapabilityService::new(Box::new(SeededEntropy::new(seed)), Box::new(clock))
}

fn hours(h: u64) -> u64 {
    h * 3_600_000
}

fn later(svc: &CapabilityService, ms: i64) -> Timestamp {
    Timestamp::from_unix_ms(svc.now().unix_ms() + ms).unwrap()
}

fn root(svc: &mut CapabilityService) -> aos_cap::Capability {
    let mut rights = BTreeSet::new();
    rights.insert("*".into());
    let limits = Limits {
        steps: 1_000,
        cpu_ms: hours(8),
        gpu_ms: hours(4),
        money_cents: 20_000,
        egress_channels: BTreeSet::from(["*".into()]),
    };
    svc.root(rights, limits, later(svc, 86_400_000)).unwrap()
}

fn child_req(svc: &CapabilityService, rights: &[&str], steps: u64, channels: &[&str]) -> IssueRequest {
    IssueRequest {
        subject: Actor::AgentTask(Ulid::from_u128(7)),
        rights: rights.iter().map(|s| (*s).to_owned()).collect(),
        object_scope: BTreeMap::new(),
        limits: Limits {
            steps,
            cpu_ms: hours(1),
            gpu_ms: 0,
            money_cents: 100,
            egress_channels: channels.iter().map(|s| (*s).to_owned()).collect(),
        },
        expires_at: later(svc, 3_600_000),
    }
}

#[test]
fn attenuation_holds_and_widening_is_rejected() {
    let mut svc = service(1);
    let root = root(&mut svc);
    let ok =
        svc.issue(&Actor::User, root.id.as_str(), child_req(&svc, &["ml.dataset.*"], 10, &["model:default"])).unwrap();
    assert!(ok.within(&root));
    assert!(ok.verify_signature_round_trip(&svc));
    assert!(!ok.grants_task_create());
    assert!(ok.allows_right("ml.dataset.write"));
    assert!(!ok.allows_right("ml.experiment.create"));

    let widened = child_req(&svc, &["ml.*"], 10, &["model:default"]);
    // parent of this attempt is the child, which only has ml.dataset.*
    let err = svc.issue(&Actor::User, ok.id.as_str(), widened).unwrap_err();
    assert!(err.to_string().contains("not an attenuation"), "{err}");

    let delegated = child_req(&svc, &["sys.task.create"], 1, &[]);
    let err = svc.issue(&Actor::User, root.id.as_str(), delegated).unwrap_err();
    assert!(err.to_string().contains("sys.task.create"), "{err}");

    let star = child_req(&svc, &["*"], 1, &[]);
    assert!(svc.issue(&Actor::User, root.id.as_str(), star).is_err());
}

trait SigCheck {
    fn verify_signature_round_trip(&self, svc: &CapabilityService) -> bool;
}

impl SigCheck for aos_cap::Capability {
    fn verify_signature_round_trip(&self, svc: &CapabilityService) -> bool {
        svc.verify(self).is_ok()
    }
}

#[test]
fn agent_cannot_issue_and_forged_signature_is_rejected() {
    let mut svc = service(2);
    let root = root(&mut svc);
    let agent = Actor::AgentTask(Ulid::from_u128(9));
    let err = svc.issue(&agent, root.id.as_str(), child_req(&svc, &["ml.dataset.read"], 1, &[])).unwrap_err();
    assert!(err.to_string().contains("cannot issue"), "{err}");

    let cap = svc.issue(&Actor::System, root.id.as_str(), child_req(&svc, &["ml.dataset.read"], 1, &[])).unwrap();
    let mut forged = cap.clone();
    forged.rights.insert("ml.dataset.write".into());
    assert!(svc.verify(&forged).is_err());
    forged = cap.clone();
    forged.signature[0] ^= 0xff;
    assert!(svc.verify(&forged).is_err());
    assert!(svc.authorize(&cap.id, "ml.dataset.write").is_err());
    assert!(svc.authorize(&cap.id, "ml.dataset.read").is_ok());
}

#[test]
fn quota_deduction_is_exact_and_a_rejected_charge_does_not_move_it() {
    let mut svc = service(3);
    let root = root(&mut svc);
    let cap = svc.issue(&Actor::User, root.id.as_str(), child_req(&svc, &["demo.counter.write"], 2, &[])).unwrap();
    let start_steps = svc.remaining(&cap.id).unwrap().steps;
    let start_cpu = svc.remaining(&cap.id).unwrap().cpu_ms;
    assert_eq!(start_steps, 2);

    let cost = Cost { steps: 1, cpu_ms: 1_500, gpu_ms: 0, money_cents: 0 };
    svc.try_charge(&cap.id, &cost).unwrap();
    svc.try_charge(&cap.id, &cost).unwrap();
    let left = svc.remaining(&cap.id).unwrap();
    assert_eq!(left.steps, 0);
    assert_eq!(left.cpu_ms, start_cpu - 3_000);

    let before = left.clone();
    let err = svc.try_charge(&cap.id, &Cost::steps(1)).unwrap_err();
    assert!(err.to_string().contains("quota"), "{err}");
    assert_eq!(svc.remaining(&cap.id).unwrap(), &before);

    svc.refund(&cap.id, &cost);
    let restored = svc.remaining(&cap.id).unwrap();
    assert_eq!(restored.steps, 1);
    assert_eq!(restored.cpu_ms, start_cpu - 1_500);
    // The signed grant is unchanged by spending.
    assert_eq!(svc.get(&cap.id).unwrap().limits.steps, 2);
    assert!(svc.verify(svc.get(&cap.id).unwrap()).is_ok());
}

#[test]
fn random_attenuations_match_the_predicate() {
    let mut rng = 0x1234_5678_u64;
    let mut next = || {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        rng
    };
    let patterns =
        ["ml.*", "ml.dataset.*", "ml.dataset.write", "ml.dataset.read", "ml.experiment.*", "demo.counter.write"];
    let channels = ["*", "deliver:*", "deliver:minio-*", "model:default", "notify:*"];
    for i in 0..2_000 {
        let mut svc = service(100 + i);
        let mut parent_rights = BTreeSet::new();
        let n = (next() % 3) + 1;
        for _ in 0..n {
            parent_rights.insert(patterns[(next() as usize) % patterns.len()].to_owned());
        }
        let mut parent_ch = BTreeSet::new();
        parent_ch.insert(channels[(next() as usize) % channels.len()].to_owned());
        let parent_limits =
            Limits { steps: 100, cpu_ms: 10_000, gpu_ms: 10_000, money_cents: 1_000, egress_channels: parent_ch };
        let parent = svc.root(parent_rights.clone(), parent_limits.clone(), later(&svc, 10_000_000)).unwrap();

        let mut child_rights = BTreeSet::new();
        let m = (next() % 3) + 1;
        for _ in 0..m {
            child_rights.insert(patterns[(next() as usize) % patterns.len()].to_owned());
        }
        let mut child_ch = BTreeSet::new();
        child_ch.insert(channels[(next() as usize) % channels.len()].to_owned());
        let steps = next() % 150;
        let child_limits = Limits {
            steps,
            cpu_ms: next() % 15_000,
            gpu_ms: 0,
            money_cents: next() % 1_500,
            egress_channels: child_ch,
        };
        let req = IssueRequest {
            subject: Actor::AgentTask(Ulid::from_u128(i as u128 + 1)),
            rights: child_rights.clone(),
            object_scope: BTreeMap::new(),
            limits: child_limits.clone(),
            expires_at: later(&svc, 5_000),
        };
        let rights_ok = child_rights.iter().all(|r| parent_rights.iter().any(|g| aos_cap::right_within(g, r)))
            && child_rights.iter().all(|r| !aos_cap::right_covers(r, "sys.task.create"));
        let limits_ok = child_limits.within(&parent_limits);
        let expect_ok = rights_ok && limits_ok;
        let got = svc.issue(&Actor::User, parent.id.as_str(), req);
        assert_eq!(got.is_ok(), expect_ok, "case {i}: rights {child_rights:?} limits steps {steps} got {got:?}");
        if let Ok(cap) = got {
            assert!(cap.within(&parent));
            assert!(!cap.grants_task_create());
        }
    }
}

#[test]
fn scope_narrows_and_object_ids_cannot_grow() {
    let mut svc = service(4);
    let root = root(&mut svc);
    let id_a = ObjectId(Ulid::from_u128(11));
    let id_b = ObjectId(Ulid::from_u128(12));
    let mut scope = BTreeMap::new();
    scope.insert("dataset".into(), BTreeSet::from([id_a]));
    let mut req = child_req(&svc, &["ml.dataset.write"], 1, &[]);
    req.object_scope = scope;
    let cap = svc.issue(&Actor::User, root.id.as_str(), req).unwrap();

    let mut wider = child_req(&svc, &["ml.dataset.write"], 1, &[]);
    wider.object_scope.insert("dataset".into(), BTreeSet::from([id_a, id_b]));
    assert!(svc.issue(&Actor::User, cap.id.as_str(), wider).is_err());

    let mut dropped = child_req(&svc, &["ml.dataset.write"], 1, &[]);
    dropped.object_scope.clear();
    assert!(svc.issue(&Actor::User, cap.id.as_str(), dropped).is_err());
}
