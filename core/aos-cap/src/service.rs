//! Issuing and spending capability tokens (SPEC §9.1).
//!
//! Only this service holds the signing key. It signs a token after checking
//! attenuation, so a signature is also a proof that the token was a subset of
//! its parent at issue time. Spending is tracked beside the grant.

use std::collections::{BTreeMap, BTreeSet};

use aos_types::id::{Actor, ObjectId};
use aos_types::time::Timestamp;
use aos_types::ulid::{Clock, Entropy, UlidGenerator};
use p256::ecdsa::SigningKey;

use crate::pattern;
use crate::token::{self, Capability, Limits, ROOT_ID, TASK_CREATE};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cost {
    pub steps: u64,
    pub cpu_ms: u64,
    pub gpu_ms: u64,
    pub money_cents: u64,
}

impl Cost {
    pub fn zero() -> Self {
        Cost { steps: 0, cpu_ms: 0, gpu_ms: 0, money_cents: 0 }
    }

    pub fn steps(steps: u64) -> Self {
        Cost { steps, ..Cost::zero() }
    }
}

#[derive(Clone, Debug)]
pub struct IssueRequest {
    pub subject: Actor,
    pub rights: BTreeSet<String>,
    pub object_scope: BTreeMap<String, BTreeSet<ObjectId>>,
    pub limits: Limits,
    pub expires_at: Timestamp,
}

#[derive(Debug)]
pub enum Error {
    AgentCannotIssue,
    Unknown(String),
    Expired,
    BadSignature,
    NotAttenuated(String),
    Quota(String),
    Shape(String),
    Exists(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::AgentCannotIssue => f.write_str("an agent cannot issue a capability"),
            Error::Unknown(id) => write!(f, "unknown capability {id}"),
            Error::Expired => f.write_str("capability expired"),
            Error::BadSignature => f.write_str("capability signature rejected"),
            Error::NotAttenuated(m) => write!(f, "not an attenuation: {m}"),
            Error::Quota(m) => write!(f, "quota exceeded: {m}"),
            Error::Shape(m) => write!(f, "invalid capability: {m}"),
            Error::Exists(id) => write!(f, "capability {id} already exists"),
        }
    }
}

impl std::error::Error for Error {}

pub struct CapabilityService {
    signing: SigningKey,
    generator: UlidGenerator,
    entropy: Box<dyn Entropy + Send>,
    clock: Box<dyn Clock + Send>,
    tokens: BTreeMap<String, Capability>,
    /// Budget still available. Independent of the signed grant.
    remaining: BTreeMap<String, Limits>,
}

impl CapabilityService {
    pub fn new(entropy: Box<dyn Entropy + Send>, clock: Box<dyn Clock + Send>) -> Self {
        let mut entropy = entropy;
        let signing = loop {
            let mut buf = [0u8; 32];
            entropy.fill(&mut buf);
            if let Ok(key) = SigningKey::from_slice(&buf) {
                break key;
            }
        };
        CapabilityService {
            signing,
            generator: UlidGenerator::new(),
            entropy,
            clock,
            tokens: BTreeMap::new(),
            remaining: BTreeMap::new(),
        }
    }

    pub fn now(&self) -> Timestamp {
        Timestamp::from_unix_ms(self.clock.now_ms() as i64).expect("clock within range")
    }

    pub fn root(
        &mut self,
        rights: BTreeSet<String>,
        limits: Limits,
        expires_at: Timestamp,
    ) -> Result<Capability, Error> {
        if self.tokens.contains_key(ROOT_ID) {
            return Err(Error::Exists(ROOT_ID.into()));
        }
        self.store(Capability {
            id: ROOT_ID.into(),
            subject: Actor::User,
            rights,
            object_scope: BTreeMap::new(),
            limits,
            expires_at,
            parent: None,
            signature: Vec::new(),
        })
    }

    /// Issues a child of `parent_id`. `requested_by` must be the user or the
    /// system; an agent cannot mint a token for itself or anyone else.
    pub fn issue(&mut self, requested_by: &Actor, parent_id: &str, req: IssueRequest) -> Result<Capability, Error> {
        if matches!(requested_by, Actor::AgentTask(_)) {
            return Err(Error::AgentCannotIssue);
        }
        if !matches!(requested_by, Actor::User | Actor::System) {
            return Err(Error::AgentCannotIssue);
        }
        let parent = self.tokens.get(parent_id).cloned().ok_or_else(|| Error::Unknown(parent_id.into()))?;
        self.verify(&parent)?;
        let id = format!("cap:{}", self.generator.next(&*self.clock, &mut *self.entropy).expect("ulid"));
        let child = Capability {
            id,
            subject: req.subject,
            rights: req.rights,
            object_scope: req.object_scope,
            limits: req.limits,
            expires_at: req.expires_at,
            parent: Some(parent.id.clone()),
            signature: Vec::new(),
        };
        self.check_child(&parent, &child)?;
        let remaining = self.remaining.get(&parent.id).cloned().ok_or_else(|| Error::Unknown(parent.id.clone()))?;
        if !budget_fits(&child.limits, &remaining) {
            return Err(Error::Quota("parent budget cannot reserve this grant".into()));
        }
        let reserved = Cost {
            steps: child.limits.steps,
            cpu_ms: child.limits.cpu_ms,
            gpu_ms: child.limits.gpu_ms,
            money_cents: child.limits.money_cents,
        };
        let left = remaining.checked_sub(&reserved).ok_or_else(|| Error::Quota("reserve".into()))?;
        self.remaining.insert(parent.id.clone(), left);
        self.store(child)
    }

    fn check_child(&self, parent: &Capability, child: &Capability) -> Result<(), Error> {
        token::validate_shape(child).map_err(|e| Error::Shape(e.0))?;
        if child.expires_at <= self.now() {
            return Err(Error::Expired);
        }
        if !child.within(parent) {
            return Err(Error::NotAttenuated("rights, limits, scope or expiry exceed the parent".into()));
        }
        if child.grants_task_create() {
            return Err(Error::NotAttenuated(format!("{TASK_CREATE} cannot be delegated")));
        }
        for r in &child.rights {
            if !parent.rights.iter().any(|g| pattern::right_within(g, r)) {
                return Err(Error::NotAttenuated(format!("right {r}")));
            }
        }
        Ok(())
    }

    fn store(&mut self, cap: Capability) -> Result<Capability, Error> {
        token::validate_shape(&cap).map_err(|e| Error::Shape(e.0))?;
        if cap.expires_at <= self.now() {
            return Err(Error::Expired);
        }
        let signed = cap.sign(&self.signing);
        signed.verify(self.signing.verifying_key()).map_err(|_| Error::BadSignature)?;
        self.remaining.insert(signed.id.clone(), signed.limits.clone());
        self.tokens.insert(signed.id.clone(), signed.clone());
        Ok(signed)
    }

    pub fn get(&self, id: &str) -> Option<&Capability> {
        self.tokens.get(id)
    }

    pub fn remaining(&self, id: &str) -> Option<&Limits> {
        self.remaining.get(id)
    }

    pub fn verify(&self, cap: &Capability) -> Result<(), Error> {
        token::validate_shape(cap).map_err(|e| Error::Shape(e.0))?;
        cap.verify(self.signing.verifying_key()).map_err(|_| Error::BadSignature)?;
        if cap.expires_at <= self.now() {
            return Err(Error::Expired);
        }
        Ok(())
    }

    /// Checks the signature, expiry and that the grant contains `right`.
    pub fn authorize(&self, id: &str, right: &str) -> Result<&Capability, Error> {
        let cap = self.tokens.get(id).cloned().ok_or_else(|| Error::Unknown(id.into()))?;
        self.verify(&cap)?;
        if !cap.allows_right(right) {
            return Err(Error::NotAttenuated(format!("missing right {right}")));
        }
        Ok(self.tokens.get(id).expect("just found"))
    }

    pub fn try_charge(&mut self, id: &str, cost: &Cost) -> Result<(), Error> {
        let cap = self.tokens.get(id).cloned().ok_or_else(|| Error::Unknown(id.into()))?;
        self.verify(&cap)?;
        let left = self.remaining.get(id).cloned().ok_or_else(|| Error::Unknown(id.into()))?;
        let next = left.checked_sub(cost).ok_or_else(|| Error::Quota(format_cost(cost)))?;
        self.remaining.insert(id.to_owned(), next);
        Ok(())
    }

    pub fn refund(&mut self, id: &str, cost: &Cost) {
        if let Some(left) = self.remaining.get(id).cloned() {
            self.remaining.insert(id.to_owned(), left.add(cost));
        }
    }
}

fn budget_fits(grant: &Limits, remaining: &Limits) -> bool {
    grant.steps <= remaining.steps
        && grant.cpu_ms <= remaining.cpu_ms
        && grant.gpu_ms <= remaining.gpu_ms
        && grant.money_cents <= remaining.money_cents
        && grant.egress_channels.iter().all(|c| remaining.egress_channels.iter().any(|p| pattern::channel_within(p, c)))
}

fn format_cost(cost: &Cost) -> String {
    format!("steps {} cpu_ms {} gpu_ms {} cents {}", cost.steps, cost.cpu_ms, cost.gpu_ms, cost.money_cents)
}
