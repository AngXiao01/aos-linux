//! Standing rules (SPEC §9.3).
//!
//! A rule matches only when every condition it states is true. Among the
//! rules that match, `deny` beats `confirm` and `confirm` beats `allow`.
//! Nothing matching uses `default`, which itself defaults to `confirm`.
//! Grants answer a different question: whether a proposed capability can be
//! issued without asking.

mod parse;
mod sign;

use std::fmt;

use aos_cap::{Limits, channel_covers, right_covers};
use aos_types::Sensitivity;

pub use parse::parse;
pub use sign::{SignedPolicy, key_id, sign, verify};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Confirm,
    Deny,
}

impl Effect {
    pub fn as_str(self) -> &'static str {
        match self {
            Effect::Allow => "allow",
            Effect::Confirm => "confirm",
            Effect::Deny => "deny",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Effect::Allow => 1,
            Effect::Confirm => 2,
            Effect::Deny => 3,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Effect::Allow),
            "confirm" => Some(Effect::Confirm),
            "deny" => Some(Effect::Deny),
            _ => None,
        }
    }
}

impl fmt::Display for Effect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub effect: Effect,
    pub channel: Option<String>,
    pub max_sensitivity: Option<Sensitivity>,
    pub min_sensitivity: Option<Sensitivity>,
    pub max_cost_cents_per_day: Option<u64>,
    pub when: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub rights: Vec<String>,
    pub limits: Limits,
    pub max_ttl_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub rights: Vec<String>,
    pub limits: Limits,
    pub ttl_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub name: String,
    pub signed_by: String,
    pub grants: Vec<Grant>,
    pub rules: Vec<Rule>,
    pub default: Effect,
}

#[derive(Clone, Debug)]
pub struct Facts<'a> {
    pub channel: &'a str,
    pub sensitivity: Sensitivity,
    pub cost_cents: u64,
    pub spent_today_cents: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub effect: Effect,
    pub rule: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl Policy {
    /// `when_eval` reports whether a rule's `when` expression is true.
    /// An error fails closed: a `deny` rule is treated as matched, any other
    /// rule is treated as unmatched.
    pub fn decide(&self, facts: &Facts<'_>, mut when_eval: impl FnMut(&str) -> Result<bool, String>) -> Decision {
        let mut winner: Option<(u8, usize)> = None;
        for (i, rule) in self.rules.iter().enumerate() {
            if !matches_rule(rule, facts, &mut when_eval) {
                continue;
            }
            let rank = rule.effect.rank();
            if winner.as_ref().is_none_or(|(best, _)| rank > *best) {
                winner = Some((rank, i));
            }
        }
        match winner {
            Some((_, i)) => Decision { effect: self.rules[i].effect, rule: format!("{i}") },
            None => Decision { effect: self.default, rule: "default".into() },
        }
    }

    pub fn covers(&self, proposal: &Proposal) -> bool {
        self.grants.iter().any(|g| grant_covers(g, proposal))
    }
}

fn matches_rule(rule: &Rule, facts: &Facts<'_>, when_eval: &mut impl FnMut(&str) -> Result<bool, String>) -> bool {
    if let Some(pattern) = &rule.channel
        && !channel_covers(pattern, facts.channel)
    {
        return false;
    }
    if let Some(max) = rule.max_sensitivity
        && facts.sensitivity > max
    {
        return false;
    }
    if let Some(min) = rule.min_sensitivity
        && facts.sensitivity < min
    {
        return false;
    }
    if let Some(max) = rule.max_cost_cents_per_day
        && facts.spent_today_cents.saturating_add(facts.cost_cents) > max
    {
        return false;
    }
    if let Some(expr) = &rule.when {
        match when_eval(expr) {
            Ok(true) => {}
            Ok(false) => return false,
            Err(_) if rule.effect == Effect::Deny => {}
            Err(_) => return false,
        }
    }
    true
}

fn grant_covers(grant: &Grant, proposal: &Proposal) -> bool {
    proposal.rights.iter().all(|need| grant.rights.iter().any(|have| right_covers(have, need)))
        && proposal.limits.within(&grant.limits)
        && proposal.ttl_ms <= grant.max_ttl_ms
}
