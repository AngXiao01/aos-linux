//! A standing rule is signed as a whole. Changing any grant or rule
//! invalidates the signature (SPEC §9.3).

use aos_types::Sensitivity;
use aos_types::cbor::{self, Value};
use aos_types::codec::{ToCbor, record};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

use crate::{Error, Grant, Policy, Rule};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPolicy {
    pub policy: Policy,
    pub signature: Vec<u8>,
}

pub fn sign(policy: &Policy, key: &SigningKey) -> Result<SignedPolicy, Error> {
    let id = key_id(&VerifyingKey::from(key));
    if policy.signed_by != id {
        return Err(Error(format!("signed_by is {}, the key is {id}", policy.signed_by)));
    }
    let sig: Signature = key.sign(&canonical(policy));
    Ok(SignedPolicy { policy: policy.clone(), signature: sig.to_bytes().into_iter().collect() })
}

pub fn verify(signed: &SignedPolicy, key: &VerifyingKey) -> Result<(), Error> {
    if signed.policy.signed_by != key_id(key) {
        return Err(Error("signed_by does not match the trust key".into()));
    }
    let sig = Signature::from_slice(&signed.signature).map_err(|_| Error("bad policy signature".into()))?;
    key.verify(&canonical(&signed.policy), &sig).map_err(|_| Error("policy signature rejected".into()))
}

/// `iphone:` plus the compressed SEC1 public key. The dev confirmer uses the
/// same text, so a policy signed by it names that key.
pub fn key_id(key: &VerifyingKey) -> String {
    let point = key.to_encoded_point(true);
    let mut hex = String::with_capacity(point.as_bytes().len() * 2);
    for b in point.as_bytes() {
        hex.push(char::from(b"0123456789abcdef"[(b >> 4) as usize]));
        hex.push(char::from(b"0123456789abcdef"[(b & 0xf) as usize]));
    }
    format!("iphone:{hex}")
}

fn canonical(policy: &Policy) -> Vec<u8> {
    cbor::encode(&policy_value(policy))
}

fn policy_value(policy: &Policy) -> Value {
    record([
        ("name", Value::from(policy.name.as_str())),
        ("signed_by", Value::from(policy.signed_by.as_str())),
        ("grants", Value::Array(policy.grants.iter().map(grant_value).collect())),
        ("rules", Value::Array(policy.rules.iter().map(rule_value).collect())),
        ("default", Value::from(policy.default.as_str())),
    ])
}

fn grant_value(grant: &Grant) -> Value {
    record([
        ("rights", Value::Array(grant.rights.iter().map(|r| Value::from(r.as_str())).collect())),
        ("limits", grant.limits.to_cbor()),
        ("max_ttl_ms", Value::Unsigned(grant.max_ttl_ms)),
    ])
}

fn rule_value(rule: &Rule) -> Value {
    record([
        ("effect", Value::from(rule.effect.as_str())),
        ("channel", opt_text(rule.channel.as_deref())),
        ("max_sensitivity", sens(rule.max_sensitivity)),
        ("min_sensitivity", sens(rule.min_sensitivity)),
        ("max_cost_cents_per_day", rule.max_cost_cents_per_day.map(Value::Unsigned).unwrap_or(Value::Null)),
        ("when", opt_text(rule.when.as_deref())),
    ])
}

fn sens(s: Option<Sensitivity>) -> Value {
    match s {
        Some(s) => Value::from(s.as_str()),
        None => Value::Null,
    }
}

fn opt_text(s: Option<&str>) -> Value {
    match s {
        Some(s) => Value::from(s),
        None => Value::Null,
    }
}
