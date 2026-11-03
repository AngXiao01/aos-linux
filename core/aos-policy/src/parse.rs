//! The standing-rule YAML document (SPEC §9.3).

use std::collections::BTreeSet;

use aos_cap::{Limits, parse_channel, parse_right};
use aos_types::Sensitivity;
use aos_types::yaml::{self, Yaml};

use crate::{Effect, Error, Grant, Policy, Rule};

pub fn parse(text: &str) -> Result<Policy, Error> {
    let doc = yaml::parse(text).map_err(|e| Error(e.to_string()))?;
    for key in doc.keys().map_err(|e| Error(e.to_string()))? {
        if !matches!(key, "policy" | "signed_by" | "grants" | "rules" | "default") {
            return Err(Error(format!("unknown policy field {key}")));
        }
    }
    let name = text_at(&doc, "policy")?;
    let signed_by = text_at(&doc, "signed_by")?;
    if name.is_empty() || signed_by.is_empty() {
        return Err(Error("policy name and signed_by are required".into()));
    }
    let default = match doc.get("default") {
        None => Effect::Confirm,
        Some(v) => {
            let s = v.as_str().map_err(|e| Error(e.to_string()))?;
            Effect::parse(s).ok_or_else(|| Error(format!("unknown default {s}")))?
        }
    };
    let grants = match doc.get("grants") {
        None => Vec::new(),
        Some(v) => v.as_seq().map_err(|e| Error(e.to_string()))?.iter().map(parse_grant).collect::<Result<_, _>>()?,
    };
    let rules = match doc.get("rules") {
        None => Vec::new(),
        Some(v) => v.as_seq().map_err(|e| Error(e.to_string()))?.iter().map(parse_rule).collect::<Result<_, _>>()?,
    };
    Ok(Policy { name, signed_by, grants, rules, default })
}

fn text_at(doc: &Yaml, key: &str) -> Result<String, Error> {
    Ok(doc.need(key).map_err(|e| Error(e.to_string()))?.as_str().map_err(|e| Error(e.to_string()))?.to_owned())
}

fn parse_grant(y: &Yaml) -> Result<Grant, Error> {
    for key in y.keys().map_err(|e| Error(e.to_string()))? {
        if !matches!(key, "rights" | "limits" | "max_ttl") {
            return Err(Error(format!("unknown grant field {key}")));
        }
    }
    let mut rights = Vec::new();
    for item in y.need("rights").map_err(|e| Error(e.to_string()))?.as_seq().map_err(|e| Error(e.to_string()))? {
        let s = item.as_str().map_err(|e| Error(e.to_string()))?.to_owned();
        parse_right(&s).map_err(|e| Error(e.to_string()))?;
        rights.push(s);
    }
    if rights.is_empty() {
        return Err(Error("grant rights are empty".into()));
    }
    let limits = parse_limits(y.need("limits").map_err(|e| Error(e.to_string()))?)?;
    let ttl = y.need("max_ttl").map_err(|e| Error(e.to_string()))?.as_str().map_err(|e| Error(e.to_string()))?;
    Ok(Grant { rights, limits, max_ttl_ms: parse_ttl(ttl)? })
}

fn parse_limits(y: &Yaml) -> Result<Limits, Error> {
    for key in y.keys().map_err(|e| Error(e.to_string()))? {
        if !matches!(key, "steps" | "cpu_hours" | "gpu_hours" | "money_cny" | "egress_channels") {
            return Err(Error(format!("unknown limit {key}")));
        }
    }
    let steps = opt_u64(y, "steps")?.unwrap_or(0);
    let cpu_ms = hours_to_ms(opt_f64(y, "cpu_hours")?.unwrap_or(0.0))?;
    let gpu_ms = hours_to_ms(opt_f64(y, "gpu_hours")?.unwrap_or(0.0))?;
    let money_cents = cny_to_cents(opt_f64(y, "money_cny")?.unwrap_or(0.0))?;
    let mut egress_channels = BTreeSet::new();
    if let Some(list) = y.get("egress_channels") {
        for item in list.as_seq().map_err(|e| Error(e.to_string()))? {
            let s = item.as_str().map_err(|e| Error(e.to_string()))?.to_owned();
            parse_channel(&s).map_err(|e| Error(e.to_string()))?;
            egress_channels.insert(s);
        }
    }
    Ok(Limits { steps, cpu_ms, gpu_ms, money_cents, egress_channels })
}

fn parse_rule(y: &Yaml) -> Result<Rule, Error> {
    let map = y.as_map().map_err(|e| Error(e.to_string()))?;
    if map.len() != 1 {
        return Err(Error("a rule states exactly one of allow, confirm, deny".into()));
    }
    let (name, body) = &map[0];
    let effect = Effect::parse(name).ok_or_else(|| Error(format!("unknown effect {name}")))?;
    for key in body.keys().map_err(|e| Error(e.to_string()))? {
        if !matches!(key, "channel" | "max_sensitivity" | "min_sensitivity" | "max_cost_cny_per_day" | "when") {
            return Err(Error(format!("unknown rule condition {key}")));
        }
    }
    let channel = match body.get("channel") {
        None => None,
        Some(v) => {
            let s = v.as_str().map_err(|e| Error(e.to_string()))?.to_owned();
            parse_channel(&s).map_err(|e| Error(e.to_string()))?;
            Some(s)
        }
    };
    Ok(Rule {
        effect,
        channel,
        max_sensitivity: opt_sensitivity(body, "max_sensitivity")?,
        min_sensitivity: opt_sensitivity(body, "min_sensitivity")?,
        max_cost_cents_per_day: match body.get("max_cost_cny_per_day") {
            None => None,
            Some(v) => Some(cny_to_cents(number(v)?)?),
        },
        when: match body.get("when") {
            None => None,
            Some(v) => Some(v.as_str().map_err(|e| Error(e.to_string()))?.to_owned()),
        },
    })
}

fn opt_sensitivity(y: &Yaml, key: &str) -> Result<Option<Sensitivity>, Error> {
    match y.get(key) {
        None => Ok(None),
        Some(v) => {
            let s = v.as_str().map_err(|e| Error(e.to_string()))?;
            s.parse().map(Some).map_err(|_| Error(format!("unknown sensitivity {s}")))
        }
    }
}

fn opt_u64(y: &Yaml, key: &str) -> Result<Option<u64>, Error> {
    match y.get(key) {
        None => Ok(None),
        Some(v) => {
            let n = number(v)?;
            if n < 0.0 || n.fract() != 0.0 {
                return Err(Error(format!("{key} must be a whole number")));
            }
            Ok(Some(n as u64))
        }
    }
}

fn opt_f64(y: &Yaml, key: &str) -> Result<Option<f64>, Error> {
    match y.get(key) {
        None => Ok(None),
        Some(v) => Ok(Some(number(v)?)),
    }
}

fn number(v: &Yaml) -> Result<f64, Error> {
    v.as_f64().map_err(|e| Error(e.to_string()))
}

fn hours_to_ms(hours: f64) -> Result<u64, Error> {
    if !hours.is_finite() || hours < 0.0 {
        return Err(Error("negative duration".into()));
    }
    Ok((hours * 3_600_000.0).ceil() as u64)
}

fn cny_to_cents(cny: f64) -> Result<u64, Error> {
    if !cny.is_finite() || cny < 0.0 {
        return Err(Error("negative money".into()));
    }
    Ok((cny * 100.0).ceil() as u64)
}

fn parse_ttl(text: &str) -> Result<u64, Error> {
    let (num, mul) = if let Some(n) = text.strip_suffix('h') {
        (n, 3_600_000u64)
    } else if let Some(n) = text.strip_suffix('m') {
        (n, 60_000)
    } else if let Some(n) = text.strip_suffix('s') {
        (n, 1_000)
    } else if let Some(n) = text.strip_suffix('d') {
        (n, 86_400_000)
    } else {
        return Err(Error(format!("ttl {text:?} needs a unit: h, m, s or d")));
    };
    let n: u64 = num.parse().map_err(|_| Error(format!("bad ttl {text}")))?;
    n.checked_mul(mul).ok_or_else(|| Error("ttl overflow".into()))
}
