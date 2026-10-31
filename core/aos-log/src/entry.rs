//! Log entries (SPEC §7.1). The log is the only source of truth; every index
//! is rebuilt from it.

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use aos_types::cbor::{self, Value};
use aos_types::codec::{self, Error, FromCbor, Record, SchemaError, ToCbor, record};
use aos_types::id::ParseError;
use aos_types::value;
use aos_types::{Actor, Digest, FieldValue, Object, ObjectId, Timestamp, TxId};

/// `main`, or a name such as `task/01JC90...`: a lowercase-led first segment
/// followed by `/`-separated segments of `[A-Za-z0-9_-]`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BranchName(String);

const MAIN: &str = "main";
const MAX_BRANCH_LEN: usize = 128;

impl BranchName {
    pub fn main() -> Self {
        BranchName(MAIN.to_owned())
    }

    pub fn is_main(&self) -> bool {
        self.0 == MAIN
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BranchName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for BranchName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for BranchName {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut segments = s.split('/');
        let first = segments.next().unwrap_or_default();
        let first_ok = first.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            && first.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-');
        let rest_ok = segments
            .all(|seg| !seg.is_empty() && seg.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'));
        if s.len() <= MAX_BRANCH_LEN && first_ok && rest_ok {
            Ok(BranchName(s.to_owned()))
        } else {
            Err(ParseError("invalid branch name"))
        }
    }
}

/// One object write. The written state is stored whole: v1's "patch" is the
/// full object after the write (see DECISIONS.md).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Write {
    /// `None` when this write creates the object.
    pub prev_version: Option<u64>,
    pub object: Arc<Object>,
}

impl Write {
    pub fn id(&self) -> ObjectId {
        self.object.id
    }

    pub fn new_version(&self) -> u64 {
        self.object.version
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxRecord {
    pub branch: BranchName,
    pub tx: TxId,
    pub actor: Actor,
    pub capability: Option<String>,
    /// Qualified action name, e.g. `ml.dataset.dedupe@1`; `None` for direct
    /// edits and reverts.
    pub action: Option<String>,
    pub inputs: BTreeMap<String, FieldValue>,
    pub writes: Vec<Write>,
    /// Egress intents created by this transaction (SPEC §11).
    pub intents: Vec<ObjectId>,
    /// Set on the reverse transaction appended by `revert` (SPEC §7.6).
    pub revert_of: Option<TxId>,
    /// Set on the copy appended to `main` when a branch is committed.
    pub merged_from: Option<BranchName>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BranchOp {
    /// Reads `main` entries with `seq < base`.
    Fork {
        base: u64,
    },
    Rebase {
        base: u64,
    },
    /// Sent for review.
    Submit,
    /// Returned from review to the agent.
    Reopen,
    Discard,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    Tx(TxRecord),
    Branch {
        branch: BranchName,
        actor: Actor,
        op: BranchOp,
    },
    /// Closes the group of `txs` entries merged from `branch` that
    /// immediately precede it. A group without its commit never took effect
    /// (SPEC §7.5).
    Commit {
        branch: BranchName,
        actor: Actor,
        txs: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub seq: u64,
    /// Hash of the previous entry; all zeros for the first.
    pub prev_hash: Digest,
    pub timestamp: Timestamp,
    pub body: Body,
}

/// The `prev_hash` of entry 0.
pub const GENESIS: Digest = Digest::from_bytes([0; 32]);

/// A record read back from storage, with the hash it claims and the hash its
/// content actually has.
#[derive(Clone, Debug)]
pub struct Decoded {
    pub entry: Entry,
    pub stored_hash: Digest,
    pub computed_hash: Digest,
}

impl Entry {
    /// `SHA-256(canonical_cbor(entry without hash))`.
    pub fn hash(&self) -> Digest {
        Digest::of_value(&self.unsigned())
    }

    /// The stored record: `[entry, hash]`, where `entry` is the canonical
    /// encoding the hash covers. Equivalent to the entry carrying a `hash`
    /// field (SPEC §7.1), but the hash can be checked against the stored
    /// bytes without re-encoding.
    pub fn encode(&self) -> (Vec<u8>, Digest) {
        let body = cbor::encode(&self.unsigned());
        let hash = Digest::of(&body);
        let mut out = Vec::with_capacity(body.len() + 35);
        out.push(0x82);
        out.extend_from_slice(&body);
        cbor::encode_into(&hash.to_cbor(), &mut out);
        (out, hash)
    }

    pub fn decode(bytes: &[u8]) -> Result<Decoded, Error> {
        let Some((&0x82, rest)) = bytes.split_first() else {
            return Err(SchemaError::new("expected [entry, hash]").into());
        };
        let (unsigned, used) = cbor::decode_prefix(rest)?;
        let computed_hash = Digest::of(&rest[..used]);
        let stored_hash = Digest::from_cbor(&cbor::decode(&rest[used..])?).map_err(|e| e.within("hash"))?;
        let entry = Entry::from_cbor(&unsigned)?;
        Ok(Decoded { entry, stored_hash, computed_hash })
    }

    fn unsigned(&self) -> Value {
        let mut e = vec![
            ("seq", Value::Unsigned(self.seq)),
            ("prev_hash", self.prev_hash.to_cbor()),
            ("timestamp", Value::int(self.timestamp.unix_ms())),
        ];
        match &self.body {
            Body::Tx(tx) => {
                e.push(("kind", "tx".into()));
                tx.entries(&mut e);
            }
            Body::Branch { branch, actor, op } => {
                let kind = match op {
                    BranchOp::Fork { .. } => "fork",
                    BranchOp::Rebase { .. } => "rebase",
                    BranchOp::Submit => "submit",
                    BranchOp::Reopen => "reopen",
                    BranchOp::Discard => "discard",
                };
                e.push(("kind", kind.into()));
                e.push(("branch", branch.as_str().into()));
                e.push(("actor", actor.to_string().into()));
                if let BranchOp::Fork { base } | BranchOp::Rebase { base } = op {
                    e.push(("base", Value::Unsigned(*base)));
                }
            }
            Body::Commit { branch, actor, txs } => {
                e.push(("kind", "commit".into()));
                e.push(("branch", branch.as_str().into()));
                e.push(("actor", actor.to_string().into()));
                e.push(("txs", Value::Unsigned(*txs)));
            }
        }
        record(e)
    }
}

impl FromCbor for Entry {
    fn from_cbor(v: &Value) -> Result<Self, SchemaError> {
        let mut r = Record::new(v)?;
        let seq = r.req("seq", codec::uint)?;
        let prev_hash = r.req("prev_hash", Digest::from_cbor)?;
        let timestamp = r.req("timestamp", |v| {
            Timestamp::from_unix_ms(codec::int(v)?).ok_or_else(|| SchemaError::new("timestamp out of range"))
        })?;
        let kind = r.req("kind", codec::text)?;
        let body = match kind {
            "tx" => Body::Tx(TxRecord::read(&mut r)?),
            "commit" => Body::Commit {
                branch: r.req("branch", codec::parsed)?,
                actor: r.req("actor", codec::parsed)?,
                txs: r.req("txs", codec::uint)?,
            },
            "fork" | "rebase" | "submit" | "reopen" | "discard" => {
                let branch = r.req("branch", codec::parsed)?;
                let actor = r.req("actor", codec::parsed)?;
                let op = match kind {
                    "fork" => BranchOp::Fork { base: r.req("base", codec::uint)? },
                    "rebase" => BranchOp::Rebase { base: r.req("base", codec::uint)? },
                    "submit" => BranchOp::Submit,
                    "reopen" => BranchOp::Reopen,
                    _ => BranchOp::Discard,
                };
                Body::Branch { branch, actor, op }
            }
            other => return Err(SchemaError::new(format!("unknown kind {other:?}")).within("kind")),
        };
        r.finish()?;
        Ok(Entry { seq, prev_hash, timestamp, body })
    }
}

impl TxRecord {
    fn entries(&self, e: &mut Vec<(&'static str, Value)>) {
        e.push(("branch", self.branch.as_str().into()));
        e.push(("tx", self.tx.to_string().into()));
        e.push(("actor", self.actor.to_string().into()));
        e.push(("inputs", value::map_to_cbor(&self.inputs)));
        e.push(("writes", Value::Array(self.writes.iter().map(Write::to_cbor).collect())));
        e.push(("intents", Value::Array(self.intents.iter().map(|id| id.to_string().into()).collect())));
        e.extend(self.capability.as_ref().map(|c| ("capability", c.as_str().into())));
        e.extend(self.action.as_ref().map(|a| ("action", a.as_str().into())));
        e.extend(self.revert_of.map(|t| ("revert_of", t.to_string().into())));
        e.extend(self.merged_from.as_ref().map(|b| ("merged_from", b.as_str().into())));
    }

    fn read(r: &mut Record<'_>) -> Result<Self, SchemaError> {
        let tx = TxRecord {
            branch: r.req("branch", codec::parsed)?,
            tx: r.req("tx", codec::parsed)?,
            actor: r.req("actor", codec::parsed)?,
            capability: r.opt("capability", codec::text)?.map(str::to_owned),
            action: r.opt("action", codec::text)?.map(str::to_owned),
            inputs: r.req("inputs", value::map_from_cbor)?,
            writes: r.req("writes", |v| {
                codec::array(v)?.iter().enumerate().map(|(i, w)| Write::from_cbor(w).map_err(|e| e.within(i))).collect()
            })?,
            intents: r.req("intents", |v| codec::array(v)?.iter().map(codec::parsed).collect())?,
            revert_of: r.opt("revert_of", codec::parsed)?,
            merged_from: r.opt("merged_from", codec::parsed)?,
        };
        tx.check().map_err(|e| e.within("writes"))?;
        Ok(tx)
    }

    /// Invariants every stored transaction satisfies: at least one write, one
    /// write per object, versions advance by one, and each written object
    /// names this transaction and its actor.
    pub fn check(&self) -> Result<(), SchemaError> {
        if self.writes.is_empty() {
            return Err(SchemaError::new("a transaction writes at least one object"));
        }
        let mut seen = HashSet::new();
        for (i, w) in self.writes.iter().enumerate() {
            let o = &w.object;
            let err = |m: &str| Err(SchemaError::new(m).within(i));
            if !seen.insert(o.id) {
                return err("object written twice");
            }
            if o.version != w.prev_version.map_or(1, |p| p + 1) {
                return err("version must advance by one");
            }
            if o.provenance.tx != self.tx || o.provenance.actor != self.actor {
                return err("object provenance must name this transaction and actor");
            }
        }
        Ok(())
    }
}

impl ToCbor for Write {
    fn to_cbor(&self) -> Value {
        record([
            ("prev_version", self.prev_version.map_or(Value::Null, Value::Unsigned)),
            ("object", self.object.to_cbor()),
        ])
    }
}

impl FromCbor for Write {
    fn from_cbor(v: &Value) -> Result<Self, SchemaError> {
        let mut r = Record::new(v)?;
        let prev_version = r.req("prev_version", |v| match v {
            Value::Null => Ok(None),
            Value::Unsigned(n) if *n > 0 => Ok(Some(*n)),
            _ => Err(SchemaError::new("expected positive integer or null")),
        })?;
        let object = Arc::new(r.req("object", Object::from_cbor)?);
        r.finish()?;
        Ok(Write { prev_version, object })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_names() {
        for ok in ["main", "task/01JC90AAAAAAAAAAAAAAAAAAAA", "review-2", "a/b_c/D-1"] {
            assert_eq!(ok.parse::<BranchName>().unwrap().as_str(), ok);
        }
        for bad in ["", "Main", "task/", "/x", "a//b", "a b", "1task", &"a".repeat(129)] {
            assert!(bad.parse::<BranchName>().is_err(), "{bad}");
        }
        assert!(BranchName::main().is_main());
    }
}
