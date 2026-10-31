//! Object and transaction ids, object references and actors (SPEC §6.1).

use std::fmt;
use std::str::FromStr;

use crate::ulid::Ulid;

macro_rules! ulid_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub Ulid);

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl FromStr for $name {
            type Err = crate::ulid::ParseUlidError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                s.parse().map($name)
            }
        }
    };
}

ulid_id!(
    /// Globally unique, immutable object identity.
    ObjectId
);
ulid_id!(
    /// Transaction identity.
    TxId
);

/// A reference to an object, optionally pinned to a version: `ID` or `ID@N`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjRef {
    pub id: ObjectId,
    /// `None` means "the version visible in the reader's snapshot".
    pub version: Option<u64>,
}

impl ObjRef {
    pub fn latest(id: ObjectId) -> Self {
        ObjRef { id, version: None }
    }

    pub fn at(id: ObjectId, version: u64) -> Self {
        ObjRef { id, version: Some(version) }
    }
}

impl fmt::Display for ObjRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.version {
            Some(v) => write!(f, "{}@{v}", self.id),
            None => write!(f, "{}", self.id),
        }
    }
}

impl fmt::Debug for ObjRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError(pub &'static str);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ParseError {}

impl FromStr for ObjRef {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (id, version) = match s.split_once('@') {
            Some((id, v)) => (id, Some(parse_version(v)?)),
            None => (s, None),
        };
        let id = id.parse().map_err(|_| ParseError("invalid object id"))?;
        Ok(ObjRef { id, version })
    }
}

/// A positive decimal integer without leading zeros.
pub(crate) fn parse_version(s: &str) -> Result<u64, ParseError> {
    const ERR: ParseError = ParseError("version must be a positive integer without leading zeros");
    if s.is_empty() || s.starts_with('0') || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ERR);
    }
    s.parse().map_err(|_| ERR)
}

/// Who performed a write (SPEC §6.1). Humans and agents are both actors; the
/// log treats their edits the same way.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Actor {
    User,
    AgentTask(Ulid),
    Adapter(String),
    System,
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Actor::User => f.write_str("user"),
            Actor::AgentTask(id) => write!(f, "agent:task/{id}"),
            Actor::Adapter(name) => write!(f, "adapter:{name}"),
            Actor::System => f.write_str("system"),
        }
    }
}

impl fmt::Debug for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Actor {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => return Ok(Actor::User),
            "system" => return Ok(Actor::System),
            _ => {}
        }
        if let Some(id) = s.strip_prefix("agent:task/") {
            return id.parse().map(Actor::AgentTask).map_err(|_| ParseError("invalid task id"));
        }
        if let Some(name) = s.strip_prefix("adapter:") {
            if is_slug(name) {
                return Ok(Actor::Adapter(name.to_owned()));
            }
            return Err(ParseError("invalid adapter name"));
        }
        Err(ParseError("unknown actor"))
    }
}

const MAX_NAME_LEN: usize = 64;

/// `[a-z][a-z0-9_]*`: field names, provider names.
pub fn is_ident(s: &str) -> bool {
    name_like(s, |c| c.is_ascii_lowercase(), |c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// `[A-Z][A-Za-z0-9]*`: type names.
pub fn is_type_ident(s: &str) -> bool {
    name_like(s, |c| c.is_ascii_uppercase(), |c| c.is_ascii_alphanumeric())
}

/// `[a-z][a-z0-9_-]*`: adapter names.
pub fn is_slug(s: &str) -> bool {
    name_like(s, |c| c.is_ascii_lowercase(), |c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

fn name_like(s: &str, first: impl Fn(u8) -> bool, rest: impl Fn(u8) -> bool) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= MAX_NAME_LEN && first(b[0]) && b[1..].iter().all(|&c| rest(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "01JC8Z3K9Q6V2X4M7N1P0R5T8W";

    #[test]
    fn obj_ref_text_forms() {
        let r: ObjRef = format!("{ID}@7").parse().unwrap();
        assert_eq!(r.version, Some(7));
        assert_eq!(r.to_string(), format!("{ID}@7"));
        assert_eq!(ID.parse::<ObjRef>().unwrap().version, None);
        for bad in ["@1", "{ID}@", "{ID}@0", "{ID}@07", "{ID}@+7", "{ID}@1@2"] {
            assert!(bad.replace("{ID}", ID).parse::<ObjRef>().is_err(), "{bad}");
        }
    }

    #[test]
    fn actor_text_forms() {
        for s in ["user", "system", "adapter:minio-client-acme", &format!("agent:task/{ID}")] {
            assert_eq!(s.parse::<Actor>().unwrap().to_string(), s);
        }
        for bad in ["User", "adapter:", "adapter:Bad", "agent:task/xyz", "agent:01JC"] {
            assert!(bad.parse::<Actor>().is_err(), "{bad}");
        }
    }

    #[test]
    fn identifier_classes() {
        assert!(is_ident("sample_count") && !is_ident("SampleCount") && !is_ident("_x") && !is_ident(""));
        assert!(is_type_ident("DatasetVersion") && !is_type_ident("datasetVersion") && !is_type_ident("Data_Set"));
        assert!(is_slug("host-folder") && !is_slug("-x"));
        assert!(!is_ident(&"a".repeat(65)));
    }
}
