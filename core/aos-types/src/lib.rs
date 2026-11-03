//! AOS core data types: objects, types, deterministic CBOR and hashing
//! (SPEC §6, §7.1).
//!
//! This crate performs no I/O. Time and randomness are supplied through
//! [`ulid::Clock`] and [`ulid::Entropy`].

pub mod cbor;
pub mod codec;
pub mod digest;
pub mod id;
pub mod object;
pub mod schema;
pub mod sim;
pub mod template;
pub mod time;
pub mod ulid;
pub mod value;
pub mod yaml;

pub use codec::{FromCbor, ToCbor};
pub use digest::Digest;
pub use id::{Actor, ObjRef, ObjectId, TxId};
pub use object::{Object, Origin, Provenance, Sensitivity, Taint};
pub use schema::{FieldDecl, FieldKind, TypeDecl, TypeName, TypeRef};
pub use time::Timestamp;
pub use ulid::Ulid;
pub use value::FieldValue;
