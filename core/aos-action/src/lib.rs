//! Action declarations, the host ABI and the wasmtime sandbox (SPEC §8, §9).
//!
//! Guest code gets no WASI, no clock and no filesystem. The only imports it
//! may have are the `aos` functions defined in [`abi`]. Anything else is an
//! I/O attempt: the transaction is dropped and an `ActionViolation` is written.

mod abi;
mod catalog;
mod context;
mod decl;
mod expr;
mod query;
mod review;
mod runtime;

pub use catalog::Catalog;
pub use context::{BlobStore, Violation};
pub use decl::{ActionDecl, Reversibility, parse_action, parse_type};
pub use expr::{Expr, eval_bool, parse as parse_expr};
pub use review::{Dispatch, IntentReview, IntentView, Review};
pub use runtime::{Call, Error, IMPORTS, Outcome, Runtime};

pub struct Host {
    cx: *mut (),
    limiter: Limiter,
    handles: Vec<Vec<u8>>,
    violation: Option<Violation>,
}

// The pointer is only dereferenced on the thread that is inside `invoke`,
// and the store is not sent anywhere while it is set.
unsafe impl Send for Host {}

struct Limiter {
    memory_bytes: usize,
}

impl Default for Host {
    fn default() -> Self {
        Host { cx: std::ptr::null_mut(), limiter: Limiter { memory_bytes: 0 }, handles: Vec::new(), violation: None }
    }
}
