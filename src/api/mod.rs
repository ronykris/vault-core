//! Public API for vault-core
//!
//! This module provides the public API surface documented in ADR-002 and ADR-003.
//! All cryptographic primitives are in private modules; this API composes
//! them into safe, high-level operations.

mod keys;
mod wrapping;
mod encryption;
mod ingest;
mod signatures;
mod formats;
mod session;

// Re-export all public functions
pub use keys::*;
pub use wrapping::*;
pub use encryption::*;
pub use ingest::*;
pub use signatures::*;
pub use formats::*;
pub use session::*;
