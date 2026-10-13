//! Unofficial, pure-Rust client for the Proton Mail API.
//!
//! See `README.md` for scope and `AGENTS.md` for the rules that bind this
//! crate (no secrets in errors or logs, zeroized key material, fixture tests).

pub mod actions;
pub mod error;
pub mod events;
pub mod http;
pub mod keys;
pub mod labels;
pub mod messages;
pub mod session;
pub mod srp;
pub mod types;
