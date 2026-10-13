//! A logged-in (or resumable) Proton session.

use std::sync::Arc;

use crate::http::Transport;

/// One account session; owns the [`Transport`] that holds its tokens.
pub struct Session {
    transport: Arc<Transport>,
}

#[allow(dead_code)] // the login flow and every endpoint module build on these
impl Session {
    /// Wraps a transport that already holds (or will receive) tokens.
    pub(crate) fn from_transport(transport: Arc<Transport>) -> Self {
        Self { transport }
    }

    /// The transport every call of this session goes through.
    pub(crate) fn transport(&self) -> &Transport {
        &self.transport
    }
}
