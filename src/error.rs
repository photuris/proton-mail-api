//! Typed errors for the whole crate.
//!
//! `Debug` is written by hand so that server text and verification tokens
//! never reach a log line through `{:?}`.

use std::fmt;
use std::time::Duration;

/// Every way a call into the Proton API can fail.
#[derive(thiserror::Error)]
pub enum Error {
    /// The server answered with an error envelope this crate has no typed
    /// variant for. `message` is server text; read it only to show a user.
    #[error("api error code {code} (http {status})")]
    Api {
        /// HTTP status of the response.
        status: u16,
        /// Proton `Code` from the envelope, `0` when the body had none.
        code: i64,
        /// Proton `Error` text from the envelope, empty when absent.
        message: String,
    },
    /// Proton's anti-abuse system refused the request (code 2028).
    #[error("refused by Proton anti-abuse (code 2028)")]
    Blocked {
        /// Proton's reason text, as sent ("" when absent).
        message: String,
    },
    /// Proton wants a human-verification challenge solved (code 9001).
    #[error("human verification required")]
    HumanVerificationRequired {
        /// Challenge methods the server offers, such as `captcha`.
        methods: Vec<String>,
        /// Token to present with the solved challenge.
        token: String,
    },
    /// Proton wants the device verified (code 9002).
    #[error("device verification required")]
    DeviceVerificationRequired,
    /// Still answered 429 or 503 after every permitted retry.
    #[error("rate limited after retries; server asked to wait {retry_after:?}")]
    RateLimited {
        /// The last wait the server asked for, uncapped.
        retry_after: Duration,
    },
    /// The server rejected the `x-pm-appversion` header (codes 5001, 5003).
    #[error("app version rejected by server")]
    AppVersionRejected,
    /// The server rejected the password (code 8002).
    #[error("wrong password")]
    WrongPassword,
    /// The session can no longer be used; the caller must log in again.
    #[error("session expired or revoked")]
    SessionExpired,
    /// The request failed before a usable response arrived.
    #[error("transport error")]
    Transport(#[source] reqwest::Error),
    /// The body of a successful response did not match the expected shape.
    /// Carries nothing, because the body may hold secrets.
    #[error("invalid response from server")]
    InvalidResponse,
    /// An SRP primitive failed.
    #[error(transparent)]
    Srp(#[from] crate::srp::SrpError),
    /// A cryptographic step failed. A fixed description, never a formatted
    /// lower-level error.
    #[error("crypto error: {0}")]
    Crypto(&'static str),
    /// None of the account's keys could be unlocked.
    #[error("no key could be unlocked")]
    NoUsableKey,
    /// The server refused an action for some of the messages.
    #[error("action failed for {} message(s)", .ids.len())]
    ActionFailed {
        /// Ids of the messages the action failed for.
        ids: Vec<String>,
    },
    /// The client was configured with an unusable value.
    #[error("invalid client configuration: {0}")]
    InvalidConfig(&'static str),
}

/// Result alias used across the crate.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Proton's reason text for [`Error::Api`] and [`Error::Blocked`]; `None`
    /// when it is empty and for every other variant. The crate never prints
    /// it; show it only if you choose to.
    pub fn server_message(&self) -> Option<&str> {
        match self {
            Self::Api { message, .. } | Self::Blocked { message } => {
                Some(message.as_str()).filter(|m| !m.is_empty())
            }
            _ => None,
        }
    }
}

impl fmt::Debug for Error {
    /// Prints like a derived `Debug`, except that `Api::message`,
    /// `Blocked::message` and the verification token print as `"<redacted>"` and the verification
    /// methods print only as a count, since they are server text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Api { status, code, .. } => f
                .debug_struct("Api")
                .field("status", status)
                .field("code", code)
                .field("message", &"<redacted>")
                .finish(),
            Self::Blocked { .. } => f
                .debug_struct("Blocked")
                .field("message", &"<redacted>")
                .finish(),
            Self::HumanVerificationRequired { methods, .. } => f
                .debug_struct("HumanVerificationRequired")
                .field("methods", &format_args!("<{} items>", methods.len()))
                .field("token", &"<redacted>")
                .finish(),
            Self::DeviceVerificationRequired => f.write_str("DeviceVerificationRequired"),
            Self::RateLimited { retry_after } => f
                .debug_struct("RateLimited")
                .field("retry_after", retry_after)
                .finish(),
            Self::AppVersionRejected => f.write_str("AppVersionRejected"),
            Self::WrongPassword => f.write_str("WrongPassword"),
            Self::SessionExpired => f.write_str("SessionExpired"),
            Self::Transport(e) => f.debug_tuple("Transport").field(e).finish(),
            Self::InvalidResponse => f.write_str("InvalidResponse"),
            Self::Srp(e) => f.debug_tuple("Srp").field(e).finish(),
            Self::Crypto(s) => f.debug_tuple("Crypto").field(s).finish(),
            Self::NoUsableKey => f.write_str("NoUsableKey"),
            Self::ActionFailed { ids } => f.debug_struct("ActionFailed").field("ids", ids).finish(),
            Self::InvalidConfig(s) => f.debug_tuple("InvalidConfig").field(s).finish(),
        }
    }
}
