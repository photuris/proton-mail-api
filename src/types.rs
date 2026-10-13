//! Wire types shared by every endpoint.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Proton's boolean: a `0`/`1` integer on the wire. Also accepts a JSON
/// boolean when reading.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApiBool(pub bool);

impl Serialize for ApiBool {
    /// Writes `1` for true and `0` for false.
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(u8::from(self.0))
    }
}

impl<'de> Deserialize<'de> for ApiBool {
    /// Reads `0`, `1`, `false` or `true`; any other value is an error.
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Bool(bool),
            Int(u64),
        }

        match Repr::deserialize(d)? {
            Repr::Bool(b) => Ok(Self(b)),
            Repr::Int(n @ (0 | 1)) => Ok(Self(n == 1)),
            Repr::Int(_) => Err(serde::de::Error::custom("expected 0 or 1")),
        }
    }
}

/// Error envelope Proton returns on failures (and sometimes on success).
#[derive(Default, Deserialize)]
pub struct ApiErrorBody {
    /// Proton status code; `0` when the body has none.
    #[serde(rename = "Code", default)]
    pub code: i64,
    /// Human-readable server text.
    #[serde(rename = "Error", default)]
    pub error: Option<String>,
    /// Code-specific detail, such as the human-verification token.
    #[serde(rename = "Details", default)]
    pub details: Option<serde_json::Value>,
}

impl fmt::Debug for ApiErrorBody {
    /// Prints `code`; `error` and `details` may hold server text and the
    /// verification token, so they print as `"<redacted>"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiErrorBody")
            .field("code", &self.code)
            .field("error", &"<redacted>")
            .field("details", &"<redacted>")
            .finish()
    }
}

/// Success body of a call that returns only `{Code:1000}` or nothing.
#[derive(Debug, Default, Deserialize)]
pub struct Empty {
    /// Proton status code; `0` when the body has none.
    #[serde(rename = "Code", default)]
    pub code: i64,
}
