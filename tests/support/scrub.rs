//! Default-deny scrubber for captured Proton responses.
//!
//! Strings and numbers are replaced unless a rule keeps them; ids and
//! addresses map to stable placeholders; free-form header maps are replaced
//! wholesale. One [`Scrubber`] is shared across all captured files so the
//! same id maps to the same placeholder in every file.

use std::collections::{BTreeSet, HashMap};

use serde_json::{Map, Value, json};

/// Proton's fixed system label ids (go-proton-api `label_types.go`, WebClients
/// `MAILBOX_LABEL_IDS`).
const SYSTEM_IDS: [&str; 14] = [
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "12", "15", "16",
];
const TIME_KEYS: [&str; 7] = [
    "Time",
    "CreateTime",
    "ModifyTime",
    "ExpirationTime",
    "LastUsedTime",
    "SnoozeTime",
    "ValidUntil",
];
const NUMBER_KEYS: [&str; 19] = [
    "Code",
    "Type",
    "Action",
    "Refresh",
    "More",
    "Stale",
    "Unread",
    "IsReplied",
    "IsRepliedAll",
    "IsForwarded",
    "Primary",
    "Active",
    "Flags",
    "Send",
    "Receive",
    "Status",
    "Order",
    "Version",
    "PasswordMode",
];
/// The known free-form maps of these endpoints.
const OPAQUE_KEYS: [&str; 3] = ["Headers", "ParsedHeaders", "Details"];
const SAFE_MIME: [&str; 13] = [
    "text/plain",
    "text/html",
    "text/calendar",
    "multipart/mixed",
    "multipart/alternative",
    "multipart/related",
    "message/rfc822",
    "application/octet-stream",
    "application/pdf",
    "application/pgp-keys",
    "image/png",
    "image/jpeg",
    "image/gif",
];
const LABEL_ID_KEYS: [&str; 3] = ["LabelID", "LabelIDs", "ParentID"];

/// Arrays keep this many elements.
const ARRAY_KEEP: usize = 3;
/// Larger `Order` values are zeroed: a message's `Order` is a global sequence
/// that re-encodes arrival time.
const MAX_KEPT_ORDER: i64 = 9999;
const SCRUBBED: &str = "<scrubbed>";

/// Maps ids and addresses to stable placeholders and drops everything else.
#[derive(Default)]
pub struct Scrubber {
    ids: HashMap<String, usize>,
    emails: HashMap<String, usize>,
}

impl Scrubber {
    pub fn new() -> Self {
        Self::default()
    }

    /// The scrubbed copy of `value`. The root is scrubbed by type.
    pub fn scrub(&mut self, value: &Value) -> Value {
        self.by_type(value)
    }

    /// `id-<n>` for `s`, or `s` itself when it is empty or a system id in a
    /// label context.
    fn id(&mut self, s: &str, label_context: bool) -> String {
        if s.is_empty() || (label_context && SYSTEM_IDS.contains(&s)) {
            return s.to_string();
        }

        let next = self.ids.len() + 1;
        let n = *self.ids.entry(s.to_string()).or_insert(next);

        format!("id-{n}")
    }

    /// `user<n>@example.invalid` for `s`, or `""` for `""`.
    fn email(&mut self, s: &str) -> String {
        if s.is_empty() {
            return String::new();
        }

        let next = self.emails.len() + 1;
        let n = *self.emails.entry(s.to_string()).or_insert(next);

        format!("user{n}@example.invalid")
    }

    /// Rule 7: scrub by the shape of the value alone.
    fn by_type(&mut self, value: &Value) -> Value {
        match value {
            Value::Object(map) => self.object(map),
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .take(ARRAY_KEEP)
                    .map(|v| self.by_type(v))
                    .collect(),
            ),
            Value::String(s) if s.is_empty() => Value::String(String::new()),
            Value::String(_) => json!(SCRUBBED),
            Value::Number(_) => json!(0),
            Value::Bool(_) | Value::Null => value.clone(),
        }
    }

    /// Scrubs each entry; keys that are not plain schema names become
    /// `k<n>` without ever colliding with another key.
    fn object(&mut self, map: &Map<String, Value>) -> Value {
        let label_record = map.contains_key("Name") && map.contains_key("Color");
        let taken: BTreeSet<&str> = map.keys().map(String::as_str).collect();
        let mut renamed: Vec<String> = Vec::new();
        let mut next = 1;
        let mut out = Map::new();

        for (key, value) in map {
            let scrubbed = self.entry(key, value, label_record);
            let new_key = if plain_key(key) {
                key.clone()
            } else {
                loop {
                    let candidate = format!("k{next}");

                    next += 1;

                    if !taken.contains(candidate.as_str()) && !renamed.contains(&candidate) {
                        renamed.push(candidate.clone());
                        break candidate;
                    }
                }
            };

            out.insert(new_key, scrubbed);
        }

        Value::Object(out)
    }

    /// Rules 1 to 7 for one object entry.
    fn entry(&mut self, key: &str, value: &Value, label_record: bool) -> Value {
        if OPAQUE_KEYS.contains(&key) {
            return json!({ "X-Scrubbed": SCRUBBED });
        }

        let label_context = LABEL_ID_KEYS.contains(&key) || (key == "ID" && label_record);

        if key.ends_with("ID")
            && let Value::String(s) = value
        {
            return Value::String(self.id(s, label_context));
        }

        if key.ends_with("IDs")
            && let Value::Array(items) = value
        {
            return Value::Array(
                items
                    .iter()
                    .take(ARRAY_KEEP)
                    .map(|item| match item {
                        Value::String(s) => Value::String(self.id(s, label_context)),
                        other => self.by_type(other),
                    })
                    .collect(),
            );
        }

        if matches!(key, "Email" | "Address")
            && let Value::String(s) = value
        {
            return Value::String(self.email(s));
        }

        if value.is_number() {
            if TIME_KEYS.contains(&key) {
                return json!(1_700_000_000);
            }

            if key == "Order" && value.as_i64().is_none_or(|n| n > MAX_KEPT_ORDER) {
                return json!(0);
            }

            return if NUMBER_KEYS.contains(&key) {
                value.clone()
            } else {
                json!(0)
            };
        }

        if let Value::String(s) = value {
            match key {
                "MIMEType" => {
                    return json!(if SAFE_MIME.contains(&s.as_str()) {
                        s.as_str()
                    } else {
                        "application/octet-stream"
                    });
                }
                "Disposition" if matches!(s.as_str(), "inline" | "attachment") => {
                    return value.clone();
                }
                "Color" if hex_color(s) => return value.clone(),
                _ => {}
            }
        }

        self.by_type(value)
    }
}

/// An object key that is a schema name: non-empty ASCII alphanumerics and `_`.
fn plain_key(key: &str) -> bool {
    !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// `^#[0-9A-Fa-f]{6}$`, without a regex dependency.
fn hex_color(s: &str) -> bool {
    let b = s.as_bytes();

    b.len() == 7 && b[0] == b'#' && b[1..].iter().all(u8::is_ascii_hexdigit)
}
