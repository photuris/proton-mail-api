//! Labels, folders and system folders.
//!
//! `GET /core/v4/labels?Type=<n>` lists one kind at a time; [`Session::labels`]
//! gathers all three.

use serde::Deserialize;

use crate::error::Result;
use crate::session::Session;

/// The kinds of label Proton keeps in one table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelType {
    /// A custom label; a message may carry several.
    Label = 1,
    /// A custom folder; a message sits in one.
    Folder = 3,
    /// A built-in folder such as Inbox; see [`system`].
    System = 4,
}

impl LabelType {
    /// The number the API uses for this kind.
    pub fn as_i64(self) -> i64 {
        self as i64
    }

    /// The kind for an API number; `None` for kinds this crate does not model.
    pub fn from_i64(v: i64) -> Option<LabelType> {
        match v {
            1 => Some(Self::Label),
            3 => Some(Self::Folder),
            4 => Some(Self::System),
            _ => None,
        }
    }
}

/// One label, folder or system folder.
#[derive(Debug, Clone, Deserialize)]
pub struct Label {
    /// Stable id; for system folders one of the [`system`] constants.
    #[serde(rename = "ID")]
    pub id: String,
    /// Id of the parent folder; `None` at the top level.
    #[serde(
        rename = "ParentID",
        default,
        deserialize_with = "empty_string_is_none"
    )]
    pub parent_id: Option<String>,
    /// Display name.
    #[serde(rename = "Name")]
    pub name: String,
    /// Full path, for nested folders; empty when the server sends none.
    #[serde(rename = "Path", default)]
    pub path: String,
    /// Colour as `#rrggbb`; empty when the server sends none.
    #[serde(rename = "Color", default)]
    pub color: String,
    /// Raw kind number; see [`LabelType::from_i64`].
    #[serde(rename = "Type")]
    pub r#type: i64,
}

/// Ids of the built-in folders.
pub mod system {
    /// Inbox.
    pub const INBOX: &str = "0";
    /// Every draft, including ones in other folders.
    pub const ALL_DRAFTS: &str = "1";
    /// Every sent message, including ones in other folders.
    pub const ALL_SENT: &str = "2";
    /// Trash.
    pub const TRASH: &str = "3";
    /// Spam.
    pub const SPAM: &str = "4";
    /// All mail.
    pub const ALL_MAIL: &str = "5";
    /// Archive.
    pub const ARCHIVE: &str = "6";
    /// Sent.
    pub const SENT: &str = "7";
    /// Drafts.
    pub const DRAFTS: &str = "8";
    /// Outbox.
    pub const OUTBOX: &str = "9";
    /// Starred.
    pub const STARRED: &str = "10";
    /// Scheduled.
    pub const SCHEDULED: &str = "12";
    /// All mail without trash and spam.
    pub const ALMOST_ALL_MAIL: &str = "15";
    /// Snoozed.
    pub const SNOOZED: &str = "16";
}

/// Reads `""` and `null` as `None`.
fn empty_string_is_none<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d).map(|s| s.filter(|s| !s.is_empty()))
}

/// Response of `GET /core/v4/labels`.
#[derive(Deserialize)]
struct LabelsResponse {
    #[serde(rename = "Labels", default)]
    labels: Vec<Label>,
}

impl Session {
    /// Lists the labels of one kind.
    ///
    /// # Errors
    ///
    /// Any [`Error`](crate::error::Error) the transport classifies to, or
    /// `InvalidResponse` when the reply does not parse.
    pub async fn labels_of_type(&self, t: LabelType) -> Result<Vec<Label>> {
        let reply: LabelsResponse = self
            .transport()
            .get_json("/core/v4/labels", &[("Type", t.as_i64().to_string())])
            .await?;

        Ok(reply.labels)
    }

    /// Lists every label, then every folder, then every system folder.
    ///
    /// # Errors
    ///
    /// As for [`labels_of_type`](Self::labels_of_type); the first failure wins.
    pub async fn labels(&self) -> Result<Vec<Label>> {
        let mut all = self.labels_of_type(LabelType::Label).await?;

        all.extend(self.labels_of_type(LabelType::Folder).await?);
        all.extend(self.labels_of_type(LabelType::System).await?);

        Ok(all)
    }
}
