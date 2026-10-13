//! Message triage: mark read or unread, add or remove a label, move to a folder.
//!
//! Every call splits its ids into chunks of [`ACTION_CHUNK`] and sends one
//! request per chunk, in order. A per-message failure inside a label reply
//! does not stop later chunks; the failed ids are returned together at the end.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::session::Session;
use crate::types::Empty;

/// Most ids Proton accepts in one triage request (go-proton-api `maxPageSize`).
pub const ACTION_CHUNK: usize = 150;

/// Per-message status Proton reports for a label request.
const ITEM_OK: i64 = 1000;

/// Body of `PUT /mail/v4/messages/{read,unread}`.
#[derive(Serialize)]
struct IdsBody<'a> {
    #[serde(rename = "IDs")]
    ids: &'a [String],
}

/// Body of `PUT /mail/v4/messages/{label,unlabel}`.
#[derive(Serialize)]
struct LabelBody<'a> {
    #[serde(rename = "LabelID")]
    label_id: &'a str,
    #[serde(rename = "IDs")]
    ids: &'a [String],
}

/// Reply to a label or unlabel request. Every field may be absent: the
/// reference fake server answers with an empty body.
#[derive(Default, Deserialize)]
struct LabelReply {
    #[serde(rename = "Responses", default)]
    responses: Vec<ItemReply>,
}

#[derive(Deserialize)]
struct ItemReply {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Response")]
    response: ItemStatus,
}

#[derive(Deserialize)]
struct ItemStatus {
    #[serde(rename = "Code", default)]
    code: i64,
}

impl Session {
    /// Marks the messages read.
    ///
    /// # Errors
    ///
    /// Any transport [`Error`], unchanged; the first one stops the call.
    pub async fn mark_read(&self, ids: &[String]) -> Result<()> {
        self.set_read("/mail/v4/messages/read", ids).await
    }

    /// Marks the messages unread.
    ///
    /// # Errors
    ///
    /// Any transport [`Error`], unchanged; the first one stops the call.
    pub async fn mark_unread(&self, ids: &[String]) -> Result<()> {
        self.set_read("/mail/v4/messages/unread", ids).await
    }

    /// Adds `label_id` to the messages.
    ///
    /// # Errors
    ///
    /// [`Error::ActionFailed`] with every id the server refused, after all
    /// chunks were sent; any transport [`Error`] stops the call at once.
    pub async fn add_label(&self, ids: &[String], label_id: &str) -> Result<()> {
        self.set_label("/mail/v4/messages/label", ids, label_id)
            .await
    }

    /// Removes `label_id` from the messages.
    ///
    /// # Errors
    ///
    /// As for [`Session::add_label`].
    pub async fn remove_label(&self, ids: &[String], label_id: &str) -> Result<()> {
        self.set_label("/mail/v4/messages/unlabel", ids, label_id)
            .await
    }

    /// Moves the messages into `folder_id`. Proton keeps folders exclusive,
    /// so this is [`Session::add_label`] with a folder id.
    ///
    /// # Errors
    ///
    /// As for [`Session::add_label`].
    pub async fn move_to(&self, ids: &[String], folder_id: &str) -> Result<()> {
        self.add_label(ids, folder_id).await
    }

    async fn set_read(&self, path: &str, ids: &[String]) -> Result<()> {
        for chunk in ids.chunks(ACTION_CHUNK) {
            let _: Empty = self
                .transport()
                .put_json(path, &IdsBody { ids: chunk })
                .await?;
        }

        Ok(())
    }

    async fn set_label(&self, path: &str, ids: &[String], label_id: &str) -> Result<()> {
        let mut failed = Vec::new();

        for chunk in ids.chunks(ACTION_CHUNK) {
            let reply: LabelReply = self
                .transport()
                .put_json(
                    path,
                    &LabelBody {
                        label_id,
                        ids: chunk,
                    },
                )
                .await?;

            failed.extend(
                reply
                    .responses
                    .into_iter()
                    .filter(|r| r.response.code != ITEM_OK)
                    .map(|r| r.id),
            );
        }

        if failed.is_empty() {
            Ok(())
        } else {
            Err(Error::ActionFailed { ids: failed })
        }
    }
}
