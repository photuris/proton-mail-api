//! Recipient key lookup and the send flow.
//!
//! [`Session::send`] looks up every recipient, creates the draft, builds the
//! package with [`crate::compose`] and sends it. The draft and the send
//! request go out through [`Transport::post_json_once`], so neither is ever
//! repeated on a 429 or 503: a repeated send could deliver a message twice.
//!
//! [`Transport::post_json_once`]: crate::http::Transport::post_json_once

use std::collections::HashSet;
use std::fmt;

use pgp::composed::{Deserializable, SignedPublicKey};
use serde::{Deserialize, Serialize};

use crate::compose::{
    BodyType, Package, RecipientKey, RecipientKind, build_package, encrypt_draft_body,
    encryption_subkey,
};
use crate::error::{Error, Result};
use crate::keys::{AddressKey, UnlockedKeys};
use crate::messages::{MessageMetadata, Recipient};
use crate::session::Session;
use crate::types::{ApiBool, path_segment};

/// `RecipientType` of a Proton recipient in the key lookup reply.
const RECIPIENT_TYPE_INTERNAL: i64 = 1;

/// Bit of a lookup key's `Flags` that is clear when the key is obsolete.
const KEY_FLAG_NOT_OBSOLETE: i64 = 2;

/// What a message answers or forwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentAction {
    /// A reply to the sender.
    Reply,
    /// A reply to the sender and all other recipients.
    ReplyAll,
    /// A forward.
    Forward,
}

impl ParentAction {
    /// The `Action` value of the draft request.
    fn wire(self) -> u8 {
        match self {
            Self::Reply => 0,
            Self::ReplyAll => 1,
            Self::Forward => 2,
        }
    }
}

/// The message a new message replies to or forwards.
#[derive(Debug, Clone)]
pub struct ParentRef {
    /// Id of the parent message.
    pub id: String,
    /// How the new message relates to it.
    pub action: ParentAction,
}

/// A message to send.
#[derive(Clone)]
pub struct OutgoingMessage {
    /// The sending address; its address must belong to an unlocked key.
    pub from: Recipient,
    /// To recipients.
    pub to: Vec<Recipient>,
    /// Cc recipients.
    pub cc: Vec<Recipient>,
    /// Bcc recipients; they get a package entry like the others.
    pub bcc: Vec<Recipient>,
    /// Subject line.
    pub subject: String,
    /// The body text, plain or HTML as `body_type` says.
    pub body: String,
    /// How `body` is written.
    pub body_type: BodyType,
    /// The message this one replies to or forwards.
    pub parent: Option<ParentRef>,
}

impl fmt::Debug for OutgoingMessage {
    /// Prints the addresses, body type and parent; the subject and the body
    /// print as `"<redacted>"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutgoingMessage")
            .field("from", &self.from)
            .field("to", &self.to)
            .field("cc", &self.cc)
            .field("bcc", &self.bcc)
            .field("subject", &"<redacted>")
            .field("body", &"<redacted>")
            .field("body_type", &self.body_type)
            .field("parent", &self.parent)
            .finish()
    }
}

/// Body of `GET /core/v4/keys`. No `Debug`: it holds keys.
#[derive(Deserialize)]
struct KeysReply {
    #[serde(rename = "Keys", default)]
    keys: Option<Vec<LookupKey>>,
    #[serde(rename = "RecipientType")]
    recipient_type: i64,
}

/// One public key of a recipient as the lookup lists it.
#[derive(Deserialize)]
struct LookupKey {
    #[serde(rename = "Flags", default)]
    flags: i64,
    #[serde(rename = "PublicKey", default)]
    public_key: Option<String>,
}

/// Body of `POST /mail/v4/messages`.
#[derive(Serialize)]
struct DraftRequest<'a> {
    #[serde(rename = "Message")]
    message: DraftMessage<'a>,
    #[serde(rename = "AttachmentKeyPackets")]
    attachment_key_packets: [String; 0],
    #[serde(rename = "ParentID", skip_serializing_if = "Option::is_none")]
    parent_id: Option<&'a str>,
    #[serde(rename = "Action", skip_serializing_if = "Option::is_none")]
    action: Option<u8>,
}

/// The `Message` of a [`DraftRequest`].
#[derive(Serialize)]
struct DraftMessage<'a> {
    #[serde(rename = "Subject")]
    subject: &'a str,
    #[serde(rename = "Sender")]
    sender: &'a Recipient,
    #[serde(rename = "ToList")]
    to_list: &'a [Recipient],
    #[serde(rename = "CCList")]
    cc_list: &'a [Recipient],
    #[serde(rename = "BCCList")]
    bcc_list: &'a [Recipient],
    #[serde(rename = "Body")]
    body: String,
    #[serde(rename = "MIMEType")]
    mime_type: &'static str,
    #[serde(rename = "AddressID")]
    address_id: &'a str,
    #[serde(rename = "Unread")]
    unread: ApiBool,
}

/// Body of `POST /mail/v4/messages/<id>`.
#[derive(Serialize)]
struct SendRequest<'a> {
    #[serde(rename = "Packages")]
    packages: &'a [Package],
}

/// Reply to the draft request.
#[derive(Deserialize)]
struct DraftReply {
    #[serde(rename = "Message")]
    message: MessageMetadata,
}

/// Reply to the send request.
#[derive(Deserialize)]
struct SentReply {
    #[serde(rename = "Sent")]
    sent: MessageMetadata,
}

impl Session {
    /// Looks up how `email` receives mail: `GET /core/v4/keys?Email=<email>`.
    ///
    /// A Proton recipient is [`RecipientKind::Internal`] with the first of
    /// their keys that is not obsolete, parses and has a usable encryption
    /// subkey (see [`crate::compose::encryption_subkey`]); any other recipient
    /// is [`RecipientKind::External`]. The result carries `email` as given.
    ///
    /// # Errors
    ///
    /// [`Error::RecipientKeyUnusable`] when a Proton recipient has no such
    /// key; [`Error::InvalidResponse`] on an unexpected body; otherwise
    /// whatever the transport reports.
    pub async fn recipient_key(&self, email: &str) -> Result<RecipientKey> {
        let reply: KeysReply = self
            .transport()
            .get_json("/core/v4/keys", &[("Email", email.to_owned())])
            .await?;

        let kind = if reply.recipient_type == RECIPIENT_TYPE_INTERNAL {
            let key =
                usable_key(reply.keys.unwrap_or_default()).ok_or(Error::RecipientKeyUnusable)?;

            RecipientKind::Internal(key)
        } else {
            RecipientKind::External
        };

        Ok(RecipientKey {
            email: email.to_owned(),
            kind,
        })
    }

    /// Sends `msg` and returns the server's metadata of the sent message.
    ///
    /// Looks up every recipient (to, cc and bcc, each distinct address once),
    /// creates the draft, then sends it in one package. Nothing is created
    /// before the lookups have all succeeded. The draft and the send request
    /// are never repeated.
    ///
    /// # Errors
    ///
    /// - [`Error::NoRecipients`], [`Error::UnknownSender`] and any lookup
    ///   error, before anything is created.
    /// - The draft request's own error, as it is, when the draft could not be
    ///   created. If its response was lost a draft may still exist; its id is
    ///   unknown.
    /// - [`Error::SendRejected`] when the server refused the send before
    ///   processing it: the message was not sent and the draft is kept.
    /// - [`Error::SendOutcomeUnknown`] when the send request got no readable
    ///   answer, a 5xx or an undecodable body: the message may be sent or may
    ///   still be sent, so the caller must not send it again.
    pub async fn send(
        &self,
        keys: &UnlockedKeys,
        msg: &OutgoingMessage,
    ) -> Result<MessageMetadata> {
        let recipients: Vec<&Recipient> = msg.to.iter().chain(&msg.cc).chain(&msg.bcc).collect();

        if recipients.is_empty() {
            return Err(Error::NoRecipients);
        }

        let sender = sender_key(keys, &msg.from.address)?;

        let mut seen = HashSet::new();
        let mut recipient_keys = Vec::new();

        for recipient in recipients {
            if seen.insert(recipient.address.to_ascii_lowercase()) {
                recipient_keys.push(self.recipient_key(&recipient.address).await?);
            }
        }

        let body = encrypt_draft_body(sender, &msg.body)?;
        let package = build_package(sender, &msg.body, msg.body_type, &recipient_keys)?;

        let draft = DraftRequest {
            message: DraftMessage {
                subject: &msg.subject,
                sender: &msg.from,
                to_list: &msg.to,
                cc_list: &msg.cc,
                bcc_list: &msg.bcc,
                body,
                mime_type: msg.body_type.mime_type(),
                address_id: &sender.address_id,
                unread: ApiBool(false),
            },
            attachment_key_packets: [],
            parent_id: msg.parent.as_ref().map(|p| p.id.as_str()),
            action: msg.parent.as_ref().map(|p| p.action.wire()),
        };
        let created: DraftReply = self
            .transport()
            .post_json_once("/mail/v4/messages", &draft)
            .await?;
        let draft_id = created.message.id;

        let sent: SentReply = self
            .transport()
            .post_json_once(
                &format!("/mail/v4/messages/{}", path_segment(&draft_id)),
                &SendRequest {
                    packages: std::slice::from_ref(&package),
                },
            )
            .await
            .map_err(|e| match e {
                Error::Transport(_) | Error::InvalidResponse => {
                    Error::SendOutcomeUnknown { draft_id }
                }
                Error::Api { status, .. } if status >= 500 => {
                    Error::SendOutcomeUnknown { draft_id }
                }
                e => Error::SendRejected {
                    draft_id,
                    source: Box::new(e),
                },
            })?;

        Ok(sent.sent)
    }
}

/// The first key that is not obsolete, parses and has a usable encryption
/// subkey.
fn usable_key(keys: Vec<LookupKey>) -> Option<SignedPublicKey> {
    keys.into_iter()
        .filter(|k| k.flags & KEY_FLAG_NOT_OBSOLETE != 0)
        .filter_map(|k| {
            SignedPublicKey::from_string(k.public_key.as_deref()?)
                .ok()
                .map(|(key, _)| key)
        })
        .find(|key| encryption_subkey(key).is_some())
}

/// The key for `address`: its primary key, else its first.
fn sender_key<'a>(keys: &'a UnlockedKeys, address: &str) -> Result<&'a AddressKey> {
    let matching = || {
        keys.address_keys
            .iter()
            .filter(|k| k.email.eq_ignore_ascii_case(address))
    };

    matching()
        .find(|k| k.primary)
        .or_else(|| matching().next())
        .ok_or(Error::UnknownSender)
}
