//! Recipient key lookup and the send flow.
//!
//! [`Session::send`] looks up every recipient, creates the draft, builds the
//! package with [`crate::compose`] and sends it. The draft and the send
//! request go out through [`Transport::post_json_once`], so neither is ever
//! repeated on a 429 or 503: a repeated send could deliver a message twice.
//! Each attachment upload goes out once through
//! [`Transport::post_multipart_once`], because a repeated upload would attach
//! the file twice.
//!
//! [`Transport::post_json_once`]: crate::http::Transport::post_json_once
//! [`Transport::post_multipart_once`]: crate::http::Transport::post_multipart_once

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use pgp::composed::{Deserializable, SignedPublicKey};
use reqwest::multipart::{Form, Part};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::compose::{
    AttachmentKey, BodyType, EncryptedAttachment, Package, RecipientKey, RecipientKind,
    add_attachment_keys, attachment_session_key, build_package, encrypt_attachment,
    encrypt_draft_body, encryption_subkey, rekey_for_sender,
};
use crate::error::{Error, Result};
use crate::keys::{AddressKey, UnlockedKeys};
use crate::messages::{Attachment, MessageMetadata, Recipient};
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
    /// The parent's attachments to carry over. Used only when `action` is
    /// [`ParentAction::Forward`]; ignored otherwise.
    pub forward_attachments: Vec<Attachment>,
}

/// How an outgoing attachment is shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachmentDisposition {
    /// A regular attachment.
    Attachment,
    /// An inline part the body refers to as `cid:<content_id>`.
    Inline {
        /// The content id, without angle brackets.
        content_id: String,
    },
}

/// A file to attach to an outgoing message.
#[derive(Clone)]
pub struct OutgoingAttachment {
    /// File name.
    pub filename: String,
    /// MIME type, such as `image/png`.
    pub mime_type: String,
    /// The file bytes.
    pub data: Vec<u8>,
    /// Regular or inline.
    pub disposition: AttachmentDisposition,
}

impl fmt::Debug for OutgoingAttachment {
    /// Prints the name, MIME type and disposition; the data prints as its
    /// length.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutgoingAttachment")
            .field("filename", &self.filename)
            .field("mime_type", &self.mime_type)
            .field("disposition", &self.disposition)
            .field("data", &format_args!("<{} bytes>", self.data.len()))
            .finish()
    }
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
    /// Files to attach, uploaded in this order.
    pub attachments: Vec<OutgoingAttachment>,
}

impl fmt::Debug for OutgoingMessage {
    /// Prints the addresses, body type and parent; the subject and the body
    /// print as `"<redacted>"` and the attachments as a count.
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
            .field(
                "attachments",
                &format_args!("<{} items>", self.attachments.len()),
            )
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
    /// `[]` unless this forwards attachments, then an object by parent
    /// attachment id.
    attachment_key_packets: Value,
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

/// An attachment the draft response lists: a copy of a forwarded one.
#[derive(Deserialize)]
struct DraftAttachment {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "KeyPackets", default)]
    key_packets: Option<String>,
    #[serde(rename = "Signature", default)]
    signature: Option<String>,
}

/// Reply to the attachment upload request.
#[derive(Deserialize)]
struct UploadReply {
    #[serde(rename = "Attachment")]
    attachment: UploadedAttachment,
}

/// The uploaded attachment as the server reports it.
#[derive(Deserialize)]
struct UploadedAttachment {
    #[serde(rename = "ID")]
    id: String,
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
    /// encrypts the attachments, creates the draft, uploads the attachments
    /// one by one, then sends the draft in one package. Nothing is created
    /// before the lookups and the attachment crypto have all succeeded. The
    /// draft, each upload and the send request are never repeated, except
    /// for one repeat after a token refresh on 401.
    ///
    /// For a forward, `forward_attachments` of the parent are re-keyed to the
    /// sender and copied by the server into the draft.
    ///
    /// # Errors
    ///
    /// - [`Error::NoRecipients`], [`Error::UnknownSender`] and any lookup
    ///   error, before anything is created.
    /// - [`Error::Crypto`] when an attachment cannot be encrypted or a
    ///   forwarded attachment's key cannot be recovered, before anything is
    ///   created.
    /// - The draft request's own error, as it is, when the draft could not be
    ///   created. If its response was lost a draft may still exist; its id is
    ///   unknown.
    /// - [`Error::SendRejected`] when the message was not sent and the draft
    ///   is kept: the server refused the send before processing it, or an
    ///   attachment step after the draft failed (an upload, reading the
    ///   draft's attachments, or attachment crypto). The draft may hold some
    ///   of the attachments.
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
        let mut package = build_package(sender, &msg.body, msg.body_type, &recipient_keys)?;
        let encrypted = msg
            .attachments
            .iter()
            .map(|a| encrypt_attachment(sender, &a.filename, &a.data))
            .collect::<Result<Vec<_>>>()?;
        let forwarded = forwarded_key_packets(keys, sender, msg)?;

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
            attachment_key_packets: if forwarded.is_empty() {
                json!([])
            } else {
                json!(forwarded)
            },
            parent_id: msg.parent.as_ref().map(|p| p.id.as_str()),
            action: msg.parent.as_ref().map(|p| p.action.wire()),
        };
        let created: Value = self
            .transport()
            .post_json_once("/mail/v4/messages", &draft)
            .await?;
        let draft_id = created["Message"]["ID"]
            .as_str()
            .ok_or(Error::InvalidResponse)?
            .to_owned();

        let attach = async {
            let mut attachment_keys = draft_attachment_keys(keys, &created, forwarded.len())?;

            attachment_keys.extend(
                self.upload_all(&draft_id, &msg.attachments, &encrypted)
                    .await?,
            );

            add_attachment_keys(&mut package, &recipient_keys, &attachment_keys)
        };

        attach.await.map_err(|source| Error::SendRejected {
            draft_id: draft_id.clone(),
            source: Box::new(source),
        })?;

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

    /// Uploads `attachments` to the draft `draft_id`, in order, each once,
    /// and returns their keys. `encrypted` holds the matching crypto of each.
    async fn upload_all(
        &self,
        draft_id: &str,
        attachments: &[OutgoingAttachment],
        encrypted: &[EncryptedAttachment],
    ) -> Result<Vec<AttachmentKey>> {
        let mut keys = Vec::with_capacity(attachments.len());

        for (attachment, crypto) in attachments.iter().zip(encrypted) {
            let reply: UploadReply = self
                .transport()
                .post_multipart_once("/mail/v4/attachments", || {
                    upload_form(draft_id, attachment, crypto)
                })
                .await?;

            keys.push(AttachmentKey {
                id: reply.attachment.id,
                session_key: crypto.session_key.clone(),
                signed: true,
            });
        }

        Ok(keys)
    }
}

/// The multipart form of one attachment upload.
fn upload_form(
    draft_id: &str,
    attachment: &OutgoingAttachment,
    crypto: &EncryptedAttachment,
) -> reqwest::Result<Form> {
    let (disposition, content_id) = match &attachment.disposition {
        AttachmentDisposition::Attachment => ("attachment", ""),
        AttachmentDisposition::Inline { content_id } => ("inline", content_id.as_str()),
    };

    Ok(Form::new()
        .text("MessageID", draft_id.to_owned())
        .text("Filename", attachment.filename.clone())
        .text("MIMEType", attachment.mime_type.clone())
        .text("Disposition", disposition)
        .text("ContentID", content_id.to_owned())
        .part("KeyPackets", blob(&crypto.key_packets)?)
        .part("DataPacket", blob(&crypto.data_packet)?)
        .part("Signature", blob(&crypto.signature)?))
}

/// A file part named `blob` with the generic binary content type.
fn blob(bytes: &[u8]) -> reqwest::Result<Part> {
    Part::bytes(bytes.to_vec())
        .file_name("blob")
        .mime_str("application/octet-stream")
}

/// For a forward, the key packet of each forwarded attachment re-encrypted to
/// the sender, by the parent attachment's id; empty for any other message.
fn forwarded_key_packets(
    keys: &UnlockedKeys,
    sender: &AddressKey,
    msg: &OutgoingMessage,
) -> Result<BTreeMap<String, String>> {
    let Some(parent) = msg
        .parent
        .as_ref()
        .filter(|p| p.action == ParentAction::Forward)
    else {
        return Ok(BTreeMap::new());
    };

    parent
        .forward_attachments
        .iter()
        .map(|a| {
            let session_key = attachment_session_key(keys, &a.key_packets)?;

            Ok((a.id.clone(), rekey_for_sender(sender, &session_key)?))
        })
        .collect()
}

/// The keys of every attachment the draft response `created` lists: the
/// copies the server made of forwarded attachments, and any other it lists.
/// A missing or null list is an empty one. `expected` is how many forwarded
/// attachments the draft must list at least.
///
/// # Errors
///
/// [`Error::InvalidResponse`] when the list is not a list of attachments,
/// has fewer than `expected` entries, or has one without key packets;
/// [`Error::Crypto`] when an attachment's key packets open with no key.
fn draft_attachment_keys(
    keys: &UnlockedKeys,
    created: &Value,
    expected: usize,
) -> Result<Vec<AttachmentKey>> {
    let copies: Vec<DraftAttachment> = match created.pointer("/Message/Attachments") {
        None | Some(Value::Null) => Vec::new(),
        Some(list) => serde_json::from_value(list.clone()).map_err(|_| Error::InvalidResponse)?,
    };

    if copies.len() < expected {
        return Err(Error::InvalidResponse);
    }

    copies
        .into_iter()
        .map(|copy| {
            let key_packets = copy
                .key_packets
                .filter(|k| !k.is_empty())
                .ok_or(Error::InvalidResponse)?;

            Ok(AttachmentKey {
                id: copy.id,
                session_key: attachment_session_key(keys, &key_packets)?,
                signed: copy.signature.is_some_and(|s| !s.is_empty()),
            })
        })
        .collect()
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
