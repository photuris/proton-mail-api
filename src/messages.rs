//! Messages: listing metadata by label, fetching a full message, decrypting
//! its body and downloading attachments.
//!
//! Bodies and attachments are decrypted with the keys from
//! [`Session::unlock_keys`]. Signatures are not verified.

use std::io::Cursor;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use mail_parser::{HeaderName, MessageParser, MessagePart, MimeHeaders, PartType};
use pgp::composed::Message as PgpMessage;
use pgp::types::Password;
use serde::Deserialize;

use crate::error::{Error, Result};
use crate::keys::UnlockedKeys;
use crate::session::Session;
use crate::types::{ApiBool, path_segment};

/// Page size when the caller passes `0`.
const DEFAULT_PAGE_SIZE: u32 = 50;
/// Largest page size the API accepts.
const MAX_PAGE_SIZE: u32 = 150;

/// A name and address, as Proton lists senders and recipients.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Recipient {
    /// Display name; empty when the server sends none.
    #[serde(rename = "Name", default)]
    pub name: String,
    /// Email address.
    #[serde(rename = "Address")]
    pub address: String,
}

/// What the API lists about a message without its body.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct MessageMetadata {
    /// Message id.
    #[serde(rename = "ID")]
    pub id: String,
    /// Id of the address the message belongs to.
    #[serde(rename = "AddressID", default)]
    pub address_id: String,
    /// Id of the conversation, when the server sends one.
    #[serde(rename = "ConversationID", default)]
    pub conversation_id: Option<String>,
    /// Ids of the labels and folders the message is in.
    #[serde(rename = "LabelIDs", default, deserialize_with = "null_is_empty")]
    pub label_ids: Vec<String>,
    /// The `Message-ID` of the original mail, when known.
    #[serde(rename = "ExternalID", default)]
    pub external_id: Option<String>,
    /// Subject line.
    #[serde(rename = "Subject", default)]
    pub subject: String,
    /// Who sent it.
    #[serde(rename = "Sender", default)]
    pub sender: Option<Recipient>,
    /// To recipients.
    #[serde(rename = "ToList", default, deserialize_with = "null_is_empty")]
    pub to_list: Vec<Recipient>,
    /// Cc recipients.
    #[serde(rename = "CCList", default, deserialize_with = "null_is_empty")]
    pub cc_list: Vec<Recipient>,
    /// Bcc recipients.
    #[serde(rename = "BCCList", default, deserialize_with = "null_is_empty")]
    pub bcc_list: Vec<Recipient>,
    /// Reply-To addresses.
    #[serde(rename = "ReplyTos", default, deserialize_with = "null_is_empty")]
    pub reply_tos: Vec<Recipient>,
    /// Bit mask; see [`flags`].
    #[serde(rename = "Flags", default)]
    pub flags: i64,
    /// Unix time in seconds.
    #[serde(rename = "Time", default)]
    pub time: i64,
    /// Size in bytes.
    #[serde(rename = "Size", default)]
    pub size: i64,
    /// Not read yet.
    #[serde(rename = "Unread", default)]
    pub unread: ApiBool,
    /// Has been replied to.
    #[serde(rename = "IsReplied", default)]
    pub is_replied: ApiBool,
    /// Has been replied to, all recipients.
    #[serde(rename = "IsRepliedAll", default)]
    pub is_replied_all: ApiBool,
    /// Has been forwarded.
    #[serde(rename = "IsForwarded", default)]
    pub is_forwarded: ApiBool,
    /// Number of attachments.
    #[serde(rename = "NumAttachments", default)]
    pub num_attachments: i64,
}

/// Bits of [`MessageMetadata::flags`].
pub mod flags {
    /// Received.
    pub const RECEIVED: i64 = 1 << 0;
    /// Sent.
    pub const SENT: i64 = 1 << 1;
    /// Between Proton users.
    pub const INTERNAL: i64 = 1 << 2;
    /// End-to-end encrypted.
    pub const E2E: i64 = 1 << 3;
    /// Automatically generated.
    pub const AUTO: i64 = 1 << 4;
    /// Replied to.
    pub const REPLIED: i64 = 1 << 5;
    /// Replied to, all recipients.
    pub const REPLIED_ALL: i64 = 1 << 6;
    /// Forwarded.
    pub const FORWARDED: i64 = 1 << 7;
}

impl MessageMetadata {
    /// Every bit of `f` is set (go-proton-api `Matches`).
    pub fn has_all_flags(&self, f: i64) -> bool {
        self.flags & f == f
    }

    /// At least one bit of `f` is set (go-proton-api `Has`).
    pub fn has_any_flag(&self, f: i64) -> bool {
        self.flags & f != 0
    }

    /// Neither received nor sent.
    pub fn is_draft(&self) -> bool {
        !self.has_any_flag(flags::RECEIVED | flags::SENT)
    }
}

/// An attachment as listed on a message; its bytes come from
/// [`Session::attachment`].
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Attachment {
    /// Attachment id.
    #[serde(rename = "ID")]
    pub id: String,
    /// File name.
    #[serde(rename = "Name", default)]
    pub name: String,
    /// Size in bytes.
    #[serde(rename = "Size", default)]
    pub size: i64,
    /// MIME type.
    #[serde(rename = "MIMEType", default)]
    pub mime_type: String,
    /// `attachment` or `inline`.
    #[serde(rename = "Disposition", default)]
    pub disposition: String,
    /// Base64 of the packets that hold the session key.
    #[serde(rename = "KeyPackets", default)]
    pub key_packets: String,
    /// Part headers: each value is a string or an array of strings.
    #[serde(rename = "Headers", default)]
    pub headers: Option<serde_json::Value>,
}

impl Attachment {
    /// `Headers["content-id"]` (case-insensitive key): a string, or the first
    /// element of an array of strings; surrounding `<>` stripped; absent or
    /// empty gives `None`.
    pub fn content_id(&self) -> Option<String> {
        let (_, value) = self
            .headers
            .as_ref()?
            .as_object()?
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-id"))?;
        let id = match value {
            serde_json::Value::String(s) => s.as_str(),
            serde_json::Value::Array(a) => a.first()?.as_str()?,
            _ => return None,
        };
        let id = id.trim().trim_start_matches('<').trim_end_matches('>');

        (!id.is_empty()).then(|| id.to_owned())
    }
}

/// A message with its still-encrypted body.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Message {
    /// The listed fields.
    #[serde(flatten)]
    pub meta: MessageMetadata,
    /// Raw header block of the original mail.
    #[serde(rename = "Header", default)]
    pub header: String,
    /// Armored PGP message holding the body.
    #[serde(rename = "Body", default)]
    pub body: String,
    /// MIME type of the decrypted body.
    #[serde(rename = "MIMEType", default)]
    pub mime_type: String,
    /// Attachments, still encrypted.
    #[serde(rename = "Attachments", default, deserialize_with = "null_is_empty")]
    pub attachments: Vec<Attachment>,
}

/// Which page of which label [`Session::list_messages`] asks for.
#[derive(Debug, Clone)]
pub struct MessageQuery {
    /// Only messages with this label or in this folder.
    pub label_id: Option<String>,
    /// Zero-based page number.
    pub page: u32,
    /// Messages per page; `0` means 50, and more than 150 is cut to 150.
    pub page_size: u32,
    /// Newest first.
    pub desc: bool,
}

impl Default for MessageQuery {
    fn default() -> Self {
        Self {
            label_id: None,
            page: 0,
            page_size: DEFAULT_PAGE_SIZE,
            desc: true,
        }
    }
}

/// One page of message metadata.
#[derive(Debug, Clone)]
pub struct MessagePage {
    /// Messages matching the query over all pages.
    pub total: i64,
    /// This page's messages.
    pub messages: Vec<MessageMetadata>,
    /// The server's index may lag behind; the page may be incomplete.
    pub stale: bool,
}

/// A decrypted body. No `Debug`: it is mail content.
pub struct DecryptedBody {
    /// MIME type the message was stored with.
    pub mime_type: String,
    /// The decrypted bytes.
    pub bytes: Vec<u8>,
}

/// A part of a PGP/MIME body that is not its text or HTML.
pub struct MimePart {
    /// File name, when the part has one.
    pub name: Option<String>,
    /// `type/subtype`, lower-case.
    pub mime_type: String,
    /// `Content-ID` without `<>`.
    pub content_id: Option<String>,
    /// The decoded content.
    pub bytes: Vec<u8>,
}

/// The pieces of a parsed `multipart/mixed` body.
struct MimeBody {
    text: Option<String>,
    html: Option<String>,
    attachments: Vec<MimePart>,
}

impl DecryptedBody {
    /// `text/plain` gives `(Some(text), None)` and `text/html` gives
    /// `(None, Some(html))`. `multipart/mixed` is parsed as a MIME message and
    /// gives its text and HTML bodies; when that finds nothing usable, the
    /// bytes come back as the text. Any other type is treated as
    /// `text/plain`. Parameters on the type (`; charset=utf-8`) are ignored.
    pub fn text_and_html(&self) -> (Option<String>, Option<String>) {
        if self.is_mixed() {
            return match parse_mime(&self.bytes) {
                Some(mime) => (mime.text, mime.html),
                None => (Some(self.lossy()), None),
            };
        }

        if self.media_type().eq_ignore_ascii_case("text/html") {
            (None, Some(self.lossy()))
        } else {
            (Some(self.lossy()), None)
        }
    }

    /// For `multipart/mixed`, every part that is not the text or HTML body;
    /// otherwise empty.
    pub fn mime_attachments(&self) -> Vec<MimePart> {
        if !self.is_mixed() {
            return Vec::new();
        }

        parse_mime(&self.bytes).map_or_else(Vec::new, |mime| mime.attachments)
    }

    /// The media type without parameters such as `; charset=utf-8`.
    fn media_type(&self) -> &str {
        self.mime_type.split(';').next().unwrap_or("").trim()
    }

    fn is_mixed(&self) -> bool {
        self.media_type().eq_ignore_ascii_case("multipart/mixed")
    }

    fn lossy(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

/// Splits an RFC 822 message into its text body, HTML body and everything
/// else. The bodies are the first `text/plain` and `text/html` parts that the
/// parser classes as body parts (it leaves out related resources after the
/// first part) and that are neither `attachment` nor named. `None` when the
/// bytes do not parse or carry neither `Content-Type` nor `MIME-Version`,
/// such as plain text that merely looks like a header.
fn parse_mime(bytes: &[u8]) -> Option<MimeBody> {
    let message = MessageParser::default().parse(bytes)?;
    let is_body = |p: &MessagePart<'_>| {
        !p.content_disposition().is_some_and(|d| d.is_attachment()) && p.attachment_name().is_none()
    };
    let text = message
        .text_bodies()
        .find(|p| is_body(p) && matches!(p.body, PartType::Text(_)) && is_plain(p));
    let html = message
        .html_bodies()
        .find(|p| is_body(p) && matches!(p.body, PartType::Html(_)));
    let is_chosen = |p: &MessagePart<'_>| {
        [text, html]
            .into_iter()
            .flatten()
            .any(|chosen| std::ptr::eq(chosen, p))
    };
    // No Content-Type and no MIME-Version: not MIME at all (plain text that
    // merely looks like a header), so the caller falls back to the raw text.
    if message.root_part().content_type().is_none()
        && message.header(HeaderName::MimeVersion).is_none()
    {
        return None;
    }

    let attachments: Vec<MimePart> = message
        .parts
        .iter()
        .filter(|p| !p.is_multipart() && !is_chosen(p))
        .map(|part| MimePart {
            name: part.attachment_name().map(str::to_owned),
            mime_type: part_mime_type(part),
            content_id: part
                .content_id()
                .map(|id| id.trim_matches(['<', '>']).to_owned())
                .filter(|id| !id.is_empty()),
            bytes: part.contents().to_vec(),
        })
        .collect();
    let body =
        |p: Option<&MessagePart<'_>>| p.and_then(MessagePart::text_contents).map(str::to_owned);

    Some(MimeBody {
        text: body(text),
        html: body(html),
        attachments,
    })
}

/// A part with no `Content-Type` is `text/plain` (RFC 2045).
fn is_plain(part: &MessagePart<'_>) -> bool {
    part.content_type()
        .is_none_or(|ct| ct.ctype().eq_ignore_ascii_case("text") && is_plain_subtype(ct.subtype()))
}

fn is_plain_subtype(subtype: Option<&str>) -> bool {
    subtype.is_none_or(|s| s.eq_ignore_ascii_case("plain"))
}

/// `type/subtype` of a part, lower-case; `message/rfc822` for a nested
/// message and `application/octet-stream` when the part says nothing.
fn part_mime_type(part: &MessagePart<'_>) -> String {
    match part.content_type() {
        Some(ct) => format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("octet-stream"))
            .to_ascii_lowercase(),
        None if part.is_message() => "message/rfc822".to_owned(),
        None => "application/octet-stream".to_owned(),
    }
}

impl Message {
    /// Decrypts the body with the first of `keys` that fits.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] with a fixed text when the body does not parse or no
    /// key decrypts it. The text never holds the body, a key or a library
    /// error.
    pub fn decrypt_body(&self, keys: &UnlockedKeys) -> Result<DecryptedBody> {
        let (message, _) = PgpMessage::from_string(&self.body)
            .map_err(|_| Error::Crypto("message does not parse"))?;

        Ok(DecryptedBody {
            mime_type: self.mime_type.clone(),
            bytes: decrypt(message, keys)?,
        })
    }
}

/// Decrypts `message` with `keys` (empty password; they are permanently
/// unlocked), decompressing if needed.
fn decrypt(message: PgpMessage<'_>, keys: &UnlockedKeys) -> Result<Vec<u8>> {
    const FAILED: Error = Error::Crypto("message decryption failed");

    let empty = Password::empty();
    let mut decrypted = message
        .decrypt_with_keys(vec![&empty], keys.decryption_keys())
        .map_err(|_| FAILED)?;

    if decrypted.is_compressed() {
        decrypted = decrypted.decompress().map_err(|_| FAILED)?;
    }

    decrypted.as_data_vec().map_err(|_| FAILED)
}

/// Reads `null` as an empty list.
fn null_is_empty<'de, D: serde::Deserializer<'de>, T: serde::Deserialize<'de>>(
    d: D,
) -> std::result::Result<Vec<T>, D::Error> {
    Option::<Vec<T>>::deserialize(d).map(Option::unwrap_or_default)
}

/// Body of `GET /mail/v4/messages`.
#[derive(Deserialize)]
struct ListReply {
    #[serde(rename = "Total", default)]
    total: i64,
    #[serde(rename = "Messages", default, deserialize_with = "null_is_empty")]
    messages: Vec<MessageMetadata>,
    #[serde(rename = "Stale", default)]
    stale: ApiBool,
}

/// Body of `GET /mail/v4/messages/<id>`.
#[derive(Deserialize)]
struct MessageReply {
    #[serde(rename = "Message")]
    message: Message,
}

impl Session {
    /// Lists one page of message metadata, newest first unless
    /// `q.desc` is false.
    ///
    /// # Errors
    ///
    /// Whatever the transport reports; [`Error::InvalidResponse`] on an
    /// unexpected body.
    pub async fn list_messages(&self, q: &MessageQuery) -> Result<MessagePage> {
        let page_size = match q.page_size {
            0 => DEFAULT_PAGE_SIZE,
            n => n.min(MAX_PAGE_SIZE),
        };
        let mut query = vec![
            ("Page", q.page.to_string()),
            ("PageSize", page_size.to_string()),
            ("Sort", "Time".to_owned()),
            ("Desc", u8::from(q.desc).to_string()),
        ];

        if let Some(label_id) = &q.label_id {
            query.push(("LabelID", label_id.clone()));
        }

        let reply: ListReply = self
            .transport()
            .get_json("/mail/v4/messages", &query)
            .await?;

        Ok(MessagePage {
            total: reply.total,
            messages: reply.messages,
            stale: reply.stale.0,
        })
    }

    /// Fetches one message with its encrypted body and attachment list.
    ///
    /// # Errors
    ///
    /// Whatever the transport reports; [`Error::InvalidResponse`] on an
    /// unexpected body.
    pub async fn message(&self, id: &str) -> Result<Message> {
        let reply: MessageReply = self
            .transport()
            .get_json(&format!("/mail/v4/messages/{}", path_segment(id)), &[])
            .await?;

        Ok(reply.message)
    }

    /// Downloads an attachment and decrypts it with `keys`.
    ///
    /// # Errors
    ///
    /// Whatever the transport reports; [`Error::Crypto`] with a fixed text
    /// when the key packets do not decode or no key decrypts the data.
    pub async fn attachment(&self, att: &Attachment, keys: &UnlockedKeys) -> Result<Vec<u8>> {
        let data = self
            .transport()
            .get_bytes(&format!("/mail/v4/attachments/{}", path_segment(&att.id)))
            .await?;
        let mut packets = B64
            .decode(&att.key_packets)
            .map_err(|_| Error::Crypto("attachment key packets do not decode"))?;

        packets.extend_from_slice(&data);

        let message = PgpMessage::from_bytes(Cursor::new(packets))
            .map_err(|_| Error::Crypto("attachment does not parse"))?;

        decrypt(message, keys)
    }
}
