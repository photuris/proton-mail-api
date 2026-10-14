//! Message packaging for send: the armored draft body and the send package.
//!
//! Everything here is a pure function over unlocked keys and public keys; no
//! request is made. The draft body is encrypted to the sender's own key. The
//! send package holds one signed data packet under a fresh session key, a key
//! packet for each Proton recipient, and the session key itself when an
//! external recipient receives the message in the clear.
//!
//! Attachments: [`encrypt_attachment`] makes the upload parts,
//! [`attachment_session_key`] and [`rekey_for_sender`] carry a stored
//! attachment into a forward, and [`add_attachment_keys`] adds the attachment
//! key entries to a package.
//!
//! Only v4 keys with an encryption subkey are supported ([`encryption_subkey`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Cursor;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use pgp::composed::{
    ArmorOptions, DetachedSignature, MessageBuilder, PlainSessionKey, RawSessionKey,
    SignedPublicKey, SignedPublicSubKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{
    LiteralData, Packet, PacketParser, PacketTrait, PublicKey, PublicKeyEncryptedSessionKey,
    SignatureType, SymEncryptedProtectedData,
};
use pgp::ser::Serialize as _;
use pgp::types::{
    DecryptionKey, EskType, KeyDetails, KeyVersion, Password, PkeskVersion, Timestamp,
};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};
use crate::keys::{AddressKey, UnlockedKeys};

/// Package and address type of a Proton recipient (`PACKAGE_TYPE.SEND_PM`).
pub const PACKAGE_INTERNAL: u32 = 1;

/// Package and address type of a recipient reached in the clear
/// (`PACKAGE_TYPE.SEND_CLEAR`).
pub const PACKAGE_CLEAR: u32 = 4;

/// Length in bytes of the AES-256 session key.
const SESSION_KEY_LEN: usize = 32;

/// How the message body is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyType {
    /// `text/plain`.
    Plain,
    /// `text/html`.
    Html,
}

impl BodyType {
    /// The MIME type Proton expects for this body type.
    pub fn mime_type(self) -> &'static str {
        match self {
            Self::Plain => "text/plain",
            Self::Html => "text/html",
        }
    }
}

/// How a recipient receives the message.
#[derive(Debug, Clone)]
#[expect(
    clippy::large_enum_variant,
    reason = "the API takes the key by value; one value per recipient, never in bulk"
)]
pub enum RecipientKind {
    /// A Proton recipient; the message is encrypted to this key.
    Internal(SignedPublicKey),
    /// Any other recipient; Proton delivers the message in the clear.
    External,
}

/// One recipient of a message and how to reach them.
#[derive(Debug, Clone)]
pub struct RecipientKey {
    /// The recipient's email address.
    pub email: String,
    /// How the recipient receives the message.
    pub kind: RecipientKind,
}

/// One recipient's entry in a [`Package`].
#[derive(Debug, Clone, Serialize)]
pub struct PackageAddress {
    /// [`PACKAGE_INTERNAL`] or [`PACKAGE_CLEAR`].
    #[serde(rename = "Type")]
    pub r#type: u32,
    /// `1` when the body is signed for this recipient inside the data
    /// packet, `0` otherwise.
    #[serde(rename = "Signature")]
    pub signature: u32,
    /// Base64 key packet holding the session key for a Proton recipient.
    #[serde(rename = "BodyKeyPacket", skip_serializing_if = "Option::is_none")]
    pub body_key_packet: Option<String>,
    /// Base64 key packet of each attachment's session key for a Proton
    /// recipient, by attachment id; empty (and omitted) without attachments
    /// and for external recipients.
    #[serde(
        rename = "AttachmentKeyPackets",
        skip_serializing_if = "BTreeMap::is_empty",
        default
    )]
    pub attachment_key_packets: BTreeMap<String, String>,
}

/// The session key of a package, handed to Proton for external recipients.
#[derive(Clone, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct BodyKey {
    /// Base64 session key.
    #[serde(rename = "Key")]
    pub key: String,
    /// Symmetric algorithm of the session key; always `aes256`.
    #[serde(rename = "Algorithm")]
    pub algorithm: String,
}

impl fmt::Debug for BodyKey {
    /// Prints the algorithm; the key prints as `"<redacted>"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodyKey")
            .field("key", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

/// The one package a send request carries.
#[derive(Clone, Serialize)]
pub struct Package {
    /// Recipients by email address.
    #[serde(rename = "Addresses")]
    pub addresses: BTreeMap<String, PackageAddress>,
    /// MIME type of the body, from [`BodyType::mime_type`].
    #[serde(rename = "MIMEType")]
    pub mime_type: String,
    /// Bitwise OR of the address types.
    #[serde(rename = "Type")]
    pub r#type: u32,
    /// Base64 of the signed, encrypted data packet.
    #[serde(rename = "Body")]
    pub body: String,
    /// The session key; present only when some recipient is external.
    #[serde(rename = "BodyKey", skip_serializing_if = "Option::is_none")]
    pub body_key: Option<BodyKey>,
    /// The attachments' session keys by attachment id; present only when
    /// some recipient is external and the message has attachments.
    #[serde(
        rename = "AttachmentKeys",
        skip_serializing_if = "BTreeMap::is_empty",
        default
    )]
    pub attachment_keys: BTreeMap<String, BodyKey>,
}

impl fmt::Debug for Package {
    /// Prints the addresses, MIME type and type; the body prints as
    /// `"<encrypted>"` and the session keys as redacted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Package")
            .field("addresses", &self.addresses)
            .field("mime_type", &self.mime_type)
            .field("type", &self.r#type)
            .field("body", &"<encrypted>")
            .field("body_key", &self.body_key)
            .field("attachment_keys", &self.attachment_keys)
            .finish()
    }
}

/// The key a message to `public` is encrypted to, or `None` when it has no
/// valid one.
///
/// The primary key must be v4 and not revoked. A subkey is a candidate when
/// it is not revoked, its bindings verify against the primary key, its newest
/// binding allows encryption and has not expired, and its algorithm can
/// encrypt. The candidate created last wins, the first on a tie. The primary
/// key itself is never chosen. Expiry is judged at the current time; see
/// [`encryption_subkey_at`].
pub fn encryption_subkey(public: &SignedPublicKey) -> Option<&SignedPublicSubKey> {
    encryption_subkey_at(public, Timestamp::now())
}

/// [`encryption_subkey`] with expiry judged at `now`: a subkey whose binding
/// expires exactly at `now` is already expired.
pub fn encryption_subkey_at(
    public: &SignedPublicKey,
    now: Timestamp,
) -> Option<&SignedPublicSubKey> {
    if public.primary_key.version() != KeyVersion::V4
        || !public.details.revocation_signatures.is_empty()
    {
        return None;
    }

    let now = u64::from(now.as_secs());
    let mut best: Option<&SignedPublicSubKey> = None;

    for sub in &public.public_subkeys {
        if usable_subkey(sub, &public.primary_key, now)
            && best.is_none_or(|b| sub.key.created_at() > b.key.created_at())
        {
            best = Some(sub);
        }
    }

    best
}

/// Whether `sub` is a candidate of [`encryption_subkey_at`] at `now` (seconds
/// since the epoch).
fn usable_subkey(sub: &SignedPublicSubKey, primary: &PublicKey, now: u64) -> bool {
    if sub
        .signatures
        .iter()
        .any(|s| s.typ() == Some(SignatureType::SubkeyRevocation))
        || sub.verify_bindings(primary).is_err()
    {
        return false;
    }

    let Some(binding) = sub
        .signatures
        .iter()
        .filter(|s| s.typ() == Some(SignatureType::SubkeyBinding))
        .max_by_key(|s| s.created())
    else {
        return false;
    };

    let flags = binding.key_flags();

    if !(flags.encrypt_comms() || flags.encrypt_storage()) {
        return false;
    }

    // A zero duration means the key does not expire.
    let unexpired = binding
        .key_expiration_time()
        .filter(|d| d.as_secs() != 0)
        .is_none_or(|d| u64::from(sub.key.created_at().as_secs()) + u64::from(d.as_secs()) > now);

    unexpired && sub.key.algorithm().can_encrypt()
}

/// Armored message of `body`, encrypted to the sender's own key and signed by
/// it: the `Body` of a draft.
///
/// # Errors
///
/// [`Error::Crypto`] when the sender key has no usable encryption subkey
/// (see [`encryption_subkey`]) or any encryption step fails.
pub fn encrypt_draft_body(sender: &AddressKey, body: &str) -> Result<String> {
    let public = sender.key.to_public_key();
    let sub = encryption_subkey(&public).ok_or(Error::Crypto("sender key cannot encrypt"))?;

    let mut builder = MessageBuilder::from_bytes("", body.as_bytes().to_vec())
        .seipd_v1(OsRng, SymmetricKeyAlgorithm::AES256);

    builder
        .encrypt_to_key(OsRng, sub)
        .map_err(|_| Error::Crypto("draft body encryption failed"))?;
    builder.sign(
        &sender.key.primary_key,
        Password::empty(),
        HashAlgorithm::Sha256,
    );

    builder
        .to_armored_string(OsRng, ArmorOptions::default())
        .map_err(|_| Error::Crypto("draft body encryption failed"))
}

/// The send package for `recipients`: one signed data packet under a fresh
/// session key, a key packet for each Proton recipient, and the session key
/// when a recipient is external.
///
/// A recipient whose email repeats an earlier one (ASCII case-insensitive) is
/// skipped. BCC recipients are passed like any other.
///
/// # Errors
///
/// [`Error::NoRecipients`] when `recipients` is empty;
/// [`Error::RecipientKeyUnusable`] when a Proton recipient's key has no
/// usable encryption subkey; [`Error::Crypto`] when an encryption step fails.
pub fn build_package(
    sender: &AddressKey,
    body: &str,
    body_type: BodyType,
    recipients: &[RecipientKey],
) -> Result<Package> {
    if recipients.is_empty() {
        return Err(Error::NoRecipients);
    }

    let session_key = fresh_session_key();

    let mut builder = MessageBuilder::from_bytes("", body.as_bytes().to_vec())
        .seipd_v1(OsRng, SymmetricKeyAlgorithm::AES256);

    builder
        .set_session_key(session_key.clone())
        .map_err(|_| Error::Crypto("package encryption failed"))?;
    builder.sign(
        &sender.key.primary_key,
        Password::empty(),
        HashAlgorithm::Sha256,
    );

    let data = builder
        .to_vec(OsRng)
        .map_err(|_| Error::Crypto("package encryption failed"))?;

    let mut addresses = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut package_type = 0;
    let mut external = false;

    for recipient in recipients {
        if !seen.insert(recipient.email.to_ascii_lowercase()) {
            continue;
        }

        let address = match &recipient.kind {
            RecipientKind::Internal(public) => {
                let sub = encryption_subkey(public).ok_or(Error::RecipientKeyUnusable)?;

                PackageAddress {
                    r#type: PACKAGE_INTERNAL,
                    signature: 1,
                    body_key_packet: Some(B64.encode(key_packet(&session_key, sub)?)),
                    attachment_key_packets: BTreeMap::new(),
                }
            }
            RecipientKind::External => {
                external = true;

                PackageAddress {
                    r#type: PACKAGE_CLEAR,
                    signature: 0,
                    body_key_packet: None,
                    attachment_key_packets: BTreeMap::new(),
                }
            }
        };

        package_type |= address.r#type;
        addresses.insert(recipient.email.clone(), address);
    }

    Ok(Package {
        addresses,
        mime_type: body_type.mime_type().to_owned(),
        r#type: package_type,
        body: B64.encode(data),
        body_key: external.then(|| BodyKey {
            key: B64.encode(session_key.as_ref()),
            algorithm: "aes256".to_owned(),
        }),
        attachment_keys: BTreeMap::new(),
    })
}

/// A random AES-256 session key.
fn fresh_session_key() -> RawSessionKey {
    let mut bytes = Zeroizing::new(vec![0u8; SESSION_KEY_LEN]);

    OsRng.fill_bytes(&mut bytes);

    RawSessionKey::from(bytes)
}

/// The v3 key packet carrying `session_key` to `sub`, with its header.
fn key_packet(session_key: &RawSessionKey, sub: &SignedPublicSubKey) -> Result<Vec<u8>> {
    const FAILED: Error = Error::Crypto("key packet encryption failed");

    let packet = PublicKeyEncryptedSessionKey::from_session_key_v3(
        OsRng,
        session_key,
        SymmetricKeyAlgorithm::AES256,
        sub,
    )
    .map_err(|_| FAILED)?;
    let mut out = Vec::new();

    packet.to_writer_with_header(&mut out).map_err(|_| FAILED)?;

    Ok(out)
}

/// A file encrypted for upload. No `Debug` derive: the hand-written one
/// prints sizes only.
pub struct EncryptedAttachment {
    /// Version 3 key packet, with header, carrying the session key to the
    /// sender's encryption subkey.
    pub key_packets: Vec<u8>,
    /// One version 1 encrypted data packet, unsigned, whose literal data
    /// carries the file name.
    pub data_packet: Vec<u8>,
    /// Binary detached signature of the file bytes by the sender's primary
    /// key, with its packet header.
    pub signature: Vec<u8>,
    /// The session key of `data_packet`.
    pub session_key: RawSessionKey,
}

impl fmt::Debug for EncryptedAttachment {
    /// Prints the sizes; the session key prints as `"<redacted>"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedAttachment")
            .field(
                "key_packets",
                &format_args!("<{} bytes>", self.key_packets.len()),
            )
            .field(
                "data_packet",
                &format_args!("<{} bytes>", self.data_packet.len()),
            )
            .field(
                "signature",
                &format_args!("<{} bytes>", self.signature.len()),
            )
            .field("session_key", &"<redacted>")
            .finish()
    }
}

/// One draft attachment's key material for the send package.
pub struct AttachmentKey {
    /// Attachment id.
    pub id: String,
    /// The session key of the attachment's data packet.
    pub session_key: RawSessionKey,
    /// Whether the attachment has a signature.
    pub signed: bool,
}

impl fmt::Debug for AttachmentKey {
    /// Prints the id and `signed`; the session key prints as `"<redacted>"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachmentKey")
            .field("id", &self.id)
            .field("signed", &self.signed)
            .field("session_key", &"<redacted>")
            .finish()
    }
}

/// Encrypts `data` for upload as an attachment named `filename`: a fresh
/// session key, the data packet under it, a key packet to the sender's
/// encryption subkey, and a detached signature of `data` by the sender.
///
/// # Errors
///
/// [`Error::Crypto`] when the sender key has no usable encryption subkey
/// (see [`encryption_subkey`]) or any encryption or signing step fails.
pub fn encrypt_attachment(
    sender: &AddressKey,
    filename: &str,
    data: &[u8],
) -> Result<EncryptedAttachment> {
    const FAILED: Error = Error::Crypto("attachment encryption failed");

    let public = sender.key.to_public_key();
    let sub = encryption_subkey(&public).ok_or(Error::Crypto("sender key cannot encrypt"))?;
    let session_key = fresh_session_key();

    // `MessageBuilder` in rpgp 0.21 drops the file name, so the literal packet
    // is built by hand to carry it.
    let literal =
        LiteralData::from_bytes(filename.to_owned(), data.to_vec().into()).map_err(|_| FAILED)?;
    let mut plaintext = Zeroizing::new(Vec::new());

    literal
        .to_writer_with_header(&mut *plaintext)
        .map_err(|_| FAILED)?;

    let mut data_packet = Vec::new();

    SymEncryptedProtectedData::encrypt_seipdv1(
        OsRng,
        SymmetricKeyAlgorithm::AES256,
        session_key.as_ref(),
        &plaintext,
    )
    .and_then(|packet| packet.to_writer_with_header(&mut data_packet))
    .map_err(|_| FAILED)?;

    let signature = DetachedSignature::sign_binary_data(
        OsRng,
        &sender.key.primary_key,
        &Password::empty(),
        HashAlgorithm::Sha256,
        data,
    )
    .and_then(|s| s.to_bytes())
    .map_err(|_| FAILED)?;

    Ok(EncryptedAttachment {
        key_packets: key_packet(&session_key, sub)?,
        data_packet,
        signature,
        session_key,
    })
}

/// The session key held in `key_packets_b64`, the standard base64 of one or
/// more key packets, opened with any of the secret subkeys in
/// `keys.decryption_keys()`.
///
/// Packets that are not version 3 key packets are skipped. Only AES-256
/// session keys are accepted.
///
/// # Errors
///
/// [`Error::Crypto`] when the base64 or the packets do not parse, no packet
/// opens with any key, or the session key is not AES-256.
pub fn attachment_session_key(keys: &UnlockedKeys, key_packets_b64: &str) -> Result<RawSessionKey> {
    const UNDECRYPTABLE: Error = Error::Crypto("attachment key cannot be decrypted");

    let bytes = B64.decode(key_packets_b64).map_err(|_| UNDECRYPTABLE)?;
    let packets = PacketParser::new(Cursor::new(bytes))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| UNDECRYPTABLE)?;
    let secret_keys = keys.decryption_keys();

    for packet in &packets {
        let Packet::PublicKeyEncryptedSessionKey(pkesk) = packet else {
            continue;
        };

        if pkesk.version() != PkeskVersion::V3 {
            continue;
        }

        let values = pkesk.values().map_err(|_| UNDECRYPTABLE)?;

        for secret in &secret_keys {
            for subkey in &secret.secret_subkeys {
                // A subkey the packet is not for fails to decrypt; try the next.
                if let Ok(Ok(plain)) = subkey
                    .key
                    .decrypt(&Password::empty(), values, EskType::V3_4)
                    && let PlainSessionKey::V3_4 { ref key, sym_alg } = plain
                {
                    return if sym_alg == SymmetricKeyAlgorithm::AES256 {
                        Ok(key.clone())
                    } else {
                        Err(Error::Crypto("unsupported attachment cipher"))
                    };
                }
            }
        }
    }

    Err(UNDECRYPTABLE)
}

/// The base64 key packet carrying `session_key` (as AES-256) to the sender's
/// encryption subkey.
///
/// # Errors
///
/// [`Error::Crypto`] when the sender key has no usable encryption subkey or
/// the encryption fails.
pub fn rekey_for_sender(sender: &AddressKey, session_key: &RawSessionKey) -> Result<String> {
    let public = sender.key.to_public_key();
    let sub = encryption_subkey(&public).ok_or(Error::Crypto("sender key cannot encrypt"))?;

    Ok(B64.encode(key_packet(session_key, sub)?))
}

/// Adds the attachment key entries to `package`, which was built for
/// `recipients`.
///
/// Each Proton address gains a key packet per attachment, and its `Signature`
/// stays 1 only when every attachment is signed. When some recipient is
/// external the package gains the session key of every attachment. Nothing
/// changes without `attachments`.
///
/// # Errors
///
/// [`Error::RecipientKeyUnusable`] when a Proton recipient's key has no usable
/// encryption subkey; [`Error::Crypto`] when an encryption step fails.
pub fn add_attachment_keys(
    package: &mut Package,
    recipients: &[RecipientKey],
    attachments: &[AttachmentKey],
) -> Result<()> {
    if attachments.is_empty() {
        return Ok(());
    }

    let all_signed = attachments.iter().all(|a| a.signed);

    for (email, address) in &mut package.addresses {
        let Some(RecipientKind::Internal(public)) = recipients
            .iter()
            .find(|r| r.email.eq_ignore_ascii_case(email))
            .map(|r| &r.kind)
        else {
            continue;
        };
        let sub = encryption_subkey(public).ok_or(Error::RecipientKeyUnusable)?;

        for attachment in attachments {
            address.attachment_key_packets.insert(
                attachment.id.clone(),
                B64.encode(key_packet(&attachment.session_key, sub)?),
            );
        }

        address.signature = u32::from(all_signed);
    }

    if recipients
        .iter()
        .any(|r| matches!(r.kind, RecipientKind::External))
    {
        for attachment in attachments {
            package.attachment_keys.insert(
                attachment.id.clone(),
                BodyKey {
                    key: B64.encode(attachment.session_key.as_ref()),
                    algorithm: "aes256".to_owned(),
                },
            );
        }
    }

    Ok(())
}
