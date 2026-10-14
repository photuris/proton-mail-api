//! Message packaging for send: the armored draft body and the send package.
//!
//! Everything here is a pure function over unlocked keys and public keys; no
//! request is made. The draft body is encrypted to the sender's own key. The
//! send package holds one signed data packet under a fresh session key, a key
//! packet for each Proton recipient, and the session key itself when an
//! external recipient receives the message in the clear.
//!
//! Only v4 keys with an encryption subkey are supported ([`encryption_subkey`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use pgp::composed::{
    ArmorOptions, MessageBuilder, RawSessionKey, SignedPublicKey, SignedPublicSubKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{PacketTrait, PublicKey, PublicKeyEncryptedSessionKey, SignatureType};
use pgp::types::{KeyDetails, KeyVersion, Password, Timestamp};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};
use crate::keys::AddressKey;

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
}

impl fmt::Debug for Package {
    /// Prints the addresses, MIME type and type; the body prints as
    /// `"<encrypted>"` and the session key as redacted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Package")
            .field("addresses", &self.addresses)
            .field("mime_type", &self.mime_type)
            .field("type", &self.r#type)
            .field("body", &"<encrypted>")
            .field("body_key", &self.body_key)
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
/// key itself is never chosen.
pub fn encryption_subkey(public: &SignedPublicKey) -> Option<&SignedPublicSubKey> {
    if public.primary_key.version() != KeyVersion::V4
        || !public.details.revocation_signatures.is_empty()
    {
        return None;
    }

    let now = u64::from(Timestamp::now().as_secs());
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

/// Whether `sub` is a candidate of [`encryption_subkey`] at `now` (seconds
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

    let mut bytes = Zeroizing::new(vec![0u8; SESSION_KEY_LEN]);

    OsRng.fill_bytes(&mut bytes);

    let session_key = RawSessionKey::from(bytes);

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
                }
            }
            RecipientKind::External => {
                external = true;

                PackageAddress {
                    r#type: PACKAGE_CLEAR,
                    signature: 0,
                    body_key_packet: None,
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
    })
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
