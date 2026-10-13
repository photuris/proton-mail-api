//! The account's keys: fetching the user, addresses and key salts, and
//! unlocking the user keys (mailbox password) and address keys (their tokens).
//!
//! [`Session::unlock_keys`] returns keys whose password protection has been
//! removed for good, so later decryption uses an empty password.

use std::collections::HashMap;
use std::fmt;
use std::io::Read;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use pgp::composed::{Deserializable, DetachedSignature, Message, SignedSecretKey};
use pgp::types::Password;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::session::Session;
use crate::srp;
use crate::types::ApiBool;

/// Length in bytes of a decoded `KeySalt`.
const KEY_SALT_LEN: usize = 16;

/// One armored private key as the API lists it, still locked.
#[derive(Clone, Deserialize)]
pub struct KeyRecord {
    /// Key id.
    #[serde(rename = "ID")]
    pub id: String,
    /// Armored private key, locked with the key password.
    #[serde(rename = "PrivateKey")]
    pub private_key: Zeroizing<String>,
    /// Whether this is the primary key of its owner.
    #[serde(rename = "Primary", default)]
    pub primary: ApiBool,
    /// Whether the key may be used.
    #[serde(rename = "Active", default)]
    pub active: ApiBool,
    /// Key flags bitmask.
    #[serde(rename = "Flags", default)]
    pub flags: i64,
    /// Armored message holding the address key's passphrase.
    #[serde(rename = "Token", default)]
    pub token: Option<Zeroizing<String>>,
    /// Armored detached signature over the decrypted token.
    #[serde(rename = "Signature", default)]
    pub signature: Option<String>,
}

impl fmt::Debug for KeyRecord {
    /// Prints the plain fields; the key, token and signature print as
    /// `"<redacted>"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyRecord")
            .field("id", &self.id)
            .field("primary", &self.primary.0)
            .field("active", &self.active.0)
            .field("flags", &self.flags)
            .field("private_key", &"<redacted>")
            .field("token", &"<redacted>")
            .field("signature", &"<redacted>")
            .finish()
    }
}

/// The account holder.
#[derive(Debug, Clone, Deserialize)]
pub struct User {
    /// User id.
    #[serde(rename = "ID")]
    pub id: String,
    /// Account name.
    #[serde(rename = "Name")]
    pub name: String,
    /// Account email address; may be empty.
    #[serde(rename = "Email", default)]
    pub email: String,
    /// The user keys.
    #[serde(rename = "Keys", default)]
    pub keys: Vec<KeyRecord>,
}

/// One email address of the account.
#[derive(Debug, Clone, Deserialize)]
pub struct Address {
    /// Address id.
    #[serde(rename = "ID")]
    pub id: String,
    /// The email address.
    #[serde(rename = "Email")]
    pub email: String,
    /// Display name.
    #[serde(rename = "DisplayName", default)]
    pub display_name: String,
    /// Whether the address may send.
    #[serde(rename = "Send", default)]
    pub send: ApiBool,
    /// Whether the address may receive.
    #[serde(rename = "Receive", default)]
    pub receive: ApiBool,
    /// Address status code.
    #[serde(rename = "Status", default)]
    pub status: i64,
    /// Address type code.
    #[serde(rename = "Type", default)]
    pub r#type: i64,
    /// Position among the account's addresses.
    #[serde(rename = "Order", default)]
    pub order: i64,
    /// The address keys.
    #[serde(rename = "Keys", default)]
    pub keys: Vec<KeyRecord>,
}

/// Salt of one user key's password.
#[derive(Debug, Clone, Deserialize)]
pub struct KeySalt {
    /// Id of the key the salt belongs to.
    #[serde(rename = "ID")]
    pub id: String,
    /// Base64 salt; absent or empty for very old keys.
    #[serde(rename = "KeySalt", default)]
    pub key_salt: Option<String>,
}

/// An unlocked address key and the address it belongs to. No `Debug`.
pub struct AddressKey {
    /// Id of the address.
    pub address_id: String,
    /// Email address.
    pub email: String,
    /// Id of the key.
    pub key_id: String,
    /// Whether this is the primary key of the address.
    pub primary: bool,
    /// The key, with its password protection removed.
    pub key: SignedSecretKey,
}

/// Every key that could be unlocked, with password protection removed.
pub struct UnlockedKeys {
    /// Unlocked user keys; the primary user key first.
    pub user_keys: Vec<SignedSecretKey>,
    /// Unlocked address keys, addresses in `Order`.
    pub address_keys: Vec<AddressKey>,
    /// The primary user key's password; also what the session persists.
    pub key_password: Zeroizing<String>,
}

impl UnlockedKeys {
    /// Every key to try when decrypting mail: address keys first, then user
    /// keys.
    pub fn decryption_keys(&self) -> Vec<&SignedSecretKey> {
        self.address_keys
            .iter()
            .map(|a| &a.key)
            .chain(&self.user_keys)
            .collect()
    }
}

impl fmt::Debug for UnlockedKeys {
    /// Prints the key counts; the password prints as `"<redacted>"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedKeys")
            .field("user_keys", &self.user_keys.len())
            .field("address_keys", &self.address_keys.len())
            .field("key_password", &"<redacted>")
            .finish()
    }
}

/// Body of `GET /core/v4/users`.
#[derive(Deserialize)]
struct UserReply {
    #[serde(rename = "User")]
    user: User,
}

/// Body of `GET /core/v4/addresses`.
#[derive(Deserialize)]
struct AddressesReply {
    #[serde(rename = "Addresses", default)]
    addresses: Vec<Address>,
}

/// Body of `GET /core/v4/keys/salts`.
#[derive(Deserialize)]
struct SaltsReply {
    #[serde(rename = "KeySalts", default)]
    key_salts: Vec<KeySalt>,
}

impl Session {
    /// Fetches the account holder and the user keys.
    ///
    /// # Errors
    ///
    /// Whatever the transport reports; [`Error::InvalidResponse`] on an
    /// unexpected body.
    pub async fn user(&self) -> Result<User> {
        let reply: UserReply = self.transport().get_json("/core/v4/users", &[]).await?;

        Ok(reply.user)
    }

    /// Fetches the addresses, sorted by `Order`.
    ///
    /// # Errors
    ///
    /// Whatever the transport reports; [`Error::InvalidResponse`] on an
    /// unexpected body.
    pub async fn addresses(&self) -> Result<Vec<Address>> {
        let reply: AddressesReply = self.transport().get_json("/core/v4/addresses", &[]).await?;
        let mut addresses = reply.addresses;

        addresses.sort_by_key(|a| a.order);

        Ok(addresses)
    }

    /// Fetches the salts of the user keys' passwords.
    ///
    /// # Errors
    ///
    /// Whatever the transport reports; [`Error::InvalidResponse`] on an
    /// unexpected body.
    pub async fn key_salts(&self) -> Result<Vec<KeySalt>> {
        let reply: SaltsReply = self
            .transport()
            .get_json("/core/v4/keys/salts", &[])
            .await?;

        Ok(reply.key_salts)
    }

    /// Unlocks the user keys with `mailbox_password` and the address keys
    /// with their tokens, and remembers the primary key's password so
    /// [`persist`](Session::persist) carries it.
    ///
    /// Keys that cannot be unlocked are skipped, except the primary user key.
    ///
    /// # Errors
    ///
    /// [`Error::NoUsableKey`] when the primary user key is inactive or does
    /// not unlock, or when no address key unlocks; the transport's errors
    /// from the three fetches.
    pub async fn unlock_keys(&self, mailbox_password: &str) -> Result<UnlockedKeys> {
        let user = self.user().await?;
        let salts = self.key_salts().await?;
        let addresses = self.addresses().await?;

        let salts: HashMap<&str, &str> = salts
            .iter()
            .filter_map(|s| Some((s.id.as_str(), present(s.key_salt.as_deref())?)))
            .collect();

        let primary = user
            .keys
            .iter()
            .find(|k| k.primary.0)
            .or(user.keys.first())
            .filter(|k| k.active.0)
            .ok_or(Error::NoUsableKey)?;
        let primary_password = user_key_password(mailbox_password, salts.get(primary.id.as_str()))
            .ok_or(Error::NoUsableKey)?;
        let primary_key =
            unlock_key(&primary.private_key, &primary_password).map_err(|_| Error::NoUsableKey)?;

        let mut user_keys = vec![primary_key];

        for record in user
            .keys
            .iter()
            .filter(|k| k.active.0 && k.id != primary.id)
        {
            if let Some(password) =
                user_key_password(mailbox_password, salts.get(record.id.as_str()))
                && let Ok(key) = unlock_key(&record.private_key, &password)
            {
                user_keys.push(key);
            }
        }

        let mut address_keys = Vec::new();

        for address in &addresses {
            for record in address.keys.iter().filter(|k| k.active.0) {
                let password = match (
                    present(record.token.as_deref().map(String::as_str)),
                    present(record.signature.as_deref()),
                ) {
                    (Some(token), Some(signature)) => {
                        match token_password(token, signature, &user_keys) {
                            Some(password) => password,
                            None => continue,
                        }
                    }
                    _ => primary_password.clone(),
                };

                if let Ok(key) = unlock_key(&record.private_key, &password) {
                    address_keys.push(AddressKey {
                        address_id: address.id.clone(),
                        email: address.email.clone(),
                        key_id: record.id.clone(),
                        primary: record.primary.0,
                        key,
                    });
                }
            }
        }

        if address_keys.is_empty() {
            return Err(Error::NoUsableKey);
        }

        self.set_key_password(primary_password.clone());

        Ok(UnlockedKeys {
            user_keys,
            address_keys,
            key_password: primary_password,
        })
    }
}

/// `Some(s)` only when `s` is present and non-empty.
fn present(s: Option<&str>) -> Option<&str> {
    s.filter(|s| !s.is_empty())
}

/// Password of a user key: derived from its salt, or the mailbox password
/// itself when the key has no salt. `None` when the salt is unusable.
fn user_key_password(mailbox_password: &str, salt: Option<&&str>) -> Option<Zeroizing<String>> {
    match salt {
        None => Some(Zeroizing::new(mailbox_password.to_owned())),
        Some(salt) => {
            let salt = B64.decode(salt).ok().filter(|s| s.len() == KEY_SALT_LEN)?;

            srp::key_password(mailbox_password.as_bytes(), &salt).ok()
        }
    }
}

/// Decrypts `token` with the user keys, checks the detached `signature`
/// over it against the user keys, and returns the token text as the address
/// key's password. `None` on any failure.
fn token_password(
    token: &str,
    signature: &str,
    user_keys: &[SignedSecretKey],
) -> Option<Zeroizing<String>> {
    let (message, _) = Message::from_string(token).ok()?;
    let empty = Password::empty();
    let mut decrypted = message
        .decrypt_with_keys(vec![&empty], user_keys.iter().collect())
        .ok()?;

    if decrypted.is_compressed() {
        decrypted = decrypted.decompress().ok()?;
    }

    // Room for a token, so the buffer is not reallocated and left behind.
    let mut bytes = Zeroizing::new(Vec::with_capacity(256));

    decrypted.read_to_end(&mut bytes).ok()?;

    let (signature, _) = DetachedSignature::from_string(signature).ok()?;

    user_keys
        .iter()
        .any(|k| signature.verify(&k.to_public_key(), &bytes).is_ok())
        .then_some(())?;

    Some(Zeroizing::new(std::str::from_utf8(&bytes).ok()?.to_owned()))
}

/// Parses an armored private key and permanently removes the password from
/// the primary key and every secret subkey.
fn unlock_key(armored: &str, password: &str) -> Result<SignedSecretKey> {
    let (mut key, _) = SignedSecretKey::from_string(armored)
        .map_err(|_| Error::Crypto("private key does not parse"))?;
    let password = Password::from(password);

    key.primary_key
        .remove_password(&password)
        .map_err(|_| Error::Crypto("key does not unlock"))?;

    for subkey in &mut key.secret_subkeys {
        subkey
            .key
            .remove_password(&password)
            .map_err(|_| Error::Crypto("key does not unlock"))?;
    }

    Ok(key)
}
