//! Offline tests for attachment encryption, session-key recovery and the
//! attachment entries of a send package. Keys are generated here with rpgp and
//! every output is opened with rpgp again.

use std::io::Cursor;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use pgp::composed::{
    Deserializable, DetachedSignature, EncryptionCaps, KeyType, Message, PlainSessionKey,
    RawSessionKey, SecretKeyParamsBuilder, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{Packet, PacketParser};
use pgp::types::{KeyVersion, Password, PkeskVersion};
use proton_mail_api::compose::{
    AttachmentKey, BodyType, EncryptedAttachment, Package, RecipientKey, RecipientKind,
    add_attachment_keys, attachment_session_key, build_package, encrypt_attachment,
    rekey_for_sender,
};
use proton_mail_api::error::Error;
use proton_mail_api::keys::{AddressKey, UnlockedKeys};
use rand::thread_rng;
use serde_json::Value;
use zeroize::Zeroizing;

const BODY: &str = "Hello Zoë,\nthe second line.\n";
const FILE: &[u8] = b"%PDF-1.7 not really a pdf \x00\x01\x02\xff";
const OTHER_FILE: &[u8] = b"second attachment, plain text\n";
const FILENAME: &str = "report \u{e9}t\u{e9}.pdf";

/// A v4 key: Ed25519 primary and one Curve25519 encryption subkey.
fn default_key() -> SignedSecretKey {
    let mut subkey = SubkeyParamsBuilder::default();

    subkey
        .version(KeyVersion::V4)
        .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
        .can_sign(false)
        .can_encrypt(EncryptionCaps::All);

    let mut params = SecretKeyParamsBuilder::default();

    params
        .version(KeyVersion::V4)
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .can_encrypt(EncryptionCaps::None)
        .primary_user_id("Test <test@example.com>".into())
        .subkeys(vec![subkey.build().expect("subkey params")]);

    params
        .build()
        .expect("key params")
        .generate(thread_rng())
        .expect("key generates")
}

/// An address key for `secret`.
fn address_key(secret: SignedSecretKey) -> AddressKey {
    AddressKey {
        address_id: "a1".into(),
        email: "sender@example.com".into(),
        key_id: "k1".into(),
        primary: true,
        key: secret,
    }
}

/// Unlocked keys holding exactly `secrets` as address keys.
fn unlocked(secrets: &[&SignedSecretKey]) -> UnlockedKeys {
    UnlockedKeys {
        user_keys: Vec::new(),
        address_keys: secrets.iter().map(|s| address_key((*s).clone())).collect(),
        key_password: Zeroizing::new(String::new()),
    }
}

fn internal(email: &str, secret: &SignedSecretKey) -> RecipientKey {
    RecipientKey {
        email: email.into(),
        kind: RecipientKind::Internal(secret.to_public_key()),
    }
}

fn external(email: &str) -> RecipientKey {
    RecipientKey {
        email: email.into(),
        kind: RecipientKind::External,
    }
}

/// `encrypt_attachment` succeeded.
fn encrypted(sender: &AddressKey, name: &str, data: &[u8]) -> EncryptedAttachment {
    let result = encrypt_attachment(sender, name, data);

    assert!(result.is_ok(), "encrypt_attachment must succeed");

    result.unwrap_or_else(|_| unreachable!())
}

/// The attachment's key as the send package takes it.
fn key_of(id: &str, attachment: &EncryptedAttachment, signed: bool) -> AttachmentKey {
    AttachmentKey {
        id: id.into(),
        session_key: attachment.session_key.clone(),
        signed,
    }
}

/// `build_package` succeeded.
fn built(sender: &AddressKey, recipients: &[RecipientKey]) -> Package {
    let result = build_package(sender, BODY, BodyType::Plain, recipients);

    assert!(result.is_ok(), "build_package must succeed");

    result.unwrap_or_else(|_| unreachable!())
}

fn unb64(text: &str) -> Vec<u8> {
    B64.decode(text).expect("valid base64")
}

fn open(bytes: &[u8]) -> Message<'static> {
    Message::from_bytes(Cursor::new(bytes.to_vec())).expect("message parses")
}

/// The message decrypted with `secret`, `None` when it does not decrypt.
fn decrypt_with(bytes: &[u8], secret: &SignedSecretKey) -> Option<Message<'static>> {
    open(bytes).decrypt(&Password::empty(), secret).ok()
}

/// The message decrypted with `session_key`.
fn decrypt_with_session_key(bytes: &[u8], session_key: &RawSessionKey) -> Option<Message<'static>> {
    open(bytes)
        .decrypt_with_session_key(PlainSessionKey::V3_4 {
            key: session_key.clone(),
            sym_alg: SymmetricKeyAlgorithm::AES256,
        })
        .ok()
}

/// Whether `message` decrypted and holds exactly `expected`.
fn holds(message: Option<Message<'_>>, expected: &[u8]) -> bool {
    message.is_some_and(|mut m| m.as_data_vec().is_ok_and(|plain| plain == expected))
}

fn packets(bytes: &[u8]) -> Vec<Packet> {
    PacketParser::new(Cursor::new(bytes))
        .collect::<Result<Vec<_>, _>>()
        .expect("packets parse")
}

/// Exactly one packet, a version 1 `SymEncryptedProtectedData`.
fn is_data_packet(bytes: &[u8]) -> bool {
    matches!(packets(bytes).as_slice(), [Packet::SymEncryptedProtectedData(d)] if d.version() == 1)
}

/// Exactly one packet, a version 3 `PublicKeyEncryptedSessionKey`.
fn is_key_packet(bytes: &[u8]) -> bool {
    matches!(
        packets(bytes).as_slice(),
        [Packet::PublicKeyEncryptedSessionKey(k)] if k.version() == PkeskVersion::V3
    )
}

/// Whether any object in `value` has a field called `name`.
fn has_field(value: &Value, name: &str) -> bool {
    match value {
        Value::Object(map) => map.contains_key(name) || map.values().any(|v| has_field(v, name)),
        Value::Array(items) => items.iter().any(|v| has_field(v, name)),
        _ => false,
    }
}

#[test]
fn encrypted_attachment_decrypts_for_sender_and_signature_verifies() {
    let secret = default_key();
    let sender = address_key(secret.clone());
    let attachment = encrypted(&sender, FILENAME, FILE);

    assert!(is_key_packet(&attachment.key_packets), "key packet shape");
    assert!(is_data_packet(&attachment.data_packet), "data packet shape");

    let message = decrypt_with(
        &[
            attachment.key_packets.clone(),
            attachment.data_packet.clone(),
        ]
        .concat(),
        &secret,
    );

    assert!(message.is_some(), "the sender decrypts the attachment");

    let mut message = message.unwrap_or_else(|| unreachable!());
    let name = message
        .literal_data_header()
        .map(|h| h.file_name().to_vec());

    assert!(
        name.as_deref() == Some(FILENAME.as_bytes()),
        "the literal file name is the given name"
    );
    assert!(
        message.as_data_vec().is_ok_and(|plain| plain == FILE),
        "the plaintext is the file"
    );

    let signature = DetachedSignature::from_bytes(Cursor::new(&attachment.signature));

    assert!(signature.is_ok(), "the signature parses");
    assert!(
        signature
            .unwrap_or_else(|_| unreachable!())
            .verify(&secret.to_public_key(), FILE)
            .is_ok(),
        "the signature verifies over the file bytes"
    );
}

#[test]
fn session_key_round_trips_through_key_packets() {
    let secret = default_key();
    let sender = address_key(secret.clone());
    let attachment = encrypted(&sender, FILENAME, FILE);
    let found = attachment_session_key(&unlocked(&[&secret]), &B64.encode(&attachment.key_packets));

    assert!(
        found.as_ref().is_ok_and(|k| *k == attachment.session_key),
        "the recovered session key equals the one used"
    );
    assert!(
        found.is_ok_and(|k| holds(decrypt_with_session_key(&attachment.data_packet, &k), FILE)),
        "the recovered session key decrypts the data packet"
    );
}

#[test]
fn session_key_found_with_a_non_primary_address_key() {
    let wrong = default_key();
    let mine = default_key();
    let mine_sender = address_key(mine.clone());
    let attachment = encrypted(&mine_sender, FILENAME, FILE);
    let keys = unlocked(&[&wrong, &mine]);
    let found = attachment_session_key(&keys, &B64.encode(&attachment.key_packets));

    assert!(
        found.is_ok_and(|k| k == attachment.session_key),
        "the second address key opens it after the first is skipped"
    );

    let unrelated = encrypted(&address_key(default_key()), "x", OTHER_FILE);
    let both = [unrelated.key_packets, attachment.key_packets.clone()].concat();
    let found = attachment_session_key(&unlocked(&[&mine]), &B64.encode(both));

    assert!(
        found.is_ok_and(|k| k == attachment.session_key),
        "the second of two key packets opens with the user's key"
    );
}

#[test]
fn undecryptable_key_packets_are_crypto_error() {
    let mine = default_key();
    let unrelated = encrypted(&address_key(default_key()), "x", FILE);
    let keys = unlocked(&[&mine]);

    assert!(
        matches!(
            attachment_session_key(&keys, &B64.encode(&unrelated.key_packets)),
            Err(Error::Crypto(_))
        ),
        "key packets to an unrelated key are a crypto error"
    );
    assert!(
        matches!(
            attachment_session_key(&keys, "not base64 !!"),
            Err(Error::Crypto(_))
        ),
        "invalid base64 is a crypto error"
    );
}

#[test]
fn rekeyed_session_key_decrypts_for_sender() {
    let secret = default_key();
    let sender = address_key(secret.clone());
    let attachment = encrypted(&sender, FILENAME, FILE);
    let rekeyed = rekey_for_sender(&sender, &attachment.session_key);

    assert!(rekeyed.is_ok(), "rekey_for_sender must succeed");

    let key_packet = unb64(&rekeyed.unwrap_or_default());

    assert!(is_key_packet(&key_packet), "key packet shape");
    assert!(
        holds(
            decrypt_with(&[key_packet, attachment.data_packet].concat(), &secret),
            FILE
        ),
        "the sender decrypts with the re-keyed packet"
    );
}

#[test]
fn internal_recipients_get_attachment_key_packets() {
    let sender = address_key(default_key());
    let first = default_key();
    let second = default_key();
    let recipients = [
        internal("one@example.com", &first),
        internal("two@example.com", &second),
    ];
    let a = encrypted(&sender, "a.bin", FILE);
    let b = encrypted(&sender, "b.txt", OTHER_FILE);

    for (b_signed, expected) in [(true, 1), (false, 0)] {
        let mut package = built(&sender, &recipients);
        let added = add_attachment_keys(
            &mut package,
            &recipients,
            &[key_of("att-a", &a, true), key_of("att-b", &b, b_signed)],
        );

        assert!(added.is_ok(), "add_attachment_keys must succeed");

        for (email, secret) in [("one@example.com", &first), ("two@example.com", &second)] {
            let address = &package.addresses[email];

            assert!(
                address.attachment_key_packets.len() == 2,
                "{email}: one key packet per attachment"
            );

            for (id, attachment, data) in [("att-a", &a, FILE), ("att-b", &b, OTHER_FILE)] {
                let key_packet = unb64(&address.attachment_key_packets[id]);

                assert!(
                    holds(
                        decrypt_with(
                            &[key_packet, attachment.data_packet.clone()].concat(),
                            secret
                        ),
                        data
                    ),
                    "{email}: {id} decrypts for the recipient"
                );
            }

            assert!(
                address.signature == expected,
                "{email}: signature is {expected} when the second is signed: {b_signed}"
            );
        }

        assert!(
            package.attachment_keys.is_empty(),
            "no package attachment keys without an external recipient"
        );
    }
}

#[test]
fn external_recipients_get_package_attachment_keys() {
    let sender = address_key(default_key());
    let recipient = default_key();
    let a = encrypted(&sender, "a.bin", FILE);
    let b = encrypted(&sender, "b.txt", OTHER_FILE);
    let keys = [key_of("att-a", &a, true), key_of("att-b", &b, true)];
    let mixed = [
        internal("r@example.com", &recipient),
        external("e@example.com"),
    ];
    let mut package = built(&sender, &mixed);

    assert!(
        add_attachment_keys(&mut package, &mixed, &keys).is_ok(),
        "add_attachment_keys must succeed"
    );
    assert!(
        package.attachment_keys.len() == 2,
        "both attachments have a package key"
    );

    for (id, attachment, data) in [("att-a", &a, FILE), ("att-b", &b, OTHER_FILE)] {
        let entry = &package.attachment_keys[id];

        assert!(entry.algorithm == "aes256", "{id}: algorithm is aes256");
        assert!(
            holds(
                decrypt_with_session_key(
                    &attachment.data_packet,
                    &RawSessionKey::from(unb64(&entry.key).as_slice())
                ),
                data
            ),
            "{id}: the key decrypts the data packet"
        );
    }

    assert!(
        package.addresses["e@example.com"]
            .attachment_key_packets
            .is_empty(),
        "the external address has no key packets"
    );
    assert!(
        package.addresses["r@example.com"]
            .attachment_key_packets
            .len()
            == 2,
        "the internal address has both key packets"
    );

    let internal_only = [internal("r@example.com", &recipient)];
    let mut package = built(&sender, &internal_only);

    assert!(
        add_attachment_keys(&mut package, &internal_only, &keys).is_ok(),
        "add_attachment_keys must succeed"
    );
    assert!(
        package.attachment_keys.is_empty(),
        "an internal-only package has no attachment keys"
    );
}

#[test]
fn no_attachments_leaves_json_unchanged_and_debug_redacts() {
    let sender = address_key(default_key());
    let recipient = default_key();
    let recipients = [
        internal("r@example.com", &recipient),
        external("e@example.com"),
    ];
    let mut package = built(&sender, &recipients);
    let before = serde_json::to_value(&package).expect("package serialises");

    assert!(
        add_attachment_keys(&mut package, &recipients, &[]).is_ok(),
        "no attachments is fine"
    );

    let after = serde_json::to_value(&package).expect("package serialises");

    assert!(before == after, "the JSON is unchanged");
    assert!(
        !has_field(&after, "AttachmentKeys") && !has_field(&after, "AttachmentKeyPackets"),
        "no attachment field anywhere"
    );

    let attachment = encrypted(&sender, FILENAME, FILE);
    let key = key_of("att-a", &attachment, true);

    assert!(
        add_attachment_keys(&mut package, &recipients, std::slice::from_ref(&key)).is_ok(),
        "add_attachment_keys must succeed"
    );

    let session_key = attachment.session_key.as_ref();
    let secrets = [
        B64.encode(session_key),
        format!("{session_key:?}"),
        format!("{:?}", attachment.data_packet),
    ];

    for (name, shown) in [
        ("package", format!("{package:?}")),
        ("attachment key", format!("{key:?}")),
        ("encrypted attachment", format!("{attachment:?}")),
    ] {
        assert!(shown.contains("<redacted>"), "{name}: marks the redaction");

        for secret in &secrets {
            assert!(!shown.contains(secret), "{name}: holds no secret material");
        }
    }
}
