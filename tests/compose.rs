//! Offline tests for draft body encryption and send package building. Keys
//! are generated here with rpgp and every output is opened with rpgp again.

use std::io::Cursor;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use pgp::composed::{
    EncryptionCaps, KeyType, Message, PlainSessionKey, SecretKeyParamsBuilder, SignedPublicKey,
    SignedPublicSubKey, SignedSecretKey, SubkeyParams, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{
    KeyFlags, Packet, PacketParser, Signature, SignatureConfig, SignatureType, Subpacket,
    SubpacketData,
};
use pgp::types::{
    Duration, Fingerprint, KeyDetails, KeyVersion, Password, PkeskVersion, Timestamp,
};
use proton_mail_api::compose::{
    BodyType, Package, RecipientKey, RecipientKind, build_package, encrypt_draft_body,
    encryption_subkey, encryption_subkey_at,
};
use proton_mail_api::error::Error;
use proton_mail_api::keys::AddressKey;
use rand::thread_rng;
use serde_json::Value;

const BODY: &str = "Hello Zoë,\nthe second line.\n";

/// A secret key with an Ed25519 primary and the given subkeys, no password.
fn generate(version: KeyVersion, primary: KeyType, subkeys: Vec<SubkeyParams>) -> SignedSecretKey {
    let mut params = SecretKeyParamsBuilder::default();

    params
        .version(version)
        .key_type(primary)
        .can_certify(true)
        .can_sign(true)
        .can_encrypt(EncryptionCaps::None)
        .primary_user_id("Test <test@example.com>".into())
        .subkeys(subkeys);

    params
        .build()
        .expect("key params")
        .generate(thread_rng())
        .expect("key generates")
}

/// Parameters of a subkey created at `created_at`.
fn subkey(
    version: KeyVersion,
    key_type: KeyType,
    caps: EncryptionCaps,
    sign: bool,
    created_at: Timestamp,
) -> SubkeyParams {
    let mut params = SubkeyParamsBuilder::default();

    params
        .version(version)
        .key_type(key_type)
        .can_sign(sign)
        .can_encrypt(caps)
        .created_at(created_at);

    params.build().expect("subkey params")
}

/// A Curve25519 encryption subkey of a v4 key, created at `created_at`.
fn ecdh(created_at: Timestamp) -> SubkeyParams {
    subkey(
        KeyVersion::V4,
        KeyType::ECDH(ECCCurve::Curve25519Legacy),
        EncryptionCaps::All,
        false,
        created_at,
    )
}

/// A v4 key: Ed25519 primary and one Curve25519 encryption subkey.
fn default_key() -> SignedSecretKey {
    generate(
        KeyVersion::V4,
        KeyType::Ed25519Legacy,
        vec![ecdh(Timestamp::now())],
    )
}

/// A v6 key: Ed25519 primary and an X25519 encryption subkey.
fn v6_key() -> SignedSecretKey {
    generate(
        KeyVersion::V6,
        KeyType::Ed25519,
        vec![subkey(
            KeyVersion::V6,
            KeyType::X25519,
            EncryptionCaps::All,
            false,
            Timestamp::now(),
        )],
    )
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

/// `build_package` succeeded.
fn built(result: Result<Package, Error>) -> Package {
    assert!(result.is_ok(), "build_package must succeed");

    result.unwrap_or_else(|_| unreachable!())
}

fn unb64(text: &str) -> Vec<u8> {
    B64.decode(text).expect("valid base64")
}

/// `seconds` before now.
fn ago(seconds: u32) -> Timestamp {
    Timestamp::from_secs(Timestamp::now().as_secs() - seconds)
}

fn open(bytes: &[u8]) -> Message<'static> {
    Message::from_bytes(Cursor::new(bytes.to_vec())).expect("message parses")
}

/// The message decrypted with `secret`, `None` when it does not decrypt.
fn decrypt_with(bytes: &[u8], secret: &SignedSecretKey) -> Option<Message<'static>> {
    open(bytes).decrypt(&Password::empty(), secret).ok()
}

/// The message decrypted with the base64 AES-256 session key `key`.
fn decrypt_with_session_key(bytes: &[u8], key: &str) -> Option<Message<'static>> {
    open(bytes)
        .decrypt_with_session_key(PlainSessionKey::V3_4 {
            key: unb64(key).into(),
            sym_alg: SymmetricKeyAlgorithm::AES256,
        })
        .ok()
}

/// The plaintext of `message` and whether `signer`'s signature on it verifies.
fn read_and_verify(mut message: Message<'_>, signer: &SignedPublicKey) -> (Vec<u8>, bool) {
    let plain = message.as_data_vec().expect("message reads");
    let verified = message.verify(signer).is_ok();

    (plain, verified)
}

/// Whether `message` decrypted and holds `BODY` signed by `signer`.
fn is_body_signed_by(message: Option<Message<'_>>, signer: &SignedPublicKey) -> bool {
    message.is_some_and(|m| read_and_verify(m, signer) == (BODY.as_bytes().to_vec(), true))
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

#[test]
fn draft_body_decrypts_for_sender_and_verifies() {
    let sender = address_key(default_key());
    let armored = encrypt_draft_body(&sender, BODY);

    assert!(armored.is_ok(), "encrypt_draft_body must succeed");

    let armored = armored.unwrap_or_else(|_| unreachable!());

    assert!(
        armored.starts_with("-----BEGIN PGP MESSAGE-----"),
        "body is an armored message"
    );

    let (message, _) = Message::from_string(&armored).expect("armored body parses");
    let message = message.decrypt(&Password::empty(), &sender.key).ok();

    assert!(
        is_body_signed_by(message, &sender.key.to_public_key()),
        "sender decrypts the body and the signature verifies"
    );
}

#[test]
fn internal_package_decrypts_for_recipient_and_verifies() {
    let sender = address_key(default_key());
    let recipient = default_key();

    for body_type in [BodyType::Plain, BodyType::Html] {
        let package = built(build_package(
            &sender,
            BODY,
            body_type,
            &[internal("r@example.com", &recipient)],
        ));
        let address = &package.addresses["r@example.com"];
        let key_packet = unb64(address.body_key_packet.as_deref().unwrap_or_default());
        let body = unb64(&package.body);

        assert!(
            is_key_packet(&key_packet),
            "{body_type:?}: key packet shape"
        );
        assert!(is_data_packet(&body), "{body_type:?}: data packet shape");
        assert!(
            is_body_signed_by(
                decrypt_with(&[key_packet, body].concat(), &recipient),
                &sender.key.to_public_key()
            ),
            "{body_type:?}: recipient decrypts and the signature verifies"
        );
        assert!(
            address.r#type == 1 && address.signature == 1,
            "{body_type:?}: address type 1, signature 1"
        );
        assert!(package.r#type == 1, "{body_type:?}: package type 1");
        assert!(package.body_key.is_none(), "{body_type:?}: no body key");
        assert!(
            package.mime_type == body_type.mime_type(),
            "{body_type:?}: mime type matches"
        );
    }
}

#[test]
fn external_package_carries_session_key_and_decrypts() {
    let sender = address_key(default_key());
    let recipients = [external("e@example.com")];
    let package = built(build_package(&sender, BODY, BodyType::Plain, &recipients));
    let other = built(build_package(&sender, BODY, BodyType::Plain, &recipients));
    let body = unb64(&package.body);
    let body_key = package.body_key.as_ref();
    let address = &package.addresses["e@example.com"];

    assert!(
        body_key.is_some(),
        "an external recipient gets the body key"
    );

    let body_key = body_key.expect("checked above");

    assert!(is_data_packet(&body), "data packet shape");
    assert!(
        is_body_signed_by(
            decrypt_with_session_key(&body, &body_key.key),
            &sender.key.to_public_key()
        ),
        "session key decrypts the body"
    );
    assert!(body_key.algorithm == "aes256", "algorithm is aes256");
    assert!(
        address.r#type == 4 && address.signature == 0 && address.body_key_packet.is_none(),
        "address type 4, signature 0, no key packet"
    );
    assert!(package.r#type == 4, "package type 4");
    assert!(
        other
            .body_key
            .as_ref()
            .is_some_and(|k| k.key != body_key.key),
        "each package has a fresh session key"
    );
}

#[test]
fn mixed_package_ors_types_and_both_paths_decrypt() {
    let sender = address_key(default_key());
    let recipient = default_key();
    let package = built(build_package(
        &sender,
        BODY,
        BodyType::Html,
        &[
            internal("r@example.com", &recipient),
            external("e@example.com"),
        ],
    ));
    let signer = sender.key.to_public_key();
    let body = unb64(&package.body);
    let key_packet = unb64(
        package.addresses["r@example.com"]
            .body_key_packet
            .as_deref()
            .unwrap_or_default(),
    );

    assert!(package.r#type == 5, "package type is 1 | 4");
    assert!(
        is_body_signed_by(
            decrypt_with(&[key_packet, body.clone()].concat(), &recipient),
            &signer
        ),
        "internal path decrypts"
    );
    assert!(
        package
            .body_key
            .as_ref()
            .is_some_and(|k| is_body_signed_by(decrypt_with_session_key(&body, &k.key), &signer)),
        "external path decrypts"
    );
}

#[test]
fn duplicate_recipients_collapse_case_insensitively() {
    let sender = address_key(default_key());
    let package = built(build_package(
        &sender,
        BODY,
        BodyType::Plain,
        &[external("A@x.org"), external("a@X.org")],
    ));

    assert!(
        package.addresses.keys().collect::<Vec<_>>() == ["A@x.org"],
        "one entry, keyed by the first spelling"
    );
}

#[test]
fn recipient_without_encryption_key_is_unusable() {
    let sender = address_key(default_key());
    let no_subkey = generate(KeyVersion::V4, KeyType::Ed25519Legacy, vec![]);
    let v6 = v6_key();

    for (name, key) in [("no subkey", &no_subkey), ("v6", &v6)] {
        let result = build_package(
            &sender,
            BODY,
            BodyType::Plain,
            &[internal("r@example.com", key)],
        );

        assert!(
            matches!(result, Err(Error::RecipientKeyUnusable)),
            "{name}: recipient key is unusable"
        );
    }

    let result = encrypt_draft_body(&address_key(v6), BODY);

    assert!(
        matches!(result, Err(Error::Crypto("sender key cannot encrypt"))),
        "v6 sender key cannot encrypt"
    );
}

#[test]
fn rsa_recipient_decrypts() {
    let sender = address_key(default_key());
    let recipient = generate(
        KeyVersion::V4,
        KeyType::Rsa(2048),
        vec![subkey(
            KeyVersion::V4,
            KeyType::Rsa(2048),
            EncryptionCaps::All,
            false,
            Timestamp::now(),
        )],
    );
    let package = built(build_package(
        &sender,
        BODY,
        BodyType::Plain,
        &[internal("r@example.com", &recipient)],
    ));
    let key_packet = unb64(
        package.addresses["r@example.com"]
            .body_key_packet
            .as_deref()
            .unwrap_or_default(),
    );

    assert!(
        is_body_signed_by(
            decrypt_with(&[key_packet, unb64(&package.body)].concat(), &recipient),
            &sender.key.to_public_key()
        ),
        "RSA recipient decrypts"
    );
}

/// Key flags allowing the given kinds of encryption.
fn flags_with(comms: bool, storage: bool) -> KeyFlags {
    let mut flags = KeyFlags::default();

    flags.set_encrypt_comms(comms);
    flags.set_encrypt_storage(storage);

    flags
}

/// Key flags allowing both kinds of encryption.
fn encrypt_flags() -> KeyFlags {
    flags_with(true, true)
}

/// A signature of type `typ` by `signer`'s primary key over `sub`, created at
/// `created`, with the given key flags and key expiration (seconds).
fn sign_subkey(
    signer: &SignedSecretKey,
    typ: SignatureType,
    flags: KeyFlags,
    expires: Option<u32>,
    created: Timestamp,
    sub: &SignedPublicSubKey,
) -> Signature {
    let primary = &signer.primary_key;
    let mut config = SignatureConfig::v4(typ, primary.algorithm(), HashAlgorithm::Sha256);
    let mut hashed = vec![
        SubpacketData::SignatureCreationTime(created),
        SubpacketData::KeyFlags(flags),
        SubpacketData::IssuerFingerprint(primary.fingerprint()),
    ];

    if let Some(seconds) = expires {
        hashed.push(SubpacketData::KeyExpirationTime(Duration::from_secs(
            seconds,
        )));
    }

    config.hashed_subpackets = hashed
        .into_iter()
        .map(|data| Subpacket::regular(data).expect("subpacket"))
        .collect();

    config
        .sign_subkey_binding(
            primary,
            &signer.to_public_key().primary_key,
            &Password::empty(),
            &sub.key,
        )
        .expect("subkey signature signs")
}

/// A binding of `sub` by `signer` that allows encryption.
fn binding(
    signer: &SignedSecretKey,
    expires: Option<u32>,
    created: Timestamp,
    sub: &SignedPublicSubKey,
) -> Signature {
    sign_subkey(
        signer,
        SignatureType::SubkeyBinding,
        encrypt_flags(),
        expires,
        created,
        sub,
    )
}

/// A revocation of `sub` by `signer`.
fn revocation(signer: &SignedSecretKey, sub: &SignedPublicSubKey) -> Signature {
    sign_subkey(
        signer,
        SignatureType::SubkeyRevocation,
        KeyFlags::default(),
        None,
        Timestamp::now(),
        sub,
    )
}

/// `sub` with `signatures` in place of its own.
fn resigned(sub: &SignedPublicSubKey, signatures: Vec<Signature>) -> SignedPublicSubKey {
    SignedPublicSubKey::new(sub.key.clone(), signatures)
}

/// Fingerprint of the subkey selected for `public` at `now`.
fn chosen(public: &SignedPublicKey, now: Timestamp) -> Option<Fingerprint> {
    encryption_subkey_at(public, now).map(|s| s.fingerprint())
}

#[test]
fn newest_valid_subkey_is_chosen() {
    // Subkey 0 is older (created two hours ago), subkey 1 newer (one hour ago).
    let secret = generate(
        KeyVersion::V4,
        KeyType::Ed25519Legacy,
        vec![ecdh(ago(7200)), ecdh(ago(3600))],
    );
    let public = secret.to_public_key();
    let older = public.public_subkeys[0].clone();
    let newer = public.public_subkeys[1].clone();
    let (older_fp, newer_fp) = (older.fingerprint(), newer.fingerprint());
    let stranger = default_key();
    let now = Timestamp::now();

    // A copy of the key with the given replacements for subkey 0 and 1.
    let with = |first: Option<SignedPublicSubKey>, second: SignedPublicSubKey| {
        let mut copy = public.clone();

        copy.public_subkeys = vec![first.unwrap_or_else(|| older.clone()), second];

        copy
    };
    let with_newer = |second: SignedPublicSubKey| with(None, second);

    // The newer subkey with its own binding plus `extra`.
    let plus = |extra: Vec<Signature>| {
        let mut signatures = newer.signatures.clone();

        signatures.extend(extra);

        SignedPublicSubKey {
            key: newer.key.clone(),
            signatures,
        }
    };

    // A newer RSA subkey whose binding allows only signing.
    let rsa_signing = generate(
        KeyVersion::V4,
        KeyType::Ed25519Legacy,
        vec![
            ecdh(ago(7200)),
            subkey(
                KeyVersion::V4,
                KeyType::Rsa(2048),
                EncryptionCaps::None,
                true,
                ago(3600),
            ),
        ],
    )
    .to_public_key();
    let rsa_older_fp = rsa_signing.public_subkeys[0].fingerprint();

    let mut primary_revoked = public.clone();

    primary_revoked.details.revocation_signatures.push(
        SignatureConfig::v4(
            SignatureType::KeyRevocation,
            secret.primary_key.algorithm(),
            HashAlgorithm::Sha256,
        )
        .sign_key(&secret.primary_key, &Password::empty(), &public.primary_key)
        .expect("primary revocation signs"),
    );

    // Two valid subkeys created in the same second: the first wins.
    let tie_time = ago(3600);
    let tie = generate(
        KeyVersion::V4,
        KeyType::Ed25519Legacy,
        vec![ecdh(tie_time), ecdh(tie_time)],
    )
    .to_public_key();
    let tie_first_fp = tie.public_subkeys[0].fingerprint();

    // A newer signing-only Ed25519 subkey whose binding, valid and signed by
    // the primary, claims encryption: only its algorithm rules it out.
    let odd = generate(
        KeyVersion::V4,
        KeyType::Ed25519Legacy,
        vec![
            ecdh(ago(7200)),
            subkey(
                KeyVersion::V4,
                KeyType::Ed25519Legacy,
                EncryptionCaps::None,
                true,
                ago(3600),
            ),
        ],
    );
    let mut cannot_encrypt = odd.to_public_key();
    let odd_sub = cannot_encrypt.public_subkeys[1].clone();
    let odd_older_fp = cannot_encrypt.public_subkeys[0].fingerprint();

    cannot_encrypt.public_subkeys[1] = resigned(&odd_sub, vec![binding(&odd, None, now, &odd_sub)]);

    // A binding of the newer subkey with the given flags, no expiry.
    let flagged = |comms, storage| {
        with_newer(resigned(
            &newer,
            vec![sign_subkey(
                &secret,
                SignatureType::SubkeyBinding,
                flags_with(comms, storage),
                None,
                now,
                &newer,
            )],
        ))
    };

    // A binding of the newer subkey that expires `lifetime` seconds after
    // the subkey was created.
    let expiring = |lifetime| {
        with_newer(resigned(
            &newer,
            vec![binding(&secret, Some(lifetime), now, &newer)],
        ))
    };
    let expiry = newer.key.created_at().as_secs() + 100;
    let at = |secs| Timestamp::from_secs(secs);

    let cases = [
        ("newer valid", public.clone(), now, Some(newer_fp.clone())),
        (
            "newer binding with zero expiry",
            expiring(0),
            now,
            Some(newer_fp.clone()),
        ),
        (
            "newer binding expired",
            expiring(1),
            now,
            Some(older_fp.clone()),
        ),
        (
            "finite expiry whose sum exceeds u32::MAX",
            expiring(u32::MAX),
            now,
            Some(newer_fp.clone()),
        ),
        (
            "one second before the expiry",
            expiring(100),
            at(expiry - 1),
            Some(newer_fp.clone()),
        ),
        (
            "exactly at the expiry",
            expiring(100),
            at(expiry),
            Some(older_fp.clone()),
        ),
        (
            "latest of two bindings decides",
            with_newer(plus(vec![binding(
                &secret,
                Some(1),
                Timestamp::from_secs(now.as_secs() + 10),
                &newer,
            )])),
            now,
            Some(older_fp.clone()),
        ),
        (
            "newer revoked",
            with_newer(plus(vec![revocation(&secret, &newer)])),
            now,
            Some(older_fp.clone()),
        ),
        (
            "newer bound by an unrelated primary",
            with_newer(resigned(
                &newer,
                vec![binding(&stranger, None, now, &newer)],
            )),
            now,
            Some(older_fp.clone()),
        ),
        (
            "newer RSA binding allows only signing",
            rsa_signing,
            now,
            Some(rsa_older_fp),
        ),
        (
            "newer binding allows only communications encryption",
            flagged(true, false),
            now,
            Some(newer_fp.clone()),
        ),
        (
            "newer binding allows only storage encryption",
            flagged(false, true),
            now,
            Some(newer_fp.clone()),
        ),
        (
            "newer binding allows no encryption",
            flagged(false, false),
            now,
            Some(older_fp.clone()),
        ),
        (
            "newer algorithm cannot encrypt",
            cannot_encrypt,
            now,
            Some(odd_older_fp),
        ),
        (
            "equal creation times keep the first",
            tie,
            now,
            Some(tie_first_fp),
        ),
        (
            "older expired and newer revoked",
            with(
                Some(resigned(
                    &older,
                    vec![binding(&secret, Some(1), now, &older)],
                )),
                plus(vec![revocation(&secret, &newer)]),
            ),
            now,
            None,
        ),
        ("primary revoked", primary_revoked, now, None),
    ];

    for (name, key, at, expected) in cases {
        assert!(chosen(&key, at) == expected, "{name}: wrong subkey chosen");
    }

    assert!(
        encryption_subkey(&expiring(1)).map(|s| s.fingerprint()) == Some(older_fp)
            && encryption_subkey(&public).map(|s| s.fingerprint()) == Some(newer_fp),
        "encryption_subkey judges expiry at the current time"
    );

    // The package encrypts to the newer subkey: a key holding only the older
    // subkey's secret cannot open it.
    let sender = address_key(default_key());
    let package = built(build_package(
        &sender,
        BODY,
        BodyType::Plain,
        &[RecipientKey {
            email: "r@example.com".into(),
            kind: RecipientKind::Internal(public),
        }],
    ));
    let packet = unb64(
        package.addresses["r@example.com"]
            .body_key_packet
            .as_deref()
            .unwrap_or_default(),
    );
    let message = [packet, unb64(&package.body)].concat();
    let mut only_newer = secret.clone();
    let mut only_older = secret;

    only_newer.secret_subkeys.remove(0);
    only_older.secret_subkeys.remove(1);

    assert!(
        is_body_signed_by(
            decrypt_with(&message, &only_newer),
            &sender.key.to_public_key()
        ),
        "newer subkey's secret decrypts"
    );
    assert!(
        decrypt_with(&message, &only_older).is_none(),
        "older subkey's secret does not decrypt"
    );
}

#[test]
fn no_recipients_is_error() {
    let sender = address_key(default_key());
    let result = build_package(&sender, BODY, BodyType::Plain, &[]);

    assert!(
        matches!(result, Err(Error::NoRecipients)),
        "empty recipients is NoRecipients"
    );
}

#[test]
fn package_json_uses_proton_field_names() {
    let sender = address_key(default_key());
    let recipient = default_key();
    let keys = |value: &Value| {
        let mut keys: Vec<String> = value
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect();

        keys.sort();

        keys
    };

    let mixed = built(build_package(
        &sender,
        BODY,
        BodyType::Plain,
        &[
            internal("r@example.com", &recipient),
            external("e@example.com"),
        ],
    ));
    let json = serde_json::to_value(&mixed).expect("package serialises");

    assert!(
        keys(&json) == ["Addresses", "Body", "BodyKey", "MIMEType", "Type"],
        "top-level keys"
    );
    assert!(
        keys(&json["BodyKey"]) == ["Algorithm", "Key"],
        "body key fields"
    );
    assert!(
        keys(&json["Addresses"]["e@example.com"]) == ["Signature", "Type"],
        "external address has no BodyKeyPacket"
    );
    assert!(
        keys(&json["Addresses"]["r@example.com"]) == ["BodyKeyPacket", "Signature", "Type"],
        "internal address fields"
    );

    let internal_only = built(build_package(
        &sender,
        BODY,
        BodyType::Plain,
        &[internal("r@example.com", &recipient)],
    ));
    let json = serde_json::to_value(&internal_only).expect("package serialises");

    assert!(
        keys(&json) == ["Addresses", "Body", "MIMEType", "Type"],
        "internal-only package has no BodyKey"
    );
}

#[test]
fn debug_redacts_session_key_and_body() {
    let sender = address_key(default_key());
    let recipient = default_key();
    let package = built(build_package(
        &sender,
        BODY,
        BodyType::Plain,
        &[
            internal("r@example.com", &recipient),
            external("e@example.com"),
        ],
    ));
    let key = package.body_key.as_ref().map(|k| k.key.clone());
    let shown = format!("{package:?}");

    assert!(key.is_some(), "mixed package has a session key");
    assert!(
        !shown.contains(&key.unwrap_or_default()),
        "debug holds no session key"
    );
    assert!(!shown.contains(&package.body), "debug holds no body");
    assert!(shown.contains("r@example.com"), "debug shows the addresses");
}
