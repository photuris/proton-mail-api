//! Offline tests for key fetching and unlocking. Keys are generated here with
//! rpgp, locked the way Proton locks them, and served from wiremock.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use pgp::composed::{
    ArmorOptions, DetachedSignature, EncryptionCaps, KeyType, Message, MessageBuilder,
    SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::Password;
use proton_mail_api::error::Error;
use proton_mail_api::keys::{KeyRecord, UnlockedKeys};
use proton_mail_api::session::{Client, PersistedSession, Session};
use proton_mail_api::srp;
use rand::{RngCore, thread_rng};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const MAILBOX: &str = "correct horse mailbox";

/// A generated user key, kept with the password that locks it.
struct TestKey {
    secret: SignedSecretKey,
    public: SignedPublicKey,
    password: String,
}

impl TestKey {
    /// Ed25519 primary plus a Curve25519 ECDH encryption subkey, both locked
    /// with `password`.
    fn new(password: &str) -> Self {
        let mut subkey = SubkeyParamsBuilder::default();

        subkey
            .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
            .can_sign(false)
            .can_encrypt(EncryptionCaps::All)
            .can_authenticate(false)
            .passphrase(Some(password.to_owned()));

        let mut params = SecretKeyParamsBuilder::default();

        params
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .primary_user_id("Test <test@example.com>".into())
            .passphrase(Some(password.to_owned()))
            .subkeys(vec![subkey.build().expect("subkey params")]);

        let secret = params
            .build()
            .expect("key params")
            .generate(thread_rng())
            .expect("key generates");

        Self {
            public: secret.to_public_key(),
            secret,
            password: password.to_owned(),
        }
    }

    /// A key locked with the key password derived from `MAILBOX` and `salt`.
    fn salted(salt: &[u8]) -> Self {
        let derived = srp::key_password(MAILBOX.as_bytes(), salt).expect("key password");

        Self::new(&derived)
    }

    fn armored(&self) -> String {
        self.secret
            .to_armored_string(ArmorOptions::default())
            .expect("key armors")
    }

    /// Encrypts `plain` to the encryption subkey, armored.
    fn encrypt(&self, plain: &[u8]) -> String {
        let mut builder = MessageBuilder::from_bytes("", plain.to_vec())
            .seipd_v1(thread_rng(), SymmetricKeyAlgorithm::AES256);

        builder
            .encrypt_to_key(thread_rng(), &self.public.public_subkeys[0])
            .expect("encrypts to subkey");
        builder
            .to_armored_string(thread_rng(), ArmorOptions::default())
            .expect("message armors")
    }

    /// Armored detached signature over `data`, made by the primary key.
    fn sign(&self, data: &[u8]) -> String {
        DetachedSignature::sign_binary_data(
            thread_rng(),
            &self.secret.primary_key,
            &Password::from(self.password.as_str()),
            HashAlgorithm::Sha256,
            data,
        )
        .expect("signs")
        .to_armored_string(ArmorOptions::default())
        .expect("signature armors")
    }

    /// Whether some key in `keys`, with an empty password, decrypts a message
    /// encrypted to this key.
    fn decrypts_with(&self, keys: &[&SignedSecretKey]) -> bool {
        let plain = b"short test message";
        let armored = self.encrypt(plain);
        let (message, _) = Message::from_string(&armored).expect("message parses");
        let empty = Password::empty();

        let Ok(mut decrypted) = message.decrypt_with_keys(vec![&empty], keys.to_vec()) else {
            return false;
        };

        decrypted.as_data_vec().is_ok_and(|got| got == plain)
    }
}

/// A key record as the API lists it.
fn record(id: &str, key: &TestKey, primary: bool, active: bool) -> Value {
    json!({
        "ID": id,
        "PrivateKey": key.armored(),
        "Primary": u8::from(primary),
        "Active": u8::from(active),
        "Flags": 3,
    })
}

/// An address key record whose password the user key `owner` delivers in a
/// token signed by `signer`.
fn token_record(
    id: &str,
    key_armored: &str,
    token: &str,
    owner: &TestKey,
    signer: &TestKey,
) -> Value {
    json!({
        "ID": id,
        "PrivateKey": key_armored,
        "Primary": 1,
        "Active": 1,
        "Flags": 3,
        "Token": owner.encrypt(token.as_bytes()),
        "Signature": signer.sign(token.as_bytes()),
    })
}

fn address(id: &str, email: &str, order: i64, keys: Vec<Value>) -> Value {
    json!({
        "ID": id, "Email": email, "Send": 1, "Receive": 1, "Status": 1,
        "Type": 1, "Order": order, "DisplayName": "Test", "Keys": keys,
    })
}

/// Serves the three key endpoints.
async fn mount(
    server: &MockServer,
    user_keys: Vec<Value>,
    salts: Vec<Value>,
    addresses: Vec<Value>,
) {
    let replies = [
        (
            "/core/v4/users",
            json!({"Code": 1000, "User": {
                "ID": "user-1", "Name": "test", "Email": "test@example.com", "Keys": user_keys,
            }}),
        ),
        (
            "/core/v4/keys/salts",
            json!({"Code": 1000, "KeySalts": salts}),
        ),
        (
            "/core/v4/addresses",
            json!({"Code": 1000, "Addresses": addresses}),
        ),
    ];

    for (p, body) in replies {
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }
}

/// A resumed session pointed at `server`.
fn session(server: &MockServer) -> Session {
    session_with_key_password(server, Value::Null)
}

/// A resumed session pointed at `server` whose blob carries `key_password`.
fn session_with_key_password(server: &MockServer, key_password: Value) -> Session {
    let blob: PersistedSession = serde_json::from_value(json!({
        "uid": "uid-1",
        "access_token": "access-1",
        "refresh_token": "refresh-1",
        "password_mode": "Single",
        "scope": "full",
        "key_password": key_password,
    }))
    .expect("blob parses");

    Client::builder()
        .app_version("web-mail@test")
        .base_url(server.uri())
        .max_retries(0)
        .build()
        .expect("valid config")
        .resume(blob)
        .expect("resumes")
}

fn salt() -> Vec<u8> {
    let mut salt = vec![0u8; 16];

    thread_rng().fill_bytes(&mut salt);

    salt
}

fn salt_entry(id: &str, salt: &[u8]) -> Value {
    json!({"ID": id, "KeySalt": B64.encode(salt)})
}

/// The `key_password` of the session's persisted form.
fn persisted_key_password(session: &Session) -> Value {
    serde_json::to_value(session.persist()).expect("blob serialises")["key_password"].clone()
}

/// `unlock_keys` succeeded.
fn unlocked(result: Result<UnlockedKeys, Error>) -> UnlockedKeys {
    assert!(result.is_ok(), "unlock_keys must succeed");

    result.unwrap_or_else(|_| unreachable!())
}

/// A random token that passes as an address key password.
fn token() -> String {
    let mut bytes = [0u8; 32];

    thread_rng().fill_bytes(&mut bytes);

    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn unlocks_user_key_with_salted_key_password() {
    let server = MockServer::start().await;
    let salt = salt();
    let user = TestKey::salted(&salt);
    // The address key has no token: it is locked with the primary key password.
    let address_key = TestKey::salted(&salt);

    mount(
        &server,
        vec![record("k1", &user, true, true)],
        vec![salt_entry("k1", &salt)],
        vec![address(
            "a1",
            "a@example.com",
            1,
            vec![record("ak1", &address_key, true, true)],
        )],
    )
    .await;

    let keys = unlocked(session(&server).unlock_keys(MAILBOX).await);

    assert!(keys.user_keys.len() == 1, "one user key");
    assert!(
        user.decrypts_with(&keys.user_keys.iter().collect::<Vec<_>>()),
        "unlocked user key decrypts"
    );
    assert!(
        address_key.decrypts_with(&keys.decryption_keys()),
        "address key falls back to the primary key password"
    );
}

/// Serves the user and addresses, and answers the salts endpoint the way
/// Proton does once the post-login scope has lapsed. `salts_calls` is how
/// many salts requests the test expects.
async fn mount_lapsed_salts(
    server: &MockServer,
    user_keys: Vec<Value>,
    addresses: Vec<Value>,
    salts_calls: u64,
) {
    for (p, body) in [
        (
            "/core/v4/users",
            json!({"Code": 1000, "User": {
                "ID": "user-1", "Name": "test", "Email": "test@example.com", "Keys": user_keys,
            }}),
        ),
        (
            "/core/v4/addresses",
            json!({"Code": 1000, "Addresses": addresses}),
        ),
    ] {
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    Mock::given(method("GET"))
        .and(path("/core/v4/keys/salts"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "Code": 9101, "Error": "Access token does not have sufficient scope",
        })))
        .expect(salts_calls)
        .mount(server)
        .await;
}

#[tokio::test]
async fn resumed_key_password_unlocks_without_fetching_salts() {
    let server = MockServer::start().await;
    let salt = salt();
    let derived = srp::key_password(MAILBOX.as_bytes(), &salt).expect("key password");
    let user = TestKey::salted(&salt);
    let address_key = TestKey::salted(&salt);

    mount_lapsed_salts(
        &server,
        vec![record("k1", &user, true, true)],
        vec![address(
            "a1",
            "a@example.com",
            1,
            vec![record("ak1", &address_key, true, true)],
        )],
        0,
    )
    .await;

    let session = session_with_key_password(&server, json!(derived.as_str()));
    // The mailbox password is wrong on purpose: the stored key password wins.
    let keys = unlocked(session.unlock_keys("not the mailbox password").await);

    assert!(
        user.decrypts_with(&keys.user_keys.iter().collect::<Vec<_>>()),
        "user key unlocks with the stored key password"
    );
    assert!(
        address_key.decrypts_with(&keys.decryption_keys()),
        "address key unlocks"
    );
    assert!(
        persisted_key_password(&session) == json!(derived.as_str()),
        "stored key password still persists"
    );
}

#[tokio::test]
async fn stale_key_password_falls_back_to_salts() {
    let server = MockServer::start().await;
    let salt = salt();
    let user = TestKey::salted(&salt);
    let address_key = TestKey::salted(&salt);

    mount(
        &server,
        vec![record("k1", &user, true, true)],
        vec![salt_entry("k1", &salt)],
        vec![address(
            "a1",
            "a@example.com",
            1,
            vec![record("ak1", &address_key, true, true)],
        )],
    )
    .await;

    let session = session_with_key_password(&server, json!("old key password"));
    let keys = unlocked(session.unlock_keys(MAILBOX).await);

    assert!(
        user.decrypts_with(&keys.user_keys.iter().collect::<Vec<_>>()),
        "user key unlocks through the salts"
    );
    assert!(
        persisted_key_password(&session) != json!("old key password"),
        "the fresh key password replaces the stale one"
    );
}

#[tokio::test]
async fn stale_key_password_with_lapsed_salts_is_an_error() {
    let server = MockServer::start().await;
    let salt = salt();
    let user = TestKey::salted(&salt);
    let address_key = TestKey::salted(&salt);

    mount_lapsed_salts(
        &server,
        vec![record("k1", &user, true, true)],
        vec![address(
            "a1",
            "a@example.com",
            1,
            vec![record("ak1", &address_key, true, true)],
        )],
        1,
    )
    .await;

    let session = session_with_key_password(&server, json!("old key password"));

    assert!(
        matches!(
            session.unlock_keys(MAILBOX).await,
            Err(Error::Api { code: 9101, .. })
        ),
        "the scope error surfaces so the caller can ask for a new login"
    );
}

#[tokio::test]
async fn missing_key_salt_uses_password_directly() {
    let server = MockServer::start().await;
    let first = TestKey::new(MAILBOX);
    let second = TestKey::new(MAILBOX);
    let address_key = TestKey::new(MAILBOX);

    mount(
        &server,
        vec![
            record("k1", &first, true, true),
            record("k2", &second, false, true),
        ],
        // k1 has an empty salt, k2 has no entry at all.
        vec![
            json!({"ID": "k1", "KeySalt": ""}),
            json!({"ID": "other", "KeySalt": null}),
        ],
        vec![address(
            "a1",
            "a@example.com",
            1,
            vec![record("ak1", &address_key, true, true)],
        )],
    )
    .await;

    let session = session(&server);
    let keys = unlocked(session.unlock_keys(MAILBOX).await);

    assert!(keys.user_keys.len() == 2, "both user keys unlock");
    assert!(
        first.decrypts_with(&keys.decryption_keys()),
        "first decrypts"
    );
    assert!(
        second.decrypts_with(&keys.decryption_keys()),
        "second decrypts"
    );
    assert!(
        persisted_key_password(&session) == json!(MAILBOX),
        "unsalted key password is the mailbox password"
    );
}

#[tokio::test]
async fn two_user_keys_with_distinct_salts_unlock_and_primary_password_persists() {
    let server = MockServer::start().await;
    let (salt1, salt2) = (salt(), salt());
    let first = TestKey::salted(&salt1);
    let second = TestKey::salted(&salt2);
    let address_key = TestKey::salted(&salt2);
    let derived = srp::key_password(MAILBOX.as_bytes(), &salt2).expect("key password");

    mount(
        &server,
        vec![
            record("k1", &first, false, true),
            record("k2", &second, true, true),
        ],
        vec![salt_entry("k1", &salt1), salt_entry("k2", &salt2)],
        vec![address(
            "a1",
            "a@example.com",
            1,
            vec![record("ak1", &address_key, true, true)],
        )],
    )
    .await;

    let session = session(&server);
    let keys = unlocked(session.unlock_keys(MAILBOX).await);

    assert!(keys.user_keys.len() == 2, "both user keys unlock");
    assert!(
        first.decrypts_with(&keys.decryption_keys()),
        "first decrypts"
    );
    assert!(
        second.decrypts_with(&keys.decryption_keys()),
        "second decrypts"
    );
    assert!(
        persisted_key_password(&session) == json!(derived.as_str()),
        "persisted key_password is the primary key's"
    );
    assert!(
        *keys.key_password == *derived,
        "returned key_password is the primary key's"
    );
}

#[tokio::test]
async fn unlocks_address_key_via_token_and_signature() {
    let server = MockServer::start().await;
    let salt = salt();
    let user = TestKey::salted(&salt);
    let token = token();
    let address_key = TestKey::new(&token);

    mount(
        &server,
        vec![record("k1", &user, true, true)],
        vec![salt_entry("k1", &salt)],
        vec![address(
            "a1",
            "a@example.com",
            1,
            vec![token_record(
                "ak1",
                &address_key.armored(),
                &token,
                &user,
                &user,
            )],
        )],
    )
    .await;

    let keys = unlocked(session(&server).unlock_keys(MAILBOX).await);

    assert!(keys.address_keys.len() == 1, "one address key");
    assert!(
        keys.address_keys[0].email == "a@example.com",
        "email carried"
    );
    assert!(keys.address_keys[0].primary, "primary flag carried");
    assert!(
        address_key.decrypts_with(&[&keys.address_keys[0].key]),
        "address key decrypts"
    );
}

#[tokio::test]
async fn address_key_with_bad_signature_is_skipped() {
    let server = MockServer::start().await;
    let salt = salt();
    let user = TestKey::salted(&salt);
    let stranger = TestKey::new("stranger");
    let (good_token, bad_token) = (token(), token());
    let good = TestKey::new(&good_token);
    let bad = TestKey::new(&bad_token);

    mount(
        &server,
        vec![record("k1", &user, true, true)],
        vec![salt_entry("k1", &salt)],
        vec![address(
            "a1",
            "a@example.com",
            1,
            vec![
                token_record("bad", &bad.armored(), &bad_token, &user, &stranger),
                token_record("good", &good.armored(), &good_token, &user, &user),
            ],
        )],
    )
    .await;

    let keys = unlocked(session(&server).unlock_keys(MAILBOX).await);

    assert!(keys.address_keys.len() == 1, "only the validly signed key");
    assert!(keys.address_keys[0].key_id == "good", "it is the good one");
    assert!(
        good.decrypts_with(&[&keys.address_keys[0].key]),
        "good key decrypts"
    );
}

#[tokio::test]
async fn inactive_keys_are_skipped() {
    let server = MockServer::start().await;
    let salt = salt();
    let user = TestKey::salted(&salt);
    let inactive_user = TestKey::salted(&salt);
    let address_key = TestKey::salted(&salt);
    let inactive_address = TestKey::salted(&salt);

    mount(
        &server,
        vec![
            record("k1", &user, true, true),
            record("k2", &inactive_user, false, false),
        ],
        vec![salt_entry("k1", &salt), salt_entry("k2", &salt)],
        vec![address(
            "a1",
            "a@example.com",
            1,
            vec![
                record("ak1", &address_key, true, true),
                record("ak2", &inactive_address, false, false),
            ],
        )],
    )
    .await;

    let keys = unlocked(session(&server).unlock_keys(MAILBOX).await);

    assert!(keys.user_keys.len() == 1, "inactive user key skipped");
    assert!(keys.address_keys.len() == 1, "inactive address key skipped");
    assert!(
        keys.address_keys[0].key_id == "ak1",
        "active address key kept"
    );
}

#[tokio::test]
async fn no_unlockable_key_is_error() {
    let server = MockServer::start().await;
    let wrong = "wrong mailbox passphrase";
    let salt = salt();
    let user = TestKey::salted(&salt);
    let address_key = TestKey::salted(&salt);

    mount(
        &server,
        vec![record("k1", &user, true, true)],
        vec![salt_entry("k1", &salt)],
        vec![address(
            "a1",
            "a@example.com",
            1,
            vec![record("ak1", &address_key, true, true)],
        )],
    )
    .await;

    let session = session(&server);
    let result = session.unlock_keys(wrong).await;

    assert!(
        matches!(result, Err(Error::NoUsableKey)),
        "wrong password is NoUsableKey"
    );

    let err = result.expect_err("an error");
    let text = format!("{err:?} {err}");

    assert!(!text.contains(wrong), "error holds no wrong passphrase");
    assert!(!text.contains(MAILBOX), "error holds no real passphrase");
    assert!(
        persisted_key_password(&session) == Value::Null,
        "nothing persisted on failure"
    );
}

#[tokio::test]
async fn unlocked_keys_and_key_record_debug_are_redacted() {
    let server = MockServer::start().await;
    let salt = salt();
    let user = TestKey::salted(&salt);
    let address_key = TestKey::salted(&salt);
    let mut rec = record("k1", &user, true, true);

    rec["Token"] = json!("token-text-marker");
    rec["Signature"] = json!("signature-text-marker");

    let parsed: KeyRecord = serde_json::from_value(rec).expect("record parses");
    let shown = format!("{parsed:?}");

    assert!(shown.contains("<redacted>"), "record marks redaction");
    assert!(shown.contains("k1"), "record shows its id");
    assert!(!shown.contains("PGP"), "record holds no key text");
    assert!(
        !shown.contains("token-text-marker"),
        "record holds no token"
    );
    assert!(
        !shown.contains("signature-text-marker"),
        "record holds no signature"
    );

    mount(
        &server,
        vec![record("k1", &user, true, true)],
        vec![salt_entry("k1", &salt)],
        vec![address(
            "a1",
            "a@example.com",
            1,
            vec![record("ak1", &address_key, true, true)],
        )],
    )
    .await;

    let keys = unlocked(session(&server).unlock_keys(MAILBOX).await);
    let shown = format!("{keys:?}");

    assert!(
        shown == "UnlockedKeys { user_keys: 1, address_keys: 1, key_password: \"<redacted>\" }",
        "unlocked keys debug is counts and a marker"
    );
}
