//! Offline tests for recipient key lookup and `Session::send`, against a
//! wiremock server and a resumed `Session`. Keys are generated here with rpgp
//! and every output is opened with rpgp again.

use std::io::Cursor;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use pgp::composed::{
    ArmorOptions, EncryptionCaps, KeyType, Message, SecretKeyParamsBuilder, SignedSecretKey,
    SubkeyParams, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::types::{KeyDetails, Password};
use proton_mail_api::compose::{BodyType, RecipientKind};
use proton_mail_api::error::Error;
use proton_mail_api::keys::{AddressKey, UnlockedKeys};
use proton_mail_api::messages::Recipient;
use proton_mail_api::send::{OutgoingMessage, ParentAction, ParentRef};
use proton_mail_api::session::{Client, PersistedSession, Session};
use rand::thread_rng;
use serde_json::{Value, json};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// The app version every test client sends.
const APP_VERSION: &str = "web-mail@test";

const SENDER: &str = "sender@example.com";

/// A session resumed against `server` that allows `retries` retries on a
/// 429/503 for calls that may repeat. No network call is made.
fn session(server: &MockServer, retries: u32) -> Session {
    let blob: PersistedSession = serde_json::from_value(json!({
        "uid": "uid-a",
        "access_token": "access-a",
        "refresh_token": "refresh-a",
        "password_mode": "Single",
        "scope": "full",
        "key_password": null,
    }))
    .expect("blob parses");

    Client::builder()
        .app_version(APP_VERSION)
        .base_url(server.uri())
        .max_retries(retries)
        .build()
        .expect("valid config")
        .resume(blob)
        .expect("resume succeeds")
}

/// A secret key with an Ed25519 primary and the given subkeys, no password.
fn generate(subkeys: Vec<SubkeyParams>) -> SignedSecretKey {
    let mut params = SecretKeyParamsBuilder::default();

    params
        .key_type(KeyType::Ed25519Legacy)
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

/// A key that can encrypt: Ed25519 primary and a Curve25519 subkey.
fn usable_key() -> SignedSecretKey {
    let mut subkey = SubkeyParamsBuilder::default();

    subkey
        .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
        .can_sign(false)
        .can_encrypt(EncryptionCaps::All);

    generate(vec![subkey.build().expect("subkey params")])
}

/// A key with no encryption subkey.
fn signing_only_key() -> SignedSecretKey {
    generate(Vec::new())
}

/// The armored public half of `secret`.
fn armored_public(secret: &SignedSecretKey) -> String {
    secret
        .to_public_key()
        .to_armored_string(ArmorOptions::default())
        .expect("key armors")
}

/// The unlocked keys of an account with one address, `SENDER`, using `secret`.
fn unlocked(secret: SignedSecretKey) -> UnlockedKeys {
    UnlockedKeys {
        user_keys: Vec::new(),
        address_keys: vec![AddressKey {
            address_id: "addr-1".into(),
            email: SENDER.into(),
            key_id: "key-1".into(),
            primary: true,
            key: secret,
        }],
        key_password: String::new().into(),
    }
}

fn person(address: &str) -> Recipient {
    Recipient {
        name: String::new(),
        address: address.into(),
    }
}

fn named(name: &str, address: &str) -> Recipient {
    Recipient {
        name: name.into(),
        address: address.into(),
    }
}

/// A plain-text message from `SENDER` to `to`.
fn message(to: &[&str]) -> OutgoingMessage {
    OutgoingMessage {
        from: named("Sender", SENDER),
        to: to.iter().map(|a| person(a)).collect(),
        cc: Vec::new(),
        bcc: Vec::new(),
        subject: "Hi".into(),
        body: "Hello there,\nsecond line.\n".into(),
        body_type: BodyType::Plain,
        parent: None,
        attachments: vec![],
    }
}

/// Serves the key lookup of `email` with the reply `body`.
async fn mount_lookup_body(server: &MockServer, email: &str, body: Value) {
    Mock::given(method("GET"))
        .and(path("/core/v4/keys"))
        .and(query_param("Email", email))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

/// Serves the key lookup of `email`.
async fn mount_lookup(server: &MockServer, email: &str, recipient_type: u32, keys: Value) {
    mount_lookup_body(
        server,
        email,
        json!({
            "Code": 1000,
            "Keys": keys,
            "RecipientType": recipient_type,
        }),
    )
    .await;
}

/// Serves the lookup of an external `email`.
async fn mount_external(server: &MockServer, email: &str) {
    mount_lookup(server, email, 2, json!([])).await;
}

/// Serves the lookup of a Proton `email` with `secret`'s public key.
async fn mount_internal(server: &MockServer, email: &str, secret: &SignedSecretKey) {
    mount_lookup(
        server,
        email,
        1,
        json!([{ "Flags": 3, "PublicKey": armored_public(secret) }]),
    )
    .await;
}

/// Serves the draft request with a draft named `id`.
async fn mount_draft(server: &MockServer, id: &str) {
    Mock::given(method("POST"))
        .and(path("/mail/v4/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Code": 1000,
            "Message": { "ID": id, "AddressID": "addr-1", "Flags": 0 },
        })))
        .mount(server)
        .await;
}

/// Serves the send request of draft `id` with `response`.
async fn mount_send(server: &MockServer, id: &str, response: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path(format!("/mail/v4/messages/{id}")))
        .respond_with(response)
        .mount(server)
        .await;
}

/// The reply of a successful send.
fn sent_ok() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "Code": 1000,
        "Sent": { "ID": "sent-id", "AddressID": "addr-1", "Flags": 2 },
    }))
}

/// Serves a successful draft request and send request of draft `id`.
async fn mount_flow(server: &MockServer, id: &str) {
    mount_draft(server, id).await;
    mount_send(server, id, sent_ok()).await;
}

/// Every request the client sent to `server`, in arrival order. Requests that
/// lack the configured `x-pm-appversion` header are not the client's (stray
/// header-less hits have been seen on `/`), so they are left out.
async fn client_requests(server: &MockServer) -> Vec<Request> {
    server
        .received_requests()
        .await
        .expect("recording is on")
        .into_iter()
        .filter(|r| {
            r.headers
                .get("x-pm-appversion")
                .is_some_and(|v| v.to_str().is_ok_and(|v| v == APP_VERSION))
        })
        .collect()
}

/// The client's requests as `METHOD path` lines.
async fn request_lines(server: &MockServer) -> Vec<String> {
    client_requests(server)
        .await
        .iter()
        .map(|r| format!("{} {}", r.method, r.url.path()))
        .collect()
}

/// The client's POSTs to exactly `p`.
async fn posts_to(server: &MockServer, p: &str) -> Vec<Request> {
    client_requests(server)
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.path() == p)
        .collect()
}

fn json_body(r: &Request) -> Value {
    serde_json::from_slice(&r.body).expect("json body")
}

/// The `Email` query values of the client's key lookups, in order.
async fn lookups(server: &MockServer) -> Vec<String> {
    client_requests(server)
        .await
        .iter()
        .filter(|r| r.url.path() == "/core/v4/keys")
        .map(|r| {
            r.url
                .query_pairs()
                .find(|(k, _)| k == "Email")
                .map(|(_, v)| v.into_owned())
                .expect("Email query")
        })
        .collect()
}

/// The plaintext of `message` opened with `secret`.
fn read(message: Message<'_>, secret: &SignedSecretKey) -> Vec<u8> {
    let mut message = message
        .decrypt(&Password::empty(), secret)
        .expect("message decrypts");

    message.as_data_vec().expect("message reads")
}

/// The plaintext of the binary packets `bytes` opened with `secret`.
fn open(bytes: &[u8], secret: &SignedSecretKey) -> Vec<u8> {
    read(
        Message::from_bytes(Cursor::new(bytes.to_vec())).expect("message parses"),
        secret,
    )
}

/// The plaintext of the armored message `armored` opened with `secret`.
fn open_armored(armored: &str, secret: &SignedSecretKey) -> Vec<u8> {
    read(
        Message::from_string(armored).expect("armor parses").0,
        secret,
    )
}

fn unb64(text: &str) -> Vec<u8> {
    B64.decode(text).expect("valid base64")
}

/// `"Address"` of each entry of a recipient list.
fn addresses(list: &Value) -> Vec<&str> {
    list.as_array()
        .expect("list")
        .iter()
        .map(|r| r["Address"].as_str().expect("address"))
        .collect()
}

#[tokio::test]
async fn send_to_internal_and_external_posts_draft_then_one_package() {
    let server = MockServer::start().await;
    let sender = usable_key();
    let alice = usable_key();
    let keys = unlocked(sender);

    mount_internal(&server, "alice@proton.test", &alice).await;
    mount_external(&server, "bob@x.org").await;
    mount_flow(&server, "draft-1").await;

    let msg = message(&["alice@proton.test", "bob@x.org"]);
    let sent = session(&server, 0)
        .send(&keys, &msg)
        .await
        .expect("send succeeds");

    assert_eq!(sent.id, "sent-id");
    assert_eq!(
        request_lines(&server).await,
        [
            "GET /core/v4/keys",
            "GET /core/v4/keys",
            "POST /mail/v4/messages",
            "POST /mail/v4/messages/draft-1",
        ]
    );
    assert_eq!(lookups(&server).await, ["alice@proton.test", "bob@x.org"]);

    let mut draft = json_body(&posts_to(&server, "/mail/v4/messages").await[0]);
    let draft_body = draft["Message"]["Body"]
        .as_str()
        .expect("armored body")
        .to_owned();

    draft["Message"]["Body"] = Value::Null;

    assert_eq!(
        draft,
        json!({
            "Message": {
                "Subject": "Hi",
                "Sender": { "Name": "Sender", "Address": SENDER },
                "ToList": [
                    { "Name": "", "Address": "alice@proton.test" },
                    { "Name": "", "Address": "bob@x.org" },
                ],
                "CCList": [],
                "BCCList": [],
                "Body": null,
                "MIMEType": "text/plain",
                "AddressID": "addr-1",
                "Unread": 0,
            },
            "AttachmentKeyPackets": [],
        })
    );
    assert_eq!(
        open_armored(&draft_body, &keys.address_keys[0].key),
        msg.body.as_bytes()
    );

    let send = json_body(&posts_to(&server, "/mail/v4/messages/draft-1").await[0]);
    let packages = send["Packages"].as_array().expect("packages");

    assert_eq!(packages.len(), 1);

    let package = &packages[0];
    let entry = &package["Addresses"]["alice@proton.test"];

    assert_eq!(package["Type"], 5);
    assert_eq!(package["Addresses"]["bob@x.org"]["Type"], 4);
    assert_eq!(entry["Type"], 1);

    let mut data = unb64(entry["BodyKeyPacket"].as_str().expect("key packet"));

    data.extend(unb64(package["Body"].as_str().expect("body")));

    assert_eq!(open(&data, &alice), msg.body.as_bytes());
}

#[tokio::test]
async fn recipient_key_picks_first_usable_key_and_handles_external() {
    let server = MockServer::start().await;
    let obsolete = usable_key();
    let wanted = usable_key();
    let malformed = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nbm90IGEga2V5\n-----END PGP PUBLIC KEY BLOCK-----\n";

    mount_lookup(
        &server,
        "p@proton.test",
        1,
        json!([
            { "Flags": 1, "PublicKey": armored_public(&obsolete) },
            { "Flags": 3, "PublicKey": malformed },
            { "Flags": 3, "PublicKey": armored_public(&signing_only_key()) },
            { "Flags": 3, "PublicKey": armored_public(&wanted) },
        ]),
    )
    .await;
    mount_lookup(
        &server,
        "e@x.org",
        2,
        json!([{ "Flags": 3, "PublicKey": armored_public(&wanted) }]),
    )
    .await;
    mount_lookup(&server, "n@x.org", 2, Value::Null).await;

    let session = session(&server, 0);

    let internal = session
        .recipient_key("p@proton.test")
        .await
        .expect("lookup succeeds");

    assert_eq!(internal.email, "p@proton.test");
    assert!(
        matches!(
            &internal.kind,
            RecipientKind::Internal(key) if key.fingerprint() == wanted.fingerprint()
        ),
        "the fourth key is the first usable one"
    );

    for email in ["e@x.org", "n@x.org"] {
        let external = session.recipient_key(email).await.expect("lookup succeeds");

        assert_eq!(external.email, email);
        assert!(matches!(external.kind, RecipientKind::External));
    }
}

#[tokio::test]
async fn internal_without_usable_key_fails_before_draft() {
    let usable = armored_public(&usable_key());
    let cases = [
        (
            json!({ "Code": 1000, "RecipientType": 1,
                "Keys": [{ "Flags": 1, "PublicKey": usable }] }),
            false,
        ),
        (
            json!({ "Code": 1000, "RecipientType": 1,
                "Keys": [{ "Flags": 3, "PublicKey": armored_public(&signing_only_key()) }] }),
            false,
        ),
        // No `RecipientType`: not a recipient type, so never external.
        (
            json!({ "Code": 1000, "Keys": [{ "Flags": 3, "PublicKey": usable }] }),
            true,
        ),
    ];

    for (i, (reply, malformed)) in cases.into_iter().enumerate() {
        let server = MockServer::start().await;

        mount_lookup_body(&server, "p@proton.test", reply).await;
        mount_flow(&server, "draft-1").await;

        let result = session(&server, 0)
            .send(&unlocked(usable_key()), &message(&["p@proton.test"]))
            .await;

        assert!(
            if malformed {
                matches!(result, Err(Error::InvalidResponse))
            } else {
                matches!(result, Err(Error::RecipientKeyUnusable))
            },
            "case {i}: the lookup must fail before a draft"
        );
        assert_eq!(request_lines(&server).await, ["GET /core/v4/keys"]);
    }
}

#[tokio::test]
async fn no_recipients_and_unknown_sender_send_nothing() {
    let server = MockServer::start().await;
    let keys = unlocked(usable_key());
    let session = session(&server, 0);

    mount_external(&server, "bob@x.org").await;
    mount_flow(&server, "draft-1").await;

    let none = session.send(&keys, &message(&[])).await;

    assert!(matches!(none, Err(Error::NoRecipients)));
    assert!(client_requests(&server).await.is_empty());

    let mut stranger = message(&["bob@x.org"]);

    stranger.from = person("someone-else@example.com");

    let unknown = session.send(&keys, &stranger).await;

    assert!(matches!(unknown, Err(Error::UnknownSender)));
    assert!(client_requests(&server).await.is_empty());
}

#[tokio::test]
async fn reply_sets_parent_id_and_action() {
    let table = [
        (ParentAction::Reply, 0),
        (ParentAction::ReplyAll, 1),
        (ParentAction::Forward, 2),
    ];

    for (action, wire) in table {
        let server = MockServer::start().await;

        mount_external(&server, "bob@x.org").await;
        mount_flow(&server, "draft-1").await;

        let mut msg = message(&["bob@x.org"]);

        msg.parent = Some(ParentRef {
            id: "parent-1".into(),
            action,
            forward_attachments: vec![],
        });

        session(&server, 0)
            .send(&unlocked(usable_key()), &msg)
            .await
            .expect("send succeeds");

        let draft = json_body(&posts_to(&server, "/mail/v4/messages").await[0]);

        assert_eq!(draft["ParentID"], "parent-1");
        assert_eq!(draft["Action"], wire);
    }
}

#[tokio::test]
async fn bcc_recipients_get_packages_and_duplicates_collapse() {
    let server = MockServer::start().await;
    let carol = usable_key();

    mount_external(&server, "Bob@x.org").await;
    // Served so that a lookup of the second spelling would succeed and be seen.
    mount_external(&server, "bob@x.org").await;
    mount_internal(&server, "carol@proton.test", &carol).await;
    mount_flow(&server, "draft-1").await;

    let mut msg = message(&["Bob@x.org"]);

    msg.bcc = vec![person("bob@x.org"), person("carol@proton.test")];

    session(&server, 0)
        .send(&unlocked(usable_key()), &msg)
        .await
        .expect("send succeeds");

    assert_eq!(lookups(&server).await, ["Bob@x.org", "carol@proton.test"]);

    let draft = json_body(&posts_to(&server, "/mail/v4/messages").await[0]);

    assert_eq!(
        addresses(&draft["Message"]["BCCList"]),
        ["bob@x.org", "carol@proton.test"]
    );

    let send = json_body(&posts_to(&server, "/mail/v4/messages/draft-1").await[0]);
    let package = &send["Packages"][0];
    let entries = package["Addresses"].as_object().expect("addresses");

    assert_eq!(entries.len(), 2);
    assert_eq!(entries["Bob@x.org"]["Type"], 4);
    assert_eq!(entries["carol@proton.test"]["Type"], 1);
    assert!(entries["carol@proton.test"]["BodyKeyPacket"].is_string());
}

#[tokio::test]
async fn send_rejection_keeps_draft_and_is_not_repeated() {
    let table = [
        ResponseTemplate::new(422).set_body_json(json!({ "Code": 2001, "Error": "invalid" })),
        ResponseTemplate::new(429).insert_header("Retry-After", "0"),
    ];

    for (i, response) in table.into_iter().enumerate() {
        let server = MockServer::start().await;

        mount_external(&server, "bob@x.org").await;
        mount_draft(&server, "draft-7").await;
        mount_send(&server, "draft-7", response).await;

        // Retries are allowed so that a repeated send would be seen.
        let result = session(&server, 2)
            .send(&unlocked(usable_key()), &message(&["bob@x.org"]))
            .await;

        let Err(Error::SendRejected { draft_id, source }) = result else {
            panic!("case {i}: the send must be rejected");
        };

        assert_eq!(draft_id, "draft-7");
        match (i, *source) {
            (0, Error::Api { status, code, .. }) => assert_eq!((status, code), (422, 2001)),
            (1, Error::RateLimited { .. }) => {}
            _ => panic!("case {i}: unexpected source"),
        }

        assert_eq!(posts_to(&server, "/mail/v4/messages").await.len(), 1);
        assert_eq!(
            posts_to(&server, "/mail/v4/messages/draft-7").await.len(),
            1
        );
    }
}

#[tokio::test]
async fn send_with_unreadable_outcome_is_unknown() {
    let table = [
        ResponseTemplate::new(200).set_body_string("not json"),
        ResponseTemplate::new(503)
            .insert_header("Retry-After", "0")
            .set_body_json(json!({ "Code": 2500, "Error": "unavailable" })),
        // A 503 is never a definite refusal, whatever its code.
        ResponseTemplate::new(503)
            .insert_header("Retry-After", "0")
            .set_body_json(json!({ "Code": 10013, "Error": "SERVERMARKER" })),
    ];

    for (i, response) in table.into_iter().enumerate() {
        let server = MockServer::start().await;

        mount_external(&server, "bob@x.org").await;
        mount_draft(&server, "draft-8").await;
        mount_send(&server, "draft-8", response).await;

        let result = session(&server, 2)
            .send(&unlocked(usable_key()), &message(&["bob@x.org"]))
            .await;

        assert!(
            matches!(
                &result,
                Err(Error::SendOutcomeUnknown { draft_id }) if draft_id == "draft-8"
            ),
            "case {i}: the outcome must be unknown"
        );
        assert_eq!(
            posts_to(&server, "/mail/v4/messages/draft-8").await.len(),
            1
        );
    }
}

#[tokio::test]
async fn draft_post_is_not_repeated_and_debug_redacts() {
    let server = MockServer::start().await;

    mount_external(&server, "bob@x.org").await;
    Mock::given(method("POST"))
        .and(path("/mail/v4/messages"))
        .respond_with(
            ResponseTemplate::new(503)
                .insert_header("Retry-After", "0")
                .set_body_json(json!({ "Code": 2500, "Error": "unavailable" })),
        )
        .mount(&server)
        .await;

    let result = session(&server, 2)
        .send(&unlocked(usable_key()), &message(&["bob@x.org"]))
        .await;

    assert!(
        matches!(result, Err(Error::Api { status: 503, .. })),
        "a failed draft request is returned as it is"
    );
    assert_eq!(posts_to(&server, "/mail/v4/messages").await.len(), 1);
    assert_eq!(
        client_requests(&server)
            .await
            .iter()
            .filter(|r| r.method.as_str() == "POST")
            .count(),
        1
    );

    let mut msg = message(&["bob@x.org"]);

    msg.subject = "SUBJECTMARKER".into();
    msg.body = "BODYMARKER".into();

    let debug = format!("{msg:?}");

    assert!(!debug.contains("SUBJECTMARKER"));
    assert!(!debug.contains("BODYMARKER"));
    assert!(debug.contains("bob@x.org"));
}
