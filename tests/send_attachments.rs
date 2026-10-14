//! Offline tests for attachments on `Session::send`, against a wiremock server
//! and a resumed `Session`. Keys are generated here with rpgp and every
//! output is opened with rpgp again.

use std::io::Cursor;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use pgp::composed::{
    ArmorOptions, Deserializable, DetachedSignature, EncryptionCaps, KeyType, Message,
    PlainSessionKey, SecretKeyParamsBuilder, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::Password;
use proton_mail_api::compose::{BodyType, encrypt_attachment};
use proton_mail_api::error::Error;
use proton_mail_api::keys::{AddressKey, UnlockedKeys};
use proton_mail_api::messages::{Attachment, Recipient};
use proton_mail_api::send::{
    AttachmentDisposition, OutgoingAttachment, OutgoingMessage, ParentAction, ParentRef,
};
use proton_mail_api::session::{Client, PersistedSession, Session};
use rand::thread_rng;
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// The app version every test client sends.
const APP_VERSION: &str = "web-mail@test";

const SENDER: &str = "sender@example.com";

/// File bytes with `\r\n`, a blank line and the byte `0xff`.
const DATA: &[u8] = b"line one\r\nline two\r\n\r\n\xff\x00tail\r\n";

const UPLOAD_PATH: &str = "/mail/v4/attachments";

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

/// A key that can encrypt: Ed25519 primary and a Curve25519 subkey.
fn usable_key() -> SignedSecretKey {
    let mut subkey = SubkeyParamsBuilder::default();

    subkey
        .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
        .can_sign(false)
        .can_encrypt(EncryptionCaps::All);

    let mut params = SecretKeyParamsBuilder::default();

    params
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

/// The armored public half of `secret`.
fn armored_public(secret: &SignedSecretKey) -> String {
    secret
        .to_public_key()
        .to_armored_string(ArmorOptions::default())
        .expect("key armors")
}

/// An address key for `secret` of `email`.
fn address_key(email: &str, primary: bool, secret: SignedSecretKey) -> AddressKey {
    AddressKey {
        address_id: format!("addr-{email}"),
        email: email.into(),
        key_id: format!("key-{email}"),
        primary,
        key: secret,
    }
}

/// The unlocked keys of an account whose address keys are `keys`.
fn account(keys: Vec<AddressKey>) -> UnlockedKeys {
    UnlockedKeys {
        user_keys: Vec::new(),
        address_keys: keys,
        key_password: String::new().into(),
    }
}

/// The unlocked keys of an account with one address, `SENDER`, using `secret`.
fn unlocked(secret: &SignedSecretKey) -> UnlockedKeys {
    account(vec![address_key(SENDER, true, secret.clone())])
}

fn person(address: &str) -> Recipient {
    Recipient {
        name: String::new(),
        address: address.into(),
    }
}

/// A plain-text message from `SENDER` to `to` with `attachments`.
fn message(to: &[&str], attachments: Vec<OutgoingAttachment>) -> OutgoingMessage {
    OutgoingMessage {
        from: Recipient {
            name: "Sender".into(),
            address: SENDER.into(),
        },
        to: to.iter().map(|a| person(a)).collect(),
        cc: Vec::new(),
        bcc: Vec::new(),
        subject: "Hi".into(),
        body: "Hello there,\nsecond line.\n".into(),
        body_type: BodyType::Plain,
        parent: None,
        attachments,
    }
}

/// A regular attachment of `DATA`.
fn file(name: &str) -> OutgoingAttachment {
    OutgoingAttachment {
        filename: name.into(),
        mime_type: "application/pdf".into(),
        data: DATA.to_vec(),
        disposition: AttachmentDisposition::Attachment,
    }
}

/// A forward of `parent-1` carrying `attachments`.
fn forward(msg: &mut OutgoingMessage, attachments: Vec<Attachment>) {
    msg.parent = Some(ParentRef {
        id: "parent-1".into(),
        action: ParentAction::Forward,
        forward_attachments: attachments,
    });
}

/// Serves the key lookup of `email` with the reply `body`.
async fn mount_lookup(server: &MockServer, email: &str, recipient_type: u32, keys: Value) {
    Mock::given(method("GET"))
        .and(path("/core/v4/keys"))
        .and(query_param("Email", email))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Code": 1000,
            "Keys": keys,
            "RecipientType": recipient_type,
        })))
        .mount(server)
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

/// Serves the draft request with a draft named `id` whose `Message` also has
/// the fields of `extra`.
async fn mount_draft_with(server: &MockServer, id: &str, extra: Value) {
    let mut message = json!({ "ID": id, "AddressID": "addr-1", "Flags": 0 });

    if let (Some(map), Some(extra)) = (message.as_object_mut(), extra.as_object()) {
        map.extend(extra.clone());
    }

    Mock::given(method("POST"))
        .and(path("/mail/v4/messages"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "Code": 1000, "Message": message })),
        )
        .mount(server)
        .await;
}

/// Serves the draft request with a draft named `id` and no attachments.
async fn mount_draft(server: &MockServer, id: &str) {
    mount_draft_with(server, id, json!({})).await;
}

/// Serves the send request of draft `id` with a success.
async fn mount_send(server: &MockServer, id: &str) {
    Mock::given(method("POST"))
        .and(path(format!("/mail/v4/messages/{id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Code": 1000,
            "Sent": { "ID": "sent-id", "AddressID": "addr-1", "Flags": 2 },
        })))
        .mount(server)
        .await;
}

/// The reply of an upload that created attachment `id`.
fn uploaded(id: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "Code": 1000,
        "Attachment": { "ID": id, "Name": "x", "Size": 1 },
    }))
}

/// Serves uploads with a success for attachment `id`.
async fn mount_upload(server: &MockServer, id: &str) {
    Mock::given(method("POST"))
        .and(path(UPLOAD_PATH))
        .respond_with(uploaded(id))
        .mount(server)
        .await;
}

/// The reply of a successful token refresh.
fn refreshed() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "Code": 1000,
        "UID": "uid-a",
        "AccessToken": "access-new",
        "RefreshToken": "refresh-new",
    }))
}

/// Serves token refreshes with a success.
async fn mount_refresh(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/auth/v4/refresh"))
        .respond_with(refreshed())
        .mount(server)
        .await;
}

/// Every request the client sent to `server`, in arrival order. Requests that
/// lack the configured `x-pm-appversion` header are not the client's, so they
/// are left out.
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

/// The client's requests to exactly `p`, whatever the method.
async fn requests_to(server: &MockServer, p: &str) -> Vec<Request> {
    client_requests(server)
        .await
        .into_iter()
        .filter(|r| r.url.path() == p)
        .collect()
}

fn json_body(r: &Request) -> Value {
    serde_json::from_slice(&r.body).expect("json body")
}

fn unb64(text: &str) -> Vec<u8> {
    B64.decode(text).expect("valid base64")
}

/// The plaintext of the binary packets `bytes` opened with `secret`, `None`
/// when they do not open.
fn open_with(bytes: &[u8], secret: &SignedSecretKey) -> Option<Vec<u8>> {
    let message = Message::from_bytes(Cursor::new(bytes.to_vec())).ok()?;

    message
        .decrypt(&Password::empty(), secret)
        .ok()?
        .as_data_vec()
        .ok()
}

/// The plaintext of the binary packets `bytes` opened with the AES-256
/// session key `key`.
fn open_with_session_key(bytes: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let message = Message::from_bytes(Cursor::new(bytes.to_vec())).ok()?;

    message
        .decrypt_with_session_key(PlainSessionKey::V3_4 {
            key: key.into(),
            sym_alg: SymmetricKeyAlgorithm::AES256,
        })
        .ok()?
        .as_data_vec()
        .ok()
}

/// Whether `key_packet` ++ `data_packet` opens with `secret` to `DATA`.
fn opens_to_data(key_packet: &[u8], data_packet: &[u8], secret: &SignedSecretKey) -> bool {
    open_with(&[key_packet, data_packet].concat(), secret).is_some_and(|plain| plain == DATA)
}

// ── Multipart parsing ───────────────────────────────────────────────────────

/// One part of a multipart body.
struct FormPart {
    name: String,
    filename: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

/// Where `needle` first occurs in `hay`.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// The value of `key="..."` in a `Content-Disposition` header line.
fn quoted(line: &str, key: &str) -> Option<String> {
    line.split("; ")
        .find_map(|segment| segment.strip_prefix(&format!("{key}=\"")))
        .and_then(|rest| rest.strip_suffix('"'))
        .map(str::to_owned)
}

/// The parts of the multipart body of `request`, split on the boundary of its
/// `Content-Type` over the raw bytes.
fn parse_multipart(request: &Request) -> Vec<FormPart> {
    let content_type = request
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .expect("content type");
    let boundary = content_type
        .split("boundary=")
        .nth(1)
        .expect("boundary")
        .trim_matches('"');
    let delimiter = format!("--{boundary}").into_bytes();
    let mut rest = request.body.as_slice();
    let mut parts = Vec::new();
    let mut first = true;

    while let Some(at) = find(rest, &delimiter) {
        let segment = &rest[..at];

        rest = &rest[at + delimiter.len()..];

        if first {
            first = false;

            continue;
        }

        // Between two delimiters: CRLF, headers, a blank line, the content, CRLF.
        let segment = segment
            .strip_prefix(b"\r\n")
            .expect("part starts with CRLF");
        let segment = segment.strip_suffix(b"\r\n").expect("part ends with CRLF");
        let split = find(segment, b"\r\n\r\n").expect("headers end");
        let headers = String::from_utf8(segment[..split].to_vec()).expect("text headers");
        let mut part = FormPart {
            name: String::new(),
            filename: None,
            content_type: None,
            body: segment[split + 4..].to_vec(),
        };

        for line in headers.split("\r\n") {
            let lower = line.to_ascii_lowercase();

            if lower.starts_with("content-disposition:") {
                part.name = quoted(line, "name").expect("part name");
                part.filename = quoted(line, "filename");
            } else if let Some(value) = lower.strip_prefix("content-type:") {
                part.content_type = Some(value.trim().to_owned());
            }
        }

        parts.push(part);
    }

    assert!(
        rest.starts_with(b"--"),
        "the body ends with the closing delimiter"
    );

    parts
}

/// The only part called `name`.
fn part<'a>(parts: &'a [FormPart], name: &str) -> &'a FormPart {
    let found: Vec<_> = parts.iter().filter(|p| p.name == name).collect();

    assert_eq!(found.len(), 1, "exactly one part called {name}");

    found[0]
}

/// The text of the only part called `name`.
fn text(parts: &[FormPart], name: &str) -> String {
    let part = part(parts, name);

    assert!(part.filename.is_none(), "{name} is a text part");

    String::from_utf8(part.body.clone()).expect("text part")
}

/// The body of the only file part called `name`, which must be a `blob` of
/// type `application/octet-stream`.
fn blob<'a>(parts: &'a [FormPart], name: &str) -> &'a [u8] {
    let part = part(parts, name);

    assert_eq!(part.filename.as_deref(), Some("blob"), "{name} filename");
    assert_eq!(
        part.content_type.as_deref(),
        Some("application/octet-stream"),
        "{name} content type"
    );

    &part.body
}

/// The package of the send request to draft `id`.
async fn sent_package(server: &MockServer, id: &str) -> Value {
    let sends = requests_to(server, &format!("/mail/v4/messages/{id}")).await;

    assert_eq!(sends.len(), 1, "one send request");

    json_body(&sends[0])["Packages"][0].clone()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn send_with_attachment_uploads_after_draft_then_sends_keys() {
    let server = MockServer::start().await;
    let sender = usable_key();
    let alice = usable_key();

    mount_internal(&server, "alice@proton.test", &alice).await;
    mount_draft(&server, "draft-1").await;
    mount_upload(&server, "att-1").await;
    mount_send(&server, "draft-1").await;

    session(&server, 0)
        .send(
            &unlocked(&sender),
            &message(&["alice@proton.test"], vec![file("report.pdf")]),
        )
        .await
        .expect("send succeeds");

    assert_eq!(
        request_lines(&server).await,
        [
            "GET /core/v4/keys",
            "POST /mail/v4/messages",
            "POST /mail/v4/attachments",
            "POST /mail/v4/messages/draft-1",
        ]
    );

    let draft = json_body(&requests_to(&server, "/mail/v4/messages").await[0]);

    assert_eq!(draft["AttachmentKeyPackets"], json!([]));

    let uploads = requests_to(&server, UPLOAD_PATH).await;
    let parts = parse_multipart(&uploads[0]);

    assert_eq!(parts.len(), 8, "eight parts");
    assert_eq!(text(&parts, "MessageID"), "draft-1");
    assert_eq!(text(&parts, "Filename"), "report.pdf");
    assert_eq!(text(&parts, "MIMEType"), "application/pdf");
    assert_eq!(text(&parts, "Disposition"), "attachment");
    assert_eq!(text(&parts, "ContentID"), "");

    let key_packets = blob(&parts, "KeyPackets");
    let data_packet = blob(&parts, "DataPacket");
    let signature = blob(&parts, "Signature");

    assert!(
        opens_to_data(key_packets, data_packet, &sender),
        "the sender decrypts the upload to the file"
    );
    assert!(
        DetachedSignature::from_bytes(Cursor::new(signature))
            .is_ok_and(|s| s.verify(&sender.to_public_key(), DATA).is_ok()),
        "the signature verifies over the file"
    );

    let package = sent_package(&server, "draft-1").await;
    let entry = &package["Addresses"]["alice@proton.test"];

    assert_eq!(entry["Signature"], 1);
    assert!(
        opens_to_data(
            &unb64(
                entry["AttachmentKeyPackets"]["att-1"]
                    .as_str()
                    .expect("key packet")
            ),
            data_packet,
            &alice
        ),
        "the recipient decrypts the uploaded data packet"
    );
    assert!(package.get("AttachmentKeys").is_none());
}

#[tokio::test]
async fn external_recipient_gets_package_attachment_keys() {
    let server = MockServer::start().await;

    mount_external(&server, "bob@x.org").await;
    mount_draft(&server, "draft-1").await;
    mount_upload(&server, "att-1").await;
    mount_send(&server, "draft-1").await;

    session(&server, 0)
        .send(
            &unlocked(&usable_key()),
            &message(&["bob@x.org"], vec![file("report.pdf")]),
        )
        .await
        .expect("send succeeds");

    let parts = parse_multipart(&requests_to(&server, UPLOAD_PATH).await[0]);
    let package = sent_package(&server, "draft-1").await;
    let key = &package["AttachmentKeys"]["att-1"];

    assert_eq!(key["Algorithm"], "aes256");
    assert_eq!(
        open_with_session_key(
            blob(&parts, "DataPacket"),
            &unb64(key["Key"].as_str().expect("key"))
        )
        .as_deref(),
        Some(DATA)
    );
}

#[tokio::test]
async fn inline_attachment_sends_content_id() {
    let server = MockServer::start().await;

    mount_external(&server, "bob@x.org").await;
    mount_draft(&server, "draft-1").await;
    mount_upload(&server, "att-1").await;
    mount_send(&server, "draft-1").await;

    let mut inline = file("logo.png");

    inline.mime_type = "image/png".into();
    inline.disposition = AttachmentDisposition::Inline {
        content_id: "logo@example".into(),
    };

    session(&server, 0)
        .send(
            &unlocked(&usable_key()),
            &message(&["bob@x.org"], vec![inline]),
        )
        .await
        .expect("send succeeds");

    let parts = parse_multipart(&requests_to(&server, UPLOAD_PATH).await[0]);

    assert_eq!(text(&parts, "Disposition"), "inline");
    assert_eq!(text(&parts, "ContentID"), "logo@example");
    assert_eq!(text(&parts, "MIMEType"), "image/png");
}

#[tokio::test]
async fn forward_rekeys_parent_attachments_and_adds_new_upload() {
    let server = MockServer::start().await;
    let sender = usable_key();
    let second = usable_key();
    let alice = usable_key();
    let keys = account(vec![
        address_key(SENDER, true, sender.clone()),
        address_key("second@example.com", false, second.clone()),
    ]);

    // The parent's attachment as the account stores it: for the second key.
    let parent =
        encrypt_attachment(&keys.address_keys[1], "old.bin", DATA).expect("parent encrypts");
    // The copy the server makes into the draft: for the sending key.
    let copy = encrypt_attachment(&keys.address_keys[0], "old.bin", DATA).expect("copy encrypts");

    mount_internal(&server, "alice@proton.test", &alice).await;
    mount_draft_with(
        &server,
        "draft-1",
        json!({ "Attachments": [{
            "ID": "copy-1",
            "KeyPackets": B64.encode(&copy.key_packets),
            "Signature": "",
        }] }),
    )
    .await;
    mount_upload(&server, "att-1").await;
    mount_send(&server, "draft-1").await;

    let mut msg = message(&["alice@proton.test"], vec![file("new.pdf")]);

    forward(
        &mut msg,
        vec![Attachment {
            id: "parent-att".into(),
            name: "old.bin".into(),
            size: 1,
            mime_type: "application/octet-stream".into(),
            disposition: "attachment".into(),
            key_packets: B64.encode(&parent.key_packets),
            headers: None,
        }],
    );

    session(&server, 0)
        .send(&keys, &msg)
        .await
        .expect("send succeeds");

    assert_eq!(
        request_lines(&server).await,
        [
            "GET /core/v4/keys",
            "POST /mail/v4/messages",
            "POST /mail/v4/attachments",
            "POST /mail/v4/messages/draft-1",
        ]
    );

    let draft = json_body(&requests_to(&server, "/mail/v4/messages").await[0]);
    let rekeyed = draft["AttachmentKeyPackets"]["parent-att"]
        .as_str()
        .expect("re-keyed packet");

    assert_eq!(draft["Action"], 2);
    assert_eq!(
        draft["AttachmentKeyPackets"].as_object().map(|m| m.len()),
        Some(1)
    );
    assert!(
        opens_to_data(&unb64(rekeyed), &parent.data_packet, &sender),
        "the sender decrypts the parent's data with the re-keyed packet"
    );

    let uploads = requests_to(&server, UPLOAD_PATH).await;

    assert_eq!(uploads.len(), 1);

    let upload_parts = parse_multipart(&uploads[0]);
    let package = sent_package(&server, "draft-1").await;
    let entry = &package["Addresses"]["alice@proton.test"];
    let packets = entry["AttachmentKeyPackets"].as_object().expect("packets");

    assert_eq!(packets.len(), 2);
    assert!(
        opens_to_data(
            &unb64(packets["copy-1"].as_str().expect("copy packet")),
            &copy.data_packet,
            &alice
        ),
        "the recipient decrypts the copy"
    );
    assert!(
        opens_to_data(
            &unb64(packets["att-1"].as_str().expect("upload packet")),
            blob(&upload_parts, "DataPacket"),
            &alice
        ),
        "the recipient decrypts the upload"
    );
    assert_eq!(entry["Signature"], 0, "the copy has no signature");
}

#[tokio::test]
async fn forward_attachments_ignored_for_reply() {
    let server = MockServer::start().await;
    let alice = usable_key();
    let keys = account(vec![
        address_key(SENDER, true, usable_key()),
        address_key("second@example.com", false, usable_key()),
    ]);
    let (attachment, _) = parent_attachment(&keys.address_keys[1]);

    mount_internal(&server, "alice@proton.test", &alice).await;
    mount_draft(&server, "draft-1").await;
    mount_send(&server, "draft-1").await;

    let mut msg = message(&["alice@proton.test"], vec![]);

    msg.parent = Some(ParentRef {
        id: "parent-1".into(),
        action: ParentAction::Reply,
        forward_attachments: vec![attachment],
    });

    let result = session(&server, 0).send(&keys, &msg).await;
    let drafts = requests_to(&server, "/mail/v4/messages").await;

    assert_eq!(drafts.len(), 1, "one draft request");

    let draft = json_body(&drafts[0]);

    assert_eq!(draft["Action"], 0);
    assert_eq!(draft["AttachmentKeyPackets"], json!([]));
    assert!(result.is_ok(), "got {result:?}");

    let package = sent_package(&server, "draft-1").await;

    assert!(package.get("AttachmentKeys").is_none());
    assert!(
        package["Addresses"]["alice@proton.test"]
            .get("AttachmentKeyPackets")
            .is_none()
    );
}

/// What a failing upload row expects of the error.
type SourceCheck = fn(&Error) -> bool;

#[tokio::test]
async fn upload_failure_is_send_rejected_without_send() {
    let failing = |status: u16, body: Value| {
        ResponseTemplate::new(status)
            .insert_header("Retry-After", "0")
            .set_body_json(body)
    };
    let hv = json!({
        "Code": 9001,
        "Error": "BODYMARKER",
        "Details": {
            "HumanVerificationMethods": ["captcha"],
            "HumanVerificationToken": "BODYMARKER",
        },
    });
    let blocked = json!({ "Code": 2028, "Error": "BODYMARKER" });
    let table: Vec<(&str, ResponseTemplate, usize, usize, SourceCheck)> = vec![
        (
            "422",
            failing(422, json!({ "Code": 2001, "Error": "BODYMARKER" })),
            1,
            1,
            |e| {
                matches!(
                    e,
                    Error::Api {
                        status: 422,
                        code: 2001,
                        ..
                    }
                )
            },
        ),
        (
            "503",
            failing(503, json!({ "Code": 2500, "Error": "BODYMARKER" })),
            1,
            1,
            |e| matches!(e, Error::Api { status: 503, .. }),
        ),
        (
            "429",
            ResponseTemplate::new(429).insert_header("Retry-After", "0"),
            1,
            1,
            |e| matches!(e, Error::RateLimited { .. }),
        ),
        ("503 verification", failing(503, hv.clone()), 1, 1, |e| {
            matches!(e, Error::HumanVerificationRequired { .. })
        }),
        (
            "second upload 422",
            failing(422, json!({ "Code": 2001, "Error": "BODYMARKER" })),
            2,
            2,
            |e| matches!(e, Error::Api { status: 422, .. }),
        ),
        (
            "not json",
            ResponseTemplate::new(200).set_body_string("not json BODYMARKER"),
            1,
            1,
            |e| matches!(e, Error::InvalidResponse),
        ),
        ("401 verification", failing(401, hv), 1, 1, |e| {
            matches!(e, Error::HumanVerificationRequired { .. })
        }),
        ("401 blocked", failing(401, blocked.clone()), 1, 1, |e| {
            matches!(e, Error::Blocked { .. })
        }),
        ("503 blocked", failing(503, blocked), 1, 1, |e| {
            matches!(e, Error::Blocked { .. })
        }),
    ];

    for (name, response, attachments, uploads, check) in table {
        let server = MockServer::start().await;

        mount_external(&server, "bob@x.org").await;
        mount_draft(&server, "draft-1").await;
        mount_send(&server, "draft-1").await;
        mount_refresh(&server).await;

        // In the two-attachment row the first upload succeeds.
        if attachments == 2 {
            Mock::given(method("POST"))
                .and(path(UPLOAD_PATH))
                .respond_with(uploaded("att-1"))
                .up_to_n_times(1)
                .mount(&server)
                .await;
        }

        Mock::given(method("POST"))
            .and(path(UPLOAD_PATH))
            .respond_with(response)
            .mount(&server)
            .await;

        let files = (0..attachments)
            .map(|i| file(&format!("f{i}.bin")))
            .collect();

        // Retries are allowed so that a repeated upload would be seen.
        let result = session(&server, 2)
            .send(&unlocked(&usable_key()), &message(&["bob@x.org"], files))
            .await;

        let Err(error) = result else {
            panic!("{name}: the send must fail");
        };
        let shown = format!("{error} {error:?}");
        let Error::SendRejected { draft_id, source } = error else {
            panic!("{name}: expected SendRejected, got {shown}");
        };

        assert_eq!(draft_id, "draft-1", "{name}: draft id");
        assert!(check(&source), "{name}: unexpected source {source:?}");
        assert!(
            !shown.contains("BODYMARKER"),
            "{name}: error leaks the body"
        );
        assert_eq!(
            requests_to(&server, UPLOAD_PATH).await.len(),
            uploads,
            "{name}: uploads"
        );
        assert_eq!(
            requests_to(&server, "/mail/v4/messages").await.len(),
            1,
            "{name}: one draft"
        );
        assert!(
            requests_to(&server, "/mail/v4/messages/draft-1")
                .await
                .is_empty(),
            "{name}: no send and no delete"
        );
        assert!(
            requests_to(&server, "/auth/v4/refresh").await.is_empty(),
            "{name}: no refresh"
        );
    }
}

#[tokio::test]
async fn upload_401_refreshes_once_then_stops() {
    // Row one: the repeat after the refresh succeeds.
    let server = MockServer::start().await;

    mount_external(&server, "bob@x.org").await;
    mount_draft(&server, "draft-1").await;
    mount_send(&server, "draft-1").await;
    mount_refresh(&server).await;
    Mock::given(method("POST"))
        .and(path(UPLOAD_PATH))
        .and(header("authorization", "Bearer access-a"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(UPLOAD_PATH))
        .and(header("authorization", "Bearer access-new"))
        .respond_with(uploaded("att-1"))
        .mount(&server)
        .await;

    session(&server, 2)
        .send(
            &unlocked(&usable_key()),
            &message(&["bob@x.org"], vec![file("report.pdf")]),
        )
        .await
        .expect("send succeeds after the refresh");

    let uploads = requests_to(&server, UPLOAD_PATH).await;

    assert_eq!(uploads.len(), 2, "one repeat");
    assert_eq!(
        uploads[1]
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok()),
        Some("Bearer access-new")
    );
    assert_eq!(requests_to(&server, "/auth/v4/refresh").await.len(), 1);

    let (first, second) = (parse_multipart(&uploads[0]), parse_multipart(&uploads[1]));

    assert_eq!(first.len(), 8);
    assert_eq!(second.len(), 8);

    for (a, b) in first.iter().zip(&second) {
        assert_eq!(
            (&a.name, &a.filename, &a.content_type, &a.body),
            (&b.name, &b.filename, &b.content_type, &b.body),
            "part {} is byte-equal on the repeat",
            a.name
        );
    }

    // Row two: the repeat answers 401 as well.
    let server = MockServer::start().await;

    mount_external(&server, "bob@x.org").await;
    mount_draft(&server, "draft-1").await;
    mount_send(&server, "draft-1").await;
    mount_refresh(&server).await;
    Mock::given(method("POST"))
        .and(path(UPLOAD_PATH))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let result = session(&server, 2)
        .send(
            &unlocked(&usable_key()),
            &message(&["bob@x.org"], vec![file("report.pdf")]),
        )
        .await;

    assert!(
        matches!(
            &result,
            Err(Error::SendRejected { draft_id, source })
                if draft_id == "draft-1" && matches!(**source, Error::SessionExpired)
        ),
        "got {result:?}"
    );
    assert_eq!(requests_to(&server, UPLOAD_PATH).await.len(), 2);
    assert_eq!(requests_to(&server, "/auth/v4/refresh").await.len(), 1);
    assert!(
        requests_to(&server, "/mail/v4/messages/draft-1")
            .await
            .is_empty()
    );
}

/// A parent attachment whose key packets are for `key`.
fn parent_attachment(key: &AddressKey) -> (Attachment, Vec<u8>) {
    let encrypted = encrypt_attachment(key, "old.bin", DATA).expect("parent encrypts");
    let attachment = Attachment {
        id: "parent-att".into(),
        name: "old.bin".into(),
        size: 1,
        mime_type: "application/octet-stream".into(),
        disposition: "attachment".into(),
        key_packets: B64.encode(&encrypted.key_packets),
        headers: None,
    };

    (attachment, encrypted.key_packets)
}

#[tokio::test]
async fn bad_forward_key_packets_fail_before_draft() {
    let server = MockServer::start().await;
    let keys = unlocked(&usable_key());
    let (attachment, _) = parent_attachment(&address_key("other@example.com", true, usable_key()));

    mount_external(&server, "bob@x.org").await;
    mount_draft(&server, "draft-1").await;
    mount_send(&server, "draft-1").await;

    let mut msg = message(&["bob@x.org"], vec![]);

    forward(&mut msg, vec![attachment]);

    let result = session(&server, 0).send(&keys, &msg).await;

    assert!(matches!(result, Err(Error::Crypto(_))), "got {result:?}");
    assert!(requests_to(&server, "/mail/v4/messages").await.is_empty());
    assert!(requests_to(&server, UPLOAD_PATH).await.is_empty());
}

#[tokio::test]
async fn draft_attachment_copies_missing_or_bad_are_send_rejected() {
    let keys = unlocked(&usable_key());
    let unrelated = encrypt_attachment(
        &address_key("other@example.com", true, usable_key()),
        "old.bin",
        DATA,
    )
    .expect("encrypts");
    let table: Vec<(&str, Value, SourceCheck)> = vec![
        ("omitted", json!({}), |e| {
            matches!(e, Error::InvalidResponse)
        }),
        (
            "empty key packets",
            json!({ "Attachments": [{ "ID": "copy-1", "KeyPackets": "", "Signature": "" }] }),
            |e| matches!(e, Error::InvalidResponse),
        ),
        ("not a list", json!({ "Attachments": "oops" }), |e| {
            matches!(e, Error::InvalidResponse)
        }),
        (
            "undecryptable",
            json!({ "Attachments": [{
                "ID": "copy-1",
                "KeyPackets": B64.encode(&unrelated.key_packets),
                "Signature": "",
            }] }),
            |e| matches!(e, Error::Crypto(_)),
        ),
        ("fewer than forwarded", json!({ "Attachments": [] }), |e| {
            matches!(e, Error::InvalidResponse)
        }),
    ];

    for (name, extra, check) in table {
        let server = MockServer::start().await;
        let (attachment, _) = parent_attachment(&keys.address_keys[0]);

        mount_external(&server, "bob@x.org").await;
        mount_draft_with(&server, "draft-1", extra).await;
        mount_upload(&server, "att-1").await;
        mount_send(&server, "draft-1").await;

        let mut msg = message(&["bob@x.org"], vec![file("new.pdf")]);

        forward(&mut msg, vec![attachment]);

        let result = session(&server, 0).send(&keys, &msg).await;
        let Err(Error::SendRejected { draft_id, source }) = result else {
            panic!("{name}: expected SendRejected");
        };

        assert_eq!(draft_id, "draft-1", "{name}: draft id");
        assert!(check(&source), "{name}: unexpected source {source:?}");
        assert_eq!(
            requests_to(&server, "/mail/v4/messages").await.len(),
            1,
            "{name}: one draft"
        );
        assert!(
            requests_to(&server, UPLOAD_PATH).await.is_empty(),
            "{name}: no upload"
        );
        assert!(
            requests_to(&server, "/mail/v4/messages/draft-1")
                .await
                .is_empty(),
            "{name}: no send"
        );
    }
}

#[tokio::test]
async fn no_attachments_send_is_unchanged() {
    for kind in ["new", "reply", "forward"] {
        let server = MockServer::start().await;
        let sender = usable_key();
        let alice = usable_key();

        mount_internal(&server, "alice@proton.test", &alice).await;
        mount_external(&server, "bob@x.org").await;
        mount_draft(&server, "draft-1").await;
        mount_send(&server, "draft-1").await;

        let mut msg = message(&["alice@proton.test", "bob@x.org"], vec![]);

        match kind {
            "reply" => {
                msg.parent = Some(ParentRef {
                    id: "parent-1".into(),
                    action: ParentAction::Reply,
                    forward_attachments: vec![],
                });
            }
            "forward" => forward(&mut msg, vec![]),
            _ => {}
        }

        session(&server, 0)
            .send(&unlocked(&sender), &msg)
            .await
            .expect("send succeeds");

        assert_eq!(
            request_lines(&server).await,
            [
                "GET /core/v4/keys",
                "GET /core/v4/keys",
                "POST /mail/v4/messages",
                "POST /mail/v4/messages/draft-1",
            ],
            "{kind}: requests"
        );

        let draft = json_body(&requests_to(&server, "/mail/v4/messages").await[0]);

        assert_eq!(draft["AttachmentKeyPackets"], json!([]), "{kind}: draft");

        let package = sent_package(&server, "draft-1").await;
        let internal = &package["Addresses"]["alice@proton.test"];
        let external = &package["Addresses"]["bob@x.org"];

        assert!(
            package.get("AttachmentKeys").is_none(),
            "{kind}: package keys"
        );
        assert!(
            internal.get("AttachmentKeyPackets").is_none(),
            "{kind}: internal"
        );
        assert!(
            external.get("AttachmentKeyPackets").is_none(),
            "{kind}: external"
        );
        assert_eq!(internal["Signature"], 1, "{kind}: internal signature");
        assert_eq!(external["Signature"], 0, "{kind}: external signature");

        let bytes = [
            unb64(internal["BodyKeyPacket"].as_str().expect("key packet")),
            unb64(package["Body"].as_str().expect("body")),
        ]
        .concat();
        let mut opened = Message::from_bytes(Cursor::new(bytes))
            .expect("message parses")
            .decrypt(&Password::empty(), &alice)
            .expect("the recipient decrypts the body");

        assert_eq!(opened.as_data_vec().expect("reads"), msg.body.as_bytes());
        assert!(
            opened.verify(&sender.to_public_key()).is_ok(),
            "{kind}: the body signature verifies"
        );
    }
}

#[test]
fn attachments_debug_shows_no_data() {
    let data = b"DATAMARKER".to_vec();
    let numeric = format!("{data:?}");
    let attachment = OutgoingAttachment {
        filename: "a.bin".into(),
        mime_type: "application/octet-stream".into(),
        data,
        disposition: AttachmentDisposition::Attachment,
    };
    let message = message(&["bob@x.org"], vec![attachment.clone()]);

    for (shown, expected) in [
        (format!("{attachment:?}"), "<10 bytes>"),
        (format!("{message:?}"), "<1 items>"),
    ] {
        assert!(shown.contains(expected), "{shown}");
        assert!(!shown.contains("DATAMARKER"), "{shown}");
        assert!(!shown.contains(&numeric), "{shown}");
    }
}
