//! Offline tests for listing, fetching and decrypting messages and
//! attachments. Keys are generated here with rpgp, unlocked through
//! `Session::unlock_keys` against wiremock, and mail is encrypted to them.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use pgp::composed::{
    ArmorOptions, EncryptionCaps, KeyType, MessageBuilder, SecretKeyParamsBuilder, SignedPublicKey,
    SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{CompressionAlgorithm, Password};
use proton_mail_api::error::Error;
use proton_mail_api::keys::UnlockedKeys;
use proton_mail_api::messages::{Attachment, DecryptedBody, MessageQuery};
use proton_mail_api::session::{Client, PersistedSession, Session};
use rand::thread_rng;
use serde_json::{Value, json};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const MAILBOX: &str = "correct horse mailbox";

/// A generated key, kept with the password that locks it.
struct TestKey {
    secret: SignedSecretKey,
    public: SignedPublicKey,
}

impl TestKey {
    /// Ed25519 primary plus a Curve25519 ECDH encryption subkey, both locked
    /// with `MAILBOX`.
    fn new() -> Self {
        let mut subkey = SubkeyParamsBuilder::default();

        subkey
            .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
            .can_sign(false)
            .can_encrypt(EncryptionCaps::All)
            .can_authenticate(false)
            .passphrase(Some(MAILBOX.to_owned()));

        let mut params = SecretKeyParamsBuilder::default();

        params
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .primary_user_id("Test <test@example.com>".into())
            .passphrase(Some(MAILBOX.to_owned()))
            .subkeys(vec![subkey.build().expect("subkey params")]);

        let secret = params
            .build()
            .expect("key params")
            .generate(thread_rng())
            .expect("key generates");

        Self {
            public: secret.to_public_key(),
            secret,
        }
    }

    fn armored(&self) -> String {
        self.secret
            .to_armored_string(ArmorOptions::default())
            .expect("key armors")
    }

    /// Encrypts `plain` to the encryption subkey the way Proton stores a
    /// body: compressed, signed, armored.
    fn encrypt_body(&self, plain: &[u8]) -> String {
        let mut builder = MessageBuilder::from_bytes("", plain.to_vec())
            .seipd_v1(thread_rng(), SymmetricKeyAlgorithm::AES256);

        builder
            .compression(CompressionAlgorithm::ZLIB)
            .sign(
                &self.secret.primary_key,
                Password::from(MAILBOX),
                HashAlgorithm::Sha256,
            )
            .encrypt_to_key(thread_rng(), &self.public.public_subkeys[0])
            .expect("encrypts to subkey");
        builder
            .to_armored_string(thread_rng(), ArmorOptions::default())
            .expect("message armors")
    }

    /// Encrypts `plain` to the encryption subkey and splits the result the way
    /// Proton serves an attachment: the key packet, then the data packet.
    fn encrypt_attachment(&self, plain: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut builder = MessageBuilder::from_bytes("", plain.to_vec())
            .seipd_v1(thread_rng(), SymmetricKeyAlgorithm::AES256);

        builder
            .encrypt_to_key(thread_rng(), &self.public.public_subkeys[0])
            .expect("encrypts to subkey");

        let bytes = builder.to_vec(thread_rng()).expect("message serialises");

        // A new-format public-key encrypted session key packet (tag 1) with a
        // one-octet length comes first.
        assert!(bytes[0] == 0xC1 && bytes[1] < 192, "key packet header");

        let split = 2 + usize::from(bytes[1]);

        (bytes[..split].to_vec(), bytes[split..].to_vec())
    }
}

/// A resumed session pointed at `server`.
fn session(server: &MockServer) -> Session {
    let blob: PersistedSession = serde_json::from_value(json!({
        "uid": "uid-1",
        "access_token": "access-1",
        "refresh_token": "refresh-1",
        "password_mode": "Single",
        "scope": "full",
        "key_password": null,
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

/// Serves one user key and one address key for `address_key`, then unlocks
/// them through the session.
async fn unlock(server: &MockServer, session: &Session, address_key: &TestKey) -> UnlockedKeys {
    let user_key = TestKey::new();
    let replies = [
        (
            "/core/v4/users",
            json!({"Code": 1000, "User": {
                "ID": "user-1", "Name": "test", "Email": "test@example.com",
                "Keys": [{
                    "ID": "k1", "PrivateKey": user_key.armored(),
                    "Primary": 1, "Active": 1, "Flags": 3,
                }],
            }}),
        ),
        // No salt: the key password is the mailbox password itself.
        ("/core/v4/keys/salts", json!({"Code": 1000, "KeySalts": []})),
        (
            "/core/v4/addresses",
            json!({"Code": 1000, "Addresses": [{
                "ID": "a1", "Email": "a@example.com", "Send": 1, "Receive": 1,
                "Status": 1, "Type": 1, "Order": 1, "DisplayName": "Test",
                "Keys": [{
                    "ID": "ak1", "PrivateKey": address_key.armored(),
                    "Primary": 1, "Active": 1, "Flags": 3,
                }],
            }]}),
        ),
    ];

    for (p, body) in replies {
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    let result = session.unlock_keys(MAILBOX).await;

    assert!(result.is_ok(), "unlock_keys must succeed");

    result.unwrap_or_else(|_| unreachable!())
}

/// Serves `GET /mail/v4/messages/<id>` with `message` merged over a minimal
/// message.
async fn mount_message(server: &MockServer, id: &str, fields: Value) {
    let mut message = json!({
        "ID": id, "AddressID": "a1", "LabelIDs": ["0", "5"], "Subject": "Hello",
        "Flags": 1, "Time": 1_700_000_000, "Size": 1234, "Unread": 0,
    });

    for (k, v) in fields.as_object().expect("fields are an object") {
        message[k] = v.clone();
    }

    Mock::given(method("GET"))
        .and(path(format!("/mail/v4/messages/{id}")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"Code": 1000, "Message": message})),
        )
        .mount(server)
        .await;
}

/// The page reply for `total`.
fn page_reply(total: i64) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "Code": 1000, "Total": total, "Messages": [], "Stale": 0,
    }))
}

#[tokio::test]
async fn list_messages_from_default_query_sends_desc_1_and_parses_page() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/mail/v4/messages"))
        .and(query_param("LabelID", "0"))
        .and(query_param("Page", "0"))
        .and(query_param("PageSize", "50"))
        .and(query_param("Sort", "Time"))
        .and(query_param("Desc", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Code": 1000,
            "Total": 7,
            "Stale": 1,
            "Messages": [
                {
                    "ID": "m1", "AddressID": "a1", "ConversationID": "c1",
                    "LabelIDs": ["0", "5"], "ExternalID": "<ext@example.com>",
                    "Subject": "First", "Sender": {"Name": "Ann", "Address": "ann@example.com"},
                    "ToList": [{"Name": "", "Address": "me@example.com"}],
                    "CCList": [], "BCCList": [], "ReplyTos": [],
                    "Flags": 1, "Time": 1_700_000_000, "Size": 321,
                    "Unread": 1, "IsReplied": 0, "IsRepliedAll": 0, "IsForwarded": 0,
                    "NumAttachments": 2,
                },
                {
                    "ID": "m2", "AddressID": "a1", "LabelIDs": ["0"],
                    "Subject": "Second", "Sender": {"Name": "Bob", "Address": "bob@example.com"},
                    "ToList": [{"Name": "Me", "Address": "me@example.com"}],
                    "CCList": null, "BCCList": null, "ReplyTos": null,
                    "Flags": 2, "Time": 1_700_000_100, "Size": 99,
                    "Unread": 0, "IsReplied": 1, "IsRepliedAll": 0, "IsForwarded": 0,
                    "NumAttachments": 0,
                },
            ],
        })))
        .mount(&server)
        .await;

    let query = MessageQuery {
        label_id: Some("0".into()),
        ..MessageQuery::default()
    };
    let result = session(&server).list_messages(&query).await;

    assert!(result.is_ok(), "list_messages must succeed");

    let page = result.unwrap_or_else(|_| unreachable!());

    assert!(page.total == 7, "total");
    assert!(page.stale, "stale");
    assert!(page.messages.len() == 2, "two messages");

    let first = &page.messages[0];

    assert!(first.id == "m1" && first.conversation_id.as_deref() == Some("c1"));
    assert!(first.label_ids == ["0", "5"], "label ids");
    assert!(first.subject == "First", "subject");
    assert!(
        first.sender.as_ref().map(|s| s.address.as_str()) == Some("ann@example.com"),
        "sender"
    );
    assert!(first.to_list.len() == 1 && first.to_list[0].name.is_empty());
    assert!(first.unread.0 && first.num_attachments == 2, "unread");
    assert!(first.has_any_flag(proton_mail_api::messages::flags::RECEIVED));
    assert!(!first.is_draft(), "received is not a draft");

    let second = &page.messages[1];

    assert!(second.id == "m2" && !second.unread.0 && second.is_replied.0);
    assert!(second.conversation_id.is_none(), "no conversation id");
    assert!(
        second.bcc_list.is_empty() && second.cc_list.is_empty() && second.reply_tos.is_empty(),
        "null recipient lists are empty"
    );
}

#[tokio::test]
async fn page_size_zero_defaults_and_is_capped_at_150() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/mail/v4/messages"))
        .and(query_param("PageSize", "50"))
        .and(query_param("Desc", "0"))
        .respond_with(page_reply(50))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/mail/v4/messages"))
        .and(query_param("PageSize", "150"))
        .and(query_param("Page", "3"))
        .respond_with(page_reply(150))
        .mount(&server)
        .await;

    let session = session(&server);
    let zero = session
        .list_messages(&MessageQuery {
            page_size: 0,
            desc: false,
            ..MessageQuery::default()
        })
        .await;
    let huge = session
        .list_messages(&MessageQuery {
            page: 3,
            page_size: 1000,
            ..MessageQuery::default()
        })
        .await;

    assert!(zero.is_ok_and(|p| p.total == 50), "0 becomes 50");
    assert!(huge.is_ok_and(|p| p.total == 150), "1000 becomes 150");
}

/// Fetches `msg-1` and decrypts its body.
async fn fetch_and_decrypt(session: &Session, keys: &UnlockedKeys) -> DecryptedBody {
    let fetched = session.message("msg-1").await;

    assert!(fetched.is_ok(), "message must fetch");

    let message = fetched.unwrap_or_else(|_| unreachable!());
    let body = message.decrypt_body(keys);

    assert!(body.is_ok(), "decrypt_body must succeed");

    body.unwrap_or_else(|_| unreachable!())
}

#[tokio::test]
async fn decrypt_html_body() {
    let server = MockServer::start().await;
    let session = session(&server);
    let address_key = TestKey::new();
    let keys = unlock(&server, &session, &address_key).await;
    let html = "<html><body><p>Héllo <b>there</b></p></body></html>";

    mount_message(
        &server,
        "msg-1",
        json!({"MIMEType": "text/html", "Body": address_key.encrypt_body(html.as_bytes())}),
    )
    .await;

    let body = fetch_and_decrypt(&session, &keys).await;

    assert!(body.mime_type == "text/html", "mime type");
    assert!(
        body.text_and_html() == (None, Some(html.to_owned())),
        "html only"
    );
    assert!(body.mime_attachments().is_empty(), "no attachments");
}

#[tokio::test]
async fn decrypt_plain_text_body() {
    let server = MockServer::start().await;
    let session = session(&server);
    let address_key = TestKey::new();
    let keys = unlock(&server, &session, &address_key).await;
    let text = "Line one\nLine two — ünïcode\n";

    mount_message(
        &server,
        "msg-1",
        json!({"MIMEType": "text/plain", "Body": address_key.encrypt_body(text.as_bytes())}),
    )
    .await;

    let body = fetch_and_decrypt(&session, &keys).await;

    assert!(
        body.text_and_html() == (Some(text.to_owned()), None),
        "text only"
    );
    assert!(body.mime_attachments().is_empty(), "no attachments");
}

#[tokio::test]
async fn decrypt_pgp_mime_body_extracts_text_html_and_attachment() {
    let server = MockServer::start().await;
    let session = session(&server);
    let address_key = TestKey::new();
    let keys = unlock(&server, &session, &address_key).await;
    let file: Vec<u8> = (0..=255u8).chain(0..=99u8).collect();
    let mime = format!(
        "Content-Type: multipart/mixed; boundary=\"bound\"\r\n\r\n\
         --bound\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\r\n\
         Plain words\r\n\
         --bound\r\n\
         Content-Type: text/html; charset=utf-8\r\n\r\n\
         <p>Html words</p>\r\n\
         --bound\r\n\
         Content-Type: application/octet-stream; name=\"report.bin\"\r\n\
         Content-Disposition: attachment; filename=\"report.bin\"\r\n\
         Content-Transfer-Encoding: base64\r\n\
         Content-ID: <img1@example.com>\r\n\r\n\
         {}\r\n\
         --bound--\r\n",
        B64.encode(&file)
    );

    mount_message(
        &server,
        "msg-1",
        json!({"MIMEType": "multipart/mixed", "Body": address_key.encrypt_body(mime.as_bytes())}),
    )
    .await;

    let body = fetch_and_decrypt(&session, &keys).await;
    let (text, html) = body.text_and_html();

    assert!(
        text.as_deref().map(str::trim) == Some("Plain words"),
        "text body"
    );
    assert!(
        html.as_deref().map(str::trim) == Some("<p>Html words</p>"),
        "html body"
    );

    let parts = body.mime_attachments();

    assert!(parts.len() == 1, "one attachment part");
    assert!(parts[0].name.as_deref() == Some("report.bin"), "name");
    assert!(parts[0].mime_type == "application/octet-stream", "type");
    assert!(
        parts[0].content_id.as_deref() == Some("img1@example.com"),
        "content id"
    );
    assert!(parts[0].bytes == file, "decoded bytes");
}

#[tokio::test]
async fn attachment_download_prepends_key_packets_and_decrypts() {
    let server = MockServer::start().await;
    let session = session(&server);
    let address_key = TestKey::new();
    let keys = unlock(&server, &session, &address_key).await;
    let plain: Vec<u8> = (0..=255u8).cycle().take(5000).collect();
    let (key_packets, data) = address_key.encrypt_attachment(&plain);

    Mock::given(method("GET"))
        .and(path("/mail/v4/attachments/att-1"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(data))
        .expect(1)
        .mount(&server)
        .await;

    let attachment: Attachment = serde_json::from_value(json!({
        "ID": "att-1", "Name": "blob.bin", "Size": 5000,
        "MIMEType": "application/octet-stream", "Disposition": "attachment",
        "KeyPackets": B64.encode(key_packets),
    }))
    .expect("attachment parses");
    let result = session.attachment(&attachment, &keys).await;

    assert!(result.is_ok(), "attachment must decrypt");
    assert!(
        result.unwrap_or_else(|_| unreachable!()) == plain,
        "plaintext matches"
    );
}

#[test]
fn attachment_content_id_from_headers_string_or_array() {
    let with = |headers: Value| -> Option<String> {
        let mut att = json!({"ID": "att-1"});

        if !headers.is_null() {
            att["Headers"] = headers;
        }

        serde_json::from_value::<Attachment>(att)
            .expect("attachment parses")
            .content_id()
    };

    assert!(with(json!({"Content-Id": "<a@example.com>"})).as_deref() == Some("a@example.com"));
    assert!(with(json!({"content-id": "b@example.com"})).as_deref() == Some("b@example.com"));
    assert!(
        with(json!({"CONTENT-ID": ["<c@example.com>", "<other>"]})).as_deref()
            == Some("c@example.com"),
        "first element of an array"
    );
    assert!(with(json!({"Content-Id": ""})).is_none(), "empty string");
    assert!(with(json!({"Content-Id": []})).is_none(), "empty array");
    assert!(
        with(json!({"Content-Type": "text/plain"})).is_none(),
        "absent"
    );
    assert!(with(Value::Null).is_none(), "no headers");
}

#[tokio::test]
async fn decrypt_with_wrong_key_is_crypto_error_without_ciphertext() {
    let server = MockServer::start().await;
    let session = session(&server);
    let address_key = TestKey::new();
    let keys = unlock(&server, &session, &address_key).await;
    let stranger = TestKey::new();
    let armored = stranger.encrypt_body(b"for someone else");

    mount_message(
        &server,
        "msg-1",
        json!({"MIMEType": "text/plain", "Body": armored}),
    )
    .await;

    let fetched = session.message("msg-1").await;

    assert!(fetched.is_ok(), "message must fetch");

    let result = fetched
        .unwrap_or_else(|_| unreachable!())
        .decrypt_body(&keys);

    assert!(result.is_err(), "wrong key must not decrypt");

    let Err(err) = result else { unreachable!() };
    let shown = format!("{err}");
    let debug = format!("{err:?}");

    assert!(matches!(err, Error::Crypto(_)), "crypto error");
    assert!(shown == "crypto error: message decryption failed");

    for line in armored.lines().filter(|l| l.len() >= 16) {
        for window in line.as_bytes().windows(16) {
            let fragment = String::from_utf8_lossy(window);

            assert!(
                !shown.contains(fragment.as_ref()) && !debug.contains(fragment.as_ref()),
                "error text must not carry ciphertext"
            );
        }
    }
}

/// A decrypted body with the given type and CRLF-terminated lines.
fn body(mime_type: &str, text: &str) -> DecryptedBody {
    DecryptedBody {
        mime_type: mime_type.to_owned(),
        bytes: text.replace('\n', "\r\n").into_bytes(),
    }
}

#[test]
fn mime_type_parameters_are_ignored() {
    let html = body("text/html; charset=utf-8", "<p>Hello</p>");

    assert!(
        html.text_and_html() == (None, Some("<p>Hello</p>".to_owned())),
        "html with a charset parameter"
    );
    assert!(
        body("TEXT/HTML ;charset=utf-8", "<p>Hi</p>")
            .text_and_html()
            .1
            .is_some(),
        "case and spacing"
    );

    let mixed = body(
        "multipart/mixed; boundary=x",
        "Content-Type: multipart/mixed; boundary=x

--x
Content-Type: text/plain; charset=utf-8

Words
--x
Content-Type: application/octet-stream
Content-Disposition: attachment; filename=a.bin

raw
--x--
",
    );

    assert!(mixed.mime_attachments().len() == 1, "attachment found");
    assert!(
        mixed.text_and_html().0.as_deref().map(str::trim) == Some("Words"),
        "text found"
    );
}

#[test]
fn inline_related_resources_are_attachments_not_bodies() {
    let related = body(
        "multipart/mixed",
        "From: Ann <ann@example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=m

--m
Content-Type: multipart/related; boundary=x

--x
Content-Type: text/html; charset=utf-8

<p>Actual body</p>
--x
Content-Type: text/plain; charset=utf-8; name=notes.txt
Content-Disposition: inline; filename=notes.txt
Content-ID: <notes@example.com>

Inline file contents
--x--
--m--
",
    );
    let (text, html) = related.text_and_html();
    let parts = related.mime_attachments();

    assert!(text.is_none(), "inline file is not the text body");
    assert!(
        html.as_deref().map(str::trim) == Some("<p>Actual body</p>"),
        "html body"
    );
    assert!(parts.len() == 1, "one attachment");
    assert!(parts[0].name.as_deref() == Some("notes.txt"), "name");
    assert!(
        parts[0].content_id.as_deref() == Some("notes@example.com"),
        "content id"
    );

    // Named only by its disposition, not inside a related container.
    let named = body(
        "multipart/mixed",
        "Content-Type: multipart/mixed; boundary=m

--m
Content-Type: text/plain

Plain body
--m
Content-Type: text/html
Content-Disposition: inline; filename=page.html

<p>A file</p>
--m--
",
    );
    let (text, html) = named.text_and_html();

    assert!(
        text.as_deref().map(str::trim) == Some("Plain body"),
        "text body"
    );
    assert!(html.is_none(), "named html is not the html body");
    assert!(named.mime_attachments().len() == 1, "named html is a part");
}

#[test]
fn non_mime_plaintext_under_mixed_falls_back_to_text() {
    let raw = "Meeting: tomorrow\nBring notes\n";
    let plain = DecryptedBody {
        mime_type: "multipart/mixed".to_owned(),
        bytes: raw.as_bytes().to_vec(),
    };

    assert!(plain.text_and_html() == (Some(raw.to_owned()), None));
    assert!(plain.mime_attachments().is_empty(), "no parts");
}

#[test]
fn single_part_attachment_root_is_a_mime_part() {
    let attachment = body(
        "multipart/mixed",
        "MIME-Version: 1.0
Content-Type: application/octet-stream; name=file.bin
Content-Disposition: attachment; filename=file.bin
Content-Transfer-Encoding: base64

AQID",
    );
    let parts = attachment.mime_attachments();

    assert!(parts.len() == 1, "the root is one part");
    assert!(parts[0].mime_type == "application/octet-stream", "type");
    assert!(parts[0].name.as_deref() == Some("file.bin"), "name");
    assert!(parts[0].bytes == [1, 2, 3], "decoded bytes");
    assert!(attachment.text_and_html() == (None, None), "no body");
}

#[test]
fn blank_mime_bodies_keep_their_type() {
    let html = body(
        "multipart/mixed",
        "Content-Type: text/html; charset=utf-8\n\n",
    );
    let text = DecryptedBody {
        mime_type: "multipart/mixed".to_owned(),
        bytes: b"Content-Type: text/plain\r\n\r\n  ".to_vec(),
    };

    assert!(html.text_and_html() == (None, Some(String::new())), "html");
    assert!(
        text.text_and_html() == (Some("  ".to_owned()), None),
        "whitespace text"
    );
}
