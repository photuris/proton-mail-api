//! Offline shape tests over the scrubbed captures in `fixtures/live/`.
//!
//! Each file is served unmodified through wiremock at its real path and read
//! back through a resumed `Session`; expected values come from the same file.

use proton_mail_api::labels::{LabelType, system};
use proton_mail_api::messages::MessageQuery;
use proton_mail_api::session::{Client, PersistedSession, Session};
use serde_json::{Value, json};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The bytes of one captured file.
fn bytes(name: &str) -> Vec<u8> {
    let file = format!(
        "{}/tests/fixtures/live/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );

    std::fs::read(&file).unwrap_or_else(|e| panic!("read {file}: {e}"))
}

/// One captured file as JSON.
fn capture(name: &str) -> Value {
    serde_json::from_slice(&bytes(name)).expect("capture is JSON")
}

/// Serves `name` at `p`, only for requests carrying `query` when it is given.
async fn serve(server: &MockServer, name: &str, p: &str, query: Option<(&str, &str)>) {
    let mock = Mock::given(method("GET")).and(path(p));
    let mock = match query {
        Some((key, value)) => mock.and(query_param(key, value)),
        None => mock,
    };

    mock.respond_with(ResponseTemplate::new(200).set_body_bytes(bytes(name)))
        .mount(server)
        .await;
}

/// A session resumed from a blob, pointed at `server`.
fn session(server: &MockServer) -> Session {
    let blob: PersistedSession = serde_json::from_value(json!({
        "uid": "uid-c",
        "access_token": "access-c",
        "refresh_token": "refresh-c",
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
        .expect("resume succeeds")
}

/// A string field.
fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().expect("string field")
}

/// A field of `v` that is an array.
fn list<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v[key].as_array().expect("array field")
}

/// A `0`/`1` field as a bool.
fn flag(v: &Value, key: &str) -> bool {
    v[key].as_i64().expect("integer field") != 0
}

#[tokio::test]
async fn captured_user_parses() {
    let server = MockServer::start().await;
    let file = capture("users");
    let user = &file["User"];

    serve(&server, "users", "/core/v4/users", None).await;

    let got = session(&server).user().await.expect("user parses");
    let keys = list(user, "Keys");

    assert_eq!(got.id, text(user, "ID"));
    assert_eq!(got.keys.len(), keys.len());

    for (got, want) in got.keys.iter().zip(keys) {
        assert_eq!(got.id, text(want, "ID"));
        assert_eq!(got.primary.0, flag(want, "Primary"));
        assert_eq!(got.active.0, flag(want, "Active"));
    }
}

#[tokio::test]
async fn captured_addresses_parse() {
    let server = MockServer::start().await;
    let file = capture("addresses");
    let mut want: Vec<&Value> = list(&file, "Addresses").iter().collect();

    want.sort_by_key(|a| a["Order"].as_i64().expect("integer Order"));
    serve(&server, "addresses", "/core/v4/addresses", None).await;

    let got = session(&server).addresses().await.expect("addresses parse");

    assert_eq!(got.len(), want.len());

    for (got, want) in got.iter().zip(want) {
        assert_eq!(got.id, text(want, "ID"));
        assert_eq!(got.email, text(want, "Email"));
        assert_eq!(got.keys.len(), list(want, "Keys").len());
    }
}

#[tokio::test]
async fn captured_key_salts_parse() {
    let server = MockServer::start().await;
    let file = capture("key_salts");
    let want = list(&file, "KeySalts");

    serve(&server, "key_salts", "/core/v4/keys/salts", None).await;

    let got = session(&server).key_salts().await.expect("salts parse");

    assert_eq!(got.len(), want.len());

    for (got, want) in got.iter().zip(want) {
        assert_eq!(got.id, text(want, "ID"));
        assert_eq!(got.key_salt.as_deref(), want["KeySalt"].as_str());
    }
}

#[tokio::test]
async fn captured_labels_parse_by_type() {
    let server = MockServer::start().await;
    let files = [("labels_1", "1"), ("labels_3", "3"), ("labels_4", "4")];
    let mut want: Vec<(String, i64)> = Vec::new();

    for (name, kind) in files {
        let file = capture(name);

        for label in list(&file, "Labels") {
            want.push((
                text(label, "ID").to_owned(),
                label["Type"].as_i64().expect("integer Type"),
            ));
        }

        serve(&server, name, "/core/v4/labels", Some(("Type", kind))).await;
    }

    let session = session(&server);
    let got = session.labels().await.expect("labels parse");
    let got: Vec<(String, i64)> = got.into_iter().map(|l| (l.id, l.r#type)).collect();

    assert_eq!(got, want);

    let folders = session
        .labels_of_type(LabelType::Folder)
        .await
        .expect("folders parse");

    assert_eq!(folders.len(), list(&capture("labels_3"), "Labels").len());
}

#[tokio::test]
async fn captured_message_list_parses() {
    let server = MockServer::start().await;
    let file = capture("messages_inbox");
    let want = list(&file, "Messages");

    serve(&server, "messages_inbox", "/mail/v4/messages", None).await;

    let query = MessageQuery {
        label_id: Some(system::INBOX.into()),
        ..Default::default()
    };
    let page = session(&server)
        .list_messages(&query)
        .await
        .expect("list parses");

    assert_eq!(page.total, file["Total"].as_i64().expect("integer Total"));
    assert_eq!(page.messages.len(), want.len());

    for (got, want) in page.messages.iter().zip(want) {
        let label_ids: Vec<&str> = list(want, "LabelIDs")
            .iter()
            .map(|id| id.as_str().expect("string id"))
            .collect();

        assert_eq!(got.id, text(want, "ID"));
        assert_eq!(got.unread.0, want["Unread"] == 1);
        assert_eq!(got.label_ids, label_ids);
        assert_eq!(
            got.sender.as_ref().expect("sender").address,
            text(&want["Sender"], "Address")
        );
    }
}

#[tokio::test]
async fn captured_message_parses() {
    let server = MockServer::start().await;
    let file = capture("message");
    let want = &file["Message"];
    let id = text(want, "ID");

    serve(&server, "message", &format!("/mail/v4/messages/{id}"), None).await;

    let got = session(&server).message(id).await.expect("message parses");

    assert_eq!(got.meta.id, id);
    assert_eq!(got.mime_type, text(want, "MIMEType"));
    assert_eq!(got.body, text(want, "Body"));
    assert_eq!(got.attachments.len(), list(want, "Attachments").len());
}

#[tokio::test]
async fn captured_events_parse() {
    let server = MockServer::start().await;
    let latest = capture("events_latest");
    let event = capture("event");
    let id = text(&latest, "EventID");

    serve(&server, "events_latest", "/core/v4/events/latest", None).await;
    serve(&server, "event", &format!("/core/v4/events/{id}"), None).await;

    let session = session(&server);

    assert_eq!(session.latest_event_id().await.expect("latest parses"), id);

    let batch = session.events(id).await.expect("event parses");

    assert!(!batch.more);
    assert_eq!(batch.events.len(), 1);
    assert_eq!(batch.events[0].event_id, text(&event, "EventID"));
    assert!(!batch.events[0].more.0);
    assert_eq!(
        batch.events[0].requires_resync(),
        event["Refresh"].as_i64().expect("integer Refresh") & 1 != 0
    );
}
