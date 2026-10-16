//! Offline tests for message triage, against a wiremock server and a
//! resumed `Session`.

use proton_mail_api::error::Error;
use proton_mail_api::session::{Client, PersistedSession, Session};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// A session resumed against `server`; no network call is made.
fn session(server: &MockServer) -> Session {
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
        .app_version("web-mail@test")
        .base_url(server.uri())
        .max_retries(0)
        .build()
        .expect("valid config")
        .resume(blob)
        .expect("resume succeeds")
}

/// `n` ids named `m0`, `m1`, ...
fn ids(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("m{i}")).collect()
}

/// Every PUT received at `p`, in arrival order.
async fn puts(server: &MockServer, p: &str) -> Vec<Request> {
    server
        .received_requests()
        .await
        .expect("recording on")
        .into_iter()
        .filter(|r| r.method.as_str() == "PUT" && r.url.path() == p)
        .collect()
}

/// The JSON body of a request.
fn body(r: &Request) -> Value {
    serde_json::from_slice(&r.body).expect("json body")
}

/// Answers every PUT at `p` with an empty 200 body.
async fn mount_empty(server: &MockServer, p: &str) {
    Mock::given(method("PUT"))
        .and(path(p))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
}

#[tokio::test]
async fn mark_read_and_unread_put_ids() {
    let server = MockServer::start().await;

    mount_empty(&server, "/mail/v4/messages/read").await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/unread"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "Code": 1000 })))
        .mount(&server)
        .await;

    let s = session(&server);
    let list = vec!["a".to_owned(), "b".to_owned()];

    s.mark_read(&list).await.expect("mark_read");
    s.mark_unread(&list).await.expect("mark_unread");

    let read = puts(&server, "/mail/v4/messages/read").await;
    let unread = puts(&server, "/mail/v4/messages/unread").await;

    assert_eq!(read.len(), 1);
    assert_eq!(unread.len(), 1);
    assert_eq!(body(&read[0]), json!({ "IDs": ["a", "b"] }));
    assert_eq!(body(&unread[0]), json!({ "IDs": ["a", "b"] }));
}

#[tokio::test]
async fn add_label_chunks_at_150() {
    let server = MockServer::start().await;

    mount_empty(&server, "/mail/v4/messages/label").await;

    session(&server)
        .add_label(&ids(301), "lbl")
        .await
        .expect("add_label");

    let reqs = puts(&server, "/mail/v4/messages/label").await;
    let sizes: Vec<usize> = reqs
        .iter()
        .map(|r| body(r)["IDs"].as_array().expect("IDs array").len())
        .collect();

    assert_eq!(sizes, [150, 150, 1]);
    assert_eq!(body(&reqs[0])["LabelID"], "lbl");
    assert_eq!(body(&reqs[0])["IDs"][0], "m0");
    assert_eq!(body(&reqs[2])["IDs"][0], "m300");
    assert_eq!(
        server
            .received_requests()
            .await
            .expect("recording on")
            .len(),
        3,
        "nothing but the three chunks"
    );
}

#[tokio::test]
async fn label_item_failure_is_action_failed() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/unlabel"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Code": 1001,
            "Responses": [
                { "ID": "m1", "Response": { "Code": 1000 } },
                { "ID": "m2", "Response": { "Code": 2001, "Error": "bad id" } },
            ],
        })))
        .mount(&server)
        .await;

    let err = session(&server)
        .remove_label(&["m1".to_owned(), "m2".to_owned()], "lbl")
        .await
        .expect_err("one item failed");

    match err {
        Error::ActionFailed { ids } => assert_eq!(ids, ["m2"]),
        other => panic!("expected ActionFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn move_to_uses_label_endpoint_with_folder_id() {
    let server = MockServer::start().await;

    mount_empty(&server, "/mail/v4/messages/label").await;

    session(&server)
        .move_to(&["a".to_owned()], "6")
        .await
        .expect("move_to");

    let reqs = puts(&server, "/mail/v4/messages/label").await;

    assert_eq!(reqs.len(), 1);
    assert_eq!(body(&reqs[0]), json!({ "LabelID": "6", "IDs": ["a"] }));
}

#[tokio::test]
async fn empty_ids_sends_nothing() {
    let server = MockServer::start().await;

    for p in [
        "/mail/v4/messages/read",
        "/mail/v4/messages/unread",
        "/mail/v4/messages/label",
        "/mail/v4/messages/unlabel",
    ] {
        Mock::given(method("PUT"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
    }

    let s = session(&server);

    s.mark_read(&[]).await.expect("mark_read");
    s.mark_unread(&[]).await.expect("mark_unread");
    s.add_label(&[], "lbl").await.expect("add_label");
    s.remove_label(&[], "lbl").await.expect("remove_label");
    s.move_to(&[], "6").await.expect("move_to");

    assert!(
        server
            .received_requests()
            .await
            .expect("recording on")
            .is_empty()
    );
}

#[tokio::test]
async fn delete_messages_chunks_and_reports_refused_ids() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/delete"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Code": 1001,
            "Responses": [
                { "ID": "m0", "Response": { "Code": 1000 } },
                { "ID": "m7", "Response": { "Code": 2501, "Error": "gone" } },
            ],
        })))
        .mount(&server)
        .await;

    let err = session(&server)
        .delete_messages(&ids(151))
        .await
        .expect_err("one item refused per chunk");

    let reqs = puts(&server, "/mail/v4/messages/delete").await;
    let sizes: Vec<usize> = reqs
        .iter()
        .map(|r| body(r)["IDs"].as_array().expect("IDs array").len())
        .collect();

    assert_eq!(sizes, [150, 1], "both chunks sent despite the refusal");
    assert_eq!(body(&reqs[1]), json!({ "IDs": ["m150"] }));
    match err {
        Error::ActionFailed { ids } => assert_eq!(ids, ["m7", "m7"]),
        other => panic!("expected ActionFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn delete_messages_with_no_ids_sends_nothing() {
    let server = MockServer::start().await;

    session(&server)
        .delete_messages(&[])
        .await
        .expect("delete_messages");

    assert!(
        server
            .received_requests()
            .await
            .expect("recording on")
            .is_empty()
    );
}

#[tokio::test]
async fn empty_deletes_with_encoded_label_id() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/mail/v4/messages/empty"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "Code": 1000 })))
        .expect(1)
        .mount(&server)
        .await;

    session(&server).empty("a&b=c").await.expect("empty");

    let reqs = server.received_requests().await.expect("recording on");
    let query: Vec<(String, String)> = reqs[0].url.query_pairs().into_owned().collect();

    assert_eq!(query, [("LabelID".to_owned(), "a&b=c".to_owned())]);
}
