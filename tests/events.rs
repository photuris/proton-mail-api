//! Offline tests for the change-event feed, against a wiremock server.

use proton_mail_api::events::{Event, EventAction};
use proton_mail_api::session::{Client, PersistedSession, Session};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A resumed session pointed at `server`.
fn session(server: &MockServer) -> Session {
    let client = Client::builder()
        .app_version("web-mail@test")
        .base_url(server.uri())
        .max_retries(0)
        .build()
        .expect("valid config");
    let blob: PersistedSession = serde_json::from_value(json!({
        "uid": "uid-1",
        "access_token": "access-1",
        "refresh_token": "refresh-1",
        "password_mode": "Single",
        "scope": "full",
        "key_password": null,
    }))
    .expect("blob parses");

    client.resume(blob).expect("blob resumes")
}

/// Serves `body` for `GET <p>`.
async fn mount_get(server: &MockServer, p: &str, body: Value) {
    Mock::given(method("GET"))
        .and(path(p))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

#[tokio::test]
async fn latest_event_id_parses() {
    let server = MockServer::start().await;

    mount_get(
        &server,
        "/core/v4/events/latest",
        json!({ "Code": 1000, "EventID": "ev-latest", "Unknown": [1, 2] }),
    )
    .await;

    let id = session(&server)
        .latest_event_id()
        .await
        .expect("latest id loads");

    assert_eq!(id, "ev-latest");
}

#[tokio::test]
async fn events_parses_message_and_label_actions() {
    let server = MockServer::start().await;

    mount_get(
        &server,
        "/core/v4/events/e0",
        json!({
            "Code": 1000,
            "EventID": "e1",
            "More": 0,
            "Refresh": 0,
            "Messages": [
                { "ID": "m1", "Action": 1, "Message": { "ID": "m1", "Subject": "hi", "Unread": 1 } },
                { "ID": "m2", "Action": 3, "Message": { "ID": "m2", "Unread": 0 } },
            ],
            "Labels": [ { "ID": "l1", "Action": 0 } ],
            "MessageCounts": [ { "LabelID": "0", "Total": 3, "Unread": 1 } ],
        }),
    )
    .await;

    let batch = session(&server).events("e0").await.expect("events load");

    assert_eq!(batch.events.len(), 1);
    assert!(!batch.more);
    assert_eq!(batch.latest_event_id, "e1");

    let event = &batch.events[0];

    assert_eq!(event.messages.len(), 2);
    assert_eq!(event.messages[0].id, "m1");
    assert_eq!(
        EventAction::from_i64(event.messages[0].action),
        Some(EventAction::Create)
    );
    assert_eq!(
        event.messages[0].message.as_ref().expect("payload kept")["Subject"],
        "hi"
    );
    assert_eq!(event.messages[1].id, "m2");
    assert_eq!(
        EventAction::from_i64(event.messages[1].action),
        Some(EventAction::UpdateFlags)
    );

    assert_eq!(event.labels.len(), 1);
    assert_eq!(event.labels[0].id, "l1");
    assert_eq!(
        EventAction::from_i64(event.labels[0].action),
        Some(EventAction::Delete)
    );
    assert!(event.labels[0].label.is_none(), "a delete carries no label");

    assert_eq!(EventAction::from_i64(2), Some(EventAction::Update));
    assert_eq!(EventAction::from_i64(9), None);
}

#[tokio::test]
async fn events_follows_more_chain() {
    let server = MockServer::start().await;

    mount_get(
        &server,
        "/core/v4/events/e0",
        json!({ "EventID": "e1", "More": 1 }),
    )
    .await;
    mount_get(
        &server,
        "/core/v4/events/e1",
        json!({ "EventID": "e2", "More": 1 }),
    )
    .await;
    mount_get(
        &server,
        "/core/v4/events/e2",
        json!({ "EventID": "e3", "More": 0 }),
    )
    .await;

    let batch = session(&server).events("e0").await.expect("events load");
    let ids: Vec<&str> = batch.events.iter().map(|e| e.event_id.as_str()).collect();

    assert_eq!(ids, ["e1", "e2", "e3"]);
    assert!(!batch.more);
    assert_eq!(batch.latest_event_id, "e3");
}

#[tokio::test]
async fn events_null_arrays_are_empty() {
    let server = MockServer::start().await;

    mount_get(
        &server,
        "/core/v4/events/e0",
        json!({ "Code": 1000, "EventID": "e0", "More": 0, "Messages": null, "Labels": null }),
    )
    .await;

    let batch = session(&server)
        .events("e0")
        .await
        .expect("null arrays parse");

    assert_eq!(
        batch.events.len(),
        1,
        "an event that repeats `since` is kept"
    );
    assert!(batch.events[0].messages.is_empty());
    assert!(batch.events[0].labels.is_empty());
    assert_eq!(batch.latest_event_id, "e0");
}

#[test]
fn refresh_bit_sets_requires_resync() {
    let resync = |refresh: i64| {
        serde_json::from_value::<Event>(json!({ "EventID": "e", "Refresh": refresh }))
            .expect("event parses")
            .requires_resync()
    };

    assert!(!resync(0));
    assert!(resync(1));
    assert!(!resync(2), "only bit 1 means a mail resync");
    assert!(resync(3));
    assert!(resync(255));
}
