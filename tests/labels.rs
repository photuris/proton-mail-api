//! Offline tests for label listing, against a wiremock server.

use proton_mail_api::labels::{LabelType, system};
use proton_mail_api::session::{Client, PersistedSession, Session};
use serde_json::{Value, json};
use wiremock::matchers::{method, path, query_param};
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

/// Serves `labels` for `GET /core/v4/labels?Type=<kind>`.
async fn mount_labels(server: &MockServer, kind: &str, labels: Value) {
    Mock::given(method("GET"))
        .and(path("/core/v4/labels"))
        .and(query_param("Type", kind))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "Code": 1000, "Labels": labels })),
        )
        .mount(server)
        .await;
}

#[tokio::test]
async fn labels_fetches_all_three_types_in_order() {
    let server = MockServer::start().await;

    mount_labels(
        &server,
        "3",
        json!([{ "ID": "f1", "ParentID": null, "Name": "Work", "Path": "Work", "Color": "#fff", "Type": 3 }]),
    )
    .await;
    mount_labels(
        &server,
        "4",
        json!([
            { "ID": system::INBOX, "Name": "Inbox", "Path": "Inbox", "Color": "#fff", "Type": 4 },
            { "ID": system::ARCHIVE, "Name": "Archive", "Path": "Archive", "Color": "#fff", "Type": 4 },
        ]),
    )
    .await;
    mount_labels(
        &server,
        "1",
        json!([{ "ID": "l1", "ParentID": "", "Name": "Bills", "Path": "Bills", "Color": "#f00", "Type": 1 }]),
    )
    .await;

    let all = session(&server).labels().await.expect("labels load");
    let ids: Vec<&str> = all.iter().map(|l| l.id.as_str()).collect();

    assert_eq!(ids, ["l1", "f1", system::INBOX, system::ARCHIVE]);
    assert_eq!(all[0].name, "Bills");
    assert_eq!(all[0].color, "#f00");
    assert_eq!(all[1].path, "Work");
    assert_eq!(all[2].r#type, LabelType::System.as_i64());
}

#[tokio::test]
async fn label_parent_id_empty_string_is_none() {
    let server = MockServer::start().await;

    mount_labels(
        &server,
        "3",
        json!([
            { "ID": "top", "ParentID": "", "Name": "Top", "Type": 3 },
            { "ID": "nul", "ParentID": null, "Name": "Null", "Type": 3 },
            { "ID": "gone", "Name": "Absent", "Type": 3 },
            { "ID": "kid", "ParentID": "top", "Name": "Kid", "Path": "Top/Kid", "Type": 3 },
        ]),
    )
    .await;

    let folders = session(&server)
        .labels_of_type(LabelType::Folder)
        .await
        .expect("folders load");
    let parents: Vec<Option<&str>> = folders.iter().map(|l| l.parent_id.as_deref()).collect();

    assert_eq!(parents, [None, None, None, Some("top")]);
    assert_eq!(folders[2].path, "", "a missing Path reads as empty");
}

#[tokio::test]
async fn labels_of_type_sends_numeric_type() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/core/v4/labels"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "Code": 1000, "Labels": [] })),
        )
        .mount(&server)
        .await;

    let s = session(&server);

    for t in [LabelType::Label, LabelType::Folder, LabelType::System] {
        assert_eq!(LabelType::from_i64(t.as_i64()), Some(t));
        assert!(s.labels_of_type(t).await.expect("empty list").is_empty());
    }

    assert_eq!(
        LabelType::from_i64(2),
        None,
        "contact groups are not modelled"
    );

    let queries: Vec<String> = server
        .received_requests()
        .await
        .expect("recording is on")
        .iter()
        .map(|r| r.url.query().unwrap_or_default().to_owned())
        .collect();

    assert_eq!(queries, ["Type=1", "Type=3", "Type=4"]);
}
