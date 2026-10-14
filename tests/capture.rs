//! Fixture capture against the real Proton API, plus an offline test of its
//! `raw_get` seam.
//!
//! `capture_live_fixtures` runs only when `PROTON_CAPTURE=1`; it is never run
//! in CI. It only reads (GET). Each response is parsed as JSON, scrubbed
//! (see `support/scrub.rs`) and staged in `tests/fixtures/live.tmp`; the
//! stage replaces `tests/fixtures/live` only when every file was captured.
//! Raw bodies are never written or printed, and failure messages carry the
//! step name and the crate's error text only.
//!
//! Variables: `PROTON_USERNAME`, `PROTON_PASSWORD`, `PROTON_APP_VERSION`
//! (required) and `PROTON_TOTP`, `PROTON_USER_AGENT` (optional).

#[path = "support/scrub.rs"]
mod scrub;

use std::path::{Path, PathBuf};
use std::{env, fs, io};

use proton_mail_api::session::{Client, PersistedSession, Session};
use scrub::Scrubber;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Every file a complete capture stages.
const FILES: [&str; 10] = [
    "users.json",
    "addresses.json",
    "key_salts.json",
    "labels_1.json",
    "labels_3.json",
    "labels_4.json",
    "messages_inbox.json",
    "message.json",
    "events_latest.json",
    "event.json",
];

/// A variable that is set and not empty.
fn var(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
}

/// A variable the capture cannot run without.
fn required(name: &str) -> String {
    var(name).unwrap_or_else(|| panic!("{name} required"))
}

/// Percent-encodes `s` as one path segment, with the crate's rule: every byte
/// outside `A-Za-z0-9-_~` becomes uppercase `%XX`.
fn path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());

    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }

    out
}

/// Stages scrubbed responses and collects failures.
struct Capture<'a> {
    session: &'a Session,
    scrubber: Scrubber,
    dir: PathBuf,
    failures: Vec<String>,
}

impl Capture<'_> {
    /// GETs `request`, stages the scrubbed JSON as `file` and returns the
    /// unscrubbed value for the caller to pick ids from. Records a failure
    /// and returns `None` on any problem.
    async fn get(&mut self, file: &str, request: &str) -> Option<Value> {
        let body = match self.session.raw_get(request).await {
            Ok(body) => body,
            Err(e) => {
                self.failures.push(format!("{file}: {e}"));
                return None;
            }
        };
        let Ok(value) = serde_json::from_slice::<Value>(&body) else {
            self.failures.push(format!("{file}: response is not JSON"));
            return None;
        };

        drop(body);

        let scrubbed = self.scrubber.scrub(&value);
        let text = match serde_json::to_string_pretty(&scrubbed) {
            Ok(text) => text,
            Err(e) => {
                self.failures.push(format!("{file}: {e}"));
                return None;
            }
        };

        if let Err(e) = fs::write(self.dir.join(file), format!("{text}\n")) {
            self.failures.push(format!("{file}: {e}"));
            return None;
        }

        eprintln!("captured {file}");
        Some(value)
    }

    /// Every GET of the capture, in order.
    async fn run(&mut self) {
        for (file, request) in [
            ("users.json", "/core/v4/users"),
            ("addresses.json", "/core/v4/addresses"),
            ("key_salts.json", "/core/v4/keys/salts"),
            ("labels_1.json", "/core/v4/labels?Type=1"),
            ("labels_3.json", "/core/v4/labels?Type=3"),
            ("labels_4.json", "/core/v4/labels?Type=4"),
        ] {
            self.get(file, request).await;
        }

        let list = self
            .get(
                "messages_inbox.json",
                "/mail/v4/messages?LabelID=0&Page=0&PageSize=3&Sort=Time&Desc=1",
            )
            .await;

        if let Some(list) = list {
            match list["Messages"][0]["ID"].as_str() {
                Some(id) => {
                    let request = format!("/mail/v4/messages/{}", path_segment(id));

                    self.get("message.json", &request).await;
                }
                None => self
                    .failures
                    .push("capture needs at least one Inbox message".to_string()),
            }
        }

        let latest = self
            .get("events_latest.json", "/core/v4/events/latest")
            .await;

        if let Some(latest) = latest {
            match latest["EventID"].as_str() {
                Some(id) => {
                    let request = format!("/core/v4/events/{}", path_segment(id));

                    // A quiet account has no message changes here; expected.
                    self.get("event.json", &request).await;
                }
                None => self
                    .failures
                    .push("latest event has no EventID".to_string()),
            }
        }
    }
}

/// Replaces `live` with `live.tmp`, keeping the old `live` until the new one
/// is in place.
fn publish(fixtures: &Path) -> io::Result<()> {
    let (live, old, tmp) = (
        fixtures.join("live"),
        fixtures.join("live.old"),
        fixtures.join("live.tmp"),
    );

    // A leftover from an interrupted earlier run.
    let _ = fs::remove_dir_all(&old);

    let had_live = live.exists();

    if had_live {
        fs::rename(&live, &old)?;
    }

    if let Err(e) = fs::rename(&tmp, &live) {
        if had_live {
            let _ = fs::rename(&old, &live);
        }

        return Err(e);
    }

    let _ = fs::remove_dir_all(&old);

    Ok(())
}

/// A blob built the way a consumer's store would hand it back.
fn blob(uid: &str, access: &str, refresh: &str) -> PersistedSession {
    serde_json::from_value(json!({
        "uid": uid,
        "access_token": access,
        "refresh_token": refresh,
        "password_mode": "Single",
        "scope": "full",
        "key_password": null,
    }))
    .expect("blob parses")
}

#[tokio::test]
async fn raw_get_returns_raw_body_with_query() {
    let server = MockServer::start().await;
    let body: &[u8] = b"not json \x00\xff raw";

    Mock::given(method("GET"))
        .and(path("/x"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let client = Client::builder()
        .app_version("web-mail@test")
        .base_url(server.uri())
        .max_retries(0)
        .build()
        .expect("valid config");
    let session = client
        .resume(blob("uid-1", "access-1", "refresh-1"))
        .expect("resume succeeds");

    let got = session.raw_get("/x?y=1").await.expect("raw_get succeeds");

    assert_eq!(got, body);

    let requests = server.received_requests().await.expect("requests recorded");

    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.query(), Some("y=1"));
}

#[tokio::test]
async fn capture_live_fixtures() {
    if env::var("PROTON_CAPTURE").as_deref() != Ok("1") {
        eprintln!("capture skipped");
        return;
    }

    let username = required("PROTON_USERNAME");
    let password = required("PROTON_PASSWORD");
    let app_version = required("PROTON_APP_VERSION");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let tmp = fixtures.join("live.tmp");

    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap_or_else(|e| panic!("clearing live.tmp: {e}"));
    }

    fs::create_dir_all(&tmp).unwrap_or_else(|e| panic!("creating live.tmp: {e}"));

    let mut failures: Vec<String> = Vec::new();
    let mut builder = Client::builder().app_version(app_version);

    if let Some(user_agent) = var("PROTON_USER_AGENT") {
        builder = builder.user_agent(user_agent);
    }

    match builder.build() {
        Err(e) => failures.push(format!("build client: {e}")),
        Ok(client) => match client.login(&username, &password).await {
            Err(e) => failures.push(format!("login: {e}")),
            Ok(outcome) => {
                let session = outcome.session;
                let mut ready = true;

                if outcome.needs_totp {
                    ready = match var("PROTON_TOTP") {
                        Some(code) => match session.submit_totp(&code).await {
                            Ok(()) => true,
                            Err(e) => {
                                failures.push(format!("submit totp: {e}"));
                                false
                            }
                        },
                        None => {
                            failures.push("PROTON_TOTP required".to_string());
                            false
                        }
                    };
                }

                if ready {
                    let mut capture = Capture {
                        session: &session,
                        scrubber: Scrubber::new(),
                        dir: tmp.clone(),
                        failures: Vec::new(),
                    };

                    capture.run().await;
                    failures.append(&mut capture.failures);
                }

                if let Err(e) = session.logout().await {
                    failures.push(format!("logout: {e}"));
                }
            }
        },
    }

    for file in FILES {
        if !tmp.join(file).exists() {
            failures.push(format!("missing {file}"));
        }
    }

    if failures.is_empty() && publish(&fixtures).is_err() {
        failures.push("publishing fixtures failed".to_string());
    }

    if !failures.is_empty() {
        let _ = fs::remove_dir_all(&tmp);

        panic!("{}", failures.join("; "));
    }

    eprintln!("captured {} files", FILES.len());
}
