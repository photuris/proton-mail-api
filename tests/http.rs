//! Offline tests for the transport, against a wiremock server.

use std::sync::Arc;
use std::time::{Duration, Instant};

use proton_mail_api::error::Error;
use proton_mail_api::http::{AuthTokens, Transport, TransportConfig};
use proton_mail_api::types::{ApiBool, ApiErrorBody, Empty};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::json;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The app version every test transport sends.
const APP_VERSION: &str = "web-mail@test";

/// A decoded success body.
#[derive(Debug, Deserialize)]
struct Thing {
    #[serde(rename = "Name")]
    name: String,
}

/// A transport pointed at `server` that allows `max_retries` retries.
fn transport(server: &MockServer, max_retries: u32) -> Transport {
    let mut config = TransportConfig::new(APP_VERSION);

    config.base_url = server.uri();
    config.max_retries = max_retries;

    Transport::new(reqwest::Client::new(), config).expect("valid config")
}

/// Tokens with recognisable values.
fn tokens(suffix: &str) -> AuthTokens {
    AuthTokens {
        uid: "uid-1".into(),
        access_token: format!("access-{suffix}"),
        refresh_token: format!("refresh-{suffix}"),
    }
}

/// Every request the transport sent to `server`, whatever the path. Requests
/// that lack the configured `x-pm-appversion` header are not the transport's
/// (the flake this guards against showed stray header-less hits on `/`), so
/// they are left out; any extra request the library itself makes still counts.
async fn transport_requests(server: &MockServer) -> Vec<wiremock::Request> {
    let all = server.received_requests().await.expect("recording is on");

    all.into_iter()
        .filter(|r| {
            r.headers
                .get("x-pm-appversion")
                .is_some_and(|v| v.to_str().is_ok_and(|v| v == APP_VERSION))
        })
        .collect()
}

/// How many of `requests` went to `path`.
fn count_to(requests: &[wiremock::Request], path: &str) -> usize {
    requests.iter().filter(|r| r.url.path() == path).count()
}

/// The 9001 envelope Proton sends for a human-verification challenge.
fn hv_body() -> serde_json::Value {
    json!({
        "Code": 9001,
        "Error": "Human verification required",
        "Details": {
            "HumanVerificationMethods": ["captcha"],
            "HumanVerificationToken": "tok"
        }
    })
}

/// The response of a successful `POST /auth/v4/refresh`.
fn refreshed() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "Code": 1000,
        "UID": "uid-1",
        "AccessToken": "access-new",
        "RefreshToken": "refresh-new"
    }))
}

#[tokio::test]
async fn sends_required_headers_with_and_without_tokens() {
    let server = MockServer::start().await;
    let t = transport(&server, 3);

    Mock::given(path("/ping"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Code": 1000})))
        .mount(&server)
        .await;

    t.get_json::<Empty>("/ping", &[])
        .await
        .expect("anonymous call");
    t.set_tokens(Some(tokens("a")));
    t.get_json::<Empty>("/ping", &[])
        .await
        .expect("authenticated call");

    let seen = transport_requests(&server).await;
    let value = |i: usize, name: &str| {
        seen[i]
            .headers
            .get(name)
            .map(|v| v.to_str().unwrap().to_owned())
    };

    assert_eq!(seen.len(), 2);
    assert_eq!(
        value(0, "x-pm-appversion").as_deref(),
        Some("web-mail@test")
    );
    assert_eq!(value(0, "accept").as_deref(), Some("application/json"));
    assert_eq!(value(0, "authorization"), None);
    assert_eq!(value(0, "x-pm-uid"), None);
    assert_eq!(
        value(1, "x-pm-appversion").as_deref(),
        Some("web-mail@test")
    );
    assert_eq!(
        value(1, "authorization").as_deref(),
        Some("Bearer access-a")
    );
    assert_eq!(value(1, "x-pm-uid").as_deref(), Some("uid-1"));
}

#[tokio::test]
async fn success_envelope_decodes_into_type() {
    let server = MockServer::start().await;
    let t = transport(&server, 3);

    Mock::given(path("/thing"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"Code": 1000, "Name": "widget"})),
        )
        .mount(&server)
        .await;
    Mock::given(path("/nothing"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let thing = t.get_json::<Thing>("/thing", &[]).await;
    let nothing = t.delete_json::<Empty>("/nothing").await;

    assert!(
        matches!(&thing, Ok(x) if x.name == "widget"),
        "got {thing:?}"
    );
    assert!(matches!(&nothing, Ok(Empty { code: 0 })), "got {nothing:?}");
}

#[tokio::test]
async fn human_verification_is_typed_and_not_retried() {
    let server = MockServer::start().await;
    let t = transport(&server, 3);

    Mock::given(path("/login"))
        .respond_with(ResponseTemplate::new(422).set_body_json(hv_body()))
        .expect(1)
        .mount(&server)
        .await;

    let got = t.post_json::<_, Empty>("/login", &json!({})).await;

    assert!(
        matches!(
            &got,
            Err(Error::HumanVerificationRequired { methods, token })
                if methods == &["captcha"] && token == "tok"
        ),
        "got {got:?}"
    );
}

#[tokio::test]
async fn challenge_on_429_is_typed_not_retried() {
    let server = MockServer::start().await;
    let t = transport(&server, 3);

    Mock::given(path("/login"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "0")
                .set_body_json(hv_body()),
        )
        .expect(1)
        .mount(&server)
        .await;

    let got = t.post_json::<_, Empty>("/login", &json!({})).await;
    let requests = transport_requests(&server).await;

    assert!(
        matches!(got, Err(Error::HumanVerificationRequired { .. })),
        "got {got:?}"
    );
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn rate_limit_honours_retry_after_then_succeeds() {
    let server = MockServer::start().await;
    let t = transport(&server, 3);

    Mock::given(path("/thing"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "1"))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/thing"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Name": "ok"})))
        .expect(1)
        .mount(&server)
        .await;

    let start = Instant::now();
    let got = t.get_json::<Thing>("/thing", &[]).await;
    let elapsed = start.elapsed();
    let requests = transport_requests(&server).await;

    assert!(matches!(&got, Ok(x) if x.name == "ok"), "got {got:?}");
    assert_eq!(requests.len(), 2);
    assert!(
        elapsed >= Duration::from_secs(1),
        "retried after only {elapsed:?}"
    );
    assert!(elapsed < Duration::from_secs(4), "waited {elapsed:?}");
}

#[tokio::test]
async fn rate_limit_exhausted_is_rate_limited_error() {
    let server = MockServer::start().await;
    let t = transport(&server, 1);

    Mock::given(path("/thing"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .mount(&server)
        .await;

    let got = t.get_json::<Empty>("/thing", &[]).await;
    let requests = transport_requests(&server).await;

    assert!(
        matches!(&got, Err(Error::RateLimited { retry_after }) if retry_after.is_zero()),
        "got {got:?}"
    );
    assert_eq!(requests.len(), 2);
}

#[tokio::test]
async fn app_version_rejected_on_5003() {
    let server = MockServer::start().await;
    let t = transport(&server, 3);

    Mock::given(path("/thing"))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(json!({"Code": 5003, "Error": "bad version"})),
        )
        .mount(&server)
        .await;

    let got = t.get_json::<Empty>("/thing", &[]).await;

    assert!(matches!(got, Err(Error::AppVersionRejected)), "got {got:?}");
}

#[tokio::test]
async fn unauthorized_refreshes_once_and_retries_with_new_token() {
    let server = MockServer::start().await;
    let t = transport(&server, 3);

    t.set_tokens(Some(tokens("old")));

    Mock::given(path("/thing"))
        .and(header("authorization", "Bearer access-old"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/auth/v4/refresh"))
        .and(header("x-pm-uid", "uid-1"))
        .and(body_partial_json(json!({
            "UID": "uid-1",
            "RefreshToken": "refresh-old",
            "ResponseType": "token",
            "GrantType": "refresh_token",
            "RedirectURI": "https://protonmail.ch"
        })))
        .respond_with(refreshed())
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/thing"))
        .and(header("authorization", "Bearer access-new"))
        .and(header("x-pm-uid", "uid-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Name": "ok"})))
        .expect(1)
        .mount(&server)
        .await;

    let got = t.get_json::<Thing>("/thing", &[]).await;
    let now = t.tokens().expect("tokens kept");

    assert!(matches!(&got, Ok(x) if x.name == "ok"), "got {got:?}");
    assert_eq!(now.access_token, "access-new");
    assert_eq!(now.refresh_token, "refresh-new");
}

#[tokio::test]
async fn refresh_failure_422_is_session_expired() {
    let server = MockServer::start().await;
    let t = transport(&server, 3);

    t.set_tokens(Some(tokens("old")));

    Mock::given(path("/thing"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/auth/v4/refresh"))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({"Code": 2001, "Error": "x"})))
        .expect(1)
        .mount(&server)
        .await;

    let got = t.get_json::<Empty>("/thing", &[]).await;

    assert!(matches!(got, Err(Error::SessionExpired)), "got {got:?}");
    assert!(
        t.tokens().is_some(),
        "tokens must not be cleared automatically"
    );
}

#[tokio::test]
async fn refresh_endpoint_401_is_session_expired_with_one_refresh() {
    let server = MockServer::start().await;
    let t = transport(&server, 3);

    t.set_tokens(Some(tokens("old")));

    Mock::given(path("/thing"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/auth/v4/refresh"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;

    let got = t.get_json::<Empty>("/thing", &[]).await;
    let requests = transport_requests(&server).await;
    let refreshes = count_to(&requests, "/auth/v4/refresh");

    assert!(matches!(got, Err(Error::SessionExpired)), "got {got:?}");
    assert_eq!(refreshes, 1);
    assert_eq!(requests.len(), 2);
}

#[tokio::test]
async fn invalid_json_is_invalid_response_without_body() {
    let server = MockServer::start().await;
    let t = transport(&server, 3);

    Mock::given(path("/thing"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json SECRETMARKER"))
        .mount(&server)
        .await;

    let err = t
        .get_json::<Thing>("/thing", &[])
        .await
        .expect_err("body is not json");

    assert!(matches!(err, Error::InvalidResponse), "got {err:?}");
    assert!(!format!("{err:?}").contains("SECRETMARKER"));
    assert!(!err.to_string().contains("SECRETMARKER"));
}

#[test]
fn api_bool_accepts_0_1_and_bool() {
    let parsed: Vec<ApiBool> = serde_json::from_str("[0, 1, false, true]").unwrap();

    assert_eq!(
        parsed,
        [ApiBool(false), ApiBool(true), ApiBool(false), ApiBool(true)]
    );
    assert_eq!(serde_json::to_string(&ApiBool(true)).unwrap(), "1");
    assert_eq!(serde_json::to_string(&ApiBool(false)).unwrap(), "0");
    assert!(serde_json::from_str::<ApiBool>("2").is_err());
}

#[test]
fn error_and_token_debug_are_redacted() {
    let t = tokens("SECRETTOKEN");
    let api = Error::Api {
        status: 422,
        code: 2001,
        message: "SECRETMARKER".into(),
    };
    let hv = Error::HumanVerificationRequired {
        methods: vec!["SECRETMARKER".into()],
        token: "SECRETMARKER".into(),
    };
    let envelope: ApiErrorBody = serde_json::from_value(json!({
        "Code": 9001,
        "Error": "SECRETMARKER",
        "Details": {"HumanVerificationToken": "SECRETMARKER"}
    }))
    .unwrap();

    let tokens_debug = format!("{t:?}");

    assert!(!tokens_debug.contains("SECRETTOKEN"), "{tokens_debug}");
    assert!(!tokens_debug.contains("uid-1"), "{tokens_debug}");
    assert!(!format!("{api:?}").contains("SECRETMARKER"));
    assert!(!format!("{hv:?}").contains("SECRETMARKER"));
    assert!(!format!("{envelope:?}").contains("SECRETMARKER"));
    assert!(format!("{api:?}").contains("2001"));
    assert!(format!("{hv:?}").contains("<1 items>"), "{hv:?}");
    assert!(
        matches!(&hv, Error::HumanVerificationRequired { token, .. } if token == "SECRETMARKER")
    );
}

#[tokio::test]
async fn concurrent_unauthorized_requests_share_one_refresh() {
    let server = MockServer::start().await;
    let t = transport(&server, 3);

    t.set_tokens(Some(tokens("old")));

    Mock::given(path("/thing"))
        .and(header("authorization", "Bearer access-old"))
        .respond_with(ResponseTemplate::new(401).set_delay(Duration::from_millis(100)))
        .expect(2)
        .mount(&server)
        .await;
    // Refresh tokens are single-use: a second exchange is refused.
    Mock::given(path("/auth/v4/refresh"))
        .respond_with(refreshed().set_delay(Duration::from_millis(200)))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(path("/auth/v4/refresh"))
        .respond_with(
            ResponseTemplate::new(422).set_body_json(json!({"Code": 10013, "Error": "used"})),
        )
        .mount(&server)
        .await;
    Mock::given(path("/thing"))
        .and(header("authorization", "Bearer access-new"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Name": "ok"})))
        .expect(2)
        .mount(&server)
        .await;

    let (a, b) = tokio::join!(
        t.get_json::<Thing>("/thing", &[]),
        t.get_json::<Thing>("/thing", &[]),
    );
    let requests = transport_requests(&server).await;
    let refreshes = count_to(&requests, "/auth/v4/refresh");
    assert!(matches!(&a, Ok(x) if x.name == "ok"), "got {a:?}");
    assert!(matches!(&b, Ok(x) if x.name == "ok"), "got {b:?}");
    assert_eq!(refreshes, 1);
    assert_eq!(requests.len(), 5);
    assert_eq!(t.tokens().expect("tokens kept").access_token, "access-new");
}

#[tokio::test]
async fn unauthorized_outranks_error_code_mappings() {
    // No tokens stored: a 401 carrying 5003.
    let server = MockServer::start().await;
    let t = transport(&server, 3);

    Mock::given(path("/thing"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({"Code": 5003, "Error": "version"})),
        )
        .mount(&server)
        .await;

    let anonymous = t.get_json::<Empty>("/thing", &[]).await;

    // The retry after a successful refresh answers 401 carrying 8002.
    let server = MockServer::start().await;
    let t = transport(&server, 3);

    t.set_tokens(Some(tokens("old")));

    Mock::given(path("/thing"))
        .and(header("authorization", "Bearer access-old"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    Mock::given(path("/thing"))
        .and(header("authorization", "Bearer access-new"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({"Code": 8002, "Error": "password"})),
        )
        .mount(&server)
        .await;
    Mock::given(path("/auth/v4/refresh"))
        .respond_with(refreshed())
        .mount(&server)
        .await;

    let retried = t.get_json::<Empty>("/thing", &[]).await;

    // The refresh endpoint itself answers 401 carrying 5001.
    let server = MockServer::start().await;
    let t = transport(&server, 3);

    t.set_tokens(Some(tokens("old")));

    Mock::given(path("/auth/v4/refresh"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({"Code": 5001, "Error": "version"})),
        )
        .mount(&server)
        .await;

    let refresh = t.refresh_tokens().await;

    assert!(
        matches!(anonymous, Err(Error::SessionExpired)),
        "got {anonymous:?}"
    );
    assert!(
        matches!(retried, Err(Error::SessionExpired)),
        "got {retried:?}"
    );
    assert!(
        matches!(refresh, Err(Error::SessionExpired)),
        "got {refresh:?}"
    );
}

#[tokio::test]
async fn explicit_code_zero_is_an_api_error() {
    let server = MockServer::start().await;
    let t = transport(&server, 3);

    Mock::given(path("/thing"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"Code": 0, "Error": "rejected"})),
        )
        .mount(&server)
        .await;

    let got = t.get_json::<Empty>("/thing", &[]).await;

    assert!(
        matches!(
            &got,
            Err(Error::Api { status: 200, code: 0, message }) if message == "rejected"
        ),
        "got {got:?}"
    );
}

#[tokio::test]
async fn huge_retry_after_is_capped_without_overflow() {
    let server = MockServer::start().await;
    let mut config = TransportConfig::new(APP_VERSION);

    config.base_url = server.uri();
    config.max_retries = 1;
    config.max_retry_wait = Duration::ZERO;

    let t = Arc::new(Transport::new(reqwest::Client::new(), config).expect("valid config"));

    Mock::given(path("/thing"))
        .respond_with(
            ResponseTemplate::new(429).insert_header("Retry-After", u64::MAX.to_string().as_str()),
        )
        .mount(&server)
        .await;

    // The jitter is random and only some draws overflow, so try many times.
    for attempt in 0..24 {
        let task = Arc::clone(&t);
        let joined = tokio::spawn(async move { task.get_json::<Empty>("/thing", &[]).await }).await;

        assert!(joined.is_ok(), "request panicked on attempt {attempt}");

        let got = joined.unwrap();

        assert!(
            matches!(
                &got,
                Err(Error::RateLimited { retry_after }) if *retry_after == Duration::from_secs(u64::MAX)
            ),
            "got {got:?}"
        );
    }
}

/// The 2028 envelope Proton sends when its anti-abuse system blocks a client.
fn blocked_body() -> serde_json::Value {
    json!({"Code": 2028, "Error": "unusual activity"})
}

#[tokio::test]
async fn blocked_2028_is_typed_with_reason_and_not_retried() {
    let server = MockServer::start().await;
    let t = transport(&server, 3);

    Mock::given(path("/login"))
        .respond_with(ResponseTemplate::new(422).set_body_json(blocked_body()))
        .mount(&server)
        .await;

    let got = t.post_json::<_, Empty>("/login", &json!({})).await;
    let requests = transport_requests(&server).await;

    assert!(matches!(&got, Err(Error::Blocked { .. })), "got {got:?}");
    assert_eq!(got.unwrap_err().server_message(), Some("unusual activity"));
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn blocked_2028_on_retryable_and_success_statuses_is_not_retried() {
    for (status, retry_after) in [(429, Some("0")), (503, Some("0")), (200, None)] {
        let server = MockServer::start().await;
        let t = transport(&server, 3);
        let mut response = ResponseTemplate::new(status).set_body_json(blocked_body());

        if let Some(wait) = retry_after {
            response = response.insert_header("Retry-After", wait);
        }

        Mock::given(path("/thing"))
            .respond_with(response)
            .mount(&server)
            .await;

        let got = t.get_json::<Empty>("/thing", &[]).await;
        let requests = transport_requests(&server).await;

        assert!(
            matches!(&got, Err(Error::Blocked { .. })),
            "status {status}: got {got:?}"
        );
        assert_eq!(requests.len(), 1, "status {status}");
    }
}

#[tokio::test]
async fn blocked_2028_on_401_and_on_refresh_does_not_refresh_again() {
    // (a) the call itself answers 401 carrying 2028.
    let server = MockServer::start().await;
    let t = transport(&server, 3);

    t.set_tokens(Some(tokens("old")));

    Mock::given(path("/thing"))
        .respond_with(ResponseTemplate::new(401).set_body_json(blocked_body()))
        .mount(&server)
        .await;
    Mock::given(path("/auth/v4/refresh"))
        .respond_with(refreshed())
        .mount(&server)
        .await;

    let on_call = t.get_json::<Empty>("/thing", &[]).await;
    let requests = transport_requests(&server).await;

    assert!(
        matches!(&on_call, Err(Error::Blocked { .. })),
        "got {on_call:?}"
    );
    assert_eq!(count_to(&requests, "/auth/v4/refresh"), 0);
    assert_eq!(requests.len(), 1);

    // (b) a plain 401, then the refresh answers 2028.
    let server = MockServer::start().await;
    let t = transport(&server, 3);

    t.set_tokens(Some(tokens("old")));

    Mock::given(path("/thing"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    Mock::given(path("/auth/v4/refresh"))
        .respond_with(ResponseTemplate::new(422).set_body_json(blocked_body()))
        .mount(&server)
        .await;

    let on_refresh = t.get_json::<Empty>("/thing", &[]).await;
    let requests = transport_requests(&server).await;

    assert!(
        matches!(&on_refresh, Err(Error::Blocked { .. })),
        "got {on_refresh:?}"
    );
    assert_eq!(count_to(&requests, "/auth/v4/refresh"), 1);
    assert_eq!(count_to(&requests, "/thing"), 1);
    assert_eq!(requests.len(), 2);
}

/// The error a 422 carrying `body` produces, from a fresh server.
async fn error_for(body: serde_json::Value) -> Error {
    let server = MockServer::start().await;
    let t = transport(&server, 0);

    Mock::given(path("/x"))
        .respond_with(ResponseTemplate::new(422).set_body_json(body))
        .mount(&server)
        .await;

    t.get_json::<Empty>("/x", &[]).await.unwrap_err()
}

#[tokio::test]
async fn blocked_debug_and_server_message_contract() {
    let blocked = error_for(json!({"Code": 2028, "Error": "SECRETMARKER"})).await;
    let bare = error_for(json!({"Code": 2028})).await;
    let api = error_for(json!({"Code": 2001, "Error": "bad value"})).await;
    let api_bare = error_for(json!({"Code": 2001})).await;

    assert!(matches!(&blocked, Error::Blocked { .. }), "got {blocked:?}");
    assert!(!format!("{blocked:?}").contains("SECRETMARKER"));
    assert!(!blocked.to_string().contains("SECRETMARKER"));
    assert_eq!(blocked.server_message(), Some("SECRETMARKER"));
    assert!(
        matches!(&bare, Error::Blocked { message } if message.is_empty()),
        "got {bare:?}"
    );
    assert_eq!(format!("{bare:?}"), r#"Blocked { message: "<redacted>" }"#);
    assert_eq!(bare.server_message(), None);
    assert!(matches!(&api, Error::Api { code: 2001, .. }), "got {api:?}");
    assert_eq!(api.server_message(), Some("bad value"));
    assert_eq!(api_bare.server_message(), None);
    assert_eq!(Error::WrongPassword.server_message(), None);
}

#[tokio::test]
async fn user_agent_default_custom_and_invalid() {
    let user_agents = |requests: &[wiremock::Request]| -> Vec<String> {
        requests
            .iter()
            .map(|r| {
                r.headers
                    .get("user-agent")
                    .map(|v| v.to_str().unwrap().to_owned())
                    .unwrap_or_default()
            })
            .collect()
    };

    // Default.
    let server = MockServer::start().await;
    let t = transport(&server, 0);

    Mock::given(path("/ping"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Code": 1000})))
        .mount(&server)
        .await;
    t.get_json::<Empty>("/ping", &[]).await.expect("call");

    let expected = format!(
        "proton-mail-api/{} ({})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS
    );

    assert_eq!(user_agents(&transport_requests(&server).await), [expected]);

    // Custom, on a normal request and on the refresh request.
    let server = MockServer::start().await;
    let mut config = TransportConfig::new(APP_VERSION);

    config.base_url = server.uri();
    config.user_agent = "posto/0.1 (linux)".into();

    let t = Transport::new(reqwest::Client::new(), config).expect("valid config");

    t.set_tokens(Some(tokens("old")));
    Mock::given(path("/ping"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Code": 1000})))
        .mount(&server)
        .await;
    Mock::given(path("/auth/v4/refresh"))
        .respond_with(refreshed())
        .mount(&server)
        .await;
    t.get_json::<Empty>("/ping", &[]).await.expect("call");
    t.refresh_tokens().await.expect("refresh");

    let requests = transport_requests(&server).await;

    assert_eq!(count_to(&requests, "/ping"), 1);
    assert_eq!(count_to(&requests, "/auth/v4/refresh"), 1);
    assert_eq!(
        user_agents(&requests),
        ["posto/0.1 (linux)", "posto/0.1 (linux)"]
    );

    // Invalid.
    for bad in ["", "bad\nua"] {
        let mut config = TransportConfig::new(APP_VERSION);

        config.user_agent = bad.into();

        let err = Transport::new(reqwest::Client::new(), config)
            .err()
            .expect("rejected");

        assert!(
            matches!(
                err,
                Error::InvalidConfig("user agent is not a valid header value")
            ),
            "got {err:?}"
        );
        assert!(!err.to_string().contains("bad"));
        assert!(!format!("{err:?}").contains("bad"));
    }
}

/// A body whose serialisation fails with text that must never be shown.
struct FailedBody;

impl Serialize for FailedBody {
    fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom("PASSWORDMARKER"))
    }
}

#[tokio::test]
async fn json_body_build_error_is_static_and_redacted() {
    let server = MockServer::start().await;
    let t = transport(&server, 2);

    t.set_tokens(Some(tokens("old")));

    let got = t
        .post_json_once::<_, serde_json::Value>("/review", &FailedBody)
        .await;
    let shown = format!("{got:?}");

    assert!(
        matches!(
            &got,
            Err(Error::InvalidConfig("request body cannot be replayed"))
        ),
        "got {shown}"
    );
    assert!(!shown.contains("PASSWORDMARKER"), "Debug leaks: {shown}");
    assert!(
        !got.expect_err("an error")
            .to_string()
            .contains("PASSWORDMARKER"),
        "Display leaks"
    );
    assert!(transport_requests(&server).await.is_empty(), "nothing sent");
}
