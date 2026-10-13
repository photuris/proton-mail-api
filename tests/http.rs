//! Offline tests for the transport, against a wiremock server.

use std::time::{Duration, Instant};

use proton_mail_api::error::Error;
use proton_mail_api::http::{AuthTokens, Transport, TransportConfig};
use proton_mail_api::types::{ApiBool, ApiErrorBody, Empty};
use serde::Deserialize;
use serde_json::json;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A decoded success body.
#[derive(Debug, Deserialize)]
struct Thing {
    #[serde(rename = "Name")]
    name: String,
}

/// A transport pointed at `server` that allows `max_retries` retries.
fn transport(server: &MockServer, max_retries: u32) -> Transport {
    let mut config = TransportConfig::new("web-mail@test");

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

    let seen = server.received_requests().await.expect("recording is on");
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
    let requests = server.received_requests().await.expect("recording is on");

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
    let requests = server.received_requests().await.expect("recording is on");

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
    let requests = server.received_requests().await.expect("recording is on");

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
    let requests = server.received_requests().await.expect("recording is on");
    let refreshes = requests
        .iter()
        .filter(|r| r.url.path() == "/auth/v4/refresh")
        .count();

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
        methods: vec!["captcha".into()],
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
    assert!(
        matches!(&hv, Error::HumanVerificationRequired { token, .. } if token == "SECRETMARKER")
    );
}
