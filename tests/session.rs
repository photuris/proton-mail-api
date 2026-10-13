//! Offline tests for `Client` and `Session`, against a wiremock server and
//! the go-srp vector in `fixtures/srp-vectors.json`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use proton_mail_api::error::Error;
use proton_mail_api::session::{Client, PasswordMode, PersistedSession, Session};
use proton_mail_api::srp::SrpError;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// The app version every test client sends.
const APP_VERSION: &str = "web-mail@test";

/// The captured go-srp vector.
fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/srp-vectors.json")).expect("fixture parses")
}

/// A string field of a JSON object.
fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().expect("string field")
}

/// A client pointed at `server`; with `seam` it uses the vector's client secret.
fn client(server: &MockServer, seam: bool) -> Client {
    let mut builder = Client::builder()
        .app_version(APP_VERSION)
        .base_url(server.uri())
        .max_retries(0);

    if seam {
        let secret = B64
            .decode(text(&vectors(), "client_secret_b64"))
            .expect("secret decodes");

        builder = builder.srp_client_secret(secret);
    }

    builder.build().expect("valid config")
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

/// Serves the `/auth/v4/info` reply for the vector, with the given `Version`.
async fn mount_info(server: &MockServer, version: u32) {
    let v = vectors();

    Mock::given(method("POST"))
        .and(path("/auth/v4/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Code": 1000,
            "Version": version,
            "Modulus": text(&v, "modulus_clearsigned"),
            "ServerEphemeral": text(&v, "server_ephemeral_b64"),
            "Salt": text(&v, "salt_b64"),
            "SRPSession": "srp-session-1",
        })))
        .mount(server)
        .await;
}

/// Serves a successful `/auth/v4` reply with the given proof and 2FA bitmask.
async fn mount_auth(server: &MockServer, server_proof: &str, two_fa: u32, password_mode: u32) {
    Mock::given(method("POST"))
        .and(path("/auth/v4"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Code": 1000,
            "UID": "uid-1",
            "AccessToken": "access-1",
            "RefreshToken": "refresh-1",
            "ServerProof": server_proof,
            "Scope": "full self",
            "PasswordMode": password_mode,
            "2FA": { "Enabled": two_fa },
        })))
        .mount(server)
        .await;
}

/// Every request `server` saw for `method_name` and `p`.
async fn requests_to(server: &MockServer, method_name: &str, p: &str) -> Vec<Request> {
    server
        .received_requests()
        .await
        .expect("recording is on")
        .into_iter()
        .filter(|r| r.method.as_str() == method_name && r.url.path() == p)
        .collect()
}

/// A request header as text.
fn header(r: &Request, name: &str) -> Option<String> {
    r.headers
        .get(name)
        .map(|v| v.to_str().expect("ascii header").to_owned())
}

/// A request body as JSON.
fn body(r: &Request) -> Value {
    serde_json::from_slice(&r.body).expect("json body")
}

/// The persisted form of `session` as JSON.
fn persisted(session: &Session) -> Value {
    serde_json::to_value(session.persist()).expect("blob serialises")
}

#[tokio::test]
async fn login_without_2fa_returns_session_with_tokens() {
    let server = MockServer::start().await;
    let v = vectors();
    let proof = text(&v, "expected_server_proof_b64");

    mount_info(&server, 4).await;
    mount_auth(&server, proof, 0, 1).await;

    let missing = Client::builder().build();

    assert!(
        matches!(
            missing,
            Err(Error::InvalidConfig("app_version is required"))
        ),
        "missing app_version must be rejected"
    );

    let outcome = client(&server, true)
        .login(text(&v, "username"), text(&v, "password"))
        .await
        .expect("login succeeds");

    assert!(!outcome.needs_totp, "no 2FA expected");
    assert_eq!(outcome.password_mode, PasswordMode::Single);
    assert_eq!(outcome.scope, "full self");
    assert_eq!(outcome.session.password_mode(), PasswordMode::Single);
    assert_eq!(outcome.session.uid(), "uid-1");

    let saved = persisted(&outcome.session);

    assert!(text(&saved, "access_token") == "access-1", "access token");
    assert!(
        text(&saved, "refresh_token") == "refresh-1",
        "refresh token"
    );
    assert!(text(&saved, "scope") == "full self", "scope");

    let info = requests_to(&server, "POST", "/auth/v4/info").await;

    assert_eq!(info.len(), 1);
    assert_eq!(body(&info[0]), json!({ "Username": text(&v, "username") }));
    assert_eq!(
        header(&info[0], "x-pm-appversion").as_deref(),
        Some(APP_VERSION)
    );

    let auth = requests_to(&server, "POST", "/auth/v4").await;

    assert_eq!(auth.len(), 1);

    let sent = body(&auth[0]);

    assert!(text(&sent, "Username") == text(&v, "username"), "username");
    assert!(
        text(&sent, "ClientEphemeral") == text(&v, "client_ephemeral_b64"),
        "client ephemeral"
    );
    assert!(
        text(&sent, "ClientProof") == text(&v, "client_proof_b64"),
        "client proof"
    );
    assert!(text(&sent, "SRPSession") == "srp-session-1", "srp session");
}

#[tokio::test]
async fn login_with_wrong_server_proof_is_crypto_error() {
    let server = MockServer::start().await;
    let v = vectors();
    let wrong = B64.encode([7u8; 256]);

    mount_info(&server, 4).await;
    mount_auth(&server, &wrong, 0, 1).await;

    let result = client(&server, true)
        .login(text(&v, "username"), text(&v, "password"))
        .await;

    assert!(
        matches!(result, Err(Error::Crypto("server proof mismatch"))),
        "a wrong server proof must be a crypto error"
    );
}

#[tokio::test]
async fn login_reports_totp_required_and_submit_totp_posts_code() {
    let server = MockServer::start().await;
    let v = vectors();

    mount_info(&server, 4).await;
    mount_auth(&server, text(&v, "expected_server_proof_b64"), 1, 2).await;
    Mock::given(method("POST"))
        .and(path("/auth/v4/2fa"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Code": 1000,
            "Scope": "full self twofactor",
        })))
        .mount(&server)
        .await;

    let outcome = client(&server, true)
        .login(text(&v, "username"), text(&v, "password"))
        .await
        .expect("login succeeds");

    assert!(outcome.needs_totp, "2FA bit 1 means TOTP is required");
    assert_eq!(outcome.password_mode, PasswordMode::Two);
    assert!(
        requests_to(&server, "POST", "/auth/v4/2fa")
            .await
            .is_empty(),
        "login must not submit a code"
    );

    outcome
        .session
        .submit_totp("123456")
        .await
        .expect("code accepted");

    let sent = requests_to(&server, "POST", "/auth/v4/2fa").await;

    assert_eq!(sent.len(), 1);
    assert_eq!(body(&sent[0]), json!({ "TwoFactorCode": "123456" }));
    assert_eq!(header(&sent[0], "x-pm-uid").as_deref(), Some("uid-1"));
    assert!(
        header(&sent[0], "authorization").as_deref() == Some("Bearer access-1"),
        "bearer token"
    );

    let saved = persisted(&outcome.session);

    assert!(
        text(&saved, "scope") == "full self twofactor",
        "scope from the 2FA reply is stored"
    );
}

#[tokio::test]
async fn wrong_password_8002_is_wrong_password() {
    let server = MockServer::start().await;
    let v = vectors();

    mount_info(&server, 4).await;
    Mock::given(method("POST"))
        .and(path("/auth/v4"))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "Code": 8002,
            "Error": "Incorrect login credentials",
        })))
        .mount(&server)
        .await;

    let result = client(&server, true)
        .login(text(&v, "username"), "not the password")
        .await;

    assert!(
        matches!(result, Err(Error::WrongPassword)),
        "8002 must surface as WrongPassword"
    );
}

#[tokio::test]
async fn human_verification_on_auth_is_typed() {
    let server = MockServer::start().await;
    let v = vectors();

    mount_info(&server, 4).await;
    Mock::given(method("POST"))
        .and(path("/auth/v4"))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "Code": 9001,
            "Error": "Human verification required",
            "Details": {
                "HumanVerificationMethods": ["captcha"],
                "HumanVerificationToken": "hv-token",
            },
        })))
        .mount(&server)
        .await;

    // Allow retries: a verification challenge must still be sent only once.
    let retrying = Client::builder()
        .app_version(APP_VERSION)
        .base_url(server.uri())
        .max_retries(3)
        .build()
        .expect("valid config");
    let result = retrying
        .login(text(&v, "username"), text(&v, "password"))
        .await;

    match result {
        Err(Error::HumanVerificationRequired { methods, token }) => {
            assert_eq!(methods, ["captcha"]);
            assert!(token == "hv-token", "verification token");
        }
        _ => panic!("expected a human-verification error"),
    }

    assert_eq!(
        requests_to(&server, "POST", "/auth/v4").await.len(),
        1,
        "a verification challenge is never retried"
    );
}

#[tokio::test]
async fn unsupported_auth_version_is_srp_error() {
    let server = MockServer::start().await;
    let v = vectors();

    mount_info(&server, 2).await;

    let result = client(&server, true)
        .login(text(&v, "username"), text(&v, "password"))
        .await;

    assert!(
        matches!(result, Err(Error::Srp(SrpError::UnsupportedVersion(2)))),
        "version 2 must be an SRP error"
    );
    assert!(
        requests_to(&server, "POST", "/auth/v4").await.is_empty(),
        "no proof is sent for an unsupported version"
    );
}

#[tokio::test]
async fn resume_then_refresh_updates_persisted_tokens() {
    let server = MockServer::start().await;
    let client = client(&server, false);

    for (uid, access, refresh) in [("", "a", "r"), ("u", "", "r"), ("u", "a", "")] {
        assert!(
            matches!(
                client.resume(blob(uid, access, refresh)),
                Err(Error::InvalidResponse)
            ),
            "an empty uid or token must be rejected"
        );
    }

    Mock::given(method("POST"))
        .and(path("/auth/v4/refresh"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Code": 1000,
            "UID": "uid-r",
            "AccessToken": "access-new",
            "RefreshToken": "refresh-new",
        })))
        .mount(&server)
        .await;

    let session = client
        .resume(blob("uid-r", "access-old", "refresh-old"))
        .expect("resume succeeds");

    assert!(
        server
            .received_requests()
            .await
            .expect("recording")
            .is_empty(),
        "resume makes no network call"
    );

    session.refresh().await.expect("refresh succeeds");

    let saved = persisted(&session);

    assert!(text(&saved, "uid") == "uid-r", "uid");
    assert!(text(&saved, "access_token") == "access-new", "access token");
    assert!(
        text(&saved, "refresh_token") == "refresh-new",
        "refresh token"
    );
    assert!(text(&saved, "scope") == "full", "scope survives refresh");

    let sent = requests_to(&server, "POST", "/auth/v4/refresh").await;

    assert_eq!(sent.len(), 1);
    assert!(
        text(&body(&sent[0]), "RefreshToken") == "refresh-old",
        "refresh sends the old refresh token"
    );
}

#[tokio::test]
async fn two_sessions_on_one_client_do_not_share_tokens() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<Session>();

    let server = MockServer::start().await;
    let client = client(&server, false);

    Mock::given(method("POST"))
        .and(path("/auth/v4/2fa"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "Code": 1000 })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/auth/v4"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "Code": 1000 })))
        .mount(&server)
        .await;

    let a = client
        .resume(blob("uid-a", "access-a", "refresh-a"))
        .expect("resume a");
    let b = client
        .resume(blob("uid-b", "access-b", "refresh-b"))
        .expect("resume b");

    a.submit_totp("111111").await.expect("a posts");
    b.submit_totp("222222").await.expect("b posts");

    let sent = requests_to(&server, "POST", "/auth/v4/2fa").await;

    assert_eq!(sent.len(), 2);

    for (r, uid, bearer) in [
        (&sent[0], "uid-a", "Bearer access-a"),
        (&sent[1], "uid-b", "Bearer access-b"),
    ] {
        assert_eq!(header(r, "x-pm-uid").as_deref(), Some(uid));
        assert!(
            header(r, "authorization").as_deref() == Some(bearer),
            "each session sends its own bearer token"
        );
    }

    a.logout().await.expect("a logs out");

    let left = persisted(&b);

    assert!(text(&left, "uid") == "uid-b", "b keeps its uid");
    assert!(
        text(&left, "access_token") == "access-b",
        "b keeps its access token"
    );
    assert!(
        text(&left, "refresh_token") == "refresh-b",
        "b keeps its refresh token"
    );
}

#[tokio::test]
async fn logout_sends_delete_with_uid_header() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/auth/v4"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "Code": 1000 })))
        .mount(&server)
        .await;

    let session = client(&server, false)
        .resume(blob("uid-out", "access-out", "refresh-out"))
        .expect("resume succeeds");
    let result = session.logout().await;
    let sent = requests_to(&server, "DELETE", "/auth/v4").await;

    assert!(result.is_ok(), "logout succeeds on {{Code:1000}}");
    assert_eq!(sent.len(), 1);
    assert_eq!(header(&sent[0], "x-pm-uid").as_deref(), Some("uid-out"));
    assert!(
        header(&sent[0], "authorization").as_deref() == Some("Bearer access-out"),
        "bearer token"
    );
}

#[tokio::test]
async fn persisted_session_json_roundtrips_and_debug_is_redacted() {
    let server = MockServer::start().await;
    let original = json!({
        "uid": "uid-secret-xyz",
        "access_token": "access-secret-xyz",
        "refresh_token": "refresh-secret-xyz",
        "password_mode": "Two",
        "scope": "full self",
        "key_password": "keypass-secret-xyz",
    });
    let parsed: PersistedSession = serde_json::from_value(original.clone()).expect("blob parses");
    let again = serde_json::to_value(&parsed).expect("blob serialises");

    for key in [
        "uid",
        "access_token",
        "refresh_token",
        "password_mode",
        "scope",
        "key_password",
    ] {
        assert!(again[key] == original[key], "field {key} differs");
    }

    assert!(parsed.uid() == "uid-secret-xyz", "uid accessor");

    // A resumed session carries the blob, key password included.
    let session = client(&server, false)
        .resume(parsed.clone())
        .expect("resume succeeds");
    let resumed = persisted(&session);

    for key in ["uid", "access_token", "refresh_token", "key_password"] {
        assert!(resumed[key] == original[key], "resumed field {key} differs");
    }

    assert_eq!(session.password_mode(), PasswordMode::Two);

    for shown in [format!("{parsed:?}"), format!("{session:?}")] {
        assert!(!shown.contains("secret-xyz"), "debug output leaks a secret");
        assert!(shown.contains("Two"), "debug output keeps the mode");
    }
}
