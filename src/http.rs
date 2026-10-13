//! HTTP transport: headers, bounded 429/503 backoff, typed errors, and a
//! single token refresh on 401.
//!
//! Every public call goes through [`Transport::send`], which wraps
//! [`Transport::send_once`]. `refresh_tokens` uses `send_once` only, so the
//! call graph has no async recursion.

use std::fmt;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rand::{Rng, RngCore};
use reqwest::header::HeaderValue;
use reqwest::{Method, RequestBuilder};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::types::ApiErrorBody;

/// Wait applied to a 429/503 that carries no usable `Retry-After`.
const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(10);

/// Upper bound of the random delay added to every backoff, in milliseconds.
const JITTER_MS: u64 = 2000;

/// The three secrets that authenticate a session. Wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AuthTokens {
    /// Session id, sent as `x-pm-uid`.
    pub uid: String,
    /// Short-lived bearer token.
    pub access_token: String,
    /// Token that obtains a new access token.
    pub refresh_token: String,
}

impl fmt::Debug for AuthTokens {
    /// Prints every field as `"<redacted>"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthTokens")
            .field("uid", &"<redacted>")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .finish()
    }
}

/// Settings of one [`Transport`].
#[derive(Clone)]
pub struct TransportConfig {
    /// API root, such as `https://mail.proton.me/api`.
    pub base_url: String,
    /// Value of the `x-pm-appversion` header.
    pub app_version: String,
    /// How many times a 429/503 is retried before giving up.
    pub max_retries: u32,
    /// Longest single wait between retries.
    pub max_retry_wait: Duration,
}

impl TransportConfig {
    /// Defaults for the public Proton API with the given app version.
    pub fn new(app_version: impl Into<String>) -> Self {
        Self {
            base_url: "https://mail.proton.me/api".to_owned(),
            app_version: app_version.into(),
            max_retries: 3,
            max_retry_wait: Duration::from_secs(60),
        }
    }
}

/// A fully read response. No `Debug`: the body may hold secrets.
struct Buffered {
    status: u16,
    body: Vec<u8>,
}

/// Body of `POST /auth/v4/refresh`, borrowed so no extra copy of the
/// refresh token is made.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct RefreshRequest<'a> {
    #[serde(rename = "UID")]
    uid: &'a str,
    refresh_token: &'a str,
    response_type: &'a str,
    grant_type: &'a str,
    #[serde(rename = "RedirectURI")]
    redirect_uri: &'a str,
    state: String,
}

/// Response of `POST /auth/v4/refresh`. Wiped on drop.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct RefreshResponse {
    #[serde(rename = "UID", default)]
    uid: Option<String>,
    #[serde(rename = "AccessToken")]
    access_token: String,
    #[serde(rename = "RefreshToken")]
    refresh_token: String,
}

/// Talks to the Proton API for one session; owns that session's tokens.
pub struct Transport {
    http: reqwest::Client,
    config: TransportConfig,
    tokens: RwLock<Option<AuthTokens>>,
    /// Bumped by every token replacement; lets a request tell whether a
    /// refresh happened while it was in flight.
    generation: AtomicU64,
    /// Held across the refresh exchange so concurrent 401s do not submit
    /// the same refresh token twice.
    refresh_lock: Mutex<()>,
}

impl Transport {
    /// Builds a transport around the process-wide `http` client.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the base URL does not parse or the app
    /// version is empty or not a valid header value.
    pub fn new(http: reqwest::Client, mut config: TransportConfig) -> Result<Self> {
        if config.app_version.is_empty() || HeaderValue::from_str(&config.app_version).is_err() {
            return Err(Error::InvalidConfig(
                "app version is not a valid header value",
            ));
        }

        if reqwest::Url::parse(&config.base_url).is_err() {
            return Err(Error::InvalidConfig("base url is not a valid URL"));
        }

        config.base_url = config.base_url.trim_end_matches('/').to_owned();

        Ok(Self {
            http,
            config,
            tokens: RwLock::new(None),
            generation: AtomicU64::new(0),
            refresh_lock: Mutex::new(()),
        })
    }

    /// Replaces the stored tokens; `None` signs the transport out locally.
    pub fn set_tokens(&self, tokens: Option<AuthTokens>) {
        let mut slot = self.tokens.write().unwrap_or_else(|e| e.into_inner());

        *slot = tokens;
        self.generation.fetch_add(1, Ordering::AcqRel);
    }

    /// A copy of the stored tokens, if any.
    pub fn tokens(&self) -> Option<AuthTokens> {
        self.tokens
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The API root, without a trailing slash.
    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    /// `GET path` with `query`, decoding the success body into `T`.
    ///
    /// # Errors
    ///
    /// Any [`Error`] the response classifies to; see the module docs.
    pub async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T> {
        let buffered = self
            .send(
                || {
                    let req = self.builder(Method::GET, path, true);

                    if query.is_empty() {
                        req
                    } else {
                        req.query(query)
                    }
                },
                true,
            )
            .await?;

        decode(&buffered.body)
    }

    /// `POST path` with a JSON `body`, decoding the success body into `T`.
    ///
    /// # Errors
    ///
    /// Any [`Error`] the response classifies to; see the module docs.
    pub async fn post_json<B: Serialize + Sync, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        self.json_call(Method::POST, path, body).await
    }

    /// `PUT path` with a JSON `body`, decoding the success body into `T`.
    ///
    /// # Errors
    ///
    /// Any [`Error`] the response classifies to; see the module docs.
    pub async fn put_json<B: Serialize + Sync, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        self.json_call(Method::PUT, path, body).await
    }

    /// `DELETE path`, decoding the success body into `T`.
    ///
    /// # Errors
    ///
    /// Any [`Error`] the response classifies to; see the module docs.
    pub async fn delete_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let buffered = self
            .send(|| self.builder(Method::DELETE, path, true), true)
            .await?;

        decode(&buffered.body)
    }

    /// `GET path`, returning the raw success body.
    ///
    /// # Errors
    ///
    /// Any [`Error`] the response classifies to; see the module docs.
    pub async fn get_bytes(&self, path: &str) -> Result<Vec<u8>> {
        let buffered = self
            .send(|| self.builder(Method::GET, path, true), true)
            .await?;

        Ok(buffered.body)
    }

    /// Exchanges the stored refresh token for new tokens and stores them.
    /// Does not itself refresh on 401. Concurrent refreshes queue behind
    /// one another.
    ///
    /// # Errors
    ///
    /// [`Error::SessionExpired`] when no tokens are stored or the server
    /// rejects the refresh token; otherwise as for any call.
    pub async fn refresh_tokens(&self) -> Result<()> {
        let _guard = self.refresh_lock.lock().await;

        self.refresh_locked().await
    }

    /// The refresh exchange itself; the caller holds `refresh_lock`.
    async fn refresh_locked(&self) -> Result<()> {
        let Some(old) = self.tokens() else {
            return Err(Error::SessionExpired);
        };

        let mut state = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut state);

        let body = RefreshRequest {
            uid: &old.uid,
            refresh_token: &old.refresh_token,
            response_type: "token",
            grant_type: "refresh_token",
            redirect_uri: "https://protonmail.ch",
            state: state.iter().map(|b| format!("{b:02x}")).collect(),
        };

        let req = self
            .builder(Method::POST, "/auth/v4/refresh", false)
            .header("x-pm-uid", &old.uid)
            .json(&body);
        let buffered = self.send_once(req).await?;

        if matches!(buffered.status, 400 | 422) {
            return Err(Error::SessionExpired);
        }

        let buffered = classify(buffered)?;
        let fresh: RefreshResponse = decode(&buffered.body)?;

        self.set_tokens(Some(AuthTokens {
            uid: fresh.uid.clone().unwrap_or_else(|| old.uid.clone()),
            access_token: fresh.access_token.clone(),
            refresh_token: fresh.refresh_token.clone(),
        }));

        Ok(())
    }

    /// Shared body of `post_json` and `put_json`.
    async fn json_call<B: Serialize + Sync, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let buffered = self
            .send(|| self.builder(method.clone(), path, true).json(body), true)
            .await?;

        decode(&buffered.body)
    }

    /// Starts a request with the headers every call carries. With `auth`
    /// and stored tokens it adds `x-pm-uid` and the bearer token.
    fn builder(&self, method: Method, path: &str, auth: bool) -> RequestBuilder {
        let url = format!("{}{path}", self.config.base_url);
        let req = self
            .http
            .request(method, url)
            .header("x-pm-appversion", &self.config.app_version)
            .header(reqwest::header::ACCEPT, "application/json");

        match self.tokens().filter(|_| auth) {
            Some(t) => req.header("x-pm-uid", &t.uid).bearer_auth(&t.access_token),
            None => req,
        }
    }

    /// Sends the request `build` makes, refreshing the tokens once and
    /// re-sending on 401 when `auto_refresh` is set and tokens are stored.
    async fn send(
        &self,
        build: impl Fn() -> RequestBuilder,
        auto_refresh: bool,
    ) -> Result<Buffered> {
        // Read before `build()` so the request's tokens are never older than
        // this generation.
        let generation = self.generation.load(Ordering::Acquire);
        let first = self.send_once(build()).await?;

        if first.status == 401 && auto_refresh && self.tokens().is_some() {
            {
                let _guard = self.refresh_lock.lock().await;

                // Another request refreshed while this one was in flight or
                // queued: retry with its tokens instead of rotating again.
                if self.generation.load(Ordering::Acquire) == generation {
                    self.refresh_locked().await?;
                }
            }

            return classify(self.send_once(build()).await?);
        }

        classify(first)
    }

    /// Sends one request, retrying 429/503 within the configured bounds.
    /// Returns every other response as it came, except that human and
    /// device verification become errors here so they are never retried.
    async fn send_once(&self, req: RequestBuilder) -> Result<Buffered> {
        let mut retries = 0;

        loop {
            let attempt = req
                .try_clone()
                .ok_or(Error::InvalidConfig("request body cannot be replayed"))?;
            let response = attempt.send().await.map_err(Error::Transport)?;

            let status = response.status().as_u16();
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map_or(DEFAULT_RETRY_AFTER, Duration::from_secs);
            let body = response.bytes().await.map_err(Error::Transport)?.to_vec();

            if let Some(err) = verification_error(&body) {
                return Err(err);
            }

            if !matches!(status, 429 | 503) {
                return Ok(Buffered { status, body });
            }

            if retries >= self.config.max_retries {
                return Err(Error::RateLimited { retry_after });
            }

            retries += 1;

            let jitter = Duration::from_millis(rand::thread_rng().gen_range(0..=JITTER_MS));

            tokio::time::sleep(
                retry_after
                    .saturating_add(jitter)
                    .min(self.config.max_retry_wait),
            )
            .await;
        }
    }
}

/// Maps code 9001 and 9002 bodies to their errors, whatever the status.
fn verification_error(body: &[u8]) -> Option<Error> {
    let envelope: ApiErrorBody = serde_json::from_slice(body).ok()?;

    match envelope.code {
        9001 => {
            let details = envelope.details.as_ref();
            let methods = details
                .and_then(|d| d.get("HumanVerificationMethods"))
                .and_then(|m| m.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            let token = details
                .and_then(|d| d.get("HumanVerificationToken"))
                .and_then(|t| t.as_str())
                .unwrap_or_default()
                .to_owned();

            Some(Error::HumanVerificationRequired { methods, token })
        }
        9002 => Some(Error::DeviceVerificationRequired),
        _ => None,
    }
}

/// The two envelope fields `classify` needs. Unlike [`ApiErrorBody`], it
/// keeps an absent `Code` apart from an explicit `Code: 0`.
#[derive(Default, Deserialize)]
struct Envelope {
    #[serde(rename = "Code")]
    code: Option<i64>,
    #[serde(rename = "Error")]
    error: Option<String>,
}

/// Turns a non-success response into its typed error. A 2xx whose `Code`
/// is absent, 1000 or 1001 passes through. HTTP 401 outranks every code
/// mapping here (verification codes were handled earlier).
fn classify(buffered: Buffered) -> Result<Buffered> {
    let envelope: Envelope = serde_json::from_slice(&buffered.body).unwrap_or_default();

    if (200..300).contains(&buffered.status) && matches!(envelope.code, None | Some(1000 | 1001)) {
        return Ok(buffered);
    }

    if buffered.status == 401 {
        return Err(Error::SessionExpired);
    }

    let code = envelope.code.unwrap_or(0);

    Err(match code {
        5001 | 5003 => Error::AppVersionRejected,
        8002 => Error::WrongPassword,
        10013 => Error::SessionExpired,
        _ => Error::Api {
            status: buffered.status,
            code,
            message: envelope.error.unwrap_or_default(),
        },
    })
}

/// Decodes a success body; an empty body reads as `{}`. The failure
/// carries nothing, because the body may hold secrets.
fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    let body = if body.iter().all(u8::is_ascii_whitespace) {
        b"{}"
    } else {
        body
    };

    serde_json::from_slice(body).map_err(|_| Error::InvalidResponse)
}
