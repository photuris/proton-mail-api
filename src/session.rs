//! A logged-in (or resumable) Proton session, and the [`Client`] that makes them.
//!
//! [`Client::login`] runs Proton's SRP exchange and hands back a [`Session`]
//! with its own [`Transport`]; [`Client::resume`] rebuilds one from a
//! [`PersistedSession`] without touching the network.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};
use crate::http::{AuthTokens, Transport, TransportConfig};
use crate::srp;
use crate::types::Empty;

/// Which password protects the mail keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PasswordMode {
    /// One password for login and for the mail keys.
    Single,
    /// A separate mailbox password unlocks the mail keys.
    Two,
}

/// Collects the settings of a [`Client`].
#[derive(Default)]
pub struct ClientBuilder {
    app_version: Option<String>,
    base_url: Option<String>,
    max_retries: Option<u32>,
    srp_secret: Option<Zeroizing<Vec<u8>>>,
}

impl ClientBuilder {
    /// Value of the `x-pm-appversion` header. Required.
    pub fn app_version(mut self, v: impl Into<String>) -> Self {
        self.app_version = Some(v.into());
        self
    }

    /// API root; defaults to `https://mail.proton.me/api`.
    pub fn base_url(mut self, v: impl Into<String>) -> Self {
        self.base_url = Some(v.into());
        self
    }

    /// How many times a 429/503 is retried before giving up.
    pub fn max_retries(mut self, n: u32) -> Self {
        self.max_retries = Some(n);
        self
    }

    /// Test seam: use this fixed 256-byte little-endian SRP client secret
    /// instead of a random one. Never set it outside tests.
    #[doc(hidden)]
    pub fn srp_client_secret(mut self, secret: Vec<u8>) -> Self {
        self.srp_secret = Some(Zeroizing::new(secret));
        self
    }

    /// Builds the client.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when `app_version` is missing or the app
    /// version or base URL is unusable; [`Error::Transport`] when the HTTP
    /// client cannot be created.
    pub fn build(self) -> Result<Client> {
        let app_version = self
            .app_version
            .ok_or(Error::InvalidConfig("app_version is required"))?;
        let mut config = TransportConfig::new(app_version);

        if let Some(url) = self.base_url {
            config.base_url = url;
        }

        if let Some(n) = self.max_retries {
            config.max_retries = n;
        }

        let http = reqwest::Client::builder()
            .build()
            .map_err(Error::Transport)?;

        // Reject a bad config here rather than at the first login.
        Transport::new(http.clone(), config.clone())?;

        Ok(Client {
            http,
            config,
            srp_secret: self.srp_secret,
        })
    }
}

/// Entry point: logs in or resumes sessions. Cheap to clone; every session
/// it makes has its own tokens.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    config: TransportConfig,
    srp_secret: Option<Zeroizing<Vec<u8>>>,
}

impl Client {
    /// Starts a [`ClientBuilder`].
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// A fresh, token-less transport; two logins never share tokens.
    fn new_transport(&self) -> Result<Transport> {
        Transport::new(self.http.clone(), self.config.clone())
    }

    /// Logs in with Proton's SRP exchange. When the outcome says
    /// `needs_totp`, call [`Session::submit_totp`] before using the session.
    ///
    /// # Errors
    ///
    /// [`Error::WrongPassword`], [`Error::HumanVerificationRequired`] and the
    /// other transport errors as they arrive; [`Error::Srp`] when the
    /// server's parameters are unusable; [`Error::Crypto`] when the server
    /// proof does not match; [`Error::InvalidResponse`] on a malformed reply.
    pub async fn login(&self, username: &str, password: &str) -> Result<LoginOutcome> {
        let transport = Arc::new(self.new_transport()?);

        let info: AuthInfoResponse = transport
            .post_json("/auth/v4/info", &AuthInfoRequest { username })
            .await?;

        let modulus = srp::verify_modulus(&info.modulus)?;
        let salt = decode_b64(&info.salt)?;
        let server_ephemeral = decode_b64(&info.server_ephemeral)?;
        let password = Zeroizing::new(password.as_bytes().to_vec());
        let hashed = Zeroizing::new(srp::hash_password(
            info.version,
            &password,
            &salt,
            &modulus,
        )?);

        drop(password);

        // ponytail: bcrypt and modpow run on the async thread (~100 ms);
        // move to spawn_blocking if callers log in concurrently at scale.
        let proofs = match &self.srp_secret {
            Some(secret) => {
                srp::generate_proofs_with_secret(&modulus, &server_ephemeral, &hashed, secret)?
            }
            None => srp::generate_proofs(&modulus, &server_ephemeral, &hashed)?,
        };

        let auth: AuthResponse = transport
            .post_json(
                "/auth/v4",
                &AuthRequest {
                    username,
                    client_ephemeral: B64.encode(&proofs.client_ephemeral),
                    client_proof: B64.encode(&proofs.client_proof),
                    srp_session: &info.srp_session,
                },
            )
            .await?;

        let proof_ok = B64
            .decode(&auth.server_proof)
            .is_ok_and(|p| bool::from(p.ct_eq(&proofs.expected_server_proof)));

        if !proof_ok {
            return Err(Error::Crypto("server proof mismatch"));
        }

        let password_mode = match auth.password_mode {
            1 => PasswordMode::Single,
            2 => PasswordMode::Two,
            _ => return Err(Error::InvalidResponse),
        };

        transport.set_tokens(Some(AuthTokens {
            uid: auth.uid.clone(),
            access_token: auth.access_token.clone(),
            refresh_token: auth.refresh_token.clone(),
        }));

        Ok(LoginOutcome {
            session: Session::new(transport, password_mode, auth.scope.clone(), None),
            needs_totp: auth.two_fa.enabled & 1 != 0,
            password_mode,
            scope: auth.scope.clone(),
        })
    }

    /// Rebuilds a session from a persisted blob. Makes no network call.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidResponse`] when the blob's uid, access token or
    /// refresh token is empty.
    pub fn resume(&self, persisted: PersistedSession) -> Result<Session> {
        if persisted.uid.is_empty()
            || persisted.access_token.is_empty()
            || persisted.refresh_token.is_empty()
        {
            return Err(Error::InvalidResponse);
        }

        let transport = Arc::new(self.new_transport()?);

        transport.set_tokens(Some(AuthTokens {
            uid: persisted.uid.clone(),
            access_token: persisted.access_token.clone(),
            refresh_token: persisted.refresh_token.clone(),
        }));

        Ok(Session::new(
            transport,
            persisted.password_mode,
            persisted.scope.clone(),
            persisted.key_password.clone().map(Zeroizing::new),
        ))
    }
}

/// What a login returned.
#[derive(Debug)]
pub struct LoginOutcome {
    /// The new session; not yet usable if `needs_totp` is set.
    pub session: Session,
    /// The account has TOTP on: call [`Session::submit_totp`] next.
    pub needs_totp: bool,
    /// Which password unlocks the mail keys.
    pub password_mode: PasswordMode,
    /// Space-separated scopes the server granted.
    pub scope: String,
}

/// Mutable parts of a session, behind one lock that is never held across an
/// await.
struct State {
    password_mode: PasswordMode,
    scope: String,
    key_password: Option<Zeroizing<String>>,
}

/// One account session; owns the [`Transport`] that holds its tokens.
pub struct Session {
    transport: Arc<Transport>,
    state: Mutex<State>,
}

impl fmt::Debug for Session {
    /// Prints the password mode only; the transport holds the tokens.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("password_mode", &self.password_mode())
            .field("secrets", &"<redacted>")
            .finish()
    }
}

#[allow(dead_code)] // the key and endpoint modules build on these
impl Session {
    /// Wraps a transport that already holds (or will receive) tokens.
    pub(crate) fn from_transport(transport: Arc<Transport>) -> Self {
        Self::new(transport, PasswordMode::Single, String::new(), None)
    }

    fn new(
        transport: Arc<Transport>,
        password_mode: PasswordMode,
        scope: String,
        key_password: Option<Zeroizing<String>>,
    ) -> Self {
        Self {
            transport,
            state: Mutex::new(State {
                password_mode,
                scope,
                key_password,
            }),
        }
    }

    /// The transport every call of this session goes through.
    pub(crate) fn transport(&self) -> &Transport {
        &self.transport
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Completes the TOTP step of a login with the 6-digit `code`.
    ///
    /// # Errors
    ///
    /// Whatever the server answers for a rejected code, as a typed error.
    pub async fn submit_totp(&self, code: &str) -> Result<()> {
        let reply: TotpResponse = self
            .transport
            .post_json("/auth/v4/2fa", &TotpRequest { code })
            .await?;

        if let Some(scope) = reply.scope {
            self.state().scope = scope;
        }

        Ok(())
    }

    /// Exchanges the refresh token for new tokens.
    ///
    /// # Errors
    ///
    /// [`Error::SessionExpired`] when the server rejects the refresh token.
    pub async fn refresh(&self) -> Result<()> {
        self.transport.refresh_tokens().await
    }

    /// Ends the session on the server. The local tokens are cleared even
    /// when the server answers with an error.
    ///
    /// # Errors
    ///
    /// The server's error, after the local tokens are gone.
    pub async fn logout(self) -> Result<()> {
        let result = self.transport.delete_json::<Empty>("/auth/v4").await;

        self.transport.set_tokens(None);
        self.state().key_password = None;

        result.map(|_| ())
    }

    /// Snapshot of everything needed to [`Client::resume`] this session.
    pub fn persist(&self) -> PersistedSession {
        let tokens = self.transport.tokens();
        let state = self.state();

        PersistedSession {
            uid: tokens.as_ref().map(|t| t.uid.clone()).unwrap_or_default(),
            access_token: tokens
                .as_ref()
                .map(|t| t.access_token.clone())
                .unwrap_or_default(),
            refresh_token: tokens
                .as_ref()
                .map(|t| t.refresh_token.clone())
                .unwrap_or_default(),
            password_mode: state.password_mode,
            scope: state.scope.clone(),
            key_password: state.key_password.as_deref().cloned(),
        }
    }

    /// The Proton session id; empty once the tokens are cleared.
    pub fn uid(&self) -> String {
        self.transport
            .tokens()
            .map(|t| t.uid.clone())
            .unwrap_or_default()
    }

    /// Which password unlocks the mail keys.
    pub fn password_mode(&self) -> PasswordMode {
        self.state().password_mode
    }

    /// Remembers the derived key password so `persist` can carry it.
    pub(crate) fn set_key_password(&self, key_password: Zeroizing<String>) {
        self.state().key_password = Some(key_password);
    }

    /// The remembered key password, if any.
    pub(crate) fn key_password(&self) -> Option<Zeroizing<String>> {
        self.state().key_password.clone()
    }
}

/// The secrets a consumer stores to resume a session later. Opaque: the
/// fields are private and only serde and [`uid`](Self::uid) are public.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PersistedSession {
    uid: String,
    access_token: String,
    refresh_token: String,
    #[zeroize(skip)]
    password_mode: PasswordMode,
    scope: String,
    key_password: Option<String>,
}

impl PersistedSession {
    /// The Proton session id, for keying a store.
    pub fn uid(&self) -> &str {
        &self.uid
    }
}

impl fmt::Debug for PersistedSession {
    /// Prints the password mode; the rest is `"<redacted>"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistedSession")
            .field("password_mode", &self.password_mode)
            .field("secrets", &"<redacted>")
            .finish()
    }
}

/// Decodes a std-base64 field of a response; the failure carries nothing.
fn decode_b64(s: &str) -> Result<Vec<u8>> {
    B64.decode(s).map_err(|_| Error::InvalidResponse)
}

/// Body of `POST /auth/v4/info`.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct AuthInfoRequest<'a> {
    username: &'a str,
}

/// Response of `POST /auth/v4/info`.
#[derive(Deserialize)]
struct AuthInfoResponse {
    #[serde(rename = "Version")]
    version: u32,
    #[serde(rename = "Modulus")]
    modulus: String,
    #[serde(rename = "ServerEphemeral")]
    server_ephemeral: String,
    #[serde(rename = "Salt")]
    salt: String,
    #[serde(rename = "SRPSession")]
    srp_session: String,
}

/// Body of `POST /auth/v4`.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct AuthRequest<'a> {
    username: &'a str,
    client_ephemeral: String,
    client_proof: String,
    #[serde(rename = "SRPSession")]
    srp_session: &'a str,
}

/// The `2FA` object of the login response.
#[derive(Default, Deserialize)]
struct TwoFa {
    #[serde(rename = "Enabled", default)]
    enabled: u32,
}

/// Response of `POST /auth/v4`. Wiped on drop.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct AuthResponse {
    #[serde(rename = "UID")]
    uid: String,
    #[serde(rename = "AccessToken")]
    access_token: String,
    #[serde(rename = "RefreshToken")]
    refresh_token: String,
    #[serde(rename = "ServerProof")]
    server_proof: String,
    #[serde(rename = "Scope", default)]
    #[zeroize(skip)]
    scope: String,
    #[serde(rename = "PasswordMode")]
    #[zeroize(skip)]
    password_mode: u32,
    #[serde(rename = "2FA", default)]
    #[zeroize(skip)]
    two_fa: TwoFa,
}

/// Body of `POST /auth/v4/2fa`.
#[derive(Serialize)]
struct TotpRequest<'a> {
    #[serde(rename = "TwoFactorCode")]
    code: &'a str,
}

/// Response of `POST /auth/v4/2fa`.
#[derive(Deserialize)]
struct TotpResponse {
    #[serde(rename = "Scope", default)]
    scope: Option<String>,
}
