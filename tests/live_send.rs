//! Send test against the real Proton API.
//!
//! Runs only when `PROTON_LIVE_SEND=1`; it is never run in CI. It reads
//! `PROTON_USERNAME`, `PROTON_PASSWORD`, `PROTON_APP_VERSION`, and optionally
//! `PROTON_MAILBOX_PASSWORD` (defaults to the login password),
//! `PROTON_TOTP` (a current 6-digit code), `PROTON_USER_AGENT` (overrides the
//! default `User-Agent`) and `PROTON_LIVE_SEND_EXTERNAL` (an address outside
//! Proton). Failure messages name the step and the crate's error text; they
//! never carry message content, tokens, passwords or key text.
//!
//! This test sends real mail: one message to the account itself and, when
//! `PROTON_LIVE_SEND_EXTERNAL` is set, one to that address. Both stay in
//! place; the test deletes nothing.

use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use proton_mail_api::compose::BodyType;
use proton_mail_api::error::Result as ApiResult;
use proton_mail_api::keys::{Address, UnlockedKeys};
use proton_mail_api::labels::system;
use proton_mail_api::messages::{MessageQuery, Recipient};
use proton_mail_api::send::OutgoingMessage;
use proton_mail_api::session::{Client, Session};

type Outcome = Result<(), String>;

/// How often the Inbox poll asks, and how long it waits between asks.
const INBOX_POLLS: u32 = 5;
const INBOX_POLL_WAIT: Duration = Duration::from_secs(3);

/// `Status` of an enabled address.
const ADDRESS_ENABLED: i64 = 1;

/// A variable that is set and not empty.
fn var(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
}

/// A variable the test cannot run without.
fn required(name: &str) -> Result<String, String> {
    var(name).ok_or_else(|| format!("{name} required"))
}

/// Records a failed call under `step` and hands back a successful value.
fn take<T>(results: &mut Vec<Outcome>, step: &str, r: ApiResult<T>) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(e) => {
            results.push(Err(format!("{step}: {e}")));
            None
        }
    }
}

/// Records whether `ok` held; `failure` is the message when it did not.
fn expect(results: &mut Vec<Outcome>, ok: bool, failure: &str) {
    results.push(if ok { Ok(()) } else { Err(failure.to_string()) });
}

/// The first address, by `order`, that may send, is enabled and has an
/// unlocked key. `addresses` arrives sorted by `order`.
fn sender<'a>(addresses: &'a [Address], keys: &UnlockedKeys) -> Option<&'a Address> {
    addresses.iter().find(|a| {
        a.send.0
            && a.status == ADDRESS_ENABLED
            && keys
                .address_keys
                .iter()
                .any(|k| k.email.eq_ignore_ascii_case(&a.email))
    })
}

/// A plain-text message with no cc, bcc or parent.
fn message(from: &Address, to: &str, subject: String, body: &str) -> OutgoingMessage {
    OutgoingMessage {
        from: Recipient {
            name: from.display_name.clone(),
            address: from.email.clone(),
        },
        to: vec![Recipient {
            name: String::new(),
            address: to.to_string(),
        }],
        cc: Vec::new(),
        bcc: Vec::new(),
        subject,
        body: body.to_string(),
        body_type: BodyType::Plain,
        parent: None,
        attachments: vec![],
    }
}

/// Asks the Inbox until a message with `subject` shows up and returns its id.
/// A miss records nothing; an API error is recorded and ends the poll.
async fn poll_inbox(
    session: &Session,
    subject: &str,
    results: &mut Vec<Outcome>,
) -> Option<String> {
    let query = MessageQuery {
        label_id: Some(system::INBOX.into()),
        ..Default::default()
    };
    for attempt in 0..INBOX_POLLS {
        let page = take(results, "list inbox", session.list_messages(&query).await)?;
        if let Some(found) = page.messages.iter().find(|m| m.subject == subject) {
            return Some(found.id.clone());
        }
        if attempt + 1 < INBOX_POLLS {
            tokio::time::sleep(INBOX_POLL_WAIT).await;
        }
    }
    results.push(Err("sent message did not arrive in Inbox".to_string()));
    None
}

/// Everything after login. Steps that need an earlier result are skipped
/// when that result is missing; the earlier failure is already recorded.
async fn send_steps(
    session: &Session,
    mailbox_password: &str,
    external: Option<&str>,
    results: &mut Vec<Outcome>,
) {
    let Some(keys) = take(
        results,
        "unlock keys",
        session.unlock_keys(mailbox_password).await,
    ) else {
        return;
    };
    let Some(addresses) = take(results, "list addresses", session.addresses().await) else {
        return;
    };
    let Some(from) = sender(&addresses, &keys) else {
        results.push(Err("no sendable address".to_string()));
        return;
    };

    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let marker = format!("proton-mail-api live send {secs}");
    let body = format!("live send check {secs}");

    let to_self = message(from, &from.email, marker.clone(), &body);
    let sent = take(results, "send to self", session.send(&keys, &to_self).await);

    if sent.is_some()
        && let Some(id) = poll_inbox(session, &marker, results).await
        && let Some(received) = take(results, "fetch sent message", session.message(&id).await)
        && let Some(decrypted) = take(
            results,
            "decrypt sent message",
            received.decrypt_body(&keys),
        )
    {
        let text = decrypted.text_and_html().0;
        expect(
            results,
            text.as_deref().map(str::trim) == Some(body.as_str()),
            "received body does not match",
        );
    }

    if let Some(address) = external {
        let outgoing = message(from, address, format!("{marker} external"), &body);
        take(
            results,
            "send to external",
            session.send(&keys, &outgoing).await,
        );
    }
}

#[tokio::test]
async fn live_send() {
    if env::var("PROTON_LIVE_SEND").as_deref() != Ok("1") {
        eprintln!("live send skipped");
        return;
    }

    let mut results: Vec<Outcome> = Vec::new();

    let username = required("PROTON_USERNAME");
    let password = required("PROTON_PASSWORD");
    let app_version = required("PROTON_APP_VERSION");
    let (Ok(username), Ok(password), Ok(app_version)) = (&username, &password, &app_version) else {
        let first = [username, password, app_version]
            .into_iter()
            .find_map(Result::err)
            .unwrap_or_default();
        panic!("{first}");
    };
    let mailbox_password = var("PROTON_MAILBOX_PASSWORD").unwrap_or_else(|| password.clone());
    let external = var("PROTON_LIVE_SEND_EXTERNAL");

    let mut builder = Client::builder().app_version(app_version.clone());

    if let Some(user_agent) = var("PROTON_USER_AGENT") {
        builder = builder.user_agent(user_agent);
    }

    let client = builder.build().map_err(|e| format!("build client: {e}"));
    let login = match &client {
        Ok(client) => take(
            &mut results,
            "login",
            client.login(username, password).await,
        ),
        Err(e) => {
            results.push(Err(e.clone()));
            None
        }
    };

    if let Some(outcome) = login {
        let session = outcome.session;
        let mut ready = true;
        if outcome.needs_totp {
            ready = match var("PROTON_TOTP") {
                Some(code) => take(
                    &mut results,
                    "submit totp",
                    session.submit_totp(&code).await,
                )
                .is_some(),
                None => {
                    results.push(Err("PROTON_TOTP required".to_string()));
                    false
                }
            };
        }
        if ready {
            send_steps(
                &session,
                &mailbox_password,
                external.as_deref(),
                &mut results,
            )
            .await;
        }
        take(&mut results, "logout", session.logout().await);
    }

    let failures: Vec<String> = results.into_iter().filter_map(Result::err).collect();
    assert!(failures.is_empty(), "{}", failures.join("; "));
}
