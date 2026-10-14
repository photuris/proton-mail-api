//! End-to-end test against the real Proton API.
//!
//! Runs only when `PROTON_LIVE_TEST=1`; it is never run in CI. It reads
//! `PROTON_USERNAME`, `PROTON_PASSWORD`, `PROTON_APP_VERSION`, and optionally
//! `PROTON_MAILBOX_PASSWORD` (defaults to the login password),
//! `PROTON_TOTP` (a current 6-digit code) and `PROTON_USER_AGENT` (overrides
//! the default `User-Agent`). Failure messages name the step and the
//! crate's error text; they never carry message content, tokens,
//! passwords or key text.
//!
//! The test flips and restores the newest Inbox message's read state and moves
//! it to Archive and back, best effort.

use std::env;
use std::time::Duration;

use proton_mail_api::error::Result as ApiResult;
use proton_mail_api::labels::system;
use proton_mail_api::messages::MessageQuery;
use proton_mail_api::session::{Client, Session};

type Outcome = Result<(), String>;

/// How often the events poll asks, and how long it waits between asks.
const EVENT_POLLS: u32 = 3;
const EVENT_POLL_WAIT: Duration = Duration::from_secs(2);

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

/// Sets the unread flag of one message.
async fn set_unread(session: &Session, id: &str, unread: bool) -> ApiResult<()> {
    let ids = [id.to_string()];
    if unread {
        session.mark_unread(&ids).await
    } else {
        session.mark_read(&ids).await
    }
}

/// Flips the read state and restores it, then moves the message to Archive
/// and back. Returns whether any call changed the mailbox. A restore that is
/// not confirmed is reported and stops further changes.
async fn triage(session: &Session, id: &str, was_unread: bool, results: &mut Vec<Outcome>) -> bool {
    let mut changed = false;
    let ids = [id.to_string()];

    let flipped = take(
        results,
        "flip read state",
        set_unread(session, id, !was_unread).await,
    );
    changed |= flipped.is_some();
    if flipped.is_some()
        && let Some(message) = take(results, "refetch message", session.message(id).await)
    {
        expect(
            results,
            message.meta.unread.0 == !was_unread,
            "read state did not change",
        );
    }

    let restored = take(
        results,
        "restore read state",
        set_unread(session, id, was_unread).await,
    );
    changed |= restored.is_some();
    let confirmed = restored.is_some()
        && take(results, "refetch message", session.message(id).await)
            .is_some_and(|message| message.meta.unread.0 == was_unread);
    if !confirmed {
        results.push(Err("read state was not restored".to_string()));
        results.push(Err(
            "skipped archive round-trip after a failed restore".to_string()
        ));
        return changed;
    }

    let moved = take(
        results,
        "move to archive",
        session.move_to(&ids, system::ARCHIVE).await,
    );
    changed |= moved.is_some();
    if moved.is_some()
        && let Some(message) = take(results, "refetch message", session.message(id).await)
    {
        let labels = &message.meta.label_ids;
        expect(
            results,
            labels.iter().any(|l| l == system::ARCHIVE)
                && !labels.iter().any(|l| l == system::INBOX),
            "message did not move to Archive",
        );
    }

    let back = take(
        results,
        "move back to inbox",
        session.move_to(&ids, system::INBOX).await,
    );
    changed |= back.is_some();
    let home = take(results, "refetch message", session.message(id).await).is_some_and(|message| {
        let labels = &message.meta.label_ids;
        labels.iter().any(|l| l == system::INBOX) && !labels.iter().any(|l| l == system::ARCHIVE)
    });
    expect(results, home, "message did not move back to Inbox");

    changed
}

/// Asks the events feed after `before` until a batch names message `id`.
/// An error ends the poll at once.
async fn poll_events(session: &Session, before: &str, id: &str, results: &mut Vec<Outcome>) {
    for attempt in 0..EVENT_POLLS {
        let Some(batch) = take(results, "read events", session.events(before).await) else {
            return;
        };
        if batch
            .events
            .iter()
            .any(|event| event.messages.iter().any(|m| m.id == id))
        {
            return;
        }
        if attempt + 1 < EVENT_POLLS {
            tokio::time::sleep(EVENT_POLL_WAIT).await;
        }
    }
    results.push(Err(
        "events feed did not report the triage changes".to_string()
    ));
}

/// Everything after login. Steps that need an earlier result are skipped
/// when that result is missing; the earlier failure is already recorded.
async fn read_steps(session: &Session, mailbox_password: &str, results: &mut Vec<Outcome>) {
    let keys = take(
        results,
        "unlock keys",
        session.unlock_keys(mailbox_password).await,
    );

    if let Some(labels) = take(results, "list labels", session.labels().await) {
        expect(results, !labels.is_empty(), "label list is empty");
    }

    let query = MessageQuery {
        label_id: Some(system::INBOX.to_string()),
        ..Default::default()
    };
    let page = take(results, "list inbox", session.list_messages(&query).await);

    let before = take(results, "latest event id", session.latest_event_id().await).and_then(|id| {
        let known = !id.is_empty();
        expect(results, known, "latest event id is empty");
        known.then_some(id)
    });

    if let Some(page) = page {
        match page.messages.first() {
            None => results.push(Err("live test needs at least one Inbox message".to_string())),
            Some(newest) => {
                let message = take(results, "fetch message", session.message(&newest.id).await);
                if let (Some(message), Some(keys)) = (message, keys.as_ref()) {
                    if let Some(body) = take(results, "decrypt body", message.decrypt_body(keys)) {
                        let (text, html) = body.text_and_html();
                        let usable = [text, html].into_iter().flatten().any(|s| !s.is_empty());
                        expect(results, usable, "decrypted body has no text or html");
                    }
                    if let Some(first) = message.attachments.first()
                        && let Some(bytes) = take(
                            results,
                            "download attachment",
                            session.attachment(first, keys).await,
                        )
                    {
                        expect(results, !bytes.is_empty(), "decrypted attachment is empty");
                    }
                }

                let changed = triage(session, &newest.id, newest.unread.0, results).await;
                if changed && let Some(before) = &before {
                    poll_events(session, before, &newest.id, results).await;
                }
            }
        }
    }
}

#[tokio::test]
async fn live_end_to_end() {
    if env::var("PROTON_LIVE_TEST").as_deref() != Ok("1") {
        eprintln!("live test skipped");
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
            read_steps(&session, &mailbox_password, &mut results).await;
        }
        take(&mut results, "logout", session.logout().await);
    }

    let failures: Vec<String> = results.into_iter().filter_map(Result::err).collect();
    assert!(failures.is_empty(), "{}", failures.join("; "));
}
