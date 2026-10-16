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
//! This test sends real mail: one message to the account itself with a text
//! attachment and an inline image, a forward of that message to the account
//! itself (carrying the received attachments) and, when
//! `PROTON_LIVE_SEND_EXTERNAL` is set, one plain message with the text
//! attachment to that address. Last, it permanently deletes the two
//! messages it found in the Inbox (the message and the forward) and checks
//! that they left All Mail; the rest stay in place.

use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use proton_mail_api::compose::BodyType;
use proton_mail_api::error::Result as ApiResult;
use proton_mail_api::keys::{Address, UnlockedKeys};
use proton_mail_api::labels::system;
use proton_mail_api::messages::{Message, MessageQuery, Recipient};
use proton_mail_api::send::{
    AttachmentDisposition, OutgoingAttachment, OutgoingMessage, ParentAction, ParentRef,
};
use proton_mail_api::session::{Client, Session};

type Outcome = Result<(), String>;

/// How often the Inbox poll asks, and how long it waits between asks.
const INBOX_POLLS: u32 = 5;
const INBOX_POLL_WAIT: Duration = Duration::from_secs(3);

/// `Status` of an enabled address.
const ADDRESS_ENABLED: i64 = 1;

/// A valid 1x1 PNG, used as the inline image.
const PNG: [u8; 70] = [
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0x63, 0xfc, 0xcf, 0xc0, 0x50,
    0x0f, 0x00, 0x04, 0x85, 0x01, 0x80, 0x84, 0xa9, 0x8c, 0x21, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45,
    0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

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

/// The regular attachment: a text file that depends on `secs`.
fn text_attachment(secs: u64) -> OutgoingAttachment {
    OutgoingAttachment {
        filename: "live-send-check.txt".to_string(),
        mime_type: "text/plain".to_string(),
        data: format!("attachment check {secs}").into_bytes(),
        disposition: AttachmentDisposition::Attachment,
    }
}

/// The inline attachment: the 1x1 PNG, referred to by the HTML body.
fn inline_attachment() -> OutgoingAttachment {
    OutgoingAttachment {
        filename: "live-inline.png".to_string(),
        mime_type: "image/png".to_string(),
        data: PNG.to_vec(),
        disposition: AttachmentDisposition::Inline {
            content_id: "live-inline@proton-mail-api".to_string(),
        },
    }
}

/// Asks the Inbox until a message with `subject` shows up and returns its id.
/// A miss records `missing`; an API error is recorded and ends the poll.
async fn poll_inbox(
    session: &Session,
    subject: &str,
    missing: &str,
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
    results.push(Err(missing.to_string()));
    None
}

/// Checks that `received` carries the `sent` attachments: each is found by
/// name and downloads to the sent bytes; an inline one keeps its content id.
async fn check_attachments(
    session: &Session,
    keys: &UnlockedKeys,
    received: &Message,
    sent: &[OutgoingAttachment],
    results: &mut Vec<Outcome>,
) {
    expect(
        results,
        received.attachments.len() <= sent.len(),
        "received message has extra attachments",
    );

    for want in sent {
        let Some(att) = received
            .attachments
            .iter()
            .find(|a| a.name == want.filename)
        else {
            results.push(Err(
                "download attachment: received attachment missing".to_string()
            ));
            continue;
        };

        let mut failure = "received attachment does not match";
        if let AttachmentDisposition::Inline { content_id } = &want.disposition {
            expect(
                results,
                att.disposition.eq_ignore_ascii_case("inline")
                    && att.content_id().as_deref() == Some(content_id.as_str()),
                "inline attachment lost its content id",
            );
            failure = "received inline attachment does not match";
        }

        if let Some(data) = take(
            results,
            "download attachment",
            session.attachment(att, keys).await,
        ) {
            expect(results, data == want.data, failure);
        }
    }
}

/// Forwards `received` to the account itself with its attachments, waits for
/// the forward in the Inbox and checks that the `sent` attachments came along.
/// Returns the id of the forward as received, if it arrived.
async fn forward_to_self(
    session: &Session,
    keys: &UnlockedKeys,
    from: &Address,
    marker: &str,
    received: &Message,
    sent: &[OutgoingAttachment],
    results: &mut Vec<Outcome>,
) -> Option<String> {
    let subject = format!("{marker} forward");
    let forward = OutgoingMessage {
        parent: Some(ParentRef {
            id: received.meta.id.clone(),
            action: ParentAction::Forward,
            forward_attachments: received.attachments.clone(),
        }),
        ..message(from, &from.email, subject.clone(), "forward check")
    };

    take(
        results,
        "forward to self",
        session.send(keys, &forward).await,
    )?;

    let id = poll_inbox(
        session,
        &subject,
        "forwarded message did not arrive in Inbox",
        results,
    )
    .await?;
    let Some(forwarded) = take(
        results,
        "fetch forwarded message",
        session.message(&id).await,
    ) else {
        return Some(id);
    };

    let mut matches = forwarded.attachments.len() == sent.len();
    for want in sent {
        let Some(att) = forwarded
            .attachments
            .iter()
            .find(|a| a.name == want.filename)
        else {
            matches = false;
            continue;
        };
        let Some(data) = take(
            results,
            "download attachment",
            session.attachment(att, keys).await,
        ) else {
            continue;
        };
        matches &= data == want.data;
    }
    expect(results, matches, "forwarded attachment does not match");

    Some(id)
}

/// Permanently deletes `ids`, then asks All Mail until none of them is
/// listed. A miss records a failure; an API error is recorded and ends the
/// poll.
async fn delete_and_confirm(session: &Session, ids: &[String], results: &mut Vec<Outcome>) {
    if take(
        results,
        "delete messages",
        session.delete_messages(ids).await,
    )
    .is_none()
    {
        return;
    }

    let query = MessageQuery {
        label_id: Some(system::ALL_MAIL.into()),
        ..Default::default()
    };
    for attempt in 0..INBOX_POLLS {
        let Some(page) = take(
            results,
            "list all mail",
            session.list_messages(&query).await,
        ) else {
            return;
        };
        if !page.messages.iter().any(|m| ids.contains(&m.id)) {
            return;
        }
        if attempt + 1 < INBOX_POLLS {
            tokio::time::sleep(INBOX_POLL_WAIT).await;
        }
    }
    results.push(Err("deleted message still in All Mail".to_string()));
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
    let html = format!("<p>{body}</p><img src=\"cid:live-inline@proton-mail-api\">");
    let attachments = vec![text_attachment(secs), inline_attachment()];

    let to_self = OutgoingMessage {
        body_type: BodyType::Html,
        attachments: attachments.clone(),
        ..message(from, &from.email, marker.clone(), &html)
    };
    let sent = take(results, "send to self", session.send(&keys, &to_self).await);

    if sent.is_some()
        && let Some(id) = poll_inbox(
            session,
            &marker,
            "sent message did not arrive in Inbox",
            results,
        )
        .await
        && let Some(received) = take(results, "fetch sent message", session.message(&id).await)
    {
        if let Some(decrypted) = take(
            results,
            "decrypt sent message",
            received.decrypt_body(&keys),
        ) {
            expect(
                results,
                decrypted
                    .text_and_html()
                    .1
                    .as_deref()
                    .is_some_and(|html| html.contains(&body)),
                "received body does not match",
            );
        }

        check_attachments(session, &keys, &received, &attachments, results).await;
        let forwarded = forward_to_self(
            session,
            &keys,
            from,
            &marker,
            &received,
            &attachments,
            results,
        )
        .await;

        let ids: Vec<String> = [Some(id), forwarded].into_iter().flatten().collect();
        delete_and_confirm(session, &ids, results).await;
    }

    if let Some(address) = external {
        let outgoing = OutgoingMessage {
            attachments: vec![text_attachment(secs)],
            ..message(from, address, format!("{marker} external"), &body)
        };
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
