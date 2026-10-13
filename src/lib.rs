//! Unofficial, pure-Rust client for the Proton Mail API.
//!
//! See `README.md` for scope and `AGENTS.md` for the rules that bind this
//! crate (no secrets in errors or logs, zeroized key material, fixture tests).
//!
//! # Example
//!
//! ```no_run
//! use proton_mail_api::labels::system;
//! use proton_mail_api::messages::MessageQuery;
//! use proton_mail_api::session::Client;
//!
//! async fn run(
//!     username: &str,
//!     password: &str,
//!     totp: &str,
//! ) -> proton_mail_api::error::Result<()> {
//!     let client = Client::builder()
//!         .app_version("web-mail@0.0.0")
//!         .build()?;
//!
//!     // Log in; submit the 6-digit code when the account has TOTP on.
//!     let outcome = client.login(username, password).await?;
//!     let session = outcome.session;
//!     if outcome.needs_totp {
//!         session.submit_totp(totp).await?;
//!     }
//!
//!     // Persist the opaque blob, then rebuild a session from it (no network).
//!     let blob = session.persist();
//!     let session = client.resume(blob)?;
//!
//!     // Unlock the user and address keys with the mailbox password.
//!     let keys = session.unlock_keys(password).await?;
//!
//!     let labels = session.labels().await?;
//!     println!("{} labels", labels.len());
//!
//!     // Newest page of the Inbox, then the first message in full.
//!     let page = session
//!         .list_messages(&MessageQuery {
//!             label_id: Some(system::INBOX.to_string()),
//!             ..Default::default()
//!         })
//!         .await?;
//!     let ids: Vec<String> = page.messages.iter().map(|m| m.id.clone()).collect();
//!
//!     if let Some(first) = ids.first() {
//!         let message = session.message(first).await?;
//!         let body = message.decrypt_body(&keys)?;
//!         let (text, html) = body.text_and_html();
//!         println!("text: {}, html: {}", text.is_some(), html.is_some());
//!
//!         if let Some(attachment) = message.attachments.first() {
//!             let bytes = session.attachment(attachment, &keys).await?;
//!             println!("attachment: {} bytes", bytes.len());
//!         }
//!     }
//!
//!     // Poll the change feed from the newest event.
//!     let latest = session.latest_event_id().await?;
//!     let batch = session.events(&latest).await?;
//!     println!("{} events", batch.events.len());
//!
//!     // Triage.
//!     session.mark_read(&ids).await?;
//!     session.move_to(&ids, system::ARCHIVE).await?;
//!
//!     session.logout().await?;
//!     Ok(())
//! }
//! ```

pub mod actions;
pub mod error;
pub mod events;
pub mod http;
pub mod keys;
pub mod labels;
pub mod messages;
pub mod session;
pub mod srp;
pub mod types;
