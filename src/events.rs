//! The change-event feed: what changed on the server since an event id.
//!
//! The consumer polls [`Session::events`] with the last id it handled; this
//! module has no timer.

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::labels::Label;
use crate::session::Session;
use crate::types::{ApiBool, path_segment};

/// Most events one [`Session::events`] call collects (as go-proton-api).
const MAX_COLLECTED_EVENTS: usize = 50;

/// What happened to the item an event entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventAction {
    /// The item is gone.
    Delete = 0,
    /// The item is new.
    Create = 1,
    /// The item changed.
    Update = 2,
    /// Only the item's flags changed.
    UpdateFlags = 3,
}

impl EventAction {
    /// The action for an API number; `None` for numbers this crate does not know.
    pub fn from_i64(v: i64) -> Option<EventAction> {
        match v {
            0 => Some(Self::Delete),
            1 => Some(Self::Create),
            2 => Some(Self::Update),
            3 => Some(Self::UpdateFlags),
            _ => None,
        }
    }
}

/// A change to one message.
#[derive(Debug, Clone, Deserialize)]
pub struct MessageEvent {
    /// Id of the message.
    #[serde(rename = "ID")]
    pub id: String,
    /// Raw action number; see [`EventAction::from_i64`].
    #[serde(rename = "Action")]
    pub action: i64,
    /// The message payload as the server sent it; absent on delete.
    #[serde(rename = "Message", default)]
    pub message: Option<serde_json::Value>,
}

/// A change to one label or folder.
#[derive(Debug, Clone, Deserialize)]
pub struct LabelEvent {
    /// Id of the label.
    #[serde(rename = "ID")]
    pub id: String,
    /// Raw action number; see [`EventAction::from_i64`].
    #[serde(rename = "Action")]
    pub action: i64,
    /// The label after the change; absent on delete.
    #[serde(rename = "Label", default)]
    pub label: Option<Label>,
}

/// One step of the feed.
#[derive(Debug, Clone, Deserialize)]
pub struct Event {
    /// Id to pass to [`Session::events`] to read what follows this event.
    #[serde(rename = "EventID")]
    pub event_id: String,
    /// More events wait after this one.
    #[serde(rename = "More", default)]
    pub more: ApiBool,
    /// Bit mask of areas the server wants refetched; bit 1 is mail.
    #[serde(rename = "Refresh", default)]
    pub refresh: i64,
    /// Message changes.
    #[serde(rename = "Messages", default, deserialize_with = "null_is_empty")]
    pub messages: Vec<MessageEvent>,
    /// Label changes.
    #[serde(rename = "Labels", default, deserialize_with = "null_is_empty")]
    pub labels: Vec<LabelEvent>,
}

impl Event {
    /// The server lost track of the changes: refetch mail instead of applying them.
    pub fn requires_resync(&self) -> bool {
        self.refresh & 1 != 0
    }
}

/// What one [`Session::events`] call collected.
#[derive(Debug, Clone)]
pub struct EventBatch {
    /// The events in order; the first may carry the id that was asked for
    /// when nothing is new.
    pub events: Vec<Event>,
    /// More events wait on the server (the call stopped at its cap).
    pub more: bool,
    /// Id of the last event; pass it to the next call.
    pub latest_event_id: String,
}

/// Reads `null` as an empty list.
fn null_is_empty<'de, D: serde::Deserializer<'de>, T: serde::Deserialize<'de>>(
    d: D,
) -> std::result::Result<Vec<T>, D::Error> {
    Option::<Vec<T>>::deserialize(d).map(Option::unwrap_or_default)
}

/// Response of `GET /core/v4/events/latest`.
#[derive(Deserialize)]
struct LatestResponse {
    #[serde(rename = "EventID")]
    event_id: String,
}

impl Session {
    /// The id of the newest event; start polling from here.
    ///
    /// # Errors
    ///
    /// Any [`Error`](crate::error::Error) the transport classifies to, or
    /// `InvalidResponse` when the reply does not parse.
    pub async fn latest_event_id(&self) -> Result<String> {
        let reply: LatestResponse = self
            .transport()
            .get_json("/core/v4/events/latest", &[])
            .await?;

        Ok(reply.event_id)
    }

    /// Reads the events after `since`, following the server's `More` flag for
    /// at most 50 events. `since` and each followed id are sent as one
    /// escaped path segment. The first event may repeat `since` when nothing is
    /// new; it is returned all the same.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when `since` or a followed id is `.` or `..`,
    /// before any request for it is sent; otherwise any [`Error`] the
    /// transport classifies to, or `InvalidResponse` when a reply does not
    /// parse.
    pub async fn events(&self, since: &str) -> Result<EventBatch> {
        let mut events: Vec<Event> = Vec::new();
        let mut next = since.to_owned();

        loop {
            // No escaping helps here: URL parsing reads `%2E%2E` as `..` too.
            if matches!(next.as_str(), "." | "..") {
                return Err(Error::InvalidConfig("event id is a dot segment"));
            }

            let event: Event = self
                .transport()
                .get_json(&format!("/core/v4/events/{}", path_segment(&next)), &[])
                .await?;
            let more = event.more.0;

            next.clone_from(&event.event_id);
            events.push(event);

            if !more || events.len() >= MAX_COLLECTED_EVENTS {
                return Ok(EventBatch {
                    events,
                    more,
                    latest_event_id: next,
                });
            }
        }
    }
}
