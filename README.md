# proton-mail-api

Unofficial, pure-Rust client for the Proton Mail API: login (Proton SRP,
2FA), key unlock, and the mail operations a desktop client needs. Built to be
imported by [posto](../posto); it knows nothing about posto.

Status: pre-alpha. Proton has no public API contract; this can break without
notice. Bridge is the only route Proton supports.

## Scope of the first cut

- Session: SRP login, TOTP, refresh, logout
- Keys: unlock user and address keys with the mailbox password (OpenPGP)
- Read: labels, message list, fetch and decrypt body and attachments,
  change-events feed
- Triage: mark read/unread, move, label, permanently delete, empty a folder
- Send: plain or HTML body; Proton recipients get the message encrypted,
  others in the clear; reply and forward; attachments, regular and inline;
  a forward carries the original's attachments

Out of scope for now: calendar, SimpleLogin aliases, contacts beyond lookup
of recipient public keys.

## Live test

`tests/live.rs` runs the whole stack against the real Proton API. It does
nothing unless `PROTON_LIVE_TEST=1`; CI never sets it.

| Variable | Use |
|----------|-----|
| `PROTON_LIVE_TEST` | `1` to run the test |
| `PROTON_USERNAME` | Account username |
| `PROTON_PASSWORD` | Login password |
| `PROTON_MAILBOX_PASSWORD` | Optional; defaults to the login password |
| `PROTON_TOTP` | Optional; a current 6-digit code, needed when 2FA is on |
| `PROTON_APP_VERSION` | `x-pm-appversion` value to send |
| `PROTON_USER_AGENT` | Optional; overrides the default `User-Agent` |

Code 2028 is Proton's anti-abuse block; stop retrying and wait before the next attempt.

```sh
PROTON_LIVE_TEST=1 PROTON_USERNAME=... PROTON_PASSWORD=... \
  PROTON_APP_VERSION=... cargo test --test live
```

The live test flips and restores the read state of the newest Inbox message,
and moves it to Archive and back. Restoring is best effort; a failed restore
is reported by name.

## Live send test

`tests/live_send.rs` sends real mail: one message to the account itself with
a text attachment and an inline image, which it then finds in the Inbox,
decrypts and downloads the attachments of; a forward of that message to the
account itself, which it checks for the same attachments; and optionally one
plain message with the text attachment to an address outside Proton. All stay
in place; the test deletes nothing. It does nothing
unless `PROTON_LIVE_SEND=1`; CI never sets it. It uses the same variables as
the live test, plus `PROTON_LIVE_SEND_EXTERNAL`, an optional address outside
Proton that receives the optional external message. Its success is the only check; read
the message yourself.

```sh
PROTON_LIVE_SEND=1 PROTON_USERNAME=... PROTON_PASSWORD='...' \
  PROTON_APP_VERSION=... cargo test --test live_send -- --nocapture
```

## Sending

`Session::send` looks up every recipient's keys before it creates the draft, so
a lookup failure sends nothing and leaves no draft. The draft and send requests
are never repeated automatically, with one exception: a 401 is refused before
processing, so a token refresh repeats the request once.

Attachments are uploaded after the draft is created. An upload is never
repeated, because a repeat would attach the file twice; the one exception is
a 401, which is refused before processing, so a token refresh repeats it
once. A failed upload, or a failure reading the draft's forwarded
attachments, is `SendRejected` with the draft id: the message was not sent,
and the draft is kept and may hold some of the attachments. A lost upload
response is also `SendRejected`, because the final send was never made.

- `SendRejected` means the message was not sent: Proton refused the final
  send before processing it, or an attachment step failed after the draft was
  created. The draft is kept and may hold some of the attachments.
- `SendOutcomeUnknown` means the message may have been sent or may still be
  sent. Never send it again. Once delivery is done, the draft's `SENT` flag
  confirms it; its absence proves nothing.

Limits: a Proton recipient needs a v4 key with a valid encryption subkey (v6
keys and primary-key-only keys are refused), and the sending address needs the
same.

## Capturing fixtures

`tests/capture.rs` records the responses of the GET endpoints the crate reads
and writes them as pretty JSON under `tests/fixtures/live/`. It does nothing
unless `PROTON_CAPTURE=1`; CI never sets it. It uses the same variables as
the live test (`PROTON_USERNAME`, `PROTON_PASSWORD`, `PROTON_APP_VERSION`,
and optionally `PROTON_TOTP` and `PROTON_USER_AGENT`).

```sh
PROTON_CAPTURE=1 PROTON_USERNAME=... PROTON_PASSWORD='...' \
  PROTON_APP_VERSION=... cargo test --test capture -- --nocapture
```

- The capture is read-only: it sends GET requests only.
- Every response is scrubbed by a default-deny policy
  (`tests/support/scrub.rs`): ids and addresses become placeholders, header
  maps are dropped, and a string or number survives only if a rule keeps it.
  Raw responses are never written or printed.
- The files are staged in `tests/fixtures/live.tmp` and replace
  `tests/fixtures/live` only when the whole capture succeeded.
- Read every file before you commit it. The scrubber is tested offline, but
  only you can tell whether something in your mailbox leaked through.

## Checks

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```
