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
- Triage: mark read/unread, move, label
- Send: plaintext to external recipients, PGP to Proton recipients (run 2;
  not in this release)

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
