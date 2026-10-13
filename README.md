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

## Checks

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```
