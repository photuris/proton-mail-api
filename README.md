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
- Send: plaintext to external recipients, PGP to Proton recipients

Out of scope for now: calendar, SimpleLogin aliases, contacts beyond lookup
of recipient public keys.

## Checks

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```
