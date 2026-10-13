# proton-mail-api: notes for agents

Read `README.md` first. This file holds what the code does not say.

## Shape

- Single library crate, edition 2024, pure Rust. No Go FFI for SRP: Proton's
  SRP variant (bcrypt-hashed password, Proton-signed modulus) is
  reimplemented here and tested against captured vectors.
- Reference implementations, in order of trust: `ProtonMail/go-proton-api`
  (the Bridge library), `ProtonMail/WebClients` (the web app, authoritative
  for message packaging on send), `emersion/hydroxide`, `proton-api-rs`
  (archived community crate; shows the shape, not the SRP).
- The crate owns the Proton model (session, keys, labels, messages). The
  consumer maps it into its own store. No posto types in here.
- Secrets the consumer must persist (refresh token, session UID, unlocked
  key material if cached) are handed back as one opaque serialisable blob.

## Module map

- `src/lib.rs`: module list and the crate-level usage example.
- `src/error.rs`: `Error` (redacted `Debug`) and the `Result` alias.
- `src/types.rs`: wire helpers shared by endpoints (`ApiBool`, error envelope,
  path-segment encoding).
- `src/http.rs`: `Transport`: headers, 429/503 backoff, typed errors, 401
  refresh-and-retry.
- `src/srp.rs`: Proton's SRP-6a variant, modulus verification, key password.
- `src/session.rs`: `Client` builder, login, TOTP, refresh, logout,
  `PersistedSession`.
- `src/keys.rs`: fetch user, addresses and salts; `UnlockedKeys`.
- `src/labels.rs`: labels, folders, system folder ids.
- `src/events.rs`: latest event id and the change-event feed.
- `src/messages.rs`: list, fetch, decrypt bodies (incl. PGP/MIME) and
  attachments.
- `src/actions.rs`: mark read/unread, add/remove label, move.

## Rules

- Never put a token, password, passphrase, or private key in an error, log,
  or debug output. `Debug` impls on those types print a redaction marker.
  Never format deserialisation errors that can embed response bodies.
- Private key material lives in types that zeroize on drop.
- Tests run without a live server: fixtures captured from real responses
  with identifiers scrubbed. A live integration test exists but is gated by
  `PROTON_LIVE_TEST=1` and credentials from env; it is never run in CI.
  Its variables: `PROTON_LIVE_TEST`, `PROTON_USERNAME`, `PROTON_PASSWORD`,
  `PROTON_MAILBOX_PASSWORD` (optional), `PROTON_TOTP` (optional),
  `PROTON_APP_VERSION`.
- Fixtures in run 1 are synthetic: built from go-proton-api type definitions
  and rpgp-generated keys, because no real captures exist yet. When a real
  capture lands, it replaces the synthetic fixture for that endpoint.
- Proton rate-limits and may challenge unknown clients with human
  verification. Back off on 429; surface a verification challenge as a
  typed error, never retry it.
- `std::env::set_var` only in a synchronous `main`. Tests pass values in.

## Checks before claiming done

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```
