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

## Rules

- Never put a token, password, passphrase, or private key in an error, log,
  or debug output. `Debug` impls on those types print a redaction marker.
  Never format deserialisation errors that can embed response bodies.
- Private key material lives in types that zeroize on drop.
- Tests run without a live server: fixtures captured from real responses
  with identifiers scrubbed. A live integration test exists but is gated by
  `PROTON_LIVE_TEST=1` and credentials from env; it is never run in CI.
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
