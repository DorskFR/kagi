# kagi

This project follows kihon (`~/Documents/kihon`, from `github.com/DorskFR/kihon`). The rules below are specific to this project and override kihon.

## Project

- Shared passkey (WebAuthn) relying-party toolkit. One repo, two packages consumed by git tag:
  the Rust crate `kagi` (root `Cargo.toml`, `src/`) and the npm package `@dorsk/kagi` (root
  `package.json`, TypeScript source in `ts/` shipped as-is, no build step).
- Stack: Rust 2024 on webauthn-rs `=0.6.2` (`conditional-ui`), framework-agnostic. Browser
  helper over `navigator.credentials`, zero runtime dependencies. `ts/generated` is written by
  ts-rs during `cargo test` and committed.
- Commands: `make lint`, `make test`, `make fmt`. Cargo runs under
  `flock ~/.cache/kagi-build.lock`; use the Makefile targets or the same `flock` prefix.
- Deploy: none. A release is a signed `vX.Y.Z` tag plus a GitHub release; consumers bump the tag.
- Tracker: YouTrack `KAGI`.

## Rules

- No new dependency, Rust or npm, without human approval. Every crate in `Cargo.lock` and every
  package in `package-lock.json` must already be used by a sibling project at that version.
- No HTTP, sessions, cookies, CSRF or user tables in the crate; it returns verified results and
  the apps keep the rest.
- A ceremony store never evicts a live ceremony: caps refuse.
- Decoy answers must stay indistinguishable from real ones, across restarts with the same key.
- Keep the webauthn-rs `Passkey` serde format: apps store it as is.
- Bump `Cargo.toml` and `package.json` versions together; the tag is the release.
