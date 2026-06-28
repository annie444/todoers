# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A zero-knowledge, end-to-end-encrypted collaborative todo app. A ratatui TUI client
holds the keys and does all crypto; the Axum server is a **blind relay** that stores
only opaque bytes (ciphertext, wrapped keys, public keys) and assigns ordering. The
server can never read list contents, DEKs, private keys, or passwords.

Four-crate Cargo workspace (edition 2024):

- **`todoers-types`** — the shared wire + key schema, and the *cryptographic contract*.
  Not just DTOs: `signing_view()` / `aead_aad()` define the exact signed/AEAD byte
  layout. This layout is **duplicated** in `todoers-client/src/crypto.rs` and the two MUST
  agree byte-for-byte, or signature verification rejects every valid update. The
  `postgres` feature gates `sqlx::Type` derives so the server can use the types in queries.
- **`todoers-server`** — Axum + PostgreSQL (sqlx). Stateless blind relay + OPAQUE auth.
- **`todoers-client`** — the client **library**: local-first SQLite store (SQLCipher,
  encrypted at rest), OPAQUE client, all crypto (`auth.rs`, `crypto.rs`, `sqlcipher.rs`,
  `device_key/`, `db.rs`, `model.rs`, `list_doc.rs`, `net/`, `session.rs`).
- **`todoers`** — the client **binary**: the ratatui TUI (`app.rs`, `components/`,
  `store*.rs`, `sync.rs`) plus the startup bootstrap (`main.rs`); depends on `todoers-client`.
  Keep this lib/binary boundary in mind: crypto/DB/networking live in `todoers-client/src/`;
  only UI and bootstrap live in `todoers/src/`.

## Component deep-dives — when to reference each

The sections below are a high-level map. Each major component has a dedicated
architecture outline; read the relevant one **before** working in that area, and
keep it updated when the architecture changes:

- **When working on encryption, key escrow, OPAQUE auth, the signing/AEAD byte
  layout, DEKs/epochs, membership rotation, or the SQLCipher at-rest layer, reference the
  architecture outline in [ENCRYPTION.md](./ENCRYPTION.md).** (Spans `todoers-types/src/lib.rs`,
  `todoers-client/src/crypto.rs`, `todoers-client/src/auth.rs`,
  `todoers-client/src/sqlcipher.rs`, `todoers-client/src/device_key/`, and
  `todoers-server/src/crypto.rs`.)
- **When working on the server — HTTP/WebSocket endpoints, routing, the
  `AuthMember` extractor, the update log/snapshots, or real-time fanout — reference
  the architecture outline in [API.md](./API.md).** (Covers `todoers-server`.)
- **When working on the TUI client — the event loop, the `Component` trait,
  actions, modes, modals, input capture, or off-loop networked work — reference the
  architecture outline in [TUI.md](./TUI.md).** (Covers the `todoers` client.)

## Build & run

The two crates differ in build requirements — this matters constantly:

- **Server uses compile-time-checked `sqlx::query!` macros with no `.sqlx` offline cache.**
  Building or testing `todoers-server` requires a live `DATABASE_URL` pointing at a
  **migrated** PostgreSQL instance. `.envrc` sets it (use direnv, or export it yourself):
  `export DATABASE_URL=postgresql://todoers:todoers@localhost:5432/todoers`
- **`todoers-client` also uses compile-time-checked `sqlx::query!` macros** for some queries
  (the `account` and device-cache rows; list/item queries are unchecked runtime
  `sqlx::query()`). So building or testing `todoers-client` needs `CLIENT_DATABASE_URL`
  pointing at a **migrated** SQLite file, with no `.sqlx` offline cache. `sqlx.toml` maps the
  var (`database-url-var = "CLIENT_DATABASE_URL"`); `.envrc` sets it. One-time setup:
  `cd todoers-client && sqlx database create && sqlx migrate run --source db/migrations`.
  (This dev DB is plaintext and only used for macro schema checks — separate from the app's
  real **encrypted** `todoers.db`. SQLCipher with no key opens a plaintext DB fine.)
- Both server and client embed migrations via `sqlx::migrate!` and run them on startup
  (server: `todoers-server/db/migrations/`, PostgreSQL; client:
  `todoers-client/db/migrations/`, SQLite).
- The **client** has a `vergen-gix` build script — it reads git/cargo/build info at compile
  time (used in `--version`). A git repo must be present to build the client.

Common commands (`just --list` for the full set; recipes use podman):

```sh
just db-up            # start a Postgres 18 container (volume-backed) on :5432
just run-server       # db-up, export DATABASE_URL, then cargo run -p todoers-server
just db-exec          # psql into the running container
just db-down          # stop & remove the container; db-clean wipes the volume

cargo todoers         # run the TUI client  (alias for: run -p todoers --)
cargo server          # run the server      (alias; needs DATABASE_URL)
cargo b / c / t       # build / check / test  (aliases in .cargo/config.toml)
```

Tests (`cargo test`):
- Server tests use `#[sqlx::test]`, which provisions an **ephemeral per-test database** —
  they still need `DATABASE_URL` set (and Postgres reachable) at both compile and run time.
- `todoers-server/src/routes/testutil.rs` drives the OPAQUE *client* side through all four
  auth endpoints; call `register_and_login(...)` to get a real bearer token in one line.
- Crypto/auth round-trips in the client (`todoers-client/src/auth.rs`, `crypto.rs`) play the
  OPAQUE server in-process and need no DB or network at runtime (building still needs
  `CLIENT_DATABASE_URL`, as above). Run one test:
  `cargo test -p todoers-client escrow_round_trip_recovers_identity`.

Server config: layered via the `config` crate (`todoers.toml`, `/etc/todoers*`, XDG config
dir, then `TODOERS__`-prefixed env vars with `__` as separator). See `todoers-server/todoers.toml`.

## Crypto & data model (the parts that span files)

**Identity & auth (OPAQUE).** Registration/login is OPAQUE (`opaque-ke`, `SharedCipherSuite`
defined once in `todoers-types`), so the password and the derived `export_key` never reach
the server. The server's long-lived `ServerSetup` is persisted to `general.key_file` —
regenerating it invalidates every stored password. `member_id` is **not** random: it's
`HMAC-SHA256(identity_pub)` (`MemberId::from_identity_pub`), used directly as OPAQUE's
`credential_identifier`, so client and server must derive it identically. Sessions store
only a SHA-512 *hash* of the bearer token; logout is per-device. Unknown-user logins run
OPAQUE against a deterministic placeholder id to stay enumeration-resistant.

**Key escrow — two wrappings of the same secret keys** (`todoers-client/src/auth.rs`):
1. *escrow* copy, sealed under `derive_escrow_key(export_key)`, uploaded to the server so a
   fresh device can recover after login;
2. *local* copy, sealed under an Argon2id key derived from the password (params stored in the
   SQLite `account` row), for **offline** unlock with no server.
Unwrapped private keys and DEKs are class-3 material: in memory only, never written to disk.

**Database encryption at rest (SQLCipher).** The whole local SQLite DB is encrypted with
SQLCipher (`todoers-client/src/sqlcipher.rs`), so even the class-2 plaintext-for-convenience
columns are protected on disk. A random 32-byte SQLCipher key is wrapped in a
`TodoersKeyEnvelope` (JSON at `{data_dir}/db_keys.json`, **outside** the DB since it must be
read before the DB opens) for two recipients: a **device** recipient (X-Wing KEM, private key
in the OS keyring) and a **password** recipient (Argon2id over a generated **recovery key**).
On first run the bootstrap (`todoers/src/main.rs`) generates and displays the recovery key;
thereafter the DB **auto-unlocks via the device key**, falling back to the recovery key if
that device key is lost. `Db::new`/`Db::init` take the key and set `PRAGMA key` (sqlx 0.9
emits it first, as SQLCipher requires). Note: this requires `todoers-client` to depend on
`libsqlite3-sys` **explicitly** with `bundled-sqlcipher-vendored-openssl` — a
`[workspace.dependencies]` entry alone does not activate the feature, and without it
`PRAGMA key` is silently ignored and the DB is cleartext (guarded by the regression test
`db::tests::keyed_database_is_encrypted_on_disk`). This is a separate layer from the account
keys (escrow above) and the per-list DEKs (below). See [ENCRYPTION.md](./ENCRYPTION.md).

**Per-list encryption (DEK + epochs).** Each list has a Data Encryption Key per `Epoch`.
Updates are `XChaCha20-Poly1305(DEK[epoch])` over a Loro CRDT binary update, then Ed25519
encrypt-then-sign over `signing_view`. Each member's DEK is sealed to their X25519 pubkey as
a `KeySlot` (anonymous sealed box via `dryoc`). Adding a member just seals the current DEK to
them; **removing** a member rotates: new DEK, `current_epoch += 1`, re-seal to remaining
members, drop the removed member's slots (see `crypto::add_member`/`remove_member` and the
matching `db::add_member`/`remove_member`).

**The log (`updates`) + snapshots.** The server append-only `updates` table assigns a global
`seq` (`GENERATED ALWAYS AS IDENTITY`); `seq` is server-assigned, unsigned, and untrusted —
CRDT merge is order-independent so reordering is harmless. Idempotency comes from a UNIQUE
constraint on the Ed25519 signature. Clients pull `?after=<seq>`; periodically a client
compacts by uploading a re-encrypted snapshot with a `covers_seq` high-water mark, and the
server deletes folded-away updates in the same transaction. The blindness contract is
documented at the top of `todoers-server/db/migrations/0001_init.sql`; class-(1/2/3) at-rest
rules are at the top of `todoers-client/db/migrations/0001_init.sql`.

**Real-time.** `Hub` (`state.rs`) is a per-list `tokio::broadcast` channel — no external
broker. WS subscribers get live fanout; laggards/offline clients fall back to the pull
endpoint. WS membership enforcement is currently a stub (`routes/ws.rs`).

## Server request flow

`main.rs` → `routes::build_router` wires all endpoints under `/v1` plus `/healthz`, with a
`TraceLayer`. `AppState` (db pool + `Hub` + `OpaqueServer` + `verify_signatures`) is cheaply
cloneable and passed as Axum state. Authenticated handlers take an `AuthMember` extractor
(`routes/auth.rs`), which resolves `Bearer` token → session → `member_id` on every request.
All DB access goes through `db.rs`; multi-statement work uses `Db::safe_transaction`. Errors
funnel through `error::AppError` (`IntoResponse`), which logs internals and returns opaque
messages. A background `DbWorker` (`workers.rs`) periodically GCs expired sessions/logins.

## Client (TUI) architecture

Ratatui Component architecture in `app.rs`. `App` owns: a `Config`, the SQLite `Db`, the current `Mode`, a map
of `Mode → Box<dyn Component>`, and an mpsc `Action` channel. The loop is
`handle_events → handle_actions → render`. Events become `Action`s; `App` mutates global state
and also forwards each action to the active component's `update`. Components implement the
`Component` trait (`components/mod.rs`): `draw` is required, the rest default to no-ops.

- **`Action`** (`action.rs`) is the single message enum. `Action::Register` carries the
  password and is deliberately redacted in both `Display` and the `debug!` in `handle_actions` —
  never log it verbatim.
- **Input capture**: while a text input is focused, `App.capturing` suppresses keybinding
  dispatch (except a hard-quit allowlist) so keystrokes reach the input.
- **Config** (`config.rs`): defaults baked in via `include_str!("../app_config.toml")`, then
  layered over user files (toml/json/yaml/ini) from the XDG config dir; keybindings and styles
  parse from strings (e.g. `"ctrl-d"`, `"underline red on blue"`).
- **Networked work runs off the UI loop**: `App` spawns tokio tasks (e.g. registration calls
  `net::register`) and feeds results back as `Action`s. CPU-bound KDF work uses `spawn_blocking`.
- The `net/` module (in `todoers-client`) is HTTP transport only; `auth.rs` (also
  `todoers-client`) is pure (builds/consumes wire DTOs, no I/O) so it stays unit-testable.
  `App`, `Action`, `Config`, and the components live in the `todoers` binary; the `Db`, `Store`
  session keys, crypto, and `net/` come from `todoers-client`.

## Conventions

- The HTTP/WS wire is **postcard** (binary): requests/responses are `postcard::to_stdvec` /
  `from_bytes` of the `todoers-types` DTOs — no `axum::Json`, not base64-JSON. Client `net/`
  calls funnel through the `req` / `decode` / `unit` helpers in `todoers-client/src/net/mod.rs`;
  reuse them instead of re-inlining the send → `error_for_status` → decode chain.
- 16-byte ids are stored as Postgres `UUID` / sqlx `Uuid` (a `member_id` is an opaque 16 bytes,
  not a real RFC-4122 UUID). SQLite stores ids/keys as length-checked `BLOB`s.
- DEKs and secret keys use `zeroize`; the `Dek` type zeroes on drop.
- When touching the update/signature path, change `signing_view`/`aead_aad` in **both**
  `todoers-types/src/lib.rs` and `todoers-client/src/crypto.rs` together.
