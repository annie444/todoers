# API.md

Architecture outline for **`todoers-server`** — the Axum + PostgreSQL blind relay
and its HTTP/WebSocket API. The server stores only opaque bytes and assigns
ordering; it never sees list contents, DEKs, private keys, or passwords. For the
cryptographic side of what these bytes mean, see
[ENCRYPTION.md](./ENCRYPTION.md).

## Build & test note (read first)

The server uses compile-time-checked `sqlx::query!` macros with **no `.sqlx`
offline cache**, so building *or* testing `todoers-server` requires a live
`DATABASE_URL` pointing at a **migrated** PostgreSQL instance:

```sh
export DATABASE_URL=postgresql://todoers:todoers@localhost:5432/todoers   # see .envrc
just db-up && just run-server      # start Postgres 18, migrate, run the server
```

Tests use `#[sqlx::test]`, which provisions an **ephemeral per-test database**
(still needs `DATABASE_URL` at compile and run time).
`todoers-server/src/routes/testutil.rs` drives the OPAQUE *client* side through
all four auth endpoints — call `register_and_login(...)` for a real bearer token
in one line.

## Request flow

`main.rs` → `routes::build_router` (`routes/mod.rs`) wires every endpoint under
`/v1` plus `/healthz`, behind a `TraceLayer`.

- **`AppState`** (`state.rs`) holds the db pool, the `Hub`, the `OpaqueServer`,
  and the `verify_signatures` flag. It is cheaply cloneable (`PgPool` and `Hub`
  are internally `Arc`) and is passed as Axum state.
- **Auth** is the `AuthMember` extractor (`routes/auth.rs`): it resolves
  `Authorization: Bearer <token>` → SHA-512 hash → session row → `member_id` on
  every authenticated request. Missing/invalid token → `401`. Because the
  extractor runs before the body extractor, an unauthenticated POST is rejected
  before its body is parsed.
- **All DB access** goes through `db.rs`; multi-statement work uses
  `Db::safe_transaction`.
- **Errors** funnel through `error::AppError` (`IntoResponse`), which logs
  internals and returns opaque messages.
- A background **`DbWorker`** (`workers.rs`) periodically GCs expired sessions and
  in-progress logins.

## Configuration

Layered via the `config` crate: `todoers.toml`, `/etc/todoers*`, the XDG config
dir, then `TODOERS__`-prefixed env vars (with `__` as the nesting separator). See
`todoers-server/todoers.toml` and `todoers-server/src/config.rs`. The long-lived
OPAQUE `ServerSetup` is persisted to `general.key_file` — **regenerating it
invalidates every stored password.**

## Endpoints

Handlers live in `todoers-server/src/routes/`. All `/v1/*` routes except the auth
endpoints require a bearer token via `AuthMember`.

### Health
| Method | Path | Handler | Notes |
| --- | --- | --- | --- |
| GET | `/healthz` | `health::healthz` | Liveness; no auth. |

### Auth — OPAQUE, two messages per flow (`routes/auth.rs`)
| Method | Path | Notes |
| --- | --- | --- |
| POST | `/v1/auth/register/start` | Server is **stateless** between the two register messages. Responds to a `RegistrationRequest`. |
| POST | `/v1/auth/register/finish` | Persists the OPAQUE record, public identity, and the escrowed (already-sealed) private keys. `member_id` is re-derived from `identity_pub`. |
| POST | `/v1/auth/login/start` | Stashes transient `ServerLogin` state in `login_cache` keyed by `login_id`; returns `(login_id, credential_response)`. Unknown users get a deterministic placeholder so the response is enumeration-resistant. |
| POST | `/v1/auth/login/finish` | Finishes the AKE, mints a session token (only its SHA-512 hash is stored), returns the token + escrow blob for a fresh device to rehydrate keys. |
| POST | `/v1/auth/logout` | Revokes **this device's** session (per-device, by token hash). Requires auth. |

Sessions are **tagged with the device** that minted them: `NULL` for a password
login, the `device_id` for a device login (below). This lets revocation kill a
device's live sessions and lets sensitive ops require a password session.

### Password-less device login — trusted device keys (`routes/device.rs`)
A device seals its keys on disk under a local AGE/SSH key and enrolls a per-device
Ed25519 *device-auth* public key. It then logs in without a password by signing a
server challenge (`device_challenge_view`), verified against the enrolled key.

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/v1/auth/devices` | Enroll this device's Ed25519 trusted key. **Step-up:** requires a recent *password* session (a device session or a stale one → `403`). → `201`. |
| GET | `/v1/auth/devices` | List the caller's enrolled devices (any session). |
| DELETE | `/v1/auth/devices/{device_id}` | Revoke a device (compromise kill-switch): future device logins are rejected **and** its live sessions are deleted. **Step-up** required. → `204`. |
| POST | `/v1/auth/device-login/start` | Issue a challenge for an enrolled, non-revoked device (else `401`). Stashes `device_id ‖ nonce` in the consume-once `login_cache`. |
| POST | `/v1/auth/device-login/finish` | Verify the signed challenge (gated by `verify_signatures`), mint a session **tagged with `device_id`**, and return the token + public identity (no escrow blob — the device already has its keys). |

### Control plane — lists, members, keys (`routes/lists.rs`, `routes/users.rs`)
| Method | Path | Notes |
| --- | --- | --- |
| POST | `/v1/lists` | Create a list; body carries the creator's `wrapped_dek`. → `201` + `list_id`. |
| GET | `/v1/lists/{list_id}` | List metadata: `current_epoch`, members, latest snapshot. |
| POST | `/v1/lists/{list_id}/members` | Add a member with a DEK sealed to them. (`TODO`: owner-role enforcement.) → `204`. |
| DELETE | `/v1/lists/{list_id}/members` | Remove a member; client has rotated the DEK and bumped the epoch. → `204`. |
| GET | `/v1/lists/{list_id}/keys` | The **caller's own** wrapped DEKs (one per live epoch). |
| GET | `/v1/users/{username}/pubkeys` | Public keys for a user (to seal a DEK to them when adding). |

### Data plane — updates & snapshots (`routes/updates.rs`, `routes/snapshots.rs`)
| Method | Path | Notes |
| --- | --- | --- |
| POST | `/v1/lists/{list_id}/updates` | Append one signed, encrypted update. Server assigns `seq`; checks `author == caller`, nonce=24B, sig=64B, and (if `verify_signatures`) the Ed25519 signature. Fans out to WS subscribers. → `201` + `seq`. |
| GET | `/v1/lists/{list_id}/updates?after=N&limit=M` | Pull the log after `seq` N (default limit 500). |
| GET | `/v1/lists/{list_id}/snapshot` | Fetch the current compaction snapshot. |
| PUT | `/v1/lists/{list_id}/snapshot` | Client-driven compaction: store the re-encrypted snapshot and delete superseded updates **in one transaction**. → `204`. |

### Real-time (`routes/ws.rs`)
| Method | Path | Notes |
| --- | --- | --- |
| ANY | `/v1/lists/{list_id}/ws` | WebSocket upgrade (`any()` so it works over HTTP/1.1 GET and HTTP/2). Subscribes to the list's broadcast channel and forwards every published update. Inbound writes are not accepted — appends go through the POST path. |

## The log, ordering, and idempotency

The append-only `updates` table assigns a global `seq`
(`GENERATED ALWAYS AS IDENTITY`). `seq` is server-assigned, **unsigned, and
untrusted** — CRDT merge is order-independent, so reordering or withholding is
harmless. Idempotency comes from a **UNIQUE constraint on the Ed25519
signature**. Clients pull `?after=<seq>`; periodically a client compacts by
`PUT`ing a re-encrypted snapshot with a `covers_seq` high-water mark, and the
server deletes folded-away updates in the same transaction.

## Real-time fanout (`Hub`, `state.rs`)

`Hub` is a per-list `tokio::broadcast` channel (capacity 256) — no external
broker. WS subscribers get live fanout; a client that lags past the ring buffer
receives `RecvError::Lagged`, the server closes the socket, and the client
reconciles via the pull endpoint (the same snapshot-then-tail path it already
has). Offline members simply catch up via pull on next connect.

> **Known stub:** WS membership enforcement is not yet implemented
> (`routes/ws.rs`) — auth is checked but list membership is not. Likewise,
> owner-role checks on add/remove member are marked `TODO` in `routes/lists.rs`.
