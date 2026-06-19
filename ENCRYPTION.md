# ENCRYPTION.md

Architecture outline for the **cryptographic contract** that makes todoers
zero-knowledge. The server is a blind relay: it stores only opaque bytes
(ciphertext, wrapped keys, public keys) and assigns ordering. It can never read
list contents, DEKs, private keys, or passwords. Everything in this document is
client-side except the one narrowly-scoped check noted under *Signatures*.

> **Golden rule:** the byte layout of the signed / AEAD-associated data is
> **duplicated** in two places and the two MUST agree byte-for-byte, or every
> valid signature is rejected. See [The signing contract](#the-signing-contract).

## Where the code lives

| Concern | File |
| --- | --- |
| Wire + key schema, `signing_view` / `aead_aad` (the canonical layout) | `todoers-types/src/lib.rs` |
| All client crypto: AEAD, sealing, KDFs, key wrapping, membership ops | `todoers/src/crypto.rs` |
| OPAQUE auth driver (register / login / unlock), key escrow | `todoers/src/auth.rs` |
| Server OPAQUE wrapper + `ServerSetup` persistence | `todoers-server/src/crypto.rs` |
| Server-side optional signature verification | `todoers-server/src/routes/updates.rs` |
| Blindness contract (at rest, server) | `todoers-server/db/migrations/0001_init.sql` (header) |
| Class-(1/2/3) at-rest rules (client) | `todoers/db/migrations/0001_init.sql` (header) |

## Primitives

- **OPAQUE** (`opaque-ke`) — password-authenticated key exchange. The password
  and the derived `export_key` never reach the server. `SharedCipherSuite`
  (Ristretto255 / TripleDH / SHA-512 / Argon2) is defined **once** in
  `todoers-types` and used by both sides.
- **X25519** (`x25519-dalek` / `dryoc` sealed boxes) — identity keypair; DEKs are
  *sealed to* a member's X25519 public key.
- **Ed25519** (`ed25519-dalek`) — signing keypair; every update is signed and
  verifiable by every member.
- **XChaCha20-Poly1305** (`chacha20poly1305`) — AEAD over list updates, snapshots,
  and the wrapped secret-keys blob (24-byte random nonce).
- **Argon2id** (`argon2`) — KDF for the offline local master key.
- **HMAC-SHA256** — deterministic id derivation.

## Identity & the member id

`member_id` is **not random**: it is `HMAC-SHA256("todoers:member-id:identity:v0001",
identity_pub)` truncated to 16 bytes (`MemberId::from_identity_pub` in
`todoers-types`). It doubles as OPAQUE's `credential_identifier`, so the client
and server MUST derive it identically. The server always re-derives it from the
uploaded `identity_pub` rather than trusting a client-supplied value, so a client
can't forge a mismatch.

Sessions store only a **SHA-512 hash** of the bearer token; logout is per-device.
Unknown-user logins run OPAQUE against a deterministic placeholder id to stay
enumeration-resistant (`placeholder_credential_id` in
`todoers-server/src/routes/auth.rs`).

## Key escrow — two wrappings of the same secret keys

The unwrapped secret keys are `identity_secret(32) ‖ signing_seed(32)`. At
registration (`auth::register_finish`) they are sealed **twice** under two
different master keys:

1. **escrow copy** — sealed under `derive_escrow_key(export_key)` (a single
   domain-separated SHA-256 over the high-entropy OPAQUE `export_key`), uploaded
   to the server so a **fresh device** can recover after an online login.
2. **local copy** — sealed under `derive_local_master(password, salt, Argon2id
   params)`, persisted in the SQLite `account` row for **offline** unlock with no
   server. KDF params are stored per-account so they can evolve.

Both wrappings produce `nonce(24) ‖ XChaCha20-Poly1305(master, id ‖ sign)`. A
wrong key (wrong password / wrong `export_key`) fails the AEAD tag check.
`build_local_account` re-creates the local copy after a fresh-device login.

### Optional third wrapping — password-less device unlock (`crypto::device_*`)

When a device opts in (`[device_unlock]` config), the same secret keys are sealed
a **third** way: to a local **AGE/SSH** key via the `age` crate, written to
`account.device_wrapped_keys`. Bundled in that cache is a per-device **Ed25519
device-auth keypair**; its public half is enrolled with the server (`POST
/v1/auth/devices`). On later launches the app decrypts the cache with the local
key (no password) and does a **device login** — signing a server challenge with
the device-auth key — to get a session. AGE is encryption-only, so the dedicated
Ed25519 key keeps the server's check uniform (it only ever does Ed25519 verify).

The cache blob is **class-1** (already encrypted), safe at rest like the others.
Its protection is only as strong as the local key — prefer agent/passphrase/
hardware-backed keys over a plaintext identity file. Trusted keys are stored
server-side as plaintext public keys (no list content), so zero-knowledge holds.
**Revoking** a device rejects its future logins and deletes its live sessions;
enroll/revoke require step-up (a recent password, never a device, session).

Unwrapped private keys and DEKs are **class-3** material: in memory only
(`UnlockedKeys`), never written to disk.

## Per-list encryption — DEKs and epochs

Each list has a **Data Encryption Key (DEK)** per `Epoch` (a `u32` generation
counter). An update is:

```
ciphertext = XChaCha20-Poly1305(DEK[epoch], nonce, plaintext = Loro CRDT update, aad = aead_aad)
signature  = Ed25519(signing_key, signing_view)        // encrypt-then-sign
```

Each member's DEK is sealed to their X25519 pubkey as a `KeySlot` (anonymous
sealed box via `dryoc` — carries no sender identity; only the holder of the
matching secret can open it). `KeySlot`s are keyed by `(epoch, member)` so a
member coming online fetches exactly the keys for the epochs still live in the log.

### Membership changes (`crypto::add_member` / `remove_member`)

- **Add** — seal the *current* DEK to the new member and append a `KeySlot`. No
  rotation; they only ever see data from now on.
- **Remove** — **rotate**: generate a new DEK, `current_epoch += 1`, re-seal to
  the *remaining* members, and drop the removed member's slots. Future updates
  use the new epoch. (You cannot retract plaintext they already synced — that
  boundary is inherent.)

The matching server-side persistence is `db::add_member` / `db::remove_member`.

## The signing contract

`aead_aad` and `signing_view` define the exact byte layout that is signed and fed
as AEAD associated data:

```
AAD          = version ‖ list_id(16) ‖ epoch_le(4) ‖ author(16) ‖ nonce(24)
signing_view = AAD ‖ ciphertext
```

The AAD binds a ciphertext to its `(list, epoch, author, nonce)` context so a
member can't lift a valid ciphertext into a different list/epoch/author. All
fields are fixed-width, so plain concatenation is unambiguous.

**This layout is duplicated** in `todoers-types/src/lib.rs` (`signing_view` /
`aead_aad`, used by the server) and `todoers/src/crypto.rs` (the private
`signing_view` / `aead_aad`, used by the client). When you touch the
update/signature path, **change both together** or signature verification rejects
every valid update.

## Signatures on the server (the one allowed "understanding")

The server is otherwise blind, but when `verify_signatures` is on
(`AppState`), `append_update` verifies the Ed25519 signature over
`signing_view` before storing, using the author's `signing_pub` fetched from
membership (so a non-member has no key → rejected). This is the single piece of
content a blind relay is permitted to check. Idempotency is enforced separately
by a UNIQUE constraint on the signature.

## At-rest classes

- **Server** (`todoers-server/db/migrations/0001_init.sql`): every `_pub` column
  is public; every `ciphertext` / `wrapped_*` / `opaque_*` column is opaque bytes.
  No plaintext ever touches the DB.
- **Client** (`todoers/db/migrations/0001_init.sql`): class-(1) already-encrypted
  or public (safe on plain SQLite), class-(2) plaintext-for-convenience (safe only
  under SQLCipher), class-(3) never persisted (DEKs / private keys, memory only).

## Tests to run

```sh
cargo test -p todoers escrow_round_trip_recovers_identity   # full register→login→unlock cycle
cargo test -p todoers wrong_password_fails_login
```

These play the OPAQUE server side in-process and need no DB or network
(`todoers/src/auth.rs`).
