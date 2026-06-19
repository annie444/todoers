-- ============================================================================
-- Zero-knowledge shared todo app — PostgreSQL schema.
--
-- BLINDNESS CONTRACT: the database stores no plaintext. Columns ending in
-- _pub are non-secret public keys every ciphertext / wrapped_* / opaque_*
-- column is opaque bytes the server cannot interpret. List content, DEKs,
-- private keys, and passwords never touch this DB in the clear.
--
-- 16-byte identifiers are stored as UUID (a UUID is exactly 16 bytes and maps
-- cleanly to [u8 16] / uuid::Uuid). member_id is the client-derived hash of a
-- user's identity_pub it is not a real RFC-4122 UUID, just an opaque 16 bytes.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "moddatetime";
CREATE EXTENSION IF NOT EXISTS "pg_prewarm";

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'member_role') THEN
        CREATE TYPE member_role AS ENUM ('owner', 'member');
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- users — identity. Public keys are cleartext private keys are wrapped under
-- a master key derived from the OPAQUE export_key, so the server stays blind.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    member_id           UUID PRIMARY KEY,
    username            TEXT NOT NULL UNIQUE,                       -- OPAQUE login lookup handle
    identity_pub        BYTEA NOT NULL UNIQUE CHECK (octet_length(identity_pub) = 32),  -- X25519 DEKs sealed to this
    signing_pub         BYTEA NOT NULL UNIQUE CHECK (octet_length(signing_pub) = 32),   -- Ed25519 verifies updates
    wrapped_secret_keys BYTEA NOT NULL,                            -- X25519+Ed25519 privs, sealed under master key
    opaque_record       BYTEA NOT NULL,                            -- OPAQUE server registration record
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS users_by_identity_pub ON users (identity_pub);
CREATE UNIQUE INDEX IF NOT EXISTS users_by_username ON users (username);

CREATE OR REPLACE TRIGGER users_set_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION moddatetime('updated_at');

-- ---------------------------------------------------------------------------
-- login_cache — OPAQUE authentication state. One row per in-progress login,
-- keyed by the temporary OPAQUE export_key (the client proves possession of
-- the corresponding import key). After successful login, the server deletes
-- this row and issues a session token referencing the user.
-- ---------------------------------------------------------------------------
CREATE UNLOGGED TABLE IF NOT EXISTS login_cache (
    login_id   UUID PRIMARY KEY,
    member_id  UUID,
    state      BYTEA NOT NULL, -- OPAQUE server login state
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS login_cache_by_expires_at ON login_cache (expires_at);

ALTER TABLE login_cache SET (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_vacuum_threshold = 50
);

SELECT pg_prewarm('login_cache');

-- ---------------------------------------------------------------------------
-- sessions — minted after a successful OPAQUE login. We store only a HASH of
-- the bearer token, never the token itself: a database leak then can't be
-- replayed as a credential. The server hashes the presented token on each
-- request and looks the row up by `token_hash`.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    token_hash BYTEA PRIMARY KEY,                 -- hash of the bearer token, never the token
    member_id  UUID NOT NULL REFERENCES users(member_id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Serves the periodic cleanup of expired sessions.
CREATE INDEX IF NOT EXISTS sessions_by_expires_at ON sessions (expires_at);

-- ---------------------------------------------------------------------------
-- lists — the list itself. current_epoch is the DEK generation new updates are
-- written under. encrypted_name is AEAD'd under the current DEK (nullable).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS lists (
    list_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    current_epoch  BIGINT NOT NULL DEFAULT 1 CHECK (current_epoch >= 1),
    encrypted_name BYTEA,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE TRIGGER lists_set_updated_at BEFORE UPDATE ON lists
    FOR EACH ROW EXECUTE FUNCTION moddatetime('updated_at');

-- ---------------------------------------------------------------------------
-- list_members — who can read/write, and their role. The membership graph is
-- cleartext metadata (an inherent E2EE leak see the threat-model note).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS list_members (
    list_id    UUID NOT NULL REFERENCES lists(list_id) ON DELETE CASCADE,
    member_id  UUID NOT NULL REFERENCES users(member_id) ON DELETE CASCADE,
    role       member_role NOT NULL DEFAULT 'member',
    added_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (list_id, member_id)
);

CREATE INDEX IF NOT EXISTS list_members_by_member ON list_members (member_id);

-- ---------------------------------------------------------------------------
-- key_slots — one wrapped DEK per (list, epoch, member). On rotation you add a
-- new epoch's slots for the remaining members on compaction you GC retired
-- epochs. A returning client fetches exactly the epochs still live in the log.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS key_slots (
    list_id     UUID NOT NULL REFERENCES lists(list_id) ON DELETE CASCADE,
    epoch       BIGINT NOT NULL CHECK (epoch >= 1),
    member_id   UUID NOT NULL REFERENCES users(member_id) ON DELETE CASCADE,
    wrapped_dek BYTEA NOT NULL,                                    -- sealed_box(DEK[epoch], member.identity_pub)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (list_id, epoch, member_id)
);

CREATE INDEX IF NOT EXISTS key_slots_fetch ON key_slots (list_id, member_id);

-- ---------------------------------------------------------------------------
-- updates — the append-only log. seq is a GLOBAL identity column giving total
-- storage order per-list pulls filter by list_id and ORDER BY seq. seq is
-- server-assigned and unsigned (the author signs context+ciphertext, never the
-- storage slot). author is FK RESTRICT so you can't delete a user out from
-- under their history — compact past them first.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS updates (
    seq        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    list_id    UUID NOT NULL REFERENCES lists(list_id) ON DELETE CASCADE,
    epoch      BIGINT NOT NULL CHECK (epoch >= 1),
    author     UUID NOT NULL REFERENCES users(member_id) ON DELETE RESTRICT,
    nonce      BYTEA NOT NULL CHECK (octet_length(nonce) = 24),   -- XChaCha20-Poly1305
    ciphertext BYTEA NOT NULL,                                    -- AEAD(DEK[epoch]) of a Loro binary update
    signature  BYTEA NOT NULL CHECK (octet_length(signature) = 64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Idempotent re-delivery: an Ed25519 signature is unique per update, so a
    -- retried insert collides here and the app treats it as already-stored.
    CONSTRAINT updates_signature_unique UNIQUE (signature)
);

CREATE INDEX IF NOT EXISTS updates_pull ON updates (list_id, seq);

-- ---------------------------------------------------------------------------
-- snapshots — compacted state, one current snapshot per list. covers_seq is
-- the high-water mark the snapshot incorporates after upserting, the app
-- deletes updates with seq <= covers_seq. Re-encrypted under current_epoch at
-- compaction time so a new member needs only the current DEK to read history.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS snapshots (
    list_id     UUID PRIMARY KEY REFERENCES lists(list_id) ON DELETE CASCADE,
    epoch       BIGINT NOT NULL CHECK (epoch >= 1),
    covers_seq  BIGINT NOT NULL DEFAULT 0,
    nonce       BYTEA NOT NULL CHECK (octet_length(nonce) = 24),
    ciphertext  BYTEA NOT NULL,                                   -- AEAD(DEK[epoch]) of the merged Loro doc
    signature   BYTEA NOT NULL CHECK (octet_length(signature) = 64),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE TRIGGER snapshots_set_updated_at BEFORE UPDATE ON snapshots
    FOR EACH ROW EXECUTE FUNCTION moddatetime('updated_at');

COMMENT ON COLUMN users.wrapped_secret_keys IS 'X25519+Ed25519 private keys sealed under the OPAQUE export_key-derived master key - server-blind.';
COMMENT ON COLUMN updates.seq IS 'Global append order. Per-list pull = WHERE list_id=arg1 AND seq>arg2 ORDER BY seq.';
COMMENT ON TABLE  snapshots IS 'One compacted snapshot per list - replaces updates with seq <= covers_seq.';
