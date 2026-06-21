-- ============================================================================
-- Zero-knowledge shared todo app — CLIENT-LOCAL SQLite schema.
--
-- This is the on-device store, NOT the server. It's the local-first half: the
-- materialized CRDT, an outbound queue for offline edits, sync cursors against
-- the server's log, cached wrapped keys, and a member directory used for
-- OFFLINE signature verification.
--
-- ── AT-REST ENCRYPTION — READ FIRST ───────────────────────────────────────
-- Every column falls into one of three classes:
--
--   (1) already-encrypted or public — safe at rest on plain SQLite.
--       wrapped_secret_keys, wrapped_dek, *_pub, outbound envelopes. These are
--       the same bytes the blind server already holds; disk access reveals
--       nothing new.
--
--   (2) plaintext-for-convenience — safe at rest ONLY if the DB file is
--       encrypted. Decrypted list names, the Loro document, the todo read
--       model. Recommended: open this DB with SQLCipher, keyed by a
--       password-derived key (Argon2id over the local salt in `account`).
--       Without SQLCipher, drop the class-(2) columns and decrypt into memory
--       on demand instead.
--
--   (3) never persisted — unwrapped DEKs and unwrapped private keys live in
--       process memory only. There is no table for them. They are rehydrated
--       at unlock (see notes on `key_slots` and `account`).
--
-- ── CONVENTIONS ────────────────────────────────────────────────────────────
-- 16-byte ids and crypto material as BLOB (with length CHECKs); timestamps as
-- INTEGER unix seconds via unixepoch(). Tables are STRICT for rigid typing.
-- Requires SQLite 3.38+ (STRICT 3.37, unixepoch() 3.38). Re-runnable.
-- Per connection, set: PRAGMA foreign_keys = ON;  PRAGMA journal_mode = WAL;
-- updated_at is maintained in application code (no triggers, to avoid the
-- AFTER UPDATE self-recursion footgun).
-- ============================================================================

-- ── account: the logged-in user (singleton row, id = 1) ─────────────────────
CREATE TABLE IF NOT EXISTS account (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    member_id           BLOB NOT NULL CHECK (length(member_id) = 16),
    username            TEXT NOT NULL,
    identity_pub        BLOB NOT NULL CHECK (length(identity_pub) = 32),  -- X25519
    signing_pub         BLOB NOT NULL CHECK (length(signing_pub) = 32),   -- Ed25519
    -- class (1): private keys sealed under the master key. Unwrapped into
    -- memory at unlock; the plaintext keys are never written back here.
    wrapped_secret_keys BLOB NOT NULL,
    -- Local at-rest KDF params, so the master key (and/or SQLCipher key) can be
    -- derived OFFLINE from the password. This is deliberately separate from the
    -- OPAQUE login, which is interactive and can't run without the server.
    kdf_salt            BLOB NOT NULL CHECK (length(kdf_salt) = 16),
    kdf_mem_kib         INTEGER NOT NULL,
    kdf_iters           INTEGER NOT NULL,
    kdf_parallelism     INTEGER NOT NULL,
    device_id           BLOB CHECK (device_id IS NULL OR length(device_id) = 16),
    device_wrapped_keys BLOB,  -- local key file: seal(UnlockedKeys ‖ device-auth key)
    created_at          INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at          INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

-- ── lists: local mirror of each shared list's metadata + sync cursors ───────
CREATE TABLE IF NOT EXISTS lists (
    list_id             BLOB PRIMARY KEY CHECK (length(list_id) = 16),
    role                TEXT NOT NULL CHECK (role IN ('owner','member')),  -- my role
    current_epoch       INTEGER NOT NULL CHECK (current_epoch >= 1),
    name_plaintext      TEXT,    -- class (2): decrypted title; NULL until decrypted
    -- Cursors against the server's GLOBAL seq:
    server_snapshot_seq INTEGER NOT NULL DEFAULT 0,  -- server's compaction high-water mark
    applied_through_seq INTEGER NOT NULL DEFAULT 0,  -- last server seq merged into our doc
    last_synced_at      INTEGER,
    created_at          INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at          INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT, WITHOUT ROWID;

-- ── list_members: cached public identities of co-members ────────────────────
-- class (1), public. Needed OFFLINE to verify each update's Ed25519 signature
-- (look up the author's signing_pub) and to seal DEKs when adding a member.
CREATE TABLE IF NOT EXISTS list_members (
    list_id      BLOB NOT NULL REFERENCES lists(list_id) ON DELETE CASCADE,
    member_id    BLOB NOT NULL CHECK (length(member_id) = 16),
    identity_pub BLOB NOT NULL CHECK (length(identity_pub) = 32),
    signing_pub  BLOB NOT NULL CHECK (length(signing_pub) = 32),
    role         TEXT NOT NULL CHECK (role IN ('owner','member')),
    added_at     INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (list_id, member_id)
) STRICT, WITHOUT ROWID;

-- ── key_slots: cached WRAPPED DEKs (class 1, safe at rest) ───────────────────
-- Unlike the server, the client only holds ITS OWN wrapped DEK per epoch, so
-- the key is (list_id, epoch) — no member dimension. At unlock, run open_sealed
-- over these rows into an in-memory (list_id, epoch) -> DEK map (class 3).
CREATE TABLE IF NOT EXISTS key_slots (
    list_id     BLOB NOT NULL REFERENCES lists(list_id) ON DELETE CASCADE,
    epoch       INTEGER NOT NULL CHECK (epoch >= 1),
    wrapped_dek BLOB NOT NULL,   -- sealed_box(DEK[epoch], my identity_pub)
    created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (list_id, epoch)
) STRICT, WITHOUT ROWID;

-- ── documents: the materialized Loro CRDT, one per list ─────────────────────
-- class (2): plaintext Loro snapshot — protect with SQLCipher. This is the
-- local source of truth for reads. Disposable: rebuildable from the server
-- snapshot + tail of updates if lost or corrupted.
CREATE TABLE IF NOT EXISTS documents (
    list_id       BLOB PRIMARY KEY REFERENCES lists(list_id) ON DELETE CASCADE,
    loro_snapshot BLOB NOT NULL,   -- Loro export(ExportMode::Snapshot)
    updated_at    INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT, WITHOUT ROWID;

-- ── outbound: locally-produced update envelopes awaiting upload ─────────────
-- class (1): each payload is already encrypted + signed — the exact bytes the
-- server will store — so it's safe at rest regardless of SQLCipher. The
-- uploader drains this; a row is deleted once the server acks (assigns a seq).
CREATE TABLE IF NOT EXISTS outbound (
    local_id        INTEGER PRIMARY KEY,    -- rowid; preserves local edit order
    list_id         BLOB NOT NULL REFERENCES lists(list_id) ON DELETE CASCADE,
    epoch           INTEGER NOT NULL CHECK (epoch >= 1),  -- DEK epoch it was sealed under
    payload         BLOB NOT NULL,          -- serialized UpdatePayload (e.g. postcard)
    signature       BLOB NOT NULL CHECK (length(signature) = 64),
    status          TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending','inflight')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
    last_attempt_at INTEGER,
    -- guards against enqueuing the same produced update twice
    CONSTRAINT outbound_sig_unique UNIQUE (signature)
) STRICT;

CREATE INDEX IF NOT EXISTS outbound_drain ON outbound (list_id, local_id);

-- ── todo_items: OPTIONAL denormalized read model for fast UI ────────────────
-- class (2), plaintext, SQLCipher-only. Fully DERIVED from `documents`; safe to
-- drop and rebuild by replaying the Loro doc. Omit entirely if you render by
-- querying the Loro document directly.
CREATE TABLE IF NOT EXISTS todo_items (
    list_id    BLOB NOT NULL REFERENCES lists(list_id) ON DELETE CASCADE,
    item_id    TEXT NOT NULL,              -- Loro item/container id
    text       TEXT NOT NULL,
    done       INTEGER NOT NULL DEFAULT 0 CHECK (done IN (0,1)),
    order_key  TEXT,                       -- fractional index for MovableList position
    due_at     INTEGER,                    -- unix seconds, NULL = no due date
    priority   INTEGER NOT NULL DEFAULT 0, -- 0=none 1=low 2=med 3=high
    notes      TEXT NOT NULL DEFAULT '',   -- free-text body
    tags       TEXT NOT NULL DEFAULT '[]', -- JSON array of strings (denormalized from the doc)
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (list_id, item_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS subtasks (
    list_id      BLOB NOT NULL,
    item_id      TEXT NOT NULL,
    id           TEXT NOT NULL,
    title        TEXT NOT NULL,
    done         INTEGER NOT NULL DEFAULT 0 CHECK (done IN (0,1)),
    updated_at   INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (list_id, item_id, id)
    FOREIGN KEY (list_id, item_id) REFERENCES todo_items(list_id, item_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS todo_items_by_list ON todo_items (list_id, order_key);

-- Meta-list scans ("Due Today/Week/Month") filter by due_at across ALL lists,
-- usually excluding done items; a partial index keeps it tight.
CREATE INDEX IF NOT EXISTS todo_items_due ON todo_items (due_at) WHERE done = 0;

-- Sorting a single list by priority.
CREATE INDEX IF NOT EXISTS todo_items_priority ON todo_items (list_id, priority);

CREATE TABLE sequences (
    name TEXT PRIMARY KEY,
    current_value BLOB NOT NULL
), STRICT, WITHOUT ROWID;

PRAGMA user_version = 1;
PRAGMA foreign_keys = ON;
