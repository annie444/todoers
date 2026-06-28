use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sqlx::sqlite::{
    SqliteAutoVacuum, SqliteConnectOptions, SqliteJournalMode, SqliteLockingMode,
    SqlitePoolOptions, SqliteSynchronous,
};
use sqlx::{Pool, Row, Sqlite};
use time::OffsetDateTime;
use tokio::fs;
use zeroize::Zeroizing;

use todoers_types::{
    DeviceId, Ed25519Pub, Epoch, ListId, Member, MemberId, Role, Signature, X25519Pub,
};

use crate::auth::{AccountRow, KdfSalt, NewAccount};
use crate::error::{TodoersError, TodoersResult};
use crate::model::{Priority, Subtask, SubtaskRow, TodoItem, TodoItemRow};
use crate::sqlcipher::DbCipher;

/// A list row as stored locally (the sidebar's per-list basics, before
/// aggregates like open-count are computed from the read model).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ListRow {
    pub list_id: ListId,
    pub name: Option<String>,
    pub role: Role,
    pub current_epoch: Epoch,
}

/// One cached wrapped DEK (`open_sealed` rehydrates these into the in-memory
/// [`crate::session::Session`] DEK map at unlock).
#[derive(Debug, Clone)]
pub struct KeySlotRow {
    pub list_id: ListId,
    pub epoch: Epoch,
    pub wrapped_dek: Vec<u8>,
}

/// A pending outbound update claimed by the uploader. `payload` is the exact
/// `serde_json(UpdatePayload)` bytes to POST; `local_id` is the queue rowid used
/// to ack (delete) or release (requeue) the row afterward.
#[derive(Debug, Clone)]
pub struct OutboundRow {
    pub local_id: i64,
    pub list_id: ListId,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DeviceCacheRow {
    pub device_id: DeviceId,
    pub device_wrapped_keys: Vec<u8>,
}

fn list_id_from(bytes: Vec<u8>) -> ListId {
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes);
    ListId::new(id)
}

#[derive(Clone)]
pub struct Db {
    pool: Arc<Pool<Sqlite>>,
}

impl Db {
    #[tracing::instrument(skip(key))]
    pub async fn new<P: AsRef<Path> + std::fmt::Debug>(
        data_dir: P,
        key: &[u8; 32],
        cipher: DbCipher,
    ) -> TodoersResult<Self> {
        if !data_dir.as_ref().exists() {
            fs::create_dir_all(&data_dir).await?;
        }
        // The SQLCipher key must be the first PRAGMA on every connection. sqlx
        // pre-seeds `key` ahead of `journal_mode`/`page_size` in its pragma map,
        // so setting it here emits `PRAGMA key = "x'<hex>'"` before anything else.
        // The 64-hex `x'...'` form supplies a raw key, skipping SQLCipher's KDF.
        let opts = SqliteConnectOptions::new()
            .pragma(
                "key",
                format!("\"x'{}'\"", hex::encode(key).to_ascii_uppercase()),
            )
            .pragma(
                "cipher_salt",
                format!("\"x'{}'\"", hex::encode(cipher.salt).to_ascii_uppercase()),
            )
            .pragma("kdf_iter", format!("{}", cipher.kdf_iter))
            .pragma("cipher_kdf_algorithm", cipher.kdf)
            .pragma("cipher_hmac_algorithm", cipher.hmac)
            .pragma("cipher_page_size", format!("{}", cipher.page_size))
            .pragma("cipher_default_kdf_iter", format!("{}", cipher.kdf_iter))
            .pragma("cipher_default_kdf_algorithm", cipher.kdf)
            .pragma("cipher_default_hmac_algorithm", cipher.hmac)
            .pragma("cipher_default_page_size", format!("{}", cipher.page_size))
            .statement_cache_capacity(10)
            .synchronous(SqliteSynchronous::Normal)
            .auto_vacuum(SqliteAutoVacuum::Incremental)
            .optimize_on_close(true, None)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .locking_mode(SqliteLockingMode::Normal)
            .busy_timeout(Duration::from_secs(5))
            .filename(data_dir.as_ref().join("todoers.db"));

        Ok(Self {
            pool: Arc::new(
                SqlitePoolOptions::new()
                    .max_connections(1)
                    .connect_with(opts)
                    .await?,
            ),
        })
    }

    #[tracing::instrument]
    pub fn from_pool(db: Pool<Sqlite>) -> Self {
        Self { pool: Arc::new(db) }
    }

    #[tracing::instrument(skip(key))]
    pub async fn init<P: AsRef<Path> + std::fmt::Debug>(
        data_dir: P,
        key: &[u8; 32],
        cipher: DbCipher,
    ) -> TodoersResult<Self> {
        let pool = Self::new(data_dir, key, cipher).await?;
        pool.migrate().await?;
        Ok(pool)
    }

    #[tracing::instrument(skip(self))]
    pub async fn migrate(&self) -> TodoersResult<()> {
        let mut txn = self.pool.begin().await?;
        sqlx::migrate!("db/migrations").run(&mut *txn).await?;
        txn.commit().await?;
        Ok(())
    }

    // ── account (singleton row, id = 1) ──────────────────────────────────────────
    // These use compile-time-checked `sqlx::query!` macros, so building this crate
    // needs `CLIENT_DATABASE_URL` pointing at a migrated SQLite DB (see CLAUDE.md →
    // Build & run). The list/item queries further down use unchecked runtime queries.

    /// Persist (or replace) the local account row after registration.
    #[tracing::instrument(skip(self, account))]
    pub async fn save_account(&self, account: &NewAccount) -> TodoersResult<()> {
        let mut txn = self.pool.begin().await?;
        sqlx::query!(
            r#"
            INSERT OR REPLACE INTO account
                (id, member_id, username, identity_pub, signing_pub,
                wrapped_secret_keys, kdf_salt, kdf_mem_kib, kdf_iters, kdf_parallelism)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            account.member_id.as_slice(),
            &account.username,
            account.identity_pub.as_slice(),
            account.signing_pub.as_slice(),
            &account.wrapped_secret_keys,
            account.kdf_salt.as_slice(),
            account.kdf_mem_kib,
            account.kdf_iters,
            account.kdf_parallelism,
        )
        .execute(&mut *txn)
        .await?;

        txn.commit().await?;
        Ok(())
    }

    /// Load the singleton account row, if registration has completed on this device.
    #[tracing::instrument(skip(self))]
    pub async fn load_account(&self) -> TodoersResult<Option<Zeroizing<AccountRow>>> {
        let mut conn = self.pool.acquire().await?;
        let account = sqlx::query_as!(
            AccountRow,
            r#"
            SELECT
                member_id AS "member_id: MemberId",
                username,
                identity_pub AS "identity_pub: X25519Pub",
                signing_pub AS "signing_pub: Ed25519Pub",
                wrapped_secret_keys,
                kdf_salt AS "kdf_salt: KdfSalt",
                kdf_mem_kib,
                kdf_iters,
                kdf_parallelism
            FROM account WHERE id = 1
            "#,
        )
        .fetch_optional(&mut *conn)
        .await?;
        conn.close().await?;

        Ok(account.map(Zeroizing::new))
    }

    // ── device unlock cache (class-1 sealed blob; see migration 0002) ────────────

    /// Store this device's sealed key cache + its server-side device id.
    #[tracing::instrument(skip(self, blob))]
    pub async fn save_device_cache(&self, device_id: &[u8; 16], blob: &[u8]) -> TodoersResult<()> {
        sqlx::query!(
            r#"
            UPDATE account
            SET device_id = ?, device_wrapped_keys = ?, updated_at = unixepoch()
            WHERE id = 1
            "#,
            device_id.as_slice(),
            blob,
        )
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    /// Load the device cache (`device_id`, sealed blob), if this device has
    /// enrolled for password-less unlock.
    #[tracing::instrument(skip(self))]
    pub async fn load_device_cache(&self) -> TodoersResult<Option<(DeviceId, Vec<u8>)>> {
        let row = sqlx::query_as!(
            DeviceCacheRow,
            r#"
            SELECT
                device_id AS "device_id!: DeviceId",
                device_wrapped_keys AS "device_wrapped_keys!: Vec<u8>"
            FROM account
            WHERE id = 1"#
        )
        .fetch_optional(&*self.pool)
        .await?;
        Ok(row.map(|r| (r.device_id, r.device_wrapped_keys)))
    }

    /// Forget the device cache (e.g. after revocation or a backend change).
    #[tracing::instrument(skip(self))]
    pub async fn clear_device_cache(&self) -> TodoersResult<()> {
        sqlx::query!(
            "UPDATE account SET device_id = NULL, device_wrapped_keys = NULL WHERE id = 1"
        )
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    // ── lists ─────────────────────────────────────────────────────────────────
    // From here down we use runtime (unchecked) queries — the documented client
    // convention — so new tables don't require regenerating the `.sqlx` cache.

    /// Insert or update a list's local metadata row.
    #[tracing::instrument(skip(self))]
    pub async fn upsert_list(
        &self,
        list_id: &ListId,
        role: Role,
        current_epoch: Epoch,
        name: &str,
    ) -> TodoersResult<()> {
        sqlx::query!(
            r#"
            INSERT INTO lists (list_id, role, current_epoch, name_plaintext)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(list_id) DO UPDATE SET
                role = excluded.role,
                current_epoch = excluded.current_epoch,
                name_plaintext = excluded.name_plaintext,
                updated_at = unixepoch()
            "#,
            list_id.as_slice(),
            role.as_str(),
            current_epoch,
            name,
        )
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    /// All locally-known lists (sidebar basics).
    #[tracing::instrument(skip(self))]
    pub async fn list_lists(&self) -> TodoersResult<Vec<ListRow>> {
        let rows = sqlx::query_as!(
            ListRow,
            r#"
            SELECT
                list_id AS "list_id: ListId",
                role,
                current_epoch,
                name_plaintext AS name
            FROM lists
            ORDER BY name_plaintext
            "#,
        )
        .fetch_all(&*self.pool)
        .await?;
        Ok(rows)
    }

    /// The current DEK epoch a list writes new updates under.
    #[tracing::instrument(skip(self))]
    pub async fn list_epoch(&self, list_id: &ListId) -> TodoersResult<Option<Epoch>> {
        let row = sqlx::query_scalar!(
            "SELECT current_epoch FROM lists WHERE list_id = ?",
            list_id.as_slice()
        )
        .fetch_optional(&*self.pool)
        .await?;
        Ok(row)
    }

    /// Bump (or set) a list's current DEK epoch — used after a membership
    /// rotation so subsequent updates are written under the new epoch.
    #[tracing::instrument(skip(self))]
    pub async fn set_epoch(&self, list_id: &ListId, epoch: Epoch) -> TodoersResult<()> {
        sqlx::query!(
            "UPDATE lists SET current_epoch = ?, updated_at = unixepoch() WHERE list_id = ?",
            epoch,
            list_id.as_slice()
        )
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn rename_list(&self, list_id: &ListId, name: &str) -> TodoersResult<()> {
        sqlx::query!(
            "UPDATE lists SET name_plaintext = ?, updated_at = unixepoch() WHERE list_id = ?",
            name,
            list_id.as_slice()
        )
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    /// Delete a list and everything that cascades (members, key_slots, document,
    /// outbound, todo_items) via the schema's `ON DELETE CASCADE`.
    #[tracing::instrument(skip(self))]
    pub async fn delete_list(&self, list_id: &ListId) -> TodoersResult<()> {
        sqlx::query!("DELETE FROM lists WHERE list_id = ?", list_id.as_slice())
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    // ── documents (Loro snapshot) ──────────────────────────────────────────────

    #[tracing::instrument(skip(self))]
    pub async fn load_document(&self, list_id: &ListId) -> TodoersResult<Option<Vec<u8>>> {
        let row = sqlx::query_scalar!(
            "SELECT loro_snapshot FROM documents WHERE list_id = ?",
            list_id.as_slice()
        )
        .fetch_optional(&*self.pool)
        .await?;
        Ok(row)
    }

    #[tracing::instrument(skip(self, snapshot))]
    pub async fn save_document(&self, list_id: &ListId, snapshot: &[u8]) -> TodoersResult<()> {
        sqlx::query!(
            r#"
            INSERT INTO documents (list_id, loro_snapshot)
            VALUES (?, ?)
            ON CONFLICT(list_id) DO UPDATE SET
                loro_snapshot = excluded.loro_snapshot,
                updated_at = unixepoch()
            "#,
            list_id.as_slice(),
            snapshot,
        )
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    // ── todo_items read model ──────────────────────────────────────────────────

    /// Replace the entire read model for a list (it is derived from the doc, so
    /// rebuild-from-scratch is simplest and correct). Subtasks are intentionally
    /// not projected — only the scalar fields the UI sorts/filters on.
    #[tracing::instrument(skip(self, items))]
    pub async fn replace_todo_items(
        &self,
        list_id: &ListId,
        items: &[TodoItem],
    ) -> TodoersResult<()> {
        let mut txn = self.pool.begin().await?;
        sqlx::query!(
            "DELETE FROM todo_items WHERE list_id = ?",
            list_id.as_slice()
        )
        .execute(&mut *txn)
        .await?;
        for it in items {
            let tags = serde_json::to_string(&it.tags).unwrap_or_else(|_| "[]".into());
            sqlx::query!(
                r#"
                INSERT INTO todo_items
                    (list_id, item_id, text, done, order_key, due_at, priority, notes, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
                list_id.as_slice(),
                &it.id,
                &it.title,
                it.done as i64,
                &it.order_key,
                it.due.map(|d| d.unix_timestamp()),
                it.priority.rank(),
                &it.notes,
                tags
            )
            .execute(&mut *txn)
            .await?;
        }
        txn.commit().await?;
        Ok(())
    }

    /// Load a list's read-model items in stored order (subtasks empty — load the
    /// full item from the doc for editing).
    #[tracing::instrument(skip(self))]
    pub async fn load_todo_items(&self, list_id: &ListId) -> TodoersResult<Vec<TodoItem>> {
        let item_rows = sqlx::query_as!(
            TodoItemRow,
            r#"
            SELECT
                item_id   AS "id!",
                text      AS "title!",
                notes,
                due_at,
                priority,
                done      AS "done!: bool",
                tags,
                order_key AS "order_key!"
            FROM todo_items
            WHERE list_id = ?
            ORDER BY order_key"#,
            list_id.as_slice()
        )
        .fetch_all(&*self.pool)
        .await?;
        let subtask_rows = sqlx::query_as!(
            SubtaskRow,
            r#"
            SELECT item_id AS "item_id!", id AS "id!", title AS "title!", done AS "done!: bool"
            FROM subtasks
            WHERE list_id = ?
            "#,
            list_id.as_slice()
        )
        .fetch_all(&*self.pool)
        .await?;
        let mut by_item: HashMap<String, Vec<Subtask>> = HashMap::new();
        for r in subtask_rows {
            by_item.entry(r.item_id.clone()).or_default().push(r.into());
        }

        let items = item_rows
            .into_iter()
            .map(|r| {
                let subtasks = by_item.remove(&r.id).unwrap_or_default();
                Ok::<_, TodoersError>(TodoItem {
                    subtasks,
                    due: r
                        .due_at
                        .map(OffsetDateTime::from_unix_timestamp)
                        .transpose()?,
                    priority: Priority::from_rank(r.priority),
                    tags: serde_json::from_str(&r.tags)?,
                    id: r.id,
                    title: r.title,
                    notes: r.notes,
                    done: r.done,
                    order_key: r.order_key,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(items)
    }

    /// Load every list's read-model items (for the meta-list aggregate views),
    /// paired with the owning list id.
    #[tracing::instrument(skip(self))]
    pub async fn load_all_todo_items(&self) -> TodoersResult<Vec<(ListId, TodoItem)>> {
        let rows = sqlx::query(
            "SELECT list_id, item_id, text, done, order_key, due_at, priority, notes, tags \
             FROM todo_items ORDER BY due_at",
        )
        .fetch_all(&*self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| (list_id_from(r.get::<Vec<u8>, _>("list_id")), row_to_item(r)))
            .collect())
    }

    // ── members ────────────────────────────────────────────────────────────────

    #[tracing::instrument(skip(self))]
    pub async fn list_members(&self, list_id: &ListId) -> TodoersResult<Vec<Member>> {
        let rows = sqlx::query_as!(
            Member,
            r#"
            SELECT
                member_id AS "id: MemberId",
                identity_pub AS "identity_pub: X25519Pub",
                signing_pub AS "signing_pub: Ed25519Pub",
                role AS "role: Role"
            FROM list_members
            WHERE list_id = ?"#,
            list_id.as_slice(),
        )
        .fetch_all(&*self.pool)
        .await?;
        Ok(rows)
    }

    #[tracing::instrument(skip(self))]
    pub async fn add_member_row(&self, list_id: &ListId, member: &Member) -> TodoersResult<()> {
        sqlx::query!(
            r#"
            INSERT INTO list_members (list_id, member_id, identity_pub, signing_pub, role)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(list_id, member_id) DO UPDATE SET
                identity_pub = excluded.identity_pub,
                signing_pub = excluded.signing_pub,
                role = excluded.role
            "#,
            list_id.as_slice(),
            member.id.as_slice(),
            member.identity_pub.as_slice(),
            member.signing_pub.as_slice(),
            member.role.as_str()
        )
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn remove_member_row(
        &self,
        list_id: &ListId,
        member_id: &MemberId,
    ) -> TodoersResult<()> {
        sqlx::query!(
            "DELETE FROM list_members WHERE list_id = ? AND member_id = ?",
            list_id.as_slice(),
            member_id.as_slice()
        )
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    // ── key slots (cached wrapped DEKs) ────────────────────────────────────────

    /// Save a list's wrapped DEK for a given epoch. If the row already exists, update
    /// it (e.g. after a membership rotation). The `wrapped_dek` is the class-1 sealed
    /// data from the server, which is rehydrated into the in-memory DEK map at unlock.
    #[tracing::instrument(skip(self, wrapped_dek))]
    pub async fn save_key_slot(
        &self,
        list_id: &ListId,
        epoch: Epoch,
        wrapped_dek: &[u8],
    ) -> TodoersResult<()> {
        sqlx::query!(
            r#"
            INSERT INTO key_slots (list_id, epoch, wrapped_dek)
            VALUES (?, ?, ?)
            ON CONFLICT(list_id, epoch) DO UPDATE SET wrapped_dek = excluded.wrapped_dek
            "#,
            list_id.as_slice(),
            epoch,
            wrapped_dek
        )
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    /// All cached wrapped DEKs across lists — rehydrated into memory at unlock.
    #[tracing::instrument(skip(self))]
    pub async fn load_key_slots(&self) -> TodoersResult<Vec<KeySlotRow>> {
        let rows = sqlx::query("SELECT list_id, epoch, wrapped_dek FROM key_slots")
            .fetch_all(&*self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| KeySlotRow {
                list_id: list_id_from(r.get::<Vec<u8>, _>("list_id")),
                epoch: r.get::<i64, _>("epoch") as Epoch,
                wrapped_dek: r.get::<Vec<u8>, _>("wrapped_dek"),
            })
            .collect())
    }

    // ── outbound queue ─────────────────────────────────────────────────────────

    /// Enqueue a produced, signed+encrypted update for later upload. The unique
    /// signature constraint makes re-enqueuing the same update a no-op.
    #[tracing::instrument(skip(self, payload, signature))]
    pub async fn enqueue_outbound(
        &self,
        list_id: &ListId,
        epoch: Epoch,
        payload: &[u8],
        signature: &Signature,
    ) -> TodoersResult<()> {
        sqlx::query!(
            r#"
            INSERT INTO outbound (list_id, epoch, payload, signature)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(signature) DO NOTHING
            "#,
            list_id.as_slice(),
            epoch,
            payload,
            signature.as_slice()
        )
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    /// Count pending outbound rows for a list (used by tests / a future uploader).
    #[tracing::instrument(skip(self))]
    pub async fn outbound_count(&self, list_id: &ListId) -> TodoersResult<i64> {
        let row = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM outbound WHERE list_id = ?",
            list_id.as_slice()
        )
        .fetch_one(&*self.pool)
        .await?;
        Ok(row)
    }

    /// Claim up to `limit` pending rows for upload, flipping them to `inflight`
    /// (and bumping `attempts`) in one transaction so a second drain won't
    /// double-send them. Returned in local edit order (`local_id` ascending).
    #[tracing::instrument(skip(self))]
    pub async fn take_outbound(
        &self,
        list_id: &ListId,
        limit: i64,
    ) -> TodoersResult<Vec<OutboundRow>> {
        let mut txn = self.pool.begin().await?;
        let rows = sqlx::query_as!(
            OutboundRow,
            r#"
            SELECT
                list_id AS "list_id: ListId",
                local_id,
                payload FROM outbound
            WHERE list_id = ? AND status = 'pending'
            ORDER BY local_id
            LIMIT ?
            "#,
            list_id.as_slice(),
            limit
        )
        .fetch_all(&mut *txn)
        .await?;

        for row in &rows {
            sqlx::query!(
                "UPDATE outbound SET status = 'inflight', attempts = attempts + 1, \
                 last_attempt_at = unixepoch() WHERE local_id = ?",
                row.local_id
            )
            .execute(&mut *txn)
            .await?;
        }
        txn.commit().await?;
        Ok(rows)
    }

    /// The server acked the append (assigned a seq) — drop the row.
    #[tracing::instrument(skip(self))]
    pub async fn ack_outbound(&self, local_id: i64) -> TodoersResult<()> {
        sqlx::query!("DELETE FROM outbound WHERE local_id = ?", local_id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    /// The upload failed — return the row to `pending` so a later drain retries.
    #[tracing::instrument(skip(self))]
    pub async fn release_outbound(&self, local_id: i64) -> TodoersResult<()> {
        sqlx::query!(
            "UPDATE outbound SET status = 'pending' WHERE local_id = ?",
            local_id
        )
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    // ── sync cursors (against the server's global seq) ─────────────────────────

    /// The last server `seq` merged into this list's doc (0 if never synced).
    #[tracing::instrument(skip(self))]
    pub async fn applied_through_seq(&self, list_id: &ListId) -> TodoersResult<i64> {
        let row = sqlx::query_scalar!(
            "SELECT applied_through_seq FROM lists WHERE list_id = ?",
            list_id.as_slice()
        )
        .fetch_optional(&*self.pool)
        .await?;
        Ok(row.unwrap_or(0))
    }

    /// Advance the applied-through cursor and stamp `last_synced_at`. Monotonic:
    /// never moves backward, so out-of-order WS/pull merges can't rewind it.
    #[tracing::instrument(skip(self))]
    pub async fn set_applied_through_seq(&self, list_id: &ListId, seq: i64) -> TodoersResult<()> {
        sqlx::query!(
            "UPDATE lists SET applied_through_seq = MAX(applied_through_seq, ?), \
             last_synced_at = unixepoch(), updated_at = unixepoch() WHERE list_id = ?",
            seq,
            list_id.as_slice()
        )
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    /// Record the server's compaction high-water mark (the snapshot's `covers_seq`).
    #[tracing::instrument(skip(self))]
    pub async fn set_server_snapshot_seq(&self, list_id: &ListId, seq: i64) -> TodoersResult<()> {
        sqlx::query!(
            "UPDATE lists SET server_snapshot_seq = ?, updated_at = unixepoch() WHERE list_id = ?",
            seq,
            list_id.as_slice()
        )
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    /// Insert/refresh a list's metadata discovered from the server WITHOUT
    /// clobbering a locally-decrypted name (which the blind server never holds).
    #[tracing::instrument(skip(self))]
    pub async fn upsert_list_meta(
        &self,
        list_id: &ListId,
        role: Role,
        current_epoch: Epoch,
    ) -> TodoersResult<()> {
        sqlx::query!(
            r#"
            INSERT INTO lists (list_id, role, current_epoch)
            VALUES (?, ?, ?)
            ON CONFLICT(list_id) DO UPDATE SET
                role = excluded.role,
                current_epoch = excluded.current_epoch,
                updated_at = unixepoch()
            "#,
            list_id.as_slice(),
            role.as_str(),
            current_epoch
        )
        .execute(&*self.pool)
        .await?;
        Ok(())
    }
}

/// Map a `todo_items` row to a [`TodoItem`] (subtasks are not in the read model).
fn row_to_item(r: &sqlx::sqlite::SqliteRow) -> TodoItem {
    let tags: Vec<String> = serde_json::from_str(&r.get::<String, _>("tags")).unwrap_or_default();
    TodoItem {
        id: r.get::<String, _>("item_id"),
        title: r.get::<String, _>("text"),
        notes: r.get::<String, _>("notes"),
        due: r
            .get::<Option<i64>, _>("due_at")
            .and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok()),
        priority: Priority::from_rank(r.get::<i64, _>("priority")),
        done: r.get::<i64, _>("done") != 0,
        tags,
        subtasks: Vec::new(),
        order_key: r.get::<Option<String>, _>("order_key").unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use todoers_types::{Ed25519Pub, MemberId, X25519Pub};

    #[sqlx::test(migrations = "db/migrations")]
    async fn account_round_trips(db: Pool<Sqlite>) {
        let db = Db::from_pool(db);

        let account = NewAccount {
            member_id: MemberId::new([7u8; 16]),
            username: "dana".into(),
            identity_pub: X25519Pub::new([1u8; 32]),
            signing_pub: Ed25519Pub::new([2u8; 32]),
            wrapped_secret_keys: vec![9, 8, 7, 6, 5],
            kdf_salt: [3u8; 16].into(),
            kdf_mem_kib: crate::auth::KDF_MEM_KIB.into(),
            kdf_iters: crate::auth::KDF_ITERS.into(),
            kdf_parallelism: crate::auth::KDF_PARALLELISM.into(),
        };

        assert!(db.load_account().await.unwrap().is_none());
        db.save_account(&account).await.unwrap();
        let loaded = db.load_account().await.unwrap().unwrap();

        assert_eq!(loaded.member_id, account.member_id);
        assert_eq!(loaded.username, account.username);
        assert_eq!(loaded.identity_pub, account.identity_pub);
        assert_eq!(loaded.signing_pub, account.signing_pub);
        assert_eq!(loaded.wrapped_secret_keys, account.wrapped_secret_keys);
        assert_eq!(loaded.kdf_salt, account.kdf_salt);
        assert_eq!(loaded.kdf_mem_kib, account.kdf_mem_kib);
    }

    /// Build connect options that key the database the same way [`Db::new`] does.
    fn keyed_opts(path: &std::path::Path, key: &[u8; 32]) -> SqliteConnectOptions {
        SqliteConnectOptions::new()
            .pragma("key", format!("\"x'{}'\"", hex::encode(key)))
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .filename(path)
    }

    /// Proves SQLCipher is actually engaged: a keyed database is unreadable as
    /// plaintext on disk, decryptable with the right key, and rejects a wrong key.
    /// If `bundled-sqlcipher` ever stops compiling in, `PRAGMA key` is silently
    /// ignored and this test fails on the plaintext header assertion.
    #[tokio::test]
    async fn keyed_database_is_encrypted_on_disk() {
        let path = std::env::temp_dir().join(format!("todoers-cipher-{}.db", uuid::Uuid::new_v4()));
        let key = [0x42u8; 32];

        // Create the encrypted DB and write a recognizable plaintext marker.
        let pool = Pool::<Sqlite>::connect_with(keyed_opts(&path, &key))
            .await
            .unwrap();
        sqlx::query("CREATE TABLE t (v TEXT)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO t (v) VALUES ('SUPER_SECRET_MARKER')")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;

        // On-disk header is not the SQLite magic, and our marker isn't visible.
        let raw = std::fs::read(&path).unwrap();
        assert_ne!(&raw[..16], b"SQLite format 3\0", "database is plaintext!");
        assert!(
            !raw.windows(b"SUPER_SECRET_MARKER".len())
                .any(|w| w == b"SUPER_SECRET_MARKER"),
            "plaintext leaked into the file"
        );

        // The right key reads it back.
        let pool = Pool::<Sqlite>::connect_with(keyed_opts(&path, &key))
            .await
            .unwrap();
        let v: String = sqlx::query_scalar("SELECT v FROM t")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(v, "SUPER_SECRET_MARKER");
        pool.close().await;

        // A wrong key cannot read it.
        let wrong = Pool::<Sqlite>::connect_with(keyed_opts(&path, &[0x99u8; 32])).await;
        let readable = match wrong {
            Ok(pool) => {
                let r = sqlx::query("SELECT v FROM t").fetch_one(&pool).await;
                pool.close().await;
                r.is_ok()
            }
            Err(_) => false,
        };
        assert!(!readable, "wrong key should not decrypt the database");

        let _ = std::fs::remove_file(&path);
    }
}
