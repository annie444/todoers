use std::path::Path;
use std::sync::Arc;

use sqlx::sqlite::{
    SqliteAutoVacuum, SqliteConnectOptions, SqliteJournalMode, SqliteLockingMode, SqliteSynchronous,
};
use sqlx::{Pool, Row, Sqlite};
use time::OffsetDateTime;
use tokio::fs;
use zeroize::Zeroizing;

use todoers_types::{Ed25519Pub, Epoch, ListId, Member, MemberId, Role, X25519Pub};

use crate::auth::{AccountRow, NewAccount};
use crate::config::get_data_dir;
use crate::model::{Priority, TodoItem};

/// A list row as stored locally (the sidebar's per-list basics, before
/// aggregates like open-count are computed from the read model).
#[derive(Debug, Clone)]
pub struct ListRow {
    pub list_id: ListId,
    pub name: String,
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

fn parse_role(s: &str) -> Role {
    match s {
        "owner" => Role::Owner,
        _ => Role::Member,
    }
}

fn list_id_from(bytes: Vec<u8>) -> ListId {
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes);
    ListId(id)
}

#[derive(Clone)]
pub struct Db {
    pool: Arc<Pool<Sqlite>>,
}

impl Db {
    #[tracing::instrument]
    pub async fn new<P: AsRef<Path> + std::fmt::Debug>(data_dir: P) -> anyhow::Result<Self> {
        if !data_dir.as_ref().exists() {
            fs::create_dir_all(&data_dir).await?;
        }
        let opts = SqliteConnectOptions::new()
            .statement_cache_capacity(10)
            .synchronous(SqliteSynchronous::Normal)
            .auto_vacuum(SqliteAutoVacuum::Incremental)
            .optimize_on_close(true, None)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .locking_mode(SqliteLockingMode::Normal)
            .filename(format!("{}/todoers.db", get_data_dir().display()));

        Ok(Self {
            pool: Arc::new(Pool::connect_with(opts).await?),
        })
    }

    #[tracing::instrument]
    pub async fn init<P: AsRef<Path> + std::fmt::Debug>(data_dir: P) -> anyhow::Result<Self> {
        let pool = Self::new(data_dir).await?;
        pool.migrate().await?;
        Ok(pool)
    }

    #[tracing::instrument(skip(self))]
    pub async fn migrate(&self) -> anyhow::Result<()> {
        let mut txn = self.pool.begin().await?;
        sqlx::migrate!("db/migrations").run(&mut *txn).await?;
        txn.commit().await?;
        Ok(())
    }

    // ── account (singleton row, id = 1) ──────────────────────────────────────────
    // Runtime (unchecked) queries on purpose: the client has no compile-time SQLite
    // to validate against, and the schema is owned by the embedded migration.

    /// Persist (or replace) the local account row after registration.
    #[tracing::instrument(skip(self, account))]
    pub async fn save_account(&self, account: &NewAccount) -> anyhow::Result<()> {
        let mut txn = self.pool.begin().await?;
        sqlx::query!(
            r#"
            INSERT OR REPLACE INTO account
                (id, member_id, username, identity_pub, signing_pub,
                wrapped_secret_keys, kdf_salt, kdf_mem_kib, kdf_iters, kdf_parallelism)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            account.member_id.0.as_slice(),
            &account.username,
            account.identity_pub.0.as_slice(),
            account.signing_pub.0.as_slice(),
            &account.wrapped_secret_keys,
            account.kdf_salt.0.as_slice(),
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
    pub async fn load_account(&self) -> anyhow::Result<Option<Zeroizing<AccountRow>>> {
        let mut conn = self.pool.acquire().await?;
        let account = sqlx::query_as!(
            AccountRow,
            r#"
            SELECT member_id, username, identity_pub, signing_pub,
                wrapped_secret_keys, kdf_salt, kdf_mem_kib, kdf_iters, kdf_parallelism
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
    pub async fn save_device_cache(&self, device_id: &[u8; 16], blob: &[u8]) -> anyhow::Result<()> {
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
    pub async fn load_device_cache(&self) -> anyhow::Result<Option<([u8; 16], Vec<u8>)>> {
        let row = sqlx::query!("SELECT device_id, device_wrapped_keys FROM account WHERE id = 1")
            .fetch_optional(&*self.pool)
            .await?;
        Ok(
            row.and_then(|r| match (r.device_id, r.device_wrapped_keys) {
                (Some(id), Some(blob)) if id.len() == 16 => {
                    let mut device_id = [0u8; 16];
                    device_id.copy_from_slice(&id);
                    Some((device_id, blob))
                }
                _ => None,
            }),
        )
    }

    /// Forget the device cache (e.g. after revocation or a backend change).
    #[tracing::instrument(skip(self))]
    pub async fn clear_device_cache(&self) -> anyhow::Result<()> {
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
        list_id: ListId,
        role: Role,
        current_epoch: Epoch,
        name: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO lists (list_id, role, current_epoch, name_plaintext)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(list_id) DO UPDATE SET
                role = excluded.role,
                current_epoch = excluded.current_epoch,
                name_plaintext = excluded.name_plaintext,
                updated_at = unixepoch()
            "#,
        )
        .bind(list_id.0.as_slice())
        .bind(role.as_str())
        .bind(current_epoch)
        .bind(name)
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    /// All locally-known lists (sidebar basics).
    #[tracing::instrument(skip(self))]
    pub async fn list_lists(&self) -> anyhow::Result<Vec<ListRow>> {
        let rows = sqlx::query(
            "SELECT list_id, role, current_epoch, name_plaintext FROM lists ORDER BY name_plaintext",
        )
        .fetch_all(&*self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| ListRow {
                list_id: list_id_from(r.get::<Vec<u8>, _>("list_id")),
                name: r
                    .get::<Option<String>, _>("name_plaintext")
                    .unwrap_or_default(),
                role: parse_role(&r.get::<String, _>("role")),
                current_epoch: r.get::<i64, _>("current_epoch") as Epoch,
            })
            .collect())
    }

    /// The current DEK epoch a list writes new updates under.
    #[tracing::instrument(skip(self))]
    pub async fn list_epoch(&self, list_id: ListId) -> anyhow::Result<Option<Epoch>> {
        let row = sqlx::query("SELECT current_epoch FROM lists WHERE list_id = ?")
            .bind(list_id.0.as_slice())
            .fetch_optional(&*self.pool)
            .await?;
        Ok(row.map(|r| r.get::<i64, _>("current_epoch") as Epoch))
    }

    /// Bump (or set) a list's current DEK epoch — used after a membership
    /// rotation so subsequent updates are written under the new epoch.
    #[tracing::instrument(skip(self))]
    pub async fn set_epoch(&self, list_id: ListId, epoch: Epoch) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE lists SET current_epoch = ?, updated_at = unixepoch() WHERE list_id = ?",
        )
        .bind(epoch)
        .bind(list_id.0.as_slice())
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn rename_list(&self, list_id: ListId, name: &str) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE lists SET name_plaintext = ?, updated_at = unixepoch() WHERE list_id = ?",
        )
        .bind(name)
        .bind(list_id.0.as_slice())
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    /// Delete a list and everything that cascades (members, key_slots, document,
    /// outbound, todo_items) via the schema's `ON DELETE CASCADE`.
    #[tracing::instrument(skip(self))]
    pub async fn delete_list(&self, list_id: ListId) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM lists WHERE list_id = ?")
            .bind(list_id.0.as_slice())
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    // ── documents (Loro snapshot) ──────────────────────────────────────────────

    #[tracing::instrument(skip(self))]
    pub async fn load_document(&self, list_id: ListId) -> anyhow::Result<Option<Vec<u8>>> {
        let row = sqlx::query("SELECT loro_snapshot FROM documents WHERE list_id = ?")
            .bind(list_id.0.as_slice())
            .fetch_optional(&*self.pool)
            .await?;
        Ok(row.map(|r| r.get::<Vec<u8>, _>("loro_snapshot")))
    }

    #[tracing::instrument(skip(self, snapshot))]
    pub async fn save_document(&self, list_id: ListId, snapshot: &[u8]) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO documents (list_id, loro_snapshot)
            VALUES (?, ?)
            ON CONFLICT(list_id) DO UPDATE SET
                loro_snapshot = excluded.loro_snapshot,
                updated_at = unixepoch()
            "#,
        )
        .bind(list_id.0.as_slice())
        .bind(snapshot)
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
        list_id: ListId,
        items: &[TodoItem],
    ) -> anyhow::Result<()> {
        let mut txn = self.pool.begin().await?;
        sqlx::query("DELETE FROM todo_items WHERE list_id = ?")
            .bind(list_id.0.as_slice())
            .execute(&mut *txn)
            .await?;
        for it in items {
            let tags = serde_json::to_string(&it.tags).unwrap_or_else(|_| "[]".into());
            sqlx::query(
                r#"
                INSERT INTO todo_items
                    (list_id, item_id, text, done, order_key, due_at, priority, notes, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(list_id.0.as_slice())
            .bind(&it.id)
            .bind(&it.title)
            .bind(it.done as i64)
            .bind(&it.order_key)
            .bind(it.due.map(|d| d.unix_timestamp()))
            .bind(it.priority.rank())
            .bind(&it.notes)
            .bind(tags)
            .execute(&mut *txn)
            .await?;
        }
        txn.commit().await?;
        Ok(())
    }

    /// Load a list's read-model items in stored order (subtasks empty — load the
    /// full item from the doc for editing).
    #[tracing::instrument(skip(self))]
    pub async fn load_todo_items(&self, list_id: ListId) -> anyhow::Result<Vec<TodoItem>> {
        let rows = sqlx::query(
            "SELECT item_id, text, done, order_key, due_at, priority, notes, tags \
             FROM todo_items WHERE list_id = ? ORDER BY order_key",
        )
        .bind(list_id.0.as_slice())
        .fetch_all(&*self.pool)
        .await?;
        Ok(rows.iter().map(row_to_item).collect())
    }

    /// Load every list's read-model items (for the meta-list aggregate views),
    /// paired with the owning list id.
    #[tracing::instrument(skip(self))]
    pub async fn load_all_todo_items(&self) -> anyhow::Result<Vec<(ListId, TodoItem)>> {
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
    pub async fn list_members(&self, list_id: ListId) -> anyhow::Result<Vec<Member>> {
        let rows = sqlx::query(
            "SELECT member_id, identity_pub, signing_pub, role FROM list_members WHERE list_id = ?",
        )
        .bind(list_id.0.as_slice())
        .fetch_all(&*self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| Member {
                id: MemberId(to_16(r.get::<Vec<u8>, _>("member_id"))),
                identity_pub: X25519Pub(to_32(r.get::<Vec<u8>, _>("identity_pub"))),
                signing_pub: Ed25519Pub(to_32(r.get::<Vec<u8>, _>("signing_pub"))),
                role: parse_role(&r.get::<String, _>("role")),
            })
            .collect())
    }

    #[tracing::instrument(skip(self))]
    pub async fn add_member_row(&self, list_id: ListId, member: &Member) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO list_members (list_id, member_id, identity_pub, signing_pub, role)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(list_id, member_id) DO UPDATE SET
                identity_pub = excluded.identity_pub,
                signing_pub = excluded.signing_pub,
                role = excluded.role
            "#,
        )
        .bind(list_id.0.as_slice())
        .bind(member.id.0.as_slice())
        .bind(member.identity_pub.0.as_slice())
        .bind(member.signing_pub.0.as_slice())
        .bind(member.role.as_str())
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn remove_member_row(
        &self,
        list_id: ListId,
        member_id: MemberId,
    ) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM list_members WHERE list_id = ? AND member_id = ?")
            .bind(list_id.0.as_slice())
            .bind(member_id.0.as_slice())
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    // ── key slots (cached wrapped DEKs) ────────────────────────────────────────

    #[tracing::instrument(skip(self, wrapped_dek))]
    pub async fn save_key_slot(
        &self,
        list_id: ListId,
        epoch: Epoch,
        wrapped_dek: &[u8],
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO key_slots (list_id, epoch, wrapped_dek)
            VALUES (?, ?, ?)
            ON CONFLICT(list_id, epoch) DO UPDATE SET wrapped_dek = excluded.wrapped_dek
            "#,
        )
        .bind(list_id.0.as_slice())
        .bind(epoch)
        .bind(wrapped_dek)
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    /// All cached wrapped DEKs across lists — rehydrated into memory at unlock.
    #[tracing::instrument(skip(self))]
    pub async fn load_key_slots(&self) -> anyhow::Result<Vec<KeySlotRow>> {
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
        list_id: ListId,
        epoch: Epoch,
        payload: &[u8],
        signature: &[u8; 64],
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO outbound (list_id, epoch, payload, signature)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(signature) DO NOTHING
            "#,
        )
        .bind(list_id.0.as_slice())
        .bind(epoch)
        .bind(payload)
        .bind(signature.as_slice())
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    /// Count pending outbound rows for a list (used by tests / a future uploader).
    #[tracing::instrument(skip(self))]
    pub async fn outbound_count(&self, list_id: ListId) -> anyhow::Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM outbound WHERE list_id = ?")
            .bind(list_id.0.as_slice())
            .fetch_one(&*self.pool)
            .await?;
        Ok(row.get::<i64, _>("n"))
    }
}

#[cfg(test)]
impl Db {
    /// Build a `Db` around a test-provided pool (e.g. from `#[sqlx::test]`).
    pub(crate) fn from_pool(pool: Pool<Sqlite>) -> Self {
        Self {
            pool: Arc::new(pool),
        }
    }
}

fn to_16(v: Vec<u8>) -> [u8; 16] {
    let mut a = [0u8; 16];
    a.copy_from_slice(&v);
    a
}

fn to_32(v: Vec<u8>) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
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

    impl Db {
        fn new_for_test(db: Pool<Sqlite>) -> Self {
            Self { pool: Arc::new(db) }
        }
    }

    #[sqlx::test(migrations = "db/migrations")]
    async fn account_round_trips(db: Pool<Sqlite>) {
        let db = Db::new_for_test(db);

        let account = NewAccount {
            member_id: MemberId([7u8; 16]),
            username: "dana".into(),
            identity_pub: X25519Pub([1u8; 32]),
            signing_pub: Ed25519Pub([2u8; 32]),
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
        assert_eq!(
            loaded.wrapped_secret_keys,
            account.wrapped_secret_keys.into()
        );
        assert_eq!(loaded.kdf_salt, account.kdf_salt);
        assert_eq!(loaded.kdf_mem_kib, account.kdf_mem_kib);
    }
}
