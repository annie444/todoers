use std::path::Path;
use std::sync::Arc;

use sqlx::sqlite::{
    SqliteAutoVacuum, SqliteConnectOptions, SqliteJournalMode, SqliteLockingMode, SqliteSynchronous,
};
use sqlx::{Pool, Sqlite};
use tokio::fs;
use zeroize::Zeroizing;

use crate::auth::{AccountRow, NewAccount};
use crate::config::get_data_dir;

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
