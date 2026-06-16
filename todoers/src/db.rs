use std::ops::Deref;

use sqlx::migrate::Migrate;
use sqlx::sqlite::{
    SqliteAutoVacuum, SqliteConnectOptions, SqliteJournalMode, SqliteLockingMode, SqliteSynchronous,
};
use sqlx::{Acquire, Pool, Sqlite};

pub async fn new() -> anyhow::Result<Pool<Sqlite>> {
    let opts = SqliteConnectOptions::new()
        .statement_cache_capacity(10)
        .synchronous(SqliteSynchronous::Normal)
        .auto_vacuum(SqliteAutoVacuum::Incremental)
        .optimize_on_close(true, None)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .locking_mode(SqliteLockingMode::Normal)
        .filename("todoers.db");

    Ok(Pool::connect_with(opts).await?)
}

pub async fn init() -> anyhow::Result<Pool<Sqlite>> {
    let pool = new().await?;
    migrate(&pool).await?;
    Ok(pool)
}
pub async fn migrate<'a, A>(pool: A) -> anyhow::Result<()>
where
    A: Acquire<'a>,
    <A::Connection as Deref>::Target: Migrate,
{
    sqlx::migrate!("db/migrations").run(pool).await?;
    Ok(())
}
