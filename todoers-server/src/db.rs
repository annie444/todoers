//! Database access layer. All queries are runtime (string) queries so this
//! compiles without a live DB. The server never decrypts anything here — it
//! shuffles opaque bytes and assigns `seq`.

use sqlx::postgres::{PgConnectOptions, PgSslMode};
use sqlx::{PgConnection, PgPool, Pool};
use time::{Duration, OffsetDateTime};
use tracing::{error, info};
use uuid::Uuid;

use todoers_types::{
    DeviceInfo, KeySlotDto, LoginDto, MemberDto, Role, SnapshotDto, StoredUpdateDto, UserPubkeysDto,
};

use crate::config::DbConfig;
use crate::error::{AppError, AppResult};

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("db/migrations");

#[derive(Debug, Clone)]
pub struct Db {
    pool: PgPool,
}

/// What login/start needs from the `users` row: the id to bind the session to
/// and the OPAQUE password file. (Escrow keys are fetched separately at finish.)
#[derive(Debug, Clone)]
pub struct LoginUserRow {
    pub member_id: Uuid,
    pub opaque_record: Vec<u8>,
}

/// The public identity + escrowed private keys for a member.
#[derive(Debug, Clone)]
pub struct UserKeysRow {
    pub identity_pub: Vec<u8>,
    pub signing_pub: Vec<u8>,
    pub wrapped_secret_keys: Vec<u8>,
}

/// A resolved session: which member, which device minted it (`None` = password
/// login), and when — the last two drive step-up auth for sensitive operations.
#[derive(Debug, Clone)]
pub struct SessionRow {
    pub member_id: Uuid,
    pub device_id: Option<Uuid>,
    pub created_at: OffsetDateTime,
}

impl Db {
    const LOGIN_TTL: Duration = Duration::minutes(1);
    pub async fn new(config: &DbConfig) -> anyhow::Result<Self> {
        let mut opts = PgConnectOptions::new()
            .ssl_mode(PgSslMode::Prefer)
            .database(&config.database)
            .statement_cache_capacity(10)
            .application_name("todoers-server");
        if let Some(host) = &config.host {
            opts = opts.host(host);
        }
        if let Some(user) = &config.username {
            opts = opts.username(user);
        }
        if let Some(pass) = &config.password {
            opts = opts.password(pass);
        }
        if let Some(port) = &config.port {
            opts = opts.port(*port);
        }
        if let Some(ca) = &config.ca_path {
            opts = opts.ssl_root_cert(ca);
        }
        if let Some(cert) = &config.cert_path {
            opts = opts.ssl_client_cert(cert);
        }
        if let Some(key) = &config.key_path {
            opts = opts.ssl_client_key(key);
        }

        Ok(Db {
            pool: Pool::connect_with(opts).await?,
        })
    }

    pub async fn init(config: &DbConfig) -> anyhow::Result<Self> {
        let pool = Self::new(config).await?;
        pool.migrate().await?;
        Ok(pool)
    }

    pub async fn migrate(&self) -> anyhow::Result<()> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    async fn safe_transaction<R, F>(&self, f: F) -> AppResult<R>
    where
        F: AsyncFnOnce(&mut PgConnection) -> AppResult<R>,
    {
        let mut tx = self.pool.begin().await?;
        let ret = match f(&mut tx).await {
            Ok(r) => r,
            Err(e) => {
                error!(?e, "transaction failed");
                match tx.rollback().await {
                    Ok(_) => info!("transaction rolled back successfully"),
                    Err(e) => error!(
                        ?e,
                        "transaction rollback failed; manual cleanup may be required"
                    ),
                };
                return Err(e);
            }
        };
        tx.commit().await?;
        Ok(ret)
    }

    /// Insert an update and return its server-assigned `seq`. Idempotent: a retried
    /// upload with the same signature returns the original `seq` instead of erroring.
    pub async fn insert_update(
        &self,
        list_id: Uuid,
        epoch: i64,
        author: Uuid,
        nonce: &[u8],
        ciphertext: &[u8],
        signature: &[u8],
    ) -> AppResult<i64> {
        // First try: insert, skipping on signature conflict.
        let inserted = sqlx::query_scalar!(
            r#"
            INSERT INTO updates (list_id, epoch, author, nonce, ciphertext, signature)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (signature) DO NOTHING
            RETURNING seq AS "seq!"
            "#,
            list_id,
            epoch,
            author,
            nonce,
            ciphertext,
            signature,
        )
        .fetch_optional(&self.pool)
        .await?;

        if let Some(seq) = inserted {
            return Ok(seq);
        }

        // Conflict path: the row already exists; return its existing seq.
        let seq = sqlx::query_scalar!("SELECT seq FROM updates WHERE signature = $1", signature)
            .fetch_one(&self.pool)
            .await?;
        Ok(seq)
    }

    /// Pull updates after a cursor, ordered by `seq`. The composite index
    /// `updates_pull (list_id, seq)` serves this directly.
    pub async fn fetch_updates_after(
        &self,
        list_id: Uuid,
        after: i64,
        limit: i64,
    ) -> AppResult<Vec<StoredUpdateDto>> {
        let rows = sqlx::query_as!(
            StoredUpdateDto,
            r#"
            SELECT seq, epoch, author, nonce, ciphertext, signature
            FROM updates
            WHERE list_id = $1 AND seq > $2
            ORDER BY seq
            LIMIT $3
            "#,
            list_id,
            after,
            limit.clamp(1, 1000)
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn fetch_snapshot(&self, list_id: Uuid) -> AppResult<Option<SnapshotDto>> {
        let snap = sqlx::query_as!(
            SnapshotDto,
            r#"
            SELECT epoch, covers_seq, nonce, ciphertext, signature
            FROM snapshots
            WHERE list_id = $1
            "#,
            list_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(snap)
    }

    /// Upsert the (single) snapshot for a list. Compaction-driven: the client sends
    /// a freshly merged, re-encrypted snapshot and the high-water `covers_seq`.
    /// Deleting superseded updates is done in the same handler transaction.
    pub async fn upsert_snapshot(
        &self,
        list_id: Uuid,
        epoch: i64,
        covers_seq: i64,
        nonce: &[u8],
        ciphertext: &[u8],
        signature: &[u8],
    ) -> AppResult<()> {
        self.safe_transaction(async move |tx| {
            sqlx::query!(
                r#"
            INSERT INTO snapshots (list_id, epoch, covers_seq, nonce, ciphertext, signature)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (list_id) DO UPDATE SET
                epoch = EXCLUDED.epoch,
                covers_seq = EXCLUDED.covers_seq,
                nonce = EXCLUDED.nonce,
                ciphertext = EXCLUDED.ciphertext,
                signature = EXCLUDED.signature,
                updated_at = now()
            "#,
                list_id,
                epoch,
                covers_seq,
                nonce,
                ciphertext,
                signature,
            )
            .execute(&mut *tx)
            .await?;

            // Garbage-collect updates folded into the snapshot.
            sqlx::query!(
                "DELETE FROM updates WHERE list_id = $1 AND seq <= $2",
                list_id,
                covers_seq
            )
            .execute(&mut *tx)
            .await?;
            Ok(())
        })
        .await
    }

    pub async fn list_current_epoch(&self, list_id: Uuid) -> AppResult<i64> {
        let row = sqlx::query_scalar!(
            "SELECT current_epoch FROM lists WHERE list_id = $1",
            list_id
        )
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(AppError::NotFound)
    }

    pub async fn fetch_members(&self, list_id: Uuid) -> AppResult<Vec<MemberDto>> {
        let members = sqlx::query_as!(
            MemberDto,
            r#"
            SELECT u.member_id, u.identity_pub, u.signing_pub, m.role AS "role: Role"
            FROM list_members m
            JOIN users u ON u.member_id = m.member_id
            WHERE m.list_id = $1
            ORDER BY m.added_at
            "#,
            list_id
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(members)
    }

    /// The caller's own wrapped DEKs across all live epochs for a list.
    pub async fn fetch_my_key_slots(
        &self,
        list_id: Uuid,
        member_id: Uuid,
    ) -> AppResult<Vec<KeySlotDto>> {
        let slots = sqlx::query_as!(
            KeySlotDto,
            r#"
            SELECT epoch, wrapped_dek
            FROM key_slots
            WHERE list_id = $1 AND member_id = $2
            ORDER BY epoch
            "#,
            list_id,
            member_id,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(slots)
    }

    /// The author's Ed25519 signing key for this list — present only if the author
    /// is a member, so this lookup doubles as a membership check.
    pub async fn fetch_author_signing_pub(
        &self,
        list_id: Uuid,
        author: Uuid,
    ) -> AppResult<Option<Vec<u8>>> {
        let row = sqlx::query_scalar!(
            r#"
            SELECT u.signing_pub
            FROM list_members m
            JOIN users u ON u.member_id = m.member_id
            WHERE m.list_id = $1 AND m.member_id = $2
            "#,
            list_id,
            author,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn fetch_user_pubkeys(&self, username: &str) -> AppResult<Option<UserPubkeysDto>> {
        let row = sqlx::query_as!(
            UserPubkeysDto,
            "SELECT member_id, identity_pub, signing_pub FROM users WHERE username = $1",
            username
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Create a new list and seat its creator as owner, with the creator's own
    /// epoch-1 wrapped DEK. Done in one transaction.
    pub async fn create_list(
        &self,
        list_id: Uuid,
        creator: Uuid,
        wrapped_dek: &[u8],
    ) -> AppResult<()> {
        self.safe_transaction(async move |tx| {
            sqlx::query!(
                "INSERT INTO lists (list_id, current_epoch) VALUES ($1, 1)",
                list_id
            )
            .execute(&mut *tx)
            .await?;

            sqlx::query!(
                "INSERT INTO list_members (list_id, member_id, role) VALUES ($1, $2, 'owner')",
                list_id,
                creator
            )
            .execute(&mut *tx)
            .await?;

            sqlx::query!(
                "INSERT INTO key_slots (list_id, epoch, member_id, wrapped_dek) VALUES ($1, 1, $2, $3)",
                list_id,
                creator,
                wrapped_dek,
            )
            .execute(&mut *tx)
            .await?;
            Ok(())
        }).await
    }

    /// Add a member with their sealed copy of the given epoch's DEK.
    pub async fn add_member(
        &self,
        list_id: Uuid,
        member_id: Uuid,
        role: Role,
        epoch: i64,
        wrapped_dek: &[u8],
    ) -> AppResult<()> {
        self.safe_transaction(async move |tx| {
            sqlx::query!(
                r#"
                INSERT INTO list_members (list_id, member_id, role)
                VALUES ($1, $2, $3)
                ON CONFLICT (list_id, member_id) DO UPDATE SET role = EXCLUDED.role
                "#,
                list_id,
                member_id,
                role as Role,
            )
            .execute(&mut *tx)
            .await?;

            sqlx::query!(
                r#"
                INSERT INTO key_slots (list_id, epoch, member_id, wrapped_dek)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (list_id, epoch, member_id) DO NOTHING
                "#,
                list_id,
                epoch,
                member_id,
                wrapped_dek,
            )
            .execute(&mut *tx)
            .await?;
            Ok(())
        })
        .await
    }

    pub async fn remove_member(
        &self,
        list_id: Uuid,
        member_id: Uuid,
        epoch: i64,
        wrapped_dek: &[u8],
    ) -> AppResult<()> {
        self.safe_transaction(async move |tx| {
            let remaining_member_ids = sqlx::query_scalar!(
                r#"
                    SELECT k.member_id
                    FROM key_slots k
                    WHERE k.list_id = $1 AND k.epoch = $2 AND k.member_id != $3
                    "#,
                list_id,
                epoch,
                member_id,
            )
            .fetch_all(&mut *tx)
            .await?;

            let new_epoch = epoch + 1;

            for mem_id in remaining_member_ids {
                sqlx::query!(
                    r#"
                    INSERT INTO key_slots (list_id, epoch, member_id, wrapped_dek)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (list_id, epoch, member_id) DO NOTHING
                    "#,
                    list_id,
                    new_epoch,
                    mem_id,
                    wrapped_dek,
                )
                .execute(&mut *tx)
                .await?;
            }

            sqlx::query!(
                "UPDATE lists SET current_epoch = $1 WHERE list_id = $2",
                new_epoch,
                list_id
            )
            .execute(&mut *tx)
            .await?;

            sqlx::query!(
                r#"DELETE FROM list_members WHERE list_id = $1 AND member_id = $2"#,
                list_id,
                member_id
            )
            .execute(&mut *tx)
            .await?;

            sqlx::query!(
                r#"DELETE FROM key_slots WHERE list_id = $1 AND member_id = $2"#,
                list_id,
                member_id
            )
            .execute(&mut *tx)
            .await?;
            Ok(())
        })
        .await
    }

    /// Persist a fully-formed user at the end of OPAQUE registration. `member_id`
    /// is derived by the caller from `identity_pub` (never trusted from the wire),
    /// and `opaque_record` is the serialized `ServerRegistration` password file.
    /// Every NOT NULL column on `users` is populated in this single INSERT.
    pub async fn create_user(
        &self,
        member_id: Uuid,
        username: &str,
        identity_pub: &[u8],
        signing_pub: &[u8],
        wrapped_secret_keys: &[u8],
        opaque_record: &[u8],
    ) -> AppResult<()> {
        sqlx::query!(
            r#"
            INSERT INTO public.users
                (member_id, username, identity_pub, signing_pub, wrapped_secret_keys, opaque_record)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            member_id,
            username,
            identity_pub,
            signing_pub,
            wrapped_secret_keys,
            opaque_record,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Everything login needs about a user, looked up by the public `username`
    /// handle. `None` when the user doesn't exist — the login handler still runs
    /// OPAQUE with a dummy record so the response is enumeration-resistant.
    pub async fn fetch_login_user(&self, username: &str) -> AppResult<Option<LoginUserRow>> {
        let row = sqlx::query_as!(
            LoginUserRow,
            r#"
            SELECT member_id, opaque_record
            FROM users
            WHERE username = $1
            "#,
            username
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Record a freshly minted session. `token_hash` is the hash of the bearer
    /// token (the token itself never touches the DB). `device_id` is `None` for a
    /// password login and `Some(..)` for a password-less device login.
    pub async fn create_session(
        &self,
        member_id: Uuid,
        token_hash: &[u8],
        expires_at: OffsetDateTime,
        device_id: Option<Uuid>,
    ) -> AppResult<()> {
        sqlx::query!(
            r#"
            INSERT INTO sessions (token_hash, member_id, expires_at, device_id)
            VALUES ($1, $2, $3, $4)
            "#,
            token_hash,
            member_id,
            expires_at,
            device_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Resolve a presented token hash to its session, enforcing expiry. Used by
    /// the `AuthMember` extractor on every authenticated request; the device tag
    /// and creation time drive step-up auth.
    pub async fn lookup_session(&self, token_hash: &[u8]) -> AppResult<Option<SessionRow>> {
        let now = OffsetDateTime::now_utc();
        let row = sqlx::query_as!(
            SessionRow,
            r#"
            SELECT s.member_id, s.device_id, s.created_at
            FROM sessions s
            WHERE s.token_hash = $1 AND s.expires_at > $2
            "#,
            token_hash,
            now,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Revoke exactly one session — the device whose bearer token hashes to
    /// `token_hash` (per-device logout; other sessions of the member survive).
    pub async fn delete_session(&self, token_hash: &[u8]) -> AppResult<()> {
        sqlx::query!("DELETE FROM sessions WHERE token_hash = $1", token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn cleanup_expired_sessions(&self) -> anyhow::Result<()> {
        let now = OffsetDateTime::now_utc();
        sqlx::query!("DELETE FROM sessions WHERE expires_at <= $1", now)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Stash the transient OPAQUE login state plus the member it belongs to
    /// (`None` only for the enumeration-resistant unknown-user path). Returns the
    /// `login_id` the client echoes back on finish.
    pub async fn login_start(&self, data: &[u8], member_id: Option<Uuid>) -> AppResult<Uuid> {
        self.safe_transaction(async move |tx| {
            let id = Uuid::new_v4();
            let expires = OffsetDateTime::now_utc() + Self::LOGIN_TTL;
            sqlx::query!(
                r#"
                INSERT INTO login_cache (login_id, state, expires_at, member_id)
                VALUES ($1, $2, $3, $4)
                "#,
                id,
                data,
                expires,
                member_id,
            )
            .execute(&mut *tx)
            .await?;
            Ok(id)
        })
        .await
    }

    /// Consume-once: fetch the stashed login state (if unexpired) and delete it,
    /// so a `login_id` can never be replayed.
    pub async fn login_finish(&self, id: Uuid) -> AppResult<Option<LoginDto>> {
        self.safe_transaction(async move |tx| {
            let now = OffsetDateTime::now_utc();
            let row = sqlx::query_as!(
                LoginDto,
                r#"
                SELECT l.state, l.member_id
                FROM login_cache l
                WHERE l.login_id = $1 AND l.expires_at > $2
                "#,
                id,
                now,
            )
            .fetch_optional(&mut *tx)
            .await?;

            sqlx::query!("DELETE FROM login_cache WHERE login_id = $1", id)
                .execute(&mut *tx)
                .await?;

            Ok(row)
        })
        .await
    }

    /// The public identity + escrowed private keys for a member, returned to the
    /// client after a successful login so a fresh device can rehydrate.
    pub async fn fetch_user_keys(&self, member_id: Uuid) -> AppResult<Option<UserKeysRow>> {
        let row = sqlx::query_as!(
            UserKeysRow,
            r#"
            SELECT identity_pub, signing_pub, wrapped_secret_keys
            FROM users
            WHERE member_id = $1
            "#,
            member_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    // ── trusted device keys (password-less device login) ─────────────────────

    /// Enroll (or re-enroll) a device's Ed25519 trusted key. Re-enrolling the same
    /// `device_id` rotates the key and clears any prior revocation.
    pub async fn enroll_trusted_device_key(
        &self,
        member_id: Uuid,
        device_id: Uuid,
        device_signing_pub: &[u8],
        label: &str,
    ) -> AppResult<()> {
        sqlx::query!(
            r#"
            INSERT INTO trusted_device_keys (member_id, device_id, device_signing_pub, label)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (member_id, device_id) DO UPDATE SET
                device_signing_pub = EXCLUDED.device_signing_pub,
                label = EXCLUDED.label,
                created_at = now(),
                revoked_at = NULL
            "#,
            member_id,
            device_id,
            device_signing_pub,
            label,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The Ed25519 public key for an ACTIVE (non-revoked) enrolled device, used to
    /// verify a device-login challenge. `None` if the device is unknown or revoked.
    pub async fn fetch_active_device_pub(
        &self,
        member_id: Uuid,
        device_id: Uuid,
    ) -> AppResult<Option<Vec<u8>>> {
        let row = sqlx::query_scalar!(
            r#"
            SELECT device_signing_pub
            FROM trusted_device_keys
            WHERE member_id = $1 AND device_id = $2 AND revoked_at IS NULL
            "#,
            member_id,
            device_id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Revoke a device: future device logins for it are rejected AND any live
    /// sessions it minted are deleted, so a lost/compromised device loses access
    /// immediately rather than at token expiry. Idempotent.
    pub async fn revoke_trusted_device_key(
        &self,
        member_id: Uuid,
        device_id: Uuid,
    ) -> AppResult<()> {
        self.safe_transaction(async move |tx| {
            sqlx::query!(
                r#"
                UPDATE trusted_device_keys
                SET revoked_at = now()
                WHERE member_id = $1 AND device_id = $2 AND revoked_at IS NULL
                "#,
                member_id,
                device_id,
            )
            .execute(&mut *tx)
            .await?;

            // Kill any sessions this device minted (per-device session tagging).
            sqlx::query!(
                "DELETE FROM sessions WHERE member_id = $1 AND device_id = $2",
                member_id,
                device_id,
            )
            .execute(&mut *tx)
            .await?;
            Ok(())
        })
        .await
    }

    /// List a member's enrolled devices (active and revoked) for management UIs.
    pub async fn list_trusted_device_keys(&self, member_id: Uuid) -> AppResult<Vec<DeviceInfo>> {
        let rows = sqlx::query!(
            r#"
            SELECT device_id, label, created_at, revoked_at
            FROM trusted_device_keys
            WHERE member_id = $1
            ORDER BY created_at
            "#,
            member_id,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| DeviceInfo {
                device_id: r.device_id,
                label: r.label,
                created_at: r.created_at.unix_timestamp(),
                revoked: r.revoked_at.is_some(),
            })
            .collect())
    }

    pub async fn cleanup_expired_logins(&self) -> anyhow::Result<()> {
        self.safe_transaction(async move |tx| {
            let now = OffsetDateTime::now_utc();
            sqlx::query!("DELETE FROM login_cache WHERE expires_at <= $1", now)
                .execute(&mut *tx)
                .await?;
            Ok(())
        })
        .await?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    impl Db {
        pub fn new_for_test(db: PgPool) -> Self {
            Db { pool: db }
        }
    }
}
