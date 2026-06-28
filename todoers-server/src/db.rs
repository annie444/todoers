//! Database access layer. All queries are runtime (string) queries so this
//! compiles without a live DB. The server never decrypts anything here — it
//! shuffles opaque bytes and assigns `seq`.

use sqlx::postgres::{PgConnectOptions, PgSslMode};
use sqlx::{PgConnection, PgPool, Pool};
use time::{Duration, OffsetDateTime};
use tracing::{error, info};
use uuid::Uuid;

use crate::config::DbConfig;
use crate::error::{AppError, AppResult};
use todoers_types::{
    DeviceId, DeviceInfo, Ed25519Pub, KeySlotDto, KeySlotEntry, ListId, LoginDto, MemberDto,
    MemberId, Nonce, Role, Signature, SnapshotDto, StoredUpdateDto, UserPubkeysDto, X25519Pub,
};

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("db/migrations");

#[derive(Debug, Clone)]
pub struct Db {
    pool: PgPool,
}

/// What login/start needs from the `users` row: the id to bind the session to
/// and the OPAQUE password file. (Escrow keys are fetched separately at finish.)
#[derive(Debug, Clone)]
pub struct LoginUserRow {
    pub member_id: MemberId,
    pub opaque_record: Vec<u8>,
}

/// The public identity + escrowed private keys for a member.
#[derive(Debug, Clone)]
pub struct UserKeysRow {
    pub identity_pub: X25519Pub,
    pub signing_pub: Ed25519Pub,
    pub wrapped_secret_keys: Vec<u8>,
}

/// A resolved session: which member, which device minted it (`None` = password
/// login), and when — the last two drive step-up auth for sensitive operations.
#[derive(Debug, Clone)]
pub struct SessionRow {
    pub member_id: MemberId,
    pub device_id: Option<DeviceId>,
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
        list_id: &ListId,
        epoch: i64,
        author: &MemberId,
        nonce: &Nonce,
        ciphertext: &[u8],
        signature: &Signature,
    ) -> AppResult<i64> {
        // First try: insert, skipping on signature conflict.
        let inserted = sqlx::query_scalar!(
            r#"
            INSERT INTO updates (list_id, epoch, author, nonce, ciphertext, signature)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (signature) DO NOTHING
            RETURNING seq AS "seq!"
            "#,
            list_id.as_ref(),
            epoch,
            author.as_ref(),
            nonce.as_ref(),
            ciphertext,
            signature.as_ref(),
        )
        .fetch_optional(&self.pool)
        .await?;

        if let Some(seq) = inserted {
            return Ok(seq);
        }

        // Conflict path: the row already exists; return its existing seq.
        let seq = sqlx::query_scalar!(
            "SELECT seq FROM updates WHERE signature = $1",
            signature.as_ref()
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(seq)
    }

    /// Pull updates after a cursor, ordered by `seq`. The composite index
    /// `updates_pull (list_id, seq)` serves this directly.
    pub async fn fetch_updates_after(
        &self,
        list_id: &ListId,
        after: i64,
        limit: i64,
    ) -> AppResult<Vec<StoredUpdateDto>> {
        let rows = sqlx::query_as!(
            StoredUpdateDto,
            r#"
            SELECT
                seq,
                epoch,
                author AS "author: MemberId",
                nonce AS "nonce: Nonce",
                ciphertext,
                signature AS "signature: Signature"
            FROM updates
            WHERE list_id = $1 AND seq > $2
            ORDER BY seq
            LIMIT $3
            "#,
            list_id.as_ref(),
            after,
            limit.clamp(1, 1000)
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn fetch_snapshot(&self, list_id: &ListId) -> AppResult<Option<SnapshotDto>> {
        let snap = sqlx::query_as!(
            SnapshotDto,
            r#"
            SELECT
                epoch,
                covers_seq,
                nonce AS "nonce: Nonce",
                ciphertext,
                signature AS "signature: Signature"
            FROM snapshots
            WHERE list_id = $1
            "#,
            list_id.as_ref()
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
        list_id: &ListId,
        epoch: i64,
        covers_seq: i64,
        nonce: &Nonce,
        ciphertext: &[u8],
        signature: &Signature,
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
                list_id.as_ref(),
                epoch,
                covers_seq,
                nonce.as_ref(),
                ciphertext,
                signature.as_ref(),
            )
            .execute(&mut *tx)
            .await?;

            // Garbage-collect updates folded into the snapshot.
            sqlx::query!(
                "DELETE FROM updates WHERE list_id = $1 AND seq <= $2",
                list_id.as_ref(),
                covers_seq
            )
            .execute(&mut *tx)
            .await?;
            Ok(())
        })
        .await
    }

    pub async fn list_current_epoch(&self, list_id: &ListId) -> AppResult<i64> {
        let row = sqlx::query_scalar!(
            "SELECT current_epoch FROM lists WHERE list_id = $1",
            list_id.as_ref()
        )
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(AppError::NotFound)
    }

    /// This member's role on `list_id`, or `None` if they are not a member.
    /// Used to gate owner-only operations and to confirm WS subscribers belong
    /// to the list before attaching them to its broadcast stream.
    pub async fn member_role(
        &self,
        list_id: &ListId,
        member_id: &MemberId,
    ) -> AppResult<Option<Role>> {
        let row = sqlx::query_scalar!(
            r#"
            SELECT role AS "role: Role"
            FROM list_members
            WHERE list_id = $1 AND member_id = $2
            "#,
            list_id.as_ref(),
            member_id.as_ref(),
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn fetch_members(&self, list_id: &ListId) -> AppResult<Vec<MemberDto>> {
        let members = sqlx::query_as!(
            MemberDto,
            r#"
            SELECT 
                u.member_id as "member_id: MemberId",
                u.identity_pub AS "identity_pub: X25519Pub",
                u.signing_pub AS "signing_pub: Ed25519Pub",
                m.role AS "role: Role"
            FROM list_members m
            JOIN users u ON u.member_id = m.member_id
            WHERE m.list_id = $1
            ORDER BY m.added_at
            "#,
            list_id.as_ref()
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(members)
    }

    /// The caller's own wrapped DEKs across all live epochs for a list.
    pub async fn fetch_my_key_slots(
        &self,
        list_id: &ListId,
        member_id: &MemberId,
    ) -> AppResult<Vec<KeySlotDto>> {
        let slots = sqlx::query_as!(
            KeySlotDto,
            r#"
            SELECT epoch, wrapped_dek
            FROM key_slots
            WHERE list_id = $1 AND member_id = $2
            ORDER BY epoch
            "#,
            list_id.as_ref(),
            member_id.as_ref(),
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(slots)
    }

    /// The author's Ed25519 signing key for this list — present only if the author
    /// is a member, so this lookup doubles as a membership check.
    pub async fn fetch_author_signing_pub(
        &self,
        list_id: &ListId,
        author: &MemberId,
    ) -> AppResult<Option<Vec<u8>>> {
        let row = sqlx::query_scalar!(
            r#"
            SELECT u.signing_pub
            FROM list_members m
            JOIN users u ON u.member_id = m.member_id
            WHERE m.list_id = $1 AND m.member_id = $2
            "#,
            list_id.as_ref(),
            author.as_ref(),
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn fetch_user_pubkeys(&self, username: &str) -> AppResult<Option<UserPubkeysDto>> {
        let row = sqlx::query_as!(
            UserPubkeysDto,
            r#"SELECT
                member_id AS "member_id: MemberId",
                identity_pub AS "identity_pub: X25519Pub",
                signing_pub AS "signing_pub: Ed25519Pub"
            FROM users
            WHERE username = $1"#,
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
        list_id: &ListId,
        creator: &MemberId,
        wrapped_dek: &[u8],
    ) -> AppResult<()> {
        self.safe_transaction(async move |tx| {
            sqlx::query!(
                "INSERT INTO lists (list_id, current_epoch) VALUES ($1, 1)",
                list_id.as_ref()
            )
            .execute(&mut *tx)
            .await?;

            sqlx::query!(
                "INSERT INTO list_members (list_id, member_id, role) VALUES ($1, $2, 'owner')",
                list_id.as_ref(),
                creator.as_ref()
            )
            .execute(&mut *tx)
            .await?;

            sqlx::query!(
                "INSERT INTO key_slots (list_id, epoch, member_id, wrapped_dek) VALUES ($1, 1, $2, $3)",
                list_id.as_ref(),
                creator.as_ref(),
                wrapped_dek,
            )
            .execute(&mut *tx)
            .await?;
            Ok(())
        }).await
    }

    pub async fn delete_list(&self, list_id: &ListId) -> AppResult<()> {
        sqlx::query!("DELETE FROM lists WHERE list_id = $1", list_id.as_ref())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Get the lists a user is currently apart of
    pub async fn fetch_user_lists(&self, member: &MemberId) -> AppResult<Vec<ListId>> {
        let list_ids: Vec<Vec<u8>> = sqlx::query_scalar!(
            r#"SELECT list_id
                FROM list_members
                WHERE member_id = $1"#,
            member.as_ref(),
        )
        .fetch_all(&self.pool)
        .await?;
        let list_ids: Vec<ListId> = list_ids
            .into_iter()
            .map(|id| AppResult::Ok(ListId::try_from(id)?))
            .collect::<AppResult<Vec<ListId>>>()?;
        Ok(list_ids)
    }

    /// Add a member with their sealed copy of the given epoch's DEK.
    pub async fn add_member(
        &self,
        list_id: &ListId,
        member_id: &MemberId,
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
                list_id.as_ref(),
                member_id.as_ref(),
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
                list_id.as_ref(),
                epoch,
                member_id.as_ref(),
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
        list_id: &ListId,
        member_id: &MemberId,
        epoch: i64,
        new_slots: &[KeySlotEntry],
    ) -> AppResult<()> {
        self.safe_transaction(async move |tx| {
            let new_epoch = epoch + 1;

            // Seal the rotated DEK to each remaining member individually: a sealed
            // box opens only for the pubkey it was sealed to, so every survivor
            // needs their own copy. The removed member is simply absent from the
            // caller-supplied list and has their slots dropped below.
            for slot in new_slots {
                if &slot.member_id == member_id {
                    return Err(AppError::BadRequest(
                        "removed member must not receive a new key slot".into(),
                    ));
                }
                sqlx::query!(
                    r#"
                    INSERT INTO key_slots (list_id, epoch, member_id, wrapped_dek)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (list_id, epoch, member_id) DO NOTHING
                    "#,
                    list_id.as_ref(),
                    new_epoch,
                    slot.member_id.as_ref(),
                    &slot.wrapped_dek,
                )
                .execute(&mut *tx)
                .await?;
            }

            sqlx::query!(
                "UPDATE lists SET current_epoch = $1 WHERE list_id = $2",
                new_epoch,
                list_id.as_ref()
            )
            .execute(&mut *tx)
            .await?;

            sqlx::query!(
                r#"DELETE FROM list_members WHERE list_id = $1 AND member_id = $2"#,
                list_id.as_ref(),
                member_id.as_ref()
            )
            .execute(&mut *tx)
            .await?;

            sqlx::query!(
                r#"DELETE FROM key_slots WHERE list_id = $1 AND member_id = $2"#,
                list_id.as_ref(),
                member_id.as_ref()
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
        member_id: &MemberId,
        username: &str,
        identity_pub: &X25519Pub,
        signing_pub: &Ed25519Pub,
        wrapped_secret_keys: &[u8],
        opaque_record: &[u8],
    ) -> AppResult<()> {
        sqlx::query!(
            r#"
            INSERT INTO public.users
                (member_id, username, identity_pub, signing_pub, wrapped_secret_keys, opaque_record)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            member_id.as_ref(),
            username,
            identity_pub.as_ref(),
            signing_pub.as_ref(),
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
            SELECT
                member_id AS "member_id: MemberId",
                opaque_record
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
        member_id: &MemberId,
        token_hash: &[u8; 64],
        expires_at: OffsetDateTime,
        device_id: Option<&DeviceId>,
    ) -> AppResult<()> {
        sqlx::query!(
            r#"
            INSERT INTO sessions (token_hash, member_id, expires_at, device_id)
            VALUES ($1, $2, $3, $4)
            "#,
            token_hash,
            member_id.as_ref(),
            expires_at,
            device_id.map(|d| d.as_ref().to_vec())
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Resolve a presented token hash to its session, enforcing expiry. Used by
    /// the `AuthMember` extractor on every authenticated request; the device tag
    /// and creation time drive step-up auth.
    pub async fn lookup_session(&self, token_hash: &[u8; 64]) -> AppResult<Option<SessionRow>> {
        let now = OffsetDateTime::now_utc();
        let row = sqlx::query_as!(
            SessionRow,
            r#"
            SELECT 
                member_id AS "member_id: MemberId",
                device_id AS "device_id: DeviceId",
                created_at
            FROM sessions
            WHERE token_hash = $1 AND expires_at > $2
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
    pub async fn delete_session(&self, token_hash: &[u8; 64]) -> AppResult<()> {
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
    pub async fn login_start(&self, data: &[u8], member_id: Option<MemberId>) -> AppResult<Uuid> {
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
                member_id.map(|m| m.to_vec()),
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
                SELECT l.state, l.member_id AS "member_id: Option<MemberId>"
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
    pub async fn fetch_user_keys(&self, member_id: &MemberId) -> AppResult<Option<UserKeysRow>> {
        let row = sqlx::query_as!(
            UserKeysRow,
            r#"
            SELECT
                identity_pub AS "identity_pub: X25519Pub",
                signing_pub AS "signing_pub: Ed25519Pub",
                wrapped_secret_keys
            FROM users
            WHERE member_id = $1
            "#,
            member_id.as_ref()
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
        member_id: &MemberId,
        device_id: &DeviceId,
        device_signing_pub: &Ed25519Pub,
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
            member_id.as_ref(),
            device_id.as_ref(),
            device_signing_pub.as_ref(),
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
        member_id: &MemberId,
        device_id: &DeviceId,
    ) -> AppResult<Option<Vec<u8>>> {
        let row = sqlx::query_scalar!(
            r#"
            SELECT device_signing_pub
            FROM trusted_device_keys
            WHERE member_id = $1 AND device_id = $2 AND revoked_at IS NULL
            "#,
            member_id.as_ref(),
            device_id.as_ref(),
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
        member_id: &MemberId,
        device_id: &DeviceId,
    ) -> AppResult<()> {
        self.safe_transaction(async move |tx| {
            sqlx::query!(
                r#"
                UPDATE trusted_device_keys
                SET revoked_at = now()
                WHERE member_id = $1 AND device_id = $2 AND revoked_at IS NULL
                "#,
                member_id.as_ref(),
                device_id.as_ref(),
            )
            .execute(&mut *tx)
            .await?;

            // Kill any sessions this device minted (per-device session tagging).
            sqlx::query!(
                "DELETE FROM sessions WHERE member_id = $1 AND device_id = $2",
                member_id.as_ref(),
                device_id.as_ref(),
            )
            .execute(&mut *tx)
            .await?;
            Ok(())
        })
        .await
    }

    /// List a member's enrolled devices (active and revoked) for management UIs.
    pub async fn list_trusted_device_keys(
        &self,
        member_id: &MemberId,
    ) -> AppResult<Vec<DeviceInfo>> {
        let rows = sqlx::query_as!(
            DeviceInfo,
            r#"
            SELECT
                device_id AS "device_id: DeviceId",
                label,
                created_at,
                revoked_at IS NOT NULL AS "revoked!"
            FROM trusted_device_keys
            WHERE member_id = $1
            ORDER BY created_at
            "#,
            member_id.as_ref(),
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
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
