use std::borrow::Cow;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, RECOMMENDED_SALT_LEN, Version};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, Payload};
use hkdf::Hkdf;
use old_rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use uuid::Uuid;
use x_wing::{
    DECAPSULATION_KEY_SIZE, Decapsulate, DecapsulationKey, Encapsulate, Kem, KeyExport, XWingKem,
};

use crate::device_key::{
    DeviceBackend, DeviceKeyStore, RecipientEnvelope, hex16, select_device_store,
};
use crate::error::{TodoersError, TodoersResult};

pub type HkdfSha512 = Hkdf<Sha512>;
const ENVELOPE_VERSION: u32 = 1;
const DEVICE_LABEL: &str = "device-xwing-sqlcipher-kek-v1";
const PASSWORD_LABEL: &str = "password-sqlcipher-kek-v1";
const DEFAULT_KDF_ITER: u32 = 256_000;
const DEFAULT_PAGE_SIZE: u32 = 4096;

#[derive(Debug, Serialize, Deserialize)]
pub struct TodoersKeyEnvelope {
    pub version: u32,
    pub database_id: String,
    pub cipher: DbCipher,
    pub recipients: Vec<RecipientEnvelope>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum DbCipherKdf {
    #[serde(rename = "PBKDF2_HMAC_SHA512")]
    Pbkdf2HmacSha512,
    #[serde(rename = "PBKDF2_HMAC_SHA256")]
    Pbkdf2HmacSha256,
    #[serde(rename = "PBKDF2_HMAC_SHA1")]
    Pbkdf2HmacSha1,
}

impl From<DbCipherKdf> for Cow<'static, str> {
    fn from(kdf: DbCipherKdf) -> Cow<'static, str> {
        match kdf {
            DbCipherKdf::Pbkdf2HmacSha512 => Cow::Borrowed("PBKDF2_HMAC_SHA512"),
            DbCipherKdf::Pbkdf2HmacSha256 => Cow::Borrowed("PBKDF2HMAC_SHA256"),
            DbCipherKdf::Pbkdf2HmacSha1 => Cow::Borrowed("PBKDF2_HMAC_SHA1"),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum DbCipherHmac {
    #[serde(rename = "HMAC_SHA512")]
    HmacSha512,
    #[serde(rename = "HMAC_SHA256")]
    HmacSha256,
    #[serde(rename = "HMAC_SHA1")]
    HmacSha1,
}

impl From<DbCipherHmac> for Cow<'static, str> {
    fn from(hmac: DbCipherHmac) -> Cow<'static, str> {
        match hmac {
            DbCipherHmac::HmacSha512 => Cow::Borrowed("HMAC_SHA512"),
            DbCipherHmac::HmacSha256 => Cow::Borrowed("HMAC_SHA256"),
            DbCipherHmac::HmacSha1 => Cow::Borrowed("HMAC_SHA1"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DbCipher {
    pub kdf_iter: u32,
    pub page_size: u32,
    pub hmac: DbCipherHmac,
    pub kdf: DbCipherKdf,
    #[serde(with = "hex16")]
    pub salt: [u8; 16],
}

pub async fn create_new_database_keys(
    database_id: String,
    password: &str,
) -> TodoersResult<TodoersKeyEnvelope> {
    let mut sqlcipher_key = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut sqlcipher_key);
    let mut recipients = Vec::new();

    // Device recipient
    let store = select_device_store()?;
    let (device_recipient, xwing_private_key_bytes) =
        create_device_xwing_recipient(&database_id, &sqlcipher_key, store.backend())?;
    store.store_key(&database_id, &xwing_private_key_bytes)?;
    recipients.push(device_recipient);

    // Optional password recipient
    let password_recipient = create_password_recipient(&database_id, password, &sqlcipher_key)?;
    recipients.push(password_recipient);

    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);

    Ok(TodoersKeyEnvelope {
        version: 1,
        database_id,
        cipher: DbCipher {
            kdf_iter: DEFAULT_KDF_ITER,
            page_size: DEFAULT_PAGE_SIZE,
            hmac: DbCipherHmac::HmacSha512,
            kdf: DbCipherKdf::Pbkdf2HmacSha512,
            salt,
        },
        recipients,
    })
}

fn create_device_xwing_recipient(
    database_id: &str,
    sqlcipher_key: &[u8; 32],
    backend: DeviceBackend,
) -> TodoersResult<(RecipientEnvelope, Vec<u8>)> {
    let id = Uuid::new_v4();

    let (decapsulation_key, encapsulation_key) = XWingKem::generate_keypair();
    let (kem_ciphertext, shared_secret) = encapsulation_key.encapsulate();

    let (kek_salt, kek) =
        derive_kek_from_secret(None, shared_secret.as_ref(), database_id, DEVICE_LABEL)?;
    let nonce = random_nonce();
    let recipient_aad = recipient_aad(database_id, &id, DEVICE_LABEL);
    let wrapped_key = aead_encrypt(&kek, &nonce, sqlcipher_key, &recipient_aad)?;

    let recipient = RecipientEnvelope::DeviceXWing {
        id,
        label: DEVICE_LABEL.to_string(),
        encapsulation_key: Box::new(encapsulation_key.to_bytes()),
        kem_ciphertext: Box::new(kem_ciphertext),
        backend,
        wrapped_key,
        nonce,
        kek_salt,
    };

    Ok((recipient, decapsulation_key.to_bytes().to_vec()))
}

fn create_password_recipient(
    database_id: &str,
    password: &str,
    sqlcipher_key: &[u8; 32],
) -> TodoersResult<RecipientEnvelope> {
    let id = Uuid::new_v4();

    let mut salt = [0u8; RECOMMENDED_SALT_LEN];
    let mut rng = OsRng;
    rng.fill_bytes(&mut salt);

    let derived_key = hash_password(password, &salt, 65536, 3, 1)?;
    let (kek_salt, kek) = derive_kek_from_secret(None, &derived_key, database_id, PASSWORD_LABEL)?;
    let nonce = random_nonce();
    let recipient_aad = recipient_aad(database_id, &id, PASSWORD_LABEL);
    let wrapped_key = aead_encrypt(&kek, &nonce, sqlcipher_key, &recipient_aad)?;

    Ok(RecipientEnvelope::Password {
        id,
        label: PASSWORD_LABEL.to_string(),
        argon2_salt: salt,
        argon2_memory_cost_kib: 65536,
        argon2_time_cost: 3,
        argon2_parallelism: 1,
        wrapped_key,
        nonce,
        kek_salt,
    })
}

pub async fn unlock_with_password(
    envelope: &TodoersKeyEnvelope,
    password: &str,
) -> TodoersResult<[u8; 32]> {
    let (id, label, wrapped_key, salt, kek_salt, nonce, m_cost, t_cost, p_cost) = envelope
        .recipients
        .iter()
        .find_map(|r| match r {
            RecipientEnvelope::Password {
                id,
                label,
                argon2_salt,
                argon2_memory_cost_kib,
                argon2_time_cost,
                argon2_parallelism,
                wrapped_key,
                nonce,
                kek_salt,
                ..
            } => Some((
                id,
                label,
                wrapped_key,
                argon2_salt,
                kek_salt,
                nonce,
                argon2_memory_cost_kib,
                argon2_time_cost,
                argon2_parallelism,
            )),
            _ => None,
        })
        .ok_or(TodoersError::NoPassword)?;

    let shared_secret = hash_password(password, salt, *m_cost, *t_cost, *p_cost)?;
    let (_, kek) = derive_kek_from_secret(
        Some(*kek_salt),
        &shared_secret,
        &envelope.database_id,
        label,
    )?;
    let recipient_aad = recipient_aad(&envelope.database_id, id, label);
    let plaintext = aead_decrypt(&kek, nonce, wrapped_key, &recipient_aad)?;
    plaintext
        .try_into()
        .map_err(|_| TodoersError::InvalidKeyLength)
}

pub async fn unlock_with_device(envelope: &TodoersKeyEnvelope) -> TodoersResult<[u8; 32]> {
    let store = select_device_store()?;

    let recipient = envelope
        .recipients
        .iter()
        .find(|r| {
            matches!(r, RecipientEnvelope::DeviceXWing { backend, .. } if *backend == store.backend())
        })
        .ok_or(TodoersError::NoDevRecipient)?;

    let private_key_bytes = store.get_key(&envelope.database_id)?;
    let private_key: [u8; DECAPSULATION_KEY_SIZE] = private_key_bytes
        .try_into()
        .map_err(|_| TodoersError::InvalidKeyLength)?;

    match recipient {
        RecipientEnvelope::DeviceXWing {
            id,
            label,
            kem_ciphertext,
            wrapped_key,
            nonce,
            kek_salt,
            ..
        } => {
            let sk = DecapsulationKey::from(private_key);
            let shared_secret = sk.decapsulate(kem_ciphertext);
            let (_, kek) = derive_kek_from_secret(
                Some(*kek_salt),
                shared_secret.as_ref(),
                &envelope.database_id,
                label,
            )?;
            let recipient_aad = recipient_aad(&envelope.database_id, id, label);
            let plaintext = aead_decrypt(&kek, nonce, wrapped_key, &recipient_aad)?;
            plaintext
                .try_into()
                .map_err(|_| TodoersError::InvalidKeyLength)
        }
        _ => unreachable!(),
    }
}

fn hash_password(
    password: &str,
    salt: &[u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> TodoersResult<[u8; 32]> {
    let mut derived_key = [0u8; 32];
    let hasher = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(m_cost, t_cost, p_cost, Some(32)).map_err(TodoersError::Argon2)?,
    );
    hasher
        .hash_password_into(password.as_bytes(), salt, &mut derived_key)
        .map_err(TodoersError::Argon2)?;
    Ok(derived_key)
}

fn derive_kek_from_secret(
    salt: Option<[u8; 16]>,
    secret: &[u8; 32],
    database_id: &str,
    purpose: &str,
) -> TodoersResult<([u8; 16], [u8; 32])> {
    let salt = match salt {
        Some(s) => s,
        None => {
            let mut rng = OsRng;
            let mut salt = [0u8; 16];
            rng.fill_bytes(&mut salt);
            salt
        }
    };
    let hkdf = HkdfSha512::new(Some(&salt), secret);

    let mut info = Vec::new();
    info.extend_from_slice(b"todoers/");
    info.extend_from_slice(purpose.as_bytes());
    info.extend_from_slice(b"/");
    info.extend_from_slice(database_id.as_bytes());

    let mut output = [0u8; 32];
    hkdf.expand(&info, &mut output)?;
    Ok((salt, output))
}

fn random_nonce() -> [u8; 24] {
    let mut rng = OsRng;
    XChaCha20Poly1305::generate_nonce(&mut rng).into()
}

fn recipient_aad(database_id: &str, recipient_id: &Uuid, label: &str) -> Vec<u8> {
    format!("todoers-envelope-v{ENVELOPE_VERSION}/{database_id}/{recipient_id}/{label}")
        .into_bytes()
}

fn aead_encrypt(
    kek: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
    data: &[u8],
) -> TodoersResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(kek.into());
    let encrypted = cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad: data,
            },
        )
        .map_err(TodoersError::ChaCha)?;
    Ok(encrypted)
}

fn aead_decrypt(
    kek: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    data: &[u8],
) -> TodoersResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(kek.into());
    let secret = cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad: data,
            },
        )
        .map_err(TodoersError::ChaCha)?;
    Ok(secret)
}

/// Crockford base32 alphabet (omits I, L, O, U) for transcribable recovery keys.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Generate a ~128-bit recovery key as upper-case Crockford base32, dash-grouped
/// in fours for display. The grouping and case are cosmetic: feed [`canonical`]
/// of this string — or of whatever the user types back — to the KDF.
pub fn generate_recovery_key() -> String {
    let mut bytes = [0u8; 16];
    let mut rng = OsRng;
    rng.fill_bytes(&mut bytes);

    base32_encode(&bytes)
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).expect("base32 output is ASCII"))
        .collect::<Vec<_>>()
        .join("-")
}

/// Normalize a recovery key for KDF input: drop non-alphanumerics and upper-case.
/// This makes dashes, spaces, and letter case irrelevant to the user.
pub fn canonical(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CROCKFORD[((acc >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(CROCKFORD[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Load the SQLCipher key envelope from `path`, creating it on first run.
///
/// On first run a fresh SQLCipher key is generated and sealed to both a device
/// recipient (key in the OS keyring) and a password recipient derived from a
/// newly generated recovery key, which is returned as `Some` so the caller can
/// display it once — it is the only password-based fallback if the device key is
/// lost. On subsequent runs the existing envelope is returned with `None`.
pub async fn load_or_create_envelope(
    path: &Path,
) -> TodoersResult<(TodoersKeyEnvelope, Option<String>)> {
    if tokio::fs::try_exists(path).await? {
        let bytes = tokio::fs::read(path).await?;
        let envelope: TodoersKeyEnvelope = serde_json::from_slice(&bytes)?;
        return Ok((envelope, None));
    }

    let recovery = generate_recovery_key();
    let envelope =
        create_new_database_keys(Uuid::new_v4().to_string(), &canonical(&recovery)).await?;

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(path, serde_json::to_vec_pretty(&envelope)?).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    }

    Ok((envelope, Some(recovery)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "correct horse battery staple";

    /// Each test uses a fresh database id so the in-memory mock keyring (shared
    /// process-wide via `select_device_store`) never sees a key collision when
    /// tests run in parallel.
    fn fresh_db_id() -> String {
        Uuid::new_v4().to_string()
    }

    fn count_recipients(envelope: &TodoersKeyEnvelope) -> (usize, usize) {
        let devices = envelope
            .recipients
            .iter()
            .filter(|r| matches!(r, RecipientEnvelope::DeviceXWing { .. }))
            .count();
        let passwords = envelope
            .recipients
            .iter()
            .filter(|r| matches!(r, RecipientEnvelope::Password { .. }))
            .count();
        (devices, passwords)
    }

    #[tokio::test]
    async fn both_recipients_round_trip() {
        let id = fresh_db_id();
        let envelope = create_new_database_keys(id, PASSWORD).await.unwrap();

        // Exactly one device recipient and one password recipient are sealed.
        assert_eq!(count_recipients(&envelope), (1, 1));

        let from_password = unlock_with_password(&envelope, PASSWORD).await.unwrap();
        let from_device = unlock_with_device(&envelope).await.unwrap();

        // The original SQLCipher key is never returned by the API, so proving the
        // round trip means both recipients unwrap the *same* 32 bytes.
        assert_eq!(from_password, from_device);
    }

    #[tokio::test]
    async fn wrong_password_fails_but_device_still_unlocks() {
        let id = fresh_db_id();
        let envelope = create_new_database_keys(id, PASSWORD).await.unwrap();

        // Wrong password derives a different KEK, so the AEAD unwrap fails.
        let err = unlock_with_password(&envelope, "not the password")
            .await
            .unwrap_err();
        assert!(matches!(err, TodoersError::ChaCha(_)), "got {err:?}");

        // The device recipient is independent and still recovers the key.
        unlock_with_device(&envelope).await.unwrap();
    }

    #[tokio::test]
    async fn missing_password_recipient_is_reported() {
        let id = fresh_db_id();
        let mut envelope = create_new_database_keys(id, PASSWORD).await.unwrap();

        // Drop the password recipient, leaving only the device recipient.
        envelope
            .recipients
            .retain(|r| matches!(r, RecipientEnvelope::DeviceXWing { .. }));

        let err = unlock_with_password(&envelope, PASSWORD).await.unwrap_err();
        assert!(matches!(err, TodoersError::NoPassword), "got {err:?}");
    }

    #[tokio::test]
    async fn envelope_survives_serde() {
        let id = fresh_db_id();
        let envelope = create_new_database_keys(id, PASSWORD).await.unwrap();

        // Round-trip through JSON to exercise the hex (de)serializers on the wire
        // format, then confirm both unlock paths still recover the key.
        let json = serde_json::to_string(&envelope).unwrap();
        let restored: TodoersKeyEnvelope = serde_json::from_str(&json).unwrap();

        let from_password = unlock_with_password(&restored, PASSWORD).await.unwrap();
        let from_device = unlock_with_device(&restored).await.unwrap();
        assert_eq!(from_password, from_device);
    }

    #[test]
    fn canonical_ignores_dashes_spaces_and_case() {
        assert_eq!(canonical("4h8k-9q2m"), "4H8K9Q2M");
        assert_eq!(canonical("  a b-c "), "ABC");
    }

    #[test]
    fn recovery_key_is_grouped_base32() {
        let rk = generate_recovery_key();
        // 16 random bytes -> 26 Crockford base32 chars, grouped in fours: six
        // groups of four plus a trailing pair, joined by six dashes => 32 chars.
        assert_eq!(rk.len(), 26 + 6);
        assert!(rk.split('-').all(|g| !g.is_empty()));

        let canon = canonical(&rk);
        assert_eq!(canon.len(), 26);
        assert!(canon.bytes().all(|b| CROCKFORD.contains(&b)));
    }

    #[tokio::test]
    async fn load_or_create_envelope_first_run_then_reload() {
        let path = std::env::temp_dir().join(format!("todoers-envelope-{}.json", Uuid::new_v4()));

        // First run: the file is created and a recovery key is handed back.
        let (env1, recovery) = load_or_create_envelope(&path).await.unwrap();
        let recovery = recovery.expect("first run yields a recovery key");
        assert_eq!(count_recipients(&env1), (1, 1));

        // The recovery key (canonicalized, exactly as a user re-types it) unwraps
        // the same SQLCipher key as the device path.
        let from_recovery = unlock_with_password(&env1, &canonical(&recovery))
            .await
            .unwrap();
        let from_device = unlock_with_device(&env1).await.unwrap();
        assert_eq!(from_recovery, from_device);

        // Second run: no new recovery key, same persisted envelope, device unlock
        // still recovers the identical key.
        let (env2, none) = load_or_create_envelope(&path).await.unwrap();
        assert!(none.is_none());
        assert_eq!(env1.database_id, env2.database_id);
        assert_eq!(unlock_with_device(&env2).await.unwrap(), from_device);

        let _ = std::fs::remove_file(&path);
    }
}
