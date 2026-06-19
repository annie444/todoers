//! Wire + key schema for a zero-knowledge, shareable todo list.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use dryoc::dryocbox::{DryocBox, KeyPair, PublicKey};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use old_rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use todoers_types::{
    Ed25519Pub, Epoch, KeySlot, ListId, ListMetadata, Member, MemberId, UpdatePayload, X25519Pub,
};

use crate::error::{AppError, AppResult};

/// Associated data for the AEAD: binds the ciphertext to its context so a
/// member can't lift a valid ciphertext into a different list/epoch/author.
/// All fields fixed-width, so plain concatenation is unambiguous.
#[tracing::instrument(skip(p))]
fn aead_aad(p: &UpdatePayload) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 16 + 4 + 16 + 24);
    v.push(p.version);
    v.extend_from_slice(&p.list_id.0);
    v.extend_from_slice(&p.epoch.to_le_bytes());
    v.extend_from_slice(&p.author.0);
    v.extend_from_slice(&p.nonce);
    v
}

/// The signed view = AAD || ciphertext. The author commits to "I produced
/// *this* ciphertext in *this* context." Verifiable by every member.
#[tracing::instrument(skip(p))]
fn signing_view(p: &UpdatePayload) -> Vec<u8> {
    let mut v = aead_aad(p);
    v.extend_from_slice(&p.ciphertext);
    v
}

/// Encrypt a Loro update and sign it. `dek` is the symmetric key for `epoch`.
#[tracing::instrument(skip(loro_update, signing_key, list_id))]
pub fn produce_update(
    version: u8,
    list_id: ListId,
    epoch: Epoch,
    author: MemberId,
    dek: &[u8; 32],
    signing_key: &ed25519_dalek::SigningKey,
    loro_update: &[u8],
) -> AppResult<UpdatePayload> {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    // Build a partial payload so AAD can be computed before ciphertext exists.
    let mut payload = UpdatePayload {
        version,
        list_id,
        epoch,
        author,
        nonce,
        ciphertext: Vec::new(),
        signature: [0u8; 64],
    };

    let cipher = XChaCha20Poly1305::new(dek.into());
    payload.ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: loro_update,
                aad: &aead_aad(&payload),
            },
        )
        .expect("encryption is infallible with valid key/nonce");

    let sig = signing_key.sign(&signing_view(&payload));
    payload.signature = sig.to_bytes();
    Ok(payload)
}

/// Verify author signature, then decrypt. Returns the Loro update bytes.
#[tracing::instrument(skip(p, expect_list))]
pub fn verify_and_decrypt(
    p: &UpdatePayload,
    expect_list: ListId,
    author_signing_pub: &Ed25519Pub,
    dek: &[u8; 32],
) -> AppResult<Vec<u8>> {
    if p.list_id != expect_list {
        return Err(AppError::WrongList);
    }

    let vk = VerifyingKey::from_bytes(&author_signing_pub.0)?;
    let sig = Signature::from_bytes(&p.signature);
    vk.verify(&signing_view(p), &sig)?;

    let cipher = XChaCha20Poly1305::new(dek.into());
    cipher
        .decrypt(
            XNonce::from_slice(&p.nonce),
            chacha20poly1305::aead::Payload {
                msg: &p.ciphertext,
                aad: &aead_aad(p),
            },
        )
        .map_err(|_| AppError::Aead)
}

// ---------------------------------------------------------------------------
// DEK wrapping — thin abstraction over a libsodium-style sealed box.
// Provided by `dryoc` (dryocbox sealed).
// ---------------------------------------------------------------------------

/// Seal a DEK to a member's X25519 public key (anonymous; no sender key needed).
#[tracing::instrument]
pub fn seal_to(dek: &[u8; 32], recipient: &X25519Pub) -> Vec<u8> {
    let recipient_pk = PublicKey::from(recipient.0);
    // Anonymous sealed box: ephemeral sender keypair is generated inside.
    DryocBox::seal_to_vecbox(dek, &recipient_pk)
        .expect("sealing is infallible with a valid public key")
        .to_vec()
}

/// Open a sealed DEK with your own X25519 keypair.
#[tracing::instrument(skip(my_secret))]
pub fn open_sealed(
    wrapped: &[u8],
    my_pub: &X25519Pub,
    my_secret: &[u8; 32],
) -> AppResult<[u8; 32]> {
    let keypair = KeyPair {
        public_key: PublicKey::from(my_pub.0),
        secret_key: my_secret.into(),
    };
    let dek = DryocBox::from_bytes(wrapped)
        .map_err(|_| AppError::Aead)?
        .unseal_to_vec(&keypair)
        .map_err(|_| AppError::Aead)?;
    dek.try_into().map_err(|_| AppError::Aead)
}

// ---------------------------------------------------------------------------
// Account bootstrap — keypair generation and master-key wrapping of the user's
// private identity. Used by the auth driver (`crate::auth`).
//
//   secret-keys plaintext = identity_secret(32) ‖ signing_seed(32)
//   wrapped               = nonce(24) ‖ XChaCha20Poly1305(master, plaintext)
//
// Two wrappings exist over the SAME plaintext, under two different master keys:
//   - escrow_master  = derive_escrow_key(export_key)         → stored on server
//   - local_master   = derive_local_master(password, salt..) → stored on device
// ---------------------------------------------------------------------------

/// Length of the unwrapped secret-keys plaintext: X25519 secret ‖ Ed25519 seed.
const SECRET_KEYS_LEN: usize = 64;
const ESCROW_WRAP_DOMAIN: &[u8] = b"todoers:escrow-wrap:v1";

/// Generate a fresh X25519 identity keypair. Returns `(secret, public)`; the raw
/// secret bytes are interoperable with `open_sealed` (same curve as dryoc).
#[tracing::instrument]
pub fn generate_identity() -> ([u8; 32], X25519Pub) {
    let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    (secret.to_bytes(), X25519Pub(public.to_bytes()))
}

/// Generate a fresh Ed25519 signing keypair. Returns `(seed, public)` where the
/// 32-byte seed reconstructs the `SigningKey` via `SigningKey::from_bytes`.
#[tracing::instrument]
pub fn generate_signing() -> ([u8; 32], Ed25519Pub) {
    let mut rng = OsRng;
    let sk = ed25519_dalek::SigningKey::generate(&mut rng);
    (sk.to_bytes(), Ed25519Pub(sk.verifying_key().to_bytes()))
}

/// Derive the 32-byte AEAD key that wraps the escrowed secret keys from the
/// OPAQUE `export_key`. `export_key` is already uniform high-entropy output, so a
/// single domain-separated SHA-256 is a sound KDF (no HKDF needed).
#[tracing::instrument]
pub fn derive_escrow_key(export_key: &[u8]) -> [u8; 32] {
    let digest = Sha256::new()
        .chain_update(ESCROW_WRAP_DOMAIN)
        .chain_update(export_key)
        .finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

/// Derive the 32-byte local master key from the password and stored Argon2id
/// parameters. This is the OFFLINE path — it needs no server interaction.
#[tracing::instrument(skip(password, salt))]
pub fn derive_local_master(
    password: &[u8],
    salt: &[u8],
    mem_kib: u32,
    iters: u32,
    parallelism: u32,
) -> AppResult<[u8; 32]> {
    let params = Params::new(mem_kib, iters, parallelism, Some(32)).map_err(|_| AppError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| AppError::Kdf)?;
    Ok(out)
}

/// Seal the private identity under `master`: `nonce(24) ‖ AEAD(master, id ‖ sign)`.
#[tracing::instrument(skip(master, identity_secret, signing_seed))]
pub fn wrap_secret_keys(
    master: &[u8; 32],
    identity_secret: &[u8; 32],
    signing_seed: &[u8; 32],
) -> Vec<u8> {
    let mut plaintext = [0u8; SECRET_KEYS_LEN];
    plaintext[..32].copy_from_slice(identity_secret);
    plaintext[32..].copy_from_slice(signing_seed);

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new(master.into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext.as_slice())
        .expect("encryption is infallible with valid key/nonce");
    plaintext.zeroize();

    let mut out = Vec::with_capacity(24 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Reverse `wrap_secret_keys`. A wrong key (wrong password / wrong export_key)
/// fails the AEAD tag check and returns `AppError::Aead`.
#[tracing::instrument(skip(master, blob))]
pub fn unwrap_secret_keys(master: &[u8; 32], blob: &[u8]) -> AppResult<([u8; 32], [u8; 32])> {
    if blob.len() < 24 {
        return Err(AppError::Aead);
    }
    let (nonce, ciphertext) = blob.split_at(24);
    let cipher = XChaCha20Poly1305::new(master.into());
    let plaintext = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| AppError::Aead)?;
    if plaintext.len() != SECRET_KEYS_LEN {
        return Err(AppError::Aead);
    }
    let mut identity_secret = [0u8; 32];
    let mut signing_seed = [0u8; 32];
    identity_secret.copy_from_slice(&plaintext[..32]);
    signing_seed.copy_from_slice(&plaintext[32..]);
    Ok((identity_secret, signing_seed))
}

// ---------------------------------------------------------------------------
// Membership operations — what an Owner does. (Client-side; server just stores.)
// ---------------------------------------------------------------------------

/// Add a member: seal the *current* DEK to their pubkey and append a KeySlot.
/// No rotation needed — they only ever see data from now on, and the snapshot
/// is already under current_epoch.
#[tracing::instrument(skip(meta, new))]
pub fn add_member(meta: &mut ListMetadata, new: Member, current_dek: &[u8; 32]) {
    let wrapped = seal_to(current_dek, &new.identity_pub);
    meta.key_slots.push(KeySlot {
        epoch: meta.current_epoch,
        member: new.id,
        wrapped_dek: wrapped,
    });
    meta.members.push(new);
}

/// Remove a member: rotate. Generate a fresh DEK, bump the epoch, re-seal to
/// the *remaining* members, and drop the removed member's slots. Future updates
/// use the new epoch. (You cannot retract plaintext they already synced — that
/// boundary is inherent, not fixable by rotation.)
#[tracing::instrument(skip(meta, remove))]
pub fn remove_member(meta: &mut ListMetadata, remove: MemberId, new_dek: &[u8; 32]) {
    meta.members.retain(|m| m.id != remove);
    meta.current_epoch += 1;
    let epoch = meta.current_epoch;

    // Re-seal the new DEK to everyone who remains.
    for m in &meta.members {
        meta.key_slots.push(KeySlot {
            epoch,
            member: m.id,
            wrapped_dek: seal_to(new_dek, &m.identity_pub),
        });
    }
    // Optionally also drop key_slots for the removed member across all epochs.
    meta.key_slots.retain(|s| s.member != remove);
}
