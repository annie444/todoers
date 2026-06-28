//! Wire + key schema for a zero-knowledge, shareable todo list.

use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use dryoc::dryocbox::{DryocBox, KeyPair, PublicKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use old_rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use tracing::error;
use x_wing::{
    CIPHERTEXT_SIZE, Ciphertext, DecapsulationKey, EncapsulationKey, KeyExport, XWingKem,
    kem::{Decapsulate, Encapsulate, Kem},
};
use zeroize::{Zeroize, Zeroizing};

use todoers_types::{
    DEVICE_CHALLENGE_VERSION, Dek, DeviceId, Ed25519Pub, Ed25519Signing, Epoch, KeySlot, ListId,
    ListMetadata, Member, MemberId, Nonce, UpdatePayload, X25519Pub, X25519Secret, aead_aad,
    device_challenge_view, signing_view,
};

use crate::error::{TodoersError, TodoersResult};

/// Encrypt a Loro update and sign it. `dek` is the symmetric key for `epoch`.
#[tracing::instrument(skip(loro_update, signing_key, list_id))]
pub fn produce_update(
    version: u8,
    list_id: &ListId,
    epoch: Epoch,
    author: &MemberId,
    dek: &Dek,
    signing_key: &SigningKey,
    loro_update: &[u8],
) -> TodoersResult<UpdatePayload> {
    let nonce = Nonce::generate(&mut OsRng);

    // Build a partial payload so AAD can be computed before ciphertext exists.
    let cipher = XChaCha20Poly1305::new(dek.as_ref().into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce.as_ref()),
            chacha20poly1305::aead::Payload {
                msg: loro_update,
                aad: &todoers_types::aead_aad(version, list_id, epoch, author, &nonce),
            },
        )
        .expect("encryption is infallible with valid key/nonce");

    let sig = signing_key.sign(&signing_view(
        version,
        list_id,
        epoch,
        author,
        &nonce,
        &ciphertext,
    ));
    let payload = UpdatePayload {
        version,
        list_id: *list_id,
        epoch,
        author: *author,
        nonce,
        ciphertext,
        signature: sig.into(),
    };
    Ok(payload)
}

/// Verify author signature, then decrypt. Returns the Loro update bytes.
#[tracing::instrument(skip(p, expect_list))]
pub fn verify_and_decrypt(
    p: &UpdatePayload,
    expect_list: &ListId,
    author_signing_pub: &Ed25519Pub,
    dek: &[u8; 32],
) -> TodoersResult<Vec<u8>> {
    if &p.list_id != expect_list {
        return Err(TodoersError::WrongList);
    }

    let vk = VerifyingKey::from_bytes(author_signing_pub.as_ref())?;
    let sig = Signature::from_bytes(&p.signature);
    vk.verify(
        &signing_view(
            p.version,
            &p.list_id,
            p.epoch,
            &p.author,
            &p.nonce,
            &p.ciphertext,
        ),
        &sig,
    )?;

    let cipher = XChaCha20Poly1305::new(dek.into());
    cipher
        .decrypt(
            XNonce::from_slice(p.nonce.as_ref()),
            chacha20poly1305::aead::Payload {
                msg: &p.ciphertext,
                aad: &aead_aad(p.version, &p.list_id, p.epoch, &p.author, &p.nonce),
            },
        )
        .map_err(|_| TodoersError::Aead)
}

// ---------------------------------------------------------------------------
// DEK wrapping — thin abstraction over a libsodium-style sealed box.
// Provided by `dryoc` (dryocbox sealed).
// ---------------------------------------------------------------------------

/// Seal a DEK to a member's X25519 public key (anonymous; no sender key needed).
#[tracing::instrument]
pub fn seal_to(dek: &Dek, recipient: &X25519Pub) -> Vec<u8> {
    let recipient_pk = PublicKey::from(recipient.as_ref());
    // Anonymous sealed box: ephemeral sender keypair is generated inside.
    DryocBox::seal_to_vecbox(dek.as_ref(), &recipient_pk)
        .expect("sealing is infallible with a valid public key")
        .to_vec()
}

/// Open a sealed DEK with your own X25519 keypair.
#[tracing::instrument(skip(my_secret))]
pub fn open_sealed(wrapped: &[u8], my_pub: &X25519Pub, my_secret: &[u8; 32]) -> TodoersResult<Dek> {
    let keypair = KeyPair {
        public_key: PublicKey::from(my_pub.as_ref()),
        secret_key: my_secret.into(),
    };
    let dek = DryocBox::from_bytes(wrapped)
        .map_err(|_| TodoersError::Aead)?
        .unseal_to_vec(&keypair)
        .map_err(|_| TodoersError::Aead)?;
    dek.try_into().map_err(|_| TodoersError::Aead)
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
pub fn generate_identity() -> (X25519Secret, X25519Pub) {
    let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    (secret.into(), public.into())
}

/// Generate a fresh Ed25519 signing keypair. Returns `(seed, public)` where the
/// 32-byte seed reconstructs the `SigningKey` via `SigningKey::from_bytes`.
#[tracing::instrument]
pub fn generate_signing() -> (Ed25519Signing, Ed25519Pub) {
    let mut rng = OsRng;
    let sk = ed25519_dalek::SigningKey::generate(&mut rng);
    (sk.clone().into(), sk.verifying_key().into())
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
) -> TodoersResult<[u8; 32]> {
    let params =
        Params::new(mem_kib, iters, parallelism, Some(32)).map_err(|_| TodoersError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| TodoersError::Kdf)?;
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
/// fails the AEAD tag check and returns `TodoersError::Aead`.
#[tracing::instrument(skip(master, blob))]
pub fn unwrap_secret_keys(
    master: &[u8; 32],
    blob: &[u8],
) -> TodoersResult<(X25519Secret, Ed25519Signing)> {
    if blob.len() < 24 {
        return Err(TodoersError::Aead);
    }
    let (nonce, ciphertext) = blob.split_at(24);
    let cipher = XChaCha20Poly1305::new(master.into());
    let plaintext = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| TodoersError::Aead)?;
    if plaintext.len() != SECRET_KEYS_LEN {
        return Err(TodoersError::Aead);
    }
    let mut identity_secret = [0u8; 32];
    let mut signing_seed = [0u8; 32];
    identity_secret.copy_from_slice(&plaintext[..32]);
    signing_seed.copy_from_slice(&plaintext[32..]);
    Ok((identity_secret.into(), signing_seed.into()))
}

// ---------------------------------------------------------------------------
// Device vault — encrypt the unlocked keys to a LOCAL AGE/SSH key so the app can
// unlock without a password (password-less device unlock). The sealed blob is
// class-1 (already encrypted), safe at rest exactly like `wrapped_secret_keys`.
// The protection is only as strong as the local private key: prefer an
// agent/passphrase/hardware-backed key over a plaintext identity file.
// ---------------------------------------------------------------------------

#[tracing::instrument]
pub fn keygen<P: AsRef<Path> + std::fmt::Debug>(
    output_path: P,
    header: Option<&'static str>,
) -> TodoersResult<String> {
    let (secret_key, public_key) = XWingKem::generate_keypair();
    let mut encoded_secret = hex::encode(secret_key.as_bytes());
    let encoded_public = hex::encode(public_key.to_bytes());

    // The secret key file is class-3 material: create it owner-only (0o600) and
    // refuse to clobber an existing key (overwriting would orphan any cache
    // already sealed to the old key — the user must remove it explicitly).
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    // TODO(windows): `mode(0o600)` is unix-only. If Windows support is added,
    // restrict this file's ACL to the current user (the default ACL may grant
    // broader read access), e.g. via a `windows-acl`/`windows-sys` DACL set.
    let mut file = opts.open(output_path.as_ref()).map_err(|e| {
        error!(?e, "failed to create device vault key");
        TodoersError::DeviceVault(format!(
            "failed to create device vault key at {}: {e}",
            output_path.as_ref().display()
        ))
    })?;
    let contents = Zeroizing::new(if let Some(contents) = header {
        format!("{contents}\n{encoded_secret}\n")
    } else {
        format!("{encoded_secret}\n")
    });
    encoded_secret.zeroize(); // wipe the standalone hex copy; `contents` zeroizes on drop
    std::io::Write::write_all(&mut file, contents.as_bytes()).map_err(|e| {
        error!(?e, "failed to write device vault key");
        TodoersError::DeviceVault(format!("failed to write device vault key: {e}"))
    })?;
    Ok(encoded_public)
}

/// Seal `plaintext` to a local X-Wing `recipient` (the hex-encoded public
/// encapsulation key from [`keygen`]). KEM-DEM: encapsulate to the recipient to
/// derive a 32-byte shared key, then `XChaCha20-Poly1305` over `plaintext`. The
/// blob layout is `ciphertext(1120) || nonce(24) || aead(tag+ct)`.
#[tracing::instrument(skip(plaintext))]
pub fn device_seal(recipient: &str, plaintext: &[u8]) -> TodoersResult<Vec<u8>> {
    let pk_bytes = hex::decode(recipient.trim())
        .map_err(|e| TodoersError::DeviceVault(format!("recipient is not valid hex: {e}")))?;
    let ek = EncapsulationKey::try_from(pk_bytes.as_slice())
        .map_err(|e| TodoersError::DeviceVault(format!("invalid recipient key: {e}")))?;

    let (ct, ss) = ek.encapsulate();
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(ss.as_slice()));
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let aead = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| TodoersError::Aead)?;

    let mut out = Vec::with_capacity(CIPHERTEXT_SIZE + nonce.len() + aead.len());
    out.extend_from_slice(ct.as_slice());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&aead);
    Ok(out)
}

/// Open a [`device_seal`] blob with the local X-Wing identity (the file
/// contents: comments plus one hex-encoded 32-byte decapsulation key). A
/// wrong/short key fails the KEM or the AEAD tag and returns an error.
#[tracing::instrument(skip(identity_contents, blob))]
pub fn device_open(identity_contents: &str, blob: &[u8]) -> TodoersResult<Vec<u8>> {
    // The identity file may hold comments (`#…`) above the single key line.
    let sk_hex = identity_contents
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or_else(|| TodoersError::DeviceVault("no device key found in identity file".into()))?;
    let sk: [u8; 32] = hex::decode(sk_hex)
        .map_err(|e| TodoersError::DeviceVault(format!("identity is not valid hex: {e}")))?
        .as_slice()
        .try_into()
        .map_err(|_| TodoersError::DeviceVault("device key must be 32 bytes".into()))?;
    let dk = DecapsulationKey::from(sk);

    if blob.len() < CIPHERTEXT_SIZE + 24 {
        return Err(TodoersError::DeviceVault(
            "device cache blob is too short".into(),
        ));
    }
    let (ct_bytes, rest) = blob.split_at(CIPHERTEXT_SIZE);
    let (nonce, aead) = rest.split_at(24);
    let ct = Ciphertext::try_from(ct_bytes)
        .map_err(|_| TodoersError::DeviceVault("invalid KEM ciphertext".into()))?;

    let ss = dk.decapsulate(&ct);
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(ss.as_slice()));
    cipher
        .decrypt(XNonce::from_slice(nonce), aead)
        .map_err(|_| TodoersError::Aead)
}

/// Sign a server-issued device-login challenge with the per-device Ed25519
/// device-auth key. Mirrors the server's `device_challenge_view` byte layout.
#[tracing::instrument(skip(device_signing_seed, nonce))]
pub fn sign_device_challenge(
    device_signing_seed: &[u8; 32],
    member_id: &MemberId,
    device_id: &DeviceId,
    nonce: &Nonce,
) -> [u8; 64] {
    let sk = ed25519_dalek::SigningKey::from_bytes(device_signing_seed);
    let msg = device_challenge_view(DEVICE_CHALLENGE_VERSION, member_id, device_id, nonce);
    sk.sign(&msg).to_bytes()
}

// ---------------------------------------------------------------------------
// Membership operations — what an Owner does. (Client-side; server just stores.)
// ---------------------------------------------------------------------------

/// Add a member: seal the *current* DEK to their pubkey and append a KeySlot.
/// No rotation needed — they only ever see data from now on, and the snapshot
/// is already under current_epoch.
#[tracing::instrument(skip(meta, new))]
pub fn add_member(meta: &mut ListMetadata, new: Member, current_dek: &Dek) {
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
pub fn remove_member(meta: &mut ListMetadata, remove: MemberId, new_dek: &Dek) {
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
