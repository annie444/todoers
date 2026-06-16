//! Wire + key schema for a zero-knowledge, shareable todo list.

use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use dryoc::dryocbox::{DryocBox, KeyPair, PublicKey};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use old_rand_core::{OsRng, RngCore};

use todoers_types::{
    Ed25519Pub, Epoch, KeySlot, ListId, ListMetadata, Member, MemberId, UpdatePayload, X25519Pub,
};

use crate::error::{AppError, AppResult};

/// Associated data for the AEAD: binds the ciphertext to its context so a
/// member can't lift a valid ciphertext into a different list/epoch/author.
/// All fields fixed-width, so plain concatenation is unambiguous.
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
fn signing_view(p: &UpdatePayload) -> Vec<u8> {
    let mut v = aead_aad(p);
    v.extend_from_slice(&p.ciphertext);
    v
}

/// Encrypt a Loro update and sign it. `dek` is the symmetric key for `epoch`.
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
// Provided by `crypto_box` (sealed-box feature) or `dryoc` (dryocbox sealed).
// ---------------------------------------------------------------------------

/// Seal a DEK to a member's X25519 public key (anonymous; no sender key needed).
pub fn seal_to(dek: &[u8; 32], recipient: &X25519Pub) -> Vec<u8> {
    let recipient_pk = PublicKey::from(recipient.0);
    // Anonymous sealed box: ephemeral sender keypair is generated inside.
    DryocBox::seal_to_vecbox(dek, &recipient_pk)
        .expect("sealing is infallible with a valid public key")
        .to_vec()
}

/// Open a sealed DEK with your own X25519 keypair.
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
// Membership operations — what an Owner does. (Client-side; server just stores.)
// ---------------------------------------------------------------------------

/// Add a member: seal the *current* DEK to their pubkey and append a KeySlot.
/// No rotation needed — they only ever see data from now on, and the snapshot
/// is already under current_epoch.
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
