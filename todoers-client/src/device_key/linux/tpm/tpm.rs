//! TPM2-backed sealed secret store — core TPM semantics.
//!
//! This module implements the *cryptographic spine* of a credential store whose
//! at-rest protection is rooted in the local TPM, with an update-resilient
//! `PolicyAuthorize` (signed-PCR) authorization policy. The keyring-core
//! `CredentialApi`/`CredentialStoreApi` wiring lives elsewhere; this file only
//! concerns itself with talking to the chip.
//!
//! # Architecture in one paragraph
//!
//! We provision a persistent **storage primary** (the "SRK") once, under the
//! owner hierarchy, and park it at a fixed persistent handle so we never pay the
//! primary-derivation cost again. Under that parent we **seal** a single 32-byte
//! data-encryption key (DEK). Everything else the store holds is AEAD-wrapped
//! under that DEK in normal files (not done here — that's your XChaCha20 layer).
//! The sealed DEK's authorization policy is *not* a literal `PolicyPCR` (which
//! would break on every kernel/firmware update); it's a `PolicyAuthorize` term
//! bound to the **Name of an offline signing key**. At unseal time we present a
//! `PolicyPCR` for the *current* PCRs plus a signature (produced offline by that
//! key) blessing those PCR values. OS updates => re-sign offline, never re-seal.
//!
//! The security of the whole thing is the **(SRK, signing-key) tuple**:
//!   * the SRK binds the sealed blob to *this* physical TPM (the private area is
//!     encrypted to the SRK and is useless on any other chip), and
//!   * the signed PCR policy lets the *unlock conditions* survive patching.
//!
//! # Threat model note (write this down for your NIST trail)
//!
//! There is deliberately **no operator-knowledge factor** (no PIN/passphrase):
//! this is auto-unlock. The sealed DEK is therefore recoverable by anything that
//! can reach the TPM as the owning user, on this host, in a PCR state the signer
//! has blessed. You are defending against *offline disk theft / blob
//! exfiltration*, not a live local attacker. That's the inherent cost of "no
//! master password," and it's the same posture as systemd-creds / clevis /
//! TPM-LUKS.
//!
//! # The seal-time vs. unseal-time split
//!
//! ```text
//!   PROVISION (once, per host)          OFFLINE (you, in CI, holds priv key)
//!   ------------------------            -----------------------------------
//!   provision_srk()                     for each blessed PCR state:
//!   load signing PUBLIC key               approved = pcr_policy_digest(state)
//!   authorized_policy_digest()  <------    aHash    = authorization_ahash(approved, ref)
//!   seal(dek) -> (priv, pub) blobs        sig      = Sign_privkey(aHash)
//!                                         ship {pub_blob, priv_blob, signature, ref}
//!
//!   UNSEAL (every cold start)
//!   ------------------------
//!   load (priv, pub) under SRK
//!   policy session: policy_pcr(current) ; verify_signature(aHash, sig) -> ticket
//!                   policy_authorize(approved, ref, keyName, ticket)
//!   unseal() -> DEK
//! ```
//!
//! # Cargo
//! ```toml
//! tss-esapi = "7"          # pin to your version; signatures below target 7.x
//! thiserror = "2"
//! ```

use std::convert::TryFrom;
use std::str::FromStr;

use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::SessionType;
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_VERIFIED};
use tss_esapi::handles::SessionHandle;
use tss_esapi::handles::{KeyHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::AesKeyBits;
use tss_esapi::interface_types::resource_handles::{Hierarchy, Provision};
use tss_esapi::interface_types::session_handles::{AuthSession, PolicySession};
use tss_esapi::structures::{
    Digest, EccPoint, EccScheme, KeyedHashScheme, MaxBuffer, Name, Nonce, PcrSelectionList,
    PcrSelectionListBuilder, PcrSlot, Private, Public, PublicBuilder, PublicEccParametersBuilder,
    PublicKeyedHashParameters, SensitiveData, Signature, SymmetricDefinition,
    SymmetricDefinitionObject, VerifiedTicket,
};
use tss_esapi::tcti_ldr::DeviceConfig;
use tss_esapi::tss2_esys::{TPM2B_DIGEST, TPMT_TK_VERIFIED};
use tss_esapi::{Context, TctiNameConf};

/// Conventional owner-hierarchy persistent slot for the SRK.
/// (EK lives at 0x81010001 by convention; don't collide with it.)
pub const SRK_PERSISTENT_HANDLE: u32 = 0x8100_0001;

/// `policyRef` ties a signature to a *purpose*. Keep it fixed and identical on
/// the seal side and the unseal side, or `PolicyAuthorize` will not reproduce
/// the same authPolicy digest. Empty is legal; a label is good hygiene.
pub const POLICY_REF: &[u8] = b"tui-secret-store/v1";

#[derive(Debug, thiserror::Error)]
pub enum TpmStoreError {
    #[error("TPM/ESAPI error: {0}")]
    Tss(#[from] tss_esapi::Error),
    #[error("expected a session but the TPM returned none")]
    NoSession,
    #[error("sealed secret too large ({0} bytes); seal a DEK, not bulk data")]
    SecretTooLarge(u32),
    #[error("conversion: {0}")]
    Convert(String),
}

impl From<TpmStoreError> for keyring_core::Error {
    fn from(e: TpmStoreError) -> Self {
        match e {
            TpmStoreError::SecretTooLarge(size) => {
                keyring_core::Error::TooLong("sealed secret too large".to_string(), size)
            }
            _ => keyring_core::Error::PlatformFailure(Box::new(e)),
        }
    }
}

type Result<T> = std::result::Result<T, TpmStoreError>;

/// Open an ESAPI context against the in-kernel resource manager.
///
/// `/dev/tpmrm0` (not `/dev/tpm0`) so the kernel virtualizes the scarce transient
/// object/session slots for us and we don't need tpm2-abrmd. The owning user must
/// be in group `tss` (or have a matching udev rule) to open it without root.
pub fn open_context() -> Result<Context> {
    // Honors $TPM2TOOLS_TCTI / $TCTI if set, else falls back to the RM device.
    let tcti = TctiNameConf::from_environment_variable()
        .or_else(|_| Ok(TctiNameConf::Device(DeviceConfig::from_str("/dev/tpmrm0")?)))
        .map_err(|e: tss_esapi::Error| TpmStoreError::Convert(format!("tcti: {e}")))?;
    Ok(Context::new(tcti)?)
}

// ---------------------------------------------------------------------------
// 1. Persistent SRK provisioning
// ---------------------------------------------------------------------------

/// Return a handle to the persistent SRK, provisioning it if it isn't there yet.
///
/// Idempotent: if `0x81000001` is already populated we just adopt it. NOTE: this
/// adopts *whatever* is at that handle. In a hardened deployment you'd also read
/// its public area and assert it matches `srk_template()` before trusting it,
/// to detect a squatted handle.
pub fn provision_srk(ctx: &mut Context) -> Result<KeyHandle> {
    let persistent = PersistentTpmHandle::new(SRK_PERSISTENT_HANDLE)
        .map_err(|e| TpmStoreError::Convert(format!("persistent handle: {e}")))?;

    // Already provisioned? `tr_from_tpm_public` resolves an existing TPM handle
    // into an ESYS object handle, or errors if nothing is there.
    if let Ok(obj) = ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent)) {
        return Ok(obj.into());
    }

    // Create the primary under the owner hierarchy, then evict it to NV.
    // create_primary runs under a session; the owner auth is empty by default.
    let primary = ctx.execute_with_nullauth_session(|c| {
        c.create_primary(Hierarchy::Owner, srk_template()?, None, None, None, None)
    })?;

    // Persist (TPM2_EvictControl). Requires owner authorization (Provision::Owner).
    let persisted = ctx.execute_with_nullauth_session(|c| {
        c.evict_control(
            Provision::Owner,
            primary.key_handle.into(),
            Persistent::Persistent(persistent),
        )
    })?;

    // The transient copy is no longer needed once it's persistent.
    let _ = ctx.flush_context(primary.key_handle.into());

    Ok(persisted.into())
}

/// A standard ECC-P256 restricted storage key — the parent under which we seal.
/// ECC over RSA: far faster primary derivation and smaller. This is SRK-shaped
/// but not byte-identical to the TCG "provisioning guidance" SRK; if you'd rather
/// not own provisioning at all, adopt systemd's SRK
/// (`/run/systemd/tpm2-srk-public-key.tpm2b_public`) and skip this entirely.
fn srk_template() -> std::result::Result<Public, tss_esapi::Error> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true) // key material generated in-TPM
        .with_user_with_auth(true)
        .with_restricted(true) // storage key
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .build()?;

    let ecc = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::Null) // storage key: no signing scheme
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(false)
        .with_is_decryption_key(true)
        .with_restricted(true)
        .with_symmetric(SymmetricDefinitionObject::Aes {
            key_bits: AesKeyBits::Aes128,
            mode: tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
        })
        .build()?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(ecc)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
}

// ---------------------------------------------------------------------------
// 2. The authorizing (signing) key + the authPolicy it implies
// ---------------------------------------------------------------------------

/// Load the *public* half of your offline authorizing key and return its handle
/// plus its TPM Name. The Name is what `PolicyAuthorize` hashes into the
/// authPolicy, so it MUST be produced identically at seal and unseal time:
/// same public blob, same hierarchy. We use the Owner hierarchy consistently.
///
/// `signing_pub` is your authorizing key as a TPM `Public` (an RSA or ECC
/// signing key). Converting a PEM into this `Public` is a separate concern;
/// keep the private half offline/in CI — the TPM never sees it.
pub fn load_authorizing_key(ctx: &mut Context, signing_pub: Public) -> Result<(KeyHandle, Name)> {
    let handle = ctx.load_external_public(signing_pub, Hierarchy::Owner)?;
    let name = ctx.tr_get_name(handle.into())?;
    Ok((handle.into(), name))
}

/// Compute the `PolicyAuthorize` authPolicy digest to stamp on the sealed object.
///
/// Key insight: `PolicyAuthorize` *resets* the running policy digest to a value
/// derived only from (keyName, policyRef) — it does NOT depend on the specific
/// PCR policy. That independence is exactly why updates don't require re-sealing.
/// We compute it on a **trial** session, where the signature/ticket check is
/// skipped, so we can pass an empty approved policy and a null ticket.
pub fn authorized_policy_digest(ctx: &mut Context, key_name: &Name) -> Result<Digest> {
    let trial = start_policy_session(ctx, SessionType::Trial)?;

    // Empty approved policy + null ticket are accepted in trial mode.
    let empty_policy = Digest::try_from(Vec::<u8>::new())
        .map_err(|e| TpmStoreError::Convert(format!("empty digest: {e}")))?;
    let policy_ref = Nonce::try_from(POLICY_REF.to_vec())
        .map_err(|e| TpmStoreError::Convert(format!("policy ref: {e}")))?;

    // see note in null_ticket(): version-sensitive
    let ticket = null_ticket()?;

    ctx.policy_authorize(trial, empty_policy, policy_ref, key_name, ticket)?;

    let digest = ctx.policy_get_digest(trial)?;
    ctx.flush_context(SessionHandle::from(trial).into()).ok();
    Ok(digest)
}

// ---------------------------------------------------------------------------
// 3. Sealing
// ---------------------------------------------------------------------------

/// Seal `dek` under the SRK with our `PolicyAuthorize` authPolicy.
/// Returns the (private, public) blobs to persist on disk — both are inert
/// without this TPM. Sealed sensitive data is small (~128 bytes max on most
/// TPMs): seal a DEK, never bulk secrets.
pub fn seal(
    ctx: &mut Context,
    srk: KeyHandle,
    auth_policy: Digest,
    dek: &[u8],
) -> Result<(Private, Public)> {
    if dek.len() > 128 {
        return Err(TpmStoreError::SecretTooLarge(
            dek.len().try_into().unwrap_or(u32::MAX),
        ));
    }

    let sensitive = SensitiveData::try_from(dek.to_vec())
        .map_err(|e| TpmStoreError::Convert(format!("sensitive data: {e}")))?;

    let result = ctx.execute_with_nullauth_session(|c| {
        c.create(
            srk,
            sealed_template(auth_policy.clone())?,
            None,
            Some(sensitive.clone()),
            None,
            None,
        )
    })?;

    Ok((result.out_private, result.out_public))
}

/// A KEYEDHASH "sealed data" object gated *only* by policy.
///
/// FOOTGUN (this bit people constantly): to make the object unsealable *only*
/// via the policy session and NOT also via a plain auth/HMAC session, you must
/// **clear `user_with_auth`**. Leaving it set creates a "policy OR password"
/// object — the policy becomes security theatre. `sensitive_data_origin` is also
/// cleared because we supply the data from outside.
fn sealed_template(auth_policy: Digest) -> std::result::Result<Public, tss_esapi::Error> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(false) // data supplied by us
        .with_user_with_auth(false) // <-- policy-only; do not set this true
        .with_no_da(true) // not subject to dictionary-attack lockout
        .build()?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_auth_policy(auth_policy)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
}

// ---------------------------------------------------------------------------
// 4. Offline helpers (run wherever; deterministic, no specific TPM required)
// ---------------------------------------------------------------------------

/// Compute the approved PCR policy digest for a *given expected* PCR composite.
/// Deterministic from (selection, expected digest, hash alg) — your CI can run
/// this on any TPM (or a swtpm) via a trial session. This is the value the
/// offline key signs (after wrapping into aHash below).
pub fn pcr_policy_digest(ctx: &mut Context, expected_pcr_digest: Digest) -> Result<Digest> {
    let trial = start_policy_session(ctx, SessionType::Trial)?;
    ctx.policy_pcr(trial, expected_pcr_digest, pcr_selection()?)?;
    let digest = ctx.policy_get_digest(trial)?;
    ctx.flush_context(SessionHandle::from(trial).into()).ok();
    Ok(digest)
}

/// The actual message your offline key signs:  aHash = H(approvedPolicy || policyRef).
/// `PolicyAuthorize` validates a ticket over exactly this; sign THIS digest, not
/// `approvedPolicy` raw. With an empty policyRef this collapses to H(approvedPolicy),
/// but we keep a non-empty ref, so the concatenation matters.
pub fn authorization_ahash(ctx: &mut Context, approved_policy: &Digest) -> Result<Digest> {
    // H is the signing key's nameAlg-associated hash; we standardize on SHA-256.
    // Concatenate the raw policy bytes with the policy ref, then hash.
    let mut buf = approved_policy.to_vec();
    buf.extend_from_slice(POLICY_REF);
    // You can hash in-TPM (ctx.hash) for FIPS routing, or in your system-OpenSSL
    // path. Shown here via the TPM for a single trust domain:

    let buf =
        MaxBuffer::try_from(buf).map_err(|e| TpmStoreError::Convert(format!("max buffer: {e}")))?;
    let (ahash, _ticket) = ctx.hash(buf, HashingAlgorithm::Sha256, Hierarchy::Null)?;
    Ok(ahash)
}

// ---------------------------------------------------------------------------
// 5. Unsealing (the online chain)
// ---------------------------------------------------------------------------

/// The full cold-start unlock. `signature` is the offline signature over
/// `authorization_ahash(approved)` for the PCR state we expect to currently be in.
#[allow(clippy::too_many_arguments)]
pub fn unseal(
    ctx: &mut Context,
    srk: KeyHandle,
    sealed_private: Private,
    sealed_public: Public,
    signing_pub: Public,
    approved_policy: Digest,
    signature: Signature,
) -> Result<SensitiveData> {
    // Load the sealed object under the SRK (transient).
    let item = ctx.execute_with_nullauth_session(|c| {
        c.load(srk, sealed_private.clone(), sealed_public.clone())
    })?;

    // Load the authorizing public key; capture its Name for PolicyAuthorize.
    let (sig_key, key_name) = load_authorizing_key(ctx, signing_pub)?;

    // Real (non-trial) policy session that will actually gate the unseal.
    let session = start_policy_session(ctx, SessionType::Policy)?;

    // (a) Bind to the CURRENT PCRs. Empty expected-digest => use current values;
    //     the *signature* is what decides whether this state is acceptable.
    let empty = Digest::try_from(Vec::<u8>::new())
        .map_err(|e| TpmStoreError::Convert(format!("empty: {e}")))?;
    ctx.policy_pcr(session, empty, pcr_selection()?)?;

    // (b) Verify the offline signature over aHash, yielding a ticket.
    let ahash = authorization_ahash(ctx, &approved_policy)?;
    let ticket: VerifiedTicket = ctx.verify_signature(sig_key, ahash, signature)?;

    // (c) PolicyAuthorize: TPM checks current session digest == approved_policy,
    //     validates the ticket against key_name, then RESETS the session digest
    //     to our sealed authPolicy. Match => unseal is now permitted.
    let policy_ref = Nonce::try_from(POLICY_REF.to_vec())
        .map_err(|e| TpmStoreError::Convert(format!("ref: {e}")))?;
    ctx.policy_authorize(session, approved_policy, policy_ref, &key_name, ticket)?;

    // (d) Unseal MUST run under the policy session (not a password session).
    let secret = ctx.execute_with_session(Some(session.into()), |c| c.unseal(item.into()))?;

    // Hygiene: drop transient handles.
    ctx.flush_context(item.into()).ok();
    ctx.flush_context(sig_key.into()).ok();
    ctx.flush_context(SessionHandle::from(session).into()).ok();

    Ok(secret)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Start a policy (or trial) session with SHA-256 and parameter encryption.
fn start_policy_session(ctx: &mut Context, kind: SessionType) -> Result<PolicySession> {
    let session: AuthSession = ctx
        .start_auth_session(
            None, // tpmKey: unbound/unsalted (fine for our use)
            None, // bind
            None, // nonce (TPM generates)
            kind,
            SymmetricDefinition::AES_128_CFB, // parameter encryption for the session
            HashingAlgorithm::Sha256,
        )?
        .ok_or(TpmStoreError::NoSession)?;
    PolicySession::try_from(session)
        .map_err(|e| TpmStoreError::Convert(format!("policy session: {e}")))
}

/// The PCR selection we gate against (SHA-256 bank, slots from PCR_SELECTION_SLOTS).
fn pcr_selection() -> Result<PcrSelectionList> {
    let slots: Vec<PcrSlot> = vec![PcrSlot::Slot7];
    PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &slots)
        .build()
        .map_err(|e| TpmStoreError::Convert(format!("pcr selection: {e}")))
}

/// A null `VerifiedTicket` for the trial-session `PolicyAuthorize` digest
/// computation. Trial sessions skip ticket validation, so this is well-formed
/// but never verified. Does not touch the TPM, hence no `&mut Context`.
fn null_ticket() -> Result<VerifiedTicket> {
    let null_tk = TPMT_TK_VERIFIED {
        tag: TPM2_ST_VERIFIED,   // 0x8022
        hierarchy: TPM2_RH_NULL, // 0x40000007
        // TPM2B_DIGEST.buffer is [u8; 64] (sizeof TPMU_HA / SHA-512). size 0
        // => empty digest. If you'd rather not hardcode 64, the sys crate
        // derives Default, so `TPM2B_DIGEST::default()` is equivalent.
        digest: TPM2B_DIGEST {
            size: 0,
            buffer: [0u8; 64],
        },
    };
    VerifiedTicket::try_from(null_tk)
        .map_err(|e| TpmStoreError::Convert(format!("null verified ticket: {e}")))
}
