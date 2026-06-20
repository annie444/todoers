-- ============================================================================
-- 0002 — password-less device unlock cache.
--
-- A THIRD wrapping of the secret keys (alongside the server escrow and the local
-- Argon2id copy): the unlocked keys + a per-device Ed25519 device-auth keypair,
-- sealed to a local AGE/SSH key. This blob is class (1) — already encrypted, safe
-- at rest exactly like wrapped_secret_keys. device_id is the opaque handle the
-- server knows the device by (for enroll / device-login / revoke).
-- ============================================================================

ALTER TABLE account ADD COLUMN device_id BLOB
    CHECK (device_id IS NULL OR length(device_id) = 16);
ALTER TABLE account ADD COLUMN device_wrapped_keys BLOB;  -- age file: seal(UnlockedKeys ‖ device-auth key)

PRAGMA user_version = 2;
