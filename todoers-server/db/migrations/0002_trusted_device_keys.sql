-- ============================================================================
-- Trusted device keys — password-less "device login".
--
-- Each device that opts into password-less unlock enrolls a dedicated Ed25519
-- device-auth public key here. To sync without a password the device proves
-- possession of the matching private key via a signed challenge (see the
-- /v1/auth/device-login/* endpoints). Removing (revoking) a row makes the server
-- reject that device, even if its on-disk encrypted key cache was compromised.
--
-- BLINDNESS CONTRACT: device_signing_pub is a PUBLIC key — like users.signing_pub
-- it reveals no list content, so storing it in the clear does not weaken the
-- zero-knowledge model. The server only ever verifies signatures with it.
-- ============================================================================

CREATE TABLE IF NOT EXISTS trusted_device_keys (
    member_id          UUID NOT NULL REFERENCES users(member_id) ON DELETE CASCADE,
    device_id          UUID NOT NULL,                                          -- client-generated, opaque
    device_signing_pub BYTEA NOT NULL CHECK (octet_length(device_signing_pub) = 32),  -- Ed25519, public
    label              TEXT NOT NULL DEFAULT '',                               -- human label, not a secret
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at         TIMESTAMPTZ,                                            -- NULL = active
    PRIMARY KEY (member_id, device_id)
);

CREATE INDEX IF NOT EXISTS trusted_device_keys_by_member ON trusted_device_keys (member_id);

COMMENT ON TABLE trusted_device_keys IS 'Per-device Ed25519 public keys for password-less device login; revoke a row to reject a lost/compromised device.';
