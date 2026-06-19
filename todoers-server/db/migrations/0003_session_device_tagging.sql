-- ============================================================================
-- Per-device session tagging + step-up support.
--
-- Tag each session with the device that minted it: NULL for an ordinary password
-- (OPAQUE) login, the device_id for a password-less device login. This lets us:
--   * revoke a device AND kill its live sessions in one step, and
--   * require a recent PASSWORD (non-device) session for sensitive operations
--     like enrolling/revoking trusted device keys (step-up auth), so a
--     compromised device can't escalate by enrolling more devices.
-- ============================================================================

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_id UUID;

CREATE INDEX IF NOT EXISTS sessions_by_member_device ON sessions (member_id, device_id);

COMMENT ON COLUMN sessions.device_id IS 'Device that minted this session (NULL = password login). Lets revocation kill device sessions and gates step-up auth.';
