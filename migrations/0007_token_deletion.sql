-- Retain Token IDs for existing links, idempotency and audit history.
ALTER TABLE tokens ADD COLUMN deleted_at INTEGER;
