-- Fail on duplicate shortcodes instead of overwriting or silently merging any existing data.
-- The deployment must preserve a verified pre-upgrade R2 snapshot before applying this file.
CREATE UNIQUE INDEX links_global_slug ON links(slug COLLATE BINARY);

-- Minimal irreversible reservation: deliberately contains no resolvable target URL.
CREATE TABLE deleted_links (
  slug TEXT PRIMARY KEY COLLATE BINARY,
  link_id TEXT NOT NULL UNIQUE,
  deleted_at INTEGER NOT NULL,
  token_id TEXT,
  domain TEXT,
  idempotency_key TEXT,
  request_hash TEXT,
  UNIQUE(token_id, domain, idempotency_key)
);

ALTER TABLE domains ADD COLUMN binding_state TEXT NOT NULL DEFAULT 'unbound'
  CHECK(binding_state IN ('unbound','pending','verified','failed'));
ALTER TABLE domains ADD COLUMN last_verified_at INTEGER;
ALTER TABLE domains ADD COLUMN last_checked_at INTEGER;
ALTER TABLE domains ADD COLUMN binding_error TEXT;
-- Existing bound flags were set by the guarded deployment after real CF API verification.
UPDATE domains SET binding_state='verified' WHERE bound=1;
