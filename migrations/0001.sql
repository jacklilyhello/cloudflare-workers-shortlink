PRAGMA foreign_keys = ON;

CREATE TABLE domains (
  hostname TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  bound INTEGER NOT NULL DEFAULT 0 CHECK (bound IN (0, 1)),
  created_at INTEGER NOT NULL
);

CREATE TABLE tokens (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  digest TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  revoked_at INTEGER,
  rate_per_minute INTEGER NOT NULL DEFAULT 60 CHECK (rate_per_minute BETWEEN 1 AND 1000)
);

CREATE TABLE token_domains (
  token_id TEXT NOT NULL REFERENCES tokens(id),
  domain TEXT NOT NULL REFERENCES domains(hostname),
  PRIMARY KEY (token_id, domain)
);

CREATE TABLE links (
  id TEXT PRIMARY KEY,
  domain TEXT NOT NULL REFERENCES domains(hostname),
  slug TEXT NOT NULL COLLATE BINARY,
  url TEXT NOT NULL,
  created_at INTEGER,
  expires_at INTEGER,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  confirm_enabled INTEGER NOT NULL DEFAULT 0 CHECK (confirm_enabled IN (0, 1)),
  confirm_text TEXT NOT NULL DEFAULT '',
  query_mode TEXT NOT NULL DEFAULT 'merge' CHECK (query_mode IN ('merge', 'preserve')),
  source TEXT NOT NULL CHECK (source IN ('machine', 'anonymous', 'migration', 'admin')),
  creator TEXT NOT NULL,
  token_id TEXT REFERENCES tokens(id),
  idempotency_key TEXT,
  request_hash TEXT,
  UNIQUE (domain, slug),
  UNIQUE (token_id, domain, idempotency_key),
  CHECK ((idempotency_key IS NULL AND request_hash IS NULL) OR
         (token_id IS NOT NULL AND idempotency_key IS NOT NULL AND request_hash IS NOT NULL))
);
CREATE INDEX links_created ON links(created_at DESC);
CREATE INDEX links_expiry ON links(expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE rate_windows (
  key TEXT NOT NULL,
  window INTEGER NOT NULL,
  count INTEGER NOT NULL CHECK (count >= 1),
  PRIMARY KEY (key, window)
);

CREATE TABLE audit (
  id TEXT PRIMARY KEY,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);
CREATE INDEX audit_created ON audit(created_at DESC);

CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT INTO settings (key, value) VALUES
  ('anonymous_rate_per_minute', '10'),
  ('domain_rate_per_minute', '120'),
  ('analytics_retention_days', '90'),
  ('audit_retention_days', '365'),
  ('backup_retention_days', '30'),
  ('backup_interval_hours', '24'),
  ('error_403', '没有访问权限'),
  ('error_404', '找不到这个链接'),
  ('error_disabled', '这个链接已停用或过期'),
  ('error_500', '服务暂时不可用，请稍后再试');

CREATE TABLE daily_stats (
  day TEXT NOT NULL,
  domain TEXT NOT NULL,
  slug TEXT NOT NULL,
  country TEXT NOT NULL,
  device TEXT NOT NULL,
  referrer TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 1 CHECK (count >= 1),
  PRIMARY KEY (day, domain, slug, country, device, referrer)
);

CREATE TABLE migration_records (
  source_key_hash TEXT PRIMARY KEY,
  domain TEXT NOT NULL,
  slug TEXT,
  status TEXT NOT NULL CHECK (status IN ('imported', 'unchanged', 'skipped', 'conflict')),
  value_hash TEXT NOT NULL,
  reason TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
