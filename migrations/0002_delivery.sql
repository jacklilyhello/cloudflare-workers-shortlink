CREATE TABLE IF NOT EXISTS delivery_ownership (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  project TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  worker TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS legacy_migration_runs (
  id TEXT PRIMARY KEY,
  namespace_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  cursor TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL CHECK (state IN ('running', 'complete', 'failed')),
  processed INTEGER NOT NULL DEFAULT 0,
  imported INTEGER NOT NULL DEFAULT 0,
  unchanged INTEGER NOT NULL DEFAULT 0,
  skipped INTEGER NOT NULL DEFAULT 0,
  conflicts INTEGER NOT NULL DEFAULT 0,
  unknown INTEGER NOT NULL DEFAULT 0,
  digest TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS legacy_migration_items (
  run_id TEXT NOT NULL REFERENCES legacy_migration_runs(id),
  key_hash TEXT NOT NULL,
  value_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('imported', 'unchanged', 'skipped', 'conflict', 'unknown')),
  reason TEXT NOT NULL,
  PRIMARY KEY (run_id, key_hash, value_hash)
);
