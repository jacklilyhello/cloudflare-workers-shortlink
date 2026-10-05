INSERT INTO settings(key,value) VALUES
  ('backup_enabled','1'),
  ('migration_enabled','1'),
  ('migration_interval_hours','24')
ON CONFLICT(key) DO NOTHING;

ALTER TABLE backup_jobs ADD COLUMN started_at INTEGER;
ALTER TABLE backup_jobs ADD COLUMN last_attempt_at INTEGER;
ALTER TABLE backup_jobs ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE backup_jobs ADD COLUMN retry_at INTEGER;
ALTER TABLE backup_jobs ADD COLUMN last_error_code TEXT;
ALTER TABLE backup_jobs ADD COLUMN duration_ms INTEGER;
ALTER TABLE backup_jobs ADD COLUMN snapshot_digest TEXT;
ALTER TABLE backup_jobs ADD COLUMN object_digest TEXT;
ALTER TABLE backup_jobs ADD COLUMN verification_part INTEGER NOT NULL DEFAULT 0;
ALTER TABLE backup_jobs ADD COLUMN verification_etag TEXT;
ALTER TABLE backup_jobs ADD COLUMN retention_last_error TEXT;
ALTER TABLE backup_jobs ADD COLUMN retention_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE backup_jobs ADD COLUMN retention_retry_at INTEGER;

ALTER TABLE legacy_migration_runs ADD COLUMN completed_at INTEGER;
ALTER TABLE legacy_migration_runs ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE legacy_migration_runs ADD COLUMN last_error_code TEXT;
ALTER TABLE legacy_migration_runs ADD COLUMN retry_at INTEGER;
UPDATE legacy_migration_runs SET completed_at=updated_at WHERE state='complete';

CREATE TABLE automation_locks (
  name TEXT PRIMARY KEY CHECK(name='legacy-migration'),
  lease_until INTEGER NOT NULL DEFAULT 0,
  run_id TEXT,
  last_success_at INTEGER,
  last_error_code TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  retry_at INTEGER
);
INSERT INTO automation_locks(name) VALUES('legacy-migration');
