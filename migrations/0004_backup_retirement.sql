ALTER TABLE backup_jobs ADD COLUMN retired_at INTEGER;
ALTER TABLE backup_jobs ADD COLUMN retention_checked_at INTEGER;
CREATE INDEX backup_retention_checks ON backup_jobs(status, retention_checked_at, created_at, id);
