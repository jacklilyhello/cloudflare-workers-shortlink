CREATE TABLE backup_jobs (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','uploading','complete','failed')),
  upload_id TEXT,
  upload_started_at INTEGER,
  after_row INTEGER NOT NULL DEFAULT 0,
  row_offset INTEGER NOT NULL DEFAULT 0,
  lease_until INTEGER NOT NULL DEFAULT 0,
  part_number INTEGER NOT NULL DEFAULT 1,
  parts TEXT NOT NULL DEFAULT '[]',
  size INTEGER NOT NULL DEFAULT 0,
  records INTEGER NOT NULL DEFAULT 0,
  completed_at INTEGER
);
CREATE UNIQUE INDEX backup_one_active ON backup_jobs((1)) WHERE status IN ('pending','uploading');
CREATE TABLE backup_rows (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  backup_id TEXT NOT NULL REFERENCES backup_jobs(id),
  payload TEXT NOT NULL
);
CREATE INDEX backup_rows_job ON backup_rows(backup_id,id);
