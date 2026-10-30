-- Preserve existing geographic/device/referrer aggregates and their primary key.
-- Historical UA values were not retained, so browser families cannot be backfilled.
CREATE TABLE daily_browser_stats (
  day TEXT NOT NULL,
  domain TEXT NOT NULL,
  browser TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 1 CHECK (count >= 1),
  PRIMARY KEY (day, domain, browser)
);
