-- Existing confirmation text remains literal text. All new behavior defaults off.
ALTER TABLE links ADD COLUMN confirm_mode TEXT NOT NULL DEFAULT 'text'
  CHECK (confirm_mode IN ('text', 'html'));
-- Keep the existing query_mode constraint and raw target URL intact.
ALTER TABLE links ADD COLUMN target_origin_only INTEGER NOT NULL DEFAULT 0
  CHECK (target_origin_only IN (0, 1));
ALTER TABLE domains ADD COLUMN interstitial_enabled INTEGER NOT NULL DEFAULT 0
  CHECK (interstitial_enabled IN (0, 1));
ALTER TABLE domains ADD COLUMN interstitial_delay INTEGER NOT NULL DEFAULT 5
  CHECK (interstitial_delay BETWEEN 0 AND 300);
ALTER TABLE domains ADD COLUMN interstitial_html TEXT NOT NULL DEFAULT '';
