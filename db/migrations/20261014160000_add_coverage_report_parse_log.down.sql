BEGIN;

ALTER TABLE coverage_reports DROP COLUMN IF EXISTS parse_log;

COMMIT;
