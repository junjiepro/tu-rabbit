-- Add migration script here
BEGIN;
    -- Backfill `status` for historical entries
    UPDATE users
        SET status = 1
        WHERE status = 0;
    -- Make `status` mandatory
    ALTER TABLE users ALTER COLUMN status SET DEFAULT 1;
COMMIT;