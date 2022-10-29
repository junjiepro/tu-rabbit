BEGIN;
    -- Backfill `status` for historical entries
    UPDATE users
        SET status = 1
        WHERE status IS NULL;
    -- Make `status` mandatory
    ALTER TABLE users ALTER COLUMN status SET NOT NULL;
    ALTER TABLE users ALTER COLUMN status SET DEFAULT 0;
COMMIT;