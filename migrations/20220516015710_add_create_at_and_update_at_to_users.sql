-- Add migration script here
ALTER TABLE users ADD COLUMN created_at timestamp NOT NULL DEFAULT NOW();
ALTER TABLE users ADD COLUMN update_at timestamp NOT NULL DEFAULT NOW();