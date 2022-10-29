-- Add migration script here
ALTER TABLE users ADD COLUMN user_type INTEGER NOT NULL DEFAULT 0;