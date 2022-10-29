-- Add migration script here
CREATE TABLE applications(
    application_id uuid PRIMARY KEY,
    msg_id TEXT NOT NULL UNIQUE,
    default_msg TEXT NOT NULL,
    role_msg_id TEXT NOT NULL,
    remarks TEXT NOT NULL,
    created_at timestamp NOT NULL DEFAULT NOW(),
    update_at timestamp NOT NULL DEFAULT NOW()
);