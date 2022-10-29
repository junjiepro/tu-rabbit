-- Add migration script here
BEGIN;
    CREATE TABLE roles(
        role_id uuid PRIMARY KEY,
        msg_id TEXT NOT NULL UNIQUE,
        default_msg TEXT NOT NULL,
        namespace TEXT NOT NULL,
        remarks TEXT NOT NULL,
        created_at timestamp NOT NULL DEFAULT NOW(),
        update_at timestamp NOT NULL DEFAULT NOW()
    );
    CREATE TABLE user_and_role(
        user_id uuid NOT NULL
        REFERENCES users (user_id),
        role_id uuid NOT NULL
        REFERENCES roles (role_id),
        created_at timestamp NOT NULL DEFAULT NOW(),
        PRIMARY KEY (user_id, role_id)
    );
COMMIT;