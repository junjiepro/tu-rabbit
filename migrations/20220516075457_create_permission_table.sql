-- Add migration script here
BEGIN;
    CREATE TABLE permissions(
        permission_id uuid PRIMARY KEY,
        msg_id TEXT NOT NULL UNIQUE,
        default_msg TEXT NOT NULL,
        permission TEXT NOT NULL UNIQUE,
        remarks TEXT NOT NULL,
        created_at timestamp NOT NULL DEFAULT NOW(),
        update_at timestamp NOT NULL DEFAULT NOW()
    );
    CREATE TABLE role_and_permission(
        role_id uuid NOT NULL
        REFERENCES roles (role_id),
        permission_id uuid NOT NULL
        REFERENCES permissions (permission_id),
        created_at timestamp NOT NULL DEFAULT NOW(),
        PRIMARY KEY (role_id, permission_id)
    );
COMMIT;