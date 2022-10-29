-- Add migration script here
BEGIN;
    INSERT INTO permissions (permission_id, msg_id, default_msg, permission, remarks)
    VALUES (
        'e3052e49-aa66-4bc0-8380-fa2ab51971b7',
        'admin',
        'Super Administrator',
        'admin',
        'Super Administrator'
    );
    INSERT INTO role_and_permission (role_id, permission_id)
    VALUES (
        '32cff483-5dda-4ce2-b49a-ea3a85ed54f4',
        'e3052e49-aa66-4bc0-8380-fa2ab51971b7'
    );
COMMIT;