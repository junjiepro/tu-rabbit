-- Add migration script here
BEGIN;
    INSERT INTO roles (role_id, msg_id, default_msg, namespace, remarks)
    VALUES (
        '32cff483-5dda-4ce2-b49a-ea3a85ed54f4',
        'admin',
        'Super Administrator',
        '',
        'Super Administrator'
    );
    INSERT INTO user_and_role (user_id, role_id)
    VALUES (
        'ddf8994f-d522-4659-8d02-c1d479057be6',
        '32cff483-5dda-4ce2-b49a-ea3a85ed54f4'
    );
COMMIT;