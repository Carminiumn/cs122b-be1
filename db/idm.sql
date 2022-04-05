INSERT INTO idm.role(id, name, description, precedence)
VALUES (1, 'Admin', 'Role for admin access', 5),
       (2, 'Employee', 'Role for internal employees', 10),
       (3, 'Premium', 'Role for premium users', 15);

INSERT INTO idm.token_status(id, value)
VALUES (1, 'Active'),
       (2, 'Expired'),
       (3, 'Revoked');

INSERT INTO idm.user_status(id, value)
VALUES (1, 'Active'),
       (2, 'Locked'),
       (3, 'Banned');