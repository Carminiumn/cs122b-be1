DELETE FROM idm.refresh_token WHERE id > 0;
DELETE FROM idm.user WHERE id > 0;

ALTER TABLE idm.user AUTO_INCREMENT = 1;
ALTER TABLE idm.refresh_token AUTO_INCREMENT = 1;

SET @admin_id = 1;
SET @employee_id = 2;
SET @premium_id = 3;

SET @active_status_id = (SELECT id
                         FROM idm.user_status
                         WHERE value = 'Active');
SET @locked_status_id = (SELECT id
                         FROM idm.user_status
                         WHERE value = 'Locked');
SET @banned_status_id = (SELECT id
                         FROM idm.user_status
                         WHERE value = 'Banned');

INSERT INTO idm.user (id, email, user_status_id, salt, hashed_password)
VALUES (@admin_id, 'Admin@example.com', @active_status_id, 'ebf18A==', 'QB9Kcn/pYWqSWvp7h7gtksYDYhmeLz8IyxtoKUtttfPnMcgVtCedspVwHF7ryvTNg3rpaxue3qzmIIj+yMoENg=='),
       (@employee_id, 'Employee@example.com', @active_status_id, 'j6u82Q==', 'YpqQNAOOWH5Wuii0oFmV6GoW7I1C4JGNMRIQW2e6cZty1JU63oz9zTNIlgaU/h/r9x2fmN1QYXciVDvyhKOsBA=='),
       (@premium_id, 'Premium@example.com', @active_status_id, '/97ajQ==', 'O1VbNL2bAlns/ujxP1BupI9PK7suXSVPJpkkMnHhiRX9YuNOT3+j4R/7JmyQbXgsMr3+Dh4qPt98kH/0+cHqVw==');

INSERT INTO idm.user (email, user_status_id, salt, hashed_password)
VALUES ('Active@example.com', @active_status_id, 'BXVDsQ==', '3906lItAtnDxDK5i85TKsdhfMNJgHYcK6quOR6FegjmPB6ppS6NH7j3ie83kjwotLlVZZVklclRKnyXTSVoEJw=='),
       ('Locked@example.com', @locked_status_id, 'RtmcdQ==', 'SWosU8p7X5gylD5DjZYGn/jx8btmETsayVB6kG3MWUXNXLf1udaBeKN2eJfRXN1aLWeYiDbCjkzC9gwOfDfMmA=='),
       ('Banned@example.com', @banned_status_id, '6qC3gQ==', 'phfAVFUj8x5nAETxLYM5xwrpDfRgyxaZm2s5qxEPp8eVQpQskuJIG/xwtarc/Eyt54vPzC3iqTjfr/SQzGUs8Q=='),
       ('LoginMinPass@example.com', @active_status_id, 'Vv2sSw==', '5UlJjR1TzUVWLgWQmjMRioi7tmLLQL99MIhtCi931hBzk6Qtn2szhI+On41hRaclXhChcGviuHmLthDKBWXtwQ=='),
       ('LoginMaxPass@example.com', @active_status_id, 'Ww2y+Q==', '+p1+BIm+bWDA8zqJ/8UdP4cH85ycezFz5uOTueaHJ7fzMPvnakqA7qY0h69oISE7jT4i/eeSBRW3JmKW0bh9Gg=='),
       ('a@a.io', @active_status_id, '0VJkdg==', 'EZoOTU2I1egZ+3FK5ADrZ2kHHy/9XSKr/S3nKbzfUUsJdXJaJqlVcciOsQx/aTYxsQJXTHP9ageAVzTQE9+MEw=='),
       ('LoginIsRightAtMaxLen@example.com', @active_status_id, 'Z+udXg==', 'e80+dqCEWEz1Fy5Ujt4Xaek/6LzROLZeqApaiBP7c1LQrURPEsOkXxR1qhXOimWopWwFaD2xqH56M342wxzVHA==');

SET @admin_role_id = (SELECT id
                      FROM idm.role
                      WHERE name = 'Admin');
SET @employee_role_id = (SELECT id
                         FROM idm.role
                         WHERE name = 'Employee');
SET @premium_role_id = (SELECT id
                        FROM idm.role
                        WHERE name = 'Premium');

INSERT INTO idm.refresh_token (token, user_id, token_status_id, expire_time, max_life_time)
VALUES ('c46fc3c2-9791-44d6-a86e-2922ad655284', @admin_id, 2, NOW(), NOW()),
       ('399cd90d-e715-484a-bb4d-a8ff35506ef9', @admin_id, 3, NOW(), NOW());

INSERT INTO idm.user_role (user_id, role_id)
VALUES (@admin_id, @admin_role_id),
       (@employee_id, @employee_role_id),
       (@premium_id, @premium_role_id);