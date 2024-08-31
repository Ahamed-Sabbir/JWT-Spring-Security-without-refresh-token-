INSERT INTO authority_table
VALUES(1, 'ROLE_ADMIN');

INSERT INTO authority_table
VALUES(2, 'ROLE_USER');

INSERT INTO user_table (user_id, first_name, last_name, username, password)
VALUES(101L, 'Sabbir', 'Ahamed', 'SabbirAhamed', '$2a$10$YyeI6jq4plI0algXyt5JcOhISjpYBUOCSe4Jcu/tUmJteg6IBxZCC');

INSERT INTO user_authority (user_id, authority_id)
VALUES(101L, 1);
