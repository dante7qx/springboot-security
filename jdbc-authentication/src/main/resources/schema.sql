CREATE TABLE users
(
    username VARCHAR(50)  NOT NULL PRIMARY KEY,
    password VARCHAR(500) NOT NULL,
    enabled  BOOLEAN      NOT NULL
);

CREATE TABLE authorities
(
    username  VARCHAR(50) NOT NULL,
    authority VARCHAR(50) NOT NULL,
    CONSTRAINT fk_authorities_users FOREIGN KEY (username) REFERENCES users (username)
);
CREATE UNIQUE INDEX ix_auth_username ON authorities (username, authority);


-- 初始化测试用户 (可选)
INSERT INTO users (username, password, enabled)
VALUES ('dante', '{bcrypt}$2a$10$G4Io4382I2d9yXqn0mFf.uU8ObvYw4L9X/JLgsUTu/sG3/gGfQG/u', true);

INSERT INTO authorities (username, authority)
VALUES ('dante', 'ROLE_USER');