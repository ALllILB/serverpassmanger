-- schema.sql

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS servers;
DROP TABLE IF EXISTS sections;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    access_levels TEXT
);

CREATE TABLE servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_name TEXT NOT NULL,
    local_ip TEXT,
    domain TEXT,
    port INTEGER NOT NULL,
    access_level TEXT NOT NULL,
    section TEXT,
    local_username TEXT,
    local_password_encrypted TEXT,
    domain_username TEXT,
    domain_password_encrypted TEXT
);

CREATE TABLE sections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
);

-- اضافه کردن کاربر ادمین اولیه
-- رمز عبور پیش‌فرض 'admin' است. حتما آن را بعدا عوض کنید!
INSERT INTO users (username, password_hash, role, access_levels) VALUES
('admin', 'pbkdf2:sha256:600000$wncjM1QEt87oGZzG$d52d9a3994ac610f448043621b16eb5121b67f1b7f0438a2e4e1147517c2f1f0', 'admin', 'level1,level2,level3');