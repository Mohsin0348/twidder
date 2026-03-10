DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS tokens;

CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    firstname TEXT NOT NULL,
    familyname TEXT NOT NULL,
    gender TEXT NOT NULL,
    city TEXT NOT NULL,
    country TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    writer_email TEXT NOT NULL,
    recipient_email TEXT NOT NULL,
    latitude REAL,
    longitude REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tokens (
    email TEXT NOT NULL,
    token TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS passwordrecovery (
    email TEXT NOT NULL,
    token TEXT NOT NULL
);
