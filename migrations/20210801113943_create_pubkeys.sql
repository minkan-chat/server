CREATE TABLE pubkeys (
    user_id UUID PRIMARY KEY,
    fingerprint TEXT UNIQUE NOT NULL,
    pubkey bytea UNIQUE NOT NULL
)