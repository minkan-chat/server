CREATE TABLE pubkeys (
    user_id UUID PRIMARY KEY,
    fingerprint TEXT UNIQUE,
    pubkey bytea UNIQUE
)