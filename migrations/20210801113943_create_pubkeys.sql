CREATE TABLE pubkeys (
    user uuid primary key,
    pubkey bytea UNIQUE
)