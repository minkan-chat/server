CREATE TABLE users (
    user_id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid() PRIMARY KEY,
    -- we have to create an index for the username because it is used all the time
    username VARCHAR(16) NOT NULL UNIQUE CONSTRAINT check_username CHECK (username ~* '^[a-z0-9_]{3,16}$'),
    -- A argon2 hash. It uses a PHC string to represent the hash and the salt
    hash TEXT NOT NULL,
    -- times ALWAYS in UTC
    created_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp,
    token_expiry TIMESTAMPTZ NOT NULL DEFAULT current_timestamp,
    -- the backend server has to make sure that this is unique and that the cert's uid
    -- containts the username and there's no other pub cer with that fingerprint in 
    -- pub_certs
    enc_cert BYTEA NOT NULL,
    suspended BOOLEAN NOT NULL DEFAULT false,
    suspended_reason TEXT
);