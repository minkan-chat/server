CREATE TABLE pub_certs (
    user_id UUID NOT NULL UNIQUE REFERENCES users(user_id) PRIMARY KEY,
    -- a pgp fingerprint is a sha-1 hash which is hex encoded without spaces
    -- and all UPPERCASE
    cert_fingerprint VARCHAR(40) NOT NULL UNIQUE,
    pub_cert BYTEA NOT NULL
);