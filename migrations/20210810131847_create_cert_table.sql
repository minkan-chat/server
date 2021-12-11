CREATE TABLE certificates (
    "user_id" TEXT NOT NULL UNIQUE REFERENCES users(id) PRIMARY KEY,
    -- a pgp fingerprint is a sha-1 hash which is hex encoded without spaces
    -- and all UPPERCASE
    "fingerprint" VARCHAR(40) NOT NULL UNIQUE CONSTRAINT check_sha1_uppercase_hex 
        -- a sha1 hash in uppercase hex
        CHECK (fingerprint ~* '^[A-F0-9]{40}$'),
    -- all openpgp packets for this certificate
    -- Note: if the user uploaded a certificate with encrypted secret key 
    -- material, this will be in here, so remember not to return it. 
    -- e.g. dont use https://docs.rs/sequoia-openpgp/1.6.0/sequoia_openpgp/struct.Cert.html#method.as_tsk when exporting the certificate
    "body" BYTEA NOT NULL
);