CREATE TABLE certifications (
    -- the fingerprint of the certifying certificate
    -- this links the actual user that created the certification
    -- in the certificates table
    "certifier_cert" VARCHAR(40) NOT NULL REFERENCES certificates(fingerprint),
    -- the certificate this certification is for
    -- it's actually a userid packet of a certificate
    -- but because we assume that a user's name is the only userid
    -- of a certificate, this is okay because there can only be
    -- one certification for one userid 
    "target_cert" VARCHAR(40) NOT NULL REFERENCES certificates(fingerprint)
    -- a user shouldn't certify itself
    CONSTRAINT check_no_self_signature CHECK (certifier_cert != target_cert),
    -- the actual certification a openpgp implementation can verify
    -- its a openpgp signature packet
    "body" BYTEA NOT NULL
)