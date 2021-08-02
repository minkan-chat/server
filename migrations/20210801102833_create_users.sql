CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    enc_cert bytea UNIQUE,
    username text NOT NULL,
    master_pw_hash bytea NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT current_timestamp,
    suspended bool NOT NULL DEFAULT false
)