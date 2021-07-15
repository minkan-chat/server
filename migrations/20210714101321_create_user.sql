CREATE TABLE users (
    id uuid NOT NULL,
    username text COLLATE pg_catalog."default" NOT NULL,
    password bytea NOT NULL,
    cert bytea,
    CONSTRAINT users_pkey PRIMARY KEY (id)
)