CREATE TABLE users (
    "id" UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4() PRIMARY KEY,
    -- we have to create an index for the username because it is used all the time
    -- an username is used by other users to identify each other
    -- also, the user's certificate must contain this username as an userid
    -- with the minkan host e.g. `my_name@some.minkan.host`
    "username" VARCHAR(16) NOT NULL UNIQUE CONSTRAINT check_username CHECK (username ~* '^[a-z0-9_]{3,16}$'),
    -- times ALWAYS in UTC
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT current_timestamp,
    -- this should prevent the user from taking any actions
    "suspended" BOOLEAN NOT NULL DEFAULT false,
    "suspended_reason" TEXT
);