CREATE TABLE users (
    -- refers to the `sub` claim in openid connect core
    -- see https://openid.net/specs/openid-connect-core-1_0.html
    -- it must be a json string (not an UUID)
    "id" TEXT NOT NULL UNIQUE PRIMARY KEY,
    -- refers to the `preferred_username`
    -- see https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    "username" TEXT NOT NULL
);