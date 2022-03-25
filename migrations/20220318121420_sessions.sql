CREATE TABLE sessions (
    -- the session id (`sid` claim in the id token)
    "id" TEXT NOT NULL PRIMARY KEY,
    -- the user this session related to (`sub` claim)
    "user_id" TEXT NOT NULL REFERENCES users(id),
    -- the date and time this session was first encountered
    "encountered" TIMESTAMPTZ NOT NULL DEFAULT current_timestamp
)