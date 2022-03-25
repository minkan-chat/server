-- this table stores sessions which got revoked via backchannel logout
-- if a session is encountered and it is in this table, it will be rejected.
CREATE TABLE revoked_sessions (
    -- the `sid` claim
    "id" TEXT NOT NULL PRIMARY KEY UNIQUE
)