CREATE TABLE session_info (
    session_id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    -- Not unique because a user can have multiple sessions. We need an index here, create one!
    user_id UUID NOT NULL REFERENCES users(user_id),
    -- optionally a user can set a name to directly identify a session
    -- e.g. "Minkan on my Laptop"
    session_name VARCHAR(32)
);