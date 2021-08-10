CREATE TABLE session_info (
    session_id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    -- Not unique because a user can have multiple sessions. We need an index here, create one!
    user_id UUID NOT NULL REFERENCES users(user_id),
    -- the ip address of the client who logged in/belogs that session to
    ip_address INET NOT NULL,
    -- for browser or http clients, there's often a user agent e.g:
    -- Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0
    -- these can help a user to identify active sessions
    user_agent TEXT NOT NULL,
    -- optionally a user can set a name to directly identify a session
    -- e.g. "Minkan on my Laptop"
    session_name VARCHAR(32)
);