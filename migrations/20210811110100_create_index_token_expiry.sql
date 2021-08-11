-- the token expiry is updated every two minutes for every user, so an index only scan seems like a good idea
-- this is for a query like SELECT token_expiry from users WHERE user_id = $1
CREATE INDEX token_expiry_idx ON users (user_id) INCLUDE (token_expiry);