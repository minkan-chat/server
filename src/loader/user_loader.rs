use crate::basic_loader;

basic_loader!(
    UsernameLoader,
    uuid::Uuid,
    String,
    "SELECT user_id AS ka, username AS val FROM users WHERE user_id = ANY($1)"
);
