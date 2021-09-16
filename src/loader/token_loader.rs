use crate::basic_loader;
use chrono::{DateTime, Utc};
use uuid::Uuid;

basic_loader!(
    TokenExpiryLoader,
    Uuid,
    DateTime<Utc>,
    "SELECT user_id AS ka, token_expiry AS val FROM users WHERE user_id = ANY($1)"
);
