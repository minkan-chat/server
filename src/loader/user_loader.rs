use crate::basic_loader;

basic_loader!(
    UsernameLoader,
    uuid::Uuid,
    String,
    r#"SELECT "id" AS ka, username AS val FROM users WHERE "id" = ANY($1)"#
);
