use async_graphql::{Object, ID};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::actors::{Actor, User};

#[derive(Debug)]
#[non_exhaustive]
pub struct Session {
    /// The user this session belongs to
    pub user_id: Uuid,
    /// the unique identifier of this session
    pub session_id: Uuid,
    /// a name to easier identify this session
    pub session_name: Option<String>,
}

impl Session {
    pub async fn new(
        user_id: Uuid,
        session_name: Option<String>,
        db: &Pool<Postgres>,
    ) -> Result<Self, sqlx::Error> {
        // insert the session and let the database generate a uuid
        let session_id = sqlx::query!(
            r#"
        INSERT INTO session_info (
            user_id,
            session_name
        ) VALUES ($1, $2)
        RETURNING session_id AS "id!: Uuid"
        "#,
            user_id,
            session_name
        )
        .fetch_one(db)
        .await?
        .id;

        Ok(Self {
            session_id,
            session_name,
            user_id,
        })
    }
}

#[Object]
/// Session
///
/// Keeps information about the time frame the client can use a
/// ``TokenPair`` to authenticate
impl Session {
    /// the ``Actor`` this session belongs to.
    /// This will never be an ``AuthenticatedUser``.
    pub async fn actor(&self) -> Actor {
        Actor::User(User::from(self.user_id))
    }

    /// the unique identifier of the session
    pub async fn id(&self) -> ID {
        self.user_id.into()
    }

    /// the optional name of the session to easier identify the session
    pub async fn name(&self) -> Option<String> {
        self.session_name.clone()
    }
}
