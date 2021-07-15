use async_graphql::{Schema, EmptyMutation, EmptySubscription, Context, ID, Object};
use sqlx::PgPool;
use uuid::Uuid;

pub type AzumaSchema = Schema<QueryRoot, EmptyMutation, EmptySubscription>;

pub struct QueryRoot;

pub struct Azuma {
    db: PgPool,
}

impl Azuma {
    pub fn new(db: PgPool) -> Self {
        Self {
            db
        }
    }
}

#[Object]
impl QueryRoot {
    async fn getSessionToken(&self,
                             ctx: &Context<'_>,
                             id: ID,
    ) -> ID {
        ID(Uuid::new_v4().to_string())
    }
}