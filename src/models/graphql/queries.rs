use async_graphql::{Context, Object, ID};
use moka::future::Cache;
use rand::Rng;

use super::interfaces::Actor;

pub(crate) struct Query;

#[Object]
/// The query root
impl Query {
    /// returns an Actor by its id or null if there's no such Actor
    pub(crate) async fn actor_by_id(&self, _id: ID) -> Option<Actor> {
        None
    }

    /// returns an Actor by its name
    pub(crate) async fn actor_by_name(&self, _name: String) -> Option<Actor> {
        None
    }

    /// Returns a challenge which is used to proof that the user has the control over the primary key on login
    pub(crate) async fn get_challenge(&self, ctx: &Context<'_>) -> String {
        let challenges = ctx.data::<Cache<String, ()>>().unwrap();
        let challenge: [u8; 32] = rand::thread_rng().gen();
        let challenge = hex::encode(challenge);
        challenges.insert(challenge.clone(), ()).await;
        challenge
    }
}
