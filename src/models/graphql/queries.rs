use async_graphql::{Object, ID};

use super::{
    interfaces::Actor,
    types::{Server, User},
};

pub(crate) struct Query;

#[Object]
/// The query root
impl Query {
    /// Used to get information about the current backend Server.
    pub(crate) async fn server(&self) -> Server {
        Server {}
    }

    /// returns an Actor by its id or null if there's no such Actor
    pub(crate) async fn actor_by_id(&self, id: ID) -> Option<Actor> {
        Some(Actor::User(User {}))
    }

    /// returns an Actor by its name
    pub(crate) async fn actor_by_name(&self, name: String) -> Option<Actor> {
        Some(Actor::User(User {}))
    }
}
