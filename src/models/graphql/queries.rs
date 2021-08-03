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
    /// A client, for example, need the Certificate of a Server to sign it as a proof.
    pub(crate) async fn server(&self) -> Server {
        Server {}
    }

    /// returns an Actor by its id
    pub(crate) async fn actor_by_id(&self, id: ID) -> Actor {
        Actor::User(User {})
    }

    /// returns an Actor by its name
    pub(crate) async fn actor_by_name(&self, name: String) -> Actor {
        Actor::User(User {})
    }
}
