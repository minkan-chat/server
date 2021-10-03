use async_graphql::{EmptySubscription, MergedObject, Schema};

mod bytes;
mod node;

pub use self::bytes::Bytes;
pub use node::Node;

use crate::{
    auth::{AuthMutations, AuthQueries},
    trust::{TrustMutations, TrustQueries},
};

pub type GraphQLSchema = Schema<Queries, Mutations, EmptySubscription>;

#[derive(MergedObject, Default)]
pub struct Queries(AuthQueries, TrustQueries);

#[derive(MergedObject, Default)]
pub struct Mutations(AuthMutations, TrustMutations);
