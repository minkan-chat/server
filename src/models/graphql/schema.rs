use super::{mutations::Mutation, queries::Query};
use async_graphql::{EmptySubscription, Schema};

pub(crate) type GraphQLSchema = Schema<Query, Mutation, EmptySubscription>;
