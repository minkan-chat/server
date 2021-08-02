use async_graphql::{EmptySubscription, Schema};

use super::{mutations::Mutation, queries::Query};

pub(crate) type GraphQLSchema = Schema<Query, Mutation, EmptySubscription>;
