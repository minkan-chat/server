use async_graphql::{Interface, ID};

use crate::{actors::User, auth::Session};

#[derive(Interface)]
#[graphql(field(name = "id", type = "ID"))]
/// Node
///
/// A node is an interface that all objects with an ID implement.
/// It is used for [global object identification][1].
///
/// [1]: https://graphql.org/learn/global-object-identification/
pub enum Node {
    User(User),
    Session(Session),
}
