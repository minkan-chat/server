//! Auth*entication* and auth*orization* queries
use async_graphql::MergedObject;
pub mod authentication;
mod session;
pub mod signup;
pub mod token;
pub use session::Session;

#[derive(MergedObject, Default)]
pub struct AuthQueries(pub authentication::AuthenticationQuery);

#[derive(MergedObject, Default)]
pub struct AuthMutations(pub authentication::AuthenticationMutation);
