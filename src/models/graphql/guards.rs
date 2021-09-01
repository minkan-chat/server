//! Guards used to check things before a resolver is even called

use super::mutations::helpers::Claims;

use async_graphql::guard::Guard;
use jsonwebtoken::TokenData;

/// Ensures that the request is made by an authenticated user
pub(crate) struct AuthenticationGuard;

#[async_trait::async_trait]
impl Guard for AuthenticationGuard {
    async fn check(&self, ctx: &async_graphql::Context<'_>) -> async_graphql::Result<()> {
        match ctx.data::<TokenData<Claims>>() {
            Ok(_) => Ok(()),
            Err(_) => Err(async_graphql::Error::new("Unauthenticated")),
        }
    }
}
