use crate::{
    models::graphql::types::{AuthenticatedUser, PrivateCertificate, User},
    Config,
};
use async_graphql::{Context, Object, ID};

use super::types::{
    AuthenticationCredentialsUserInput, AuthenticationResult, SignupResult, SignupUserInput,
};

pub(crate) struct Mutation;

#[Object]
/// The mutation root
impl Mutation {
    /// The clients sends a SignupUserInput to the server with all information
    async fn signup(&self, user: SignupUserInput) -> SignupResult {
        SignupResult {
            user: Some(User {}),
            errors: vec![],
        }
    }

    /// The clients sends a AuthenticationCredentialsUserInput
    async fn authenticate(
        &self,
        ctx: &Context<'_>,
        credentials: AuthenticationCredentialsUserInput,
    ) -> AuthenticationResult {
        let config = ctx.data::<Config>().unwrap();
        AuthenticationResult {
            user: Some(AuthenticatedUser {
                certificate: PrivateCertificate {
                    cert: config.server_cert.0.clone(),
                },
                id: ID("aaa".to_string()),
                name: "erik".to_string(),
            }),
            errors: vec![],
        }
    }
}
