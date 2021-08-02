use async_graphql::{ID, Object};
use crate::models::graphql::types::{AuthenticatedUser, PrivateCertificate, User};

use super::types::{AuthenticationCredentialsUserInput, AuthenticationResult, SignupUserInput, SignupResult};

pub(crate) struct Mutation;

#[Object]
/// The mutation root
impl Mutation {
    /// The clients sends a SignupUserInput to the server with all information
    async fn signup(&self, user: SignupUserInput) -> SignupResult {
        SignupResult {
            user: Some(User {}),
            errors: vec![]
        }
    }

    /// The clients sends a AuthenticationCredentialsUserInput
    async fn authenticate(&self, credentials: AuthenticationCredentialsUserInput) -> AuthenticationResult {
        AuthenticationResult {
            user: Some(AuthenticatedUser {
                certificate: PrivateCertificate {},
                id: ID("aaa".to_string()),
                name: "erik".to_string()
            }),
            errors: vec![]
        }
    }
}