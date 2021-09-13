use crate::{
    auth::{token::TokenPair, Session},
    certificate::{PrivateCertificate, PublicCertificate},
    loader::{PrivateCertificateLoader, PublicCertificateLoader, UsernameLoader},
};
use async_graphql::{dataloader::DataLoader, Context, Object};
use jsonwebtoken::EncodingKey;
use sqlx::{Pool, Postgres};

use super::User;

#[derive(Debug)]
#[repr(transparent)]
/// AuthenticatedUser
///
/// This object represents the result of an successful authentication. It is DANGEROURS
/// because the methods are able to generate new [``crate::auth::Session``]s. If this
/// ends up in a recursion, it is possible to generate unlimited sessions for an user.
///
/// Also, if this object is returned, it is possible to obtain the
/// [``crate::certificate::PrivateCertificate``] of a user.
///
/// **This struct does nothing do validate any credentials**
pub struct AuthenticatedUser(uuid::Uuid);

#[Object]
impl AuthenticatedUser {
    pub async fn id(&self) -> async_graphql::ID {
        self.0.into()
    }

    pub async fn name(&self, ctx: &Context<'_>) -> String {
        ctx.data_unchecked::<DataLoader<UsernameLoader>>()
            .load_one(self.0)
            .await
            .unwrap()
            .unwrap()
    }

    /// returns the ``PrivateCertificate`` of the ``User``
    pub async fn private_certificate(&self, ctx: &Context<'_>) -> PrivateCertificate {
        ctx.data_unchecked::<DataLoader<PrivateCertificateLoader>>()
            .load_one(self.0)
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn certificate(&self, ctx: &Context<'_>) -> PublicCertificate {
        ctx.data_unchecked::<DataLoader<PublicCertificateLoader>>()
            .load_one(self.0)
            .await
            .unwrap()
            .unwrap()
    }

    /// generates a new session and returns the first ``TokenPair``
    pub async fn token(&self, ctx: &Context<'_>, session_name: Option<String>) -> TokenPair {
        let db = ctx.data_unchecked::<Pool<Postgres>>();
        let key = ctx.data_unchecked::<EncodingKey>();
        let session = Session::new(self.0, session_name, db).await.unwrap();
        TokenPair::new(session, key).await
    }
}

impl From<User> for AuthenticatedUser {
    /// Use this with ATTENTION. You turn an unauthenticated
    /// [``crate::actors::User``] into an [``AuthenticatedUser``]
    fn from(user: User) -> Self {
        Self(user.id)
    }
}
