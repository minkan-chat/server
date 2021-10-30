//! Auth*entication*
//!
//! This part deals with authentication. It determines an user's identity
use crate::{
    actors::{AuthenticatedUser, User},
    certificate::Certificate,
    fallible::*,
    graphql::Bytes,
    loader::TokenExpiryLoader,
    result_type, tri,
};

use super::{
    signup::{ChallengeProof, SignupResult, SignupUserInput},
    token::{RefreshTokenResult, TokenPair},
};
use async_graphql::{dataloader::DataLoader, Context, Object, Result};
use jsonwebtoken::{DecodingKey, EncodingKey};
use rand::Rng;
use redis::{Client, Commands};
use sqlx::{PgPool, Pool, Postgres};

#[derive(Default)]
pub struct AuthenticationQuery;

#[derive(Default)]
pub struct AuthenticationMutation;

result_type!(AuthenticationResult, AuthenticatedUser);

#[Object]
impl AuthenticationMutation {
    /// Signup
    ///
    /// Create a new account with the values in ``user`` and
    /// uses ``proof`` to verify that the user has control over
    /// the primary key supplied in ``user``.
    async fn signup(
        &self,
        ctx: &Context<'_>,
        user: SignupUserInput,
        proof: ChallengeProof,
    ) -> SignupResult {
        // get the redis pool
        let pool = ctx.data_unchecked::<r2d2::Pool<Client>>();
        // get a connection from the pool
        let mut con = pool.get().unwrap();

        // 32 bytes in hex = 64 chars
        if proof.challenge.len() != 64 {
            return Error::InvalidChallenge(InvalidChallenge {
                challenge: proof.challenge,
                description: "challenge length is invalid".to_string(),
                hint: Some(
                    "a challenge is a 32 byte hex string in lowercase (64 chars 0-9a-f)"
                        .to_string(),
                ),
            })
            .into();
        }
        // workaround because ``GETDEL`` is not supported (yet)
        // if the key (the challenge) is in the redis db,
        // it will return that 1 key got deleted
        let count: u8 = con.del(&proof.challenge.to_lowercase()).unwrap(); // this is blocking and therefore bad
        if count != 1 {
            return Error::InvalidChallenge(InvalidChallenge {
                challenge: proof.challenge,
                description: "the supplied challenge is not in the active challenge pool"
                    .to_string(),
                hint: Some("a challenge is only valid for two minutes".to_string()),
            })
            .into();
        }

        // check if we can parse the certificate and it complies with our policy
        let cert = tri!(Certificate::check(&user.certificate.into_inner()));

        // early return if the certificate has no secret parts
        if !cert.is_tsk() {
            return Error::from(InvalidCertificate::new(
                "certificate has no secret parts".to_string(),
            ))
            .into();
        }

        // verify the challenge
        tri!(proof.verify(&cert).await);

        // User into AuthenticatedUser
        let user: AuthenticatedUser =
            tri!(User::new(user.name, &cert, user.hash, ctx.data_unchecked::<PgPool>()).await)
                .into();
        // transform the AuthenticatedUser into SignupResult<Some(user), None> (result impl from $ok)
        user.into()
    }

    /// Authenticate
    ///
    /// If a user wants to access their account, they have to log in.
    /// The client supplies the username and master password hash so
    /// the server is able to identify the user.
    async fn authenticate(
        &self,
        ctx: &Context<'_>,
        username: String,
        mpw: Bytes,
    ) -> AuthenticationResult {
        let db = ctx.data_unchecked::<Pool<Postgres>>();

        tri!(
            tri!(User::try_from(&username, db).await) // try to get user from db or early return
                .authenticate(&mpw, db) // try to authenticate the user
                .await
        )
        .into()
    }

    /// Refresh token
    ///
    /// As part of your authentication system we have short lived access tokens.
    /// If a access token expires, a long-lived refresh token is used to get
    /// a new access token. Because refresh tokens are one time only, when
    /// requesting a new access token, you'll also need a new refresh token.
    /// We call this a ``TokenPair``.
    ///
    /// # Security
    ///
    /// If the server detects that a refresh token is being reused, it will invalid
    /// all tokens belonging to the user and the user will effectivly logged out
    /// everywhere. This is because it is possible that an attacker got hand on a
    /// refresh token and may have stolen a session. However, because the server
    /// can't know if the token was first used by the attacker or by the actual
    /// user, we must invalid at least that session.
    ///
    /// # Details
    ///
    /// The server stores a token kill timestamp. This timestamp tells the server
    /// which keys to accept or to reject. If the timestamp of the kill timestamp
    /// is bigger than the timestamp the token was issued (``iat`` field in the JWT),
    /// the token is rejected.\
    /// The server will also store a list of used refresh tokens.
    async fn refresh_token(&self, ctx: &Context<'_>, token: String) -> RefreshTokenResult {
        let keys = (
            ctx.data_unchecked::<EncodingKey>(),
            ctx.data_unchecked::<DecodingKey>(),
        );
        let db = ctx.data_unchecked::<Pool<Postgres>>();
        let loader = ctx.data_unchecked::<DataLoader<TokenExpiryLoader>>();
        tri!(TokenPair::refresh(token, keys, db, loader).await).into()
    }
}

#[Object]
impl AuthenticationQuery {
    /// Request a challenge which is used in the ``signup`` mutation to proof the control
    /// over the primary key of a pgp certificate. A challenge is valid for two minutes.
    async fn challenge(&self, ctx: &Context<'_>) -> Result<Bytes> {
        // generate 32 random bytes. should be a CSPRNG
        let challenge: [u8; 32] = rand::thread_rng().gen();

        // get the redis pool from the context
        let pool = ctx.data_unchecked::<r2d2::Pool<Client>>();
        // get a connection
        // TODO: this is not async. Consider bb8 when we can use tokio 1.0
        // currently blocked by actix-web (will be when actix-web 4 released)
        let mut con = pool.get().unwrap();
        // encode the challenge to a hex string
        // save it in the redis database for 120 seconds
        let _: () = con.set_ex(hex::encode(challenge), true, 120)?;

        Ok(bytes::Bytes::from(challenge.to_vec()).into())
    }
}
