//! Auth*entication*
//!
//! This part deals with authentication. It determines an user's identity
//! as well as checking their identity
use std::convert::TryFrom;

use crate::{
    actors::{AuthenticatedUser, User},
    certificate::{PrivateCertificate, PublicCertificate},
    fallible::*,
    tri,
};

use super::signup::{ChallengeProof, SignupResult, SignupUserInput};
use async_graphql::{Context, Object, Result};
use rand::Rng;
use redis::{Client, Commands};
use sqlx::{Pool, Postgres};

#[derive(Default)]
pub struct AuthenticationQuery;

#[derive(Default)]
pub struct AuthenticationMutation;

#[Object]
impl AuthenticationMutation {
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
        let cert = tri!(PrivateCertificate::try_from(user.certificate.into_inner()));

        let db = ctx.data_unchecked::<Pool<Postgres>>();

        let pub_cert: PublicCertificate = cert.clone().into();
        // verify the challenge
        tri!(proof.verify(pub_cert).await);

        let user: AuthenticatedUser = tri!(User::new(user.name, cert, user.hash, db).await).into();
        user.into()
    }
}

#[Object]
impl AuthenticationQuery {
    async fn challenge(&self, ctx: &Context<'_>) -> Result<String> {
        // generate 32 random bytes. should be a CSPRNG
        let challenge: [u8; 32] = rand::thread_rng().gen();
        // encode these 32 random bytes to a hex string
        let challenge = hex::encode(challenge);

        // get the redis pool from the context
        let pool = ctx.data_unchecked::<r2d2::Pool<Client>>();
        // get a connection
        // TODO: this is not async. Consider bb8 when we can use tokio 1.0
        // currently blocked by actix-web (will be when actix-web 4 released)
        let mut con = pool.get().unwrap();
        let _: () = con.set_ex(&challenge, true, 120)?;
        Ok(challenge)
    }
}
